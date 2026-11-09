// core.ts - runtime-neutral dashboard logic shared by the Node server (app.ts) and the Cloudflare
// Worker (src/worker/index.ts): validation, security headers, the view cache, the /api/state body,
// run summaries and the live-feed diff. No node:* imports here - only fetch-era globals.
import { EXPLORER, validateAccountId } from '../lib/near.ts';
import { AGENT_METHODS } from '../lib/spendfuse.ts';
import type { ConfigView, LogEntry, Stats } from '../lib/types.ts';
import type { KeyJson, Views } from './backend.ts';

export const CSP = [
  "default-src 'self'",
  "script-src 'self'",
  "style-src 'self'",
  "img-src 'self' data:",
  "connect-src 'self'",
  "font-src 'self'",
  "object-src 'none'",
  "base-uri 'none'",
  "form-action 'none'",
  "frame-ancestors 'none'",
].join('; ');

export const SECURITY_HEADERS: Readonly<Record<string, string>> = {
  'content-security-policy': CSP,
  'x-content-type-options': 'nosniff',
  'x-frame-options': 'DENY',
  'referrer-policy': 'no-referrer',
  'cross-origin-opener-policy': 'same-origin',
  'cross-origin-resource-policy': 'same-origin',
  'permissions-policy': 'camera=(), microphone=(), geolocation=()',
};

export const MAX_RUNS_LISTED = 200;
const REASON_MAX_BYTES = 256;
const HASH_RE = /^[1-9A-HJ-NP-Za-km-z]{43,44}$/;
export const RUN_ID_RE = /^[A-Za-z0-9][A-Za-z0-9._-]{0,99}$/;
export const READONLY_MESSAGE = 'read-only mode: actions are disabled';

// ---------------------------------------------------------------- validation
/** Decimal u64 without leading zeros. */
export function isRequestId(v: unknown): v is string {
  return typeof v === 'string' && /^(0|[1-9]\d{0,19})$/.test(v) && BigInt(v) < 1n << 64n;
}
export function isAccountId(v: unknown): v is string {
  return typeof v === 'string' && validateAccountId(v) === null;
}
/** Optional free-text reason: printable, at most 256 UTF-8 bytes. */
export function checkReason(v: unknown): string | undefined | Error {
  if (v === undefined || v === null || v === '') return undefined;
  if (typeof v !== 'string') return new Error('reason must be a string');
  // eslint-disable-next-line no-control-regex
  if (/[\u0000-\u001f\u007f]/.test(v)) return new Error('reason has control characters');
  if (new TextEncoder().encode(v).length > REASON_MAX_BYTES) return new Error('reason is longer than 256 bytes');
  return v;
}
export const isTxHash = (v: unknown): v is string => typeof v === 'string' && HASH_RE.test(v);
export const isRunId = (id: string): boolean => RUN_ID_RE.test(id) && !id.includes('..');

// ---------------------------------------------------------------- small helpers
export class HttpError extends Error {
  readonly status: number;
  constructor(status: number, message: string) {
    super(message);
    this.status = status;
  }
}

export const jsonReplacer = (_k: string, v: unknown): unknown => (typeof v === 'bigint' ? v.toString() : v);
export const errMsg = (err: unknown): string => (err instanceof Error ? err.message : String(err));

/**
 * Promise cache with a TTL; in-flight requests are shared, failures are not kept.
 * Bounded: expired entries are swept when the map is full, then the oldest entries are dropped,
 * so varied keys (e.g. activity pages) cannot grow it without limit.
 */
export class TtlCache {
  readonly ttlMs: number;
  readonly maxEntries: number;
  readonly #map = new Map<string, { at: number; p: Promise<unknown> }>();
  constructor(ttlMs: number, maxEntries = 256) {
    this.ttlMs = ttlMs;
    this.maxEntries = Math.max(1, maxEntries);
  }
  get size(): number {
    return this.#map.size;
  }
  get<T>(key: string, fn: () => Promise<T>): Promise<T> {
    const now = Date.now();
    const hit = this.#map.get(key);
    if (hit && now - hit.at < this.ttlMs) return hit.p as Promise<T>;
    const p = fn();
    this.#map.delete(key); // re-insert at the end so Map order stays oldest-first
    if (this.#map.size >= this.maxEntries) this.#evict(now);
    this.#map.set(key, { at: now, p });
    p.catch(() => {
      if (this.#map.get(key)?.p === p) this.#map.delete(key);
    });
    return p;
  }
  #evict(now: number): void {
    for (const [k, v] of this.#map) if (now - v.at >= this.ttlMs) this.#map.delete(k);
    for (const k of this.#map.keys()) {
      if (this.#map.size < this.maxEntries) break;
      this.#map.delete(k);
    }
  }
  clear(): void {
    this.#map.clear();
  }
}

// ---------------------------------------------------------------- cached views
export interface CachedViews {
  config(): Promise<ConfigView>;
  stats(): Promise<Stats>;
  agents(): ReturnType<Views['listAllAgents']>;
  pending(): ReturnType<Views['getAllPending']>;
  activity(before?: string, limit?: number): Promise<LogEntry[]>;
  blocklist(): ReturnType<Views['getBlocklist']>;
  keys(id: string): Promise<KeyJson[]>;
  /** uncached activity read (the feed asks for exactly the new entries) */
  freshActivity(limit: number): Promise<LogEntry[]>;
  clear(): void;
}

export function cachedViews(views: Views, cache: TtlCache): CachedViews {
  return {
    config: () => cache.get('config', () => views.getConfig()),
    stats: () => cache.get('stats', () => views.getStats()),
    agents: () => cache.get('agents', () => views.listAllAgents()),
    pending: () => cache.get('pending', () => views.getAllPending()),
    activity: async (before, limit = 50) => {
      // The contract clamps before_seq to activity_written, so any larger value is the newest page:
      // fold those onto one cache key instead of one key (and one RPC call) per distinct number.
      if (before !== undefined) {
        const written = await cache.get('config', () => views.getConfig()).then(
          (cfg) => BigInt(cfg.activity_written),
          () => null,
        );
        if (written !== null && BigInt(before) >= written) before = undefined;
      }
      return cache.get(`activity:${before ?? ''}:${limit}`, () => views.getActivity(before, limit));
    },
    blocklist: () => cache.get('blocklist', () => views.getBlocklist(0, 100)),
    keys: (id) => cache.get(`keys:${id}`, () => views.listKeys(id)),
    freshActivity: (limit) => views.getActivity(undefined, limit),
    clear: () => cache.clear(),
  };
}

// ---------------------------------------------------------------- key proof
export interface KeyProof {
  accountId: string;
  keys: KeyJson[];
  fullAccess: number;
  /** every key is a function-call key whose receiver is the vault and whose methods are agent methods */
  fcOnly: boolean;
  error: string | null;
}

export function keyProof(accountId: string, vaultId: string, keys: KeyJson[] | null, error: string | null = null): KeyProof {
  const list = keys ?? [];
  const agentSet = new Set<string>(AGENT_METHODS);
  const fullAccess = list.filter((k) => k.fullAccess).length;
  const fcOnly =
    list.length > 0 &&
    list.every((k) => !k.fullAccess && k.receiverId === vaultId && !!k.methodNames?.length && k.methodNames.every((m) => agentSet.has(m)));
  return { accountId, keys: list, fullAccess, fcOnly, error };
}

// ---------------------------------------------------------------- /api/state
export interface ModeView {
  readonly: boolean;
  actions: boolean;
  role: string | null;
  signer: string | null;
  allowed: string[];
}
export const READONLY_MODE: ModeView = { readonly: true, actions: false, role: null, signer: null, allowed: [] };

export interface StateInput {
  c: CachedViews;
  vaultId: string;
  network: string;
  proofAccounts: readonly string[];
  mode: ModeView;
}

export async function buildState({ c, vaultId, network, proofAccounts, mode }: StateInput): Promise<Record<string, unknown>> {
  const names = ['config', 'stats', 'agents', 'pending', 'activity', 'blocklist'] as const;
  const settled = await Promise.allSettled([c.config(), c.stats(), c.agents(), c.pending(), c.activity(), c.blocklist()]);
  const out: Record<string, unknown> = {};
  const errors: Record<string, string> = {};
  settled.forEach((s, i) => {
    const name = names[i]!;
    if (s.status === 'fulfilled') out[name] = s.value;
    else {
      out[name] = null;
      errors[name] = errMsg(s.reason);
    }
  });
  const agentIds = Array.isArray(out.agents) ? (out.agents as { agent_id: string }[]).map((a) => a.agent_id) : [];
  const ids = [...new Set([...proofAccounts, ...agentIds])].filter(isAccountId).slice(0, 10);
  const proofs = await Promise.all(
    ids.map(async (id) => {
      try {
        return keyProof(id, vaultId, await c.keys(id));
      } catch (err) {
        return keyProof(id, vaultId, null, errMsg(err));
      }
    }),
  );
  return { vaultId, network, explorer: EXPLORER, mode: { ...mode, allowed: [...mode.allowed] }, ...out, keys: proofs, errors, fetchedAt: Date.now() };
}

// ---------------------------------------------------------------- /api/activity
export function parseActivityQuery(params: URLSearchParams): { before: string | undefined; limit: number } {
  const before = params.get('before');
  const limitRaw = params.get('limit');
  if (before !== null && !isRequestId(before)) throw new HttpError(400, 'before must be a decimal sequence number');
  let limit = 50;
  if (limitRaw !== null) {
    if (!/^\d{1,3}$/.test(limitRaw) || Number(limitRaw) < 1 || Number(limitRaw) > 100) throw new HttpError(400, 'limit must be 1..100');
    limit = Number(limitRaw);
  }
  return { before: before ?? undefined, limit };
}

// ---------------------------------------------------------------- runs
/** One row of /api/runs. `parsed` is undefined when the file was too large to read, null when it was not JSON. */
export function runSummary(id: string, size: number, mtimeMs: number, parsed: unknown): Record<string, unknown> {
  const row: Record<string, unknown> = { id, size, mtimeMs: Math.round(mtimeMs) };
  if (parsed === null) row.invalid = true;
  else if (parsed && typeof parsed === 'object' && !Array.isArray(parsed)) {
    const j = parsed as Record<string, unknown>;
    for (const k of ['title', 'name', 'scenario', 'mode', 'startedAt', 'started_at', 'outcome', 'result', 'dryRun', 'llm', 'passed', 'total', 'pass']) {
      const v = j[k];
      if (typeof v === 'string' || typeof v === 'number' || typeof v === 'boolean') row[k] = typeof v === 'string' ? v.slice(0, 200) : v;
    }
    const steps = ['steps', 'events', 'timeline', 'entries', 'scenarios'].map((k) => j[k]).find(Array.isArray);
    if (steps) row.count = (steps as unknown[]).length;
  }
  return row;
}

export const sortRuns = (rows: Record<string, unknown>[]): Record<string, unknown>[] =>
  [...rows].sort((a, b) => Number(b.mtimeMs) - Number(a.mtimeMs)).slice(0, MAX_RUNS_LISTED);

// ---------------------------------------------------------------- live feed (SSE)
export interface FeedEvent {
  event: 'status' | 'activity';
  data: unknown;
}

const statusOf = (config: ConfigView | null, stats: Stats | null, error: string | null) => ({
  paused: config?.paused ?? null,
  pause_reason: config?.pause_reason ?? null,
  pending: config?.pending ?? null,
  activity_written: config?.activity_written ?? null,
  stats,
  error,
});

export const sseFrame = (e: FeedEvent): string => `event: ${e.event}\ndata: ${JSON.stringify(e.data, jsonReplacer)}\n\n`;

/**
 * Diffs the vault between polls: a `status` event when paused/pending/stats change (or an RPC
 * error appears) and an `activity` event with the entries written since the last poll.
 * The first poll only records where the log is; it emits status but no activity.
 */
export class Feed {
  readonly #c: CachedViews;
  #lastSeq: bigint | null = null;
  #lastWritten: bigint | null = null;
  #lastStatus = '';
  constructor(c: CachedViews) {
    this.#c = c;
  }
  /** the last status frame's JSON ('' before the first poll) */
  get lastStatus(): string {
    return this.#lastStatus;
  }
  reset(): void {
    this.#lastSeq = this.#lastWritten = null;
    this.#lastStatus = '';
  }
  async poll(): Promise<FeedEvent[]> {
    const out: FeedEvent[] = [];
    const c = this.#c;
    try {
      const [config, stats] = await Promise.all([c.config(), c.stats()]);
      const st = JSON.stringify(statusOf(config, stats, null));
      if (st !== this.#lastStatus) {
        this.#lastStatus = st;
        out.push({ event: 'status', data: JSON.parse(st) });
      }
      const written = BigInt(config.activity_written);
      if (this.#lastWritten === null || this.#lastSeq === null) {
        const recent = await c.activity();
        this.#lastSeq = recent.reduce((m, e) => (BigInt(e.seq) > m ? BigInt(e.seq) : m), -1n);
        this.#lastWritten = written;
      } else if (written > this.#lastWritten) {
        const limit = Number(written - this.#lastWritten > 100n ? 100n : written - this.#lastWritten);
        const fresh = await c.freshActivity(Math.max(limit, 1));
        const since = this.#lastSeq;
        const news = fresh.filter((e) => BigInt(e.seq) > since).sort((a, b) => (BigInt(a.seq) < BigInt(b.seq) ? -1 : 1));
        this.#lastWritten = written;
        if (news.length) {
          this.#lastSeq = BigInt(news[news.length - 1]!.seq);
          c.clear(); // agents / pending / blocklist likely changed too
          out.push({ event: 'activity', data: news satisfies LogEntry[] });
        }
      }
    } catch (err) {
      const st = JSON.stringify(statusOf(null, null, errMsg(err)));
      if (st !== this.#lastStatus) {
        this.#lastStatus = st;
        out.push({ event: 'status', data: JSON.parse(st) });
      }
    }
    return out;
  }
}
