// app.ts - zero-dependency dashboard server: static web/ files, read-only JSON API, SSE feed and
// token-gated owner/guardian actions. createDashboard() takes an injected Backend so tests run offline.
import { randomBytes, timingSafeEqual } from 'node:crypto';
import { createServer } from 'node:http';
import type { IncomingMessage, Server, ServerResponse } from 'node:http';
import { readdir, readFile, stat } from 'node:fs/promises';
import { extname, join, resolve, sep } from 'node:path';
import { REPO_ROOT } from '../lib/env.ts';
import { EXPLORER, explorer, validateAccountId } from '../lib/near.ts';
import { AGENT_METHODS } from '../lib/spendfuse.ts';
import type { ConfigView, LogEntry, Stats } from '../lib/types.ts';
import type { ActionName, ActionOutcome, Backend, KeyJson } from './backend.ts';
import { ACTION_NAMES } from './backend.ts';

export const DEFAULT_PORT = 8787;
export const DEFAULT_HOST = '127.0.0.1';
export const WEB_ROOT = join(REPO_ROOT, 'web');
export const RUNS_DIR = join(REPO_ROOT, '.spendfuse', 'runs');

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

const SECURITY_HEADERS: Record<string, string> = {
  'content-security-policy': CSP,
  'x-content-type-options': 'nosniff',
  'x-frame-options': 'DENY',
  'referrer-policy': 'no-referrer',
  'cross-origin-opener-policy': 'same-origin',
  'cross-origin-resource-policy': 'same-origin',
  'permissions-policy': 'camera=(), microphone=(), geolocation=()',
};

const CONTENT_TYPES: Record<string, string> = {
  '.html': 'text/html; charset=utf-8',
  '.js': 'text/javascript; charset=utf-8',
  '.css': 'text/css; charset=utf-8',
  '.json': 'application/json; charset=utf-8',
  '.svg': 'image/svg+xml',
  '.png': 'image/png',
  '.ico': 'image/x-icon',
  '.txt': 'text/plain; charset=utf-8',
};

export const MAX_BODY = 4096;
const MAX_RUN_BYTES = 2 * 1024 * 1024;
const MAX_RUNS_LISTED = 200;
const REASON_MAX_BYTES = 256;
const HASH_RE = /^[1-9A-HJ-NP-Za-km-z]{43,44}$/;
const RUN_ID_RE = /^[A-Za-z0-9][A-Za-z0-9._-]{0,99}$/;
const LOOPBACK_HOSTS = new Set(['127.0.0.1', '::1', 'localhost']);
const LOOPBACK_HOST_HEADERS = new Set(['127.0.0.1', 'localhost', '[::1]']);

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
  if (Buffer.byteLength(v, 'utf8') > REASON_MAX_BYTES) return new Error('reason is longer than 256 bytes');
  return v;
}
export const isTxHash = (v: unknown): v is string => typeof v === 'string' && HASH_RE.test(v);

// ---------------------------------------------------------------- small helpers
class HttpError extends Error {
  readonly status: number;
  constructor(status: number, message: string) {
    super(message);
    this.status = status;
  }
}

const jsonReplacer = (_k: string, v: unknown) => (typeof v === 'bigint' ? v.toString() : v);

function sendJson(res: ServerResponse, status: number, body: unknown): void {
  const text = JSON.stringify(body, jsonReplacer);
  res.writeHead(status, { ...SECURITY_HEADERS, 'content-type': 'application/json; charset=utf-8', 'cache-control': 'no-store' });
  res.end(text);
}

const errMsg = (err: unknown): string => (err instanceof Error ? err.message : String(err));

function readBody(req: IncomingMessage, max: number): Promise<string> {
  return new Promise((ok, fail) => {
    const declared = Number(req.headers['content-length'] ?? 0);
    if (declared > max) {
      fail(new HttpError(413, `body larger than ${max} bytes`));
      req.resume();
      return;
    }
    const chunks: Buffer[] = [];
    let size = 0;
    let done = false;
    req.on('data', (c: Buffer) => {
      if (done) return;
      size += c.length;
      if (size > max) {
        done = true;
        fail(new HttpError(413, `body larger than ${max} bytes`));
        req.resume();
        return;
      }
      chunks.push(c);
    });
    req.on('end', () => {
      if (!done) ok(Buffer.concat(chunks).toString('utf8'));
    });
    req.on('error', (e) => {
      if (!done) fail(e);
    });
  });
}

/** Promise cache with a TTL; in-flight requests are shared, failures are not kept. */
export class TtlCache {
  readonly ttlMs: number;
  readonly #map = new Map<string, { at: number; p: Promise<unknown> }>();
  constructor(ttlMs: number) {
    this.ttlMs = ttlMs;
  }
  get<T>(key: string, fn: () => Promise<T>): Promise<T> {
    const now = Date.now();
    const hit = this.#map.get(key);
    if (hit && now - hit.at < this.ttlMs) return hit.p as Promise<T>;
    const p = fn();
    this.#map.set(key, { at: now, p });
    p.catch(() => {
      if (this.#map.get(key)?.p === p) this.#map.delete(key);
    });
    return p;
  }
  clear(): void {
    this.#map.clear();
  }
}

// ---------------------------------------------------------------- options
export interface DashboardOptions {
  backend: Backend;
  host?: string;
  port?: number;
  /** disables every POST route */
  readonly?: boolean;
  /** fixed token (tests); default random per process */
  token?: string;
  webRoot?: string;
  runsDir?: string;
  cacheMs?: number;
  pollMs?: number;
  heartbeatMs?: number;
  log?: (msg: string) => void;
}

export interface Dashboard {
  server: Server;
  token: string;
  actionsEnabled: boolean;
  url: string;
  close(): Promise<void>;
}

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

// ---------------------------------------------------------------- server
export function createDashboard(opts: DashboardOptions): Promise<Dashboard> {
  const { backend } = opts;
  const views = backend.views;
  const host = opts.host ?? DEFAULT_HOST;
  const readonly = !!opts.readonly;
  const local = LOOPBACK_HOSTS.has(host);
  const signers = readonly || !local ? null : backend.signers;
  const actionsEnabled = signers !== null;
  const token = opts.token ?? randomBytes(24).toString('base64url');
  const tokenBuf = Buffer.from(token);
  const webRoot = resolve(opts.webRoot ?? WEB_ROOT);
  const runsDir = resolve(opts.runsDir ?? RUNS_DIR);
  const cache = new TtlCache(opts.cacheMs ?? 2000);
  const pollMs = opts.pollMs ?? 3000;
  const heartbeatMs = opts.heartbeatMs ?? 15000;
  const log = opts.log ?? ((m: string) => console.log(m));

  const c = {
    config: () => cache.get('config', () => views.getConfig()),
    stats: () => cache.get('stats', () => views.getStats()),
    agents: () => cache.get('agents', () => views.listAllAgents()),
    pending: () => cache.get('pending', () => views.getAllPending()),
    activity: (before?: string, limit = 50) => cache.get(`activity:${before ?? ''}:${limit}`, () => views.getActivity(before, limit)),
    blocklist: () => cache.get('blocklist', () => views.getBlocklist(0, 100)),
    keys: (id: string) => cache.get(`keys:${id}`, () => views.listKeys(id)),
  };

  // ------------------------------------------------ /api/state
  async function state(): Promise<Record<string, unknown>> {
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
    const ids = [...new Set([...backend.proofAccounts, ...agentIds])].filter(isAccountId).slice(0, 10);
    const proofs = await Promise.all(
      ids.map(async (id) => {
        try {
          return keyProof(id, backend.vaultId, await c.keys(id));
        } catch (err) {
          return keyProof(id, backend.vaultId, null, errMsg(err));
        }
      }),
    );
    return {
      vaultId: backend.vaultId,
      network: backend.network,
      explorer: EXPLORER,
      mode: {
        readonly,
        actions: actionsEnabled,
        role: signers?.role ?? null,
        signer: signers?.accountId ?? null,
        allowed: signers ? [...signers.allowed] : [],
      },
      ...out,
      keys: proofs,
      errors,
      fetchedAt: Date.now(),
    };
  }

  // ------------------------------------------------ runs
  async function listRuns(): Promise<unknown[]> {
    let names: string[];
    try {
      names = await readdir(runsDir);
    } catch {
      return [];
    }
    const files = names.filter((n) => n.endsWith('.json') && RUN_ID_RE.test(n.slice(0, -5)));
    const rows = await Promise.all(
      files.map(async (n) => {
        const id = n.slice(0, -5);
        try {
          const st = await stat(join(runsDir, n));
          if (!st.isFile()) return null;
          const row: Record<string, unknown> = { id, size: st.size, mtimeMs: Math.round(st.mtimeMs) };
          if (st.size <= MAX_RUN_BYTES) {
            try {
              const j = JSON.parse(await readFile(join(runsDir, n), 'utf8')) as Record<string, unknown>;
              if (j && typeof j === 'object' && !Array.isArray(j)) {
                for (const k of ['title', 'name', 'scenario', 'mode', 'startedAt', 'started_at', 'outcome', 'result']) {
                  const v = j[k];
                  if (typeof v === 'string' || typeof v === 'number' || typeof v === 'boolean') row[k] = typeof v === 'string' ? v.slice(0, 200) : v;
                }
                const steps = ['steps', 'events', 'timeline', 'entries'].map((k) => j[k]).find(Array.isArray);
                if (steps) row.count = (steps as unknown[]).length;
              }
            } catch {
              row.invalid = true;
            }
          }
          return row;
        } catch {
          return null;
        }
      }),
    );
    return rows
      .filter((r): r is Record<string, unknown> => r !== null)
      .sort((a, b) => Number(b.mtimeMs) - Number(a.mtimeMs))
      .slice(0, MAX_RUNS_LISTED);
  }

  async function getRun(id: string): Promise<unknown> {
    if (!RUN_ID_RE.test(id) || id.includes('..')) throw new HttpError(400, 'bad run id');
    const file = resolve(runsDir, `${id}.json`);
    if (!file.startsWith(runsDir + sep)) throw new HttpError(400, 'bad run id');
    let st;
    try {
      st = await stat(file);
    } catch {
      throw new HttpError(404, 'run not found');
    }
    if (!st.isFile()) throw new HttpError(404, 'run not found');
    if (st.size > MAX_RUN_BYTES) throw new HttpError(413, 'run file too large');
    try {
      const text = await readFile(file, 'utf8');
      return JSON.parse(backend.redactRun ? backend.redactRun(text) : text);
    } catch {
      throw new HttpError(422, 'run file is not valid JSON');
    }
  }

  // ------------------------------------------------ SSE
  const clients = new Set<ServerResponse>();
  let pollTimer: NodeJS.Timeout | null = null;
  let beatTimer: NodeJS.Timeout | null = null;
  let busy = false;
  let lastSeq: bigint | null = null;
  let lastWritten: bigint | null = null;
  let lastStatus = '';

  const broadcast = (event: string, data: unknown) => {
    const frame = `event: ${event}\ndata: ${JSON.stringify(data, jsonReplacer)}\n\n`;
    for (const r of clients) r.write(frame);
  };

  const statusOf = (config: ConfigView | null, stats: Stats | null, error: string | null) => ({
    paused: config?.paused ?? null,
    pause_reason: config?.pause_reason ?? null,
    pending: config?.pending ?? null,
    activity_written: config?.activity_written ?? null,
    stats,
    error,
  });

  async function tick(): Promise<void> {
    if (busy || clients.size === 0) return;
    busy = true;
    try {
      const [config, stats] = await Promise.all([c.config(), c.stats()]);
      const st = JSON.stringify(statusOf(config, stats, null));
      if (st !== lastStatus) {
        lastStatus = st;
        broadcast('status', JSON.parse(st));
      }
      const written = BigInt(config.activity_written);
      if (lastWritten === null || lastSeq === null) {
        const recent = await c.activity();
        lastSeq = recent.reduce((m, e) => (BigInt(e.seq) > m ? BigInt(e.seq) : m), -1n);
        lastWritten = written;
      } else if (written > lastWritten) {
        const limit = Number(written - lastWritten > 100n ? 100n : written - lastWritten);
        const fresh = await views.getActivity(undefined, Math.max(limit, 1));
        const since = lastSeq;
        const news = fresh.filter((e) => BigInt(e.seq) > since).sort((a, b) => (BigInt(a.seq) < BigInt(b.seq) ? -1 : 1));
        lastWritten = written;
        if (news.length) {
          lastSeq = BigInt(news[news.length - 1]!.seq);
          cache.clear(); // agents / pending / blocklist likely changed too
          broadcast('activity', news satisfies LogEntry[]);
        }
      }
    } catch (err) {
      const st = JSON.stringify(statusOf(null, null, errMsg(err)));
      if (st !== lastStatus) {
        lastStatus = st;
        broadcast('status', JSON.parse(st));
      }
    } finally {
      busy = false;
    }
  }

  function startPoller(): void {
    if (pollTimer) return;
    pollTimer = setInterval(() => void tick(), pollMs);
    beatTimer = setInterval(() => {
      for (const r of clients) r.write(': ping\n\n');
    }, heartbeatMs);
    pollTimer.unref();
    beatTimer.unref();
    void tick();
  }
  function stopPoller(): void {
    if (pollTimer) clearInterval(pollTimer);
    if (beatTimer) clearInterval(beatTimer);
    pollTimer = beatTimer = null;
    lastSeq = lastWritten = null;
    lastStatus = '';
  }

  function openStream(req: IncomingMessage, res: ServerResponse): void {
    res.writeHead(200, {
      ...SECURITY_HEADERS,
      'content-type': 'text/event-stream; charset=utf-8',
      'cache-control': 'no-store',
      connection: 'keep-alive',
      'x-accel-buffering': 'no',
    });
    res.write(`retry: ${Math.max(pollMs, 1000)}\n\n`);
    if (lastStatus) res.write(`event: status\ndata: ${lastStatus}\n\n`);
    clients.add(res);
    const drop = () => {
      clients.delete(res);
      if (clients.size === 0) stopPoller();
    };
    req.on('close', drop);
    res.on('close', drop);
    startPoller();
  }

  // ------------------------------------------------ actions
  function checkToken(req: IncomingMessage): boolean {
    const h = req.headers['x-spendfuse-token'];
    if (typeof h !== 'string') return false;
    const b = Buffer.from(h);
    return b.length === tokenBuf.length && timingSafeEqual(b, tokenBuf);
  }

  const ALLOWED_KEYS: Record<ActionName, readonly string[]> = {
    approve: ['request_id'],
    reject: ['request_id', 'reason'],
    freeze: ['agent_id', 'reason'],
    unfreeze: ['agent_id'],
    pause: ['reason'],
    unpause: [],
  };

  async function action(name: ActionName, req: IncomingMessage): Promise<{ status: number; body: unknown }> {
    if (readonly) throw new HttpError(403, 'read-only mode: actions are disabled');
    if (!signers) throw new HttpError(403, 'actions are disabled (no OWNER_KEY / GUARDIAN_KEY, or not bound to localhost)');
    if (!checkToken(req)) throw new HttpError(403, 'missing or wrong X-Spendfuse-Token');
    const origin = req.headers.origin;
    if (origin !== undefined && origin !== `http://${req.headers.host}`) throw new HttpError(403, 'cross-origin request refused');
    const ct = String(req.headers['content-type'] ?? '').split(';')[0]!.trim().toLowerCase();
    if (ct !== 'application/json') throw new HttpError(415, 'content-type must be application/json');
    if (!signers.allowed.includes(name)) throw new HttpError(403, `${signers.role} cannot ${name}`);

    const raw = await readBody(req, MAX_BODY);
    let body: unknown;
    try {
      body = raw.trim() === '' ? {} : JSON.parse(raw);
    } catch {
      throw new HttpError(400, 'body is not JSON');
    }
    if (!body || typeof body !== 'object' || Array.isArray(body)) throw new HttpError(400, 'body must be a JSON object');
    const b = body as Record<string, unknown>;
    for (const k of Object.keys(b)) if (!ALLOWED_KEYS[name].includes(k)) throw new HttpError(400, `unknown field ${k}`);
    const reason = checkReason(b.reason);
    if (reason instanceof Error) throw new HttpError(400, reason.message);
    const needId = () => {
      if (!isRequestId(b.request_id)) throw new HttpError(400, 'request_id must be a decimal string');
      return b.request_id;
    };
    const needAgent = () => {
      if (!isAccountId(b.agent_id)) throw new HttpError(400, 'agent_id is not a valid account id');
      return b.agent_id;
    };

    let out: ActionOutcome;
    switch (name) {
      case 'approve':
        out = await signers.approve(needId());
        break;
      case 'reject':
        out = await signers.reject(needId(), reason);
        break;
      case 'freeze':
        out = await signers.freeze(needAgent(), reason);
        break;
      case 'unfreeze':
        out = await signers.unfreeze(needAgent());
        break;
      case 'pause':
        out = await signers.pause(reason);
        break;
      case 'unpause':
        out = await signers.unpause();
        break;
    }
    cache.clear();
    const hash = isTxHash(out.hash) ? out.hash : null;
    log(`[action] ${name} by ${signers.accountId}: ${out.ok ? 'ok' : `failed: ${out.error ?? ''}`}${hash ? ` ${explorer.tx(hash)}` : ''}`);
    return { status: out.ok ? 200 : 502, body: { ok: out.ok, action: name, hash, url: hash ? explorer.tx(hash) : null, error: out.error, result: out.result } };
  }

  // ------------------------------------------------ static
  async function serveStatic(pathname: string, res: ServerResponse, head: boolean): Promise<void> {
    let decoded: string;
    try {
      decoded = decodeURIComponent(pathname);
    } catch {
      throw new HttpError(400, 'bad path');
    }
    if (decoded.includes('\0') || decoded.includes('\\')) throw new HttpError(400, 'bad path');
    const segs = decoded.split('/');
    if (segs.some((s) => s === '..' || (s.startsWith('.') && s !== ''))) throw new HttpError(403, 'forbidden');
    const rel = decoded === '/' ? 'index.html' : decoded.replace(/^\/+/, '');
    const file = resolve(webRoot, rel);
    if (!file.startsWith(webRoot + sep)) throw new HttpError(403, 'forbidden');
    const type = CONTENT_TYPES[extname(file).toLowerCase()];
    if (!type) throw new HttpError(404, 'not found');
    let data: Buffer;
    try {
      const st = await stat(file);
      if (!st.isFile()) throw new Error('not a file');
      data = await readFile(file);
    } catch {
      throw new HttpError(404, 'not found');
    }
    res.writeHead(200, { ...SECURITY_HEADERS, 'content-type': type, 'content-length': data.length, 'cache-control': 'no-cache' });
    res.end(head ? undefined : data);
  }

  // ------------------------------------------------ router
  async function handle(req: IncomingMessage, res: ServerResponse): Promise<void> {
    const method = req.method ?? 'GET';
    // DNS rebinding: a loopback bind only answers to loopback Host names, READONLY included (it
    // still serves the vault views and run logs to whatever page could otherwise read them)
    if (local) {
      const h = String(req.headers.host ?? '').replace(/:\d+$/, '');
      if (!LOOPBACK_HOST_HEADERS.has(h)) throw new HttpError(421, 'unexpected Host header');
    }
    const rawPath = (req.url ?? '/').split('?')[0] ?? '/';
    const url = new URL(req.url ?? '/', 'http://localhost');
    if (!rawPath.startsWith('/api/')) {
      if (method !== 'GET' && method !== 'HEAD') throw new HttpError(405, 'method not allowed');
      return serveStatic(rawPath, res, method === 'HEAD');
    }
    const path = rawPath;
    if (method === 'POST') {
      const name = path.slice('/api/'.length) as ActionName;
      if (!ACTION_NAMES.includes(name)) throw new HttpError(404, 'no such route');
      const r = await action(name, req);
      return sendJson(res, r.status, r.body);
    }
    if (method !== 'GET' && method !== 'HEAD') throw new HttpError(405, 'method not allowed');
    if (path === '/api/state') return sendJson(res, 200, await state());
    if (path === '/api/activity') {
      const before = url.searchParams.get('before');
      const limitRaw = url.searchParams.get('limit');
      if (before !== null && !isRequestId(before)) throw new HttpError(400, 'before must be a decimal sequence number');
      let limit = 50;
      if (limitRaw !== null) {
        if (!/^\d{1,3}$/.test(limitRaw) || Number(limitRaw) < 1 || Number(limitRaw) > 100) throw new HttpError(400, 'limit must be 1..100');
        limit = Number(limitRaw);
      }
      return sendJson(res, 200, { activity: await c.activity(before ?? undefined, limit) });
    }
    if (path === '/api/runs') return sendJson(res, 200, { runs: await listRuns() });
    if (path.startsWith('/api/runs/')) {
      let id: string;
      try {
        id = decodeURIComponent(path.slice('/api/runs/'.length));
      } catch {
        throw new HttpError(400, 'bad run id');
      }
      return sendJson(res, 200, { id, run: await getRun(id) });
    }
    if (path === '/api/events') return openStream(req, res);
    throw new HttpError(404, 'no such route');
  }

  const server = createServer((req, res) => {
    handle(req, res).catch((err: unknown) => {
      if (res.headersSent) {
        res.end();
        return;
      }
      const status = err instanceof HttpError ? err.status : 500;
      const msg = err instanceof HttpError ? err.message : 'internal error';
      if (!(err instanceof HttpError)) log(`[error] ${errMsg(err)}`);
      sendJson(res, status, { error: msg });
    });
  });
  server.headersTimeout = 10_000;
  server.requestTimeout = 15_000;

  return new Promise((ok, fail) => {
    server.once('error', fail);
    server.listen(opts.port ?? DEFAULT_PORT, host, () => {
      server.off('error', fail);
      const addr = server.address();
      const port = typeof addr === 'object' && addr ? addr.port : (opts.port ?? DEFAULT_PORT);
      const shownHost = host.includes(':') ? `[${host}]` : host;
      ok({
        server,
        token,
        actionsEnabled,
        url: `http://${shownHost}:${port}`,
        close: () =>
          new Promise<void>((done) => {
            stopPoller();
            for (const r of clients) r.end();
            clients.clear();
            server.close(() => done());
            server.closeAllConnections();
          }),
      });
    });
  });
}
