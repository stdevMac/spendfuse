// counterparty.ts - NEAR counterparty check ("scout") for an AI-agent payment guard.
// Zero dependencies. Runs as-is on Node 26 (type stripping: erasable TypeScript only).
// Read-only: JSON-RPC view calls, FastNear Transactions API read queries, NearBlocks v3 GETs.
// It never signs, never sends a transaction, never needs a key (keys only raise rate limits).

export type Network = "testnet" | "mainnet";
export type Decision = "allow" | "warn" | "block";
export type Severity = "block" | "warn" | "info";
export type AccountType =
  | "invalid" | "named" | "near-implicit" | "eth-implicit" | "deterministic" | "universal";

export interface Reason { code: string; severity: Severity; detail: string; source: string }

export interface Facts {
  accountType: AccountType;
  exists: boolean | null;             // null = RPC could not answer
  uninitialized: boolean;             // universal account funded by a transfer but not initialized
  balanceYocto: string | null;
  storageUsage: number | null;
  codeHash: string | null;            // LOCAL code hash only: all-1s also for global-contract accounts
  globalContractHash: string | null;  // AccountContract::Global(hash): immutable code
  globalContractAccountId: string | null; // AccountContract::GlobalByAccount(id): publisher can swap code
  hasContract: boolean | null;
  fullAccessKeys: number | null;
  functionCallKeys: number | null;
  createdAtMs: number | null;
  createdTx: string | null;
  createdSource: string | null;
  deletedBefore: boolean | null;
  txCount: number | null;
  lastActivityMs: number | null;
  lastDeployMs: number | null;
  lookbackBlock: number | null;
  lookbackAtMs: number | null;
  existedAtLookback: boolean | null;
  codeAtLookback: string | null;
}

export interface Verdict {
  receiver: string;
  network: Network;
  decision: Decision;
  reasons: Reason[];
  facts: Facts;
  checkedAt: string;
  durationMs: number;
}

// Shared blocklist lookup. "confirmed" (or true) = payments are blocked; "reported" = an open report, the vault
// routes payments to a human unless the receiver is allowlisted; false / null = not listed.
export type BlockStatus = "reported" | "confirmed";
export type BlocklistHook = (accountId: string) => boolean | BlockStatus | null | Promise<boolean | BlockStatus | null>;

export interface Endpoints { rpc: string; archival: string; fastnearTx: string; nearblocks: string }

export interface CheckOptions {
  network?: Network;                                  // default "testnet"
  allowlist?: string[];                               // owner-approved payees
  pinned?: Record<string, { code?: string; createdTx?: string }>; // expected contractId()/creation tx
  blocklist?: BlocklistHook;                          // e.g. vaultBlocklist(...); also checks ancestors
  priorPayments?: (receiver: string) => number | null | Promise<number | null>;
  self?: { vault?: string; agent?: string };
  minAgeDays?: number;                                // default 3
  minTxCount?: number;                                // default 5
  recentDeployDays?: number;                          // default = minAgeDays
  contractSeverity?: Severity;                        // non-allowlisted contract receivers, default "warn"
  onUnavailable?: "warn" | "block";                   // default "warn" (route to a human)
  useNearBlocks?: boolean;                            // default true
  nearblocksPerMinute?: number;                       // default 5 (keyless tier is about 6/min, UNVERIFIED)
  fastnearApiKey?: string;
  nearblocksApiKey?: string;
  timeoutMs?: number;                                 // per request, default 8000
  endpoints?: Partial<Endpoints>;
}

export const ENDPOINTS: Record<Network, Endpoints> = {
  testnet: {
    rpc: "https://rpc.testnet.fastnear.com",
    archival: "https://archival-rpc.testnet.fastnear.com",
    fastnearTx: "https://tx.test.fastnear.com",
    nearblocks: "https://api-testnet.nearblocks.io",
  },
  mainnet: {
    rpc: "https://rpc.mainnet.fastnear.com",
    archival: "https://archival-rpc.mainnet.fastnear.com",
    fastnearTx: "https://tx.main.fastnear.com",
    nearblocks: "https://api.nearblocks.io",
  },
};

export const EMPTY_CODE_HASH = "11111111111111111111111111111111";
const DAY_MS = 86_400_000;
const REGISTRARS = new Set(["testnet", "near"]);
const BURN_ADDRESSES = new Set([
  "0".repeat(64),
  "0x" + "0".repeat(40),
  "0x000000000000000000000000000000000000dead",
]);
// Downgraded to info when the receiver is on the allowlist.
const SOFT_CODES = new Set(["NEW_ACCOUNT", "LOW_ACTIVITY", "NEW_PAYEE", "HAS_CONTRACT", "AGE_UNKNOWN"]);

// ---------- account IDs (mirrors near-account-id-rs src/validation.rs) ----------

const NAME_RE = /^(([a-z\d]+[-_])*[a-z\d]+\.)*([a-z\d]+[-_])*[a-z\d]+$/;

export function accountType(id: string): AccountType {
  if (id.length < 2 || id.length > 64 || !NAME_RE.test(id)) return "invalid";
  if (/^[0-9a-f]{64}$/.test(id)) return "near-implicit";
  if (/^0x[0-9a-f]{40}$/.test(id)) return "eth-implicit";
  if (/^0s[0-9a-f]{40}$/.test(id)) return "deterministic";
  if (/^0u[0-9a-hjkmnp-tv-z]{51}[0g]$/.test(id)) return "universal";
  return "named";
}

// Ancestors that could have created this account (only a parent can create a subaccount).
export function ancestors(id: string): string[] {
  const parts = id.split(".");
  const out: string[] = [];
  for (let i = 1; i < parts.length; i++) {
    const a = parts.slice(i).join(".");
    if (!REGISTRARS.has(a)) out.push(a);
  }
  return out;
}

function skeleton(id: string): string {
  return id.replace(/\.(testnet|near)$/, "").replace(/[-_.]/g, "")
    .replace(/rn/g, "m").replace(/vv/g, "w")
    .replace(/0/g, "o").replace(/[1il]/g, "l").replace(/5/g, "s");
}

function osa(a: string, b: string): number {
  const d: number[][] = [];
  for (let i = 0; i <= a.length; i++) d.push([i, ...new Array(b.length).fill(0)]);
  for (let j = 1; j <= b.length; j++) d[0][j] = j;
  for (let i = 1; i <= a.length; i++) {
    for (let j = 1; j <= b.length; j++) {
      const cost = a[i - 1] === b[j - 1] ? 0 : 1;
      d[i][j] = Math.min(d[i - 1][j] + 1, d[i][j - 1] + 1, d[i - 1][j - 1] + cost);
      if (i > 1 && j > 1 && a[i - 1] === b[j - 2] && a[i - 2] === b[j - 1]) {
        d[i][j] = Math.min(d[i][j], d[i - 2][j - 2] + 1);
      }
    }
  }
  return d[a.length][b.length];
}

export function lookalikeOf(id: string, allowlist: Iterable<string>): string | null {
  for (const good of allowlist) {
    if (id === good || id.endsWith("." + good)) continue; // exact, or a real subaccount of it
    const base = good.replace(/\.(testnet|near)$/, "");
    const limit = good.length >= 12 ? 2 : 1;
    if (skeleton(id) === skeleton(good)) return good;
    if (Math.abs(id.length - good.length) <= limit && osa(id, good) <= limit) return good;
    if (base.length >= 5 && id.includes(base)) return good; // guest-book-refund.testnet, guest-book.testnet.x.testnet
  }
  return null;
}

// ---------- transport ----------

export class RpcFailure extends Error {
  kind: string;
  constructor(kind: string, message: string) {
    super(`${kind}: ${message}`);
    this.kind = kind;
  }
}

function auth(key?: string): Record<string, string> {
  return key ? { authorization: `Bearer ${key}` } : {};
}

async function postJson(url: string, body: unknown, timeoutMs: number, key?: string) {
  const res = await fetch(url, {
    method: "POST",
    headers: { "content-type": "application/json", ...auth(key) },
    body: JSON.stringify(body),
    signal: AbortSignal.timeout(timeoutMs),
  });
  const text = await res.text();
  let json: any = null;
  try { json = JSON.parse(text); } catch { /* not JSON */ }
  return { status: res.status, json, text };
}

export async function rpc(url: string, method: string, params: unknown, timeoutMs = 8000, key?: string): Promise<any> {
  const r = await postJson(url, { jsonrpc: "2.0", id: "scout", method, params }, timeoutMs, key);
  if (r.json?.error) {
    const e = r.json.error; // { name: "HANDLER_ERROR", cause: { name: "UNKNOWN_ACCOUNT", info }, code, message, data }
    throw new RpcFailure(e.cause?.name ?? e.name ?? "RPC_ERROR", String(e.data ?? e.message ?? ""));
  }
  if (r.status !== 200 || !r.json) throw new RpcFailure(`HTTP_${r.status}`, r.text.slice(0, 200));
  return r.json.result;
}

type BlockRef = { finality: "final" } | { block_id: number | string };

async function viewAccount(url: string, id: string, ref: BlockRef, t: number, key?: string): Promise<any | null> {
  try {
    return await rpc(url, "query", { request_type: "view_account", account_id: id, ...ref }, t, key);
  } catch (e) {
    if (e instanceof RpcFailure && e.kind === "UNKNOWN_ACCOUNT") return null;
    throw e;
  }
}

async function keyCounts(url: string, id: string, t: number, key?: string) {
  const r = await rpc(url, "query", { request_type: "view_access_key_list", account_id: id, finality: "final" }, t, key);
  let full = 0;
  let fc = 0;
  for (const k of r.keys ?? []) {
    const p = k.access_key?.permission; // "FullAccess" | {FunctionCall} | {GasKeyFullAccess} | {GasKeyFunctionCall}
    if (p === "FullAccess" || (p && typeof p === "object" && "GasKeyFullAccess" in p)) full++;
    else fc++;
  }
  return { full, fc };
}

// Contract identity that also covers global contracts (code_hash alone misses them).
export function contractId(a: any): string | null {
  if (a.global_contract_hash) return `global:${a.global_contract_hash}`;
  if (a.global_contract_account_id) return `global-by-account:${a.global_contract_account_id}`;
  return a.code_hash && a.code_hash !== EMPTY_CODE_HASH ? a.code_hash : null;
}

// Block about `days` ago. Uses the regular RPC while it still has the state (~34 h on
// FastNear testnet), archival otherwise. Cached for 5 minutes per endpoint and window.
const lookbackCache = new Map<string, { at: number; hash: string; height: number; timeMs: number; archival: boolean }>();

async function lookbackBlock(ep: Endpoints, days: number, t: number, key?: string) {
  const ck = `${ep.rpc}|${days}`;
  const hit = lookbackCache.get(ck);
  if (hit && Date.now() - hit.at < 300_000) return hit;
  const s = (await rpc(ep.rpc, "status", [], t, key)).sync_info;
  const spanBlocks = s.latest_block_height - s.earliest_block_height;
  const spanMs = Date.parse(s.latest_block_time) - Date.parse(s.earliest_block_time);
  const msPerBlock = spanBlocks > 0 && spanMs > 0 ? spanMs / spanBlocks : 600;
  let height = Math.floor(s.latest_block_height - (days * DAY_MS) / msPerBlock);
  const archival = height < s.earliest_block_height + 2000; // margin: GC keeps moving
  const url = archival ? ep.archival : ep.rpc;
  for (let i = 0; i < 5; i++, height--) {
    try {
      const h = (await rpc(url, "block", { block_id: height }, t, key)).header;
      const v = { at: Date.now(), hash: h.hash, height: h.height, timeMs: nsToMs(h.timestamp_nanosec), archival };
      lookbackCache.set(ck, v);
      return v;
    } catch (e) {
      if (!(e instanceof RpcFailure && e.kind === "UNKNOWN_BLOCK")) throw e; // skipped height: try the one below
    }
  }
  throw new RpcFailure("UNKNOWN_BLOCK", `no block found below height ${height + 5}`);
}

async function fastnearAccount(ep: Endpoints, id: string, filters: Record<string, unknown>, t: number, key?: string) {
  const r = await postJson(`${ep.fastnearTx}/v0/account`, { account_id: id, ...filters }, t, key);
  if (r.status !== 200 || !r.json) throw new Error(`fastnear-tx HTTP ${r.status}: ${r.text.slice(0, 120)}`);
  return { txs: (r.json.account_txs ?? []) as any[], count: (r.json.txs_count ?? null) as number | null };
}

// NearBlocks: token bucket per host. When out of tokens or after a 429 it SKIPS (returns
// undefined) instead of waiting, so the scout stays fast and falls back to FastNear/archival.
const nbBuckets = new Map<string, { tokens: number; at: number; cooldownUntil: number }>();

async function nearblocksGet(ep: Endpoints, path: string, perMinute: number, t: number, key?: string): Promise<any> {
  const now = Date.now();
  const burst = 2;
  const b = nbBuckets.get(ep.nearblocks) ?? { tokens: burst, at: now, cooldownUntil: 0 };
  nbBuckets.set(ep.nearblocks, b);
  if (now < b.cooldownUntil) return undefined;
  b.tokens = Math.min(burst, b.tokens + ((now - b.at) / 60_000) * perMinute);
  b.at = now;
  if (b.tokens < 1) return undefined;
  b.tokens -= 1;
  try {
    const res = await fetch(ep.nearblocks + path, { headers: auth(key), signal: AbortSignal.timeout(t) });
    if (res.status === 429) { b.cooldownUntil = Date.now() + 60_000; return undefined; }
    if (!res.ok) return undefined;
    return ((await res.json()) as any).data; // v3 envelope: { data, errors, meta }; missing account => data: null
  } catch {
    return undefined;
  }
}

function nsToMs(ns: string | number): number {
  return Number(BigInt(ns) / 1_000_000n);
}

function ago(ms: number): string {
  const h = (Date.now() - ms) / 3_600_000;
  return h < 48 ? `${h.toFixed(1)}h` : `${(h / 24).toFixed(1)}d`;
}

function msg(e: unknown): string {
  return e instanceof Error ? e.message : String(e);
}

// ---------- the check ----------

export async function checkCounterparty(receiver: string, opts: CheckOptions = {}): Promise<Verdict> {
  const t0 = Date.now();
  const network = opts.network ?? "testnet";
  const ep: Endpoints = { ...ENDPOINTS[network], ...opts.endpoints };
  const t = opts.timeoutMs ?? 8000;
  const fnKey = opts.fastnearApiKey;
  const minAgeDays = opts.minAgeDays ?? 3;
  const minTx = opts.minTxCount ?? 5;
  const deployDays = opts.recentDeployDays ?? minAgeDays;
  const unavailable: Severity = opts.onUnavailable ?? "warn";
  const useNB = opts.useNearBlocks ?? true;
  const nbRate = opts.nearblocksPerMinute ?? 5;
  const allow = new Set(opts.allowlist ?? []);
  const allowlisted = allow.has(receiver);
  const reasons: Reason[] = [];
  const add = (code: string, severity: Severity, detail: string, source: string) => {
    reasons.push({ code, severity, detail, source });
  };
  const facts: Facts = {
    accountType: accountType(receiver), exists: null, uninitialized: false, balanceYocto: null,
    storageUsage: null, codeHash: null, globalContractHash: null, globalContractAccountId: null,
    hasContract: null, fullAccessKeys: null, functionCallKeys: null, createdAtMs: null, createdTx: null,
    createdSource: null, deletedBefore: null, txCount: null, lastActivityMs: null, lastDeployMs: null,
    lookbackBlock: null, lookbackAtMs: null, existedAtLookback: null, codeAtLookback: null,
  };
  const finish = (): Verdict => {
    if (allowlisted) for (const r of reasons) if (SOFT_CODES.has(r.code)) r.severity = "info";
    const decision: Decision = reasons.some((r) => r.severity === "block") ? "block"
      : reasons.some((r) => r.severity === "warn") ? "warn" : "allow";
    return { receiver, network, decision, reasons, facts, checkedAt: new Date().toISOString(), durationMs: Date.now() - t0 };
  };

  // 1. Local checks: no network needed.
  if (facts.accountType === "invalid") {
    add("INVALID_ACCOUNT_ID", "block", "not a valid NEAR account ID (2-64 chars of a-z 0-9 - _ separated by dots)", "local");
    return finish();
  }
  if (BURN_ADDRESSES.has(receiver)) add("BURN_ADDRESS", "block", "well-known burn address; nobody can move funds sent here", "local");
  if (receiver === opts.self?.vault || receiver === opts.self?.agent) add("SELF_PAYMENT", "warn", "receiver is the vault or the agent itself", "local");
  if (allowlisted) {
    add("ALLOWLISTED", "info", "receiver is on the owner allowlist", "policy");
  } else {
    const look = lookalikeOf(receiver, allow);
    if (look) add("LOOKALIKE", "warn", `looks like allowlisted ${look}`, "local");
    const parent = [...allow].find((g) => receiver.endsWith("." + g));
    if (parent) add("SUBACCOUNT_OF_ALLOWLISTED", "info", `only ${parent} (or its subtree) could have created it`, "local");
  }

  // 2. Shared blocklist, including ancestors: only a parent can create a subaccount.
  if (opts.blocklist) {
    try {
      const hook = opts.blocklist;
      const ids = [receiver, ...ancestors(receiver)];
      const hits = await Promise.all(ids.map(async (id) => {
        const h = await hook(id);
        return h === true ? "confirmed" : h === "confirmed" || h === "reported" ? h : null;
      }));
      if (hits[0] === "confirmed") add("BLOCKLISTED", "block", "receiver is on the shared blocklist (confirmed)", "blocklist");
      else if (hits[0] === "reported" && !allowlisted) add("REPORTED_RECEIVER", "warn", "receiver has an open report on the shared blocklist", "blocklist");
      ids.slice(1).forEach((a, i) => {
        const h = hits[i + 1];
        const why = `every account under ${a} was created from inside its subtree`;
        if (h === "confirmed") add("PARENT_REPORTED", "block", `ancestor ${a} is on the shared blocklist (confirmed); ${why}`, "blocklist");
        else if (h === "reported" && !allowlisted) add("PARENT_REPORTED", "warn", `ancestor ${a} has an open report on the shared blocklist; ${why}`, "blocklist");
      });
    } catch (e) {
      add("CHECK_UNAVAILABLE", unavailable, `blocklist lookup failed: ${msg(e)}`, "blocklist");
    }
  }

  // 3. Chain state and history, in parallel.
  const [acct, keys, first, latest, back] = await Promise.allSettled([
    viewAccount(ep.rpc, receiver, { finality: "final" }, t, fnKey),
    keyCounts(ep.rpc, receiver, t, fnKey),
    fastnearAccount(ep, receiver, { desc: false, limit: 1, is_real_receiver: true, is_success: true }, t, fnKey),
    fastnearAccount(ep, receiver, { desc: true, limit: 1 }, t, fnKey),
    (async () => {
      const b = await lookbackBlock(ep, minAgeDays, t, fnKey);
      return { b, a: await viewAccount(b.archival ? ep.archival : ep.rpc, receiver, { block_id: b.hash }, t, fnKey) };
    })(),
  ]);

  let current: any = null;
  if (acct.status === "rejected") {
    add("CHECK_UNAVAILABLE", unavailable, `view_account failed: ${msg(acct.reason)}`, "rpc");
  } else if (acct.value === null) {
    facts.exists = false;
    if (facts.accountType === "named") {
      add("ACCOUNT_DOES_NOT_EXIST", "block", "named account does not exist; a Transfer fails with AccountDoesNotExist (refunded)", "rpc");
    } else {
      add("IMPLICIT_WOULD_CREATE", "warn", `${facts.accountType} account does not exist yet; a Transfer creates it for whoever holds its key or init state`, "rpc");
    }
  } else {
    current = acct.value;
    facts.exists = true;
    facts.balanceYocto = current.amount;
    facts.storageUsage = current.storage_usage;
    facts.codeHash = current.code_hash;
    facts.globalContractHash = current.global_contract_hash ?? null;
    facts.globalContractAccountId = current.global_contract_account_id ?? null;
    facts.hasContract = contractId(current) !== null;
    facts.uninitialized = current.state === "uninitialized";
    if (facts.uninitialized) add("UNINITIALIZED_UNIVERSAL", "warn", "universal account is funded but has no state yet", "rpc");
  }

  if (keys.status === "fulfilled" && facts.exists) { // view_access_key_list answers {keys: []} (no error) for a missing account
    facts.fullAccessKeys = keys.value.full;
    facts.functionCallKeys = keys.value.fc;
  } else if (keys.status === "rejected" && facts.exists !== false) {
    // Without the key list FUNDS_UNRECOVERABLE cannot be evaluated: say so (and keep the verdict out of the cache).
    add("CHECK_UNAVAILABLE", unavailable, `view_access_key_list failed: ${msg(keys.reason)}; FUNDS_UNRECOVERABLE not checked`, "rpc");
  }
  if (first.status === "fulfilled" && first.value.txs[0]) {
    const tx = first.value.txs[0];
    facts.createdAtMs = nsToMs(tx.tx_block_timestamp);
    facts.createdTx = tx.transaction_hash;
    facts.createdSource = "fastnear-tx";
  }
  if (latest.status === "fulfilled") {
    facts.txCount = latest.value.count;
    if (latest.value.txs[0]) facts.lastActivityMs = nsToMs(latest.value.txs[0].tx_block_timestamp);
  }
  if (back.status === "fulfilled") {
    facts.lookbackBlock = back.value.b.height;
    facts.lookbackAtMs = back.value.b.timeMs;
    facts.existedAtLookback = back.value.a !== null;
    facts.codeAtLookback = back.value.a ? contractId(back.value.a) : null;
  }

  // 4. NearBlocks enrichment, only for accounts that exist, only while tokens last.
  let nbSkipped = false; // undefined = not asked (local budget, 429, error); null = NearBlocks has no such account
  if (useNB && facts.exists) {
    const nb = await nearblocksGet(ep, `/v3/accounts/${receiver}`, nbRate, t, opts.nearblocksApiKey);
    if (nb === undefined) nbSkipped = true;
    if (nb) {
      facts.deletedBefore = Boolean(nb.deleted?.transaction_hash);
      if (nb.created?.block_timestamp) {
        const created = nsToMs(nb.created.block_timestamp);
        if (facts.createdAtMs === null || created > facts.createdAtMs) { // keep the YOUNGER estimate
          facts.createdAtMs = created;
          facts.createdTx = nb.created.transaction_hash;
          facts.createdSource = "nearblocks";
        }
      }
    }
    if (facts.hasContract && !facts.globalContractHash && !facts.globalContractAccountId) {
      const deps = await nearblocksGet(ep, `/v3/accounts/${receiver}/contract/deployments`, nbRate, t, opts.nearblocksApiKey);
      if (deps === undefined) nbSkipped = true;
      if (Array.isArray(deps) && deps.length) {
        facts.lastDeployMs = Math.max(...deps.map((d: any) => nsToMs(d.block.block_timestamp)));
      }
    }
  }

  // 5. Scoring.
  if (facts.exists) {
    const now = Date.now();
    const lookAt = facts.lookbackAtMs ? new Date(facts.lookbackAtMs).toISOString() : "";

    if (facts.existedAtLookback === false) {
      add("NEW_ACCOUNT", "warn", `did not exist ${minAgeDays}d ago (archival view_account at block ${facts.lookbackBlock}, ${lookAt})`, "archival");
      if (facts.createdAtMs !== null && now - facts.createdAtMs > minAgeDays * DAY_MS) {
        add("RECREATED_ACCOUNT", "warn", `first seen ${new Date(facts.createdAtMs).toISOString()} but missing ${minAgeDays}d ago: deleted and re-created, possibly by someone else`, "archival");
      }
    } else if (facts.existedAtLookback === null) {
      if (facts.createdAtMs === null) add("AGE_UNKNOWN", "warn", "no archival or indexer answer for account age", "scout");
      else if (now - facts.createdAtMs < minAgeDays * DAY_MS) {
        add("NEW_ACCOUNT", "warn", `created ${ago(facts.createdAtMs)} ago`, facts.createdSource ?? "indexer");
      }
    }
    if (nbSkipped) add("ENRICHMENT_SKIPPED", "info", "NearBlocks not asked (rate budget, 429 or error): deletion and deploy history not checked; the archival lookback still covers the window", "nearblocks");
    if (facts.deletedBefore) add("DELETED_BEFORE", "warn", "NearBlocks has a deletion on record for this account ID", "nearblocks");
    if (facts.txCount !== null && facts.txCount < minTx) {
      add("LOW_ACTIVITY", "warn", `${facts.txCount} transactions on record (< ${minTx})`, "fastnear-tx");
    }
    if (first.status === "rejected" || latest.status === "rejected") { // do not skip silently (same idea as ENRICHMENT_SKIPPED)
      add("TX_INDEX_UNAVAILABLE", "info", "FastNear Transactions API did not answer: creation tx, creator and tx count not checked, so LOW_ACTIVITY was skipped", "fastnear-tx");
    }

    if (facts.fullAccessKeys === 0 && !facts.uninitialized) {
      if (facts.hasContract) add("LOCKED_CONTRACT", "info", "no full-access keys: only contract code can move funds", "rpc");
      else if (facts.accountType === "named" || facts.accountType === "near-implicit") {
        add("FUNDS_UNRECOVERABLE", "block", "no full-access keys and no contract: NEAR sent here can never be moved", "rpc");
      }
    }

    if (facts.hasContract) {
      const kind = facts.globalContractAccountId ? `global contract published by ${facts.globalContractAccountId}`
        : facts.globalContractHash ? "global contract (immutable, by hash)" : "contract";
      add("HAS_CONTRACT", allowlisted ? "info" : (opts.contractSeverity ?? "warn"), `receiver runs a ${kind}; a plain Transfer runs no code, but the code controls the funds afterwards`, "rpc");
      if (facts.globalContractAccountId) {
        add("UPGRADABLE_BY_THIRD_PARTY", "warn", `code can change whenever ${facts.globalContractAccountId} republishes, with no transaction on this account`, "rpc");
      }
      if (facts.lastDeployMs !== null && now - facts.lastDeployMs < deployDays * DAY_MS) {
        add("RECENT_DEPLOY", "warn", `contract deployed ${ago(facts.lastDeployMs)} ago`, "nearblocks");
      }
    }
    if (facts.existedAtLookback && current && facts.codeAtLookback !== contractId(current)) {
      add("CODE_CHANGED", "warn", `contract changed since ${lookAt}: ${facts.codeAtLookback ?? "none"} -> ${contractId(current) ?? "none"}`, "archival");
    }

    const pin = opts.pinned?.[receiver];
    if (pin?.code && pin.code !== contractId(current)) {
      add("PIN_MISMATCH", "block", `contract ${contractId(current) ?? "none"} != pinned ${pin.code}`, "policy");
    }
    if (pin?.createdTx && facts.createdTx && pin.createdTx !== facts.createdTx) {
      add("PIN_MISMATCH", "block", `creation tx ${facts.createdTx} != pinned ${pin.createdTx}: the account was re-created`, "policy");
    }

    if (!allowlisted) {
      try {
        let n: number | null = null;
        if (opts.priorPayments) n = await opts.priorPayments(receiver);
        else if (opts.self?.vault && useNB) {
          const q = `/v3/accounts/${opts.self.vault}/receipts?predecessor=${opts.self.vault}&receiver=${receiver}&limit=1`;
          const r = await nearblocksGet(ep, q, nbRate, t, opts.nearblocksApiKey);
          if (Array.isArray(r)) n = r.length;
        }
        if (n === 0) add("NEW_PAYEE", "info", "no earlier receipt from the vault to this receiver: the vault's new-payee cap applies", "history");
      } catch { /* optional signal */ }
    }
  }

  return finish();
}

// One scout per agent: options bound once, verdicts cached briefly (short TTL limits TOCTOU).
export function createScout(opts: CheckOptions = {}, ttlMs = 60_000) {
  const cache = new Map<string, { at: number; v: Verdict }>();
  return {
    async check(receiver: string): Promise<Verdict> {
      const hit = cache.get(receiver);
      if (hit && Date.now() - hit.at < ttlMs) return hit.v;
      const v = await checkCounterparty(receiver, opts);
      if (!v.reasons.some((r) => r.code === "CHECK_UNAVAILABLE")) cache.set(receiver, { at: Date.now(), v });
      return v;
    },
  };
}

// ---------- contract views (for a vault-backed blocklist) ----------

export async function viewFunction(network: Network, contract: string, method: string, args: unknown,
  o: { timeoutMs?: number; apiKey?: string; rpcUrl?: string } = {}): Promise<unknown> {
  const r = await rpc(o.rpcUrl ?? ENDPOINTS[network].rpc, "query", {
    request_type: "call_function", finality: "final", account_id: contract, method_name: method,
    args_base64: Buffer.from(JSON.stringify(args)).toString("base64"),
  }, o.timeoutMs ?? 8000, o.apiKey);
  // Contract errors come back INSIDE result (no JSON-RPC error): { result: { error: "wasm execution failed ..." } }
  if (r.error) throw new RpcFailure("CALL_FUNCTION_ERROR", String(r.error));
  const text = Buffer.from(r.result).toString("utf8");
  return text ? JSON.parse(text) : null;
}

// Spendfuse vault: get_block_entry(account_id) -> Option<BlocklistView> with status "reported" | "confirmed" (serde snake_case)
// (contract/src/lib.rs). Throws on RPC / contract errors so the scout reports CHECK_UNAVAILABLE.
export function vaultBlocklist(network: Network, vault: string,
  o: { timeoutMs?: number; apiKey?: string; rpcUrl?: string } = {}): BlocklistHook {
  return async (accountId: string): Promise<BlockStatus | null> => {
    const e = await viewFunction(network, vault, "get_block_entry", { account_id: accountId }, o) as { status?: unknown } | null;
    if (e == null) return null;
    const st = String(e.status ?? "").toLowerCase();
    if (st === "confirmed" || st === "reported") return st;
    throw new RpcFailure("BAD_VIEW_RESULT", `get_block_entry(${accountId}) returned status ${JSON.stringify(e.status)}`);
  };
}
