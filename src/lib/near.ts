// near.ts - near-api-js 7.4.0 helpers for Spendfuse on NEAR testnet.
// Node 26 ESM: runs as .ts directly (type stripping), or with tsx. Tested in test/.
import {
  JsonRpcProvider,
  KeyPair,
  KeyPairSigner,
  PublicKey,
  actions,
  getTransactionLastResult,
  keyToImplicitAddress,
} from 'near-api-js';
import type { Action, KeyPairString, Provider } from 'near-api-js';
import { isNetworkError } from './errors.ts';
import type { AccessKeyReason } from './errors.ts';

// ---------------------------------------------------------------- endpoints
/** Answered `status` with HTTP 200 on 2026-11-08 (chain_id testnet, nearcore 2.14.0-rc.5, protocol 88). Fastest first. */
export const TESTNET_RPCS = [
  'https://test.rpc.fastnear.com', // FastNEAR, ~0.4 s; free-tier limit not published
  'https://rpc.testnet.fastnear.com', // FastNEAR alias, ~0.3 s
  'https://near-testnet.drpc.org', // dRPC, ~0.8 s; free tier ~2,100 CU/s
  'https://testnet-rpc.intea.rs', // Intear, ~1.6 s; limit not published
  'https://rpc.testnet.near.org', // NEAR, ~3.8 s; docs: "severely rate limited"
] as const;
/** Needed for txs/blocks older than the GC window of regular nodes (a few epochs, i.e. days) and for historical queries. */
export const TESTNET_ARCHIVAL_RPCS = [
  'https://archival-rpc.testnet.fastnear.com',
  'https://archival-rpc.testnet.near.org',
] as const;

export interface ProviderOptions {
  /** per-endpoint ATTEMPTS made by near-api-js itself (it retries only HTTP 408/500/503). Library default 12
   *  (~2 min of backoff). Careful: the library treats 0 as "no attempt at all" and throws RetriesExceeded. */
  retries?: number;
  wait?: number;
  backoff?: number;
  headers?: Record<string, string>;
}

/**
 * A Provider over several endpoints that moves to the next endpoint ONLY on network/HTTP errors.
 * near-api-js' own FailoverRpcProvider fails over on every error, including deterministic ones
 * (AccountDoesNotExist, access-key rejections, view panics), calls console.error for each, and
 * throws FailoverRpcError at the end. This keeps the typed error and stays quiet.
 */
export function makeProvider(urls: readonly string[] = TESTNET_RPCS, opts: ProviderOptions = {}): Provider {
  const { headers, retries = 2, wait = 300, backoff = 2 } = opts;
  const list = urls.map((url) => new JsonRpcProvider({ url, headers }, { retries: Math.max(1, retries), wait, backoff }));
  const first = list[0];
  if (!first) throw new Error('makeProvider: no RPC url');
  if (list.length === 1) return first;
  let current = 0; // sticky: keep using the endpoint that answered last
  return new Proxy(first, {
    get(_target, prop) {
      const value: unknown = Reflect.get(list[current] ?? first, prop);
      if (typeof value !== 'function') return value;
      return (...args: unknown[]) => {
        const start = current;
        const attempt = (i: number): unknown => {
          const idx = (start + i) % list.length;
          const p = list[idx] as unknown as Record<PropertyKey, (...a: unknown[]) => unknown>;
          const out = p[prop]!(...args);
          if (!(out instanceof Promise)) return out;
          return out.then(
            (v) => {
              current = idx;
              return v;
            },
            (err) => {
              if (i + 1 < list.length && isNetworkError(err)) return attempt(i + 1);
              throw err;
            },
          );
        };
        return attempt(0);
      };
    },
  });
}

// ---------------------------------------------------------------- keys
export interface NewKey {
  keyPair: KeyPair;
  /** "ed25519:<base58 64-byte secret>" - store it like a password, never log it */
  secretKey: KeyPairString;
  /** "ed25519:<base58 32-byte key>" */
  publicKey: string;
}
export function newKey(): NewKey {
  const keyPair = KeyPair.fromRandom('ed25519');
  return { keyPair, secretKey: keyPair.toString(), publicKey: keyPair.getPublicKey().toString() };
}
export const signerFromSecret = (secretKey: KeyPairString): KeyPairSigner => KeyPairSigner.fromSecretKey(secretKey);
/** 64 lowercase hex chars; the account exists once someone transfers NEAR to it. */
export const implicitAccountId = (publicKey: string | PublicKey): string => keyToImplicitAddress(publicKey);

// ---------------------------------------------------------------- views
/** View call. NB: the provider takes `method`, Account.callFunction takes `methodName`. */
export async function view<T>(provider: Provider, contractId: string, method: string, args: Record<string, unknown> = {}): Promise<T> {
  return (await provider.callFunction({ contractId, method, args })) as T;
}

// ---------------------------------------------------------------- explorer
export const EXPLORER = 'https://testnet.nearblocks.io';
export const explorer = {
  tx: (hash: string): string => `${EXPLORER}/txns/${hash}`,
  account: (accountId: string): string => `${EXPLORER}/address/${accountId}`,
  block: (heightOrHash: string | number): string => `${EXPLORER}/blocks/${heightOrHash}`,
  receipt: (receiptId: string): string => `${EXPLORER}/hash/${receiptId}`,
};

// ---------------------------------------------------------------- tx results
export type TxResult = Awaited<ReturnType<Provider['viewTransactionStatus']>>;

export interface TxSummary {
  hash: string;
  url: string;
  /** false when the tx failed; also false while pending */
  ok: boolean;
  /** status not final yet (waitUntil NONE/INCLUDED, or status NotStarted/Started) */
  pending: boolean;
  /** decoded return value of the last receipt (JSON-parsed when it is JSON) */
  value: unknown;
  /** panic message without the "Smart contract panicked: " prefix, or the Failure JSON */
  error: string | null;
  failure: unknown;
  logs: string[];
  /** NEP-297 events: logs that start with EVENT_JSON: */
  events: unknown[];
  gasBurnt: bigint;
  tokensBurnt: bigint;
  /** receipts that failed even when the tx as a whole succeeded (e.g. a cross-contract call the callback swallowed) */
  receiptFailures: { receiptId: string; executor: string; failure: unknown }[];
}

const PANIC = 'Smart contract panicked: ';
type LooseOutcome = { id: string; outcome: { logs: string[]; gas_burnt: number | string; tokens_burnt: string; executor_id: string; status: unknown } };
const failureOf = (status: unknown): unknown =>
  status && typeof status === 'object' && 'Failure' in status ? (status as { Failure: unknown }).Failure : null;

export function summarize(hash: string, res: TxResult): TxSummary {
  const r = res as unknown as { status?: unknown; transaction_outcome?: LooseOutcome; receipts_outcome?: LooseOutcome[] };
  const status = r.status;
  const failure = failureOf(status);
  const pending = !status || typeof status === 'string';
  const receipts = r.receipts_outcome ?? [];
  const outcomes = [r.transaction_outcome, ...receipts].filter((o): o is LooseOutcome => !!o);
  const logs = outcomes.flatMap((o) => o.outcome.logs);
  const events = logs
    .filter((l) => l.startsWith('EVENT_JSON:'))
    .flatMap((l) => {
      try {
        return [JSON.parse(l.slice('EVENT_JSON:'.length)) as unknown];
      } catch {
        return [];
      }
    });
  const raw = (failure as { ActionError?: { kind?: { FunctionCallError?: { ExecutionError?: unknown } } } } | null)?.ActionError?.kind
    ?.FunctionCallError?.ExecutionError;
  let value: unknown = null;
  if (!failure && !pending) {
    try {
      value = getTransactionLastResult(res);
    } catch {
      value = null;
    }
  }
  return {
    hash,
    url: explorer.tx(hash),
    ok: !failure && !pending,
    pending,
    value,
    error: failure ? (typeof raw === 'string' ? raw.replace(PANIC, '') : JSON.stringify(failure)) : null,
    failure,
    logs,
    events,
    gasBurnt: outcomes.reduce((s, o) => s + BigInt(o.outcome.gas_burnt), 0n),
    tokensBurnt: outcomes.reduce((s, o) => s + BigInt(o.outcome.tokens_burnt), 0n),
    receiptFailures: receipts
      .filter((o) => failureOf(o.outcome.status))
      .map((o) => ({ receiptId: o.id, executor: o.outcome.executor_id, failure: failureOf(o.outcome.status) })),
  };
}

// ---------------------------------------------------------------- function-call keys
/**
 * AddKey action for the agent's key. `allowance: null` = unlimited (Option<u128>::None).
 * Prefer this over account.addFunctionCallAccessKey(), which always sets an allowance (default 0.25 NEAR)
 * and cannot create an unlimited key. Send it from the OWNER account (full-access key):
 *   owner.signAndSendTransaction({ receiverId: owner.accountId, actions: [addAgentKeyAction(...)] })
 */
export function addAgentKeyAction(publicKey: string | PublicKey, vaultId: string, methodNames: string[], allowance: bigint | null): Action {
  const pk = typeof publicKey === 'string' ? PublicKey.fromString(publicKey) : publicKey;
  return actions.addFunctionCallAccessKey(pk, vaultId, methodNames, allowance ?? undefined);
}

export interface KeyInfo {
  publicKey: string;
  nonce: bigint;
  fullAccess: boolean;
  receiverId?: string;
  /** empty = any method of receiverId */
  methodNames?: string[];
  /** remaining allowance in yoctoNEAR; null = unlimited */
  allowance?: bigint | null;
}
type RawPermission = 'FullAccess' | { FunctionCall: { allowance?: string | null; receiver_id: string; method_names: string[] } };

export async function listKeys(provider: Provider, accountId: string): Promise<KeyInfo[]> {
  const list = (await provider.viewAccessKeyList({ accountId })) as unknown as {
    keys: { public_key: string; access_key: { nonce: number | string | bigint; permission: RawPermission } }[];
  };
  return list.keys.map(({ public_key, access_key }) => {
    const base = { publicKey: public_key, nonce: BigInt(access_key.nonce) };
    const perm = access_key.permission;
    if (perm === 'FullAccess') return { ...base, fullAccess: true };
    const fc = perm.FunctionCall;
    return {
      ...base,
      fullAccess: false,
      receiverId: fc.receiver_id,
      methodNames: fc.method_names,
      allowance: fc.allowance == null ? null : BigInt(fc.allowance),
    };
  });
}

/** Client-side mirror of the protocol checks, to refuse locally before signing. The chain enforces them anyway. */
export function keyAllows(key: KeyInfo, call: { receiverId: string; methodName: string; deposit?: bigint }): AccessKeyReason | null {
  if (key.fullAccess) return null;
  if ((call.deposit ?? 0n) > 0n) return 'DepositWithFunctionCall';
  if (call.receiverId !== key.receiverId) return 'ReceiverMismatch';
  if (key.methodNames?.length && !key.methodNames.includes(call.methodName)) return 'MethodNameMismatch';
  return null;
}

// ---------------------------------------------------------------- faucet (documented, never called here)
/** near-cli-rs testnet config (config_mod.rs) and near/near-contract-helper app.js `router.post('/account', ...)`. */
export const FAUCET_URL = 'https://helper.nearprotocol.com/account';
const ACCOUNT_ID_RE = /^(([a-z\d]+[-_])*[a-z\d]+\.)*([a-z\d]+[-_])*[a-z\d]+$/;

/** NEAR account id rules (nearcore near-account-id): 2..64 chars, a-z 0-9, separators - _ . between alphanumerics. */
export function validateAccountId(id: string): string | null {
  if (id.length < 2 || id.length > 64) return 'length must be 2..64';
  if (!ACCOUNT_ID_RE.test(id)) return 'only a-z 0-9 with single - _ . separators between them';
  return null;
}

/** What the helper can create: a direct sub-account of `testnet` whose id does not start with "temp-". */
export function validateFaucetName(id: string): string | null {
  const base = validateAccountId(id);
  if (base) return base;
  if (!id.endsWith('.testnet') || id.slice(0, -'.testnet'.length).includes('.')) {
    return 'the faucet signs as `testnet`, so it can only create <label>.testnet';
  }
  if (id.startsWith('temp-')) return 'helper answers 403 "Please, do not drain testnet faucet." for ids starting with temp-';
  return null;
}

/**
 * Builds (does NOT send) the faucet request. Send it yourself, at most 10 per IP per 12 h:
 *   const { url, init } = faucetRequest('spendfuse-demo.testnet', publicKey);
 *   const res = await fetch(url, init);   // >= 400: error text; else JSON final execution outcome
 */
export function faucetRequest(newAccountId: string, newAccountPublicKey: string): { url: string; init: RequestInit } {
  const problem = validateFaucetName(newAccountId);
  if (problem) throw new Error(`${newAccountId}: ${problem}`);
  PublicKey.fromString(newAccountPublicKey); // throws on a malformed key (the helper would answer 400)
  return {
    url: FAUCET_URL,
    init: {
      method: 'POST',
      headers: { 'content-type': 'application/json' },
      body: JSON.stringify({ newAccountId, newAccountPublicKey }),
    },
  };
}
