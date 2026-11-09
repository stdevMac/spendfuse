// errors.ts - classify anything near-api-js 7.4.0 throws, so the Spendfuse agent loop and the
// dashboard can react to it. No dedicated test file: it is exercised through decodeContractError
// (src/lib/spendfuse.ts) in test/client.test.ts ("decodeContractError handles panics ...").
//
// Facts this relies on (near-api-js 7.4.0, node_modules/near-api-js/lib/index.js):
// - every typed RPC error sets `name = this.constructor.name` (rpc-errors/index.js:5)
// - the main bundle imports its error classes from "near-api-js/rpc-errors" (index.js:873),
//   so `instanceof` against classes imported from 'near-api-js/rpc-errors' works
// - HTTP 408/429/500/502/503 become a ProviderError whose `.cause` is the status number
//   (fetchJsonRpc, index.js ~3069); only 408/500/503 are retried by the library
// - an RPC-side rejection of the tx (INVALID_TRANSACTION) is parsed with txHash "" (index.js:955)
import { FailoverRpcError } from 'near-api-js';

export type AccessKeyReason =
  | 'ReceiverMismatch'
  | 'MethodNameMismatch'
  | 'NotEnoughAllowance'
  | 'DepositWithFunctionCall'
  | 'RequiresFullAccess'
  | 'AccessKeyNotFound';

export type ErrorKind =
  | 'contract-panic' // the contract panicked inside a transaction: the tx is on chain, gas was burnt
  | 'view-panic' // the contract panicked inside a view call
  | 'access-key' // the access key does not allow this tx: rejected by the RPC, nothing on chain
  | 'tx-failed' // other on-chain failure (txHash set)
  | 'tx-rejected' // other rejection before inclusion (nonce, balance, expired ...), nothing on chain
  | 'transient' // network, HTTP 408/429/5xx, tx timeout: poll by hash or resend the SAME signed tx
  | 'rpc'; // anything else, e.g. AccountDoesNotExistError, ContractMethodNotFoundError

export interface Explained {
  kind: ErrorKind;
  /** error class name, e.g. AccessKeyMethodNameMismatchActionError */
  name: string;
  /** human text; for panics this is the bare panic message the contract passed to env::panic_str */
  message: string;
  txHash: string | null;
  reason?: AccessKeyReason;
  details?: Record<string, string>;
  /** HTTP status, when the error came from the transport (ProviderError.cause) */
  status?: number;
}

type Loose = Record<string, unknown> & {
  name?: unknown;
  message?: unknown;
  cause?: unknown;
  type?: unknown;
  txHash?: unknown;
  errors?: unknown;
  panicMessage?: unknown;
  transactionResult?: { transaction_outcome?: { id?: string } };
};

const PANIC = 'Smart contract panicked: ';

const ACCESS_KEY: Record<string, AccessKeyReason> = {
  AccessKeyReceiverMismatchActionError: 'ReceiverMismatch',
  AccessKeyMethodNameMismatchActionError: 'MethodNameMismatch',
  AccessKeyNotEnoughAllowanceActionError: 'NotEnoughAllowance',
  AccessKeyDepositWithFunctionCallActionError: 'DepositWithFunctionCall',
  AccessKeyRequiresFullAccessActionError: 'RequiresFullAccess',
  AccessKeyNotFoundActionError: 'AccessKeyNotFound',
};
const DETAIL_FIELDS = ['akReceiver', 'txReceiver', 'methodName', 'accountId', 'publicKey', 'allowance', 'cost'];

/** FailoverRpcProvider throws FailoverRpcError{errors[]} after trying every provider: return the last real error. */
export function unwrap(err: unknown): unknown {
  const e = err as Loose | null;
  if ((err instanceof FailoverRpcError || e?.name === 'FailoverRpcError') && Array.isArray(e?.errors) && e.errors.length) {
    return e.errors.at(-1);
  }
  return err;
}

const HTTP_TRANSIENT = new Set([408, 429, 500, 502, 503, 504]);

/** The endpoint, not the request, is the problem: another endpoint may answer. */
export function isNetworkError(err: unknown): boolean {
  const e = unwrap(err) as Loose | null;
  if (!e || typeof e !== 'object') return false;
  if (e.name === 'TypeError' && /fetch failed|network/i.test(String(e.message))) return true; // undici: DNS, refused, reset
  if (typeof e.cause === 'number' && HTTP_TRANSIENT.has(e.cause)) return true; // ProviderError from fetchJsonRpc
  if (e.type === 'RetriesExceeded') return true; // TypedError after the library's own retries
  // AbortSignal.timeout, an HTML error page instead of JSON, nearcore INTERNAL_ERROR
  return e.name === 'AbortError' || e.name === 'TimeoutError' || e.name === 'SyntaxError' || e.name === 'InternalRpcError';
}

/** Safe to poll the tx by hash (or resend the same signed bytes); never a reason to re-sign. */
export function isTransient(err: unknown): boolean {
  const e = unwrap(err) as Loose | null;
  return e?.name === 'TransactionTimeoutError' || isNetworkError(e);
}

export function explain(err: unknown): Explained {
  const e = (unwrap(err) ?? {}) as Loose;
  const name = typeof e.name === 'string' ? e.name : 'Error';
  const message = String(e.message ?? e);
  const resultHash = e.transactionResult?.transaction_outcome?.id ?? null;
  const txHash = (typeof e.txHash === 'string' && e.txHash) || resultHash || null;

  const reason = ACCESS_KEY[name];
  if (reason) {
    const details: Record<string, string> = {};
    for (const f of DETAIL_FIELDS) if (e[f] != null) details[f] = String(e[f]);
    return { kind: 'access-key', name, message, txHash, reason, details };
  }
  if (name === 'ContractExecutionError') {
    // FunctionCallError::ExecutionError(String) inside a tx: "Smart contract panicked: <msg>",
    // "Exceeded the prepaid gas.", ... The tx hash comes from the attached result (index.js:1245).
    if (message.startsWith(PANIC)) return { kind: 'contract-panic', name, message: message.slice(PANIC.length), txHash };
    return { kind: txHash ? 'tx-failed' : 'rpc', name, message, txHash };
  }
  if (name === 'HostGuestPanicError' && typeof e.panicMessage === 'string') {
    return { kind: txHash ? 'contract-panic' : 'view-panic', name, message: e.panicMessage, txHash };
  }
  // A view call that panics is NOT typed: RpcError("wasm execution failed with error: HostError(GuestPanic { panic_msg: \"...\" })")
  const m = message.match(/panic_msg: "((?:[^"\\]|\\.)*)"/);
  if (m) {
    let text = m[1] ?? '';
    try {
      text = JSON.parse(`"${text}"`);
    } catch {
      /* keep the raw text */
    }
    return { kind: 'view-panic', name, message: text, txHash: null };
  }
  if ('txHash' in e && 'blockHash' in e) return { kind: txHash ? 'tx-failed' : 'tx-rejected', name, message, txHash };
  if (isTransient(e)) {
    return { kind: 'transient', name, message, txHash: null, status: typeof e.cause === 'number' ? e.cause : undefined };
  }
  return { kind: 'rpc', name, message, txHash: null };
}
