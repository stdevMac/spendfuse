// spendfuse.ts - typed client for the Spendfuse vault contract (contract/src/lib.rs is the source of truth).
// Views go through the provider; change calls go through makeSender (signs once, hash before broadcast,
// never re-signs after a timeout) and return { summary, events, result }.
import { Account, teraToGas } from 'near-api-js';
import type { Provider, Signer } from 'near-api-js';
import { explain } from './errors.ts';
import type { ErrorKind } from './errors.ts';
import { makeSender } from './send.ts';
import type { SenderOptions } from './send.ts';
import { view } from './near.ts';
import type { TxSummary } from './near.ts';
import type {
  AccountId,
  AgentView,
  BlocklistView,
  CheckResult,
  ConfigView,
  EventName,
  LogEntry,
  PayeeStat,
  PaymentResult,
  PendingPayment,
  Policy,
  PolicyInput,
  Stats,
  SpendfuseEvent,
  U128,
  U64,
} from './types.ts';
import { EVENT_NAMES } from './types.ts';

// ---------------------------------------------------------------- constants
export const ONE_YOCTO = 1n;
export const NEAR = 10n ** 24n;
/** The only methods the agent's function-call key may call. */
export const AGENT_METHODS = ['request_payment', 'self_freeze', 'report_receiver'] as const;
export type AgentMethod = (typeof AGENT_METHODS)[number];

/** Prepaid gas per method. request_payment / approve schedule a transfer plus a 20 TGas callback. */
export const GAS = {
  request_payment: teraToGas('50'),
  approve: teraToGas('50'),
  withdraw: teraToGas('30'),
  remove_agent: teraToGas('50'),
  freeze: teraToGas('50'), // freeze_agent / self_freeze cancel up to 5 pending requests
  add_canaries: teraToGas('50'),
  init: teraToGas('30'),
  default: teraToGas('30'),
} as const;

// ---------------------------------------------------------------- helpers
const isPlainObject = (v: unknown): v is Record<string, unknown> => {
  if (v === null || typeof v !== 'object' || Array.isArray(v)) return false;
  const proto = Object.getPrototypeOf(v);
  return proto === Object.prototype || proto === null;
};

/**
 * Prepare call args: drop undefined keys (deeply, in plain objects) so absent Options are omitted,
 * and turn bigint into a decimal string (U128 / U64 on the wire). Arrays keep their length.
 */
export function stripUndefined<T>(value: T): T {
  const walk = (v: unknown): unknown => {
    if (typeof v === 'bigint') return v.toString();
    if (Array.isArray(v)) return v.map(walk);
    if (isPlainObject(v)) {
      const out: Record<string, unknown> = {};
      for (const [k, x] of Object.entries(v)) if (x !== undefined) out[k] = walk(x);
      return out;
    }
    return v;
  };
  return walk(value) as T;
}

const EVENT_SET: ReadonlySet<string> = new Set(EVENT_NAMES);
const EVENT_PREFIX = 'EVENT_JSON:';

/** Spendfuse NEP-297 events in log order. Other standards, unknown event names and bad JSON are skipped. */
export function parseEvents(logs: readonly string[]): SpendfuseEvent[] {
  const out: SpendfuseEvent[] = [];
  for (const line of logs) {
    if (!line.startsWith(EVENT_PREFIX)) continue;
    let ev: unknown;
    try {
      ev = JSON.parse(line.slice(EVENT_PREFIX.length));
    } catch {
      continue;
    }
    if (!isPlainObject(ev) || ev.standard !== 'tripwire') continue;
    if (typeof ev.event !== 'string' || !EVENT_SET.has(ev.event) || !Array.isArray(ev.data)) continue;
    out.push({ standard: 'tripwire', version: String(ev.version ?? ''), event: ev.event as EventName, data: ev.data as SpendfuseEvent['data'] });
  }
  return out;
}

/** Validate a U128 / U64 value and return it as a decimal string. */
export function toU128(v: bigint | string | number, name = 'amount'): U128 {
  const s = typeof v === 'bigint' ? v.toString() : typeof v === 'number' && Number.isSafeInteger(v) ? String(v) : v;
  if (typeof s !== 'string' || !/^(0|[1-9]\d*)$/.test(s)) throw new RangeError(`${name} must be a non-negative integer (yocto), got ${String(v)}`);
  if (BigInt(s) >= 1n << 128n) throw new RangeError(`${name} does not fit in u128`);
  return s;
}
export const toU64 = (v: bigint | string | number, name = 'value'): U64 => {
  const s = toU128(v, name);
  if (BigInt(s) >= 1n << 64n) throw new RangeError(`${name} does not fit in u64`);
  return s;
};

/** yoctoNEAR -> "1.2345" (truncated to `digits`, trailing zeros removed). */
export function formatNear(yocto: bigint | string, digits = 4): string {
  const y = BigInt(yocto);
  const neg = y < 0n;
  const abs = neg ? -y : y;
  const whole = abs / NEAR;
  const frac = (abs % NEAR).toString().padStart(24, '0').slice(0, digits).replace(/0+$/, '');
  return `${neg ? '-' : ''}${whole}${frac ? `.${frac}` : ''}`;
}

/** Policy amounts may be given as bigint yocto; the result has only the contract's keys. */
export type PolicyLike = Omit<PolicyInput, 'max_per_payment' | 'daily_limit' | 'approval_threshold' | 'new_payee_limit' | 'expires_at_ms'> & {
  max_per_payment: bigint | U128;
  daily_limit: bigint | U128;
  approval_threshold: bigint | U128;
  new_payee_limit: bigint | U128;
  expires_at_ms?: bigint | U64 | number | null;
};

export function toPolicyInput(p: PolicyLike | Policy): PolicyInput {
  const out: PolicyInput = {
    max_per_payment: toU128(p.max_per_payment, 'max_per_payment'),
    daily_limit: toU128(p.daily_limit, 'daily_limit'),
    approval_threshold: toU128(p.approval_threshold, 'approval_threshold'),
    new_payee_limit: toU128(p.new_payee_limit, 'new_payee_limit'),
    max_payments_per_hour: p.max_payments_per_hour,
    allowlist_only: p.allowlist_only,
    allowlist: p.allowlist ? [...p.allowlist] : undefined,
    auto_freeze_after_blocks: p.auto_freeze_after_blocks,
    expires_at_ms: p.expires_at_ms == null ? undefined : toU64(p.expires_at_ms, 'expires_at_ms'),
  };
  return stripUndefined(out);
}

// ---------------------------------------------------------------- call results
export interface CallResult<T> {
  summary: TxSummary;
  events: SpendfuseEvent[];
  /** decoded return value; null when the tx failed, is still pending, or the method returns nothing */
  result: T | null;
  ok: boolean;
  /** contract panic message (or failure JSON) when !ok */
  error: string | null;
}

export function toCallResult<T>(summary: TxSummary): CallResult<T> {
  const value = summary.ok && summary.value !== '' ? summary.value : null;
  return { summary, events: parseEvents(summary.logs), result: (value ?? null) as T | null, ok: summary.ok, error: summary.error };
}

export interface DecodedError {
  kind: ErrorKind | 'tx-failure';
  /** the bare contract panic message when there is one, else a human message */
  message: string;
  txHash: string | null;
  name: string;
  /** true when the message came from the contract (panic in a tx or a view) */
  contract: boolean;
}

const PANIC = 'Smart contract panicked: ';
const PANIC_MSG = /panic_msg: "((?:[^"\\]|\\.)*)"/;

function panicFromText(text: string): string | null {
  if (text.startsWith(PANIC)) return text.slice(PANIC.length);
  const m = text.match(PANIC_MSG);
  if (!m) return null;
  try {
    return JSON.parse(`"${m[1] ?? ''}"`) as string;
  } catch {
    return m[1] ?? '';
  }
}

/**
 * Pull the contract's panic message out of anything: a thrown near-api-js error, a view RpcError,
 * a failed TxSummary / CallResult, or a raw string.
 */
export function decodeContractError(err: unknown): DecodedError {
  if (typeof err === 'string') {
    const p = panicFromText(err);
    return { kind: p === null ? 'rpc' : 'contract-panic', message: p ?? err, txHash: null, name: 'string', contract: p !== null };
  }
  if (isPlainObject(err) && 'summary' in err && isPlainObject(err.summary)) return decodeContractError(err.summary);
  if (isPlainObject(err) && typeof err.hash === 'string' && 'ok' in err && 'logs' in err) {
    const s = err as unknown as TxSummary;
    if (s.ok) return { kind: 'tx-failure', message: 'transaction succeeded', txHash: s.hash, name: 'TxSummary', contract: false };
    if (s.pending) return { kind: 'transient', message: 'transaction is not final yet', txHash: s.hash, name: 'TxSummary', contract: false };
    const exec = (s.failure as { ActionError?: { kind?: { FunctionCallError?: { ExecutionError?: unknown } } } } | null)?.ActionError?.kind
      ?.FunctionCallError?.ExecutionError;
    const isPanic = typeof exec === 'string' && exec.startsWith(PANIC);
    return { kind: isPanic ? 'contract-panic' : 'tx-failure', message: s.error ?? 'transaction failed', txHash: s.hash, name: 'TxSummary', contract: isPanic };
  }
  const e = explain(err);
  const contract = e.kind === 'contract-panic' || e.kind === 'view-panic';
  return { kind: e.kind, message: e.message, txHash: e.txHash, name: e.name, contract };
}

// ---------------------------------------------------------------- views
export interface ClientOptions {
  provider: Provider;
  vaultId: string;
}

export class SpendfuseClient {
  readonly provider: Provider;
  readonly vaultId: string;

  constructor({ provider, vaultId }: ClientOptions) {
    this.provider = provider;
    this.vaultId = vaultId;
  }

  /** Any view; undefined args are stripped. */
  view<T>(method: string, args: Record<string, unknown> = {}): Promise<T> {
    return view<T>(this.provider, this.vaultId, method, stripUndefined(args));
  }

  getConfig(): Promise<ConfigView> {
    return this.view('get_config');
  }
  getStats(): Promise<Stats> {
    return this.view('get_stats');
  }
  getAgent(agentId: AccountId): Promise<AgentView | null> {
    return this.view('get_agent', { agent_id: agentId });
  }
  /** limit defaults to 50 (max 50) */
  listAgents(fromIndex?: number, limit?: number): Promise<AgentView[]> {
    return this.view('list_agents', { from_index: fromIndex, limit });
  }
  /** Dry run of request_payment. Canaries look like ordinary receivers here. */
  checkPayment(agentId: AccountId, receiverId: AccountId, amount: bigint | U128): Promise<CheckResult> {
    return this.view('check_payment', { agent_id: agentId, receiver_id: receiverId, amount: toU128(amount) });
  }
  /** limit defaults to 50 (max 100) */
  getPending(fromIndex?: number, limit?: number): Promise<PendingPayment[]> {
    return this.view('get_pending', { from_index: fromIndex, limit });
  }
  getPendingRequest(requestId: bigint | U64): Promise<PendingPayment | null> {
    return this.view('get_pending_request', { request_id: toU64(requestId, 'request_id') });
  }
  /** Newest first; pass the last seq seen as beforeSeq to page back. limit defaults to 50 (max 100). */
  getActivity(beforeSeq?: bigint | U64, limit?: number): Promise<LogEntry[]> {
    return this.view('get_activity', { before_seq: beforeSeq === undefined ? undefined : toU64(beforeSeq, 'before_seq'), limit });
  }
  /** limit defaults to 50 (max 100) */
  getBlocklist(fromIndex?: number, limit?: number): Promise<BlocklistView[]> {
    return this.view('get_blocklist', { from_index: fromIndex, limit });
  }
  getBlockEntry(accountId: AccountId): Promise<BlocklistView | null> {
    return this.view('get_block_entry', { account_id: accountId });
  }
  getPayee(agentId: AccountId, receiverId: AccountId): Promise<PayeeStat | null> {
    return this.view('get_payee', { agent_id: agentId, receiver_id: receiverId });
  }

  async listAllAgents(): Promise<AgentView[]> {
    const out: AgentView[] = [];
    for (;;) {
      const page = await this.listAgents(out.length, 50);
      out.push(...page);
      if (page.length < 50) return out;
    }
  }
  async getAllPending(): Promise<PendingPayment[]> {
    const out: PendingPayment[] = [];
    for (;;) {
      const page = await this.getPending(out.length, 100);
      out.push(...page);
      if (page.length < 100) return out;
    }
  }
}

export const createSpendfuseClient = (opts: ClientOptions): SpendfuseClient => new SpendfuseClient(opts);

// ---------------------------------------------------------------- signers
export interface SignerContext {
  accountId: string;
  provider: Provider;
  signer: Signer;
}
/** An Account with a signer, or the parts of one. */
export type Who = Account | SignerContext;

export interface ApiOptions {
  vaultId: string;
  senderOptions?: SenderOptions;
  /** called with each tx hash before it is broadcast (persist it for the incident log) */
  onHash?: (hash: string, methodName: string) => unknown;
}

export interface CallOptions {
  gas?: bigint;
  onHash?: (hash: string) => unknown;
}

function contextOf(who: Who): SignerContext {
  if (who instanceof Account) {
    const signer = who.getSigner();
    if (!signer) throw new Error(`Account ${who.accountId} has no signer`);
    return { accountId: who.accountId, provider: who.provider, signer };
  }
  return who;
}

class Caller {
  readonly accountId: string;
  readonly vaultId: string;
  readonly #send: ReturnType<typeof makeSender>;
  readonly #onHash: ApiOptions['onHash'];

  constructor(who: Who, opts: ApiOptions) {
    const ctx = contextOf(who);
    this.accountId = ctx.accountId;
    this.vaultId = opts.vaultId;
    this.#send = makeSender(ctx.accountId, ctx.provider, ctx.signer, opts.senderOptions);
    this.#onHash = opts.onHash;
  }

  /** Low-level: one function call on the vault. undefined args are stripped. */
  async call<T>(methodName: string, args: Record<string, unknown>, gas: bigint, deposit: bigint, opts: CallOptions = {}): Promise<CallResult<T>> {
    const summary = await this.#send({
      receiverId: this.vaultId,
      methodName,
      args: stripUndefined(args),
      gas: opts.gas ?? gas,
      deposit,
      onHash: async (hash) => {
        await this.#onHash?.(hash, methodName);
        await opts.onHash?.(hash);
      },
    });
    return toCallResult<T>(summary);
  }
}

// ---------------------------------------------------------------- agent (function-call key, deposit 0)
export interface PaymentRequest {
  receiver_id: AccountId;
  /** yoctoNEAR; parse LLM output with parseNearStrict first */
  amount: bigint | U128;
  memo?: string;
}

export class AgentApi extends Caller {
  /** result is the final PaymentResult (from the settlement callback when a transfer was sent). */
  requestPayment(req: PaymentRequest, opts?: CallOptions): Promise<CallResult<PaymentResult>> {
    const args = { receiver_id: req.receiver_id, amount: toU128(req.amount), memo: req.memo };
    return this.call('request_payment', args, GAS.request_payment, 0n, opts);
  }
  /** false when already frozen */
  selfFreeze(reason?: string, opts?: CallOptions): Promise<CallResult<boolean>> {
    return this.call('self_freeze', { reason }, GAS.freeze, 0n, opts);
  }
  /** Free for an active agent (20 reports); the FC key cannot attach the 0.01 NEAR deposit. */
  reportReceiver(receiverId: AccountId, reason: string, evidence?: string, opts?: CallOptions): Promise<CallResult<BlocklistView>> {
    return this.call('report_receiver', { receiver_id: receiverId, reason, evidence }, GAS.default, 0n, opts);
  }
}

// ---------------------------------------------------------------- guardian (free calls, can only tighten)
export class GuardianApi extends Caller {
  /** false when already frozen; rejects the agent's pending requests */
  freezeAgent(agentId: AccountId, reason?: string, opts?: CallOptions): Promise<CallResult<boolean>> {
    return this.call('freeze_agent', { agent_id: agentId, reason }, GAS.freeze, 0n, opts);
  }
  /** false when already paused */
  pause(reason?: string, opts?: CallOptions): Promise<CallResult<boolean>> {
    return this.call('pause', { reason }, GAS.default, 0n, opts);
  }
  reject(requestId: bigint | U64, reason?: string, opts?: CallOptions): Promise<CallResult<PendingPayment>> {
    return this.call('reject', { request_id: toU64(requestId, 'request_id'), reason }, GAS.default, 0n, opts);
  }
  blockReceiver(receiverId: AccountId, reason: string, evidence?: string, opts?: CallOptions): Promise<CallResult<BlocklistView>> {
    return this.call('block_receiver', { receiver_id: receiverId, reason, evidence }, GAS.default, 0n, opts);
  }
  /** hex sha256 hashes (canaryHash); at most 50 per call. Returns how many were new. */
  addCanaries(hashes: string[], opts?: CallOptions): Promise<CallResult<number>> {
    if (hashes.length > 50) throw new RangeError('At most 50 canaries per call');
    return this.call('add_canaries', { hashes }, GAS.add_canaries, 0n, opts);
  }
  /** Free for the owner and guardians. */
  reportReceiver(receiverId: AccountId, reason: string, evidence?: string, opts?: CallOptions): Promise<CallResult<BlocklistView>> {
    return this.call('report_receiver', { receiver_id: receiverId, reason, evidence }, GAS.default, 0n, opts);
  }
  /** Anyone. limit defaults to 10 (max 20). Returns how many expired. */
  expireStale(limit?: number, opts?: CallOptions): Promise<CallResult<number>> {
    return this.call('expire_stale', { limit }, GAS.default, 0n, opts);
  }
}

// ---------------------------------------------------------------- owner (full-access key, 1 yocto on owner-only methods)
export class OwnerApi extends GuardianApi {
  registerAgent(agentId: AccountId, label: string, policy: PolicyLike | Policy, opts?: CallOptions): Promise<CallResult<AgentView>> {
    return this.call('register_agent', { agent_id: agentId, label, policy: toPolicyInput(policy) }, GAS.default, ONE_YOCTO, opts);
  }
  updatePolicy(agentId: AccountId, policy: PolicyLike | Policy, opts?: CallOptions): Promise<CallResult<AgentView>> {
    return this.call('update_policy', { agent_id: agentId, policy: toPolicyInput(policy) }, GAS.default, ONE_YOCTO, opts);
  }
  /** Returns how many pending requests were rejected. */
  removeAgent(agentId: AccountId, opts?: CallOptions): Promise<CallResult<number>> {
    return this.call('remove_agent', { agent_id: agentId }, GAS.remove_agent, ONE_YOCTO, opts);
  }
  unfreezeAgent(agentId: AccountId, opts?: CallOptions): Promise<CallResult<AgentView>> {
    return this.call('unfreeze_agent', { agent_id: agentId }, GAS.default, ONE_YOCTO, opts);
  }
  unpause(opts?: CallOptions): Promise<CallResult<null>> {
    return this.call('unpause', {}, GAS.default, ONE_YOCTO, opts);
  }
  /** false when the receiver was not listed */
  unblockReceiver(receiverId: AccountId, opts?: CallOptions): Promise<CallResult<boolean>> {
    return this.call('unblock_receiver', { receiver_id: receiverId }, GAS.default, ONE_YOCTO, opts);
  }
  removeCanary(hash: string, opts?: CallOptions): Promise<CallResult<boolean>> {
    return this.call('remove_canary', { hash }, GAS.default, ONE_YOCTO, opts);
  }
  /** result: PaymentResult from the settlement callback ('paid' / 'transfer_failed'), or 'expired'. */
  approve(requestId: bigint | U64, opts?: CallOptions): Promise<CallResult<PaymentResult>> {
    return this.call('approve', { request_id: toU64(requestId, 'request_id') }, GAS.approve, ONE_YOCTO, opts);
  }
  /** Sends unreserved funds to the owner. */
  withdraw(amount: bigint | U128, opts?: CallOptions): Promise<CallResult<null>> {
    return this.call('withdraw', { amount: toU128(amount) }, GAS.withdraw, ONE_YOCTO, opts);
  }
  addGuardian(accountId: AccountId, opts?: CallOptions): Promise<CallResult<AccountId[]>> {
    return this.call('add_guardian', { account_id: accountId }, GAS.default, ONE_YOCTO, opts);
  }
  removeGuardian(accountId: AccountId, opts?: CallOptions): Promise<CallResult<AccountId[]>> {
    return this.call('remove_guardian', { account_id: accountId }, GAS.default, ONE_YOCTO, opts);
  }
  /** Proposing the current owner cancels a pending proposal. */
  proposeOwner(newOwnerId: AccountId, opts?: CallOptions): Promise<CallResult<null>> {
    return this.call('propose_owner', { new_owner_id: newOwnerId }, GAS.default, ONE_YOCTO, opts);
  }
  /** Signed by the PROPOSED owner (build an OwnerApi with that account). */
  acceptOwner(opts?: CallOptions): Promise<CallResult<null>> {
    return this.call('accept_owner', {}, GAS.default, ONE_YOCTO, opts);
  }
  /** Anyone can fund the vault. Returns the available balance (U128). */
  deposit(amount: bigint | U128, opts?: CallOptions): Promise<CallResult<U128>> {
    const yocto = BigInt(toU128(amount));
    if (yocto === 0n) throw new RangeError('Attach a deposit');
    return this.call('deposit', {}, GAS.default, yocto, opts);
  }
}

export const agentApi = (who: Who, opts: ApiOptions): AgentApi => new AgentApi(who, opts);
export const guardianApi = (who: Who, opts: ApiOptions): GuardianApi => new GuardianApi(who, opts);
export const ownerApi = (who: Who, opts: ApiOptions): OwnerApi => new OwnerApi(who, opts);
