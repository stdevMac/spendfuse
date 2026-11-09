// chain.ts - the ChainBackend the agent runtime talks to, plus FakeChain: an in-memory vault that
// mirrors contract/src/lib.rs (evaluate, submit_payment, on_payment_settled, approve/reject, freeze)
// and the protocol's function-call access-key checks. Used by tests and --dry-run.
import { PAYEES } from '../lib/env.ts';
import { explorer } from '../lib/near.ts';
import { AGENT_METHODS, NEAR } from '../lib/spendfuse.ts';
import type { AgentView, CheckResult, PaymentResult, PaymentStatus, PolicyInput, Reason } from '../lib/types.ts';

export interface PayArgs {
  receiver_id: string;
  amount: bigint;
  memo?: string;
}

export interface TxRef {
  hash: string;
  url: string;
  method: string;
  actor: string;
  ok: boolean;
  /** true for FakeChain hashes (nothing on chain) */
  simulated: boolean;
}

/** One call to the chain. tx is null when nothing landed (view, or rejected before inclusion). */
export interface ChainCall<T> {
  result: T | null;
  tx: TxRef | null;
  error: string | null;
  /** explain(err).kind for live errors, mirrored by FakeChain ('access-key', 'contract-panic', ...) */
  errorKind?: string;
  /** access-key reason, e.g. MethodNameMismatch */
  reason?: string;
}

/** Off-chain counterparty check, reduced to what the guard needs (src/scout/counterparty.ts Verdict). */
export interface ScoutSummary {
  decision: 'allow' | 'warn' | 'block';
  reasons: { code: string; severity: string; detail: string }[];
}

export type RawAction = 'transfer' | 'add_full_access_key' | 'delete_account';

export interface OwnerOps {
  unfreeze(): Promise<ChainCall<AgentView>>;
  unpause(): Promise<ChainCall<null>>;
  approve(requestId: string): Promise<ChainCall<PaymentResult>>;
  reject(requestId: string, reason: string): Promise<ChainCall<unknown>>;
  addCanary(accountId: string): Promise<ChainCall<number>>;
  /** merges the patch into the agent's current policy and sends update_policy */
  updatePolicy(patch: Partial<PolicyInput>): Promise<ChainCall<AgentView>>;
}

export interface ChainBackend {
  readonly kind: 'fake' | 'live';
  readonly agentId: string;
  readonly vaultId: string;
  checkPayment(receiverId: string, amount: bigint): Promise<CheckResult>;
  requestPayment(p: PayArgs): Promise<ChainCall<PaymentResult>>;
  selfFreeze(reason: string): Promise<ChainCall<boolean>>;
  reportReceiver(receiverId: string, reason: string): Promise<ChainCall<unknown>>;
  getAgent(): Promise<AgentView>;
  /** true when receiverId is a planted canary (probe of vault state; hidden from check_payment) */
  isCanary(receiverId: string): Promise<boolean>;
  scout(receiverId: string): Promise<ScoutSummary>;
  /** A raw function call signed by the agent key, bypassing the guard (attack scenarios). */
  rawAgentCall(c: { receiverId: string; methodName: string; args: Record<string, unknown>; deposit?: bigint }): Promise<ChainCall<unknown>>;
  /** A non-function-call action signed by the agent key; a function-call key cannot authorize it. */
  rawAgentAction(action: RawAction, receiverId: string, amount?: bigint): Promise<ChainCall<unknown>>;
  owner: OwnerOps;
}

// ---------------------------------------------------------------- FakeChain
const HOUR = 3_600_000;
const DAY = 24 * HOUR;
const MAX_PENDING_PER_AGENT = 5;
const MAX_PENDING_VAULT = 100;
const MAX_PAYEES = 256;
const HARD_FREEZE_BACKSTOP = 25;
const PENDING_TTL_MS = DAY;

/** contract is_environmental_block: the block comes only from vault state (balance or a full approval
 * queue), possibly alongside soft signals, not from a limit the agent broke. Counted, never auto-freezes. */
export function isEnvironmentalBlock(reasons: readonly Reason[]): boolean {
  const env = (r: Reason) => r === 'INSUFFICIENT_VAULT_BALANCE' || r === 'TOO_MANY_PENDING';
  return reasons.some(env) && reasons.every((r) => env(r) || r === 'NEW_PAYEE' || r === 'NEEDS_APPROVAL' || r === 'REPORTED_RECEIVER');
}

export interface FakePolicy {
  max_per_payment: bigint;
  daily_limit: bigint;
  approval_threshold: bigint;
  new_payee_limit: bigint;
  max_payments_per_hour: number;
  allowlist_only: boolean;
  allowlist: string[];
  auto_freeze_after_blocks: number;
  expires_at_ms: number | null;
}

interface Pending {
  id: number;
  receiver_id: string;
  amount: bigint;
  memo?: string;
  reasons: Reason[];
  at: number;
}

export interface FakeChainOptions {
  ownerId?: string;
  vaultId?: string;
  agentId?: string;
  policy?: Partial<FakePolicy>;
  /** vault balance available for payments (yocto) */
  balance?: bigint;
  /** accounts that exist (a Transfer to a missing named account fails) */
  accounts?: string[];
  canaries?: string[];
  now?: () => number;
  /** per-receiver scout verdicts that override the built-in rules */
  scoutOverrides?: Record<string, ScoutSummary>;
}

const n = (near: string): bigint => {
  const [i, f = ''] = near.split('.');
  return BigInt(i) * NEAR + BigInt((f + '0'.repeat(24)).slice(0, 24));
};

/** The setup-testnet.ts policy (1 / 3 / 0.5 / 0.2 NEAR, 10 per hour, shop allowlisted). */
export function testnetPolicy(shopId: string): FakePolicy {
  return {
    max_per_payment: n('1'),
    daily_limit: n('3'),
    approval_threshold: n('0.5'),
    new_payee_limit: n('0.2'),
    max_payments_per_hour: 10,
    allowlist_only: false,
    allowlist: [shopId],
    auto_freeze_after_blocks: 0,
    expires_at_ms: null,
  };
}

const isImplicit = (id: string) => /^[0-9a-f]{64}$/.test(id) || /^0x[0-9a-f]{40}$/.test(id);

export class FakeChain implements ChainBackend {
  readonly kind = 'fake' as const;
  readonly ownerId: string;
  readonly vaultId: string;
  readonly agentId: string;
  policy: FakePolicy;
  balance: bigint;
  frozen: { reason: string; by: string; at: number } | null = null;
  paused = false;
  readonly accounts: Set<string>;
  readonly canaries: Set<string>;
  readonly blocklist = new Map<string, 'reported' | 'confirmed'>();
  readonly payees = new Map<string, number>();
  readonly pending = new Map<number, Pending>();
  /** [at, amount] of paid spend (rolled back on a failed transfer) */
  spends: { at: number; amount: bigint; id: number }[] = [];
  recentPayments: number[] = [];
  recentBlocks: number[] = [];
  reports = 0;
  readonly counters = { paid: 0, blocked: 0, escalated: 0, tripped: 0, approved: 0, rejected: 0, expired: 0, failed: 0, blocked_while_frozen: 0, reports: 0 };
  readonly events: { event: string; data: Record<string, unknown> }[] = [];
  readonly transfers: { receiver: string; amount: bigint; ok: boolean }[] = [];
  readonly scoutOverrides: Record<string, ScoutSummary>;
  now: () => number;
  #nextId = 1;
  #tx = 0;

  constructor(o: FakeChainOptions = {}) {
    this.ownerId = o.ownerId ?? 'owner.testnet';
    this.vaultId = o.vaultId ?? `vault.${this.ownerId}`;
    this.agentId = o.agentId ?? `agent.${this.ownerId}`;
    const shop = `${PAYEES.shop.prefix}.${this.ownerId}`;
    this.policy = { ...testnetPolicy(shop), ...o.policy };
    this.balance = o.balance ?? n('5');
    this.accounts = new Set(o.accounts ?? [this.ownerId, this.vaultId, this.agentId, shop, `${PAYEES.api.prefix}.${this.ownerId}`, `${PAYEES.data.prefix}.${this.ownerId}`, `guardian.${this.ownerId}`]);
    this.canaries = new Set(o.canaries ?? []);
    this.scoutOverrides = o.scoutOverrides ?? {};
    this.now = o.now ?? Date.now;
  }

  // ------------------------------------------------ helpers
  #ref(method: string, actor: string, ok: boolean): TxRef {
    const hash = `FAKE${String(++this.#tx).padStart(4, '0')}${'x'.repeat(8)}`;
    return { hash, url: explorer.tx(hash), method, actor, ok, simulated: true };
  }
  #emit(event: string, data: Record<string, unknown>) {
    this.events.push({ event, data });
  }
  /** contract expire_agent_pending: requests older than PENDING_TTL_MS stop counting against limits. */
  expirePending() {
    const now = this.now();
    for (const p of [...this.pending.values()]) {
      if (p.at + PENDING_TTL_MS > now) continue;
      this.pending.delete(p.id);
      this.counters.expired++;
      this.#emit('expired', { request_id: String(p.id), receiver_id: p.receiver_id, amount: p.amount.toString() });
    }
  }
  get reserved(): bigint {
    let r = 0n;
    for (const p of this.pending.values()) r += p.amount;
    return r;
  }
  spent24h(): bigint {
    const since = this.now() - DAY;
    return this.spends.filter((s) => s.at > since).reduce((a, s) => a + s.amount, 0n);
  }
  paymentsLastHour(): number {
    const since = this.now() - HOUR;
    return this.recentPayments.filter((t) => t > since).length;
  }
  blocksLastHour(): number {
    const since = this.now() - HOUR;
    return this.recentBlocks.filter((t) => t > since).length;
  }
  #freeze(reason: string, by: string) {
    this.frozen = { reason, by, at: this.now() };
    for (const p of [...this.pending.values()]) {
      this.pending.delete(p.id);
      this.counters.rejected++;
      this.#emit('rejected', { request_id: String(p.id), reason: 'agent frozen' });
    }
    this.#emit('frozen', { agent_id: this.agentId, reason, by });
  }
  #result(status: PaymentStatus, id: number, reasons: Reason[], p: PayArgs, frozen = false): PaymentResult {
    return { status, request_id: String(id), reasons, amount: p.amount.toString(), receiver_id: p.receiver_id, frozen };
  }

  /** contract evaluate(); checkCanary is false for the check_payment view. */
  evaluate(receiverId: string, amount: bigint, checkCanary: boolean): CheckResult {
    const p = this.policy;
    // Like the contract (live_reserved, check_payment's retain), expired requests never count, even
    // in the check_payment view, which does not run expirePending first.
    const now = this.now();
    const live = [...this.pending.values()].filter((x) => x.at + PENDING_TTL_MS > now);
    const reserved = live.reduce((a, x) => a + x.amount, 0n);
    if (this.frozen) return { verdict: 'block', reasons: ['AGENT_FROZEN'] };
    if (checkCanary && this.canaries.has(receiverId)) return { verdict: 'trip', reasons: ['TRIPWIRE'] };
    if (this.paused) return { verdict: 'block', reasons: ['VAULT_PAUSED'] };
    if (p.expires_at_ms !== null && this.now() >= p.expires_at_ms) return { verdict: 'block', reasons: ['POLICY_EXPIRED'] };
    const allowlisted = p.allowlist.includes(receiverId);
    const hard: Reason[] = [];
    if (receiverId === this.agentId || receiverId === this.vaultId) hard.push('SELF_PAYMENT');
    if (this.blocklist.get(receiverId) === 'confirmed') hard.push('BLOCKLISTED');
    if (amount === 0n) hard.push('ZERO_AMOUNT');
    if (p.allowlist_only && !allowlisted) hard.push('NOT_ALLOWLISTED');
    if (amount > p.max_per_payment) hard.push('OVER_PER_PAYMENT_CAP');
    if (this.paymentsLastHour() >= p.max_payments_per_hour) hard.push('RATE_LIMITED');
    if (this.spent24h() + reserved + amount > p.daily_limit) hard.push('OVER_DAILY_LIMIT');
    if (this.balance - this.reserved < amount) hard.push('INSUFFICIENT_VAULT_BALANCE');
    if (hard.length) return { verdict: 'block', reasons: hard };
    const soft: Reason[] = [];
    if (this.blocklist.get(receiverId) === 'reported' && !allowlisted) soft.push('REPORTED_RECEIVER');
    if (!allowlisted && !this.payees.has(receiverId) && (amount > p.new_payee_limit || this.payees.size >= MAX_PAYEES)) soft.push('NEW_PAYEE');
    if (amount > p.approval_threshold) soft.push('NEEDS_APPROVAL');
    if (soft.length) {
      if (live.length >= MAX_PENDING_PER_AGENT || this.pending.size >= MAX_PENDING_VAULT) {
        return { verdict: 'block', reasons: [...soft, 'TOO_MANY_PENDING'] };
      }
      return { verdict: 'warn', reasons: soft };
    }
    return { verdict: 'allow', reasons: [] };
  }

  #transfer(id: number, p: PayArgs): PaymentResult {
    const ok = this.accounts.has(p.receiver_id) || isImplicit(p.receiver_id);
    this.transfers.push({ receiver: p.receiver_id, amount: p.amount, ok });
    if (ok) {
      this.balance -= p.amount;
      this.accounts.add(p.receiver_id);
      this.#emit('paid', { request_id: String(id), receiver_id: p.receiver_id, amount: p.amount.toString() });
      return this.#result('paid', id, [], p);
    }
    // on_payment_settled: roll back spend, payee and counters; the failed transfer refunds the vault.
    this.spends = this.spends.filter((s) => s.id !== id);
    const c = (this.payees.get(p.receiver_id) ?? 1) - 1;
    if (c <= 0) this.payees.delete(p.receiver_id);
    else this.payees.set(p.receiver_id, c);
    this.counters.failed++; // the contract keeps counters.paid as is
    this.#emit('transfer_failed', { request_id: String(id), receiver_id: p.receiver_id, amount: p.amount.toString() });
    return this.#result('transfer_failed', id, [], p);
  }

  /** contract submit_payment (request_payment from the agent). */
  submit(p: PayArgs): PaymentResult {
    const id = this.#nextId++;
    this.expirePending();
    const v = this.evaluate(p.receiver_id, p.amount, true);
    const now = this.now();
    if (v.verdict === 'trip') {
      this.counters.tripped++;
      this.#emit('tripped', { request_id: String(id), receiver_id: p.receiver_id });
      this.#freeze('TRIPWIRE: attempted payment to a canary payee', this.vaultId);
      return this.#result('tripped', id, v.reasons, p, true);
    }
    if (v.verdict === 'block') {
      // Repeats while frozen or paused are logged quietly and do not count as new blocks.
      const quiet = v.reasons.length === 1 && (v.reasons[0] === 'AGENT_FROZEN' || v.reasons[0] === 'VAULT_PAUSED');
      if (quiet) {
        const frozen = v.reasons[0] === 'AGENT_FROZEN';
        if (frozen) this.counters.blocked_while_frozen++;
        return this.#result('blocked', id, v.reasons, p, frozen);
      }
      this.counters.blocked++;
      this.#emit('blocked', { request_id: String(id), receiver_id: p.receiver_id, reasons: v.reasons });
      // Environmental blocks are counted but do not count toward auto-freeze.
      if (isEnvironmentalBlock(v.reasons)) return this.#result('blocked', id, v.reasons, p);
      this.recentBlocks.push(now);
      const configured = this.policy.auto_freeze_after_blocks;
      const threshold = configured === 0 ? HARD_FREEZE_BACKSTOP : Math.min(configured, HARD_FREEZE_BACKSTOP);
      const n = this.blocksLastHour();
      if (n >= threshold) {
        this.#freeze(`AUTO_FREEZE: ${n} blocked payment attempts within 1h`, this.vaultId);
        return this.#result('blocked', id, v.reasons, p, true);
      }
      return this.#result('blocked', id, v.reasons, p);
    }
    this.recentPayments.push(now);
    if (v.verdict === 'warn') {
      this.pending.set(id, { id, receiver_id: p.receiver_id, amount: p.amount, memo: p.memo, reasons: v.reasons, at: now });
      this.counters.escalated++;
      this.#emit('escalated', { request_id: String(id), receiver_id: p.receiver_id, reasons: v.reasons });
      return this.#result('pending_approval', id, v.reasons, p);
    }
    this.spends.push({ at: now, amount: p.amount, id });
    this.payees.set(p.receiver_id, (this.payees.get(p.receiver_id) ?? 0) + 1);
    this.counters.paid++;
    return this.#transfer(id, p);
  }

  agentView(): AgentView {
    const p = this.policy;
    const spent = this.spent24h();
    return {
      agent_id: this.agentId,
      label: 'fake agent',
      status: this.frozen
        ? { state: 'frozen', reason: this.frozen.reason, by: this.frozen.by, at_ms: String(this.frozen.at) }
        : { state: 'active' },
      policy: {
        max_per_payment: p.max_per_payment.toString(),
        daily_limit: p.daily_limit.toString(),
        approval_threshold: p.approval_threshold.toString(),
        new_payee_limit: p.new_payee_limit.toString(),
        max_payments_per_hour: p.max_payments_per_hour,
        allowlist_only: p.allowlist_only,
        allowlist: [...p.allowlist],
        auto_freeze_after_blocks: p.auto_freeze_after_blocks,
        expires_at_ms: p.expires_at_ms === null ? null : String(p.expires_at_ms),
      },
      spent_24h: spent.toString(),
      remaining_24h: (p.daily_limit > spent ? p.daily_limit - spent : 0n).toString(),
      reserved: this.reserved.toString(),
      payments_last_hour: this.paymentsLastHour(),
      blocks_last_hour: this.blocksLastHour(),
      pending_ids: [...this.pending.keys()].map(String),
      total_spent: this.spends.reduce((a, s) => a + s.amount, 0n).toString(),
      payee_count: this.payees.size,
      counters: { ...this.counters },
      created_at_ms: '0',
    };
  }

  // ------------------------------------------------ ChainBackend
  async checkPayment(receiverId: string, amount: bigint): Promise<CheckResult> {
    return this.evaluate(receiverId, amount, false);
  }
  async requestPayment(p: PayArgs): Promise<ChainCall<PaymentResult>> {
    const result = this.submit(p);
    return { result, tx: this.#ref('request_payment', this.agentId, true), error: null };
  }
  async selfFreeze(reason: string): Promise<ChainCall<boolean>> {
    if (this.frozen) return { result: false, tx: this.#ref('self_freeze', this.agentId, true), error: null };
    this.#freeze(reason || 'self freeze', this.agentId);
    return { result: true, tx: this.#ref('self_freeze', this.agentId, true), error: null };
  }
  async reportReceiver(receiverId: string, reason: string): Promise<ChainCall<unknown>> {
    if (this.frozen || this.reports >= 20) {
      const error = this.frozen ? 'agent is frozen' : 'report limit reached';
      return { result: null, tx: this.#ref('report_receiver', this.agentId, false), error, errorKind: 'contract-panic' };
    }
    this.reports++;
    this.counters.reports++;
    if (!this.blocklist.has(receiverId)) this.blocklist.set(receiverId, 'reported');
    this.#emit('reported', { receiver_id: receiverId, reason });
    return { result: { account_id: receiverId, status: this.blocklist.get(receiverId) }, tx: this.#ref('report_receiver', this.agentId, true), error: null };
  }
  async getAgent(): Promise<AgentView> {
    return this.agentView();
  }
  async isCanary(receiverId: string): Promise<boolean> {
    return this.canaries.has(receiverId);
  }
  async scout(receiverId: string): Promise<ScoutSummary> {
    const o = this.scoutOverrides[receiverId];
    if (o) return o;
    if (this.accounts.has(receiverId)) return { decision: 'allow', reasons: [] };
    if (isImplicit(receiverId)) {
      return { decision: 'warn', reasons: [{ code: 'IMPLICIT_WOULD_CREATE', severity: 'warn', detail: 'implicit account does not exist yet' }] };
    }
    return { decision: 'block', reasons: [{ code: 'ACCOUNT_DOES_NOT_EXIST', severity: 'block', detail: 'named account does not exist' }] };
  }

  /** Protocol access-key check for the agent's function-call key (receiver = vault, AGENT_METHODS, no deposit). */
  #keyCheck(receiverId: string, methodName: string, deposit: bigint): string | null {
    if (deposit > 0n) return 'DepositWithFunctionCall';
    if (receiverId !== this.vaultId) return 'ReceiverMismatch';
    if (!(AGENT_METHODS as readonly string[]).includes(methodName)) return 'MethodNameMismatch';
    return null;
  }

  async rawAgentCall(c: { receiverId: string; methodName: string; args: Record<string, unknown>; deposit?: bigint }): Promise<ChainCall<unknown>> {
    const bad = this.#keyCheck(c.receiverId, c.methodName, c.deposit ?? 0n);
    if (bad) return { result: null, tx: null, error: `access key does not allow this call (${bad})`, errorKind: 'access-key', reason: bad };
    if (c.methodName === 'request_payment') {
      const amount = BigInt(String(c.args.amount ?? '0'));
      return this.requestPayment({ receiver_id: String(c.args.receiver_id), amount, memo: c.args.memo as string | undefined });
    }
    if (c.methodName === 'self_freeze') return this.selfFreeze(String(c.args.reason ?? ''));
    return this.reportReceiver(String(c.args.receiver_id), String(c.args.reason ?? ''));
  }

  async rawAgentAction(_action: RawAction, _receiverId: string, _amount?: bigint): Promise<ChainCall<unknown>> {
    return { result: null, tx: null, error: 'access key does not allow this action (RequiresFullAccess)', errorKind: 'access-key', reason: 'RequiresFullAccess' };
  }

  // ------------------------------------------------ owner / guardian
  readonly owner: OwnerOps = {
    unfreeze: async () => {
      if (!this.frozen) return { result: null, tx: this.#ref('unfreeze_agent', this.ownerId, false), error: 'agent is not frozen', errorKind: 'contract-panic' };
      this.frozen = null;
      this.recentBlocks = [];
      this.#emit('unfrozen', { agent_id: this.agentId });
      return { result: this.agentView(), tx: this.#ref('unfreeze_agent', this.ownerId, true), error: null };
    },
    unpause: async () => {
      this.paused = false;
      return { result: null, tx: this.#ref('unpause', this.ownerId, true), error: null };
    },
    approve: async (requestId: string) => {
      const p = this.pending.get(Number(requestId));
      if (!p) return { result: null, tx: this.#ref('approve', this.ownerId, false), error: 'request is not pending', errorKind: 'contract-panic' };
      const recheck = this.paused ? 'vault is paused'
        : this.frozen ? 'agent is frozen'
        : this.blocklist.get(p.receiver_id) === 'confirmed' ? 'receiver is blocklisted'
        : this.canaries.has(p.receiver_id) ? 'receiver is not payable'
        : this.balance - this.reserved + p.amount < p.amount ? 'insufficient vault balance'
        : null;
      if (recheck) return { result: null, tx: this.#ref('approve', this.ownerId, false), error: recheck, errorKind: 'contract-panic' };
      this.pending.delete(p.id);
      this.counters.approved++;
      this.spends.push({ at: this.now(), amount: p.amount, id: p.id });
      this.payees.set(p.receiver_id, (this.payees.get(p.receiver_id) ?? 0) + 1);
      this.#emit('approved', { request_id: requestId });
      const result = this.#transfer(p.id, { receiver_id: p.receiver_id, amount: p.amount, memo: p.memo });
      return { result, tx: this.#ref('approve', this.ownerId, true), error: null };
    },
    reject: async (requestId: string, reason: string) => {
      const p = this.pending.get(Number(requestId));
      if (!p) return { result: null, tx: this.#ref('reject', this.ownerId, false), error: 'request is not pending', errorKind: 'contract-panic' };
      this.pending.delete(p.id);
      this.counters.rejected++;
      this.#emit('rejected', { request_id: requestId, reason });
      return { result: { request_id: requestId, receiver_id: p.receiver_id, amount: p.amount.toString() }, tx: this.#ref('reject', this.ownerId, true), error: null };
    },
    addCanary: async (accountId: string) => {
      const fresh = this.canaries.has(accountId) ? 0 : 1;
      this.canaries.add(accountId);
      return { result: fresh, tx: this.#ref('add_canaries', this.ownerId, true), error: null };
    },
    updatePolicy: async (patch: Partial<PolicyInput>) => {
      const p = { ...this.policy };
      if (patch.max_per_payment !== undefined) p.max_per_payment = BigInt(patch.max_per_payment);
      if (patch.daily_limit !== undefined) p.daily_limit = BigInt(patch.daily_limit);
      if (patch.approval_threshold !== undefined) p.approval_threshold = BigInt(patch.approval_threshold);
      if (patch.new_payee_limit !== undefined) p.new_payee_limit = BigInt(patch.new_payee_limit);
      if (patch.max_payments_per_hour !== undefined) p.max_payments_per_hour = patch.max_payments_per_hour;
      if (patch.allowlist_only !== undefined) p.allowlist_only = patch.allowlist_only;
      if (patch.allowlist !== undefined) p.allowlist = [...patch.allowlist];
      if (patch.auto_freeze_after_blocks !== undefined) p.auto_freeze_after_blocks = patch.auto_freeze_after_blocks;
      if (patch.expires_at_ms !== undefined) p.expires_at_ms = patch.expires_at_ms === null ? null : Number(patch.expires_at_ms);
      this.policy = p;
      this.#emit('policy_updated', { agent_id: this.agentId });
      return { result: this.agentView(), tx: this.#ref('update_policy', this.ownerId, true), error: null };
    },
  };
}
