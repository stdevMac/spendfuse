// guard.ts - the agent-side pre-flight check: vault check_payment view + off-chain scout + canary probe,
// combined into allow / warn / block. The vault contract is the real enforcement; this wrapper only avoids
// sending what will obviously fail, routes doubtful payments to a human, and keeps reasons from the model.
import { formatNear } from '../lib/spendfuse.ts';
import type { CheckResult, PaymentResult } from '../lib/types.ts';
import type { ChainBackend, ChainCall, ScoutSummary } from './chain.ts';
import type { CheckCall, PayCall } from './tools.ts';

export type Decision = 'allow' | 'warn' | 'block';
/** send: forward request_payment; hold: local human-approval request; refuse: nothing is sent */
export type GuardAction = 'send' | 'hold' | 'refuse';

export interface GuardReason {
  source: 'vault' | 'scout' | 'guard' | 'llm';
  code: string;
  detail?: string;
}

/** Turn trust from the LLM layer: payments on an unverified turn are held for a human. */
export interface TurnTrust {
  verified: boolean;
  kind: 'scripted' | 'tee-verified' | 'gateway-verified' | 'unverified';
  chatId?: string;
  detail?: string;
}

export interface GuardDecision {
  decision: Decision;
  action: GuardAction;
  reasons: GuardReason[];
  vault: CheckResult | null;
  scout: ScoutSummary | null;
  /** the receiver is a planted canary: forwarded so the vault trips and freezes the agent */
  canary: boolean;
}

export interface GuardOptions {
  /** forward vault-blocked payments so the attempt is recorded and counts toward auto-freeze (default true) */
  recordBlocked?: boolean;
  /** forward canary payments so the vault freezes the agent (default true) */
  tripCanaries?: boolean;
}

/** Exactly what the model is told on a block. Nothing about canaries, watchlists or limits. */
export const REFUSED = 'refused';
export const HELD = 'pending human approval';

const QUIET = new Set(['AGENT_FROZEN', 'VAULT_PAUSED']);

/** Pure decision table (exported for tests). */
export function combine(vault: CheckResult, scout: ScoutSummary, trust: TurnTrust, opts: GuardOptions = {}): GuardDecision {
  const reasons: GuardReason[] = [
    ...vault.reasons.map((code) => ({ source: 'vault' as const, code })),
    ...scout.reasons.filter((r) => r.severity !== 'info').map((r) => ({ source: 'scout' as const, code: r.code, detail: r.detail })),
  ];
  const base = { vault, scout, canary: false };
  if (vault.verdict === 'block' || vault.verdict === 'trip') {
    const quiet = vault.reasons.every((r) => QUIET.has(r));
    const action: GuardAction = !quiet && (opts.recordBlocked ?? true) ? 'send' : 'refuse';
    return { ...base, decision: 'block', action, reasons };
  }
  if (scout.decision === 'block') return { ...base, decision: 'block', action: 'refuse', reasons };
  // The vault already escalates warn verdicts to the owner on chain.
  if (vault.verdict === 'warn') return { ...base, decision: 'warn', action: 'send', reasons };
  if (scout.decision === 'warn' || !trust.verified) {
    if (!trust.verified) reasons.push({ source: 'llm', code: 'UNVERIFIED_TURN', detail: trust.detail ?? trust.kind });
    return { ...base, decision: 'warn', action: 'hold', reasons };
  }
  return { ...base, decision: 'allow', action: 'send', reasons };
}

const failed = (code: string, detail: string): GuardDecision => ({
  decision: 'block', action: 'refuse', reasons: [{ source: 'guard', code, detail }], vault: null, scout: null, canary: false,
});

/** Canary probe, vault view and scout for one payment. Fails closed. */
export async function evaluatePayment(chain: ChainBackend, call: PayCall, trust: TurnTrust, opts: GuardOptions = {}): Promise<GuardDecision> {
  let canary: boolean;
  try {
    canary = await chain.isCanary(call.receiver_id);
  } catch (e) {
    return failed('CANARY_PROBE_FAILED', (e as Error).message);
  }
  if (canary) {
    const action: GuardAction = opts.tripCanaries ?? true ? 'send' : 'refuse';
    return { decision: 'block', action, reasons: [{ source: 'guard', code: 'CANARY' }], vault: null, scout: null, canary: true };
  }
  let vault: CheckResult;
  try {
    vault = await chain.checkPayment(call.receiver_id, call.amount);
  } catch (e) {
    return failed('VAULT_CHECK_FAILED', (e as Error).message);
  }
  let scout: ScoutSummary;
  try {
    scout = await chain.scout(call.receiver_id);
  } catch (e) {
    scout = { decision: 'warn', reasons: [{ code: 'CHECK_UNAVAILABLE', severity: 'warn', detail: (e as Error).message }] };
  }
  return combine(vault, scout, trust, opts);
}

export interface ApprovalRequest {
  /** vault: pending on chain (owner approves with approve(request_id)); local: held by this wrapper, nothing sent */
  where: 'vault' | 'local';
  request_id?: string;
  receiver_id: string;
  amount_near: string;
  memo: string;
  reasons: GuardReason[];
  at: string;
}

export type PayOutcome = 'paid' | 'escalated' | 'held' | 'refused' | 'tripped' | 'auto_frozen' | 'transfer_failed' | 'error';

export interface GuardedPayResult {
  outcome: PayOutcome;
  /** the only text the model sees */
  modelMessage: string;
  decision: GuardDecision;
  chain: ChainCall<PaymentResult> | null;
  approval: ApprovalRequest | null;
}

/** Evaluate, then send / hold / refuse. Blocks and canaries read back to the model as exactly REFUSED. */
export async function guardedPay(chain: ChainBackend, call: PayCall, trust: TurnTrust, opts: GuardOptions = {}): Promise<GuardedPayResult> {
  const decision = await evaluatePayment(chain, call, trust, opts);
  const at = new Date().toISOString();
  const base = { receiver_id: call.receiver_id, amount_near: call.amount_near, memo: call.memo, reasons: decision.reasons, at };
  if (decision.action === 'refuse') return { outcome: 'refused', modelMessage: REFUSED, decision, chain: null, approval: null };
  if (decision.action === 'hold') {
    return { outcome: 'held', modelMessage: HELD, decision, chain: null, approval: { where: 'local', ...base } };
  }
  const res = await chain.requestPayment({ receiver_id: call.receiver_id, amount: call.amount, memo: call.memo || undefined });
  const r = res.result;
  if (!r) return { outcome: 'error', modelMessage: REFUSED, decision, chain: res, approval: null };
  switch (r.status) {
    case 'paid':
      return { outcome: 'paid', modelMessage: `paid ${formatNear(r.amount)} NEAR to ${r.receiver_id}`, decision, chain: res, approval: null };
    case 'pending_approval': {
      const reasons = [...decision.reasons.filter((x) => x.source !== 'vault'), ...r.reasons.map((code) => ({ source: 'vault' as const, code }))];
      return { outcome: 'escalated', modelMessage: HELD, decision, chain: res, approval: { where: 'vault', request_id: r.request_id, ...base, reasons } };
    }
    case 'transfer_failed':
      return { outcome: 'transfer_failed', modelMessage: 'payment failed: the transfer did not complete and nothing was spent', decision, chain: res, approval: null };
    case 'tripped':
      return { outcome: 'tripped', modelMessage: REFUSED, decision, chain: res, approval: null };
    default:
      // frozen is also true on a quiet AGENT_FROZEN block (already frozen, not frozen by this attempt)
      const autoFrozen = r.frozen && !r.reasons.every((x) => x === 'AGENT_FROZEN');
      return { outcome: autoFrozen ? 'auto_frozen' : 'refused', modelMessage: REFUSED, decision, chain: res, approval: null };
  }
}

/** check_receiver: the view verdict only, coarse, with no canary probe (a canary looks like any receiver). */
export async function checkReceiver(chain: ChainBackend, call: CheckCall, trust: TurnTrust): Promise<string> {
  try {
    const [vault, scout] = await Promise.all([
      chain.checkPayment(call.receiver_id, call.amount),
      chain.scout(call.receiver_id).catch((): ScoutSummary => ({ decision: 'warn', reasons: [] })),
    ]);
    const d = combine(vault, scout, trust);
    return d.decision === 'allow' ? 'ok' : d.decision === 'warn' ? 'needs human approval' : 'not allowed';
  } catch {
    return 'unavailable';
  }
}
