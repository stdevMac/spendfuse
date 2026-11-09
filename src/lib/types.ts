// types.ts - JSON wire types of the Spendfuse vault contract (contract/src/lib.rs, version 1.0.0).
// Field names are snake_case as on the wire. U128 / U64 travel as decimal strings; u32 / u64 / bool as JSON numbers / booleans.

/** yoctoNEAR amount, U128 as a decimal string */
export type U128 = string;
/** U64 as a decimal string (ids, timestamps in ms, block heights) */
export type U64 = string;
export type AccountId = string;

export const REASONS = [
  'AGENT_FROZEN',
  'TRIPWIRE',
  'VAULT_PAUSED',
  'POLICY_EXPIRED',
  'SELF_PAYMENT',
  'BLOCKLISTED',
  'ZERO_AMOUNT',
  'NOT_ALLOWLISTED',
  'OVER_PER_PAYMENT_CAP',
  'RATE_LIMITED',
  'OVER_DAILY_LIMIT',
  'INSUFFICIENT_VAULT_BALANCE',
  'TOO_MANY_PENDING',
  'REPORTED_RECEIVER',
  'NEW_PAYEE',
  'NEEDS_APPROVAL',
  'UNKNOWN_AGENT',
] as const;
/** enum Reason (SCREAMING_SNAKE_CASE) */
export type Reason = (typeof REASONS)[number];

/** enum Verdict */
export type Verdict = 'allow' | 'warn' | 'block' | 'trip';

/** enum PaymentStatus */
export type PaymentStatus = 'paid' | 'pending_approval' | 'blocked' | 'tripped' | 'expired' | 'transfer_failed';

/** enum AgentStatus, internally tagged by "state" */
export type AgentStatus = { state: 'active' } | { state: 'frozen'; reason: string; by: AccountId; at_ms: U64 };

/** enum BlockStatus */
export type BlockStatus = 'reported' | 'confirmed';

export const EVENT_NAMES = [
  'paid',
  'blocked',
  'tripped',
  'escalated',
  'approved',
  'rejected',
  'expired',
  'transfer_failed',
  'frozen',
  'unfrozen',
  'paused',
  'unpaused',
  'reported',
  'blocklisted',
  'unblocklisted',
  'agent_registered',
  'policy_updated',
  'agent_removed',
  'canaries_added',
  'canary_removed',
  'guardian_added',
  'guardian_removed',
  'owner_proposed',
  'owner_changed',
  'deposit',
  'withdraw',
] as const;
/** enum EventKind (snake_case): LogEntry.kind and the NEP-297 "event" field */
export type EventName = (typeof EVENT_NAMES)[number];

/** struct Policy as returned by views (every field present; None serializes as null). */
export interface Policy {
  max_per_payment: U128;
  daily_limit: U128;
  /** payments above this wait for the owner; "0" means every payment waits */
  approval_threshold: U128;
  /** a first payment to a receiver above this waits for the owner */
  new_payee_limit: U128;
  /** 1..=300 */
  max_payments_per_hour: number;
  allowlist_only: boolean;
  allowlist: AccountId[];
  /** 0 = backstop (25); at most 25 */
  auto_freeze_after_blocks: number;
  expires_at_ms: U64 | null;
}

/**
 * Policy as sent to register_agent / update_policy. The struct has deny_unknown_fields: send only
 * these keys. Fields with #[serde(default)] may be omitted.
 */
export interface PolicyInput {
  max_per_payment: U128;
  daily_limit: U128;
  approval_threshold: U128;
  new_payee_limit: U128;
  max_payments_per_hour: number;
  allowlist_only?: boolean;
  allowlist?: AccountId[];
  auto_freeze_after_blocks?: number;
  expires_at_ms?: U64 | null;
}

/** struct AgentCounters */
export interface AgentCounters {
  paid: number;
  blocked: number;
  escalated: number;
  tripped: number;
  approved: number;
  rejected: number;
  expired: number;
  failed: number;
  blocked_while_frozen: number;
  reports: number;
}

/** struct AgentView */
export interface AgentView {
  agent_id: AccountId;
  label: string;
  status: AgentStatus;
  policy: Policy;
  spent_24h: U128;
  remaining_24h: U128;
  reserved: U128;
  payments_last_hour: number;
  blocks_last_hour: number;
  pending_ids: U64[];
  total_spent: U128;
  payee_count: number;
  counters: AgentCounters;
  created_at_ms: U64;
}

/** struct ConfigView */
export interface ConfigView {
  version: string;
  owner_id: AccountId;
  pending_owner: AccountId | null;
  guardians: AccountId[];
  paused: boolean;
  pause_reason: string | null;
  agents: number;
  canaries: number;
  blocklist: number;
  open_reports: number;
  pending: number;
  reserved: U128;
  balance: U128;
  storage_locked: U128;
  available: U128;
  activity_written: U64;
  ring_capacity: number;
}

/** struct Stats (u64 counters are JSON numbers) */
export interface Stats {
  requests: number;
  paid: number;
  paid_total: U128;
  blocked: number;
  escalated: number;
  tripped: number;
  approved: number;
  rejected: number;
  expired: number;
  failed: number;
  freezes: number;
  blocked_while_frozen: number;
  blocked_while_paused: number;
  reports: number;
  canaries_added: number;
}

/** struct CheckResult (check_payment dry run; canaries are hidden there) */
export interface CheckResult {
  verdict: Verdict;
  reasons: Reason[];
}

/** struct PaymentResult */
export interface PaymentResult {
  status: PaymentStatus;
  request_id: U64;
  reasons: Reason[];
  amount: U128;
  receiver_id: AccountId;
  frozen: boolean;
}

/**
 * request_payment / approve return PromiseOrValue<PaymentResult>. It is serde-untagged: on the wire
 * the final tx value is a bare PaymentResult either way (from the callback when a transfer was sent).
 */
export type PaymentResultWire = PaymentResult;

/** struct PendingPayment */
export interface PendingPayment {
  id: U64;
  agent_id: AccountId;
  receiver_id: AccountId;
  amount: U128;
  memo: string | null;
  reasons: Reason[];
  created_at_ms: U64;
  expires_at_ms: U64;
}

/** struct LogEntry (get_activity). Optional fields are omitted when None; reasons when empty. */
export interface LogEntry {
  seq: U64;
  at_ms: U64;
  block_height: U64;
  kind: EventName;
  agent_id?: AccountId;
  receiver_id?: AccountId;
  amount?: U128;
  request_id?: U64;
  reasons?: Reason[];
  note?: string;
  by: AccountId;
}

/** struct BlocklistView */
export interface BlocklistView {
  account_id: AccountId;
  status: BlockStatus;
  reason: string;
  evidence: string | null;
  reporter: AccountId;
  confirmed_by: AccountId | null;
  at_ms: U64;
  reports: number;
}

/** struct PayeeStat */
export interface PayeeStat {
  count: number;
  total: U128;
  first_ms: U64;
  last_ms: U64;
}

/**
 * Event data: a LogEntry without "kind". "seq" is absent on quiet events (logged only, not kept in the
 * activity ring: repeats while frozen/paused, cancellations by freeze/removal, repeat reports, small deposits).
 */
export type EventData = Omit<LogEntry, 'kind' | 'seq'> & { seq?: U64 };

/** NEP-297 event: log line "EVENT_JSON:" + JSON */
export interface SpendfuseEvent {
  standard: 'tripwire';
  version: string;
  event: EventName;
  data: EventData[];
}
