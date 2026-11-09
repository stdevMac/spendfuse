//! # Tripwire: a spending firewall for AI agents on NEAR
//!
//! The vault contract holds the money. An AI agent never does: it can only *ask* the vault
//! to pay, using a function-call access key that is limited to `request_payment`,
//! `report_receiver` and `self_freeze`.
//!
//! Every request ends in exactly one of these states:
//! - **paid**: every check passed and the transfer was sent;
//! - **pending approval**: a soft signal fired (new payee, large amount, reported receiver).
//!   The amount is reserved until the owner approves it or a guardian rejects it;
//! - **blocked**: a hard limit was hit. The attempt is recorded and counts toward auto-freeze,
//!   except environmental blocks (see below);
//! - **tripped**: the receiver is a canary, a decoy payee that no honest flow ever pays.
//!   The agent is frozen on the spot.
//!
//! Checks run in this order and the first match decides:
//! 1. agent frozen
//! 2. canary
//! 3. vault paused
//! 4. policy expired
//! 5. hard limits: self-payment, confirmed blocklist, zero amount, allowlist,
//!    per-payment cap, hourly rate, rolling 24h limit, vault balance
//! 6. soft signals: reported receiver, new payee, amount above the approval threshold
//! 7. allow
//!
//! Blocked requests *return* a result instead of panicking, so the record and any
//! auto-freeze are committed on chain. Environmental blocks, where the only hard reason is
//! the vault balance (`INSUFFICIENT_VAULT_BALANCE`) or a full approval queue
//! (`TOO_MANY_PENDING`), possibly alongside soft signals, are counted as blocked but do not
//! count toward auto-freeze: they say nothing about the agent being compromised.
//!
//! Roles:
//! - the **owner** signs with a full-access key and attaches 1 yoctoNEAR to every owner-only
//!   method. A function-call key cannot attach a deposit, so a leaked agent or guardian key
//!   can never approve, unfreeze, withdraw or change a policy;
//! - **guardians** make free calls (a function-call key is enough) and can only make the
//!   vault stricter: freeze, pause, reject, blocklist, dismiss open reports and add canaries.
//!
//! Known limitations:
//! - payee records are not deleted by `remove_agent` (the agent's epoch changes so they are
//!   never read again), so their storage stays locked in the vault;
//! - blocklist entries and canaries added by guardians lock storage stake paid by the vault.
//!   The owner can free it in bulk with `unblock_receivers` and `remove_canary`.

use near_sdk::json_types::{U64, U128};
use near_sdk::serde_json::{self, json};
use near_sdk::store::{IterableMap, LookupMap, LookupSet, Vector};
use near_sdk::{
    AccountId, BorshStorageKey, CryptoHash, Gas, NearToken, PanicOnDefault, Promise, PromiseError,
    PromiseOrValue, assert_one_yocto, env, near, require,
};

pub const VERSION: &str = "1.0.0";
const EVENT_STANDARD: &str = "tripwire";

/// The activity ring keeps the newest 256 events in contract state (the logs keep all of them).
const RING_CAP: u32 = 256;
const MAX_AGENTS: u32 = 200;
const MAX_GUARDIANS: usize = 10;
const MAX_ALLOWLIST: usize = 100;
const MAX_CANARIES: u32 = 1000;
const MAX_CANARIES_PER_CALL: usize = 50;
const MAX_PENDING_PER_AGENT: usize = 5;
const MAX_PENDING_TOTAL: u32 = 100;
const MAX_OPEN_REPORTS: u32 = 200;
const MAX_BLOCKLIST: u32 = 1000;
const MAX_UNBLOCK_PER_CALL: usize = 100;
/// Generous storage estimate for one new blocklist entry and its activity-ring event.
const REPORT_STORAGE_BYTES: u128 = 1000;
const MAX_RATE: u32 = 300;
/// An agent is always frozen after this many blocked attempts within an hour.
const HARD_FREEZE_BACKSTOP: u32 = 25;
/// After this many distinct payees, every new payee needs approval (bounds payee storage).
const MAX_PAYEES_PER_AGENT: u32 = 256;
/// Reports an active agent may file for free; after that a deposit is required.
const MAX_FREE_REPORTS_PER_AGENT: u32 = 20;

const HOUR_MS: u64 = 3_600_000;
const PENDING_TTL_MS: u64 = 24 * HOUR_MS;

const MEMO_MAX: usize = 256;
const NOTE_MAX: usize = 160;
const LABEL_MAX: usize = 64;
const REASON_MAX: usize = 256;
const EVIDENCE_MAX: usize = 512;

/// Anti-spam deposit for reports from accounts that do not get free reports. The vault keeps it.
const REPORT_DEPOSIT: NearToken = NearToken::from_millinear(10);
/// Balance kept free so new records never push the vault below its storage stake.
const STORAGE_MARGIN: NearToken = NearToken::from_millinear(50);
/// Smaller deposits are logged but not written to the activity ring.
const RING_DEPOSIT_MIN: NearToken = NearToken::from_millinear(100);
const CALLBACK_GAS: Gas = Gas::from_tgas(20);
const EXPIRE_DEFAULT: u32 = 10;
const EXPIRE_MAX: u32 = 20;
/// Stale requests a payment request sweeps when the global pending queue is full.
const EXPIRE_IN_REQUEST: u32 = 5;
const HASH_ERROR: &str = "canary hash must be 64 hex characters (sha256 of the account id)";

// ------------------------------------------------------------------------------------------
// Types
// ------------------------------------------------------------------------------------------

/// Why a request was blocked, escalated or tripped.
#[near(serializers = [json, borsh])]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum Reason {
    AgentFrozen,
    Tripwire,
    VaultPaused,
    PolicyExpired,
    SelfPayment,
    Blocklisted,
    ZeroAmount,
    NotAllowlisted,
    OverPerPaymentCap,
    RateLimited,
    OverDailyLimit,
    InsufficientVaultBalance,
    TooManyPending,
    ReportedReceiver,
    NewPayee,
    NeedsApproval,
    UnknownAgent,
}

impl Reason {
    /// The verdict a reason leads to on its own.
    pub fn verdict(self) -> Verdict {
        match self {
            Reason::Tripwire => Verdict::Trip,
            Reason::ReportedReceiver | Reason::NewPayee | Reason::NeedsApproval => Verdict::Warn,
            _ => Verdict::Block,
        }
    }
}

/// Outcome of the policy check: `allow` pays, `warn` asks a human, `block` refuses,
/// `trip` refuses and freezes the agent.
#[near(serializers = [json])]
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord)]
#[serde(rename_all = "snake_case")]
pub enum Verdict {
    Allow,
    Warn,
    Block,
    Trip,
}

#[near(serializers = [json])]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum PaymentStatus {
    Paid,
    PendingApproval,
    Blocked,
    Tripped,
    Expired,
    TransferFailed,
}

#[near(serializers = [json, borsh])]
#[derive(Clone, Debug, PartialEq)]
#[serde(tag = "state", rename_all = "snake_case")]
pub enum AgentStatus {
    Active,
    Frozen { reason: String, by: AccountId, at_ms: U64 },
}

#[near(serializers = [json, borsh])]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum BlockStatus {
    /// Someone reported the receiver: payments to it need approval (unless allowlisted).
    Reported,
    /// The owner or a guardian confirmed it: payments to it are blocked.
    Confirmed,
}

#[near(serializers = [json, borsh])]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum EventKind {
    Paid,
    Blocked,
    Tripped,
    Escalated,
    Approved,
    Rejected,
    Expired,
    TransferFailed,
    Frozen,
    Unfrozen,
    Paused,
    Unpaused,
    Reported,
    Blocklisted,
    Unblocklisted,
    AgentRegistered,
    PolicyUpdated,
    AgentRemoved,
    CanariesAdded,
    CanaryRemoved,
    GuardianAdded,
    GuardianRemoved,
    OwnerProposed,
    OwnerChanged,
    Deposit,
    Withdraw,
}

#[near]
#[derive(BorshStorageKey)]
enum StorageKey {
    Agents,
    Canaries,
    Blocklist,
    Payees,
    Pending,
    Activity,
}

/// Spending rules for one agent. Amounts are yoctoNEAR strings in JSON.
/// Unknown fields are rejected, so a misspelled rule fails loudly instead of being ignored.
#[near(serializers = [json, borsh])]
#[derive(Clone, Debug, PartialEq)]
#[serde(deny_unknown_fields)]
pub struct Policy {
    /// Largest single payment.
    pub max_per_payment: U128,
    /// Most the agent may commit in any rolling 24 hours (paid plus reserved for approval).
    pub daily_limit: U128,
    /// Payments above this amount wait for the owner. 0 means every payment waits.
    pub approval_threshold: U128,
    /// A first payment to a receiver above this amount waits for the owner.
    pub new_payee_limit: U128,
    /// Most payment requests per rolling hour (paid or queued).
    pub max_payments_per_hour: u32,
    /// Only receivers on `allowlist` may be paid.
    #[serde(default)]
    pub allowlist_only: bool,
    /// Trusted receivers: never a "new payee" and not affected by reports.
    #[serde(default)]
    pub allowlist: Vec<AccountId>,
    /// Freeze after this many blocked attempts within an hour. 0 means the backstop (25).
    #[serde(default)]
    pub auto_freeze_after_blocks: u32,
    /// The agent can no longer pay at or after this time (ms since the Unix epoch).
    #[serde(default)]
    pub expires_at_ms: Option<U64>,
}

impl Policy {
    fn validate(&mut self, now_ms: u64) {
        self.allowlist.sort();
        self.allowlist.dedup();
        require!(self.max_per_payment.0 > 0, "max_per_payment must be > 0");
        require!(self.daily_limit.0 > 0, "daily_limit must be > 0");
        require!(
            (1..=MAX_RATE).contains(&self.max_payments_per_hour),
            "max_payments_per_hour must be between 1 and 300"
        );
        require!(
            self.auto_freeze_after_blocks <= HARD_FREEZE_BACKSTOP,
            "auto_freeze_after_blocks must be at most 25"
        );
        require!(self.allowlist.len() <= MAX_ALLOWLIST, "allowlist can hold at most 100 accounts");
        if let Some(e) = self.expires_at_ms {
            require!(e.0 > now_ms, "expires_at_ms must be in the future");
        }
    }

    fn allowlisted(&self, id: &AccountId) -> bool {
        self.allowlist.binary_search(id).is_ok()
    }
}

#[near(serializers = [json, borsh])]
#[derive(Clone, Debug, Default, PartialEq)]
pub struct AgentCounters {
    pub paid: u32,
    pub blocked: u32,
    pub escalated: u32,
    pub tripped: u32,
    pub approved: u32,
    pub rejected: u32,
    pub expired: u32,
    pub failed: u32,
    pub blocked_while_frozen: u32,
    pub reports: u32,
}

#[near(serializers = [borsh])]
#[derive(Clone, Debug)]
pub struct AgentState {
    pub label: String,
    pub policy: Policy,
    pub status: AgentStatus,
    /// (hour since the epoch, yoctoNEAR paid in that hour), for the last 24-25 hours.
    pub hourly_spend: Vec<(u64, u128)>,
    /// When paid or queued requests were made, last hour only.
    pub recent_payments: Vec<u64>,
    /// When blocked requests were made, last hour only.
    pub recent_blocks: Vec<u64>,
    pub pending_ids: Vec<u64>,
    pub total_spent: u128,
    pub payee_count: u32,
    pub counters: AgentCounters,
    /// Also the epoch of this agent's payee records: re-registering starts fresh.
    pub created_at_ms: u64,
}

impl AgentState {
    fn new(label: String, policy: Policy, now_ms: u64) -> Self {
        Self {
            label,
            policy,
            status: AgentStatus::Active,
            hourly_spend: Vec::new(),
            recent_payments: Vec::new(),
            recent_blocks: Vec::new(),
            pending_ids: Vec::new(),
            total_spent: 0,
            payee_count: 0,
            counters: AgentCounters::default(),
            created_at_ms: now_ms,
        }
    }

    fn is_frozen(&self) -> bool {
        matches!(self.status, AgentStatus::Frozen { .. })
    }

    /// Drop spend buckets older than 24 hours and timestamps older than an hour.
    /// A bucket is kept for 24-25 hours, so no 24-hour window can exceed the daily limit.
    fn prune(&mut self, now_ms: u64) {
        let hour = now_ms / HOUR_MS;
        self.hourly_spend.retain(|(b, amount)| b + 24 >= hour && *amount > 0);
        self.recent_payments.retain(|t| t + HOUR_MS > now_ms);
        self.recent_blocks.retain(|t| t + HOUR_MS > now_ms);
    }

    fn spent_24h(&self) -> u128 {
        self.hourly_spend.iter().fold(0u128, |acc, (_, a)| acc.saturating_add(*a))
    }

    fn add_spend(&mut self, now_ms: u64, amount: u128) {
        let hour = now_ms / HOUR_MS;
        match self.hourly_spend.iter_mut().find(|(b, _)| *b == hour) {
            Some((_, a)) => *a = a.saturating_add(amount),
            None => self.hourly_spend.push((hour, amount)),
        }
    }

    fn payments_last_hour(&self, now_ms: u64) -> u32 {
        self.recent_payments.iter().filter(|t| **t + HOUR_MS > now_ms).count() as u32
    }

    fn blocks_last_hour(&self, now_ms: u64) -> u32 {
        self.recent_blocks.iter().filter(|t| **t + HOUR_MS > now_ms).count() as u32
    }
}

/// A request waiting for the owner. Its amount is reserved until it is settled.
#[near(serializers = [json, borsh])]
#[derive(Clone, Debug, PartialEq)]
pub struct PendingPayment {
    pub id: U64,
    pub agent_id: AccountId,
    pub receiver_id: AccountId,
    pub amount: U128,
    pub memo: Option<String>,
    pub reasons: Vec<Reason>,
    pub created_at_ms: U64,
    pub expires_at_ms: U64,
}

#[near(serializers = [borsh])]
#[derive(Clone, Debug)]
pub struct BlockEntry {
    pub status: BlockStatus,
    pub reason: String,
    pub evidence: Option<String>,
    pub reporter: AccountId,
    pub confirmed_by: Option<AccountId>,
    pub at_ms: u64,
    pub reports: u32,
}

/// What one agent has paid one receiver.
#[near(serializers = [json, borsh])]
#[derive(Clone, Debug, PartialEq)]
pub struct PayeeStat {
    pub count: u32,
    pub total: U128,
    pub first_ms: U64,
    pub last_ms: U64,
}

/// One activity record. The same data is logged as a NEP-297 `EVENT_JSON` event.
#[near(serializers = [json, borsh])]
#[derive(Clone, Debug)]
pub struct LogEntry {
    pub seq: U64,
    pub at_ms: U64,
    pub block_height: U64,
    pub kind: EventKind,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub agent_id: Option<AccountId>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub receiver_id: Option<AccountId>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub amount: Option<U128>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub request_id: Option<U64>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub reasons: Vec<Reason>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub note: Option<String>,
    pub by: AccountId,
}

#[near(serializers = [json, borsh])]
#[derive(Clone, Debug, Default)]
pub struct Stats {
    pub requests: u64,
    pub paid: u64,
    pub paid_total: U128,
    pub blocked: u64,
    pub escalated: u64,
    pub tripped: u64,
    pub approved: u64,
    pub rejected: u64,
    pub expired: u64,
    pub failed: u64,
    pub freezes: u64,
    pub blocked_while_frozen: u64,
    pub blocked_while_paused: u64,
    pub reports: u64,
    pub canaries_added: u64,
}

/// What `request_payment` and `approve` return (directly, or from the settlement callback).
#[near(serializers = [json])]
#[derive(Clone, Debug, PartialEq)]
pub struct PaymentResult {
    pub status: PaymentStatus,
    pub request_id: U64,
    pub reasons: Vec<Reason>,
    pub amount: U128,
    pub receiver_id: AccountId,
    pub frozen: bool,
}

#[near(serializers = [json])]
#[derive(Clone, Debug, PartialEq)]
pub struct CheckResult {
    pub verdict: Verdict,
    pub reasons: Vec<Reason>,
}

#[near(serializers = [json])]
#[derive(Clone, Debug, PartialEq)]
pub struct AgentView {
    pub agent_id: AccountId,
    pub label: String,
    pub status: AgentStatus,
    pub policy: Policy,
    pub spent_24h: U128,
    pub remaining_24h: U128,
    pub reserved: U128,
    pub payments_last_hour: u32,
    pub blocks_last_hour: u32,
    pub pending_ids: Vec<U64>,
    pub total_spent: U128,
    pub payee_count: u32,
    pub counters: AgentCounters,
    pub created_at_ms: U64,
}

#[near(serializers = [json])]
#[derive(Clone, Debug, PartialEq)]
pub struct BlocklistView {
    pub account_id: AccountId,
    pub status: BlockStatus,
    pub reason: String,
    pub evidence: Option<String>,
    pub reporter: AccountId,
    pub confirmed_by: Option<AccountId>,
    pub at_ms: U64,
    pub reports: u32,
}

#[near(serializers = [json])]
#[derive(Clone, Debug, PartialEq)]
pub struct ConfigView {
    pub version: String,
    pub owner_id: AccountId,
    pub pending_owner: Option<AccountId>,
    pub guardians: Vec<AccountId>,
    pub paused: bool,
    pub pause_reason: Option<String>,
    pub agents: u32,
    pub canaries: u32,
    pub blocklist: u32,
    pub open_reports: u32,
    pub pending: u32,
    pub reserved: U128,
    pub balance: U128,
    pub storage_locked: U128,
    pub available: U128,
    pub activity_written: U64,
    pub ring_capacity: u32,
}

// ------------------------------------------------------------------------------------------
// State
// ------------------------------------------------------------------------------------------

#[near(contract_state)]
#[derive(PanicOnDefault)]
pub struct Tripwire {
    owner_id: AccountId,
    pending_owner: Option<AccountId>,
    /// Sorted, so membership is a binary search.
    guardians: Vec<AccountId>,
    agents: IterableMap<AccountId, AgentState>,
    /// sha256 of each canary account id. The ids themselves are never stored.
    canaries: LookupSet<CryptoHash>,
    canary_count: u32,
    blocklist: IterableMap<AccountId, BlockEntry>,
    open_reports: u32,
    /// Keyed by sha256("agent|epoch|receiver").
    payees: LookupMap<CryptoHash, PayeeStat>,
    pending: IterableMap<u64, PendingPayment>,
    /// Sum of all pending amounts. It is never paid out by anything else.
    reserved: u128,
    activity: Vector<LogEntry>,
    log_written: u64,
    next_request_id: u64,
    paused: bool,
    pause_reason: Option<String>,
    stats: Stats,
}

// ------------------------------------------------------------------------------------------
// Free helpers
// ------------------------------------------------------------------------------------------

/// Cut a string to at most `max` bytes without splitting a UTF-8 character.
fn truncate_utf8(s: &mut String, max: usize) {
    if s.len() > max {
        let mut cut = max;
        while !s.is_char_boundary(cut) {
            cut -= 1;
        }
        s.truncate(cut);
    }
}

/// True when a block is caused only by the vault's own state (balance or approval queue),
/// possibly alongside soft signals, and not by any limit the agent itself broke.
fn is_environmental_block(reasons: &[Reason]) -> bool {
    let env_reason = |r: &Reason| matches!(r, Reason::InsufficientVaultBalance | Reason::TooManyPending);
    reasons.iter().any(env_reason)
        && reasons.iter().all(|r| {
            env_reason(r) || matches!(r, Reason::NewPayee | Reason::NeedsApproval | Reason::ReportedReceiver)
        })
}

/// Balance not needed for this account's storage stake.
fn free_balance_yocto() -> u128 {
    let locked = env::storage_byte_cost().as_yoctonear().saturating_mul(env::storage_usage() as u128);
    env::account_balance().as_yoctonear().saturating_sub(locked)
}

fn account_hash(id: &AccountId) -> CryptoHash {
    env::sha256_array(id.as_str())
}

/// Account ids cannot contain '|', so the key is unambiguous.
fn payee_key(agent_id: &AccountId, epoch: u64, receiver_id: &AccountId) -> CryptoHash {
    env::sha256_array(format!("{agent_id}|{epoch}|{receiver_id}"))
}

fn nibble(c: u8) -> Option<u8> {
    match c {
        b'0'..=b'9' => Some(c - b'0'),
        b'a'..=b'f' => Some(c - b'a' + 10),
        b'A'..=b'F' => Some(c - b'A' + 10),
        _ => None,
    }
}

fn parse_hash(s: &str) -> CryptoHash {
    let b = s.trim().as_bytes();
    if b.len() != 64 {
        env::panic_str(HASH_ERROR);
    }
    let mut out = [0u8; 32];
    for (i, pair) in b.chunks(2).enumerate() {
        match (nibble(pair[0]), nibble(pair[1])) {
            (Some(hi), Some(lo)) => out[i] = (hi << 4) | lo,
            _ => env::panic_str(HASH_ERROR),
        }
    }
    out
}

#[cfg(test)]
pub(crate) fn to_hex(h: &CryptoHash) -> String {
    h.iter().map(|b| format!("{b:02x}")).collect()
}

/// Characters that render as nothing or reorder text: zero-width characters, bidi controls,
/// invisible operators, variation selectors and Unicode tag characters.
fn is_hidden_char(c: char) -> bool {
    matches!(c as u32,
        0x00AD | 0x034F | 0x061C | 0x115F | 0x1160 | 0x17B4 | 0x17B5 | 0x180E
        | 0x200B..=0x200F | 0x202A..=0x202E | 0x2060..=0x2064 | 0x2066..=0x2069
        | 0x3164 | 0xFE00..=0xFE0F | 0xFEFF | 0xFFA0 | 0xFFF9..=0xFFFB
        | 0x1D173..=0x1D17A | 0xE0000..=0xE007F | 0xE0100..=0xE01EF)
}

/// Make untrusted text safe to store and display: drop hidden characters, turn control
/// characters and line separators into spaces, trim, and cap the length in bytes.
fn clean_text(s: &str, max: usize) -> String {
    let mut out = String::new();
    for c in s.chars() {
        if is_hidden_char(c) {
            continue;
        }
        let c = if c.is_control() || c == '\u{2028}' || c == '\u{2029}' { ' ' } else { c };
        if out.is_empty() && c.is_whitespace() {
            continue;
        }
        if out.len() + c.len_utf8() > max {
            break;
        }
        out.push(c);
    }
    let end = out.trim_end().len();
    out.truncate(end);
    out
}

fn clipped(mut s: String, max: usize) -> String {
    truncate_utf8(&mut s, max);
    s
}

/// Optional untrusted text: cleaned, and `None` when nothing is left.
fn clean_opt(s: Option<String>, max: usize) -> Option<String> {
    s.map(|s| clean_text(&s, max)).filter(|s| !s.is_empty())
}

/// A new activity record. Only for change methods: views cannot read the predecessor.
fn new_entry(kind: EventKind) -> LogEntry {
    LogEntry {
        seq: U64(0),
        at_ms: U64(env::block_timestamp_ms()),
        block_height: U64(env::block_height()),
        kind,
        agent_id: None,
        receiver_id: None,
        amount: None,
        request_id: None,
        reasons: Vec::new(),
        note: None,
        by: env::predecessor_account_id(),
    }
}

fn pending_entry(kind: EventKind, p: &PendingPayment) -> LogEntry {
    let mut e = new_entry(kind);
    e.agent_id = Some(p.agent_id.clone());
    e.receiver_id = Some(p.receiver_id.clone());
    e.amount = Some(p.amount);
    e.request_id = Some(p.id);
    e.reasons = p.reasons.clone();
    e
}

fn block_view_of(id: &AccountId, e: &BlockEntry) -> BlocklistView {
    BlocklistView {
        account_id: id.clone(),
        status: e.status,
        reason: e.reason.clone(),
        evidence: e.evidence.clone(),
        reporter: e.reporter.clone(),
        confirmed_by: e.confirmed_by.clone(),
        at_ms: U64(e.at_ms),
        reports: e.reports,
    }
}

fn page(from_index: Option<u32>, limit: Option<u32>, default: u32, max: u32) -> (usize, usize) {
    (from_index.unwrap_or(0) as usize, limit.unwrap_or(default).min(max) as usize)
}

// ------------------------------------------------------------------------------------------
// Internal methods (not exported)
// ------------------------------------------------------------------------------------------

impl Tripwire {
    /// Spendable balance if `released` stopped being reserved.
    fn available_after_release(&self, released: u128) -> u128 {
        free_balance_yocto()
            .saturating_sub(self.reserved.saturating_sub(released))
            .saturating_sub(STORAGE_MARGIN.as_yoctonear())
    }

    fn available(&self) -> u128 {
        self.available_after_release(0)
    }

    fn live_reserved(&self, a: &AgentState, now_ms: u64) -> u128 {
        a.pending_ids
            .iter()
            .filter_map(|id| self.pending.get(id))
            .filter(|p| p.expires_at_ms.0 > now_ms)
            .fold(0u128, |acc, p| acc.saturating_add(p.amount.0))
    }

    fn assert_owner(&self) {
        require!(env::predecessor_account_id() == self.owner_id, "Only the owner can call this method");
    }

    fn assert_owner_or_guardian(&self) -> AccountId {
        let by = env::predecessor_account_id();
        require!(self.is_privileged(&by), "Only the owner or a guardian can call this method");
        by
    }

    fn is_privileged(&self, id: &AccountId) -> bool {
        *id == self.owner_id || self.guardians.binary_search(id).is_ok()
    }

    /// Remove a blocklist entry and log it. Returns false if there was none.
    fn unblock_internal(&mut self, receiver_id: AccountId) -> bool {
        let Some(old) = self.blocklist.remove(&receiver_id) else {
            return false;
        };
        if old.status == BlockStatus::Reported {
            self.open_reports = self.open_reports.saturating_sub(1);
        }
        let mut e = new_entry(EventKind::Unblocklisted);
        e.receiver_id = Some(receiver_id);
        self.emit(e, true);
        true
    }

    fn is_guardian(&self, id: &AccountId) -> bool {
        self.guardians.binary_search(id).is_ok()
    }

    /// Log a NEP-297 event. With `keep`, also give it a sequence number and store it in the
    /// activity ring. Quiet events (repeats and spam) are only logged.
    fn emit(&mut self, mut entry: LogEntry, keep: bool) {
        let kind = entry.kind;
        if keep {
            entry.seq = U64(self.log_written);
        }
        let mut data = serde_json::to_value(&entry).unwrap_or_else(|_| env::panic_str("event serialization failed"));
        if let Some(obj) = data.as_object_mut() {
            obj.remove("kind");
            if !keep {
                obj.remove("seq");
            }
        }
        if keep {
            if self.activity.len() < RING_CAP {
                self.activity.push(entry);
            } else {
                self.activity.set((self.log_written % RING_CAP as u64) as u32, entry);
            }
            self.log_written += 1;
        }
        let event = json!({
            "standard": EVENT_STANDARD,
            "version": VERSION,
            "event": kind,
            "data": [data],
        });
        env::log_str(&format!("EVENT_JSON:{event}"));
    }

    /// Remove a pending request and release its reservation.
    fn take_pending(&mut self, id: u64) -> Option<PendingPayment> {
        let p = self.pending.remove(&id)?;
        self.reserved = self.reserved.saturating_sub(p.amount.0);
        if let Some(a) = self.agents.get_mut(&p.agent_id) {
            a.pending_ids.retain(|x| *x != id);
        }
        Some(p)
    }

    fn record_expired(&mut self, p: &PendingPayment) {
        if let Some(a) = self.agents.get_mut(&p.agent_id) {
            a.counters.expired += 1;
        }
        self.stats.expired += 1;
        self.emit(pending_entry(EventKind::Expired, p), true);
    }

    /// Expire this agent's stale requests, so they stop counting against its limits.
    fn expire_agent_pending(&mut self, agent_id: &AccountId, now_ms: u64) {
        let ids = match self.agents.get(agent_id) {
            Some(a) => a.pending_ids.clone(),
            None => return,
        };
        let mut expired = Vec::new();
        let mut missing = Vec::new();
        for id in ids {
            match self.pending.get(&id) {
                Some(p) if p.expires_at_ms.0 > now_ms => {}
                Some(_) => expired.push(id),
                None => missing.push(id),
            }
        }
        for id in expired {
            if let Some(p) = self.take_pending(id) {
                self.record_expired(&p);
            }
        }
        if !missing.is_empty() {
            if let Some(a) = self.agents.get_mut(agent_id) {
                a.pending_ids.retain(|x| !missing.contains(x));
            }
        }
    }

    fn expire_stale_internal(&mut self, limit: u32, now_ms: u64) -> u32 {
        let ids: Vec<u64> = self
            .pending
            .iter()
            .filter(|(_, p)| p.expires_at_ms.0 <= now_ms)
            .map(|(id, _)| *id)
            .take(limit as usize)
            .collect();
        for id in &ids {
            if let Some(p) = self.take_pending(*id) {
                self.record_expired(&p);
            }
        }
        ids.len() as u32
    }

    /// Reject every pending request of an agent. The events are quiet: the caller's own
    /// event says how many were cancelled.
    fn cancel_all_pending(&mut self, agent_id: &AccountId, note: &str) -> u32 {
        let ids = match self.agents.get(agent_id) {
            Some(a) => a.pending_ids.clone(),
            None => return 0,
        };
        let mut n = 0u32;
        for id in ids {
            if let Some(p) = self.pending.remove(&id) {
                self.reserved = self.reserved.saturating_sub(p.amount.0);
                let mut e = pending_entry(EventKind::Rejected, &p);
                e.note = Some(note.to_string());
                self.emit(e, false);
                n += 1;
            }
        }
        if let Some(a) = self.agents.get_mut(agent_id) {
            a.pending_ids.clear();
            a.counters.rejected += n;
        }
        self.stats.rejected += n as u64;
        n
    }

    fn freeze_internal(&mut self, agent_id: &AccountId, reason: &str, by: AccountId) -> u32 {
        let n = self.cancel_all_pending(agent_id, "cancelled by freeze");
        let reason = clean_text(reason, REASON_MAX);
        let now = env::block_timestamp_ms();
        if let Some(a) = self.agents.get_mut(agent_id) {
            a.status = AgentStatus::Frozen { reason: reason.clone(), by: by.clone(), at_ms: U64(now) };
        }
        self.stats.freezes += 1;
        let mut note = clipped(reason, NOTE_MAX - 32);
        if n > 0 {
            note.push_str(&format!(" (cancelled {n} pending)"));
        }
        let mut e = new_entry(EventKind::Frozen);
        e.agent_id = Some(agent_id.clone());
        e.note = Some(note);
        e.by = by;
        self.emit(e, true);
        n
    }

    /// Record a payment to a receiver. Returns true if the agent never paid it before.
    fn bump_payee(&mut self, agent_id: &AccountId, epoch: u64, receiver_id: &AccountId, amount: u128, now_ms: u64) -> bool {
        let key = payee_key(agent_id, epoch, receiver_id);
        match self.payees.get_mut(&key) {
            Some(s) => {
                s.count += 1;
                s.total = U128(s.total.0.saturating_add(amount));
                s.last_ms = U64(now_ms);
                false
            }
            None => {
                let stat = PayeeStat { count: 1, total: U128(amount), first_ms: U64(now_ms), last_ms: U64(now_ms) };
                self.payees.insert(key, stat);
                true
            }
        }
    }

    /// Transfer, then settle in `on_payment_settled` (which rolls back if the transfer fails).
    fn payment_promise(request_id: u64, agent_id: AccountId, receiver_id: AccountId, amount: u128, at_ms: u64) -> Promise {
        Promise::new(receiver_id.clone()).transfer(NearToken::from_yoctonear(amount)).then(
            Self::ext(env::current_account_id())
                .with_static_gas(CALLBACK_GAS)
                .with_unused_gas_weight(0)
                .on_payment_settled(U64(request_id), agent_id, receiver_id, U128(amount), U64(at_ms)),
        )
    }

    fn view_of(&self, agent_id: &AccountId, stored: &AgentState, now_ms: u64) -> AgentView {
        let mut a = stored.clone();
        a.prune(now_ms);
        let reserved = self.live_reserved(&a, now_ms);
        let spent = a.spent_24h();
        let pending_ids = a
            .pending_ids
            .iter()
            .filter(|id| self.pending.get(*id).is_some_and(|p| p.expires_at_ms.0 > now_ms))
            .map(|id| U64(*id))
            .collect();
        AgentView {
            agent_id: agent_id.clone(),
            label: a.label.clone(),
            status: a.status.clone(),
            policy: a.policy.clone(),
            spent_24h: U128(spent),
            remaining_24h: U128(a.policy.daily_limit.0.saturating_sub(spent).saturating_sub(reserved)),
            reserved: U128(reserved),
            payments_last_hour: a.payments_last_hour(now_ms),
            blocks_last_hour: a.blocks_last_hour(now_ms),
            pending_ids,
            total_spent: U128(a.total_spent),
            payee_count: a.payee_count,
            counters: a.counters.clone(),
            created_at_ms: U64(a.created_at_ms),
        }
    }

    fn agent_view(&self, agent_id: &AccountId, now_ms: u64) -> AgentView {
        let a = self.agents.get(agent_id).unwrap_or_else(|| env::panic_str("Unknown agent"));
        self.view_of(agent_id, a, now_ms)
    }

    /// The policy check. `a` must already be pruned. With `check_canary` false (the public
    /// dry run), canaries look like ordinary receivers.
    fn evaluate(
        &self,
        agent_id: &AccountId,
        a: &AgentState,
        receiver_id: &AccountId,
        amount: u128,
        now_ms: u64,
        check_canary: bool,
    ) -> (Verdict, Vec<Reason>) {
        if a.is_frozen() {
            return (Verdict::Block, vec![Reason::AgentFrozen]);
        }
        if check_canary && self.canaries.contains(&account_hash(receiver_id)) {
            return (Verdict::Trip, vec![Reason::Tripwire]);
        }
        if self.paused {
            return (Verdict::Block, vec![Reason::VaultPaused]);
        }
        let p = &a.policy;
        if p.expires_at_ms.is_some_and(|e| now_ms >= e.0) {
            return (Verdict::Block, vec![Reason::PolicyExpired]);
        }

        let listed = self.blocklist.get(receiver_id).map(|e| e.status);
        let allowlisted = p.allowlisted(receiver_id);
        let mut block = Vec::new();
        if receiver_id == agent_id || *receiver_id == env::current_account_id() {
            block.push(Reason::SelfPayment);
        }
        if listed == Some(BlockStatus::Confirmed) {
            block.push(Reason::Blocklisted);
        }
        if amount == 0 {
            block.push(Reason::ZeroAmount);
        }
        if p.allowlist_only && !allowlisted {
            block.push(Reason::NotAllowlisted);
        }
        if amount > p.max_per_payment.0 {
            block.push(Reason::OverPerPaymentCap);
        }
        if a.payments_last_hour(now_ms) >= p.max_payments_per_hour {
            block.push(Reason::RateLimited);
        }
        let committed = a.spent_24h().saturating_add(self.live_reserved(a, now_ms));
        if committed.saturating_add(amount) > p.daily_limit.0 {
            block.push(Reason::OverDailyLimit);
        }
        if amount > self.available() {
            block.push(Reason::InsufficientVaultBalance);
        }
        if !block.is_empty() {
            return (Verdict::Block, block);
        }

        let mut warn = Vec::new();
        if !allowlisted && listed == Some(BlockStatus::Reported) {
            warn.push(Reason::ReportedReceiver);
        }
        if !allowlisted
            && !self.payees.contains_key(&payee_key(agent_id, a.created_at_ms, receiver_id))
            && (amount > p.new_payee_limit.0 || a.payee_count >= MAX_PAYEES_PER_AGENT)
        {
            warn.push(Reason::NewPayee);
        }
        if amount > p.approval_threshold.0 {
            warn.push(Reason::NeedsApproval);
        }
        if warn.is_empty() {
            return (Verdict::Allow, warn);
        }
        let live_pending = a
            .pending_ids
            .iter()
            .filter(|id| self.pending.get(*id).is_some_and(|p| p.expires_at_ms.0 > now_ms))
            .count();
        if live_pending >= MAX_PENDING_PER_AGENT || self.pending.len() >= MAX_PENDING_TOTAL {
            warn.push(Reason::TooManyPending);
            return (Verdict::Block, warn);
        }
        (Verdict::Warn, warn)
    }

    /// The body of `request_payment`. Returns the transfer promise when the payment is sent.
    fn submit_payment(&mut self, receiver_id: AccountId, amount: U128, memo: Option<String>) -> (PaymentResult, Option<Promise>) {
        let agent_id = env::predecessor_account_id();
        require!(self.agents.contains_key(&agent_id), "Caller is not a registered agent");
        let now = env::block_timestamp_ms();
        let request_id = self.next_request_id;
        self.next_request_id += 1;
        self.stats.requests += 1;
        let memo = clean_opt(memo, MEMO_MAX);

        self.expire_agent_pending(&agent_id, now);
        if self.pending.len() >= MAX_PENDING_TOTAL {
            self.expire_stale_internal(EXPIRE_IN_REQUEST, now);
        }
        let mut a = self.agents.get(&agent_id).cloned().unwrap_or_else(|| env::panic_str("Unknown agent"));
        a.prune(now);
        let amt = amount.0;
        let (verdict, reasons) = self.evaluate(&agent_id, &a, &receiver_id, amt, now, true);

        let mut entry = new_entry(EventKind::Blocked);
        entry.agent_id = Some(agent_id.clone());
        entry.receiver_id = Some(receiver_id.clone());
        entry.amount = Some(amount);
        entry.request_id = Some(U64(request_id));
        entry.reasons = reasons.clone();
        entry.note = memo.clone().map(|m| clipped(m, NOTE_MAX));

        let mut result = PaymentResult {
            status: PaymentStatus::Blocked,
            request_id: U64(request_id),
            reasons,
            amount,
            receiver_id: receiver_id.clone(),
            frozen: a.is_frozen(),
        };

        match verdict {
            Verdict::Trip => {
                a.counters.tripped += 1;
                self.stats.tripped += 1;
                self.agents.insert(agent_id.clone(), a);
                entry.kind = EventKind::Tripped;
                self.emit(entry, true);
                self.freeze_internal(&agent_id, "TRIPWIRE: attempted payment to a canary payee", env::current_account_id());
                result.status = PaymentStatus::Tripped;
                result.frozen = true;
                (result, None)
            }
            // Repeats while frozen or paused are logged quietly and do not count as new blocks.
            Verdict::Block if result.reasons == [Reason::AgentFrozen] => {
                a.counters.blocked_while_frozen += 1;
                self.stats.blocked_while_frozen += 1;
                self.agents.insert(agent_id, a);
                self.emit(entry, false);
                result.frozen = true;
                (result, None)
            }
            Verdict::Block if result.reasons == [Reason::VaultPaused] => {
                self.stats.blocked_while_paused += 1;
                self.agents.insert(agent_id, a);
                self.emit(entry, false);
                (result, None)
            }
            // Environmental blocks (vault balance or a full approval queue, possibly with soft
            // signals) are counted but do not count toward auto-freeze.
            Verdict::Block if is_environmental_block(&result.reasons) => {
                a.counters.blocked += 1;
                self.stats.blocked += 1;
                self.agents.insert(agent_id, a);
                self.emit(entry, true);
                (result, None)
            }
            Verdict::Block => {
                a.counters.blocked += 1;
                self.stats.blocked += 1;
                a.recent_blocks.push(now);
                let threshold = match a.policy.auto_freeze_after_blocks {
                    0 => HARD_FREEZE_BACKSTOP,
                    n => n.min(HARD_FREEZE_BACKSTOP),
                };
                let n = a.blocks_last_hour(now);
                self.agents.insert(agent_id.clone(), a);
                self.emit(entry, true);
                if n >= threshold {
                    let reason = format!("AUTO_FREEZE: {n} blocked payment attempts within 1h");
                    self.freeze_internal(&agent_id, &reason, env::current_account_id());
                    result.frozen = true;
                }
                (result, None)
            }
            Verdict::Warn => {
                let p = PendingPayment {
                    id: U64(request_id),
                    agent_id: agent_id.clone(),
                    receiver_id,
                    amount,
                    memo,
                    reasons: result.reasons.clone(),
                    created_at_ms: U64(now),
                    expires_at_ms: U64(now + PENDING_TTL_MS),
                };
                self.pending.insert(request_id, p);
                self.reserved = self.reserved.saturating_add(amt);
                a.pending_ids.push(request_id);
                a.recent_payments.push(now);
                a.counters.escalated += 1;
                self.stats.escalated += 1;
                self.agents.insert(agent_id, a);
                entry.kind = EventKind::Escalated;
                self.emit(entry, true);
                result.status = PaymentStatus::PendingApproval;
                (result, None)
            }
            Verdict::Allow => {
                a.add_spend(now, amt);
                a.recent_payments.push(now);
                a.total_spent = a.total_spent.saturating_add(amt);
                a.counters.paid += 1;
                self.stats.paid += 1;
                self.stats.paid_total = U128(self.stats.paid_total.0.saturating_add(amt));
                let epoch = a.created_at_ms;
                if self.bump_payee(&agent_id, epoch, &receiver_id, amt, now) {
                    a.payee_count += 1;
                }
                self.agents.insert(agent_id.clone(), a);
                entry.kind = EventKind::Paid;
                self.emit(entry, true);
                result.status = PaymentStatus::Paid;
                let promise = Self::payment_promise(request_id, agent_id, receiver_id, amt, now);
                (result, Some(promise))
            }
        }
    }
}

// ------------------------------------------------------------------------------------------
// Public interface
// ------------------------------------------------------------------------------------------

#[near]
impl Tripwire {
    /// Deploy and call this with the vault account's own key (it is private).
    #[init]
    #[private]
    #[deny_unknown_arguments]
    pub fn new(owner_id: AccountId, guardians: Option<Vec<AccountId>>) -> Self {
        let mut guardians = guardians.unwrap_or_default();
        guardians.sort();
        guardians.dedup();
        require!(guardians.len() <= MAX_GUARDIANS, "Too many guardians (max 10)");
        require!(!guardians.contains(&owner_id), "The owner cannot also be a guardian");
        Self {
            owner_id,
            pending_owner: None,
            guardians,
            agents: IterableMap::new(StorageKey::Agents),
            canaries: LookupSet::new(StorageKey::Canaries),
            canary_count: 0,
            blocklist: IterableMap::new(StorageKey::Blocklist),
            open_reports: 0,
            payees: LookupMap::new(StorageKey::Payees),
            pending: IterableMap::new(StorageKey::Pending),
            reserved: 0,
            activity: Vector::new(StorageKey::Activity),
            log_written: 0,
            next_request_id: 1,
            paused: false,
            pause_reason: None,
            stats: Stats::default(),
        }
    }

    // --- Agent -------------------------------------------------------------------------------

    /// Ask the vault to pay `amount` yoctoNEAR to `receiver_id`. Paid requests return the
    /// settlement result; every other outcome returns immediately. Only registered agents.
    #[deny_unknown_arguments]
    pub fn request_payment(&mut self, receiver_id: AccountId, amount: U128, memo: Option<String>) -> PromiseOrValue<PaymentResult> {
        match self.submit_payment(receiver_id, amount, memo) {
            (_, Some(promise)) => PromiseOrValue::Promise(promise),
            (result, None) => PromiseOrValue::Value(result),
        }
    }

    /// Settlement callback for every outgoing payment. Rolls the spend back if the transfer
    /// failed (the runtime refunds the amount to the vault).
    #[private]
    pub fn on_payment_settled(
        &mut self,
        request_id: U64,
        agent_id: AccountId,
        receiver_id: AccountId,
        amount: U128,
        at_ms: U64,
        #[callback_result] result: Result<(), PromiseError>,
    ) -> PaymentResult {
        let mut out = PaymentResult {
            status: PaymentStatus::Paid,
            request_id,
            reasons: Vec::new(),
            amount,
            receiver_id: receiver_id.clone(),
            frozen: false,
        };
        if result.is_ok() {
            out.frozen = self.agents.get(&agent_id).is_some_and(|a| a.is_frozen());
            return out;
        }
        out.status = PaymentStatus::TransferFailed;
        let amt = amount.0;
        let bucket = at_ms.0 / HOUR_MS;
        if let Some(mut a) = self.agents.get(&agent_id).cloned() {
            if let Some(b) = a.hourly_spend.iter_mut().find(|(h, _)| *h == bucket) {
                b.1 = b.1.saturating_sub(amt);
            }
            a.total_spent = a.total_spent.saturating_sub(amt);
            a.counters.failed += 1;
            let key = payee_key(&agent_id, a.created_at_ms, &receiver_id);
            let mut forget = false;
            if let Some(s) = self.payees.get_mut(&key) {
                s.count = s.count.saturating_sub(1);
                s.total = U128(s.total.0.saturating_sub(amt));
                forget = s.count == 0;
            }
            if forget {
                self.payees.remove(&key);
                a.payee_count = a.payee_count.saturating_sub(1);
            }
            out.frozen = a.is_frozen();
            self.agents.insert(agent_id.clone(), a);
        }
        self.stats.paid_total = U128(self.stats.paid_total.0.saturating_sub(amt));
        self.stats.failed += 1;
        let mut e = new_entry(EventKind::TransferFailed);
        e.agent_id = Some(agent_id);
        e.receiver_id = Some(receiver_id);
        e.amount = Some(amount);
        e.request_id = Some(request_id);
        self.emit(e, true);
        out
    }

    /// An agent can always freeze itself, for example when it notices it is being steered.
    pub fn self_freeze(&mut self, reason: Option<String>) -> bool {
        let agent_id = env::predecessor_account_id();
        let frozen = self
            .agents
            .get(&agent_id)
            .map(|a| a.is_frozen())
            .unwrap_or_else(|| env::panic_str("Caller is not a registered agent"));
        if frozen {
            return false;
        }
        let r = clean_opt(reason, REASON_MAX - 16).unwrap_or_else(|| "agent requested a freeze".to_string());
        self.freeze_internal(&agent_id, &format!("SELF_FREEZE: {r}"), agent_id.clone());
        true
    }

    /// Report a suspicious receiver. Payments to it then need approval (unless allowlisted)
    /// until the owner or a guardian reviews it. Free for the owner, guardians and active
    /// agents (20 each); everyone else attaches 0.01 NEAR, which the vault keeps. A free
    /// agent report that adds a new entry needs the vault to afford its storage. The owner
    /// and guardians are not bound by the cap on open reports.
    #[payable]
    pub fn report_receiver(&mut self, receiver_id: AccountId, reason: String, evidence: Option<String>) -> BlocklistView {
        let by = env::predecessor_account_id();
        let free = self.is_privileged(&by)
            || self
                .agents
                .get(&by)
                .is_some_and(|a| !a.is_frozen() && a.counters.reports < MAX_FREE_REPORTS_PER_AGENT);
        require!(
            free || env::attached_deposit() >= REPORT_DEPOSIT,
            "Reports from this account need an attached deposit of 0.01 NEAR"
        );
        let reason = clean_text(&reason, REASON_MAX);
        require!(!reason.is_empty(), "reason is required");
        let evidence = clean_opt(evidence, EVIDENCE_MAX);
        let now = env::block_timestamp_ms();

        let existing = self.blocklist.get_mut(&receiver_id).map(|e| {
            e.reports = e.reports.saturating_add(1);
            if e.evidence.is_none() {
                e.evidence = evidence.clone();
            }
            e.clone()
        });
        let (view, keep) = match existing {
            Some(e) => (block_view_of(&receiver_id, &e), false),
            None => {
                let privileged = self.is_privileged(&by);
                require!(
                    privileged || self.open_reports < MAX_OPEN_REPORTS,
                    "Too many open reports (max 200); ask the owner or a guardian to review them"
                );
                require!(self.blocklist.len() < MAX_BLOCKLIST, "Blocklist is full (max 1000)");
                // A free report from an agent is paid for from the vault's balance.
                if free && !privileged {
                    require!(
                        self.available() >= REPORT_STORAGE_BYTES * env::storage_byte_cost().as_yoctonear(),
                        "Vault balance is too low to store a new report"
                    );
                }
                let e = BlockEntry {
                    status: BlockStatus::Reported,
                    reason: reason.clone(),
                    evidence,
                    reporter: by.clone(),
                    confirmed_by: None,
                    at_ms: now,
                    reports: 1,
                };
                let view = block_view_of(&receiver_id, &e);
                self.blocklist.insert(receiver_id.clone(), e);
                self.open_reports += 1;
                (view, true)
            }
        };
        if let Some(a) = self.agents.get_mut(&by) {
            a.counters.reports += 1;
        }
        self.stats.reports += 1;
        let mut e = new_entry(EventKind::Reported);
        e.receiver_id = Some(receiver_id);
        e.note = Some(clipped(reason, NOTE_MAX));
        self.emit(e, keep);
        view
    }

    // --- Owner (full-access key, 1 yoctoNEAR) --------------------------------------------------

    #[payable]
    #[deny_unknown_arguments]
    pub fn register_agent(&mut self, agent_id: AccountId, label: String, policy: Policy) -> AgentView {
        self.assert_owner();
        assert_one_yocto();
        require!(
            agent_id != env::current_account_id() && agent_id != self.owner_id && !self.is_guardian(&agent_id),
            "An agent must be a separate account from the vault, owner and guardians"
        );
        require!(!self.agents.contains_key(&agent_id), "Agent is already registered");
        require!(self.agents.len() < MAX_AGENTS, "Too many agents (max 200)");
        let now = env::block_timestamp_ms();
        let mut policy = policy;
        policy.validate(now);
        let label = clean_text(&label, LABEL_MAX);
        let a = AgentState::new(label.clone(), policy, now);
        let view = self.view_of(&agent_id, &a, now);
        self.agents.insert(agent_id.clone(), a);
        let mut e = new_entry(EventKind::AgentRegistered);
        e.agent_id = Some(agent_id);
        e.note = Some(label).filter(|l| !l.is_empty());
        self.emit(e, true);
        view
    }

    #[payable]
    #[deny_unknown_arguments]
    pub fn update_policy(&mut self, agent_id: AccountId, policy: Policy) -> AgentView {
        self.assert_owner();
        assert_one_yocto();
        require!(self.agents.contains_key(&agent_id), "Unknown agent");
        let now = env::block_timestamp_ms();
        let mut policy = policy;
        policy.validate(now);
        if let Some(a) = self.agents.get_mut(&agent_id) {
            a.policy = policy;
        }
        let mut e = new_entry(EventKind::PolicyUpdated);
        e.agent_id = Some(agent_id.clone());
        self.emit(e, true);
        self.agent_view(&agent_id, now)
    }

    /// Remove an agent and reject its pending requests. Returns how many were rejected.
    #[payable]
    pub fn remove_agent(&mut self, agent_id: AccountId) -> u32 {
        self.assert_owner();
        assert_one_yocto();
        require!(self.agents.contains_key(&agent_id), "Unknown agent");
        let n = self.cancel_all_pending(&agent_id, "cancelled by agent removal");
        self.agents.remove(&agent_id);
        let mut e = new_entry(EventKind::AgentRemoved);
        e.agent_id = Some(agent_id);
        e.note = Some(format!("cancelled {n} pending"));
        self.emit(e, true);
        n
    }

    #[payable]
    pub fn unfreeze_agent(&mut self, agent_id: AccountId) -> AgentView {
        self.assert_owner();
        assert_one_yocto();
        let now = env::block_timestamp_ms();
        let a = self.agents.get_mut(&agent_id).unwrap_or_else(|| env::panic_str("Unknown agent"));
        require!(a.is_frozen(), "Agent is not frozen");
        a.status = AgentStatus::Active;
        a.recent_blocks.clear();
        let mut e = new_entry(EventKind::Unfrozen);
        e.agent_id = Some(agent_id.clone());
        self.emit(e, true);
        self.agent_view(&agent_id, now)
    }

    #[payable]
    pub fn unpause(&mut self) {
        self.assert_owner();
        assert_one_yocto();
        require!(self.paused, "Vault is not paused");
        self.paused = false;
        self.pause_reason = None;
        self.emit(new_entry(EventKind::Unpaused), true);
    }

    /// Remove a receiver from the blocklist (reported or confirmed).
    #[payable]
    pub fn unblock_receiver(&mut self, receiver_id: AccountId) -> bool {
        self.assert_owner();
        assert_one_yocto();
        self.unblock_internal(receiver_id)
    }

    /// Remove several receivers from the blocklist (reported or confirmed), at most 100 per
    /// call. Returns how many entries were removed.
    #[payable]
    pub fn unblock_receivers(&mut self, receiver_ids: Vec<AccountId>) -> u32 {
        self.assert_owner();
        assert_one_yocto();
        require!(receiver_ids.len() <= MAX_UNBLOCK_PER_CALL, "At most 100 receivers per call");
        let mut removed = 0;
        for id in receiver_ids {
            if self.unblock_internal(id) {
                removed += 1;
            }
        }
        removed
    }

    #[payable]
    pub fn remove_canary(&mut self, hash: String) -> bool {
        self.assert_owner();
        assert_one_yocto();
        let h = parse_hash(&hash);
        if !self.canaries.remove(&h) {
            return false;
        }
        self.canary_count = self.canary_count.saturating_sub(1);
        self.emit(new_entry(EventKind::CanaryRemoved), true);
        true
    }

    /// Pay a pending request. This overrides its soft signals only: pause, freeze,
    /// blocklist, canaries and the vault balance are checked again.
    #[payable]
    pub fn approve(&mut self, request_id: U64) -> PromiseOrValue<PaymentResult> {
        self.assert_owner();
        assert_one_yocto();
        let now = env::block_timestamp_ms();
        let p = self
            .pending
            .get(&request_id.0)
            .cloned()
            .unwrap_or_else(|| env::panic_str("Unknown or already settled request"));
        if now >= p.expires_at_ms.0 {
            self.take_pending(p.id.0);
            self.record_expired(&p);
            return PromiseOrValue::Value(PaymentResult {
                status: PaymentStatus::Expired,
                request_id,
                reasons: p.reasons.clone(),
                amount: p.amount,
                receiver_id: p.receiver_id.clone(),
                frozen: self.agents.get(&p.agent_id).is_some_and(|a| a.is_frozen()),
            });
        }
        require!(!self.paused, "Vault is paused; unpause before approving");
        require!(
            self.agents.get(&p.agent_id).is_some_and(|a| !a.is_frozen()),
            "Agent is frozen; unfreeze it or reject this request"
        );
        require!(
            self.blocklist.get(&p.receiver_id).map(|e| e.status) != Some(BlockStatus::Confirmed),
            "Receiver is blocklisted; reject this request"
        );
        require!(
            !self.canaries.contains(&account_hash(&p.receiver_id)),
            "Receiver is on a hidden watchlist; reject this request"
        );
        let amt = p.amount.0;
        require!(amt <= self.available_after_release(amt), "Vault balance is too low for this payment");

        self.take_pending(p.id.0);
        let mut a = self.agents.get(&p.agent_id).cloned().unwrap_or_else(|| env::panic_str("Unknown agent"));
        a.prune(now);
        a.add_spend(now, amt);
        a.total_spent = a.total_spent.saturating_add(amt);
        a.counters.approved += 1;
        if self.bump_payee(&p.agent_id, a.created_at_ms, &p.receiver_id, amt, now) {
            a.payee_count += 1;
        }
        self.agents.insert(p.agent_id.clone(), a);
        self.stats.approved += 1;
        self.stats.paid_total = U128(self.stats.paid_total.0.saturating_add(amt));
        self.emit(pending_entry(EventKind::Approved, &p), true);
        PromiseOrValue::Promise(Self::payment_promise(p.id.0, p.agent_id, p.receiver_id, amt, now))
    }

    /// Send unreserved funds to the owner. Works while paused.
    #[payable]
    pub fn withdraw(&mut self, amount: U128) -> Promise {
        self.assert_owner();
        assert_one_yocto();
        require!(amount.0 > 0, "amount must be > 0");
        require!(amount.0 <= self.available(), "Amount exceeds the available balance");
        let mut e = new_entry(EventKind::Withdraw);
        e.amount = Some(amount);
        self.emit(e, true);
        Promise::new(self.owner_id.clone()).transfer(NearToken::from_yoctonear(amount.0))
    }

    #[payable]
    pub fn add_guardian(&mut self, account_id: AccountId) -> Vec<AccountId> {
        self.assert_owner();
        assert_one_yocto();
        require!(account_id != self.owner_id, "The owner cannot also be a guardian");
        require!(!self.agents.contains_key(&account_id), "An agent cannot be a guardian");
        match self.guardians.binary_search(&account_id) {
            Ok(_) => env::panic_str("Already a guardian"),
            Err(i) => {
                require!(self.guardians.len() < MAX_GUARDIANS, "Too many guardians (max 10)");
                self.guardians.insert(i, account_id.clone());
            }
        }
        let mut e = new_entry(EventKind::GuardianAdded);
        e.note = Some(account_id.to_string());
        self.emit(e, true);
        self.guardians.clone()
    }

    #[payable]
    pub fn remove_guardian(&mut self, account_id: AccountId) -> Vec<AccountId> {
        self.assert_owner();
        assert_one_yocto();
        match self.guardians.binary_search(&account_id) {
            Ok(i) => {
                self.guardians.remove(i);
            }
            Err(_) => env::panic_str("Not a guardian"),
        }
        let mut e = new_entry(EventKind::GuardianRemoved);
        e.note = Some(account_id.to_string());
        self.emit(e, true);
        self.guardians.clone()
    }

    /// Step one of an ownership transfer. Proposing your own account cancels a pending proposal.
    #[payable]
    pub fn propose_owner(&mut self, new_owner_id: AccountId) {
        self.assert_owner();
        assert_one_yocto();
        require!(!self.agents.contains_key(&new_owner_id), "An agent cannot be the owner");
        require!(
            !self.is_guardian(&new_owner_id),
            "Remove the account from the guardians before making it the owner"
        );
        let cancel = new_owner_id == self.owner_id;
        self.pending_owner = if cancel { None } else { Some(new_owner_id.clone()) };
        let mut e = new_entry(EventKind::OwnerProposed);
        e.note = Some(if cancel { "proposal cancelled".to_string() } else { new_owner_id.to_string() });
        self.emit(e, true);
    }

    /// Step two: the proposed owner accepts with its full-access key.
    #[payable]
    pub fn accept_owner(&mut self) {
        let new_owner = self.pending_owner.clone().unwrap_or_else(|| env::panic_str("No ownership transfer is pending"));
        require!(env::predecessor_account_id() == new_owner, "Only the proposed owner can accept ownership");
        assert_one_yocto();
        require!(!self.agents.contains_key(&new_owner), "An agent cannot be the owner");
        require!(
            !self.is_guardian(&new_owner),
            "Remove the account from the guardians before making it the owner"
        );
        let old = std::mem::replace(&mut self.owner_id, new_owner.clone());
        self.pending_owner = None;
        let mut e = new_entry(EventKind::OwnerChanged);
        e.note = Some(format!("{old} -> {new_owner}"));
        self.emit(e, true);
    }

    // --- Owner or guardian (free calls, can only tighten) ---------------------------------------

    /// Freeze an agent and reject its pending requests. Returns false if already frozen.
    pub fn freeze_agent(&mut self, agent_id: AccountId, reason: Option<String>) -> bool {
        let by = self.assert_owner_or_guardian();
        let frozen = self
            .agents
            .get(&agent_id)
            .map(|a| a.is_frozen())
            .unwrap_or_else(|| env::panic_str("Unknown agent"));
        if frozen {
            return false;
        }
        let default = if by == self.owner_id { "frozen by owner" } else { "frozen by guardian" };
        let reason = clean_opt(reason, REASON_MAX).unwrap_or_else(|| default.to_string());
        self.freeze_internal(&agent_id, &reason, by);
        true
    }

    /// Stop all payments. Canaries still trip while paused. Returns false if already paused.
    pub fn pause(&mut self, reason: Option<String>) -> bool {
        let by = self.assert_owner_or_guardian();
        if self.paused {
            return false;
        }
        let default = if by == self.owner_id { "paused by owner" } else { "paused by guardian" };
        let reason = clean_opt(reason, REASON_MAX).unwrap_or_else(|| default.to_string());
        self.paused = true;
        self.pause_reason = Some(reason.clone());
        let mut e = new_entry(EventKind::Paused);
        e.note = Some(clipped(reason, NOTE_MAX));
        self.emit(e, true);
        true
    }

    pub fn reject(&mut self, request_id: U64, reason: Option<String>) -> PendingPayment {
        self.assert_owner_or_guardian();
        let p = self
            .take_pending(request_id.0)
            .unwrap_or_else(|| env::panic_str("Unknown or already settled request"));
        if let Some(a) = self.agents.get_mut(&p.agent_id) {
            a.counters.rejected += 1;
        }
        self.stats.rejected += 1;
        let mut e = pending_entry(EventKind::Rejected, &p);
        e.note = clean_opt(reason, NOTE_MAX);
        self.emit(e, true);
        p
    }

    /// Dismiss an open report: removes the blocklist entry only while its status is
    /// `reported`. Returns false if there is no entry or it is already confirmed (only the
    /// owner can lift a confirmed entry, with `unblock_receiver`).
    pub fn dismiss_report(&mut self, receiver_id: AccountId) -> bool {
        self.assert_owner_or_guardian();
        if self.blocklist.get(&receiver_id).map(|e| e.status) != Some(BlockStatus::Reported) {
            return false;
        }
        self.unblock_internal(receiver_id)
    }

    /// Confirm a receiver as bad: payments to it are blocked for every agent.
    pub fn block_receiver(&mut self, receiver_id: AccountId, reason: String, evidence: Option<String>) -> BlocklistView {
        let by = self.assert_owner_or_guardian();
        let reason = clean_text(&reason, REASON_MAX);
        require!(!reason.is_empty(), "reason is required");
        let evidence = clean_opt(evidence, EVIDENCE_MAX);
        let now = env::block_timestamp_ms();
        let entry = match self.blocklist.get(&receiver_id).cloned() {
            Some(mut old) => {
                if old.status == BlockStatus::Reported {
                    self.open_reports = self.open_reports.saturating_sub(1);
                }
                old.status = BlockStatus::Confirmed;
                old.confirmed_by = Some(by.clone());
                old.reason = reason.clone();
                if evidence.is_some() {
                    old.evidence = evidence;
                }
                old.at_ms = now;
                old
            }
            None => {
                require!(self.blocklist.len() < MAX_BLOCKLIST, "Blocklist is full (max 1000)");
                BlockEntry {
                    status: BlockStatus::Confirmed,
                    reason: reason.clone(),
                    evidence,
                    reporter: by.clone(),
                    confirmed_by: Some(by.clone()),
                    at_ms: now,
                    reports: 0,
                }
            }
        };
        let view = block_view_of(&receiver_id, &entry);
        self.blocklist.insert(receiver_id.clone(), entry);
        let mut e = new_entry(EventKind::Blocklisted);
        e.receiver_id = Some(receiver_id);
        e.note = Some(clipped(reason, NOTE_MAX));
        self.emit(e, true);
        view
    }

    /// Add canaries: hex sha256 of decoy account ids. Returns how many were new.
    pub fn add_canaries(&mut self, hashes: Vec<String>) -> u32 {
        self.assert_owner_or_guardian();
        require!(hashes.len() <= MAX_CANARIES_PER_CALL, "At most 50 canaries per call");
        let mut fresh: Vec<CryptoHash> = Vec::new();
        for h in &hashes {
            let h = parse_hash(h);
            if !fresh.contains(&h) && !self.canaries.contains(&h) {
                fresh.push(h);
            }
        }
        let n = fresh.len() as u32;
        require!(self.canary_count + n <= MAX_CANARIES, "Too many canaries (max 1000)");
        for h in fresh {
            self.canaries.insert(h);
        }
        self.canary_count += n;
        self.stats.canaries_added += n as u64;
        if n > 0 {
            let mut e = new_entry(EventKind::CanariesAdded);
            e.note = Some(format!("added {n}"));
            self.emit(e, true);
        }
        n
    }

    // --- Anyone ------------------------------------------------------------------------------

    /// Fund the vault (a plain transfer works too). Returns the available balance.
    #[payable]
    pub fn deposit(&mut self) -> U128 {
        let amount = env::attached_deposit();
        require!(!amount.is_zero(), "Attach a deposit");
        let mut e = new_entry(EventKind::Deposit);
        e.amount = Some(U128(amount.as_yoctonear()));
        self.emit(e, amount >= RING_DEPOSIT_MIN);
        U128(self.available())
    }

    /// Expire stale pending requests (at most 20 per call) and release their reservations.
    pub fn expire_stale(&mut self, limit: Option<u32>) -> u32 {
        let limit = limit.unwrap_or(EXPIRE_DEFAULT).min(EXPIRE_MAX);
        self.expire_stale_internal(limit, env::block_timestamp_ms())
    }

    // --- Views -------------------------------------------------------------------------------

    pub fn get_config(&self) -> ConfigView {
        let locked = env::storage_byte_cost().as_yoctonear().saturating_mul(env::storage_usage() as u128);
        ConfigView {
            version: VERSION.to_string(),
            owner_id: self.owner_id.clone(),
            pending_owner: self.pending_owner.clone(),
            guardians: self.guardians.clone(),
            paused: self.paused,
            pause_reason: self.pause_reason.clone(),
            agents: self.agents.len(),
            canaries: self.canary_count,
            blocklist: self.blocklist.len(),
            open_reports: self.open_reports,
            pending: self.pending.len(),
            reserved: U128(self.reserved),
            balance: U128(env::account_balance().as_yoctonear()),
            storage_locked: U128(locked),
            available: U128(self.available()),
            activity_written: U64(self.log_written),
            ring_capacity: RING_CAP,
        }
    }

    pub fn get_stats(&self) -> Stats {
        self.stats.clone()
    }

    pub fn get_agent(&self, agent_id: AccountId) -> Option<AgentView> {
        let now = env::block_timestamp_ms();
        self.agents.get(&agent_id).map(|a| self.view_of(&agent_id, a, now))
    }

    pub fn list_agents(&self, from_index: Option<u32>, limit: Option<u32>) -> Vec<AgentView> {
        let (from, limit) = page(from_index, limit, 50, 50);
        let now = env::block_timestamp_ms();
        self.agents.iter().skip(from).take(limit).map(|(id, a)| self.view_of(id, a, now)).collect()
    }

    /// Dry run of `request_payment` for agent-side wrappers and dashboards. Changes nothing,
    /// and canaries are not revealed (they look like ordinary receivers here).
    pub fn check_payment(&self, agent_id: AccountId, receiver_id: AccountId, amount: U128) -> CheckResult {
        let now = env::block_timestamp_ms();
        let Some(stored) = self.agents.get(&agent_id) else {
            return CheckResult { verdict: Verdict::Block, reasons: vec![Reason::UnknownAgent] };
        };
        let mut a = stored.clone();
        a.prune(now);
        a.pending_ids.retain(|id| self.pending.get(id).is_some_and(|p| p.expires_at_ms.0 > now));
        let (verdict, reasons) = self.evaluate(&agent_id, &a, &receiver_id, amount.0, now, false);
        CheckResult { verdict, reasons }
    }

    pub fn get_pending(&self, from_index: Option<u32>, limit: Option<u32>) -> Vec<PendingPayment> {
        let (from, limit) = page(from_index, limit, 50, 100);
        self.pending.iter().skip(from).take(limit).map(|(_, p)| p.clone()).collect()
    }

    pub fn get_pending_request(&self, request_id: U64) -> Option<PendingPayment> {
        self.pending.get(&request_id.0).cloned()
    }

    /// Newest first. Pass the last `seq` you saw as `before_seq` to page back.
    pub fn get_activity(&self, before_seq: Option<U64>, limit: Option<u32>) -> Vec<LogEntry> {
        let limit = limit.unwrap_or(50).min(100) as usize;
        let written = self.log_written;
        let oldest = written - self.activity.len() as u64;
        let mut seq = before_seq.map(|s| s.0).unwrap_or(written).min(written);
        let mut out = Vec::new();
        while seq > oldest && out.len() < limit {
            seq -= 1;
            if let Some(e) = self.activity.get((seq % RING_CAP as u64) as u32) {
                out.push(e.clone());
            }
        }
        out
    }

    pub fn get_blocklist(&self, from_index: Option<u32>, limit: Option<u32>) -> Vec<BlocklistView> {
        let (from, limit) = page(from_index, limit, 50, 100);
        self.blocklist.iter().skip(from).take(limit).map(|(id, e)| block_view_of(id, e)).collect()
    }

    pub fn get_block_entry(&self, account_id: AccountId) -> Option<BlocklistView> {
        self.blocklist.get(&account_id).map(|e| block_view_of(&account_id, e))
    }

    pub fn get_payee(&self, agent_id: AccountId, receiver_id: AccountId) -> Option<PayeeStat> {
        let a = self.agents.get(&agent_id)?;
        self.payees.get(&payee_key(&agent_id, a.created_at_ms, &receiver_id)).cloned()
    }
}

#[cfg(test)]
mod tests;
