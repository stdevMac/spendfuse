#![allow(dead_code)]
//! Unit tests for the Tripwire vault. Run with `cargo test` (never with `--cfg near`).
//! The mocked VM does not enforce `#[private]`, `#[payable]`, init-once or unknown-argument
//! checks; those are covered by the testnet drills in `src/scripts/`.

use super::*;
use near_sdk::mock::MockAction;
use near_sdk::serde_json::Value;
use near_sdk::test_utils::{VMContextBuilder, get_created_receipts, get_logs};
use near_sdk::testing_env;
use std::panic::{AssertUnwindSafe, catch_unwind};

const NEAR: u128 = 1_000_000_000_000_000_000_000_000;
const MILLI: u128 = NEAR / 1000;
const T0: u64 = 1_762_000_000_000;
const H: u64 = HOUR_MS;
const TTL: u64 = PENDING_TTL_MS;
const CANARY: &str = "canary-7f3a.testnet";
const CANARY_HASH: &str = "1e0b149bf10c045d3ce48c0a0d32a6b2d3ff8243589fe00a57b5b830acc6bff7";

// ------------------------------------------------------------------ helpers

fn acc(s: &str) -> AccountId {
    s.parse().unwrap()
}

fn ctx_bal(pred: &str, now_ms: u64, dep: u128, bal: u128) {
    let mut b = VMContextBuilder::new();
    b.current_account_id(acc("vault.testnet"))
        .signer_account_id(acc(pred))
        .predecessor_account_id(acc(pred))
        .block_timestamp(now_ms * 1_000_000)
        .storage_usage(10_000)
        .attached_deposit(NearToken::from_yoctonear(dep))
        .account_balance(NearToken::from_yoctonear(bal));
    testing_env!(b.build());
}

fn set(pred: &str, now_ms: u64, dep: u128) {
    ctx_bal(pred, now_ms, dep, 50 * NEAR)
}
fn owner(now: u64) {
    set("owner.testnet", now, 1)
}
fn guardian(now: u64) {
    set("guardian.testnet", now, 0)
}

fn policy() -> Policy {
    Policy {
        max_per_payment: U128(2 * NEAR),
        daily_limit: U128(5 * NEAR),
        approval_threshold: U128(NEAR),
        new_payee_limit: U128(NEAR / 2),
        max_payments_per_hour: 10,
        allowlist_only: false,
        allowlist: vec![],
        auto_freeze_after_blocks: 0,
        expires_at_ms: None,
    }
}

fn setup_with(p: Policy) -> Tripwire {
    set("vault.testnet", T0, 0);
    let mut c = Tripwire::new(acc("owner.testnet"), Some(vec![acc("guardian.testnet")]));
    owner(T0);
    c.register_agent(acc("agent.testnet"), "shopping agent".into(), p);
    c
}
fn setup() -> Tripwire {
    setup_with(policy())
}

fn pay(c: &mut Tripwire, now: u64, to: &str, amt: u128) -> PaymentResult {
    pay_memo(c, now, to, amt, Some("test".into()))
}
fn pay_memo(c: &mut Tripwire, now: u64, to: &str, amt: u128, memo: Option<String>) -> PaymentResult {
    set("agent.testnet", now, 0);
    let (r, p) = c.submit_payment(acc(to), U128(amt), memo);
    drop(p);
    r
}

fn view(c: &Tripwire) -> AgentView {
    c.get_agent(acc("agent.testnet")).unwrap()
}

fn value<T>(r: PromiseOrValue<T>) -> T {
    match r {
        PromiseOrValue::Value(v) => v,
        PromiseOrValue::Promise(p) => {
            drop(p);
            panic!("expected a value, got a promise")
        }
    }
}
fn expect_promise<T>(r: PromiseOrValue<T>) {
    match r {
        PromiseOrValue::Promise(p) => drop(p),
        PromiseOrValue::Value(_) => panic!("expected a promise, got a value"),
    }
}

fn events() -> Vec<Value> {
    get_logs()
        .iter()
        .filter_map(|l| l.strip_prefix("EVENT_JSON:"))
        .map(|j| serde_json::from_str(j).unwrap())
        .collect()
}
fn event_names() -> Vec<String> {
    events().iter().map(|e| e["event"].as_str().unwrap().to_string()).collect()
}
fn last_data() -> Value {
    events().last().unwrap()["data"][0].clone()
}

fn panic_msg<R>(f: impl FnOnce() -> R) -> String {
    match catch_unwind(AssertUnwindSafe(f)) {
        Ok(_) => panic!("expected a panic"),
        Err(e) => e
            .downcast_ref::<String>()
            .cloned()
            .or_else(|| e.downcast_ref::<&str>().map(|s| s.to_string()))
            .unwrap_or_default(),
    }
}
fn assert_panics<R>(needle: &str, f: impl FnOnce() -> R) {
    let m = panic_msg(f);
    assert!(m.contains(needle), "expected {needle:?}, got: {m}");
}

const OWNER_ERR: &str = "Only the owner can call this method";
const OWNER_OR_GUARDIAN_ERR: &str = "Only the owner or a guardian can call this method";
const SETTLED_ERR: &str = "Unknown or already settled request";

fn hash_of(id: &str) -> String {
    to_hex(&account_hash(&acc(id)))
}

fn add_canary(c: &mut Tripwire, now: u64) {
    guardian(now);
    assert_eq!(c.add_canaries(vec![CANARY_HASH.into()]), 1);
}

fn is_transfer(a: &MockAction, amount: u128) -> bool {
    matches!(a, MockAction::Transfer { deposit, .. } if deposit.as_yoctonear() == amount)
}

// ------------------------------------------------------------------ 1. init

#[test]
fn init_sorts_and_dedups_guardians() {
    set("vault.testnet", T0, 0);
    let c = Tripwire::new(
        acc("owner.testnet"),
        Some(vec![acc("guardian.testnet"), acc("g2.testnet"), acc("guardian.testnet")]),
    );
    let cfg = c.get_config();
    assert_eq!(cfg.guardians, vec![acc("g2.testnet"), acc("guardian.testnet")]);
    assert_eq!(cfg.version, "1.0.0");
    assert_eq!(cfg.ring_capacity, 256);
    assert_eq!(cfg.owner_id, acc("owner.testnet"));
    assert!(!cfg.paused);
    assert_eq!(cfg.agents, 0);
    assert_eq!(cfg.activity_written.0, 0);
}

#[test]
fn init_rejects_owner_as_guardian() {
    set("vault.testnet", T0, 0);
    assert_panics("The owner cannot also be a guardian", || {
        Tripwire::new(acc("owner.testnet"), Some(vec![acc("owner.testnet")]))
    });
}

#[test]
fn init_rejects_too_many_guardians() {
    set("vault.testnet", T0, 0);
    let gs: Vec<AccountId> = (0..11).map(|i| acc(&format!("g{i}.testnet"))).collect();
    assert_panics("Too many guardians (max 10)", || Tripwire::new(acc("owner.testnet"), Some(gs)));
}

#[test]
fn canary_hash_fixture_matches() {
    set("vault.testnet", T0, 0);
    assert_eq!(hash_of(CANARY), CANARY_HASH);
}

// ------------------------------------------------------------------ 2. happy path

#[test]
fn small_payment_is_paid_with_transfer_and_callback() {
    let mut c = setup();
    let r = pay(&mut c, T0, "shop.testnet", 3 * NEAR / 10);
    assert_eq!(r.status, PaymentStatus::Paid);
    assert_eq!(r.request_id.0, 1);
    assert!(r.reasons.is_empty());
    assert!(!r.frozen);

    let receipts = get_created_receipts();
    assert_eq!(receipts.len(), 2);
    assert_eq!(receipts[0].receiver_id, acc("shop.testnet"));
    assert!(is_transfer(&receipts[0].actions[0], 3 * NEAR / 10));
    assert_eq!(receipts[1].receiver_id, acc("vault.testnet"));
    match &receipts[1].actions[0] {
        MockAction::FunctionCallWeight { method_name, args, prepaid_gas, gas_weight, .. } => {
            assert_eq!(method_name.as_slice(), b"on_payment_settled".as_slice());
            assert_eq!(*prepaid_gas, Gas::from_tgas(20));
            assert_eq!(gas_weight.0, 0);
            let a: Value = serde_json::from_slice(args).unwrap();
            assert_eq!(a["request_id"], "1");
            assert_eq!(a["agent_id"], "agent.testnet");
            assert_eq!(a["receiver_id"], "shop.testnet");
            assert_eq!(a["amount"], "300000000000000000000000");
            assert_eq!(a["at_ms"], T0.to_string());
        }
        other => panic!("unexpected action {other:?}"),
    }

    let ev = events();
    assert_eq!(ev.len(), 1);
    assert_eq!(ev[0]["standard"], "tripwire");
    assert_eq!(ev[0]["version"], "1.0.0");
    assert_eq!(ev[0]["event"], "paid");
    let d = &ev[0]["data"][0];
    assert_eq!(d["seq"], "1");
    assert_eq!(d["at_ms"], "1762000000000");
    assert_eq!(d["block_height"], "0");
    assert_eq!(d["agent_id"], "agent.testnet");
    assert_eq!(d["receiver_id"], "shop.testnet");
    assert_eq!(d["amount"], "300000000000000000000000");
    assert_eq!(d["request_id"], "1");
    assert_eq!(d["note"], "test");
    assert_eq!(d["by"], "agent.testnet");
    assert!(d.get("kind").is_none());
    assert!(d.get("reasons").is_none());

    let v = view(&c);
    assert_eq!(v.spent_24h.0, 3 * NEAR / 10);
    assert_eq!(v.payee_count, 1);
    assert_eq!(v.counters.paid, 1);
    assert_eq!(v.total_spent.0, 3 * NEAR / 10);
    let kinds: Vec<EventKind> = c.get_activity(None, None).iter().map(|e| e.kind).collect();
    assert_eq!(kinds, vec![EventKind::Paid, EventKind::AgentRegistered]);
    let s = c.get_stats();
    assert_eq!(s.requests, 1);
    assert_eq!(s.paid, 1);
    assert_eq!(s.paid_total.0, 3 * NEAR / 10);

    let p = c.get_payee(acc("agent.testnet"), acc("shop.testnet")).unwrap();
    assert_eq!(p.count, 1);
    assert_eq!(p.total.0, 3 * NEAR / 10);
    assert_eq!(p.first_ms.0, T0);
    assert_eq!(p.last_ms.0, T0);
}

#[test]
fn request_payment_returns_promise_or_value() {
    let mut c = setup();
    set("agent.testnet", T0, 0);
    expect_promise(c.request_payment(acc("shop.testnet"), U128(NEAR / 10), None));
    set("agent.testnet", T0 + 1, 0);
    let r = value(c.request_payment(acc("shop.testnet"), U128(3 * NEAR), None));
    assert_eq!(r.status, PaymentStatus::Blocked);
    assert_eq!(r.reasons, vec![Reason::OverPerPaymentCap]);
    assert!(get_created_receipts().is_empty());
}

// ------------------------------------------------------------------ 3-5. approvals

#[test]
fn escalate_then_approve() {
    let mut c = setup();
    let r = pay(&mut c, T0, "shop.testnet", 8 * NEAR / 10);
    assert_eq!(r.status, PaymentStatus::PendingApproval);
    assert_eq!(r.reasons, vec![Reason::NewPayee]);
    assert!(get_created_receipts().is_empty());
    assert_eq!(event_names(), vec!["escalated"]);
    let v = view(&c);
    assert_eq!(v.reserved.0, 8 * NEAR / 10);
    assert_eq!(v.pending_ids, vec![U64(1)]);
    assert_eq!(v.remaining_24h.0, 42 * NEAR / 10);
    assert_eq!(v.spent_24h.0, 0);
    assert_eq!(c.get_config().pending, 1);
    assert_eq!(c.get_config().reserved.0, 8 * NEAR / 10);

    owner(T0 + 2);
    expect_promise(c.approve(U64(1)));
    let receipts = get_created_receipts();
    assert_eq!(receipts.len(), 2);
    assert!(is_transfer(&receipts[0].actions[0], 8 * NEAR / 10));
    assert_eq!(event_names(), vec!["approved"]);
    assert_eq!(last_data()["by"], "owner.testnet");
    let cfg = c.get_config();
    assert_eq!(cfg.reserved.0, 0);
    assert_eq!(cfg.pending, 0);
    let v = view(&c);
    assert_eq!(v.spent_24h.0, 8 * NEAR / 10);
    assert_eq!(v.counters.approved, 1);
    assert!(v.pending_ids.is_empty());
    assert_eq!(c.get_stats().approved, 1);

    // The receiver is now a known payee, so the same amount goes straight through.
    assert_eq!(pay(&mut c, T0 + 3, "shop.testnet", 8 * NEAR / 10).status, PaymentStatus::Paid);
}

#[test]
fn approve_needs_owner_and_one_yocto() {
    let mut c = setup();
    pay(&mut c, T0, "shop.testnet", 8 * NEAR / 10);
    guardian(T0 + 1);
    assert_panics(OWNER_ERR, || c.approve(U64(1)));
    set("owner.testnet", T0 + 1, 0);
    assert_panics("1 yoctoNEAR", || c.approve(U64(1)));
    owner(T0 + 1);
    assert_panics(SETTLED_ERR, || c.approve(U64(99)));
    assert_eq!(c.get_config().pending, 1);
}

#[test]
fn reject_by_guardian() {
    let mut c = setup();
    pay(&mut c, T0, "shop.testnet", 8 * NEAR / 10);
    set("mallory.testnet", T0 + 1, 0);
    assert_panics(OWNER_OR_GUARDIAN_ERR, || c.reject(U64(1), None));
    guardian(T0 + 1);
    let p = c.reject(U64(1), Some("not ordered by a human".into()));
    assert_eq!(p.id.0, 1);
    assert_eq!(p.receiver_id, acc("shop.testnet"));
    assert_eq!(event_names(), vec!["rejected"]);
    let d = last_data();
    assert_eq!(d["by"], "guardian.testnet");
    assert_eq!(d["note"], "not ordered by a human");
    assert!(d.get("seq").is_some());
    assert_eq!(c.get_config().reserved.0, 0);
    assert_eq!(view(&c).counters.rejected, 1);
    assert_eq!(c.get_stats().rejected, 1);
    assert_panics(SETTLED_ERR, || c.reject(U64(1), None));
    owner(T0 + 2);
    assert_panics(SETTLED_ERR, || c.approve(U64(1)));
}

#[test]
fn pending_requests_expire() {
    let mut c = setup();
    assert_eq!(pay(&mut c, T0, "shop.testnet", 8 * NEAR / 10).request_id.0, 1);
    let r = pay(&mut c, T0 + TTL, "other.testnet", NEAR / 10);
    assert_eq!(r.status, PaymentStatus::Paid);
    assert_eq!(event_names(), vec!["expired", "paid"]);
    assert_eq!(c.get_config().reserved.0, 0);

    let r = pay(&mut c, T0 + TTL + 1, "shop.testnet", 8 * NEAR / 10);
    assert_eq!(r.request_id.0, 3);
    assert_eq!(r.status, PaymentStatus::PendingApproval);
    owner(T0 + 2 * TTL + 5);
    let r = value(c.approve(U64(3)));
    assert_eq!(r.status, PaymentStatus::Expired);
    assert_eq!(r.reasons, vec![Reason::NewPayee]);
    assert!(get_created_receipts().is_empty());
    assert_eq!(event_names(), vec!["expired"]);
    assert_eq!(c.get_stats().expired, 2);
    assert_eq!(view(&c).counters.expired, 2);
    assert_eq!(c.get_config().pending, 0);
}

#[test]
fn expire_stale_can_be_called_by_anyone() {
    let mut c = setup();
    for i in 0..3 {
        pay(&mut c, T0, &format!("p{i}.testnet"), 8 * NEAR / 10);
    }
    assert_eq!(c.get_config().reserved.0, 24 * NEAR / 10);
    set("stranger.testnet", T0 + TTL - 1, 0);
    assert_eq!(c.expire_stale(None), 0);
    set("stranger.testnet", T0 + TTL, 0);
    assert_eq!(c.expire_stale(Some(1)), 1);
    assert_eq!(c.expire_stale(None), 2);
    assert_eq!(c.expire_stale(None), 0);
    assert_eq!(c.get_config().reserved.0, 0);
    assert_eq!(c.get_config().pending, 0);
    assert!(view(&c).pending_ids.is_empty());
}

// ------------------------------------------------------------------ 7. canary

#[test]
fn canary_trips_and_freezes_agent() {
    let mut c = setup();
    add_canary(&mut c, T0);
    pay(&mut c, T0 + 1, "shop.testnet", 8 * NEAR / 10);
    let r = pay(&mut c, T0 + 2, CANARY, 10 * MILLI);
    assert_eq!(r.status, PaymentStatus::Tripped);
    assert_eq!(r.reasons, vec![Reason::Tripwire]);
    assert!(r.frozen);
    assert!(get_created_receipts().is_empty());
    assert_eq!(event_names(), vec!["tripped", "rejected", "frozen"]);
    let ev = events();
    assert!(ev[1]["data"][0].get("seq").is_none(), "cancellations are quiet");
    assert_eq!(ev[1]["data"][0]["note"], "cancelled by freeze");
    let frozen = &ev[2]["data"][0];
    assert_eq!(frozen["note"], "TRIPWIRE: attempted payment to a canary payee (cancelled 1 pending)");
    assert_eq!(frozen["by"], "vault.testnet");

    let v = view(&c);
    match &v.status {
        AgentStatus::Frozen { reason, by, at_ms } => {
            assert!(reason.starts_with("TRIPWIRE"));
            assert_eq!(by, &acc("vault.testnet"));
            assert_eq!(at_ms.0, T0 + 2);
        }
        s => panic!("expected frozen, got {s:?}"),
    }
    assert_eq!(v.counters.tripped, 1);
    assert_eq!(v.counters.rejected, 1);
    let cfg = c.get_config();
    assert_eq!(cfg.pending, 0);
    assert_eq!(cfg.reserved.0, 0);
    let s = c.get_stats();
    assert_eq!(s.tripped, 1);
    assert_eq!(s.freezes, 1);

    // A frozen agent is refused quietly and the activity ring does not grow.
    let written = c.get_config().activity_written.0;
    let r = pay(&mut c, T0 + 3, "shop.testnet", NEAR / 100);
    assert_eq!(r.status, PaymentStatus::Blocked);
    assert_eq!(r.reasons, vec![Reason::AgentFrozen]);
    assert!(r.frozen);
    assert_eq!(event_names(), vec!["blocked"]);
    assert!(last_data().get("seq").is_none());
    assert_eq!(c.get_config().activity_written.0, written);
    assert_eq!(view(&c).counters.blocked_while_frozen, 1);
    assert_eq!(c.get_stats().blocked_while_frozen, 1);
    // A frozen agent cannot trip again either.
    assert_eq!(pay(&mut c, T0 + 4, CANARY, NEAR / 100).reasons, vec![Reason::AgentFrozen]);
}

#[test]
fn check_payment_hides_canaries() {
    let mut c = setup();
    add_canary(&mut c, T0);
    set("anyone.testnet", T0 + 1, 0);
    let written = c.get_config().activity_written.0;
    let a = acc("agent.testnet");
    let chk = |c: &Tripwire, to: &str, amt: u128| c.check_payment(a.clone(), acc(to), U128(amt));
    assert_eq!(chk(&c, CANARY, 10 * MILLI), CheckResult { verdict: Verdict::Allow, reasons: vec![] });
    assert_eq!(
        chk(&c, "shop.testnet", 3 * NEAR),
        CheckResult { verdict: Verdict::Block, reasons: vec![Reason::OverPerPaymentCap] }
    );
    assert_eq!(
        chk(&c, "shop.testnet", 8 * NEAR / 10),
        CheckResult { verdict: Verdict::Warn, reasons: vec![Reason::NewPayee] }
    );
    assert_eq!(
        chk(&c, "shop.testnet", 15 * NEAR / 10),
        CheckResult { verdict: Verdict::Warn, reasons: vec![Reason::NewPayee, Reason::NeedsApproval] }
    );
    assert_eq!(
        c.check_payment(acc("nobody.testnet"), acc("shop.testnet"), U128(1)),
        CheckResult { verdict: Verdict::Block, reasons: vec![Reason::UnknownAgent] }
    );
    assert_eq!(
        chk(&c, "agent.testnet", NEAR / 10),
        CheckResult { verdict: Verdict::Block, reasons: vec![Reason::SelfPayment] }
    );
    assert_eq!(
        chk(&c, "vault.testnet", NEAR / 10).reasons,
        vec![Reason::SelfPayment]
    );
    assert_eq!(chk(&c, "shop.testnet", 0).reasons, vec![Reason::ZeroAmount]);
    assert_eq!(c.get_config().activity_written.0, written);
}

#[test]
fn canary_trips_even_while_paused() {
    let mut c = setup();
    add_canary(&mut c, T0);
    guardian(T0 + 1);
    assert!(c.pause(None));
    let r = pay(&mut c, T0 + 2, CANARY, NEAR / 100);
    assert_eq!(r.status, PaymentStatus::Tripped);
    assert!(view(&c).status != AgentStatus::Active);
}

// ------------------------------------------------------------------ 9. reports and blocklist

#[test]
fn reports_warn_and_blocklist_blocks() {
    let mut c = setup();
    set("agent.testnet", T0, 0);
    let b = c.report_receiver(acc("mallory.testnet"), "asked for a refund twice".into(), None);
    assert_eq!(b.status, BlockStatus::Reported);
    assert_eq!(b.reports, 1);
    assert_eq!(b.reporter, acc("agent.testnet"));
    assert_eq!(event_names(), vec!["reported"]);
    assert!(last_data().get("seq").is_some());
    assert_eq!(c.get_config().open_reports, 1);
    assert_eq!(view(&c).counters.reports, 1);

    let r = pay(&mut c, T0 + 1, "mallory.testnet", NEAR / 10);
    assert_eq!(r.status, PaymentStatus::PendingApproval);
    assert_eq!(r.reasons, vec![Reason::ReportedReceiver]);

    set("shop.testnet", T0 + 2, 0);
    assert_panics("Reports from this account need an attached deposit of 0.01 NEAR", || {
        c.report_receiver(acc("mallory.testnet"), "same".into(), None)
    });
    set("shop.testnet", T0 + 2, 10 * MILLI);
    let b = c.report_receiver(acc("mallory.testnet"), "same".into(), Some("order 42".into()));
    assert_eq!(b.reports, 2);
    assert_eq!(b.evidence.as_deref(), Some("order 42"));
    assert_eq!(b.reason, "asked for a refund twice");
    assert_eq!(event_names(), vec!["reported"]);
    assert!(last_data().get("seq").is_none(), "repeat reports are quiet");
    assert_eq!(c.get_config().open_reports, 1);
    assert_eq!(c.get_stats().reports, 2);

    guardian(T0 + 3);
    let b = c.block_receiver(acc("mallory.testnet"), "confirmed scam".into(), None);
    assert_eq!(b.status, BlockStatus::Confirmed);
    assert_eq!(b.confirmed_by, Some(acc("guardian.testnet")));
    assert_eq!(b.evidence.as_deref(), Some("order 42"));
    assert_eq!(c.get_config().open_reports, 0);
    assert_eq!(c.get_config().blocklist, 1);
    assert_eq!(event_names(), vec!["blocklisted"]);

    let r = pay(&mut c, T0 + 4, "mallory.testnet", NEAR / 10);
    assert_eq!(r.status, PaymentStatus::Blocked);
    assert_eq!(r.reasons, vec![Reason::Blocklisted]);

    guardian(T0 + 5);
    assert_panics(OWNER_ERR, || c.unblock_receiver(acc("mallory.testnet")));
    owner(T0 + 5);
    assert!(c.unblock_receiver(acc("mallory.testnet")));
    assert_eq!(event_names(), vec!["unblocklisted"]);
    assert!(!c.unblock_receiver(acc("mallory.testnet")));
    assert_eq!(c.get_config().blocklist, 0);
    assert_eq!(pay(&mut c, T0 + 6, "mallory.testnet", NEAR / 10).status, PaymentStatus::Paid);
}

#[test]
fn block_receiver_new_entry_and_validation() {
    let mut c = setup();
    set("stranger.testnet", T0, 0);
    assert_panics(OWNER_OR_GUARDIAN_ERR, || c.block_receiver(acc("x.testnet"), "r".into(), None));
    owner(T0);
    assert_panics("reason is required", || c.block_receiver(acc("x.testnet"), " \u{200b} ".into(), None));
    let b = c.block_receiver(acc("x.testnet"), "drainer".into(), Some("tx abc".into()));
    assert_eq!(b.status, BlockStatus::Confirmed);
    assert_eq!(b.reporter, acc("owner.testnet"));
    assert_eq!(b.confirmed_by, Some(acc("owner.testnet")));
    assert_eq!(b.reports, 0);
    assert_eq!(c.get_block_entry(acc("x.testnet")).unwrap(), b);
    assert_eq!(c.get_config().open_reports, 0);
    // An unblock of a reported (not confirmed) entry closes the open report.
    set("agent.testnet", T0 + 1, 0);
    c.report_receiver(acc("y.testnet"), "odd".into(), None);
    assert_eq!(c.get_config().open_reports, 1);
    owner(T0 + 2);
    assert!(c.unblock_receiver(acc("y.testnet")));
    assert_eq!(c.get_config().open_reports, 0);
}

#[test]
fn allowlisted_payees_ignore_reports() {
    let mut p = policy();
    p.allowlist = vec![acc("shop.testnet")];
    let mut c = setup_with(p);
    set("agent.testnet", T0, 0);
    c.report_receiver(acc("shop.testnet"), "griefing".into(), None);
    assert_eq!(pay(&mut c, T0 + 1, "shop.testnet", 8 * NEAR / 10).status, PaymentStatus::Paid);
}

#[test]
fn free_reports_are_capped_per_agent() {
    let mut c = setup();
    for i in 0..20 {
        set("agent.testnet", T0 + i, 0);
        c.report_receiver(acc(&format!("r{i}.testnet")), "odd".into(), None);
    }
    set("agent.testnet", T0 + 30, 0);
    assert_panics("need an attached deposit", || c.report_receiver(acc("r20.testnet"), "odd".into(), None));
    set("agent.testnet", T0 + 30, 10 * MILLI);
    c.report_receiver(acc("r20.testnet"), "odd".into(), None);
    assert_eq!(view(&c).counters.reports, 21);
    // Owner and guardians are always free.
    owner(T0 + 31);
    set("owner.testnet", T0 + 31, 0);
    c.report_receiver(acc("r21.testnet"), "odd".into(), None);
    guardian(T0 + 32);
    c.report_receiver(acc("r22.testnet"), "odd".into(), None);
    assert_eq!(c.get_stats().reports, 23);
    assert_eq!(c.get_config().open_reports, 23);
}

#[test]
fn frozen_agent_must_pay_to_report() {
    let mut c = setup();
    guardian(T0);
    assert!(c.freeze_agent(acc("agent.testnet"), None));
    set("agent.testnet", T0 + 1, 0);
    assert_panics("need an attached deposit", || c.report_receiver(acc("r.testnet"), "odd".into(), None));
}

#[test]
fn report_needs_reason() {
    let mut c = setup();
    set("agent.testnet", T0, 0);
    assert_panics("reason is required", || c.report_receiver(acc("r.testnet"), "\n\t ".into(), None));
}

// ------------------------------------------------------------------ 10. limits

#[test]
fn per_payment_cap() {
    let mut c = setup();
    let r = pay(&mut c, T0, "shop.testnet", 2 * NEAR + 1);
    assert_eq!(r.status, PaymentStatus::Blocked);
    assert_eq!(r.reasons, vec![Reason::OverPerPaymentCap]);
    assert_eq!(event_names(), vec!["blocked"]);
    assert!(last_data().get("seq").is_some());
    assert_eq!(last_data()["reasons"], serde_json::json!(["OVER_PER_PAYMENT_CAP"]));
    assert_eq!(view(&c).counters.blocked, 1);
    assert_eq!(view(&c).blocks_last_hour, 1);
    assert_eq!(c.get_stats().blocked, 1);
}

#[test]
fn daily_limit_rolls_over_24_hours() {
    let mut p = policy();
    p.allowlist = vec![acc("shop.testnet")];
    p.approval_threshold = U128(2 * NEAR);
    let mut c = setup_with(p);
    assert_eq!(pay(&mut c, T0, "shop.testnet", 2 * NEAR).status, PaymentStatus::Paid);
    assert_eq!(pay(&mut c, T0 + 1, "shop.testnet", 2 * NEAR).status, PaymentStatus::Paid);
    assert_eq!(pay(&mut c, T0 + 2, "shop.testnet", 2 * NEAR).reasons, vec![Reason::OverDailyLimit]);
    assert_eq!(pay(&mut c, T0 + 3, "shop.testnet", NEAR).status, PaymentStatus::Paid);
    assert_eq!(view(&c).remaining_24h.0, 0);
    assert_eq!(pay(&mut c, T0 + 4, "shop.testnet", MILLI).reasons, vec![Reason::OverDailyLimit]);
    assert_eq!(T0 / H, 489_444);
    assert_eq!((T0 + 24 * H) / H, 489_468);
    assert_eq!(pay(&mut c, T0 + 24 * H, "shop.testnet", MILLI).reasons, vec![Reason::OverDailyLimit]);
    assert_eq!(pay(&mut c, T0 + 25 * H, "shop.testnet", MILLI).status, PaymentStatus::Paid);
    assert_eq!(view(&c).spent_24h.0, MILLI);
    assert_eq!(view(&c).total_spent.0, 5 * NEAR + MILLI);
}

#[test]
fn hourly_rate_limit() {
    let mut c = setup();
    for i in 0..10 {
        assert_eq!(pay(&mut c, T0 + i, "shop.testnet", NEAR / 100).status, PaymentStatus::Paid, "payment {i}");
    }
    assert_eq!(view(&c).payments_last_hour, 10);
    assert_eq!(pay(&mut c, T0 + 10, "shop.testnet", NEAR / 100).reasons, vec![Reason::RateLimited]);
    assert_eq!(pay(&mut c, T0 + H, "shop.testnet", NEAR / 100).status, PaymentStatus::Paid);
    assert_eq!(view(&c).payments_last_hour, 10);
}

#[test]
fn allowlist_only_mode() {
    let mut p = policy();
    p.allowlist_only = true;
    p.allowlist = vec![acc("shop.testnet")];
    let mut c = setup_with(p);
    assert_eq!(pay(&mut c, T0, "shop.testnet", 3 * NEAR / 10).status, PaymentStatus::Paid);
    assert_eq!(pay(&mut c, T0 + 1, "shop.testnet", 8 * NEAR / 10).status, PaymentStatus::Paid);
    assert_eq!(pay(&mut c, T0 + 2, "mallory.testnet", NEAR / 100).reasons, vec![Reason::NotAllowlisted]);
}

#[test]
fn vault_balance_is_checked() {
    let mut c = setup();
    // 1 NEAR balance, 0.1 NEAR locked for storage, 0.05 NEAR margin: 0.85 NEAR available.
    ctx_bal("agent.testnet", T0 + 1, 0, NEAR);
    assert_eq!(c.available(), 85 * NEAR / 100);
    let (r, p) = c.submit_payment(acc("shop.testnet"), U128(9 * NEAR / 10), None);
    drop(p);
    assert_eq!(r.reasons, vec![Reason::InsufficientVaultBalance]);
    ctx_bal("agent.testnet", T0 + 2, 0, NEAR);
    let (r, p) = c.submit_payment(acc("shop.testnet"), U128(3 * NEAR / 10), None);
    drop(p);
    assert_eq!(r.status, PaymentStatus::Paid);
}

#[test]
fn pending_queue_is_capped_per_agent() {
    let mut c = setup();
    for i in 0..5 {
        assert_eq!(pay(&mut c, T0, &format!("p{i}.testnet"), 8 * NEAR / 10).status, PaymentStatus::PendingApproval);
    }
    let r = pay(&mut c, T0 + 1, "p5.testnet", 8 * NEAR / 10);
    assert_eq!(r.status, PaymentStatus::Blocked);
    assert_eq!(r.reasons, vec![Reason::NewPayee, Reason::TooManyPending]);
    assert_eq!(c.get_config().pending, 5);
    // Plain allowed payments still work while the queue is full.
    assert_eq!(pay(&mut c, T0 + 2, "p6.testnet", NEAR / 10).status, PaymentStatus::Paid);
}

#[test]
fn reserved_amounts_count_against_daily_limit() {
    let mut c = setup();
    for i in 0..5 {
        pay(&mut c, T0, &format!("p{i}.testnet"), 8 * NEAR / 10);
    }
    // 4 NEAR reserved + 1.1 NEAR > 5 NEAR daily limit.
    assert_eq!(pay(&mut c, T0 + 1, "p0.testnet", 11 * NEAR / 10).reasons, vec![Reason::OverDailyLimit]);
    assert_eq!(view(&c).remaining_24h.0, NEAR);
}

#[test]
fn policy_expiry() {
    let mut p = policy();
    p.expires_at_ms = Some(U64(T0 + 1000));
    let mut c = setup_with(p);
    assert_eq!(pay(&mut c, T0 + 999, "shop.testnet", NEAR / 10).status, PaymentStatus::Paid);
    let r = pay(&mut c, T0 + 1000, "shop.testnet", NEAR / 10);
    assert_eq!(r.status, PaymentStatus::Blocked);
    assert_eq!(r.reasons, vec![Reason::PolicyExpired]);
}

#[test]
fn payee_cap_forces_review_of_new_payees() {
    let mut p = policy();
    p.max_payments_per_hour = 300;
    p.daily_limit = U128(100 * NEAR);
    p.allowlist = vec![acc("trusted.testnet")];
    let mut c = setup_with(p);
    for i in 0..256u64 {
        let r = pay(&mut c, T0 + i, &format!("p{i}.testnet"), MILLI);
        assert_eq!(r.status, PaymentStatus::Paid, "payee {i}");
    }
    assert_eq!(view(&c).payee_count, 256);
    let r = pay(&mut c, T0 + 300, "p256.testnet", MILLI);
    assert_eq!(r.status, PaymentStatus::PendingApproval);
    assert_eq!(r.reasons, vec![Reason::NewPayee]);
    assert_eq!(pay(&mut c, T0 + 301, "p7.testnet", MILLI).status, PaymentStatus::Paid);
    assert_eq!(pay(&mut c, T0 + 302, "trusted.testnet", MILLI).status, PaymentStatus::Paid);
}

// ------------------------------------------------------------------ 11. auto-freeze

fn auto_policy(n: u32) -> Policy {
    let mut p = policy();
    p.auto_freeze_after_blocks = n;
    p
}

#[test]
fn repeated_blocks_auto_freeze() {
    let mut c = setup_with(auto_policy(3));
    for i in 1..=2 {
        let r = pay(&mut c, T0 + i, "shop.testnet", 3 * NEAR);
        assert!(!r.frozen);
        assert_eq!(event_names(), vec!["blocked"]);
    }
    let r = pay(&mut c, T0 + 3, "shop.testnet", 3 * NEAR);
    assert_eq!(r.status, PaymentStatus::Blocked);
    assert!(r.frozen);
    assert_eq!(event_names(), vec!["blocked", "frozen"]);
    match view(&c).status {
        AgentStatus::Frozen { reason, by, .. } => {
            assert_eq!(reason, "AUTO_FREEZE: 3 blocked payment attempts within 1h");
            assert_eq!(by, acc("vault.testnet"));
        }
        s => panic!("expected frozen, got {s:?}"),
    }
    assert_eq!(c.get_stats().freezes, 1);
    // Unfreezing clears the block history so the agent is not refrozen at once.
    owner(T0 + 4);
    let v = c.unfreeze_agent(acc("agent.testnet"));
    assert_eq!(v.status, AgentStatus::Active);
    assert_eq!(v.blocks_last_hour, 0);
    assert!(!pay(&mut c, T0 + 5, "shop.testnet", 3 * NEAR).frozen);
}

#[test]
fn spaced_blocks_do_not_freeze() {
    let mut c = setup_with(auto_policy(3));
    for i in 0..6 {
        let r = pay(&mut c, T0 + i * (H / 2 + 1), "shop.testnet", 3 * NEAR);
        assert!(!r.frozen, "attempt {i}");
    }
    assert_eq!(view(&c).counters.blocked, 6);
}

#[test]
fn default_backstop_freezes_after_25_blocks() {
    let mut c = setup_with(auto_policy(0));
    for i in 1..=24 {
        assert!(!pay(&mut c, T0 + i, "shop.testnet", 3 * NEAR).frozen, "attempt {i}");
    }
    assert!(pay(&mut c, T0 + 25, "shop.testnet", 3 * NEAR).frozen);
}

#[test]
fn auto_freeze_cancels_pending() {
    let mut c = setup_with(auto_policy(1));
    pay(&mut c, T0, "p0.testnet", 8 * NEAR / 10);
    let r = pay(&mut c, T0 + 1, "shop.testnet", 3 * NEAR);
    assert!(r.frozen);
    assert_eq!(event_names(), vec!["blocked", "rejected", "frozen"]);
    assert_eq!(c.get_config().reserved.0, 0);
}

// ------------------------------------------------------------------ 12. callback

#[test]
fn failed_transfer_rolls_back_accounting() {
    let mut c = setup();
    pay(&mut c, T0, "shop.testnet", 3 * NEAR / 10);
    set("vault.testnet", T0 + 1, 0);
    let r = c.on_payment_settled(
        U64(1),
        acc("agent.testnet"),
        acc("shop.testnet"),
        U128(3 * NEAR / 10),
        U64(T0),
        Err(PromiseError::Failed),
    );
    assert_eq!(r.status, PaymentStatus::TransferFailed);
    assert_eq!(r.request_id.0, 1);
    assert_eq!(event_names(), vec!["transfer_failed"]);
    let d = last_data();
    assert_eq!(d["request_id"], "1");
    assert_eq!(d["amount"], "300000000000000000000000");
    let v = view(&c);
    assert_eq!(v.spent_24h.0, 0);
    assert_eq!(v.total_spent.0, 0);
    assert_eq!(v.payee_count, 0);
    assert_eq!(v.counters.failed, 1);
    assert!(c.get_payee(acc("agent.testnet"), acc("shop.testnet")).is_none());
    let s = c.get_stats();
    assert_eq!(s.paid_total.0, 0);
    assert_eq!(s.failed, 1);
}

#[test]
fn failed_transfer_keeps_earlier_payee_history() {
    let mut c = setup();
    pay(&mut c, T0, "shop.testnet", NEAR / 10);
    pay(&mut c, T0 + 1, "shop.testnet", 2 * NEAR / 10);
    set("vault.testnet", T0 + 2, 0);
    c.on_payment_settled(U64(2), acc("agent.testnet"), acc("shop.testnet"), U128(2 * NEAR / 10), U64(T0 + 1), Err(PromiseError::Failed));
    let p = c.get_payee(acc("agent.testnet"), acc("shop.testnet")).unwrap();
    assert_eq!(p.count, 1);
    assert_eq!(p.total.0, NEAR / 10);
    assert_eq!(view(&c).payee_count, 1);
    assert_eq!(view(&c).spent_24h.0, NEAR / 10);
}

#[test]
fn successful_transfer_callback_is_silent() {
    let mut c = setup();
    pay(&mut c, T0, "shop.testnet", 3 * NEAR / 10);
    let before = view(&c);
    set("vault.testnet", T0 + 1, 0);
    let r = c.on_payment_settled(U64(1), acc("agent.testnet"), acc("shop.testnet"), U128(3 * NEAR / 10), U64(T0), Ok(()));
    assert_eq!(r.status, PaymentStatus::Paid);
    assert!(!r.frozen);
    assert!(get_logs().is_empty());
    assert_eq!(view(&c), before);
}

#[test]
fn callback_for_removed_agent_still_fixes_totals() {
    let mut c = setup();
    pay(&mut c, T0, "shop.testnet", 3 * NEAR / 10);
    owner(T0 + 1);
    c.remove_agent(acc("agent.testnet"));
    set("vault.testnet", T0 + 2, 0);
    let r = c.on_payment_settled(U64(1), acc("agent.testnet"), acc("shop.testnet"), U128(3 * NEAR / 10), U64(T0), Err(PromiseError::Failed));
    assert_eq!(r.status, PaymentStatus::TransferFailed);
    assert_eq!(c.get_stats().paid_total.0, 0);
}

// ------------------------------------------------------------------ 13-14. pause and withdraw

#[test]
fn pause_blocks_payments_quietly() {
    let mut c = setup();
    guardian(T0);
    assert!(c.pause(Some("incident drill".into())));
    assert_eq!(event_names(), vec!["paused"]);
    assert_eq!(last_data()["note"], "incident drill");
    assert!(!c.pause(None));
    let cfg = c.get_config();
    assert!(cfg.paused);
    assert_eq!(cfg.pause_reason.as_deref(), Some("incident drill"));

    let r = pay(&mut c, T0 + 1, "shop.testnet", NEAR / 10);
    assert_eq!(r.status, PaymentStatus::Blocked);
    assert_eq!(r.reasons, vec![Reason::VaultPaused]);
    assert!(last_data().get("seq").is_none());
    assert_eq!(c.get_stats().blocked_while_paused, 1);
    assert_eq!(view(&c).counters.blocked, 0);

    guardian(T0 + 2);
    assert_panics(OWNER_ERR, || c.unpause());
    owner(T0 + 2);
    c.unpause();
    assert_eq!(event_names(), vec!["unpaused"]);
    assert!(!c.get_config().paused);
    assert!(c.get_config().pause_reason.is_none());
    assert_panics("Vault is not paused", || c.unpause());
    assert_eq!(pay(&mut c, T0 + 3, "shop.testnet", NEAR / 10).status, PaymentStatus::Paid);
}

#[test]
fn pause_default_reason_and_permissions() {
    let mut c = setup();
    set("stranger.testnet", T0, 0);
    assert_panics(OWNER_OR_GUARDIAN_ERR, || c.pause(None));
    owner(T0);
    assert!(c.pause(None));
    assert_eq!(c.get_config().pause_reason.as_deref(), Some("paused by owner"));
}

#[test]
fn withdraw_rules() {
    let mut c = setup();
    guardian(T0);
    assert_panics(OWNER_ERR, || c.withdraw(U128(NEAR)));
    set("owner.testnet", T0, 0);
    assert_panics("1 yoctoNEAR", || c.withdraw(U128(NEAR)));
    owner(T0);
    assert_panics("amount must be > 0", || c.withdraw(U128(0)));
    assert_eq!(c.get_config().available.0, 4985 * NEAR / 100 + 1); // +1: the attached yocto is in the balance
    assert_panics("Amount exceeds the available balance", || c.withdraw(U128(50 * NEAR)));
    c.pause(None);
    owner(T0 + 1);
    drop(c.withdraw(U128(NEAR)));
    let receipts = get_created_receipts();
    assert_eq!(receipts.len(), 1);
    assert_eq!(receipts[0].receiver_id, acc("owner.testnet"));
    assert!(is_transfer(&receipts[0].actions[0], NEAR));
    assert_eq!(event_names(), vec!["withdraw"]);
    assert_eq!(last_data()["amount"], NEAR.to_string());
}

#[test]
fn withdraw_cannot_touch_reserved_funds() {
    let mut c = setup();
    for i in 0..5 {
        pay(&mut c, T0, &format!("p{i}.testnet"), 8 * NEAR / 10);
    }
    owner(T0 + 1);
    // 49.85 available minus 4 NEAR reserved.
    assert_eq!(c.get_config().available.0, 4585 * NEAR / 100 + 1);
    assert_panics("Amount exceeds the available balance", || c.withdraw(U128(46 * NEAR)));
}

// ------------------------------------------------------------------ 15. roles

#[test]
fn freeze_and_unfreeze_roles() {
    let mut c = setup();
    set("agent.testnet", T0, 0);
    assert_panics(OWNER_OR_GUARDIAN_ERR, || c.freeze_agent(acc("agent.testnet"), None));
    guardian(T0);
    assert_panics("Unknown agent", || c.freeze_agent(acc("nobody.testnet"), None));
    assert!(c.freeze_agent(acc("agent.testnet"), None));
    assert_eq!(event_names(), vec!["frozen"]);
    assert_eq!(last_data()["by"], "guardian.testnet");
    assert!(!c.freeze_agent(acc("agent.testnet"), None));
    match view(&c).status {
        AgentStatus::Frozen { reason, by, .. } => {
            assert_eq!(reason, "frozen by guardian");
            assert_eq!(by, acc("guardian.testnet"));
        }
        s => panic!("expected frozen, got {s:?}"),
    }
    assert_panics(OWNER_ERR, || c.unfreeze_agent(acc("agent.testnet")));
    owner(T0 + 1);
    assert_eq!(c.unfreeze_agent(acc("agent.testnet")).status, AgentStatus::Active);
    assert_eq!(event_names(), vec!["unfrozen"]);
    assert_panics("Agent is not frozen", || c.unfreeze_agent(acc("agent.testnet")));
    assert_panics("Unknown agent", || c.unfreeze_agent(acc("nobody.testnet")));
}

#[test]
fn self_freeze() {
    let mut c = setup();
    pay(&mut c, T0, "p0.testnet", 8 * NEAR / 10);
    set("agent.testnet", T0 + 1, 0);
    assert!(c.self_freeze(Some("instructions look tampered".into())));
    assert_eq!(event_names(), vec!["rejected", "frozen"]);
    match view(&c).status {
        AgentStatus::Frozen { reason, by, .. } => {
            assert_eq!(reason, "SELF_FREEZE: instructions look tampered");
            assert_eq!(by, acc("agent.testnet"));
        }
        s => panic!("expected frozen, got {s:?}"),
    }
    assert!(!c.self_freeze(None));
    assert_eq!(c.get_config().pending, 0);
}

#[test]
fn self_freeze_default_reason() {
    let mut c = setup();
    set("agent.testnet", T0, 0);
    assert!(c.self_freeze(None));
    match view(&c).status {
        AgentStatus::Frozen { reason, .. } => assert_eq!(reason, "SELF_FREEZE: agent requested a freeze"),
        s => panic!("expected frozen, got {s:?}"),
    }
}

#[test]
fn strangers_cannot_act_as_agents() {
    let mut c = setup();
    set("stranger.testnet", T0, 0);
    assert_panics("Caller is not a registered agent", || c.self_freeze(None));
    assert_panics("Caller is not a registered agent", || {
        c.submit_payment(acc("shop.testnet"), U128(1), None)
    });
    assert_eq!(c.get_stats().requests, 0);
}

#[test]
fn request_ids_count_every_agent_attempt() {
    let mut c = setup();
    assert_eq!(pay(&mut c, T0, "shop.testnet", 3 * NEAR).request_id.0, 1);
    assert_eq!(pay(&mut c, T0 + 1, "shop.testnet", NEAR / 10).request_id.0, 2);
    guardian(T0 + 2);
    c.freeze_agent(acc("agent.testnet"), None);
    assert_eq!(pay(&mut c, T0 + 3, "shop.testnet", NEAR / 10).request_id.0, 3);
    assert_eq!(c.get_stats().requests, 3);
}

// ------------------------------------------------------------------ 16. registration and policy

#[test]
fn register_agent_checks() {
    let mut c = setup();
    let reg = |c: &mut Tripwire, id: &str, p: Policy| c.register_agent(acc(id), "a".into(), p);
    guardian(T0);
    assert_panics(OWNER_ERR, || reg(&mut c, "a2.testnet", policy()));
    set("owner.testnet", T0, 0);
    assert_panics("1 yoctoNEAR", || reg(&mut c, "a2.testnet", policy()));
    owner(T0);
    for id in ["vault.testnet", "owner.testnet", "guardian.testnet"] {
        assert_panics("An agent must be a separate account", || reg(&mut c, id, policy()));
    }
    assert_panics("Agent is already registered", || reg(&mut c, "agent.testnet", policy()));

    let cases: Vec<(Box<dyn Fn(&mut Policy)>, &str)> = vec![
        (Box::new(|p| p.max_per_payment = U128(0)), "max_per_payment must be > 0"),
        (Box::new(|p| p.daily_limit = U128(0)), "daily_limit must be > 0"),
        (Box::new(|p| p.max_payments_per_hour = 0), "max_payments_per_hour must be between 1 and 300"),
        (Box::new(|p| p.max_payments_per_hour = 301), "max_payments_per_hour must be between 1 and 300"),
        (Box::new(|p| p.auto_freeze_after_blocks = 26), "auto_freeze_after_blocks must be at most 25"),
        (Box::new(|p| p.expires_at_ms = Some(U64(T0))), "expires_at_ms must be in the future"),
        (
            Box::new(|p| p.allowlist = (0..101).map(|i| acc(&format!("s{i}.testnet"))).collect()),
            "allowlist can hold at most 100 accounts",
        ),
    ];
    for (edit, msg) in cases {
        let mut p = policy();
        edit(&mut p);
        owner(T0);
        assert_panics(msg, || reg(&mut c, "a2.testnet", p));
    }
    assert_eq!(c.get_config().agents, 1);

    owner(T0);
    let mut p = policy();
    p.allowlist = vec![acc("shop.testnet"), acc("shop.testnet"), acc("mallory.testnet")];
    p.max_payments_per_hour = 300;
    p.auto_freeze_after_blocks = 25;
    let v = c.register_agent(acc("a2.testnet"), "  second \u{202e}agent\n".into(), p);
    assert_eq!(v.label, "second agent");
    assert_eq!(v.policy.allowlist, vec![acc("mallory.testnet"), acc("shop.testnet")]);
    assert_eq!(v.status, AgentStatus::Active);
    assert_eq!(event_names(), vec!["agent_registered"]);
    assert_eq!(last_data()["note"], "second agent");
    assert_eq!(c.get_config().agents, 2);
}

#[test]
fn update_policy_rules() {
    let mut c = setup();
    let mut p = policy();
    p.max_per_payment = U128(NEAR / 10);
    guardian(T0);
    assert_panics(OWNER_ERR, || c.update_policy(acc("agent.testnet"), p.clone()));
    owner(T0);
    assert_panics("Unknown agent", || c.update_policy(acc("nobody.testnet"), p.clone()));
    let mut bad = policy();
    bad.daily_limit = U128(0);
    assert_panics("daily_limit must be > 0", || c.update_policy(acc("agent.testnet"), bad));
    let v = c.update_policy(acc("agent.testnet"), p);
    assert_eq!(v.policy.max_per_payment.0, NEAR / 10);
    assert_eq!(event_names(), vec!["policy_updated"]);
    assert_eq!(pay(&mut c, T0 + 1, "shop.testnet", NEAR / 5).reasons, vec![Reason::OverPerPaymentCap]);
}

#[test]
fn remove_agent_cancels_pending_and_resets_payees() {
    let mut c = setup();
    pay(&mut c, T0, "shop.testnet", 3 * NEAR / 10);
    pay(&mut c, T0 + 1, "other.testnet", 8 * NEAR / 10);
    set("stranger.testnet", T0 + 2, 1);
    assert_panics(OWNER_ERR, || c.remove_agent(acc("agent.testnet")));
    owner(T0 + 2);
    assert_panics("Unknown agent", || c.remove_agent(acc("nobody.testnet")));
    assert_eq!(c.remove_agent(acc("agent.testnet")), 1);
    assert_eq!(event_names(), vec!["rejected", "agent_removed"]);
    assert_eq!(last_data()["note"], "cancelled 1 pending");
    assert_eq!(c.get_config().reserved.0, 0);
    assert_eq!(c.get_config().pending, 0);
    assert_eq!(c.get_config().agents, 0);
    assert!(c.get_agent(acc("agent.testnet")).is_none());

    owner(T0 + 5);
    c.register_agent(acc("agent.testnet"), "again".into(), policy());
    assert!(c.get_payee(acc("agent.testnet"), acc("shop.testnet")).is_none());
    assert_eq!(view(&c).payee_count, 0);
}

// ------------------------------------------------------------------ 20. activity ring

#[test]
fn activity_ring_pages_newest_first() {
    let mut c = setup();
    for i in 0..300 {
        set("donor.testnet", T0 + i, NEAR / 10);
        c.deposit();
    }
    let cfg = c.get_config();
    assert_eq!(cfg.activity_written.0, 301);
    let seqs = |page: &[LogEntry]| page.iter().map(|e| e.seq.0).collect::<Vec<_>>();

    let p1 = c.get_activity(None, Some(100));
    assert_eq!(seqs(&p1), (201..=300).rev().collect::<Vec<_>>());
    assert!(p1.iter().all(|e| e.kind == EventKind::Deposit));
    let p2 = c.get_activity(Some(U64(201)), Some(100));
    assert_eq!(seqs(&p2), (101..=200).rev().collect::<Vec<_>>());
    let p3 = c.get_activity(Some(U64(101)), Some(100));
    assert_eq!(p3.len(), 56);
    assert_eq!(seqs(&p3), (45..=100).rev().collect::<Vec<_>>());
    assert!(c.get_activity(Some(U64(45)), Some(100)).is_empty());
    assert_eq!(c.get_activity(None, None).len(), 50);
    assert_eq!(c.get_activity(None, Some(500)).len(), 100);
    assert_eq!(c.get_activity(Some(U64(10_000)), Some(1))[0].seq.0, 300);
    let e = &c.get_activity(Some(U64(46)), Some(1))[0];
    assert_eq!(e.seq.0, 45);
    assert_eq!(e.by, acc("donor.testnet"));
    assert_eq!(e.amount, Some(U128(NEAR / 10)));
}

#[test]
fn deposits() {
    let mut c = setup();
    set("donor.testnet", T0, 0);
    assert_panics("Attach a deposit", || c.deposit());
    let written = c.get_config().activity_written.0;
    set("donor.testnet", T0, 50 * MILLI);
    let avail = c.deposit();
    assert_eq!(avail, c.get_config().available);
    assert_eq!(event_names(), vec!["deposit"]);
    assert!(last_data().get("seq").is_none());
    assert_eq!(c.get_config().activity_written.0, written);
    set("donor.testnet", T0 + 1, NEAR / 10);
    c.deposit();
    assert!(last_data().get("seq").is_some());
    assert_eq!(c.get_config().activity_written.0, written + 1);
}

// ------------------------------------------------------------------ 21. text cleaning

#[test]
fn memos_are_cleaned_and_clipped() {
    let mut c = setup();
    let tagged = format!("hello{}", ['\u{E006E}', '\u{E006F}', '\u{E0074}', '\u{E0065}'].iter().collect::<String>());
    let r = pay_memo(&mut c, T0, "p0.testnet", 8 * NEAR / 10, Some(tagged));
    assert_eq!(c.get_pending_request(r.request_id).unwrap().memo.as_deref(), Some("hello"));

    let long = "\u{e9}".repeat(300);
    let r = pay_memo(&mut c, T0 + 1, "p1.testnet", 8 * NEAR / 10, Some(long));
    let memo = c.get_pending_request(r.request_id).unwrap().memo.unwrap();
    assert_eq!(memo.chars().count(), 128);
    assert_eq!(last_data()["note"].as_str().unwrap().chars().count(), 80);

    let r = pay_memo(&mut c, T0 + 2, "p2.testnet", 8 * NEAR / 10, Some(" \u{200b}\u{feff} ".into()));
    assert!(c.get_pending_request(r.request_id).unwrap().memo.is_none());
}

#[test]
fn clean_text_rules() {
    assert_eq!(clean_text("  a\u{202e}b\u{200b}c\n\td  ", 64), "abc  d");
    assert_eq!(clean_text("line\u{2028}two", 64), "line two");
    assert_eq!(clean_text("\u{e9}\u{e9}\u{e9}", 5), "\u{e9}\u{e9}");
    assert_eq!(clean_text("", 10), "");
    let mut s = String::from("h\u{e9}llo");
    truncate_utf8(&mut s, 2);
    assert_eq!(s, "h");
}

#[test]
fn canary_hash_parsing() {
    let mut c = setup();
    guardian(T0);
    let padded = format!("  {}  ", CANARY_HASH.to_uppercase());
    assert_eq!(c.add_canaries(vec![padded]), 1);
    let needle = "canary hash must be 64 hex characters";
    assert_panics(needle, || c.add_canaries(vec![CANARY_HASH[..63].to_string()]));
    let bad = format!("{}g", &CANARY_HASH[..63]);
    assert_panics(needle, || c.add_canaries(vec![bad]));
    assert_eq!(pay(&mut c, T0 + 1, CANARY, MILLI).status, PaymentStatus::Tripped);
}

// ------------------------------------------------------------------ 24. JSON shapes

#[test]
fn json_shapes() {
    let r = PaymentResult {
        status: PaymentStatus::Paid,
        request_id: U64(1),
        reasons: vec![],
        amount: U128(3 * NEAR / 10),
        receiver_id: acc("shop.testnet"),
        frozen: false,
    };
    let expected = r#"{"status":"paid","request_id":"1","reasons":[],"amount":"300000000000000000000000","receiver_id":"shop.testnet","frozen":false}"#;
    assert_eq!(serde_json::to_string(&r).unwrap(), expected);
    let wrapped: PromiseOrValue<PaymentResult> = PromiseOrValue::Value(r);
    assert_eq!(serde_json::to_string(&wrapped).unwrap(), expected);

    let p = serde_json::json!({
        "max_per_payment": "1", "daily_limit": "1", "approval_threshold": "1",
        "new_payee_limit": "1", "max_payments_per_hour": 1, "daily_limt": "5"
    });
    let err = serde_json::from_value::<Policy>(p).unwrap_err().to_string();
    assert!(err.contains("unknown field"), "{err}");
    let ok: Policy = serde_json::from_value(serde_json::json!({
        "max_per_payment": "1", "daily_limit": "1", "approval_threshold": "1",
        "new_payee_limit": "1", "max_payments_per_hour": 1
    }))
    .unwrap();
    assert!(!ok.allowlist_only && ok.allowlist.is_empty() && ok.expires_at_ms.is_none());

    assert_eq!(serde_json::to_string(&AgentStatus::Active).unwrap(), r#"{"state":"active"}"#);
    let f = AgentStatus::Frozen { reason: "x".into(), by: acc("g.testnet"), at_ms: U64(5) };
    assert_eq!(serde_json::to_string(&f).unwrap(), r#"{"state":"frozen","reason":"x","by":"g.testnet","at_ms":"5"}"#);
    assert_eq!(serde_json::to_string(&Reason::NewPayee).unwrap(), r#""NEW_PAYEE""#);
    assert_eq!(serde_json::to_string(&Verdict::Warn).unwrap(), r#""warn""#);
    assert_eq!(serde_json::to_string(&PaymentStatus::PendingApproval).unwrap(), r#""pending_approval""#);
    assert_eq!(serde_json::to_string(&EventKind::TransferFailed).unwrap(), r#""transfer_failed""#);
    assert_eq!(serde_json::to_string(&BlockStatus::Confirmed).unwrap(), r#""confirmed""#);
}

#[test]
fn reason_verdicts() {
    assert_eq!(Reason::Tripwire.verdict(), Verdict::Trip);
    for r in [Reason::ReportedReceiver, Reason::NewPayee, Reason::NeedsApproval] {
        assert_eq!(r.verdict(), Verdict::Warn);
    }
    for r in [Reason::AgentFrozen, Reason::Blocklisted, Reason::OverDailyLimit, Reason::TooManyPending, Reason::UnknownAgent] {
        assert_eq!(r.verdict(), Verdict::Block);
    }
}

// ------------------------------------------------------------------ 28. canaries

#[test]
fn canary_management() {
    let mut c = setup();
    set("stranger.testnet", T0, 0);
    assert_panics(OWNER_OR_GUARDIAN_ERR, || c.add_canaries(vec![CANARY_HASH.into()]));
    guardian(T0);
    let decoy = hash_of("decoy-1.testnet");
    assert_eq!(c.add_canaries(vec![CANARY_HASH.into(), decoy.clone(), CANARY_HASH.into()]), 2);
    assert_eq!(event_names(), vec!["canaries_added"]);
    assert_eq!(last_data()["note"], "added 2");
    assert_eq!(c.get_config().canaries, 2);
    guardian(T0 + 1);
    assert_eq!(c.add_canaries(vec![decoy.clone()]), 0);
    assert!(get_logs().is_empty());
    let many: Vec<String> = (0..51).map(|i| hash_of(&format!("d{i}.testnet"))).collect();
    assert_panics("At most 50 canaries per call", || c.add_canaries(many));
    assert_eq!(c.get_stats().canaries_added, 2);

    guardian(T0 + 2);
    assert_panics(OWNER_ERR, || c.remove_canary(decoy.clone()));
    owner(T0 + 2);
    assert!(c.remove_canary(decoy.clone()));
    assert_eq!(event_names(), vec!["canary_removed"]);
    assert!(!c.remove_canary(decoy));
    assert_eq!(c.get_config().canaries, 1);
    // A removed canary no longer trips.
    assert_eq!(pay(&mut c, T0 + 3, "decoy-1.testnet", MILLI).status, PaymentStatus::Paid);
}

#[test]
fn approve_refuses_hidden_watchlist_receiver() {
    let mut c = setup();
    pay(&mut c, T0, "decoy-1.testnet", 8 * NEAR / 10);
    guardian(T0 + 1);
    c.add_canaries(vec![hash_of("decoy-1.testnet")]);
    owner(T0 + 2);
    assert_panics("Receiver is on a hidden watchlist; reject this request", || c.approve(U64(1)));
    assert_eq!(c.get_config().pending, 1);
}

// ------------------------------------------------------------------ 29. guardians and ownership

#[test]
fn guardian_management() {
    let mut c = setup();
    guardian(T0);
    assert_panics(OWNER_ERR, || c.add_guardian(acc("g2.testnet")));
    owner(T0);
    assert_panics("The owner cannot also be a guardian", || c.add_guardian(acc("owner.testnet")));
    assert_panics("An agent cannot be a guardian", || c.add_guardian(acc("agent.testnet")));
    assert_panics("Already a guardian", || c.add_guardian(acc("guardian.testnet")));
    for i in 0..9 {
        owner(T0 + i);
        c.add_guardian(acc(&format!("g{i}.testnet")));
    }
    assert_eq!(event_names(), vec!["guardian_added"]);
    assert_eq!(last_data()["note"], "g8.testnet");
    assert_eq!(c.get_config().guardians.len(), 10);
    owner(T0 + 10);
    assert_panics("Too many guardians (max 10)", || c.add_guardian(acc("g9.testnet")));
    assert_panics("Not a guardian", || c.remove_guardian(acc("nobody.testnet")));
    let gs = c.remove_guardian(acc("guardian.testnet"));
    assert_eq!(gs.len(), 9);
    assert!(!gs.contains(&acc("guardian.testnet")));
    assert_eq!(event_names(), vec!["guardian_removed"]);
    // A removed guardian loses its powers.
    guardian(T0 + 11);
    assert_panics(OWNER_OR_GUARDIAN_ERR, || c.pause(None));
}

#[test]
fn ownership_transfer_is_two_step() {
    let mut c = setup();
    guardian(T0);
    assert_panics(OWNER_ERR, || c.propose_owner(acc("new.testnet")));
    owner(T0);
    assert_panics("An agent cannot be the owner", || c.propose_owner(acc("agent.testnet")));
    assert_panics("Remove the account from the guardians", || c.propose_owner(acc("guardian.testnet")));
    set("new.testnet", T0, 1);
    assert_panics("No ownership transfer is pending", || c.accept_owner());

    owner(T0 + 1);
    c.propose_owner(acc("new.testnet"));
    assert_eq!(event_names(), vec!["owner_proposed"]);
    assert_eq!(c.get_config().pending_owner, Some(acc("new.testnet")));
    set("stranger.testnet", T0 + 2, 1);
    assert_panics("Only the proposed owner can accept ownership", || c.accept_owner());
    set("new.testnet", T0 + 2, 0);
    assert_panics("1 yoctoNEAR", || c.accept_owner());
    set("new.testnet", T0 + 2, 1);
    c.accept_owner();
    assert_eq!(event_names(), vec!["owner_changed"]);
    assert_eq!(last_data()["note"], "owner.testnet -> new.testnet");
    let cfg = c.get_config();
    assert_eq!(cfg.owner_id, acc("new.testnet"));
    assert!(cfg.pending_owner.is_none());
    owner(T0 + 3);
    assert_panics(OWNER_OR_GUARDIAN_ERR, || c.pause(None));
    assert_panics(OWNER_ERR, || c.withdraw(U128(NEAR)));
}

#[test]
fn proposing_self_cancels_transfer() {
    let mut c = setup();
    owner(T0);
    c.propose_owner(acc("new.testnet"));
    owner(T0 + 1);
    c.propose_owner(acc("owner.testnet"));
    assert_eq!(last_data()["note"], "proposal cancelled");
    assert!(c.get_config().pending_owner.is_none());
    set("new.testnet", T0 + 2, 1);
    assert_panics("No ownership transfer is pending", || c.accept_owner());
}

#[test]
fn guardian_promoted_after_proposal_cannot_accept() {
    let mut c = setup();
    owner(T0);
    c.propose_owner(acc("new.testnet"));
    owner(T0 + 1);
    c.add_guardian(acc("new.testnet"));
    set("new.testnet", T0 + 2, 1);
    assert_panics("Remove the account from the guardians", || c.accept_owner());
}

// ------------------------------------------------------------------ 32. approve refusals

#[test]
fn approve_refused_while_paused() {
    let mut c = setup();
    pay(&mut c, T0, "shop.testnet", 8 * NEAR / 10);
    guardian(T0 + 1);
    c.pause(None);
    owner(T0 + 2);
    assert_panics("Vault is paused; unpause before approving", || c.approve(U64(1)));
}

#[test]
fn approve_refused_for_blocklisted_receiver() {
    let mut c = setup();
    pay(&mut c, T0, "shop.testnet", 8 * NEAR / 10);
    guardian(T0 + 1);
    c.block_receiver(acc("shop.testnet"), "confirmed scam".into(), None);
    owner(T0 + 2);
    assert_panics("Receiver is blocklisted; reject this request", || c.approve(U64(1)));
    guardian(T0 + 3);
    c.reject(U64(1), None);
}

#[test]
fn approve_refused_when_balance_too_low() {
    let mut c = setup();
    pay(&mut c, T0, "shop.testnet", 8 * NEAR / 10);
    // 0.5 NEAR balance: 0.4 free, 0.35 available once the reservation is released.
    ctx_bal("owner.testnet", T0 + 1, 1, NEAR / 2);
    assert_eq!(c.available_after_release(8 * NEAR / 10), 35 * NEAR / 100 + 1);
    assert_panics("Vault balance is too low for this payment", || c.approve(U64(1)));
    assert_eq!(c.get_config().pending, 1);
}

#[test]
fn approve_can_exceed_soft_limits_but_not_daily() {
    // approve overrides the soft warnings, and the reservation keeps the daily cap intact.
    let mut c = setup();
    pay(&mut c, T0, "shop.testnet", 15 * NEAR / 10);
    owner(T0 + 1);
    expect_promise(c.approve(U64(1)));
    assert_eq!(view(&c).spent_24h.0, 15 * NEAR / 10);
    assert_eq!(view(&c).remaining_24h.0, 35 * NEAR / 10);
}

// ------------------------------------------------------------------ pagination

#[test]
fn pagination_views() {
    let mut c = setup();
    for i in 0..3 {
        owner(T0 + i);
        c.register_agent(acc(&format!("a{i}.testnet")), format!("agent {i}"), policy());
    }
    assert_eq!(c.list_agents(None, None).len(), 4);
    let page = c.list_agents(Some(1), Some(2));
    assert_eq!(page.len(), 2);
    assert_eq!(c.list_agents(Some(10), None).len(), 0);

    for i in 0..3 {
        pay(&mut c, T0 + 10, &format!("p{i}.testnet"), 8 * NEAR / 10);
    }
    let pend = c.get_pending(None, None);
    assert_eq!(pend.len(), 3);
    assert_eq!(c.get_pending(Some(2), Some(5)).len(), 1);
    assert_eq!(c.get_pending_request(U64(2)).unwrap(), pend[1]);
    assert!(c.get_pending_request(U64(99)).is_none());

    guardian(T0 + 20);
    for i in 0..3 {
        c.block_receiver(acc(&format!("b{i}.testnet")), "bad".into(), None);
    }
    assert_eq!(c.get_blocklist(None, None).len(), 3);
    assert_eq!(c.get_blocklist(Some(1), Some(1)).len(), 1);
    assert!(c.get_block_entry(acc("b9.testnet")).is_none());
}

// ------------------------------------------------------------------ environmental blocks

#[test]
fn insufficient_balance_blocks_do_not_auto_freeze() {
    let mut c = setup_with(auto_policy(3));
    for i in 1..=6 {
        // 1 NEAR balance: 0.85 NEAR available, so 0.9 NEAR is refused.
        ctx_bal("agent.testnet", T0 + i, 0, NEAR);
        let (r, p) = c.submit_payment(acc("shop.testnet"), U128(9 * NEAR / 10), None);
        drop(p);
        assert_eq!(r.status, PaymentStatus::Blocked);
        assert!(r.reasons.contains(&Reason::InsufficientVaultBalance));
        assert!(!r.frozen, "attempt {i}");
        assert_eq!(event_names(), vec!["blocked"]);
    }
    let v = view(&c);
    assert_eq!(v.status, AgentStatus::Active);
    assert_eq!(v.counters.blocked, 6);
    assert_eq!(v.blocks_last_hour, 0);
    assert_eq!(c.get_stats().blocked, 6);
    // A real hard block still counts toward auto-freeze.
    for i in 1..=2 {
        assert!(!pay(&mut c, T0 + 10 + i, "shop.testnet", 3 * NEAR).frozen);
    }
    assert!(pay(&mut c, T0 + 13, "shop.testnet", 3 * NEAR).frozen);
    assert_eq!(view(&c).counters.blocked, 9);
}

#[test]
fn hard_reason_with_low_balance_still_counts() {
    let mut c = setup_with(auto_policy(1));
    // Over the per-payment cap and over the balance: not environmental.
    ctx_bal("agent.testnet", T0 + 1, 0, NEAR);
    let (r, p) = c.submit_payment(acc("shop.testnet"), U128(3 * NEAR), None);
    drop(p);
    assert!(r.reasons.contains(&Reason::OverPerPaymentCap));
    assert!(r.reasons.contains(&Reason::InsufficientVaultBalance));
    assert!(r.frozen);
}

#[test]
fn full_approval_queue_does_not_auto_freeze() {
    let mut c = setup_with(auto_policy(1));
    for i in 0..5 {
        assert_eq!(pay(&mut c, T0, &format!("p{i}.testnet"), 8 * NEAR / 10).status, PaymentStatus::PendingApproval);
    }
    for i in 0..4 {
        let r = pay(&mut c, T0 + 1 + i, &format!("q{i}.testnet"), 8 * NEAR / 10);
        assert_eq!(r.reasons, vec![Reason::NewPayee, Reason::TooManyPending]);
        assert!(!r.frozen);
    }
    assert_eq!(view(&c).status, AgentStatus::Active);
    assert_eq!(view(&c).counters.blocked, 4);
    assert_eq!(c.get_config().pending, 5);
}

#[test]
fn environmental_block_classification() {
    use Reason::*;
    assert!(is_environmental_block(&[InsufficientVaultBalance]));
    assert!(is_environmental_block(&[NewPayee, NeedsApproval, TooManyPending]));
    assert!(is_environmental_block(&[ReportedReceiver, TooManyPending]));
    assert!(!is_environmental_block(&[]));
    assert!(!is_environmental_block(&[NewPayee]));
    assert!(!is_environmental_block(&[OverDailyLimit, InsufficientVaultBalance]));
    assert!(!is_environmental_block(&[Blocklisted, TooManyPending]));
}

// ------------------------------------------------------------------ report review

#[test]
fn privileged_reports_ignore_open_report_cap() {
    let mut c = setup();
    c.open_reports = MAX_OPEN_REPORTS;
    set("agent.testnet", T0, 0);
    assert_panics("Too many open reports", || c.report_receiver(acc("r.testnet"), "odd".into(), None));
    guardian(T0 + 1);
    c.report_receiver(acc("r1.testnet"), "odd".into(), None);
    set("owner.testnet", T0 + 2, 0);
    c.report_receiver(acc("r2.testnet"), "odd".into(), None);
    assert_eq!(c.get_config().open_reports, MAX_OPEN_REPORTS + 2);
}

#[test]
fn guardian_dismisses_reported_entry() {
    let mut c = setup();
    set("agent.testnet", T0, 0);
    c.report_receiver(acc("shop.testnet"), "odd".into(), None);
    assert_eq!(c.get_config().open_reports, 1);
    guardian(T0 + 1);
    assert!(c.dismiss_report(acc("shop.testnet")));
    assert_eq!(event_names(), vec!["unblocklisted"]);
    assert!(c.get_block_entry(acc("shop.testnet")).is_none());
    assert_eq!(c.get_config().open_reports, 0);
    // Nothing left to dismiss.
    assert!(!c.dismiss_report(acc("shop.testnet")));
    // The owner can dismiss too (free call).
    set("agent.testnet", T0 + 2, 0);
    c.report_receiver(acc("shop2.testnet"), "odd".into(), None);
    set("owner.testnet", T0 + 3, 0);
    assert!(c.dismiss_report(acc("shop2.testnet")));
    assert_eq!(c.get_config().open_reports, 0);
}

#[test]
fn dismissing_confirmed_entry_returns_false() {
    let mut c = setup();
    guardian(T0);
    c.block_receiver(acc("bad.testnet"), "scam".into(), None);
    assert!(!c.dismiss_report(acc("bad.testnet")));
    assert_eq!(c.get_block_entry(acc("bad.testnet")).unwrap().status, BlockStatus::Confirmed);
}

#[test]
fn only_owner_or_guardian_can_dismiss() {
    let mut c = setup();
    set("agent.testnet", T0, 0);
    c.report_receiver(acc("shop.testnet"), "odd".into(), None);
    assert_panics(OWNER_OR_GUARDIAN_ERR, || c.dismiss_report(acc("shop.testnet")));
    set("mallory.testnet", T0 + 1, 0);
    assert_panics(OWNER_OR_GUARDIAN_ERR, || c.dismiss_report(acc("shop.testnet")));
    assert_eq!(c.get_config().open_reports, 1);
}

#[test]
fn unblock_receivers_in_bulk() {
    let mut c = setup();
    guardian(T0);
    c.block_receiver(acc("a.testnet"), "scam".into(), None);
    c.report_receiver(acc("b.testnet"), "odd".into(), None);
    assert_eq!(c.get_config().open_reports, 1);
    owner(T0 + 1);
    let n = c.unblock_receivers(vec![acc("a.testnet"), acc("b.testnet"), acc("c.testnet")]);
    assert_eq!(n, 2);
    assert_eq!(event_names(), vec!["unblocklisted", "unblocklisted"]);
    assert!(c.get_blocklist(None, None).is_empty());
    assert_eq!(c.get_config().open_reports, 0);
    let many: Vec<AccountId> = (0..101).map(|i| acc(&format!("x{i}.testnet"))).collect();
    assert_panics("At most 100 receivers per call", || c.unblock_receivers(many));
    guardian(T0 + 2);
    assert_panics(OWNER_ERR, || c.unblock_receivers(vec![]));
    set("owner.testnet", T0 + 3, 0);
    assert_panics("Requires attached deposit of exactly 1 yoctoNEAR", || c.unblock_receivers(vec![]));
}

#[test]
fn free_agent_report_needs_storage_balance() {
    let mut c = setup();
    // 0.155 NEAR balance: 0.1 locked, 0.05 margin, 0.005 available < 0.01 storage estimate.
    let low = 155 * MILLI;
    ctx_bal("agent.testnet", T0, 0, low);
    assert_panics("Vault balance is too low to store a new report", || {
        c.report_receiver(acc("r.testnet"), "odd".into(), None)
    });
    // The owner, guardians and deposit payers are not limited.
    ctx_bal("guardian.testnet", T0 + 1, 0, low);
    c.report_receiver(acc("r.testnet"), "odd".into(), None);
    ctx_bal("stranger.testnet", T0 + 2, 10 * MILLI, low);
    c.report_receiver(acc("r2.testnet"), "odd".into(), None);
    // Re-reporting an existing entry stores nothing new.
    ctx_bal("agent.testnet", T0 + 3, 0, low);
    assert_eq!(c.report_receiver(acc("r.testnet"), "odd".into(), None).reports, 2);
    // With enough balance the agent can report again.
    ctx_bal("agent.testnet", T0 + 4, 0, NEAR);
    c.report_receiver(acc("r3.testnet"), "odd".into(), None);
    assert_eq!(c.get_config().open_reports, 3);
}
