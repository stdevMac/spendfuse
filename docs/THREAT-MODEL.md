# Threat model

This document lists what Spendfuse protects, who it protects against, and where each control is
enforced. It also lists what Spendfuse does not protect against. See `ARCHITECTURE.md` for how the
parts fit together.

Each mitigation is tagged with the layer that enforces it:

- **Protocol**: the NEAR runtime's access-key rules. Nothing in this repo can weaken them.
- **Contract**: `contract/src/lib.rs`, running on chain. This is the real enforcement.
- **Off-chain**: the agent runtime, guard, scout and dashboard (`src/`). Advisory. Anyone who holds
  the agent key can skip it.

The proof column names a contract unit test (`contract/src/tests.rs`, run with
`npm run test:contract`), a TypeScript test (`test/*.test.ts`, run with `npm test`), or a live
scenario from `npm run demo` (`src/agent/scenarios.ts`). The latest live run is committed as
`docs/proofs/live-run-2026-11-09T04-59-38-380Z.json` and `docs/proofs/live-demo-2026-11-09.log`
(canary ids shortened); it ran 2026-11-09 04:59:38-05:00:59 UTC and passed 8 of 8 scenarios on
testnet, using the scripted model. New
runs of `npm run demo` are saved to `.spendfuse/runs/`. `npm run demo:dry` runs the same scenarios
offline on `FakeChain`.

## Assets

1. **Vault funds.** NEAR held by `vault.tw-firewall-demo.testnet`.
2. **Policy and roles.** Each agent's `Policy`, the owner, the guardian list, the agent list.
3. **Canary identities.** The plain account ids of the decoy payees. Only their sha256 hashes are on
   chain. The ids live in `.spendfuse/canaries.json` on the operator's machine. This only holds until
   a canary trips: the trip transaction's `receiver_id` is the full id, so a tripped canary is public
   and should be rotated (`remove_canary`, then plant a new one). The demo canary has tripped on
   testnet and is public.
4. **Owner and guardian keys.** Full-access keys kept in `.env`.
5. **Audit trail.** NEP-297 event logs, the 256-entry activity ring, and the stats counters.
6. **Reserved funds.** Amounts held for pending approvals.

## Actors

| Actor | Trust | Capabilities |
|---|---|---|
| Owner | Fully trusted | Full-access key. All owner methods (1 yocto). Can approve, unfreeze, unpause, withdraw, change policy. |
| Guardian | Trusted to make things stricter | Free calls: freeze, pause, reject, block receiver, add canaries, dismiss report. |
| Agent (honest model) | Not trusted with funds | A function-call key on the vault for `request_payment`, `self_freeze`, `report_receiver`. |
| Attacker with the stolen agent key | Hostile | Everything the agent key can sign, with no off-chain guard in the way. |
| Attacker who prompt-injects the agent | Hostile | Controls the content of documents the model reads, and so possibly the model's tool calls. Does not hold the key. |
| Malicious payee | Hostile | Controls a receiver account: can be new, look like a known name, deploy code, delete and recreate itself. |

## Threats and mitigations

### T1. Stolen agent key is used to move funds directly

| Mitigation | Layer | Proof |
|---|---|---|
| The agent account only holds a function-call key (created in `src/scripts/setup-testnet.ts`). A function-call key cannot send a `Transfer`, add keys, call another contract, call a method outside its list, or attach a deposit. | Protocol | Live scenario 6 `stolen-key`: five attempts were rejected with `RequiresFullAccess` (transfer), `MethodNameMismatch` (`withdraw`), `RequiresFullAccess` (add a full-access key), `ReceiverMismatch` (another contract), `DepositWithFunctionCall` (deposit). |
| Every owner method needs exactly 1 yoctoNEAR (`assert_one_yocto`), so a function-call key cannot call it even if the method name were allowed. | Protocol + Contract | `approve_needs_owner_and_one_yocto`, `withdraw_rules` |
| Agent methods check that the caller is a registered agent. | Contract | `strangers_cannot_act_as_agents` |
| The dashboard checks each agent's keys and flags any full-access key or a key for another receiver (`keyProof`). | Off-chain | `test/server.test.ts`: "keyProof flags full-access and off-vault keys" |

### T2. Stolen agent key is used to drain within `request_payment`

| Mitigation | Layer | Proof |
|---|---|---|
| Per-payment cap, hourly count, and rolling 24 h limit that also counts reserved amounts. | Contract | `per_payment_cap`, `hourly_rate_limit`, `daily_limit_rolls_over_24_hours`, `reserved_amounts_count_against_daily_limit`; live scenario 7 `bypass-cap`: a raw 1.5 NEAR request was blocked with `OVER_PER_PAYMENT_CAP` |
| Payments above `approval_threshold`, and new payees above `new_payee_limit`, wait for the owner. | Contract | `escalate_then_approve`; live scenario 5 `over-threshold` (held `NEEDS_APPROVAL`, approved, paid) |
| Many small payments to fresh accounts ("salami"): every counted block in the last hour goes toward `auto_freeze_after_blocks`, with a hard backstop of 25. | Contract | `repeated_blocks_auto_freeze`, `spaced_blocks_do_not_freeze`, `default_backstop_freezes_after_25_blocks`; live scenario 3 `salami` ended in `AUTO_FREEZE` after 3 blocks with `OVER_DAILY_LIMIT`; for that scenario the owner set `auto_freeze_after_blocks` to 3 and `daily_limit` to 0.3 NEAR above the 24 h spend; `npm run demo:dry` gives the same result |
| After 256 payees, every new payee needs approval. | Contract | `payee_cap_forces_review_of_new_payees` |
| Optional `allowlist_only` mode and optional policy expiry. | Contract | `allowlist_only_mode`, `policy_expiry` |
| A payment can never use storage stake or reserved funds. | Contract | `vault_balance_is_checked`, `withdraw_cannot_touch_reserved_funds` |
| A freeze cancels all pending requests of that agent. | Contract | `auto_freeze_cancels_pending` |

What is left: see L3.

### T3. Prompt injection redirects a payment

| Mitigation | Layer | Proof |
|---|---|---|
| Documents are wrapped as untrusted data and the system prompt says not to follow them. | Off-chain (model hint only) | Not a control. The scripted model in scenario 2 falls for the injection on purpose. |
| Tool arguments are parsed strictly (`parseToolCall`): unknown keys, bad account ids, bad amounts and control characters are refused. | Off-chain | `test/agent.test.ts`: "pay parsing is strict" |
| A payee this agent has never paid, above `new_payee_limit`, is escalated to the owner. | Contract | `escalate_then_approve` (a new payee is held with `NEW_PAYEE`); live scenario 2 `injection`: the injected 0.4 NEAR refund to `feed` is held `pending_approval [NEW_PAYEE]` and the owner rejects it; nothing is paid. `npm run demo:dry` gives the same result. |
| The guard holds payments locally on scout warnings, or when the model turn is not verified (`UNVERIFIED_TURN`). | Off-chain | `test/agent.test.ts`: "an unverified model turn is held locally and nothing is sent" |
| The model only learns `paid ...`, `refused`, `pending human approval` or a transfer-failed note, so it cannot probe the policy or the canary list through tool results. | Off-chain | Live scenario 4 `canary` checks that the model saw exactly `refused` (`noLeak`). |
| The model is told to call `self_freeze` if it thinks it is being manipulated. | Contract method, model decides | `self_freeze` |

### T4. The attacker is caught by a canary

Canaries are for an attacker (or a hijacked model) who pays an address they found in the
operator's material. A canary is never paid by an honest flow.

| Mitigation | Layer | Proof |
|---|---|---|
| A payment to a canary hash returns `tripped` and freezes the agent at once, even while the vault is paused. | Contract | `canary_trips_and_freezes_agent`, `canary_trips_even_while_paused`; live scenario 4 `canary`: tripped `[TRIPWIRE]`, agent frozen |
| Only hashes are stored on chain. `check_payment` hides canaries. `approve` refuses them. | Contract | `check_payment_hides_canaries`, `approve_refuses_hidden_watchlist_receiver`, `canary_management` |
| If the guard spots a canary, it still sends the payment so the vault trips. If the probe fails, it refuses (`CANARY_PROBE_FAILED`). | Off-chain | `test/agent.test.ts`: "a canary payment trips the vault and the model sees only \"refused\""; live scenario 4. The probe-failure path has no test. |
| Canary ids are shortened to 8 characters in saved and served run logs. This only avoids putting a ready-to-paste copy of a still-planted canary in the repo or dashboard; a tripped canary's id is already public in its trip tx args. | Off-chain | Code only: `redactCanaryIds` in `src/server/backend.ts`. No test. |
| A drill checks the whole path end to end. | Contract + off-chain | `npm run drill:dry` (offline). `npm run drill` sends live transactions. |

### T5. Malicious payee

| Mitigation | Layer | Proof |
|---|---|---|
| Scout blocks invalid ids, burn addresses, accounts that do not exist, and accounts whose funds could not be recovered (no full-access key and no contract). It warns on lookalikes of allowlisted names, new or recreated accounts, unknown account age, accounts deleted before, low activity, contracts, global contracts a third party can upgrade, recent deploys, changed code, implicit ids that the transfer would create, uninitialized universal accounts, self-payment, and checks that could not run. Results are cached for 60 s. At runtime the scout also reads the vault's blocklist (`get_block_entry`) for the receiver and its parent accounts: a confirmed parent blocks (`PARENT_REPORTED`), a reported one warns. It does not check pinned contracts (see L16). | Off-chain | Live scenario 8 `missing-receiver`: guard refused with `ACCOUNT_DOES_NOT_EXIST`. There are no unit tests for the individual scout checks yet, and no live run has hit a listed entry (the demo vault's blocklist is empty). |
| If a transfer fails (for example the account does not exist), the callback rolls back spend, payee record and totals. | Contract | `failed_transfer_rolls_back_accounting`; live scenario 8: raw send gave `transfer_failed` and a rollback |
| Anyone can report a receiver (free for owner, guardians and up to 20 per agent; others pay 0.01 NEAR, which the vault keeps). A reported receiver needs approval; a confirmed one is blocked. | Contract | `reports_warn_and_blocklist_blocks`, `free_reports_are_capped_per_agent`, `frozen_agent_must_pay_to_report`, `free_agent_report_needs_storage_balance` |
| Allowlisted receivers ignore reports, so a stranger cannot block the operator's known payees. | Contract | `allowlisted_payees_ignore_reports` |
| Memos and other text are cleaned of hidden, bidi and control characters before they are stored. | Contract | `memos_are_cleaned_and_clipped`, `clean_text_rules` |

### T6. Approving the wrong thing

| Mitigation | Layer | Proof |
|---|---|---|
| `approve` re-checks pause, frozen agent, confirmed blocklist, canary and vault balance. | Contract | `approve_refused_while_paused`, `approve_refused_for_blocklisted_receiver`, `approve_refuses_hidden_watchlist_receiver`, `approve_refused_when_balance_too_low` |
| Approval overrides only soft signals; the daily limit was enforced when the request was made. | Contract | `approve_can_exceed_soft_limits_but_not_daily` |
| Pending requests expire after 24 h. | Contract | `pending_requests_expire` |
| The queue is bounded (5 per agent, 100 total). | Contract | `pending_queue_is_capped_per_agent`, `full_approval_queue_does_not_auto_freeze` |

### T7. Takeover of the owner role or roles

| Mitigation | Layer | Proof |
|---|---|---|
| Ownership transfer is two-step (`propose_owner`, then `accept_owner` by the new account). | Contract | `ownership_transfer_is_two_step`, `guardian_promoted_after_proposal_cannot_accept` |
| Guardians cannot approve, unfreeze, unpause, withdraw, change policy, unblock or remove canaries. | Contract | `freeze_and_unfreeze_roles`, `reject_by_guardian`, `only_owner_or_guardian_can_dismiss`, `guardian_management` |

### T8. Attacks on the local dashboard

| Mitigation | Layer | Proof |
|---|---|---|
| Binds to `127.0.0.1`, checks the `Host` header (DNS rebinding), needs a random per-process token on every action, refuses cross-origin POSTs, caps body size, sends a strict CSP. `READONLY=1` turns all actions off. | Off-chain | `test/server.test.ts` |

## Out of scope and known limitations

These are true of the current code. They are listed so a reviewer does not have to find them.

**L1. The owner key is total trust.** Anyone with `OWNER_KEY` can withdraw, change policy and
unfreeze. Spendfuse does not protect against a compromised owner. The dashboard process holds the
owner key when it runs with actions on.

**L2. The vault still has a full-access key until lockdown.** `npm run lockdown` is planned for just
before submission and has not been run yet. `npm run lockdown:dry` previews it with view calls only
(no key needed). It
deletes the vault's own key (`src/scripts/lockdown.ts`) and refuses if another full-access key is
present. Until it is run, whoever holds `VAULT_KEY` can redeploy the contract or move funds.
`npm run status` shows the current key state; after lockdown it prints
`vault locked: no full-access keys`. After lockdown the contract cannot be upgraded;
fixing a bug means deploying a new vault and moving funds to it.

**L3. A stolen agent key can still spend inside the policy (salami under `new_payee_limit`).**
A first payment to a fresh payee needs approval only when it is above `new_payee_limit`, so
payments at or below it go through, up to `max_payments_per_hour` and `daily_limit`. With the
policy set by `npm run setup` (0.2 NEAR new-payee limit, 0.5 NEAR approval threshold, 10 payments
per hour, 3 NEAR per rolling 24 h): an attacker paying 0.19 NEAR per tx to fresh payees gets 10
payments (1.9 NEAR) in the first hour and 5 more in the second, 15 in all = 2.85 NEAR; the 16th
would pass 3 NEAR and is blocked `OVER_DAILY_LIMIT`. At exactly 0.2 NEAR it is 2 NEAR in the first
hour and 3 NEAR after 15 payments. Allowlisted payees skip the new-payee and report checks, so the
same 3 NEAR can go to the allowlisted shop in 6 payments of 0.5 NEAR. None of these is a block, so
auto-freeze never fires. The real bound is `daily_limit` per rolling 24 h (3 NEAR), repeating every
24 h until the owner freezes the agent. The policy bounds the loss; it does not make it zero.
Live scenario 3 does not show this bound: to show the freeze mechanics it tightens the policy
(`daily_limit` 0.3 NEAR above the 24 h spend, `auto_freeze_after_blocks: 3`), so the first 0.25
NEAR part was held and the next 3 parts were `OVER_DAILY_LIMIT` blocks, which froze the agent. The
default freeze threshold is the backstop of 25 blocks per hour. Under the setup policy the same
0.25 NEAR parts would each be held as `NEW_PAYEE` (0.25 > 0.2), and after 5 pending requests the
rest are blocked `TOO_MANY_PENDING`, which never counts toward auto-freeze (L10); nothing is paid
without the owner.

**L4. Canaries only catch attackers who do not check.** Canary hashes are unsalted, and contract
state is public. Anyone can hash a candidate id and look it up with `view_state`, which is what the
Spendfuse guard itself does (`LiveChain.isCanary`). The ids are random implicit accounts, so they
cannot be guessed, but an attacker who already holds an id can test it before paying. Once a canary
trips, its id is public in the trip transaction's arguments; rotate it (`remove_canary`, then plant
a new one).

**L5. The off-chain guard can be skipped.** With the agent key, an attacker calls
`request_payment` directly. Scenarios 7 and 8 do this on purpose. Only contract and protocol rules
hold in that case. Scout checks (account age, lookalikes, code changes) are off-chain only.

**L6. The canary probe depends on the storage layout.** `LiveChain.isCanary` assumes the borsh key
`0x01 || sha256(id)`. The code marks this as unverified; live scenario 4 confirms it on the
deployed contract. A change to `StorageKey` order would break the probe. The guard would then
treat a canary as an ordinary receiver, and the vault would still trip on it.

**L7. Scout depends on third parties.** It reads NEAR RPC, archival RPC, FastNear and NearBlocks.
If they are wrong or down, results degrade. A failed scout is a `warn` and a held payment, not an
allow.

**L8. Guardians can cause denial of service and lock storage.** A guardian can pause the vault,
freeze agents and reject every request; only the owner can undo a pause or freeze. A guardian can
add up to 1000 blocklist entries and 1000 canary hashes, which lock vault storage stake until the
owner calls `unblock_receivers` or `remove_canary`. A guardian can also `dismiss_report`, which
removes a reported (not confirmed) entry and so removes that soft signal.

**L9. Report griefing.** Each agent has 20 free reports in its lifetime (only while not frozen),
and anyone can report for 0.01 NEAR. Reports from accounts other than the owner and guardians
stop at 200 open reports. A reported payee goes to the approval queue. This can slow
payments to a non-allowlisted payee but cannot move funds.

**L10. Environmental blocks never auto-freeze.** A block caused only by `INSUFFICIENT_VAULT_BALANCE`
or `TOO_MANY_PENDING` is not counted, so an empty or full vault does not freeze honest agents
(`insufficient_balance_blocks_do_not_auto_freeze`, `environmental_block_classification`). A key
thief can send many of these; each one writes a ring entry, so older activity can be pushed out
of the 256-entry ring. No funds move, the full history stays in the NEP-297 logs, and the gas
allowance on the agent key (1 NEAR) bounds the spam.

**L11. Leftover storage.** `remove_agent` does not delete that agent's payee records, so their
storage stays locked.

**L12. Conservative accounting.** A failed transfer is rolled back in the spend, payee and total
amounts, but not in the hourly payment count or the `paid` count in the stats. The 24 h window keeps buckets for 24 to 25 hours.
Both err on the strict side.

**L13. Model trust is limited.** The live proof run used the scripted model, not a real LLM. In
`nearai` mode, `src/llm/near-attest.ts` checks the Intel TDX quote and TCB status, non-debug mode,
nonce and key binding, the compose hash, RTMR3 replay, NVIDIA GPU evidence through NRAS, and the
model name when the report includes it. It does not compare MRTD or RTMR0-2, does not pin measurements unless
`NEARAI_PINNED_COMPOSE_HASHES` is set, and does not bind the attested TLS fingerprint to the live
connection. Gateway receipts do not prove which model ran, so `nearai` mode rejects them (only
`provider_tee` receipts count as verified). `openrouter` mode is never verified, so
every payment there is held. In all modes the contract limits apply no matter what the model does.

**L14. FakeChain is a mirror, not the contract.** `npm run demo:dry` and the TypeScript tests run
against `FakeChain` in `src/agent/chain.ts`, a TypeScript copy of the contract's rules. Its scout is a simplified stand-in,
not the real scout in `src/scout/counterparty.ts`. `test/fakechain-parity.test.ts` checks the
block and freeze rules against the contract (environmental and quiet blocks, the freeze threshold
and its backstop of 25, 24 h expiry of pending requests), but the vault-wide paused-block counter
is not modelled, and a fresh fake vault has funds and no earlier payees or spending, so results
can differ from a live run. In the latest live run (2026-11-09 04:59 UTC, vault topped up first)
all 8 verdicts match the dry run, including the scenario 2 hold-and-reject and the scenario 3
auto-freeze. What still differs: scenario 5 is held `[NEW_PAYEE, NEEDS_APPROVAL]` in the dry run
but only `[NEEDS_APPROVAL]` live (the live vault has paid `billing.` before); the fake scout does
not report `NEW_ACCOUNT` (live scenarios 2 and 5 show `scout:NEW_ACCOUNT`); scenario 3's
`daily_limit` patch differs (0.95 NEAR dry, 4.25 NEAR live, both 0.3 NEAR above the 24 h spend);
the live run raises `daily_limit` for earlier spending first; and scenario 4's dry verdict text
adds `agent frozen (TRIPWIRE: ...)` while the live one reads `1 tripped`. The contract
itself is tested by the 77 Rust tests and by the live run.

**L15. Not covered at all.** Bugs in NEAR itself or in near-sdk, front-running or validator
behavior, theft of the operator's machine or `.env`, phishing of the owner, and social engineering
of the human who approves requests.

**L16. The scout's blocklist check is advisory; pinned code is not wired up.** `LiveChain` gives
the scout a `vaultBlocklist` hook that calls the vault's `get_block_entry` view for the receiver
and its parent accounts. These parent checks run off chain, so a key thief can skip them; the contract enforces the blocklist for the exact
receiver only. If the view fails, the scout reports `CHECK_UNAVAILABLE` (a warning). The optional
pinned-contract hook (`pinned` in `src/scout/counterparty.ts`) is still not configured by
`LiveChain`, and the creator and key-age checks in `src/scout/extras.ts` (`extraSignals`) are
not called by the runtime.
