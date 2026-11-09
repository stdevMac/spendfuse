# Architecture

This document describes how Spendfuse is built and how one payment moves through it. Every name
below is a real function, type or file in this repository. The contract is the only part that
enforces anything. Everything off chain is advisory and can be bypassed by someone who holds the
agent key (scenarios 7 and 8 do exactly that).

## Components

| Component | Where | What it does |
|---|---|---|
| Vault contract | `contract/src/lib.rs` | Holds the NEAR. Runs the policy check on every request, pays, queues for approval, blocks, or freezes. Stores agents, policies, canary hashes, blocklist, pending requests, payee stats and an activity ring. |
| Contract tests | `contract/src/tests.rs` | 77 unit tests (`npm run test:contract`). |
| Agent account key | created by `src/scripts/setup-testnet.ts` | A function-call access key on `agent.<owner>`, scoped to the vault and to `request_payment`, `self_freeze`, `report_receiver` (`AGENT_METHODS` in `src/lib/spendfuse.ts`), with a 1 NEAR gas allowance. |
| Agent runtime | `src/agent/runtime.ts` | The model loop (`runAgent`): model turn, per-turn trust check, strict argument parsing, guarded tool dispatch, transcript (`RunLog`). |
| Tools | `src/agent/tools.ts` | The five tools the model sees (`AGENT_TOOLS`): `pay`, `check_receiver`, `report_receiver`, `self_freeze`, `fetch_document`. `parseToolCall` rejects unknown keys, wrong types, control characters and malformed amounts before anything reaches the chain. |
| Guard | `src/agent/guard.ts` | The single path from a proposed payment to the vault (`guardedPay`). Combines a canary probe, the vault's `check_payment` view and the scout into send / hold / refuse (`combine`). Tells the model only `paid ...`, `refused`, `pending human approval` or a transfer-failed note. |
| Chain backends | `src/agent/chain.ts`, `src/agent/live-chain.ts` | `ChainBackend` interface. `LiveChain` talks to testnet. `FakeChain` is an in-memory TypeScript mirror of the contract and of the protocol's access-key checks, used by tests and `--dry-run`. |
| Scout | `src/scout/counterparty.ts`, `src/scout/extras.ts` | Read-only counterparty checks on the receiver: does it exist, account type, age, activity, keys, contract code, lookalikes of allowlisted names, burn addresses. Results are cached for 60 s. Never signs. `LiveChain` gives it a blocklist hook (`vaultBlocklist`, which calls the vault's `get_block_entry` view) for the receiver and each of its parent accounts: a confirmed entry blocks (`BLOCKLISTED`, `PARENT_REPORTED`), a reported one warns unless the receiver is allowlisted, and a failed lookup gives `CHECK_UNAVAILABLE`. The optional pinned-contract hook is not configured, and the creator and key-age checks in `extras.ts` (`extraSignals`) are not called by the runtime. |
| LLM layer | `src/agent/llm.ts`, `src/llm/*` | `makeAgentLlm` picks `scripted` (default, offline, no key), `nearai` (NEAR AI Cloud with per-turn TEE receipt checks) or `openrouter` (no receipts, every turn unverified). |
| Scenarios | `src/agent/scenarios.ts` | The 8 attack and control scenarios (`SCENARIOS`, `runScenario`). |
| Scripts | `src/scripts/*` | `setup-testnet`, `attack-demo`, `drill`, `status`, `lockdown`, `newkey`. |
| Dashboard | `src/server/*`, `web/*` | Local web console (`npm run dashboard`): state, approval queue, incident feed, key proof, blocklist, saved runs, and token-gated owner or guardian actions. |
| Hosted dashboard | `src/worker/*`, `wrangler.jsonc` | Cloudflare Worker serving a read-only copy at https://spendfuse.marcosmaceo.com: same `web/` front end and the same read-only JSON as `READONLY=1`, no keys. |

Note: the base58 `canaryHash` in `src/scout/canary.ts` was written for an older contract interface
(`request_transfer`) and is not on the payment path. The runtime uses the hex `canaryHash` in
`src/lib/canary.ts` (which reuses `newImplicitCanary` from `src/scout/canary.ts`).

## Accounts and roles

The live testnet deployment uses these accounts:

- owner: `tw-firewall-demo.testnet` (full-access key, signs every owner method with 1 yoctoNEAR)
- vault: `vault.tw-firewall-demo.testnet` (the contract)
- agent: `agent.tw-firewall-demo.testnet` (only a function-call key on the vault)
- guardian: `guardian.tw-firewall-demo.testnet`
- payees: `store.tw-firewall-demo.testnet` (the allowlisted shop, `SHOP_ID`), `billing.tw-firewall-demo.testnet`
  (API provider, `API_ID`), `feed.tw-firewall-demo.testnet` (data feed, `DATA_ID`; doubles as the stand-in
  attacker). The defaults come from `PAYEES` / `payeeId()` in `src/lib/env.ts`; setting the env variable
  overrides one.

Roles inside the contract:

- **Owner.** Every owner method calls `assert_owner()` and `assert_one_yocto()`. A function-call key
  cannot attach a deposit, so these methods need the owner's full-access key. Owner methods:
  `register_agent`, `update_policy`, `remove_agent`, `unfreeze_agent`, `unpause`, `approve`,
  `withdraw`, `unblock_receiver`, `unblock_receivers`, `remove_canary`, `add_guardian`,
  `remove_guardian`, `propose_owner`. The proposed owner calls `accept_owner` (two-step transfer).
- **Guardian** (up to 10). Free calls that check `assert_owner_or_guardian()`: `freeze_agent`,
  `pause`, `reject`, `dismiss_report`, `block_receiver`, `add_canaries`. The owner can call them too.
  These can only make the vault stricter, with one exception: `dismiss_report` removes a
  *reported* (not confirmed) entry. See the threat model.
- **Agent** (up to 200). `request_payment`, `self_freeze`, `report_receiver`.
- **Anyone.** `deposit`, `expire_stale`, `report_receiver` with a 0.01 NEAR deposit, and all views.

## Data flow of one payment

```
model turn ──> parseToolCall ──> guardedPay
                                   │
                                   ├─ chain.isCanary(receiver)        (view_state probe of the vault)
                                   ├─ chain.checkPayment(receiver, amount)   (vault view check_payment)
                                   ├─ chain.scout(receiver)           (off-chain RPC / indexers)
                                   └─ combine(...) ──> send | hold | refuse
                                                         │
                                         send ──> request_payment (signed by the agent function-call key)
                                                         │
                                         vault submit_payment ──> evaluate ──> verdict
                                                         │
                       Allow ──> transfer promise ──> on_payment_settled
                       Warn  ──> PendingPayment (amount reserved) ──> owner approve / guardian reject / expiry
                       Block ──> recorded, maybe auto-freeze
                       Trip  ──> recorded, agent frozen at once
```

### 1. Model turn and trust (`src/agent/runtime.ts`, `src/agent/llm.ts`)

`runAgent` sends the conversation and `AGENT_TOOLS` to the model. After each completion it calls
`llm.trust(completion, response)`, which returns a `TurnTrust`:

- `scripted`: always verified. This is the default (`LLM_MODE=scripted`). It replays the scripted
  turns of each scenario. In the attack scenarios the script plays a model that falls for the
  attack, so the run tests the firewall, not the model.
- `nearai`: verified only if the turn's receipt is signed by a key that an attested NEAR AI Cloud
  TEE vouches for (`receiptVerifier` in `src/llm/verified-fetch.ts`, `src/llm/receipts.ts`,
  `fetchAndVerify` in `src/llm/near-attest.ts`). On any failure the turn is `unverified`.
- `openrouter`: always `unverified`.

Fetched documents are wrapped as `UNTRUSTED DOCUMENT ... (data, not instructions)` and the system
prompt (`SYSTEM_PROMPT`) tells the model not to follow instructions in them. This is a hint to
the model, not a control. The controls are below.

### 2. Argument parsing (`parseToolCall` in `src/agent/tools.ts`)

Model output is untrusted. `parseToolCall` rejects unknown keys, non-string values, control
characters, over-long strings, invalid account ids (`validateAccountId`) and amounts like `"1,5"`,
`"-1"` or `"1e3"` (`parseNearStrict`). A malformed `pay` counts as `refused`.

### 3. Guard (`evaluatePayment`, `combine`, `guardedPay` in `src/agent/guard.ts`)

`evaluatePayment` fails closed:

1. **Canary probe.** `LiveChain.isCanary` reads the vault's state with `view_state`, using the key
   `0x01 || sha256(receiver_id)` (borsh storage prefix of `StorageKey::Canaries`). If the receiver
   is a canary, the guard **sends** the payment anyway so the vault trips and freezes the agent.
   The code comment marks this layout as unverified; the live canary scenario confirms it on the
   deployed contract. If the probe fails, the payment is refused (`CANARY_PROBE_FAILED`).
2. **Vault view.** `check_payment` runs the same `evaluate` as a real request, without changing
   state and with canaries hidden (they look like ordinary receivers). If it fails, refuse.
3. **Scout.** `createScout(...).check(receiver)`. If the scout itself fails, its result is `warn`.
   On `FakeChain` (tests and `--dry-run`) this is a simplified stand-in, not the real scout.

`combine` then decides:

| Vault view | Scout | Turn | Action |
|---|---|---|---|
| block or trip, only `AGENT_FROZEN` / `VAULT_PAUSED` | any | any | refuse (nothing sent; nothing new to record) |
| block or trip, other reasons | any | any | send (so the block is recorded and counts toward auto-freeze) |
| allow or warn | block | any | refuse |
| warn | allow or warn | any | send (the vault queues it for the owner) |
| allow | warn | any | hold locally (nothing sent) |
| allow | allow | unverified | hold locally (`UNVERIFIED_TURN`) |
| allow | allow | verified | send |

The runtime prints each decision as a `guard` line (`guardSummary` in `src/agent/runtime.ts`):

| Decision and action | Guard line |
|---|---|
| block, send | `block → forwarded to vault to be recorded on-chain` |
| block, send, canary | `block → forwarded to vault, which trips the canary and freezes the agent` |
| block, refuse | `block → refused locally, nothing sent` |
| warn, send | `warn → forwarded to vault, which pays or holds it for owner approval` |
| warn, hold | `warn → held locally for human approval, nothing sent` |
| allow, send | `allow → forwarded to vault for payment` |

A forwarded block is deliberate: the vault records it on chain (activity ring and NEP-297 event)
and counts it toward auto-freeze, which is how scenario 3 freezes the agent. The committed proof log
(`docs/proofs/live-demo-2026-11-09.log`) was recorded with this wording.

The model only ever sees `paid ...`, `pending human approval`, `refused`, or a transfer-failed
note. It never sees canary, watchlist or limit details (scenario 4 checks this with `noLeak`).
`check_receiver` returns only `ok`, `needs human approval`, `not allowed` or `unavailable`, and
never probes canaries.

### 4. Contract: `request_payment` → `submit_payment` → `evaluate` (`contract/src/lib.rs`)

`request_payment` is the public method. It calls the internal `submit_payment` and returns either
a promise (paid) or a `PaymentResult` value. Blocked requests return a value instead of panicking,
so the record and any freeze are committed on chain.

`submit_payment`:

1. Requires the caller to be a registered agent. Assigns a request id. Cleans the memo
   (`clean_opt`, 256 bytes).
2. Expires this agent's stale pending requests (`expire_agent_pending`). If the global queue is
   full, sweeps up to 5 stale requests (`expire_stale_internal`).
3. Prunes the agent's rate windows (`AgentState::prune`) and runs `evaluate`.

`evaluate` checks in this order. The first match decides:

1. agent frozen → Block `AGENT_FROZEN`
2. receiver hash in the canary set → Trip `TRIPWIRE`, the canary tripwire (checked before pause, so canaries still trip
   while paused)
3. vault paused → Block `VAULT_PAUSED`
4. policy expired → Block `POLICY_EXPIRED`
5. hard limits, all collected together: `SELF_PAYMENT` (agent or vault), `BLOCKLISTED` (confirmed
   entry), `ZERO_AMOUNT`, `NOT_ALLOWLISTED` (when `allowlist_only`), `OVER_PER_PAYMENT_CAP`,
   `RATE_LIMITED`, `OVER_DAILY_LIMIT` (spent plus reserved plus this amount), and
   `INSUFFICIENT_VAULT_BALANCE`. Any of these → Block.
6. soft signals: `REPORTED_RECEIVER` (reported entry, not allowlisted), `NEW_PAYEE` (no payee
   record for this agent and amount above `new_payee_limit`, or the agent already has 256 payees),
   `NEEDS_APPROVAL` (amount above `approval_threshold`). Any of these → Warn, unless the agent
   already has 5 live pending requests or the vault has 100, in which case `TOO_MANY_PENDING` is
   added and the verdict becomes Block.
7. otherwise → Allow.

Allowlisted receivers are never a new payee and ignore reports, but they still go through every
hard limit and the approval threshold.

### 5. Verdict paths

- **Allow.** `add_spend` records the amount in the current hour bucket, the request goes into
  `recent_payments`, `bump_payee` updates the payee record, a `paid` event is emitted, and
  `payment_promise` sends a `Transfer` followed by the private callback `on_payment_settled`
  (20 Tgas). If the transfer fails (for example a named account that does not exist), the runtime
  refunds the vault and the callback rolls back the hour bucket, `total_spent`, the payee record
  (removed if it was the first payment) and `paid_total`, and emits `transfer_failed`. Scenario 8
  shows this on testnet.
- **Warn (escalate).** A `PendingPayment` is stored with a 24 hour expiry. Its amount is added to
  `reserved` and counts against the daily limit and against `withdraw`. The request also counts
  toward the hourly rate. An `escalated` event is emitted and the agent gets `pending_approval`.
- **Block.** Returned as `blocked` with every hard reason. Three kinds:
  - quiet blocks (only `AGENT_FROZEN` or only `VAULT_PAUSED`): counted in separate stats, logged
    as an event but not stored in the activity ring, not counted toward auto-freeze;
  - environmental blocks (`is_environmental_block`: the hard reasons are only
    `INSUFFICIENT_VAULT_BALANCE` and/or `TOO_MANY_PENDING`, maybe with soft signals): counted and
    stored, but not counted toward auto-freeze;
  - all other blocks: the time goes into `recent_blocks`. If the blocks in the last hour reach
    `auto_freeze_after_blocks` (1 to 25; 0 means the backstop of 25), the agent is frozen with
    reason `AUTO_FREEZE: n blocked payment attempts within 1h`.
- **Trip (freeze).** The attempt is recorded as `tripped`, then `freeze_internal` freezes the agent
  with reason `TRIPWIRE: attempted payment to a canary payee`. No transfer is made.

Every freeze (`freeze_internal`, used by trip, auto-freeze, `freeze_agent` and `self_freeze`)
also cancels all of that agent's pending requests and releases their reservations. Only the owner
can unfreeze (`unfreeze_agent`), which also clears `recent_blocks`.

## Owner approval flow

1. A Warn verdict creates `PendingPayment` with `id`, `agent_id`, `receiver_id`, `amount`, `memo`,
   `reasons`, `created_at_ms`, `expires_at_ms` (24 h later).
2. The owner sees it in `get_pending` (dashboard: Approval queue).
3. `approve(request_id)` (owner, 1 yocto):
   - if expired: releases it, records `expired`, returns `expired`;
   - refuses (panics) if the vault is paused, the agent is frozen, the receiver is a confirmed
     blocklist entry, the receiver is a canary ("hidden watchlist"), or the vault balance is too
     low after releasing this reservation;
   - otherwise records the spend and payee, emits `approved`, and sends the same transfer plus
     `on_payment_settled` callback as an allowed payment.
   Approval overrides only the soft signals. The hard limits were already checked when the request
   was made, and the reserved amount was already counted against the daily limit.
4. `reject(request_id, reason)` (owner or guardian) releases the reservation and emits `rejected`.
5. Anyone can call `expire_stale(limit)` (at most 20 per call) to release requests older than 24 h.

The scenario `over-threshold` (5) runs this path live: escalated, approved, paid. `injection` (2)
runs it live with a reject: held `[NEW_PAYEE]`, rejected by the owner, nothing paid.

## Guardian role

A guardian is a separate account listed in `guardians`. Its calls are free (no deposit), so a
function-call key on the vault is enough; the setup script gives the demo guardian a full-access
key on its own account. A guardian can freeze an agent, pause the vault, reject a pending request,
confirm a receiver as bad (`block_receiver`), add canary hashes, and dismiss an open report. It
cannot approve, unfreeze, unpause, withdraw, change a policy, unblock a confirmed entry, remove a
canary or add guardians: those check `assert_owner` and need 1 yocto.

## Canaries

A canary is a decoy payee that no honest flow ever pays.

- `newImplicitCanary` (`src/lib/canary.ts`) makes a random 64-hex implicit account id. The secret
  key is dropped. The account does not exist on chain until something pays it.
- Only `canaryHash(id)` = hex `sha256(utf8(id))` goes on chain, via `add_canaries` (at most 50 per
  call, 1000 total). The contract stores the 32-byte hash in a `LookupSet<CryptoHash>` and never the
  id. `remove_canary` (owner) removes one.
- The ids are kept locally in `.spendfuse/canaries.json` (mode 0600, gitignored). The dashboard
  shortens any canary id to its first 8 characters before serving runs (`redactCanaryIds`,
  `redactRunJson` in `src/server/backend.ts`).
- `check_payment` hides canaries. `request_payment` trips on them. `approve` refuses them.
- **A tripped canary is no longer secret.** The trip is a `request_payment` whose `receiver_id` is
  the canary id, so the full id is in the transaction arguments for anyone to read. Shortening ids
  in run files and in the dashboard only avoids handing out a ready-to-paste copy of a canary that
  is still planted. A live `npm run demo` reuses the first canary in `.spendfuse/canaries.json`, so
  the demo canary is public. Rotate a tripped canary: `remove_canary(hash)` (owner, 1 yocto; no
  npm script, `OwnerApi.removeCanary` in `src/lib/spendfuse.ts`), then plant a new one
  (`npm run setup` plants 2 fresh ones when `.spendfuse/canaries.json` is absent; move the old file
  aside first). See "Rotating canaries" in the README.
- `npm run drill:dry` (or `npm run drill` for live) plants a fresh canary, has the agent pay it,
  confirms the freeze, and has the owner unfreeze (`runDrill` in `src/scripts/drill.ts`).

## Rate windows

Kept per agent in `AgentState`:

- `recent_payments`: times of paid or queued requests in the last hour. `RATE_LIMITED` when the
  count is at least `max_payments_per_hour` (1 to 300).
- `hourly_spend`: `(hour since epoch, yoctoNEAR)` buckets. `prune` keeps a bucket while it is at
  most 24 hours behind the current hour, so a payment counts for 24 to 25 hours. This errs on the
  strict side: no real 24-hour window can exceed `daily_limit`. `OVER_DAILY_LIMIT` uses
  `spent_24h + live reserved + amount`.
- `recent_blocks`: times of counted blocks in the last hour, for auto-freeze.

Policy fields (`Policy`, `#[serde(deny_unknown_fields)]`, checked by `Policy::validate`):
`max_per_payment`, `daily_limit`, `approval_threshold`, `new_payee_limit`,
`max_payments_per_hour`, `allowlist_only`, `allowlist` (at most 100), `auto_freeze_after_blocks`
(at most 25), `expires_at_ms`. The demo policy from `setup-testnet.ts`: 1 NEAR per payment, 3 NEAR
per 24 h, approval above 0.5 NEAR, new payees above 0.2 NEAR need approval, 10 payments per hour.

## Events and the activity ring

`emit` writes every event as a NEP-297 log line: `EVENT_JSON:{"standard":"tripwire","version":"1.0.0","event":<kind>,"data":[...]}`.
Event kinds are listed in `EventKind` (`paid`, `blocked`, `tripped`, `escalated`, `approved`,
`rejected`, `expired`, `transfer_failed`, `frozen`, `unfrozen`, `paused`, ... `withdraw`).

Most events are also stored in an on-chain ring of the newest 256 entries (`activity`,
`RING_CAP`), each with a sequence number. `get_activity(before_seq, limit)` pages newest first.
"Quiet" events are logged but not stored: repeats while frozen or paused, repeat reports of the
same receiver, pending requests cancelled by a freeze or removal (the freeze event carries the
count), and deposits under 0.1 NEAR. The logs (and the explorer) keep the full history; the ring
only keeps the latest 256. `parseEvents` in `src/lib/spendfuse.ts` decodes the logs.

All untrusted text stored on chain (memo, reason, evidence, label, notes) goes through
`clean_text`: hidden and bidi characters are dropped, control characters become spaces, and the
length is capped in bytes.

## Storage accounting

The vault pays for its own storage. `free_balance_yocto` is the account balance minus
`storage_usage * storage_byte_cost`. The spendable amount is:

```
available = free balance - reserved - STORAGE_MARGIN (0.05 NEAR)
```

Payments (`INSUFFICIENT_VAULT_BALANCE`), approvals and `withdraw` are limited to `available`, so a
payment can never eat into the storage stake or into reserved funds. A free report from an agent
that creates a new blocklist entry requires `available` to cover 1000 bytes of storage.

All collections are bounded: 200 agents, 10 guardians, 100 allowlist entries, 1000 canaries,
1000 blocklist entries, 200 open reports (owner and guardian reports are not bound by this cap), 5 pending per agent and 100 in total, 256 activity
entries, and 256 payees per agent before every new payee needs approval. `get_config` shows
`balance`, `storage_locked`, `reserved` and `available`.

Payee records are keyed by `sha256("agent|epoch|receiver")`, where the epoch is the agent's
`created_at_ms`. `remove_agent` does not delete them; re-registering the agent starts a new epoch,
so old records are never read again but their storage stays locked.

## Dashboard (`npm run dashboard`)

`src/server/index.ts` starts `createDashboard` (`src/server/app.ts`) with a live backend
(`src/server/backend.ts`). It has no runtime dependencies and serves `web/`.

- Read-only JSON: `/api/state` (config, stats, agents, pending, activity, blocklist, and a key
  proof for each agent from `view_access_key_list`, flagging full-access or off-vault keys via
  `keyProof`), `/api/activity`, `/api/runs`, `/api/runs/<id>`, and an SSE feed at `/api/events`.
- Actions (POST): `approve`, `reject`, `freeze`, `unfreeze`, `pause`, `unpause`. They are signed
  with `OWNER_KEY` from `.env`, or with `GUARDIAN_KEY` if there is no owner key, in which case only
  `reject`, `freeze` and `pause` are allowed.
- Protections: binds to `127.0.0.1` by default, rejects foreign `Host` headers (DNS rebinding),
  requires a random per-process token in `x-spendfuse-token`, refuses cross-origin POSTs and
  non-JSON bodies, caps body size, validates ids, and sends a strict CSP and related headers.
  `READONLY=1` disables every POST route. These are covered by `test/server.test.ts`.
- Shared core: validation, security headers, the view cache (`TtlCache`, `cachedViews`), the
  `/api/state` body (`buildState`), run summaries and the SSE diff (`Feed`) are in
  `src/server/core.ts`, and the live views in `src/server/views.ts`. Neither imports `node:*`, so
  the Worker uses the same code.

### Hosted read-only dashboard (`npm run web:deploy`)

`src/worker/index.ts` is a Cloudflare Worker (config in `wrangler.jsonc`; vars `NETWORK`,
`OWNER_ID`, `VAULT_ID`, no secrets). Every request goes through the Worker first
(`run_worker_first`) so static files from `web/` get the same CSP and headers.
`src/worker/handler.ts` (`createHandler`) is a pure `Request -> Response` function tested in
`test/worker.test.ts`, including a check that its `/api/state` equals the Node server's in
READONLY mode.

- API: `GET /api/state`, `/api/activity`, `/api/runs`, `/api/runs/<id>`, `/api/events`. The mode is
  always `{ readonly: true, actions: false }`, so the front end shows "read-only" and no action
  buttons. `POST`, `PUT`, `PATCH`, `DELETE` get `403 read-only mode`; other methods get `405`.
- Chain reads go to public testnet RPC through near-api-js and a 5 s in-isolate cache shared by
  all requests (`TtlCache`).
- Runs: only the recorded proofs in `docs/proofs/live-run-*.json`, imported at build time
  (`src/worker/runs.ts`); canary ids in them are already redacted.
- `/api/events` is a bounded SSE stream: it polls every 5 s, sends `status` / `activity` frames,
  and closes after about 25 s; `EventSource` reconnects after the `retry: 5000` hint. No
  connection is held open indefinitely.

## Scripts

- `npm run setup` / `npm run setup:dry`: idempotent testnet setup (`src/scripts/setup-testnet.ts`):
  accounts, function-call agent key, deploy and init, guardian, agent registration, canaries.
  `--redeploy` deploys new code over an existing vault (code only, state kept, no re-init); it
  needs `VAULT_KEY`, so it is impossible after lockdown.
- `npm run demo` / `npm run demo:dry`: the 8 scenarios live or on `FakeChain`
  (`src/scripts/attack-demo.ts`). They run in the order 1, 5, 2, 8, 7, 6, 4, 3: all share one vault
  and agent, and 4 and 3 leave the agent frozen, so they run last (3 after 4 because its
  `daily_limit` patch is computed from the 24 h spend the earlier scenarios leave). Each run is saved to `.spendfuse/runs/<timestamp>.json`. The live run used as proof is committed
  in `docs/proofs/` (canary ids shortened). Before a
  live run, if earlier runs still hold payments in the hourly window or spending in the 24 h
  window, the owner raises `max_payments_per_hour` and/or `daily_limit` by that amount for the run
  and restores them in cleanup (the 2026-11-09 04:59 UTC proof run raised only `daily_limit`,
  3 to 6.3 NEAR).
- `npm run drill` / `npm run drill:dry`: canary drill.
- `npm run status`: read-only report of the vault, its keys and recent activity.
- `npm run lockdown` / `npm run lockdown:dry`: deletes the vault's own full-access key
  (`src/scripts/lockdown.ts`). It refuses if the vault holds any other full-access key. This is
  planned for just before submission and has not been run yet; `npm run status` shows the current
  key state (`vault locked: no full-access keys` once it is done). The dry run is keyless: it needs
  only `VAULT_ID` or `OWNER_ID` (vault defaults to `vault.<OWNER_ID>`), reads the keys with view
  calls, and names the single full-access key the live run would delete. `VAULT_KEY` is needed only
  for the live run, which refuses any other key.
- `npm run newkey`: prints a fresh key pair locally.

## Build and versions

- Node 24 or later (tested on 26.7). TypeScript runs natively; there is no build step.
- Rust 1.99.1, pinned in `contract/rust-toolchain.toml`. `wasm-opt` is optional, but only binaryen
  version 132 with `wasm-opt -Oz --enable-bulk-memory --enable-nontrapping-float-to-int` (what
  `contract/build.sh` runs) reproduces the deployed wasm byte for byte: a clean rebuild in a copy of
  `contract/` gave 304800 bytes, sha256 `e5a0d903...`. Set `WASM_OPT=/path/to/wasm-opt`;
  `build.sh` prints the wasm-opt version and flags and warns if the version is not 132 or
  `WASM_OPT_LEVEL` is not `-Oz`.
- Deployed wasm: `contract/res/tripwire.wasm`, 304800 bytes, sha256
  `e5a0d9039e00c9bdaaa7168fc573d2fa5795ce277756b24f946d2b7ce41d9a98`, NEAR code hash
  `GTNcofHtGDJRRXVWdmzaq7C44442yV9m7qZKF329Etfh`, deployed in tx
  `GGGu5tUBu5AnjvXpvRTvKLsiK5cHvNsiw43Pr44KbkTE`.
