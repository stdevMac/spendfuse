# Spendfuse demo kit

This file has three parts:

1. A 60-90 second video script and shot list.
2. Drafts for the X (Twitter) post, plus a longer thread.
3. A list of screenshots to capture.

Nothing here has been posted. The human posts it.

Every claim below comes from the code or from the latest live run:

- run file: `docs/proofs/live-run-2026-11-09T04-59-38-380Z.json` (8/8 PASS, testnet, scripted model,
  2026-11-09 04:59:38-05:00:59 UTC)
- console log: `docs/proofs/live-demo-2026-11-09.log`

Canary ids are shortened in both. That only keeps a ready-to-paste copy of the planted canary out
of the repo; it does not make the id secret. A tripped canary's full id is in the trip
transaction's arguments on chain, and the demo canary has tripped on testnet, so it is public and
should be rotated (README, "Rotating canaries"). A new `npm run demo` saves its run to
`.spendfuse/runs/`.

Testnet accounts used in the demo:

| Role | Account |
| --- | --- |
| owner | `tw-firewall-demo.testnet` |
| vault (contract) | `vault.tw-firewall-demo.testnet` |
| agent | `agent.tw-firewall-demo.testnet` |
| guardian | `guardian.tw-firewall-demo.testnet` |
| payees | `store.`, `billing.`, `feed.tw-firewall-demo.testnet` |

---

## 1. Video script (60-90 seconds)

### Before you record

- `npm run demo` is **live**. It sends real testnet transactions with the agent and owner keys
  from `.env`. Only the human should run it, and only on purpose.
- For a practice take that sends nothing, use `npm run demo:dry`. Its header says
  `DRY RUN (fake chain, nothing sent)` and its tx hashes start with `FAKE`. Do not present a dry
  run as a live run.
  The dry run ends `8/8` with the same verdict as the latest live run in every scenario:
  scenario [2] is held `pending_approval [NEW_PAYEE]` and the owner rejects it, and scenario [3]
  auto-freezes. Small differences remain (README, "Live proof on testnet"): for example scenario
  [5] also lists `NEW_PAYEE` in the dry run, and the live run first raises `daily_limit` for
  earlier spending. The vault was topped up before the latest live run, so no block there carries
  `INSUFFICIENT_VAULT_BALANCE`; if a later run shows it, the vault's free balance is low again.
- The default model is `scripted` (no API key needed). The scenarios use fixed model turns, so the
  run is repeatable. Say this on screen or in the description. Do not imply a live LLM made the
  choices unless you ran with `--llm=nearai` (or `--llm=openrouter`). Note that `npm run demo`
  takes the model from `LLM_MODE` in `.env` (default `scripted`), so check that the header line
  says `model: scripted` before you record.
- Start the dashboard first, in a second terminal: `npm run dashboard`. It binds to
  `127.0.0.1:8787`. If `OWNER_KEY` or `GUARDIAN_KEY` is set and it is bound to loopback, it prints
  a URL with a token (valid until the process exits) and action buttons appear. For recording,
  `READONLY=1 npm run dashboard` hides every action and still shows all views. Do not show the
  token URL on screen.
- The latest live run sent 18 transactions (each one is linked in the log) and took about 81 seconds
  (04:59:38 to 05:00:59 UTC). Record it once, then cut it down.
- The scenarios run in this order: 1, 5, 2, 8, 7, 6, 4, 3. The two that freeze the agent (4 and
  3) run last on purpose. The numbers in square brackets in the log are scenario numbers.
- Before the scenarios, on a re-run, the owner raises `daily_limit` (and `max_payments_per_hour`
  when needed) by what earlier runs still hold in their windows, and restores them in cleanup. In
  the latest live run that was `daily_limit` 3 to 6.3 NEAR, restored to 3 NEAR at the end. Between scenarios
  the demo uses the owner key: it approves or rejects held payments, unfreezes the agent, and
  patches the policy (for scenario [3], `auto_freeze_after_blocks: 3` and a `daily_limit` 0.3 NEAR
  above the 24h spend).
  These owner transactions are in the log too.

### Shot list and narration

| Time | Shot | Narration |
| --- | --- | --- |
| 0:00-0:08 | Title card: "Spendfuse: a spending firewall for AI agents on NEAR". | "If an AI agent holds a wallet key, one prompt injection or one leaked key can drain it." |
| 0:08-0:20 | Dashboard, Console tab. Point at the "Proof: agent keys" card: one key, `FunctionCall`, receiver `vault.tw-firewall-demo.testnet`, methods `request_payment`, `self_freeze`, `report_receiver`, pill "FUNCTION-CALL ONLY". | "Spendfuse splits it. The vault contract holds the money. The agent only gets a NEAR function-call key. It can ask the vault to pay. It cannot move funds itself." |
| 0:20-0:30 | Terminal: `npm run demo`. Show the header line `LIVE on testnet - model: scripted`, then scenario [1] ending in `vault result: paid` and `PASS`. | "Eight scenarios run against the live testnet vault. First, a normal purchase from an allowlisted shop. It is paid." |
| 0:30-0:42 | Terminal: scenario [2]. Highlight the fetched invoice text marked `[SIMULATED ATTACK]`, the agent's `pay` to `feed.tw-firewall-demo.testnet`, then `vault result: pending_approval [NEW_PAYEE]`, the `HUMAN APPROVAL NEEDED` line, and `owner ... rejects it` with `reject ok`. Optionally cut to the reject tx (link below). | "Here a fetched invoice carries a simulated injection that asks for a new refund address. The scripted agent falls for it. The vault decides, not the agent: a payee this agent has never paid waits for a human. The owner sees the request and rejects it. Nothing is paid." |
| 0:42-0:55 | Terminal: scenario [6]. Show the five `ATTACK` lines and the typed errors: `RequiresFullAccess`, `MethodNameMismatch`, `ReceiverMismatch`, `DepositWithFunctionCall`. | "Now assume the agent key is stolen. A direct transfer, `withdraw`, adding a full-access key, calling another contract, attaching a deposit. The NEAR protocol rejects all five at the access-key layer. No transaction lands." |
| 0:55-1:07 | Terminal: scenario [4], `vault result: tripped [TRIPWIRE] (agent frozen)`. Then cut to the explorer page for that tx (link below). | "A canary is a decoy payee that no honest flow ever pays. The vault stores only its hash. When the agent tries to pay it, the agent is frozen in the same transaction, and the agent is told only 'refused'." |
| 1:07-1:17 | Terminal: scenarios [7] and [3]. Show `blocked [OVER_PER_PAYMENT_CAP]`, then the salami run ending in `AUTO_FREEZE`. | "Bypassing the wrapper does not help. The contract enforces caps, rate and 24-hour limits itself. Repeated blocked attempts freeze the agent automatically. To show that, this scenario tightened the daily limit and set the freeze threshold to 3; the built-in backstop is 25 per hour." |
| 1:17-1:27 | Terminal: `8/8 scenarios behaved as expected`. Then dashboard Incident feed and the Attack runs tab with the same run selected. | "Eight of eight behaved as expected, on testnet, with explorer links for every landed transaction. The code and the run log are in the repo." |
| 1:27-1:30 | End card: repo URL, "#NEARHackathon". | "Spendfuse. Built on NEAR." |

### Explorer links for the video

Use the canary freeze. It is the clearest single on-chain proof. The stolen-key attempts in
scenario [6] were rejected before any transaction existed, so they have no tx page. For those, show
the terminal lines and the agent account's key list instead.

- Canary trip, agent frozen (scenario [4]):
  https://testnet.nearblocks.io/txns/2tC28AerbqsP91dJU6s9gtoXnSjUGjHf9AXuJXSMnKU1
- Raw request over the per-payment cap, blocked on chain (scenario [7]):
  https://testnet.nearblocks.io/txns/HdA79d6T33Uyg9pAiKPMJ9xFvPXvzikMP9WcaKPVBn4d
- Salami block that auto-froze the agent (scenario [3]):
  https://testnet.nearblocks.io/txns/FMtvaDGD5UD6NVtfttTCKS8CDdwexP6nDCsQV29aogye
- Injection payment, held `pending_approval [NEW_PAYEE]` (scenario [2]):
  https://testnet.nearblocks.io/txns/HXToFNZsZxVoKVf2TXtEf5ib95TJkFveprY6oT8boSCV
- Owner rejects the injected payment (scenario [2]):
  https://testnet.nearblocks.io/txns/AXhRxcogYRkYy7EuvrKcmzSRTfesLwSuECZ7BsE5ugGN
- Agent account (show its access keys):
  https://testnet.nearblocks.io/address/agent.tw-firewall-demo.testnet

### Things not to say

- Do not say the vault code is immutable yet. Deleting the vault's own full-access key is
  **planned**: run `npm run lockdown`, and `npm run status` shows the lock state. Say "planned"
  until it is done.
- Do not say a real LLM was fooled by a real exploit. The injection text is written for the test
  and the default model is scripted.
- Do not claim users, partners, audits or mainnet use. There are none.
- Do not say the canary ids stay secret. A tripped canary's id is public in its trip transaction.
- Do not say the normal policy stops salami. Scenario 3 tightens `daily_limit` to show the freeze.
  Under the setup policy a key thief can still pay fresh payees up to 0.2 NEAR each without
  approval, at most 10 per hour and 3 NEAR per rolling 24 h (README, "Security model and
  limitations").

---

## 2. X (Twitter) post drafts

Each draft is at most 280 characters with `<REPO_URL>` as written. X counts any link as 23
characters, so a real URL keeps them under the limit.

### Draft A (problem first)

```
AI agents with wallet keys are one prompt injection away from being drained.

Spendfuse keeps the money in a NEAR vault contract. The agent only gets a function-call key: it can ask to pay, never move funds.

@NEARProtocol #NEARHackathon
Code + 8/8 testnet run: <REPO_URL>
```

### Draft B (stolen key)

```
What if your AI agent's key leaks?

With Spendfuse on @NEARProtocol, the agent's key can only call 3 methods on one vault. Transfer, withdraw, add key, other contract, deposit: the protocol rejected all 5 on testnet.

#NEARHackathon
Try it: <REPO_URL>
```

### Draft C (canary)

```
An injected agent may pay whoever the document says.

Spendfuse plants canary payees. Pay one and the vault on @NEARProtocol freezes the agent in the same tx. Caps, rate limits and human approval are enforced on chain.

#NEARHackathon
Repo + demo: <REPO_URL>
```

### Thread (5 posts)

1/5
```
AI agents are starting to hold wallets. If the agent holds the key, one prompt injection or one leaked key can drain it.

Spendfuse is a spending firewall for AI agents, built on @NEARProtocol for #NEARHackathon. Thread:
```

2/5
```
The vault contract holds the funds. The agent only gets a NEAR function-call key, scoped to one contract and 3 methods. That key cannot transfer NEAR, add keys or attach a deposit. Owner-only actions need a full-access key and 1 yoctoNEAR.
```

3/5
```
Every request ends as paid, pending approval, blocked or tripped. The contract checks freeze, canary, pause, policy expiry, allowlist, per-payment cap, hourly rate and 24h limit. New payees and large amounts wait for a human.
```

4/5
```
Canaries are decoy payees no honest flow pays. The vault stores only their hash. Pay one and the agent is frozen on the spot. Repeated blocked attempts auto-freeze too. Guardians can only make the vault stricter.
```

5/5
```
8 attack scenarios, 8/8 passed live on testnet, explorer link for every landed tx. Default model is scripted, so it reruns with no API key. Known limits are in the contract docs.

Code: <REPO_URL>
```

Optional 6th post, only once `npm run lockdown` has been run and `npm run status` confirms it:

```
The vault's own full-access key is now deleted, so the contract code can no longer be changed. Check it yourself: npm run status.
```

---

## 3. Screenshots to capture

Use the live testnet deployment. Crop out the terminal prompt if it shows local paths you do not
want public. Never capture `.env`, a key, or the dashboard token URL.

1. **Dashboard, Console tab, top.** Header with vault link and `testnet` tag, the ACTIVE pill,
   the `read-only` mode tag, and the stats row (available, paid out, requests, paid, escalated,
   blocked, canary trips, freezes).
2. **Dashboard, "Proof: agent keys" card.** The single `FunctionCall` key, receiver
   `vault.tw-firewall-demo.testnet`, the three method names, "deposits: impossible", and the
   "FUNCTION-CALL ONLY" pill.
3. **Dashboard, Incident feed.** Shows paid, escalated, blocked, frozen and canary trip events
   with their colour legend.
4. **Dashboard, Agents table.** Status, spent 24h vs daily limit, per-payment cap, hourly rate,
   payees and counters for `agent.tw-firewall-demo.testnet`.
5. **Dashboard, Attack runs tab.** Run `2026-11-09T04-59-38-380Z` selected, with its meta and the
   step timeline. Dry runs (`dryRun: true`, `FAKE` hashes) are listed in the same tab; do not
   capture one as the live run.
6. **Terminal, scenario [6].** The five stolen-key attempts and their typed access-key errors.
7. **Terminal, scenario [4].** `vault result: tripped [TRIPWIRE] (agent frozen)` and the tx link.
8. **Terminal, scenario [2].** The `[SIMULATED ATTACK]` invoice text, the agent's `pay` to
   `feed.`, `vault result: pending_approval [NEW_PAYEE]`, and the owner reject (`reject ok` with
   its tx link).
9. **Terminal, last lines.** `8/8 scenarios behaved as expected` and the saved run path.
10. **Explorer, canary tx.** The nearblocks page for `2tC28Aer...` showing the `request_payment`
    call to the vault.
11. **Explorer, agent account keys.** `agent.tw-firewall-demo.testnet` with only the
    function-call key.
12. **Terminal, `npm run status`.** Read-only report of the vault (views only, nothing signed).
    Its `vault keys:` line says either `WARNING: vault still has a full-access key ...` or
    `vault locked: no full-access keys`. Capture this after lockdown if you want to show the lock
    state; before lockdown, label it as "before lockdown".
13. **Terminal, `npm test` passing** (optional). The Node test suite (74 tests, all passing at
    the time of writing) runs offline with no keys.
