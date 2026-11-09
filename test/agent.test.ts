// agent.test.ts - offline tests for the agent wrapper on FakeChain with the scripted model.
import { test } from 'node:test';
import assert from 'node:assert/strict';
import { FakeChain } from '../src/agent/chain.ts';
import { combine, guardedPay, HELD, REFUSED } from '../src/agent/guard.ts';
import type { TurnTrust } from '../src/agent/guard.ts';
import { makeAgentLlm } from '../src/agent/llm.ts';
import { guardSummary, runAgent } from '../src/agent/runtime.ts';
import { runScenario, SCENARIOS, selectScenarios } from '../src/agent/scenarios.ts';
import type { ScenarioIds } from '../src/agent/scenarios.ts';
import { parseToolCall } from '../src/agent/tools.ts';
import type { PayCall } from '../src/agent/tools.ts';
import { newImplicitCanary } from '../src/lib/canary.ts';
import { runDrill } from '../src/scripts/drill.ts';
import { DRY_OWNER_ID, idsFor } from '../src/scripts/attack-demo.ts';

const OWNER = 'owner.testnet';
const SHOP = `store.${OWNER}`;
const API = `billing.${OWNER}`;
const DATA = `feed.${OWNER}`;
const VERIFIED: TurnTrust = { verified: true, kind: 'scripted' };
const UNVERIFIED: TurnTrust = { verified: false, kind: 'unverified', detail: 'test' };

function payCall(receiver_id: string, amount_near: string): PayCall {
  const p = parseToolCall('pay', { receiver_id, amount_near, memo: 'test' });
  assert.ok(p.ok, p.ok ? '' : p.error);
  return p.call as PayCall;
}

test('pay parsing is strict', () => {
  for (const bad of ['1,5', '-1', '1e3', '0x10', ' 1', '1.0000000000000000000000001', '']) {
    const r = parseToolCall('pay', { receiver_id: SHOP, amount_near: bad });
    assert.equal(r.ok, false, `accepted amount ${JSON.stringify(bad)}`);
  }
  assert.equal(parseToolCall('pay', { receiver_id: SHOP, amount_near: 1 }).ok, false, 'accepted a number');
  assert.equal(parseToolCall('pay', { receiver_id: SHOP, amount_near: '0.1', to: DATA }).ok, false, 'accepted an unknown key');
  assert.equal(parseToolCall('pay', { receiver_id: 'Shop..testnet', amount_near: '0.1' }).ok, false, 'accepted a bad account id');
  assert.equal(parseToolCall('pay', '{not json').ok, false);
  assert.equal(parseToolCall('pay', { receiver_id: SHOP, amount_near: '0.1', memo: 'a\u0000b' }).ok, false, 'accepted a control character');
  assert.equal(parseToolCall('fetch_document', { doc_id: '../etc' }).ok, false);
  assert.equal(parseToolCall('withdraw', {}).ok, false);
  const ok = parseToolCall('pay', JSON.stringify({ receiver_id: SHOP, amount_near: '1.5' }));
  assert.ok(ok.ok && ok.call.tool === 'pay' && ok.call.amount === 1_500_000_000_000_000_000_000_000n);
});

test('a canary payment trips the vault and the model sees only "refused"', async () => {
  const canary = newImplicitCanary().accountId;
  const chain = new FakeChain({ ownerId: OWNER, canaries: [canary] });
  const r = await guardedPay(chain, payCall(canary, '0.01'), VERIFIED);
  assert.equal(r.outcome, 'tripped');
  assert.equal(r.modelMessage, REFUSED);
  assert.equal((await chain.getAgent()).status.state, 'frozen');
  // the canary is invisible to the vault view: it looks like an ordinary receiver
  assert.ok(!(await chain.checkPayment(canary, 1n)).reasons.includes('TRIPWIRE' as never));
});

test('a vault block refuses without revealing the reason', async () => {
  const chain = new FakeChain({ ownerId: OWNER });
  await chain.reportReceiver(DATA, 'test report');
  chain.blocklist.set(DATA, 'confirmed');
  const r = await guardedPay(chain, payCall(DATA, '0.1'), VERIFIED);
  assert.equal(r.decision.decision, 'block');
  assert.equal(r.modelMessage, REFUSED);
  assert.doesNotMatch(r.modelMessage, /BLOCKLIST|canary|watchlist|limit/i);
  const over = await guardedPay(chain, payCall(SHOP, '2'), VERIFIED);
  assert.equal(over.modelMessage, REFUSED);
});

test('a vault warn becomes an on-chain approval request', async () => {
  const chain = new FakeChain({ ownerId: OWNER });
  const r = await guardedPay(chain, payCall(API, '0.6'), VERIFIED);
  assert.equal(r.outcome, 'escalated');
  assert.equal(r.modelMessage, HELD);
  assert.equal(r.approval?.where, 'vault');
  assert.ok(r.approval?.request_id);
  assert.equal(chain.pending.size, 1);
  const paid = await chain.owner.approve(r.approval!.request_id!);
  assert.equal(paid.result?.status, 'paid');
});

test('an unverified model turn is held locally and nothing is sent', async () => {
  const chain = new FakeChain({ ownerId: OWNER });
  const r = await guardedPay(chain, payCall(SHOP, '0.05'), UNVERIFIED);
  assert.equal(r.outcome, 'held');
  assert.equal(r.approval?.where, 'local');
  assert.ok(r.decision.reasons.some((x) => x.code === 'UNVERIFIED_TURN'));
  assert.equal(chain.transfers.length, 0);
  assert.equal(chain.pending.size, 0);
});

test('combine: scout block refuses, quiet vault blocks are not forwarded', () => {
  const allow = { verdict: 'allow' as const, reasons: [] };
  const d = combine(allow as never, { decision: 'block', reasons: [{ code: 'ACCOUNT_DOES_NOT_EXIST', severity: 'block', detail: '' }] }, VERIFIED);
  assert.deepEqual([d.decision, d.action], ['block', 'refuse']);
  const frozen = combine({ verdict: 'block', reasons: ['AGENT_FROZEN'] } as never, { decision: 'allow', reasons: [] }, VERIFIED);
  assert.deepEqual([frozen.decision, frozen.action], ['block', 'refuse']);
  const capped = combine({ verdict: 'block', reasons: ['OVER_PER_PAYMENT_CAP'] } as never, { decision: 'allow', reasons: [] }, VERIFIED);
  assert.deepEqual([capped.decision, capped.action], ['block', 'send']);
});

test('runAgent records the transcript, tx links and verdict', async () => {
  const chain = new FakeChain({ ownerId: OWNER });
  const llm = await makeAgentLlm('scripted', {
    turns: [
      { tool_calls: [{ name: 'pay', arguments: '{"receiver_id":"store.owner.testnet","amount_near":"1,5"}' }] },
      { tool_calls: [{ name: 'pay', arguments: { receiver_id: SHOP, amount_near: '0.05', memo: 'order' } }] },
      { content: 'Paid.' },
    ],
  });
  const run = await runAgent({ llm, chain, task: 'buy the thing' });
  assert.equal(run.stoppedBy, 'final');
  assert.match(run.toolMessages[0].content, /^invalid arguments/);
  assert.equal(run.toolMessages[1].content, 'paid 0.05 NEAR to store.owner.testnet');
  assert.equal(run.verdict.outcome, 'refused');
  assert.ok(run.log.txs.some((t) => t.method === 'request_payment' && t.url.includes(t.hash)));
  assert.ok(run.log.entries.every((e) => !Number.isNaN(Date.parse(e.t))));
});

test('selectScenarios accepts numbers and ids and rejects unknown ones', () => {
  assert.deepEqual(selectScenarios('4,legit').map((s) => s.n), [1, 4]);
  assert.throws(() => selectScenarios('99'));
  assert.equal(SCENARIOS.length, 8);
});

test('all 8 scripted scenarios produce the expected outcomes on one fake chain', async () => {
  const canary = newImplicitCanary().accountId;
  const chain = new FakeChain({ ownerId: OWNER, canaries: [canary] });
  const ids: ScenarioIds = {
    owner: OWNER, vault: chain.vaultId, agent: chain.agentId, shop: SHOP, api: API, attacker: DATA,
    ghost: `ghost-test.${OWNER}`, canary,
  };
  for (const s of SCENARIOS) {
    const run = await runScenario(s, { chain, ids, llmFor: (x) => makeAgentLlm('scripted', { turns: x.script(ids) }) });
    assert.ok(run.pass, `scenario ${s.n} (${s.id}) failed: ${run.why}`);
    // fetch_document is excluded: the vendor list in scenario 4 is the lure that names the canary
    for (const m of (run.agent?.toolMessages ?? []).filter((x) => x.tool !== 'fetch_document')) {
      assert.ok(!m.content.includes(canary), `scenario ${s.n} leaked the canary id to the model`);
      assert.doesNotMatch(m.content, /TRIPWIRE|canary|watchlist/i, `scenario ${s.n} leaked a reason to the model`);
    }
  }
  assert.equal(chain.transfers.filter((t) => t.ok && t.receiver === DATA).length, 0, 'the attacker was paid');
  assert.equal(chain.transfers.filter((t) => t.ok && t.receiver === canary).length, 0, 'the canary was paid');
});

test('canary drill freezes and the owner unfreezes', async () => {
  const chain = new FakeChain({ ownerId: OWNER });
  const r = await runDrill(chain);
  assert.ok(r.pass, JSON.stringify(r.steps));
  assert.equal((await chain.getAgent()).status.state, 'active');
});

test('guard line says what happened to the payment', () => {
  assert.equal(guardSummary({ decision: 'block', action: 'send' }), 'block → forwarded to vault to be recorded on-chain');
  assert.equal(guardSummary({ decision: 'block', action: 'send', canary: true }), 'block → forwarded to vault, which trips the canary and freezes the agent');
  assert.equal(guardSummary({ decision: 'block', action: 'refuse' }), 'block → refused locally, nothing sent');
  assert.equal(guardSummary({ decision: 'warn', action: 'hold' }), 'warn → held locally for human approval, nothing sent');
  assert.equal(guardSummary({ decision: 'warn', action: 'send' }), 'warn → forwarded to vault, which pays or holds it for owner approval');
  assert.equal(guardSummary({ decision: 'allow', action: 'send' }), 'allow → forwarded to vault for payment');
});

test('scenarios that leave the agent frozen run last', () => {
  const firstFreeze = SCENARIOS.findIndex((s) => s.freezes);
  assert.ok(firstFreeze > 0);
  assert.ok(SCENARIOS.slice(firstFreeze).every((s) => s.freezes), SCENARIOS.map((s) => s.n).join(','));
  assert.deepEqual(SCENARIOS.map((s) => s.n), [1, 5, 2, 8, 7, 6, 4, 3]);
});

test('dry and live use the same default payee names (store. / billing. / feed.)', () => {
  const names = ['VAULT_ID', 'AGENT_ID', 'SHOP_ID', 'API_ID', 'DATA_ID', 'ATTACKER_ID'];
  const saved = Object.fromEntries(names.map((n) => [n, process.env[n]]));
  try {
    for (const n of names) delete process.env[n];
    const ids = idsFor(DRY_OWNER_ID);
    assert.deepEqual([ids.shop, ids.api, ids.attacker], ['store.tw-firewall-demo.testnet', 'billing.tw-firewall-demo.testnet', 'feed.tw-firewall-demo.testnet']);
    process.env.SHOP_ID = 'shop.legacy.testnet';
    process.env.DATA_ID = 'data.legacy.testnet';
    const legacy = idsFor('legacy.testnet');
    assert.deepEqual([legacy.shop, legacy.api, legacy.attacker], ['shop.legacy.testnet', 'billing.legacy.testnet', 'data.legacy.testnet']);
    const chain = new FakeChain({ ownerId: 'o.testnet' });
    for (const id of ['store.o.testnet', 'billing.o.testnet', 'feed.o.testnet']) assert.ok(chain.accounts.has(id), id);
    assert.ok(chain.policy.allowlist.includes('store.o.testnet'));
  } finally {
    for (const n of names) if (saved[n] === undefined) delete process.env[n]; else process.env[n] = saved[n];
  }
});
