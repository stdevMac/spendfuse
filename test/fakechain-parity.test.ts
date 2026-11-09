// fakechain-parity.test.ts - FakeChain's block/freeze bookkeeping matches contract/src/lib.rs submit_payment
// (is_environmental_block, quiet AGENT_FROZEN / VAULT_PAUSED blocks, auto-freeze threshold and backstop).
import { test } from 'node:test';
import assert from 'node:assert/strict';
import { FakeChain, isEnvironmentalBlock } from '../src/agent/chain.ts';
import { NEAR } from '../src/lib/spendfuse.ts';
import type { Reason } from '../src/lib/types.ts';

const OWNER = 'owner.testnet';
const fresh = (i: number) => i.toString(16).padStart(64, '0'); // implicit ids, never payees yet
const q = NEAR / 4n; // 0.25 NEAR: over new_payee_limit, under approval_threshold

test('isEnvironmentalBlock mirrors the contract rule', () => {
  const yes: Reason[][] = [
    ['INSUFFICIENT_VAULT_BALANCE'],
    ['TOO_MANY_PENDING'],
    ['NEW_PAYEE', 'TOO_MANY_PENDING'],
    ['REPORTED_RECEIVER', 'NEW_PAYEE', 'NEEDS_APPROVAL', 'TOO_MANY_PENDING'],
    ['INSUFFICIENT_VAULT_BALANCE', 'TOO_MANY_PENDING'],
  ];
  const no: Reason[][] = [
    [],
    ['NEW_PAYEE'],
    ['NEW_PAYEE', 'NEEDS_APPROVAL'],
    ['OVER_DAILY_LIMIT'],
    ['OVER_DAILY_LIMIT', 'INSUFFICIENT_VAULT_BALANCE'],
    ['OVER_PER_PAYMENT_CAP', 'OVER_DAILY_LIMIT', 'INSUFFICIENT_VAULT_BALANCE'],
    ['RATE_LIMITED', 'INSUFFICIENT_VAULT_BALANCE'],
    ['AGENT_FROZEN'],
    ['VAULT_PAUSED'],
  ];
  for (const r of yes) assert.equal(isEnvironmentalBlock(r), true, r.join(','));
  for (const r of no) assert.equal(isEnvironmentalBlock(r), false, r.join(','));
});

test('TOO_MANY_PENDING blocks are counted but never auto-freeze', async () => {
  const chain = new FakeChain({ ownerId: OWNER, policy: { auto_freeze_after_blocks: 1, daily_limit: 100n * NEAR, max_payments_per_hour: 100 }, balance: 100n * NEAR });
  for (let i = 0; i < 5; i++) assert.equal(chain.submit({ receiver_id: fresh(i), amount: q }).status, 'pending_approval');
  for (let i = 5; i < 10; i++) {
    const r = chain.submit({ receiver_id: fresh(i), amount: q });
    assert.equal(r.status, 'blocked');
    assert.deepEqual(r.reasons, ['NEW_PAYEE', 'TOO_MANY_PENDING']);
    assert.equal(r.frozen, false);
  }
  const v = await chain.getAgent();
  assert.equal(v.status.state, 'active');
  assert.equal(v.counters.blocked, 5);
  assert.equal(v.blocks_last_hour, 0);
  assert.equal(chain.events.filter((e) => e.event === 'blocked').length, 5);
});

test('INSUFFICIENT_VAULT_BALANCE alone is environmental; with a limit reason it is not', async () => {
  const chain = new FakeChain({ ownerId: OWNER, balance: q, policy: { auto_freeze_after_blocks: 1 } });
  const shop = `store.${OWNER}`;
  const env = chain.submit({ receiver_id: shop, amount: q + 1n });
  assert.deepEqual(env.reasons, ['INSUFFICIENT_VAULT_BALANCE']);
  assert.equal(env.frozen, false);
  assert.equal(chain.blocksLastHour(), 0);
  const hard = chain.submit({ receiver_id: shop, amount: 4n * NEAR });
  assert.deepEqual(hard.reasons, ['OVER_PER_PAYMENT_CAP', 'OVER_DAILY_LIMIT', 'INSUFFICIENT_VAULT_BALANCE']);
  assert.equal(hard.frozen, true);
  assert.match((await chain.getAgent()).status.state, /frozen/);
  assert.equal(chain.counters.blocked, 2);
});

test('limit blocks count toward auto-freeze at the configured threshold', () => {
  const chain = new FakeChain({ ownerId: OWNER, policy: { auto_freeze_after_blocks: 3 } });
  const shop = `store.${OWNER}`;
  for (let i = 1; i <= 3; i++) {
    const r = chain.submit({ receiver_id: shop, amount: 2n * NEAR });
    assert.deepEqual(r.reasons, ['OVER_PER_PAYMENT_CAP']);
    assert.equal(r.frozen, i === 3);
  }
  assert.equal(chain.frozen?.reason, 'AUTO_FREEZE: 3 blocked payment attempts within 1h');
  assert.equal(chain.frozen?.by, chain.vaultId);
});

test('threshold 0 falls back to the hard backstop of 25', () => {
  const chain = new FakeChain({ ownerId: OWNER, policy: { auto_freeze_after_blocks: 0 } });
  const shop = `store.${OWNER}`;
  for (let i = 1; i <= 25; i++) assert.equal(chain.submit({ receiver_id: shop, amount: 2n * NEAR }).frozen, i === 25);
  assert.equal(chain.frozen?.reason, 'AUTO_FREEZE: 25 blocked payment attempts within 1h');
});

test('AGENT_FROZEN and VAULT_PAUSED blocks are quiet', async () => {
  const chain = new FakeChain({ ownerId: OWNER, policy: { auto_freeze_after_blocks: 1 } });
  const shop = `store.${OWNER}`;
  chain.paused = true;
  const paused = chain.submit({ receiver_id: shop, amount: q });
  assert.deepEqual(paused.reasons, ['VAULT_PAUSED']);
  assert.equal(paused.frozen, false);
  assert.equal(chain.frozen, null);
  chain.paused = false;
  await chain.selfFreeze('test');
  const frozen = chain.submit({ receiver_id: shop, amount: q });
  assert.deepEqual(frozen.reasons, ['AGENT_FROZEN']);
  assert.equal(frozen.frozen, true);
  assert.equal(chain.counters.blocked, 0);
  assert.equal(chain.counters.blocked_while_frozen, 1);
  assert.equal(chain.blocksLastHour(), 0);
});

test('pending requests expire after 24h and stop counting against limits', () => {
  let t = 1_000_000;
  const chain = new FakeChain({ ownerId: OWNER, now: () => t });
  for (let i = 0; i < 5; i++) chain.submit({ receiver_id: fresh(i), amount: q });
  assert.equal(chain.submit({ receiver_id: fresh(5), amount: q }).status, 'blocked');
  t += 24 * 3_600_000;
  assert.equal(chain.submit({ receiver_id: fresh(6), amount: q }).status, 'pending_approval');
  assert.equal(chain.counters.expired, 5);
  assert.equal(chain.pending.size, 1);
});

test('check_payment view ignores expired requests like the contract', async () => {
  let t = 1_000_000;
  const chain = new FakeChain({ ownerId: OWNER, now: () => t });
  for (let i = 0; i < 5; i++) chain.submit({ receiver_id: fresh(i), amount: q });
  assert.deepEqual((await chain.checkPayment(fresh(9), q)).reasons, ['NEW_PAYEE', 'TOO_MANY_PENDING']);
  t += 24 * 3_600_000;
  assert.deepEqual(await chain.checkPayment(fresh(9), q), { verdict: 'warn', reasons: ['NEW_PAYEE'] });
  assert.equal(chain.pending.size, 5); // the view does not mutate
});
