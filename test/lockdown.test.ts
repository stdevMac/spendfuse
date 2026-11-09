// lockdown.test.ts - the lockdown plan (pure) and the keyless vault id lookup; no network.
import { test } from 'node:test';
import assert from 'node:assert/strict';
import type { KeyInfo } from '../src/lib/near.ts';
import { lockdownPlan, vaultIdFromEnv } from '../src/scripts/lockdown.ts';

const V = 'vault.o.testnet';
const full = (publicKey: string): KeyInfo => ({ publicKey, nonce: 1n, fullAccess: true });
const fc = (publicKey: string): KeyInfo => ({ publicKey, nonce: 1n, fullAccess: false, receiverId: V, methodNames: ['request_payment'], allowance: null });

test('keyless (dry run): the single full-access key is the target', () => {
  assert.deepEqual(lockdownPlan(V, [full('ed25519:A'), fc('ed25519:B')], null), { kind: 'delete', publicKey: 'ed25519:A', known: false });
  assert.deepEqual(lockdownPlan(V, [fc('ed25519:B')], null), { kind: 'locked' });
  const two = lockdownPlan(V, [full('ed25519:A'), full('ed25519:C')], null);
  assert.equal(two.kind, 'refuse');
});

test('with VAULT_KEY: it must be on the vault, full access, and the only full-access key', () => {
  assert.deepEqual(lockdownPlan(V, [full('ed25519:A'), fc('ed25519:B')], 'ed25519:A'), { kind: 'delete', publicKey: 'ed25519:A', known: true });
  assert.match((lockdownPlan(V, [full('ed25519:A')], 'ed25519:Z') as { reason: string }).reason, /not on/);
  assert.match((lockdownPlan(V, [full('ed25519:A'), fc('ed25519:B')], 'ed25519:B') as { reason: string }).reason, /not a full-access key/);
  assert.match((lockdownPlan(V, [full('ed25519:A'), full('ed25519:C')], 'ed25519:A') as { reason: string }).reason, /other full-access key/);
  assert.deepEqual(lockdownPlan(V, [], 'ed25519:A'), { kind: 'locked' });
});

test('vault id: VAULT_ID, else vault.<OWNER_ID>, else a clear error', () => {
  const saved = { VAULT_ID: process.env.VAULT_ID, OWNER_ID: process.env.OWNER_ID };
  try {
    delete process.env.VAULT_ID;
    process.env.OWNER_ID = 'tw-firewall-demo.testnet';
    assert.equal(vaultIdFromEnv(), 'vault.tw-firewall-demo.testnet');
    process.env.VAULT_ID = 'other.testnet';
    assert.equal(vaultIdFromEnv(), 'other.testnet');
    delete process.env.VAULT_ID;
    delete process.env.OWNER_ID;
    assert.throws(() => vaultIdFromEnv(), /Missing VAULT_ID.*OWNER_ID/);
    process.env.OWNER_ID = 'Bad Owner';
    assert.throws(() => vaultIdFromEnv(), /vault id from OWNER_ID/);
  } finally {
    for (const [k, v] of Object.entries(saved)) if (v === undefined) delete process.env[k]; else process.env[k] = v;
  }
});
