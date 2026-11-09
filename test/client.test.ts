// client.test.ts - offline tests for the Spendfuse client layer. No network except a 127.0.0.1 stub RPC;
// a zero-signature signer is used, so nothing here could be broadcast.
import { test } from 'node:test';
import assert from 'node:assert/strict';
import { createServer } from 'node:http';
import type { AddressInfo } from 'node:net';
import { mkdtempSync, readFileSync, statSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { decodeSignedTransaction, KeyPair, nearToYocto, PublicKey, Signer, teraToGas } from 'near-api-js';
import { parseNearStrict } from '../src/lib/amount.ts';
import { canaryHash, newImplicitCanary } from '../src/lib/canary.ts';
import { appendEnv, envFileNames, loadEnv } from '../src/lib/env.ts';
import { makeProvider } from '../src/lib/near.ts';
import {
  agentApi,
  decodeContractError,
  formatNear,
  ownerApi,
  parseEvents,
  stripUndefined,
  toPolicyInput,
  toU128,
  SpendfuseClient,
} from '../src/lib/spendfuse.ts';

// ---------------------------------------------------------------- fixtures
class ZeroSigner extends Signer {
  #pk: PublicKey;
  constructor(pk: PublicKey) {
    super();
    this.#pk = pk;
  }
  async getPublicKey(): Promise<PublicKey> {
    return this.#pk;
  }
  protected async signBytes(_bytes: Uint8Array): Promise<Uint8Array> {
    return new Uint8Array(64);
  }
}
const BLOCK_HASH = '11111111111111111111111111111111';
const b64 = (v: unknown) => Buffer.from(JSON.stringify(v)).toString('base64');
const bytes = (v: unknown) => [...Buffer.from(JSON.stringify(v))];
const VAULT = 'vault.owner.testnet';
const PANIC_FAILURE = (msg: string) => ({ ActionError: { index: 0, kind: { FunctionCallError: { ExecutionError: `Smart contract panicked: ${msg}` } } } });

const ev = (event: string, data: unknown[], standard = 'tripwire') => `EVENT_JSON:${JSON.stringify({ standard, version: '1.0.0', event, data })}`;

type Params = Record<string, unknown> & { request_type?: string; method_name?: string; args_base64?: string; signed_tx_base64?: string };
type Reply = { result?: unknown; error?: unknown };

async function stub(handler: (method: string, params: Params) => Reply | undefined) {
  const server = createServer(async (req, res) => {
    let raw = '';
    for await (const chunk of req) raw += chunk;
    const { id, method, params } = JSON.parse(raw) as { id: string; method: string; params: Params };
    let reply = handler(method, params);
    if (!reply && method === 'block') reply = { result: { header: { hash: BLOCK_HASH, height: 1, timestamp_nanosec: '0' }, chunks: [] } };
    if (!reply && method === 'query' && params.request_type === 'view_access_key')
      reply = { result: { nonce: 100, permission: 'FullAccess', block_hash: BLOCK_HASH, block_height: 1 } };
    reply ??= { error: { name: 'REQUEST_VALIDATION_ERROR', cause: { name: 'METHOD_NOT_FOUND', info: {} }, code: -32601, message: 'no stub' } };
    res.writeHead(200, { 'content-type': 'application/json' }).end(JSON.stringify({ jsonrpc: '2.0', id, ...reply }));
  });
  await new Promise<void>((resolve) => server.listen(0, '127.0.0.1', resolve));
  const { port } = server.address() as AddressInfo;
  return { url: `http://127.0.0.1:${port}`, close: () => new Promise<void>((resolve) => server.close(() => resolve())) };
}

function txResult(hash: string, signerId: string, status: unknown, logs: string[] = []) {
  const outcome = (executor: string, st: unknown, l: string[]) => ({
    executor_id: executor,
    gas_burnt: 2_400_000_000_000,
    tokens_burnt: '240000000000000000000',
    logs: l,
    receipt_ids: [],
    status: st,
    metadata: { version: 3, gas_profile: [] },
  });
  return {
    final_execution_status: 'EXECUTED_OPTIMISTIC',
    status,
    transaction: { hash, signer_id: signerId, receiver_id: VAULT, actions: [] },
    transaction_outcome: { id: hash, block_hash: BLOCK_HASH, outcome: outcome(signerId, { SuccessReceiptId: 'R1' }, []), proof: [] },
    receipts_outcome: [{ id: 'R1', block_hash: BLOCK_HASH, outcome: outcome(VAULT, status, logs), proof: [] }],
  };
}

interface SentCall {
  signerId: string;
  receiverId: string;
  methodName: string;
  args: Record<string, unknown>;
  gas: bigint;
  deposit: bigint;
}
function decodeSent(base64: string): SentCall {
  const signed = decodeSignedTransaction(Buffer.from(base64, 'base64')) as unknown as {
    transaction: { signerId: string; receiverId: string; actions: { functionCall?: { methodName: string; args: Uint8Array; gas: bigint | number; deposit: bigint | number } }[] };
  };
  const fc = signed.transaction.actions[0]?.functionCall;
  assert.ok(fc, 'expected a FunctionCall action');
  return {
    signerId: signed.transaction.signerId,
    receiverId: signed.transaction.receiverId,
    methodName: fc.methodName,
    args: JSON.parse(Buffer.from(fc.args).toString('utf8')) as Record<string, unknown>,
    gas: BigInt(fc.gas),
    deposit: BigInt(fc.deposit),
  };
}

// ---------------------------------------------------------------- parseEvents
test('parseEvents keeps spendfuse events in order and skips everything else', () => {
  const logs = [
    'plain log line',
    ev('paid', [{ seq: '7', at_ms: '1', block_height: '2', agent_id: 'agent.t', receiver_id: 'shop.t', amount: '10', by: 'agent.t' }]),
    ev('transfer', [{}], 'nep141'), // other standard
    'EVENT_JSON:{not json',
    ev('made_up_event', [{}]), // unknown kind
    'EVENT_JSON:{"standard":"tripwire","version":"1.0.0","event":"paid","data":{}}', // data not an array
    ev('tripped', [{ at_ms: '1', block_height: '2', agent_id: 'agent.t', receiver_id: 'canary.t', reasons: ['TRIPWIRE'], by: 'agent.t' }]),
    ev('frozen', [{ seq: '9', at_ms: '1', block_height: '2', agent_id: 'agent.t', note: 'TRIPWIRE', by: 'agent.t' }]),
  ];
  const out = parseEvents(logs);
  assert.deepEqual(out.map((e) => e.event), ['paid', 'tripped', 'frozen']);
  assert.equal(out[0]?.data[0]?.amount, '10');
  assert.equal(out[1]?.data[0]?.seq, undefined); // quiet event: no seq
  assert.deepEqual(out[1]?.data[0]?.reasons, ['TRIPWIRE']);
  assert.equal(out[0]?.standard, 'tripwire');
  assert.deepEqual(parseEvents([]), []);
});

// ---------------------------------------------------------------- canary
test('canaryHash is hex sha256 of the account id (fixture)', () => {
  assert.equal(canaryHash('canary-7f3a.testnet'), '1e0b149bf10c045d3ce48c0a0d32a6b2d3ff8243589fe00a57b5b830acc6bff7');
  assert.throws(() => canaryHash('Not Valid!'), /not a valid NEAR account id/);
  const c = newImplicitCanary();
  assert.match(c.accountId, /^[0-9a-f]{64}$/);
  assert.equal(c.hash, canaryHash(c.accountId));
  assert.deepEqual(Object.keys(c).sort(), ['accountId', 'hash', 'publicKey']); // no secret key
});

// ---------------------------------------------------------------- args
test('stripUndefined drops undefined keys deeply, keeps null, stringifies bigint', () => {
  const out = stripUndefined({ a: 1, b: undefined, c: null, d: { e: undefined, f: 2n, g: [1, undefined, { h: undefined }] } });
  assert.deepEqual(out, { a: 1, c: null, d: { f: '2', g: [1, undefined, {}] } });
  assert.equal(JSON.stringify(stripUndefined({ reason: undefined })), '{}');
});

test('toPolicyInput sends only contract keys, as strings', () => {
  const p = toPolicyInput({
    max_per_payment: nearToYocto('1'),
    daily_limit: '3000000000000000000000000',
    approval_threshold: 0n,
    new_payee_limit: nearToYocto('0.2'),
    max_payments_per_hour: 10,
    expires_at_ms: null,
  });
  assert.deepEqual(p, {
    max_per_payment: '1000000000000000000000000',
    daily_limit: '3000000000000000000000000',
    approval_threshold: '0',
    new_payee_limit: '200000000000000000000000',
    max_payments_per_hour: 10,
  });
  assert.throws(() => toU128('-1'), RangeError);
  assert.throws(() => toU128('1.5'), RangeError);
  assert.throws(() => toU128(1n << 128n), RangeError);
  assert.equal(formatNear(nearToYocto('1.23456')), '1.2345');
  assert.equal(formatNear(0n), '0');
});

// ---------------------------------------------------------------- errors
test('decodeContractError handles panics in strings, summaries, view errors and plain errors', async () => {
  assert.deepEqual(decodeContractError('Smart contract panicked: Requires attached deposit of exactly 1 yoctoNEAR'), {
    kind: 'contract-panic',
    message: 'Requires attached deposit of exactly 1 yoctoNEAR',
    txHash: null,
    name: 'string',
    contract: true,
  });
  const viewText = 'wasm execution failed with error: HostError(GuestPanic { panic_msg: "Only the owner can do this \\"x\\"" })';
  assert.equal(decodeContractError(viewText).message, 'Only the owner can do this "x"');
  assert.equal(decodeContractError('socket hang up').contract, false);

  const failed = {
    hash: 'H',
    url: 'u',
    ok: false,
    pending: false,
    value: null,
    error: 'Agent is frozen',
    failure: PANIC_FAILURE('Agent is frozen'),
    logs: [],
    events: [],
    gasBurnt: 0n,
    tokensBurnt: 0n,
    receiptFailures: [],
  };
  const d = decodeContractError(failed);
  assert.equal(d.kind, 'contract-panic');
  assert.equal(d.message, 'Agent is frozen');
  assert.equal(d.txHash, 'H');
  assert.equal(decodeContractError({ summary: failed, events: [], result: null, ok: false, error: 'Agent is frozen' }).message, 'Agent is frozen');

  // a real view panic through the provider
  const s = await stub((method, p) =>
    method === 'query' && p.request_type === 'call_function'
      ? { result: { block_hash: BLOCK_HASH, block_height: 1, logs: [], error: 'wasm execution failed with error: HostError(GuestPanic { panic_msg: "The contract is not initialized" })' } }
      : undefined,
  );
  try {
    const err = await new SpendfuseClient({ provider: makeProvider([s.url]), vaultId: VAULT }).getConfig().catch((e: unknown) => e);
    const v = decodeContractError(err);
    assert.equal(v.kind, 'view-panic');
    assert.equal(v.message, 'The contract is not initialized');
    assert.equal(v.contract, true);
  } finally {
    await s.close();
  }
  assert.equal(decodeContractError(new Error('boom')).contract, false);
});

// ---------------------------------------------------------------- amounts
test('parseNearStrict edge cases', () => {
  assert.equal(parseNearStrict('1'), 10n ** 24n);
  assert.equal(parseNearStrict('0.000000000000000000000001'), 1n);
  assert.equal(parseNearStrict('0.5'), 5n * 10n ** 23n);
  for (const bad of ['', ' 1', '1 ', '01', '1.', '.5', '1e3', '-1', '+1', '0x10', '1,5', '1.0000000000000000000000001', '0', '0.0', 'NaN', 'Infinity', '１'])
    assert.throws(() => parseNearStrict(bad), RangeError, `should reject ${JSON.stringify(bad)}`);
  for (const bad of [1, 1n, null, undefined, {}, ['1']]) assert.throws(() => parseNearStrict(bad), TypeError);
  assert.throws(() => parseNearStrict('2', 10n ** 24n), RangeError); // over cap
  assert.equal(parseNearStrict('1', 10n ** 24n), 10n ** 24n); // at cap
});

// ---------------------------------------------------------------- views
test('SpendfuseClient views send the right method and args (undefined stripped)', async () => {
  const seen: { method: string; args: unknown }[] = [];
  const s = await stub((method, p) => {
    if (method !== 'query' || p.request_type !== 'call_function') return undefined;
    const args = JSON.parse(Buffer.from(String(p.args_base64), 'base64').toString('utf8') || '{}');
    seen.push({ method: String(p.method_name), args });
    const value = p.method_name === 'get_agent' ? null : p.method_name === 'check_payment' ? { verdict: 'warn', reasons: ['NEW_PAYEE'] } : [];
    return { result: { result: bytes(value), logs: [], block_hash: BLOCK_HASH, block_height: 1 } };
  });
  try {
    const c = new SpendfuseClient({ provider: makeProvider([s.url]), vaultId: VAULT });
    assert.equal(await c.getAgent('agent.t'), null);
    assert.deepEqual(await c.checkPayment('agent.t', 'shop.t', 5n), { verdict: 'warn', reasons: ['NEW_PAYEE'] });
    await c.listAgents();
    await c.getActivity(12n, 5);
    assert.deepEqual(seen, [
      { method: 'get_agent', args: { agent_id: 'agent.t' } },
      { method: 'check_payment', args: { agent_id: 'agent.t', receiver_id: 'shop.t', amount: '5' } },
      { method: 'list_agents', args: {} },
      { method: 'get_activity', args: { before_seq: '12', limit: 5 } },
    ]);
  } finally {
    await s.close();
  }
});

// ---------------------------------------------------------------- change calls (stub RPC, zero signatures)
test('AgentApi / OwnerApi: gas, deposits and args on the wire; events and result decoded', async () => {
  const sent: SentCall[] = [];
  const s = await stub((method, p) => {
    if (method !== 'send_tx') return undefined;
    const call = decodeSent(String(p.signed_tx_base64));
    sent.push(call);
    const hash = `H${sent.length}`;
    if (call.methodName === 'request_payment') {
      const result = { status: 'paid', request_id: '1', reasons: [], amount: '5', receiver_id: 'shop.t', frozen: false };
      return { result: txResult(hash, call.signerId, { SuccessValue: b64(result) }, ['note', ev('paid', [{ seq: '1', at_ms: '1', block_height: '1', agent_id: call.signerId, receiver_id: 'shop.t', amount: '5', by: call.signerId }])]) };
    }
    if (call.methodName === 'unpause') return { result: txResult(hash, call.signerId, { SuccessValue: '' }, [ev('unpaused', [{ seq: '2', at_ms: '1', block_height: '1', by: call.signerId }])]) };
    if (call.methodName === 'self_freeze') return { result: txResult(hash, call.signerId, { Failure: PANIC_FAILURE('Agent is not registered') }) };
    return { result: txResult(hash, call.signerId, { SuccessValue: b64(true) }) };
  });
  try {
    const provider = makeProvider([s.url]);
    const who = (accountId: string) => ({ accountId, provider, signer: new ZeroSigner(KeyPair.fromRandom('ed25519').getPublicKey()) });
    const hashes: string[] = [];
    const agent = agentApi(who('agent.t'), { vaultId: VAULT, onHash: (h, m) => void hashes.push(`${m}:${h.length > 0}`) });
    const owner = ownerApi(who('owner.t'), { vaultId: VAULT });

    const paid = await agent.requestPayment({ receiver_id: 'shop.t', amount: 5n });
    assert.equal(paid.ok, true);
    assert.equal(paid.result?.status, 'paid');
    assert.deepEqual(paid.events.map((e) => e.event), ['paid']);
    assert.deepEqual(hashes, ['request_payment:true']);

    const frozen = await agent.selfFreeze();
    assert.equal(frozen.ok, false);
    assert.equal(frozen.result, null);
    assert.equal(frozen.error, 'Agent is not registered');
    assert.equal(decodeContractError(frozen).message, 'Agent is not registered');

    await agent.reportReceiver('bad.t', 'phishing', undefined);
    const unpaused = await owner.unpause();
    assert.equal(unpaused.ok, true);
    assert.equal(unpaused.result, null); // void method
    assert.deepEqual(unpaused.events.map((e) => e.event), ['unpaused']);
    await owner.freezeAgent('agent.t', 'manual');
    await owner.registerAgent('agent.t', 'demo', { max_per_payment: 1n, daily_limit: 3n, approval_threshold: 0n, new_payee_limit: 1n, max_payments_per_hour: 5 });
    await owner.approve(3n);
    await owner.deposit(nearToYocto('1'));

    const byMethod = Object.fromEntries(sent.map((c) => [c.methodName, c]));
    assert.deepEqual(byMethod.request_payment, {
      signerId: 'agent.t', receiverId: VAULT, methodName: 'request_payment', args: { receiver_id: 'shop.t', amount: '5' }, gas: teraToGas('50'), deposit: 0n,
    });
    assert.deepEqual(byMethod.self_freeze?.args, {}); // reason omitted, not null
    assert.equal(byMethod.self_freeze?.deposit, 0n);
    assert.deepEqual(byMethod.report_receiver?.args, { receiver_id: 'bad.t', reason: 'phishing' });
    assert.equal(byMethod.report_receiver?.deposit, 0n);
    for (const m of ['unpause', 'register_agent', 'approve']) assert.equal(byMethod[m]?.deposit, 1n, `${m} attaches 1 yocto`);
    assert.equal(byMethod.freeze_agent?.deposit, 0n); // guardian-level method: no yocto
    assert.equal(byMethod.deposit?.deposit, nearToYocto('1'));
    assert.deepEqual(byMethod.approve?.args, { request_id: '3' });
    assert.equal(byMethod.approve?.gas, teraToGas('50'));
    assert.deepEqual(byMethod.register_agent?.args, {
      agent_id: 'agent.t',
      label: 'demo',
      policy: { max_per_payment: '1', daily_limit: '3', approval_threshold: '0', new_payee_limit: '1', max_payments_per_hour: 5 },
    });
    assert.ok(sent.every((c) => c.receiverId === VAULT));
  } finally {
    await s.close();
  }
});

// ---------------------------------------------------------------- env
test('appendEnv writes 0600, refuses duplicates and newlines; loadEnv does not override', () => {
  const dir = mkdtempSync(join(tmpdir(), 'spendfuse-env-'));
  const path = join(dir, '.env');
  appendEnv('TW_TEST_A', 'one', path);
  appendEnv('TW_TEST_B', 'two', path);
  assert.equal(statSync(path).mode & 0o777, 0o600);
  assert.equal(readFileSync(path, 'utf8'), 'TW_TEST_A=one\nTW_TEST_B=two\n');
  assert.deepEqual([...envFileNames(path)], ['TW_TEST_A', 'TW_TEST_B']);
  assert.throws(() => appendEnv('TW_TEST_A', 'again', path), /already defined/);
  assert.throws(() => appendEnv('TW_TEST_C', 'a\nb', path), /newline/);
  process.env.TW_TEST_A = 'from-process';
  assert.equal(loadEnv(path), true);
  assert.equal(process.env.TW_TEST_A, 'from-process');
  delete process.env.TW_TEST_A;
  delete process.env.TW_TEST_B;
});
