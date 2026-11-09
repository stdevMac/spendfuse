// attest.test.ts - offline tests for the pure near-attest.ts policy checks (no network).
import { test } from 'node:test';
import assert from 'node:assert/strict';
import { defaultAcceptedTcb, enforceModelPolicy, enforcePins, listFromEnv, type CheckedReport } from '../src/llm/near-attest.ts';

const report = (o: Partial<CheckedReport> = {}): CheckedReport => ({
  tcbStatus: 'UpToDate', advisoryIds: [], signingAddress: '0xabc', signingAlgo: 'ecdsa',
  composeHash: 'aa'.repeat(32), gpu: 'verified', modelName: 'z-ai/glm-5.3-flash', tlsBound: false, ...o,
});

test('model report without verified GPU evidence is rejected unless allowNoGpu', () => {
  assert.throws(() => enforceModelPolicy(report({ gpu: 'absent' }), 'z-ai/glm-5.3-flash'), /GPU/);
  assert.throws(() => enforceModelPolicy(report({ gpu: undefined }), 'z-ai/glm-5.3-flash'), /GPU/);
  enforceModelPolicy(report({ gpu: 'absent' }), 'z-ai/glm-5.3-flash', { allowNoGpu: true });
  enforceModelPolicy(report(), 'z-ai/glm-5.3-flash');
});

test('model_name must equal the requested model when present', () => {
  assert.throws(() => enforceModelPolicy(report(), 'other/model'), /not the requested/);
  enforceModelPolicy(report({ modelName: undefined }), 'other/model');
});

test('compose hash pinning', () => {
  const r = [report(), report({ composeHash: 'bb'.repeat(32) })];
  assert.equal(enforcePins(r, undefined), false);
  assert.equal(enforcePins(r, []), false);
  assert.equal(enforcePins(r, ['0x' + 'AA'.repeat(32), 'bb'.repeat(32)]), true);
  assert.throws(() => enforcePins(r, ['aa'.repeat(32)]), /not in the pinned list/);
});

test('env lists and TCB default', () => {
  assert.equal(listFromEnv(undefined), undefined);
  assert.equal(listFromEnv(' , '), undefined);
  assert.deepEqual(listFromEnv('a, b,,c'), ['a', 'b', 'c']);
  assert.deepEqual(defaultAcceptedTcb({}), ['UpToDate']);
  assert.deepEqual(defaultAcceptedTcb({ NEARAI_ACCEPTED_TCB: 'UpToDate,OutOfDate' }), ['UpToDate', 'OutOfDate']);
});
