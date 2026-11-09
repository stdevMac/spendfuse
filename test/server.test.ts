// Offline tests for the dashboard server: a fake backend is injected, nothing touches the network.
import { test, after, before, describe } from 'node:test';
import assert from 'node:assert/strict';
import { request } from 'node:http';
import { mkdtempSync, mkdirSync, rmSync, writeFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { createDashboard, CSP, isRequestId, checkReason, keyProof } from '../src/server/app.ts';
import type { Dashboard } from '../src/server/app.ts';
import type { ActionOutcome, Backend, KeyJson, Signers, Views } from '../src/server/backend.ts';
import { ACTION_NAMES, GUARDIAN_ACTIONS } from '../src/server/backend.ts';
import type { AgentView, ConfigView, LogEntry, Stats } from '../src/lib/types.ts';

const VAULT = 'vault.owner.testnet';
const AGENT = 'agent.owner.testnet';
const HASH = '9xQ7nVb3mE1sK5tR2pW8yZ4cD6fG1hJ3kL5mN7pQ9rS2';
const TOKEN = 'test-token-0123456789abcdefghijkl';

let written = 3;
const activity = (): LogEntry[] =>
  Array.from({ length: written }, (_, i) => ({
    seq: String(written - 1 - i),
    at_ms: String(1_700_000_000_000 + i),
    block_height: String(100 + i),
    kind: i === 0 && written > 3 ? 'tripped' : 'paid',
    agent_id: AGENT,
    receiver_id: '<img src=x onerror=alert(1)>',
    amount: '1000000000000000000000000',
    by: AGENT,
  }));

const config = (): ConfigView => ({
  version: '1.0.0',
  owner_id: 'owner.testnet',
  pending_owner: null,
  guardians: ['guardian.owner.testnet'],
  paused: false,
  pause_reason: null,
  agents: 1,
  canaries: 3,
  blocklist: 0,
  open_reports: 0,
  pending: 0,
  reserved: '0',
  balance: '5000000000000000000000000',
  storage_locked: '3000000000000000000000000',
  available: '2000000000000000000000000',
  activity_written: String(written),
  ring_capacity: 256,
});

const stats: Stats = {
  requests: 3, paid: 3, paid_total: '3000000000000000000000000', blocked: 0, escalated: 0, tripped: 0, approved: 0,
  rejected: 0, expired: 0, failed: 0, freezes: 0, blocked_while_frozen: 0, blocked_while_paused: 0, reports: 0, canaries_added: 3,
};

const agent = { agent_id: AGENT, label: 'demo', status: { state: 'active' }, spent_24h: '0', policy: { daily_limit: '1' } } as unknown as AgentView;

const agentKeys: KeyJson[] = [
  { publicKey: 'ed25519:abc', nonce: '1', fullAccess: false, receiverId: VAULT, methodNames: ['request_payment', 'self_freeze', 'report_receiver'], allowance: '1000000000000000000000000' },
];

let viewCalls = 0;
const fakeViews: Views = {
  getConfig: async () => (viewCalls++, config()),
  getStats: async () => stats,
  listAllAgents: async () => [agent],
  getAllPending: async () => [],
  getActivity: async (before, limit = 50) => activity().filter((e) => before === undefined || BigInt(e.seq) < BigInt(before)).slice(0, limit),
  getBlocklist: async () => [],
  listKeys: async () => agentKeys,
};

const calls: { name: string; args: unknown[] }[] = [];
const ok = (name: string) => async (...args: unknown[]): Promise<ActionOutcome> => {
  calls.push({ name, args });
  return { ok: true, hash: HASH, error: null, result: true };
};
const ownerSigners: Signers = {
  role: 'owner',
  accountId: 'owner.testnet',
  allowed: ACTION_NAMES,
  approve: ok('approve'),
  reject: ok('reject'),
  freeze: ok('freeze'),
  unfreeze: ok('unfreeze'),
  pause: ok('pause'),
  unpause: ok('unpause'),
};
const backend = (signers: Signers | null): Backend => ({ vaultId: VAULT, network: 'testnet', proofAccounts: [AGENT], views: fakeViews, signers });

interface Res {
  status: number;
  headers: Record<string, string | string[] | undefined>;
  body: string;
}
function raw(port: number, method: string, path: string, headers: Record<string, string> = {}, body?: string): Promise<Res> {
  return new Promise((resolve, reject) => {
    const req = request({ host: '127.0.0.1', port, method, path, headers }, (res) => {
      const chunks: Buffer[] = [];
      res.on('data', (c: Buffer) => chunks.push(c));
      res.on('end', () => resolve({ status: res.statusCode ?? 0, headers: res.headers, body: Buffer.concat(chunks).toString('utf8') }));
    });
    req.on('error', reject);
    if (body !== undefined) req.write(body);
    req.end();
  });
}
const portOf = (d: Dashboard) => Number(new URL(d.url).port);
const postJson = (port: number, path: string, body: unknown, headers: Record<string, string> = {}) =>
  raw(port, 'POST', path, { 'content-type': 'application/json', ...headers }, JSON.stringify(body));

let tmp: string;
let runsDir: string;
let webRoot: string;

before(() => {
  tmp = mkdtempSync(join(tmpdir(), 'spendfuse-server-'));
  runsDir = join(tmp, 'runs');
  webRoot = join(tmp, 'web');
  mkdirSync(runsDir);
  mkdirSync(webRoot);
  writeFileSync(join(webRoot, 'index.html'), '<!doctype html><title>t</title>');
  writeFileSync(join(webRoot, 'app.js'), 'console.log(1)');
  writeFileSync(join(webRoot, 'style.css'), 'body{}');
  writeFileSync(join(tmp, 'secret.txt'), 'TOP SECRET');
  writeFileSync(join(runsDir, 'run-1.json'), JSON.stringify({ title: 'Simulated refund redirect', mode: 'scripted', steps: [{ kind: 'blocked' }, { kind: 'tripped' }] }));
  writeFileSync(join(runsDir, 'broken.json'), '{nope');
});
after(() => rmSync(tmp, { recursive: true, force: true }));

describe('helpers', () => {
  test('isRequestId', () => {
    for (const v of ['0', '1', '18446744073709551615']) assert.equal(isRequestId(v), true, v);
    for (const v of ['', '01', '-1', '1.5', '18446744073709551616', 'abc', 1, null]) assert.equal(isRequestId(v), false, String(v));
  });
  test('checkReason', () => {
    assert.equal(checkReason(undefined), undefined);
    assert.equal(checkReason('ok'), 'ok');
    assert.ok(checkReason('a\nb') instanceof Error);
    assert.ok(checkReason('x'.repeat(257)) instanceof Error);
    assert.ok(checkReason(5) instanceof Error);
  });
  test('keyProof flags full-access and off-vault keys', () => {
    assert.equal(keyProof(AGENT, VAULT, agentKeys).fcOnly, true);
    const full = keyProof(AGENT, VAULT, [...agentKeys, { publicKey: 'ed25519:x', nonce: '1', fullAccess: true }]);
    assert.equal(full.fcOnly, false);
    assert.equal(full.fullAccess, 1);
    assert.equal(keyProof(AGENT, VAULT, [{ ...agentKeys[0]!, receiverId: 'evil.testnet' }]).fcOnly, false);
    assert.equal(keyProof(AGENT, VAULT, [{ ...agentKeys[0]!, methodNames: [] }]).fcOnly, false);
  });
});

describe('local mode with owner signer', () => {
  let d: Dashboard;
  let port: number;
  before(async () => {
    d = await createDashboard({ backend: backend(ownerSigners), port: 0, token: TOKEN, webRoot, runsDir, pollMs: 40, cacheMs: 0, log: () => {} });
    port = portOf(d);
  });
  after(() => d.close());

  test('binds to loopback and enables actions', () => {
    assert.match(d.url, /^http:\/\/127\.0\.0\.1:\d+$/);
    assert.equal(d.actionsEnabled, true);
  });

  test('random token by default', async () => {
    const d2 = await createDashboard({ backend: backend(ownerSigners), port: 0, webRoot, runsDir, log: () => {} });
    try {
      assert.match(d2.token, /^[A-Za-z0-9_-]{32}$/);
      assert.notEqual(d2.token, TOKEN);
    } finally {
      await d2.close();
    }
  });

  test('serves static files with content types and CSP', async () => {
    const index = await raw(port, 'GET', '/');
    assert.equal(index.status, 200);
    assert.equal(index.headers['content-type'], 'text/html; charset=utf-8');
    assert.equal(index.headers['content-security-policy'], CSP);
    assert.match(CSP, /default-src 'self'/);
    assert.match(CSP, /script-src 'self'(;|$)/);
    assert.doesNotMatch(CSP, /unsafe-inline|unsafe-eval/);
    assert.equal(index.headers['x-content-type-options'], 'nosniff');
    assert.equal(index.headers['referrer-policy'], 'no-referrer');
    assert.equal((await raw(port, 'GET', '/app.js')).headers['content-type'], 'text/javascript; charset=utf-8');
    assert.equal((await raw(port, 'GET', '/style.css')).headers['content-type'], 'text/css; charset=utf-8');
    assert.equal((await raw(port, 'GET', '/nope.js')).status, 404);
    assert.equal((await raw(port, 'GET', '/api/state')).headers['content-security-policy'], CSP);
  });

  test('blocks path traversal', async () => {
    for (const p of ['/../secret.txt', '/%2e%2e/secret.txt', '/..%2fsecret.txt', '/%2e%2e%2fsecret.txt', '/..%5csecret.txt', '/%00index.html', '/.env', '/%2fetc%2fpasswd']) {
      const r = await raw(port, 'GET', p);
      assert.ok(r.status >= 400 && r.status < 500, `${p} -> ${r.status}`);
      assert.doesNotMatch(r.body, /TOP SECRET|root:/, p);
    }
    const run = await raw(port, 'GET', '/api/runs/..%2f..%2fsecret');
    assert.equal(run.status, 400);
  });

  test('rejects foreign Host headers (DNS rebinding)', async () => {
    const r = await raw(port, 'GET', '/api/state', { host: 'evil.example:80' });
    assert.equal(r.status, 421);
  });

  test('/api/state shape', async () => {
    const r = await raw(port, 'GET', '/api/state');
    assert.equal(r.status, 200);
    assert.equal(r.headers['content-type'], 'application/json; charset=utf-8');
    const s = JSON.parse(r.body);
    assert.equal(s.vaultId, VAULT);
    assert.equal(s.network, 'testnet');
    assert.deepEqual(s.mode, { readonly: false, actions: true, role: 'owner', signer: 'owner.testnet', allowed: [...ACTION_NAMES] });
    assert.equal(s.config.version, '1.0.0');
    assert.equal(s.stats.paid, 3);
    assert.equal(s.agents.length, 1);
    assert.deepEqual(s.pending, []);
    assert.equal(s.activity.length, written);
    assert.deepEqual(s.blocklist, []);
    assert.equal(s.keys.length, 1);
    assert.equal(s.keys[0].accountId, AGENT);
    assert.equal(s.keys[0].fcOnly, true);
    assert.equal(s.keys[0].fullAccess, 0);
    assert.deepEqual(s.errors, {});
    assert.equal(typeof s.fetchedAt, 'number');
    assert.ok(!r.body.includes(TOKEN), 'token must not be in state');
  });

  test('/api/activity validates before and limit', async () => {
    const r = await raw(port, 'GET', '/api/activity?before=2&limit=5');
    assert.equal(r.status, 200);
    assert.deepEqual(JSON.parse(r.body).activity.map((e: LogEntry) => e.seq), ['1', '0']);
    assert.equal((await raw(port, 'GET', '/api/activity?before=abc')).status, 400);
    assert.equal((await raw(port, 'GET', '/api/activity?before=01')).status, 400);
    assert.equal((await raw(port, 'GET', '/api/activity?limit=1000')).status, 400);
  });

  test('/api/runs lists and returns run logs', async () => {
    const list = JSON.parse((await raw(port, 'GET', '/api/runs')).body).runs;
    const run1 = list.find((r: { id: string }) => r.id === 'run-1');
    assert.equal(run1.title, 'Simulated refund redirect');
    assert.equal(run1.count, 2);
    assert.equal(list.find((r: { id: string }) => r.id === 'broken').invalid, true);
    const one = await raw(port, 'GET', '/api/runs/run-1');
    assert.equal(one.status, 200);
    assert.equal(JSON.parse(one.body).run.steps.length, 2);
    assert.equal((await raw(port, 'GET', '/api/runs/missing')).status, 404);
    assert.equal((await raw(port, 'GET', '/api/runs/broken')).status, 422);
    assert.equal((await raw(port, 'GET', '/api/runs/.hidden')).status, 400);
  });

  test('unknown routes and methods', async () => {
    assert.equal((await raw(port, 'GET', '/api/nope')).status, 404);
    assert.equal((await raw(port, 'DELETE', '/api/state')).status, 405);
    assert.equal((await postJson(port, '/api/withdraw', {}, { 'x-spendfuse-token': TOKEN })).status, 404);
  });

  test('POST without or with a wrong token is 403', async () => {
    const before = calls.length;
    for (const name of ACTION_NAMES) {
      assert.equal((await postJson(port, `/api/${name}`, { request_id: '1' })).status, 403, name);
      assert.equal((await postJson(port, `/api/${name}`, { request_id: '1' }, { 'x-spendfuse-token': 'wrong' })).status, 403, name);
      assert.equal((await postJson(port, `/api/${name}`, { request_id: '1' }, { 'x-spendfuse-token': TOKEN.slice(0, -1) + 'X' })).status, 403, name);
    }
    assert.equal(calls.length, before);
  });

  test('POST refuses cross-origin and non-JSON', async () => {
    const t = { 'x-spendfuse-token': TOKEN };
    assert.equal((await postJson(port, '/api/pause', {}, { ...t, origin: 'http://evil.example' })).status, 403);
    assert.equal((await raw(port, 'POST', '/api/pause', { ...t, 'content-type': 'text/plain' }, '{}')).status, 415);
  });

  test('input validation rejects bad ids', async () => {
    const t = { 'x-spendfuse-token': TOKEN };
    const before = calls.length;
    for (const body of [{}, { request_id: 5 }, { request_id: '-1' }, { request_id: '1e3' }, { request_id: '007' }, { request_id: '99999999999999999999999' }]) {
      assert.equal((await postJson(port, '/api/approve', body, t)).status, 400, JSON.stringify(body));
    }
    for (const id of ['', 'A.testnet', 'a', 'bad..id', '<script>', 'x'.repeat(65), 'evil.testnet/../x']) {
      assert.equal((await postJson(port, '/api/freeze', { agent_id: id }, t)).status, 400, id);
      assert.equal((await postJson(port, '/api/unfreeze', { agent_id: id }, t)).status, 400, id);
    }
    assert.equal((await postJson(port, '/api/reject', { request_id: '1', reason: 'a\u0000b' }, t)).status, 400);
    assert.equal((await postJson(port, '/api/pause', { reason: 'x'.repeat(300) }, t)).status, 400);
    assert.equal((await postJson(port, '/api/unpause', { extra: 1 }, t)).status, 400);
    assert.equal((await postJson(port, '/api/approve', [1], t)).status, 400);
    assert.equal((await raw(port, 'POST', '/api/approve', { ...t, 'content-type': 'application/json' }, '{bad')).status, 400);
    assert.equal(calls.length, before, 'no signer call for invalid input');
  });

  test('caps body size', async () => {
    const r = await raw(port, 'POST', '/api/pause', { 'x-spendfuse-token': TOKEN, 'content-type': 'application/json' }, JSON.stringify({ reason: 'x'.repeat(10_000) }));
    assert.equal(r.status, 413);
  });

  test('valid actions reach the signer and return an explorer link', async () => {
    const t = { 'x-spendfuse-token': TOKEN };
    const r = await postJson(port, '/api/approve', { request_id: '7' }, t);
    assert.equal(r.status, 200);
    const body = JSON.parse(r.body);
    assert.equal(body.ok, true);
    assert.equal(body.url, `https://testnet.nearblocks.io/txns/${HASH}`);
    assert.deepEqual(calls.at(-1), { name: 'approve', args: ['7'] });
    await postJson(port, '/api/freeze', { agent_id: AGENT, reason: 'manual' }, t);
    assert.deepEqual(calls.at(-1), { name: 'freeze', args: [AGENT, 'manual'] });
    await postJson(port, '/api/reject', { request_id: '3' }, t);
    assert.deepEqual(calls.at(-1), { name: 'reject', args: ['3', undefined] });
    await postJson(port, '/api/unpause', {}, t);
    assert.equal(calls.at(-1)?.name, 'unpause');
  });

  test('SSE pushes status and only new activity', async () => {
    written = 3;
    const ctrl = new AbortController();
    const res = await fetch(`${d.url}/api/events`, { signal: ctrl.signal });
    assert.equal(res.headers.get('content-type'), 'text/event-stream; charset=utf-8');
    const reader = res.body!.getReader();
    const dec = new TextDecoder();
    let buf = '';
    const until = async (re: RegExp) => {
      const deadline = Date.now() + 3000;
      while (!re.test(buf)) {
        if (Date.now() > deadline) throw new Error(`timeout waiting for ${re}; got ${buf}`);
        const { value, done } = await reader.read();
        if (done) break;
        buf += dec.decode(value);
      }
    };
    await until(/event: status\ndata: .*"paused":false/);
    await new Promise((r) => setTimeout(r, 120)); // baseline poll
    written = 5;
    await until(/event: activity\ndata: (.*)\n\n/);
    const m = buf.match(/event: activity\ndata: (.*)\n\n/)!;
    const news = JSON.parse(m[1]!) as LogEntry[];
    assert.deepEqual(news.map((e) => e.seq), ['3', '4']);
    ctrl.abort();
    written = 3;
  });
});

describe('restricted modes', () => {
  test('READONLY disables every POST route even with a token and signer', async () => {
    const d = await createDashboard({ backend: backend(ownerSigners), port: 0, token: TOKEN, readonly: true, webRoot, runsDir, log: () => {} });
    try {
      assert.equal(d.actionsEnabled, false);
      const before = calls.length;
      for (const name of ACTION_NAMES) {
        const r = await postJson(portOf(d), `/api/${name}`, { request_id: '1' }, { 'x-spendfuse-token': TOKEN });
        assert.equal(r.status, 403, name);
        assert.match(JSON.parse(r.body).error, /read-only/);
      }
      assert.equal(calls.length, before);
      const s = JSON.parse((await raw(portOf(d), 'GET', '/api/state')).body);
      assert.equal(s.mode.readonly, true);
      assert.equal(s.mode.actions, false);
      assert.equal(s.mode.signer, null);
      assert.equal((await raw(portOf(d), 'GET', '/')).status, 200);
    } finally {
      await d.close();
    }
  });

  test('READONLY on loopback still rejects foreign Host headers (DNS rebinding)', async () => {
    const d = await createDashboard({ backend: backend(null), port: 0, readonly: true, webRoot, runsDir, log: () => {} });
    try {
      for (const p of ['/api/state', '/api/runs', '/']) {
        assert.equal((await raw(portOf(d), 'GET', p, { host: 'evil.example:80' })).status, 421, p);
        assert.equal((await raw(portOf(d), 'GET', p, { host: `localhost:${portOf(d)}` })).status, 200, p);
      }
    } finally {
      await d.close();
    }
  });

  test('no signer: actions disabled', async () => {
    const d = await createDashboard({ backend: backend(null), port: 0, token: TOKEN, webRoot, runsDir, log: () => {} });
    try {
      assert.equal(d.actionsEnabled, false);
      assert.equal((await postJson(portOf(d), '/api/pause', {}, { 'x-spendfuse-token': TOKEN })).status, 403);
    } finally {
      await d.close();
    }
  });

  test('guardian signer cannot approve or unfreeze', async () => {
    const g: Signers = { ...ownerSigners, role: 'guardian', accountId: 'guardian.owner.testnet', allowed: GUARDIAN_ACTIONS };
    const d = await createDashboard({ backend: backend(g), port: 0, token: TOKEN, webRoot, runsDir, log: () => {} });
    try {
      const t = { 'x-spendfuse-token': TOKEN };
      assert.equal((await postJson(portOf(d), '/api/approve', { request_id: '1' }, t)).status, 403);
      assert.equal((await postJson(portOf(d), '/api/unfreeze', { agent_id: AGENT }, t)).status, 403);
      assert.equal((await postJson(portOf(d), '/api/unpause', {}, t)).status, 403);
      assert.equal((await postJson(portOf(d), '/api/pause', {}, t)).status, 200);
    } finally {
      await d.close();
    }
  });

  test('view errors are reported per section, not as a 500', async () => {
    const failing: Views = { ...fakeViews, getConfig: async () => { throw new Error('account vault.owner.testnet does not exist'); } };
    const d = await createDashboard({ backend: { ...backend(null), views: failing }, port: 0, webRoot, runsDir, log: () => {} });
    try {
      const r = await raw(portOf(d), 'GET', '/api/state');
      assert.equal(r.status, 200);
      const s = JSON.parse(r.body);
      assert.equal(s.config, null);
      assert.match(s.errors.config, /does not exist/);
      assert.equal(s.stats.paid, 3);
    } finally {
      await d.close();
    }
  });

  test('views are cached', async () => {
    const d = await createDashboard({ backend: backend(null), port: 0, webRoot, runsDir, cacheMs: 5000, log: () => {} });
    try {
      const n = viewCalls;
      await raw(portOf(d), 'GET', '/api/state');
      await raw(portOf(d), 'GET', '/api/state');
      await raw(portOf(d), 'GET', '/api/state');
      assert.equal(viewCalls - n, 1);
    } finally {
      await d.close();
    }
  });
});
