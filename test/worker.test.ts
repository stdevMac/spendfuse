// Offline tests for the hosted read-only Worker: the fetch handler gets fake views and fake assets.
import { test, describe, after } from 'node:test';
import assert from 'node:assert/strict';
import { createHandler } from '../src/worker/handler.ts';
import type { Handler } from '../src/worker/handler.ts';
import { RECORDED } from '../src/worker/runs.ts';
import { handlerFor } from '../src/worker/index.ts';
import { createDashboard } from '../src/server/app.ts';
import { CSP, TtlCache, cachedViews } from '../src/server/core.ts';
import type { KeyJson, Views } from '../src/server/backend.ts';
import type { AgentView, ConfigView, LogEntry, Stats } from '../src/lib/types.ts';

const VAULT = 'vault.owner.testnet';
const AGENT = 'agent.owner.testnet';
let written = 3;
const activity = (): LogEntry[] =>
  Array.from({ length: written }, (_, i) => ({
    seq: String(written - 1 - i),
    at_ms: String(1_700_000_000_000 + i),
    block_height: String(100 + i),
    kind: 'paid',
    agent_id: AGENT,
    receiver_id: 'shop.testnet',
    amount: '1',
    by: AGENT,
  }));
const config = (): ConfigView =>
  ({ version: '1.0.0', owner_id: 'owner.testnet', paused: false, pause_reason: null, pending: 0, activity_written: String(written) }) as unknown as ConfigView;
const stats = { requests: 3, paid: 3 } as unknown as Stats;
const agentKeys: KeyJson[] = [{ publicKey: 'ed25519:abc', nonce: '1', fullAccess: false, receiverId: VAULT, methodNames: ['request_payment'], allowance: null }];
let rpcCalls = 0;
const views: Views = {
  getConfig: async () => (rpcCalls++, config()),
  getStats: async () => stats,
  listAllAgents: async () => [{ agent_id: AGENT } as unknown as AgentView],
  getAllPending: async () => [],
  getActivity: async (before, limit = 50) => activity().filter((e) => before === undefined || BigInt(e.seq) < BigInt(before)).slice(0, limit),
  getBlocklist: async () => [],
  listKeys: async () => agentKeys,
};
const assets = { fetch: async (r: Request) => new Response(new URL(r.url).pathname === '/' ? '<!doctype html>' : 'nope', { status: new URL(r.url).pathname === '/' ? 200 : 404, headers: { 'content-type': 'text/html' } }) };
const runs = [{ id: 'run-1', run: { startedAt: '2026-11-09T04:59:38.380Z', finishedAt: '2026-11-09T05:00:59.366Z', mode: 'live', steps: [1, 2] } }];

const h: Handler = createHandler({ views, vaultId: VAULT, network: 'testnet', proofAccounts: [AGENT], runs, assets, cacheMs: 5000, pollMs: 10, streamMs: 60, log: () => {} });
const req = (path: string, init?: RequestInit) => h(new Request(`https://spendfuse.example${path}`, init));

describe('worker handler', () => {
  test('GET /api/state is read-only state with security headers', async () => {
    const r = await req('/api/state');
    assert.equal(r.status, 200);
    assert.equal(r.headers.get('content-security-policy'), CSP);
    assert.equal(r.headers.get('x-content-type-options'), 'nosniff');
    assert.equal(r.headers.get('referrer-policy'), 'no-referrer');
    const s = (await r.json()) as Record<string, any>;
    assert.deepEqual(s.mode, { readonly: true, actions: false, role: null, signer: null, allowed: [] });
    assert.equal(s.vaultId, VAULT);
    assert.equal(s.keys[0].fcOnly, true);
    assert.deepEqual(s.errors, {});
  });

  test('views are cached across requests', async () => {
    const before = rpcCalls;
    await req('/api/state');
    await req('/api/state');
    assert.ok(rpcCalls - before <= 1);
  });

  test('state matches the Node server in READONLY mode', async () => {
    const d = await createDashboard({ backend: { vaultId: VAULT, network: 'testnet', proofAccounts: [AGENT], views, signers: null }, port: 0, readonly: true, log: () => {} });
    try {
      const node = (await (await fetch(`${d.url}/api/state`)).json()) as Record<string, unknown>;
      const worker = (await (await req('/api/state')).json()) as Record<string, unknown>;
      delete node.fetchedAt;
      delete worker.fetchedAt;
      assert.deepEqual(worker, node);
    } finally {
      await d.close();
    }
  });

  test('/api/activity validates and pages', async () => {
    const r = (await (await req('/api/activity?before=2&limit=1')).json()) as { activity: LogEntry[] };
    assert.deepEqual(r.activity.map((e) => e.seq), ['1']);
    assert.equal((await req('/api/activity?limit=500')).status, 400);
    assert.equal((await req('/api/activity?before=01')).status, 400);
  });

  test('HEAD /api/events returns headers only, without opening the stream', async () => {
    const slow = createHandler({ views, vaultId: VAULT, network: 'testnet', proofAccounts: [AGENT], runs, pollMs: 10, streamMs: 60_000, log: () => {} });
    const r = await slow(new Request('https://spendfuse.example/api/events', { method: 'HEAD' }));
    assert.equal(r.status, 200);
    assert.match(r.headers.get('content-type') ?? '', /text\/event-stream/);
    assert.equal(r.headers.get('content-security-policy'), CSP);
    assert.equal(await r.text(), '');
  });

  test('view cache is bounded and sweeps expired keys', async () => {
    const cache = new TtlCache(60_000, 8);
    for (let i = 0; i < 100; i++) await cache.get(`k${i}`, async () => i);
    assert.equal(cache.size, 8);
    assert.equal(await cache.get('k99', async () => -1), 99, 'newest entries are kept');
    const expired = new TtlCache(0, 4);
    for (let i = 0; i < 10; i++) await expired.get(`k${i}`, async () => i);
    assert.ok(expired.size <= 4);
  });

  test('activity pages past activity_written share the newest-page cache entry', async () => {
    let calls = 0;
    const counted: Views = { ...views, getActivity: async (b, l) => (calls++, views.getActivity(b, l)) };
    const c = cachedViews(counted, new TtlCache(60_000));
    const newest = await c.activity(undefined, 2);
    for (const before of ['3', '4', '999', '123456789012345']) assert.deepEqual(await c.activity(before, 2), newest);
    assert.equal(calls, 1);
    await c.activity('2', 2);
    assert.equal(calls, 2);
  });

  test('runs come from the bundled list', async () => {
    const list = (await (await req('/api/runs')).json()) as { runs: Record<string, unknown>[] };
    assert.equal(list.runs.length, 1);
    assert.equal(list.runs[0]!.id, 'run-1');
    assert.equal(list.runs[0]!.count, 2);
    assert.equal(list.runs[0]!.mtimeMs, Date.parse('2026-11-09T05:00:59.366Z'));
    const one = (await (await req('/api/runs/run-1')).json()) as { id: string; run: unknown };
    assert.equal(one.id, 'run-1');
    assert.deepEqual(one.run, runs[0]!.run);
    assert.equal((await req('/api/runs/nope')).status, 404);
    assert.equal((await req('/api/runs/..%2Fsecret')).status, 400);
    assert.equal((await req('/api/runs/%E0%A4%A')).status, 400);
  });

  test('every write method is refused', async () => {
    for (const method of ['POST', 'PUT', 'PATCH', 'DELETE']) {
      const r = await req('/api/pause', { method, body: '{}', headers: { 'content-type': 'application/json' } });
      assert.equal(r.status, 403, method);
      assert.match(((await r.json()) as { error: string }).error, /read-only/);
    }
    assert.equal((await req('/', { method: 'POST', body: 'x' })).status, 405);
    assert.equal((await req('/api/state', { method: 'OPTIONS' })).status, 405);
    assert.equal((await req('/api/nope')).status, 404);
  });

  test('static files go through ASSETS with security headers', async () => {
    const r = await req('/');
    assert.equal(r.status, 200);
    assert.equal(await r.text(), '<!doctype html>');
    assert.equal(r.headers.get('content-security-policy'), CSP);
    assert.equal(r.headers.get('x-frame-options'), 'DENY');
    assert.equal((await req('/missing.js')).status, 404);
  });

  test('/api/events streams status, then new activity, then ends', async () => {
    const live = createHandler({ views, vaultId: VAULT, network: 'testnet', proofAccounts: [AGENT], runs, cacheMs: 0, pollMs: 10, streamMs: 80, log: () => {} });
    const r = await live(new Request('https://spendfuse.example/api/events'));
    assert.equal(r.status, 200);
    assert.match(r.headers.get('content-type') ?? '', /text\/event-stream/);
    setTimeout(() => (written = 5), 15);
    const text = await r.text(); // the stream closes by itself after streamMs
    assert.match(text, /^retry: 1000\n\n/);
    assert.match(text, /event: status\ndata: \{"paused":false/);
    assert.match(text, /event: activity\ndata: \[\{"seq":"3"/);
  });

  test('bundled proof runs are listed with canary ids redacted', () => {
    assert.ok(RECORDED.length >= 1);
    for (const { id, run } of RECORDED) {
      assert.match(id, /^live-run-/);
      const r = run as { dryRun?: boolean; ids?: { canary?: string } };
      assert.equal(r.dryRun, false);
      assert.ok((r.ids?.canary ?? '').length <= 12, 'canary id is redacted to a short prefix');
    }
  });

  test('entry rejects a misconfigured network', () => {
    assert.throws(() => handlerFor({ ASSETS: assets, NETWORK: 'mainnet', OWNER_ID: 'x.near' }), /testnet only/);
    assert.throws(() => handlerFor({ ASSETS: assets, VAULT_ID: 'BAD ID' }), /VAULT_ID/);
  });
});

after(() => {
  written = 3;
});
