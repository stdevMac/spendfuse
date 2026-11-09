// app.ts - zero-dependency dashboard server: static web/ files, read-only JSON API, SSE feed and
// token-gated owner/guardian actions. createDashboard() takes an injected Backend so tests run offline.
// Route logic shared with the Cloudflare Worker (src/worker/index.ts) lives in core.ts.
import { randomBytes, timingSafeEqual } from 'node:crypto';
import { createServer } from 'node:http';
import type { IncomingMessage, Server, ServerResponse } from 'node:http';
import { readdir, readFile, stat } from 'node:fs/promises';
import { extname, join, resolve, sep } from 'node:path';
import { REPO_ROOT } from '../lib/env.ts';
import { explorer } from '../lib/near.ts';
import type { ActionName, ActionOutcome, Backend } from './backend.ts';
import { ACTION_NAMES } from './backend.ts';
import {
  buildState,
  cachedViews,
  checkReason,
  errMsg,
  Feed,
  HttpError,
  isAccountId,
  isRequestId,
  isRunId,
  isTxHash,
  jsonReplacer,
  parseActivityQuery,
  READONLY_MESSAGE,
  RUN_ID_RE,
  runSummary,
  SECURITY_HEADERS,
  sortRuns,
  sseFrame,
  TtlCache,
} from './core.ts';

export { CSP, checkReason, isAccountId, isRequestId, isTxHash, keyProof, TtlCache } from './core.ts';
export type { KeyProof } from './core.ts';

export const DEFAULT_PORT = 8787;
export const DEFAULT_HOST = '127.0.0.1';
export const WEB_ROOT = join(REPO_ROOT, 'web');
export const RUNS_DIR = join(REPO_ROOT, '.spendfuse', 'runs');

const CONTENT_TYPES: Record<string, string> = {
  '.html': 'text/html; charset=utf-8',
  '.js': 'text/javascript; charset=utf-8',
  '.css': 'text/css; charset=utf-8',
  '.json': 'application/json; charset=utf-8',
  '.svg': 'image/svg+xml',
  '.png': 'image/png',
  '.ico': 'image/x-icon',
  '.txt': 'text/plain; charset=utf-8',
  '.woff2': 'font/woff2',
};

export const MAX_BODY = 4096;
const MAX_RUN_BYTES = 2 * 1024 * 1024;
const LOOPBACK_HOSTS = new Set(['127.0.0.1', '::1', 'localhost']);
const LOOPBACK_HOST_HEADERS = new Set(['127.0.0.1', 'localhost', '[::1]']);

// ---------------------------------------------------------------- small helpers
function sendJson(res: ServerResponse, status: number, body: unknown): void {
  const text = JSON.stringify(body, jsonReplacer);
  res.writeHead(status, { ...SECURITY_HEADERS, 'content-type': 'application/json; charset=utf-8', 'cache-control': 'no-store' });
  res.end(text);
}


function readBody(req: IncomingMessage, max: number): Promise<string> {
  return new Promise((ok, fail) => {
    const declared = Number(req.headers['content-length'] ?? 0);
    if (declared > max) {
      fail(new HttpError(413, `body larger than ${max} bytes`));
      req.resume();
      return;
    }
    const chunks: Buffer[] = [];
    let size = 0;
    let done = false;
    req.on('data', (c: Buffer) => {
      if (done) return;
      size += c.length;
      if (size > max) {
        done = true;
        fail(new HttpError(413, `body larger than ${max} bytes`));
        req.resume();
        return;
      }
      chunks.push(c);
    });
    req.on('end', () => {
      if (!done) ok(Buffer.concat(chunks).toString('utf8'));
    });
    req.on('error', (e) => {
      if (!done) fail(e);
    });
  });
}


// ---------------------------------------------------------------- options
export interface DashboardOptions {
  backend: Backend;
  host?: string;
  port?: number;
  /** disables every POST route */
  readonly?: boolean;
  /** fixed token (tests); default random per process */
  token?: string;
  webRoot?: string;
  runsDir?: string;
  cacheMs?: number;
  pollMs?: number;
  heartbeatMs?: number;
  log?: (msg: string) => void;
}

export interface Dashboard {
  server: Server;
  token: string;
  actionsEnabled: boolean;
  url: string;
  close(): Promise<void>;
}

// ---------------------------------------------------------------- server
export function createDashboard(opts: DashboardOptions): Promise<Dashboard> {
  const { backend } = opts;
  const views = backend.views;
  const host = opts.host ?? DEFAULT_HOST;
  const readonly = !!opts.readonly;
  const local = LOOPBACK_HOSTS.has(host);
  const signers = readonly || !local ? null : backend.signers;
  const actionsEnabled = signers !== null;
  const token = opts.token ?? randomBytes(24).toString('base64url');
  const tokenBuf = Buffer.from(token);
  const webRoot = resolve(opts.webRoot ?? WEB_ROOT);
  const runsDir = resolve(opts.runsDir ?? RUNS_DIR);
  const cache = new TtlCache(opts.cacheMs ?? 2000);
  const pollMs = opts.pollMs ?? 3000;
  const heartbeatMs = opts.heartbeatMs ?? 15000;
  const log = opts.log ?? ((m: string) => console.log(m));

  const c = cachedViews(views, cache);

  // ------------------------------------------------ /api/state
  const state = () =>
    buildState({
      c,
      vaultId: backend.vaultId,
      network: backend.network,
      proofAccounts: backend.proofAccounts,
      mode: {
        readonly,
        actions: actionsEnabled,
        role: signers?.role ?? null,
        signer: signers?.accountId ?? null,
        allowed: signers ? [...signers.allowed] : [],
      },
    });

  // ------------------------------------------------ runs
  async function listRuns(): Promise<unknown[]> {
    let names: string[];
    try {
      names = await readdir(runsDir);
    } catch {
      return [];
    }
    const files = names.filter((n) => n.endsWith('.json') && RUN_ID_RE.test(n.slice(0, -5)));
    const rows = await Promise.all(
      files.map(async (n) => {
        const id = n.slice(0, -5);
        try {
          const st = await stat(join(runsDir, n));
          if (!st.isFile()) return null;
          let parsed: unknown;
          if (st.size <= MAX_RUN_BYTES) {
            try {
              parsed = JSON.parse(await readFile(join(runsDir, n), 'utf8'));
            } catch {
              parsed = null;
            }
          }
          return runSummary(id, st.size, st.mtimeMs, parsed);
        } catch {
          return null;
        }
      }),
    );
    return sortRuns(rows.filter((r): r is Record<string, unknown> => r !== null));
  }

  async function getRun(id: string): Promise<unknown> {
    if (!isRunId(id)) throw new HttpError(400, 'bad run id');
    const file = resolve(runsDir, `${id}.json`);
    if (!file.startsWith(runsDir + sep)) throw new HttpError(400, 'bad run id');
    let st;
    try {
      st = await stat(file);
    } catch {
      throw new HttpError(404, 'run not found');
    }
    if (!st.isFile()) throw new HttpError(404, 'run not found');
    if (st.size > MAX_RUN_BYTES) throw new HttpError(413, 'run file too large');
    try {
      const text = await readFile(file, 'utf8');
      return JSON.parse(backend.redactRun ? backend.redactRun(text) : text);
    } catch {
      throw new HttpError(422, 'run file is not valid JSON');
    }
  }

  // ------------------------------------------------ SSE
  const clients = new Set<ServerResponse>();
  const feed = new Feed(c);
  let pollTimer: NodeJS.Timeout | null = null;
  let beatTimer: NodeJS.Timeout | null = null;
  let busy = false;

  async function tick(): Promise<void> {
    if (busy || clients.size === 0) return;
    busy = true;
    try {
      for (const e of await feed.poll()) {
        const frame = sseFrame(e);
        for (const r of clients) r.write(frame);
      }
    } finally {
      busy = false;
    }
  }

  function startPoller(): void {
    if (pollTimer) return;
    pollTimer = setInterval(() => void tick(), pollMs);
    beatTimer = setInterval(() => {
      for (const r of clients) r.write(': ping\n\n');
    }, heartbeatMs);
    pollTimer.unref();
    beatTimer.unref();
    void tick();
  }
  function stopPoller(): void {
    if (pollTimer) clearInterval(pollTimer);
    if (beatTimer) clearInterval(beatTimer);
    pollTimer = beatTimer = null;
    feed.reset();
  }

  function openStream(req: IncomingMessage, res: ServerResponse): void {
    res.writeHead(200, {
      ...SECURITY_HEADERS,
      'content-type': 'text/event-stream; charset=utf-8',
      'cache-control': 'no-store',
      connection: 'keep-alive',
      'x-accel-buffering': 'no',
    });
    res.write(`retry: ${Math.max(pollMs, 1000)}\n\n`);
    if (feed.lastStatus) res.write(`event: status\ndata: ${feed.lastStatus}\n\n`);
    clients.add(res);
    const drop = () => {
      clients.delete(res);
      if (clients.size === 0) stopPoller();
    };
    req.on('close', drop);
    res.on('close', drop);
    startPoller();
  }

  // ------------------------------------------------ actions
  function checkToken(req: IncomingMessage): boolean {
    const h = req.headers['x-spendfuse-token'];
    if (typeof h !== 'string') return false;
    const b = Buffer.from(h);
    return b.length === tokenBuf.length && timingSafeEqual(b, tokenBuf);
  }

  const ALLOWED_KEYS: Record<ActionName, readonly string[]> = {
    approve: ['request_id'],
    reject: ['request_id', 'reason'],
    freeze: ['agent_id', 'reason'],
    unfreeze: ['agent_id'],
    pause: ['reason'],
    unpause: [],
  };

  async function action(name: ActionName, req: IncomingMessage): Promise<{ status: number; body: unknown }> {
    if (readonly) throw new HttpError(403, READONLY_MESSAGE);
    if (!signers) throw new HttpError(403, 'actions are disabled (no OWNER_KEY / GUARDIAN_KEY, or not bound to localhost)');
    if (!checkToken(req)) throw new HttpError(403, 'missing or wrong X-Spendfuse-Token');
    const origin = req.headers.origin;
    if (origin !== undefined && origin !== `http://${req.headers.host}`) throw new HttpError(403, 'cross-origin request refused');
    const ct = String(req.headers['content-type'] ?? '').split(';')[0]!.trim().toLowerCase();
    if (ct !== 'application/json') throw new HttpError(415, 'content-type must be application/json');
    if (!signers.allowed.includes(name)) throw new HttpError(403, `${signers.role} cannot ${name}`);

    const raw = await readBody(req, MAX_BODY);
    let body: unknown;
    try {
      body = raw.trim() === '' ? {} : JSON.parse(raw);
    } catch {
      throw new HttpError(400, 'body is not JSON');
    }
    if (!body || typeof body !== 'object' || Array.isArray(body)) throw new HttpError(400, 'body must be a JSON object');
    const b = body as Record<string, unknown>;
    for (const k of Object.keys(b)) if (!ALLOWED_KEYS[name].includes(k)) throw new HttpError(400, `unknown field ${k}`);
    const reason = checkReason(b.reason);
    if (reason instanceof Error) throw new HttpError(400, reason.message);
    const needId = () => {
      if (!isRequestId(b.request_id)) throw new HttpError(400, 'request_id must be a decimal string');
      return b.request_id;
    };
    const needAgent = () => {
      if (!isAccountId(b.agent_id)) throw new HttpError(400, 'agent_id is not a valid account id');
      return b.agent_id;
    };

    let out: ActionOutcome;
    switch (name) {
      case 'approve':
        out = await signers.approve(needId());
        break;
      case 'reject':
        out = await signers.reject(needId(), reason);
        break;
      case 'freeze':
        out = await signers.freeze(needAgent(), reason);
        break;
      case 'unfreeze':
        out = await signers.unfreeze(needAgent());
        break;
      case 'pause':
        out = await signers.pause(reason);
        break;
      case 'unpause':
        out = await signers.unpause();
        break;
    }
    cache.clear();
    const hash = isTxHash(out.hash) ? out.hash : null;
    log(`[action] ${name} by ${signers.accountId}: ${out.ok ? 'ok' : `failed: ${out.error ?? ''}`}${hash ? ` ${explorer.tx(hash)}` : ''}`);
    return { status: out.ok ? 200 : 502, body: { ok: out.ok, action: name, hash, url: hash ? explorer.tx(hash) : null, error: out.error, result: out.result } };
  }

  // ------------------------------------------------ static
  async function serveStatic(pathname: string, res: ServerResponse, head: boolean): Promise<void> {
    let decoded: string;
    try {
      decoded = decodeURIComponent(pathname);
    } catch {
      throw new HttpError(400, 'bad path');
    }
    if (decoded.includes('\0') || decoded.includes('\\')) throw new HttpError(400, 'bad path');
    const segs = decoded.split('/');
    if (segs.some((s) => s === '..' || (s.startsWith('.') && s !== ''))) throw new HttpError(403, 'forbidden');
    const rel = decoded === '/' ? 'index.html' : decoded === '/console' || decoded === '/console/' ? 'console.html' : decoded.replace(/^\/+/, '');
    const file = resolve(webRoot, rel);
    if (!file.startsWith(webRoot + sep)) throw new HttpError(403, 'forbidden');
    const type = CONTENT_TYPES[extname(file).toLowerCase()];
    if (!type) throw new HttpError(404, 'not found');
    let data: Buffer;
    try {
      const st = await stat(file);
      if (!st.isFile()) throw new Error('not a file');
      data = await readFile(file);
    } catch {
      throw new HttpError(404, 'not found');
    }
    res.writeHead(200, { ...SECURITY_HEADERS, 'content-type': type, 'content-length': data.length, 'cache-control': 'no-cache' });
    res.end(head ? undefined : data);
  }

  // ------------------------------------------------ router
  async function handle(req: IncomingMessage, res: ServerResponse): Promise<void> {
    const method = req.method ?? 'GET';
    // DNS rebinding: a loopback bind only answers to loopback Host names, READONLY included (it
    // still serves the vault views and run logs to whatever page could otherwise read them)
    if (local) {
      const h = String(req.headers.host ?? '').replace(/:\d+$/, '');
      if (!LOOPBACK_HOST_HEADERS.has(h)) throw new HttpError(421, 'unexpected Host header');
    }
    const rawPath = (req.url ?? '/').split('?')[0] ?? '/';
    const url = new URL(req.url ?? '/', 'http://localhost');
    if (!rawPath.startsWith('/api/')) {
      if (method !== 'GET' && method !== 'HEAD') throw new HttpError(405, 'method not allowed');
      return serveStatic(rawPath, res, method === 'HEAD');
    }
    const path = rawPath;
    if (method === 'POST') {
      const name = path.slice('/api/'.length) as ActionName;
      if (!ACTION_NAMES.includes(name)) throw new HttpError(404, 'no such route');
      const r = await action(name, req);
      return sendJson(res, r.status, r.body);
    }
    if (method !== 'GET' && method !== 'HEAD') throw new HttpError(405, 'method not allowed');
    if (path === '/api/state') return sendJson(res, 200, await state());
    if (path === '/api/activity') {
      const { before, limit } = parseActivityQuery(url.searchParams);
      return sendJson(res, 200, { activity: await c.activity(before, limit) });
    }
    if (path === '/api/runs') return sendJson(res, 200, { runs: await listRuns() });
    if (path.startsWith('/api/runs/')) {
      let id: string;
      try {
        id = decodeURIComponent(path.slice('/api/runs/'.length));
      } catch {
        throw new HttpError(400, 'bad run id');
      }
      return sendJson(res, 200, { id, run: await getRun(id) });
    }
    if (path === '/api/events') return openStream(req, res);
    throw new HttpError(404, 'no such route');
  }

  const server = createServer((req, res) => {
    handle(req, res).catch((err: unknown) => {
      if (res.headersSent) {
        res.end();
        return;
      }
      const status = err instanceof HttpError ? err.status : 500;
      const msg = err instanceof HttpError ? err.message : 'internal error';
      if (!(err instanceof HttpError)) log(`[error] ${errMsg(err)}`);
      sendJson(res, status, { error: msg });
    });
  });
  server.headersTimeout = 10_000;
  server.requestTimeout = 15_000;

  return new Promise((ok, fail) => {
    server.once('error', fail);
    server.listen(opts.port ?? DEFAULT_PORT, host, () => {
      server.off('error', fail);
      const addr = server.address();
      const port = typeof addr === 'object' && addr ? addr.port : (opts.port ?? DEFAULT_PORT);
      const shownHost = host.includes(':') ? `[${host}]` : host;
      ok({
        server,
        token,
        actionsEnabled,
        url: `http://${shownHost}:${port}`,
        close: () =>
          new Promise<void>((done) => {
            stopPoller();
            for (const r of clients) r.end();
            clients.clear();
            server.close(() => done());
            server.closeAllConnections();
          }),
      });
    });
  });
}
