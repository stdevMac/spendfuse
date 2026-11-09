// handler.ts - the hosted, READ-ONLY dashboard as a fetch handler (Request -> Response).
// Same JSON as the Node server in READONLY mode (route logic from src/server/core.ts); no keys, no
// signing, every write method is refused. Pure: views, runs and assets are injected, so tests run offline.
import type { Views } from '../server/backend.ts';
import {
  buildState,
  cachedViews,
  errMsg,
  Feed,
  HttpError,
  isRunId,
  jsonReplacer,
  parseActivityQuery,
  READONLY_MESSAGE,
  READONLY_MODE,
  runSummary,
  SECURITY_HEADERS,
  sortRuns,
  sseFrame,
  TtlCache,
} from '../server/core.ts';
import type { RecordedRun } from './runs.ts';

export interface AssetFetcher {
  fetch(request: Request): Promise<Response>;
}

export interface HandlerOptions {
  views: Views;
  vaultId: string;
  network: string;
  proofAccounts: readonly string[];
  runs: readonly RecordedRun[];
  /** static files (the Workers assets binding); 404 when absent */
  assets?: AssetFetcher;
  /** view cache TTL, default 5 s (shared by every request this isolate serves) */
  cacheMs?: number;
  /** SSE poll interval, default 5 s */
  pollMs?: number;
  /** how long one SSE response stays open before it closes and the browser reconnects, default 25 s */
  streamMs?: number;
  log?: (msg: string) => void;
}

export type Handler = (request: Request) => Promise<Response>;

function json(status: number, body: unknown, head = false): Response {
  return new Response(head ? null : JSON.stringify(body, jsonReplacer), {
    status,
    headers: { ...SECURITY_HEADERS, 'content-type': 'application/json; charset=utf-8', 'cache-control': 'no-store' },
  });
}

const sleep = (ms: number, signal?: AbortSignal) =>
  new Promise<void>((done) => {
    const t = setTimeout(done, ms);
    signal?.addEventListener('abort', () => {
      clearTimeout(t);
      done();
    });
  });

export function createHandler(opts: HandlerOptions): Handler {
  const cache = new TtlCache(opts.cacheMs ?? 5000);
  const c = cachedViews(opts.views, cache);
  const pollMs = opts.pollMs ?? 5000;
  const streamMs = opts.streamMs ?? 25_000;
  const log = opts.log ?? ((m: string) => console.log(m));
  const enc = new TextEncoder();

  const runRows = sortRuns(
    opts.runs.map(({ id, run }) => {
      const r = run as { finishedAt?: unknown; startedAt?: unknown } | null;
      const at = Date.parse(String(r?.finishedAt ?? r?.startedAt ?? ''));
      return runSummary(id, enc.encode(JSON.stringify(run)).length, Number.isFinite(at) ? at : 0, run);
    }),
  );
  const runById = new Map(opts.runs.map((r) => [r.id, r.run]));

  const state = () =>
    buildState({ c, vaultId: opts.vaultId, network: opts.network, proofAccounts: opts.proofAccounts, mode: READONLY_MODE });

  /** A bounded SSE response: polls the shared feed for `streamMs`, then ends; EventSource reconnects after `retry`. */
  function events(request: Request): Response {
    const feed = new Feed(c);
    const { readable, writable } = new TransformStream<Uint8Array, Uint8Array>();
    const writer = writable.getWriter();
    const stop = new AbortController();
    request.signal?.addEventListener('abort', () => stop.abort());
    void (async () => {
      const end = Date.now() + streamMs;
      try {
        await writer.write(enc.encode(`retry: ${Math.max(pollMs, 1000)}\n\n`));
        while (!stop.signal.aborted) {
          for (const e of await feed.poll()) await writer.write(enc.encode(sseFrame(e)));
          if (Date.now() + pollMs > end) break;
          await sleep(pollMs, stop.signal);
        }
      } catch {
        // client went away
      } finally {
        await writer.close().catch(() => {});
      }
    })();
    return new Response(readable, {
      status: 200,
      headers: { ...SECURITY_HEADERS, 'content-type': 'text/event-stream; charset=utf-8', 'cache-control': 'no-store' },
    });
  }

  async function api(request: Request, url: URL): Promise<Response> {
    const method = request.method;
    const path = url.pathname;
    const head = method === 'HEAD';
    if (method === 'POST' || method === 'PUT' || method === 'PATCH' || method === 'DELETE') throw new HttpError(403, READONLY_MESSAGE);
    if (method !== 'GET' && !head) throw new HttpError(405, 'method not allowed');
    if (path === '/api/state') return json(200, await state(), head);
    if (path === '/api/activity') {
      const { before, limit } = parseActivityQuery(url.searchParams);
      return json(200, { activity: await c.activity(before, limit) }, head);
    }
    if (path === '/api/runs') return json(200, { runs: runRows }, head);
    if (path.startsWith('/api/runs/')) {
      let id: string;
      try {
        id = decodeURIComponent(path.slice('/api/runs/'.length));
      } catch {
        throw new HttpError(400, 'bad run id');
      }
      if (!isRunId(id)) throw new HttpError(400, 'bad run id');
      if (!runById.has(id)) throw new HttpError(404, 'run not found');
      return json(200, { id, run: runById.get(id) }, head);
    }
    if (path === '/api/events') {
      if (head) return new Response(null, { status: 200, headers: { ...SECURITY_HEADERS, 'content-type': 'text/event-stream; charset=utf-8', 'cache-control': 'no-store' } });
      return events(request);
    }
    throw new HttpError(404, 'no such route');
  }

  const PAGE_ROUTES: Record<string, string> = { '/': '/index.html', '/console': '/console.html', '/console/': '/console.html' };

  async function staticFile(request: Request): Promise<Response> {
    if (request.method !== 'GET' && request.method !== 'HEAD') throw new HttpError(405, 'method not allowed');
    if (!opts.assets) throw new HttpError(404, 'not found');
    // the landing is "/", the console "/console": the assets binding is asked for the file itself (wrangler.jsonc
    // sets html_handling "none", so nothing is left to Cloudflare's trailing-slash rules)
    const url = new URL(request.url);
    const page = PAGE_ROUTES[url.pathname];
    const req = page ? new Request(new URL(page + url.search, url), request) : request;
    const res = await opts.assets.fetch(req);
    const headers = new Headers(res.headers);
    for (const [k, v] of Object.entries(SECURITY_HEADERS)) headers.set(k, v);
    if (!headers.has('cache-control')) headers.set('cache-control', 'no-cache');
    return new Response(res.body, { status: res.status, statusText: res.statusText, headers });
  }

  return async (request) => {
    const url = new URL(request.url);
    try {
      if (url.pathname.startsWith('/api/')) return await api(request, url);
      return await staticFile(request);
    } catch (err) {
      if (err instanceof HttpError) return json(err.status, { error: err.message });
      log(`[error] ${errMsg(err)}`);
      return json(500, { error: 'internal error' });
    }
  };
}
