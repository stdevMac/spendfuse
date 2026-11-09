// index.ts - Cloudflare Worker entry for the hosted, read-only Spendfuse dashboard
// (https://spendfuse.marcosmaceo.com). Static files come from web/ via the ASSETS binding; the API
// reads the vault over public testnet RPC. The Worker holds no keys. Config: wrangler.jsonc vars.
//   npm run web:dev     local (wrangler dev)
//   npm run web:deploy  deploy (wrangler deploy)
import { makeProvider, validateAccountId } from '../lib/near.ts';
import { liveViews } from '../server/views.ts';
import { SECURITY_HEADERS } from '../server/core.ts';
import { createHandler } from './handler.ts';
import type { AssetFetcher, Handler } from './handler.ts';
import { RECORDED } from './runs.ts';

export interface Env {
  ASSETS: AssetFetcher;
  NETWORK?: string;
  OWNER_ID?: string;
  VAULT_ID?: string;
  /** default agent.<OWNER_ID>; its keys are shown in the Proof panel */
  AGENT_ID?: string;
}

let memo: { key: string; handler: Handler } | null = null;

/** One handler per isolate (so the 5 s view cache is shared across requests), rebuilt if vars change. */
export function handlerFor(env: Env): Handler {
  const network = env.NETWORK ?? 'testnet';
  if (network !== 'testnet') throw new Error(`NETWORK=${network} is not supported (testnet only)`);
  const vaultId = env.VAULT_ID ?? (env.OWNER_ID ? `vault.${env.OWNER_ID}` : '');
  const bad = validateAccountId(vaultId);
  if (bad) throw new Error(`VAULT_ID: ${bad}`);
  const agentId = env.AGENT_ID ?? (env.OWNER_ID ? `agent.${env.OWNER_ID}` : '');
  const key = `${network}|${vaultId}|${agentId}`;
  if (memo?.key === key) return memo.handler;
  const handler = createHandler({
    views: liveViews(makeProvider(), vaultId),
    vaultId,
    network,
    proofAccounts: agentId && !validateAccountId(agentId) ? [agentId] : [],
    runs: RECORDED,
    assets: env.ASSETS,
  });
  memo = { key, handler };
  return handler;
}

export default {
  async fetch(request: Request, env: Env): Promise<Response> {
    let handler: Handler;
    try {
      handler = handlerFor(env);
    } catch (err) {
      console.log(`[error] misconfigured: ${err instanceof Error ? err.message : String(err)}`);
      return new Response(JSON.stringify({ error: 'misconfigured' }), {
        status: 500,
        headers: { ...SECURITY_HEADERS, 'content-type': 'application/json; charset=utf-8', 'cache-control': 'no-store' },
      });
    }
    return handler(request);
  },
};
