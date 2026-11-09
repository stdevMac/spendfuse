// views.ts - the live, read-only chain views (vault views + access-key lists) behind the dashboard.
// Runtime-neutral (fetch-based near-api-js provider), so the Node server and the Worker share it.
import { listKeys } from '../lib/near.ts';
import type { KeyInfo } from '../lib/near.ts';
import { SpendfuseClient } from '../lib/spendfuse.ts';
import type { Provider } from 'near-api-js';
import type { KeyJson, Views } from './backend.ts';

export const keyToJson = (k: KeyInfo): KeyJson => ({
  publicKey: k.publicKey,
  nonce: k.nonce.toString(),
  fullAccess: k.fullAccess,
  receiverId: k.receiverId,
  methodNames: k.methodNames,
  allowance: k.allowance === undefined ? undefined : k.allowance === null ? null : k.allowance.toString(),
});

export function liveViews(provider: Provider, vaultId: string): Views {
  const client = new SpendfuseClient({ provider, vaultId });
  return {
    getConfig: () => client.getConfig(),
    getStats: () => client.getStats(),
    listAllAgents: () => client.listAllAgents(),
    getAllPending: () => client.getAllPending(),
    getActivity: (before, limit) => client.getActivity(before, limit),
    getBlocklist: (from, limit) => client.getBlocklist(from, limit),
    listKeys: async (accountId) => (await listKeys(provider, accountId)).map(keyToJson),
  };
}

