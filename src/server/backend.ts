// backend.ts - what the dashboard server needs from the chain: read-only views plus optional
// owner/guardian actions. The live backend wraps SpendfuseClient; tests inject a fake.
import { readFileSync } from 'node:fs';
import { join } from 'node:path';
import type { KeyPairString, Provider } from 'near-api-js';
import { getEnv, loadEnv, REPO_ROOT } from '../lib/env.ts';
import { makeProvider, signerFromSecret, validateAccountId } from '../lib/near.ts';
import { decodeContractError, guardianApi, ownerApi } from '../lib/spendfuse.ts';
import { liveViews } from './views.ts';
import type { CallResult } from '../lib/spendfuse.ts';
import type { AgentView, BlocklistView, ConfigView, LogEntry, PendingPayment, Stats } from '../lib/types.ts';

export type ActionName = 'approve' | 'reject' | 'freeze' | 'unfreeze' | 'pause' | 'unpause';
export const ACTION_NAMES: readonly ActionName[] = ['approve', 'reject', 'freeze', 'unfreeze', 'pause', 'unpause'];
/** Actions a guardian may take (the contract allows guardians only to tighten). */
export const GUARDIAN_ACTIONS: readonly ActionName[] = ['reject', 'freeze', 'pause'];

/** Key info with bigints as strings (JSON-safe). */
export interface KeyJson {
  publicKey: string;
  nonce: string;
  fullAccess: boolean;
  receiverId?: string;
  methodNames?: string[];
  /** yocto; null = unlimited */
  allowance?: string | null;
}

export interface Views {
  getConfig(): Promise<ConfigView>;
  getStats(): Promise<Stats>;
  listAllAgents(): Promise<AgentView[]>;
  getAllPending(): Promise<PendingPayment[]>;
  getActivity(beforeSeq?: string, limit?: number): Promise<LogEntry[]>;
  getBlocklist(fromIndex?: number, limit?: number): Promise<BlocklistView[]>;
  listKeys(accountId: string): Promise<KeyJson[]>;
}

export interface ActionOutcome {
  ok: boolean;
  hash: string | null;
  error: string | null;
  result: unknown;
}

export interface Signers {
  role: 'owner' | 'guardian';
  accountId: string;
  allowed: readonly ActionName[];
  approve(requestId: string): Promise<ActionOutcome>;
  reject(requestId: string, reason?: string): Promise<ActionOutcome>;
  freeze(agentId: string, reason?: string): Promise<ActionOutcome>;
  unfreeze(agentId: string): Promise<ActionOutcome>;
  pause(reason?: string): Promise<ActionOutcome>;
  unpause(): Promise<ActionOutcome>;
}

export interface Backend {
  vaultId: string;
  network: string;
  /** extra accounts whose keys are shown in the Proof panel (e.g. AGENT_ID) */
  proofAccounts: string[];
  views: Views;
  signers: Signers | null;
  /** Redact canary ids from served run-file text (defense in depth for run files written before redaction). */
  redactRun?: (text: string) => string;
}

export const CANARIES_PATH = join(REPO_ROOT, '.spendfuse', 'canaries.json');

/** Account ids from .spendfuse/canaries.json (empty when missing or unreadable). Read fresh each call. */
export function canaryIds(path: string = CANARIES_PATH): string[] {
  try {
    const list = JSON.parse(readFileSync(path, 'utf8')) as unknown;
    if (!Array.isArray(list)) return [];
    return list
      .map((c) => (c && typeof c === 'object' ? (c as { accountId?: unknown }).accountId : undefined))
      .filter((id): id is string => typeof id === 'string' && id.length > 8);
  } catch {
    return [];
  }
}

/** Replace each full canary id in text with its first 8 chars + '…'. */
export function redactCanaryIds(text: string, ids: readonly string[] = canaryIds()): string {
  let out = text;
  for (const id of ids) if (id.length > 8) out = out.split(id).join(`${id.slice(0, 8)}…`);
  return out;
}

/** Redact canaries from parsed JSON (round-trips through a string so nested transcripts are covered). */
export function redactRunJson<T>(value: T, ids: readonly string[] = canaryIds()): T {
  if (!ids.length) return value;
  return JSON.parse(redactCanaryIds(JSON.stringify(value), ids)) as T;
}

export { keyToJson, liveViews } from './views.ts';

const outcome = (r: CallResult<unknown>): ActionOutcome => ({ ok: r.ok, hash: r.summary.hash, error: r.error, result: r.result });
async function run(fn: () => Promise<CallResult<unknown>>): Promise<ActionOutcome> {
  try {
    return outcome(await fn());
  } catch (err) {
    const d = decodeContractError(err);
    return { ok: false, hash: d.txHash, error: d.message, result: null };
  }
}

/** Owner signer (OWNER_ID + OWNER_KEY) or else guardian signer (GUARDIAN_ID + GUARDIAN_KEY); null when neither is set. */
export function liveSigners(provider: Provider, vaultId: string, log: (msg: string) => void = console.log): Signers | null {
  const ownerId = getEnv('OWNER_ID');
  const ownerKey = getEnv('OWNER_KEY');
  const guardianId = getEnv('GUARDIAN_ID');
  const guardianKey = getEnv('GUARDIAN_KEY');
  const onHash = (hash: string, method: string) => log(`[tx] ${method} ${hash}`);
  if (ownerId && ownerKey) {
    const api = ownerApi({ accountId: ownerId, provider, signer: signerFromSecret(ownerKey as KeyPairString) }, { vaultId, onHash });
    return {
      role: 'owner',
      accountId: ownerId,
      allowed: ACTION_NAMES,
      approve: (id) => run(() => api.approve(id)),
      reject: (id, reason) => run(() => api.reject(id, reason)),
      freeze: (agent, reason) => run(() => api.freezeAgent(agent, reason)),
      unfreeze: (agent) => run(() => api.unfreezeAgent(agent)),
      pause: (reason) => run(() => api.pause(reason)),
      unpause: () => run(() => api.unpause()),
    };
  }
  if (guardianId && guardianKey) {
    const api = guardianApi({ accountId: guardianId, provider, signer: signerFromSecret(guardianKey as KeyPairString) }, { vaultId, onHash });
    const denied = async (): Promise<ActionOutcome> => ({ ok: false, hash: null, error: 'guardians cannot do this', result: null });
    return {
      role: 'guardian',
      accountId: guardianId,
      allowed: GUARDIAN_ACTIONS,
      approve: denied,
      reject: (id, reason) => run(() => api.reject(id, reason)),
      freeze: (agent, reason) => run(() => api.freezeAgent(agent, reason)),
      unfreeze: denied,
      pause: (reason) => run(() => api.pause(reason)),
      unpause: denied,
    };
  }
  return null;
}

export interface LiveOptions {
  /** build signers (local mode only); false for READONLY */
  withSigners: boolean;
  log?: (msg: string) => void;
}

/** Backend from .env: VAULT_ID (default vault.<OWNER_ID>), AGENT_ID (default agent.<OWNER_ID>). */
export function liveBackend(opts: LiveOptions): Backend {
  loadEnv();
  const ownerId = getEnv('OWNER_ID');
  const vaultId = getEnv('VAULT_ID') ?? (ownerId ? `vault.${ownerId}` : undefined);
  if (!vaultId) throw new Error('Set VAULT_ID or OWNER_ID in .env');
  const bad = validateAccountId(vaultId);
  if (bad) throw new Error(`VAULT_ID: ${bad}`);
  const agentId = getEnv('AGENT_ID') ?? (ownerId ? `agent.${ownerId}` : undefined);
  const provider = makeProvider();
  return {
    vaultId,
    network: 'testnet',
    proofAccounts: agentId && !validateAccountId(agentId) ? [agentId] : [],
    views: liveViews(provider, vaultId),
    signers: opts.withSigners ? liveSigners(provider, vaultId, opts.log) : null,
    redactRun: (text) => redactCanaryIds(text),
  };
}
