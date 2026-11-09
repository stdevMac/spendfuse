// lockdown.ts - remove the vault's own full-access key so nobody can redeploy or delete the vault.
//   node src/scripts/lockdown.ts --dry-run   read-only: list keys and check the contract, send nothing.
//                                            Needs only VAULT_ID or OWNER_ID (vault = vault.<OWNER_ID>);
//                                            no secret key (VAULT_KEY is used, if set, to mark its key).
//   node src/scripts/lockdown.ts             sends one DeleteKey tx, signed by VAULT_KEY, deleting VAULT_KEY
// After this the vault has no full-access keys: the contract code can no longer be changed by anyone,
// and only the contract's own methods (owner/guardian/agent calls) can move funds.
// Refuses when VAULT_KEY is not on the vault, or when the vault holds any other full-access key.
// Secret keys are never printed; .env is not edited (remove VAULT_KEY yourself afterwards).
import { Account, KeyPair, PublicKey, actions } from 'near-api-js';
import type { Action, KeyPairString } from 'near-api-js';
import { getEnv, loadEnv, requireEnv } from '../lib/env.ts';
import { unwrap } from '../lib/errors.ts';
import { explorer, listKeys, makeProvider, summarize, validateAccountId } from '../lib/near.ts';
import type { KeyInfo, TxResult, TxSummary } from '../lib/near.ts';
import { decodeContractError, SpendfuseClient } from '../lib/spendfuse.ts';

const EMPTY_CODE = '11111111111111111111111111111111';
const DRY = process.argv.slice(2).includes('--dry-run');

const log = (msg: string) => console.log(msg);

async function sendActions(signer: Account, receiverId: string, acts: Action[]): Promise<TxSummary> {
  const res = (await signer.signAndSendTransaction({ receiverId, actions: acts, waitUntil: 'EXECUTED_OPTIMISTIC', throwOnFailure: false })) as unknown as TxResult;
  const hash = (res as unknown as { transaction_outcome: { id: string } }).transaction_outcome.id;
  return summarize(hash, res);
}

const describe = (k: KeyInfo) =>
  k.fullAccess ? `${k.publicKey} FULL ACCESS` : `${k.publicKey} -> ${k.receiverId} [${k.methodNames?.join(', ') ?? ''}]`;

export type LockdownPlan =
  | { kind: 'locked' }
  | { kind: 'refuse'; reason: string }
  | { kind: 'delete'; publicKey: string; known: boolean };

/**
 * What lockdown would do with these vault keys. vaultPub is VAULT_KEY's public key, or null when no
 * key is available (keyless dry run): then the single full-access key on the vault is the target,
 * and the live run must be given its secret as VAULT_KEY.
 */
export function lockdownPlan(vaultId: string, keys: KeyInfo[], vaultPub: string | null): LockdownPlan {
  const full = keys.filter((k) => k.fullAccess);
  if (!full.length) return { kind: 'locked' };
  if (vaultPub === null) {
    if (full.length > 1)
      return { kind: 'refuse', reason: `refusing: ${vaultId} has ${full.length} full-access keys; lockdown deletes exactly one (VAULT_KEY), so remove the others (or investigate) first` };
    return { kind: 'delete', publicKey: full[0]!.publicKey, known: false };
  }
  const mine = keys.find((k) => k.publicKey === vaultPub);
  if (!mine) return { kind: 'refuse', reason: `refusing: the VAULT_KEY public key ${vaultPub} is not on ${vaultId}` };
  if (!mine.fullAccess) return { kind: 'refuse', reason: `refusing: VAULT_KEY ${vaultPub} is on ${vaultId} but is not a full-access key` };
  const unknown = full.filter((k) => k.publicKey !== vaultPub);
  if (unknown.length)
    return { kind: 'refuse', reason: `refusing: ${vaultId} has ${unknown.length} other full-access key(s) this script does not know about (${unknown.map((k) => k.publicKey).join(', ')}); remove them (or investigate) first` };
  return { kind: 'delete', publicKey: vaultPub, known: true };
}

/** VAULT_ID, else vault.<OWNER_ID>. */
export function vaultIdFromEnv(): string {
  const explicit = getEnv('VAULT_ID');
  const owner = getEnv('OWNER_ID');
  const vaultId = explicit ?? (owner ? `vault.${owner}` : undefined);
  if (!vaultId) return requireEnv('VAULT_ID', 'Or set OWNER_ID and the vault defaults to vault.<OWNER_ID>.');
  const bad = validateAccountId(vaultId);
  if (bad) throw new Error(`${explicit ? 'VAULT_ID' : 'vault id from OWNER_ID'}: ${bad}`);
  return vaultId;
}

async function main(): Promise<void> {
  for (const a of process.argv.slice(2)) if (a !== '--dry-run') throw new Error(`unknown argument ${a}`);
  loadEnv();
  const vaultId = vaultIdFromEnv();
  // the live run signs with the key it deletes; a dry run only reads, so it needs no secret
  const secret = DRY ? getEnv('VAULT_KEY') : requireEnv('VAULT_KEY', 'lockdown signs with the vault key it deletes.');
  const vaultKey = secret ? KeyPair.fromString(secret as KeyPairString) : null;
  const vaultPub = vaultKey ? vaultKey.getPublicKey().toString() : null;
  const provider = makeProvider();
  log(`Spendfuse lockdown - ${DRY ? 'DRY RUN (read-only, nothing sent)' : 'LIVE on testnet'}`);
  log(`vault ${vaultId}  ${explorer.account(vaultId)}`);
  if (!vaultPub) log('VAULT_KEY not set: keyless dry run (view calls only); the live run needs VAULT_KEY');

  // 1. contract deployed and initialized
  try {
    const acct = await provider.viewAccount({ accountId: vaultId });
    if (acct.code_hash === EMPTY_CODE) throw new Error(`${vaultId} has no contract deployed; run npm run setup first (lockdown would brick the account)`);
  } catch (err) {
    if ((unwrap(err) as { name?: string } | null)?.name === 'AccountDoesNotExistError') throw new Error(`${vaultId} does not exist`);
    throw err;
  }
  const client = new SpendfuseClient({ provider, vaultId });
  const config = await client.getConfig().catch((err: unknown) => {
    throw new Error(`contract is deployed but get_config failed (not initialized?): ${decodeContractError(err).message}`);
  });
  log(`contract ${config.version} initialized, owner ${config.owner_id}, agents ${config.agents}${config.paused ? ', PAUSED' : ''}`);

  // 2. keys (view_access_key_list): VAULT_KEY must be present, and it must be the only full-access key
  const keys = await listKeys(provider, vaultId);
  log(`vault keys (${keys.length}):`);
  for (const k of keys) log(`  ${describe(k)}${vaultPub && k.publicKey === vaultPub ? '  <- VAULT_KEY' : ''}`);
  const plan = lockdownPlan(vaultId, keys, vaultPub);
  if (plan.kind === 'locked') {
    log('vault keys: 0 full-access - already locked; nothing to do');
    return;
  }
  if (plan.kind === 'refuse') throw new Error(plan.reason);

  if (DRY) {
    log(`[plan] DeleteKey ${plan.publicKey} on ${vaultId}, signed by that same key`);
    if (!plan.known) log(`[plan] the live run needs VAULT_KEY = the secret of ${plan.publicKey} (it refuses any other key)`);
    log('[plan] afterwards: vault keys: 0 full-access - the contract code can no longer be changed by anyone');
    log('dry run: nothing sent. Run npm run lockdown to do it.');
    return;
  }

  // 3. the key deletes itself
  if (!vaultKey || !plan.known) throw new Error('internal: live lockdown without VAULT_KEY');
  const vault = new Account(vaultId, provider, vaultKey.toString() as KeyPairString);
  const s = await sendActions(vault, vaultId, [actions.deleteKey(PublicKey.fromString(plan.publicKey))]);
  if (!s.ok) throw new Error(`DeleteKey failed: ${decodeContractError(s).message} (${s.url})`);
  log(`[done] DeleteKey ${plan.publicKey} - ${s.url}`);

  const after = await listKeys(provider, vaultId);
  const fullAfter = after.filter((k) => k.fullAccess).length;
  if (fullAfter) throw new Error(`vault still has ${fullAfter} full-access key(s) after DeleteKey; check ${explorer.account(vaultId)}`);
  log(`vault keys: ${fullAfter} full-access - the contract code can no longer be changed by anyone`);
  log('VAULT_KEY is now useless: remove the VAULT_KEY line from .env yourself (this script does not edit .env).');
}

if (import.meta.main) {
  main().catch((err: unknown) => {
    console.error(`lockdown failed: ${decodeContractError(err).message}`);
    process.exitCode = 1;
  });
}
