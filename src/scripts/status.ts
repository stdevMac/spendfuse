// status.ts - read-only report of the vault (views and view_account only; nothing is signed).
//   node src/scripts/status.ts [--json] [--activity N]
// Uses VAULT_ID (default vault.<OWNER_ID>) and AGENT_ID (default agent.<OWNER_ID>) from .env.
import { getEnv, loadEnv } from '../lib/env.ts';
import { unwrap } from '../lib/errors.ts';
import { explorer, listKeys, makeProvider } from '../lib/near.ts';
import { decodeContractError, formatNear, SpendfuseClient } from '../lib/spendfuse.ts';

const args = process.argv.slice(2);
const JSON_OUT = args.includes('--json');
const ai = args.indexOf('--activity');
const ACTIVITY = ai >= 0 ? Math.min(100, Math.max(1, Number(args[ai + 1]) || 10)) : 10;

async function main(): Promise<void> {
  loadEnv();
  const ownerId = getEnv('OWNER_ID');
  const vaultId = getEnv('VAULT_ID') ?? (ownerId ? `vault.${ownerId}` : undefined);
  const agentId = getEnv('AGENT_ID') ?? (ownerId ? `agent.${ownerId}` : undefined);
  if (!vaultId) throw new Error('Set VAULT_ID or OWNER_ID in .env');
  const provider = makeProvider();
  const client = new SpendfuseClient({ provider, vaultId });

  try {
    const acct = await provider.viewAccount({ accountId: vaultId });
    if (acct.code_hash === '11111111111111111111111111111111') {
      console.log(`${vaultId} exists but has no contract yet; run src/scripts/setup-testnet.ts`);
      return;
    }
  } catch (err) {
    if ((unwrap(err) as { name?: string } | null)?.name === 'AccountDoesNotExistError') {
      console.log(`${vaultId} does not exist yet; run src/scripts/setup-testnet.ts`);
      return;
    }
    throw err;
  }

  const [config, stats, agents, pending, activity, blocklist] = await Promise.all([
    client.getConfig(),
    client.getStats(),
    client.listAllAgents(),
    client.getAllPending(),
    client.getActivity(undefined, ACTIVITY),
    client.getBlocklist(0, 100),
  ]);
  const agentKeys = agentId ? await listKeys(provider, agentId).catch(() => null) : null;
  const vaultKeys = await listKeys(provider, vaultId).catch(() => null);
  const vaultFull = vaultKeys ? vaultKeys.filter((k) => k.fullAccess).length : null;
  const VAULT_WARN = 'WARNING: vault still has a full-access key: the code can be replaced; run npm run lockdown';
  const VAULT_OK = 'vault locked: no full-access keys';
  const keyJson = (ks: typeof agentKeys) =>
    ks?.map((k) => ({ ...k, nonce: k.nonce.toString(), allowance: k.allowance == null ? k.allowance : k.allowance.toString() })) ?? null;

  if (JSON_OUT) {
    const vaultLock = vaultFull == null ? null : { fullAccessKeys: vaultFull, locked: vaultFull === 0, message: vaultFull ? VAULT_WARN : VAULT_OK };
    console.log(JSON.stringify({ vaultId, config, stats, agents, pending, activity, blocklist, agentId, agentKeys: keyJson(agentKeys), vaultKeys: keyJson(vaultKeys), vaultLock }, null, 2));
    return;
  }

  const n = formatNear;
  console.log(`Vault ${vaultId}  (contract ${config.version})  ${explorer.account(vaultId)}`);
  if (vaultFull == null) console.log('  vault keys: could not list');
  else console.log(`  vault keys: ${vaultKeys!.length} key(s), ${vaultFull} full-access - ${vaultFull ? VAULT_WARN : VAULT_OK}`);
  console.log(`  owner ${config.owner_id}${config.pending_owner ? `  (pending owner ${config.pending_owner})` : ''}`);
  console.log(`  guardians [${config.guardians.join(', ')}]`);
  console.log(`  ${config.paused ? `PAUSED: ${config.pause_reason ?? ''}` : 'not paused'}`);
  console.log(`  balance ${n(config.balance)} NEAR = storage ${n(config.storage_locked)} + reserved ${n(config.reserved)} + available ${n(config.available)}`);
  console.log(`  agents ${config.agents}, canaries ${config.canaries}, blocklist ${config.blocklist} (open reports ${config.open_reports}), pending ${config.pending}`);
  console.log(
    `  stats: requests ${stats.requests}, paid ${stats.paid} (${n(stats.paid_total)} NEAR), blocked ${stats.blocked}, escalated ${stats.escalated}, ` +
      `tripped ${stats.tripped}, approved ${stats.approved}, rejected ${stats.rejected}, expired ${stats.expired}, failed ${stats.failed}, freezes ${stats.freezes}`,
  );

  console.log(`\nAgents (${agents.length})`);
  for (const a of agents) {
    const st = a.status.state === 'frozen' ? `FROZEN by ${a.status.by}: ${a.status.reason}` : 'active';
    console.log(`  ${a.agent_id} "${a.label}"  ${st}`);
    console.log(
      `    24h spent ${n(a.spent_24h)} / ${n(a.policy.daily_limit)} NEAR, remaining ${n(a.remaining_24h)}, reserved ${n(a.reserved)}, ` +
        `payments last hour ${a.payments_last_hour}/${a.policy.max_payments_per_hour}, blocks last hour ${a.blocks_last_hour}`,
    );
    console.log(
      `    policy: max ${n(a.policy.max_per_payment)}, approval above ${n(a.policy.approval_threshold)}, new payee ${n(a.policy.new_payee_limit)}, ` +
        `allowlist${a.policy.allowlist_only ? ' (only)' : ''} [${a.policy.allowlist.join(', ')}]${a.policy.expires_at_ms ? `, expires ${new Date(Number(a.policy.expires_at_ms)).toISOString()}` : ''}`,
    );
  }

  console.log(`\nPending approvals (${pending.length})`);
  for (const p of pending)
    console.log(`  #${p.id} ${p.agent_id} -> ${p.receiver_id} ${n(p.amount)} NEAR [${p.reasons.join(', ')}] expires ${new Date(Number(p.expires_at_ms)).toISOString()}${p.memo ? ` memo ${JSON.stringify(p.memo)}` : ''}`);

  console.log(`\nBlocklist (${blocklist.length})`);
  for (const b of blocklist) console.log(`  ${b.account_id} ${b.status} by ${b.reporter}: ${b.reason}`);

  console.log(`\nRecent activity (newest first, ${activity.length})`);
  for (const e of activity) {
    const parts = [e.agent_id, e.receiver_id && `-> ${e.receiver_id}`, e.amount && `${n(e.amount)} NEAR`, e.request_id && `#${e.request_id}`, e.reasons?.length && `[${e.reasons.join(', ')}]`, e.note && JSON.stringify(e.note)];
    console.log(`  ${e.seq.padStart(4)} ${new Date(Number(e.at_ms)).toISOString()} ${e.kind.padEnd(16)} ${parts.filter(Boolean).join(' ')}  (by ${e.by})`);
  }

  if (agentId) {
    console.log(`\nAgent keys ${agentId}`);
    if (!agentKeys) console.log('  account not found');
    else {
      const full = agentKeys.filter((k) => k.fullAccess).length;
      console.log(`  ${agentKeys.length} key(s), ${full} full-access${full ? '  <-- WARNING: expected 0' : ''}`);
      for (const k of agentKeys.filter((x) => !x.fullAccess))
        console.log(`  ${k.publicKey} -> ${k.receiverId} [${k.methodNames?.join(', ')}] allowance ${k.allowance == null ? 'unlimited' : `${n(k.allowance)} NEAR`}`);
    }
  }
}

main().catch((err: unknown) => {
  console.error(`status failed: ${decodeContractError(err).message}`);
  process.exitCode = 1;
});
