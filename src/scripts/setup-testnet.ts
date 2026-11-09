// setup-testnet.ts - one-time, idempotent testnet setup, run by a human:
//   node src/scripts/setup-testnet.ts [--dry-run] [--no-deposit]
// Needs OWNER_ID (+ OWNER_KEY unless --dry-run) in .env, and a funded owner account.
// Each step checks chain state first and is skipped when already done, so a re-run resumes.
// New keys are appended to .env (mode 0600) BEFORE the tx that uses them; secrets are never printed.
// Accounts: vault.<owner> (contract), guardian.<owner>, agent.<owner> (function-call key only),
// store./billing./feed.<owner> (payees; the owner's key is their full-access key so funds stay recoverable). Override with VAULT_ID, GUARDIAN_ID, AGENT_ID, SHOP_ID, API_ID, DATA_ID.
import { createHash } from 'node:crypto';
import { existsSync, mkdirSync, readFileSync, writeFileSync } from 'node:fs';
import { join } from 'node:path';
import { Account, KeyPair, PublicKey, actions, baseEncode, nearToYocto, teraToGas } from 'near-api-js';
import type { Action, KeyPairString, Provider } from 'near-api-js';
import { appendEnv, envFileNames, getEnv, loadEnv, PAYEES, REPO_ROOT, requireEnv } from '../lib/env.ts';
import { explain, unwrap } from '../lib/errors.ts';
import { explorer, listKeys, makeProvider, newKey, summarize, validateAccountId } from '../lib/near.ts';
import type { TxResult, TxSummary } from '../lib/near.ts';
import { newImplicitCanary } from '../lib/canary.ts';
import type { CanaryRecord } from '../lib/canary.ts';
import { AGENT_METHODS, decodeContractError, formatNear, ownerApi, SpendfuseClient } from '../lib/spendfuse.ts';
import type { CallResult, PolicyLike } from '../lib/spendfuse.ts';
import type { ConfigView } from '../lib/types.ts';

const argv = new Set(process.argv.slice(2));
const DRY = argv.has('--dry-run');
const REDEPLOY = argv.has('--redeploy');
const NO_DEPOSIT = argv.has('--no-deposit');
for (const a of argv) if (!['--dry-run', '--no-deposit', '--redeploy'].includes(a)) throw new Error(`unknown flag ${a}`);

const WASM_PATH = join(REPO_ROOT, 'contract/res/tripwire.wasm');
const CANARY_PATH = join(REPO_ROOT, '.spendfuse/canaries.json');
const EMPTY_CODE = '11111111111111111111111111111111';

// Funding (NEAR). The 300 KB wasm locks ~3 NEAR of storage, so the vault gets 5 and a 1 NEAR deposit on top.
const FUND = { vault: '5', guardian: '0.5', agent: '0.5', payee: '0.1', deposit: '1', gasMargin: '0.5' } as const;
const AGENT_KEY_ALLOWANCE = nearToYocto('1'); // gas budget of the agent's function-call key
const POLICY: Omit<PolicyLike, 'allowlist'> = {
  max_per_payment: nearToYocto('1'),
  daily_limit: nearToYocto('3'),
  approval_threshold: nearToYocto('0.5'),
  new_payee_limit: nearToYocto('0.2'),
  max_payments_per_hour: 10,
};

// ---------------------------------------------------------------- helpers
const log = (msg: string) => console.log(msg);
const step = (name: string, state: 'done' | 'skip' | 'plan' | 'run' | 'warn', detail = '') =>
  log(`${{ done: '[done]', skip: '[skip]', plan: '[plan]', run: '[ .. ]', warn: '[warn]' }[state]} ${name}${detail ? ` - ${detail}` : ''}`);

function idFor(envName: string, prefix: string, ownerId: string): string {
  const id = getEnv(envName) ?? `${prefix}.${ownerId}`;
  const bad = validateAccountId(id);
  if (bad) throw new Error(`${envName}: ${bad}`);
  return id;
}

interface AccountInfo {
  amount: bigint;
  codeHash: string;
}
async function accountInfo(provider: Provider, accountId: string): Promise<AccountInfo | null> {
  try {
    const v = await provider.viewAccount({ accountId });
    return { amount: BigInt(v.amount), codeHash: v.code_hash };
  } catch (err) {
    if ((unwrap(err) as { name?: string } | null)?.name === 'AccountDoesNotExistError') return null;
    throw err;
  }
}

/** Existing key from .env, or (live mode) a new one appended to .env first. null in dry-run when missing. */
function ensureKey(envName: string): KeyPair | null {
  const existing = getEnv(envName);
  if (existing) return KeyPair.fromString(existing as KeyPairString);
  if (DRY) return null;
  const k = newKey();
  appendEnv(envName, k.secretKey);
  log(`       new key ${envName} written to .env (public ${k.publicKey})`);
  return k.keyPair;
}

/** Record an account id in .env so later scripts find it (no-op when already there). */
function rememberId(envName: string, value: string): void {
  if (DRY || envFileNames().has(envName)) return;
  appendEnv(envName, value);
}

async function sendActions(signer: Account, receiverId: string, acts: Action[]): Promise<TxSummary> {
  const res = (await signer.signAndSendTransaction({ receiverId, actions: acts, waitUntil: 'EXECUTED_OPTIMISTIC', throwOnFailure: false })) as unknown as TxResult;
  const hash = (res as unknown as { transaction_outcome: { id: string } }).transaction_outcome.id;
  return summarize(hash, res);
}

function check(name: string, s: TxSummary | CallResult<unknown>): void {
  const summary = 'summary' in s ? s.summary : s;
  if (!summary.ok) throw new Error(`${name} failed: ${decodeContractError(summary).message} (${summary.url})`);
  step(name, 'done', summary.url);
}

const isDirectSub = (id: string, parent: string) => id.endsWith(`.${parent}`) && !id.slice(0, -parent.length - 1).includes('.');

// ---------------------------------------------------------------- main
async function main(): Promise<void> {
  loadEnv();
  const ownerId = requireEnv('OWNER_ID', 'Run src/scripts/newkey.ts and create the owner account first.');
  const ids = {
    vault: idFor('VAULT_ID', 'vault', ownerId),
    guardian: idFor('GUARDIAN_ID', 'guardian', ownerId),
    agent: idFor('AGENT_ID', 'agent', ownerId),
    shop: idFor(PAYEES.shop.env, PAYEES.shop.prefix, ownerId),
    api: idFor(PAYEES.api.env, PAYEES.api.prefix, ownerId),
    data: idFor(PAYEES.data.env, PAYEES.data.prefix, ownerId),
  };
  const provider = makeProvider();
  const client = new SpendfuseClient({ provider, vaultId: ids.vault });
  const wasm = readFileSync(WASM_PATH);
  const wasmHash = baseEncode(createHash('sha256').update(wasm).digest());

  log(`Spendfuse testnet setup${DRY ? ' (dry run: views only, nothing is written or sent)' : ''}`);
  log(`  owner ${ownerId}`);
  for (const [k, v] of Object.entries(ids)) log(`  ${k.padEnd(8)} ${v}`);
  log(`  wasm    ${WASM_PATH} (${wasm.length} bytes, sha256 ${wasmHash})`);

  // -- read state
  const infos = Object.fromEntries(
    await Promise.all(Object.entries({ owner: ownerId, ...ids }).map(async ([k, id]) => [k, await accountInfo(provider, id)] as const)),
  ) as Record<'owner' | keyof typeof ids, AccountInfo | null>;

  // -- budget
  const toCreate = (['vault', 'guardian', 'agent', 'shop', 'api', 'data'] as const).filter((k) => !infos[k]);
  const fundOf = (k: (typeof toCreate)[number]) => nearToYocto(k === 'vault' ? FUND.vault : k === 'guardian' ? FUND.guardian : k === 'agent' ? FUND.agent : FUND.payee);
  const needed =
    toCreate.reduce((sum, k) => sum + fundOf(k), 0n) + (NO_DEPOSIT ? 0n : nearToYocto(FUND.deposit)) + nearToYocto(FUND.gasMargin);
  if (!infos.owner) {
    step('owner account', 'warn', `${ownerId} does not exist yet; it needs about ${formatNear(needed)} NEAR`);
    if (!DRY) throw new Error(`Create and fund ${ownerId} first.`);
  } else {
    log(`  owner balance ${formatNear(infos.owner.amount)} NEAR, this run needs up to ~${formatNear(needed)} NEAR`);
    if (!DRY && infos.owner.amount < needed) throw new Error(`Owner balance too low: ${formatNear(infos.owner.amount)} < ${formatNear(needed)} NEAR`);
  }
  for (const k of toCreate)
    if (!isDirectSub(ids[k], ownerId)) throw new Error(`${ids[k]} does not exist and is not a direct sub-account of ${ownerId}; create it yourself or unset the override`);

  const owner = DRY ? null : new Account(ownerId, provider, requireEnv('OWNER_KEY') as KeyPairString);
  const ownerCalls = owner ? ownerApi(owner, { vaultId: ids.vault }) : null;

  // -- 1. vault account
  const vaultKey = infos.vault ? (getEnv('VAULT_KEY') ? ensureKey('VAULT_KEY') : null) : ensureKey('VAULT_KEY');
  if (infos.vault) step('vault account', 'skip', 'exists');
  else if (DRY) step('vault account', 'plan', `create with ${FUND.vault} NEAR and a new full-access VAULT_KEY`);
  else {
    rememberId('VAULT_ID', ids.vault);
    check('vault account', await sendActions(owner!, ids.vault, [
      actions.createAccount(),
      actions.transfer(nearToYocto(FUND.vault)),
      actions.addFullAccessKey(vaultKey!.getPublicKey()),
    ]));
  }

  // -- 2. guardian account (full-access key, it signs freeze/pause/reject)
  if (infos.guardian) step('guardian account', 'skip', 'exists');
  else if (DRY) step('guardian account', 'plan', `create with ${FUND.guardian} NEAR and a new full-access GUARDIAN_KEY`);
  else {
    const k = ensureKey('GUARDIAN_KEY')!;
    rememberId('GUARDIAN_ID', ids.guardian);
    check('guardian account', await sendActions(owner!, ids.guardian, [
      actions.createAccount(),
      actions.transfer(nearToYocto(FUND.guardian)),
      actions.addFullAccessKey(k.getPublicKey()),
    ]));
  }

  // -- 3. agent account: ONLY a function-call key limited to the vault's agent methods
  if (infos.agent) step('agent account', 'skip', 'exists');
  else if (DRY) step('agent account', 'plan', `create with ${FUND.agent} NEAR and a function-call AGENT_KEY for ${ids.vault} [${AGENT_METHODS.join(', ')}], allowance 1 NEAR`);
  else {
    const k = ensureKey('AGENT_KEY')!;
    rememberId('AGENT_ID', ids.agent);
    check('agent account', await sendActions(owner!, ids.agent, [
      actions.createAccount(),
      actions.transfer(nearToYocto(FUND.agent)),
      actions.addFunctionCallAccessKey(PublicKey.fromString(k.getPublicKey().toString()), ids.vault, [...AGENT_METHODS], AGENT_KEY_ALLOWANCE),
    ]));
  }

  // -- 4. payees: plain accounts holding the OWNER's public key as a full-access key, so
  // funds paid to them stay recoverable (a keyless, code-less account is a black hole -
  // the scout flags it as FUNDS_UNRECOVERABLE and the guard refuses to pay it).
  const ownerPub = owner ? KeyPair.fromString(requireEnv('OWNER_KEY') as KeyPairString).getPublicKey() : null;
  for (const k of ['shop', 'api', 'data'] as const) {
    if (infos[k]) {
      const keys = await listKeys(provider, ids[k]);
      if (keys.length === 0 && infos[k]!.codeHash === EMPTY_CODE)
        step(`payee ${ids[k]}`, 'warn', `exists but has no keys and no code: funds sent there are unrecoverable; set ${PAYEES[k].env} to a new name`);
      else step(`payee ${ids[k]}`, 'skip', 'exists');
    } else if (DRY) step(`payee ${ids[k]}`, 'plan', `create with ${FUND.payee} NEAR and the owner's public key as full-access key`);
    else
      check(`payee ${ids[k]}`, await sendActions(owner!, ids[k], [
        actions.createAccount(),
        actions.transfer(nearToYocto(FUND.payee)),
        actions.addFullAccessKey(ownerPub!),
      ]));
  }

  // -- 5. contract deploy + init (signed by the vault, `new` is #[private])
  const codeHash = (await accountInfo(provider, ids.vault))?.codeHash ?? EMPTY_CODE;
  let config: ConfigView | null = null;
  if (codeHash !== EMPTY_CODE) {
    if (codeHash !== wasmHash && !REDEPLOY) step('contract code', 'warn', `deployed code ${codeHash} differs from local wasm ${wasmHash}; pass --redeploy to upgrade it (state is kept, no re-init)`);
    else if (codeHash !== wasmHash && DRY) step('contract code', 'plan', `redeploy wasm ${wasmHash} over ${codeHash} (code only, state kept)`);
    else if (codeHash !== wasmHash) {
      if (!vaultKey) throw new Error('VAULT_KEY is missing from .env; it is needed to redeploy (if the vault is locked, the code can no longer be changed)');
      const vault = new Account(ids.vault, provider, vaultKey.toString() as KeyPairString);
      check('contract redeploy', await sendActions(vault, ids.vault, [actions.deployContract(wasm)]));
    }
    try {
      config = await client.getConfig();
    } catch (err) {
      if (!/not initialized/i.test(explain(err).message)) throw err;
    }
  }
  const initArgs = { owner_id: ownerId, guardians: [ids.guardian] };
  if (config) step('contract deploy + init', 'skip', `version ${config.version}, owner ${config.owner_id}`);
  else if (DRY) step('contract deploy + init', 'plan', codeHash === EMPTY_CODE ? `deploy wasm and call new(${JSON.stringify(initArgs)}) in one tx` : `code present, call new(${JSON.stringify(initArgs)})`);
  else {
    if (!vaultKey) throw new Error('VAULT_KEY is missing from .env; it is needed to deploy and initialize the vault');
    const vault = new Account(ids.vault, provider, vaultKey.toString() as KeyPairString);
    const init = actions.functionCall('new', initArgs, teraToGas('30'), 0n);
    check('contract deploy + init', await sendActions(vault, ids.vault, codeHash === EMPTY_CODE ? [actions.deployContract(wasm), init] : [init]));
    config = await client.getConfig();
  }
  if (config && config.owner_id !== ownerId) throw new Error(`vault owner is ${config.owner_id}, not ${ownerId}; stopping`);

  // -- 6. guardian registered on the vault
  if (config?.guardians.includes(ids.guardian)) step('guardian on vault', 'skip', 'listed');
  else if (DRY || !config) step('guardian on vault', 'plan', `add_guardian(${ids.guardian}) if init did not list it`);
  else check('guardian on vault', await ownerCalls!.addGuardian(ids.guardian));

  // -- 7. agent registration
  const policy: PolicyLike = { ...POLICY, allowlist: [ids.shop] };
  const agent = config ? await client.getAgent(ids.agent) : null;
  if (agent && !DRY && JSON.stringify([...agent.policy.allowlist].sort()) !== JSON.stringify([ids.shop]))
    check('agent allowlist', await ownerCalls!.updatePolicy(ids.agent, { ...agent.policy, allowlist: [ids.shop] }));
  else if (agent) step('agent registration', 'skip', `status ${agent.status.state}`);
  else if (DRY || !config)
    step('agent registration', 'plan', `register_agent(${ids.agent}): max 1 / day 3 / approval above 0.5 / new payee 0.2 NEAR, 10 per hour, allowlist [${ids.shop}]`);
  else check('agent registration', await ownerCalls!.registerAgent(ids.agent, 'demo shopping agent', policy));

  // -- 8. canaries: random implicit ids, only their hashes go on chain
  let canaries: CanaryRecord[] | null = existsSync(CANARY_PATH) ? (JSON.parse(readFileSync(CANARY_PATH, 'utf8')) as CanaryRecord[]) : null;
  const onChain = config?.canaries ?? 0;
  if (canaries && onChain >= canaries.length) step('canaries', 'skip', `${onChain} on chain, ${canaries.length} in ${CANARY_PATH}`);
  else if (DRY || !config) step('canaries', 'plan', canaries ? `add_canaries for ${canaries.length} hashes from ${CANARY_PATH}` : `generate 2 canaries, save to ${CANARY_PATH}, add_canaries`);
  else {
    if (!canaries) {
      canaries = [newImplicitCanary(), newImplicitCanary()];
      mkdirSync(join(REPO_ROOT, '.spendfuse'), { recursive: true });
      writeFileSync(CANARY_PATH, `${JSON.stringify(canaries, null, 2)}\n`, { mode: 0o600 });
      log(`       canary ids saved to ${CANARY_PATH} (no secret keys)`);
    }
    check('canaries', await ownerCalls!.addCanaries(canaries.map((c) => c.hash))); // idempotent
  }

  // -- 9. working balance for the agent
  const available = config ? BigInt((await client.getConfig()).available) : 0n;
  const daily = BigInt(policy.daily_limit);
  if (NO_DEPOSIT) step('deposit', 'skip', '--no-deposit');
  else if (config && available >= daily) step('deposit', 'skip', `available ${formatNear(available)} NEAR >= daily limit`);
  else if (DRY || !config) step('deposit', 'plan', `deposit ${FUND.deposit} NEAR if available < ${formatNear(daily)} NEAR`);
  else check('deposit', await ownerCalls!.deposit(nearToYocto(FUND.deposit)));

  // -- proofs (public data only)
  log('');
  if (await accountInfo(provider, ids.agent)) {
    const keys = await listKeys(provider, ids.agent);
    const full = keys.filter((k) => k.fullAccess).length;
    log(`agent keys: ${keys.length} total, ${full} full-access${full ? '  <-- expected 0' : ''}`);
    for (const k of keys.filter((x) => !x.fullAccess))
      log(`  ${k.publicKey} -> ${k.receiverId} [${k.methodNames?.join(', ')}] allowance ${k.allowance == null ? 'unlimited' : `${formatNear(k.allowance)} NEAR`}`);
  }
  if (config) {
    const c = await client.getConfig();
    log(`vault: balance ${formatNear(c.balance)} NEAR, storage ${formatNear(c.storage_locked)}, available ${formatNear(c.available)}, agents ${c.agents}, guardians [${c.guardians.join(', ')}], canaries ${c.canaries}`);
  }
  log(`explorer: ${explorer.account(ids.vault)}`);
}

main().catch((err: unknown) => {
  const e = decodeContractError(err);
  console.error(`setup failed: ${e.message}${e.txHash ? ` (${explorer.tx(e.txHash)})` : ''}`);
  process.exitCode = 1;
});
