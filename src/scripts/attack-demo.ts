// attack-demo.ts - run the Spendfuse attack scenarios and narrate what the guard and the vault did.
//   node src/scripts/attack-demo.ts --dry-run            in-memory FakeChain, scripted model, nothing sent
//   node src/scripts/attack-demo.ts --live [--only=1,4]  testnet: sends real transactions (agent + owner keys)
// Options: --only=<n|id,...>  --llm=scripted|nearai|openrouter (default LLM_MODE)  --attest  --leave-frozen
// Writes .spendfuse/runs/<timestamp>.json (gitignored). Secrets are read from .env and never printed.
import { chmodSync, existsSync, mkdirSync, readFileSync, writeFileSync } from 'node:fs';
import { join } from 'node:path';
import type { KeyPairString } from 'near-api-js';
import { getEnv, llmMode, loadEnv, payeeId, REPO_ROOT, requireEnv } from '../lib/env.ts';
import type { LlmMode } from '../lib/env.ts';
import { newImplicitCanary } from '../lib/canary.ts';
import type { CanaryRecord } from '../lib/canary.ts';
import { makeProvider, signerFromSecret } from '../lib/near.ts';
import { FakeChain } from '../agent/chain.ts';
import type { ChainBackend } from '../agent/chain.ts';
import { LiveChain } from '../agent/live-chain.ts';
import { makeAgentLlm } from '../agent/llm.ts';
import type { AgentLlm } from '../agent/llm.ts';
import type { TranscriptEntry } from '../agent/runtime.ts';
import { runScenario, selectScenarios } from '../agent/scenarios.ts';
import type { ScenarioIds, ScenarioRun } from '../agent/scenarios.ts';

export const CANARY_PATH = join(REPO_ROOT, '.spendfuse/canaries.json');
export const RUNS_DIR = join(REPO_ROOT, '.spendfuse/runs');

export interface DemoArgs {
  dry: boolean;
  live: boolean;
  only?: string;
  llm: LlmMode;
  attest: boolean;
  leaveFrozen: boolean;
}

export function parseArgs(argv: string[]): DemoArgs {
  const a: DemoArgs = { dry: false, live: false, llm: 'scripted', attest: false, leaveFrozen: false };
  let llm: string | undefined;
  for (const arg of argv) {
    if (arg === '--dry-run') a.dry = true;
    else if (arg === '--live') a.live = true;
    else if (arg === '--attest') a.attest = true;
    else if (arg === '--leave-frozen') a.leaveFrozen = true;
    else if (arg.startsWith('--only=')) a.only = arg.slice(7);
    else if (arg.startsWith('--llm=')) llm = arg.slice(6);
    else throw new Error(`unknown argument ${arg}`);
  }
  if (a.dry === a.live) throw new Error('pass exactly one of --dry-run (fake chain) or --live (testnet, sends transactions)');
  // a dry run stays offline and free unless a model is asked for explicitly
  a.llm = (llm ?? (a.dry ? 'scripted' : llmMode())) as LlmMode;
  if (!['scripted', 'nearai', 'openrouter'].includes(a.llm)) throw new Error(`unknown --llm=${a.llm}`);
  return a;
}

const ICON: Record<string, string> = {
  user: 'task  ', assistant: 'model ', tool_call: 'tool  ', tool_result: '  ->  ', guard: 'guard ', chain: 'chain ',
  approval: 'HUMAN ', attacker: 'ATTACK', owner: 'owner ', check: 'check ', note: '      ', error: 'ERROR ', system: 'sys   ',
};

export function narrate(e: TranscriptEntry): string {
  const url = (e.data as { url?: string; simulated?: boolean } | undefined);
  const link = url?.url ? `\n           ${url.url}${url.simulated ? ' (simulated, not on chain)' : ''}` : '';
  const text = e.text.length > 400 ? `${e.text.slice(0, 400)}...` : e.text;
  return `  ${ICON[e.kind] ?? e.kind} ${text.replace(/\n/g, '\n           ')}${link}`;
}

function loadCanaries(): CanaryRecord[] {
  if (!existsSync(CANARY_PATH)) return [];
  try {
    return JSON.parse(readFileSync(CANARY_PATH, 'utf8')) as CanaryRecord[];
  } catch {
    return [];
  }
}

export function saveCanary(c: CanaryRecord): void {
  mkdirSync(join(REPO_ROOT, '.spendfuse'), { recursive: true, mode: 0o700 });
  writeFileSync(CANARY_PATH, JSON.stringify([...loadCanaries(), c], null, 2) + '\n', { mode: 0o600 });
}

/** Dry-run owner when OWNER_ID is unset: the live demo deployment, so dry and live logs line up. */
export const DRY_OWNER_ID = 'tw-firewall-demo.testnet';

export interface DemoSetup {
  chain: ChainBackend;
  ids: Omit<ScenarioIds, 'canary'>;
}

export function idsFor(ownerId: string): Omit<ScenarioIds, 'canary'> {
  return {
    owner: ownerId,
    vault: getEnv('VAULT_ID') ?? `vault.${ownerId}`,
    agent: getEnv('AGENT_ID') ?? `agent.${ownerId}`,
    shop: payeeId('shop', ownerId),
    api: payeeId('api', ownerId),
    attacker: getEnv('ATTACKER_ID') ?? payeeId('data', ownerId),
    ghost: `ghost-${Date.now().toString(36)}.${ownerId}`,
  };
}

export function setupChain(dry: boolean): DemoSetup {
  loadEnv();
  const ownerId = dry ? getEnv('OWNER_ID') ?? DRY_OWNER_ID : requireEnv('OWNER_ID');
  const ids = idsFor(ownerId);
  if (dry) {
    const chain = new FakeChain({
      ownerId, vaultId: ids.vault, agentId: ids.agent,
      accounts: [ownerId, ids.vault, ids.agent, ids.shop, ids.api, ids.attacker],
      policy: { allowlist: [ids.shop] },
    });
    return { chain, ids };
  }
  const provider = makeProvider();
  const chain = new LiveChain({
    provider,
    vaultId: ids.vault,
    agentId: ids.agent,
    agentSigner: signerFromSecret(requireEnv('AGENT_KEY') as KeyPairString),
    ownerId,
    ownerSigner: signerFromSecret(requireEnv('OWNER_KEY') as KeyPairString),
  });
  return { chain, ids };
}

/** A canary for the run: the first one in .spendfuse/canaries.json (live), or a fresh one planted now. */
export async function canaryFor(chain: ChainBackend, out: (s: string) => void): Promise<string> {
  if (chain.kind === 'live') {
    const known = loadCanaries()[0];
    if (known) return known.accountId;
  }
  const c = newImplicitCanary();
  const r = await chain.owner.addCanary(c.accountId);
  if (r.error) throw new Error(`could not plant a canary: ${r.error}`);
  if (chain.kind === 'live') saveCanary(c);
  out(`planted canary ${c.accountId.slice(0, 8)}... (${r.tx?.url ?? 'no tx'})`);
  return c.accountId;
}

/** Replace every full canary id in a serialized record with its first 8 chars + '…' (covers transcripts too). */
export function redactIds(text: string, ids: readonly string[]): string {
  let out = text;
  for (const id of ids) if (id && id.length > 8) out = out.split(id).join(`${id.slice(0, 8)}…`);
  return out;
}

const replacer = (_k: string, v: unknown) => (typeof v === 'bigint' ? v.toString() : v);

export function runRecord(r: ScenarioRun) {
  return {
    n: r.n, id: r.id, title: r.title, expected: r.expected, pass: r.pass, why: r.why, outcomes: r.outcomes,
    frozenAfter: r.frozenAfter, startedAt: r.startedAt, finishedAt: r.finishedAt,
    verdict: r.agent?.verdict ?? null, turns: r.agent?.turns ?? [],
    txs: r.log.txs, approvals: r.log.approvals, transcript: r.log.entries,
  };
}

async function main() {
  loadEnv(); // before parseArgs so LLM_MODE from .env applies to --live
  const args = parseArgs(process.argv.slice(2));
  const scenarios = selectScenarios(args.only);
  const { chain, ids: baseIds } = setupChain(args.dry);
  const out = (s: string) => console.log(s);
  out(`Spendfuse attack demo - ${args.dry ? 'DRY RUN (fake chain, nothing sent)' : 'LIVE on testnet'} - model: ${args.llm}`);
  out(`vault ${chain.vaultId}, agent ${chain.agentId}, ${scenarios.length} scenario(s)`);
  // run order is not numeric: the scenarios that leave the agent frozen (4, 3) go last, so the
  // others start from an active agent; [n] below is the scenario's own number
  out(`run order: ${scenarios.map((s) => s.n).join(', ')} (scenarios that freeze the agent run last; [n] is the scenario number)\n`);

  const ids: ScenarioIds = { ...baseIds, canary: scenarios.some((s) => s.id === 'canary') ? await canaryFor(chain, out) : '' };
  let shared: AgentLlm | null = null;
  const llmFor = async (s: (typeof scenarios)[number]) => {
    if (args.llm === 'scripted') return makeAgentLlm('scripted', { turns: s.script(ids) });
    shared ??= await makeAgentLlm(args.llm, { attest: args.attest });
    return shared;
  };

  // Re-runs within an hour: escalations and payments from earlier runs still sit in the vault's
  // sliding 1h window, so the scripted scenarios would hit RATE_LIMITED early. Give this run the
  // headroom the earlier runs used (the cap a fresh run sees is unchanged) and restore it after.
  // Same for the 24h daily limit: earlier runs' spending and reservations stay in that window.
  const restore: { max_payments_per_hour?: number; daily_limit?: string } = {};
  const fmt = (y: bigint) => `${Number(y / 10n ** 20n) / 10_000} NEAR`;
  let cleaned: Promise<void> | null = null;
  // Unfreeze (unless --leave-frozen) and restore the lifted limits. Runs once: from finally or on Ctrl-C.
  const cleanup = (): Promise<void> => (cleaned ??= (async () => {
    if (!args.leaveFrozen) {
      try {
        const a = await chain.getAgent();
        if (a.status.state === 'frozen') {
          const r = await chain.owner.unfreeze();
          out(`cleanup: owner unfroze the agent${r.tx ? ` (${r.tx.url})` : ''}${r.error ? ` - failed: ${r.error}` : ''}`);
        }
      } catch (e) {
        out(`cleanup failed: ${(e as Error).message}`);
      }
    }
    if (Object.keys(restore).length) {
      const what = Object.entries(restore).map(([k, v]) => `${k} to ${k === 'daily_limit' ? fmt(BigInt(v)) : v}`).join(', ');
      try {
        const r = await chain.owner.updatePolicy(restore);
        out(`cleanup: owner restored ${what}${r.tx ? ` (${r.tx.url})` : ''}${r.error ? ` - failed: ${r.error}` : ''}`);
      } catch (e) {
        out(`cleanup: restoring ${what} failed: ${(e as Error).message}`);
      }
    }
  })());
  let interrupted = false;
  process.once('SIGINT', () => {
    interrupted = true;
    out('\ninterrupted: cleaning up before exit (Ctrl-C again to abort cleanup)');
    cleanup().finally(() => process.exit(130));
  });

  const startedAt = new Date();
  const runs: ScenarioRun[] = [];
  try {
    if (chain.kind === 'live') {
      const a = await chain.getAgent();
      const used = a.payments_last_hour;
      const committed = BigInt(a.spent_24h) + BigInt(a.reserved);
      const lift: { max_payments_per_hour?: number; daily_limit?: string } = {};
      const notes: string[] = [];
      if (used > 0) {
        const current = a.policy.max_payments_per_hour;
        lift.max_payments_per_hour = Math.min(300, current + used);
        notes.push(`${used} payment(s) from earlier runs are still in the 1h window: max_payments_per_hour ${current} -> ${lift.max_payments_per_hour}`);
      }
      if (committed > 0n) {
        const current = BigInt(a.policy.daily_limit);
        lift.daily_limit = (current + committed).toString();
        notes.push(`${fmt(committed)} from earlier runs is still in the 24h window: daily_limit ${fmt(current)} -> ${fmt(current + committed)}`);
      }
      if (notes.length) {
        // record first: a timed-out update may still land, and restoring to the current values is harmless
        if (lift.max_payments_per_hour !== undefined) restore.max_payments_per_hour = a.policy.max_payments_per_hour;
        if (lift.daily_limit !== undefined) restore.daily_limit = String(a.policy.daily_limit);
        const r = await chain.owner.updatePolicy(lift);
        out(`note: owner gives this run the headroom earlier runs used (a fresh vault sees the unchanged policy)${r.tx ? ` (${r.tx.url})` : ''}${r.error ? ` - failed: ${r.error}` : ''}`);
        for (const n of notes) out(`  - ${n}`);
        out('');
      }
    }

    for (const s of scenarios) {
      if (interrupted) break;
      out(`[${s.n}] ${s.title}`);
      out(`    expected: ${s.expected}`);
      const run = await runScenario(s, { chain, ids, llmFor, onEntry: (e) => out(narrate(e)) });
      runs.push(run);
      out(`  ${run.pass ? '✓ PASS' : '✗ FAIL'} ${run.why}\n`);
    }
  } finally {
    await cleanup();
  }

  const passed = runs.filter((r) => r.pass).length;
  out(`${passed}/${runs.length} scenarios behaved as expected`);
  mkdirSync(RUNS_DIR, { recursive: true, mode: 0o700 });
  chmodSync(RUNS_DIR, 0o700); // mode above only applies when the dir is created
  const file = join(RUNS_DIR, `${startedAt.toISOString().replace(/[:.]/g, '-')}.json`);
  const record = {
    startedAt: startedAt.toISOString(), finishedAt: new Date().toISOString(), dryRun: args.dry, llm: args.llm,
    vault: chain.vaultId, agent: chain.agentId, ids: { ...ids, canary: ids.canary ? `${ids.canary.slice(0, 8)}...` : '' },
    passed, total: runs.length, scenarios: runs.map(runRecord),
  };
  const known = [ids.canary, ...loadCanaries().map((c) => c.accountId)];
  writeFileSync(file, redactIds(JSON.stringify(record, replacer, 2), known) + '\n', { mode: 0o600 });
  out(`run saved to ${file}`);
  if (passed !== runs.length) process.exitCode = 1;
}

if (import.meta.main) {
  main().catch((e) => {
    console.error(`attack-demo failed: ${(e as Error).message}`);
    process.exitCode = 1;
  });
}
