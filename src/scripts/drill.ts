// drill.ts - canary drill: plant a fresh canary, have the agent pay it, confirm the vault froze the agent,
// then have the owner unfreeze it.
//   node src/scripts/drill.ts --dry-run   in-memory FakeChain, nothing sent
//   node src/scripts/drill.ts --live      testnet: add_canaries + request_payment + unfreeze (real transactions)
// The canary account id is appended to .spendfuse/canaries.json in live mode (no secret key is kept).
import { mkdirSync, writeFileSync } from 'node:fs';
import { join } from 'node:path';
import { newImplicitCanary } from '../lib/canary.ts';
import type { ChainBackend } from '../agent/chain.ts';
import { REFUSED } from '../agent/guard.ts';
import { makeAgentLlm } from '../agent/llm.ts';
import { RunLog, runAgent } from '../agent/runtime.ts';
import type { TranscriptEntry } from '../agent/runtime.ts';
import { narrate, RUNS_DIR, saveCanary, setupChain } from './attack-demo.ts';

export interface DrillResult {
  pass: boolean;
  steps: { step: string; ok: boolean; detail: string }[];
  log: RunLog;
}

/** Runs the drill against any backend. Leaves the agent unfrozen when it succeeds. */
export async function runDrill(chain: ChainBackend, onEntry?: (e: TranscriptEntry) => void): Promise<DrillResult> {
  const log = new RunLog(onEntry);
  const steps: DrillResult['steps'] = [];
  const step = (s: string, ok: boolean, detail: string) => {
    steps.push({ step: s, ok, detail });
    log.add('check', `${ok ? '✓' : '✗'} ${s}: ${detail}`);
    return ok;
  };
  const done = () => ({ pass: steps.every((s) => s.ok), steps, log });

  const start = await chain.getAgent();
  if (start.status.state === 'frozen') {
    log.add('owner', `agent starts frozen (${start.status.reason}); owner unfreezes it first`);
    log.chain('owner unfreeze', await chain.owner.unfreeze());
  }

  const c = newImplicitCanary();
  const planted = log.chain('owner add_canaries', await chain.owner.addCanary(c.accountId));
  if (!step('plant canary', !planted.error, planted.error ?? `canary ${c.accountId.slice(0, 8)}... planted`)) return done();
  if (chain.kind === 'live') saveCanary(c);
  const probe = await chain.isCanary(c.accountId).catch(() => false);
  step('guard sees the canary', probe, probe ? 'canary probe matches' : 'canary probe did not match (storage layout?)');

  const llm = await makeAgentLlm('scripted', {
    turns: [{ content: 'Paying the listed vendor.', tool_calls: [{ name: 'pay', arguments: { receiver_id: c.accountId, amount_near: '0.01', memo: 'canary drill' } }] }],
  });
  const run = await runAgent({ llm, chain, task: 'Canary drill: pay 0.01 NEAR to the listed vendor.', log, maxSteps: 3 });
  const payMsg = run.toolMessages.find((m) => m.tool === 'pay')?.content;
  step('payment tripped the vault', run.payOutcomes.includes('tripped'), run.payOutcomes.join(', ') || 'no payment');
  step('model told only "refused"', payMsg === REFUSED, JSON.stringify(payMsg));

  const after = await chain.getAgent();
  const frozen = after.status.state === 'frozen';
  step('agent frozen', frozen, after.status.state === 'frozen' ? `reason: ${after.status.reason}` : 'agent is still active');
  if (frozen) {
    const u = log.chain('owner unfreeze', await chain.owner.unfreeze());
    const back = (await chain.getAgent()).status.state;
    step('owner unfroze the agent', !u.error && back !== 'frozen', u.error ?? `state: ${back}`);
  }
  return done();
}

async function main() {
  const argv = process.argv.slice(2);
  const dry = argv.includes('--dry-run');
  const live = argv.includes('--live');
  const bad = argv.filter((a) => a !== '--dry-run' && a !== '--live');
  if (bad.length || dry === live) throw new Error('usage: drill.ts --dry-run | --live');
  const { chain } = setupChain(dry);
  console.log(`Spendfuse canary drill - ${dry ? 'DRY RUN (fake chain, nothing sent)' : 'LIVE on testnet'}`);
  const r = await runDrill(chain, (e) => console.log(narrate(e)));
  console.log(r.pass ? '✓ drill passed' : '✗ drill failed');
  mkdirSync(RUNS_DIR, { recursive: true });
  const file = join(RUNS_DIR, `drill-${new Date().toISOString().replace(/[:.]/g, '-')}.json`);
  writeFileSync(file, JSON.stringify({ dryRun: dry, pass: r.pass, steps: r.steps, txs: r.log.txs, transcript: r.log.entries }, (_k, v) => (typeof v === 'bigint' ? v.toString() : v), 2) + '\n');
  console.log(`saved ${file}`);
  if (!r.pass) process.exitCode = 1;
}

if (import.meta.main) {
  main().catch((e) => {
    console.error(`drill failed: ${(e as Error).message}`);
    process.exitCode = 1;
  });
}
