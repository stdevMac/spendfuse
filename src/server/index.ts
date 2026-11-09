// index.ts - Spendfuse dashboard server entry point.
//   node src/server/index.ts            local mode on 127.0.0.1:8787 (PORT, HOST override)
//   READONLY=1 node src/server/index.ts  public mode: every POST route is disabled
// Actions (approve / reject / freeze / unfreeze / pause / unpause) need OWNER_KEY or GUARDIAN_KEY,
// a loopback bind and the per-process token printed below. Views are read-only RPC calls.
import { getEnv, loadEnv } from '../lib/env.ts';
import { liveBackend } from './backend.ts';
import { createDashboard, DEFAULT_HOST, DEFAULT_PORT } from './app.ts';

export { createDashboard } from './app.ts';
export type { Dashboard, DashboardOptions } from './app.ts';
export type { Backend, Signers, Views } from './backend.ts';

async function main(): Promise<void> {
  loadEnv();
  const readonly = getEnv('READONLY') === '1' || getEnv('READONLY') === 'true';
  const host = getEnv('HOST') ?? DEFAULT_HOST;
  const portRaw = getEnv('PORT');
  const port = portRaw === undefined ? DEFAULT_PORT : Number(portRaw);
  if (!Number.isInteger(port) || port < 0 || port > 65535) throw new Error('PORT must be 0..65535');

  const backend = liveBackend({ withSigners: !readonly });
  const dash = await createDashboard({ backend, host, port, readonly });
  console.log(`Spendfuse dashboard for ${backend.vaultId} (${backend.network})`);
  if (readonly) console.log(`  READONLY mode: actions disabled. ${dash.url}/`);
  else if (dash.actionsEnabled) {
    console.log(`  actions enabled for ${backend.signers?.role} ${backend.signers?.accountId}`);
    console.log(`  open: ${dash.url}/?token=${dash.token}`);
    console.log('  (the token is valid until this process exits; do not share it)');
  } else {
    console.log(`  view-only (no OWNER_KEY / GUARDIAN_KEY, or not bound to loopback). ${dash.url}/`);
  }
  const stop = () => {
    void dash.close().then(() => process.exit(0));
  };
  process.on('SIGINT', stop);
  process.on('SIGTERM', stop);
}

if (import.meta.main) {
  main().catch((err: unknown) => {
    console.error(`dashboard failed: ${err instanceof Error ? err.message : String(err)}`);
    process.exitCode = 1;
  });
}
