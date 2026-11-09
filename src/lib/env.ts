// env.ts - load .env from the repo root and read settings. Values are never logged.
import { appendFileSync, chmodSync, existsSync, readFileSync, writeFileSync } from 'node:fs';
import { fileURLToPath } from 'node:url';
import { join } from 'node:path';

/** Repo root (this file lives in src/lib). */
export const REPO_ROOT = fileURLToPath(new URL('../../', import.meta.url));
export const ENV_PATH = join(REPO_ROOT, '.env');

export type EnvName =
  | 'OWNER_ID'
  | 'OWNER_KEY'
  | 'VAULT_ID'
  | 'VAULT_KEY'
  | 'AGENT_ID'
  | 'AGENT_KEY'
  | 'GUARDIAN_ID'
  | 'GUARDIAN_KEY'
  | 'NEARAI_API_KEY'
  | 'OPENROUTER_API_KEY'
  | 'LLM_MODE'
  | (string & {});

export type LlmMode = 'scripted' | 'nearai' | 'openrouter';

/**
 * Demo payee accounts: <prefix>.<OWNER_ID> unless SHOP_ID / API_ID / DATA_ID is set. One table for
 * npm run setup, the attack demo (dry and live) and the FakeChain, so dry and live runs print the
 * same names. Earlier versions defaulted to shop. / api. / data.; set the *_ID variables to keep
 * using accounts created under those names.
 */
export const PAYEES = {
  shop: { env: 'SHOP_ID', prefix: 'store' },
  api: { env: 'API_ID', prefix: 'billing' },
  data: { env: 'DATA_ID', prefix: 'feed' },
} as const;
export type PayeeRole = keyof typeof PAYEES;

/** The payee id for a role: its env variable, else <prefix>.<ownerId>. */
export const payeeId = (role: PayeeRole, ownerId: string): string => getEnv(PAYEES[role].env) ?? `${PAYEES[role].prefix}.${ownerId}`;

let loaded = false;

/** Load .env once (variables already set in the process win). Returns true if a file was read. */
export function loadEnv(path: string = ENV_PATH): boolean {
  if (loaded && path === ENV_PATH) return true;
  if (!existsSync(path)) return false;
  process.loadEnvFile(path);
  if (path === ENV_PATH) loaded = true;
  return true;
}

/** Trimmed value, or undefined when unset or empty. */
export function getEnv(name: EnvName): string | undefined {
  const v = process.env[name]?.trim();
  return v ? v : undefined;
}

export function hasEnv(name: EnvName): boolean {
  return getEnv(name) !== undefined;
}

/** Throws a helpful error (naming the variable, never a value) when it is missing. */
export function requireEnv(name: EnvName, hint?: string): string {
  const v = getEnv(name);
  if (v === undefined) {
    const where = existsSync(ENV_PATH) ? `${ENV_PATH} (or the process environment)` : `the environment or a new ${ENV_PATH}`;
    throw new Error(`Missing ${name}: set it in ${where}.${hint ? ` ${hint}` : ''}`);
  }
  return v;
}

export function llmMode(): LlmMode {
  const m = getEnv('LLM_MODE') ?? 'scripted';
  if (m === 'scripted' || m === 'nearai' || m === 'openrouter') return m;
  throw new Error(`LLM_MODE must be scripted, nearai or openrouter (got ${JSON.stringify(m)})`);
}

/** Names defined in the .env file (values are not returned). */
export function envFileNames(path: string = ENV_PATH): Set<string> {
  if (!existsSync(path)) return new Set();
  const names = new Set<string>();
  for (const line of readFileSync(path, 'utf8').split(/\r?\n/)) {
    const m = line.match(/^\s*(?:export\s+)?([A-Za-z_][A-Za-z0-9_]*)\s*=/);
    if (m?.[1]) names.add(m[1]);
  }
  return names;
}

/**
 * Append NAME=value to .env (mode 0600) and set it in process.env. Refuses to overwrite a name
 * already in the file. Never prints the value.
 */
export function appendEnv(name: string, value: string, path: string = ENV_PATH): void {
  if (!/^[A-Za-z_][A-Za-z0-9_]*$/.test(name)) throw new Error(`bad env name ${name}`);
  if (/[\r\n]/.test(value)) throw new Error(`value for ${name} contains a newline`);
  if (envFileNames(path).has(name)) throw new Error(`${name} is already defined in ${path}; not overwriting`);
  if (!existsSync(path)) writeFileSync(path, '', { mode: 0o600 });
  const text = readFileSync(path, 'utf8');
  const sep = text.length && !text.endsWith('\n') ? '\n' : '';
  appendFileSync(path, `${sep}${name}=${value}\n`, { mode: 0o600 });
  chmodSync(path, 0o600);
  process.env[name] = value;
}
