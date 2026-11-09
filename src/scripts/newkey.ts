// newkey.ts - make an ed25519 key and append NAME=secret to .env (mode 0600). Only the public key is printed.
// Usage: node src/scripts/newkey.ts OWNER_KEY
import { KeyPair } from 'near-api-js';
import { appendEnv, ENV_PATH } from '../lib/env.ts';

const name = process.argv[2];
if (!name) {
  console.error('usage: node src/scripts/newkey.ts NAME   (e.g. OWNER_KEY)');
  process.exit(2);
}
const kp = KeyPair.fromRandom('ed25519');
appendEnv(name, kp.toString());
console.log(`${name} written to ${ENV_PATH}; public key: ${kp.getPublicKey().toString()}`);
