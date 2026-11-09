// canary.ts - canary hashes for add_canaries / remove_canary: lowercase hex sha256 of the utf8 account id,
// the same bytes as env::sha256_array(account_id) in the contract. (src/scout/canary.ts canaryHash is base58
// for an older interface; do not use it with this contract.)
import { createHash } from 'node:crypto';
import { validateAccountId } from './near.ts';
import { newImplicitCanary as newImplicit } from '../scout/canary.ts';

export function canaryHash(accountId: string): string {
  const problem = validateAccountId(accountId);
  if (problem) throw new Error(`not a valid NEAR account id (${problem}): ${accountId}`);
  return createHash('sha256').update(accountId, 'utf8').digest('hex');
}

export interface CanaryRecord {
  /** 64-hex implicit account id: high entropy, so the hash cannot be guessed from a dictionary */
  accountId: string;
  /** hex sha256 of accountId, what the contract stores */
  hash: string;
  publicKey: string;
}

/**
 * A fresh implicit-account canary. The secret key is deliberately dropped: nothing should ever be
 * signed by a canary, and secrets live only in .env.
 */
export function newImplicitCanary(): CanaryRecord {
  const { accountId, publicKey } = newImplicit();
  return { accountId, hash: canaryHash(accountId), publicKey };
}
