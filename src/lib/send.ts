// send.ts - send one function call signed by the agent's FUNCTION-CALL access key.
// The hash is computed and handed to onHash() BEFORE broadcasting, a timeout never leads to a
// second signature (that could double-spend), and the result is decoded with summarize().
// Tested in test/offline.test.ts against a local stub RPC with a zero-signature signer.
import { Account, actions, baseEncode, teraToGas } from 'near-api-js';
import type { Provider, SignedTransaction, Signer, TxExecutionStatus } from 'near-api-js';
import { isTransient, unwrap } from './errors.ts';
import { summarize } from './near.ts';
import type { TxResult, TxSummary } from './near.ts';

export interface SendArgs {
  receiverId: string;
  methodName: string;
  args?: Record<string, unknown> | Uint8Array;
  /** prepaid gas. It is charged against the key's allowance up front at max(gas_price, min_gas_purchase_price)
   *  = 1e9 yocto/gas on testnet today: 50 TGas = 0.05 NEAR of allowance; the unused part is refunded to it. */
  gas?: bigint;
  /** must be 0n for a function-call key (DepositWithFunctionCall) */
  deposit?: bigint;
  /** persist the hash (incident log, dashboard) before the tx is broadcast */
  onHash?: (hash: string) => unknown;
}

export interface SenderOptions {
  /** how long to keep polling after a timeout / network error */
  budgetMs?: number;
  baseDelayMs?: number;
  waitUntil?: TxExecutionStatus;
}

const sleep = (ms: number) => new Promise((resolve) => setTimeout(resolve, ms));
const nameOf = (err: unknown) => (unwrap(err) as { name?: string } | null)?.name;

/** true if the network already knows this tx hash (so it must not be re-signed). */
async function isKnown(provider: Provider, txHash: string, accountId: string): Promise<boolean> {
  try {
    await provider.viewTransactionStatus({ txHash, accountId, waitUntil: 'NONE' });
    return true;
  } catch (err) {
    if (nameOf(err) === 'UnknownTransactionError') return false;
    throw err;
  }
}

async function waitForTx(
  provider: Provider,
  txHash: string,
  accountId: string,
  signedTransaction: SignedTransaction,
  { budgetMs, baseDelayMs, waitUntil }: Required<SenderOptions>,
): Promise<TxResult> {
  const deadline = Date.now() + budgetMs;
  for (let delay = baseDelayMs; Date.now() < deadline; delay = Math.min(delay * 2, 10 * baseDelayMs)) {
    try {
      return await provider.viewTransactionStatus({ txHash, accountId, waitUntil });
    } catch (err) {
      if (nameOf(err) === 'UnknownTransactionError') {
        // Not seen (yet). Re-sending the SAME signed bytes is safe: same hash, same nonce.
        await provider.sendTransactionUntil(signedTransaction, 'NONE').catch(() => {});
      } else if (!isTransient(err)) {
        throw err;
      }
    }
    await sleep(delay);
  }
  throw new Error(`tx ${txHash} not resolved within ${budgetMs} ms; look it up later by hash`);
}

/** One sender per (account, key). Throws the typed near-api-js error on rejection: use explain(err). */
export function makeSender(accountId: string, provider: Provider, signer: Signer, opts: SenderOptions = {}) {
  const o: Required<SenderOptions> = { budgetMs: 120_000, baseDelayMs: 1_000, waitUntil: 'EXECUTED_OPTIMISTIC', ...opts };
  let account = new Account(accountId, provider, signer);
  return async function send({ receiverId, methodName, args = {}, gas = teraToGas('50'), deposit = 0n, onHash }: SendArgs): Promise<TxSummary> {
    for (let attempt = 0; ; attempt++) {
      const publicKey = await signer.getPublicKey();
      // NB: actions.functionCall() defaults gas to 0n; always pass it.
      const tx = await account.createTransaction({ receiverId, publicKey, actions: [actions.functionCall(methodName, args, gas, deposit)] });
      const { txHash, signedTransaction } = await signer.signTransaction(tx);
      const hash = baseEncode(txHash);
      await onHash?.(hash);
      try {
        return summarize(hash, await provider.sendTransactionUntil(signedTransaction, o.waitUntil));
      } catch (err) {
        if (nameOf(err) === 'InvalidNonceError' && attempt < 3) {
          // Our nonce was stale. If this exact tx is already known it went through: follow it.
          if (await isKnown(provider, hash, accountId)) return summarize(hash, await waitForTx(provider, hash, accountId, signedTransaction, o));
          account = new Account(accountId, provider, signer); // the nonce cache is private: start a fresh one
          continue; // a tx rejected for its nonce can never execute later, so re-signing is safe
        }
        if (!isTransient(err)) throw err; // rejected (access key, balance, expired ...): nothing on chain
        return summarize(hash, await waitForTx(provider, hash, accountId, signedTransaction, o));
      }
    }
  };
}
