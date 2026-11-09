// live-chain.ts - ChainBackend on a real vault: views through SpendfuseClient, agent calls signed by the
// agent's function-call key (AgentApi / makeSender), owner calls by the owner's full-access key.
// Constructing it sends nothing; every method that sends a transaction says so in its name.
import { createHash } from 'node:crypto';
import { Account, KeyPair, actions } from 'near-api-js';
import type { Provider, Signer } from 'near-api-js';
import { canaryHash } from '../lib/canary.ts';
import { explain } from '../lib/errors.ts';
import { explorer } from '../lib/near.ts';
import { makeSender } from '../lib/send.ts';
import { agentApi, ownerApi, toPolicyInput, SpendfuseClient } from '../lib/spendfuse.ts';
import type { AgentApi, CallResult, OwnerApi } from '../lib/spendfuse.ts';
import type { AgentView, CheckResult, PaymentResult, PolicyInput } from '../lib/types.ts';
import { createScout, ENDPOINTS, rpc, vaultBlocklist } from '../scout/counterparty.ts';
import type { CheckOptions } from '../scout/counterparty.ts';
import type { ChainBackend, ChainCall, OwnerOps, PayArgs, RawAction, ScoutSummary, TxRef } from './chain.ts';

export interface LiveChainOptions {
  provider: Provider;
  vaultId: string;
  agentId: string;
  agentSigner: Signer;
  ownerId?: string;
  ownerSigner?: Signer;
  /** extra scout options (allowlist and self are filled in from the vault; blocklist defaults to the vault's get_block_entry) */
  scout?: CheckOptions;
  rpcUrl?: string;
  /** StorageKey::Canaries prefix byte (enum order in contract/src/lib.rs: Agents=0, Canaries=1) */
  canaryPrefix?: number;
}

const ref = (method: string, actor: string, hash: string, ok: boolean): TxRef => ({ hash, url: explorer.tx(hash), method, actor, ok, simulated: false });

function fromCall<T>(r: CallResult<T>, method: string, actor: string): ChainCall<T> {
  return { result: r.result, tx: ref(method, actor, r.summary.hash, r.ok), error: r.error, errorKind: r.ok ? undefined : 'contract-panic' };
}

function fromError<T>(err: unknown, method: string, actor: string): ChainCall<T> {
  const e = explain(err);
  return { result: null, tx: e.txHash ? ref(method, actor, e.txHash, false) : null, error: e.message, errorKind: e.kind, reason: e.reason };
}

export class LiveChain implements ChainBackend {
  readonly kind = 'live' as const;
  readonly vaultId: string;
  readonly agentId: string;
  readonly client: SpendfuseClient;
  readonly #o: LiveChainOptions;
  readonly #agent: AgentApi;
  readonly #owner: OwnerApi | null;
  #scout: ReturnType<typeof createScout> | null = null;

  constructor(o: LiveChainOptions) {
    this.#o = o;
    this.vaultId = o.vaultId;
    this.agentId = o.agentId;
    this.client = new SpendfuseClient({ provider: o.provider, vaultId: o.vaultId });
    this.#agent = agentApi({ accountId: o.agentId, provider: o.provider, signer: o.agentSigner }, { vaultId: o.vaultId });
    this.#owner = o.ownerId && o.ownerSigner ? ownerApi({ accountId: o.ownerId, provider: o.provider, signer: o.ownerSigner }, { vaultId: o.vaultId }) : null;
  }

  checkPayment(receiverId: string, amount: bigint): Promise<CheckResult> {
    return this.client.checkPayment(this.agentId, receiverId, amount);
  }

  async #agentCall<T>(method: string, fn: () => Promise<CallResult<T>>): Promise<ChainCall<T>> {
    try {
      return fromCall(await fn(), method, this.agentId);
    } catch (err) {
      return fromError<T>(err, method, this.agentId);
    }
  }

  requestPayment(p: PayArgs): Promise<ChainCall<PaymentResult>> {
    return this.#agentCall('request_payment', () => this.#agent.requestPayment(p));
  }
  selfFreeze(reason: string): Promise<ChainCall<boolean>> {
    return this.#agentCall('self_freeze', () => this.#agent.selfFreeze(reason));
  }
  reportReceiver(receiverId: string, reason: string): Promise<ChainCall<unknown>> {
    return this.#agentCall('report_receiver', () => this.#agent.reportReceiver(receiverId, reason));
  }

  async getAgent(): Promise<AgentView> {
    const a = await this.client.getAgent(this.agentId);
    if (!a) throw new Error(`agent ${this.agentId} is not registered in ${this.vaultId}`);
    return a;
  }

  /** view_state prefix query for StorageKey::Canaries ++ sha256(account_id); exact key compare. Unverified layout. */
  async isCanary(receiverId: string): Promise<boolean> {
    const hash = createHash('sha256').update(receiverId, 'utf8').digest();
    const key = Buffer.concat([Buffer.from([this.#o.canaryPrefix ?? 1]), hash]).toString('base64');
    const res = await rpc(this.#o.rpcUrl ?? ENDPOINTS.testnet.rpc, 'query', {
      request_type: 'view_state',
      finality: 'final',
      account_id: this.vaultId,
      prefix_base64: key,
      include_proof: false,
    });
    const values: { key: string }[] = res?.values ?? [];
    return values.some((v) => v.key === key);
  }

  async scout(receiverId: string): Promise<ScoutSummary> {
    if (!this.#scout) {
      const agent = await this.getAgent();
      const network = this.#o.scout?.network ?? 'testnet';
      this.#scout = createScout({
        network,
        onUnavailable: 'warn',
        // the vault enforces its blocklist for the exact receiver only; the scout also checks parent accounts
        blocklist: vaultBlocklist(network, this.vaultId, { rpcUrl: this.#o.rpcUrl, timeoutMs: this.#o.scout?.timeoutMs }),
        ...this.#o.scout,
        allowlist: agent.policy.allowlist,
        self: { vault: this.vaultId, agent: this.agentId },
      });
    }
    const v = await this.#scout.check(receiverId);
    return { decision: v.decision, reasons: v.reasons.map((r) => ({ code: r.code, severity: r.severity, detail: r.detail })) };
  }

  /** Sends a raw function call with the agent key (no client-side key check, so the protocol decides). */
  async rawAgentCall(c: { receiverId: string; methodName: string; args: Record<string, unknown>; deposit?: bigint }): Promise<ChainCall<unknown>> {
    const send = makeSender(this.agentId, this.#o.provider, this.#o.agentSigner);
    try {
      const s = await send({ receiverId: c.receiverId, methodName: c.methodName, args: c.args, deposit: c.deposit ?? 0n });
      return { result: s.ok ? s.value : null, tx: ref(c.methodName, this.agentId, s.hash, s.ok), error: s.error, errorKind: s.ok ? undefined : 'tx-failed' };
    } catch (err) {
      return fromError(err, c.methodName, this.agentId);
    }
  }

  /** Signs and broadcasts a non-function-call action with the agent key; the RPC rejects it (RequiresFullAccess). */
  async rawAgentAction(action: RawAction, receiverId: string, amount = 1n): Promise<ChainCall<unknown>> {
    const signer = this.#o.agentSigner;
    try {
      const account = new Account(this.agentId, this.#o.provider, signer);
      const publicKey = await signer.getPublicKey();
      const act = action === 'transfer' ? actions.transfer(amount)
        : action === 'add_full_access_key' ? actions.addFullAccessKey(KeyPair.fromRandom('ed25519').getPublicKey())
        : actions.deleteAccount(receiverId);
      // add_full_access_key and delete_account act on the signer's own account
      const target = action === 'transfer' ? receiverId : this.agentId;
      const tx = await account.createTransaction({ receiverId: target, publicKey, actions: [act] });
      const { signedTransaction } = await signer.signTransaction(tx);
      await this.#o.provider.sendTransactionUntil(signedTransaction, 'EXECUTED_OPTIMISTIC');
      return { result: null, tx: null, error: 'unexpected: the transaction was accepted', errorKind: 'accepted' };
    } catch (err) {
      return fromError(err, action, this.agentId);
    }
  }

  #requireOwner(): OwnerApi {
    if (!this.#owner) throw new Error('owner signer not configured');
    return this.#owner;
  }
  async #ownerCall<T>(method: string, fn: (o: OwnerApi) => Promise<CallResult<T>>): Promise<ChainCall<T>> {
    const o = this.#requireOwner();
    try {
      return fromCall(await fn(o), method, o.accountId);
    } catch (err) {
      return fromError<T>(err, method, o.accountId);
    }
  }

  readonly owner: OwnerOps = {
    unfreeze: () => this.#ownerCall('unfreeze_agent', (o) => o.unfreezeAgent(this.agentId)),
    unpause: () => this.#ownerCall('unpause', (o) => o.unpause()),
    approve: (id) => this.#ownerCall('approve', (o) => o.approve(id)),
    reject: (id, reason) => this.#ownerCall('reject', (o) => o.reject(id, reason)),
    addCanary: async (accountId) => this.#ownerCall('add_canaries', (o) => o.addCanaries([canaryHash(accountId)])),
    updatePolicy: async (patch: Partial<PolicyInput>) => {
      const agent = await this.getAgent();
      // a past expires_at_ms makes update_policy panic; it is kept on purpose (dropping it would loosen the policy)
      const policy = { ...toPolicyInput(agent.policy), ...patch };
      return this.#ownerCall('update_policy', (o) => o.updatePolicy(this.agentId, policy));
    },
  };
}
