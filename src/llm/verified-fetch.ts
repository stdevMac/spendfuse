// verified-fetch.ts - per-turn TEE receipts for ANY OpenAI-SDK client on NEAR AI Cloud (no @nearai/inference-sdk needed).
//   createCapturingFetch() keeps the exact request/response bytes of each non-streaming chat completion (by id);
//   verifyCompletion() fetches GET /v1/signature/{id} and checks it against those bytes and the attested signers.
//   Plug receiptVerifier() into runAgent({ verify }) so no tool (e.g. `pay`) runs on an unverified model turn.
// deps: openai@7.53.0 + receipts.ts / near-attest.ts deps. Node >= 24 (type stripping).
// "attested signers" = keys from a genuine TDX (+ NVIDIA GPU for models) report; code measurements are pinned only
// when NEARAI_PINNED_COMPOSE_HASHES is set, and TLS is not bound to the attestation (see near-attest.ts header).
import { fetchAndVerify } from './near-attest.ts';
import {
  fetchReceipt,
  gatewayReceiptText,
  modelReceiptText,
  sha256hex,
  verifyReceiptSignature,
  type Attestation,
  type Receipt,
  type SigningAlgo,
} from './receipts.ts';

export interface Captured { model: string; req: Uint8Array; res: Uint8Array; servedBy: string | null }

const sameHex = (a: string, b: string) => a.replace(/^0x/i, '').toLowerCase() === b.replace(/^0x/i, '').toLowerCase();
const bytesOf = (b: unknown): Uint8Array | undefined =>
  typeof b === 'string' ? new TextEncoder().encode(b) // openai@7 hands fetch a JSON string for chat requests
  : b instanceof ArrayBuffer ? new Uint8Array(b)
  : ArrayBuffer.isView(b) ? new Uint8Array(b.buffer, b.byteOffset, b.byteLength)
  : undefined;

/** Pass `.fetch` to new OpenAI({ fetch }) or makeClient('near', { fetch }). Keeps the last `max` completions. */
export function createCapturingFetch(base: typeof fetch = fetch, max = 256) {
  const captured = new Map<string, Captured>();
  const capturingFetch = (async (input: Parameters<typeof fetch>[0], init?: Parameters<typeof fetch>[1]) => {
    const res = await base(input, init);
    const url = new URL(input instanceof Request ? input.url : String(input));
    const req = bytesOf(init?.body);
    if (!res.ok || !url.pathname.endsWith('/chat/completions') || !req) return res;
    let model: unknown;
    let stream: unknown;
    try {
      ({ model, stream } = JSON.parse(new TextDecoder().decode(req)));
    } catch {
      return res;
    }
    if (stream === true || typeof model !== 'string') return res; // streams get gateway receipts: never captured, so verify fails closed
    const resBytes = new Uint8Array(await res.clone().arrayBuffer()); // decoded body = the bytes the TEE signed
    let id: unknown;
    try {
      id = JSON.parse(new TextDecoder().decode(resBytes)).id;
    } catch {
      return res;
    }
    if (typeof id === 'string') {
      captured.set(id, { model, req, res: resBytes, servedBy: res.headers.get('x-serving-provider') });
      if (captured.size > max) captured.delete(captured.keys().next().value as string);
    }
    return res;
  }) as typeof fetch;
  return { fetch: capturingFetch, captured };
}

/** `signingAddress` set: the report of that one model replica (GET /v1/attestation/report?signing_address=...). */
export type GetAttestation = (model: string, force?: boolean, signingAddress?: string) => Promise<Attestation>;
type Fetcher = (model: string, algo: SigningAlgo, acceptedTcb: readonly string[], signingAddress?: string) => Promise<Attestation>;

/** Attestation cache keyed by model, or by model + signer. Caches the PROMISE (concurrent turns share one fetch:
 *  cloud-api serves at most 8 concurrent ANONYMOUS report requests per instance, then 429 + Retry-After: 1; see
 *  crates/api/src/routes/attestation/report.rs ANONYMOUS_REPORT_CONCURRENCY) and forgets failures.
 *  `algo` must match verifyCompletion's. `fetcher` is only for tests. */
export function attestationCache(
  algo: SigningAlgo = 'ecdsa',
  { ttlMs = 60 * 60_000, acceptedTcb = ['UpToDate'], fetcher = fetchAndVerify }: { ttlMs?: number; acceptedTcb?: readonly string[]; fetcher?: Fetcher } = {},
): GetAttestation {
  const cache = new Map<string, { at: number; att: Promise<Attestation> }>();
  return (model, force = false, signingAddress) => {
    const key = signingAddress ? `${model}@${signingAddress.replace(/^0x/i, '').toLowerCase()}` : model;
    const hit = cache.get(key);
    if (hit && !force && Date.now() - hit.at <= ttlMs) return hit.att;
    const att = fetcher(model, algo, acceptedTcb, signingAddress);
    cache.set(key, { at: Date.now(), att });
    att.catch(() => {
      if (cache.get(key)?.att === att) cache.delete(key);
    });
    return att;
  };
}

export interface VerifyOptions {
  apiKey?: string;
  algo?: SigningAlgo; // default 'ecdsa' (EIP-191, ecrecover-able on NEAR); must match the attestation's algo
  allowGatewayReceipt?: boolean; // default false: only provider_tee (model TEE) receipts pass
  fetchImpl?: typeof fetch; // for GET /v1/signature; defaults to the global fetch
  receiptRetry?: { attempts?: number; baseDelayMs?: number };
}

export interface StepVerdict {
  id: string;
  model: string;
  verdict: 'tee-verified' | 'gateway-verified';
  receipt: Receipt;
  signer: string;
  servedBy: string | null;
  requestSha256: string;
  responseSha256: string;
  attestationNonce: string;
}

export async function verifyCompletion(
  captured: Map<string, Captured>,
  id: string,
  getAttestation: GetAttestation,
  opts: VerifyOptions = {},
): Promise<StepVerdict> {
  const c = captured.get(id);
  if (!c) throw new Error(`no captured bytes for ${id} (streamed, failed or evicted): cannot verify`);
  const apiKey = opts.apiKey ?? process.env.NEARAI_API_KEY;
  if (!apiKey) throw new Error('missing NEARAI_API_KEY');
  const algo = opts.algo ?? 'ecdsa';
  const receipt = await fetchReceipt(id, algo, apiKey, { fetchImpl: opts.fetchImpl, ...opts.receiptRetry });
  if (receipt.signing_algo !== algo) throw new Error('signature.algo_mismatch');

  let att = await getAttestation(c.model);
  let signer: string;
  let verdict: StepVerdict['verdict'];
  if (receipt.signature_kind === 'provider_tee') {
    if (receipt.text !== modelReceiptText(c.model, c.req, c.res)) throw new Error('signature.payload_mismatch');
    const find = (a: Attestation) => a.models.find((m) => m.signingAlgo === algo && sameHex(m.signingAddress, receipt.signing_address));
    let m = find(att);
    if (!m) {
      // Another replica (or a restarted one with a fresh key) served this turn: attest THAT signer, once.
      // A forced unpinned re-fetch could land on yet another replica; ?signing_address= cannot, and cloud-api
      // answers HTTP 503 "Signing address not found on this provider" for a key no replica holds.
      att = await getAttestation(c.model, false, receipt.signing_address).catch((e: unknown) => {
        throw new Error(`signature.signer_mismatch: no attestation for receipt signer ${receipt.signing_address} (${(e as Error).message})`, { cause: e });
      });
      m = find(att);
    }
    if (!m) throw new Error('signature.signer_mismatch: receipt signer is not an attested model key');
    verifyReceiptSignature(receipt, m.signingAddress);
    signer = m.signingAddress;
    verdict = 'tee-verified';
  } else {
    if (!opts.allowGatewayReceipt) throw new Error('signature.kind_mismatch: gateway receipt (alias, redaction or streaming path?)');
    if (receipt.text !== gatewayReceiptText(c.req, c.res)) throw new Error('signature.payload_mismatch');
    if (!sameHex(att.gateway.signingAddress, receipt.signing_address)) att = await getAttestation(c.model, true);
    if (att.gateway.signingAlgo !== algo) throw new Error('signature.algo_mismatch: gateway attestation');
    verifyReceiptSignature(receipt, att.gateway.signingAddress);
    signer = att.gateway.signingAddress;
    verdict = 'gateway-verified';
  }
  return {
    id,
    model: c.model,
    verdict,
    receipt,
    signer,
    servedBy: c.servedBy,
    requestSha256: sha256hex(c.req),
    responseSha256: sha256hex(c.res),
    attestationNonce: att.nonce,
  };
}

/** runAgent's `verify` hook: every model turn needs a valid receipt, or the run halts (AgentHalted) before its tools run. */
export const receiptVerifier = (captured: Map<string, Captured>, getAttestation: GetAttestation, opts: VerifyOptions = {}) =>
  (completion: { id: string }) => verifyCompletion(captured, completion.id, getAttestation, opts);
