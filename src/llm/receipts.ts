// receipts.ts - "verified completion" on NEAR AI Cloud without the SDK:
//   attest (free GET) -> pinned, non-streaming chat call with exact bytes -> GET /v1/signature/{id} -> verify.
// deps: ethers@6.17.0 tweetnacl@1.0.3 (+ near-attest.ts deps). Node >= 24 (type stripping).
// "tee-verified" = the receipt is signed by a key that a genuine TDX + NVIDIA-GPU TEE report vouches for. It does
// NOT mean the TEE runs reviewed code unless compose hashes are pinned (att.measurementsPinned), and the HTTPS
// connection itself is not bound to the attestation (att.tlsBound is false); see near-attest.ts.
import { createHash } from 'node:crypto';
import { hexlify, verifyMessage } from 'ethers';
import nacl from 'tweetnacl';
import { fetchAndVerify } from './near-attest.ts';

const BASE_URL = process.env.NEARAI_BASE_URL ?? 'https://cloud-api.near.ai/v1';

export type SigningAlgo = 'ecdsa' | 'ed25519';
export interface Receipt {
  text: string;
  signature: string;
  signing_address: string;
  signing_algo: SigningAlgo;
  signature_kind: 'provider_tee' | 'gateway';
}
export type Attestation = Awaited<ReturnType<typeof fetchAndVerify>>;

export const sha256hex = (b: Uint8Array) => createHash('sha256').update(b).digest('hex');
/** provider_tee: signed by the model TEE. `model` is the exact `model` string of the request JSON. */
export const modelReceiptText = (model: string, req: Uint8Array, res: Uint8Array) => `${model}:${sha256hex(req)}:${sha256hex(res)}`;
/** gateway: signed by the attested gateway over client-visible bytes; does NOT prove which model ran. */
export const gatewayReceiptText = (req: Uint8Array, res: Uint8Array) => `${sha256hex(req)}:${sha256hex(res)}`;

const unhex = (s: string) => Buffer.from(s.replace(/^0x/i, ''), 'hex');
const sameHex = (a: string, b: string) => a.replace(/^0x/i, '').toLowerCase() === b.replace(/^0x/i, '').toLowerCase();

/** Signature check only (mirrors @nearai/inference-sdk core/chat.ts): EIP-191 personal_sign or raw Ed25519 over UTF-8 text. */
export function verifyReceiptSignature(r: Receipt, expectedSigner: string): void {
  if (!sameHex(r.signing_address, expectedSigner)) throw new Error('signature.signer_mismatch: receipt signer is not the attested key');
  const sig = unhex(r.signature);
  const id = unhex(r.signing_address);
  if (r.signing_algo === 'ecdsa') {
    if (sig.length !== 65 || id.length !== 20) throw new Error('signature.format_invalid: ecdsa wants 65-byte sig, 20-byte address');
    const recovered = verifyMessage(r.text, hexlify(sig)); // keccak256("\x19Ethereum Signed Message:\n" + len + text)
    if (!sameHex(recovered, r.signing_address)) throw new Error('signature.invalid (ecdsa)');
  } else if (r.signing_algo === 'ed25519') {
    if (sig.length !== 64 || id.length !== 32) throw new Error('signature.format_invalid: ed25519 wants 64-byte sig, 32-byte key');
    if (!nacl.sign.detached.verify(new TextEncoder().encode(r.text), sig, id)) throw new Error('signature.invalid (ed25519)');
  } else {
    throw new Error(`unknown signing_algo ${String(r.signing_algo)}`);
  }
}

const sleep = (ms: number) => new Promise((r) => setTimeout(r, ms));

/** GET /v1/signature/{chat_id}?signing_algo=...  (auth required; 404 until the receipt is stored -> retry) */
export async function fetchReceipt(
  chatId: string,
  algo: SigningAlgo,
  apiKey: string,
  { fetchImpl = fetch, attempts = 6, baseDelayMs = 250 }: { fetchImpl?: typeof fetch; attempts?: number; baseDelayMs?: number } = {},
): Promise<Receipt> {
  const url = `${BASE_URL}/signature/${encodeURIComponent(chatId)}?signing_algo=${algo}`;
  let last = '';
  for (let i = 0; i < attempts; i++) {
    const res = await fetchImpl(url, { headers: { authorization: `Bearer ${apiKey}`, accept: 'application/json' } });
    if (res.ok) {
      const body = (await res.json()) as Partial<Receipt> & { error_code?: string; message?: string };
      // 200 + {error_code, message}: no receipt exists, e.g. SIGNATURE_UNSUPPORTED (Chutes) or STREAM_DISCONNECTED
      if (body.error_code !== undefined && body.text === undefined) throw new Error(`receipt unavailable: ${body.error_code}: ${body.message}`);
      if (typeof body.text !== 'string' || typeof body.signature !== 'string' || typeof body.signing_address !== 'string') {
        throw new Error('malformed receipt');
      }
      if (body.signature_kind !== 'provider_tee' && body.signature_kind !== 'gateway') throw new Error('receipt has no signature_kind');
      return body as Receipt;
    }
    last = `HTTP ${res.status}: ${await res.text()}`;
    const retryable = res.status === 404 || res.status === 408 || res.status === 425 || res.status === 429 || res.status >= 500;
    if (!retryable) break;
    await sleep(baseDelayMs * 2 ** i);
  }
  throw new Error(`receipt fetch failed (${last})`);
}

export interface VerifiedCompletion {
  completion: any;
  verdict: 'tee-verified' | 'gateway-verified';
  receipt: Receipt;
  servedBy: string | null;
  requestSha256: string;
  responseSha256: string;
  attestationNonce: string;
  modelSigner: string;
  gatewaySigner: string;
}

/**
 * One non-streaming chat completion whose exact bytes are checked against a TEE receipt.
 * Policy: require provider_tee unless allowGatewayReceipt is set (then the result is labeled gateway-verified).
 */
export async function chatWithReceipt(opts: {
  body: { model: string; messages: unknown[]; stream?: boolean; [k: string]: unknown };
  apiKey?: string;
  signingAlgo?: SigningAlgo;
  attestation?: Attestation; // reuse a cached attestation (re-attest when it is older than ~1 h or a check fails)
  acceptedTcb?: readonly string[];
  allowGatewayReceipt?: boolean;
  fetchImpl?: typeof fetch;
  receiptRetry?: { attempts?: number; baseDelayMs?: number };
}): Promise<VerifiedCompletion> {
  const algo = opts.signingAlgo ?? 'ecdsa';
  const apiKey = opts.apiKey ?? process.env.NEARAI_API_KEY;
  if (!apiKey) throw new Error('missing NEARAI_API_KEY');
  if (opts.body.stream) throw new Error('use stream:false - streamed responses are re-signed by the gateway (gateway kind)');
  const fetchImpl = opts.fetchImpl ?? fetch;

  // 1) free attestation: gateway TDX + model TDX + NVIDIA GPU, nonce-bound (measurements pinned only if configured)
  const att = opts.attestation ?? (await fetchAndVerify(opts.body.model, algo, opts.acceptedTcb ?? ['UpToDate']));
  const target = att.models.find((m) => m.signingAlgo === algo && m.signingPublicKey);
  if (!target?.signingPublicKey) throw new Error('e2ee.model_public_key_required: no attested model key for this algorithm');

  // 2) exact request bytes; pin the attested replica (routing-only header, 64-130 hex chars, no 0x).
  //    Do NOT send x-signing-algo here: it is an E2EE header and needs a client key.
  const reqBytes = new TextEncoder().encode(JSON.stringify(opts.body));
  const res = await fetchImpl(`${BASE_URL}/chat/completions`, {
    method: 'POST',
    headers: {
      authorization: `Bearer ${apiKey}`,
      'content-type': 'application/json',
      accept: 'application/json',
      'x-no-aliasing': 'true',
      'x-model-pub-key': target.signingPublicKey,
    },
    body: reqBytes,
  });
  const resBytes = new Uint8Array(await res.arrayBuffer()); // decoded body = bytes the TEE signed
  if (!res.ok) throw new Error(`chat HTTP ${res.status}: ${new TextDecoder().decode(resBytes)}`);
  const completion = JSON.parse(new TextDecoder().decode(resBytes));
  if (typeof completion?.id !== 'string') throw new Error('completion has no id');

  // 3) receipt
  const receipt = await fetchReceipt(completion.id, algo, apiKey, { fetchImpl, ...opts.receiptRetry });
  if (receipt.signing_algo !== algo) throw new Error('signature.algo_mismatch');

  // 4) verify: text covers these exact bytes, signature valid, signer is the attested key
  let verdict: VerifiedCompletion['verdict'];
  if (receipt.signature_kind === 'provider_tee') {
    if (receipt.text !== modelReceiptText(opts.body.model, reqBytes, resBytes)) throw new Error('signature.payload_mismatch');
    // the pin can fall open (unknown key), so the signer comparison below is what actually enforces "this replica"
    verifyReceiptSignature(receipt, target.signingAddress);
    verdict = 'tee-verified';
  } else {
    if (!opts.allowGatewayReceipt) throw new Error('signature.kind_mismatch: got a gateway receipt (alias, redaction or streaming path?)');
    if (receipt.text !== gatewayReceiptText(reqBytes, resBytes)) throw new Error('signature.payload_mismatch');
    verifyReceiptSignature(receipt, att.gateway.signingAddress);
    verdict = 'gateway-verified';
  }
  return {
    completion,
    verdict,
    receipt,
    servedBy: res.headers.get('x-serving-provider'),
    requestSha256: sha256hex(reqBytes),
    responseSha256: sha256hex(resBytes),
    attestationNonce: att.nonce,
    modelSigner: target.signingAddress,
    gatewaySigner: att.gateway.signingAddress,
  };
}

if (import.meta.main) {
  // LIVE + PAID (tiny): needs NEARAI_API_KEY.  node receipts.ts z-ai/glm-5.3-flash
  const model = process.argv[2] ?? 'z-ai/glm-5.3-flash';
  const out = await chatWithReceipt({
    body: { model, messages: [{ role: 'user', content: 'Reply with the single word: ok' }], max_tokens: 512, thinking_token_budget: 128 },
    acceptedTcb: ['UpToDate', 'OutOfDate', 'TDRelaunchAdvised'],
  });
  console.log(JSON.stringify({ verdict: out.verdict, servedBy: out.servedBy, id: out.completion.id, text: out.completion.choices?.[0]?.message?.content, receipt: out.receipt }, null, 2));
}
