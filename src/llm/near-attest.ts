// near-attest.ts - verify a NEAR AI Cloud attestation report (gateway + model TEEs).
//
// What IS verified (per report, gateway and every model replica):
//   - the Intel TDX quote signature chain against Intel PCS collateral, and its TCB status is in the accepted
//     list (default ['UpToDate']; widen with the acceptedTcb argument or NEARAI_ACCEPTED_TCB=a,b,c);
//   - the TD is not in debug mode;
//   - report_data binds our fresh nonce (no replay) and the signing identity (address / Ed25519 key, hashed with
//     the report's own tls_cert_fingerprint when one is present);
//   - MRCONFIGID = sha256(app_compose) and an RTMR3 replay of the event log, so app_compose / compose hash are
//     what the TDX VM really booted with;
//   - model reports only: NVIDIA GPU evidence through NRAS (nonce-bound, NVIDIA-signed JWT). A model report
//     WITHOUT verified GPU evidence is rejected unless allowNoGpu is set;
//   - model reports only: model_name (when the report has it) equals the requested model.
// What is NOT verified:
//   - Measurements are only pinned when NEARAI_PINNED_COMPOSE_HASHES (or opts.pinnedComposeHashes) is set.
//     Without it the result says measurementsPinned: false: "a genuine TDX VM running SOME compose file", not
//     "running the code we reviewed". MRTD / RTMR0-2 (firmware, kernel, OS image) are never compared to anything.
//   - tls_cert_fingerprint is NOT compared with the live TLS peer certificate (global fetch exposes no peer
//     cert), so the HTTPS connection is NOT bound to the attestation: tlsBound is always false.
//   - Nothing here proves which replica serves a later chat call; receipts.ts / verified-fetch.ts check per-turn
//     signatures against the attested signing keys.
// Runs on Node >= 24 with native type stripping:  node near-attest.ts [model] [ecdsa|ed25519] [signing_address]
// deps: @phala/dcap-qvl@0.7.1 ethers@6.17.0 jose@6 (all read-only network calls:
//   GET cloud-api.near.ai, GET Intel PCS collateral, POST evidence to NVIDIA NRAS (free, stateless))
import { createHash, randomBytes } from 'node:crypto';
import dcap from '@phala/dcap-qvl';
import { computeAddress } from 'ethers';
import { createRemoteJWKSet, jwtVerify } from 'jose';

const BASE_URL = process.env.NEARAI_BASE_URL ?? 'https://cloud-api.near.ai/v1';
const NRAS_URL = 'https://nras.attestation.nvidia.com/v3/attest/gpu';
const NVIDIA_JWKS = createRemoteJWKSet(new URL('https://nras.attestation.nvidia.com/.well-known/jwks.json'));

type TdxEvent = { imr: number; event_type: number; digest?: string; event: string; event_payload?: string };
export interface NearReport {
  intel_quote: string;
  event_log: string | TdxEvent[];
  signing_address: string;
  signing_algo: 'ecdsa' | 'ed25519';
  signing_public_key?: string;
  request_nonce?: string;
  tls_cert_fingerprint?: string;
  nvidia_payload?: string;
  model_name?: string;
  info: { app_id?: string; compose_hash?: string; tcb_info: string | { app_compose: string } };
}
export interface CheckedReport {
  tcbStatus: string;
  advisoryIds: string[];
  signingAddress: string;
  signingAlgo: string;
  signingPublicKey?: string; // model reports: the key to pin with the x-model-pub-key header
  composeHash: string;
  appId?: string;
  gpu?: 'verified' | 'absent';
  modelName?: string;
  /** the report's own claim; bound in report_data but never compared with the live TLS peer certificate */
  tlsCertFingerprint?: string;
  tlsBound: false;
}

export interface AttestOptions {
  /** accept model reports with no (verified) NVIDIA GPU evidence. Default false. */
  allowNoGpu?: boolean;
  /** allowed compose hashes (hex, sha256 of app_compose). Default: NEARAI_PINNED_COMPOSE_HASHES (comma-separated). */
  pinnedComposeHashes?: readonly string[];
}

const normHex = (s: string) => s.trim().replace(/^0x/i, '').toLowerCase();

/** Comma-separated list from env (empty / unset -> undefined). */
export function listFromEnv(v: string | undefined): string[] | undefined {
  const xs = (v ?? '').split(',').map((x) => x.trim()).filter(Boolean);
  return xs.length ? xs : undefined;
}

/** Default accepted TCB statuses: NEARAI_ACCEPTED_TCB (comma-separated) or ['UpToDate']. */
export const defaultAcceptedTcb = (env: Record<string, string | undefined> = process.env): string[] =>
  listFromEnv(env.NEARAI_ACCEPTED_TCB) ?? ['UpToDate'];

/** Pure model-report policy: GPU evidence verified (unless allowNoGpu) and model_name matches the request. */
export function enforceModelPolicy(m: CheckedReport, requestedModel: string, opts: AttestOptions = {}): void {
  if (m.gpu !== 'verified' && !opts.allowNoGpu) {
    throw new Error(`model report ${m.signingAddress} has no verified NVIDIA GPU evidence (gpu: ${m.gpu ?? 'absent'})`);
  }
  if (m.modelName !== undefined && m.modelName !== requestedModel) {
    throw new Error(`model report is for ${m.modelName}, not the requested ${requestedModel}`);
  }
}

/** Pure measurement pinning. Returns true when a pin list was enforced, false when there is none. */
export function enforcePins(reports: readonly CheckedReport[], pins: readonly string[] | undefined): boolean {
  if (!pins || pins.length === 0) return false;
  const allowed = new Set(pins.map(normHex));
  for (const r of reports) {
    if (!allowed.has(normHex(r.composeHash))) throw new Error(`compose hash ${r.composeHash} is not in the pinned list`);
  }
  return true;
}

const unhex = (s: string) => Buffer.from(s.replace(/^0x/i, ''), 'hex');
const sha256 = (b: Uint8Array) => createHash('sha256').update(b).digest();
const sha384 = (b: Uint8Array) => createHash('sha384').update(b).digest();

/** RTMR3 = fold(SHA384(rtmr || digest)) over imr==3 events; each digest is recomputed from its payload. */
export function replayRtmr3(eventLog: NearReport['event_log']): Buffer {
  const events: TdxEvent[] = typeof eventLog === 'string' ? JSON.parse(eventLog) : eventLog;
  let rtmr: Buffer = Buffer.alloc(48);
  for (const ev of events) {
    if (ev.imr !== 3) continue;
    const type = Buffer.alloc(4);
    type.writeUInt32LE(ev.event_type >>> 0);
    const digest = sha384(Buffer.concat([type, Buffer.from(':'), Buffer.from(ev.event, 'utf8'), Buffer.from(':'), unhex(ev.event_payload ?? '')]));
    if (ev.digest && !unhex(ev.digest).equals(digest)) throw new Error(`RTMR3 event digest mismatch (${ev.event})`);
    rtmr = sha384(Buffer.concat([rtmr, digest]));
  }
  return rtmr;
}

/** Checks one NEAR-operated dstack report: quote, debug bit, report_data (signer+nonce), MRCONFIGID, RTMR3, GPU. */
export async function checkNearReport(r: NearReport, nonceHex: string, acceptedTcb: readonly string[]): Promise<CheckedReport> {
  // 1) Intel TDX quote signature chain + TCB status (collateral fetched from Intel PCS).
  const verified = await dcap.getCollateralAndVerify(unhex(r.intel_quote), dcap.INTEL_PCS_URL);
  if (!acceptedTcb.includes(verified.status)) throw new Error(`TCB status ${verified.status} rejected [${verified.advisory_ids.join(', ')}]`);
  const td = verified.report.asTd10() ?? verified.report.asTd15()?.base;
  if (!td) throw new Error(`expected a TDX report, got ${verified.report.type}`);
  if (td.tdAttributes[0] & 1) throw new Error('TD is in debug mode');

  // 2) report_data = identity-binding(32) || client nonce(32)
  const reportData = Buffer.from(td.reportData);
  if (!reportData.subarray(32).equals(unhex(nonceHex))) throw new Error('nonce not bound in quote (stale or replayed report)');
  const identity = unhex(r.signing_address);
  if (identity.length !== ({ ecdsa: 20, ed25519: 32 } as const)[r.signing_algo]) throw new Error('bad signing identity length');
  const expectedBinding = r.tls_cert_fingerprint
    ? sha256(Buffer.concat([identity, unhex(r.tls_cert_fingerprint)]))
    : Buffer.concat([identity, Buffer.alloc(32 - identity.length)]);
  if (!reportData.subarray(0, 32).equals(expectedBinding)) throw new Error('signing key not bound in quote');
  if (r.signing_algo === 'ecdsa' && r.signing_public_key) {
    const pk = r.signing_public_key.replace(/^0x/, '');
    const addr = computeAddress('0x' + (pk.length === 128 ? '04' + pk : pk));
    if (addr.toLowerCase() !== r.signing_address.toLowerCase()) throw new Error('signing_public_key does not match signing_address');
  }

  // 3) MRCONFIGID = 0x01 || sha256(app_compose exact bytes) || 15 zero bytes
  const tcbInfo = typeof r.info.tcb_info === 'string' ? JSON.parse(r.info.tcb_info) : r.info.tcb_info;
  const composeHash = sha256(Buffer.from(tcbInfo.app_compose, 'utf8'));
  const expectedMrConfig = Buffer.concat([Buffer.from([1]), composeHash, Buffer.alloc(15)]);
  if (!Buffer.from(td.mrConfigId).equals(expectedMrConfig)) throw new Error('MRCONFIGID does not match app_compose');

  // 4) RTMR3 replay authenticates app-id / compose-hash / key-provider events
  if (!replayRtmr3(r.event_log).equals(Buffer.from(td.rtMr3))) throw new Error('RTMR3 replay mismatch');

  // 5) NVIDIA GPU evidence (model reports only): NRAS verdict JWT, signed by NVIDIA, nonce-bound
  let gpu: CheckedReport['gpu'] = 'absent';
  if (r.nvidia_payload) {
    const payload = JSON.parse(r.nvidia_payload);
    if (String(payload.nonce).toLowerCase() !== nonceHex.toLowerCase()) throw new Error('GPU evidence nonce mismatch');
    const res = await fetch(NRAS_URL, { method: 'POST', headers: { 'content-type': 'application/json', accept: 'application/json' }, body: JSON.stringify(payload) });
    if (!res.ok) throw new Error(`NRAS HTTP ${res.status}: ${await res.text()}`);
    const body = (await res.json()) as unknown[];
    const overall = (body as [string, string][]).find((e) => Array.isArray(e) && e[0] === 'JWT')?.[1];
    if (!overall) throw new Error('NRAS response has no overall JWT');
    const { payload: claims } = await jwtVerify(overall, NVIDIA_JWKS);
    if (claims['x-nvidia-overall-att-result'] !== true) throw new Error('NVIDIA overall attestation result is not true');
    if (String(claims['eat_nonce']).toLowerCase() !== nonceHex.toLowerCase()) throw new Error('NRAS eat_nonce mismatch');
    gpu = 'verified';
  }

  return {
    tcbStatus: verified.status,
    advisoryIds: verified.advisory_ids,
    signingAddress: r.signing_address,
    signingAlgo: r.signing_algo,
    signingPublicKey: r.signing_public_key?.replace(/^0x/i, ''),
    composeHash: composeHash.toString('hex'),
    appId: r.info.app_id,
    gpu,
    modelName: r.model_name,
    tlsCertFingerprint: r.tls_cert_fingerprint,
    tlsBound: false,
  };
}

/** `signingAddress` (optional) asks for the report of exactly that model replica; an address the provider does not
 *  know gets HTTP 503 "Signing address not found on this provider" (checked live 2026-11-08).
 *  Result: measurementsPinned says whether compose hashes were checked against a pin list; tlsBound is always
 *  false (see the header). Log "genuine TDX VM, measurements not pinned" when measurementsPinned is false. */
export async function fetchAndVerify(
  model: string,
  signingAlgo: 'ecdsa' | 'ed25519' = 'ecdsa',
  acceptedTcb: readonly string[] = defaultAcceptedTcb(),
  signingAddress?: string,
  opts: AttestOptions = {},
) {
  const nonce = randomBytes(32).toString('hex');
  const url = new URL(`${BASE_URL}/attestation/report`);
  const query: Record<string, string> = { model, signing_algo: signingAlgo, nonce, provider: 'near' };
  if (signingAddress) query.signing_address = signingAddress;
  url.search = new URLSearchParams(query).toString();
  const res = await fetch(url, { headers: { 'x-no-aliasing': 'true', accept: 'application/json' } });
  if (!res.ok) throw new Error(`attestation report HTTP ${res.status}: ${await res.text()}`);
  const report = (await res.json()) as { gateway_attestation: NearReport; model_attestations?: NearReport[] };
  const gateway = await checkNearReport(report.gateway_attestation, nonce, acceptedTcb);
  const modelReports = report.model_attestations ?? []; // the field is omitted when empty
  if (modelReports.length === 0) throw new Error('no model attestations (Incognito / non-TEE model?)');
  const models = await Promise.all(modelReports.map((m) => checkNearReport(m, nonce, acceptedTcb)));
  const norm = (a: string) => a.replace(/^0x/i, '').toLowerCase();
  if (signingAddress && !models.some((m) => norm(m.signingAddress) === norm(signingAddress))) {
    throw new Error(`report does not cover the requested signing_address ${signingAddress}`);
  }
  for (const m of models) enforceModelPolicy(m, model, opts);
  const measurementsPinned = enforcePins([gateway, ...models], opts.pinnedComposeHashes ?? listFromEnv(process.env.NEARAI_PINNED_COMPOSE_HASHES));
  return { nonce, gateway, models, measurementsPinned, tlsBound: false as const };
}

if (import.meta.main) {
  const model = process.argv[2] ?? 'z-ai/glm-5.3-flash';
  const algo = (process.argv[3] ?? 'ecdsa') as 'ecdsa' | 'ed25519';
  const signingAddress = process.argv[4]; // optional: one specific model replica
  const t0 = Date.now();
  // Diagnostic CLI: deliberately widened TCB list so a stale platform still prints its status (env overrides).
  const tcb = listFromEnv(process.env.NEARAI_ACCEPTED_TCB) ?? ['UpToDate', 'OutOfDate', 'TDRelaunchAdvised'];
  const result = await fetchAndVerify(model, algo, tcb, signingAddress);
  const summary = result.measurementsPinned ? 'genuine TDX VM, compose hashes pinned' : 'genuine TDX VM, measurements not pinned';
  console.log(JSON.stringify({ model, ms: Date.now() - t0, summary, ...result }, null, 2));
}
