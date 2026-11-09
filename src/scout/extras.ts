// extras.ts - add-on signals for counterparty.ts. Read-only, zero dependencies, Node 26 type stripping.
//
//  keyAges()        age of every current access key, read from its nonce. Costs no extra call: it parses
//                   the same view_access_key_list the scout already makes. nearcore seeds a new key's
//                   nonce with (block_height - 1) * 1e6 (core/primitives/src/account.rs, AccessKey::nonce)
//                   since protocol 45 (_DeprecatedAccessKeyNonceRange in core/primitives-core/src/version.rs).
//                   Nonces only go up, so nobody can make a key look OLDER than it is.
//  creationFromTx() who created an account: the signer of its creation transaction (FastNear /v0/transactions).
//  extraSignals()   turns both into Reasons; withExtras() merges them into a Verdict.
import { ENDPOINTS, rpc, type BlocklistHook, type Decision, type Network, type Reason, type Verdict } from "./counterparty.ts";

export const NONCE_MULTIPLIER = 1_000_000; // AccessKey::ACCESS_KEY_NONCE_RANGE_MULTIPLIER
const DAY_MS = 86_400_000;

export interface KeyAge {
  publicKey: string;
  full: boolean;
  gasKey: boolean;
  preRule: boolean;             // nonce < 1e6: added before the nonce rule existed (protocol 45), so years old
  addedAtHeight: number | null; // null when the nonce carries no date (pre-rule key or gas key)
  txsSince: number | null;      // transactions signed with the key since it was added (exact below 1e6)
}

export function keyAges(keys: any[]): KeyAge[] {
  return keys.map((k) => {
    const p = k?.access_key?.permission;
    const obj = p !== null && typeof p === "object";
    const gasKey = obj && ("GasKeyFullAccess" in p || "GasKeyFunctionCall" in p);
    const full = p === "FullAccess" || (obj && "GasKeyFullAccess" in p);
    const nonce = Number(k?.access_key?.nonce);
    const usable = !gasKey && Number.isSafeInteger(nonce) && nonce >= 0; // gas-key nonce semantics UNVERIFIED: skip
    const preRule = usable && nonce < NONCE_MULTIPLIER;
    const dated = usable && !preRule;
    return {
      publicKey: String(k?.public_key),
      full,
      gasKey,
      preRule,
      addedAtHeight: dated ? Math.floor(nonce / NONCE_MULTIPLIER) + 1 : null,
      txsSince: dated ? nonce % NONCE_MULTIPLIER : null,
    };
  });
}

// headHeight/msPerBlock come from the RPC `status`. msPerBlock is today's block time; older blocks were
// slower, so the age of an old key is UNDERSTATED (the safe direction). Recent heights convert accurately.
export function keyAgeReason(ages: KeyAge[], headHeight: number, msPerBlock: number, minAgeDays: number): Reason | null {
  if (ages.length === 0) return null;
  if (ages.some((a) => a.preRule)) {
    return { code: "KEYS_PREDATE_NONCE_RULE", severity: "info", detail: "a current key has a nonce below 1e6, so it was added before protocol 45: this account incarnation is years old", source: "rpc" };
  }
  const heights = ages.map((a) => a.addedAtHeight).filter((h): h is number => h !== null);
  if (heights.length === 0) return null;
  const oldest = Math.min(...heights);
  const days = ((headHeight - oldest) * msPerBlock) / DAY_MS;
  if (days < minAgeDays) {
    return { code: "YOUNG_KEYS", severity: "warn", detail: `every current key was added in the last ${days.toFixed(1)}d (oldest at block ${oldest}): a new account, or one whose keys were all replaced`, source: "rpc" };
  }
  return { code: "KEY_AGE", severity: "info", detail: `oldest current key added at block ${oldest}, at least ~${days.toFixed(0)}d ago`, source: "rpc" };
}

export interface Creation {
  txHash: string;
  signer: string;                        // signed (and paid for) the creating transaction
  txReceiver: string;                    // the registrar ("testnet", "near") or the parent account
  method: string | null;                 // "create_account" when created through a registrar contract
  createdInBlock: number | null;         // block of the receipt that created the account
  createdOk: boolean | null;
  signerKey: string;
  signerKeyAddedAtHeight: number | null; // from the transaction nonce: how fresh the creator's key was
  isCreation: boolean;                   // false: the earliest INDEXED tx is not the creation (account predates the index)
}

// `detail` is a FastNear Transactions API /v0/transactions response for the account's creation tx
// (facts.createdTx from checkCounterparty).
export function creationFromTx(detail: any, accountId: string): Creation | null {
  const t = detail?.transactions?.[0];
  const tx = t?.transaction;
  if (!tx) return null;
  const call = (tx.actions ?? []).find((a: any) => a !== null && typeof a === "object" && "FunctionCall" in a);
  const mine = ((t.receipts ?? []) as any[]).filter((r) => r?.receipt?.receiver_id === accountId);
  const created = mine.find((r) => (r.receipt?.receipt?.Action?.actions ?? []).includes("CreateAccount"));
  const creating = created ?? mine[0];
  // Implicit accounts (64 hex, 0x + 40 hex) have no CreateAccount action: the first Transfer to them creates them.
  const implicit = /^[0-9a-f]{64}$/.test(accountId) || /^0x[0-9a-f]{40}$/.test(accountId);
  const transfer = (creating?.receipt?.receipt?.Action?.actions ?? []).some((a: any) => a !== null && typeof a === "object" && "Transfer" in a);
  const status = creating?.execution_outcome?.outcome?.status;
  const nonce = Number(tx.nonce);
  return {
    txHash: String(tx.hash),
    signer: String(tx.signer_id),
    txReceiver: String(tx.receiver_id),
    method: call ? String(call.FunctionCall.method_name) : null,
    createdInBlock: creating?.execution_outcome?.block_height ?? null,
    createdOk: status && typeof status === "object" ? "SuccessValue" in status || "SuccessReceiptId" in status : null,
    signerKey: String(tx.public_key),
    signerKeyAddedAtHeight: Number.isSafeInteger(nonce) && nonce >= NONCE_MULTIPLIER ? Math.floor(nonce / NONCE_MULTIPLIER) + 1 : null,
    isCreation: Boolean(created) || (implicit && transfer),
  };
}

// ---------- fetchers (same transports as counterparty.ts) ----------

type Net = { timeoutMs?: number; apiKey?: string };

export async function chainClock(network: Network, o: Net = {}) {
  const s = (await rpc(ENDPOINTS[network].rpc, "status", [], o.timeoutMs ?? 8000, o.apiKey)).sync_info;
  const spanBlocks = s.latest_block_height - s.earliest_block_height;
  const spanMs = Date.parse(s.latest_block_time) - Date.parse(s.earliest_block_time);
  return { headHeight: s.latest_block_height as number, msPerBlock: spanBlocks > 0 && spanMs > 0 ? spanMs / spanBlocks : 600 };
}

export async function fetchKeyAges(network: Network, accountId: string, o: Net = {}) {
  const r = await rpc(ENDPOINTS[network].rpc, "query", { request_type: "view_access_key_list", account_id: accountId, finality: "final" }, o.timeoutMs ?? 8000, o.apiKey);
  return { blockHeight: r.block_height as number, ages: keyAges(r.keys ?? []) };
}

export async function fetchCreation(network: Network, accountId: string, txHash: string, o: Net = {}) {
  const res = await fetch(`${ENDPOINTS[network].fastnearTx}/v0/transactions`, {
    method: "POST",
    headers: { "content-type": "application/json", ...(o.apiKey ? { authorization: `Bearer ${o.apiKey}` } : {}) },
    body: JSON.stringify({ tx_hashes: [txHash] }),
    signal: AbortSignal.timeout(o.timeoutMs ?? 8000),
  });
  if (!res.ok) throw new Error(`fastnear-tx HTTP ${res.status}`);
  return creationFromTx(await res.json(), accountId);
}

// ---------- signals ----------

export interface ExtraOptions {
  minAgeDays?: number;                                           // default 3, same as checkCounterparty
  blocklist?: BlocklistHook; // checks the CREATOR against the shared list (confirmed = block, reported = warn)
  timeoutMs?: number;
  fastnearApiKey?: string;
}

export async function extraSignals(v: Verdict, o: ExtraOptions = {}): Promise<Reason[]> {
  const out: Reason[] = [];
  if (!v.facts.exists) return out;
  const net: Net = { timeoutMs: o.timeoutMs ?? 8000, apiKey: o.fastnearApiKey };
  const [keys, clock, creation] = await Promise.allSettled([
    fetchKeyAges(v.network, v.receiver, net),
    chainClock(v.network, net),
    v.facts.createdTx ? fetchCreation(v.network, v.receiver, v.facts.createdTx, net) : Promise.resolve(null),
  ]);
  if (keys.status === "fulfilled" && clock.status === "fulfilled") {
    const r = keyAgeReason(keys.value.ages, clock.value.headHeight, clock.value.msPerBlock, o.minAgeDays ?? 3);
    if (r) out.push(r);
  }
  if (creation.status === "fulfilled" && creation.value) {
    const c = creation.value;
    if (!c.isCreation) {
      // FastNear's index starts at testnet block 42378039 (2021-04-01) / mainnet block 9823032 (2020-07-21):
      // older accounts show their earliest indexed tx instead, so "created" is only a lower bound on age.
      out.push({ code: "FIRST_SEEN", severity: "info", detail: `earliest indexed tx ${c.txHash} (signer ${c.signer}) is not a creation: the account predates the index`, source: "fastnear-tx" });
      return out;
    }
    out.push({ code: "CREATOR", severity: "info", detail: `created by ${c.signer} via ${c.txReceiver}${c.method ? "." + c.method : ""} (tx ${c.txHash})`, source: "fastnear-tx" });
    if (o.blocklist) {
      try {
        const h = await o.blocklist(c.signer);
        if (h === true || h === "confirmed") out.push({ code: "CREATOR_REPORTED", severity: "block", detail: `creator ${c.signer} is on the shared blocklist (confirmed)`, source: "blocklist" });
        else if (h === "reported") out.push({ code: "CREATOR_REPORTED", severity: "warn", detail: `creator ${c.signer} has an open report on the shared blocklist`, source: "blocklist" });
      } catch (e) {
        out.push({ code: "CHECK_UNAVAILABLE", severity: "warn", detail: `creator blocklist lookup failed: ${e instanceof Error ? e.message : String(e)}`, source: "blocklist" });
      }
    }
  }
  return out;
}

export function withExtras(v: Verdict, extra: Reason[]): Verdict {
  const reasons = [...v.reasons, ...extra];
  const decision: Decision = reasons.some((r) => r.severity === "block") ? "block"
    : reasons.some((r) => r.severity === "warn") ? "warn" : "allow";
  return { ...v, reasons, decision };
}
