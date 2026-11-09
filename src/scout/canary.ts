// canary.ts - helpers for Spendfuse canary payees. Zero dependencies, Node 26 type stripping.
// Nothing here signs, sends or touches the chain.
//
//  canaryHash(id)      the Base58CryptoHash that R1's add_canary(receiver_hash) expects:
//                      base58(sha256(utf8(receiver_id))), the same bytes as env::sha256_array(receiver_id.as_bytes())
//                      (code/R1-near-sdk-rs/src/lib.rs:167 add_canary, :197 the check in request_transfer).
//  implicitFromSeed()  a near-implicit account id (64 hex = the ed25519 public key) plus NEAR-format keys.
//  newImplicitCanary() the same from a random seed. A canary like this has a high-entropy id (no dictionary
//                      guess of the hash) and, if something ever pays it, the funds stay recoverable.
//                      Keep secretKey offline. The account does not exist on chain until someone funds it.
import { createHash, createPrivateKey, createPublicKey, randomBytes } from "node:crypto";
import { accountType } from "./counterparty.ts";

const ALPHABET = "123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz"; // Bitcoin alphabet, used by NEAR

export function base58(bytes: Uint8Array): string {
  let zeros = 0;
  while (zeros < bytes.length && bytes[zeros] === 0) zeros++;
  let n = 0n;
  for (const b of bytes) n = (n << 8n) | BigInt(b);
  let out = "";
  while (n > 0n) {
    out = ALPHABET[Number(n % 58n)] + out;
    n /= 58n;
  }
  return "1".repeat(zeros) + out;
}

export function canaryHash(accountId: string): string {
  if (accountType(accountId) === "invalid") throw new Error(`not a valid NEAR account id: ${accountId}`);
  return base58(createHash("sha256").update(accountId, "utf8").digest());
}

const PKCS8_ED25519_PREFIX = Buffer.from("302e020100300506032b657004220420", "hex"); // RFC 8410 private key header

export function implicitFromSeed(seed: Uint8Array) {
  if (seed.length !== 32) throw new Error("seed must be 32 bytes");
  const priv = createPrivateKey({ key: Buffer.concat([PKCS8_ED25519_PREFIX, seed]), format: "der", type: "pkcs8" });
  const x = createPublicKey(priv).export({ format: "jwk" }).x;
  if (!x) throw new Error("no public key");
  const pub = Buffer.from(x, "base64url");
  return {
    accountId: pub.toString("hex"),                                   // near-implicit account id
    publicKey: `ed25519:${base58(pub)}`,
    secretKey: `ed25519:${base58(Buffer.concat([seed, pub]))}`,       // near-cli / near-api-js format: seed || pub
  };
}

export function newImplicitCanary() {
  return implicitFromSeed(randomBytes(32));
}
