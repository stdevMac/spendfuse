// amount.ts - strict decimal-NEAR -> yoctoNEAR for LLM tool arguments (dependency-free, Node >= 22 type stripping).
// Why: near-api-js 7.4.0 nearToYocto() is lenient. Tested 2026-11-08: nearToYocto("1,5") === 15 NEAR (comma dropped,
// 10x the intended amount), nearToYocto("-1") === -1 NEAR, nearToYocto(" 1") === 1 NEAR. Never feed it model output.
const DECIMAL_NEAR = /^(0|[1-9]\d{0,11})(?:\.(\d{1,24}))?$/; // no sign, comma, exponent, spaces or leading zeros

export function parseNearStrict(input: unknown, maxYocto?: bigint): bigint {
  if (typeof input !== 'string') throw new TypeError('amount_near must be a string such as "1.5"');
  const m = input.match(DECIMAL_NEAR);
  if (!m) throw new RangeError(`bad amount_near ${JSON.stringify(input)}: use a plain decimal such as "1.5"`);
  const yocto = BigInt(m[1]) * 10n ** 24n + BigInt((m[2] ?? '').padEnd(24, '0'));
  if (yocto === 0n) throw new RangeError('amount_near must be greater than 0');
  if (maxYocto !== undefined && yocto > maxYocto) throw new RangeError(`amount_near ${input} is over the client cap`);
  return yocto;
}

/** U128 travels as a JSON string: { receiver_id, amount: toU128(parseNearStrict(a.amount_near)) } */
export const toU128 = (yocto: bigint): string => yocto.toString();
