#!/usr/bin/env python3
"""Offline sanity check of a NEAR contract wasm (no nearcore needed).

Prints size, sections, imports and exports, and fails (exit 1) when:
  * a function type returns more than one value (nearcore 2.14 runs wasmparser with
    multi_value = false, runtime/near-vm-runner/src/features.rs:51),
  * an import is not from module "env" (NEAR host functions all live in "env"),
  * the wasm is larger than max_contract_size (4 MiB on testnet/mainnet PV 88),
  * `--cfg near` looks missing (no env.panic_utf8 import: panics would be bare traps).
This is a quick pre-flight, NOT a replacement for nearcore's own validation.
"""
import sys

MAX_CONTRACT_SIZE = 4_194_304


def leb(b, i):
    result = shift = 0
    while True:
        x = b[i]; i += 1
        result |= (x & 0x7F) << shift
        shift += 7
        if x < 0x80:
            return result, i


def name(b, i):
    n, i = leb(b, i)
    return b[i:i + n].decode(), i + n


def main(path):
    b = open(path, 'rb').read()
    assert b[:8] == b'\0asm\x01\0\0\0', 'not a wasm module'
    problems, imports, exports, customs, multi = [], [], [], [], 0
    sections = {}
    i = 8
    while i < len(b):
        sid = b[i]; size, j = leb(b, i + 1); end = j + size
        sections[sid] = sections.get(sid, 0) + size
        if sid == 0:
            customs.append(name(b, j)[0])
        elif sid == 1:  # type section
            n, k = leb(b, j)
            for _ in range(n):
                assert b[k] == 0x60; k += 1
                np, k = leb(b, k); k += np
                nr, k = leb(b, k); k += nr
                multi += nr > 1
        elif sid == 2:  # import section
            n, k = leb(b, j)
            for _ in range(n):
                mod, k = name(b, k); fld, k = name(b, k); kind = b[k]; k += 1
                if kind == 0: _, k = leb(b, k)
                elif kind == 1: k += 1; fl, k = leb(b, k); _, k = leb(b, k); k = leb(b, k)[1] if fl & 1 else k
                elif kind == 2: fl, k = leb(b, k); _, k = leb(b, k); k = leb(b, k)[1] if fl & 1 else k
                elif kind == 3: k += 2
                imports.append((mod, fld, 'func table memory global'.split()[kind]))
        elif sid == 7:  # export section
            n, k = leb(b, j)
            for _ in range(n):
                fld, k = name(b, k); kind = b[k]; k += 1; _, k = leb(b, k)
                exports.append((fld, 'func table memory global'.split()[kind]))
        i = end
    print(f'{path}: {len(b)} bytes, sections {dict(sorted(sections.items()))}, custom {customs}')
    print(f'  imports ({len(imports)}): ' + ' '.join(f'{m}.{f}' + ('' if k == 'func' else f'[{k}]') for m, f, k in imports))
    print(f'  exports ({len(exports)}): ' + ' '.join(f + ('' if k == 'func' else f'[{k}]') for f, k in exports))
    if multi:
        problems.append(f'{multi} function type(s) with multiple results (multi-value is disabled in nearcore)')
    bad = [f'{m}.{f}' for m, f, _ in imports if m != 'env']
    if bad:
        problems.append(f'non-env imports: {bad}')
    if len(b) > MAX_CONTRACT_SIZE:
        problems.append(f'larger than max_contract_size {MAX_CONTRACT_SIZE}')
    if not any(f == 'panic_utf8' for _, f, _ in imports):
        problems.append('no env.panic_utf8 import: built without `--cfg near`? (panic messages will be lost)')
    for p in problems:
        print('  PROBLEM:', p)
    print('  OK' if not problems else '  FAILED')
    return 1 if problems else 0


if __name__ == '__main__':
    sys.exit(max(main(p) for p in sys.argv[1:]))
