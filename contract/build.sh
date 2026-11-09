#!/usr/bin/env bash
# Build a near-sdk 5.30 contract for NEAR testnet/mainnet (protocol 88) WITHOUT cargo-near.
#   ./build.sh                 -> target/near/<crate>.wasm (+ <crate>.opt.wasm if wasm-opt found)
#                                 and the final wasm (optimised if possible) in res/<crate>.wasm
# Env knobs:
#   RUST_TOOLCHAIN=1.99.1      rustup toolchain (default: the channel in rust-toolchain.toml;
#                              an installed `stable` of that exact version is accepted too)
#   JOBS=2                     cargo -j (keep low on a shared machine)
#   WASM_OPT=/path/wasm-opt    binaryen 132 (npm "binaryen@132.0.0" works). Default lookup:
#                              $WASM_OPT, then wasm-opt on PATH, then `npx --no-install wasm-opt`;
#                              optimisation is skipped with a warning if none is found
#   WASM_OPT_LEVEL=-Oz         cargo-near uses the -Os equivalent; -Oz is ~0.4% smaller here
# Reproducible build: the deployed res/tripwire.wasm is reproduced byte for byte by rustc 1.99.1
# + binaryen version 132 with exactly `wasm-opt -Oz --enable-bulk-memory
# --enable-nontrapping-float-to-int`. Another binaryen version or level gives a different
# (still valid) wasm, so the script warns loudly when either differs.
set -euo pipefail
cd "$(dirname "$0")"
NAME="$(sed -n 's/^name *= *"\(.*\)"/\1/p' Cargo.toml | head -1 | tr - _)"
TARGET_DIR="${CARGO_TARGET_DIR:-target}"
OUT="$TARGET_DIR/near"

# .cargo/config.toml supplies `-C link-arg=-s --cfg near` for wasm32; env RUSTFLAGS would replace it.
if [[ -n "${RUSTFLAGS:-}${CARGO_ENCODED_RUSTFLAGS:-}" ]]; then
  echo "error: unset RUSTFLAGS / CARGO_ENCODED_RUSTFLAGS (they override .cargo/config.toml)" >&2
  exit 1
fi

# Homebrew's rust is often first on PATH and has no wasm32 std. `rustup run stable cargo` is
# not enough: cargo then still finds Homebrew's `rustc` on PATH (E0463 "can't find crate for
# `std`"), so put the rustup toolchain's bin dir first.
if command -v rustup >/dev/null 2>&1; then
  # Pick the first candidate that is installed with the wasm32 target, without letting rustup
  # auto-install anything: RUST_TOOLCHAIN if set, else the channel pinned in
  # rust-toolchain.toml, else an installed `stable` whose version equals that pin.
  PIN="$(sed -n 's/^channel *= *"\(.*\)"/\1/p' rust-toolchain.toml 2>/dev/null | head -1)"
  has_wasm() {
    local rc; rc="$(RUSTUP_AUTO_INSTALL=0 rustup which --toolchain "$1" rustc 2>/dev/null)" || return 1
    [[ -d "$("$rc" --print target-libdir --target wasm32-unknown-unknown 2>/dev/null)" ]]
  }
  TC=""
  if [[ -n "${RUST_TOOLCHAIN:-}" ]]; then
    has_wasm "$RUST_TOOLCHAIN" && TC="$RUST_TOOLCHAIN"
  elif [[ -n "$PIN" ]] && has_wasm "$PIN"; then
    TC="$PIN"
  elif [[ -n "$PIN" ]] && has_wasm stable &&
    [[ "$(RUSTUP_AUTO_INSTALL=0 rustup run stable rustc --version | awk '{print $2}')" == "$PIN" ]]; then
    TC=stable
  fi
  if [[ -z "$TC" ]]; then
    want="${RUST_TOOLCHAIN:-${PIN:-stable}}"
    echo "error: toolchain $want with the wasm32 target is not installed:" >&2
    echo "  rustup toolchain install $want --target wasm32-unknown-unknown" >&2
    exit 1
  fi
  export RUSTUP_TOOLCHAIN="$TC"
  export PATH="$(dirname "$(rustup which --toolchain "$TC" rustc)"):$PATH"
fi
CARGO=(cargo)
"${CARGO[@]}" --version; rustc --version
rustc --print target-libdir --target wasm32-unknown-unknown >/dev/null 2>&1 &&
  [[ -d "$(rustc --print target-libdir --target wasm32-unknown-unknown)" ]] ||
  { echo "error: run 'rustup target add wasm32-unknown-unknown'" >&2; exit 1; }
# Dependency panic locations embed absolute registry paths (/Users/<name>/.cargo/...): remap
# $HOME so the on-chain wasm does not carry your user name. A --config array is appended to
# the rustflags from .cargo/config.toml (checked: --cfg near and -s still apply).
REMAP="target.wasm32-unknown-unknown.rustflags=[\"--remap-path-prefix=$HOME=/home\"]"
nice -n 10 "${CARGO[@]}" build --target wasm32-unknown-unknown --release -j "${JOBS:-2}" \
  --config "$REMAP" "$@"

mkdir -p "$OUT"
rm -f "$OUT/$NAME.opt.wasm"
cp "$TARGET_DIR/wasm32-unknown-unknown/release/$NAME.wasm" "$OUT/$NAME.wasm"

WASM_OPT_CMD=()
if [[ -n "${WASM_OPT:-}" ]]; then
  WASM_OPT_CMD=("$WASM_OPT")
elif command -v wasm-opt >/dev/null 2>&1; then
  WASM_OPT_CMD=("$(command -v wasm-opt)")
elif command -v npx >/dev/null 2>&1 && npx --no-install wasm-opt --version >/dev/null 2>&1; then
  WASM_OPT_CMD=(npx --no-install wasm-opt)
fi
FINAL="$OUT/$NAME.wasm"
WASM_OPT_PIN=132
WASM_OPT_FLAGS=("${WASM_OPT_LEVEL:--Oz}" --enable-bulk-memory --enable-nontrapping-float-to-int)
if (( ${#WASM_OPT_CMD[@]} )); then
  WASM_OPT_VER="$("${WASM_OPT_CMD[@]}" --version 2>/dev/null | head -1 || true)"
  echo "wasm-opt: ${WASM_OPT_VER:-unknown version} (${WASM_OPT_CMD[*]}); flags: ${WASM_OPT_FLAGS[*]}"
  if [[ ! "$WASM_OPT_VER" =~ ^wasm-opt\ version\ ${WASM_OPT_PIN}([^0-9]|$) ]]; then
    echo "WARNING: ************************************************************************" >&2
    echo "WARNING: wasm-opt is '${WASM_OPT_VER:-unknown}', not binaryen version $WASM_OPT_PIN." >&2
    echo "WARNING: the output will NOT be byte-identical to the deployed wasm. For a reproducible" >&2
    echo "WARNING: build use binaryen $WASM_OPT_PIN, e.g. npm i -g binaryen@$WASM_OPT_PIN.0.0 or" >&2
    echo "WARNING: WASM_OPT=/path/to/binaryen-version_$WASM_OPT_PIN/bin/wasm-opt ./build.sh" >&2
    echo "WARNING: ************************************************************************" >&2
  fi
  if [[ "${WASM_OPT_FLAGS[0]}" != "-Oz" ]]; then
    echo "WARNING: WASM_OPT_LEVEL=${WASM_OPT_FLAGS[0]} (not -Oz): the output will NOT match the deployed wasm" >&2
  fi
  # The stripped wasm has no target_features section, so tell binaryen about the
  # post-MVP opcodes rustc >= 1.87 emits (same two features cargo-near enables).
  "${WASM_OPT_CMD[@]}" "${WASM_OPT_FLAGS[@]}" "$OUT/$NAME.wasm" -o "$OUT/$NAME.opt.wasm"
  FINAL="$OUT/$NAME.opt.wasm"
else
  echo "warning: wasm-opt not found: skipping size optimisation (the unoptimised wasm is deployable)" >&2
fi
ls -l "$OUT"/*.wasm
shasum -a 256 "$OUT"/*.wasm
if command -v python3 >/dev/null 2>&1; then
  for w in "$OUT"/*.wasm; do python3 -I check_wasm.py "$w"; done
fi
# res/ holds the committed, deployed wasm. Never overwrite it with a build that
# differs unless asked to (UPDATE_RES=1), so a reviewer's rebuild cannot clobber it.
mkdir -p res
SHA="$(shasum -a 256 "$FINAL" | awk '{print $1}')"
SIZE="$(wc -c < "$FINAL" | tr -d ' ')"
OLD_SHA=""
[[ -f "res/$NAME.wasm" ]] && OLD_SHA="$(shasum -a 256 "res/$NAME.wasm" | awk '{print $1}')"
if [[ "$SHA" == "$OLD_SHA" ]]; then
  echo "res/$NAME.wasm (from $(basename "$FINAL")): $SIZE bytes, sha256 $SHA"
  echo "MATCH: byte-identical to the committed res/$NAME.wasm"
elif [[ -z "$OLD_SHA" || "${UPDATE_RES:-}" == "1" ]]; then
  cp "$FINAL" "res/$NAME.wasm"
  echo "res/$NAME.wasm (from $(basename "$FINAL")): $SIZE bytes, sha256 $SHA"
  echo "res/$NAME.wasm updated"
else
  echo "$FINAL: $SIZE bytes, sha256 $SHA"
  echo "DIFFERS from the committed res/$NAME.wasm (sha256 $OLD_SHA); res/ left unchanged (UPDATE_RES=1 to replace it)" >&2
fi
