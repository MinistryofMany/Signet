#!/usr/bin/env bash
# Build the Rust PRF interop tool and run the cross-language VOPRF check
# against the real @cloudflare/voprf-ts library (the ADR Phase 2 suite
# decision gate). Exits 0 and prints PRF INTEROP OK on success.
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
INTEROP_DIR="$ROOT/interop"

echo "[1/3] building prf_interop_tool (release)..."
cargo build --release --example prf_interop_tool --manifest-path "$ROOT/Cargo.toml" >/dev/null

BIN="$ROOT/target/release/examples/prf_interop_tool"
if [[ ! -x "$BIN" ]]; then
  echo "prf_interop_tool binary not found at $BIN" >&2
  exit 1
fi

echo "[2/3] installing TS deps (pinned @cloudflare/voprf-ts)..."
if [[ ! -d "$INTEROP_DIR/node_modules/@cloudflare/voprf-ts" ]]; then
  ( cd "$INTEROP_DIR" && npm install --silent --no-audit --no-fund )
fi

echo "[3/3] running PRF interop driver..."
node "$INTEROP_DIR/prf.mjs" "$INTEROP_DIR/prf-vectors.json" "$BIN"
