#!/usr/bin/env bash
# Build the Rust interop tool and run the cross-language check against the real
# @cloudflare/blindrsa-ts library. Exits 0 and prints INTEROP OK on success.
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
NODE_DIR="$ROOT/interop/node"

echo "[1/3] building interop_tool (release)..."
cargo build --release --example interop_tool --manifest-path "$ROOT/Cargo.toml" >/dev/null

BIN="$ROOT/target/release/examples/interop_tool"
if [[ ! -x "$BIN" ]]; then
  echo "interop_tool binary not found at $BIN" >&2
  exit 1
fi

echo "[2/3] installing TS deps (pinned @cloudflare/blindrsa-ts)..."
if [[ ! -d "$NODE_DIR/node_modules/@cloudflare/blindrsa-ts" ]]; then
  ( cd "$NODE_DIR" && npm install --silent --no-audit --no-fund )
fi

echo "[3/3] running interop driver..."
SIGNET_INTEROP_BIN="$BIN" node "$NODE_DIR/interop.mjs"
