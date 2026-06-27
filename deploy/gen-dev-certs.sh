#!/usr/bin/env bash
# Generate a dev CA + server cert + client cert for mTLS, into deploy/certs/.
# Pure Rust (rcgen) — no openssl needed.
#
#   ./deploy/gen-dev-certs.sh [extra_server_san ...]
#
# The server cert always includes SANs: signet, localhost, 127.0.0.1 (so it
# works as `https://signet:8443` inside docker-compose and on localhost in dev).
# Pass extra SANs (hostnames or IPs) as arguments if you reach the signer under
# another name.
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
OUT="$ROOT/deploy/certs"

cargo run --quiet --release --example gen_certs --manifest-path "$ROOT/Cargo.toml" -- "$OUT" "$@"

echo
echo "Generated in $OUT:"
echo "  ca.pem / ca.key          CA (server trusts client certs signed by this)"
echo "  server.pem / server.key  Signet server cert (SANs: signet, localhost, 127.0.0.1)"
echo "  client.pem / client.key  FreedInk client cert, CN 'freedink' (mount into FreedInk)"
echo "  admin.pem  / admin.key    admin client cert, CN 'signet-admin' (for /key/rotate)"
echo
echo "These are DEV certs. For production use your real PKI and keep ca.key offline."
