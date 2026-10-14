#!/usr/bin/env bash
# Builds the program inside the Anchor Docker image (see scripts/solana.ps1).
set -euo pipefail
if [ ! -f Cargo.lock ]; then
  # Pick crate versions compatible with Solana's bundled rustc (rust-version in Cargo.toml).
  CARGO_RESOLVER_INCOMPATIBLE_RUST_VERSIONS=fallback cargo generate-lockfile
  # blake3 >= 1.6 pulls in edition-2024 crates the bundled cargo can't parse.
  cargo update -p blake3 --precise 1.5.5
fi
anchor build "$@" 2>&1 | grep -vE '^\s+(Compiling|Downloaded|Downloading|Locking|Adding)' || true
test -f target/deploy/tip_protocol.so && echo "BUILD OK: $(du -h target/deploy/tip_protocol.so | cut -f1)"
