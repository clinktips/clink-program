#!/usr/bin/env bash
# Runs the program's Rust unit tests inside the Anchor Docker image (see scripts/solana.ps1).
set -euo pipefail
cargo test -p tip-protocol --lib 2>&1 | grep -vE '^\s+(Compiling|Downloaded|Downloading|Locking|Adding)'
