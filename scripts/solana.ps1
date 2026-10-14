# Runs Solana/Anchor commands in Docker (no WSL/Rust install needed on Windows).
#   .\scripts\solana.ps1 "anchor build"
#   .\scripts\solana.ps1 "solana balance"
# The deployer wallet lives in the `tipproto-solana` Docker volume, never in this folder.
param([Parameter(Mandatory)][string]$Command)

$root = Split-Path $PSScriptRoot -Parent
docker run --rm `
  -v "${root}:/work" `
  -v tipproto-solana:/root/.config/solana `
  -v tipproto-cargo:/root/.cargo/registry `
  -w /work `
  solanafoundation/anchor:v0.31.1 bash -lc $Command
