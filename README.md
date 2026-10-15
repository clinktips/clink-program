# clink program

The on-chain program behind [clink](https://clink.tips): non-custodial tipping on Solana for Discord and Telegram.

This repository holds the code that moves money, so anyone can read exactly what it does and check that it matches what is deployed. The bots, backend and website only build transactions; every payment is signed in the user's own wallet and runs through this program.

| | |
|---|---|
| Program id | `D95BsuB9LaGnk68SedbwMKmvP6mr4wtXnoC3oU3Nckaw` |
| Status | Devnet preview. Not deployed to mainnet. |
| Framework | Anchor 0.31.1 |
| License | Apache-2.0 |

## How it works

Tips are addressed to a social identity, `sha256("tipproto:v1:<platform>:<user id>")`, using the platform's permanent numeric user id, never a username.

- **Recipient has linked a wallet:** `tip_linked` sends the tip straight to it.
- **Recipient hasn't linked one yet:** `tip_escrow` locks the tip in an account only this program controls. The recipient collects it with `claim_tip` after linking a wallet, or the tipper takes it back with `refund_tip` once it expires.
- **Linking** (`link_identity`) needs a co-signature from the clink attestor, given only after the person logs in with that Discord or Telegram account.
- **Servers** (Discord servers, Telegram groups) can link a payout wallet (`link_server`) and receive part of the protocol fee from tips sent in them.

## What the program guarantees

- Escrowed tips can only go to the recipient's linked wallet, or back to the tipper after expiry. Nobody else can move them, the team included.
- The refund deadline is fixed per tip when it's created; it can't be extended later.
- The protocol fee is capped at 5% (`MAX_FEE_BPS`) and charged only when a tip is delivered, never on refunds. A server's share comes out of that fee, never out of the tip, and is capped at 75% of it.
- Pausing blocks new tips only. Claims and refunds always work.
- An existing link can't be moved silently. Switching to another wallet waits 3 days (`RELINK_DELAY_SECS`); until then tips keep going to the current wallet, and that wallet can cancel the switch on its own (`cancel_relink`).
- Only the program's upgrade authority can initialize the config, and admin handovers are two-step (`set_admin`, then `accept_admin` by the new admin).

[SECURITY.md](SECURITY.md) lists what you still have to trust us for and how each part is limited.

## Build

Builds inside the official Anchor Docker image, so no local Rust or Solana install is needed.

```bash
docker run --rm -v "$PWD:/work" -w /work solanafoundation/anchor:v0.31.1 bash scripts/build.sh
```

On Windows: `.\scripts\solana.ps1 'bash scripts/build.sh'`. The output is `target/deploy/tip_protocol.so`.

`Cargo.lock` is committed and the crate pins `rust-version = "1.79"` (the compiler in Solana's platform tools), so builds are reproducible.

## Test

```bash
docker run --rm -v "$PWD:/work" -w /work solanafoundation/anchor:v0.31.1 bash scripts/unit-test.sh
```

These unit tests cover the wallet-switch timing. The end-to-end suite (26 checks against a local validator, including the attack cases: fake attestor, wrong wallet claiming, fee above the cap, early refund, a leaked attestor key moving a link, a tampered recipient, an unaccepted admin handover) drives clink's transaction builders and lives with the backend.

## Verified build

Once deployed, the program will be submitted for a verified build, so explorers can show that the deployed bytecode matches a commit in this repository. Until then, treat the program id above as unverified.

## Reporting a vulnerability

See [SECURITY.md](SECURITY.md).
