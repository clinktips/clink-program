# clink program

The on-chain program behind [clink](https://clinktips.com): non-custodial tipping on Solana for Discord and Telegram.

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
- **SOL** has its own instructions (`tip_linked_sol`, `claim_tip_sol`) that move plain SOL, so recipients never end up holding wrapped SOL.
- **Linking** (`link_identity`) needs a co-signature from the clink attestor, given only after the person logs in with that Discord or Telegram account.
- **Recipients don't have to sign.** Linking and claiming take a separate payer, so clink can pay the fees for someone who only pasted their address. The payout still goes only to the identity's linked wallet; the program checks it on every claim.
- **Servers** (Discord servers, Telegram groups) can link a payout wallet (`link_server`) and receive part of the protocol fee from tips sent in them.

## What the program guarantees

- Escrowed tips can only go to the recipient's linked wallet, or back to the tipper after expiry. Nobody else can move them, the team included.
- The refund deadline is fixed per tip when it's created; it can't be extended later.
- The protocol fee is capped at 5% (`MAX_FEE_BPS`) and charged only when a tip is delivered, never on refunds. A server's share comes out of that fee, never out of the tip, and is capped at 75% of it.
- Pausing blocks new tips only. Claims and refunds always work.
- An existing link can't be moved silently. Switching to another wallet waits 3 days (`RELINK_DELAY_SECS`); until then tips keep going to the current wallet, and that wallet can cancel the switch on its own (`cancel_relink`).
- The linked wallet can remove its link at any time (`unlink_identity`); nobody else can. The link's rent goes back to whoever paid it.
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

You can check that the program on devnet is built from this repository. Build it in the Anchor image, pinned by digest so everyone gets the same compiler, then compare it with the deployed bytes:

```
docker run --rm -v "$PWD:/src:ro" solanafoundation/anchor@sha256:21ab8a16e19df4301a198d7a55ab2988549aa2d996e6b5ad229c1d95b9f2d326 bash -lc '
  cp -r /src /build && cd /build &&
  cargo build-sbf --manifest-path programs/tip_protocol/Cargo.toml -- --locked >/dev/null 2>&1 &&
  solana program dump -u devnet D95BsuB9LaGnk68SedbwMKmvP6mr4wtXnoC3oU3Nckaw /tmp/onchain.so >/dev/null &&
  for f in target/deploy/tip_protocol.so /tmp/onchain.so; do python3 -c "import sys,hashlib;print(hashlib.sha256(open(sys.argv[1],\"rb\").read().rstrip(b\"\0\")).hexdigest())" $f; done'
```

Both lines print the same hash. Trailing zero bytes are stripped first, because the program account is larger than the program. This is the same hash `solana-verify get-program-hash` reports. At the current commit the hash is `ca8727c4ce3aedc77301f5cd4c98b1ced683c24e82c8a269d8a35e1f4aaff2d3`.

Explorers show a "Verified" badge only on mainnet, because the public verification service doesn't support devnet. The mainnet program will be submitted there at launch.

## Reporting a vulnerability

See [SECURITY.md](SECURITY.md).
