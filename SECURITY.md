# Security

clink is non-custodial: this program moves money, and only when the person whose money it is signs. This page lists what the code guarantees, what you still have to trust us for, and how each of those is limited.

## What the program enforces

These hold no matter what our servers or bots do:

- **You sign every payment yourself.** The bots and website only build transactions. Your wallet shows the program and the amount before you approve.
- **Unclaimed tips are locked in the program.** Only the recipient's linked wallet can claim one, and once it expires only the original tipper can take it back.
- **Fixed refund deadline.** It is set when the tip is made and can't be extended.
- **Capped fees.** At most 5%, charged only on delivery, never on refunds. A server's share comes out of that fee, never out of the tip.
- **Pausing can't trap funds.** It blocks new tips only.
- **The one-time setup is limited to 10% of a tip.** If you collect by pasting an address, our fee wallet pays the network's account deposits. A tip pays them back once, but only if that's at most 10% of the tip: exactly the deposit from a SOL tip, or from another coin the same amount converted at the current price. The program refuses anything above 10%. If none of your tips is big enough, collecting by pasting isn't offered; connecting a wallet you already have still works, because it pays the setup itself. Once paid back, the deposit is yours.
- **Linked wallets can't be moved silently.** See below.

## What you trust us for, and how it's limited

### The attestor (account linking)

Linking "this Discord or Telegram account belongs to this wallet" needs a co-signature from our attestor key, given only after you log in with that account. If that key leaked, an attacker could claim to own your account. Limits:

- **A first link takes effect at once,** so collecting your first tip is one click. This means a leaked key could collect tips waiting for someone who has *never* linked a wallet. Tips to anyone who has linked are not exposed this way.
- **An existing link can't be moved instantly.** Switching to another wallet waits 3 days, enforced by the program. During that time tips keep going to your current wallet, our bot messages you about the pending switch, and your current wallet alone can cancel it (`cancel_relink`), without us.
- **Every link is public.** Links and switch requests are on-chain events (`IdentityLinked`, `RelinkRequested`, `RelinkCancelled`) anyone can watch.
- **The key can be replaced** by the admin at any time.

### The upgrade key and the admin

Whoever holds the upgrade key can replace the program. Before mainnet, both roles move to [Squads](https://squads.so) multisigs, so no single person or stolen laptop can change anything:

| Role | What it can do | Holder on mainnet |
|---|---|---|
| Upgrade authority | Replace the program code | Squads multisig, 2 of 3 keys, 48-hour time lock before an upgrade executes |
| Admin | Pause new tips, set fees (max 5%), rotate the attestor, set server bonuses | Squads multisig, 2 of 3 keys |

The time lock gives everyone two days to see an upgrade coming. Admin changes are two-step: the new admin has to accept. Both holders are visible in any Solana explorer. Once the program is stable, the plan is to make it immutable.

## Before mainnet

- [ ] Upgrade authority and admin on Squads multisigs as above
- [ ] Attestor key on its own host, separate from the public web server
- [ ] Verified build submitted for the deployed program
- [ ] External audit of this program

## Reporting a vulnerability

Email **hello@clinktips.com** with the subject "security". Please don't open a public issue for anything that could put funds at risk. We'll reply within 48 hours.
