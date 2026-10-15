//! Tip Protocol — non-custodial social tipping on Solana.
//!
//! Tips are addressed to a social identity (`sha256("tipproto:v1:<platform>:<user id>")`).
//! - If the identity has linked a wallet, the tip goes straight to that wallet (`tip_linked`).
//! - Otherwise it is held in a per-tip escrow PDA (`tip_escrow`) that the recipient can
//!   `claim_tip` after linking, or the tipper can `refund_tip` once it expires.
//!
//! Trust guarantees enforced on-chain:
//! - Nobody but the linked recipient or (after expiry) the original tipper can move escrowed funds.
//! - The refund deadline is fixed per tip at creation; the admin cannot extend it later.
//! - The protocol fee is hard-capped at `MAX_FEE_BPS` and only charged on delivery, never on refunds.
//! - Pausing blocks new tips only; claims and refunds always work.
//! - Linking and claiming don't need the recipient's signature (a relayer can pay the fees), but
//!   escrowed tips can only ever go to the identity's linked wallet.
//! - The linked wallet can remove its link at any time (`unlink_identity`); nobody else can. The
//!   link's rent goes back to whoever paid it, so a relayer that paid can't be drained this way.
//! - A relayer that paid the link's rent for a pasted address is paid back once, out of the first
//!   SOL tip collected; from then on the deposit belongs to the recipient. Someone tipped only in a
//!   token can pay it in that token instead (`claim_tip_with_setup`): the relayer names the amount,
//!   but never more than the admin's cap for that token (`set_setup_cap`), and only once per link.
//! - The attestor can link a new identity instantly, but it can never silently move an existing
//!   link: switching to another wallet waits `RELINK_DELAY_SECS`, tips keep going to the current
//!   wallet meanwhile, and the current wallet can cancel the switch on its own.
//! - Servers (Discord guilds, Telegram groups) can earn a share of the protocol fee from tips sent
//!   in them. The share comes out of the fee, never out of the tip, and is capped below 100% of the
//!   fee so tipping yourself in circles always costs money.

use anchor_lang::prelude::*;
use anchor_spl::{
    associated_token::AssociatedToken,
    token_interface::{
        close_account, transfer_checked, CloseAccount, Mint, TokenAccount, TokenInterface,
        TransferChecked,
    },
};

// Replaced by `anchor keys sync` before the first deploy.
declare_id!("D95BsuB9LaGnk68SedbwMKmvP6mr4wtXnoC3oU3Nckaw");

pub const CONFIG_SEED: &[u8] = b"config";
pub const LINK_SEED: &[u8] = b"link";
pub const TIP_SEED: &[u8] = b"tip";
pub const SERVER_SEED: &[u8] = b"server";
pub const SETUP_CAP_SEED: &[u8] = b"setup_cap";

pub const MAX_FEE_BPS: u16 = 500; // 5% hard cap
pub const MIN_REFUND_SECS: i64 = 24 * 60 * 60; // 1 day
pub const MAX_REFUND_SECS: i64 = 90 * 24 * 60 * 60; // 90 days
pub const MAX_EXEMPT_MINTS: usize = 4;
pub const MAX_SERVER_SHARE_BPS: u16 = 7_500; // at most 75% of the fee goes to the server
/// Wrapped SOL. SOL tips sent with the `_sol` instructions arrive as plain SOL instead.
pub const NATIVE_MINT: Pubkey = pubkey!("So11111111111111111111111111111111111111112");
/// Size of a link account before `rent_payer` was added (see `migrate_link`).
pub const LEGACY_LINK_LEN: usize = 8 + 32 + 32 + 8 + 1 + 32 + 8;
pub const RELINK_DELAY_SECS: i64 = 3 * 24 * 60 * 60; // 3 days to notice and cancel a wallet switch

#[program]
pub mod tip_protocol {
    use super::*;

    /// One-time setup. Only the program's upgrade authority may call it, so nobody can
    /// front-run the deploy and take over the config.
    pub fn initialize(ctx: Context<Initialize>, params: ConfigParams) -> Result<()> {
        params.validate()?;
        let config = &mut ctx.accounts.config;
        config.admin = ctx.accounts.admin.key();
        config.apply(params);
        config.bump = ctx.bumps.config;
        Ok(())
    }

    pub fn update_config(ctx: Context<UpdateConfig>, params: ConfigParams) -> Result<()> {
        params.validate()?;
        ctx.accounts.config.apply(params);
        Ok(())
    }

    /// Step 1 of an admin handover: names the next admin. Nothing changes until it accepts, so a
    /// mistyped address can't lock the config forever; calling this again replaces the proposal.
    pub fn set_admin(ctx: Context<UpdateConfig>, new_admin: Pubkey) -> Result<()> {
        ctx.accounts.config.pending_admin = new_admin;
        Ok(())
    }

    /// Step 2: the proposed admin (e.g. a multisig vault) signs to take over.
    pub fn accept_admin(ctx: Context<AcceptAdmin>) -> Result<()> {
        let config = &mut ctx.accounts.config;
        config.admin = ctx.accounts.new_admin.key();
        config.pending_admin = Pubkey::default();
        Ok(())
    }

    /// Links a social identity to a wallet. The attestor (our backend) co-signs only after the
    /// user proved ownership of the account via OAuth / Telegram login. `payer` pays the rent: the
    /// user's own wallet when they connect it, or a relayer when they only paste their address, so
    /// the wallet itself doesn't have to sign.
    ///
    /// A first link takes effect at once. If the identity is already linked to another wallet, the
    /// new wallet only becomes pending and takes over after `RELINK_DELAY_SECS`, so a leaked
    /// attestor key can't redirect anyone's tips without them having days to cancel.
    pub fn link_identity(ctx: Context<LinkIdentity>, identity_hash: [u8; 32]) -> Result<()> {
        let now = Clock::get()?.unix_timestamp;
        let wallet = ctx.accounts.wallet.key();
        let link = &mut ctx.accounts.link;
        link.settle(now);
        if link.wallet == Pubkey::default() {
            link.identity_hash = identity_hash;
            link.wallet = wallet;
            link.linked_at = now;
            link.bump = ctx.bumps.link;
            link.rent_payer = ctx.accounts.payer.key();
            emit!(IdentityLinked {
                identity_hash,
                wallet,
            });
        } else if link.wallet == wallet {
            // Linking the current wallet again (signed by it) drops any pending switch.
            link.clear_pending();
        } else if link.pending_wallet != wallet {
            // Asking again for the wallet that is already pending keeps its original timer.
            link.pending_wallet = wallet;
            link.pending_at = now + RELINK_DELAY_SECS;
            emit!(RelinkRequested {
                identity_hash,
                wallet: link.wallet,
                pending_wallet: wallet,
                effective_at: link.pending_at,
            });
        }
        Ok(())
    }

    /// The currently linked wallet stops a pending switch. Needs no attestor, so it works even
    /// if the backend is down or compromised.
    pub fn cancel_relink(ctx: Context<CancelRelink>) -> Result<()> {
        let link = &mut ctx.accounts.link;
        link.settle(Clock::get()?.unix_timestamp);
        require_keys_eq!(ctx.accounts.wallet.key(), link.wallet, TipError::Unauthorized);
        require!(link.pending_wallet != Pubkey::default(), TipError::NoPendingRelink);
        link.clear_pending();
        emit!(RelinkCancelled {
            identity_hash: link.identity_hash,
            wallet: link.wallet,
        });
        Ok(())
    }

    /// The linked wallet removes the link; the identity counts as never linked afterwards. Only the
    /// current wallet can do this, never the attestor or admin. The rent goes back to whoever paid
    /// it (the wallet itself, or the relayer that linked it for a pasted address).
    pub fn unlink_identity(ctx: Context<UnlinkIdentity>) -> Result<()> {
        let link = &mut ctx.accounts.link;
        link.settle(Clock::get()?.unix_timestamp);
        require_keys_eq!(ctx.accounts.wallet.key(), link.wallet, TipError::Unauthorized);
        emit!(IdentityUnlinked {
            identity_hash: link.identity_hash,
            wallet: link.wallet,
        });
        Ok(())
    }

    /// Grows a link account created before `rent_payer` existed to the current size. Anyone may pay
    /// for it; an unknown rent payer means the rent goes back to the wallet on unlink.
    pub fn migrate_link(ctx: Context<MigrateLink>, identity_hash: [u8; 32]) -> Result<()> {
        let info = ctx.accounts.link.to_account_info();
        let (expected, _) = Pubkey::find_program_address(&[LINK_SEED, identity_hash.as_ref()], ctx.program_id);
        require_keys_eq!(info.key(), expected, TipError::Unauthorized);
        require_keys_eq!(*info.owner, crate::ID, TipError::Unauthorized);
        let new_len = 8 + IdentityLink::INIT_SPACE;
        require!(info.data_len() == LEGACY_LINK_LEN, TipError::AlreadyMigrated);
        let topup = Rent::get()?.minimum_balance(new_len).saturating_sub(info.lamports());
        sol_transfer(&ctx.accounts.system_program, &ctx.accounts.payer.to_account_info(), &info, topup)?;
        info.resize(new_len)?;
        Ok(())
    }

    /// Links a server (Discord guild / Telegram group) to the payout wallet of one of its admins.
    /// The attestor co-signs only after the bot verified the caller's admin rights. Relinking keeps
    /// any bonus the server has.
    pub fn link_server(ctx: Context<LinkServer>, server_hash: [u8; 32]) -> Result<()> {
        let server = &mut ctx.accounts.server;
        server.server_hash = server_hash;
        server.wallet = ctx.accounts.wallet.key();
        server.bump = ctx.bumps.server;
        emit!(ServerLinked {
            server_hash,
            wallet: server.wallet,
        });
        Ok(())
    }

    /// Admin-only, time-limited higher share for a server (e.g. founding servers).
    pub fn set_server_bonus(
        ctx: Context<SetServerBonus>,
        bonus_share_bps: u16,
        bonus_until: i64,
    ) -> Result<()> {
        require!(
            bonus_share_bps <= MAX_SERVER_SHARE_BPS,
            TipError::ServerShareTooHigh
        );
        let server = &mut ctx.accounts.server;
        server.bonus_share_bps = bonus_share_bps;
        server.bonus_until = bonus_until;
        Ok(())
    }

    /// Tip an identity that already linked a wallet: funds go straight to the recipient.
    pub fn tip_linked(ctx: Context<TipLinked>, identity_hash: [u8; 32], amount: u64) -> Result<()> {
        let config = &ctx.accounts.config;
        require!(!config.paused, TipError::Paused);
        require!(amount > 0, TipError::ZeroAmount);
        let now = Clock::get()?.unix_timestamp;
        require_keys_eq!(
            ctx.accounts.recipient.key(),
            ctx.accounts.link.current_wallet(now),
            TipError::WrongRecipient
        );

        let fee = config.fee_for(&ctx.accounts.mint.key(), amount);
        let a = &ctx.accounts;
        let (server_cut, server_token) =
            server_payout(&a.config, fee, &a.server, &a.server_token, &a.mint.key())?;
        transfer(
            &a.token_program,
            &a.tipper_token,
            &a.recipient_token,
            a.tipper.to_account_info(),
            &a.mint,
            amount - fee,
            &[],
        )?;
        transfer(
            &a.token_program,
            &a.tipper_token,
            &a.treasury_token,
            a.tipper.to_account_info(),
            &a.mint,
            fee - server_cut,
            &[],
        )?;
        if let Some(server_token) = server_token {
            transfer(
                &a.token_program,
                &a.tipper_token,
                server_token,
                a.tipper.to_account_info(),
                &a.mint,
                server_cut,
                &[],
            )?;
        }

        emit!(TipSent {
            tipper: a.tipper.key(),
            identity_hash,
            mint: a.mint.key(),
            amount,
            fee,
            server_cut,
            server: a.server.as_ref().map(|s| s.key()),
            tip: None,
        });
        Ok(())
    }

    /// Tip an identity that has not linked a wallet yet: funds are escrowed until claimed or
    /// refunded. `seed` lets one tipper hold many open tips.
    pub fn tip_escrow(
        ctx: Context<TipEscrow>,
        identity_hash: [u8; 32],
        amount: u64,
        seed: u64,
    ) -> Result<()> {
        let config = &ctx.accounts.config;
        require!(!config.paused, TipError::Paused);
        require!(amount > 0, TipError::ZeroAmount);

        let now = Clock::get()?.unix_timestamp;
        let tip = &mut ctx.accounts.tip;
        tip.tipper = ctx.accounts.tipper.key();
        tip.identity_hash = identity_hash;
        tip.mint = ctx.accounts.mint.key();
        tip.amount = amount;
        tip.seed = seed;
        tip.created_at = now;
        tip.expires_at = now + config.refund_after_secs;
        tip.bump = ctx.bumps.tip;
        tip.server = ctx
            .accounts
            .server
            .as_ref()
            .map(|s| s.key())
            .unwrap_or_default();

        let a = &ctx.accounts;
        transfer(
            &a.token_program,
            &a.tipper_token,
            &a.vault,
            a.tipper.to_account_info(),
            &a.mint,
            amount,
            &[],
        )?;

        emit!(TipSent {
            tipper: a.tipper.key(),
            identity_hash,
            mint: a.mint.key(),
            amount,
            fee: 0,
            server_cut: 0,
            server: a.server.as_ref().map(|s| s.key()),
            tip: Some(a.tip.key()),
        });
        Ok(())
    }

    /// Collects an escrowed tip into the wallet linked to the tip's identity. Anyone may send it
    /// (the recipient, or a relayer paying the fees): the destination is fixed by the link.
    pub fn claim_tip(ctx: Context<ClaimTip>) -> Result<()> {
        let a = &ctx.accounts;
        require_keys_eq!(
            a.wallet.key(),
            a.link.current_wallet(Clock::get()?.unix_timestamp),
            TipError::WrongRecipient
        );
        // Read the vault balance rather than `tip.amount` so Token-2022 transfer fees are handled.
        let amount = a.vault.amount;
        let fee = a.config.fee_for(&a.mint.key(), amount);
        let recorded = a.tip.server;
        let passed = a.server.as_ref().map(|s| s.key()).unwrap_or_default();
        require_keys_eq!(passed, recorded, TipError::WrongServer);
        let (server_cut, server_token) =
            server_payout(&a.config, fee, &a.server, &a.server_token, &a.mint.key())?;

        let tipper_key = a.tip.tipper;
        let seed_bytes = a.tip.seed.to_le_bytes();
        let signer: &[&[&[u8]]] = &[&[TIP_SEED, tipper_key.as_ref(), &seed_bytes, &[a.tip.bump]]];

        transfer(
            &a.token_program,
            &a.vault,
            &a.recipient_token,
            a.tip.to_account_info(),
            &a.mint,
            amount - fee,
            signer,
        )?;
        transfer(
            &a.token_program,
            &a.vault,
            &a.treasury_token,
            a.tip.to_account_info(),
            &a.mint,
            fee - server_cut,
            signer,
        )?;
        if let Some(server_token) = server_token {
            transfer(
                &a.token_program,
                &a.vault,
                server_token,
                a.tip.to_account_info(),
                &a.mint,
                server_cut,
                signer,
            )?;
        }
        close_vault(&a.token_program, &a.vault, &a.tipper, a.tip.to_account_info(), signer)?;

        emit!(TipClaimed {
            tip: a.tip.key(),
            wallet: a.wallet.key(),
            amount,
            fee,
            server_cut,
        });
        Ok(())
    }

    /// Like `tip_linked`, for SOL: moves plain SOL with system transfers, so the recipient gets
    /// SOL rather than a wrapped-SOL token account they would have to unwrap themselves.
    pub fn tip_linked_sol(
        ctx: Context<TipLinkedSol>,
        identity_hash: [u8; 32],
        amount: u64,
    ) -> Result<()> {
        let a = &ctx.accounts;
        require!(!a.config.paused, TipError::Paused);
        require!(amount > 0, TipError::ZeroAmount);
        require_keys_eq!(
            a.recipient.key(),
            a.link.current_wallet(Clock::get()?.unix_timestamp),
            TipError::WrongRecipient
        );
        let fee = a.config.fee_for(&NATIVE_MINT, amount);
        let server_cut = sol_server_cut(&a.config, fee, &a.server, &a.server_wallet)?;

        let from = a.tipper.to_account_info();
        sol_transfer(&a.system_program, &from, &a.recipient, amount - fee)?;
        sol_transfer(&a.system_program, &from, &a.treasury, fee - server_cut)?;
        if let Some(server_wallet) = &a.server_wallet {
            sol_transfer(&a.system_program, &from, server_wallet, server_cut)?;
        }

        emit!(TipSent {
            tipper: a.tipper.key(),
            identity_hash,
            mint: NATIVE_MINT,
            amount,
            fee,
            server_cut,
            server: a.server.as_ref().map(|s| s.key()),
            tip: None,
        });
        Ok(())
    }

    /// Like `claim_tip`, for escrowed SOL: unwraps the vault and pays out plain SOL. The tipper
    /// still gets back the rent of both the tip and the vault account.
    pub fn claim_tip_sol(ctx: Context<ClaimTipSol>) -> Result<()> {
        let a = &ctx.accounts;
        require_keys_eq!(
            a.wallet.key(),
            a.link.current_wallet(Clock::get()?.unix_timestamp),
            TipError::WrongRecipient
        );
        let amount = a.vault.amount;
        let fee = a.config.fee_for(&NATIVE_MINT, amount);
        let recorded = a.tip.server;
        let passed = a.server.as_ref().map(|s| s.key()).unwrap_or_default();
        require_keys_eq!(passed, recorded, TipError::WrongServer);
        let server_cut = sol_server_cut(&a.config, fee, &a.server, &a.server_wallet)?;

        // One-time setup: if a relayer paid this link's rent (the recipient only pasted an address),
        // the first SOL tip collected pays it back, and the recipient owns the deposit from then on.
        let wallet_key = a.wallet.key();
        let relayer_paid = a.link.rent_payer != Pubkey::default() && a.link.rent_payer != wallet_key;
        // The rent minimum, not the account's balance: extra SOL sent to the link can't raise it.
        let setup = if relayer_paid { Rent::get()?.minimum_balance(a.link.to_account_info().data_len()) } else { 0 };
        require!(amount - fee >= setup, TipError::TipTooSmallForSetup);

        let tipper_key = a.tip.tipper;
        let seed_bytes = a.tip.seed.to_le_bytes();
        let signer: &[&[&[u8]]] = &[&[TIP_SEED, tipper_key.as_ref(), &seed_bytes, &[a.tip.bump]]];

        // Closing a wrapped-SOL account releases all its lamports: the tip plus the account's rent.
        // Close it into the tip account (owned by this program), hand out the tip from there, and
        // let `close = tipper` return what's left (both accounts' rent) to the tipper.
        let tip_info = a.tip.to_account_info();
        close_vault(&a.token_program, &a.vault, &tip_info, tip_info.clone(), signer)?;
        tip_info.sub_lamports(amount)?;
        a.wallet.add_lamports(amount - fee - setup)?;
        a.treasury.add_lamports(fee - server_cut)?;
        if let Some(server_wallet) = &a.server_wallet {
            server_wallet.add_lamports(server_cut)?;
        }
        if setup > 0 {
            let relayer = a.rent_payer.as_ref().ok_or(TipError::WrongRentPayer)?;
            require_keys_eq!(relayer.key(), a.link.rent_payer, TipError::WrongRentPayer);
            relayer.add_lamports(setup)?;
        }

        emit!(TipClaimed {
            tip: a.tip.key(),
            wallet: wallet_key,
            amount,
            fee,
            server_cut,
        });
        if relayer_paid {
            ctx.accounts.link.rent_payer = wallet_key;
        }
        Ok(())
    }

    /// Admin: the most a relayer may take from a tip in `mint` to pay back a link's one-time setup
    /// (see `claim_tip_with_setup`). 0 turns it off for that token.
    pub fn set_setup_cap(ctx: Context<SetSetupCap>, max: u64) -> Result<()> {
        let cap = &mut ctx.accounts.setup_cap;
        cap.mint = ctx.accounts.mint.key();
        cap.max = max;
        cap.bump = ctx.bumps.setup_cap;
        Ok(())
    }

    /// Like `claim_tip`, for a recipient whose link a relayer paid for (they pasted an address) and
    /// who was tipped in a token rather than SOL: `setup_fee` of the tip goes to the relayer to pay
    /// back the setup, at most the admin's cap for this token. From then on the deposit belongs to
    /// the recipient, exactly as after `claim_tip_sol`. Only the relayer that paid can call it.
    pub fn claim_tip_with_setup(ctx: Context<ClaimTipWithSetup>, setup_fee: u64) -> Result<()> {
        let a = &ctx.accounts;
        let wallet_key = a.wallet.key();
        require_keys_eq!(
            wallet_key,
            a.link.current_wallet(Clock::get()?.unix_timestamp),
            TipError::WrongRecipient
        );
        let relayer_paid = a.link.rent_payer != Pubkey::default() && a.link.rent_payer != wallet_key;
        require!(relayer_paid, TipError::NoSetupDue);
        require_keys_eq!(a.payer.key(), a.link.rent_payer, TipError::WrongRentPayer);
        require!(setup_fee <= a.setup_cap.max, TipError::SetupFeeTooHigh);

        let amount = a.vault.amount;
        let fee = a.config.fee_for(&a.mint.key(), amount);
        require!(amount - fee >= setup_fee, TipError::TipTooSmallForSetup);
        let recorded = a.tip.server;
        let passed = a.server.as_ref().map(|s| s.key()).unwrap_or_default();
        require_keys_eq!(passed, recorded, TipError::WrongServer);
        let (server_cut, server_token) =
            server_payout(&a.config, fee, &a.server, &a.server_token, &a.mint.key())?;

        let tipper_key = a.tip.tipper;
        let seed_bytes = a.tip.seed.to_le_bytes();
        let signer: &[&[&[u8]]] = &[&[TIP_SEED, tipper_key.as_ref(), &seed_bytes, &[a.tip.bump]]];
        let tip_info = a.tip.to_account_info();

        transfer(
            &a.token_program,
            &a.vault,
            &a.recipient_token,
            tip_info.clone(),
            &a.mint,
            amount - fee - setup_fee,
            signer,
        )?;
        transfer(&a.token_program, &a.vault, &a.payer_token, tip_info.clone(), &a.mint, setup_fee, signer)?;
        transfer(
            &a.token_program,
            &a.vault,
            &a.treasury_token,
            tip_info.clone(),
            &a.mint,
            fee - server_cut,
            signer,
        )?;
        if let Some(server_token) = server_token {
            transfer(&a.token_program, &a.vault, server_token, tip_info.clone(), &a.mint, server_cut, signer)?;
        }
        close_vault(&a.token_program, &a.vault, &a.tipper, tip_info, signer)?;

        emit!(TipClaimed {
            tip: a.tip.key(),
            wallet: wallet_key,
            amount,
            fee,
            server_cut,
        });
        emit!(SetupRepaid {
            link: a.link.key(),
            relayer: a.payer.key(),
            mint: a.mint.key(),
            amount: setup_fee,
        });
        ctx.accounts.link.rent_payer = wallet_key;
        Ok(())
    }

    /// Tipper takes back an unclaimed tip after it expired. No fee is charged.
    pub fn refund_tip(ctx: Context<RefundTip>) -> Result<()> {
        let a = &ctx.accounts;
        require!(
            Clock::get()?.unix_timestamp >= a.tip.expires_at,
            TipError::NotExpired
        );

        let amount = a.vault.amount;
        let tipper_key = a.tip.tipper;
        let seed_bytes = a.tip.seed.to_le_bytes();
        let signer: &[&[&[u8]]] = &[&[TIP_SEED, tipper_key.as_ref(), &seed_bytes, &[a.tip.bump]]];

        transfer(
            &a.token_program,
            &a.vault,
            &a.tipper_token,
            a.tip.to_account_info(),
            &a.mint,
            amount,
            signer,
        )?;
        close_vault(&a.token_program, &a.vault, &a.tipper, a.tip.to_account_info(), signer)?;

        emit!(TipRefunded {
            tip: a.tip.key(),
            tipper: a.tipper.key(),
            amount,
        });
        Ok(())
    }
}

fn transfer<'info>(
    token_program: &Interface<'info, TokenInterface>,
    from: &InterfaceAccount<'info, TokenAccount>,
    to: &InterfaceAccount<'info, TokenAccount>,
    authority: AccountInfo<'info>,
    mint: &InterfaceAccount<'info, Mint>,
    amount: u64,
    signer: &[&[&[u8]]],
) -> Result<()> {
    if amount == 0 {
        return Ok(());
    }
    let accounts = TransferChecked {
        from: from.to_account_info(),
        mint: mint.to_account_info(),
        to: to.to_account_info(),
        authority,
    };
    transfer_checked(
        CpiContext::new_with_signer(token_program.to_account_info(), accounts, signer),
        amount,
        mint.decimals,
    )
}

fn close_vault<'info>(
    token_program: &Interface<'info, TokenInterface>,
    vault: &InterfaceAccount<'info, TokenAccount>,
    destination: &AccountInfo<'info>,
    authority: AccountInfo<'info>,
    signer: &[&[&[u8]]],
) -> Result<()> {
    let accounts = CloseAccount {
        account: vault.to_account_info(),
        destination: destination.clone(),
        authority,
    };
    close_account(CpiContext::new_with_signer(
        token_program.to_account_info(),
        accounts,
        signer,
    ))
}

fn sol_transfer<'info>(
    system_program: &Program<'info, System>,
    from: &AccountInfo<'info>,
    to: &AccountInfo<'info>,
    amount: u64,
) -> Result<()> {
    if amount == 0 {
        return Ok(());
    }
    let accounts = anchor_lang::system_program::Transfer {
        from: from.clone(),
        to: to.clone(),
    };
    anchor_lang::system_program::transfer(
        CpiContext::new(system_program.to_account_info(), accounts),
        amount,
    )
}

/// `server_payout` for SOL: pays the server's wallet itself instead of a token account.
fn sol_server_cut<'info>(
    config: &Config,
    fee: u64,
    server: &Option<Account<'info, ServerLink>>,
    server_wallet: &Option<UncheckedAccount<'info>>,
) -> Result<u64> {
    match (server, server_wallet) {
        (None, None) => Ok(0),
        (Some(server), Some(wallet)) => {
            require_keys_eq!(wallet.key(), server.wallet, TipError::WrongServerWallet);
            Ok(config.server_cut(fee, server, Clock::get()?.unix_timestamp))
        }
        _ => err!(TipError::WrongServerWallet),
    }
}

/// Validates the optional server accounts and returns the server's cut of `fee`.
/// Either both server accounts are passed or neither; the token account must belong to the
/// server's linked payout wallet and hold the tip's mint.
fn server_payout<'a, 'info>(
    config: &Config,
    fee: u64,
    server: &Option<Account<'info, ServerLink>>,
    server_token: &'a Option<InterfaceAccount<'info, TokenAccount>>,
    mint: &Pubkey,
) -> Result<(u64, Option<&'a InterfaceAccount<'info, TokenAccount>>)> {
    match (server, server_token) {
        (None, None) => Ok((0, None)),
        (Some(server), Some(token)) => {
            require_keys_eq!(token.owner, server.wallet, TipError::WrongServerWallet);
            require_keys_eq!(token.mint, *mint, TipError::WrongServerWallet);
            let now = Clock::get()?.unix_timestamp;
            Ok((config.server_cut(fee, server, now), Some(token)))
        }
        _ => err!(TipError::WrongServerWallet),
    }
}

// ---------------------------------------------------------------------------
// Accounts
// ---------------------------------------------------------------------------

#[derive(Accounts)]
pub struct Initialize<'info> {
    #[account(mut)]
    pub admin: Signer<'info>,
    #[account(init, payer = admin, space = 8 + Config::INIT_SPACE, seeds = [CONFIG_SEED], bump)]
    pub config: Account<'info, Config>,
    #[account(constraint = program.programdata_address()? == Some(program_data.key()) @ TipError::Unauthorized)]
    pub program: Program<'info, crate::program::TipProtocol>,
    #[account(constraint = program_data.upgrade_authority_address == Some(admin.key()) @ TipError::Unauthorized)]
    pub program_data: Account<'info, ProgramData>,
    pub system_program: Program<'info, System>,
}

#[derive(Accounts)]
pub struct UpdateConfig<'info> {
    #[account(mut, seeds = [CONFIG_SEED], bump = config.bump, has_one = admin @ TipError::Unauthorized)]
    pub config: Account<'info, Config>,
    pub admin: Signer<'info>,
}

#[derive(Accounts)]
pub struct AcceptAdmin<'info> {
    #[account(
        mut,
        seeds = [CONFIG_SEED],
        bump = config.bump,
        constraint = config.pending_admin != Pubkey::default() @ TipError::Unauthorized,
        constraint = config.pending_admin == new_admin.key() @ TipError::Unauthorized
    )]
    pub config: Account<'info, Config>,
    pub new_admin: Signer<'info>,
}

#[derive(Accounts)]
#[instruction(identity_hash: [u8; 32])]
pub struct LinkIdentity<'info> {
    #[account(seeds = [CONFIG_SEED], bump = config.bump, has_one = attestor @ TipError::Unauthorized)]
    pub config: Account<'info, Config>,
    pub attestor: Signer<'info>,
    #[account(mut)]
    pub payer: Signer<'info>,
    /// CHECK: the wallet the identity's owner chose; the attestor vouches for the identity, not the key.
    pub wallet: UncheckedAccount<'info>,
    #[account(
        init_if_needed,
        payer = payer,
        space = 8 + IdentityLink::INIT_SPACE,
        seeds = [LINK_SEED, identity_hash.as_ref()],
        bump
    )]
    pub link: Account<'info, IdentityLink>,
    pub system_program: Program<'info, System>,
}

#[derive(Accounts)]
pub struct UnlinkIdentity<'info> {
    pub wallet: Signer<'info>,
    #[account(
        mut,
        close = rent_payer,
        seeds = [LINK_SEED, link.identity_hash.as_ref()],
        bump = link.bump
    )]
    pub link: Account<'info, IdentityLink>,
    /// CHECK: receives the link's rent: whoever paid it, or the wallet if unknown (old links).
    #[account(
        mut,
        constraint = rent_payer.key() == link.refund_to() @ TipError::WrongRentPayer
    )]
    pub rent_payer: UncheckedAccount<'info>,
}

#[derive(Accounts)]
pub struct MigrateLink<'info> {
    #[account(mut)]
    pub payer: Signer<'info>,
    /// CHECK: a link account in the old layout; address, owner and size are checked in the handler.
    #[account(mut)]
    pub link: UncheckedAccount<'info>,
    pub system_program: Program<'info, System>,
}

#[derive(Accounts)]
pub struct CancelRelink<'info> {
    pub wallet: Signer<'info>,
    #[account(mut, seeds = [LINK_SEED, link.identity_hash.as_ref()], bump = link.bump)]
    pub link: Account<'info, IdentityLink>,
}

#[derive(Accounts)]
#[instruction(server_hash: [u8; 32])]
pub struct LinkServer<'info> {
    #[account(seeds = [CONFIG_SEED], bump = config.bump, has_one = attestor @ TipError::Unauthorized)]
    pub config: Account<'info, Config>,
    pub attestor: Signer<'info>,
    #[account(mut)]
    pub wallet: Signer<'info>,
    #[account(
        init_if_needed,
        payer = wallet,
        space = 8 + ServerLink::INIT_SPACE,
        seeds = [SERVER_SEED, server_hash.as_ref()],
        bump
    )]
    pub server: Account<'info, ServerLink>,
    pub system_program: Program<'info, System>,
}

#[derive(Accounts)]
pub struct SetServerBonus<'info> {
    #[account(seeds = [CONFIG_SEED], bump = config.bump, has_one = admin @ TipError::Unauthorized)]
    pub config: Account<'info, Config>,
    pub admin: Signer<'info>,
    #[account(mut, seeds = [SERVER_SEED, server.server_hash.as_ref()], bump = server.bump)]
    pub server: Account<'info, ServerLink>,
}

#[derive(Accounts)]
#[instruction(identity_hash: [u8; 32])]
pub struct TipLinked<'info> {
    #[account(seeds = [CONFIG_SEED], bump = config.bump)]
    pub config: Account<'info, Config>,
    #[account(mut)]
    pub tipper: Signer<'info>,
    #[account(seeds = [LINK_SEED, identity_hash.as_ref()], bump = link.bump)]
    pub link: Account<'info, IdentityLink>,
    /// CHECK: must be the identity's current wallet (checked in the handler).
    pub recipient: UncheckedAccount<'info>,
    #[account(mint::token_program = token_program)]
    pub mint: InterfaceAccount<'info, Mint>,
    #[account(mut, token::mint = mint, token::authority = tipper, token::token_program = token_program)]
    pub tipper_token: InterfaceAccount<'info, TokenAccount>,
    #[account(
        init_if_needed,
        payer = tipper,
        associated_token::mint = mint,
        associated_token::authority = recipient,
        associated_token::token_program = token_program
    )]
    pub recipient_token: InterfaceAccount<'info, TokenAccount>,
    /// CHECK: fee recipient from config.
    #[account(address = config.treasury @ TipError::WrongTreasury)]
    pub treasury: UncheckedAccount<'info>,
    #[account(
        init_if_needed,
        payer = tipper,
        associated_token::mint = mint,
        associated_token::authority = treasury,
        associated_token::token_program = token_program
    )]
    pub treasury_token: InterfaceAccount<'info, TokenAccount>,
    #[account(seeds = [SERVER_SEED, server.server_hash.as_ref()], bump = server.bump)]
    pub server: Option<Account<'info, ServerLink>>,
    /// Payout token account of the server's wallet (checked in `server_payout`).
    #[account(mut)]
    pub server_token: Option<InterfaceAccount<'info, TokenAccount>>,
    pub token_program: Interface<'info, TokenInterface>,
    pub associated_token_program: Program<'info, AssociatedToken>,
    pub system_program: Program<'info, System>,
}

#[derive(Accounts)]
#[instruction(identity_hash: [u8; 32], amount: u64, seed: u64)]
pub struct TipEscrow<'info> {
    #[account(seeds = [CONFIG_SEED], bump = config.bump)]
    pub config: Account<'info, Config>,
    #[account(mut)]
    pub tipper: Signer<'info>,
    #[account(mint::token_program = token_program)]
    pub mint: InterfaceAccount<'info, Mint>,
    #[account(mut, token::mint = mint, token::authority = tipper, token::token_program = token_program)]
    pub tipper_token: InterfaceAccount<'info, TokenAccount>,
    #[account(
        init,
        payer = tipper,
        space = 8 + Tip::INIT_SPACE,
        seeds = [TIP_SEED, tipper.key().as_ref(), &seed.to_le_bytes()],
        bump
    )]
    pub tip: Account<'info, Tip>,
    #[account(
        init,
        payer = tipper,
        associated_token::mint = mint,
        associated_token::authority = tip,
        associated_token::token_program = token_program
    )]
    pub vault: InterfaceAccount<'info, TokenAccount>,
    #[account(seeds = [SERVER_SEED, server.server_hash.as_ref()], bump = server.bump)]
    pub server: Option<Account<'info, ServerLink>>,
    pub token_program: Interface<'info, TokenInterface>,
    pub associated_token_program: Program<'info, AssociatedToken>,
    pub system_program: Program<'info, System>,
}

#[derive(Accounts)]
pub struct ClaimTip<'info> {
    #[account(seeds = [CONFIG_SEED], bump = config.bump)]
    pub config: Account<'info, Config>,
    /// Pays for any token accounts that need creating: the recipient or a relayer.
    #[account(mut)]
    pub payer: Signer<'info>,
    /// CHECK: must be the identity's current wallet (checked in the handler).
    pub wallet: UncheckedAccount<'info>,
    #[account(
        mut,
        close = tipper,
        has_one = tipper,
        has_one = mint,
        seeds = [TIP_SEED, tip.tipper.as_ref(), &tip.seed.to_le_bytes()],
        bump = tip.bump
    )]
    pub tip: Account<'info, Tip>,
    /// CHECK: receives the rent of the closed tip + vault accounts (checked via has_one).
    #[account(mut)]
    pub tipper: UncheckedAccount<'info>,
    #[account(mint::token_program = token_program)]
    pub mint: InterfaceAccount<'info, Mint>,
    /// Must point at `wallet` (checked in the handler, pending switches included).
    #[account(seeds = [LINK_SEED, tip.identity_hash.as_ref()], bump = link.bump)]
    pub link: Account<'info, IdentityLink>,
    #[account(
        mut,
        associated_token::mint = mint,
        associated_token::authority = tip,
        associated_token::token_program = token_program
    )]
    pub vault: InterfaceAccount<'info, TokenAccount>,
    #[account(
        init_if_needed,
        payer = payer,
        associated_token::mint = mint,
        associated_token::authority = wallet,
        associated_token::token_program = token_program
    )]
    pub recipient_token: InterfaceAccount<'info, TokenAccount>,
    /// CHECK: fee recipient from config.
    #[account(address = config.treasury @ TipError::WrongTreasury)]
    pub treasury: UncheckedAccount<'info>,
    #[account(
        init_if_needed,
        payer = payer,
        associated_token::mint = mint,
        associated_token::authority = treasury,
        associated_token::token_program = token_program
    )]
    pub treasury_token: InterfaceAccount<'info, TokenAccount>,
    #[account(seeds = [SERVER_SEED, server.server_hash.as_ref()], bump = server.bump)]
    pub server: Option<Account<'info, ServerLink>>,
    /// Payout token account of the server's wallet (checked in `server_payout`).
    #[account(mut)]
    pub server_token: Option<InterfaceAccount<'info, TokenAccount>>,
    pub token_program: Interface<'info, TokenInterface>,
    pub associated_token_program: Program<'info, AssociatedToken>,
    pub system_program: Program<'info, System>,
}

#[derive(Accounts)]
pub struct SetSetupCap<'info> {
    #[account(seeds = [CONFIG_SEED], bump = config.bump, has_one = admin @ TipError::Unauthorized)]
    pub config: Account<'info, Config>,
    #[account(mut)]
    pub admin: Signer<'info>,
    pub mint: InterfaceAccount<'info, Mint>,
    #[account(
        init_if_needed,
        payer = admin,
        space = 8 + SetupCap::INIT_SPACE,
        seeds = [SETUP_CAP_SEED, mint.key().as_ref()],
        bump
    )]
    pub setup_cap: Account<'info, SetupCap>,
    pub system_program: Program<'info, System>,
}

#[derive(Accounts)]
pub struct ClaimTipWithSetup<'info> {
    #[account(seeds = [CONFIG_SEED], bump = config.bump)]
    pub config: Box<Account<'info, Config>>,
    /// The relayer that paid the link's rent (checked in the handler); pays any new token accounts.
    #[account(mut)]
    pub payer: Signer<'info>,
    /// CHECK: must be the identity's current wallet (checked in the handler).
    pub wallet: UncheckedAccount<'info>,
    #[account(
        mut,
        close = tipper,
        has_one = tipper,
        has_one = mint,
        seeds = [TIP_SEED, tip.tipper.as_ref(), &tip.seed.to_le_bytes()],
        bump = tip.bump
    )]
    pub tip: Box<Account<'info, Tip>>,
    /// CHECK: receives the rent of the closed tip + vault accounts (checked via has_one).
    #[account(mut)]
    pub tipper: UncheckedAccount<'info>,
    #[account(mint::token_program = token_program)]
    pub mint: Box<InterfaceAccount<'info, Mint>>,
    #[account(mut, seeds = [LINK_SEED, tip.identity_hash.as_ref()], bump = link.bump)]
    pub link: Box<Account<'info, IdentityLink>>,
    /// The admin's cap for this token; the seeds tie it to `mint`.
    #[account(seeds = [SETUP_CAP_SEED, mint.key().as_ref()], bump = setup_cap.bump)]
    pub setup_cap: Box<Account<'info, SetupCap>>,
    #[account(
        mut,
        associated_token::mint = mint,
        associated_token::authority = tip,
        associated_token::token_program = token_program
    )]
    pub vault: Box<InterfaceAccount<'info, TokenAccount>>,
    #[account(
        init_if_needed,
        payer = payer,
        associated_token::mint = mint,
        associated_token::authority = wallet,
        associated_token::token_program = token_program
    )]
    pub recipient_token: Box<InterfaceAccount<'info, TokenAccount>>,
    /// Where the setup fee goes: the relayer's own token account.
    #[account(
        init_if_needed,
        payer = payer,
        associated_token::mint = mint,
        associated_token::authority = payer,
        associated_token::token_program = token_program
    )]
    pub payer_token: Box<InterfaceAccount<'info, TokenAccount>>,
    /// CHECK: fee recipient from config.
    #[account(address = config.treasury @ TipError::WrongTreasury)]
    pub treasury: UncheckedAccount<'info>,
    #[account(
        init_if_needed,
        payer = payer,
        associated_token::mint = mint,
        associated_token::authority = treasury,
        associated_token::token_program = token_program
    )]
    pub treasury_token: Box<InterfaceAccount<'info, TokenAccount>>,
    #[account(seeds = [SERVER_SEED, server.server_hash.as_ref()], bump = server.bump)]
    pub server: Option<Account<'info, ServerLink>>,
    /// Payout token account of the server's wallet (checked in `server_payout`).
    #[account(mut)]
    pub server_token: Option<InterfaceAccount<'info, TokenAccount>>,
    pub token_program: Interface<'info, TokenInterface>,
    pub associated_token_program: Program<'info, AssociatedToken>,
    pub system_program: Program<'info, System>,
}

#[derive(Accounts)]
#[instruction(identity_hash: [u8; 32])]
pub struct TipLinkedSol<'info> {
    #[account(seeds = [CONFIG_SEED], bump = config.bump)]
    pub config: Account<'info, Config>,
    #[account(mut)]
    pub tipper: Signer<'info>,
    #[account(seeds = [LINK_SEED, identity_hash.as_ref()], bump = link.bump)]
    pub link: Account<'info, IdentityLink>,
    /// CHECK: must be the identity's current wallet (checked in the handler).
    #[account(mut)]
    pub recipient: UncheckedAccount<'info>,
    /// CHECK: fee recipient from config.
    #[account(mut, address = config.treasury @ TipError::WrongTreasury)]
    pub treasury: UncheckedAccount<'info>,
    #[account(seeds = [SERVER_SEED, server.server_hash.as_ref()], bump = server.bump)]
    pub server: Option<Account<'info, ServerLink>>,
    /// CHECK: the server's payout wallet (checked in `sol_server_cut`).
    #[account(mut)]
    pub server_wallet: Option<UncheckedAccount<'info>>,
    pub system_program: Program<'info, System>,
}

#[derive(Accounts)]
pub struct ClaimTipSol<'info> {
    #[account(seeds = [CONFIG_SEED], bump = config.bump)]
    pub config: Account<'info, Config>,
    /// Pays the transaction fee: the recipient or a relayer. Nothing needs creating here.
    pub payer: Signer<'info>,
    /// CHECK: must be the identity's current wallet (checked in the handler).
    #[account(mut)]
    pub wallet: UncheckedAccount<'info>,
    #[account(
        mut,
        close = tipper,
        has_one = tipper,
        has_one = mint,
        seeds = [TIP_SEED, tip.tipper.as_ref(), &tip.seed.to_le_bytes()],
        bump = tip.bump
    )]
    pub tip: Account<'info, Tip>,
    /// CHECK: receives the rent of the closed tip and vault accounts (checked via has_one).
    #[account(mut)]
    pub tipper: UncheckedAccount<'info>,
    #[account(address = NATIVE_MINT @ TipError::NotSol, mint::token_program = token_program)]
    pub mint: InterfaceAccount<'info, Mint>,
    #[account(mut, seeds = [LINK_SEED, tip.identity_hash.as_ref()], bump = link.bump)]
    pub link: Account<'info, IdentityLink>,
    #[account(
        mut,
        associated_token::mint = mint,
        associated_token::authority = tip,
        associated_token::token_program = token_program
    )]
    pub vault: InterfaceAccount<'info, TokenAccount>,
    /// CHECK: fee recipient from config.
    #[account(mut, address = config.treasury @ TipError::WrongTreasury)]
    pub treasury: UncheckedAccount<'info>,
    #[account(seeds = [SERVER_SEED, server.server_hash.as_ref()], bump = server.bump)]
    pub server: Option<Account<'info, ServerLink>>,
    /// CHECK: the server's payout wallet (checked in `sol_server_cut`).
    #[account(mut)]
    pub server_wallet: Option<UncheckedAccount<'info>>,
    /// CHECK: the relayer that paid the link's rent, paid back once (checked in the handler).
    #[account(mut)]
    pub rent_payer: Option<UncheckedAccount<'info>>,
    pub token_program: Interface<'info, TokenInterface>,
}

#[derive(Accounts)]
pub struct RefundTip<'info> {
    #[account(mut)]
    pub tipper: Signer<'info>,
    #[account(
        mut,
        close = tipper,
        has_one = tipper,
        has_one = mint,
        seeds = [TIP_SEED, tipper.key().as_ref(), &tip.seed.to_le_bytes()],
        bump = tip.bump
    )]
    pub tip: Account<'info, Tip>,
    #[account(mint::token_program = token_program)]
    pub mint: InterfaceAccount<'info, Mint>,
    #[account(
        mut,
        associated_token::mint = mint,
        associated_token::authority = tip,
        associated_token::token_program = token_program
    )]
    pub vault: InterfaceAccount<'info, TokenAccount>,
    #[account(
        init_if_needed,
        payer = tipper,
        associated_token::mint = mint,
        associated_token::authority = tipper,
        associated_token::token_program = token_program
    )]
    pub tipper_token: InterfaceAccount<'info, TokenAccount>,
    pub token_program: Interface<'info, TokenInterface>,
    pub associated_token_program: Program<'info, AssociatedToken>,
    pub system_program: Program<'info, System>,
}

// ---------------------------------------------------------------------------
// State
// ---------------------------------------------------------------------------

#[derive(AnchorSerialize, AnchorDeserialize, Clone)]
pub struct ConfigParams {
    pub attestor: Pubkey,
    pub treasury: Pubkey,
    pub fee_bps: u16,
    pub refund_after_secs: i64,
    /// Mints that pay no protocol fee (e.g. the project's own coin once it launches).
    pub fee_exempt_mints: Vec<Pubkey>,
    pub paused: bool,
    /// Share of the fee paid to the server a tip was sent in, in bps of the fee.
    pub server_share_bps: u16,
}

impl ConfigParams {
    fn validate(&self) -> Result<()> {
        require!(self.fee_bps <= MAX_FEE_BPS, TipError::FeeTooHigh);
        require!(
            (MIN_REFUND_SECS..=MAX_REFUND_SECS).contains(&self.refund_after_secs),
            TipError::InvalidRefundWindow
        );
        require!(
            self.fee_exempt_mints.len() <= MAX_EXEMPT_MINTS,
            TipError::TooManyExemptMints
        );
        require!(
            self.server_share_bps <= MAX_SERVER_SHARE_BPS,
            TipError::ServerShareTooHigh
        );
        Ok(())
    }
}

#[account]
#[derive(InitSpace)]
pub struct Config {
    pub admin: Pubkey,
    pub attestor: Pubkey,
    pub treasury: Pubkey,
    pub fee_bps: u16,
    pub refund_after_secs: i64,
    pub paused: bool,
    #[max_len(4)]
    pub fee_exempt_mints: Vec<Pubkey>,
    pub bump: u8,
    pub server_share_bps: u16,
    /// Proposed next admin (see `set_admin`), or the default key for none.
    pub pending_admin: Pubkey,
}

impl Config {
    fn apply(&mut self, p: ConfigParams) {
        self.attestor = p.attestor;
        self.treasury = p.treasury;
        self.fee_bps = p.fee_bps;
        self.refund_after_secs = p.refund_after_secs;
        self.fee_exempt_mints = p.fee_exempt_mints;
        self.paused = p.paused;
        self.server_share_bps = p.server_share_bps;
    }

    /// The server's part of `fee`; a running bonus overrides the default share.
    pub fn server_cut(&self, fee: u64, server: &ServerLink, now: i64) -> u64 {
        let bps = if now < server.bonus_until {
            server.bonus_share_bps
        } else {
            self.server_share_bps
        };
        // Both shares are capped at MAX_SERVER_SHARE_BPS, so this never exceeds `fee`.
        ((fee as u128) * (bps.min(MAX_SERVER_SHARE_BPS) as u128) / 10_000) as u64
    }

    pub fn fee_for(&self, mint: &Pubkey, amount: u64) -> u64 {
        if self.fee_exempt_mints.contains(mint) {
            return 0;
        }
        // fee_bps <= 500, so this can't overflow or exceed `amount`.
        ((amount as u128) * (self.fee_bps as u128) / 10_000) as u64
    }
}

#[account]
#[derive(InitSpace)]
pub struct IdentityLink {
    pub identity_hash: [u8; 32],
    pub wallet: Pubkey,
    pub linked_at: i64,
    pub bump: u8,
    /// Wallet waiting to take over, or the default key for none.
    pub pending_wallet: Pubkey,
    /// When `pending_wallet` takes over.
    pub pending_at: i64,
    /// Who paid this account's rent and gets it back on unlink; the default key for old links.
    pub rent_payer: Pubkey,
}

impl IdentityLink {
    fn has_pending(&self) -> bool {
        self.pending_wallet != Pubkey::default()
    }

    /// The wallet tips go to right now: the pending one once its delay has passed.
    pub fn current_wallet(&self, now: i64) -> Pubkey {
        if self.has_pending() && now >= self.pending_at {
            self.pending_wallet
        } else {
            self.wallet
        }
    }

    /// Writes a switch whose delay has passed into `wallet`.
    fn settle(&mut self, now: i64) {
        if self.has_pending() && now >= self.pending_at {
            self.wallet = self.pending_wallet;
            self.linked_at = self.pending_at;
            self.clear_pending();
        }
    }

    /// Where the rent goes when the link is removed.
    pub fn refund_to(&self) -> Pubkey {
        if self.rent_payer == Pubkey::default() {
            self.wallet
        } else {
            self.rent_payer
        }
    }

    fn clear_pending(&mut self) {
        self.pending_wallet = Pubkey::default();
        self.pending_at = 0;
    }
}

#[account]
#[derive(InitSpace)]
pub struct Tip {
    pub tipper: Pubkey,
    pub identity_hash: [u8; 32],
    pub mint: Pubkey,
    pub amount: u64,
    pub seed: u64,
    pub created_at: i64,
    pub expires_at: i64,
    pub bump: u8,
    /// ServerLink the tip was sent in, or the default key for none.
    pub server: Pubkey,
}

#[account]
#[derive(InitSpace)]
pub struct ServerLink {
    pub server_hash: [u8; 32],
    pub wallet: Pubkey,
    pub bonus_share_bps: u16,
    pub bonus_until: i64,
    pub bump: u8,
}

// ---------------------------------------------------------------------------
// Events & errors
// ---------------------------------------------------------------------------

/// The most a relayer may take from one tip in `mint` for a link's one-time setup.
#[account]
#[derive(InitSpace)]
pub struct SetupCap {
    pub mint: Pubkey,
    pub max: u64,
    pub bump: u8,
}

#[event]
pub struct SetupRepaid {
    pub link: Pubkey,
    pub relayer: Pubkey,
    pub mint: Pubkey,
    pub amount: u64,
}

#[event]
pub struct IdentityLinked {
    pub identity_hash: [u8; 32],
    pub wallet: Pubkey,
}

#[event]
pub struct RelinkRequested {
    pub identity_hash: [u8; 32],
    pub wallet: Pubkey,
    pub pending_wallet: Pubkey,
    pub effective_at: i64,
}

#[event]
pub struct IdentityUnlinked {
    pub identity_hash: [u8; 32],
    pub wallet: Pubkey,
}

#[event]
pub struct RelinkCancelled {
    pub identity_hash: [u8; 32],
    pub wallet: Pubkey,
}

#[event]
pub struct TipSent {
    pub tipper: Pubkey,
    pub identity_hash: [u8; 32],
    pub mint: Pubkey,
    pub amount: u64,
    pub fee: u64,
    pub server_cut: u64,
    pub server: Option<Pubkey>,
    /// Escrow account if the recipient hasn't linked a wallet yet.
    pub tip: Option<Pubkey>,
}

#[event]
pub struct TipClaimed {
    pub tip: Pubkey,
    pub wallet: Pubkey,
    pub amount: u64,
    pub fee: u64,
    pub server_cut: u64,
}

#[event]
pub struct ServerLinked {
    pub server_hash: [u8; 32],
    pub wallet: Pubkey,
}

#[event]
pub struct TipRefunded {
    pub tip: Pubkey,
    pub tipper: Pubkey,
    pub amount: u64,
}

#[error_code]
pub enum TipError {
    #[msg("Not authorized")]
    Unauthorized,
    #[msg("Fee exceeds the hard cap")]
    FeeTooHigh,
    #[msg("Refund window out of range")]
    InvalidRefundWindow,
    #[msg("Too many fee-exempt mints")]
    TooManyExemptMints,
    #[msg("Tipping is paused")]
    Paused,
    #[msg("Amount must be greater than zero")]
    ZeroAmount,
    #[msg("Recipient does not match the linked wallet")]
    WrongRecipient,
    #[msg("Treasury does not match config")]
    WrongTreasury,
    #[msg("Tip has not expired yet")]
    NotExpired,
    #[msg("Server share exceeds the hard cap")]
    ServerShareTooHigh,
    #[msg("Server payout account does not match the server's wallet")]
    WrongServerWallet,
    #[msg("Server does not match the one the tip was sent in")]
    WrongServer,
    #[msg("No wallet switch is pending")]
    NoPendingRelink,
    #[msg("Only SOL tips can use this instruction")]
    NotSol,
    #[msg("Rent must go back to whoever paid it")]
    WrongRentPayer,
    #[msg("This link already has the current layout")]
    AlreadyMigrated,
    #[msg("The tip is too small to cover the one-time setup")]
    TipTooSmallForSetup,
    #[msg("Setup fee is above the cap for this token")]
    SetupFeeTooHigh,
    #[msg("This link has no setup to pay back")]
    NoSetupDue,
}

#[cfg(test)]
mod tests {
    use super::*;

    fn link(wallet: Pubkey) -> IdentityLink {
        IdentityLink {
            identity_hash: [7; 32],
            wallet,
            linked_at: 0,
            bump: 255,
            pending_wallet: Pubkey::default(),
            pending_at: 0,
            rent_payer: Pubkey::default(),
        }
    }

    #[test]
    fn pending_switch_waits_for_the_delay() {
        let (old, new) = (Pubkey::new_unique(), Pubkey::new_unique());
        let mut l = link(old);
        l.pending_wallet = new;
        l.pending_at = 1_000 + RELINK_DELAY_SECS;
        assert_eq!(l.current_wallet(1_000), old);
        assert_eq!(l.current_wallet(l.pending_at - 1), old);
        assert_eq!(l.current_wallet(l.pending_at), new);
    }

    #[test]
    fn settle_applies_only_a_due_switch() {
        let (old, new) = (Pubkey::new_unique(), Pubkey::new_unique());
        let mut l = link(old);
        l.pending_wallet = new;
        l.pending_at = 5_000;

        l.settle(4_999);
        assert_eq!((l.wallet, l.pending_wallet), (old, new));

        l.settle(5_000);
        assert_eq!(l.wallet, new);
        assert_eq!(l.linked_at, 5_000);
        assert!(!l.has_pending());
        assert_eq!(l.current_wallet(9_999), new);
    }

    #[test]
    fn rent_goes_back_to_the_payer_or_the_wallet() {
        let (wallet, relayer) = (Pubkey::new_unique(), Pubkey::new_unique());
        let mut l = link(wallet);
        assert_eq!(l.refund_to(), wallet, "old links: unknown payer, refund the wallet");
        l.rent_payer = relayer;
        assert_eq!(l.refund_to(), relayer);
    }

    #[test]
    fn legacy_size_matches_the_layout_without_rent_payer() {
        assert_eq!(LEGACY_LINK_LEN + 32, 8 + IdentityLink::INIT_SPACE);
    }

    #[test]
    fn no_pending_means_current_wallet_never_changes() {
        let old = Pubkey::new_unique();
        let mut l = link(old);
        l.settle(i64::MAX);
        assert_eq!(l.current_wallet(i64::MAX), old);
    }
}
