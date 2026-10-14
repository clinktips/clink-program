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

pub const MAX_FEE_BPS: u16 = 500; // 5% hard cap
pub const MIN_REFUND_SECS: i64 = 24 * 60 * 60; // 1 day
pub const MAX_REFUND_SECS: i64 = 90 * 24 * 60 * 60; // 90 days
pub const MAX_EXEMPT_MINTS: usize = 4;

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

    pub fn set_admin(ctx: Context<UpdateConfig>, new_admin: Pubkey) -> Result<()> {
        ctx.accounts.config.admin = new_admin;
        Ok(())
    }

    /// Links a social identity to a wallet. The attestor (our backend) co-signs only after the
    /// user proved ownership of the account via OAuth / Telegram login.
    pub fn link_identity(ctx: Context<LinkIdentity>, identity_hash: [u8; 32]) -> Result<()> {
        let link = &mut ctx.accounts.link;
        link.identity_hash = identity_hash;
        link.wallet = ctx.accounts.wallet.key();
        link.linked_at = Clock::get()?.unix_timestamp;
        link.bump = ctx.bumps.link;
        emit!(IdentityLinked {
            identity_hash,
            wallet: link.wallet,
        });
        Ok(())
    }

    /// Tip an identity that already linked a wallet: funds go straight to the recipient.
    pub fn tip_linked(ctx: Context<TipLinked>, identity_hash: [u8; 32], amount: u64) -> Result<()> {
        let config = &ctx.accounts.config;
        require!(!config.paused, TipError::Paused);
        require!(amount > 0, TipError::ZeroAmount);

        let fee = config.fee_for(&ctx.accounts.mint.key(), amount);
        let a = &ctx.accounts;
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
            fee,
            &[],
        )?;

        emit!(TipSent {
            tipper: a.tipper.key(),
            identity_hash,
            mint: a.mint.key(),
            amount,
            fee,
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
            tip: Some(a.tip.key()),
        });
        Ok(())
    }

    /// Recipient (the wallet linked to the tip's identity) collects an escrowed tip.
    pub fn claim_tip(ctx: Context<ClaimTip>) -> Result<()> {
        let a = &ctx.accounts;
        // Read the vault balance rather than `tip.amount` so Token-2022 transfer fees are handled.
        let amount = a.vault.amount;
        let fee = a.config.fee_for(&a.mint.key(), amount);

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
            fee,
            signer,
        )?;
        close_vault(&a.token_program, &a.vault, &a.tipper, a.tip.to_account_info(), signer)?;

        emit!(TipClaimed {
            tip: a.tip.key(),
            wallet: a.wallet.key(),
            amount,
            fee,
        });
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
#[instruction(identity_hash: [u8; 32])]
pub struct LinkIdentity<'info> {
    #[account(seeds = [CONFIG_SEED], bump = config.bump, has_one = attestor @ TipError::Unauthorized)]
    pub config: Account<'info, Config>,
    pub attestor: Signer<'info>,
    #[account(mut)]
    pub wallet: Signer<'info>,
    #[account(
        init_if_needed,
        payer = wallet,
        space = 8 + IdentityLink::INIT_SPACE,
        seeds = [LINK_SEED, identity_hash.as_ref()],
        bump
    )]
    pub link: Account<'info, IdentityLink>,
    pub system_program: Program<'info, System>,
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
    /// CHECK: must be the wallet linked to the identity.
    #[account(address = link.wallet @ TipError::WrongRecipient)]
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
    pub token_program: Interface<'info, TokenInterface>,
    pub associated_token_program: Program<'info, AssociatedToken>,
    pub system_program: Program<'info, System>,
}

#[derive(Accounts)]
pub struct ClaimTip<'info> {
    #[account(seeds = [CONFIG_SEED], bump = config.bump)]
    pub config: Account<'info, Config>,
    #[account(mut)]
    pub wallet: Signer<'info>,
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
    #[account(
        seeds = [LINK_SEED, tip.identity_hash.as_ref()],
        bump = link.bump,
        has_one = wallet @ TipError::WrongRecipient
    )]
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
        payer = wallet,
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
        payer = wallet,
        associated_token::mint = mint,
        associated_token::authority = treasury,
        associated_token::token_program = token_program
    )]
    pub treasury_token: InterfaceAccount<'info, TokenAccount>,
    pub token_program: Interface<'info, TokenInterface>,
    pub associated_token_program: Program<'info, AssociatedToken>,
    pub system_program: Program<'info, System>,
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
}

impl Config {
    fn apply(&mut self, p: ConfigParams) {
        self.attestor = p.attestor;
        self.treasury = p.treasury;
        self.fee_bps = p.fee_bps;
        self.refund_after_secs = p.refund_after_secs;
        self.fee_exempt_mints = p.fee_exempt_mints;
        self.paused = p.paused;
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
}

// ---------------------------------------------------------------------------
// Events & errors
// ---------------------------------------------------------------------------

#[event]
pub struct IdentityLinked {
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
    /// Escrow account if the recipient hasn't linked a wallet yet.
    pub tip: Option<Pubkey>,
}

#[event]
pub struct TipClaimed {
    pub tip: Pubkey,
    pub wallet: Pubkey,
    pub amount: u64,
    pub fee: u64,
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
}
