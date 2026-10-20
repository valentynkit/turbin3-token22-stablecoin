//! Task 4: accounts start frozen (DefaultAccountState) and are thawed one by one after KYC.

use anyhow::Result;
use litesvm::LiteSVM;
use solana_keypair::Keypair;
use solana_pubkey::Pubkey;
use solana_signer::Signer;
use spl_associated_token_account_interface::instruction::create_associated_token_account_idempotent;
use spl_token_2022_interface::instruction::{freeze_account, thaw_account};

use crate::{TOKEN_2022, ata, send};

/// Anyone can pay for someone else's ATA. On this mint it is born Frozen.
pub fn open_account(
    svm: &mut LiteSVM,
    payer: &Keypair,
    owner: &Pubkey,
    mint: &Pubkey,
) -> Result<Pubkey> {
    let ix = create_associated_token_account_idempotent(&payer.pubkey(), owner, mint, &TOKEN_2022);
    send(svm, &[ix], &[payer])?;
    Ok(ata(owner, mint))
}

/// Thaws this one account. The mint default stays Frozen, so the next new
/// account is still gated; UpdateDefaultAccountState would open every wallet.
pub fn approve_kyc(
    svm: &mut LiteSVM,
    freeze_authority: &Keypair,
    account: &Pubkey,
    mint: &Pubkey,
) -> Result<()> {
    let ix = thaw_account(&TOKEN_2022, account, mint, &freeze_authority.pubkey(), &[])?;
    send(svm, &[ix], &[freeze_authority])
}

pub fn freeze(
    svm: &mut LiteSVM,
    freeze_authority: &Keypair,
    account: &Pubkey,
    mint: &Pubkey,
) -> Result<()> {
    let ix = freeze_account(&TOKEN_2022, account, mint, &freeze_authority.pubkey(), &[])?;
    send(svm, &[ix], &[freeze_authority])
}
