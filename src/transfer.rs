//! Task 2: public transfer with the fee asserted on-chain. Also used for seizure.

use anyhow::{Context, Result};
use litesvm::LiteSVM;
use solana_clock::Clock;
use solana_keypair::Keypair;
use solana_pubkey::Pubkey;
use solana_signer::Signer;
use spl_token_2022_interface::extension::transfer_fee::TransferFeeConfig;
use spl_token_2022_interface::extension::transfer_fee::instruction::transfer_checked_with_fee;

use crate::{TOKEN_2022, send, state};

/// Fee for `amount` at the epoch the cluster is in right now. The config holds
/// an older and a newer fee; which one applies depends on the epoch, so a fee
/// rate cached earlier can be wrong after SetTransferFee.
pub fn current_fee(svm: &LiteSVM, mint: &Pubkey, amount: u64) -> Result<u64> {
    let epoch = svm.get_sysvar::<Clock>().epoch;
    state::mint_extension::<TransferFeeConfig>(svm, mint)?
        .calculate_epoch_fee(epoch, amount)
        .context("fee overflow")
}

/// Returns the fee withheld in the destination. The program rejects the
/// transfer if `fee` does not match its own calculation.
pub fn transfer_with_fee(
    svm: &mut LiteSVM,
    authority: &Keypair,
    source: &Pubkey,
    mint: &Pubkey,
    destination: &Pubkey,
    amount: u64,
) -> Result<u64> {
    let fee = current_fee(svm, mint, amount)?;
    let decimals = state::mint(svm, mint)?.decimals;
    let ix = transfer_checked_with_fee(
        &TOKEN_2022,
        source,
        mint,
        destination,
        &authority.pubkey(),
        &[],
        amount,
        decimals,
        fee,
    )?;
    send(svm, &[ix], &[authority])?;
    Ok(fee)
}

/// The permanent delegate can sign for any account of the mint, but only
/// over the public `amount`.
pub fn seize(
    svm: &mut LiteSVM,
    permanent_delegate: &Keypair,
    from: &Pubkey,
    mint: &Pubkey,
    treasury: &Pubkey,
) -> Result<u64> {
    let amount = state::account(svm, from)?.amount;
    transfer_with_fee(svm, permanent_delegate, from, mint, treasury, amount)?;
    Ok(amount)
}
