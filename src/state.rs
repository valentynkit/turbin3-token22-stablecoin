//! Task 3: every read of mint or account state goes through StateWithExtensions.

use anyhow::{Context, Result};
use bytemuck::Pod;
use litesvm::LiteSVM;
use solana_pubkey::Pubkey;
use spl_token_2022_interface::extension::{
    BaseStateWithExtensions, Extension, ExtensionType, StateWithExtensions,
};
use spl_token_2022_interface::state::{Account, Mint};
use spl_token_metadata_interface::state::TokenMetadata;

fn data(svm: &LiteSVM, address: &Pubkey) -> Result<Vec<u8>> {
    Ok(svm.get_account(address).context("account not found")?.data)
}

pub fn mint(svm: &LiteSVM, mint: &Pubkey) -> Result<Mint> {
    Ok(StateWithExtensions::<Mint>::unpack(&data(svm, mint)?)?.base)
}

pub fn account(svm: &LiteSVM, account: &Pubkey) -> Result<Account> {
    Ok(StateWithExtensions::<Account>::unpack(&data(svm, account)?)?.base)
}

pub fn mint_extension<E: Extension + Pod>(svm: &LiteSVM, mint: &Pubkey) -> Result<E> {
    let data = data(svm, mint)?;
    Ok(*StateWithExtensions::<Mint>::unpack(&data)?.get_extension::<E>()?)
}

pub fn account_extension<E: Extension + Pod>(svm: &LiteSVM, account: &Pubkey) -> Result<E> {
    let data = data(svm, account)?;
    Ok(*StateWithExtensions::<Account>::unpack(&data)?.get_extension::<E>()?)
}

/// TokenMetadata lives in the mint's own TLV data (MetadataPointer points at the mint).
pub fn metadata(svm: &LiteSVM, mint: &Pubkey) -> Result<TokenMetadata> {
    let data = data(svm, mint)?;
    Ok(
        StateWithExtensions::<Mint>::unpack(&data)?
            .get_variable_len_extension::<TokenMetadata>()?,
    )
}

pub fn mint_extension_types(svm: &LiteSVM, mint: &Pubkey) -> Result<Vec<ExtensionType>> {
    Ok(StateWithExtensions::<Mint>::unpack(&data(svm, mint)?)?.get_extension_types()?)
}

pub fn account_extension_types(svm: &LiteSVM, account: &Pubkey) -> Result<Vec<ExtensionType>> {
    Ok(StateWithExtensions::<Account>::unpack(&data(svm, account)?)?.get_extension_types()?)
}
