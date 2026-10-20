//! Tasks 1 and 5: create the stablecoin mint, and re-issue it with confidential transfers.

use std::mem::size_of;

use anyhow::Result;
use litesvm::LiteSVM;
use solana_keypair::Keypair;
use solana_pubkey::Pubkey;
use solana_signer::Signer;
use solana_system_interface::instruction::create_account;
use solana_zk_sdk::encryption::elgamal::ElGamalPubkey;
use spl_token_2022_interface::extension::{
    ExtensionType, Length, confidential_transfer, confidential_transfer_fee,
    default_account_state::instruction::initialize_default_account_state, metadata_pointer,
    transfer_fee::instruction::initialize_transfer_fee_config,
};
use spl_token_2022_interface::instruction::{
    burn_checked, close_account, initialize_mint_close_authority, initialize_mint2,
    initialize_permanent_delegate, mint_to_checked,
};
use spl_token_2022_interface::state::{AccountState, Mint};
use spl_token_metadata_interface::state::TokenMetadata;
use spl_type_length_value::variable_len_pack::VariableLenPack;

use crate::{TOKEN_2022, send};

pub const BASE_EXTENSIONS: [ExtensionType; 4] = [
    ExtensionType::TransferFeeConfig,
    ExtensionType::MetadataPointer,
    ExtensionType::DefaultAccountState,
    ExtensionType::MintCloseAuthority,
];

/// Added on re-issue. InitializeMint rejects TransferFeeConfig plus
/// ConfidentialTransferMint without ConfidentialTransferFeeConfig.
pub const CONFIDENTIAL_EXTENSIONS: [ExtensionType; 3] = [
    ExtensionType::PermanentDelegate,
    ExtensionType::ConfidentialTransferMint,
    ExtensionType::ConfidentialTransferFeeConfig,
];

pub struct MintConfig {
    pub decimals: u8,
    pub fee_basis_points: u16,
    pub max_fee: u64,
    pub name: String,
    pub symbol: String,
    pub uri: String,
}

pub struct ConfidentialConfig {
    pub permanent_delegate: Pubkey,
    pub auditor: ElGamalPubkey,
    pub withdraw_withheld_authority: ElGamalPubkey,
}

/// Task 1 when `confidential` is None, task 5 when it is Some. The issuer
/// holds every authority to keep the example small.
pub fn create_mint(
    svm: &mut LiteSVM,
    issuer: &Keypair,
    mint: &Keypair,
    cfg: &MintConfig,
    confidential: Option<&ConfidentialConfig>,
) -> Result<()> {
    let issuer_key = issuer.pubkey();
    let mint_key = mint.pubkey();

    let mut extensions = BASE_EXTENSIONS.to_vec();
    if confidential.is_some() {
        extensions.extend(CONFIDENTIAL_EXTENSIONS);
    }
    // Space covers fixed-size extensions only. TokenMetadata is variable
    // length and the metadata Initialize instruction reallocs the mint
    // itself, so here we only pre-fund the rent for that extra TLV entry:
    // 2-byte type + 2-byte length + borsh-packed metadata.
    let space = ExtensionType::try_calculate_account_len::<Mint>(&extensions)?;
    let metadata = TokenMetadata {
        name: cfg.name.clone(),
        symbol: cfg.symbol.clone(),
        uri: cfg.uri.clone(),
        ..Default::default()
    };
    let metadata_len =
        size_of::<ExtensionType>() + size_of::<Length>() + metadata.get_packed_len()?;
    let lamports = svm.minimum_balance_for_rent_exemption(space + metadata_len);

    let mut ixs = vec![
        create_account(&issuer_key, &mint_key, lamports, space as u64, &TOKEN_2022),
        initialize_transfer_fee_config(
            &TOKEN_2022,
            &mint_key,
            Some(&issuer_key),
            Some(&issuer_key),
            cfg.fee_basis_points,
            cfg.max_fee,
        )?,
        metadata_pointer::instruction::initialize(
            &TOKEN_2022,
            &mint_key,
            Some(issuer_key),
            Some(mint_key),
        )?,
        initialize_default_account_state(&TOKEN_2022, &mint_key, &AccountState::Frozen)?,
        initialize_mint_close_authority(&TOKEN_2022, &mint_key, Some(&issuer_key))?,
    ];
    if let Some(ct) = confidential {
        ixs.extend([
            initialize_permanent_delegate(&TOKEN_2022, &mint_key, &ct.permanent_delegate)?,
            confidential_transfer::instruction::initialize_mint(
                &TOKEN_2022,
                &mint_key,
                Some(issuer_key),
                false, // manual approval: the issuer must ApproveAccount each wallet
                Some(ct.auditor.into()),
            )?,
            confidential_transfer_fee::instruction::initialize_confidential_transfer_fee_config(
                &TOKEN_2022,
                &mint_key,
                Some(issuer_key),
                &ct.withdraw_withheld_authority.into(),
            )?,
        ]);
    }
    // Extensions are only writable while the mint is uninitialized, so every
    // init above must come before this one.
    ixs.push(initialize_mint2(
        &TOKEN_2022,
        &mint_key,
        &issuer_key,
        Some(&issuer_key),
        cfg.decimals,
    )?);
    // TokenMetadata checks the mint authority, so it can only run after InitializeMint.
    ixs.push(spl_token_metadata_interface::instruction::initialize(
        &TOKEN_2022,
        &mint_key,
        &issuer_key,
        &mint_key,
        &issuer_key,
        cfg.name.clone(),
        cfg.symbol.clone(),
        cfg.uri.clone(),
    ));

    send(svm, &ixs, &[issuer, mint])
}

/// Only succeeds once supply is zero.
pub fn close_mint(svm: &mut LiteSVM, close_authority: &Keypair, mint: &Pubkey) -> Result<()> {
    let authority = close_authority.pubkey();
    let ix = close_account(&TOKEN_2022, mint, &authority, &authority, &[])?;
    send(svm, &[ix], &[close_authority])
}

pub fn mint_to(
    svm: &mut LiteSVM,
    mint_authority: &Keypair,
    mint: &Pubkey,
    account: &Pubkey,
    amount: u64,
) -> Result<()> {
    let decimals = crate::state::mint(svm, mint)?.decimals;
    let authority = mint_authority.pubkey();
    let ix = mint_to_checked(
        &TOKEN_2022,
        mint,
        account,
        &authority,
        &[],
        amount,
        decimals,
    )?;
    send(svm, &[ix], &[mint_authority])
}

pub fn burn(
    svm: &mut LiteSVM,
    owner: &Keypair,
    account: &Pubkey,
    mint: &Pubkey,
    amount: u64,
) -> Result<()> {
    let decimals = crate::state::mint(svm, mint)?.decimals;
    let ix = burn_checked(
        &TOKEN_2022,
        account,
        mint,
        &owner.pubkey(),
        &[],
        amount,
        decimals,
    )?;
    send(svm, &[ix], &[owner])
}
