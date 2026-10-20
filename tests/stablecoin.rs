use litesvm::LiteSVM;
use solana_clock::Clock;
use solana_keypair::Keypair;
use solana_pubkey::Pubkey;
use solana_signer::Signer;
use solana_system_interface::instruction::create_account;
use solana_zk_sdk::encryption::elgamal::{ElGamalCiphertext, ElGamalKeypair};
use solana_zk_sdk_pod::encryption::elgamal::PodElGamalPubkey;
use spl_token_2022_interface::extension::ExtensionType;
use spl_token_2022_interface::extension::confidential_transfer::instruction as ct_instruction;
use spl_token_2022_interface::extension::confidential_transfer::{
    ConfidentialTransferAccount, ConfidentialTransferMint,
};
use spl_token_2022_interface::extension::confidential_transfer_fee::{
    ConfidentialTransferFeeAmount, ConfidentialTransferFeeConfig,
};
use spl_token_2022_interface::extension::default_account_state::DefaultAccountState;
use spl_token_2022_interface::extension::metadata_pointer::MetadataPointer;
use spl_token_2022_interface::extension::mint_close_authority::MintCloseAuthority;
use spl_token_2022_interface::extension::permanent_delegate::PermanentDelegate;
use spl_token_2022_interface::extension::transfer_fee::instruction::{
    initialize_transfer_fee_config, set_transfer_fee, transfer_checked_with_fee,
};
use spl_token_2022_interface::extension::transfer_fee::{TransferFeeAmount, TransferFeeConfig};
use spl_token_2022_interface::instruction::initialize_mint2;
use spl_token_2022_interface::state::{AccountState, Mint};
use spl_type_length_value::variable_len_pack::VariableLenPack;
use token22_stablecoin::confidential::{self, CtKeys};
use token22_stablecoin::mint::{
    BASE_EXTENSIONS, CONFIDENTIAL_EXTENSIONS, ConfidentialConfig, MintConfig, burn, close_mint,
    create_mint, mint_to,
};
use token22_stablecoin::transfer::{seize, transfer_with_fee};
use token22_stablecoin::{TOKEN_2022, funded_keypair, kyc, new_svm, send, state};

const DECIMALS: u8 = 6;
const TOKEN: u64 = 1_000_000;
const FEE_BPS: u16 = 50; // 0.5%
const MAX_FEE: u64 = 5 * TOKEN;

fn config() -> MintConfig {
    MintConfig {
        decimals: DECIMALS,
        fee_basis_points: FEE_BPS,
        max_fee: MAX_FEE,
        name: "Remit Dollar".into(),
        symbol: "RUSD".into(),
        uri: "https://example.com/rusd.json".into(),
    }
}

struct World {
    svm: LiteSVM,
    issuer: Keypair,
    mint: Pubkey,
}

fn public_mint() -> World {
    let mut svm = new_svm();
    let issuer = funded_keypair(&mut svm);
    let mint = Keypair::new();
    create_mint(&mut svm, &issuer, &mint, &config(), None).unwrap();
    World {
        svm,
        issuer,
        mint: mint.pubkey(),
    }
}

/// Opens an account for a fresh user, thaws it (KYC passed) and funds it.
fn kyc_user(w: &mut World, amount: u64) -> (Keypair, Pubkey) {
    let user = funded_keypair(&mut w.svm);
    let account = kyc::open_account(&mut w.svm, &w.issuer, &user.pubkey(), &w.mint).unwrap();
    kyc::approve_kyc(&mut w.svm, &w.issuer, &account, &w.mint).unwrap();
    if amount > 0 {
        mint_to(&mut w.svm, &w.issuer, &w.mint, &account, amount).unwrap();
    }
    (user, account)
}

/// The transaction must fail, and for the stated reason.
fn assert_fails<T: std::fmt::Debug>(result: anyhow::Result<T>, reason: &str) {
    let err = format!("{:#}", result.expect_err("expected failure"));
    assert!(err.contains(reason), "expected `{reason}` in:\n{err}");
}

fn warp_epochs(svm: &mut LiteSVM, epochs: u64) {
    let mut clock = svm.get_sysvar::<Clock>();
    clock.epoch += epochs;
    svm.set_sysvar(&clock);
}

#[test]
fn task1_mint_with_stacked_extensions_metadata_and_close() {
    let mut w = public_mint();

    let mut types = state::mint_extension_types(&w.svm, &w.mint).unwrap();
    types.sort_by_key(|t| *t as u16);
    let mut expected = BASE_EXTENSIONS.to_vec();
    expected.push(ExtensionType::TokenMetadata);
    expected.sort_by_key(|t| *t as u16);
    assert_eq!(types, expected);

    let pointer = state::mint_extension::<MetadataPointer>(&w.svm, &w.mint).unwrap();
    assert_eq!(
        Option::<Pubkey>::from(pointer.metadata_address),
        Some(w.mint)
    );
    let metadata = state::metadata(&w.svm, &w.mint).unwrap();
    assert_eq!(metadata.name, "Remit Dollar");
    assert_eq!(metadata.symbol, "RUSD");
    assert_eq!(metadata.uri, "https://example.com/rusd.json");
    assert_eq!(metadata.mint, w.mint);
    assert_eq!(
        Option::<Pubkey>::from(metadata.update_authority),
        Some(w.issuer.pubkey())
    );

    // Fixed part sized by try_calculate_account_len, metadata TLV appended by the program.
    let fixed = ExtensionType::try_calculate_account_len::<Mint>(&BASE_EXTENSIONS).unwrap();
    let account = w.svm.get_account(&w.mint).unwrap();
    assert_eq!(
        account.data.len(),
        fixed + 4 + metadata.get_packed_len().unwrap()
    );
    assert!(account.lamports >= w.svm.minimum_balance_for_rent_exemption(account.data.len()));

    let default_state = state::mint_extension::<DefaultAccountState>(&w.svm, &w.mint).unwrap();
    assert_eq!(default_state.state, AccountState::Frozen as u8);
    let fee = state::mint_extension::<TransferFeeConfig>(&w.svm, &w.mint).unwrap();
    assert_eq!(
        u16::from(fee.newer_transfer_fee.transfer_fee_basis_points),
        FEE_BPS
    );
    let close = state::mint_extension::<MintCloseAuthority>(&w.svm, &w.mint).unwrap();
    assert_eq!(
        Option::<Pubkey>::from(close.close_authority),
        Some(w.issuer.pubkey())
    );

    let (user, account) = kyc_user(&mut w, 100 * TOKEN);
    assert_fails(
        close_mint(&mut w.svm, &w.issuer, &w.mint),
        "Mint has non-zero supply",
    );
    burn(&mut w.svm, &user, &account, &w.mint, 100 * TOKEN).unwrap();
    assert_eq!(state::mint(&w.svm, &w.mint).unwrap().supply, 0);
    close_mint(&mut w.svm, &w.issuer, &w.mint).unwrap();
    assert!(w.svm.get_account(&w.mint).is_none_or(|a| a.lamports == 0));
}

#[test]
fn task2_transfer_fee_follows_the_clock_epoch() {
    let mut w = public_mint();
    let (alice, alice_ata) = kyc_user(&mut w, 1_000 * TOKEN);
    let (_bob, bob_ata) = kyc_user(&mut w, 0);
    let amount = 100 * TOKEN;
    let withheld = |svm: &LiteSVM| {
        u64::from(
            state::account_extension::<TransferFeeAmount>(svm, &bob_ata)
                .unwrap()
                .withheld_amount,
        )
    };
    let expected_fee = |svm: &LiteSVM| {
        let epoch = svm.get_sysvar::<Clock>().epoch;
        state::mint_extension::<TransferFeeConfig>(svm, &w.mint)
            .unwrap()
            .calculate_epoch_fee(epoch, amount)
            .unwrap()
    };

    let fee = transfer_with_fee(&mut w.svm, &alice, &alice_ata, &w.mint, &bob_ata, amount).unwrap();
    assert_eq!(fee, expected_fee(&w.svm));
    assert_eq!(fee, amount * FEE_BPS as u64 / 10_000);
    assert_eq!(withheld(&w.svm), fee);
    assert_eq!(
        state::account(&w.svm, &bob_ata).unwrap().amount,
        amount - fee
    );

    // A new rate only applies two epochs after SetTransferFee.
    let ix = set_transfer_fee(&TOKEN_2022, &w.mint, &w.issuer.pubkey(), &[], 100, MAX_FEE).unwrap();
    send(&mut w.svm, &[ix], &[&w.issuer]).unwrap();
    let same_epoch_fee =
        transfer_with_fee(&mut w.svm, &alice, &alice_ata, &w.mint, &bob_ata, amount).unwrap();
    assert_eq!(same_epoch_fee, fee, "old rate still active this epoch");

    warp_epochs(&mut w.svm, 2);
    // A fee cached from before the warp is now wrong and the program rejects it.
    let stale = transfer_checked_with_fee(
        &TOKEN_2022,
        &alice_ata,
        &w.mint,
        &bob_ata,
        &alice.pubkey(),
        &[],
        amount,
        DECIMALS,
        fee,
    )
    .unwrap();
    // Custom(32) is TokenError::FeeMismatch, which logs no message.
    assert_fails(send(&mut w.svm, &[stale], &[&alice]), "Custom(32)");

    let new_fee =
        transfer_with_fee(&mut w.svm, &alice, &alice_ata, &w.mint, &bob_ata, amount).unwrap();
    assert_eq!(new_fee, expected_fee(&w.svm));
    assert_eq!(new_fee, amount * 100 / 10_000);
    assert_eq!(withheld(&w.svm), fee + same_epoch_fee + new_fee);
}

#[test]
fn task3_state_read_through_state_with_extensions() {
    let mut w = public_mint();
    let (user, account) = kyc_user(&mut w, 5 * TOKEN);

    let base = state::account(&w.svm, &account).unwrap();
    assert_eq!(base.owner, user.pubkey());
    assert_eq!(base.mint, w.mint);
    assert_eq!(base.amount, 5 * TOKEN);
    // The ATA program sized the account for what this mint requires.
    let mut types = state::account_extension_types(&w.svm, &account).unwrap();
    types.sort_by_key(|t| *t as u16);
    assert_eq!(
        types,
        vec![
            ExtensionType::TransferFeeAmount,
            ExtensionType::ImmutableOwner
        ]
    );
    assert_eq!(state::mint(&w.svm, &w.mint).unwrap().supply, 5 * TOKEN);
}

#[test]
fn task4_new_accounts_frozen_until_kyc_thaw() {
    let mut w = public_mint();
    let user = Keypair::new();
    let stranger = funded_keypair(&mut w.svm);
    // Anyone can create the account; it is born frozen.
    let account = kyc::open_account(&mut w.svm, &stranger, &user.pubkey(), &w.mint).unwrap();
    assert_eq!(
        state::account(&w.svm, &account).unwrap().state,
        AccountState::Frozen
    );
    assert_fails(
        mint_to(&mut w.svm, &w.issuer, &w.mint, &account, TOKEN),
        "Account is frozen",
    );

    kyc::approve_kyc(&mut w.svm, &w.issuer, &account, &w.mint).unwrap();
    assert_eq!(
        state::account(&w.svm, &account).unwrap().state,
        AccountState::Initialized
    );
    mint_to(&mut w.svm, &w.issuer, &w.mint, &account, TOKEN).unwrap();

    // The mint default is untouched, so the next wallet still waits for KYC.
    let default_state = state::mint_extension::<DefaultAccountState>(&w.svm, &w.mint).unwrap();
    assert_eq!(default_state.state, AccountState::Frozen as u8);
    let next = kyc::open_account(&mut w.svm, &stranger, &Pubkey::new_unique(), &w.mint).unwrap();
    assert_eq!(
        state::account(&w.svm, &next).unwrap().state,
        AccountState::Frozen
    );
}

struct CtWorld {
    w: World,
    regulator: Keypair,
    auditor: ElGamalKeypair,
    withheld_authority: ElGamalKeypair,
}

fn confidential_mint() -> CtWorld {
    let mut svm = new_svm();
    let issuer = funded_keypair(&mut svm);
    let regulator = funded_keypair(&mut svm);
    let auditor = ElGamalKeypair::new_rand();
    let withheld_authority = ElGamalKeypair::new_rand();
    let mint = Keypair::new();
    let ct = ConfidentialConfig {
        permanent_delegate: regulator.pubkey(),
        auditor: *auditor.pubkey(),
        withdraw_withheld_authority: *withheld_authority.pubkey(),
    };
    create_mint(&mut svm, &issuer, &mint, &config(), Some(&ct)).unwrap();
    CtWorld {
        w: World {
            svm,
            issuer,
            mint: mint.pubkey(),
        },
        regulator,
        auditor,
        withheld_authority,
    }
}

/// Opens (paid by the issuer), configures (owner-signed), KYC-thaws and
/// CT-approves an account, then funds its public balance.
fn ct_user(w: &mut World, amount: u64) -> (Keypair, Pubkey, CtKeys) {
    let (user, account) = kyc_user(w, amount);
    let keys = CtKeys::derive(&user, &account).unwrap();
    confidential::configure_account(&mut w.svm, &user, &account, &w.mint, &keys).unwrap();
    confidential::approve_account(&mut w.svm, &w.issuer, &account, &w.mint).unwrap();
    (user, account, keys)
}

#[test]
fn task5_reissued_mint_adds_delegate_and_confidential_extensions() {
    let mut c = confidential_mint();

    // Fee + confidential mint without ConfidentialTransferFeeConfig is
    // rejected at InitializeMint.
    let mint = Keypair::new();
    let issuer = c.w.issuer.pubkey();
    let types = [
        ExtensionType::TransferFeeConfig,
        ExtensionType::ConfidentialTransferMint,
    ];
    let space = ExtensionType::try_calculate_account_len::<Mint>(&types).unwrap();
    let lamports = c.w.svm.minimum_balance_for_rent_exemption(space);
    let ixs = [
        create_account(&issuer, &mint.pubkey(), lamports, space as u64, &TOKEN_2022),
        initialize_transfer_fee_config(&TOKEN_2022, &mint.pubkey(), None, None, FEE_BPS, MAX_FEE)
            .unwrap(),
        ct_instruction::initialize_mint(&TOKEN_2022, &mint.pubkey(), Some(issuer), false, None)
            .unwrap(),
        initialize_mint2(
            &TOKEN_2022,
            &mint.pubkey(),
            &issuer,
            Some(&issuer),
            DECIMALS,
        )
        .unwrap(),
    ];
    assert_fails(
        send(&mut c.w.svm, &ixs, &[&c.w.issuer, &mint]),
        "InstructionError(3, Custom(51))", // InitializeMint2: InvalidExtensionCombination
    );

    let w = &c.w;

    let mut types = state::mint_extension_types(&w.svm, &w.mint).unwrap();
    types.sort_by_key(|t| *t as u16);
    let mut expected = [
        BASE_EXTENSIONS.as_slice(),
        CONFIDENTIAL_EXTENSIONS.as_slice(),
    ]
    .concat();
    expected.push(ExtensionType::TokenMetadata);
    expected.sort_by_key(|t| *t as u16);
    assert_eq!(types, expected);

    let delegate = state::mint_extension::<PermanentDelegate>(&w.svm, &w.mint).unwrap();
    assert_eq!(
        Option::<Pubkey>::from(delegate.delegate),
        Some(c.regulator.pubkey())
    );

    let ct = state::mint_extension::<ConfidentialTransferMint>(&w.svm, &w.mint).unwrap();
    assert!(!bool::from(ct.auto_approve_new_accounts));
    assert_eq!(
        Option::<Pubkey>::from(ct.authority),
        Some(w.issuer.pubkey())
    );
    let auditor: Option<PodElGamalPubkey> = ct.auditor_elgamal_pubkey.into();
    assert_eq!(auditor, Some((*c.auditor.pubkey()).into()));

    let ct_fee = state::mint_extension::<ConfidentialTransferFeeConfig>(&w.svm, &w.mint).unwrap();
    assert_eq!(
        ct_fee.withdraw_withheld_authority_elgamal_pubkey,
        (*c.withheld_authority.pubkey()).into()
    );
    assert_eq!(state::metadata(&w.svm, &w.mint).unwrap().symbol, "RUSD");
}

#[test]
fn task6_confidential_lifecycle_and_public_seizure() {
    let mut c = confidential_mint();
    let w = &mut c.w;

    // ATA paid for by a third party, ConfigureAccount signed by the owner.
    let (alice, alice_ata) = kyc_user(w, 1_000 * TOKEN);
    let alice_keys = CtKeys::derive(&alice, &alice_ata).unwrap();
    confidential::configure_account(&mut w.svm, &alice, &alice_ata, &w.mint, &alice_keys).unwrap();
    let ext = state::account_extension::<ConfidentialTransferAccount>(&w.svm, &alice_ata).unwrap();
    assert!(!bool::from(ext.approved));
    assert_fails(
        confidential::deposit(&mut w.svm, &alice, &alice_ata, &w.mint, TOKEN),
        "Account not approved for confidential transfers",
    );
    confidential::approve_account(&mut w.svm, &w.issuer, &alice_ata, &w.mint).unwrap();
    let (bob, bob_ata, bob_keys) = ct_user(w, 0);

    confidential::deposit(&mut w.svm, &alice, &alice_ata, &w.mint, 600 * TOKEN).unwrap();
    assert_eq!(
        state::account(&w.svm, &alice_ata).unwrap().amount,
        400 * TOKEN
    );
    assert_eq!(
        confidential::pending_balance(&w.svm, &alice_ata, &alice_keys).unwrap(),
        600 * TOKEN
    );
    let available =
        confidential::apply_pending_balance(&mut w.svm, &alice, &alice_ata, &alice_keys).unwrap();
    assert_eq!(available, 600 * TOKEN);
    assert_eq!(
        confidential::available_balance(&w.svm, &alice_ata, &alice_keys).unwrap(),
        600 * TOKEN
    );
    assert_eq!(
        confidential::pending_balance(&w.svm, &alice_ata, &alice_keys).unwrap(),
        0
    );

    let amount = 250 * TOKEN;
    let fee = confidential::transfer(
        &mut w.svm,
        &alice,
        &alice_ata,
        &w.mint,
        &bob_ata,
        &alice_keys,
        amount,
    )
    .unwrap();
    assert_eq!(fee, amount * FEE_BPS as u64 / 10_000);
    assert_eq!(
        confidential::available_balance(&w.svm, &alice_ata, &alice_keys).unwrap(),
        350 * TOKEN
    );
    assert_eq!(
        confidential::pending_balance(&w.svm, &bob_ata, &bob_keys).unwrap(),
        amount - fee
    );
    // The fee is withheld encrypted under the withdraw-withheld authority's key.
    let withheld = state::account_extension::<ConfidentialTransferFeeAmount>(&w.svm, &bob_ata)
        .unwrap()
        .withheld_amount;
    let withheld: ElGamalCiphertext = withheld.try_into().unwrap();
    assert_eq!(
        c.withheld_authority.secret().decrypt_u32(&withheld),
        Some(fee)
    );

    // Bob's credit sits in pending until he applies it, then he can withdraw.
    let bob_available =
        confidential::apply_pending_balance(&mut w.svm, &bob, &bob_ata, &bob_keys).unwrap();
    assert_eq!(bob_available, amount - fee);
    confidential::withdraw(
        &mut w.svm,
        &bob,
        &bob_ata,
        &w.mint,
        &bob_keys,
        bob_available,
    )
    .unwrap();
    assert_eq!(
        confidential::available_balance(&w.svm, &bob_ata, &bob_keys).unwrap(),
        0
    );
    assert_eq!(
        state::account(&w.svm, &bob_ata).unwrap().amount,
        amount - fee
    );

    // Seizure by the permanent delegate, no owner signature involved.
    let (_treasury_owner, treasury) = kyc_user(w, 0);
    let seized = seize(&mut w.svm, &c.regulator, &alice_ata, &w.mint, &treasury).unwrap();
    assert_eq!(seized, 400 * TOKEN);
    assert_eq!(state::account(&w.svm, &alice_ata).unwrap().amount, 0);
    let seize_fee = seized * FEE_BPS as u64 / 10_000;
    assert_eq!(
        state::account(&w.svm, &treasury).unwrap().amount,
        seized - seize_fee
    );
    assert_eq!(
        confidential::available_balance(&w.svm, &alice_ata, &alice_keys).unwrap(),
        350 * TOKEN,
        "confidential balance is out of the delegate's reach"
    );
}

/// Backs the written finding in the README.
#[test]
fn finding_confidential_balance_escapes_seizure_but_not_freeze() {
    let mut c = confidential_mint();
    let w = &mut c.w;
    let (alice, alice_ata, alice_keys) = ct_user(w, 500 * TOKEN);
    let (_bob, bob_ata, _) = ct_user(w, 0);
    let (_t, treasury) = kyc_user(w, 0);

    // Sanctioned user moves everything into the confidential balance first.
    confidential::deposit(&mut w.svm, &alice, &alice_ata, &w.mint, 500 * TOKEN).unwrap();
    confidential::apply_pending_balance(&mut w.svm, &alice, &alice_ata, &alice_keys).unwrap();

    assert_eq!(
        seize(&mut w.svm, &c.regulator, &alice_ata, &w.mint, &treasury).unwrap(),
        0
    );
    assert_fails(
        transfer_with_fee(
            &mut w.svm,
            &c.regulator,
            &alice_ata,
            &w.mint,
            &treasury,
            TOKEN,
        ),
        "insufficient funds",
    );
    assert_eq!(
        confidential::available_balance(&w.svm, &alice_ata, &alice_keys).unwrap(),
        500 * TOKEN
    );

    // Freezing still stops the owner from moving or withdrawing it.
    kyc::freeze(&mut w.svm, &w.issuer, &alice_ata, &w.mint).unwrap();
    assert_fails(
        confidential::transfer(
            &mut w.svm,
            &alice,
            &alice_ata,
            &w.mint,
            &bob_ata,
            &alice_keys,
            TOKEN,
        ),
        "Account is frozen",
    );
    assert_fails(
        confidential::withdraw(&mut w.svm, &alice, &alice_ata, &w.mint, &alice_keys, TOKEN),
        "Account is frozen",
    );

    // A frozen account also blocks the delegate on the public side: seizure
    // needs a thaw first.
    let (_bad, bad_ata, _) = ct_user(w, 10 * TOKEN);
    kyc::freeze(&mut w.svm, &w.issuer, &bad_ata, &w.mint).unwrap();
    assert_fails(
        seize(&mut w.svm, &c.regulator, &bad_ata, &w.mint, &treasury),
        "Account is frozen",
    );
    kyc::approve_kyc(&mut w.svm, &w.issuer, &bad_ata, &w.mint).unwrap();
    assert_eq!(
        seize(&mut w.svm, &c.regulator, &bad_ata, &w.mint, &treasury).unwrap(),
        10 * TOKEN
    );
}
