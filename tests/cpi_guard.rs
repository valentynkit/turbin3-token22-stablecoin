//! Extension: programs/delegate-pull moves a user's tokens via CPI. With CPI
//! Guard on, the delegate path keeps working and the owner-signed path stops.

use litesvm::LiteSVM;
use solana_instruction::{AccountMeta, Instruction};
use solana_keypair::Keypair;
use solana_pubkey::Pubkey;
use solana_signer::Signer;
use solana_system_interface::instruction::create_account;
use spl_token_2022_interface::extension::ExtensionType;
use spl_token_2022_interface::extension::cpi_guard::CpiGuard;
use spl_token_2022_interface::extension::cpi_guard::instruction::enable_cpi_guard;
use spl_token_2022_interface::instruction::{approve_checked, initialize_mint2, reallocate};
use spl_token_2022_interface::state::Mint;
use token22_stablecoin::mint::mint_to;
use token22_stablecoin::{TOKEN_2022, ata, funded_keypair, kyc, new_svm, program_so, send, state};

const DECIMALS: u8 = 6;
const PULL_AS_DELEGATE: u8 = 0;
const TRANSFER_AS_OWNER: u8 = 1;

struct Accounts {
    program: Pubkey,
    mint: Pubkey,
    source: Pubkey,
    destination: Pubkey,
}

fn cpi_transfer(
    svm: &mut LiteSVM,
    a: &Accounts,
    tag: u8,
    authority: Pubkey,
    signer: &Keypair,
) -> anyhow::Result<()> {
    let mut data = vec![tag];
    data.extend_from_slice(&1_000_000u64.to_le_bytes());
    data.push(DECIMALS);
    let ix = Instruction {
        program_id: a.program,
        accounts: vec![
            AccountMeta::new(a.source, false),
            AccountMeta::new_readonly(a.mint, false),
            AccountMeta::new(a.destination, false),
            AccountMeta::new_readonly(authority, tag == TRANSFER_AS_OWNER),
            AccountMeta::new_readonly(TOKEN_2022, false),
        ],
        data,
    };
    send(svm, &[ix], &[signer])
}

#[test]
fn extension_cpi_guard_blocks_owner_cpi_but_not_delegate() {
    let mut svm = new_svm();
    let program = Pubkey::new_unique();
    svm.add_program(program, &program_so("delegate_pull"))
        .unwrap();
    // Matches DELEGATE_SEED in programs/delegate-pull.
    let (pda, _) = Pubkey::find_program_address(&[b"delegate"], &program);

    // Plain Token-2022 mint: the guard is an account extension, the mint needs nothing.
    let issuer = funded_keypair(&mut svm);
    let mint = Keypair::new();
    let space = ExtensionType::try_calculate_account_len::<Mint>(&[]).unwrap();
    let lamports = svm.minimum_balance_for_rent_exemption(space);
    let ixs = [
        create_account(
            &issuer.pubkey(),
            &mint.pubkey(),
            lamports,
            space as u64,
            &TOKEN_2022,
        ),
        initialize_mint2(
            &TOKEN_2022,
            &mint.pubkey(),
            &issuer.pubkey(),
            None,
            DECIMALS,
        )
        .unwrap(),
    ];
    send(&mut svm, &ixs, &[&issuer, &mint]).unwrap();

    let user = funded_keypair(&mut svm);
    let merchant = Pubkey::new_unique();
    let source = kyc::open_account(&mut svm, &issuer, &user.pubkey(), &mint.pubkey()).unwrap();
    let destination = kyc::open_account(&mut svm, &issuer, &merchant, &mint.pubkey()).unwrap();
    assert_eq!(source, ata(&user.pubkey(), &mint.pubkey()));
    mint_to(&mut svm, &issuer, &mint.pubkey(), &source, 100_000_000).unwrap();

    let approve = approve_checked(
        &TOKEN_2022,
        &source,
        &mint.pubkey(),
        &pda,
        &user.pubkey(),
        &[],
        50_000_000,
        DECIMALS,
    )
    .unwrap();
    send(&mut svm, &[approve], &[&user]).unwrap();

    let a = Accounts {
        program,
        mint: mint.pubkey(),
        source,
        destination,
    };
    let balance = |svm: &LiteSVM| state::account(svm, &destination).unwrap().amount;

    // Unguarded: both CPI paths work.
    cpi_transfer(&mut svm, &a, PULL_AS_DELEGATE, pda, &user).unwrap();
    cpi_transfer(&mut svm, &a, TRANSFER_AS_OWNER, user.pubkey(), &user).unwrap();
    assert_eq!(balance(&svm), 2_000_000);

    // The user turns on CPI Guard (top-level, owner-signed).
    let ixs = [
        reallocate(
            &TOKEN_2022,
            &source,
            &user.pubkey(),
            &user.pubkey(),
            &[],
            &[ExtensionType::CpiGuard],
        )
        .unwrap(),
        enable_cpi_guard(&TOKEN_2022, &source, &user.pubkey(), &[]).unwrap(),
    ];
    send(&mut svm, &ixs, &[&user]).unwrap();
    let guard = state::account_extension::<CpiGuard>(&svm, &source).unwrap();
    assert!(bool::from(guard.lock_cpi));

    // Same delegate instruction, unchanged, still goes through.
    cpi_transfer(&mut svm, &a, PULL_AS_DELEGATE, pda, &user).unwrap();
    assert_eq!(balance(&svm), 3_000_000);
    assert_eq!(
        state::account(&svm, &source).unwrap().delegated_amount,
        48_000_000
    );

    // Owner authority through CPI is now refused.
    let err = cpi_transfer(&mut svm, &a, TRANSFER_AS_OWNER, user.pubkey(), &user).unwrap_err();
    // Custom(42) is TokenError::CpiGuardTransferBlocked.
    assert!(format!("{err:#}").contains("Custom(42)"), "{err:#}");
    assert_eq!(balance(&svm), 3_000_000);
}
