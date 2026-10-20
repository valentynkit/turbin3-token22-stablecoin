//! Task 6: confidential lifecycle on the re-issued mint.
//!
//! Transfer and withdraw need several ZK proofs, together far over the
//! 1232-byte transaction limit. So each proof is verified first, into its own
//! context-state account, and the token instruction points at those accounts.
//! The transfer range proof (1064 bytes) does not fit even alone, so it is
//! staged in an spl-record account and verified from there.

use std::mem::size_of;

use anyhow::{Context, Result, anyhow};
use bytemuck::Pod;
use litesvm::LiteSVM;
use solana_clock::Clock;
use solana_compute_budget_interface::ComputeBudgetInstruction;
use solana_keypair::Keypair;
use solana_pubkey::Pubkey;
use solana_signer::Signer;
use solana_system_interface::instruction::create_account;
use solana_zk_elgamal_proof_interface::instruction::{
    ContextStateInfo, ProofInstruction, close_context_state,
};
use solana_zk_elgamal_proof_interface::proof_data::ZkProofData;
use solana_zk_elgamal_proof_interface::state::ProofContextState;
use solana_zk_sdk::encryption::auth_encryption::{AeCiphertext, AeKey};
use solana_zk_sdk::encryption::derivation::derive_confidential_keys;
use solana_zk_sdk::encryption::elgamal::{ElGamalCiphertext, ElGamalKeypair, ElGamalPubkey};
use solana_zk_sdk::zk_elgamal_proof_program::pubkey_validity::build_pubkey_validity_proof_data;
use solana_zk_sdk_pod::encryption::elgamal::PodElGamalPubkey;
use spl_record::state::RecordData;
use spl_token_2022_interface::extension::ExtensionType;
use spl_token_2022_interface::extension::confidential_transfer::instruction as ct;
use spl_token_2022_interface::extension::confidential_transfer::{
    ConfidentialTransferAccount, ConfidentialTransferMint,
};
use spl_token_2022_interface::extension::confidential_transfer_fee::ConfidentialTransferFeeConfig;
use spl_token_2022_interface::extension::transfer_fee::TransferFeeConfig;
use spl_token_2022_interface::instruction::reallocate;
use spl_token_confidential_transfer_proof_extraction::instruction::ProofLocation;
use spl_token_confidential_transfer_proof_generation::transfer_with_fee::transfer_with_fee_split_proof_data;
use spl_token_confidential_transfer_proof_generation::withdraw::withdraw_proof_data;

use crate::{PACKET_DATA_SIZE, TOKEN_2022, send, state};

const ZK_PROOF_PROGRAM: Pubkey =
    solana_pubkey::pubkey!("ZkE1Gama1Proof11111111111111111111111111111");

/// Signature, header, three account keys and a blockhash take about 205 bytes.
const MAX_INLINE_PROOF: usize = PACKET_DATA_SIZE - 205;

/// The owner's ElGamal keypair and AE key for one token account.
pub struct CtKeys {
    pub elgamal: ElGamalKeypair,
    pub aes: AeKey,
}

impl CtKeys {
    /// Derived from the owner's signature over the account address, so the
    /// owner can always regenerate them and nobody else can.
    pub fn derive(owner: &Keypair, account: &Pubkey) -> Result<Self> {
        let (elgamal, aes) =
            derive_confidential_keys(owner, account.as_ref()).map_err(|e| anyhow!("{e}"))?;
        Ok(Self { elgamal, aes })
    }
}

/// Owner-signed. Grows the ATA for the confidential extensions and registers
/// the owner's ElGamal key, proven valid by a PubkeyValidity proof.
pub fn configure_account(
    svm: &mut LiteSVM,
    owner: &Keypair,
    account: &Pubkey,
    mint: &Pubkey,
    keys: &CtKeys,
) -> Result<()> {
    let owner_key = owner.pubkey();
    let proof = build_pubkey_validity_proof_data(&keys.elgamal).map_err(|e| anyhow!("{e}"))?;

    let mut ixs = vec![reallocate(
        &TOKEN_2022,
        account,
        &owner_key,
        &owner_key,
        &[],
        // The fee amount extension is required because the mint charges fees.
        &[
            ExtensionType::ConfidentialTransferAccount,
            ExtensionType::ConfidentialTransferFeeAmount,
        ],
    )?];
    ixs.extend(ct::configure_account(
        &TOKEN_2022,
        account,
        mint,
        &keys.aes.encrypt(0).into(),
        65_536,
        &owner_key,
        &[],
        ProofLocation::InstructionOffset(1.try_into()?, &proof),
    )?);
    send(svm, &ixs, &[owner])
}

/// With auto-approve off, this is the issuer's gate into the confidential system.
pub fn approve_account(
    svm: &mut LiteSVM,
    ct_authority: &Keypair,
    account: &Pubkey,
    mint: &Pubkey,
) -> Result<()> {
    let ix = ct::approve_account(&TOKEN_2022, account, mint, &ct_authority.pubkey(), &[])?;
    send(svm, &[ix], &[ct_authority])
}

/// Moves public balance into the pending confidential balance.
pub fn deposit(
    svm: &mut LiteSVM,
    owner: &Keypair,
    account: &Pubkey,
    mint: &Pubkey,
    amount: u64,
) -> Result<()> {
    let decimals = state::mint(svm, mint)?.decimals;
    let ix = ct::deposit(
        &TOKEN_2022,
        account,
        mint,
        amount,
        decimals,
        &owner.pubkey(),
        &[],
    )?;
    send(svm, &[ix], &[owner])
}

/// Pending balance, decrypted with the owner's ElGamal secret. Credits are
/// split into a 16-bit low part and a 32-bit high part so each stays small
/// enough to decrypt.
pub fn pending_balance(svm: &LiteSVM, account: &Pubkey, keys: &CtKeys) -> Result<u64> {
    let ext = state::account_extension::<ConfidentialTransferAccount>(svm, account)?;
    let decrypt = |pod| -> Result<u64> {
        let ciphertext: ElGamalCiphertext = pod;
        keys.elgamal
            .secret()
            .decrypt_u32(&ciphertext)
            .context("pending balance out of range")
    };
    let lo = decrypt(ext.pending_balance_lo.try_into()?)?;
    let hi = decrypt(ext.pending_balance_hi.try_into()?)?;
    Ok(lo + (hi << 16))
}

/// Available balance, read through the AE ciphertext only the owner can open.
pub fn available_balance(svm: &LiteSVM, account: &Pubkey, keys: &CtKeys) -> Result<u64> {
    let ext = state::account_extension::<ConfidentialTransferAccount>(svm, account)?;
    let ciphertext: AeCiphertext = ext.decryptable_available_balance.try_into()?;
    ciphertext
        .decrypt(&keys.aes)
        .context("cannot decrypt available balance")
}

/// Owner-signed. Folds pending into available and returns the new available balance.
pub fn apply_pending_balance(
    svm: &mut LiteSVM,
    owner: &Keypair,
    account: &Pubkey,
    keys: &CtKeys,
) -> Result<u64> {
    let ext = state::account_extension::<ConfidentialTransferAccount>(svm, account)?;
    let new_available =
        available_balance(svm, account, keys)? + pending_balance(svm, account, keys)?;
    let ix = ct::apply_pending_balance(
        &TOKEN_2022,
        account,
        ext.pending_balance_credit_counter.into(),
        &keys.aes.encrypt(new_available).into(),
        &owner.pubkey(),
        &[],
    )?;
    send(svm, &[ix], &[owner])?;
    Ok(new_available)
}

/// Confidential transfer on a fee-bearing mint. Returns the fee withheld (in
/// encrypted form) on the destination.
pub fn transfer(
    svm: &mut LiteSVM,
    owner: &Keypair,
    source: &Pubkey,
    mint: &Pubkey,
    destination: &Pubkey,
    keys: &CtKeys,
    amount: u64,
) -> Result<u64> {
    let source_ext = state::account_extension::<ConfidentialTransferAccount>(svm, source)?;
    let destination_ext =
        state::account_extension::<ConfidentialTransferAccount>(svm, destination)?;
    let ct_mint = state::mint_extension::<ConfidentialTransferMint>(svm, mint)?;
    let ct_fee = state::mint_extension::<ConfidentialTransferFeeConfig>(svm, mint)?;
    let epoch = svm.get_sysvar::<Clock>().epoch;
    let fee_params = *state::mint_extension::<TransferFeeConfig>(svm, mint)?.get_epoch_fee(epoch);

    let auditor: Option<ElGamalPubkey> =
        Option::<PodElGamalPubkey>::from(ct_mint.auditor_elgamal_pubkey)
            .map(TryInto::try_into)
            .transpose()?;
    let available_ciphertext: ElGamalCiphertext = source_ext.available_balance.try_into()?;
    let decryptable: AeCiphertext = source_ext.decryptable_available_balance.try_into()?;
    let available = decryptable
        .decrypt(&keys.aes)
        .context("cannot decrypt available balance")?;
    let remaining = available
        .checked_sub(amount)
        .context("insufficient confidential balance")?;

    let proofs = transfer_with_fee_split_proof_data(
        &available_ciphertext,
        &decryptable,
        amount,
        &keys.elgamal,
        &keys.aes,
        &destination_ext.elgamal_pubkey.try_into()?,
        auditor.as_ref(),
        &ct_fee
            .withdraw_withheld_authority_elgamal_pubkey
            .try_into()?,
        fee_params.transfer_fee_basis_points.into(),
        fee_params.maximum_fee.into(),
    )?;
    let amount_validity = &proofs.transfer_amount_ciphertext_validity_proof_data_with_ciphertext;

    let equality = verify_into_context(
        svm,
        owner,
        ProofInstruction::VerifyCiphertextCommitmentEquality,
        &proofs.equality_proof_data,
    )?;
    let validity = verify_into_context(
        svm,
        owner,
        ProofInstruction::VerifyBatchedGroupedCiphertext3HandlesValidity,
        &amount_validity.proof_data,
    )?;
    let fee_sigma = verify_into_context(
        svm,
        owner,
        ProofInstruction::VerifyPercentageWithCap,
        &proofs.percentage_with_cap_proof_data,
    )?;
    let fee_validity = verify_into_context(
        svm,
        owner,
        ProofInstruction::VerifyBatchedGroupedCiphertext2HandlesValidity,
        &proofs.fee_ciphertext_validity_proof_data,
    )?;
    let range = verify_into_context(
        svm,
        owner,
        ProofInstruction::VerifyBatchedRangeProofU256,
        &proofs.range_proof_data,
    )?;

    let mut ixs = ct::transfer_with_fee(
        &TOKEN_2022,
        source,
        mint,
        destination,
        &keys.aes.encrypt(remaining).into(),
        &amount_validity.ciphertext_lo,
        &amount_validity.ciphertext_hi,
        &owner.pubkey(),
        &[],
        ProofLocation::ContextStateAccount(&equality),
        ProofLocation::ContextStateAccount(&validity),
        ProofLocation::ContextStateAccount(&fee_sigma),
        ProofLocation::ContextStateAccount(&fee_validity),
        ProofLocation::ContextStateAccount(&range),
    )?;
    ixs.extend(
        [equality, validity, fee_sigma, fee_validity, range]
            .iter()
            .map(|context| close_context(context, &owner.pubkey())),
    );
    send(svm, &ixs, &[owner])?;

    fee_params.calculate_fee(amount).context("fee overflow")
}

/// Owner-signed. Moves available confidential balance back to the public amount.
pub fn withdraw(
    svm: &mut LiteSVM,
    owner: &Keypair,
    account: &Pubkey,
    mint: &Pubkey,
    keys: &CtKeys,
    amount: u64,
) -> Result<()> {
    let ext = state::account_extension::<ConfidentialTransferAccount>(svm, account)?;
    let available = available_balance(svm, account, keys)?;
    let remaining = available
        .checked_sub(amount)
        .context("insufficient confidential balance")?;
    let proofs = withdraw_proof_data(
        &ext.available_balance.try_into()?,
        available,
        amount,
        &keys.elgamal,
    )?;

    let equality = verify_into_context(
        svm,
        owner,
        ProofInstruction::VerifyCiphertextCommitmentEquality,
        &proofs.equality_proof_data,
    )?;
    let range = verify_into_context(
        svm,
        owner,
        ProofInstruction::VerifyBatchedRangeProofU64,
        &proofs.range_proof_data,
    )?;

    let decimals = state::mint(svm, mint)?.decimals;
    let mut ixs = ct::withdraw(
        &TOKEN_2022,
        account,
        mint,
        amount,
        decimals,
        &keys.aes.encrypt(remaining).into(),
        &owner.pubkey(),
        &[],
        ProofLocation::ContextStateAccount(&equality),
        ProofLocation::ContextStateAccount(&range),
    )?;
    ixs.extend(
        [equality, range]
            .iter()
            .map(|c| close_context(c, &owner.pubkey())),
    );
    send(svm, &ixs, &[owner])
}

/// Verifies `proof` into a new context-state account owned by the ZK proof
/// program, with `owner` as the authority allowed to use and close it.
fn verify_into_context<T, U>(
    svm: &mut LiteSVM,
    owner: &Keypair,
    instruction: ProofInstruction,
    proof: &T,
) -> Result<Pubkey>
where
    T: Pod + ZkProofData<U>,
    U: Pod,
{
    let context = Keypair::new();
    let space = size_of::<ProofContextState<U>>();
    let lamports = svm.minimum_balance_for_rent_exemption(space);
    let create = create_account(
        &owner.pubkey(),
        &context.pubkey(),
        lamports,
        space as u64,
        &ZK_PROOF_PROGRAM,
    );
    send(svm, &[create], &[owner, &context])?;

    let info = ContextStateInfo {
        context_state_account: &context.pubkey(),
        context_state_authority: &owner.pubkey(),
    };
    let bytes = bytemuck::bytes_of(proof);
    if bytes.len() <= MAX_INLINE_PROOF {
        send(
            svm,
            &[instruction.encode_verify_proof(Some(info), proof)],
            &[owner],
        )?;
    } else {
        let record = write_record(svm, owner, bytes)?;
        let offset = RecordData::WRITABLE_START_INDEX as u32;
        let verify = instruction.encode_verify_proof_from_account(Some(info), &record, offset);
        let close =
            spl_record::instruction::close_account(&record, &owner.pubkey(), &owner.pubkey());
        // The U256 range proof costs 368k CU, more than the default budget.
        let budget = ComputeBudgetInstruction::set_compute_unit_limit(400_000);
        send(svm, &[budget, verify, close], &[owner])?;
    }
    Ok(context.pubkey())
}

/// Stages `bytes` in an spl-record account, a few hundred bytes per transaction.
fn write_record(svm: &mut LiteSVM, owner: &Keypair, bytes: &[u8]) -> Result<Pubkey> {
    const CHUNK: usize = 900;
    let record = Keypair::new();
    let space = RecordData::WRITABLE_START_INDEX + bytes.len();
    let lamports = svm.minimum_balance_for_rent_exemption(space);
    let ixs = [
        create_account(
            &owner.pubkey(),
            &record.pubkey(),
            lamports,
            space as u64,
            &spl_record::id(),
        ),
        spl_record::instruction::initialize(&record.pubkey(), &owner.pubkey()),
    ];
    send(svm, &ixs, &[owner, &record])?;
    for (i, chunk) in bytes.chunks(CHUNK).enumerate() {
        let offset = (i * CHUNK) as u64;
        let ix = spl_record::instruction::write(&record.pubkey(), &owner.pubkey(), offset, chunk);
        send(svm, &[ix], &[owner])?;
    }
    Ok(record.pubkey())
}

fn close_context(context: &Pubkey, owner: &Pubkey) -> solana_instruction::Instruction {
    close_context_state(
        ContextStateInfo {
            context_state_account: context,
            context_state_authority: owner,
        },
        owner,
    )
}
