//! Remittance stablecoin on Token-2022, driven against LiteSVM.

pub mod confidential;
pub mod kyc;
pub mod mint;
pub mod state;
pub mod transfer;

use anyhow::{Result, anyhow, ensure};
use litesvm::LiteSVM;
use solana_instruction::Instruction;
use solana_keypair::Keypair;
use solana_pubkey::Pubkey;
use solana_signer::Signer;
use solana_transaction::Transaction;

pub use spl_token_2022_interface::ID as TOKEN_2022;

/// Max serialized transaction size accepted by a real cluster.
pub const PACKET_DATA_SIZE: usize = 1232;

/// Signs with `signers` (the first one pays fees) and executes the transaction.
pub fn send(svm: &mut LiteSVM, ixs: &[Instruction], signers: &[&Keypair]) -> Result<()> {
    let tx = Transaction::new_signed_with_payer(
        ixs,
        Some(&signers[0].pubkey()),
        signers,
        svm.latest_blockhash(),
    );
    // LiteSVM accepts oversized transactions, a validator does not.
    let size = bincode::serialized_size(&tx)? as usize;
    ensure!(
        size <= PACKET_DATA_SIZE,
        "transaction is {size} bytes, limit is {PACKET_DATA_SIZE}"
    );

    let result = svm.send_transaction(tx);
    // A fresh blockhash per tx, so repeating an identical instruction is not
    // rejected as AlreadyProcessed.
    svm.expire_blockhash();
    result
        .map(|_| ())
        .map_err(|e| anyhow!("{:?}\n{}", e.err, e.meta.logs.join("\n")))
}

/// Programs built by `cargo build-sbf --manifest-path programs/Cargo.toml`.
pub fn program_so(name: &str) -> Vec<u8> {
    let path = format!(
        "{}/programs/target/deploy/{name}.so",
        env!("CARGO_MANIFEST_DIR")
    );
    std::fs::read(&path).unwrap_or_else(|_| {
        panic!("{path} missing, run: cargo build-sbf --manifest-path programs/Cargo.toml")
    })
}

/// LiteSVM ships Token-2022 11.0.0, the ATA program and the ZK ElGamal proof
/// builtin. spl-record is added for staging large proofs.
pub fn new_svm() -> LiteSVM {
    let mut svm = LiteSVM::new();
    svm.add_program(spl_record::id(), &program_so("spl_record_program"))
        .expect("load spl-record");
    svm
}

pub fn funded_keypair(svm: &mut LiteSVM) -> Keypair {
    let kp = Keypair::new();
    svm.airdrop(&kp.pubkey(), 100_000_000_000).expect("airdrop");
    kp
}

pub fn ata(owner: &Pubkey, mint: &Pubkey) -> Pubkey {
    spl_associated_token_account_interface::address::get_associated_token_address_with_program_id(
        owner,
        mint,
        &TOKEN_2022,
    )
}
