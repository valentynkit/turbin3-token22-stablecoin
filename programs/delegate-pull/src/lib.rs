//! Moves a user's Token-2022 tokens with transfer_checked via CPI.
//!
//! Instruction data: `[tag, amount: u64 LE, decimals: u8]`
//! Accounts: `[source (w), mint, destination (w), authority, token program]`
//!
//! - tag 0, pull as delegate: `authority` is this program's PDA (seed
//!   "delegate"), which the user approved beforehand. The PDA signs.
//! - tag 1, transfer as owner: `authority` is the account owner, who signed
//!   the outer transaction; the signature is forwarded through the CPI.
//!   CPI Guard exists to block exactly this.

use solana_program::{
    account_info::AccountInfo,
    entrypoint,
    entrypoint::ProgramResult,
    instruction::{AccountMeta, Instruction},
    program::{invoke, invoke_signed},
    program_error::ProgramError,
    pubkey,
    pubkey::Pubkey,
};

pub const DELEGATE_SEED: &[u8] = b"delegate";
const TOKEN_2022: Pubkey = pubkey!("TokenzQdBNbLqP5VEhdkAS6EPFLC1PHnBqCXEpPxuEb");
const TRANSFER_CHECKED: u8 = 12;

entrypoint!(process_instruction);

pub fn process_instruction(
    program_id: &Pubkey,
    accounts: &[AccountInfo],
    data: &[u8],
) -> ProgramResult {
    let [tag, rest @ ..] = data else {
        return Err(ProgramError::InvalidInstructionData);
    };
    if rest.len() != 9 {
        return Err(ProgramError::InvalidInstructionData);
    }
    let [source, mint, destination, authority, token_program] = accounts else {
        return Err(ProgramError::NotEnoughAccountKeys);
    };
    // The PDA signs below, so never hand it to an arbitrary program.
    if *token_program.key != TOKEN_2022 {
        return Err(ProgramError::IncorrectProgramId);
    }

    let mut ix_data = vec![TRANSFER_CHECKED];
    ix_data.extend_from_slice(rest);
    let ix = Instruction {
        program_id: TOKEN_2022,
        accounts: vec![
            AccountMeta::new(*source.key, false),
            AccountMeta::new_readonly(*mint.key, false),
            AccountMeta::new(*destination.key, false),
            AccountMeta::new_readonly(*authority.key, true),
        ],
        data: ix_data,
    };
    let infos = [
        source.clone(),
        mint.clone(),
        destination.clone(),
        authority.clone(),
        token_program.clone(),
    ];

    match tag {
        0 => {
            let (pda, bump) = Pubkey::find_program_address(&[DELEGATE_SEED], program_id);
            if *authority.key != pda {
                return Err(ProgramError::InvalidSeeds);
            }
            invoke_signed(&ix, &infos, &[&[DELEGATE_SEED, &[bump]]])
        }
        1 => invoke(&ix, &infos),
        _ => Err(ProgramError::InvalidInstructionData),
    }
}
