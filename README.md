# token22-stablecoin

Turbin3 Week 4. A remittance stablecoin built on Token-2022 extensions, with
a confidential re-issue and a small CPI Guard program on the side.

## Scenario

An issuer runs a remittance dollar. It wants:

- a protocol fee on every transfer,
- every new wallet frozen until it passes KYC,
- name, symbol and URI on-chain,
- the option to close the mint once it is retired.

Later two new requirements show up. Regulators want seizure, and users want
hidden amounts. ConfidentialTransferMint can only be set before
InitializeMint, and Token-2022 has no way to grow a mint afterwards (its
Reallocate only takes token accounts). So the mint gets re-issued with the
same extensions plus PermanentDelegate and confidential transfers.

## Harness

The tests run on LiteSVM 0.16.0, not on solana-test-validator. I checked
first that LiteSVM has everything the confidential flow needs:

- It loads Token-2022 11.0.0 (`litesvm-0.16.0/src/programs/mod.rs`).
- It registers the ZK ElGamal proof program from `solana_builtins::BUILTINS`.
- Its default feature set is mainnet's. That set includes both
  `disable_zk_elgamal_proof_program` and `reenable_zk_elgamal_proof_program`,
  so the proof program runs (`solana-zk-elgamal-proof-program-4.2.2/src/lib.rs:174-186`).

LiteSVM does not enforce the 1232-byte packet limit, so `send` in
`src/lib.rs` serializes every transaction and refuses anything bigger. That
check is why the transfer range proof goes through a record account (see
below). Compute limits are enforced the same way a validator does it.

The one thing LiteSVM lacks is spl-record. `programs/spl-record` rebuilds the
upstream crate (0.4.0) into a `.so`, and `new_svm()` loads it.

## Extension set

| Extension | Mint | Why |
|---|---|---|
| TransferFeeConfig | v1, v2 | Fee in basis points with a cap, taken on every transfer and withheld in the recipient's account. |
| MetadataPointer (to the mint itself) | v1, v2 | Wallets look for metadata where this points. Pointing at the mint means no separate metadata account. |
| TokenMetadata | v1, v2 | Name, symbol and URI, stored as a variable-length TLV entry in the mint. |
| DefaultAccountState = Frozen | v1, v2 | Every new token account starts frozen. Nothing moves until the freeze authority thaws it after KYC. |
| MintCloseAuthority | v1, v2 | Lets the issuer close the mint and get its rent back once supply is zero. |
| PermanentDelegate | v2 | Seizure. The delegate can transfer or burn from any account of this mint without the owner signing. |
| ConfidentialTransferMint (auto-approve off, auditor key set) | v2 | Encrypted balances and amounts. Because auto-approve is off, the issuer approves each account by hand. |
| ConfidentialTransferFeeConfig | v2 | Required by the program once a mint has both fees and confidential transfers (see below). Confidential fees are encrypted under its ElGamal key. |

On the account side, the ATA program adds TransferFeeAmount and
ImmutableOwner. ConfigureAccount adds ConfidentialTransferAccount and
ConfidentialTransferFeeAmount through a Reallocate in the same transaction.

### Why ConfidentialTransferFeeConfig is required

InitializeMint calls `check_for_invalid_mint_extension_combinations`
(spl-token-2022 11.0.0 `src/processor.rs:125`). That check rejects
TransferFeeConfig plus ConfidentialTransferMint without
ConfidentialTransferFeeConfig (spl-token-2022-interface 3.1.2
`src/extension/mod.rs:1357`). Task 5's test builds that mint and gets
`InvalidExtensionCombination` (Custom 51) on InitializeMint2.

The reason is the fee path. A confidential transfer on a fee mint has to
prove the fee was computed correctly and encrypt it for someone who can later
collect it. The transfer processor reads the withdraw-withheld authority's
ElGamal key from that extension and checks it against the proof
(`src/extension/confidential_transfer/processor.rs:758-767`). The proof set
grows from 3 to 5 proofs: equality, amount validity (3 handles), fee sigma
(percentage with cap), fee validity (2 handles), and a U256 range proof.

## Sizing and instruction order

`ExtensionType::try_calculate_account_len::<Mint>(&extensions)` gives the
exact mint size: the 82-byte base mint, padding to 165, one account-type
byte, and then for each extension a 2-byte type, a 2-byte length and the
value. The account must be created with exactly that size. InitializeMint
recomputes it from the extensions it finds and fails if the data length
differs (`src/processor.rs:122`).

That is why TokenMetadata is not in the list. It is variable length, and its
Initialize instruction reallocs the mint itself. That instruction takes no
payer, so the extra rent has to be in the mint before it runs. `create_mint`
funds rent for `space + 2 + 2 + borsh_len(metadata)`. Many examples use
`TokenMetadata::tlv_size_of()` here. It works, but it counts the
spl-type-length-value header (8-byte discriminator plus 4-byte length), not
Token-2022's 4-byte header, so it over-funds by 8 bytes of rent. Task 1's test
checks the final length is exactly `fixed + 4 + packed_len`.

The order inside the single create transaction is:

1. `create_account` with the fixed size and the full rent.
2. Every extension init: transfer fee config, metadata pointer, default
   account state, mint close authority, and on v2 also permanent delegate,
   confidential transfer mint and confidential transfer fee config. These
   unpack the mint with `unpack_uninitialized`, which returns `AlreadyInUse`
   once the mint is initialized (interface `src/extension/mod.rs:872`). So
   they have to come first.
3. `InitializeMint2`. It validates the size and the extension combination,
   and checks that a Frozen default state has a freeze authority.
4. TokenMetadata `Initialize`. It needs an initialized mint, the mint
   authority's signature, and the MetadataPointer
   (`src/extension/token_metadata/processor.rs:72-79`).

## Task to code map

| Task | Code | Test (`tests/stablecoin.rs` unless noted) |
|---|---|---|
| 1. Mint with stacked extensions, metadata, close | `src/mint.rs:create_mint` (confidential = None), `src/mint.rs:close_mint` | `task1_mint_with_stacked_extensions_metadata_and_close` |
| 2. `transfer_checked_with_fee`, fee from Clock epoch | `src/transfer.rs:current_fee`, `src/transfer.rs:transfer_with_fee` | `task2_transfer_fee_follows_the_clock_epoch` |
| 3. State only through StateWithExtensions | `src/state.rs` (every reader) | `task3_state_read_through_state_with_extensions` |
| 4. Per-account thaw after KYC | `src/kyc.rs:open_account`, `src/kyc.rs:approve_kyc` | `task4_new_accounts_frozen_until_kyc_thaw` |
| 5. Re-issue with PermanentDelegate + confidential | `src/mint.rs:create_mint` (confidential = Some), `CONFIDENTIAL_EXTENSIONS` | `task5_reissued_mint_adds_delegate_and_confidential_extensions` |
| 6. Confidential lifecycle | `src/confidential.rs`: `configure_account`, `approve_account`, `deposit`, `apply_pending_balance`, `transfer`, `withdraw` | `task6_confidential_lifecycle_and_public_seizure` |
| 6. Seizure of public balance | `src/transfer.rs:seize` | same test |
| Extension: delegate CPI vs CPI Guard | `programs/delegate-pull/src/lib.rs:process_instruction` | `tests/cpi_guard.rs:extension_cpi_guard_blocks_owner_cpi_but_not_delegate` |
| Written finding | README below | `finding_confidential_balance_escapes_seizure_but_not_freeze` |

What the tests check:

- **Task 1**: extension types on the mint, the pointer target, and the
  metadata fields read back. Also the exact account length and rent, and
  that close fails with "Mint has non-zero supply" until the tokens are
  burned, then succeeds.
- **Task 2**: the withheld amount equals `calculate_epoch_fee(clock.epoch,
  amount)`. After SetTransferFee, the old rate still applies in the same
  epoch. After warping the Clock two epochs, a fee computed from the old
  rate is rejected (`FeeMismatch`, Custom 32), and the new one is withheld.
- **Task 4**: new accounts are `Frozen`, and minting to them fails. After the
  thaw the account is `Initialized`. The mint default stays `Frozen`, so the
  next new account is still frozen.
- **Task 6**: ConfigureAccount is signed by the owner on an ATA the issuer
  paid for. Deposit fails with "Account not approved for confidential
  transfers" until ApproveAccount. Pending and available balances, decrypted
  with the owner's ElGamal and AE keys, match at every step. The recipient
  gets `amount - fee` as pending. The withheld fee decrypts to the expected
  fee under the withdraw-withheld ElGamal key. The recipient applies pending,
  then withdraws, and the public balance matches. Finally the permanent
  delegate seizes the sender's remaining public balance while the
  confidential balance stays put.
- **Extension**: before CPI Guard, both the delegate pull and the
  owner-signed CPI transfer work. After `enable_cpi_guard`, the same
  delegate instruction still works, and the owner-signed one fails with
  `CpiGuardTransferBlocked` (Custom 42).

### How the confidential instructions fit in 1232 bytes

Transfers and withdrawals need several proofs, far more than one
transaction can hold. `verify_into_context` creates a context-state account
for each proof, owned by the ZK proof program, and verifies the proof into
it. The token instruction then just references those accounts, and the
same transaction closes them to get the rent back. Sizes here: equality 320,
3-handle validity 544, percentage-with-cap 360, 2-handle validity 416, U64
range 936, U256 range 1064 bytes.

The U256 range proof does not fit even alone. A verify instruction carrying
it serializes to about 1235 bytes. So `write_record` stages it in an
spl-record account in two writes, and the proof program verifies it from the
account (`encode_verify_proof_from_account`). spl-token-client does the same.
That verify costs 368,000 CU (`solana-zk-elgamal-proof-program-4.2.2/src/lib.rs:27`),
so its transaction sets a 400k compute unit limit.

ConfigureAccount's pubkey-validity proof is small, so it sits inline right
after the instruction (`ProofLocation::InstructionOffset`).

## How to run

Needs Rust 1.85 or newer (edition 2024) and the Solana CLI (for
`cargo build-sbf`, platform-tools v1.54).

```sh
cargo build-sbf --manifest-path programs/Cargo.toml   # delegate_pull.so, spl_record_program.so
cargo test
```

No validator, no network, no ports. A run takes about 5 seconds, most of it
generating proofs. Full output of the last run is in `docs/test-output.txt`.

![tests passing](docs/tests-passing.png)
<!-- screenshot placeholder: docs/tests-passing.png -->

## Seizure vs confidentiality: the gap

| Where the tokens are | Permanent delegate can move them | Freeze stops the owner | Issuer can see the amount |
|---|---|---|---|
| Public `amount` | Yes, without the owner signing | Yes | Yes |
| Pending confidential balance | No | Yes | Only through the auditor key, by replaying history |
| Available confidential balance | No | Yes | Only through the auditor key, by replaying history |
| Withheld confidential fees | No (withdraw-withheld authority collects them) | n/a | Yes, with the withdraw-withheld key |

Seizure only covers the public balance. The confidential side can be
frozen, not taken.

## Written finding: a sanctioned user moves funds into the confidential balance first

**Short version:** the issuer can freeze those tokens, but cannot take
them. In Token-2022 11.0.0, the version LiteSVM runs, nothing on-chain moves
a confidential balance without the owner.

What happens step by step:

1. **Deposit moves tokens out of the delegate's reach.** Deposit subtracts
   from the public `amount` and adds to `pending_balance_lo/hi`, which are
   ElGamal ciphertexts under the owner's key. After ApplyPendingBalance the
   tokens sit in `available_balance`. Only the owner's AE key can open
   `decryptable_available_balance`.

2. **The permanent delegate only works on `amount`.** The delegate is
   honored in the public transfer path (`src/processor.rs:455`) and the
   public burn path. That code compares against `amount` and returns
   `InsufficientFunds` otherwise. The finding test seizes 0 from a user who
   deposited everything. A direct 1-token transfer by the delegate fails
   with "insufficient funds".

3. **Every confidential debit checks the owner, and only the owner.**
   - Withdraw: `src/extension/confidential_transfer/processor.rs:567`
   - Transfer, without fee: `:868`
   - Transfer, with fee: `:1015`
   - EmptyAccount: `:374`
   - Confidential burn: `src/extension/confidential_mint_burn/processor.rs:387`

   Each one calls `Processor::validate_owner` against
   `token_account.base.owner`. No file under `extension/confidential_transfer/`
   or `extension/confidential_mint_burn/` mentions PermanentDelegate, except
   one CPI Guard comment at `confidential_mint_burn/processor.rs:399`. On top
   of the signature, each debit needs ZK proofs, and those can only be built
   with the owner's ElGamal secret and AE key. So relaxing the signer check
   would not be enough either.

4. **ConfidentialMintBurn does not help.** That extension exists in this
   version (`src/extension/confidential_mint_burn/`). It lets the mint
   authority mint confidentially and lets the owner burn confidentially.
   `process_confidential_burn` (`processor.rs:305`) is owner-signed and
   proof-based, so it is not a seizure path.

5. **Freeze still works.** The freeze authority can freeze the account. The
   confidential processor checks `is_frozen` on deposit, withdraw, transfer
   source and destination, and apply (`processor.rs:454, 575, 887, 945, 1034,
   1095, 1221`). The finding test freezes a user with a confidential balance.
   The user's confidential transfer and withdraw then both fail with
   "Account is frozen". The funds are stuck, not seized.

6. **Freeze also blocks the delegate.** Public transfer checks
   `source.is_frozen()` before it looks at who signed (`src/processor.rs:356`).
   The finding test shows seizure from a frozen account fails, and works
   after a thaw. In practice, put thaw, seize and freeze in one transaction,
   so the user has no window in between.

7. **The auditor key gives visibility, not control.** Each confidential
   transfer carries the amount encrypted under the auditor key, checked
   against the proof (`check_auditor_ciphertext`,
   `confidential_transfer/processor.rs:780`). Deposit and withdraw amounts
   are public. So the issuer can rebuild a user's confidential balance from
   history. The auditor key cannot sign for the account or produce its
   proofs. I did not test auditor decryption; this point comes from reading
   the source.

8. **Manual approval is the real control point.** With
   `auto_approve_new_accounts = false`, a configured account is unusable
   until the confidential transfer authority calls ApproveAccount
   (`confidential_transfer/processor.rs:318-347`). Deposit fails before that
   (task 6 test). There is no instruction to revoke approval: the variants
   are InitializeMint, UpdateMint, ConfigureAccount, ApproveAccount,
   EmptyAccount, Deposit, Withdraw, Transfer, ApplyPendingBalance, the four
   credit toggles, TransferWithFee and ConfigureAccountWithRegistry. So
   sanctions screening has to happen before ApproveAccount. After that,
   freeze is the only lever.

**The gap.** Seizure reaches the public balance only. A user who deposits
and applies before the delegate acts keeps title to those tokens. The
issuer's options are to freeze them in place for as long as needed, or to
wait for the owner to withdraw. Freezing stops the user, but the tokens
still count toward supply and cannot be burned or reassigned. For a
regulated issuer this argues for:

- screening before ApproveAccount, not after;
- freezing immediately on a flag, before any thaw-seize step, since freeze
  is the one control that covers both sides;
- treating "frozen confidential balance" as its own state in compliance
  reporting, since it cannot be seized.

## What deviates or is untested

- **Harness.** The harness is LiteSVM, not solana-test-validator. Packet
  size is enforced in `send`, and compute limits follow Agave's rules. But
  nothing here has run against a real validator.
- **Authorities.** The issuer holds every authority: mint, freeze, fee
  config, withdraw-withheld, close, metadata update, and confidential
  transfer. Only the permanent delegate (regulator) is a separate key. A
  real deployment would split these.
- **Withheld fees.** Withheld fees are never harvested or withdrawn, public
  or confidential.
- **Auditor decryption.** Not asserted (see finding point 7).
- **Extension test mint.** The extension test uses a plain Token-2022 mint,
  not the stablecoin, to keep the program and test minimal. CPI Guard lives
  on the token account, so the mint does not matter.
- **Context-state accounts.** Each one is created and verified in its own
  transaction. Fewer, larger transactions would also work. This layout is
  the easiest to read.
