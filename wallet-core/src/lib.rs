//! I/O-independent native wallet state, transfer crypto, and validation.

#![forbid(unsafe_code)]

mod codec;
mod exit;
mod funding;
mod state;
mod transfer;
mod validation;

pub use codec::{
    open_encrypted_json, open_wallet_state, seal_encrypted_json, seal_wallet_state,
    wallet_state_aad,
};
pub use exit::{ExitJournal, ExitPackage, ExitStage, verify_exit_funding};
pub use funding::{
    PreparedSourceFunding, PreparedSourceSweep, SourceSweepJournal, SourceSweepStage, SourceUtxo,
    build_source_funding, build_source_sweep, source_funding_address,
};
pub use state::{
    FILE_FORMAT_VERSION, FundingJournal, FundingStage, IncomingTransfer, OutgoingTransfer,
    PendingOperation, PendingRecovery, Receipt, RecoveryAttempt, RecoveryPurpose, RecoveryStage,
    WalletCoin, WalletState,
};
pub use transfer::{
    MAX_TRANSFER_CIPHERTEXT_SIZE, TransferEnvelope, TransferPayload, TransferRequest,
    decrypt_transfer, encrypt_transfer, parse_hex32, random_secret_key, secret_xonly,
    validate_transfer_payload_size,
};
pub use validation::{
    ObservedFunding, attempt_committed, attempt_uncommitted, require_reaction_margin,
    validate_finalized_funding, validate_funding_inputs, verify_observed_funding,
    verify_public_history,
};
