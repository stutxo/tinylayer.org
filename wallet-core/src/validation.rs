use anyhow::{Context as _, Result, ensure};
use bitcoin::{OutPoint, Transaction, TxOut};
use tinylayer_client::{
    CoinMetadata, CoinStatus, SignedRecovery, authorization, capability_hash, funding_script,
    validate_reaction_window, verify_funding_utxo, verify_recovery, verify_status,
};

use crate::RecoveryAttempt;

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ObservedFunding {
    pub outpoint: OutPoint,
    pub output: TxOut,
    pub confirmations: u32,
    pub unspent: bool,
    pub coinbase: bool,
}

pub fn validate_funding_inputs(transaction: &Transaction) -> Result<()> {
    ensure!(
        !transaction.input.is_empty(),
        "funding transaction has no inputs"
    );
    ensure!(
        transaction.input.len() <= 100,
        "transaction has more than 100 inputs"
    );
    ensure!(
        transaction.weight().to_wu() <= 400_000,
        "transaction exceeds standard weight"
    );
    for input in &transaction.input {
        ensure!(
            !input.previous_output.is_null(),
            "funding transaction cannot spend a coinbase input"
        );
        ensure!(
            input.script_sig.is_empty() && !input.witness.is_empty(),
            "funding transaction must use only native SegWit or Taproot inputs"
        );
        ensure!(
            !input.sequence.is_rbf(),
            "funding transaction inputs must not signal replace-by-fee"
        );
    }
    Ok(())
}

pub fn validate_finalized_funding(
    metadata: &CoinMetadata,
    transaction: &Transaction,
) -> Result<()> {
    validate_funding_inputs(transaction)?;
    ensure!(
        transaction.compute_txid() == metadata.outpoint.txid,
        "prepared funding transaction txid does not match coin metadata"
    );
    let expected_script = funding_script(&metadata.keys);
    ensure!(
        transaction
            .output
            .iter()
            .filter(|output| output.script_pubkey == expected_script)
            .count()
            == 1,
        "funding transaction must contain exactly one Tinylayer output"
    );
    let output = transaction
        .output
        .get(metadata.outpoint.vout as usize)
        .context("prepared funding output index is missing")?;
    verify_funding_utxo(metadata, metadata.outpoint, output)?;
    Ok(())
}

pub fn verify_observed_funding(
    metadata: &CoinMetadata,
    observed: &ObservedFunding,
    minimum_confirmations: u32,
) -> Result<()> {
    verify_observed_funding_output(metadata, observed, minimum_confirmations)?;
    ensure!(observed.unspent, "Tinylayer funding output is spent");
    Ok(())
}

pub(crate) fn verify_observed_funding_output(
    metadata: &CoinMetadata,
    observed: &ObservedFunding,
    minimum_confirmations: u32,
) -> Result<()> {
    ensure!(
        observed.outpoint == metadata.outpoint,
        "observed funding output has the wrong outpoint"
    );
    verify_funding_utxo(metadata, observed.outpoint, &observed.output)?;
    ensure!(
        observed.confirmations >= minimum_confirmations,
        "funding output has {} confirmations; {minimum_confirmations} required",
        observed.confirmations
    );
    ensure!(
        !observed.coinbase || observed.confirmations >= 100,
        "coinbase funding output is not mature"
    );
    Ok(())
}

pub fn verify_public_history(
    metadata: &CoinMetadata,
    status: &CoinStatus,
    history: &[SignedRecovery],
    funding_confirmations: u32,
    minimum_reaction_blocks: u32,
) -> Result<()> {
    verify_status(&metadata.keys, status)?;
    ensure!(
        status.signature_count == history.len() as u64,
        "recovery history does not match enclave signature count"
    );
    ensure!(!history.is_empty(), "coin has no signed recovery");
    for recovery in history {
        verify_recovery(metadata, recovery)?;
    }
    for pair in history.windows(2) {
        validate_reaction_window(
            funding_confirmations,
            pair[0].delay_blocks,
            pair[1].delay_blocks,
        )?;
    }
    require_reaction_margin(
        funding_confirmations,
        history
            .last()
            .expect("history checked non-empty")
            .delay_blocks,
        minimum_reaction_blocks,
    )
}

pub fn require_reaction_margin(
    funding_confirmations: u32,
    delay_blocks: u32,
    minimum_reaction_blocks: u32,
) -> Result<()> {
    let minimum = funding_confirmations
        .checked_add(minimum_reaction_blocks)
        .context("reaction margin overflow")?;
    ensure!(
        delay_blocks > minimum,
        "latest recovery delay {delay_blocks} must be greater than funding confirmations {funding_confirmations} plus reaction margin {minimum_reaction_blocks}"
    );
    Ok(())
}

pub fn attempt_uncommitted(status: &CoinStatus, attempt: &RecoveryAttempt) -> bool {
    status.signature_count == attempt.expected_signature_count
        && status.authorization
            == authorization(
                &attempt.request.coin_id,
                &capability_hash(&attempt.request.current_capability),
                &attempt.request.current_handoff,
            )
}

pub fn attempt_committed(status: &CoinStatus, attempt: &RecoveryAttempt) -> Result<bool> {
    let completed_count = attempt
        .expected_signature_count
        .checked_add(1)
        .context("signature count overflow")?;
    Ok(status.signature_count == completed_count)
}

#[cfg(test)]
mod tests {
    use super::*;
    use bitcoin::{
        Amount, OutPoint, ScriptBuf, TxIn, TxOut, Txid, Witness, absolute, hashes::Hash as _,
        transaction,
    };
    use tinylayer_client::{CoinKeys, NetworkId, PROTOCOL_VERSION};

    #[test]
    fn reaction_margin_is_strict_and_checked() {
        assert!(require_reaction_margin(79, 100, 20).is_ok());
        assert!(require_reaction_margin(80, 100, 20).is_err());
        assert!(require_reaction_margin(81, 100, 20).is_err());
        assert!(require_reaction_margin(u32::MAX, u32::MAX, 1).is_err());
    }

    #[test]
    fn observed_funding_binds_outpoint_output_confirmations_and_unspent_state() {
        let keys = CoinKeys {
            protocol_version: PROTOCOL_VERSION,
            coin_id: [1; 32],
            client_pubkey: crate::secret_xonly(&secret(2)),
            enclave_pubkey: crate::secret_xonly(&secret(3)),
        };
        let output = TxOut {
            value: bitcoin::Amount::from_sat(100_000),
            script_pubkey: funding_script(&keys),
        };
        let transaction = Transaction {
            version: transaction::Version::TWO,
            lock_time: absolute::LockTime::ZERO,
            input: vec![TxIn {
                previous_output: OutPoint::new(Txid::from_byte_array([4; 32]), 0),
                script_sig: ScriptBuf::new(),
                sequence: bitcoin::Sequence::MAX,
                witness: Witness::new(),
            }],
            output: vec![output],
        };
        let metadata = CoinMetadata {
            keys,
            network: NetworkId::Regtest,
            outpoint: OutPoint::new(transaction.compute_txid(), 0),
            amount_sat: 100_000,
        };
        let observed = ObservedFunding {
            outpoint: metadata.outpoint,
            output: transaction.output[0].clone(),
            confirmations: 6,
            unspent: true,
            coinbase: false,
        };
        verify_observed_funding(&metadata, &observed, 6).unwrap();
        let mut wrong = observed.clone();
        wrong.confirmations = 5;
        assert!(verify_observed_funding(&metadata, &wrong, 6).is_err());
        wrong = observed.clone();
        wrong.unspent = false;
        assert!(verify_observed_funding(&metadata, &wrong, 6).is_err());
        wrong = observed;
        wrong.output.value = Amount::from_sat(99_999);
        assert!(verify_observed_funding(&metadata, &wrong, 6).is_err());
    }

    fn secret(byte: u8) -> bitcoin::secp256k1::SecretKey {
        bitcoin::secp256k1::SecretKey::from_slice(&[byte; 32]).unwrap()
    }
}
