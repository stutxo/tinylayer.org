use std::str::FromStr as _;

use anyhow::{Context as _, Result, ensure};
use bitcoin::{
    Address, Amount, OutPoint, ScriptBuf, Sequence, Transaction, TxIn, TxOut, Witness, absolute,
    address::KnownHrp,
    hashes::Hash as _,
    key::TapTweak as _,
    secp256k1::{Keypair, Message, Secp256k1, SecretKey},
    sighash::Prevouts,
    transaction::Version,
};
use serde::{Deserialize, Serialize};
use tinylayer_client::{CoinKeys, NetworkId, funding_script};

use crate::{FILE_FORMAT_VERSION, validate_funding_inputs};

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct SourceUtxo {
    pub outpoint: OutPoint,
    pub output: TxOut,
    pub confirmations: u32,
    pub coinbase: bool,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct PreparedSourceFunding {
    pub transaction: Transaction,
    pub outpoint: OutPoint,
    pub fee_sat: u64,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct PreparedSourceSweep {
    pub transaction: Transaction,
    pub fee_sat: u64,
}

pub fn source_funding_address(secret: &SecretKey, network: NetworkId) -> Address {
    let secp = Secp256k1::new();
    let internal_key = secret.x_only_public_key(&secp).0;
    let hrp = match network {
        NetworkId::Mutinynet => KnownHrp::Testnets,
        NetworkId::Mainnet => KnownHrp::Mainnet,
        NetworkId::Regtest => KnownHrp::Regtest,
    };
    Address::p2tr(&secp, internal_key, None, hrp)
}

#[allow(clippy::too_many_arguments)]
pub fn build_source_funding(
    keys: &CoinKeys,
    network: NetworkId,
    source_secret: &SecretKey,
    source: &SourceUtxo,
    amount_sat: u64,
    fee_rate_sat_vb: u64,
    max_fee_sat: u64,
) -> Result<PreparedSourceFunding> {
    ensure!(source.confirmations > 0, "funding input is not confirmed");
    ensure!(
        !source.coinbase,
        "coinbase funding inputs are not supported"
    );
    ensure!(
        !source.outpoint.is_null(),
        "funding transaction cannot spend a coinbase input"
    );
    ensure!(fee_rate_sat_vb > 0, "funding fee rate must be positive");
    ensure!(
        amount_sat <= Amount::MAX_MONEY.to_sat(),
        "funding amount exceeds Bitcoin MAX_MONEY"
    );
    let change_script = source_funding_address(source_secret, network).script_pubkey();
    ensure!(
        source.output.script_pubkey == change_script,
        "funding input does not belong to the local deposit key"
    );
    let statechain_script = funding_script(keys);
    ensure!(
        Amount::from_sat(amount_sat) >= statechain_script.minimal_non_dust(),
        "Tinylayer funding output would be dust"
    );
    let mut transaction = Transaction {
        version: Version::TWO,
        lock_time: absolute::LockTime::ZERO,
        input: vec![TxIn {
            previous_output: source.outpoint,
            script_sig: ScriptBuf::new(),
            sequence: Sequence::MAX,
            witness: Witness::new(),
        }],
        output: vec![
            TxOut {
                value: Amount::from_sat(amount_sat),
                script_pubkey: statechain_script,
            },
            TxOut {
                value: Amount::ZERO,
                script_pubkey: change_script,
            },
        ],
    };
    transaction.input[0].witness.push([0; 64]);
    let fee_sat = u128::from(fee_rate_sat_vb)
        .checked_mul(transaction.vsize() as u128)
        .and_then(|fee| u64::try_from(fee).ok())
        .context("funding fee overflow")?;
    ensure!(
        fee_sat <= max_fee_sat,
        "funding fee {fee_sat} sat exceeds maximum {max_fee_sat} sat"
    );
    let change_sat = source
        .output
        .value
        .to_sat()
        .checked_sub(amount_sat)
        .and_then(|value| value.checked_sub(fee_sat))
        .context("funding input cannot cover amount and fee")?;
    let change = Amount::from_sat(change_sat);
    ensure!(
        change >= transaction.output[1].script_pubkey.minimal_non_dust(),
        "funding input does not leave dust-safe change"
    );
    transaction.output[1].value = change;

    let sighash = bitcoin::sighash::SighashCache::new(&transaction)
        .taproot_key_spend_signature_hash(
            0,
            &Prevouts::All(std::slice::from_ref(&source.output)),
            bitcoin::TapSighashType::Default,
        )
        .context("compute funding transaction sighash")?;
    let secp = Secp256k1::new();
    let keypair = Keypair::from_secret_key(&secp, source_secret);
    let tweaked = keypair.tap_tweak(&secp, None).to_keypair();
    let message = Message::from_digest(sighash.to_byte_array());
    let signature = secp.sign_schnorr_no_aux_rand(&message, &tweaked);
    let (tweaked_public_key, _) = tweaked.x_only_public_key();
    secp.verify_schnorr(&signature, &message, &tweaked_public_key)
        .context("verify funding transaction signature")?;
    transaction.input[0].witness.clear();
    transaction.input[0].witness.push(signature.as_ref());
    validate_funding_inputs(&transaction)?;
    let outpoint = OutPoint::new(transaction.compute_txid(), 0);
    Ok(PreparedSourceFunding {
        transaction,
        outpoint,
        fee_sat,
    })
}

pub fn build_source_sweep(
    network: NetworkId,
    source_secret: &SecretKey,
    sources: &[SourceUtxo],
    destination: &str,
    fee_rate_sat_vb: u64,
    max_fee_sat: u64,
) -> Result<PreparedSourceSweep> {
    ensure!(!sources.is_empty(), "source sweep has no inputs");
    ensure!(sources.len() <= 100, "source sweep exceeds 100 inputs");
    ensure!(
        fee_rate_sat_vb > 0,
        "source sweep fee rate must be positive"
    );
    let destination = Address::from_str(destination)
        .context("invalid source sweep destination")?
        .require_network(network.bitcoin_network())
        .context("source sweep destination is for the wrong network")?;
    let expected_script = source_funding_address(source_secret, network).script_pubkey();
    ensure!(
        destination.script_pubkey() != expected_script,
        "source sweep destination cannot be the deposit address"
    );
    let mut sources = sources.to_vec();
    sources.sort_by_key(|source| source.outpoint);
    for source in &sources {
        ensure!(
            source.confirmations > 0,
            "source sweep input is not confirmed"
        );
        ensure!(
            !source.coinbase,
            "coinbase source sweep inputs are not supported"
        );
        ensure!(
            !source.outpoint.is_null(),
            "source sweep cannot spend a coinbase input"
        );
        ensure!(
            source.output.script_pubkey == expected_script,
            "source sweep input does not belong to the local deposit key"
        );
    }
    ensure!(
        sources
            .windows(2)
            .all(|pair| pair[0].outpoint != pair[1].outpoint),
        "source sweep contains a duplicate input"
    );
    let input_sat = sources.iter().try_fold(0u64, |total, source| {
        total
            .checked_add(source.output.value.to_sat())
            .context("source sweep input amount overflow")
    })?;
    let mut transaction = Transaction {
        version: Version::TWO,
        lock_time: absolute::LockTime::ZERO,
        input: sources
            .iter()
            .map(|source| TxIn {
                previous_output: source.outpoint,
                script_sig: ScriptBuf::new(),
                sequence: Sequence::MAX,
                witness: Witness::from_slice(&[[0; 64]]),
            })
            .collect(),
        output: vec![TxOut {
            value: Amount::ZERO,
            script_pubkey: destination.script_pubkey(),
        }],
    };
    let fee_sat = u128::from(fee_rate_sat_vb)
        .checked_mul(transaction.vsize() as u128)
        .and_then(|fee| u64::try_from(fee).ok())
        .context("source sweep fee overflow")?;
    ensure!(
        fee_sat <= max_fee_sat,
        "source sweep fee {fee_sat} sat exceeds maximum {max_fee_sat} sat"
    );
    let output_sat = input_sat
        .checked_sub(fee_sat)
        .context("source sweep fee exceeds its inputs")?;
    let output_amount = Amount::from_sat(output_sat);
    ensure!(
        output_amount >= transaction.output[0].script_pubkey.minimal_non_dust(),
        "source sweep output would be dust"
    );
    transaction.output[0].value = output_amount;

    let prevouts: Vec<_> = sources.iter().map(|source| source.output.clone()).collect();
    let secp = Secp256k1::new();
    let keypair = Keypair::from_secret_key(&secp, source_secret);
    let tweaked = keypair.tap_tweak(&secp, None).to_keypair();
    let (tweaked_public_key, _) = tweaked.x_only_public_key();
    let signatures: Vec<_> = (0..transaction.input.len())
        .map(|index| {
            let sighash = bitcoin::sighash::SighashCache::new(&transaction)
                .taproot_key_spend_signature_hash(
                    index,
                    &Prevouts::All(&prevouts),
                    bitcoin::TapSighashType::Default,
                )
                .context("compute source sweep sighash")?;
            let message = Message::from_digest(sighash.to_byte_array());
            let signature = secp.sign_schnorr_no_aux_rand(&message, &tweaked);
            secp.verify_schnorr(&signature, &message, &tweaked_public_key)
                .context("verify source sweep signature")?;
            Ok(signature)
        })
        .collect::<Result<_>>()?;
    for (input, signature) in transaction.input.iter_mut().zip(signatures) {
        input.witness.clear();
        input.witness.push(signature.as_ref());
    }
    validate_funding_inputs(&transaction)?;
    Ok(PreparedSourceSweep {
        transaction,
        fee_sat,
    })
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum SourceSweepStage {
    Prepared,
    SubmissionArmed,
    Observed,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct SourceSweepJournal {
    pub format_version: u32,
    pub network: NetworkId,
    pub destination: String,
    pub sources: Vec<SourceUtxo>,
    pub fee_rate_sat_vb: u64,
    pub max_fee_sat: u64,
    pub fee_sat: u64,
    pub transaction: Transaction,
    pub stage: SourceSweepStage,
}

impl SourceSweepJournal {
    pub fn prepare(
        source_secret: &SecretKey,
        network: NetworkId,
        sources: Vec<SourceUtxo>,
        destination: &str,
        fee_rate_sat_vb: u64,
        max_fee_sat: u64,
    ) -> Result<Self> {
        let mut sources = sources;
        sources.sort_by_key(|source| source.outpoint);
        let destination = Address::from_str(destination)
            .context("invalid source sweep destination")?
            .require_network(network.bitcoin_network())
            .context("source sweep destination is for the wrong network")?
            .to_string();
        let prepared = build_source_sweep(
            network,
            source_secret,
            &sources,
            &destination,
            fee_rate_sat_vb,
            max_fee_sat,
        )?;
        Ok(Self {
            format_version: FILE_FORMAT_VERSION,
            network,
            destination,
            sources,
            fee_rate_sat_vb,
            max_fee_sat,
            fee_sat: prepared.fee_sat,
            transaction: prepared.transaction,
            stage: SourceSweepStage::Prepared,
        })
    }

    pub fn validate(&self, source_secret: &SecretKey) -> Result<()> {
        ensure!(
            self.format_version == FILE_FORMAT_VERSION,
            "unsupported source sweep version {}",
            self.format_version
        );
        let expected = build_source_sweep(
            self.network,
            source_secret,
            &self.sources,
            &self.destination,
            self.fee_rate_sat_vb,
            self.max_fee_sat,
        )?;
        ensure!(
            expected.fee_sat == self.fee_sat && expected.transaction == self.transaction,
            "saved source sweep is not canonical"
        );
        Ok(())
    }

    pub fn arm_submission(&mut self, source_secret: &SecretKey) -> Result<()> {
        self.validate(source_secret)?;
        self.stage = SourceSweepStage::SubmissionArmed;
        Ok(())
    }

    pub fn mark_observed(
        &mut self,
        source_secret: &SecretKey,
        observed: &Transaction,
    ) -> Result<()> {
        self.validate(source_secret)?;
        ensure!(
            self.stage == SourceSweepStage::SubmissionArmed,
            "source sweep was not armed for submission"
        );
        ensure!(
            observed == &self.transaction,
            "observed source sweep bytes do not match the saved transaction"
        );
        self.stage = SourceSweepStage::Observed;
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use bitcoin::Txid;
    use tinylayer_client::{CoinKeys, PROTOCOL_VERSION};

    #[test]
    fn source_funding_has_exact_non_rbf_keyspend_and_change() {
        let source_secret = secret(1);
        let source_output = TxOut {
            value: Amount::from_sat(150_000),
            script_pubkey: source_funding_address(&source_secret, NetworkId::Mutinynet)
                .script_pubkey(),
        };
        let prepared = build_source_funding(
            &CoinKeys {
                protocol_version: PROTOCOL_VERSION,
                coin_id: [3; 32],
                client_pubkey: secret(2).x_only_public_key(&Secp256k1::new()).0,
                enclave_pubkey: secret(3).x_only_public_key(&Secp256k1::new()).0,
            },
            NetworkId::Mutinynet,
            &source_secret,
            &SourceUtxo {
                outpoint: OutPoint::new(Txid::from_byte_array([4; 32]), 0),
                output: source_output,
                confirmations: 1,
                coinbase: false,
            },
            100_000,
            2,
            10_000,
        )
        .unwrap();
        let transaction = prepared.transaction;
        assert_eq!(transaction.version, Version::TWO);
        assert_eq!(transaction.lock_time, absolute::LockTime::ZERO);
        assert_eq!(transaction.input[0].sequence, Sequence::MAX);
        assert_eq!(transaction.input[0].witness.len(), 1);
        assert_eq!(transaction.output.len(), 2);
        assert_eq!(transaction.output[0].value, Amount::from_sat(100_000));
        assert_eq!(
            150_000
                - transaction
                    .output
                    .iter()
                    .map(|output| output.value.to_sat())
                    .sum::<u64>(),
            prepared.fee_sat
        );
        assert_eq!(prepared.fee_sat, transaction.vsize() as u64 * 2);
        assert_eq!(prepared.outpoint.vout, 0);
        validate_funding_inputs(&transaction).unwrap();
    }

    #[test]
    fn source_sweep_sorts_and_signs_every_input_with_an_exact_fee() {
        let source_secret = secret(1);
        let script = source_funding_address(&source_secret, NetworkId::Mutinynet).script_pubkey();
        let destination = source_funding_address(&secret(2), NetworkId::Mutinynet).to_string();
        let sources = vec![
            SourceUtxo {
                outpoint: OutPoint::new(Txid::from_byte_array([9; 32]), 1),
                output: TxOut {
                    value: Amount::from_sat(40_000),
                    script_pubkey: script.clone(),
                },
                confirmations: 2,
                coinbase: false,
            },
            SourceUtxo {
                outpoint: OutPoint::new(Txid::from_byte_array([3; 32]), 0),
                output: TxOut {
                    value: Amount::from_sat(60_000),
                    script_pubkey: script,
                },
                confirmations: 3,
                coinbase: false,
            },
        ];
        let mut journal = SourceSweepJournal::prepare(
            &source_secret,
            NetworkId::Mutinynet,
            sources,
            &destination,
            2,
            10_000,
        )
        .unwrap();
        assert!(journal.sources[0].outpoint < journal.sources[1].outpoint);
        assert_eq!(journal.transaction.input.len(), 2);
        assert!(
            journal
                .transaction
                .input
                .iter()
                .all(|input| input.sequence == Sequence::MAX && input.witness.len() == 1)
        );
        assert_eq!(journal.fee_sat, journal.transaction.vsize() as u64 * 2);
        assert_eq!(
            journal.transaction.output[0].value.to_sat(),
            100_000 - journal.fee_sat
        );
        journal.validate(&source_secret).unwrap();
        journal.arm_submission(&source_secret).unwrap();
        let transaction = journal.transaction.clone();
        journal.mark_observed(&source_secret, &transaction).unwrap();
        journal.arm_submission(&source_secret).unwrap();

        let mut duplicate = journal.sources.clone();
        duplicate.push(duplicate[0].clone());
        assert!(
            build_source_sweep(
                NetworkId::Mutinynet,
                &source_secret,
                &duplicate,
                &destination,
                1,
                10_000,
            )
            .is_err()
        );
        assert!(
            build_source_sweep(
                NetworkId::Mutinynet,
                &source_secret,
                &journal.sources,
                &source_funding_address(&source_secret, NetworkId::Mutinynet).to_string(),
                1,
                10_000,
            )
            .is_err()
        );
    }

    fn secret(byte: u8) -> SecretKey {
        SecretKey::from_slice(&[byte; 32]).unwrap()
    }
}
