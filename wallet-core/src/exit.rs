use std::str::FromStr as _;

use anyhow::{Context as _, Result, ensure};
use bitcoin::{Address, Transaction, Txid, secp256k1::SecretKey};
use serde::{Deserialize, Serialize};
use tinylayer_client::{NetworkId, build_exit_child, verify_recovery};

use crate::{
    FILE_FORMAT_VERSION, FundingStage, ObservedFunding, WalletCoin, secret_xonly,
    validation::verify_observed_funding_output,
};

#[allow(clippy::too_many_arguments)]
pub fn verify_exit_funding(
    coin: &WalletCoin,
    observed: &ObservedFunding,
    minimum_confirmations: u32,
    spending_txid: Option<Txid>,
    spending_confirmed: bool,
    saved_exit_parent: Option<Txid>,
) -> Result<()> {
    let metadata = coin
        .metadata
        .as_ref()
        .context("coin has no verified funding")?;
    verify_observed_funding_output(metadata, observed, minimum_confirmations)?;
    if observed.unspent {
        return Ok(());
    }
    let spending_txid = spending_txid.context("spent funding output has no spending txid")?;
    let spending_index = coin
        .history
        .iter()
        .position(|recovery| recovery.transaction.compute_txid() == spending_txid)
        .context("funding output was spent by an unknown transaction")?;
    let owned_index = coin
        .withdrawal_recovery_index
        .context("wallet has no owned recovery")?;
    ensure!(
        spending_index <= owned_index,
        "a newer owner's recovery is already in the mempool"
    );
    let known_recovery = &coin.history[spending_index];
    verify_recovery(metadata, known_recovery)?;
    ensure!(
        !spending_confirmed
            || (spending_index == owned_index
                && saved_exit_parent.is_none_or(|parent| parent == spending_txid)),
        "a different recovery has already confirmed"
    );
    Ok(())
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct ExitPackage {
    pub format_version: u32,
    pub network: NetworkId,
    pub destination: String,
    pub fee_rate_sat_vb: u64,
    pub max_fee_sat: u64,
    pub fee_sat: u64,
    pub recovery_delay_blocks: u32,
    pub parent: Transaction,
    pub child: Transaction,
}

impl ExitPackage {
    pub fn prepare(
        coin: &WalletCoin,
        network: NetworkId,
        destination: &str,
        funding_confirmations: u32,
        fee_rate_sat_vb: u64,
        max_fee_sat: u64,
    ) -> Result<Self> {
        ensure!(fee_rate_sat_vb > 0, "exit fee rate must be positive");
        let destination = Address::from_str(destination)
            .context("invalid destination address")?
            .require_network(network.bitcoin_network())
            .context("destination address is for the wrong network")?;
        let (metadata, recovery, withdrawal_secret) = owned_recovery(coin, network)?;
        ensure!(
            funding_confirmations >= recovery.delay_blocks,
            "recovery is not final until funding has {} confirmations (currently {})",
            recovery.delay_blocks,
            funding_confirmations
        );
        let child = build_exit_child(
            recovery,
            metadata.amount_sat,
            &withdrawal_secret,
            destination.script_pubkey(),
            fee_rate_sat_vb,
        )?;
        let fee_sat = metadata
            .amount_sat
            .checked_sub(child.output[0].value.to_sat())
            .context("exit fee exceeds the coin amount")?;
        ensure!(
            fee_sat <= max_fee_sat,
            "exit fee {fee_sat} sat exceeds maximum {max_fee_sat} sat"
        );
        let package = Self {
            format_version: FILE_FORMAT_VERSION,
            network,
            destination: destination.to_string(),
            fee_rate_sat_vb,
            max_fee_sat,
            fee_sat,
            recovery_delay_blocks: recovery.delay_blocks,
            parent: recovery.transaction.clone(),
            child,
        };
        package.validate(coin)?;
        Ok(package)
    }

    pub fn validate(&self, coin: &WalletCoin) -> Result<()> {
        ensure!(
            self.format_version == FILE_FORMAT_VERSION,
            "unsupported exit package version {}",
            self.format_version
        );
        ensure!(self.fee_rate_sat_vb > 0, "exit fee rate must be positive");
        let destination = Address::from_str(&self.destination)
            .context("invalid saved exit destination")?
            .require_network(self.network.bitcoin_network())
            .context("saved exit destination is for the wrong network")?;
        let (metadata, recovery, withdrawal_secret) = owned_recovery(coin, self.network)?;
        ensure!(
            recovery.delay_blocks == self.recovery_delay_blocks
                && recovery.transaction == self.parent,
            "saved exit parent does not match the owned recovery"
        );
        let expected_child = build_exit_child(
            recovery,
            metadata.amount_sat,
            &withdrawal_secret,
            destination.script_pubkey(),
            self.fee_rate_sat_vb,
        )?;
        ensure!(
            expected_child == self.child,
            "saved exit child is not canonical"
        );
        let fee_sat = metadata
            .amount_sat
            .checked_sub(self.child.output[0].value.to_sat())
            .context("exit fee exceeds the coin amount")?;
        ensure!(fee_sat == self.fee_sat, "saved exit fee is inconsistent");
        ensure!(
            fee_sat <= self.max_fee_sat,
            "exit fee {fee_sat} sat exceeds maximum {} sat",
            self.max_fee_sat
        );
        Ok(())
    }
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum ExitStage {
    Prepared,
    SubmissionArmed,
    Observed,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct ExitJournal {
    pub package: ExitPackage,
    pub stage: ExitStage,
}

impl ExitJournal {
    pub fn prepare(
        coin: &WalletCoin,
        network: NetworkId,
        destination: &str,
        funding_confirmations: u32,
        fee_rate_sat_vb: u64,
        max_fee_sat: u64,
    ) -> Result<Self> {
        Ok(Self {
            package: ExitPackage::prepare(
                coin,
                network,
                destination,
                funding_confirmations,
                fee_rate_sat_vb,
                max_fee_sat,
            )?,
            stage: ExitStage::Prepared,
        })
    }

    pub fn validate(&self, coin: &WalletCoin) -> Result<()> {
        self.package.validate(coin)
    }

    pub fn arm_submission(&mut self, coin: &WalletCoin) -> Result<()> {
        self.validate(coin)?;
        self.stage = ExitStage::SubmissionArmed;
        Ok(())
    }

    pub fn validate_observed_parent(&self, coin: &WalletCoin, parent: &Transaction) -> Result<()> {
        self.validate(coin)?;
        ensure!(
            parent.compute_txid() == self.package.parent.compute_txid(),
            "observed exit parent has the wrong txid"
        );
        let (metadata, recovery, _) = owned_recovery(coin, self.package.network)?;
        let observed = tinylayer_client::SignedRecovery {
            transaction: parent.clone(),
            withdrawal_xonly_pubkey: recovery.withdrawal_xonly_pubkey,
            delay_blocks: recovery.delay_blocks,
        };
        verify_recovery(metadata, &observed)?;
        Ok(())
    }

    pub fn mark_observed(
        &mut self,
        coin: &WalletCoin,
        parent: &Transaction,
        child: &Transaction,
    ) -> Result<()> {
        self.validate(coin)?;
        ensure!(
            self.stage == ExitStage::SubmissionArmed,
            "exit package was not armed for submission"
        );
        self.validate_observed_parent(coin, parent)?;
        ensure!(
            child == &self.package.child,
            "observed exit child bytes do not match the saved package"
        );
        self.stage = ExitStage::Observed;
        Ok(())
    }
}

fn owned_recovery(
    coin: &WalletCoin,
    network: NetworkId,
) -> Result<(
    &tinylayer_client::CoinMetadata,
    &tinylayer_client::SignedRecovery,
    SecretKey,
)> {
    let metadata = coin
        .metadata
        .as_ref()
        .context("coin has no verified funding")?;
    ensure!(metadata.network == network, "exit network mismatch");
    ensure!(
        coin.funding
            .as_ref()
            .is_none_or(|funding| funding.stage == FundingStage::Broadcast),
        "funding has not been broadcast"
    );
    let withdrawal_secret = SecretKey::from_slice(
        &coin
            .withdrawal_secret
            .context("wallet has no current withdrawal key")?,
    )
    .context("saved withdrawal key is invalid")?;
    let recovery = coin
        .history
        .get(
            coin.withdrawal_recovery_index
                .context("wallet has no owned recovery")?,
        )
        .context("owned recovery index is invalid")?;
    ensure!(
        secret_xonly(&withdrawal_secret) == recovery.withdrawal_xonly_pubkey,
        "saved withdrawal key does not match owned recovery"
    );
    verify_recovery(metadata, recovery)?;
    Ok((metadata, recovery, withdrawal_secret))
}

#[cfg(test)]
mod tests {
    use super::*;
    use bitcoin::{
        Amount, OutPoint, Txid,
        hashes::Hash as _,
        secp256k1::{Keypair, Message, Secp256k1},
    };
    use tinylayer_client::{
        CoinMetadata, PROTOCOL_VERSION, complete_recovery, prepare_recovery, recovery_sighash,
    };
    use tinylayer_enclave::Signer;

    #[test]
    fn exit_journal_is_exact_and_requires_maturity_and_arming() {
        let mut signer = Signer::<1>::new();
        let client_secret = crate::random_secret_key();
        let capability = [3; 32];
        let next_capability = [4; 32];
        let registration = tinylayer_client::prepare_registration(
            client_secret,
            tinylayer_client::capability_hash(&capability),
        );
        let status = signer.register(registration.request.clone()).unwrap();
        let keys = tinylayer_client::complete_registration(registration, &status).unwrap();
        let metadata = CoinMetadata {
            keys,
            network: NetworkId::Regtest,
            outpoint: OutPoint::new(Txid::from_byte_array([5; 32]), 0),
            amount_sat: 100_000,
        };
        let withdrawal = crate::random_secret_key();
        let (request, prepared) = prepare_recovery(
            &metadata,
            &status,
            client_secret,
            capability,
            tinylayer_client::INITIAL_HANDOFF,
            tinylayer_client::capability_hash(&next_capability),
            withdrawal.x_only_public_key(&Secp256k1::new()).0,
            100,
            0,
        )
        .unwrap();
        let response = signer.sign(request.clone()).unwrap();
        let recovery = complete_recovery(&request, &response, prepared, client_secret).unwrap();
        let coin = WalletCoin {
            client_secret,
            keys: metadata.keys.clone(),
            metadata: Some(metadata),
            funding: None,
            current_capability: Some(next_capability),
            current_handoff: Some(response.next_handoff),
            withdrawal_secret: Some(withdrawal.secret_bytes()),
            withdrawal_recovery_index: Some(0),
            accepted_request: None,
            accepted_envelope_fingerprint: None,
            history: vec![recovery],
            outgoing: None,
        };
        let destination = Address::p2tr(
            &Secp256k1::new(),
            crate::secret_xonly(&crate::random_secret_key()),
            None,
            bitcoin::Network::Regtest,
        );
        let destination = destination.to_string();
        assert!(
            ExitJournal::prepare(&coin, NetworkId::Regtest, &destination, 99, 1, 10_000).is_err()
        );
        let mut journal =
            ExitJournal::prepare(&coin, NetworkId::Regtest, &destination, 100, 1, 10_000).unwrap();
        assert!(journal.package.fee_sat > 0);
        assert_eq!(journal.stage, ExitStage::Prepared);
        assert!(
            journal
                .mark_observed(
                    &coin,
                    &journal.package.parent.clone(),
                    &journal.package.child.clone()
                )
                .is_err()
        );
        journal.arm_submission(&coin).unwrap();
        let canonical_parent = journal.package.parent.clone();
        let mut parent = canonical_parent.clone();
        let metadata = coin.metadata.as_ref().unwrap();
        let sighash = recovery_sighash(&parent, metadata.amount_sat, &metadata.keys).unwrap();
        let signature = Secp256k1::new().sign_schnorr_with_aux_rand(
            &Message::from_digest(sighash),
            &Keypair::from_secret_key(&Secp256k1::new(), &client_secret),
            &[42; 32],
        );
        let mut witness: Vec<Vec<u8>> = parent.input[0]
            .witness
            .iter()
            .map(|item| item.to_vec())
            .collect();
        witness[1] = signature.as_ref().to_vec();
        parent.input[0].witness = bitcoin::Witness::from_slice(&witness);
        assert_eq!(parent.compute_txid(), canonical_parent.compute_txid());
        assert_ne!(parent.compute_wtxid(), canonical_parent.compute_wtxid());
        journal.validate_observed_parent(&coin, &parent).unwrap();
        let child = journal.package.child.clone();
        journal.mark_observed(&coin, &parent, &child).unwrap();
        assert_eq!(journal.stage, ExitStage::Observed);
        journal.validate(&coin).unwrap();
        journal.arm_submission(&coin).unwrap();
        assert_eq!(journal.stage, ExitStage::SubmissionArmed);
        journal.mark_observed(&coin, &parent, &child).unwrap();
        assert_eq!(
            coin.metadata.as_ref().unwrap().amount_sat,
            Amount::from_sat(100_000).to_sat()
        );
        assert_eq!(PROTOCOL_VERSION, 1);
    }
}
