use anyhow::{Context as _, Result, ensure};
use bitcoin::{
    OutPoint, Transaction,
    secp256k1::{PublicKey, Secp256k1, SecretKey},
};
use serde::{Deserialize, Serialize};
use tinylayer_client::{
    CoinKeys, CoinMetadata, CoinStatus, DELAY_STEP, HandoffToken, INITIAL_HANDOFF, NetworkId,
    PreparedRecovery, RegisterRequest, Registration, SignRequest, SignResponse, SignedRecovery,
    authorization, capability_hash, complete_recovery, complete_registration, prepare_recovery,
    prepare_registration, verify_history, verify_recovery, verify_sign_response, verify_status,
};

use crate::{
    ObservedFunding, SourceUtxo, TransferEnvelope, TransferPayload, TransferRequest,
    attempt_committed, attempt_uncommitted, build_source_funding, decrypt_transfer,
    encrypt_transfer, random_secret_key, require_reaction_margin, secret_xonly,
    validate_finalized_funding, validate_transfer_payload_size, verify_observed_funding,
};

pub const FILE_FORMAT_VERSION: u32 = 1;

#[derive(Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct WalletState {
    pub format_version: u32,
    pub coin: Option<WalletCoin>,
    pub incoming: Option<IncomingTransfer>,
    pub pending: Option<PendingOperation>,
}

impl WalletState {
    pub fn empty() -> Self {
        Self {
            format_version: FILE_FORMAT_VERSION,
            coin: None,
            incoming: None,
            pending: None,
        }
    }

    pub fn validate_version(&self) -> Result<()> {
        ensure!(
            self.format_version == FILE_FORMAT_VERSION,
            "unsupported wallet format version {}",
            self.format_version
        );
        if let Some(coin) = &self.coin {
            ensure!(
                coin.accepted_request.is_some() == coin.accepted_envelope_fingerprint.is_some(),
                "accepted transfer replay binding is incomplete"
            );
        }
        Ok(())
    }

    /// Creates and journals one exact registration request. Calling this again
    /// before completion returns the saved request rather than generating a new coin.
    pub fn begin_registration(&mut self) -> Result<RegisterRequest> {
        self.validate_version()?;
        ensure!(self.coin.is_none(), "wallet already contains a coin");
        ensure!(
            self.incoming.is_none(),
            "wallet has a pending transfer request"
        );
        match &self.pending {
            Some(PendingOperation::Registration { registration, .. }) => {
                return Ok(registration.request.clone());
            }
            Some(PendingOperation::Recovery(_)) => {
                anyhow::bail!("wallet has a pending signing operation");
            }
            None => {}
        }
        let client_secret = random_secret_key();
        let initial_capability = rand::random();
        let registration =
            prepare_registration(client_secret, capability_hash(&initial_capability));
        let request = registration.request.clone();
        self.pending = Some(PendingOperation::Registration {
            client_secret,
            initial_capability,
            registration,
        });
        Ok(request)
    }

    /// Applies an enclave registration response after the caller has durably
    /// saved the pending request.
    pub fn complete_registration(&mut self, status: &CoinStatus) -> Result<()> {
        self.validate_version()?;
        ensure!(self.coin.is_none(), "wallet already contains a coin");
        let (client_secret, initial_capability, registration) = match self
            .pending
            .as_ref()
            .context("wallet has no pending registration")?
        {
            PendingOperation::Registration {
                client_secret,
                initial_capability,
                registration,
            } => (*client_secret, *initial_capability, registration.clone()),
            PendingOperation::Recovery(_) => {
                anyhow::bail!("wallet has a pending signing operation");
            }
        };
        let keys = complete_registration(registration, status)?;
        self.coin = Some(WalletCoin {
            client_secret,
            keys,
            metadata: None,
            funding: None,
            current_capability: Some(initial_capability),
            current_handoff: Some(INITIAL_HANDOFF),
            withdrawal_secret: None,
            withdrawal_recovery_index: None,
            accepted_request: None,
            accepted_envelope_fingerprint: None,
            history: Vec::new(),
            outgoing: None,
        });
        self.pending = None;
        Ok(())
    }

    #[allow(clippy::too_many_arguments)]
    pub fn begin_funding(
        &mut self,
        network: NetworkId,
        source_secret: &SecretKey,
        source: &SourceUtxo,
        status: &CoinStatus,
        amount_sat: u64,
        delay_blocks: u32,
        fee_rate_sat_vb: u64,
        max_fee_sat: u64,
        minimum_reaction_blocks: u32,
    ) -> Result<SignRequest> {
        self.validate_version()?;
        ensure!(self.pending.is_none(), "wallet has a pending operation");
        require_reaction_margin(0, delay_blocks, minimum_reaction_blocks)?;
        let coin = self.coin.as_ref().context("register a coin first")?;
        ensure!(
            coin.metadata.is_none()
                && coin.funding.is_none()
                && coin.history.is_empty()
                && coin.current_handoff == Some(INITIAL_HANDOFF),
            "coin has already left the registration stage"
        );
        coin.verify_live_status(status)?;
        ensure!(
            status.signature_count == 0,
            "coin already has signed recoveries"
        );
        let capability = coin
            .current_capability
            .context("coin has already been transferred")?;
        let handoff = coin
            .current_handoff
            .context("coin has no current handoff")?;
        let prepared_funding = build_source_funding(
            &coin.keys,
            network,
            source_secret,
            source,
            amount_sat,
            fee_rate_sat_vb,
            max_fee_sat,
        )?;
        let metadata = coin
            .keys
            .clone()
            .metadata(network, prepared_funding.outpoint, amount_sat);
        let next_capability = rand::random();
        let withdrawal = random_secret_key();
        let (request, prepared_recovery) = prepare_recovery(
            &metadata,
            status,
            coin.client_secret,
            capability,
            handoff,
            capability_hash(&next_capability),
            withdrawal
                .x_only_public_key(&bitcoin::secp256k1::Secp256k1::new())
                .0,
            delay_blocks,
            0,
        )?;
        let coin = self.coin.as_mut().expect("coin checked above");
        coin.metadata = Some(metadata);
        coin.funding = Some(FundingJournal {
            transaction: prepared_funding.transaction,
            delay_blocks,
            fee_rate_sat_vb,
            max_fee_sat,
            fee_sat: prepared_funding.fee_sat,
            stage: FundingStage::Prepared,
        });
        self.pending = Some(PendingOperation::Recovery(PendingRecovery {
            purpose: RecoveryPurpose::Fund {
                next_capability,
                withdrawal_secret: withdrawal.secret_bytes(),
            },
            stage: RecoveryStage::Prepared {
                attempt: Box::new(RecoveryAttempt {
                    expected_signature_count: status.signature_count,
                    delay_blocks,
                    request: request.clone(),
                    prepared: Box::new(prepared_recovery),
                }),
            },
        }));
        Ok(request)
    }

    pub fn pending_sign_request(&self) -> Result<SignRequest> {
        let pending = self
            .pending
            .as_ref()
            .context("wallet has no pending operation")?;
        let PendingOperation::Recovery(recovery) = pending else {
            anyhow::bail!("wallet has a pending registration");
        };
        match &recovery.stage {
            RecoveryStage::Prepared { attempt } | RecoveryStage::Responded { attempt, .. } => {
                Ok(attempt.request.clone())
            }
        }
    }

    /// Journals the exact enclave response before any ownership state is applied.
    pub fn record_sign_response(&mut self, response: SignResponse) -> Result<()> {
        let pending = self
            .pending
            .take()
            .context("wallet has no pending operation")?;
        let PendingOperation::Recovery(PendingRecovery { purpose, stage }) = pending else {
            self.pending = Some(pending);
            anyhow::bail!("wallet has a pending registration");
        };
        match stage {
            RecoveryStage::Prepared { attempt } => {
                self.pending = Some(PendingOperation::Recovery(PendingRecovery {
                    purpose,
                    stage: RecoveryStage::Responded { attempt, response },
                }));
                Ok(())
            }
            RecoveryStage::Responded {
                attempt,
                response: saved,
            } => {
                self.pending = Some(PendingOperation::Recovery(PendingRecovery {
                    purpose,
                    stage: RecoveryStage::Responded {
                        attempt,
                        response: saved,
                    },
                }));
                ensure!(
                    saved == response,
                    "enclave response does not match saved response"
                );
                Ok(())
            }
        }
    }

    pub fn complete_funding_recovery(&mut self, status: &CoinStatus) -> Result<()> {
        let PendingOperation::Recovery(PendingRecovery { purpose, stage }) = self
            .pending
            .as_ref()
            .context("wallet has no pending funding recovery")?
        else {
            anyhow::bail!("wallet has a pending registration");
        };
        let RecoveryPurpose::Fund {
            next_capability,
            withdrawal_secret,
        } = purpose
        else {
            anyhow::bail!("wallet has a pending transfer");
        };
        let RecoveryStage::Responded { attempt, response } = stage else {
            anyhow::bail!("funding recovery has no saved enclave response");
        };
        ensure!(
            attempt.expected_signature_count == 0,
            "initial funding recovery has an invalid signature count"
        );
        let coin = self
            .coin
            .as_ref()
            .context("pending signing coin is missing")?;
        verify_status(&coin.keys, status)?;
        verify_sign_response(
            &attempt.request,
            attempt.expected_signature_count,
            status,
            response,
        )?;
        let recovery = complete_recovery(
            &attempt.request,
            response,
            (*attempt.prepared).clone(),
            coin.client_secret,
        )?;
        ensure!(
            recovery.delay_blocks == attempt.delay_blocks,
            "pending signing delay is inconsistent"
        );
        let next_capability = *next_capability;
        let withdrawal_secret = *withdrawal_secret;
        let next_handoff = response.next_handoff;
        let coin = self
            .coin
            .as_mut()
            .context("pending signing coin is missing")?;
        let funding = coin
            .funding
            .as_mut()
            .context("pending funding journal is missing")?;
        ensure!(
            funding.stage == FundingStage::Prepared,
            "funding recovery was already secured"
        );
        coin.history.push(recovery);
        funding.stage = FundingStage::RecoverySecured;
        coin.current_capability = Some(next_capability);
        coin.current_handoff = Some(next_handoff);
        coin.withdrawal_secret = Some(withdrawal_secret);
        coin.withdrawal_recovery_index = Some(coin.history.len() - 1);
        self.pending = None;
        Ok(())
    }

    pub fn funding_transaction(&self) -> Result<&Transaction> {
        let coin = self.coin.as_ref().context("wallet has no coin")?;
        let metadata = coin.metadata.as_ref().context("coin is not funded")?;
        let funding = coin
            .funding
            .as_ref()
            .context("funding journal is missing")?;
        ensure!(
            matches!(
                funding.stage,
                FundingStage::RecoverySecured | FundingStage::Broadcast
            ),
            "funding cannot be broadcast before its recovery is durable"
        );
        validate_finalized_funding(metadata, &funding.transaction)?;
        let recovery = coin
            .history
            .first()
            .context("secured funding recovery is missing")?;
        ensure!(
            recovery.delay_blocks == funding.delay_blocks,
            "secured funding recovery has the wrong delay"
        );
        verify_recovery(metadata, recovery)?;
        Ok(&funding.transaction)
    }

    pub fn mark_funding_broadcast(&mut self, txid: bitcoin::Txid) -> Result<()> {
        ensure!(
            self.funding_transaction()?.compute_txid() == txid,
            "broadcast funding txid does not match recovery outpoint"
        );
        self.coin
            .as_mut()
            .and_then(|coin| coin.funding.as_mut())
            .expect("funding checked above")
            .stage = FundingStage::Broadcast;
        Ok(())
    }

    pub fn verify_funding(
        &self,
        observed: &Transaction,
        confirmations: u32,
        unspent: bool,
    ) -> Result<u32> {
        let expected = self.funding_transaction()?;
        ensure!(
            expected == observed,
            "chain returned different funding transaction bytes"
        );
        ensure!(unspent, "Tinylayer funding output is spent");
        let coin = self.coin.as_ref().expect("funding checked above");
        let funding = coin.funding.as_ref().expect("funding checked above");
        ensure!(
            funding.stage == FundingStage::Broadcast,
            "funding transaction is not marked broadcast"
        );
        Ok(funding.delay_blocks.saturating_sub(confirmations))
    }

    pub fn begin_transfer_request(
        &mut self,
        network: NetworkId,
        coin_id: [u8; 32],
        outpoint: OutPoint,
        expected_amount_sat: u64,
        minimum_reaction_blocks: u32,
    ) -> Result<TransferRequest> {
        self.validate_version()?;
        ensure!(self.coin.is_none(), "wallet already contains a coin");
        ensure!(self.pending.is_none(), "wallet has a pending operation");
        ensure!(!outpoint.is_null(), "transfer outpoint cannot be null");
        ensure!(
            minimum_reaction_blocks >= DELAY_STEP,
            "minimum reaction margin must be at least {DELAY_STEP} blocks"
        );
        if let Some(incoming) = &self.incoming {
            ensure!(
                incoming.request.coin_id()? == coin_id
                    && incoming.request.outpoint()? == outpoint
                    && incoming.request.network == network
                    && incoming.request.expected_amount_sat == expected_amount_sat
                    && incoming.request.min_reaction_blocks == minimum_reaction_blocks,
                "wallet has another pending transfer request"
            );
            return Ok(incoming.request.clone());
        }
        let capability: [u8; 32] = rand::random();
        let withdrawal = random_secret_key();
        let transport = random_secret_key();
        let request = TransferRequest::new(
            rand::random(),
            coin_id,
            network,
            outpoint,
            expected_amount_sat,
            secret_xonly(&withdrawal),
            capability_hash(&capability),
            PublicKey::from_secret_key(&Secp256k1::new(), &transport),
            minimum_reaction_blocks,
        );
        request.validate()?;
        self.incoming = Some(IncomingTransfer {
            request: request.clone(),
            capability,
            withdrawal_secret: withdrawal.secret_bytes(),
            transport_secret: transport.secret_bytes(),
        });
        Ok(request)
    }

    pub fn incoming_transfer_request(&self) -> Result<&TransferRequest> {
        Ok(&self
            .incoming
            .as_ref()
            .context("wallet has no pending transfer request")?
            .request)
    }

    pub fn validate_outgoing_transfer_request(
        &self,
        network: NetworkId,
        request: &TransferRequest,
    ) -> Result<()> {
        self.validate_version()?;
        request.validate()?;
        let coin = self.coin.as_ref().context("wallet has no coin")?;
        let metadata = coin
            .metadata
            .as_ref()
            .context("coin has no verified funding")?;
        ensure!(
            !coin.history.is_empty(),
            "fund the coin before transferring it"
        );
        ensure!(
            coin.funding
                .as_ref()
                .is_none_or(|funding| funding.stage == FundingStage::Broadcast),
            "funding has not been broadcast"
        );
        ensure!(
            request.coin_id()? == coin.keys.coin_id,
            "transfer request is for another coin"
        );
        ensure!(
            request.network == network,
            "transfer request network mismatch"
        );
        ensure!(metadata.network == network, "coin network mismatch");
        ensure!(
            request.outpoint()? == metadata.outpoint,
            "transfer request outpoint mismatch"
        );
        ensure!(
            request.expected_amount_sat == metadata.amount_sat,
            "transfer request amount mismatch"
        );
        Ok(())
    }

    #[allow(clippy::too_many_arguments)]
    pub fn begin_transfer(
        &mut self,
        network: NetworkId,
        request: &TransferRequest,
        status: &CoinStatus,
        observed_funding: &ObservedFunding,
        minimum_confirmations: u32,
        minimum_reaction_blocks: u32,
    ) -> Result<SignRequest> {
        ensure!(self.pending.is_none(), "wallet has a pending operation");
        self.validate_outgoing_transfer_request(network, request)?;
        let coin = self.coin.as_ref().context("wallet has no coin")?;
        ensure!(coin.outgoing.is_none(), "coin has already been transferred");
        let metadata = coin
            .metadata
            .as_ref()
            .context("coin has no verified funding")?;
        verify_observed_funding(metadata, observed_funding, minimum_confirmations)?;
        let capability = coin
            .current_capability
            .context("coin has already been transferred")?;
        let handoff = coin
            .current_handoff
            .context("wallet has no current handoff token")?;
        let withdrawal_secret = SecretKey::from_slice(
            &coin
                .withdrawal_secret
                .context("wallet has no current withdrawal key")?,
        )
        .context("saved withdrawal key is invalid")?;
        verify_history(
            metadata,
            status,
            coin.client_secret,
            capability,
            handoff,
            secret_xonly(&withdrawal_secret),
            observed_funding.confirmations,
            &coin.history,
        )?;
        let delay_blocks = coin
            .history
            .last()
            .expect("history checked non-empty")
            .delay_blocks
            .checked_sub(DELAY_STEP)
            .context("recovery delay cannot be decremented")?;
        require_reaction_margin(
            observed_funding.confirmations,
            delay_blocks,
            minimum_reaction_blocks.max(request.min_reaction_blocks),
        )?;
        let (sign_request, prepared) = prepare_recovery(
            metadata,
            status,
            coin.client_secret,
            capability,
            handoff,
            request.next_capability_hash()?,
            request.withdrawal_key()?,
            delay_blocks,
            observed_funding.confirmations,
        )?;
        let mut projected_history = coin.history.clone();
        projected_history.push(prepared.recovery_serialization_template()?);
        validate_transfer_payload_size(&TransferPayload {
            format_version: FILE_FORMAT_VERSION,
            protocol_version: tinylayer_client::PROTOCOL_VERSION,
            request_id: [u8::MAX; 32],
            client_secret: coin.client_secret,
            current_handoff: [u8::MAX; 32],
            metadata: metadata.clone(),
            history: projected_history,
        })?;
        self.pending = Some(PendingOperation::Recovery(PendingRecovery {
            purpose: RecoveryPurpose::Transfer {
                request: request.clone(),
            },
            stage: RecoveryStage::Prepared {
                attempt: Box::new(RecoveryAttempt {
                    expected_signature_count: status.signature_count,
                    delay_blocks,
                    request: sign_request.clone(),
                    prepared: Box::new(prepared),
                }),
            },
        }));
        Ok(sign_request)
    }

    #[allow(clippy::too_many_arguments)]
    pub fn validate_pending_transfer(
        &self,
        status: &CoinStatus,
        observed_funding: &ObservedFunding,
        minimum_confirmations: u32,
        minimum_reaction_blocks: u32,
    ) -> Result<()> {
        let PendingOperation::Recovery(PendingRecovery { purpose, stage }) = self
            .pending
            .as_ref()
            .context("wallet has no pending transfer")?
        else {
            anyhow::bail!("wallet has a pending registration");
        };
        let RecoveryPurpose::Transfer { request } = purpose else {
            anyhow::bail!("wallet has pending funding");
        };
        let RecoveryStage::Prepared { attempt } = stage else {
            anyhow::bail!("transfer signature response is already saved");
        };
        let coin = self
            .coin
            .as_ref()
            .context("pending transfer coin is missing")?;
        let metadata = coin
            .metadata
            .as_ref()
            .context("pending transfer metadata is missing")?;
        self.validate_outgoing_transfer_request(metadata.network, request)?;
        verify_status(&coin.keys, status)?;
        if attempt_committed(status, attempt)? {
            return Ok(());
        }
        ensure!(
            attempt_uncommitted(status, attempt),
            "pending signing journal does not match live enclave state"
        );
        verify_observed_funding(metadata, observed_funding, minimum_confirmations)?;
        let capability = coin
            .current_capability
            .context("coin has already been transferred")?;
        let handoff = coin
            .current_handoff
            .context("wallet has no current handoff token")?;
        ensure!(
            attempt.request.current_capability == capability
                && attempt.request.current_handoff == handoff,
            "pending transfer does not match local ownership"
        );
        let withdrawal_secret = SecretKey::from_slice(
            &coin
                .withdrawal_secret
                .context("wallet has no current withdrawal key")?,
        )
        .context("saved withdrawal key is invalid")?;
        verify_history(
            metadata,
            status,
            coin.client_secret,
            capability,
            handoff,
            secret_xonly(&withdrawal_secret),
            observed_funding.confirmations,
            &coin.history,
        )?;
        ensure!(
            attempt.expected_signature_count == coin.history.len() as u64,
            "pending transfer signature count is inconsistent"
        );
        let expected_delay = coin
            .history
            .last()
            .expect("history checked non-empty")
            .delay_blocks
            .checked_sub(DELAY_STEP)
            .context("recovery delay cannot be decremented")?;
        ensure!(
            attempt.delay_blocks == expected_delay,
            "pending transfer delay is inconsistent"
        );
        require_reaction_margin(
            observed_funding.confirmations,
            attempt.delay_blocks,
            minimum_reaction_blocks.max(request.min_reaction_blocks),
        )
    }

    pub fn pending_transfer_request(&self) -> Result<&TransferRequest> {
        let PendingOperation::Recovery(pending) = self
            .pending
            .as_ref()
            .context("wallet has no pending transfer")?
        else {
            anyhow::bail!("wallet has a pending registration");
        };
        let RecoveryPurpose::Transfer { request } = &pending.purpose else {
            anyhow::bail!("wallet has pending funding");
        };
        Ok(request)
    }

    pub fn complete_transfer(&mut self, status: &CoinStatus) -> Result<TransferEnvelope> {
        let PendingOperation::Recovery(PendingRecovery { purpose, stage }) = self
            .pending
            .as_ref()
            .context("wallet has no pending transfer")?
        else {
            anyhow::bail!("wallet has a pending registration");
        };
        let RecoveryPurpose::Transfer { request } = purpose else {
            anyhow::bail!("wallet has pending funding");
        };
        let RecoveryStage::Responded { attempt, response } = stage else {
            anyhow::bail!("transfer has no saved enclave response");
        };
        request.validate()?;
        let coin = self
            .coin
            .as_ref()
            .context("pending transfer coin is missing")?;
        let metadata = coin
            .metadata
            .as_ref()
            .context("pending transfer metadata is missing")?;
        ensure!(
            request.coin_id()? == coin.keys.coin_id
                && request.network == metadata.network
                && request.outpoint()? == metadata.outpoint
                && request.expected_amount_sat == metadata.amount_sat,
            "pending transfer request does not match the coin"
        );
        verify_status(&coin.keys, status)?;
        verify_sign_response(
            &attempt.request,
            attempt.expected_signature_count,
            status,
            response,
        )?;
        let recovery = complete_recovery(
            &attempt.request,
            response,
            (*attempt.prepared).clone(),
            coin.client_secret,
        )?;
        ensure!(
            recovery.delay_blocks == attempt.delay_blocks,
            "pending signing delay is inconsistent"
        );
        let mut history = coin.history.clone();
        history.push(recovery);
        let retained_recovery = coin
            .history
            .get(
                coin.withdrawal_recovery_index
                    .context("wallet has no owned recovery")?,
            )
            .context("owned recovery index is invalid")?
            .clone();
        let payload = TransferPayload {
            format_version: FILE_FORMAT_VERSION,
            protocol_version: tinylayer_client::PROTOCOL_VERSION,
            request_id: request.id()?,
            client_secret: coin.client_secret,
            current_handoff: response.next_handoff,
            metadata: metadata.clone(),
            history: history.clone(),
        };
        let envelope = encrypt_transfer(request, &payload)?;

        let coin = self
            .coin
            .as_mut()
            .expect("pending transfer coin checked above");
        coin.history = vec![retained_recovery];
        coin.withdrawal_recovery_index = Some(0);
        coin.current_capability = None;
        coin.current_handoff = None;
        coin.outgoing = Some(OutgoingTransfer {
            request: request.clone(),
            envelope: envelope.clone(),
        });
        self.pending = None;
        Ok(envelope)
    }

    pub fn outgoing_transfer(&self) -> Result<&OutgoingTransfer> {
        self.coin
            .as_ref()
            .and_then(|coin| coin.outgoing.as_ref())
            .context("wallet has no completed outgoing transfer")
    }

    #[allow(clippy::too_many_arguments)]
    pub fn accept_transfer(
        &mut self,
        network: NetworkId,
        request: &TransferRequest,
        envelope: &TransferEnvelope,
        status: &CoinStatus,
        observed_funding: &ObservedFunding,
        minimum_confirmations: u32,
        minimum_reaction_blocks: u32,
    ) -> Result<bool> {
        self.validate_version()?;
        request.validate()?;
        if let Some(coin) = &self.coin {
            ensure!(
                coin.accepted_request.as_ref() == Some(request)
                    && coin.accepted_envelope_fingerprint == Some(envelope.fingerprint()),
                "wallet already contains a different coin or transfer"
            );
            return Ok(false);
        }
        ensure!(self.pending.is_none(), "wallet has a pending operation");
        let incoming = self
            .incoming
            .as_ref()
            .context("wallet has no matching transfer request")?;
        ensure!(
            incoming.request == *request,
            "saved transfer request does not match input"
        );
        let capability = incoming.capability;
        let withdrawal_secret = incoming.withdrawal_secret;
        let transport_secret = incoming.transport_secret;
        let payload = decrypt_transfer(request, transport_secret, envelope)?;
        ensure!(
            payload.metadata.network == network && request.network == network,
            "transfer network mismatch"
        );
        ensure!(
            payload.metadata.keys.coin_id == request.coin_id()?,
            "transfer coin ID mismatch"
        );
        ensure!(
            payload.metadata.outpoint == request.outpoint()?,
            "transfer outpoint mismatch"
        );
        payload.validate_expected_amount(request)?;
        ensure!(
            secret_xonly(&payload.client_secret) == payload.metadata.keys.client_pubkey,
            "transferred client secret does not match coin metadata"
        );
        let latest = payload
            .history
            .last()
            .context("transfer has no recovery history")?;
        ensure!(
            latest.withdrawal_xonly_pubkey == request.withdrawal_key()?,
            "latest recovery does not pay the receiver"
        );
        ensure!(
            request.next_capability_hash()? == capability_hash(&capability),
            "transfer request capability is inconsistent"
        );
        verify_observed_funding(&payload.metadata, observed_funding, minimum_confirmations)?;
        let withdrawal =
            SecretKey::from_slice(&withdrawal_secret).context("saved withdrawal key is invalid")?;
        verify_history(
            &payload.metadata,
            status,
            payload.client_secret,
            capability,
            payload.current_handoff,
            secret_xonly(&withdrawal),
            observed_funding.confirmations,
            &payload.history,
        )?;
        require_reaction_margin(
            observed_funding.confirmations,
            latest.delay_blocks,
            minimum_reaction_blocks.max(request.min_reaction_blocks),
        )?;
        let history_len = payload.history.len();
        self.coin = Some(WalletCoin {
            client_secret: payload.client_secret,
            keys: payload.metadata.keys.clone(),
            metadata: Some(payload.metadata),
            funding: None,
            current_capability: Some(capability),
            current_handoff: Some(payload.current_handoff),
            withdrawal_secret: Some(withdrawal_secret),
            withdrawal_recovery_index: Some(history_len - 1),
            accepted_request: Some(request.clone()),
            accepted_envelope_fingerprint: Some(envelope.fingerprint()),
            history: payload.history,
            outgoing: None,
        });
        self.incoming = None;
        Ok(true)
    }
}

#[derive(Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct WalletCoin {
    pub client_secret: SecretKey,
    pub keys: CoinKeys,
    pub metadata: Option<CoinMetadata>,
    pub funding: Option<FundingJournal>,
    pub current_capability: Option<[u8; 32]>,
    pub current_handoff: Option<HandoffToken>,
    pub withdrawal_secret: Option<[u8; 32]>,
    pub withdrawal_recovery_index: Option<usize>,
    pub accepted_request: Option<TransferRequest>,
    pub accepted_envelope_fingerprint: Option<[u8; 32]>,
    pub history: Vec<SignedRecovery>,
    pub outgoing: Option<OutgoingTransfer>,
}

impl WalletCoin {
    pub fn lifecycle(&self) -> &'static str {
        if self.current_capability.is_none() {
            "transferred"
        } else if let Some(funding) = &self.funding {
            match funding.stage {
                FundingStage::Prepared => "funding_prepared",
                FundingStage::RecoverySecured => "recovery_secured",
                FundingStage::Broadcast => "funding_broadcast",
            }
        } else if self.history.is_empty() {
            "registered"
        } else {
            "owned"
        }
    }

    pub fn verify_live_status(&self, status: &CoinStatus) -> Result<()> {
        verify_status(&self.keys, status)?;
        ensure!(
            status.signature_count == self.history.len() as u64,
            "wallet history does not match enclave"
        );
        if let (Some(capability), Some(handoff)) = (self.current_capability, self.current_handoff) {
            ensure!(
                status.authorization
                    == authorization(&self.keys.coin_id, &capability_hash(&capability), &handoff,),
                "wallet authorization does not match enclave"
            );
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::source_funding_address;
    use bitcoin::{Amount, OutPoint, TxOut, Txid, hashes::Hash as _, secp256k1::Secp256k1};
    use tinylayer_enclave::Signer;

    #[test]
    fn registration_is_journaled_and_resumable() {
        let mut state = WalletState::empty();
        let first = state.begin_registration().unwrap();
        assert_eq!(state.begin_registration().unwrap(), first);
        let signing_key = random_secret_key();
        let status = CoinStatus {
            coin_id: first.coin_id,
            signing_pubkey: signing_key.x_only_public_key(&Secp256k1::new()).0,
            authorization: authorization(
                &first.coin_id,
                &first.initial_capability_hash,
                &INITIAL_HANDOFF,
            ),
            signature_count: 0,
        };
        state.complete_registration(&status).unwrap();
        assert!(state.pending.is_none());
        assert_eq!(state.coin.as_ref().unwrap().keys.coin_id, first.coin_id);
        state
            .coin
            .as_ref()
            .unwrap()
            .verify_live_status(&status)
            .unwrap();
    }

    #[test]
    fn empty_state_keeps_the_exact_v1_schema() {
        assert_eq!(
            serde_json::to_string(&WalletState::empty()).unwrap(),
            r#"{"format_version":1,"coin":null,"incoming":null,"pending":null}"#
        );
    }

    #[test]
    fn funding_cannot_escape_before_the_saved_recovery_is_complete() {
        let mut signer = Signer::<1>::new();
        let mut state = WalletState::empty();
        let registration = state.begin_registration().unwrap();
        let status = signer.register(registration).unwrap();
        state.complete_registration(&status).unwrap();
        let source_secret = random_secret_key();
        let address = source_funding_address(&source_secret, NetworkId::Mutinynet);
        let source = SourceUtxo {
            outpoint: OutPoint::new(Txid::from_byte_array([9; 32]), 0),
            output: TxOut {
                value: Amount::from_sat(150_000),
                script_pubkey: address.script_pubkey(),
            },
            confirmations: 1,
            coinbase: false,
        };
        let request = state
            .begin_funding(
                NetworkId::Mutinynet,
                &source_secret,
                &source,
                &status,
                100_000,
                100,
                1,
                10_000,
                20,
            )
            .unwrap();
        assert!(state.funding_transaction().is_err());
        let response = signer.sign(request).unwrap();
        let committed_status = signer.status(status.coin_id).unwrap();
        let mut wrong_state: WalletState =
            serde_json::from_slice(&serde_json::to_vec(&state).unwrap()).unwrap();
        let mut wrong_response = response;
        wrong_response.next_handoff[0] ^= 1;
        wrong_state.record_sign_response(wrong_response).unwrap();
        assert!(
            wrong_state
                .complete_funding_recovery(&committed_status)
                .is_err()
        );
        state.record_sign_response(response).unwrap();
        assert!(state.funding_transaction().is_err());

        let saved = serde_json::to_vec(&state).unwrap();
        let mut resumed: WalletState = serde_json::from_slice(&saved).unwrap();
        resumed
            .complete_funding_recovery(&committed_status)
            .unwrap();
        let transaction = resumed.funding_transaction().unwrap().clone();
        let txid = transaction.compute_txid();
        resumed.mark_funding_broadcast(txid).unwrap();
        assert_eq!(resumed.verify_funding(&transaction, 1, true).unwrap(), 99);
        resumed
            .coin
            .as_ref()
            .unwrap()
            .verify_live_status(&signer.status(status.coin_id).unwrap())
            .unwrap();
    }

    #[test]
    fn transfer_is_journaled_verified_and_accepted_atomically() {
        let mut signer = Signer::<1>::new();
        let mut sender = WalletState::empty();
        let registration = sender.begin_registration().unwrap();
        let status = signer.register(registration).unwrap();
        sender.complete_registration(&status).unwrap();
        let source_secret = random_secret_key();
        let address = source_funding_address(&source_secret, NetworkId::Mutinynet);
        let source = SourceUtxo {
            outpoint: OutPoint::new(Txid::from_byte_array([7; 32]), 0),
            output: TxOut {
                value: Amount::from_sat(150_000),
                script_pubkey: address.script_pubkey(),
            },
            confirmations: 1,
            coinbase: false,
        };
        let funding_request = sender
            .begin_funding(
                NetworkId::Mutinynet,
                &source_secret,
                &source,
                &status,
                100_000,
                100,
                1,
                10_000,
                20,
            )
            .unwrap();
        sender
            .record_sign_response(signer.sign(funding_request).unwrap())
            .unwrap();
        sender
            .complete_funding_recovery(&signer.status(status.coin_id).unwrap())
            .unwrap();
        let funding = sender.funding_transaction().unwrap().clone();
        sender
            .mark_funding_broadcast(funding.compute_txid())
            .unwrap();
        let metadata = sender
            .coin
            .as_ref()
            .unwrap()
            .metadata
            .as_ref()
            .unwrap()
            .clone();
        let observed = ObservedFunding {
            outpoint: metadata.outpoint,
            output: funding.output[metadata.outpoint.vout as usize].clone(),
            confirmations: 1,
            unspent: true,
            coinbase: false,
        };

        let mut receiver = WalletState::empty();
        let transfer_request = receiver
            .begin_transfer_request(
                NetworkId::Mutinynet,
                metadata.keys.coin_id,
                metadata.outpoint,
                metadata.amount_sat,
                20,
            )
            .unwrap();
        assert_eq!(
            receiver
                .begin_transfer_request(
                    NetworkId::Mutinynet,
                    metadata.keys.coin_id,
                    metadata.outpoint,
                    metadata.amount_sat,
                    20,
                )
                .unwrap(),
            transfer_request
        );

        let status = signer.status(metadata.keys.coin_id).unwrap();
        let sign_request = sender
            .begin_transfer(
                NetworkId::Mutinynet,
                &transfer_request,
                &status,
                &observed,
                1,
                20,
            )
            .unwrap();
        sender
            .validate_pending_transfer(&status, &observed, 1, 20)
            .unwrap();
        let response = signer.sign(sign_request).unwrap();
        let committed_status = signer.status(metadata.keys.coin_id).unwrap();
        sender
            .validate_pending_transfer(&committed_status, &observed, 99, u32::MAX)
            .unwrap();
        assert!(sender.complete_transfer(&committed_status).is_err());
        sender.record_sign_response(response).unwrap();
        let saved = serde_json::to_vec(&sender).unwrap();
        let mut resumed: WalletState = serde_json::from_slice(&saved).unwrap();
        let envelope = resumed.complete_transfer(&committed_status).unwrap();
        assert_eq!(
            resumed.outgoing_transfer().unwrap().envelope.ciphertext,
            envelope.ciphertext
        );
        assert_eq!(resumed.coin.as_ref().unwrap().lifecycle(), "transferred");
        assert_eq!(resumed.coin.as_ref().unwrap().history.len(), 1);
        assert_eq!(
            resumed.coin.as_ref().unwrap().withdrawal_recovery_index,
            Some(0)
        );
        assert!(
            receiver
                .accept_transfer(
                    NetworkId::Mutinynet,
                    &transfer_request,
                    &envelope,
                    &committed_status,
                    &ObservedFunding {
                        unspent: false,
                        ..observed.clone()
                    },
                    1,
                    20,
                )
                .is_err()
        );
        assert!(
            receiver
                .accept_transfer(
                    NetworkId::Mutinynet,
                    &transfer_request,
                    &envelope,
                    &committed_status,
                    &observed,
                    1,
                    20,
                )
                .unwrap()
        );
        let accepted_json = serde_json::to_string(&receiver).unwrap();
        assert!(!accepted_json.contains(&envelope.ciphertext));
        assert_eq!(receiver.coin.as_ref().unwrap().history.len(), 2);
        assert!(
            !receiver
                .accept_transfer(
                    NetworkId::Mutinynet,
                    &transfer_request,
                    &envelope,
                    &committed_status,
                    &observed,
                    1,
                    20,
                )
                .unwrap()
        );
        let mut altered_envelope = envelope.clone();
        let replacement = if altered_envelope.nonce.starts_with("00") {
            "01"
        } else {
            "00"
        };
        altered_envelope.nonce.replace_range(0..2, replacement);
        assert!(
            receiver
                .accept_transfer(
                    NetworkId::Mutinynet,
                    &transfer_request,
                    &altered_envelope,
                    &committed_status,
                    &observed,
                    1,
                    20,
                )
                .is_err()
        );
        receiver
            .coin
            .as_ref()
            .unwrap()
            .verify_live_status(&committed_status)
            .unwrap();
        let receiver_coin = receiver.coin.as_ref().unwrap();
        let known_recovery = receiver_coin
            .history
            .first()
            .unwrap()
            .transaction
            .compute_txid();
        let owned_recovery = receiver_coin
            .history
            .last()
            .unwrap()
            .transaction
            .compute_txid();
        let mut spent_funding = observed.clone();
        spent_funding.unspent = false;
        crate::verify_exit_funding(
            receiver_coin,
            &spent_funding,
            1,
            Some(known_recovery),
            false,
            None,
        )
        .unwrap();
        assert!(
            crate::verify_exit_funding(
                receiver_coin,
                &spent_funding,
                1,
                Some(Txid::from_byte_array([99; 32])),
                false,
                None,
            )
            .is_err()
        );
        assert!(
            crate::verify_exit_funding(
                receiver_coin,
                &spent_funding,
                1,
                Some(known_recovery),
                true,
                None,
            )
            .is_err()
        );
        crate::verify_exit_funding(
            receiver_coin,
            &spent_funding,
            1,
            Some(owned_recovery),
            true,
            Some(owned_recovery),
        )
        .unwrap();
        crate::verify_exit_funding(
            receiver_coin,
            &spent_funding,
            1,
            Some(owned_recovery),
            true,
            None,
        )
        .unwrap();
        let transferred_sender = resumed.coin.as_ref().unwrap();
        assert!(
            crate::verify_exit_funding(
                transferred_sender,
                &spent_funding,
                1,
                Some(owned_recovery),
                false,
                None,
            )
            .is_err()
        );
    }
}

#[derive(Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct FundingJournal {
    pub transaction: Transaction,
    pub delay_blocks: u32,
    pub fee_rate_sat_vb: u64,
    pub max_fee_sat: u64,
    pub fee_sat: u64,
    pub stage: FundingStage,
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum FundingStage {
    Prepared,
    RecoverySecured,
    Broadcast,
}

#[derive(Deserialize, Serialize)]
#[serde(deny_unknown_fields, rename_all = "snake_case", tag = "operation")]
pub enum PendingOperation {
    Registration {
        client_secret: SecretKey,
        initial_capability: [u8; 32],
        registration: Registration,
    },
    Recovery(PendingRecovery),
}

#[derive(Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct PendingRecovery {
    pub purpose: RecoveryPurpose,
    pub stage: RecoveryStage,
}

#[derive(Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct RecoveryAttempt {
    pub expected_signature_count: u64,
    pub delay_blocks: u32,
    pub request: SignRequest,
    pub prepared: Box<PreparedRecovery>,
}

#[derive(Deserialize, Serialize)]
#[serde(deny_unknown_fields, rename_all = "snake_case", tag = "purpose")]
pub enum RecoveryPurpose {
    Fund {
        next_capability: [u8; 32],
        withdrawal_secret: [u8; 32],
    },
    Transfer {
        request: TransferRequest,
    },
}

#[derive(Deserialize, Serialize)]
#[serde(deny_unknown_fields, rename_all = "snake_case", tag = "stage")]
pub enum RecoveryStage {
    Prepared {
        attempt: Box<RecoveryAttempt>,
    },
    Responded {
        attempt: Box<RecoveryAttempt>,
        response: SignResponse,
    },
}

#[derive(Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct IncomingTransfer {
    pub request: TransferRequest,
    pub capability: [u8; 32],
    pub withdrawal_secret: [u8; 32],
    pub transport_secret: [u8; 32],
}

#[derive(Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct OutgoingTransfer {
    pub request: TransferRequest,
    pub envelope: TransferEnvelope,
}

#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct Receipt {
    pub format_version: u32,
    pub protocol_version: u32,
    pub metadata: CoinMetadata,
    pub status: tinylayer_client::CoinStatus,
    pub history: Vec<SignedRecovery>,
}
