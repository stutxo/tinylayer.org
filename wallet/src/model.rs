use std::{path::PathBuf, str::FromStr as _};

use anyhow::{Context as _, Result, ensure};
use bitcoin::{
    Amount, OutPoint, Transaction,
    hashes::Hash as _,
    secp256k1::{PublicKey, Secp256k1, SecretKey, XOnlyPublicKey, ecdh::SharedSecret},
};
use chacha20poly1305::{
    XChaCha20Poly1305, XNonce,
    aead::{Aead as _, KeyInit as _, Payload},
};
use hkdf::Hkdf;
use serde::{Deserialize, Serialize};
use sha2::Sha256;
use tinylayer_client::{
    CoinKeys, CoinMetadata, CoinStatus, HandoffToken, NetworkId, PROTOCOL_VERSION,
    PreparedRecovery, Registration, SignRequest, SignResponse, SignedRecovery,
};
use zeroize::Zeroizing;

pub const FILE_FORMAT_VERSION: u32 = 4;
const TRANSFER_INFO: &[u8] = b"Tinylayer/TransferPackage/v4";

#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct Config {
    pub format_version: u32,
    pub protocol_version: u32,
    pub network: NetworkId,
    pub enclave: EnclaveConfig,
    pub chain: ChainConfig,
    pub min_confirmations: u32,
    pub min_reaction_blocks: u32,
}

impl Config {
    pub fn validate_version(&self) -> Result<()> {
        ensure!(
            self.format_version == FILE_FORMAT_VERSION,
            "unsupported wallet configuration version {}",
            self.format_version
        );
        ensure!(
            self.protocol_version == PROTOCOL_VERSION,
            "unsupported wallet protocol version {}",
            self.protocol_version
        );
        Ok(())
    }
}

#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields, rename_all = "snake_case", tag = "mode")]
pub enum EnclaveConfig {
    Production {
        url: String,
        pcr0: String,
        pcr1: String,
        pcr2: String,
    },
    Debug {
        url: String,
        pcr0: String,
        pcr1: String,
        pcr2: String,
    },
    UnsafePlaintext {
        url: String,
    },
}

impl EnclaveConfig {
    pub fn url(&self) -> &str {
        match self {
            Self::Production { url, .. }
            | Self::Debug { url, .. }
            | Self::UnsafePlaintext { url } => url,
        }
    }

    pub fn mode_name(&self) -> &'static str {
        match self {
            Self::Production { .. } => "production",
            Self::Debug { .. } => "debug",
            Self::UnsafePlaintext { .. } => "unsafe_plaintext",
        }
    }
}

#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields, rename_all = "snake_case", tag = "mode")]
pub enum ChainConfig {
    /// Esplora-compatible explorer API (Mutinynet wallets and local tests).
    Explorer { url: String },
    /// Local Bitcoin Core RPC, restricted to regtest functional tests.
    CoreRpc {
        rpc_url: String,
        cookie_file: PathBuf,
        wallet_name: String,
    },
}

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
        Ok(())
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
#[serde(rename_all = "snake_case", tag = "operation")]
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
#[serde(rename_all = "snake_case", tag = "purpose")]
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
#[serde(rename_all = "snake_case", tag = "stage")]
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

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct TransferRequest {
    pub format_version: u32,
    pub protocol_version: u32,
    pub request_id: String,
    pub coin_id: String,
    pub network: NetworkId,
    pub outpoint: String,
    pub expected_amount_sat: u64,
    pub withdrawal_xonly_pubkey: String,
    pub next_capability_hash: String,
    pub transport_public_key: String,
    pub min_reaction_blocks: u32,
}

impl TransferRequest {
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        request_id: [u8; 32],
        coin_id: [u8; 32],
        network: NetworkId,
        outpoint: OutPoint,
        expected_amount_sat: u64,
        withdrawal_xonly_pubkey: XOnlyPublicKey,
        next_capability_hash: [u8; 32],
        transport_public_key: PublicKey,
        min_reaction_blocks: u32,
    ) -> Self {
        Self {
            format_version: FILE_FORMAT_VERSION,
            protocol_version: PROTOCOL_VERSION,
            request_id: hex::encode(request_id),
            coin_id: hex::encode(coin_id),
            network,
            outpoint: outpoint.to_string(),
            expected_amount_sat,
            withdrawal_xonly_pubkey: withdrawal_xonly_pubkey.to_string(),
            next_capability_hash: hex::encode(next_capability_hash),
            transport_public_key: transport_public_key.to_string(),
            min_reaction_blocks,
        }
    }

    pub fn validate(&self) -> Result<()> {
        ensure!(
            self.format_version == FILE_FORMAT_VERSION,
            "unsupported transfer request version {}",
            self.format_version
        );
        ensure!(
            self.protocol_version == PROTOCOL_VERSION,
            "transfer protocol version mismatch"
        );
        self.id()?;
        self.coin_id()?;
        self.outpoint()?;
        ensure!(
            self.expected_amount_sat <= Amount::MAX_MONEY.to_sat(),
            "transfer request amount exceeds Bitcoin MAX_MONEY"
        );
        self.withdrawal_key()?;
        self.next_capability_hash()?;
        self.transport_key()?;
        Ok(())
    }

    pub fn id(&self) -> Result<[u8; 32]> {
        parse_hex32("request ID", &self.request_id)
    }

    pub fn coin_id(&self) -> Result<[u8; 32]> {
        parse_hex32("coin ID", &self.coin_id)
    }

    pub fn outpoint(&self) -> Result<OutPoint> {
        self.outpoint
            .parse()
            .context("invalid transfer request outpoint")
    }

    pub fn withdrawal_key(&self) -> Result<XOnlyPublicKey> {
        XOnlyPublicKey::from_str(&self.withdrawal_xonly_pubkey)
            .context("invalid transfer request withdrawal key")
    }

    pub fn next_capability_hash(&self) -> Result<[u8; 32]> {
        parse_hex32("next capability hash", &self.next_capability_hash)
    }

    pub fn transport_key(&self) -> Result<PublicKey> {
        PublicKey::from_str(&self.transport_public_key)
            .context("invalid transfer request transport key")
    }

    fn aad(&self) -> Result<Vec<u8>> {
        self.validate()?;
        let outpoint = self.outpoint()?;
        let mut aad = Vec::with_capacity(TRANSFER_INFO.len() + 214);
        aad.extend_from_slice(TRANSFER_INFO);
        aad.extend_from_slice(&self.protocol_version.to_be_bytes());
        aad.extend_from_slice(&self.id()?);
        aad.extend_from_slice(&self.coin_id()?);
        aad.push(self.network as u8);
        aad.extend_from_slice(&outpoint.txid.to_byte_array());
        aad.extend_from_slice(&outpoint.vout.to_be_bytes());
        aad.extend_from_slice(&self.expected_amount_sat.to_be_bytes());
        aad.extend_from_slice(&self.withdrawal_key()?.serialize());
        aad.extend_from_slice(&self.next_capability_hash()?);
        aad.extend_from_slice(&self.transport_key()?.serialize());
        aad.extend_from_slice(&self.min_reaction_blocks.to_be_bytes());
        Ok(aad)
    }
}

#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct TransferEnvelope {
    pub format_version: u32,
    pub request_id: String,
    pub ephemeral_public_key: String,
    pub nonce: String,
    pub ciphertext: String,
}

#[derive(Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct TransferPayload {
    pub format_version: u32,
    pub protocol_version: u32,
    pub request_id: [u8; 32],
    pub client_secret: SecretKey,
    pub current_handoff: HandoffToken,
    pub metadata: CoinMetadata,
    pub history: Vec<SignedRecovery>,
}

impl TransferPayload {
    pub fn validate(&self) -> Result<()> {
        ensure!(
            self.format_version == FILE_FORMAT_VERSION,
            "unsupported transfer payload version {}",
            self.format_version
        );
        ensure!(
            self.protocol_version == PROTOCOL_VERSION,
            "transfer protocol version mismatch"
        );
        Ok(())
    }

    pub fn validate_expected_amount(&self, request: &TransferRequest) -> Result<()> {
        ensure!(
            self.metadata.amount_sat == request.expected_amount_sat,
            "transfer amount mismatch"
        );
        Ok(())
    }
}

#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct Receipt {
    pub format_version: u32,
    pub protocol_version: u32,
    pub metadata: CoinMetadata,
    pub status: CoinStatus,
    pub history: Vec<SignedRecovery>,
}

pub fn random_secret_key() -> SecretKey {
    loop {
        if let Ok(secret) = SecretKey::from_slice(&rand::random::<[u8; 32]>()) {
            return secret;
        }
    }
}

pub fn secret_xonly(secret: &SecretKey) -> XOnlyPublicKey {
    secret.x_only_public_key(&Secp256k1::new()).0
}

pub fn encrypt_transfer(
    request: &TransferRequest,
    payload: &TransferPayload,
) -> Result<TransferEnvelope> {
    request.validate()?;
    payload.validate()?;
    ensure!(
        payload.request_id == request.id()?,
        "transfer request mismatch"
    );
    let ephemeral = random_secret_key();
    let ephemeral_public_key = PublicKey::from_secret_key(&Secp256k1::new(), &ephemeral);
    let shared = SharedSecret::new(&request.transport_key()?, &ephemeral);
    let key = transfer_key(&shared, payload.request_id)?;
    let cipher = XChaCha20Poly1305::new_from_slice(key.as_ref())
        .map_err(|_| anyhow::anyhow!("invalid transfer encryption key"))?;
    let nonce: [u8; 24] = rand::random();
    let plaintext = Zeroizing::new(serde_json::to_vec(payload)?);
    let aad = request.aad()?;
    let ciphertext = cipher
        .encrypt(
            XNonce::from_slice(&nonce),
            Payload {
                msg: plaintext.as_slice(),
                aad: &aad,
            },
        )
        .map_err(|_| anyhow::anyhow!("failed to encrypt transfer package"))?;
    Ok(TransferEnvelope {
        format_version: FILE_FORMAT_VERSION,
        request_id: request.request_id.clone(),
        ephemeral_public_key: ephemeral_public_key.to_string(),
        nonce: hex::encode(nonce),
        ciphertext: hex::encode(ciphertext),
    })
}

pub fn decrypt_transfer(
    request: &TransferRequest,
    transport_secret: [u8; 32],
    envelope: &TransferEnvelope,
) -> Result<TransferPayload> {
    request.validate()?;
    ensure!(
        envelope.format_version == FILE_FORMAT_VERSION,
        "unsupported transfer package version {}",
        envelope.format_version
    );
    ensure!(
        envelope.request_id == request.request_id,
        "transfer request mismatch"
    );
    let ephemeral = PublicKey::from_str(&envelope.ephemeral_public_key)
        .context("invalid transfer package ephemeral key")?;
    let transport_secret =
        SecretKey::from_slice(&transport_secret).context("invalid saved transport key")?;
    let shared = SharedSecret::new(&ephemeral, &transport_secret);
    let request_id = request.id()?;
    let key = transfer_key(&shared, request_id)?;
    let cipher = XChaCha20Poly1305::new_from_slice(key.as_ref())
        .map_err(|_| anyhow::anyhow!("invalid transfer decryption key"))?;
    let nonce = hex::decode(&envelope.nonce).context("invalid transfer package nonce")?;
    ensure!(nonce.len() == 24, "invalid transfer package nonce length");
    let ciphertext =
        hex::decode(&envelope.ciphertext).context("invalid transfer package ciphertext")?;
    let aad = request.aad()?;
    let plaintext = Zeroizing::new(
        cipher
            .decrypt(
                XNonce::from_slice(&nonce),
                Payload {
                    msg: &ciphertext,
                    aad: &aad,
                },
            )
            .map_err(|_| anyhow::anyhow!("transfer package authentication failed"))?,
    );
    let payload: TransferPayload =
        serde_json::from_slice(plaintext.as_slice()).context("invalid transfer package payload")?;
    payload.validate()?;
    ensure!(
        payload.request_id == request_id,
        "transfer request mismatch"
    );
    Ok(payload)
}

pub fn parse_hex32(label: &str, value: &str) -> Result<[u8; 32]> {
    let bytes = hex::decode(value).with_context(|| format!("invalid {label} hex"))?;
    let length = bytes.len();
    bytes
        .try_into()
        .map_err(|_| anyhow::anyhow!("invalid {label} length: expected 32 bytes, got {length}"))
}

fn transfer_key(shared: &SharedSecret, request_id: [u8; 32]) -> Result<Zeroizing<[u8; 32]>> {
    let hkdf = Hkdf::<Sha256>::new(Some(&request_id), shared.as_ref());
    let mut key = Zeroizing::new([0; 32]);
    hkdf.expand(TRANSFER_INFO, key.as_mut())
        .map_err(|_| anyhow::anyhow!("failed to derive transfer encryption key"))?;
    Ok(key)
}

#[cfg(test)]
mod tests {
    use super::*;
    use bitcoin::Txid;

    #[test]
    fn transfer_package_is_encrypted_and_bound_to_request() {
        assert_eq!(FILE_FORMAT_VERSION, 4);
        assert_eq!(tinylayer_client::PROTOCOL_VERSION, 1);
        assert_eq!(TRANSFER_INFO, b"Tinylayer/TransferPackage/v4");
        let transport = random_secret_key();
        let transport_public = PublicKey::from_secret_key(&Secp256k1::new(), &transport);
        let request = TransferRequest::new(
            [1; 32],
            [2; 32],
            NetworkId::Regtest,
            OutPoint::new(Txid::from_byte_array([3; 32]), 4),
            100_000,
            secret_xonly(&random_secret_key()),
            [5; 32],
            transport_public,
            20,
        );
        let aad = request.aad().unwrap();
        assert_eq!(
            &aad[TRANSFER_INFO.len()..TRANSFER_INFO.len() + 4],
            &tinylayer_client::PROTOCOL_VERSION.to_be_bytes()
        );
        let mut payload = TransferPayload {
            format_version: FILE_FORMAT_VERSION,
            protocol_version: tinylayer_client::PROTOCOL_VERSION,
            request_id: [1; 32],
            client_secret: secret(1),
            current_handoff: [8; 32],
            metadata: test_metadata(),
            history: Vec::new(),
        };
        let mut envelope = encrypt_transfer(&request, &payload).unwrap();
        let decoded = decrypt_transfer(&request, transport.secret_bytes(), &envelope).unwrap();
        assert_eq!(decoded.protocol_version, 1);
        assert_eq!(decoded.client_secret, payload.client_secret);
        assert_eq!(decoded.current_handoff, payload.current_handoff);
        decoded.validate_expected_amount(&request).unwrap();
        let envelope_json = serde_json::to_string(&envelope).unwrap();
        assert!(!envelope_json.contains("current_handoff"));
        assert!(!envelope_json.contains(&hex::encode(payload.current_handoff)));
        let ciphertext = hex::decode(&envelope.ciphertext).unwrap();
        assert!(
            !ciphertext
                .windows(payload.current_handoff.len())
                .any(|window| window == payload.current_handoff)
        );
        assert!(
            !envelope
                .ciphertext
                .contains(&hex::encode(payload.client_secret.secret_bytes()))
        );

        let mut wrong_amount = request.clone();
        wrong_amount.expected_amount_sat += 1;
        assert!(decrypt_transfer(&wrong_amount, transport.secret_bytes(), &envelope).is_err());

        let mut missing_amount = serde_json::to_value(&request).unwrap();
        missing_amount
            .as_object_mut()
            .unwrap()
            .remove("expected_amount_sat");
        assert!(serde_json::from_value::<TransferRequest>(missing_amount).is_err());

        let mut missing_protocol = serde_json::to_value(&request).unwrap();
        missing_protocol
            .as_object_mut()
            .unwrap()
            .remove("protocol_version");
        assert!(serde_json::from_value::<TransferRequest>(missing_protocol).is_err());

        let mut wrong_protocol = request.clone();
        wrong_protocol.protocol_version = 2;
        assert_eq!(
            wrong_protocol.validate().unwrap_err().to_string(),
            "transfer protocol version mismatch"
        );

        payload.protocol_version = 2;
        assert_eq!(
            encrypt_transfer(&request, &payload)
                .unwrap_err()
                .to_string(),
            "transfer protocol version mismatch"
        );
        let incompatible_envelope = encrypt_unchecked(&request, &payload);
        let error = decrypt_transfer(&request, transport.secret_bytes(), &incompatible_envelope)
            .err()
            .expect("unsupported payload must fail");
        assert_eq!(error.to_string(), "transfer protocol version mismatch");

        envelope.ciphertext.replace_range(0..2, "00");
        assert!(decrypt_transfer(&request, transport.secret_bytes(), &envelope).is_err());
    }

    #[test]
    fn receiver_rejects_authenticated_payload_with_wrong_amount() {
        let transport = random_secret_key();
        let request = TransferRequest::new(
            [1; 32],
            [2; 32],
            NetworkId::Regtest,
            OutPoint::new(Txid::from_byte_array([3; 32]), 4),
            100_000,
            secret_xonly(&random_secret_key()),
            [5; 32],
            PublicKey::from_secret_key(&Secp256k1::new(), &transport),
            20,
        );
        let mut metadata = test_metadata();
        metadata.amount_sat += 1;
        let payload = TransferPayload {
            format_version: FILE_FORMAT_VERSION,
            protocol_version: tinylayer_client::PROTOCOL_VERSION,
            request_id: [1; 32],
            client_secret: secret(1),
            current_handoff: [8; 32],
            metadata,
            history: Vec::new(),
        };
        let envelope = encrypt_transfer(&request, &payload).unwrap();
        let received = decrypt_transfer(&request, transport.secret_bytes(), &envelope).unwrap();
        assert_eq!(
            received
                .validate_expected_amount(&request)
                .unwrap_err()
                .to_string(),
            "transfer amount mismatch"
        );
    }

    fn encrypt_unchecked(request: &TransferRequest, payload: &TransferPayload) -> TransferEnvelope {
        let ephemeral = random_secret_key();
        let ephemeral_public_key = PublicKey::from_secret_key(&Secp256k1::new(), &ephemeral);
        let shared = SharedSecret::new(&request.transport_key().unwrap(), &ephemeral);
        let key = transfer_key(&shared, payload.request_id).unwrap();
        let cipher = XChaCha20Poly1305::new_from_slice(key.as_ref()).unwrap();
        let nonce = [9; 24];
        let plaintext = serde_json::to_vec(payload).unwrap();
        let aad = request.aad().unwrap();
        let ciphertext = cipher
            .encrypt(
                XNonce::from_slice(&nonce),
                Payload {
                    msg: &plaintext,
                    aad: &aad,
                },
            )
            .unwrap();
        TransferEnvelope {
            format_version: FILE_FORMAT_VERSION,
            request_id: request.request_id.clone(),
            ephemeral_public_key: ephemeral_public_key.to_string(),
            nonce: hex::encode(nonce),
            ciphertext: hex::encode(ciphertext),
        }
    }

    fn test_metadata() -> CoinMetadata {
        CoinMetadata {
            keys: CoinKeys {
                protocol_version: tinylayer_client::PROTOCOL_VERSION,
                coin_id: [2; 32],
                client_pubkey: secret_xonly(&secret(1)),
                enclave_pubkey: secret_xonly(&secret(2)),
            },
            network: NetworkId::Regtest,
            outpoint: OutPoint::new(Txid::from_byte_array([3; 32]), 4),
            amount_sat: 100_000,
        }
    }

    fn secret(byte: u8) -> SecretKey {
        SecretKey::from_slice(&[byte; 32]).unwrap()
    }
}
