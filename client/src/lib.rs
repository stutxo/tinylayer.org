//! Untrusted Bitcoin client for the Tinylayer v1 enclave signer.

#![forbid(unsafe_code)]

use std::fmt;

use bitcoin::{
    Address, Amount, OutPoint, ScriptBuf, Sequence, Transaction, TxIn, TxOut, Witness, absolute,
    address::KnownHrp,
    hashes::Hash as _,
    opcodes::all::{OP_CHECKSIG, OP_CHECKSIGVERIFY},
    script::Builder,
    secp256k1::{Keypair, Message, Secp256k1, SecretKey, XOnlyPublicKey, schnorr::Signature},
    sighash::Prevouts,
    taproot::{ControlBlock, LeafVersion, TapLeafHash, TaprootBuilder, TaprootSpendInfo},
    transaction::Version,
};
use enclavia::{Client as EnclaviaSdkClient, Pcrs};
use serde::{Deserialize, Serialize};
use thiserror::Error;

pub use tinylayer_enclave::{
    Capability, CoinId, CoinStatus, HandoffToken, INITIAL_HANDOFF, PROTOCOL_VERSION,
    RegisterRequest, SignRequest, SignResponse, authorization, capability_hash,
};
use tinylayer_enclave::{Request, Response};

pub const LOCKTIME_STEP: u32 = 10;
const RECOVERY_SEQUENCE: Sequence = Sequence::ENABLE_RBF_NO_LOCKTIME;
/// BIP431 TRUC (v3): recovery parents carry zero fee and are fee-bumped at
/// broadcast time by a child paying for the whole package.
pub const TRUC_VERSION: Version = Version(3);
/// BIP341's x-only NUMS internal key. No discrete logarithm is known for this point.
pub const NUMS_INTERNAL_KEY_BYTES: [u8; 32] = [
    0x50, 0x92, 0x9b, 0x74, 0xc1, 0xa0, 0x49, 0x54, 0xb7, 0x8b, 0x4b, 0x60, 0x35, 0xe9, 0x7a, 0x5e,
    0x07, 0x8a, 0x5a, 0x0f, 0x28, 0xec, 0x96, 0xd5, 0x47, 0xbf, 0xee, 0x9a, 0xce, 0x80, 0x3a, 0xc0,
];

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
#[repr(u8)]
pub enum NetworkId {
    Mutinynet = 1,
    Mainnet = 2,
    Regtest = 3,
}

impl NetworkId {
    pub fn bitcoin_network(self) -> bitcoin::Network {
        match self {
            Self::Mutinynet => bitcoin::Network::Signet,
            Self::Mainnet => bitcoin::Network::Bitcoin,
            Self::Regtest => bitcoin::Network::Regtest,
        }
    }

    fn address_hrp(self) -> KnownHrp {
        match self {
            Self::Mutinynet => KnownHrp::Testnets,
            Self::Mainnet => KnownHrp::Mainnet,
            Self::Regtest => KnownHrp::Regtest,
        }
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct Registration {
    pub protocol_version: u32,
    pub request: RegisterRequest,
    pub client_pubkey: XOnlyPublicKey,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(try_from = "CoinKeysWire")]
pub struct CoinKeys {
    pub protocol_version: u32,
    pub coin_id: CoinId,
    pub client_pubkey: XOnlyPublicKey,
    pub enclave_pubkey: XOnlyPublicKey,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct CoinKeysWire {
    protocol_version: u32,
    coin_id: CoinId,
    client_pubkey: XOnlyPublicKey,
    enclave_pubkey: XOnlyPublicKey,
}

impl TryFrom<CoinKeysWire> for CoinKeys {
    type Error = Error;

    fn try_from(value: CoinKeysWire) -> Result<Self, Self::Error> {
        let keys = Self {
            protocol_version: value.protocol_version,
            coin_id: value.coin_id,
            client_pubkey: value.client_pubkey,
            enclave_pubkey: value.enclave_pubkey,
        };
        keys.validate()?;
        Ok(keys)
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct CoinMetadata {
    pub keys: CoinKeys,
    pub network: NetworkId,
    pub outpoint: OutPoint,
    pub amount_sat: u64,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct SignedRecovery {
    pub transaction: Transaction,
    pub withdrawal_xonly_pubkey: XOnlyPublicKey,
    pub locktime: u32,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct PreparedRecovery {
    request: SignRequest,
    metadata: CoinMetadata,
    transaction: Transaction,
    withdrawal_xonly_pubkey: XOnlyPublicKey,
    locktime: u32,
}

#[derive(Clone, Debug, Eq, Error, PartialEq)]
pub enum Error {
    #[error("client state protocol version does not match")]
    ProtocolVersionMismatch,
    #[error("enclave response does not match the request")]
    ResponseMismatch,
    #[error("coin metadata is inconsistent")]
    MetadataMismatch,
    #[error("client secret key does not match coin metadata")]
    WrongClientKey,
    #[error("client and enclave signing keys must be distinct")]
    EqualSigningKeys,
    #[error("enclave Schnorr signature is invalid")]
    InvalidEnclaveSignature,
    #[error("client Schnorr signature is invalid")]
    InvalidClientSignature,
    #[error("funding UTXO does not match coin metadata")]
    FundingMismatch,
    #[error("recovery locktime does not leave a safe future reaction window")]
    UnsafeLocktime,
    #[error("recovery transaction is not canonical")]
    TransactionMismatch,
    #[error("signed recovery has a non-canonical witness")]
    InvalidWitness,
    #[error("recovery history does not match the enclave signature count or authorization")]
    HistoryMismatch,
    #[error("funding outpoint cannot be null")]
    InvalidOutpoint,
    #[error("funding amount exceeds Bitcoin MAX_MONEY")]
    AmountTooLarge,
    #[error("recovery output would be dust")]
    DustOutput,
    #[error("locktime is not a valid absolute block height")]
    InvalidLocktime,
    #[error("failed to compute Taproot sighash")]
    Sighash,
    #[error("withdrawal key does not match the recovery output")]
    WithdrawalKeyMismatch,
}

#[derive(Debug)]
pub enum RemoteError {
    Enclavia(Box<enclavia::Error>),
    Protocol { status: u16, message: String },
    Json(serde_json::Error),
}

impl fmt::Display for RemoteError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Enclavia(error) => write!(f, "Enclavia connection failed: {error}"),
            Self::Protocol { status, message } => {
                write!(f, "enclave returned HTTP {status}: {message}")
            }
            Self::Json(error) => write!(f, "invalid enclave response: {error}"),
        }
    }
}

impl std::error::Error for RemoteError {}

impl From<enclavia::Error> for RemoteError {
    fn from(error: enclavia::Error) -> Self {
        Self::Enclavia(Box::new(error))
    }
}

impl From<serde_json::Error> for RemoteError {
    fn from(error: serde_json::Error) -> Self {
        Self::Json(error)
    }
}

#[derive(Clone)]
pub struct RemoteEnclave {
    client: EnclaviaSdkClient,
}

impl RemoteEnclave {
    pub async fn connect(url: &str, pcrs: Pcrs) -> Result<Self, RemoteError> {
        Ok(Self {
            client: EnclaviaSdkClient::connect(url, pcrs).await?,
        })
    }

    pub async fn connect_debug(url: &str, pcrs: Pcrs) -> Result<Self, RemoteError> {
        Ok(Self {
            client: EnclaviaSdkClient::builder(url)
                .pcrs(pcrs)
                .debug_mode(true)
                .build()
                .await?,
        })
    }

    pub async fn health(&self) -> Result<(), RemoteError> {
        let response = self.client.get("/health").send().await?;
        ensure_success(response.status(), response.bytes())
    }

    pub async fn register(&self, request: &RegisterRequest) -> Result<CoinStatus, RemoteError> {
        match self.call(Request::Register(request.clone())).await? {
            Response::Status(status) => Ok(status),
            _ => Err(unexpected_response()),
        }
    }

    pub async fn status(&self, coin_id: CoinId) -> Result<CoinStatus, RemoteError> {
        match self.call(Request::Status { coin_id }).await? {
            Response::Status(status) => Ok(status),
            _ => Err(unexpected_response()),
        }
    }

    pub async fn sign(&self, request: &SignRequest) -> Result<SignResponse, RemoteError> {
        match self.call(Request::Sign(request.clone())).await? {
            Response::Signature(response) => Ok(response),
            _ => Err(unexpected_response()),
        }
    }

    async fn call(&self, request: Request) -> Result<Response, RemoteError> {
        let response = self.client.post("/v1").json(&request)?.send().await?;
        ensure_success(response.status(), response.bytes())?;
        Ok(serde_json::from_slice(response.bytes())?)
    }
}

pub fn prepare_registration(
    client_secret: SecretKey,
    initial_capability_hash: [u8; 32],
) -> Registration {
    let coin_id = rand::random();
    let client_pubkey = client_secret.x_only_public_key(&Secp256k1::new()).0;
    Registration {
        protocol_version: PROTOCOL_VERSION,
        request: RegisterRequest {
            coin_id,
            initial_capability_hash,
        },
        client_pubkey,
    }
}

pub fn complete_registration(
    registration: Registration,
    status: &CoinStatus,
) -> Result<CoinKeys, Error> {
    if registration.protocol_version != PROTOCOL_VERSION {
        return Err(Error::ProtocolVersionMismatch);
    }
    let request = &registration.request;
    if status.coin_id != request.coin_id
        || status.signature_count != 0
        || status.authorization
            != authorization(
                &request.coin_id,
                &request.initial_capability_hash,
                &INITIAL_HANDOFF,
            )
    {
        return Err(Error::ResponseMismatch);
    }
    if registration.client_pubkey == status.signing_pubkey {
        return Err(Error::EqualSigningKeys);
    }
    Ok(CoinKeys {
        protocol_version: PROTOCOL_VERSION,
        coin_id: request.coin_id,
        client_pubkey: registration.client_pubkey,
        enclave_pubkey: status.signing_pubkey,
    })
}

impl CoinKeys {
    pub fn metadata(self, network: NetworkId, outpoint: OutPoint, amount_sat: u64) -> CoinMetadata {
        CoinMetadata {
            keys: self,
            network,
            outpoint,
            amount_sat,
        }
    }

    pub fn validate(&self) -> Result<(), Error> {
        if self.protocol_version != PROTOCOL_VERSION {
            return Err(Error::ProtocolVersionMismatch);
        }
        if self.client_pubkey == self.enclave_pubkey {
            return Err(Error::MetadataMismatch);
        }
        Ok(())
    }
}

impl CoinMetadata {
    pub fn validate(&self) -> Result<(), Error> {
        self.keys.validate()
    }
}

pub fn verify_status(keys: &CoinKeys, status: &CoinStatus) -> Result<(), Error> {
    keys.validate()?;
    if status.coin_id != keys.coin_id || status.signing_pubkey != keys.enclave_pubkey {
        return Err(Error::ResponseMismatch);
    }
    Ok(())
}

pub fn verify_sign_response(
    request: &SignRequest,
    previous_signature_count: u64,
    status: &CoinStatus,
    response: &SignResponse,
) -> Result<(), Error> {
    let expected_signature_count = previous_signature_count
        .checked_add(1)
        .ok_or(Error::ResponseMismatch)?;
    if status.coin_id != request.coin_id
        || status.signature_count != expected_signature_count
        || status.authorization
            != authorization(
                &request.coin_id,
                &request.next_capability_hash,
                &response.next_handoff,
            )
    {
        return Err(Error::ResponseMismatch);
    }
    verify_signature(
        &response.signature,
        request.sighash,
        status.signing_pubkey,
        Error::InvalidEnclaveSignature,
    )
}

#[allow(clippy::too_many_arguments)]
pub fn prepare_recovery(
    metadata: &CoinMetadata,
    status: &CoinStatus,
    client_secret: SecretKey,
    current_capability: Capability,
    current_handoff: HandoffToken,
    next_capability_hash: [u8; 32],
    withdrawal_xonly_pubkey: XOnlyPublicKey,
    locktime: u32,
    tip_height: u32,
) -> Result<(SignRequest, PreparedRecovery), Error> {
    metadata.validate()?;
    verify_status(&metadata.keys, status)?;
    let current_capability_hash = capability_hash(&current_capability);
    if status.authorization
        != authorization(
            &metadata.keys.coin_id,
            &current_capability_hash,
            &current_handoff,
        )
    {
        return Err(Error::ResponseMismatch);
    }
    if next_capability_hash == current_capability_hash {
        return Err(Error::ResponseMismatch);
    }
    require_future_locktime(tip_height, locktime)?;
    if client_xonly(client_secret) != metadata.keys.client_pubkey {
        return Err(Error::WrongClientKey);
    }
    let transaction = canonical_recovery(
        metadata.outpoint,
        metadata.amount_sat,
        withdrawal_xonly_pubkey,
        locktime,
    )?;
    let sighash = recovery_sighash(&transaction, metadata.amount_sat, &metadata.keys)?;
    let request = SignRequest {
        coin_id: metadata.keys.coin_id,
        current_capability,
        current_handoff,
        next_capability_hash,
        sighash,
    };
    Ok((
        request.clone(),
        PreparedRecovery {
            request,
            metadata: metadata.clone(),
            transaction,
            withdrawal_xonly_pubkey,
            locktime,
        },
    ))
}

pub fn complete_recovery(
    request: &SignRequest,
    enclave_response: &SignResponse,
    mut prepared: PreparedRecovery,
    client_secret: SecretKey,
) -> Result<SignedRecovery, Error> {
    if &prepared.request != request {
        return Err(Error::ResponseMismatch);
    }
    prepared.metadata.validate()?;
    if request.coin_id != prepared.metadata.keys.coin_id {
        return Err(Error::ResponseMismatch);
    }
    if client_xonly(client_secret) != prepared.metadata.keys.client_pubkey {
        return Err(Error::WrongClientKey);
    }
    let expected = canonical_recovery(
        prepared.metadata.outpoint,
        prepared.metadata.amount_sat,
        prepared.withdrawal_xonly_pubkey,
        prepared.locktime,
    )?;
    if prepared.transaction != expected {
        return Err(Error::TransactionMismatch);
    }
    let sighash = recovery_sighash(
        &prepared.transaction,
        prepared.metadata.amount_sat,
        &prepared.metadata.keys,
    )?;
    if request.sighash != sighash {
        return Err(Error::TransactionMismatch);
    }
    verify_signature(
        &enclave_response.signature,
        sighash,
        prepared.metadata.keys.enclave_pubkey,
        Error::InvalidEnclaveSignature,
    )?;

    let secp = Secp256k1::new();
    let keypair = Keypair::from_secret_key(&secp, &client_secret);
    let client_signature = secp.sign_schnorr_no_aux_rand(&Message::from_digest(sighash), &keypair);
    let leaf = funding_tapscript(&prepared.metadata.keys);
    let control = funding_control_block(&prepared.metadata.keys);
    let input = prepared
        .transaction
        .input
        .first_mut()
        .ok_or(Error::TransactionMismatch)?;
    input.witness.push(enclave_response.signature.as_ref());
    input.witness.push(client_signature.as_ref());
    input.witness.push(leaf.as_bytes());
    input.witness.push(control.serialize());

    verify_signed_recovery(
        &prepared.transaction,
        prepared.metadata.amount_sat,
        &prepared.metadata.keys,
    )?;
    Ok(SignedRecovery {
        transaction: prepared.transaction,
        withdrawal_xonly_pubkey: prepared.withdrawal_xonly_pubkey,
        locktime: prepared.locktime,
    })
}

#[allow(clippy::too_many_arguments)]
pub fn verify_history(
    metadata: &CoinMetadata,
    status: &CoinStatus,
    client_secret: SecretKey,
    current_capability: Capability,
    current_handoff: HandoffToken,
    expected_latest_withdrawal: XOnlyPublicKey,
    tip_height: u32,
    history: &[SignedRecovery],
) -> Result<(), Error> {
    verify_status(&metadata.keys, status)?;
    if client_xonly(client_secret) != metadata.keys.client_pubkey {
        return Err(Error::WrongClientKey);
    }
    let current_capability_hash = capability_hash(&current_capability);
    if status.authorization
        != authorization(
            &metadata.keys.coin_id,
            &current_capability_hash,
            &current_handoff,
        )
        || status.signature_count != history.len() as u64
        || history
            .last()
            .map(|recovery| recovery.withdrawal_xonly_pubkey)
            != Some(expected_latest_withdrawal)
    {
        return Err(Error::HistoryMismatch);
    }
    for recovery in history {
        verify_recovery(metadata, recovery)?;
    }
    for pair in history.windows(2) {
        validate_reaction_window(tip_height, pair[0].locktime, pair[1].locktime)?;
    }
    if history
        .last()
        .is_none_or(|latest| latest.locktime <= tip_height)
    {
        return Err(Error::UnsafeLocktime);
    }
    Ok(())
}

pub fn verify_recovery(metadata: &CoinMetadata, recovery: &SignedRecovery) -> Result<(), Error> {
    metadata.validate()?;
    let expected = canonical_recovery(
        metadata.outpoint,
        metadata.amount_sat,
        recovery.withdrawal_xonly_pubkey,
        recovery.locktime,
    )?;
    let mut unsigned = recovery.transaction.clone();
    if unsigned.input.len() != 1 {
        return Err(Error::TransactionMismatch);
    }
    unsigned.input[0].witness = Witness::new();
    if unsigned != expected {
        return Err(Error::TransactionMismatch);
    }
    verify_signed_recovery(&recovery.transaction, metadata.amount_sat, &metadata.keys)
}

pub fn verify_signed_recovery(
    transaction: &Transaction,
    amount_sat: u64,
    keys: &CoinKeys,
) -> Result<(), Error> {
    keys.validate()?;
    if transaction.input.len() != 1 {
        return Err(Error::InvalidWitness);
    }
    let witness = &transaction.input[0].witness;
    if witness.len() != 4 {
        return Err(Error::InvalidWitness);
    }
    let enclave_signature_bytes = &witness[0];
    let client_signature_bytes = &witness[1];
    let script_bytes = &witness[2];
    let control_bytes = &witness[3];
    if enclave_signature_bytes.len() != 64 || client_signature_bytes.len() != 64 {
        return Err(Error::InvalidWitness);
    }

    let leaf = funding_tapscript(keys);
    let expected_control = funding_control_block(keys);
    if script_bytes != leaf.as_bytes() || control_bytes != expected_control.serialize() {
        return Err(Error::InvalidWitness);
    }
    let control = ControlBlock::decode(control_bytes).map_err(|_| Error::InvalidWitness)?;
    let material = funding_material(keys);
    if control != expected_control
        || !control.verify_taproot_commitment(
            &Secp256k1::verification_only(),
            material.spend_info.output_key().to_x_only_public_key(),
            &leaf,
        )
    {
        return Err(Error::InvalidWitness);
    }

    let enclave_signature =
        Signature::from_slice(enclave_signature_bytes).map_err(|_| Error::InvalidWitness)?;
    let client_signature =
        Signature::from_slice(client_signature_bytes).map_err(|_| Error::InvalidWitness)?;
    let sighash = recovery_sighash(transaction, amount_sat, keys)?;
    verify_signature(
        &enclave_signature,
        sighash,
        keys.enclave_pubkey,
        Error::InvalidEnclaveSignature,
    )?;
    verify_signature(
        &client_signature,
        sighash,
        keys.client_pubkey,
        Error::InvalidClientSignature,
    )
}

pub fn verify_funding_utxo(
    metadata: &CoinMetadata,
    outpoint: OutPoint,
    output: &TxOut,
) -> Result<(), Error> {
    metadata.validate()?;
    let expected = TxOut {
        value: Amount::from_sat(metadata.amount_sat),
        script_pubkey: funding_script(&metadata.keys),
    };
    if outpoint != metadata.outpoint || output != &expected {
        return Err(Error::FundingMismatch);
    }
    Ok(())
}

pub fn canonical_recovery(
    outpoint: OutPoint,
    amount_sat: u64,
    withdrawal_key: XOnlyPublicKey,
    locktime: u32,
) -> Result<Transaction, Error> {
    if outpoint.is_null() {
        return Err(Error::InvalidOutpoint);
    }
    if amount_sat > Amount::MAX_MONEY.to_sat() {
        return Err(Error::AmountTooLarge);
    }
    let lock_time =
        absolute::LockTime::from_height(locktime).map_err(|_| Error::InvalidLocktime)?;
    let script_pubkey = ScriptBuf::new_p2tr(&Secp256k1::verification_only(), withdrawal_key, None);
    if Amount::from_sat(amount_sat) < script_pubkey.minimal_non_dust() {
        return Err(Error::DustOutput);
    }
    Ok(Transaction {
        version: TRUC_VERSION,
        lock_time,
        input: vec![TxIn {
            previous_output: outpoint,
            script_sig: ScriptBuf::new(),
            sequence: RECOVERY_SEQUENCE,
            witness: Witness::new(),
        }],
        output: vec![TxOut {
            value: Amount::from_sat(amount_sat),
            script_pubkey,
        }],
    })
}

/// Builds the fee-paying TRUC child that makes a zero-fee recovery parent
/// confirmable. The child spends the entire recovery output to `destination`
/// and pays the fee for the whole package, so the pair must be submitted
/// together (`submitpackage`). The recovery locktime must already be final.
pub fn build_exit_child(
    recovery: &SignedRecovery,
    amount_sat: u64,
    withdrawal_secret: &SecretKey,
    destination: ScriptBuf,
    fee_rate_sat_vb: u64,
) -> Result<Transaction, Error> {
    let parent = &recovery.transaction;
    if parent.input.len() != 1 || parent.output.len() != 1 {
        return Err(Error::TransactionMismatch);
    }
    let secp = Secp256k1::new();
    let internal = withdrawal_secret.x_only_public_key(&secp).0;
    if internal != recovery.withdrawal_xonly_pubkey {
        return Err(Error::WithdrawalKeyMismatch);
    }
    let spent_output = parent.output.first().ok_or(Error::TransactionMismatch)?;
    if spent_output.value != Amount::from_sat(amount_sat)
        || spent_output.script_pubkey != ScriptBuf::new_p2tr(&secp, internal, None)
    {
        return Err(Error::TransactionMismatch);
    }
    let mut child = Transaction {
        version: TRUC_VERSION,
        lock_time: absolute::LockTime::ZERO,
        input: vec![TxIn {
            previous_output: OutPoint::new(parent.compute_txid(), 0),
            script_sig: ScriptBuf::new(),
            sequence: Sequence::MAX,
            witness: Witness::new(),
        }],
        output: vec![TxOut {
            value: Amount::from_sat(amount_sat),
            script_pubkey: destination,
        }],
    };
    // A one-item 64-byte witness has the same size as the final signature, so
    // the fee derived from this placeholder is exact.
    child.input[0].witness.push([0; 64]);
    let package_vsize = (parent.vsize() + child.vsize()) as u128;
    let fee_sat = u128::from(fee_rate_sat_vb) * package_vsize;
    let output_sat = u128::from(amount_sat)
        .checked_sub(fee_sat)
        .and_then(|value| u64::try_from(value).ok())
        .ok_or(Error::DustOutput)?;
    let output_amount = Amount::from_sat(output_sat);
    if output_amount < child.output[0].script_pubkey.minimal_non_dust() {
        return Err(Error::DustOutput);
    }
    child.output[0].value = output_amount;
    let sighash = bitcoin::sighash::SighashCache::new(&child)
        .taproot_key_spend_signature_hash(
            0,
            &Prevouts::All(std::slice::from_ref(spent_output)),
            bitcoin::TapSighashType::Default,
        )
        .map_err(|_| Error::Sighash)?;
    let keypair = Keypair::from_secret_key(&secp, withdrawal_secret);
    let tweaked = bitcoin::key::TapTweak::tap_tweak(keypair, &secp, None).to_keypair();
    let message = Message::from_digest(sighash.to_byte_array());
    let signature = secp.sign_schnorr_no_aux_rand(&message, &tweaked);
    let (tweaked_pubkey, _) = tweaked.x_only_public_key();
    secp.verify_schnorr(&signature, &message, &tweaked_pubkey)
        .map_err(|_| Error::InvalidClientSignature)?;
    child.input[0].witness.clear();
    child.input[0].witness.push(signature.as_ref());
    Ok(child)
}

/// Returns the exact 68-byte two-party Tapscript leaf.
pub fn funding_tapscript(keys: &CoinKeys) -> ScriptBuf {
    Builder::new()
        .push_x_only_key(&keys.client_pubkey)
        .push_opcode(OP_CHECKSIGVERIFY)
        .push_x_only_key(&keys.enclave_pubkey)
        .push_opcode(OP_CHECKSIG)
        .into_script()
}

/// Derives the one-leaf P2TR funding output script.
pub fn funding_script(keys: &CoinKeys) -> ScriptBuf {
    ScriptBuf::new_p2tr_tweaked(funding_material(keys).spend_info.output_key())
}

/// Derives the one-leaf P2TR funding address for the selected network.
pub fn funding_address(keys: &CoinKeys, network: NetworkId) -> Address {
    Address::p2tr_tweaked(
        funding_material(keys).spend_info.output_key(),
        network.address_hrp(),
    )
}

/// Derives the exact 33-byte depth-zero control block.
pub fn funding_control_block(keys: &CoinKeys) -> ControlBlock {
    funding_material(keys).control_block
}

pub fn recovery_sighash(
    transaction: &Transaction,
    amount_sat: u64,
    keys: &CoinKeys,
) -> Result<[u8; 32], Error> {
    let prevout = TxOut {
        value: Amount::from_sat(amount_sat),
        script_pubkey: funding_script(keys),
    };
    let leaf_hash = TapLeafHash::from_script(&funding_tapscript(keys), LeafVersion::TapScript);
    Ok(bitcoin::sighash::SighashCache::new(transaction)
        .taproot_script_spend_signature_hash(
            0,
            &Prevouts::All(std::slice::from_ref(&prevout)),
            leaf_hash,
            bitcoin::TapSighashType::Default,
        )
        .map_err(|_| Error::Sighash)?
        .to_byte_array())
}

pub fn validate_reaction_window(
    tip_height: u32,
    older_locktime: u32,
    newer_locktime: u32,
) -> Result<(), Error> {
    if older_locktime.checked_sub(LOCKTIME_STEP) != Some(newer_locktime) {
        return Err(Error::TransactionMismatch);
    }
    require_future_locktime(tip_height, newer_locktime)
}

struct FundingMaterial {
    spend_info: TaprootSpendInfo,
    control_block: ControlBlock,
}

fn funding_material(keys: &CoinKeys) -> FundingMaterial {
    let secp = Secp256k1::verification_only();
    let leaf = funding_tapscript(keys);
    let spend_info = TaprootBuilder::new()
        .add_leaf(0, leaf.clone())
        .expect("a depth-zero leaf is a complete Taproot tree")
        .finalize(&secp, nums_internal_key())
        .expect("a depth-zero leaf is finalizable");
    let control_block = spend_info
        .control_block(&(leaf, LeafVersion::TapScript))
        .expect("the derived leaf is present in the Taproot tree");
    FundingMaterial {
        spend_info,
        control_block,
    }
}

fn nums_internal_key() -> XOnlyPublicKey {
    XOnlyPublicKey::from_slice(&NUMS_INTERNAL_KEY_BYTES)
        .expect("the BIP341 NUMS internal key is a valid x-only key")
}

fn client_xonly(secret: SecretKey) -> XOnlyPublicKey {
    secret.x_only_public_key(&Secp256k1::new()).0
}

fn verify_signature(
    signature: &Signature,
    sighash: [u8; 32],
    pubkey: XOnlyPublicKey,
    error: Error,
) -> Result<(), Error> {
    Secp256k1::verification_only()
        .verify_schnorr(signature, &Message::from_digest(sighash), &pubkey)
        .map_err(|_| error)
}

fn require_future_locktime(tip_height: u32, locktime: u32) -> Result<(), Error> {
    if locktime <= tip_height {
        return Err(Error::UnsafeLocktime);
    }
    Ok(())
}

fn ensure_success(status: u16, body: &[u8]) -> Result<(), RemoteError> {
    if (200..300).contains(&status) {
        return Ok(());
    }
    Err(RemoteError::Protocol {
        status,
        message: String::from_utf8_lossy(body).into_owned(),
    })
}

fn unexpected_response() -> RemoteError {
    RemoteError::Protocol {
        status: 500,
        message: "unexpected enclave response".into(),
    }
}
