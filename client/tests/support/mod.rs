#![allow(dead_code)]

use bitcoin::{
    OutPoint, Txid,
    hashes::Hash as _,
    secp256k1::{Secp256k1, SecretKey, XOnlyPublicKey},
};
use tinylayer_client::{
    CoinMetadata, HandoffToken, INITIAL_HANDOFF, NetworkId, SignedRecovery, capability_hash,
    complete_recovery, complete_registration, prepare_recovery, prepare_registration,
    verify_sign_response, verify_status,
};
use tinylayer_enclave::Enclave;

pub const AMOUNT: u64 = 100_000;
pub const LOCKTIME: u32 = 1_000;
pub const CAP_0: [u8; 32] = [0x90; 32];
pub const CAP_A: [u8; 32] = [0xa1; 32];
pub const CAP_B: [u8; 32] = [0xb2; 32];
pub const CAP_C: [u8; 32] = [0xc3; 32];

pub struct Opened {
    pub enclave: Enclave,
    pub client_secret: SecretKey,
    pub metadata: CoinMetadata,
}

pub fn opened() -> Opened {
    let mut enclave = Enclave::new();
    let client_secret = secret(1);
    let registration = prepare_registration(client_secret, capability_hash(&CAP_0));
    let status = enclave.register(registration.request.clone()).unwrap();
    let keys = complete_registration(registration, &status).unwrap();
    Opened {
        enclave,
        client_secret,
        metadata: keys.metadata(NetworkId::Regtest, outpoint(), AMOUNT),
    }
}

#[allow(clippy::too_many_arguments)]
pub fn sign(
    enclave: &mut Enclave,
    metadata: &CoinMetadata,
    client_secret: SecretKey,
    capability: [u8; 32],
    handoff: HandoffToken,
    next_capability_hash: [u8; 32],
    withdrawal_key: XOnlyPublicKey,
    locktime: u32,
) -> (SignedRecovery, HandoffToken) {
    let before = enclave.status(metadata.keys.coin_id).unwrap();
    let (request, prepared) = prepare_recovery(
        metadata,
        &before,
        client_secret,
        capability,
        handoff,
        next_capability_hash,
        withdrawal_key,
        locktime,
        0,
    )
    .unwrap();
    let response = enclave.sign(request.clone()).unwrap();
    let after = enclave.status(metadata.keys.coin_id).unwrap();
    verify_status(&metadata.keys, &after).unwrap();
    verify_sign_response(&request, before.signature_count, &after, &response).unwrap();
    let next_handoff = response.next_handoff;
    (
        complete_recovery(&request, &response, prepared, client_secret).unwrap(),
        next_handoff,
    )
}

pub fn initial_handoff() -> HandoffToken {
    INITIAL_HANDOFF
}

pub fn outpoint() -> OutPoint {
    OutPoint::new(Txid::from_byte_array([0x42; 32]), 7)
}

pub fn secret(byte: u8) -> SecretKey {
    SecretKey::from_slice(&[byte; 32]).unwrap()
}

pub fn xonly(byte: u8) -> XOnlyPublicKey {
    secret(byte).x_only_public_key(&Secp256k1::new()).0
}
