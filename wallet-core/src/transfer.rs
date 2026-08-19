use std::str::FromStr as _;

use anyhow::{Context as _, Result, ensure};
use bitcoin::{
    Amount, OutPoint,
    consensus::serialize,
    secp256k1::{PublicKey, Secp256k1, SecretKey, XOnlyPublicKey, ecdh::SharedSecret},
};
use chacha20poly1305::{
    XChaCha20Poly1305, XNonce,
    aead::{Aead as _, KeyInit as _, Payload},
};
use hkdf::Hkdf;
use serde::{Deserialize, Serialize};
use sha2::{Digest as _, Sha256};
use tinylayer_client::{CoinMetadata, HandoffToken, NetworkId, PROTOCOL_VERSION, SignedRecovery};
use zeroize::Zeroizing;

use crate::FILE_FORMAT_VERSION;

const TRANSFER_INFO: &[u8] = b"Tinylayer/TransferPackage/v1";
const TRANSFER_ENVELOPE_FINGERPRINT: &[u8] = b"Tinylayer/TransferEnvelopeFingerprint/v1";
pub const MAX_TRANSFER_CIPHERTEXT_SIZE: usize = 8 * 1024 * 1024 - 4096;

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
        let request_id = self.id()?;
        let coin_id = self.coin_id()?;
        ensure!(
            self.request_id == hex::encode(request_id) && self.coin_id == hex::encode(coin_id),
            "transfer request IDs must use canonical lowercase hex"
        );
        let outpoint = self.outpoint()?;
        ensure!(!outpoint.is_null(), "transfer outpoint cannot be null");
        ensure!(
            self.outpoint == outpoint.to_string(),
            "transfer outpoint must use canonical txid:vout encoding"
        );
        ensure!(
            self.expected_amount_sat <= Amount::MAX_MONEY.to_sat(),
            "transfer request amount exceeds Bitcoin MAX_MONEY"
        );
        let withdrawal_key = self.withdrawal_key()?;
        let next_capability_hash = self.next_capability_hash()?;
        let transport_key = self.transport_key()?;
        ensure!(
            self.withdrawal_xonly_pubkey == withdrawal_key.to_string()
                && self.next_capability_hash == hex::encode(next_capability_hash)
                && self.transport_public_key == transport_key.to_string(),
            "transfer request keys must use canonical lowercase encodings"
        );
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
        aad.extend_from_slice(&serialize(&outpoint.txid));
        aad.extend_from_slice(&outpoint.vout.to_be_bytes());
        aad.extend_from_slice(&self.expected_amount_sat.to_be_bytes());
        aad.extend_from_slice(&self.withdrawal_key()?.serialize());
        aad.extend_from_slice(&self.next_capability_hash()?);
        aad.extend_from_slice(&self.transport_key()?.serialize());
        aad.extend_from_slice(&self.min_reaction_blocks.to_be_bytes());
        Ok(aad)
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct TransferEnvelope {
    pub format_version: u32,
    pub request_id: String,
    pub ephemeral_public_key: String,
    pub nonce: String,
    pub ciphertext: String,
}

impl TransferEnvelope {
    pub fn fingerprint(&self) -> [u8; 32] {
        let mut hash = Sha256::new();
        hash.update(TRANSFER_ENVELOPE_FINGERPRINT);
        hash.update(self.format_version.to_be_bytes());
        for value in [
            &self.request_id,
            &self.ephemeral_public_key,
            &self.nonce,
            &self.ciphertext,
        ] {
            hash.update((value.len() as u64).to_be_bytes());
            hash.update(value.as_bytes());
        }
        hash.finalize().into()
    }
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

pub fn validate_transfer_payload_size(payload: &TransferPayload) -> Result<()> {
    let plaintext_size = serde_json::to_vec(payload)?.len();
    validate_transfer_plaintext_size(plaintext_size)
}

fn validate_transfer_plaintext_size(plaintext_size: usize) -> Result<()> {
    ensure!(
        plaintext_size
            .checked_add(16)
            .is_some_and(|size| size <= MAX_TRANSFER_CIPHERTEXT_SIZE),
        "transfer package exceeds 8 MiB ciphertext limit"
    );
    Ok(())
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
    encrypt_transfer_with_material(request, payload, random_secret_key(), rand::random())
}

fn encrypt_transfer_with_material(
    request: &TransferRequest,
    payload: &TransferPayload,
    ephemeral: SecretKey,
    nonce: [u8; 24],
) -> Result<TransferEnvelope> {
    request.validate()?;
    payload.validate()?;
    ensure!(
        payload.request_id == request.id()?,
        "transfer request mismatch"
    );
    let ephemeral_public_key = PublicKey::from_secret_key(&Secp256k1::new(), &ephemeral);
    let shared = SharedSecret::new(&request.transport_key()?, &ephemeral);
    let key = transfer_key(&shared, payload.request_id)?;
    let cipher = XChaCha20Poly1305::new_from_slice(key.as_ref())
        .map_err(|_| anyhow::anyhow!("invalid transfer encryption key"))?;
    let plaintext = Zeroizing::new(serde_json::to_vec(payload)?);
    validate_transfer_plaintext_size(plaintext.len())?;
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
    ensure!(
        envelope.ciphertext.len() <= MAX_TRANSFER_CIPHERTEXT_SIZE * 2,
        "transfer package exceeds 8 MiB ciphertext limit"
    );
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
    use bitcoin::{Txid, hashes::Hash as _};
    use tinylayer_client::{CoinKeys, NetworkId};

    #[test]
    fn transfer_package_is_encrypted_and_bound_to_request() {
        assert_eq!(FILE_FORMAT_VERSION, 1);
        assert_eq!(PROTOCOL_VERSION, 1);
        assert_eq!(TRANSFER_INFO, b"Tinylayer/TransferPackage/v1");
        let transport = secret(6);
        let request = TransferRequest::new(
            [1; 32],
            [2; 32],
            NetworkId::Regtest,
            OutPoint::new(
                Txid::from_byte_array([
                    0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b, 0x0c,
                    0x0d, 0x0e, 0x0f, 0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17, 0x18, 0x19,
                    0x1a, 0x1b, 0x1c, 0x1d, 0x1e, 0x1f,
                ]),
                4,
            ),
            100_000,
            secret_xonly(&secret(7)),
            [5; 32],
            PublicKey::from_secret_key(&Secp256k1::new(), &transport),
            20,
        );
        assert_eq!(
            hex::encode(request.aad().unwrap()),
            "54696e796c617965722f5472616e736665725061636b6167652f7631000000010101010101010101010101010101010101010101010101010101010101010101020202020202020202020202020202020202020202020202020202020202020203000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f0000000400000000000186a0989c0b76cb563971fdc9bef31ec06c3560f3249d6ee9e5d83c57625596e05f6f050505050505050505050505050505050505050505050505050505050505050503f006a18d5653c4edf5391ff23a61f03ff83d237e880ee61187fa9f379a028e0a00000014"
        );
        let mut payload = TransferPayload {
            format_version: FILE_FORMAT_VERSION,
            protocol_version: PROTOCOL_VERSION,
            request_id: [1; 32],
            client_secret: secret(7),
            current_handoff: [8; 32],
            metadata: test_metadata(),
            history: Vec::new(),
        };
        let vector_ephemeral = secret(10);
        let vector_shared = SharedSecret::new(&request.transport_key().unwrap(), &vector_ephemeral);
        let vector_key = transfer_key(&vector_shared, payload.request_id).unwrap();
        let vector_plaintext = serde_json::to_vec(&payload).unwrap();
        let vector_envelope =
            encrypt_transfer_with_material(&request, &payload, vector_ephemeral, [9; 24]).unwrap();
        assert_eq!(
            hex::encode(vector_shared.secret_bytes()),
            "6723c17088ce8c5256fa25baa61e18149cff98d11192b13b7e384920c449296b"
        );
        assert_eq!(
            hex::encode(vector_key.as_slice()),
            "9f51d66249f25989e46acadc04257ff39e1a847b759af1c2e3c548e05d74c490"
        );
        assert_eq!(
            hex::encode(vector_plaintext),
            "7b22666f726d61745f76657273696f6e223a312c2270726f746f636f6c5f76657273696f6e223a312c22726571756573745f6964223a5b312c312c312c312c312c312c312c312c312c312c312c312c312c312c312c312c312c312c312c312c312c312c312c312c312c312c312c312c312c312c312c315d2c22636c69656e745f736563726574223a2230373037303730373037303730373037303730373037303730373037303730373037303730373037303730373037303730373037303730373037303730373037222c2263757272656e745f68616e646f6666223a5b382c382c382c382c382c382c382c382c382c382c382c382c382c382c382c382c382c382c382c382c382c382c382c382c382c382c382c382c382c382c382c385d2c226d65746164617461223a7b226b657973223a7b2270726f746f636f6c5f76657273696f6e223a312c22636f696e5f6964223a5b322c322c322c322c322c322c322c322c322c322c322c322c322c322c322c322c322c322c322c322c322c322c322c322c322c322c322c322c322c322c322c325d2c22636c69656e745f7075626b6579223a2231623834633535363762313236343430393935643365643561616261303536356437316531383334363034383139666639633137663565396435646430373866222c22656e636c6176655f7075626b6579223a2234643462366364313336313033326361396264326165623964393030616134643435643965616438306163393432333337346334353161373235346430373636227d2c226e6574776f726b223a2272656774657374222c226f7574706f696e74223a22303330333033303330333033303330333033303330333033303330333033303330333033303330333033303330333033303330333033303330333033303330333a34222c22616d6f756e745f736174223a3130303030307d2c22686973746f7279223a5b5d7d"
        );
        assert_eq!(
            vector_envelope.ephemeral_public_key,
            "03f76a39d05686e34a4420897e359371836145dd3973e3982568b60f8433adde6e"
        );
        assert_eq!(
            vector_envelope.nonce,
            "090909090909090909090909090909090909090909090909"
        );
        assert_eq!(
            vector_envelope.ciphertext,
            "28979f378a3d19dd484c004245483eb5c689a5b6e3a7ddec87118ef5ce6528738086eb736511d51efefeb4381b896dd09539cc8947a1f9990345fe5984f689d2eff7ebcf9154f5177073e474f7f08de56f8f5a86a261f2c2f0dffe426c6a674acacffcf0b5bcf9ac6d0ee1b696d36ee0942ccf964f961536b522a1764fd8a0c45796f99b6b43e78cedfb0a8844e943c0960f16b3cfcdff34b392e496d5ffabdc1082ea85c1833279a99a9bb3e045b6ca4ced89f26e3fdfd084b2c1fbcf37004b60088b0a213e5905535acf42623f518caf5df0023c86eb87acc5dedadb3827e868eda07cee49fdb6c4f243f342dcce254ed243cffcef2c288ba82f11236eef28ecd223078c4e680b046bb64f3784115d36dbd538a9fa45a20e3ad7b7f3e8b5c4fec285681732b78ac652410b9d94cbf0a3e5117bf192577661726c1b00fb88505c5a2b1779c821f0dfd99901e8093f66f349433ee57166f5858b039642701b0e02e741a51471cc44ebd4ed880a776d8be850ec40e1896ed28bce7fa206d9d714226ab0320786560955157a88ee8fad443940c97206c43ba37edf3e82f64ebd357546010cd9dc7e4ed737fd26ae42c5b8df37eaed3562cd2ede97ebdbb700e2db382fa79cf9a369b2a60b8ca6d8e238219ce3654944402b60ac0cb13ace65f791c6db73309e7adefcb45118f6d77dafb4c359b27ea5b511e9959b7708c008a8c9e2dc350c6c012f3e462a67bacb232751b0564230690d5dcc972d3abcee1897a0d48d3dbb7813460aabe57c8aee5da0254fba99466b19a62647228d78944211f911470d359364daa3cae64ef59dee5659dd66ffe6f93fb79786802db145cda467d27f401256ca62bc41b6a33230fbe512c36517282a285850c4557c98b30c4fbb3f6f8337654047d6776c331e25a1e62e092ff4ec9dc039e5b11ef43e1d2a2e4323090e4734d4031afd3a9cde0c884f2d3cd0fae098f352b2874b9ce89188f93c51ce5912f43c3cca6d039e7f7a2bd37f05c5"
        );

        let padded_ephemeral = secret(11);
        let padded_public = PublicKey::from_secret_key(&Secp256k1::new(), &padded_ephemeral);
        let padded_shared = SharedSecret::new(&request.transport_key().unwrap(), &padded_ephemeral);
        let padded_key = transfer_key(&padded_shared, payload.request_id).unwrap();
        let padded_cipher = XChaCha20Poly1305::new_from_slice(padded_key.as_slice()).unwrap();
        let padded_nonce = [12; 24];
        let mut padded_plaintext = serde_json::to_vec(&payload).unwrap();
        padded_plaintext.extend(std::iter::repeat_n(b' ', 1024));
        let padded_ciphertext = padded_cipher
            .encrypt(
                XNonce::from_slice(&padded_nonce),
                Payload {
                    msg: &padded_plaintext,
                    aad: &request.aad().unwrap(),
                },
            )
            .unwrap();
        let padded_envelope = TransferEnvelope {
            format_version: FILE_FORMAT_VERSION,
            request_id: request.request_id.clone(),
            ephemeral_public_key: padded_public.to_string(),
            nonce: hex::encode(padded_nonce),
            ciphertext: hex::encode(padded_ciphertext),
        };
        decrypt_transfer(&request, transport.secret_bytes(), &padded_envelope).unwrap();
        let envelope = encrypt_transfer(&request, &payload).unwrap();
        let decoded = decrypt_transfer(&request, transport.secret_bytes(), &envelope).unwrap();
        decoded.validate_expected_amount(&request).unwrap();
        let fingerprint = envelope.fingerprint();
        let mut changed_envelope = envelope.clone();
        changed_envelope.format_version += 1;
        assert_ne!(changed_envelope.fingerprint(), fingerprint);
        let json = serde_json::to_string(&envelope).unwrap();
        assert!(!json.contains("current_handoff"));
        assert!(!json.contains(&hex::encode(payload.current_handoff)));
        assert!(!json.contains(&hex::encode(payload.client_secret.secret_bytes())));

        let mut oversized = envelope.clone();
        oversized.ciphertext = "00".repeat(MAX_TRANSFER_CIPHERTEXT_SIZE + 1);
        assert_eq!(
            decrypt_transfer(&request, transport.secret_bytes(), &oversized)
                .err()
                .unwrap()
                .to_string(),
            "transfer package exceeds 8 MiB ciphertext limit"
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
        wrong_protocol.protocol_version += 1;
        assert_eq!(
            wrong_protocol.validate().unwrap_err().to_string(),
            "transfer protocol version mismatch"
        );

        let mut null_outpoint = request.clone();
        null_outpoint.outpoint = OutPoint::null().to_string();
        assert_eq!(
            null_outpoint.validate().unwrap_err().to_string(),
            "transfer outpoint cannot be null"
        );

        let mut uppercase_id = request.clone();
        uppercase_id.request_id = "AA".repeat(32);
        assert_eq!(
            uppercase_id.validate().unwrap_err().to_string(),
            "transfer request IDs must use canonical lowercase hex"
        );

        payload.protocol_version += 1;
        assert_eq!(
            encrypt_transfer(&request, &payload)
                .unwrap_err()
                .to_string(),
            "transfer protocol version mismatch"
        );
        let incompatible = encrypt_unchecked(&request, &payload);
        let error = decrypt_transfer(&request, transport.secret_bytes(), &incompatible)
            .err()
            .expect("incompatible authenticated payload must fail");
        assert_eq!(error.to_string(), "transfer protocol version mismatch");

        let mut tampered = envelope.clone();
        tampered.ciphertext.replace_range(0..2, "00");
        assert!(decrypt_transfer(&request, transport.secret_bytes(), &tampered).is_err());

        let mut wrong_nonce = envelope.clone();
        wrong_nonce.nonce = "00".repeat(23);
        let error = decrypt_transfer(&request, transport.secret_bytes(), &wrong_nonce)
            .err()
            .expect("wrong nonce length must fail");
        assert_eq!(error.to_string(), "invalid transfer package nonce length");
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
            protocol_version: PROTOCOL_VERSION,
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
                protocol_version: PROTOCOL_VERSION,
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
