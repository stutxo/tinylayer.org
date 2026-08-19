use anyhow::{Context as _, Result, ensure};
use argon2::{Algorithm, Argon2, Params, Version};
use chacha20poly1305::{
    XChaCha20Poly1305, XNonce,
    aead::{Aead as _, KeyInit as _, Payload},
};
use serde::{Deserialize, Serialize, de::DeserializeOwned};
use sha2::{Digest as _, Sha256};
use zeroize::Zeroizing;

use crate::{FILE_FORMAT_VERSION, WalletState};

const STATE_AAD: &[u8] = b"tinylayer-wallet-state-v1";
const KDF_MEMORY_KIB: u32 = 19_456;
const KDF_ITERATIONS: u32 = 2;
const KDF_PARALLELISM: u32 = 1;

#[derive(Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
struct EncryptedState {
    format_version: u32,
    kdf: KdfParameters,
    cipher: String,
    nonce: String,
    ciphertext: String,
}

#[derive(Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
struct KdfParameters {
    algorithm: String,
    memory_kib: u32,
    iterations: u32,
    parallelism: u32,
    salt: String,
}

pub fn wallet_state_aad<T: Serialize + ?Sized>(binding: &T) -> Result<Vec<u8>> {
    let digest = Sha256::digest(serde_json::to_vec(binding)?);
    let mut aad = Vec::with_capacity(STATE_AAD.len() + digest.len());
    aad.extend_from_slice(STATE_AAD);
    aad.extend_from_slice(&digest);
    Ok(aad)
}

pub fn seal_wallet_state(state: &WalletState, password: &str, aad: &[u8]) -> Result<Vec<u8>> {
    state.validate_version()?;
    seal_encrypted_json(state, password, aad)
}

pub fn seal_encrypted_json<T: Serialize + ?Sized>(
    value: &T,
    password: &str,
    aad: &[u8],
) -> Result<Vec<u8>> {
    let plaintext = Zeroizing::new(serde_json::to_vec(value)?);
    let salt: [u8; 16] = rand::random();
    let nonce: [u8; 24] = rand::random();
    let kdf = KdfParameters {
        algorithm: "argon2id".into(),
        memory_kib: KDF_MEMORY_KIB,
        iterations: KDF_ITERATIONS,
        parallelism: KDF_PARALLELISM,
        salt: hex::encode(salt),
    };
    let key = derive_key(password, &kdf, &salt)?;
    let cipher = XChaCha20Poly1305::new_from_slice(key.as_ref())
        .map_err(|_| anyhow::anyhow!("invalid wallet encryption key"))?;
    let ciphertext = cipher
        .encrypt(
            XNonce::from_slice(&nonce),
            Payload {
                msg: plaintext.as_slice(),
                aad,
            },
        )
        .map_err(|_| anyhow::anyhow!("failed to encrypt wallet state"))?;
    let mut encoded = serde_json::to_vec_pretty(&EncryptedState {
        format_version: FILE_FORMAT_VERSION,
        kdf,
        cipher: "xchacha20poly1305".into(),
        nonce: hex::encode(nonce),
        ciphertext: hex::encode(ciphertext),
    })?;
    encoded.push(b'\n');
    Ok(encoded)
}

pub fn open_wallet_state(bytes: &[u8], password: &str, aad: &[u8]) -> Result<WalletState> {
    let state: WalletState = open_encrypted_json(bytes, password, aad)?;
    state.validate_version()?;
    Ok(state)
}

pub fn open_encrypted_json<T: DeserializeOwned>(
    bytes: &[u8],
    password: &str,
    aad: &[u8],
) -> Result<T> {
    let encrypted: EncryptedState =
        serde_json::from_slice(bytes).context("encrypted wallet state is invalid")?;
    ensure!(
        encrypted.format_version == FILE_FORMAT_VERSION,
        "unsupported encrypted wallet version {}",
        encrypted.format_version
    );
    ensure!(
        encrypted.kdf.algorithm == "argon2id",
        "unsupported wallet KDF"
    );
    ensure!(
        encrypted.cipher == "xchacha20poly1305",
        "unsupported wallet cipher"
    );
    validate_kdf(&encrypted.kdf)?;
    let salt = decode_hex("wallet salt", &encrypted.kdf.salt)?;
    ensure!(salt.len() == 16, "invalid wallet salt length");
    let nonce = decode_hex("wallet nonce", &encrypted.nonce)?;
    ensure!(nonce.len() == 24, "invalid wallet nonce length");
    let ciphertext = decode_hex("wallet ciphertext", &encrypted.ciphertext)?;
    let key = derive_key(password, &encrypted.kdf, &salt)?;
    let cipher = XChaCha20Poly1305::new_from_slice(key.as_ref())
        .map_err(|_| anyhow::anyhow!("invalid wallet encryption key"))?;
    let plaintext = Zeroizing::new(
        cipher
            .decrypt(
                XNonce::from_slice(&nonce),
                Payload {
                    msg: &ciphertext,
                    aad,
                },
            )
            .map_err(|_| anyhow::anyhow!("wallet password is incorrect or state is corrupted"))?,
    );
    serde_json::from_slice(plaintext.as_slice()).context("decrypted wallet state is invalid")
}

fn validate_kdf(kdf: &KdfParameters) -> Result<()> {
    ensure!(
        (8..=262_144).contains(&kdf.memory_kib),
        "wallet KDF memory cost is outside supported limits"
    );
    ensure!(
        (1..=10).contains(&kdf.iterations),
        "wallet KDF iteration cost is outside supported limits"
    );
    ensure!(
        (1..=16).contains(&kdf.parallelism),
        "wallet KDF parallelism is outside supported limits"
    );
    Ok(())
}

fn derive_key(password: &str, kdf: &KdfParameters, salt: &[u8]) -> Result<Zeroizing<[u8; 32]>> {
    let params = Params::new(kdf.memory_kib, kdf.iterations, kdf.parallelism, Some(32))
        .map_err(|error| anyhow::anyhow!("invalid wallet KDF parameters: {error}"))?;
    let argon2 = Argon2::new(Algorithm::Argon2id, Version::V0x13, params);
    let mut key = Zeroizing::new([0; 32]);
    argon2
        .hash_password_into(password.as_bytes(), salt, key.as_mut())
        .map_err(|error| anyhow::anyhow!("failed to derive wallet encryption key: {error}"))?;
    Ok(key)
}

fn decode_hex(label: &str, value: &str) -> Result<Vec<u8>> {
    hex::decode(value).with_context(|| format!("invalid {label}"))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn encrypted_state_round_trips_and_binds_context() {
        let state = WalletState::empty();
        let aad = wallet_state_aad(&serde_json::json!({"network": "regtest"})).unwrap();
        let encoded = seal_wallet_state(&state, "correct", &aad).unwrap();
        assert_eq!(
            open_wallet_state(&encoded, "correct", &aad)
                .unwrap()
                .format_version,
            FILE_FORMAT_VERSION
        );
        assert!(open_wallet_state(&encoded, "wrong", &aad).is_err());
        let changed = wallet_state_aad(&serde_json::json!({"network": "mutinynet"})).unwrap();
        assert!(open_wallet_state(&encoded, "correct", &changed).is_err());
        assert!(!String::from_utf8(encoded).unwrap().contains("correct"));
    }
}
