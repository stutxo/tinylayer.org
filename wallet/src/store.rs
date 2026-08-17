use std::{
    env,
    fs::{self, File, OpenOptions},
    io::{self, IsTerminal as _, Read, Write as _},
    path::{Path, PathBuf},
};

use anyhow::{Context as _, Result, ensure};
use argon2::{Algorithm, Argon2, Params, Version};
use chacha20poly1305::{
    XChaCha20Poly1305, XNonce,
    aead::{Aead as _, KeyInit as _, Payload},
};
use fs2::FileExt as _;
use serde::{Deserialize, Serialize, de::DeserializeOwned};
use sha2::{Digest as _, Sha256};
use zeroize::Zeroizing;

use crate::model::{Config, FILE_FORMAT_VERSION, WalletState};

const CONFIG_FILE: &str = "config.json";
const STATE_FILE: &str = "wallet.enc";
const LOCK_FILE: &str = ".lock";
const STATE_AAD: &[u8] = b"tinylayer-wallet-state-v3";
const MAX_FILE_SIZE: u64 = 16 * 1024 * 1024;
const KDF_MEMORY_KIB: u32 = 19_456;
const KDF_ITERATIONS: u32 = 2;
const KDF_PARALLELISM: u32 = 1;

pub struct WalletStore {
    directory: PathBuf,
    password: Zeroizing<String>,
    config: Config,
    aad: Vec<u8>,
    _lock: File,
}

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

impl WalletStore {
    pub fn initialize(
        directory: &Path,
        config: &Config,
        password: Zeroizing<String>,
    ) -> Result<()> {
        config.validate_version()?;
        ensure_secure_directory(directory)?;
        let lock = open_lock(directory)?;
        ensure!(
            !directory.join(CONFIG_FILE).exists() && !directory.join(STATE_FILE).exists(),
            "wallet is already initialized at {}",
            directory.display()
        );
        let store = Self {
            directory: directory.to_owned(),
            password,
            config: config.clone(),
            aad: state_aad(config)?,
            _lock: lock,
        };
        store.save(&WalletState::empty())?;
        write_json_atomic(&directory.join(CONFIG_FILE), config)?;
        Ok(())
    }

    pub fn open(directory: &Path, password: Zeroizing<String>) -> Result<Self> {
        ensure_private_path(directory, true)?;
        ensure_private_path(&directory.join(STATE_FILE), false)?;
        let lock = open_lock(directory)?;
        ensure_private_path(&directory.join(CONFIG_FILE), false)?;
        let config = load_config(directory)?;
        Ok(Self {
            directory: directory.to_owned(),
            password,
            config: config.clone(),
            aad: state_aad(&config)?,
            _lock: lock,
        })
    }

    pub fn config(&self) -> &Config {
        &self.config
    }

    pub fn load(&self) -> Result<WalletState> {
        let encrypted: EncryptedState = read_json_path(&self.directory.join(STATE_FILE))?;
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
        let key = derive_key(&self.password, &encrypted.kdf, &salt)?;
        let cipher = XChaCha20Poly1305::new_from_slice(key.as_ref())
            .map_err(|_| anyhow::anyhow!("invalid wallet encryption key"))?;
        let plaintext = Zeroizing::new(
            cipher
                .decrypt(
                    XNonce::from_slice(&nonce),
                    Payload {
                        msg: &ciphertext,
                        aad: &self.aad,
                    },
                )
                .map_err(|_| {
                    anyhow::anyhow!("wallet password is incorrect or state is corrupted")
                })?,
        );
        let state: WalletState = serde_json::from_slice(plaintext.as_slice())
            .context("decrypted wallet state is invalid")?;
        state.validate_version()?;
        Ok(state)
    }

    pub fn save(&self, state: &WalletState) -> Result<()> {
        state.validate_version()?;
        let plaintext = Zeroizing::new(serde_json::to_vec(state)?);
        let salt: [u8; 16] = rand::random();
        let nonce: [u8; 24] = rand::random();
        let kdf = KdfParameters {
            algorithm: "argon2id".into(),
            memory_kib: KDF_MEMORY_KIB,
            iterations: KDF_ITERATIONS,
            parallelism: KDF_PARALLELISM,
            salt: hex::encode(salt),
        };
        let key = derive_key(&self.password, &kdf, &salt)?;
        let cipher = XChaCha20Poly1305::new_from_slice(key.as_ref())
            .map_err(|_| anyhow::anyhow!("invalid wallet encryption key"))?;
        let ciphertext = cipher
            .encrypt(
                XNonce::from_slice(&nonce),
                Payload {
                    msg: plaintext.as_slice(),
                    aad: &self.aad,
                },
            )
            .map_err(|_| anyhow::anyhow!("failed to encrypt wallet state"))?;
        write_json_atomic(
            &self.directory.join(STATE_FILE),
            &EncryptedState {
                format_version: FILE_FORMAT_VERSION,
                kdf,
                cipher: "xchacha20poly1305".into(),
                nonce: hex::encode(nonce),
                ciphertext: hex::encode(ciphertext),
            },
        )
    }
}

pub fn load_config(directory: &Path) -> Result<Config> {
    ensure_private_path(directory, true)?;
    ensure_private_path(&directory.join(CONFIG_FILE), false)?;
    let config: Config = read_json_path(&directory.join(CONFIG_FILE))?;
    config.validate_version()?;
    Ok(config)
}

pub fn read_password(path: Option<&Path>, confirm: bool) -> Result<Zeroizing<String>> {
    if let Some(path) = path {
        ensure_private_path(path, false)?;
        let mut password = read_limited(File::open(path).context("open password file")?)?;
        while password
            .last()
            .is_some_and(|byte| matches!(byte, b'\n' | b'\r'))
        {
            password.pop();
        }
        ensure!(!password.is_empty(), "wallet password cannot be empty");
        return String::from_utf8(password)
            .map(Zeroizing::new)
            .context("password file is not UTF-8");
    }
    if let Ok(password) = env::var("ENCLAVIA_WALLET_PASSWORD") {
        ensure!(!password.is_empty(), "wallet password cannot be empty");
        return Ok(Zeroizing::new(password));
    }
    ensure!(
        io::stdin().is_terminal(),
        "set ENCLAVIA_WALLET_PASSWORD or use --password-file in non-interactive mode"
    );
    let password = Zeroizing::new(rpassword::prompt_password("Wallet password: ")?);
    ensure!(!password.is_empty(), "wallet password cannot be empty");
    if confirm {
        let repeated = Zeroizing::new(rpassword::prompt_password("Confirm wallet password: ")?);
        ensure!(*password == *repeated, "wallet passwords do not match");
    }
    Ok(password)
}

pub fn read_json_source<T: DeserializeOwned>(path: &Path) -> Result<T> {
    if path == Path::new("-") {
        let bytes = read_limited(io::stdin().lock())?;
        serde_json::from_slice(&bytes).context("invalid JSON from standard input")
    } else {
        read_json_path(path)
    }
}

pub fn write_json_destination<T: Serialize>(path: &Path, value: &T) -> Result<()> {
    if path == Path::new("-") {
        let stdout = io::stdout();
        let mut output = stdout.lock();
        serde_json::to_writer_pretty(&mut output, value)?;
        writeln!(output)?;
        output.flush()?;
        Ok(())
    } else {
        let mut bytes = serde_json::to_vec_pretty(value)?;
        bytes.push(b'\n');
        write_bytes_destination(path, &bytes)
    }
}

pub fn write_text_destination(path: &Path, value: &str) -> Result<()> {
    if path == Path::new("-") {
        println!("{value}");
        Ok(())
    } else {
        write_bytes_destination(path, format!("{value}\n").as_bytes())
    }
}

pub fn ensure_destination_available(path: &Path) -> Result<()> {
    if path == Path::new("-") {
        return Ok(());
    }
    match fs::symlink_metadata(path) {
        Ok(_) => Err(anyhow::anyhow!(
            "refusing to overwrite existing file: {}",
            path.display()
        )),
        Err(error) if error.kind() == io::ErrorKind::NotFound => Ok(()),
        Err(error) => Err(error).with_context(|| format!("inspect output path {}", path.display())),
    }
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

fn open_lock(directory: &Path) -> Result<File> {
    let mut options = OpenOptions::new();
    options.read(true).write(true).create(true);
    set_private_mode(&mut options);
    let lock = options
        .open(directory.join(LOCK_FILE))
        .context("open wallet lock")?;
    lock.try_lock_exclusive()
        .context("wallet is already open by another process")?;
    Ok(lock)
}

fn ensure_secure_directory(path: &Path) -> Result<()> {
    if !path.exists() {
        let mut builder = fs::DirBuilder::new();
        builder.recursive(true);
        set_private_directory_mode(&mut builder);
        builder
            .create(path)
            .with_context(|| format!("create wallet directory {}", path.display()))?;
    }
    ensure_private_path(path, true)
}

fn ensure_private_path(path: &Path, directory: bool) -> Result<()> {
    let metadata = fs::symlink_metadata(path)
        .with_context(|| format!("wallet path does not exist: {}", path.display()))?;
    ensure!(
        !metadata.file_type().is_symlink(),
        "wallet paths cannot be symlinks"
    );
    if directory {
        ensure!(metadata.is_dir(), "wallet data path is not a directory");
    } else {
        ensure!(metadata.is_file(), "wallet data path is not a regular file");
    }
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt as _;
        ensure!(
            metadata.permissions().mode() & 0o077 == 0,
            "wallet path is accessible by group or other users: {}",
            path.display()
        );
    }
    Ok(())
}

fn read_json_path<T: DeserializeOwned>(path: &Path) -> Result<T> {
    let bytes =
        read_limited(File::open(path).with_context(|| format!("open {}", path.display()))?)?;
    serde_json::from_slice(&bytes).with_context(|| format!("invalid JSON in {}", path.display()))
}

fn read_limited(reader: impl Read) -> Result<Vec<u8>> {
    let mut bytes = Vec::new();
    reader.take(MAX_FILE_SIZE + 1).read_to_end(&mut bytes)?;
    ensure!(
        bytes.len() as u64 <= MAX_FILE_SIZE,
        "input exceeds 16 MiB limit"
    );
    Ok(bytes)
}

fn decode_hex(label: &str, value: &str) -> Result<Vec<u8>> {
    hex::decode(value).with_context(|| format!("invalid {label}"))
}

fn state_aad(config: &Config) -> Result<Vec<u8>> {
    let digest = Sha256::digest(serde_json::to_vec(config)?);
    let mut aad = Vec::with_capacity(STATE_AAD.len() + digest.len());
    aad.extend_from_slice(STATE_AAD);
    aad.extend_from_slice(&digest);
    Ok(aad)
}

fn write_json_atomic<T: Serialize>(path: &Path, value: &T) -> Result<()> {
    let mut bytes = serde_json::to_vec_pretty(value)?;
    bytes.push(b'\n');
    write_bytes_atomic(path, &bytes)
}

fn write_bytes_atomic(path: &Path, bytes: &[u8]) -> Result<()> {
    let parent = path
        .parent()
        .filter(|parent| !parent.as_os_str().is_empty())
        .unwrap_or_else(|| Path::new("."));
    ensure!(
        parent.is_dir(),
        "output directory does not exist: {}",
        parent.display()
    );
    let name = path
        .file_name()
        .and_then(|name| name.to_str())
        .context("output path has no file name")?;
    let temporary = parent.join(format!(
        ".{name}.tmp-{}",
        hex::encode(rand::random::<[u8; 8]>())
    ));
    let result = (|| -> Result<()> {
        let mut options = OpenOptions::new();
        options.write(true).create_new(true);
        set_private_mode(&mut options);
        let mut file = options
            .open(&temporary)
            .with_context(|| format!("create temporary file for {}", path.display()))?;
        file.write_all(bytes)?;
        file.sync_all()?;
        fs::rename(&temporary, path)
            .with_context(|| format!("replace {} atomically", path.display()))?;
        File::open(parent)?.sync_all()?;
        Ok(())
    })();
    if result.is_err() {
        let _ = fs::remove_file(&temporary);
    }
    result
}

fn write_bytes_destination(path: &Path, bytes: &[u8]) -> Result<()> {
    let parent = path
        .parent()
        .filter(|parent| !parent.as_os_str().is_empty())
        .unwrap_or_else(|| Path::new("."));
    ensure!(
        parent.is_dir(),
        "output directory does not exist: {}",
        parent.display()
    );
    let name = path
        .file_name()
        .and_then(|name| name.to_str())
        .context("output path has no file name")?;
    let temporary = parent.join(format!(
        ".{name}.tmp-{}",
        hex::encode(rand::random::<[u8; 8]>())
    ));
    let result = (|| -> Result<()> {
        let mut options = OpenOptions::new();
        options.write(true).create_new(true);
        set_private_mode(&mut options);
        let mut file = options
            .open(&temporary)
            .with_context(|| format!("create temporary file for {}", path.display()))?;
        file.write_all(bytes)?;
        file.sync_all()?;
        match fs::hard_link(&temporary, path) {
            Ok(()) => {}
            Err(error) if error.kind() == io::ErrorKind::AlreadyExists => {
                let existing = read_limited(
                    File::open(path)
                        .with_context(|| format!("read existing output {}", path.display()))?,
                )?;
                ensure!(
                    existing == bytes,
                    "refusing to overwrite existing file: {}",
                    path.display()
                );
            }
            Err(error) => {
                return Err(error).with_context(|| {
                    format!("create output {} without overwrite", path.display())
                });
            }
        }
        fs::remove_file(&temporary)?;
        File::open(parent)?.sync_all()?;
        Ok(())
    })();
    if result.is_err() {
        let _ = fs::remove_file(&temporary);
    }
    result
}

#[cfg(unix)]
fn set_private_mode(options: &mut OpenOptions) {
    use std::os::unix::fs::OpenOptionsExt as _;
    options.mode(0o600);
}

#[cfg(not(unix))]
fn set_private_mode(_: &mut OpenOptions) {}

#[cfg(unix)]
fn set_private_directory_mode(builder: &mut fs::DirBuilder) {
    use std::os::unix::fs::DirBuilderExt as _;
    builder.mode(0o700);
}

#[cfg(not(unix))]
fn set_private_directory_mode(_: &mut fs::DirBuilder) {}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::model::{ChainConfig, EnclaveConfig};
    use tinylayer_client::NetworkId;

    #[test]
    fn encrypted_state_round_trips_and_rejects_wrong_password() {
        assert_eq!(STATE_AAD, b"tinylayer-wallet-state-v3");
        let temporary = tempfile::tempdir().unwrap();
        let directory = temporary.path().join("alice");
        let config = Config {
            format_version: FILE_FORMAT_VERSION,
            protocol_version: tinylayer_client::PROTOCOL_VERSION,
            network: NetworkId::Regtest,
            enclave: EnclaveConfig::UnsafePlaintext {
                url: "http://127.0.0.1:8080".into(),
            },
            chain: ChainConfig::CoreRpc {
                rpc_url: "http://127.0.0.1:18443".into(),
                cookie_file: directory.join("cookie"),
            },
            min_confirmations: 1,
            min_reaction_blocks: 20,
        };
        WalletStore::initialize(&directory, &config, Zeroizing::new("correct".into())).unwrap();
        let saved_config = load_config(&directory).unwrap();
        assert_eq!(
            saved_config.protocol_version,
            tinylayer_client::PROTOCOL_VERSION
        );
        let mut incompatible = saved_config.clone();
        incompatible.protocol_version = 2;
        write_json_atomic(&directory.join(CONFIG_FILE), &incompatible).unwrap();
        assert_eq!(
            load_config(&directory).unwrap_err().to_string(),
            "unsupported wallet protocol version 2"
        );
        write_json_atomic(&directory.join(CONFIG_FILE), &saved_config).unwrap();
        let store = WalletStore::open(&directory, Zeroizing::new("correct".into())).unwrap();
        assert_eq!(store.load().unwrap().format_version, FILE_FORMAT_VERSION);
        drop(store);
        let wrong = WalletStore::open(&directory, Zeroizing::new("wrong".into())).unwrap();
        assert!(wrong.load().is_err());
        drop(wrong);
        let contents = fs::read_to_string(directory.join(STATE_FILE)).unwrap();
        assert!(!contents.contains("correct"));

        let mut changed = load_config(&directory).unwrap();
        changed.min_reaction_blocks += 1;
        write_json_atomic(&directory.join(CONFIG_FILE), &changed).unwrap();
        let changed_store =
            WalletStore::open(&directory, Zeroizing::new("correct".into())).unwrap();
        assert!(changed_store.load().is_err());
    }

    #[test]
    fn artifact_writer_never_replaces_different_content() {
        let temporary = tempfile::tempdir().unwrap();
        let output = temporary.path().join("artifact.json");
        fs::write(&output, b"original\n").unwrap();
        assert!(write_json_destination(&output, &serde_json::json!({"new": true})).is_err());
        assert_eq!(fs::read(&output).unwrap(), b"original\n");

        let value = serde_json::json!({"same": true});
        let mut expected = serde_json::to_vec_pretty(&value).unwrap();
        expected.push(b'\n');
        fs::write(&output, &expected).unwrap();
        write_json_destination(&output, &value).unwrap();
        assert_eq!(fs::read(&output).unwrap(), expected);
    }
}
