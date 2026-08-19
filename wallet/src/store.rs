use std::{
    env,
    fs::{self, File, OpenOptions},
    io::{self, IsTerminal as _, Read, Write as _},
    path::{Path, PathBuf},
};

use anyhow::{Context as _, Result, ensure};
use fs2::FileExt as _;
use serde::{Serialize, de::DeserializeOwned};
use zeroize::Zeroizing;

use crate::model::{Config, NativeWalletState, WalletState};
#[cfg(test)]
use tinylayer_wallet_core::MAX_TRANSFER_CIPHERTEXT_SIZE;
use tinylayer_wallet_core::{open_encrypted_json, seal_encrypted_json, wallet_state_aad};

const CONFIG_FILE: &str = "config.json";
const STATE_FILE: &str = "wallet.enc";
const LOCK_FILE: &str = ".lock";
const MAX_FILE_SIZE: u64 = 16 * 1024 * 1024;
const MAX_STATE_FILE_SIZE: u64 = 64 * 1024 * 1024;

pub struct WalletStore {
    directory: PathBuf,
    password: Zeroizing<String>,
    config: Config,
    aad: Vec<u8>,
    _lock: File,
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
        store.save_native(&NativeWalletState::new(WalletState::empty()))?;
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
        Ok(self.load_native()?.wallet)
    }

    pub fn load_native(&self) -> Result<NativeWalletState> {
        let bytes = read_state_limited(File::open(self.directory.join(STATE_FILE))?)?;
        let state: NativeWalletState =
            open_encrypted_json(&bytes, self.password.as_str(), &self.aad)?;
        state.validate(self.config.network)?;
        Ok(state)
    }

    pub fn save(&self, state: &WalletState) -> Result<()> {
        state.validate_version()?;
        let native = self.load_native()?;
        let value = NativeWalletStateRef {
            format_version: native.format_version,
            funding_secret: &native.funding_secret,
            wallet: state,
            exit: native.exit.as_ref(),
            source_sweep: native.source_sweep.as_ref(),
        };
        let bytes = seal_encrypted_json(&value, self.password.as_str(), &self.aad)?;
        write_state_bytes_atomic(&self.directory.join(STATE_FILE), &bytes)
    }

    pub fn save_native(&self, state: &NativeWalletState) -> Result<()> {
        state.validate(self.config.network)?;
        self.write_native(state)
    }

    fn write_native(&self, state: &NativeWalletState) -> Result<()> {
        let bytes = seal_encrypted_json(state, self.password.as_str(), &self.aad)?;
        write_state_bytes_atomic(&self.directory.join(STATE_FILE), &bytes)
    }
}

#[derive(Serialize)]
struct NativeWalletStateRef<'a> {
    format_version: u32,
    funding_secret: &'a bitcoin::secp256k1::SecretKey,
    wallet: &'a WalletState,
    exit: Option<&'a tinylayer_wallet_core::ExitJournal>,
    source_sweep: Option<&'a tinylayer_wallet_core::SourceSweepJournal>,
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
    let mut bytes = serde_json::to_vec_pretty(value)?;
    bytes.push(b'\n');
    ensure_output_size(&bytes)?;
    if path == Path::new("-") {
        let stdout = io::stdout();
        let mut output = stdout.lock();
        output.write_all(&bytes)?;
        output.flush()?;
        Ok(())
    } else {
        write_bytes_destination(path, &bytes)
    }
}

pub fn write_text_destination(path: &Path, value: &str) -> Result<()> {
    let bytes = format!("{value}\n");
    ensure_output_size(bytes.as_bytes())?;
    if path == Path::new("-") {
        let stdout = io::stdout();
        let mut output = stdout.lock();
        output.write_all(bytes.as_bytes())?;
        output.flush()?;
        Ok(())
    } else {
        write_bytes_destination(path, bytes.as_bytes())
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
    read_limited_with_limit(reader, MAX_FILE_SIZE, "input exceeds 16 MiB limit")
}

fn read_state_limited(reader: impl Read) -> Result<Vec<u8>> {
    read_limited_with_limit(
        reader,
        MAX_STATE_FILE_SIZE,
        "encrypted wallet state exceeds 64 MiB limit",
    )
}

fn read_limited_with_limit(reader: impl Read, limit: u64, message: &str) -> Result<Vec<u8>> {
    let mut bytes = Vec::new();
    reader.take(limit + 1).read_to_end(&mut bytes)?;
    ensure!(bytes.len() as u64 <= limit, "{message}");
    Ok(bytes)
}

fn state_aad(config: &Config) -> Result<Vec<u8>> {
    wallet_state_aad(config)
}

fn write_json_atomic<T: Serialize>(path: &Path, value: &T) -> Result<()> {
    let mut bytes = serde_json::to_vec_pretty(value)?;
    bytes.push(b'\n');
    write_bytes_atomic(path, &bytes)
}

fn write_bytes_atomic(path: &Path, bytes: &[u8]) -> Result<()> {
    ensure_output_size(bytes)?;
    write_bytes_atomic_inner(path, bytes)
}

fn write_state_bytes_atomic(path: &Path, bytes: &[u8]) -> Result<()> {
    ensure_state_size(bytes)?;
    write_bytes_atomic_inner(path, bytes)
}

fn write_bytes_atomic_inner(path: &Path, bytes: &[u8]) -> Result<()> {
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
    ensure_output_size(bytes)?;
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

fn ensure_output_size(bytes: &[u8]) -> Result<()> {
    ensure!(
        bytes.len() as u64 <= MAX_FILE_SIZE,
        "output exceeds 16 MiB limit"
    );
    Ok(())
}

fn ensure_state_size(bytes: &[u8]) -> Result<()> {
    ensure!(
        bytes.len() as u64 <= MAX_STATE_FILE_SIZE,
        "encrypted wallet state exceeds 64 MiB limit"
    );
    Ok(())
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
    use crate::model::{ChainConfig, EnclaveConfig, FILE_FORMAT_VERSION};
    use tinylayer_client::NetworkId;

    #[test]
    fn encrypted_state_round_trips_and_rejects_wrong_password() {
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
                wallet_name: "funder".into(),
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

    #[test]
    fn oversized_writes_leave_existing_files_unchanged() {
        let temporary = tempfile::tempdir().unwrap();
        let output = temporary.path().join("state.enc");
        fs::write(&output, b"original\n").unwrap();
        let oversized = vec![0; MAX_FILE_SIZE as usize + 1];

        assert_eq!(
            write_bytes_atomic(&output, &oversized)
                .unwrap_err()
                .to_string(),
            "output exceeds 16 MiB limit"
        );
        assert_eq!(fs::read(&output).unwrap(), b"original\n");
        assert!(write_bytes_destination(&output, &oversized).is_err());
        assert_eq!(fs::read(&output).unwrap(), b"original\n");
    }

    #[test]
    fn maximum_transfer_artifact_has_a_persistable_sender_state() {
        let envelope = serde_json::json!({
            "format_version": 1,
            "request_id": "00".repeat(32),
            "ephemeral_public_key": format!("02{}", "00".repeat(32)),
            "nonce": "00".repeat(24),
            "ciphertext": "00".repeat(MAX_TRANSFER_CIPHERTEXT_SIZE),
        });
        let mut artifact = serde_json::to_vec_pretty(&envelope).unwrap();
        artifact.push(b'\n');
        assert!(artifact.len() as u64 <= MAX_FILE_SIZE);

        let final_sender = serde_json::json!({
            "outgoing": envelope,
            // Actual retained sender metadata, one recovery, and bounded funding are smaller.
            "maximum_other_state": "x".repeat(2 * 1024 * 1024),
        });
        let sealed = seal_encrypted_json(&final_sender, "password", b"test").unwrap();
        assert!(sealed.len() as u64 <= MAX_STATE_FILE_SIZE);
    }
}
