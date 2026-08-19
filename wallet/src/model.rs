use std::path::PathBuf;

use anyhow::{Result, ensure};
use bitcoin::secp256k1::{SecretKey, rand};
use serde::{Deserialize, Serialize};
use tinylayer_client::{NetworkId, PROTOCOL_VERSION};

pub use tinylayer_wallet_core::*;

pub const NATIVE_STATE_FORMAT_VERSION: u32 = 1;

#[derive(Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct NativeWalletState {
    pub format_version: u32,
    pub funding_secret: SecretKey,
    pub wallet: WalletState,
    pub exit: Option<ExitJournal>,
    pub source_sweep: Option<SourceSweepJournal>,
}

impl NativeWalletState {
    pub fn new(wallet: WalletState) -> Self {
        Self {
            format_version: NATIVE_STATE_FORMAT_VERSION,
            funding_secret: SecretKey::new(&mut rand::thread_rng()),
            wallet,
            exit: None,
            source_sweep: None,
        }
    }

    pub fn validate(&self, network: NetworkId) -> Result<()> {
        ensure!(
            self.format_version == NATIVE_STATE_FORMAT_VERSION,
            "unsupported native wallet version {}",
            self.format_version
        );
        self.wallet.validate_version()?;
        if let Some(exit) = &self.exit {
            ensure!(
                exit.package.network == network,
                "saved exit network mismatch"
            );
            exit.validate(
                self.wallet
                    .coin
                    .as_ref()
                    .ok_or_else(|| anyhow::anyhow!("saved exit has no wallet coin"))?,
            )?;
        }
        if let Some(sweep) = &self.source_sweep {
            ensure!(
                sweep.network == network,
                "saved source sweep network mismatch"
            );
            sweep.validate(&self.funding_secret)?;
        }
        Ok(())
    }
}

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
