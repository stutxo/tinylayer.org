use std::{fs, net::IpAddr, path::Path, time::Duration};

use anyhow::{Context as _, Result, bail, ensure};
use bitcoin::{Amount, BlockHash, OutPoint, ScriptBuf, Transaction, TxOut, consensus::deserialize};
use bitcoincore_rpc::{Auth, Client as BitcoinClient, RpcApi as _};
use enclavia::Pcrs;
use serde::Deserialize;
use serde_json::json;
use tinylayer_client::{
    CoinKeys, CoinMetadata, CoinStatus, NetworkId, RegisterRequest, RemoteEnclave, SignRequest,
    SignResponse, SignedRecovery, funding_address, funding_script, validate_reaction_window,
    verify_funding_utxo, verify_recovery, verify_status,
};
use tinylayer_enclave::{Request, Response};

use crate::model::{ChainConfig, EnclaveConfig};

pub enum EnclaveConnection {
    Attested(RemoteEnclave),
    Plaintext {
        client: reqwest::Client,
        url: String,
    },
}

impl EnclaveConnection {
    pub async fn connect(config: &EnclaveConfig) -> Result<Self> {
        match config {
            EnclaveConfig::Production {
                url,
                pcr0,
                pcr1,
                pcr2,
            } => {
                let pcrs = Pcrs::from_hex(pcr0, pcr1, pcr2).context("invalid PCR policy")?;
                Ok(Self::Attested(
                    RemoteEnclave::connect(url, pcrs)
                        .await
                        .context("connect to attested enclave")?,
                ))
            }
            EnclaveConfig::Debug {
                url,
                pcr0,
                pcr1,
                pcr2,
            } => {
                let pcrs = Pcrs::from_hex(pcr0, pcr1, pcr2).context("invalid PCR policy")?;
                Ok(Self::Attested(
                    RemoteEnclave::connect_debug(url, pcrs)
                        .await
                        .context("connect to debug enclave")?,
                ))
            }
            EnclaveConfig::UnsafePlaintext { url } => {
                validate_plaintext_url(url)?;
                Ok(Self::Plaintext {
                    client: reqwest::Client::builder()
                        .timeout(Duration::from_secs(30))
                        .redirect(reqwest::redirect::Policy::none())
                        .build()?,
                    url: url.trim_end_matches('/').into(),
                })
            }
        }
    }

    pub async fn health(&self) -> Result<()> {
        match self {
            Self::Attested(remote) => remote.health().await.context("enclave health check"),
            Self::Plaintext { client, url } => {
                let response = client
                    .get(format!("{url}/health"))
                    .send()
                    .await
                    .context("enclave health check")?;
                ensure!(
                    response.status().is_success(),
                    "enclave health check returned HTTP {}",
                    response.status()
                );
                Ok(())
            }
        }
    }

    pub async fn register(&self, request: &RegisterRequest) -> Result<CoinStatus> {
        match self {
            Self::Attested(remote) => remote.register(request).await.context("register coin"),
            Self::Plaintext { .. } => {
                match self.call_plain(Request::Register(request.clone())).await? {
                    Response::Status(status) => Ok(status),
                    _ => bail!("enclave returned an unexpected registration response"),
                }
            }
        }
    }

    pub async fn status(&self, coin_id: [u8; 32]) -> Result<CoinStatus> {
        match self {
            Self::Attested(remote) => remote.status(coin_id).await.context("query coin status"),
            Self::Plaintext { .. } => match self.call_plain(Request::Status { coin_id }).await? {
                Response::Status(status) => Ok(status),
                _ => bail!("enclave returned an unexpected status response"),
            },
        }
    }

    pub async fn sign(&self, request: &SignRequest) -> Result<SignResponse> {
        match self {
            Self::Attested(remote) => remote.sign(request).await.context("sign recovery"),
            Self::Plaintext { .. } => {
                match self.call_plain(Request::Sign(request.clone())).await? {
                    Response::Signature(response) => Ok(response),
                    _ => bail!("enclave returned an unexpected sign response"),
                }
            }
        }
    }

    async fn call_plain(&self, request: Request) -> Result<Response> {
        let Self::Plaintext { client, url } = self else {
            bail!("internal transport mismatch");
        };
        let response = client
            .post(format!("{url}/v1"))
            .json(&request)
            .send()
            .await
            .context("call plaintext test enclave")?;
        let status = response.status();
        let bytes = response.bytes().await?;
        if !status.is_success() {
            bail!(
                "enclave returned HTTP {}: {}",
                status.as_u16(),
                String::from_utf8_lossy(&bytes)
            );
        }
        serde_json::from_slice(&bytes).context("invalid enclave response")
    }
}

/// Chain data and broadcast backend. Mutinynet uses an Esplora-compatible
/// explorer API; local Bitcoin Core RPC remains for regtest functional tests.
pub enum Chain {
    Explorer(Explorer),
    Core(Core),
}

pub struct FundingObservation {
    pub tip_height: u32,
    pub confirmations: u32,
}

impl Chain {
    pub async fn connect(config: &ChainConfig, network: NetworkId) -> Result<Self> {
        ensure!(
            network != NetworkId::Mainnet,
            "mainnet is not supported by this wallet"
        );
        match config {
            ChainConfig::Explorer { url } => Ok(Self::Explorer(Explorer::connect(url)?)),
            ChainConfig::CoreRpc {
                rpc_url,
                cookie_file,
                wallet_name,
            } => {
                ensure!(
                    network == NetworkId::Regtest,
                    "Bitcoin Core RPC is restricted to regtest"
                );
                Ok(Self::Core(Core::connect(
                    rpc_url,
                    cookie_file,
                    wallet_name,
                    network,
                )?))
            }
        }
    }

    pub async fn verify_funding(
        &self,
        metadata: &CoinMetadata,
        minimum_confirmations: u32,
    ) -> Result<FundingObservation> {
        match self {
            Self::Explorer(explorer) => {
                explorer
                    .verify_funding(metadata, minimum_confirmations)
                    .await
            }
            Self::Core(core) => core.verify_funding(metadata, minimum_confirmations),
        }
    }

    pub async fn tip_height(&self) -> Result<u32> {
        match self {
            Self::Explorer(explorer) => explorer.tip_height().await,
            Self::Core(core) => core.tip_height(),
        }
    }

    pub fn prepare_funding(
        &self,
        keys: &CoinKeys,
        amount_sat: u64,
        fee_rate_sat_vb: u64,
        max_fee_sat: u64,
    ) -> Result<PreparedFunding> {
        match self {
            Self::Core(core) => {
                core.prepare_funding(keys, amount_sat, fee_rate_sat_vb, max_fee_sat)
            }
            Self::Explorer(_) => bail!("automatic funding requires a Bitcoin Core wallet backend"),
        }
    }

    pub fn validate_prepared_funding(
        &self,
        metadata: &CoinMetadata,
        transaction: &Transaction,
    ) -> Result<()> {
        match self {
            Self::Core(core) => core.validate_prepared_funding(metadata, transaction),
            Self::Explorer(_) => bail!("prepared funding requires a Bitcoin Core wallet backend"),
        }
    }

    pub fn broadcast_funding(
        &self,
        metadata: &CoinMetadata,
        transaction: &Transaction,
    ) -> Result<bitcoin::Txid> {
        match self {
            Self::Core(core) => core.broadcast_funding(metadata, transaction),
            Self::Explorer(_) => bail!("automatic funding requires a Bitcoin Core wallet backend"),
        }
    }

    /// Fee rate for the exit child in sat/vB.
    pub async fn recommended_fee_rate(&self) -> Result<u64> {
        match self {
            Self::Explorer(explorer) => explorer.recommended_fee_rate().await,
            Self::Core(_) => Ok(1),
        }
    }

    /// Submits the zero-fee recovery parent and its fee-paying TRUC child.
    pub async fn submit_package(&self, parent_hex: &str, child_hex: &str) -> Result<()> {
        match self {
            Self::Explorer(explorer) => explorer.submit_package(parent_hex, child_hex).await,
            Self::Core(core) => core.submit_package(parent_hex, child_hex),
        }
    }
}

pub fn default_explorer_url(network: NetworkId) -> Option<&'static str> {
    match network {
        NetworkId::Mutinynet => Some("https://mutinynet.com/api"),
        NetworkId::Mainnet | NetworkId::Regtest => None,
    }
}

pub struct Explorer {
    client: reqwest::Client,
    base_url: String,
}

#[derive(Deserialize)]
struct ExplorerTx {
    status: ExplorerTxStatus,
    vin: Vec<ExplorerVin>,
    vout: Vec<ExplorerVout>,
}

#[derive(Deserialize)]
struct ExplorerTxStatus {
    confirmed: bool,
    block_height: Option<u32>,
    block_hash: Option<BlockHash>,
}

#[derive(Deserialize)]
struct ExplorerVin {
    #[serde(default)]
    is_coinbase: bool,
}

#[derive(Deserialize)]
struct ExplorerVout {
    value: u64,
    scriptpubkey: String,
}

#[derive(Deserialize)]
struct ExplorerOutspend {
    spent: bool,
}

#[derive(Deserialize)]
struct ExplorerFees {
    #[serde(rename = "fastestFee")]
    fastest_fee: f64,
}

#[derive(Deserialize)]
struct PackageResponse {
    package_msg: String,
}

impl Explorer {
    pub fn connect(url: &str) -> Result<Self> {
        validate_explorer_url(url)?;
        Ok(Self {
            client: reqwest::Client::builder()
                .timeout(Duration::from_secs(30))
                .redirect(reqwest::redirect::Policy::none())
                .build()?,
            base_url: url.trim_end_matches('/').into(),
        })
    }

    pub async fn verify_funding(
        &self,
        metadata: &CoinMetadata,
        minimum_confirmations: u32,
    ) -> Result<FundingObservation> {
        let tip_height = self.tip_height().await?;
        let transaction = self.transaction(&metadata.outpoint.txid).await?;
        let vout = metadata.outpoint.vout as usize;
        let outspends: Vec<ExplorerOutspend> = self
            .get_json(&format!("/tx/{}/outspends", metadata.outpoint.txid))
            .await?;
        ensure!(
            !outspends.get(vout).is_none_or(|outspend| outspend.spent),
            "funding output is spent or missing"
        );
        let output = transaction
            .vout
            .get(vout)
            .context("funding output index is missing")?;
        ensure!(
            transaction.status.confirmed,
            "funding transaction is not confirmed"
        );
        let block_height = transaction
            .status
            .block_height
            .context("funding transaction has no confirmed block height")?;
        let block_hash = transaction
            .status
            .block_hash
            .context("funding transaction has no confirmed block hash")?;
        let best_hash = self.block_hash_at_height(block_height).await?;
        ensure!(
            best_hash == block_hash,
            "funding block is not in the current best chain"
        );
        let confirmations = tip_height
            .checked_sub(block_height)
            .and_then(|depth| depth.checked_add(1))
            .context("funding block is above the chain tip")?;
        ensure!(
            confirmations >= minimum_confirmations,
            "funding output has {confirmations} confirmations; {minimum_confirmations} required",
        );
        ensure!(
            !transaction.vin.first().is_some_and(|vin| vin.is_coinbase) || confirmations >= 100,
            "coinbase funding output is not mature"
        );
        let output = TxOut {
            value: Amount::from_sat(output.value),
            script_pubkey: ScriptBuf::from_hex(&output.scriptpubkey)
                .context("explorer returned an invalid funding script")?,
        };
        verify_funding_utxo(metadata, metadata.outpoint, &output)?;
        Ok(FundingObservation {
            tip_height,
            confirmations,
        })
    }

    pub async fn tip_height(&self) -> Result<u32> {
        self.get_text("/blocks/tip/height")
            .await?
            .trim()
            .parse()
            .context("explorer returned an invalid chain tip height")
    }

    pub async fn recommended_fee_rate(&self) -> Result<u64> {
        let fees: ExplorerFees = self.get_json("/v1/fees/recommended").await?;
        Ok(fees.fastest_fee.ceil().max(1.0) as u64)
    }

    pub async fn submit_package(&self, parent_hex: &str, child_hex: &str) -> Result<()> {
        let response = self
            .client
            .post(format!("{}/v1/txs/package", self.base_url))
            .json(&json!([parent_hex, child_hex]))
            .send()
            .await
            .context("submit recovery package")?;
        let status = response.status();
        let body = response.text().await?;
        ensure!(
            status.is_success(),
            "explorer rejected the recovery package with HTTP {}: {}",
            status.as_u16(),
            body
        );
        let result: PackageResponse =
            serde_json::from_str(&body).context("invalid package submission response")?;
        ensure!(
            result.package_msg == "success",
            "recovery package was not accepted: {body}"
        );
        Ok(())
    }

    async fn transaction(&self, txid: &bitcoin::Txid) -> Result<ExplorerTx> {
        self.get_json(&format!("/tx/{txid}"))
            .await
            .context("funding transaction is missing")
    }

    async fn block_hash_at_height(&self, height: u32) -> Result<BlockHash> {
        self.get_text(&format!("/block-height/{height}"))
            .await?
            .trim()
            .parse()
            .context("explorer returned an invalid block hash")
    }

    async fn get_text(&self, path: &str) -> Result<String> {
        let response = self
            .client
            .get(format!("{}{path}", self.base_url))
            .send()
            .await
            .with_context(|| format!("query explorer {path}"))?;
        let status = response.status();
        let body = response.text().await?;
        ensure!(
            status.is_success(),
            "explorer returned HTTP {} for {path}",
            status.as_u16()
        );
        Ok(body)
    }

    async fn get_json<T: for<'de> Deserialize<'de>>(&self, path: &str) -> Result<T> {
        let body = self.get_text(path).await?;
        serde_json::from_str(&body).with_context(|| format!("invalid explorer response at {path}"))
    }
}

pub struct Core {
    client: BitcoinClient,
    wallet_name: String,
    network: NetworkId,
}

pub struct PreparedFunding {
    pub transaction: Transaction,
    pub outpoint: OutPoint,
    pub fee_sat: u64,
}

enum FundingTransactionState {
    Unknown,
    Evicted,
    Known,
}

#[derive(Deserialize)]
struct ChainInfo {
    chain: String,
    blocks: u64,
    #[serde(rename = "bestblockhash")]
    best_block_hash: BlockHash,
}

#[derive(Deserialize)]
struct WalletInfo {
    #[serde(rename = "walletname")]
    wallet_name: String,
    private_keys_enabled: bool,
}

#[derive(Deserialize)]
struct WalletTransaction {
    confirmations: i32,
    txid: bitcoin::Txid,
    #[serde(default)]
    walletconflicts: Vec<bitcoin::Txid>,
    hex: String,
}

impl Core {
    pub fn connect(
        rpc_url: &str,
        cookie_file: &Path,
        wallet_name: &str,
        network: NetworkId,
    ) -> Result<Self> {
        validate_core_config(rpc_url, cookie_file)?;
        validate_core_wallet_name(wallet_name)?;
        let wallet_url = wallet_rpc_url(rpc_url, wallet_name)?;
        let client = BitcoinClient::new(&wallet_url, Auth::CookieFile(cookie_file.to_owned()))
            .context("create Bitcoin Core RPC client")?;
        Ok(Self {
            client,
            wallet_name: wallet_name.to_owned(),
            network,
        })
    }

    pub fn prepare_funding(
        &self,
        keys: &CoinKeys,
        amount_sat: u64,
        fee_rate_sat_vb: u64,
        max_fee_sat: u64,
    ) -> Result<PreparedFunding> {
        self.verify_wallet()?;
        ensure!(fee_rate_sat_vb > 0, "funding fee rate must be positive");
        ensure!(
            amount_sat <= Amount::MAX_MONEY.to_sat(),
            "funding amount exceeds Bitcoin MAX_MONEY"
        );
        let address = funding_address(keys, self.network).to_string();
        let outputs =
            serde_json::Map::from_iter([(address, json!(Amount::from_sat(amount_sat).to_btc()))]);
        let funded: bitcoincore_rpc::json::WalletCreateFundedPsbtResult = self
            .client
            .call(
                "walletcreatefundedpsbt",
                &[
                    json!([]),
                    outputs.into(),
                    json!(0),
                    json!({
                        "add_inputs": true,
                        "include_unsafe": false,
                        "minconf": 1,
                        "lockUnspents": true,
                        "fee_rate": fee_rate_sat_vb,
                        "replaceable": false,
                    }),
                    json!(false),
                ],
            )
            .context("create unbroadcast funding PSBT")?;
        let fee_sat = funded.fee.to_sat();
        ensure!(
            fee_sat <= max_fee_sat,
            "funding fee {fee_sat} sat exceeds maximum {max_fee_sat} sat"
        );
        let processed = self
            .client
            .wallet_process_psbt(&funded.psbt, Some(true), None, Some(false))
            .context("sign funding PSBT with Bitcoin Core wallet")?;
        ensure!(
            processed.complete,
            "Bitcoin Core did not completely sign the funding PSBT"
        );
        let finalized = self
            .client
            .finalize_psbt(&processed.psbt, Some(true))
            .context("finalize funding PSBT")?;
        ensure!(
            finalized.complete,
            "Bitcoin Core did not completely finalize the funding PSBT"
        );
        let bytes = finalized
            .hex
            .context("finalized funding PSBT has no transaction")?;
        let transaction: Transaction =
            deserialize(&bytes).context("Bitcoin Core returned an invalid funding transaction")?;
        validate_funding_inputs(&transaction)?;

        let script = funding_script(keys);
        let matching: Vec<_> = transaction
            .output
            .iter()
            .enumerate()
            .filter(|(_, output)| output.script_pubkey == script)
            .collect();
        ensure!(
            matching.len() == 1,
            "funding transaction must contain exactly one Tinylayer output"
        );
        let (vout, output) = matching[0];
        ensure!(
            output.value == Amount::from_sat(amount_sat),
            "funding transaction changed the Tinylayer output amount"
        );
        let outpoint = OutPoint::new(
            transaction.compute_txid(),
            u32::try_from(vout).context("funding output index exceeds u32")?,
        );
        self.test_prepared_funding(&transaction, Some(funded.fee))?;
        Ok(PreparedFunding {
            transaction,
            outpoint,
            fee_sat,
        })
    }

    pub fn validate_prepared_funding(
        &self,
        metadata: &CoinMetadata,
        transaction: &Transaction,
    ) -> Result<()> {
        self.verify_wallet()?;
        validate_finalized_funding(metadata, transaction)?;
        self.ensure_inputs_locked(transaction)?;
        self.test_prepared_funding(transaction, None)
    }

    pub fn broadcast_funding(
        &self,
        metadata: &CoinMetadata,
        transaction: &Transaction,
    ) -> Result<bitcoin::Txid> {
        self.verify_wallet()?;
        validate_finalized_funding(metadata, transaction)?;
        let expected = transaction.compute_txid();
        match self.funding_transaction_state(transaction)? {
            FundingTransactionState::Known => return Ok(expected),
            FundingTransactionState::Unknown => self.ensure_inputs_locked(transaction)?,
            FundingTransactionState::Evicted => {}
        }
        self.test_prepared_funding(transaction, None)?;
        match self.client.send_raw_transaction(transaction) {
            Ok(txid) => {
                ensure!(
                    txid == expected,
                    "Bitcoin Core returned the wrong funding txid"
                );
                Ok(txid)
            }
            Err(error) => {
                if matches!(
                    self.funding_transaction_state(transaction)?,
                    FundingTransactionState::Known
                ) {
                    Ok(expected)
                } else {
                    Err(error).context("broadcast funding transaction")
                }
            }
        }
    }

    fn verify_wallet(&self) -> Result<()> {
        let info: WalletInfo = self
            .client
            .call("getwalletinfo", &[])
            .context("query Bitcoin Core funding wallet")?;
        ensure!(
            info.wallet_name == self.wallet_name,
            "Bitcoin Core opened wallet {}, expected {}",
            info.wallet_name,
            self.wallet_name
        );
        ensure!(
            info.private_keys_enabled,
            "Bitcoin Core funding wallet has private keys disabled"
        );
        Ok(())
    }

    fn ensure_inputs_locked(&self, transaction: &Transaction) -> Result<()> {
        let inputs: Vec<_> = transaction
            .input
            .iter()
            .map(|input| {
                json!({
                    "txid": input.previous_output.txid,
                    "vout": input.previous_output.vout,
                })
            })
            .collect();
        let locked: bool = self
            .client
            .call("lockunspent", &[json!(false), json!(inputs), json!(true)])
            .context("persistently lock funding transaction inputs")?;
        ensure!(locked, "Bitcoin Core did not lock every funding input");
        Ok(())
    }

    fn test_prepared_funding(
        &self,
        transaction: &Transaction,
        expected_fee: Option<Amount>,
    ) -> Result<()> {
        let results = self
            .client
            .test_mempool_accept(&[transaction])
            .context("test unbroadcast funding transaction")?;
        let result = results
            .first()
            .context("Bitcoin Core returned no funding mempool result")?;
        ensure!(
            results.len() == 1 && result.txid == transaction.compute_txid(),
            "Bitcoin Core returned a mismatched funding mempool result"
        );
        ensure!(
            result.allowed,
            "funding transaction is not mempool-acceptable: {}",
            result.reject_reason.as_deref().unwrap_or("unknown reason")
        );
        if let Some(expected_fee) = expected_fee {
            ensure!(
                result.fees.as_ref().map(|fees| fees.base) == Some(expected_fee),
                "Bitcoin Core funding fee changed during finalization"
            );
        }
        Ok(())
    }

    fn funding_transaction_state(
        &self,
        transaction: &Transaction,
    ) -> Result<FundingTransactionState> {
        let txid = transaction.compute_txid();
        let result: WalletTransaction = match self.client.call("gettransaction", &[json!(txid)]) {
            Ok(result) => result,
            Err(error) if is_rpc_not_found(&error) => {
                return Ok(FundingTransactionState::Unknown);
            }
            Err(error) => return Err(error).context("query Bitcoin Core funding transaction"),
        };
        ensure!(
            result.txid == txid,
            "Bitcoin Core returned a mismatched funding transaction"
        );
        let observed: Transaction = deserialize(
            &hex::decode(&result.hex).context("Bitcoin Core returned invalid funding hex")?,
        )
        .context("Bitcoin Core returned an invalid funding transaction")?;
        ensure!(
            &observed == transaction,
            "Bitcoin Core funding transaction bytes do not match the journal"
        );
        ensure!(
            result.confirmations >= 0 && result.walletconflicts.is_empty(),
            "funding transaction is conflicted"
        );
        if result.confirmations > 0 {
            return Ok(FundingTransactionState::Known);
        }
        match self
            .client
            .call::<serde_json::Value>("getmempoolentry", &[json!(txid)])
        {
            Ok(_) => Ok(FundingTransactionState::Known),
            Err(error) if is_rpc_not_found(&error) => Ok(FundingTransactionState::Evicted),
            Err(error) => Err(error).context("query Bitcoin Core funding mempool entry"),
        }
    }

    pub fn verify_funding(
        &self,
        metadata: &CoinMetadata,
        minimum_confirmations: u32,
    ) -> Result<FundingObservation> {
        let mut chain = self.chain_info()?;
        let result = self
            .client
            .get_tx_out(&metadata.outpoint.txid, metadata.outpoint.vout, Some(true))
            .context("query funding UTXO")?
            .context("funding output is spent or missing")?;
        if result.bestblock != chain.best_block_hash {
            chain = self.chain_info()?;
        }
        ensure!(
            result.bestblock == chain.best_block_hash,
            "Bitcoin Core funding observation is not from the current best block"
        );
        ensure!(
            result.confirmations >= minimum_confirmations,
            "funding output has {} confirmations; {} required",
            result.confirmations,
            minimum_confirmations
        );
        ensure!(
            !result.coinbase || result.confirmations >= 100,
            "coinbase funding output is not mature"
        );
        let output = TxOut {
            value: result.value,
            script_pubkey: result
                .script_pub_key
                .script()
                .context("Bitcoin Core returned an invalid funding script")?,
        };
        verify_funding_utxo(metadata, metadata.outpoint, &output)?;
        Ok(FundingObservation {
            tip_height: u32::try_from(chain.blocks)
                .context("Bitcoin Core block height exceeds u32")?,
            confirmations: result.confirmations,
        })
    }

    pub fn tip_height(&self) -> Result<u32> {
        u32::try_from(self.chain_info()?.blocks).context("Bitcoin Core block height exceeds u32")
    }

    pub fn submit_package(&self, parent_hex: &str, child_hex: &str) -> Result<()> {
        let response: serde_json::Value = self
            .client
            .call("submitpackage", &[json!([parent_hex, child_hex])])
            .context("submit recovery package")?;
        let message = response
            .get("package_msg")
            .and_then(serde_json::Value::as_str)
            .unwrap_or_default();
        ensure!(
            message == "success",
            "recovery package was not accepted: {response}"
        );
        Ok(())
    }

    fn chain_info(&self) -> Result<ChainInfo> {
        let info: ChainInfo = self
            .client
            .call("getblockchaininfo", &[])
            .context("query Bitcoin Core chain")?;
        ensure!(
            info.chain == network_name(self.network),
            "Bitcoin Core is on {}, expected {}",
            info.chain,
            network_name(self.network)
        );
        Ok(info)
    }
}

fn is_rpc_not_found(error: &bitcoincore_rpc::Error) -> bool {
    matches!(
        error,
        bitcoincore_rpc::Error::JsonRpc(bitcoincore_rpc::jsonrpc::Error::Rpc(error))
            if error.code == -5
    )
}

fn validate_funding_inputs(transaction: &Transaction) -> Result<()> {
    ensure!(
        !transaction.input.is_empty(),
        "funding transaction has no inputs"
    );
    for input in &transaction.input {
        ensure!(
            !input.previous_output.is_null(),
            "funding transaction cannot spend a coinbase input"
        );
        ensure!(
            input.script_sig.is_empty() && !input.witness.is_empty(),
            "funding transaction must use only native SegWit or Taproot inputs"
        );
        ensure!(
            !input.sequence.is_rbf(),
            "funding transaction inputs must not signal replace-by-fee"
        );
    }
    Ok(())
}

fn validate_finalized_funding(metadata: &CoinMetadata, transaction: &Transaction) -> Result<()> {
    validate_funding_inputs(transaction)?;
    ensure!(
        transaction.compute_txid() == metadata.outpoint.txid,
        "prepared funding transaction txid does not match coin metadata"
    );
    let expected_script = funding_script(&metadata.keys);
    ensure!(
        transaction
            .output
            .iter()
            .filter(|output| output.script_pubkey == expected_script)
            .count()
            == 1,
        "funding transaction must contain exactly one Tinylayer output"
    );
    let output = transaction
        .output
        .get(metadata.outpoint.vout as usize)
        .context("prepared funding output index is missing")?;
    verify_funding_utxo(metadata, metadata.outpoint, output)?;
    Ok(())
}

pub fn validate_core_config(rpc_url: &str, cookie_file: &Path) -> Result<()> {
    let url = reqwest::Url::parse(rpc_url).context("invalid Bitcoin Core RPC URL")?;
    ensure!(
        url.scheme() == "http",
        "Bitcoin Core RPC URL must use local HTTP"
    );
    ensure!(
        url.username().is_empty() && url.password().is_none(),
        "Bitcoin Core RPC URL cannot contain credentials"
    );
    ensure!(
        url.query().is_none() && url.fragment().is_none(),
        "Bitcoin Core RPC URL cannot contain a query or fragment"
    );
    ensure!(
        url.path() == "/" || url.path().is_empty(),
        "Bitcoin Core RPC URL cannot contain a path; use --bitcoin-wallet"
    );
    let host = url.host_str().context("Bitcoin Core RPC URL has no host")?;
    ensure!(
        host.parse::<IpAddr>()
            .is_ok_and(|address| address.is_loopback()),
        "Bitcoin Core RPC is restricted to a numeric loopback address"
    );
    let metadata = fs::symlink_metadata(cookie_file)
        .with_context(|| format!("inspect Bitcoin Core cookie {}", cookie_file.display()))?;
    ensure!(
        metadata.is_file() && !metadata.file_type().is_symlink(),
        "Bitcoin Core cookie must be a regular file"
    );
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt as _;
        ensure!(
            metadata.permissions().mode() & 0o077 == 0,
            "Bitcoin Core cookie is accessible by group or other users"
        );
    }
    Ok(())
}

pub fn validate_core_wallet_name(wallet_name: &str) -> Result<()> {
    ensure!(
        !wallet_name.trim().is_empty() && wallet_name == wallet_name.trim(),
        "Bitcoin Core wallet name cannot be empty or surrounded by whitespace"
    );
    Ok(())
}

fn wallet_rpc_url(rpc_url: &str, wallet_name: &str) -> Result<String> {
    let mut url = reqwest::Url::parse(rpc_url).context("invalid Bitcoin Core RPC URL")?;
    url.path_segments_mut()
        .map_err(|_| anyhow::anyhow!("Bitcoin Core RPC URL cannot be a base URL"))?
        .clear()
        .push("wallet")
        .push(wallet_name);
    Ok(url.into())
}

pub fn validate_explorer_url(value: &str) -> Result<()> {
    let url = reqwest::Url::parse(value).context("invalid explorer URL")?;
    let loopback = url.host_str().is_some_and(|host| {
        host.eq_ignore_ascii_case("localhost")
            || host
                .parse::<IpAddr>()
                .is_ok_and(|address| address.is_loopback())
    });
    ensure!(
        url.scheme() == "https" || (url.scheme() == "http" && loopback),
        "explorer URL must use HTTPS (plain HTTP is loopback-only)"
    );
    ensure!(
        url.username().is_empty() && url.password().is_none(),
        "explorer URL cannot contain credentials"
    );
    ensure!(
        url.query().is_none() && url.fragment().is_none(),
        "explorer URL cannot contain a query or fragment"
    );
    Ok(())
}

pub fn verify_public_history(
    metadata: &CoinMetadata,
    status: &CoinStatus,
    history: &[SignedRecovery],
    funding_confirmations: u32,
    minimum_reaction_blocks: u32,
) -> Result<()> {
    verify_status(&metadata.keys, status)?;
    ensure!(
        status.signature_count == history.len() as u64,
        "recovery history does not match enclave signature count"
    );
    ensure!(!history.is_empty(), "coin has no signed recovery");
    for recovery in history {
        verify_recovery(metadata, recovery)?;
    }
    for pair in history.windows(2) {
        validate_reaction_window(
            funding_confirmations,
            pair[0].delay_blocks,
            pair[1].delay_blocks,
        )?;
    }
    require_reaction_margin(
        funding_confirmations,
        history
            .last()
            .expect("history checked non-empty")
            .delay_blocks,
        minimum_reaction_blocks,
    )
}

pub fn require_reaction_margin(
    funding_confirmations: u32,
    delay_blocks: u32,
    minimum_reaction_blocks: u32,
) -> Result<()> {
    let minimum = funding_confirmations
        .checked_add(minimum_reaction_blocks)
        .context("reaction margin overflow")?;
    ensure!(
        delay_blocks > minimum,
        "latest recovery delay {delay_blocks} must be greater than funding confirmations {funding_confirmations} plus reaction margin {minimum_reaction_blocks}"
    );
    Ok(())
}

pub fn network_name(network: NetworkId) -> &'static str {
    match network {
        NetworkId::Mutinynet => "mutinynet",
        NetworkId::Mainnet => "mainnet",
        NetworkId::Regtest => "regtest",
    }
}

fn validate_plaintext_url(value: &str) -> Result<()> {
    let url = reqwest::Url::parse(value).context("invalid plaintext enclave URL")?;
    ensure!(
        url.scheme() == "http",
        "plaintext test enclave URL must use http"
    );
    ensure!(
        url.username().is_empty() && url.password().is_none(),
        "enclave URL cannot contain credentials"
    );
    ensure!(
        url.path() == "/" || url.path().is_empty(),
        "enclave URL cannot contain a path"
    );
    let host = url
        .host_str()
        .context("plaintext enclave URL has no host")?;
    let loopback = host.eq_ignore_ascii_case("localhost")
        || host
            .parse::<IpAddr>()
            .is_ok_and(|address| address.is_loopback());
    ensure!(
        loopback,
        "plaintext enclave transport is restricted to loopback"
    );
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use bitcoin::{
        Sequence, TxIn, Witness, absolute, hashes::Hash as _, secp256k1::SecretKey,
        transaction::Version,
    };

    #[tokio::test]
    async fn mainnet_has_no_default_and_chain_connection_fails_closed() {
        assert!(default_explorer_url(NetworkId::Mainnet).is_none());
        let config = ChainConfig::Explorer {
            url: "https://mempool.space/api".into(),
        };
        let error = Chain::connect(&config, NetworkId::Mainnet)
            .await
            .err()
            .expect("mainnet must be rejected before connecting");
        assert_eq!(error.to_string(), "mainnet is not supported by this wallet");
    }

    #[test]
    fn finalized_funding_requires_stable_native_segwit_inputs_and_one_exact_output() {
        let secp = bitcoin::secp256k1::Secp256k1::new();
        let keys = CoinKeys {
            protocol_version: tinylayer_client::PROTOCOL_VERSION,
            coin_id: [1; 32],
            client_pubkey: SecretKey::from_slice(&[2; 32])
                .unwrap()
                .x_only_public_key(&secp)
                .0,
            enclave_pubkey: SecretKey::from_slice(&[3; 32])
                .unwrap()
                .x_only_public_key(&secp)
                .0,
        };
        let mut witness = Witness::new();
        witness.push([4; 64]);
        let transaction = Transaction {
            version: Version::TWO,
            lock_time: absolute::LockTime::ZERO,
            input: vec![TxIn {
                previous_output: OutPoint::new(bitcoin::Txid::from_byte_array([5; 32]), 0),
                script_sig: ScriptBuf::new(),
                sequence: Sequence::MAX,
                witness,
            }],
            output: vec![TxOut {
                value: Amount::from_sat(100_000),
                script_pubkey: funding_script(&keys),
            }],
        };
        let metadata = keys.clone().metadata(
            NetworkId::Regtest,
            OutPoint::new(transaction.compute_txid(), 0),
            100_000,
        );
        validate_finalized_funding(&metadata, &transaction).unwrap();

        let mut legacy = transaction.clone();
        legacy.input[0].script_sig = ScriptBuf::from_bytes(vec![1]);
        assert!(validate_finalized_funding(&metadata, &legacy).is_err());

        let mut witnessless = transaction.clone();
        witnessless.input[0].witness = Witness::new();
        assert!(validate_finalized_funding(&metadata, &witnessless).is_err());

        let mut replaceable = transaction.clone();
        replaceable.input[0].sequence = Sequence::ENABLE_RBF_NO_LOCKTIME;
        assert!(validate_finalized_funding(&metadata, &replaceable).is_err());

        let mut duplicate = transaction.clone();
        duplicate.output.push(duplicate.output[0].clone());
        let duplicate_metadata = keys.metadata(
            NetworkId::Regtest,
            OutPoint::new(duplicate.compute_txid(), 0),
            100_000,
        );
        assert!(validate_finalized_funding(&duplicate_metadata, &duplicate).is_err());
    }

    #[test]
    fn reaction_margin_is_strict_and_checked() {
        assert!(require_reaction_margin(79, 100, 20).is_ok());
        assert!(require_reaction_margin(80, 100, 20).is_err());
        assert!(require_reaction_margin(81, 100, 20).is_err());
        assert!(require_reaction_margin(u32::MAX, u32::MAX, 1).is_err());
    }
}
