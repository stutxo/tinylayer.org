use std::{
    collections::HashSet,
    path::{Path, PathBuf},
    str::FromStr as _,
};

use anyhow::{Context as _, Result, bail, ensure};
use bitcoin::{Address, OutPoint, consensus::encode::serialize_hex, secp256k1::SecretKey};
use clap::{Args, Parser, Subcommand, ValueEnum};
use enclavia::Pcrs;
use serde_json::{Value, json};
use tinylayer_client::{
    DELAY_STEP, INITIAL_HANDOFF, NetworkId, PROTOCOL_VERSION, authorization, build_exit_child,
    capability_hash, funding_address, funding_script, prepare_recovery, validate_production_pcrs,
    verify_history, verify_recovery, verify_status,
};

use crate::{
    model::{
        ChainConfig, Config, EnclaveConfig, ExitJournal, ExitStage, FILE_FORMAT_VERSION,
        FundingJournal, FundingStage, PendingOperation, PendingRecovery, Receipt, RecoveryAttempt,
        RecoveryPurpose, RecoveryStage, SourceSweepJournal, SourceSweepStage, TransferEnvelope,
        TransferRequest, WalletCoin, WalletState, attempt_committed, attempt_uncommitted,
        build_source_funding, decrypt_transfer, parse_hex32, random_secret_key, secret_xonly,
        source_funding_address, verify_exit_funding,
    },
    services::{
        Chain, EnclaveConnection, default_explorer_url, network_name, require_reaction_margin,
        validate_core_config, validate_core_wallet_name, validate_explorer_url,
        verify_public_history,
    },
    store::{
        WalletStore, ensure_destination_available, load_config, read_json_source, read_password,
        write_json_destination, write_text_destination,
    },
};

const DEFAULT_RECOVERY_DELAY_BLOCKS: u32 = 2_016;

#[derive(Debug, Parser)]
#[command(name = "tinylayer-wallet", version, about = "Tinylayer native wallet")]
pub struct Cli {
    #[arg(long, value_name = "DIR")]
    pub data_dir: PathBuf,
    #[arg(long, value_name = "FILE")]
    pub password_file: Option<PathBuf>,
    #[arg(long)]
    pub json: bool,
    #[command(subcommand)]
    command: Command,
}

#[derive(Debug, Subcommand)]
enum Command {
    Init(InitArgs),
    Enclave {
        #[command(subcommand)]
        command: EnclaveCommand,
    },
    Coin {
        #[command(subcommand)]
        command: CoinCommand,
    },
    Transfer {
        #[command(subcommand)]
        command: TransferCommand,
    },
    Receipt {
        #[command(subcommand)]
        command: ReceiptCommand,
    },
}

#[derive(Clone, Copy, Debug, ValueEnum)]
enum NetworkArg {
    Regtest,
    Mutinynet,
}

impl From<NetworkArg> for NetworkId {
    fn from(value: NetworkArg) -> Self {
        match value {
            NetworkArg::Regtest => Self::Regtest,
            NetworkArg::Mutinynet => Self::Mutinynet,
        }
    }
}

#[derive(Debug, Args)]
struct InitArgs {
    #[arg(long, value_enum, default_value_t = NetworkArg::Mutinynet)]
    network: NetworkArg,
    #[arg(long)]
    enclave_url: String,
    #[arg(long)]
    pcr0: Option<String>,
    #[arg(long)]
    pcr1: Option<String>,
    #[arg(long)]
    pcr2: Option<String>,
    #[arg(long, conflicts_with = "unsafe_plaintext")]
    debug_attestation: bool,
    #[arg(long)]
    unsafe_plaintext: bool,
    /// Esplora-compatible explorer API; defaults to the network's public explorer.
    #[arg(long)]
    chain_url: Option<String>,
    /// Local Bitcoin Core RPC, regtest functional tests only.
    #[arg(long)]
    bitcoin_rpc_url: Option<String>,
    #[arg(long, value_name = "FILE")]
    bitcoin_cookie_file: Option<PathBuf>,
    /// Loaded Bitcoin Core wallet used to construct and broadcast funding.
    #[arg(long)]
    bitcoin_wallet: Option<String>,
    #[arg(long, default_value_t = 6)]
    min_confirmations: u32,
    #[arg(long, default_value_t = 20)]
    min_reaction_blocks: u32,
}

#[derive(Debug, Subcommand)]
enum EnclaveCommand {
    Verify,
}

#[derive(Debug, Subcommand)]
enum CoinCommand {
    /// Show the stable P2TR address used to deposit funding sats.
    DepositAddress,
    Register,
    Fund {
        #[arg(long)]
        amount_sat: u64,
        #[arg(long, default_value_t = DEFAULT_RECOVERY_DELAY_BLOCKS)]
        delay_blocks: u32,
        #[arg(long, value_name = "SAT_VB", default_value_t = 1)]
        fee_rate: u64,
        #[arg(long, value_name = "SAT")]
        max_fee_sat: u64,
    },
    Status,
    Sign {
        #[arg(long, value_name = "FILE")]
        request: PathBuf,
        #[arg(long, value_name = "FILE")]
        output: PathBuf,
    },
    Recovery {
        #[arg(long, value_name = "FILE")]
        output: PathBuf,
    },
    /// Sweep up to 100 unreserved confirmed deposit outputs to one address.
    SourceSweep {
        #[arg(long)]
        destination: String,
        #[arg(long, value_name = "SAT_VB", default_value_t = 1)]
        fee_rate: u64,
        #[arg(long, value_name = "SAT")]
        max_fee_sat: u64,
    },
    /// Broadcast the owned zero-fee recovery with a fee-paying TRUC child.
    Exit {
        #[arg(long)]
        destination: String,
        #[arg(long, value_name = "SAT_VB")]
        fee_rate: Option<u64>,
        #[arg(long, value_name = "SAT")]
        max_fee_sat: u64,
        /// Build and verify the package without submitting it.
        #[arg(long)]
        dry_run: bool,
    },
}

#[derive(Debug, Subcommand)]
enum TransferCommand {
    /// Create a request whose exact bytes or hash require an authenticated receiver channel.
    Request {
        #[arg(long)]
        coin_id: String,
        #[arg(long)]
        outpoint: OutPoint,
        #[arg(long)]
        amount_sat: u64,
        #[arg(long, value_name = "FILE")]
        output: PathBuf,
        #[arg(long)]
        min_reaction_blocks: Option<u32>,
    },
    Accept {
        #[arg(long, value_name = "FILE")]
        request: PathBuf,
        #[arg(long, value_name = "FILE")]
        package: PathBuf,
    },
}

#[derive(Debug, Subcommand)]
enum ReceiptCommand {
    Export {
        #[arg(long, value_name = "FILE")]
        output: PathBuf,
    },
    Verify {
        #[arg(long, value_name = "FILE")]
        input: PathBuf,
    },
}

pub async fn run(cli: Cli) -> Result<()> {
    let Cli {
        data_dir,
        password_file,
        json,
        command,
    } = cli;
    match command {
        Command::Init(args) => initialize(&data_dir, password_file.as_deref(), json, args).await,
        Command::Enclave {
            command: EnclaveCommand::Verify,
        } => verify_enclave(&data_dir, json).await,
        Command::Coin { command } => match command {
            CoinCommand::DepositAddress => {
                deposit_address(&data_dir, password_file.as_deref(), json)
            }
            CoinCommand::Register => register_coin(&data_dir, password_file.as_deref(), json).await,
            CoinCommand::Fund {
                amount_sat,
                delay_blocks,
                fee_rate,
                max_fee_sat,
            } => {
                fund_coin(
                    &data_dir,
                    password_file.as_deref(),
                    json,
                    amount_sat,
                    delay_blocks,
                    fee_rate,
                    max_fee_sat,
                )
                .await
            }
            CoinCommand::Status => coin_status(&data_dir, password_file.as_deref(), json).await,
            CoinCommand::Sign { request, output } => {
                sign_transfer(&data_dir, password_file.as_deref(), json, &request, &output).await
            }
            CoinCommand::Recovery { output } => {
                export_recovery(&data_dir, password_file.as_deref(), json, &output).await
            }
            CoinCommand::SourceSweep {
                destination,
                fee_rate,
                max_fee_sat,
            } => {
                source_sweep(
                    &data_dir,
                    password_file.as_deref(),
                    json,
                    &destination,
                    fee_rate,
                    max_fee_sat,
                )
                .await
            }
            CoinCommand::Exit {
                destination,
                fee_rate,
                max_fee_sat,
                dry_run,
            } => {
                exit_coin(
                    &data_dir,
                    password_file.as_deref(),
                    json,
                    &destination,
                    fee_rate,
                    max_fee_sat,
                    dry_run,
                )
                .await
            }
        },
        Command::Transfer { command } => match command {
            TransferCommand::Request {
                coin_id,
                outpoint,
                amount_sat,
                output,
                min_reaction_blocks,
            } => create_transfer_request(
                &data_dir,
                password_file.as_deref(),
                json,
                &coin_id,
                outpoint,
                amount_sat,
                min_reaction_blocks,
                &output,
            ),
            TransferCommand::Accept { request, package } => {
                accept_transfer(
                    &data_dir,
                    password_file.as_deref(),
                    json,
                    &request,
                    &package,
                )
                .await
            }
        },
        Command::Receipt { command } => match command {
            ReceiptCommand::Export { output } => {
                export_receipt(&data_dir, password_file.as_deref(), json, &output).await
            }
            ReceiptCommand::Verify { input } => {
                verify_receipt(&data_dir, password_file.as_deref(), json, &input).await
            }
        },
    }
}

async fn initialize(
    directory: &Path,
    password_file: Option<&Path>,
    json_output: bool,
    args: InitArgs,
) -> Result<()> {
    ensure!(
        args.min_confirmations > 0,
        "minimum confirmations must be positive"
    );
    ensure!(
        args.min_reaction_blocks >= DELAY_STEP,
        "minimum reaction margin must be at least {DELAY_STEP} blocks"
    );
    let network = NetworkId::from(args.network);
    let enclave = if args.unsafe_plaintext {
        ensure!(
            network == NetworkId::Regtest,
            "plaintext transport is regtest-only"
        );
        ensure!(
            args.pcr0.is_none() && args.pcr1.is_none() && args.pcr2.is_none(),
            "PCR values are not used with plaintext test transport"
        );
        let config = EnclaveConfig::UnsafePlaintext {
            url: args.enclave_url,
        };
        EnclaveConnection::connect(&config).await?;
        config
    } else {
        let (pcr0, pcr1, pcr2) = required_pcrs(args.pcr0, args.pcr1, args.pcr2)?;
        let pcrs = Pcrs::from_hex(&pcr0, &pcr1, &pcr2).context("invalid PCR policy")?;
        if args.debug_attestation {
            ensure!(
                network == NetworkId::Regtest,
                "debug attestation is regtest-only"
            );
            EnclaveConfig::Debug {
                url: args.enclave_url,
                pcr0,
                pcr1,
                pcr2,
            }
        } else {
            validate_production_pcrs(&pcrs).context("invalid production PCR policy")?;
            EnclaveConfig::Production {
                url: args.enclave_url,
                pcr0,
                pcr1,
                pcr2,
            }
        }
    };
    let chain = match (
        args.chain_url,
        args.bitcoin_rpc_url,
        args.bitcoin_cookie_file,
        args.bitcoin_wallet,
    ) {
        (Some(url), None, None, None) => {
            validate_explorer_url(&url)?;
            ChainConfig::Explorer { url }
        }
        (None, Some(rpc_url), Some(cookie_file), Some(wallet_name)) => {
            ensure!(
                network == NetworkId::Regtest,
                "Bitcoin Core RPC is restricted to regtest"
            );
            validate_core_config(&rpc_url, &cookie_file)?;
            validate_core_wallet_name(&wallet_name)?;
            ChainConfig::CoreRpc {
                rpc_url,
                cookie_file,
                wallet_name,
            }
        }
        (None, None, None, None) => {
            let url = default_explorer_url(network)
                .context("regtest requires --chain-url or Bitcoin Core RPC options")?
                .to_owned();
            ChainConfig::Explorer { url }
        }
        _ => bail!(
            "--chain-url cannot be combined with Bitcoin Core options; Core requires --bitcoin-rpc-url, --bitcoin-cookie-file, and --bitcoin-wallet"
        ),
    };
    let config = Config {
        format_version: FILE_FORMAT_VERSION,
        protocol_version: PROTOCOL_VERSION,
        network,
        enclave,
        chain,
        min_confirmations: args.min_confirmations,
        min_reaction_blocks: args.min_reaction_blocks,
    };
    let password = read_password(password_file, true)?;
    WalletStore::initialize(directory, &config, password)?;
    emit(
        json_output,
        json!({
            "status": "initialized",
            "data_dir": directory,
            "network": network_name(network),
            "enclave_mode": config.enclave.mode_name(),
        }),
        format!(
            "Initialized {} wallet at {} using {} enclave transport",
            network_name(network),
            directory.display(),
            config.enclave.mode_name()
        ),
    )
}

async fn verify_enclave(directory: &Path, json_output: bool) -> Result<()> {
    let config = load_config(directory)?;
    connect_verified(&config).await?;
    emit(
        json_output,
        json!({
            "status": "verified",
            "url": config.enclave.url(),
            "mode": config.enclave.mode_name(),
            "client_protocol_version": PROTOCOL_VERSION,
        }),
        format!(
            "Verified {} enclave connection and health at {} (client expects protocol v{})",
            config.enclave.mode_name(),
            config.enclave.url(),
            PROTOCOL_VERSION
        ),
    )
}

fn deposit_address(
    directory: &Path,
    password_file: Option<&Path>,
    json_output: bool,
) -> Result<()> {
    let (store, config) = open_wallet(directory, password_file)?;
    ensure!(
        matches!(config.chain, ChainConfig::Explorer { .. }),
        "local deposit funding requires an explorer backend"
    );
    let native = store.load_native()?;
    let address = source_funding_address(&native.funding_secret, config.network);
    emit(
        json_output,
        json!({
            "status": "deposit_address",
            "address": address.to_string(),
            "network": network_name(config.network),
        }),
        format!("Deposit address: {address}"),
    )
}

async fn register_coin(
    directory: &Path,
    password_file: Option<&Path>,
    json_output: bool,
) -> Result<()> {
    let (store, config) = open_wallet(directory, password_file)?;
    let mut state = store.load()?;
    if let Some(coin) = &state.coin {
        ensure!(state.pending.is_none(), "wallet has a pending operation");
        ensure!(
            coin.metadata.is_none()
                && coin.history.is_empty()
                && coin.current_capability.is_some()
                && coin.current_handoff == Some(INITIAL_HANDOFF)
                && coin.outgoing.is_none(),
            "coin has already left the registration stage"
        );
        let enclave = connect_verified(&config).await?;
        let status = enclave.status(coin.keys.coin_id).await?;
        coin.verify_live_status(&status)?;
        return emit_registration(json_output, &config, coin, true);
    }
    let enclave = connect_verified(&config).await?;
    let request = match state.pending.as_ref() {
        None => {
            let request = state.begin_registration()?;
            store.save(&state)?;
            request
        }
        Some(PendingOperation::Registration { registration, .. }) => registration.request.clone(),
        Some(PendingOperation::Recovery(_)) => {
            bail!("wallet has a pending signing operation; resume that command first");
        }
    };
    let status = enclave.register(&request).await?;
    state.complete_registration(&status)?;
    store.save(&state)?;
    emit_registration(
        json_output,
        &config,
        state.coin.as_ref().expect("coin inserted"),
        false,
    )
}

async fn fund_coin(
    directory: &Path,
    password_file: Option<&Path>,
    json_output: bool,
    amount_sat: u64,
    delay_blocks: u32,
    fee_rate_sat_vb: u64,
    max_fee_sat: u64,
) -> Result<()> {
    ensure!(
        u16::try_from(delay_blocks).is_ok(),
        "recovery delay cannot exceed {} blocks",
        u16::MAX
    );
    require_reaction_margin(0, delay_blocks, 0)?;
    let (store, config) = open_wallet(directory, password_file)?;
    if matches!(&config.chain, ChainConfig::Explorer { .. }) {
        return fund_coin_explorer(
            &store,
            &config,
            json_output,
            amount_sat,
            delay_blocks,
            fee_rate_sat_vb,
            max_fee_sat,
        )
        .await;
    }
    let mut state = store.load()?;
    let funding_stage_at_start = state
        .coin
        .as_ref()
        .and_then(|coin| coin.funding.as_ref())
        .map(|funding| funding.stage);
    let needs_enclave = match state.pending.as_ref() {
        Some(_) => true,
        None => {
            funding_stage_at_start.is_none()
                || funding_stage_at_start == Some(FundingStage::Prepared)
        }
    };
    let enclave = if needs_enclave {
        Some(connect_verified(&config).await?)
    } else {
        None
    };
    let chain = Chain::connect(&config.chain, config.network).await?;
    if state
        .coin
        .as_ref()
        .context("register a coin first")?
        .funding
        .is_none()
    {
        ensure!(state.pending.is_none(), "wallet has a pending operation");
        let coin = state.coin.as_ref().expect("coin checked above");
        ensure!(
            coin.current_capability.is_some()
                && coin.current_handoff == Some(INITIAL_HANDOFF)
                && coin.metadata.is_none()
                && coin.history.is_empty(),
            "coin has already left the registration stage"
        );
        let enclave = enclave.as_ref().context("funding requires the enclave")?;
        let status = enclave.status(coin.keys.coin_id).await?;
        verify_status(&coin.keys, &status)?;
        let capability = coin.current_capability.expect("capability checked above");
        ensure!(
            status.signature_count == 0
                && status.authorization
                    == authorization(
                        &coin.keys.coin_id,
                        &capability_hash(&capability),
                        &INITIAL_HANDOFF,
                    ),
            "wallet authorization does not match enclave"
        );
        require_reaction_margin(0, delay_blocks, config.min_reaction_blocks)?;
        let prepared =
            chain.prepare_funding(&coin.keys, amount_sat, fee_rate_sat_vb, max_fee_sat)?;
        let metadata = coin
            .keys
            .clone()
            .metadata(config.network, prepared.outpoint, amount_sat);
        let coin = state.coin.as_mut().expect("coin checked above");
        coin.metadata = Some(metadata);
        coin.funding = Some(FundingJournal {
            transaction: prepared.transaction,
            delay_blocks,
            fee_rate_sat_vb,
            max_fee_sat,
            fee_sat: prepared.fee_sat,
            stage: FundingStage::Prepared,
        });
        store.save(&state)?;
        test_failpoint("after_funding_prepared")?;
    }

    {
        let coin = state
            .coin
            .as_ref()
            .context("prepared funding coin is missing")?;
        let metadata = coin
            .metadata
            .as_ref()
            .context("prepared funding metadata is missing")?;
        let funding = coin
            .funding
            .as_ref()
            .context("prepared funding journal is missing")?;
        ensure!(
            metadata.amount_sat == amount_sat
                && funding.delay_blocks == delay_blocks
                && funding.fee_rate_sat_vb == fee_rate_sat_vb
                && funding.max_fee_sat == max_fee_sat,
            "saved funding policy does not match this command"
        );
        ensure!(
            funding.fee_sat <= max_fee_sat,
            "saved funding fee exceeds this command's maximum"
        );
    }

    if let Some(PendingOperation::Recovery(pending)) = &state.pending {
        ensure!(
            matches!(&pending.purpose, RecoveryPurpose::Fund { .. }),
            "wallet has a pending transfer; resume coin sign"
        );
        let pending_delay = match &pending.stage {
            RecoveryStage::Prepared { attempt } => attempt.delay_blocks,
            RecoveryStage::Responded { attempt, .. } => attempt.delay_blocks,
        };
        ensure!(
            pending_delay == delay_blocks,
            "pending funding recovery uses a different delay"
        );
    } else if state.pending.is_some() {
        bail!("wallet has a pending registration; resume coin register");
    }

    let funding_stage = state
        .coin
        .as_ref()
        .and_then(|coin| coin.funding.as_ref())
        .map(|funding| funding.stage)
        .context("prepared funding journal is missing")?;
    if funding_stage == FundingStage::Prepared && state.pending.is_none() {
        let coin = state
            .coin
            .as_ref()
            .context("prepared funding coin is missing")?;
        let metadata = coin
            .metadata
            .as_ref()
            .context("prepared funding metadata is missing")?;
        let funding = coin
            .funding
            .as_ref()
            .context("prepared funding journal is missing")?;
        chain.validate_prepared_funding(metadata, &funding.transaction)?;
        let enclave = enclave.as_ref().context("funding requires the enclave")?;
        let status = enclave.status(coin.keys.coin_id).await?;
        verify_status(&coin.keys, &status)?;
        ensure!(
            status.signature_count == 0,
            "coin already has signed recoveries"
        );
        let capability = coin
            .current_capability
            .context("coin has already been transferred")?;
        let handoff = coin
            .current_handoff
            .context("registered coin has no current handoff token")?;
        ensure!(
            status.authorization
                == authorization(&coin.keys.coin_id, &capability_hash(&capability), &handoff),
            "wallet authorization does not match enclave"
        );
        let next_capability = rand::random();
        let withdrawal = random_secret_key();
        let (request, prepared) = prepare_recovery(
            metadata,
            &status,
            coin.client_secret,
            capability,
            handoff,
            capability_hash(&next_capability),
            secret_xonly(&withdrawal),
            delay_blocks,
            0,
        )?;
        state.pending = Some(PendingOperation::Recovery(PendingRecovery {
            purpose: RecoveryPurpose::Fund {
                next_capability,
                withdrawal_secret: withdrawal.secret_bytes(),
            },
            stage: RecoveryStage::Prepared {
                attempt: Box::new(RecoveryAttempt {
                    expected_signature_count: status.signature_count,
                    delay_blocks,
                    request,
                    prepared: Box::new(prepared),
                }),
            },
        }));
        store.save(&state)?;
        test_failpoint("after_prepare")?;
    }

    if state.pending.is_some() {
        finish_pending_funding_recovery(
            &store,
            &mut state,
            enclave.as_ref().context("funding requires the enclave")?,
            &config,
        )
        .await?;
    }

    let already_broadcast = state
        .coin
        .as_ref()
        .and_then(|coin| coin.funding.as_ref())
        .is_some_and(|funding| funding.stage == FundingStage::Broadcast);
    let coin = state
        .coin
        .as_ref()
        .context("secured funding coin is missing")?;
    let metadata = coin
        .metadata
        .as_ref()
        .context("secured funding metadata is missing")?;
    let funding = coin
        .funding
        .as_ref()
        .context("secured funding journal is missing")?;
    ensure!(
        matches!(
            funding.stage,
            FundingStage::RecoverySecured | FundingStage::Broadcast
        ),
        "funding cannot be broadcast before its recovery is durable"
    );
    let recovery = coin
        .history
        .first()
        .context("secured funding recovery is missing")?;
    ensure!(
        recovery.delay_blocks == funding.delay_blocks,
        "secured funding recovery has the wrong delay"
    );
    verify_recovery(metadata, recovery)?;
    let txid = chain.broadcast_funding(metadata, &funding.transaction)?;
    ensure!(
        txid == metadata.outpoint.txid,
        "broadcast funding txid does not match recovery outpoint"
    );
    if !already_broadcast {
        test_failpoint("after_funding_broadcast")?;
        state
            .coin
            .as_mut()
            .and_then(|coin| coin.funding.as_mut())
            .context("secured funding journal is missing")?
            .stage = FundingStage::Broadcast;
        store.save(&state)?;
    }

    emit_funding(
        json_output,
        state.coin.as_ref().context("funded coin is missing")?,
        already_broadcast,
    )
}

#[allow(clippy::too_many_arguments)]
async fn fund_coin_explorer(
    store: &WalletStore,
    config: &Config,
    json_output: bool,
    amount_sat: u64,
    delay_blocks: u32,
    fee_rate_sat_vb: u64,
    max_fee_sat: u64,
) -> Result<()> {
    let chain = Chain::connect(&config.chain, config.network).await?;
    let mut native = store.load_native()?;
    if native
        .wallet
        .coin
        .as_ref()
        .context("register a coin first")?
        .funding
        .is_none()
    {
        ensure!(
            native.wallet.pending.is_none(),
            "wallet has a pending operation"
        );
        let enclave = connect_verified(config).await?;
        let coin = native
            .wallet
            .coin
            .as_ref()
            .context("register a coin first")?;
        let status = enclave.status(coin.keys.coin_id).await?;
        let address = source_funding_address(&native.funding_secret, config.network);
        let sweep_inputs: HashSet<_> = native
            .source_sweep
            .as_ref()
            .into_iter()
            .flat_map(|sweep| sweep.sources.iter().map(|source| source.outpoint))
            .collect();
        let source = chain
            .confirmed_source_utxos(&address)
            .await?
            .into_iter()
            .filter(|source| !source.coinbase && !sweep_inputs.contains(&source.outpoint))
            .max_by_key(|source| (source.output.value.to_sat(), source.outpoint))
            .with_context(|| format!("deposit confirmed sats at {address} before funding"))?;
        native.wallet.begin_funding(
            config.network,
            &native.funding_secret,
            &source,
            &status,
            amount_sat,
            delay_blocks,
            fee_rate_sat_vb,
            max_fee_sat,
            config.min_reaction_blocks,
        )?;
        store.save_native(&native)?;
        test_failpoint("after_funding_prepared")?;
    }

    {
        let coin = native
            .wallet
            .coin
            .as_ref()
            .context("prepared funding coin is missing")?;
        let metadata = coin
            .metadata
            .as_ref()
            .context("prepared funding metadata is missing")?;
        let funding = coin
            .funding
            .as_ref()
            .context("prepared funding journal is missing")?;
        ensure!(
            metadata.amount_sat == amount_sat
                && funding.delay_blocks == delay_blocks
                && funding.fee_rate_sat_vb == fee_rate_sat_vb
                && funding.max_fee_sat == max_fee_sat,
            "saved funding policy does not match this command"
        );
        ensure!(
            funding.fee_sat <= max_fee_sat,
            "saved funding fee exceeds this command's maximum"
        );
        match native.wallet.pending.as_ref() {
            Some(PendingOperation::Recovery(PendingRecovery {
                purpose: RecoveryPurpose::Fund { .. },
                stage,
            })) => {
                let pending_delay = match stage {
                    RecoveryStage::Prepared { attempt }
                    | RecoveryStage::Responded { attempt, .. } => attempt.delay_blocks,
                };
                ensure!(
                    pending_delay == delay_blocks,
                    "pending funding recovery uses a different delay"
                );
            }
            Some(PendingOperation::Recovery(_)) => {
                bail!("wallet has a pending transfer; resume coin sign")
            }
            Some(PendingOperation::Registration { .. }) => {
                bail!("wallet has a pending registration; resume coin register")
            }
            None => ensure!(
                funding.stage != FundingStage::Prepared,
                "prepared funding has no recovery journal"
            ),
        }
    }

    let mut funding_enclave = None;
    if matches!(
        native.wallet.pending.as_ref(),
        Some(PendingOperation::Recovery(PendingRecovery {
            stage: RecoveryStage::Prepared { .. },
            ..
        }))
    ) {
        let enclave = connect_verified(config).await?;
        let coin = native
            .wallet
            .coin
            .as_ref()
            .context("pending funding coin is missing")?;
        let status = enclave.status(coin.keys.coin_id).await?;
        verify_status(&coin.keys, &status)?;
        let attempt = match native.wallet.pending.as_ref() {
            Some(PendingOperation::Recovery(PendingRecovery {
                purpose: RecoveryPurpose::Fund { .. },
                stage: RecoveryStage::Prepared { attempt },
            })) => attempt,
            _ => unreachable!("pending stage checked above"),
        };
        let committed = attempt_committed(&status, attempt)?;
        if !committed {
            ensure!(
                attempt_uncommitted(&status, attempt),
                "pending funding journal does not match live enclave state"
            );
            validate_explorer_prepared_funding(&native, &chain, config).await?;
        }
        let request = native.wallet.pending_sign_request()?;
        let response = enclave.sign(&request).await?;
        test_failpoint("after_sign")?;
        native.wallet.record_sign_response(response)?;
        store.save_native(&native)?;
        test_failpoint("after_response")?;
        funding_enclave = Some(enclave);
    }

    if matches!(
        native.wallet.pending.as_ref(),
        Some(PendingOperation::Recovery(PendingRecovery {
            purpose: RecoveryPurpose::Fund { .. },
            stage: RecoveryStage::Responded { .. },
        }))
    ) {
        if funding_enclave.is_none() {
            funding_enclave = Some(connect_verified(config).await?);
        }
        let enclave = funding_enclave.as_ref().expect("enclave inserted above");
        let coin_id = native
            .wallet
            .coin
            .as_ref()
            .context("pending funding coin is missing")?
            .keys
            .coin_id;
        let status = enclave.status(coin_id).await?;
        native.wallet.complete_funding_recovery(&status)?;
        store.save_native(&native)?;
        test_failpoint("after_recovery_secured")?;
    }

    let already_broadcast = native
        .wallet
        .coin
        .as_ref()
        .and_then(|coin| coin.funding.as_ref())
        .is_some_and(|funding| funding.stage == FundingStage::Broadcast);
    let transaction = native.wallet.funding_transaction()?.clone();
    let txid = chain.broadcast_exact(&transaction).await?;
    if !already_broadcast {
        test_failpoint("after_funding_broadcast")?;
        native.wallet.mark_funding_broadcast(txid)?;
        store.save_native(&native)?;
    }
    emit_funding(
        json_output,
        native
            .wallet
            .coin
            .as_ref()
            .context("funded coin is missing")?,
        already_broadcast,
    )
}

async fn validate_explorer_prepared_funding(
    native: &crate::model::NativeWalletState,
    chain: &Chain,
    config: &Config,
) -> Result<()> {
    let coin = native
        .wallet
        .coin
        .as_ref()
        .context("prepared funding coin is missing")?;
    let metadata = coin
        .metadata
        .as_ref()
        .context("prepared funding metadata is missing")?;
    let funding = coin
        .funding
        .as_ref()
        .context("prepared funding journal is missing")?;
    ensure!(
        funding.stage == FundingStage::Prepared,
        "funding recovery was already secured"
    );
    let source_outpoint = funding
        .transaction
        .input
        .first()
        .context("prepared funding has no input")?
        .previous_output;
    let address = source_funding_address(&native.funding_secret, config.network);
    let source = chain
        .confirmed_source_utxos(&address)
        .await?
        .into_iter()
        .find(|source| source.outpoint == source_outpoint)
        .context("prepared funding deposit is no longer confirmed and unspent")?;
    let expected = build_source_funding(
        &coin.keys,
        config.network,
        &native.funding_secret,
        &source,
        metadata.amount_sat,
        funding.fee_rate_sat_vb,
        funding.max_fee_sat,
    )?;
    ensure!(
        expected.transaction == funding.transaction
            && expected.outpoint == metadata.outpoint
            && expected.fee_sat == funding.fee_sat,
        "prepared funding transaction is not canonical"
    );
    Ok(())
}

async fn source_sweep(
    directory: &Path,
    password_file: Option<&Path>,
    json_output: bool,
    destination: &str,
    fee_rate_sat_vb: u64,
    max_fee_sat: u64,
) -> Result<()> {
    ensure!(
        fee_rate_sat_vb > 0,
        "source sweep fee rate must be positive"
    );
    let (store, config) = open_wallet(directory, password_file)?;
    ensure!(
        matches!(config.chain, ChainConfig::Explorer { .. }),
        "source sweep requires an explorer backend"
    );
    let destination = Address::from_str(destination)
        .context("invalid source sweep destination")?
        .require_network(config.network.bitcoin_network())
        .context("source sweep destination is for the wrong network")?
        .to_string();
    let chain = Chain::connect(&config.chain, config.network).await?;
    let mut native = store.load_native()?;
    if let Some(journal) = native.source_sweep.as_ref() {
        let transaction = journal.transaction.clone();
        if let Some(observed) = chain.transaction(&transaction.compute_txid()).await? {
            ensure!(
                observed.transaction == transaction,
                "observed source sweep bytes do not match the saved transaction"
            );
            if native.source_sweep.as_ref().expect("checked above").stage
                != SourceSweepStage::Observed
            {
                if native.source_sweep.as_ref().expect("checked above").stage
                    == SourceSweepStage::Prepared
                {
                    native
                        .source_sweep
                        .as_mut()
                        .expect("checked above")
                        .arm_submission(&native.funding_secret)?;
                    store.save_native(&native)?;
                }
                native
                    .source_sweep
                    .as_mut()
                    .expect("checked above")
                    .mark_observed(&native.funding_secret, &observed.transaction)?;
                store.save_native(&native)?;
            }
            if observed.confirmations >= config.min_confirmations {
                let sources = available_source_sweep_inputs(&native, &chain, &config).await?;
                if !sources.is_empty() {
                    native.source_sweep = Some(SourceSweepJournal::prepare(
                        &native.funding_secret,
                        config.network,
                        sources,
                        &destination,
                        fee_rate_sat_vb,
                        max_fee_sat,
                    )?);
                    store.save_native(&native)?;
                    test_failpoint("after_sweep_prepared")?;
                } else {
                    validate_source_sweep_policy(
                        native.source_sweep.as_ref().expect("checked above"),
                        &destination,
                        fee_rate_sat_vb,
                        max_fee_sat,
                    )?;
                    return emit_source_sweep(json_output, &native, true);
                }
            } else {
                validate_source_sweep_policy(
                    native.source_sweep.as_ref().expect("checked above"),
                    &destination,
                    fee_rate_sat_vb,
                    max_fee_sat,
                )?;
                return emit_source_sweep(json_output, &native, true);
            }
        }
    }
    if native.source_sweep.as_ref().is_some_and(|journal| {
        journal.stage == SourceSweepStage::Prepared
            && (journal.destination != destination
                || journal.fee_rate_sat_vb != fee_rate_sat_vb
                || journal.max_fee_sat != max_fee_sat)
    }) {
        native.source_sweep = None;
    }
    if native.source_sweep.is_none() {
        let sources = available_source_sweep_inputs(&native, &chain, &config).await?;
        ensure!(
            !sources.is_empty(),
            "deposit address has no unreserved confirmed outputs to sweep"
        );
        native.source_sweep = Some(SourceSweepJournal::prepare(
            &native.funding_secret,
            config.network,
            sources,
            &destination,
            fee_rate_sat_vb,
            max_fee_sat,
        )?);
        store.save_native(&native)?;
        test_failpoint("after_sweep_prepared")?;
    }

    {
        let journal = native
            .source_sweep
            .as_ref()
            .context("source sweep journal is missing")?;
        validate_source_sweep_policy(journal, &destination, fee_rate_sat_vb, max_fee_sat)?;
        journal.validate(&native.funding_secret)?;
    }

    let transaction = native
        .source_sweep
        .as_ref()
        .context("source sweep journal is missing")?
        .transaction
        .clone();
    if let Some(observed) = chain.transaction(&transaction.compute_txid()).await? {
        ensure!(
            observed.transaction == transaction,
            "observed source sweep bytes do not match the saved transaction"
        );
        if native.source_sweep.as_ref().expect("checked above").stage != SourceSweepStage::Observed
        {
            if native.source_sweep.as_ref().expect("checked above").stage
                == SourceSweepStage::Prepared
            {
                native
                    .source_sweep
                    .as_mut()
                    .expect("checked above")
                    .arm_submission(&native.funding_secret)?;
                store.save_native(&native)?;
            }
            native
                .source_sweep
                .as_mut()
                .expect("checked above")
                .mark_observed(&native.funding_secret, &observed.transaction)?;
            store.save_native(&native)?;
        }
        return emit_source_sweep(json_output, &native, true);
    }

    validate_source_sweep_inputs(&native, &chain, &config).await?;
    native
        .source_sweep
        .as_mut()
        .context("source sweep journal is missing")?
        .arm_submission(&native.funding_secret)?;
    store.save_native(&native)?;
    test_failpoint("after_sweep_armed")?;
    chain.broadcast_exact(&transaction).await?;
    test_failpoint("after_sweep_broadcast")?;
    let observed = chain
        .transaction(&transaction.compute_txid())
        .await?
        .context("broadcast source sweep is not yet observable; rerun the command")?;
    native
        .source_sweep
        .as_mut()
        .context("source sweep journal is missing")?
        .mark_observed(&native.funding_secret, &observed.transaction)?;
    store.save_native(&native)?;
    emit_source_sweep(json_output, &native, false)
}

async fn available_source_sweep_inputs(
    native: &crate::model::NativeWalletState,
    chain: &Chain,
    config: &Config,
) -> Result<Vec<crate::model::SourceUtxo>> {
    let source_address = source_funding_address(&native.funding_secret, config.network);
    let reserved: HashSet<_> = native
        .wallet
        .coin
        .as_ref()
        .and_then(|coin| coin.funding.as_ref())
        .into_iter()
        .flat_map(|funding| {
            funding
                .transaction
                .input
                .iter()
                .map(|input| input.previous_output)
        })
        .collect();
    let mut sources: Vec<_> = chain
        .confirmed_source_utxos(&source_address)
        .await?
        .into_iter()
        .filter(|source| !source.coinbase && !reserved.contains(&source.outpoint))
        .collect();
    sources.sort_by(|left, right| {
        right
            .output
            .value
            .cmp(&left.output.value)
            .then_with(|| left.outpoint.cmp(&right.outpoint))
    });
    sources.truncate(100);
    Ok(sources)
}

fn validate_source_sweep_policy(
    journal: &SourceSweepJournal,
    destination: &str,
    fee_rate_sat_vb: u64,
    max_fee_sat: u64,
) -> Result<()> {
    ensure!(
        journal.destination == destination
            && journal.fee_rate_sat_vb == fee_rate_sat_vb
            && journal.max_fee_sat == max_fee_sat,
        "saved source sweep policy does not match this command"
    );
    Ok(())
}

async fn validate_source_sweep_inputs(
    native: &crate::model::NativeWalletState,
    chain: &Chain,
    config: &Config,
) -> Result<()> {
    let journal = native
        .source_sweep
        .as_ref()
        .context("source sweep journal is missing")?;
    journal.validate(&native.funding_secret)?;
    let address = source_funding_address(&native.funding_secret, config.network);
    let available = chain.confirmed_source_utxos(&address).await?;
    for saved in &journal.sources {
        let observed = available
            .iter()
            .find(|source| source.outpoint == saved.outpoint)
            .context("saved source sweep input is no longer confirmed and unspent")?;
        ensure!(
            observed.output == saved.output && observed.coinbase == saved.coinbase,
            "saved source sweep input changed"
        );
    }
    Ok(())
}

fn emit_source_sweep(
    json_output: bool,
    native: &crate::model::NativeWalletState,
    existing: bool,
) -> Result<()> {
    let journal = native
        .source_sweep
        .as_ref()
        .context("source sweep journal is missing")?;
    let txid = journal.transaction.compute_txid();
    emit(
        json_output,
        json!({
            "status": if existing { "source_sweep_observed" } else { "source_sweep_broadcast" },
            "txid": txid.to_string(),
            "destination": journal.destination,
            "input_count": journal.sources.len(),
            "fee_rate_sat_vb": journal.fee_rate_sat_vb,
            "fee_sat": journal.fee_sat,
        }),
        format!(
            "Source sweep {txid} sends {} inputs to {} with a {} sat fee",
            journal.sources.len(),
            journal.destination,
            journal.fee_sat
        ),
    )
}

async fn sign_transfer(
    directory: &Path,
    password_file: Option<&Path>,
    json_output: bool,
    request_path: &Path,
    output_path: &Path,
) -> Result<()> {
    require_output_file(output_path)?;
    let request: TransferRequest = read_json_source(request_path)?;
    request.validate()?;
    let (store, config) = open_wallet(directory, password_file)?;
    let native = store.load_native()?;
    if let Some(coin) = &native.wallet.coin
        && let Some(outgoing) = &coin.outgoing
    {
        ensure!(
            outgoing.request == request,
            "coin was transferred using another request"
        );
        write_json_destination(output_path, &outgoing.envelope)?;
        return emit_transfer_sent(json_output, &request, &outgoing.envelope, output_path, true);
    }
    ensure!(
        native.exit.is_none(),
        "coin has a saved exit; finish that exact exit before transferring"
    );
    let mut state = native.wallet;
    if state.pending.is_some() {
        ensure!(
            state.pending_transfer_request()? == &request,
            "pending signing request does not match input"
        );
    }
    let mut enclave = None;
    if state.pending.is_none() {
        ensure_destination_available(output_path)?;
        let metadata = state
            .coin
            .as_ref()
            .context("wallet has no coin")?
            .metadata
            .as_ref()
            .context("coin has no verified funding")?
            .clone();
        let connection = connect_verified(&config).await?;
        let status = connection.status(metadata.keys.coin_id).await?;
        let chain = Chain::connect(&config.chain, config.network).await?;
        let observation = chain.observe_funding(&metadata).await?;
        state.begin_transfer(
            config.network,
            &request,
            &status,
            &observation.funding,
            config.min_confirmations,
            config.min_reaction_blocks,
        )?;
        store.save(&state)?;
        test_failpoint("after_prepare")?;
        enclave = Some(connection);
    }
    if matches!(
        state.pending.as_ref(),
        Some(PendingOperation::Recovery(PendingRecovery {
            stage: RecoveryStage::Prepared { .. },
            ..
        }))
    ) {
        if enclave.is_none() {
            enclave = Some(connect_verified(&config).await?);
        }
        let connection = enclave.as_ref().expect("enclave inserted above");
        let metadata = state
            .coin
            .as_ref()
            .and_then(|coin| coin.metadata.as_ref())
            .context("pending transfer metadata is missing")?
            .clone();
        let status = connection.status(metadata.keys.coin_id).await?;
        let chain = Chain::connect(&config.chain, config.network).await?;
        let observation = chain.observe_funding(&metadata).await?;
        state.validate_pending_transfer(
            &status,
            &observation.funding,
            config.min_confirmations,
            config.min_reaction_blocks,
        )?;
        let response = connection.sign(&state.pending_sign_request()?).await?;
        test_failpoint("after_sign")?;
        state.record_sign_response(response)?;
        store.save(&state)?;
        test_failpoint("after_response")?;
    }
    if enclave.is_none() {
        enclave = Some(connect_verified(&config).await?);
    }
    let connection = enclave.as_ref().expect("enclave inserted above");
    let coin_id = state
        .coin
        .as_ref()
        .context("pending transfer coin is missing")?
        .keys
        .coin_id;
    let status = connection.status(coin_id).await?;
    let envelope = state.complete_transfer(&status)?;
    store.save(&state)?;
    write_json_destination(output_path, &envelope)?;
    emit_transfer_sent(json_output, &request, &envelope, output_path, false)
}

#[allow(clippy::too_many_arguments)]
fn create_transfer_request(
    directory: &Path,
    password_file: Option<&Path>,
    json_output: bool,
    coin_id: &str,
    outpoint: OutPoint,
    amount_sat: u64,
    minimum_reaction_blocks: Option<u32>,
    output_path: &Path,
) -> Result<()> {
    require_output_file(output_path)?;
    let coin_id = parse_hex32("coin ID", coin_id)?;
    let (store, config) = open_wallet(directory, password_file)?;
    let mut state = store.load()?;
    let requested_margin = config
        .min_reaction_blocks
        .max(minimum_reaction_blocks.unwrap_or_default());
    let existing = state.incoming.is_some();
    if !existing {
        ensure_destination_available(output_path)?;
    }
    let request = state.begin_transfer_request(
        config.network,
        coin_id,
        outpoint,
        amount_sat,
        requested_margin,
    )?;
    if !existing {
        store.save(&state)?;
    }
    write_json_destination(output_path, &request)?;
    emit(
        json_output,
        json!({
            "status": "transfer_requested",
            "request_id": request.request_id,
            "coin_id": request.coin_id,
            "expected_amount_sat": request.expected_amount_sat,
            "output": output_path,
            "min_reaction_blocks": request.min_reaction_blocks,
        }),
        format!(
            "Created transfer request {} at {}",
            request.request_id,
            output_path.display()
        ),
    )
}

async fn accept_transfer(
    directory: &Path,
    password_file: Option<&Path>,
    json_output: bool,
    request_path: &Path,
    package_path: &Path,
) -> Result<()> {
    let request: TransferRequest = read_json_source(request_path)?;
    let envelope: TransferEnvelope = read_json_source(package_path)?;
    request.validate()?;
    let (store, config) = open_wallet(directory, password_file)?;
    let mut state = store.load()?;
    if let Some(coin) = &state.coin {
        ensure!(
            coin.accepted_request.as_ref() == Some(&request)
                && coin.accepted_envelope_fingerprint == Some(envelope.fingerprint()),
            "wallet already contains a different coin or transfer"
        );
        return emit(
            json_output,
            json!({
                "status": "already_accepted",
                "request_id": request.request_id,
                "coin_id": request.coin_id,
                "expected_amount_sat": request.expected_amount_sat,
                "signature_count": coin.history.len(),
                "latest_delay_blocks": coin.history.last().map(|recovery| recovery.delay_blocks),
            }),
            format!("Transfer {} was already accepted", request.request_id),
        );
    }
    let incoming = state
        .incoming
        .as_ref()
        .context("wallet has no matching transfer request")?;
    let payload = decrypt_transfer(&request, incoming.transport_secret, &envelope)?;
    let metadata = payload.metadata.clone();
    let enclave = connect_verified(&config).await?;
    let status = enclave.status(metadata.keys.coin_id).await?;
    let chain = Chain::connect(&config.chain, config.network).await?;
    let observation = chain.observe_funding(&metadata).await?;
    ensure!(
        state.accept_transfer(
            config.network,
            &request,
            &envelope,
            &status,
            &observation.funding,
            config.min_confirmations,
            config.min_reaction_blocks,
        )?,
        "transfer was already accepted"
    );
    store.save(&state)?;
    let coin = state.coin.as_ref().context("accepted coin is missing")?;
    let latest_delay_blocks = coin
        .history
        .last()
        .context("accepted transfer has no recovery history")?
        .delay_blocks;
    emit(
        json_output,
        json!({
            "status": "transfer_accepted",
            "request_id": request.request_id,
            "coin_id": request.coin_id,
            "expected_amount_sat": request.expected_amount_sat,
            "signature_count": status.signature_count,
            "latest_delay_blocks": latest_delay_blocks,
            "tip_height": observation.tip_height,
            "confirmations": observation.funding.confirmations,
        }),
        format!(
            "Accepted coin {} with {} signed recoveries",
            request.coin_id, status.signature_count
        ),
    )
}

async fn coin_status(
    directory: &Path,
    password_file: Option<&Path>,
    json_output: bool,
) -> Result<()> {
    let (store, config) = open_wallet(directory, password_file)?;
    let state = store.load()?;
    let Some(coin) = &state.coin else {
        let incoming = state.incoming.as_ref().map(|incoming| &incoming.request);
        return emit(
            json_output,
            json!({
                "status": "empty",
                "pending_transfer_request": incoming.map(|request| &request.request_id),
                "pending_operation": pending_name(state.pending.as_ref()),
            }),
            match incoming {
                Some(request) => format!("Waiting for transfer package {}", request.request_id),
                None => "Wallet contains no coin".into(),
            },
        );
    };
    let enclave = connect_verified(&config).await?;
    let status = enclave.status(coin.keys.coin_id).await?;
    verify_status(&coin.keys, &status)?;
    let mut confirmations = None;
    let mut tip_height = None;
    let mut reaction_safe = None;
    let mut history_current = status.signature_count == coin.history.len() as u64;
    if let Some(metadata) = &coin.metadata {
        let chain = Chain::connect(&config.chain, config.network).await?;
        let funding_stage = coin.funding.as_ref().map(|funding| funding.stage);
        if matches!(
            funding_stage,
            Some(FundingStage::Prepared | FundingStage::RecoverySecured)
        ) {
            confirmations = Some(0);
            tip_height = Some(chain.tip_height().await?);
        } else {
            let minimum_confirmations = if funding_stage == Some(FundingStage::Broadcast) {
                0
            } else {
                config.min_confirmations
            };
            let observation = chain
                .verify_funding(metadata, minimum_confirmations)
                .await?;
            confirmations = Some(observation.confirmations);
            tip_height = Some(observation.tip_height);
        }
        if let (Some(capability), Some(latest)) = (coin.current_capability, coin.history.last()) {
            let handoff = coin
                .current_handoff
                .context("owned coin has no current handoff token")?;
            let withdrawal_secret = coin
                .withdrawal_secret
                .context("owned coin has no current withdrawal key")?;
            let withdrawal_secret = SecretKey::from_slice(&withdrawal_secret)
                .context("saved withdrawal key is invalid")?;
            verify_history(
                metadata,
                &status,
                coin.client_secret,
                capability,
                handoff,
                secret_xonly(&withdrawal_secret),
                0,
                &coin.history,
            )?;
            reaction_safe = Some(
                require_reaction_margin(
                    confirmations.unwrap_or_default(),
                    latest.delay_blocks,
                    config.min_reaction_blocks,
                )
                .is_ok(),
            );
            history_current = true;
        } else if let Some(capability) = coin.current_capability {
            ensure!(
                status.signature_count == 0,
                "enclave has unrecorded signatures"
            );
            let handoff = coin
                .current_handoff
                .context("registered coin has no current handoff token")?;
            ensure!(
                status.authorization
                    == authorization(&coin.keys.coin_id, &capability_hash(&capability), &handoff,),
                "wallet authorization does not match enclave"
            );
        }
    }
    let lifecycle = if coin.current_capability.is_some()
        && coin.funding.as_ref().map(|funding| funding.stage) == Some(FundingStage::Broadcast)
        && confirmations.is_some_and(|count| count >= config.min_confirmations)
    {
        "owned"
    } else {
        coin.lifecycle()
    };
    emit(
        json_output,
        json!({
            "status": "ok",
            "lifecycle": lifecycle,
            "coin_id": hex::encode(coin.keys.coin_id),
            "signature_count": status.signature_count,
            "local_history_count": coin.history.len(),
            "history_current": history_current,
            "latest_delay_blocks": coin.history.last().map(|recovery| recovery.delay_blocks),
            "funding_stage": coin.funding.as_ref().map(|funding| funding.stage),
            "tip_height": tip_height,
            "confirmations": confirmations,
            "reaction_safe": reaction_safe,
            "pending_operation": pending_name(state.pending.as_ref()),
        }),
        format!(
            "Coin {} is {} with {} enclave signatures{}",
            hex::encode(coin.keys.coin_id),
            lifecycle,
            status.signature_count,
            if history_current {
                ""
            } else {
                " (local history is stale)"
            }
        ),
    )
}

async fn export_recovery(
    directory: &Path,
    password_file: Option<&Path>,
    json_output: bool,
    output_path: &Path,
) -> Result<()> {
    require_output_file(output_path)?;
    ensure_destination_available(output_path)?;
    let (store, _config) = open_wallet(directory, password_file)?;
    let state = store.load()?;
    let coin = state.coin.as_ref().context("wallet has no coin")?;
    let metadata = coin
        .metadata
        .as_ref()
        .context("coin has no verified funding")?;
    let withdrawal_secret = SecretKey::from_slice(
        &coin
            .withdrawal_secret
            .context("wallet has no current withdrawal key")?,
    )
    .context("saved withdrawal key is invalid")?;
    let recovery_index = coin
        .withdrawal_recovery_index
        .context("wallet has no owned recovery")?;
    let recovery = coin
        .history
        .get(recovery_index)
        .context("owned recovery index is invalid")?;
    ensure!(
        secret_xonly(&withdrawal_secret) == recovery.withdrawal_xonly_pubkey,
        "saved withdrawal key does not match owned recovery"
    );
    verify_recovery(metadata, recovery)?;
    let transaction_hex = serialize_hex(&recovery.transaction);
    write_text_destination(output_path, &transaction_hex)?;
    emit(
        json_output,
        json!({
            "status": "recovery_exported",
            "output": output_path,
            "delay_blocks": recovery.delay_blocks,
            "history_index": recovery_index,
            "txid": recovery.transaction.compute_txid().to_string(),
        }),
        format!(
            "Exported recovery transaction with a {}-block delay to {}",
            recovery.delay_blocks,
            output_path.display()
        ),
    )
}

async fn exit_coin(
    directory: &Path,
    password_file: Option<&Path>,
    json_output: bool,
    destination: &str,
    fee_rate: Option<u64>,
    max_fee_sat: u64,
    dry_run: bool,
) -> Result<()> {
    let (store, config) = open_wallet(directory, password_file)?;
    let native = store.load_native()?;
    ensure!(
        native.wallet.pending.is_none(),
        "wallet has a pending operation; finish it before exiting"
    );
    if dry_run && native.exit.is_some() {
        return emit_saved_exit_package(
            &config,
            &native,
            json_output,
            destination,
            fee_rate,
            max_fee_sat,
        );
    }
    if !dry_run {
        return exit_coin_journaled(
            &store,
            &config,
            native,
            json_output,
            destination,
            fee_rate,
            max_fee_sat,
        )
        .await;
    }
    let state = native.wallet;
    let coin = state.coin.as_ref().context("wallet has no coin")?;
    let metadata = coin
        .metadata
        .as_ref()
        .context("coin has no verified funding")?;
    let withdrawal_secret = SecretKey::from_slice(
        &coin
            .withdrawal_secret
            .context("wallet has no current withdrawal key")?,
    )
    .context("saved withdrawal key is invalid")?;
    let recovery_index = coin
        .withdrawal_recovery_index
        .context("wallet has no owned recovery")?;
    let recovery = coin
        .history
        .get(recovery_index)
        .context("owned recovery index is invalid")?;
    ensure!(
        secret_xonly(&withdrawal_secret) == recovery.withdrawal_xonly_pubkey,
        "saved withdrawal key does not match owned recovery"
    );
    verify_recovery(metadata, recovery)?;
    ensure!(
        coin.funding
            .as_ref()
            .is_none_or(|funding| funding.stage == FundingStage::Broadcast),
        "funding has not been broadcast"
    );
    let destination = Address::from_str(destination)
        .context("invalid destination address")?
        .require_network(config.network.bitcoin_network())
        .context("destination address is for the wrong network")?;
    let chain = Chain::connect(&config.chain, config.network).await?;
    let observation = chain.verify_funding(metadata, 1).await?;
    ensure!(
        observation.confirmations >= recovery.delay_blocks,
        "recovery is not final until funding has {} confirmations (currently {})",
        recovery.delay_blocks,
        observation.confirmations
    );
    let fee_rate = match fee_rate {
        Some(rate) => rate,
        None => chain.recommended_fee_rate().await?,
    };
    ensure!(fee_rate > 0, "exit fee rate must be positive");
    let child = build_exit_child(
        recovery,
        metadata.amount_sat,
        &withdrawal_secret,
        destination.script_pubkey(),
        fee_rate,
    )?;
    let parent_txid = recovery.transaction.compute_txid();
    let child_txid = child.compute_txid();
    let fee_sat = metadata.amount_sat - child.output[0].value.to_sat();
    ensure!(
        fee_sat <= max_fee_sat,
        "exit fee {fee_sat} sat exceeds maximum {max_fee_sat} sat"
    );
    let parent_hex = serialize_hex(&recovery.transaction);
    let child_hex = serialize_hex(&child);
    emit(
        json_output,
        json!({
            "status": "package_prepared",
            "coin_id": hex::encode(coin.keys.coin_id),
            "recovery_txid": parent_txid.to_string(),
            "exit_txid": child_txid.to_string(),
            "destination": destination.to_string(),
            "fee_rate_sat_vb": fee_rate,
            "fee_sat": fee_sat,
            "parent_hex": parent_hex,
            "child_hex": child_hex,
        }),
        format!(
            "Prepared recovery {parent_txid} and fee-paying child {child_txid} without broadcasting"
        ),
    )
}

async fn exit_coin_journaled(
    store: &WalletStore,
    config: &Config,
    mut native: crate::model::NativeWalletState,
    json_output: bool,
    destination: &str,
    fee_rate: Option<u64>,
    max_fee_sat: u64,
) -> Result<()> {
    let destination = Address::from_str(destination)
        .context("invalid destination address")?
        .require_network(config.network.bitcoin_network())
        .context("destination address is for the wrong network")?
        .to_string();
    let chain = Chain::connect(&config.chain, config.network).await?;
    let metadata = native
        .wallet
        .coin
        .as_ref()
        .and_then(|coin| coin.metadata.as_ref())
        .context("coin has no verified funding")?
        .clone();
    if native
        .exit
        .as_ref()
        .is_some_and(|journal| journal.stage != ExitStage::Prepared)
    {
        validate_saved_exit_policy(&native, &destination, fee_rate, max_fee_sat)?;
        let presence = observe_exit_package(
            &chain,
            native.exit.as_ref().expect("checked above"),
            native.wallet.coin.as_ref().context("wallet has no coin")?,
        )
        .await?;
        if presence.complete {
            return mark_exit_observed(store, native, json_output, true);
        }
        if presence.parent {
            native
                .exit
                .as_mut()
                .expect("checked above")
                .arm_submission(native.wallet.coin.as_ref().context("wallet has no coin")?)?;
            store.save_native(&native)?;
            test_failpoint("after_exit_armed")?;
            let child = native
                .exit
                .as_ref()
                .expect("checked above")
                .package
                .child
                .clone();
            chain.broadcast_exact(&child).await?;
            test_failpoint("after_exit_submission")?;
            let presence = observe_exit_package(
                &chain,
                native.exit.as_ref().expect("checked above"),
                native.wallet.coin.as_ref().context("wallet has no coin")?,
            )
            .await?;
            ensure!(
                presence.complete,
                "submitted exit package is not yet fully observable; rerun the command"
            );
            return mark_exit_observed(store, native, json_output, false);
        }
    }
    let mut observation = chain.observe_funding(&metadata).await?;
    if !observation.funding.unspent && observation.spending_txid.is_none() {
        let coin = native.wallet.coin.as_ref().context("wallet has no coin")?;
        for recovery in &coin.history {
            let txid = recovery.transaction.compute_txid();
            if let Some(observed) = chain.transaction(&txid).await? {
                let mut observed_recovery = recovery.clone();
                observed_recovery.transaction = observed.transaction;
                verify_recovery(&metadata, &observed_recovery)?;
                observation.spending_txid = Some(txid);
                observation.spending_confirmed = observed.confirmations > 0;
                break;
            }
        }
        if observation.spending_txid.is_none()
            && matches!(chain, Chain::Core(_))
            && native
                .exit
                .as_ref()
                .is_some_and(|exit| exit.stage != ExitStage::Prepared)
        {
            let journal = native.exit.as_ref().expect("checked above");
            let parent = chain
                .observe_authorized_transaction(&journal.package.parent)
                .await?;
            let child = if parent.is_none() {
                chain
                    .observe_authorized_transaction(&journal.package.child)
                    .await?
            } else {
                None
            };
            if let Some(observed) = parent.or(child) {
                observation.spending_txid = Some(journal.package.parent.compute_txid());
                observation.spending_confirmed = observed.confirmations > 0;
            }
        }
    }
    let saved_parent = native
        .exit
        .as_ref()
        .map(|exit| exit.package.parent.compute_txid());
    verify_exit_funding(
        native.wallet.coin.as_ref().context("wallet has no coin")?,
        &observation.funding,
        1,
        observation.spending_txid,
        observation.spending_confirmed,
        saved_parent,
    )?;

    let replace_prepared = native.exit.as_ref().is_some_and(|journal| {
        journal.stage == ExitStage::Prepared
            && (journal.package.destination != destination
                || journal.package.max_fee_sat != max_fee_sat
                || fee_rate.is_some_and(|rate| rate != journal.package.fee_rate_sat_vb))
    });
    if native.exit.is_none() || replace_prepared {
        let fee_rate = match fee_rate {
            Some(rate) => rate,
            None => chain.recommended_fee_rate().await?,
        };
        let journal = ExitJournal::prepare(
            native.wallet.coin.as_ref().context("wallet has no coin")?,
            config.network,
            &destination,
            observation.funding.confirmations,
            fee_rate,
            max_fee_sat,
        )?;
        native.exit = Some(journal);
        store.save_native(&native)?;
        test_failpoint("after_exit_prepared")?;
    }

    validate_saved_exit_policy(&native, &destination, fee_rate, max_fee_sat)?;

    let presence = observe_exit_package(
        &chain,
        native.exit.as_ref().expect("checked above"),
        native.wallet.coin.as_ref().context("wallet has no coin")?,
    )
    .await?;
    if presence.complete {
        return mark_exit_observed(store, native, json_output, true);
    }

    ensure!(
        observation.funding.confirmations
            >= native
                .exit
                .as_ref()
                .context("exit journal is missing")?
                .package
                .recovery_delay_blocks,
        "recovery is not final until funding has {} confirmations (currently {})",
        native
            .exit
            .as_ref()
            .context("exit journal is missing")?
            .package
            .recovery_delay_blocks,
        observation.funding.confirmations
    );
    native
        .exit
        .as_mut()
        .context("exit journal is missing")?
        .arm_submission(native.wallet.coin.as_ref().context("wallet has no coin")?)?;
    store.save_native(&native)?;
    test_failpoint("after_exit_armed")?;
    let journal = native.exit.as_ref().context("exit journal is missing")?;
    if presence.parent {
        chain.broadcast_exact(&journal.package.child).await?;
    } else {
        chain
            .submit_package(
                &serialize_hex(&journal.package.parent),
                &serialize_hex(&journal.package.child),
            )
            .await?;
    }
    test_failpoint("after_exit_submission")?;
    let presence = observe_exit_package(
        &chain,
        journal,
        native.wallet.coin.as_ref().context("wallet has no coin")?,
    )
    .await?;
    ensure!(
        presence.complete,
        "submitted exit package is not yet fully observable; rerun the command"
    );
    mark_exit_observed(store, native, json_output, false)
}

struct ExitPresence {
    parent: bool,
    complete: bool,
}

fn validate_saved_exit_policy(
    native: &crate::model::NativeWalletState,
    destination: &str,
    fee_rate: Option<u64>,
    max_fee_sat: u64,
) -> Result<()> {
    let coin = native.wallet.coin.as_ref().context("wallet has no coin")?;
    let journal = native.exit.as_ref().context("exit journal is missing")?;
    journal.validate(coin)?;
    ensure!(
        journal.package.destination == destination
            && journal.package.max_fee_sat == max_fee_sat
            && fee_rate.is_none_or(|rate| rate == journal.package.fee_rate_sat_vb),
        "saved exit policy does not match this command"
    );
    Ok(())
}

fn mark_exit_observed(
    store: &WalletStore,
    mut native: crate::model::NativeWalletState,
    json_output: bool,
    existing: bool,
) -> Result<()> {
    if native
        .exit
        .as_ref()
        .context("exit journal is missing")?
        .stage
        != ExitStage::Observed
    {
        if native.exit.as_ref().expect("checked above").stage == ExitStage::Prepared {
            native
                .exit
                .as_mut()
                .expect("checked above")
                .arm_submission(native.wallet.coin.as_ref().context("wallet has no coin")?)?;
            store.save_native(&native)?;
        }
        let parent = native
            .exit
            .as_ref()
            .expect("checked above")
            .package
            .parent
            .clone();
        let child = native
            .exit
            .as_ref()
            .expect("checked above")
            .package
            .child
            .clone();
        native.exit.as_mut().expect("checked above").mark_observed(
            native.wallet.coin.as_ref().context("wallet has no coin")?,
            &parent,
            &child,
        )?;
        store.save_native(&native)?;
    }
    emit_exit(json_output, &native, existing)
}

async fn observe_exit_package(
    chain: &Chain,
    journal: &ExitJournal,
    coin: &WalletCoin,
) -> Result<ExitPresence> {
    let parent_txid = journal.package.parent.compute_txid();
    let child_txid = journal.package.child.compute_txid();
    let mut child = chain.transaction(&child_txid).await?;
    if child.is_none() && matches!(chain, Chain::Core(_)) && journal.stage != ExitStage::Prepared {
        child = chain
            .observe_authorized_transaction(&journal.package.child)
            .await?;
    }
    let mut parent = chain.transaction(&parent_txid).await?;
    if parent.is_none() && matches!(chain, Chain::Core(_)) && journal.stage != ExitStage::Prepared {
        parent = chain
            .observe_authorized_transaction(&journal.package.parent)
            .await?;
    }
    if parent.is_none()
        && matches!(chain, Chain::Core(_))
        && journal.stage != ExitStage::Prepared
        && let Some(child) = &child
    {
        parent = Some(crate::services::TransactionObservation {
            transaction: journal.package.parent.clone(),
            tip_height: child.tip_height,
            confirmations: child.confirmations,
            raw_bytes_observed: false,
        });
    }
    if let Some(parent) = &parent {
        journal.validate_observed_parent(coin, &parent.transaction)?;
    }
    if let Some(child) = &child {
        if child.raw_bytes_observed {
            ensure!(
                child.transaction == journal.package.child,
                "observed exit child bytes do not match the saved package"
            );
        }
        ensure!(parent.is_some(), "exit child is visible without its parent");
    } else if parent.is_some() {
        ensure!(
            !chain.outspend(OutPoint::new(parent_txid, 0)).await?.spent,
            "exit parent is spent by an unknown transaction"
        );
    }
    Ok(ExitPresence {
        parent: parent.is_some(),
        complete: parent.is_some() && child.is_some(),
    })
}

fn emit_exit(
    json_output: bool,
    native: &crate::model::NativeWalletState,
    existing: bool,
) -> Result<()> {
    let coin = native.wallet.coin.as_ref().context("wallet has no coin")?;
    let journal = native.exit.as_ref().context("exit journal is missing")?;
    let parent_txid = journal.package.parent.compute_txid();
    let child_txid = journal.package.child.compute_txid();
    emit(
        json_output,
        json!({
            "status": if existing { "package_observed" } else { "package_submitted" },
            "coin_id": hex::encode(coin.keys.coin_id),
            "recovery_txid": parent_txid.to_string(),
            "exit_txid": child_txid.to_string(),
            "destination": journal.package.destination,
            "fee_rate_sat_vb": journal.package.fee_rate_sat_vb,
            "fee_sat": journal.package.fee_sat,
        }),
        format!(
            "Recovery {parent_txid} and fee-paying child {child_txid} are observable for {}",
            journal.package.destination
        ),
    )
}

fn emit_saved_exit_package(
    config: &Config,
    native: &crate::model::NativeWalletState,
    json_output: bool,
    destination: &str,
    fee_rate: Option<u64>,
    max_fee_sat: u64,
) -> Result<()> {
    let destination = Address::from_str(destination)
        .context("invalid destination address")?
        .require_network(config.network.bitcoin_network())?
        .to_string();
    let coin = native.wallet.coin.as_ref().context("wallet has no coin")?;
    let journal = native.exit.as_ref().context("exit journal is missing")?;
    journal.validate(coin)?;
    ensure!(
        journal.package.destination == destination
            && journal.package.max_fee_sat == max_fee_sat
            && fee_rate.is_none_or(|rate| rate == journal.package.fee_rate_sat_vb),
        "saved exit policy does not match this command"
    );
    let parent_txid = journal.package.parent.compute_txid();
    let child_txid = journal.package.child.compute_txid();
    emit(
        json_output,
        json!({
            "status": "package_prepared",
            "coin_id": hex::encode(coin.keys.coin_id),
            "recovery_txid": parent_txid.to_string(),
            "exit_txid": child_txid.to_string(),
            "destination": journal.package.destination,
            "fee_rate_sat_vb": journal.package.fee_rate_sat_vb,
            "fee_sat": journal.package.fee_sat,
            "parent_hex": serialize_hex(&journal.package.parent),
            "child_hex": serialize_hex(&journal.package.child),
        }),
        format!("Loaded saved recovery {parent_txid} and fee-paying child {child_txid}"),
    )
}

async fn export_receipt(
    directory: &Path,
    password_file: Option<&Path>,
    json_output: bool,
    output_path: &Path,
) -> Result<()> {
    require_output_file(output_path)?;
    let (store, config) = open_wallet(directory, password_file)?;
    let state = store.load()?;
    ensure!(state.pending.is_none(), "wallet has a pending operation");
    let coin = state.coin.as_ref().context("wallet has no coin")?;
    let metadata = coin
        .metadata
        .as_ref()
        .context("coin has no verified funding")?;
    ensure!(!coin.history.is_empty(), "coin has no signed recovery");
    let enclave = connect_verified(&config).await?;
    let status = enclave.status(coin.keys.coin_id).await?;
    let chain = Chain::connect(&config.chain, config.network).await?;
    let observation = chain
        .verify_funding(metadata, config.min_confirmations)
        .await?;
    verify_public_history(
        metadata,
        &status,
        &coin.history,
        observation.confirmations,
        config.min_reaction_blocks,
    )?;
    let receipt = Receipt {
        format_version: FILE_FORMAT_VERSION,
        protocol_version: PROTOCOL_VERSION,
        metadata: metadata.clone(),
        status: status.clone(),
        history: coin.history.clone(),
    };
    write_json_destination(output_path, &receipt)?;
    emit(
        json_output,
        json!({
            "status": "receipt_exported",
            "output": output_path,
            "coin_id": hex::encode(coin.keys.coin_id),
            "signature_count": status.signature_count,
            "tip_height": observation.tip_height,
        }),
        format!(
            "Exported live-verification receipt to {}",
            output_path.display()
        ),
    )
}

async fn verify_receipt(
    directory: &Path,
    password_file: Option<&Path>,
    json_output: bool,
    input_path: &Path,
) -> Result<()> {
    let (store, config) = open_wallet(directory, password_file)?;
    store.load()?;
    let receipt: Receipt = read_json_source(input_path)?;
    ensure!(
        receipt.format_version == FILE_FORMAT_VERSION,
        "unsupported receipt format version {}",
        receipt.format_version
    );
    ensure!(
        receipt.protocol_version == PROTOCOL_VERSION,
        "receipt protocol version mismatch"
    );
    ensure!(
        receipt.metadata.network == config.network,
        "receipt network mismatch"
    );
    let enclave = connect_verified(&config).await?;
    let status = enclave.status(receipt.metadata.keys.coin_id).await?;
    ensure!(
        status == receipt.status,
        "receipt is stale or enclave state changed"
    );
    let chain = Chain::connect(&config.chain, config.network).await?;
    let observation = chain
        .verify_funding(&receipt.metadata, config.min_confirmations)
        .await?;
    verify_public_history(
        &receipt.metadata,
        &status,
        &receipt.history,
        observation.confirmations,
        config.min_reaction_blocks,
    )?;
    emit(
        json_output,
        json!({
            "status": "receipt_verified",
            "coin_id": hex::encode(receipt.metadata.keys.coin_id),
            "signature_count": status.signature_count,
            "tip_height": observation.tip_height,
            "confirmations": observation.confirmations,
        }),
        format!(
            "Verified receipt for coin {} against the live enclave and configured chain backend",
            hex::encode(receipt.metadata.keys.coin_id)
        ),
    )
}

async fn finish_pending_funding_recovery(
    store: &WalletStore,
    state: &mut WalletState,
    enclave: &EnclaveConnection,
    config: &Config,
) -> Result<()> {
    if matches!(
        state.pending.as_ref(),
        Some(PendingOperation::Recovery(PendingRecovery {
            purpose: RecoveryPurpose::Fund { .. },
            stage: RecoveryStage::Prepared { .. },
        }))
    ) {
        let coin = state
            .coin
            .as_ref()
            .context("pending funding coin is missing")?;
        let metadata = coin
            .metadata
            .as_ref()
            .context("pending funding metadata is missing")?;
        let status = enclave.status(coin.keys.coin_id).await?;
        verify_status(&coin.keys, &status)?;
        let attempt = match state.pending.as_ref() {
            Some(PendingOperation::Recovery(PendingRecovery {
                purpose: RecoveryPurpose::Fund { .. },
                stage: RecoveryStage::Prepared { attempt },
            })) => attempt,
            _ => unreachable!("pending funding stage checked above"),
        };
        if !attempt_committed(&status, attempt)? {
            ensure!(
                attempt_uncommitted(&status, attempt),
                "pending funding journal does not match live enclave state"
            );
            let funding = coin
                .funding
                .as_ref()
                .context("pending funding journal is missing")?;
            ensure!(
                funding.stage == FundingStage::Prepared,
                "funding recovery was already secured"
            );
            Chain::connect(&config.chain, config.network)
                .await?
                .validate_prepared_funding(metadata, &funding.transaction)?;
            require_reaction_margin(0, attempt.delay_blocks, config.min_reaction_blocks)?;
        }
        let response = enclave.sign(&state.pending_sign_request()?).await?;
        test_failpoint("after_sign")?;
        state.record_sign_response(response)?;
        store.save(state)?;
        test_failpoint("after_response")?;
    }
    let coin_id = state
        .coin
        .as_ref()
        .context("pending funding coin is missing")?
        .keys
        .coin_id;
    let status = enclave.status(coin_id).await?;
    state.complete_funding_recovery(&status)?;
    store.save(state)?;
    test_failpoint("after_recovery_secured")?;
    Ok(())
}

async fn connect_verified(config: &Config) -> Result<EnclaveConnection> {
    #[cfg(debug_assertions)]
    if std::env::var("ENCLAVIA_WALLET_TEST_DISABLE_ENCLAVE").as_deref() == Ok("1") {
        bail!("enclave connection disabled by test");
    }
    ensure!(
        config.network != NetworkId::Mainnet,
        "mainnet is not supported by this wallet"
    );
    ensure!(
        config.network == NetworkId::Regtest
            || matches!(config.enclave, EnclaveConfig::Production { .. }),
        "debug and plaintext enclave transports are regtest-only"
    );
    let enclave = EnclaveConnection::connect(&config.enclave).await?;
    enclave.health().await?;
    Ok(enclave)
}

fn open_wallet(directory: &Path, password_file: Option<&Path>) -> Result<(WalletStore, Config)> {
    let store = WalletStore::open(directory, read_password(password_file, false)?)?;
    let config = store.config().clone();
    ensure!(
        config.network != NetworkId::Mainnet,
        "mainnet is not supported by this wallet"
    );
    Ok((store, config))
}

fn emit_registration(
    json_output: bool,
    config: &Config,
    coin: &WalletCoin,
    existing: bool,
) -> Result<()> {
    let address = funding_address(&coin.keys, config.network);
    let script = funding_script(&coin.keys);
    emit(
        json_output,
        json!({
            "status": if existing { "already_registered" } else { "registered" },
            "coin_id": hex::encode(coin.keys.coin_id),
            "funding_address": address.to_string(),
            "funding_script_hex": hex::encode(script.as_bytes()),
            "network": network_name(config.network),
        }),
        format!(
            "Registered coin {}\nTinylayer output address: {}",
            hex::encode(coin.keys.coin_id),
            address
        ),
    )
}

fn emit_funding(json_output: bool, coin: &WalletCoin, existing: bool) -> Result<()> {
    let metadata = coin
        .metadata
        .as_ref()
        .context("funded coin has no metadata")?;
    let funding = coin
        .funding
        .as_ref()
        .context("funded coin has no funding journal")?;
    let recovery = coin
        .history
        .first()
        .context("funded coin has no recovery")?;
    ensure!(
        funding.stage == FundingStage::Broadcast,
        "funding has not been broadcast"
    );
    emit(
        json_output,
        json!({
            "status": if existing { "already_funded" } else { "funding_broadcast" },
            "coin_id": hex::encode(coin.keys.coin_id),
            "outpoint": metadata.outpoint.to_string(),
            "amount_sat": metadata.amount_sat,
            "funding_txid": funding.transaction.compute_txid().to_string(),
            "funding_fee_sat": funding.fee_sat,
            "funding_fee_rate_sat_vb": funding.fee_rate_sat_vb,
            "signature_count": coin.history.len(),
            "delay_blocks": recovery.delay_blocks,
            "recovery_secured": true,
            "recovery_txid": recovery.transaction.compute_txid().to_string(),
        }),
        format!(
            "Secured recovery and broadcast funding for coin {} with a {}-block delay",
            hex::encode(coin.keys.coin_id),
            recovery.delay_blocks
        ),
    )
}

fn emit_transfer_sent(
    json_output: bool,
    request: &TransferRequest,
    envelope: &TransferEnvelope,
    output_path: &Path,
    existing: bool,
) -> Result<()> {
    emit(
        json_output,
        json!({
            "status": if existing { "already_transferred" } else { "transferred" },
            "request_id": request.request_id,
            "coin_id": request.coin_id,
            "expected_amount_sat": request.expected_amount_sat,
            "output": output_path,
            "package_encrypted": true,
            "package_version": envelope.format_version,
        }),
        format!(
            "Signed and encrypted transfer {} to {}",
            request.request_id,
            output_path.display()
        ),
    )
}

fn pending_name(pending: Option<&PendingOperation>) -> Option<&'static str> {
    pending.map(|pending| match pending {
        PendingOperation::Registration { .. } => "registration",
        PendingOperation::Recovery(PendingRecovery {
            purpose: RecoveryPurpose::Fund { .. },
            ..
        }) => "funding",
        PendingOperation::Recovery(PendingRecovery {
            purpose: RecoveryPurpose::Transfer { .. },
            ..
        }) => "transfer",
    })
}

fn required_pcrs(
    pcr0: Option<String>,
    pcr1: Option<String>,
    pcr2: Option<String>,
) -> Result<(String, String, String)> {
    match (pcr0, pcr1, pcr2) {
        (Some(pcr0), Some(pcr1), Some(pcr2)) => Ok((
            pcr0.trim().to_ascii_lowercase(),
            pcr1.trim().to_ascii_lowercase(),
            pcr2.trim().to_ascii_lowercase(),
        )),
        _ => bail!("production and debug enclave modes require --pcr0, --pcr1, and --pcr2"),
    }
}

fn emit(json_output: bool, value: Value, human: String) -> Result<()> {
    if json_output {
        println!("{}", serde_json::to_string(&value)?);
    } else {
        println!("{human}");
    }
    Ok(())
}

fn require_output_file(path: &Path) -> Result<()> {
    ensure!(path != Path::new("-"), "artifact output must be a file");
    Ok(())
}

#[cfg(debug_assertions)]
fn test_failpoint(name: &str) -> Result<()> {
    if std::env::var("ENCLAVIA_WALLET_TEST_FAILPOINT").as_deref() == Ok(name) {
        bail!("stopped at test failpoint {name}");
    }
    Ok(())
}

#[cfg(not(debug_assertions))]
fn test_failpoint(_: &str) -> Result<()> {
    Ok(())
}
