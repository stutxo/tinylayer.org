use std::{
    path::{Path, PathBuf},
    str::FromStr as _,
};

use anyhow::{Context as _, Result, bail, ensure};
use bitcoin::{
    Address, OutPoint,
    consensus::encode::serialize_hex,
    secp256k1::{PublicKey, Secp256k1, SecretKey},
};
use clap::{Args, Parser, Subcommand, ValueEnum};
use enclavia::Pcrs;
use serde_json::{Value, json};
use tinylayer_client::{
    CoinStatus, DELAY_STEP, INITIAL_HANDOFF, NetworkId, PROTOCOL_VERSION, authorization,
    build_exit_child, capability_hash, complete_recovery, complete_registration, funding_address,
    funding_script, prepare_recovery, prepare_registration, verify_history, verify_recovery,
    verify_sign_response, verify_status,
};

use crate::{
    model::{
        ChainConfig, Config, EnclaveConfig, FILE_FORMAT_VERSION, FundingJournal, FundingStage,
        IncomingTransfer, OutgoingTransfer, PendingOperation, PendingRecovery, Receipt,
        RecoveryAttempt, RecoveryPurpose, RecoveryStage, TransferEnvelope, TransferPayload,
        TransferRequest, WalletCoin, WalletState, decrypt_transfer, encrypt_transfer, parse_hex32,
        random_secret_key, secret_xonly,
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
        Pcrs::from_hex(&pcr0, &pcr1, &pcr2).context("invalid PCR policy")?;
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
        verify_status(&coin.keys, &status)?;
        if let Some(capability) = coin.current_capability {
            ensure!(
                status.authorization
                    == authorization(
                        &coin.keys.coin_id,
                        &capability_hash(&capability),
                        &INITIAL_HANDOFF,
                    ),
                "wallet capability does not match enclave"
            );
            ensure!(
                status.signature_count == coin.history.len() as u64,
                "wallet history does not match enclave"
            );
        }
        return emit_registration(json_output, &config, coin, true);
    }
    let enclave = connect_verified(&config).await?;
    if state.pending.is_none() {
        let client_secret = random_secret_key();
        let initial_capability = rand::random();
        let registration =
            prepare_registration(client_secret, capability_hash(&initial_capability));
        state.pending = Some(PendingOperation::Registration {
            client_secret,
            initial_capability,
            registration,
        });
        store.save(&state)?;
    }
    let pending = state
        .pending
        .take()
        .context("missing registration journal")?;
    let PendingOperation::Registration {
        client_secret,
        initial_capability,
        registration,
    } = pending
    else {
        bail!("wallet has a pending signing operation; resume that command first");
    };
    let status = enclave.register(&registration.request).await?;
    let keys = complete_registration(registration, &status)?;
    state.coin = Some(WalletCoin {
        client_secret,
        keys,
        metadata: None,
        funding: None,
        current_capability: Some(initial_capability),
        current_handoff: Some(INITIAL_HANDOFF),
        withdrawal_secret: None,
        withdrawal_recovery_index: None,
        accepted_request: None,
        history: Vec::new(),
        outgoing: None,
    });
    state.pending = None;
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
    let mut state = store.load()?;
    let funding_stage_at_start = state
        .coin
        .as_ref()
        .and_then(|coin| coin.funding.as_ref())
        .map(|funding| funding.stage);
    let needs_enclave = match state.pending.as_ref() {
        Some(PendingOperation::Recovery(PendingRecovery {
            purpose: RecoveryPurpose::Fund { .. },
            stage: RecoveryStage::Responded { .. },
        })) => false,
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
        let outcome =
            finish_pending_recovery(&store, &mut state, enclave.as_ref(), &config).await?;
        ensure!(
            matches!(outcome, RecoveryOutcome::FundingSecured),
            "pending operation did not secure funding recovery"
        );
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
    let mut state = store.load()?;
    if let Some(coin) = &state.coin
        && let Some(outgoing) = &coin.outgoing
    {
        ensure!(
            outgoing.request == request,
            "coin was transferred using another request"
        );
        write_json_destination(output_path, &outgoing.envelope)?;
        return emit_transfer_sent(json_output, &request, &outgoing.envelope, output_path, true);
    }
    if let Some(PendingOperation::Recovery(pending)) = &state.pending {
        let RecoveryPurpose::Transfer {
            request: pending_request,
        } = &pending.purpose
        else {
            bail!("wallet has pending funding; resume coin fund");
        };
        ensure!(
            pending_request == &request,
            "pending signing request does not match input"
        );
    } else if state.pending.is_some() {
        bail!("wallet has a pending registration; resume coin register");
    } else {
        ensure_destination_available(output_path)?;
        let coin = state.coin.as_ref().context("wallet has no coin")?;
        let metadata = coin
            .metadata
            .as_ref()
            .context("coin has no verified funding")?;
        ensure!(
            !coin.history.is_empty(),
            "fund the coin before transferring it"
        );
        ensure!(
            coin.funding
                .as_ref()
                .is_none_or(|funding| funding.stage == FundingStage::Broadcast),
            "funding has not been broadcast"
        );
        ensure!(
            request.coin_id()? == coin.keys.coin_id,
            "transfer request is for another coin"
        );
        ensure!(
            request.network == config.network,
            "transfer request network mismatch"
        );
        ensure!(
            request.outpoint()? == metadata.outpoint,
            "transfer request outpoint mismatch"
        );
        ensure!(
            request.expected_amount_sat == metadata.amount_sat,
            "transfer request amount mismatch"
        );
        let capability = coin
            .current_capability
            .context("coin has already been transferred")?;
        let handoff = coin
            .current_handoff
            .context("wallet has no current handoff token")?;
        let withdrawal_secret = coin
            .withdrawal_secret
            .context("wallet has no current withdrawal key")?;
        let withdrawal_secret =
            SecretKey::from_slice(&withdrawal_secret).context("saved withdrawal key is invalid")?;
        let enclave = connect_verified(&config).await?;
        let status = enclave.status(coin.keys.coin_id).await?;
        let chain = Chain::connect(&config.chain, config.network).await?;
        let observation = chain
            .verify_funding(metadata, config.min_confirmations)
            .await?;
        verify_history(
            metadata,
            &status,
            coin.client_secret,
            capability,
            handoff,
            secret_xonly(&withdrawal_secret),
            observation.confirmations,
            &coin.history,
        )?;
        let delay_blocks = coin
            .history
            .last()
            .expect("history checked non-empty")
            .delay_blocks
            .checked_sub(DELAY_STEP)
            .context("recovery delay cannot be decremented")?;
        require_reaction_margin(
            observation.confirmations,
            delay_blocks,
            config.min_reaction_blocks.max(request.min_reaction_blocks),
        )?;
        let (sign_request, prepared) = prepare_recovery(
            metadata,
            &status,
            coin.client_secret,
            capability,
            handoff,
            request.next_capability_hash()?,
            request.withdrawal_key()?,
            delay_blocks,
            observation.confirmations,
        )?;
        state.pending = Some(PendingOperation::Recovery(PendingRecovery {
            purpose: RecoveryPurpose::Transfer {
                request: request.clone(),
            },
            stage: RecoveryStage::Prepared {
                attempt: Box::new(RecoveryAttempt {
                    expected_signature_count: status.signature_count,
                    delay_blocks,
                    request: sign_request,
                    prepared: Box::new(prepared),
                }),
            },
        }));
        store.save(&state)?;
        test_failpoint("after_prepare")?;
        let outcome = finish_pending_recovery(&store, &mut state, Some(&enclave), &config).await?;
        let RecoveryOutcome::Transferred(envelope) = outcome else {
            bail!("pending operation was not a transfer");
        };
        write_json_destination(output_path, &envelope)?;
        return emit_transfer_sent(json_output, &request, &envelope, output_path, false);
    }
    let enclave = connect_verified(&config).await?;
    let outcome = finish_pending_recovery(&store, &mut state, Some(&enclave), &config).await?;
    let RecoveryOutcome::Transferred(envelope) = outcome else {
        bail!("pending operation was not a transfer");
    };
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
    ensure!(state.coin.is_none(), "wallet already contains a coin");
    ensure!(state.pending.is_none(), "wallet has a pending operation");
    let requested_margin = config
        .min_reaction_blocks
        .max(minimum_reaction_blocks.unwrap_or_default());
    let request = if let Some(incoming) = &state.incoming {
        ensure!(
            incoming.request.coin_id()? == coin_id,
            "wallet has another pending transfer request"
        );
        ensure!(
            incoming.request.outpoint()? == outpoint,
            "wallet has another pending transfer request"
        );
        ensure!(
            incoming.request.network == config.network
                && incoming.request.expected_amount_sat == amount_sat
                && incoming.request.min_reaction_blocks == requested_margin,
            "saved transfer request policy does not match this command"
        );
        incoming.request.clone()
    } else {
        ensure_destination_available(output_path)?;
        let capability: [u8; 32] = rand::random();
        let withdrawal = random_secret_key();
        let transport = random_secret_key();
        let request = TransferRequest::new(
            rand::random(),
            coin_id,
            config.network,
            outpoint,
            amount_sat,
            secret_xonly(&withdrawal),
            capability_hash(&capability),
            PublicKey::from_secret_key(&Secp256k1::new(), &transport),
            requested_margin,
        );
        request.validate()?;
        state.incoming = Some(IncomingTransfer {
            request: request.clone(),
            capability,
            withdrawal_secret: withdrawal.secret_bytes(),
            transport_secret: transport.secret_bytes(),
        });
        store.save(&state)?;
        request
    };
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
                && envelope.request_id == request.request_id,
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
    ensure!(state.coin.is_none(), "wallet already contains a coin");
    ensure!(state.pending.is_none(), "wallet has a pending operation");
    let incoming = state
        .incoming
        .as_ref()
        .context("wallet has no matching transfer request")?;
    ensure!(
        incoming.request == request,
        "saved transfer request does not match input"
    );
    let payload = decrypt_transfer(&request, incoming.transport_secret, &envelope)?;
    ensure!(
        payload.metadata.network == config.network,
        "transfer network mismatch"
    );
    ensure!(
        payload.metadata.keys.coin_id == request.coin_id()?,
        "transfer coin ID mismatch"
    );
    ensure!(
        payload.metadata.outpoint == request.outpoint()?,
        "transfer outpoint mismatch"
    );
    payload.validate_expected_amount(&request)?;
    ensure!(
        secret_xonly(&payload.client_secret) == payload.metadata.keys.client_pubkey,
        "transferred client secret does not match coin metadata"
    );
    let latest = payload
        .history
        .last()
        .context("transfer has no recovery history")?;
    let latest_delay_blocks = latest.delay_blocks;
    ensure!(
        latest.withdrawal_xonly_pubkey == request.withdrawal_key()?,
        "latest recovery does not pay the receiver"
    );
    ensure!(
        request.next_capability_hash()? == capability_hash(&incoming.capability),
        "transfer request capability is inconsistent"
    );
    let enclave = connect_verified(&config).await?;
    let status = enclave.status(payload.metadata.keys.coin_id).await?;
    let chain = Chain::connect(&config.chain, config.network).await?;
    let observation = chain
        .verify_funding(&payload.metadata, config.min_confirmations)
        .await?;
    verify_history(
        &payload.metadata,
        &status,
        payload.client_secret,
        incoming.capability,
        payload.current_handoff,
        secret_xonly(
            &SecretKey::from_slice(&incoming.withdrawal_secret)
                .context("saved withdrawal key is invalid")?,
        ),
        observation.confirmations,
        &payload.history,
    )?;
    require_reaction_margin(
        observation.confirmations,
        latest_delay_blocks,
        config.min_reaction_blocks.max(request.min_reaction_blocks),
    )?;
    state.coin = Some(WalletCoin {
        client_secret: payload.client_secret,
        keys: payload.metadata.keys.clone(),
        metadata: Some(payload.metadata),
        funding: None,
        current_capability: Some(incoming.capability),
        current_handoff: Some(payload.current_handoff),
        withdrawal_secret: Some(incoming.withdrawal_secret),
        withdrawal_recovery_index: Some(payload.history.len() - 1),
        accepted_request: Some(request.clone()),
        history: payload.history,
        outgoing: None,
    });
    state.incoming = None;
    store.save(&state)?;
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
            "confirmations": observation.confirmations,
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
    if dry_run {
        return emit(
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
        );
    }
    chain.submit_package(&parent_hex, &child_hex).await?;
    emit(
        json_output,
        json!({
            "status": "package_submitted",
            "coin_id": hex::encode(coin.keys.coin_id),
            "recovery_txid": parent_txid.to_string(),
            "exit_txid": child_txid.to_string(),
            "destination": destination.to_string(),
            "fee_rate_sat_vb": fee_rate,
            "fee_sat": fee_sat,
        }),
        format!(
            "Recovery {parent_txid} and fee-paying child {child_txid} were accepted into the configured service's mempool for {destination}; propagation and confirmation are not guaranteed"
        ),
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

enum RecoveryOutcome {
    FundingSecured,
    Transferred(TransferEnvelope),
}

async fn finish_pending_recovery(
    store: &WalletStore,
    state: &mut WalletState,
    enclave: Option<&EnclaveConnection>,
    config: &Config,
) -> Result<RecoveryOutcome> {
    loop {
        let pending = state.pending.take().context("missing signing journal")?;
        let PendingOperation::Recovery(PendingRecovery { purpose, stage }) = pending else {
            bail!("wallet does not have a pending signing operation");
        };
        match stage {
            RecoveryStage::Prepared { attempt } => {
                let enclave = enclave.context("pending signing requires the enclave")?;
                let attempt = *attempt;
                let coin = state
                    .coin
                    .as_ref()
                    .context("pending signing coin is missing")?;
                let metadata = coin
                    .metadata
                    .as_ref()
                    .context("pending signing metadata is missing")?;
                if let RecoveryPurpose::Transfer { request } = &purpose {
                    ensure!(
                        request.expected_amount_sat == metadata.amount_sat,
                        "transfer request amount mismatch"
                    );
                }
                let status = enclave.status(coin.keys.coin_id).await?;
                verify_status(&coin.keys, &status)?;
                let committed = attempt_committed(&status, &attempt)?;
                if !committed {
                    ensure!(
                        attempt_uncommitted(&status, &attempt),
                        "pending signing journal does not match live enclave state"
                    );
                    let chain = Chain::connect(&config.chain, config.network).await?;
                    let (funding_confirmations, reaction_blocks) = match &purpose {
                        RecoveryPurpose::Fund { .. } => {
                            let funding = coin
                                .funding
                                .as_ref()
                                .context("pending funding journal is missing")?;
                            ensure!(
                                funding.stage == FundingStage::Prepared,
                                "funding recovery was already secured"
                            );
                            chain.validate_prepared_funding(metadata, &funding.transaction)?;
                            (0, config.min_reaction_blocks)
                        }
                        RecoveryPurpose::Transfer { request } => {
                            let observation = chain
                                .verify_funding(metadata, config.min_confirmations)
                                .await?;
                            (
                                observation.confirmations,
                                config.min_reaction_blocks.max(request.min_reaction_blocks),
                            )
                        }
                    };
                    require_reaction_margin(
                        funding_confirmations,
                        attempt.delay_blocks,
                        reaction_blocks,
                    )?;
                }
                let response = enclave.sign(&attempt.request).await?;
                test_failpoint("after_sign")?;
                state.pending = Some(PendingOperation::Recovery(PendingRecovery {
                    purpose,
                    stage: RecoveryStage::Responded {
                        attempt: Box::new(attempt),
                        response,
                    },
                }));
                store.save(state)?;
                test_failpoint("after_response")?;
            }
            RecoveryStage::Responded { attempt, response } => {
                let RecoveryAttempt {
                    expected_signature_count,
                    delay_blocks,
                    request,
                    prepared,
                } = *attempt;
                let coin = state
                    .coin
                    .as_ref()
                    .context("pending signing coin is missing")?;
                if matches!(&purpose, RecoveryPurpose::Transfer { .. }) {
                    let enclave = enclave.context("pending transfer requires the enclave")?;
                    let status = enclave.status(coin.keys.coin_id).await?;
                    verify_status(&coin.keys, &status)?;
                    verify_sign_response(&request, expected_signature_count, &status, &response)?;
                } else {
                    ensure!(
                        expected_signature_count == 0,
                        "initial funding recovery has an invalid signature count"
                    );
                }
                let recovery =
                    complete_recovery(&request, &response, *prepared, coin.client_secret)?;
                ensure!(
                    recovery.delay_blocks == delay_blocks,
                    "pending signing delay is inconsistent"
                );
                let coin = state
                    .coin
                    .as_mut()
                    .context("pending signing coin is missing")?;
                coin.history.push(recovery);
                let outcome = match purpose {
                    RecoveryPurpose::Fund {
                        next_capability,
                        withdrawal_secret,
                    } => {
                        let funding = coin
                            .funding
                            .as_mut()
                            .context("pending funding journal is missing")?;
                        ensure!(
                            funding.stage == FundingStage::Prepared,
                            "funding recovery was already secured"
                        );
                        funding.stage = FundingStage::RecoverySecured;
                        coin.current_capability = Some(next_capability);
                        coin.current_handoff = Some(response.next_handoff);
                        coin.withdrawal_secret = Some(withdrawal_secret);
                        coin.withdrawal_recovery_index = Some(coin.history.len() - 1);
                        RecoveryOutcome::FundingSecured
                    }
                    RecoveryPurpose::Transfer { request } => {
                        let request_id = request.id()?;
                        let payload = TransferPayload {
                            format_version: FILE_FORMAT_VERSION,
                            protocol_version: PROTOCOL_VERSION,
                            request_id,
                            client_secret: coin.client_secret,
                            current_handoff: response.next_handoff,
                            metadata: coin
                                .metadata
                                .clone()
                                .context("pending transfer metadata is missing")?,
                            history: coin.history.clone(),
                        };
                        let envelope = encrypt_transfer(&request, &payload)?;
                        coin.current_capability = None;
                        coin.current_handoff = None;
                        coin.outgoing = Some(OutgoingTransfer {
                            request: request.clone(),
                            envelope: envelope.clone(),
                        });
                        RecoveryOutcome::Transferred(envelope)
                    }
                };
                state.pending = None;
                store.save(state)?;
                if matches!(&outcome, RecoveryOutcome::FundingSecured) {
                    test_failpoint("after_recovery_secured")?;
                }
                return Ok(outcome);
            }
        }
    }
}

fn attempt_uncommitted(status: &CoinStatus, attempt: &RecoveryAttempt) -> bool {
    status.signature_count == attempt.expected_signature_count
        && status.authorization
            == authorization(
                &attempt.request.coin_id,
                &capability_hash(&attempt.request.current_capability),
                &attempt.request.current_handoff,
            )
}

fn attempt_committed(status: &CoinStatus, attempt: &RecoveryAttempt) -> Result<bool> {
    let completed_count = attempt
        .expected_signature_count
        .checked_add(1)
        .context("signature count overflow")?;
    Ok(status.signature_count == completed_count)
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
            "Registered coin {}\nFunding address: {}",
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

fn test_failpoint(name: &str) -> Result<()> {
    #[cfg(debug_assertions)]
    if std::env::var("ENCLAVIA_WALLET_TEST_FAILPOINT").as_deref() == Ok(name) {
        bail!("stopped at test failpoint {name}");
    }
    Ok(())
}
