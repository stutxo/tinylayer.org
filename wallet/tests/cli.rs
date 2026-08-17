use std::{
    fs,
    net::TcpListener,
    path::Path,
    process::Command,
    sync::{Arc, Mutex, mpsc},
    thread,
};

use axum::{
    Json, Router,
    extract::{Path as AxumPath, State},
    http::StatusCode,
    routing::{get, post},
};
use bitcoin::{
    Address, KnownHrp, Transaction,
    consensus::deserialize,
    secp256k1::{Secp256k1, SecretKey},
};
use serde::Deserialize;
use serde_json::{Value, json};
use tinylayer_enclave::{Enclave, workload};

const PASSWORD: &str = "correct horse battery staple";
const AMOUNT_SAT: u64 = 100_000;

#[derive(Clone)]
struct CoreState {
    funding: Arc<Mutex<Option<Funding>>>,
    tip: Arc<Mutex<u64>>,
    confirmations: Arc<Mutex<u32>>,
}

impl Default for CoreState {
    fn default() -> Self {
        Self {
            funding: Arc::new(Mutex::new(None)),
            tip: Arc::new(Mutex::new(900)),
            confirmations: Arc::new(Mutex::new(6)),
        }
    }
}

struct Funding {
    outpoint: String,
    script_hex: String,
}

#[derive(Deserialize)]
struct RpcRequest {
    id: Value,
    method: String,
    #[serde(default)]
    params: Vec<Value>,
}

#[test]
fn alice_bob_carol_use_separate_cli_wallets() {
    let temporary = tempfile::tempdir().unwrap();
    let cookie = temporary.path().join("bitcoin.cookie");
    fs::write(&cookie, "user:password\n").unwrap();
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt as _;
        fs::set_permissions(&cookie, fs::Permissions::from_mode(0o600)).unwrap();
    }
    let (enclave_url, core_url, core_state) = start_servers();
    let alice = temporary.path().join("alice");
    let bob = temporary.path().join("bob");
    let carol = temporary.path().join("carol");
    let wrong_receiver = temporary.path().join("wrong-receiver");

    initialize(&alice, &enclave_url, &core_url, &cookie);
    initialize(&bob, &enclave_url, &core_url, &cookie);
    initialize(&carol, &enclave_url, &core_url, &cookie);
    initialize(&wrong_receiver, &enclave_url, &core_url, &cookie);
    let verified = run(&alice, &["enclave", "verify"]);
    assert_eq!(verified["status"], "verified");
    assert_eq!(verified["client_protocol_version"], 1);

    let registered = run(&alice, &["coin", "register"]);
    assert_eq!(registered["status"], "registered");
    let coin_id = registered["coin_id"].as_str().unwrap().to_owned();
    let outpoint = format!("{}:0", "42".repeat(32));
    *core_state.funding.lock().unwrap() = Some(Funding {
        outpoint: outpoint.clone(),
        script_hex: registered["funding_script_hex"]
            .as_str()
            .unwrap()
            .to_owned(),
    });
    assert_eq!(
        run(
            &alice,
            &[
                "coin",
                "fund",
                "--outpoint",
                &outpoint,
                "--amount-sat",
                &AMOUNT_SAT.to_string(),
            ],
        )["status"],
        "funded"
    );
    assert_eq!(
        run_failure_with_env(
            &alice,
            &["coin", "activate", "--locktime", "1000"],
            "after_prepare",
        )["error"],
        "stopped at test failpoint after_prepare"
    );
    *core_state.tip.lock().unwrap() = 990;
    assert_eq!(
        run_failure(&alice, &["coin", "activate", "--locktime", "1000"])["error"],
        "latest recovery locktime 1000 must be greater than tip 990 plus reaction margin 20"
    );
    assert_eq!(
        run(&alice, &["coin", "activate", "--locktime", "1050"])["status"],
        "activated"
    );

    let wrong_request = temporary.path().join("wrong-amount-request.json");
    let wrong_package = temporary.path().join("wrong-amount-package.json");
    run(
        &wrong_receiver,
        &[
            "transfer",
            "request",
            "--coin-id",
            &coin_id,
            "--outpoint",
            &outpoint,
            "--amount-sat",
            &(AMOUNT_SAT - 1).to_string(),
            "--output",
            wrong_request.to_str().unwrap(),
        ],
    );
    let count_before_mismatch = run(&alice, &["coin", "status"])["signature_count"].clone();
    assert_eq!(
        run_failure(
            &alice,
            &[
                "coin",
                "sign",
                "--request",
                wrong_request.to_str().unwrap(),
                "--output",
                wrong_package.to_str().unwrap(),
            ],
        )["error"],
        "transfer request amount mismatch"
    );
    assert!(!wrong_package.exists());
    assert_eq!(
        run(&alice, &["coin", "status"])["signature_count"],
        count_before_mismatch
    );

    let bob_request = temporary.path().join("bob-request.json");
    let alice_to_bob = temporary.path().join("alice-to-bob.json");
    assert_eq!(
        run(
            &bob,
            &[
                "transfer",
                "request",
                "--coin-id",
                &coin_id,
                "--outpoint",
                &outpoint,
                "--amount-sat",
                &AMOUNT_SAT.to_string(),
                "--output",
                bob_request.to_str().unwrap(),
            ],
        )["status"],
        "transfer_requested"
    );
    let bob_request_json: Value =
        serde_json::from_str(&fs::read_to_string(&bob_request).unwrap()).unwrap();
    assert_eq!(bob_request_json["format_version"], 3);
    assert_eq!(bob_request_json["protocol_version"], 1);
    assert_eq!(bob_request_json["expected_amount_sat"], AMOUNT_SAT);
    assert_no_raw_handoff(&bob_request_json);

    let incompatible_request = temporary.path().join("protocol-2-request.json");
    let incompatible_package = temporary.path().join("protocol-2-package.json");
    let mut incompatible_json = bob_request_json.clone();
    incompatible_json["protocol_version"] = json!(2);
    fs::write(
        &incompatible_request,
        serde_json::to_vec_pretty(&incompatible_json).unwrap(),
    )
    .unwrap();
    let count_before_incompatible = run(&alice, &["coin", "status"])["signature_count"].clone();
    assert_eq!(
        run_failure(
            &alice,
            &[
                "coin",
                "sign",
                "--request",
                incompatible_request.to_str().unwrap(),
                "--output",
                incompatible_package.to_str().unwrap(),
            ],
        )["error"],
        "transfer protocol version mismatch"
    );
    assert!(!incompatible_package.exists());
    assert_eq!(
        run(&alice, &["coin", "status"])["signature_count"],
        count_before_incompatible
    );

    assert_eq!(
        run_failure(
            &alice,
            &[
                "coin",
                "sign",
                "--request",
                bob_request.to_str().unwrap(),
                "--output",
                alice.join("wallet.enc").to_str().unwrap(),
            ],
        )["error"],
        format!(
            "refusing to overwrite existing file: {}",
            alice.join("wallet.enc").display()
        )
    );
    assert_eq!(
        run_failure_with_env(
            &alice,
            &[
                "coin",
                "sign",
                "--request",
                bob_request.to_str().unwrap(),
                "--output",
                alice_to_bob.to_str().unwrap(),
            ],
            "after_sign",
        )["error"],
        "stopped at test failpoint after_sign"
    );
    assert!(!alice_to_bob.exists());
    assert_eq!(
        run_failure_with_env(
            &alice,
            &[
                "coin",
                "sign",
                "--request",
                bob_request.to_str().unwrap(),
                "--output",
                alice_to_bob.to_str().unwrap(),
            ],
            "after_response",
        )["error"],
        "stopped at test failpoint after_response"
    );
    assert!(!alice_to_bob.exists());
    assert_eq!(
        run(
            &alice,
            &[
                "coin",
                "sign",
                "--request",
                bob_request.to_str().unwrap(),
                "--output",
                alice_to_bob.to_str().unwrap(),
            ],
        )["status"],
        "transferred"
    );
    assert_eq!(
        run(
            &alice,
            &[
                "coin",
                "sign",
                "--request",
                bob_request.to_str().unwrap(),
                "--output",
                alice_to_bob.to_str().unwrap(),
            ],
        )["status"],
        "already_transferred"
    );
    assert_eq!(
        run(
            &bob,
            &[
                "transfer",
                "accept",
                "--request",
                bob_request.to_str().unwrap(),
                "--package",
                alice_to_bob.to_str().unwrap(),
            ],
        )["signature_count"],
        2
    );
    assert_eq!(
        run(
            &bob,
            &[
                "transfer",
                "accept",
                "--request",
                bob_request.to_str().unwrap(),
                "--package",
                alice_to_bob.to_str().unwrap(),
            ],
        )["status"],
        "already_accepted"
    );

    let carol_request = temporary.path().join("carol-request.json");
    let bob_to_carol = temporary.path().join("bob-to-carol.json");
    run(
        &carol,
        &[
            "transfer",
            "request",
            "--coin-id",
            &coin_id,
            "--outpoint",
            &outpoint,
            "--amount-sat",
            &AMOUNT_SAT.to_string(),
            "--output",
            carol_request.to_str().unwrap(),
        ],
    );
    run(
        &bob,
        &[
            "coin",
            "sign",
            "--request",
            carol_request.to_str().unwrap(),
            "--output",
            bob_to_carol.to_str().unwrap(),
        ],
    );
    let accepted = run(
        &carol,
        &[
            "transfer",
            "accept",
            "--request",
            carol_request.to_str().unwrap(),
            "--package",
            bob_to_carol.to_str().unwrap(),
        ],
    );
    assert_eq!(accepted["signature_count"], 3);
    assert_eq!(accepted["expected_amount_sat"], AMOUNT_SAT);
    let status = run(&carol, &["coin", "status"]);
    assert_eq!(status["lifecycle"], "owned");
    assert_eq!(status["signature_count"], 3);
    assert_eq!(status["history_current"], true);
    assert_no_raw_handoff(&status);

    let receipt = temporary.path().join("receipt.json");
    run(
        &carol,
        &["receipt", "export", "--output", receipt.to_str().unwrap()],
    );
    let receipt_json: Value = serde_json::from_str(&fs::read_to_string(&receipt).unwrap()).unwrap();
    assert_eq!(receipt_json["format_version"], 3);
    assert_eq!(receipt_json["protocol_version"], 1);
    assert_no_raw_handoff(&receipt_json);
    let incompatible_receipt = temporary.path().join("protocol-2-receipt.json");
    let mut incompatible_receipt_json = receipt_json.clone();
    incompatible_receipt_json["protocol_version"] = json!(2);
    fs::write(
        &incompatible_receipt,
        serde_json::to_vec_pretty(&incompatible_receipt_json).unwrap(),
    )
    .unwrap();
    assert_eq!(
        run_failure(
            &alice,
            &[
                "receipt",
                "verify",
                "--input",
                incompatible_receipt.to_str().unwrap(),
            ],
        )["error"],
        "receipt protocol version mismatch"
    );
    assert_eq!(
        run(
            &alice,
            &["receipt", "verify", "--input", receipt.to_str().unwrap(),],
        )["status"],
        "receipt_verified"
    );
    *core_state.tip.lock().unwrap() = 1_100;
    let alice_recovery = temporary.path().join("alice-recovery.hex");
    run(
        &alice,
        &[
            "coin",
            "recovery",
            "--output",
            alice_recovery.to_str().unwrap(),
        ],
    );
    let recovery = temporary.path().join("carol-recovery.hex");
    run(
        &carol,
        &["coin", "recovery", "--output", recovery.to_str().unwrap()],
    );
    let recovery_hex = fs::read_to_string(&recovery).unwrap();
    assert!(recovery_hex.trim().len() > 100);
    let recovery_tx: Transaction = deserialize(&hex::decode(recovery_hex.trim()).unwrap()).unwrap();
    assert_eq!(recovery_tx.input[0].witness.len(), 4);
    assert_ne!(
        fs::read_to_string(alice_recovery).unwrap(),
        fs::read_to_string(temporary.path().join("carol-recovery.hex")).unwrap()
    );

    let encrypted_package = fs::read_to_string(alice_to_bob).unwrap();
    assert!(encrypted_package.contains("ciphertext"));
    assert!(!encrypted_package.contains("client_secret"));
    let encrypted_package_json: Value = serde_json::from_str(&encrypted_package).unwrap();
    assert_eq!(encrypted_package_json["format_version"], 3);
    assert_no_raw_handoff(&encrypted_package_json);
    assert!(
        !fs::read_to_string(alice.join("wallet.enc"))
            .unwrap()
            .contains("client_secret")
    );
}

#[test]
fn committed_superseded_activation_is_recovered() {
    let temporary = tempfile::tempdir().unwrap();
    let cookie = temporary.path().join("bitcoin.cookie");
    fs::write(&cookie, "user:password\n").unwrap();
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt as _;
        fs::set_permissions(&cookie, fs::Permissions::from_mode(0o600)).unwrap();
    }
    let (enclave_url, core_url, core_state) = start_servers();
    let alice = temporary.path().join("alice");
    initialize(&alice, &enclave_url, &core_url, &cookie);
    let registered = run(&alice, &["coin", "register"]);
    let outpoint = format!("{}:1", "43".repeat(32));
    *core_state.funding.lock().unwrap() = Some(Funding {
        outpoint: outpoint.clone(),
        script_hex: registered["funding_script_hex"]
            .as_str()
            .unwrap()
            .to_owned(),
    });
    run(
        &alice,
        &[
            "coin",
            "fund",
            "--outpoint",
            &outpoint,
            "--amount-sat",
            &AMOUNT_SAT.to_string(),
        ],
    );
    run_failure_with_env(
        &alice,
        &["coin", "activate", "--locktime", "1000"],
        "after_prepare",
    );
    *core_state.tip.lock().unwrap() = 990;
    assert_eq!(
        run_failure_with_env(
            &alice,
            &["coin", "activate", "--locktime", "1050"],
            "after_prepare",
        )["error"],
        "stopped at test failpoint after_prepare"
    );
    assert_eq!(
        run_failure_with_env(
            &alice,
            &["coin", "activate", "--locktime", "1050"],
            "commit_superseded",
        )["error"],
        "stopped at test failpoint commit_superseded"
    );
    let recovered = run(&alice, &["coin", "activate", "--locktime", "1050"]);
    assert_eq!(recovered["status"], "activated");
    assert_eq!(recovered["locktime"], 1000);
}

#[test]
fn default_and_explicit_confirmation_policies_are_enforced() {
    let temporary = tempfile::tempdir().unwrap();
    let cookie = temporary.path().join("bitcoin.cookie");
    fs::write(&cookie, "user:password\n").unwrap();
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt as _;
        fs::set_permissions(&cookie, fs::Permissions::from_mode(0o600)).unwrap();
    }
    let (enclave_url, core_url, core_state) = start_servers();
    *core_state.confirmations.lock().unwrap() = 5;

    let default_wallet = temporary.path().join("default-confirmations");
    run(
        &default_wallet,
        &[
            "init",
            "--network",
            "regtest",
            "--enclave-url",
            &enclave_url,
            "--unsafe-plaintext",
            "--bitcoin-rpc-url",
            &core_url,
            "--bitcoin-cookie-file",
            cookie.to_str().unwrap(),
        ],
    );
    let default_config: Value =
        serde_json::from_str(&fs::read_to_string(default_wallet.join("config.json")).unwrap())
            .unwrap();
    assert_eq!(default_config["format_version"], 3);
    assert_eq!(default_config["protocol_version"], 1);
    assert_eq!(default_config["min_confirmations"], 6);
    let registered = run(&default_wallet, &["coin", "register"]);
    let default_outpoint = format!("{}:0", "44".repeat(32));
    *core_state.funding.lock().unwrap() = Some(Funding {
        outpoint: default_outpoint.clone(),
        script_hex: registered["funding_script_hex"]
            .as_str()
            .unwrap()
            .to_owned(),
    });
    assert_eq!(
        run_failure(
            &default_wallet,
            &[
                "coin",
                "fund",
                "--outpoint",
                &default_outpoint,
                "--amount-sat",
                &AMOUNT_SAT.to_string(),
            ],
        )["error"],
        "funding output has 5 confirmations; 6 required"
    );

    let explicit_wallet = temporary.path().join("explicit-confirmations");
    initialize(&explicit_wallet, &enclave_url, &core_url, &cookie);
    let explicit_config: Value =
        serde_json::from_str(&fs::read_to_string(explicit_wallet.join("config.json")).unwrap())
            .unwrap();
    assert_eq!(explicit_config["min_confirmations"], 1);
    let registered = run(&explicit_wallet, &["coin", "register"]);
    let explicit_outpoint = format!("{}:0", "45".repeat(32));
    *core_state.funding.lock().unwrap() = Some(Funding {
        outpoint: explicit_outpoint.clone(),
        script_hex: registered["funding_script_hex"]
            .as_str()
            .unwrap()
            .to_owned(),
    });
    assert_eq!(
        run(
            &explicit_wallet,
            &[
                "coin",
                "fund",
                "--outpoint",
                &explicit_outpoint,
                "--amount-sat",
                &AMOUNT_SAT.to_string(),
            ],
        )["status"],
        "funded"
    );
}

#[test]
fn mainnet_is_unavailable_from_cli_and_handcrafted_config() {
    let temporary = tempfile::tempdir().unwrap();
    let rejected = Command::new(env!("CARGO_BIN_EXE_tinylayer-wallet"))
        .arg("--data-dir")
        .arg(temporary.path().join("rejected"))
        .arg("--json")
        .args([
            "init",
            "--network",
            "mainnet",
            "--enclave-url",
            "http://127.0.0.1:1",
            "--unsafe-plaintext",
            "--chain-url",
            "http://127.0.0.1:2",
        ])
        .env("ENCLAVIA_WALLET_PASSWORD", PASSWORD)
        .output()
        .unwrap();
    assert!(!rejected.status.success());
    assert!(String::from_utf8_lossy(&rejected.stderr).contains("invalid value 'mainnet'"));

    let handcrafted = temporary.path().join("handcrafted");
    run(
        &handcrafted,
        &[
            "init",
            "--network",
            "regtest",
            "--enclave-url",
            "http://127.0.0.1:1",
            "--unsafe-plaintext",
            "--chain-url",
            "http://127.0.0.1:2",
            "--min-confirmations",
            "1",
        ],
    );
    let config_path = handcrafted.join("config.json");
    let mut config: Value =
        serde_json::from_str(&fs::read_to_string(&config_path).unwrap()).unwrap();
    config["network"] = json!("mainnet");
    fs::write(&config_path, serde_json::to_vec_pretty(&config).unwrap()).unwrap();
    assert_eq!(
        run_failure(&handcrafted, &["coin", "status"])["error"],
        "mainnet is not supported by this wallet"
    );
}

#[test]
fn explorer_backed_wallet_exits_with_a_fee_paying_child() {
    let temporary = tempfile::tempdir().unwrap();
    let (enclave_url, explorer_url, explorer_state) = start_explorer_servers();
    let explorer_url = format!("{explorer_url}/api");
    let alice = temporary.path().join("alice");
    let output = run(
        &alice,
        &[
            "init",
            "--network",
            "regtest",
            "--enclave-url",
            &enclave_url,
            "--unsafe-plaintext",
            "--chain-url",
            &explorer_url,
            "--min-confirmations",
            "1",
        ],
    );
    assert_eq!(output["status"], "initialized");

    let registered = run(&alice, &["coin", "register"]);
    let outpoint = format!("{}:0", "42".repeat(32));
    *explorer_state.funding.lock().unwrap() = Some(Funding {
        outpoint: outpoint.clone(),
        script_hex: registered["funding_script_hex"]
            .as_str()
            .unwrap()
            .to_owned(),
    });
    run(
        &alice,
        &[
            "coin",
            "fund",
            "--outpoint",
            &outpoint,
            "--amount-sat",
            &AMOUNT_SAT.to_string(),
        ],
    );
    run(&alice, &["coin", "activate", "--locktime", "1000"]);

    let destination = destination_address();
    assert!(
        run_failure(
            &alice,
            &[
                "coin",
                "exit",
                "--destination",
                &destination,
                "--max-fee-sat",
                "10000",
            ],
        )["error"]
            .as_str()
            .unwrap()
            .contains("not final")
    );

    let recovery = temporary.path().join("recovery.hex");
    run(
        &alice,
        &["coin", "recovery", "--output", recovery.to_str().unwrap()],
    );
    let parent_hex = fs::read_to_string(&recovery).unwrap().trim().to_owned();

    *explorer_state.tip.lock().unwrap() = 1_000;
    assert_eq!(
        run_failure(
            &alice,
            &[
                "coin",
                "exit",
                "--destination",
                &destination,
                "--fee-rate",
                "0",
                "--max-fee-sat",
                "0",
            ],
        )["error"],
        "exit fee rate must be positive"
    );
    assert!(explorer_state.packages.lock().unwrap().is_empty());
    assert!(
        run_failure(
            &alice,
            &[
                "coin",
                "exit",
                "--destination",
                &destination,
                "--max-fee-sat",
                "0",
            ],
        )["error"]
            .as_str()
            .unwrap()
            .contains("exceeds maximum 0 sat")
    );
    assert!(explorer_state.packages.lock().unwrap().is_empty());
    assert!(
        run_failure(
            &alice,
            &[
                "coin",
                "exit",
                "--destination",
                &destination,
                "--fee-rate",
                "2",
                "--max-fee-sat",
                "0",
            ],
        )["error"]
            .as_str()
            .unwrap()
            .contains("exceeds maximum 0 sat")
    );
    assert!(explorer_state.packages.lock().unwrap().is_empty());
    let exited = run(
        &alice,
        &[
            "coin",
            "exit",
            "--destination",
            &destination,
            "--max-fee-sat",
            "10000",
        ],
    );
    assert_eq!(exited["status"], "package_submitted");
    assert_eq!(exited["fee_rate_sat_vb"], 1);

    let packages = explorer_state.packages.lock().unwrap().clone();
    assert_eq!(packages.len(), 1);
    assert_eq!(packages[0][0], parent_hex, "package parent is the recovery");
    let parent_txid = exited["recovery_txid"].as_str().unwrap();
    let child_txid = exited["exit_txid"].as_str().unwrap();
    assert_ne!(parent_txid, child_txid);
}

fn destination_address() -> String {
    let secret = SecretKey::from_slice(&[7u8; 32]).unwrap();
    let (xonly, _) = secret.x_only_public_key(&Secp256k1::new());
    Address::p2tr(&Secp256k1::new(), xonly, None, KnownHrp::Regtest).to_string()
}

#[derive(Clone)]
struct ExplorerState {
    funding: Arc<Mutex<Option<Funding>>>,
    tip: Arc<Mutex<u64>>,
    packages: Arc<Mutex<Vec<Vec<String>>>>,
}

fn start_explorer_servers() -> (String, String, ExplorerState) {
    let enclave_listener = TcpListener::bind("127.0.0.1:0").unwrap();
    let explorer_listener = TcpListener::bind("127.0.0.1:0").unwrap();
    enclave_listener.set_nonblocking(true).unwrap();
    explorer_listener.set_nonblocking(true).unwrap();
    let enclave_address = enclave_listener.local_addr().unwrap();
    let explorer_address = explorer_listener.local_addr().unwrap();
    let explorer_state = ExplorerState {
        funding: Arc::new(Mutex::new(None)),
        tip: Arc::new(Mutex::new(900)),
        packages: Arc::new(Mutex::new(Vec::new())),
    };
    let server_state = explorer_state.clone();
    let (ready_tx, ready_rx) = mpsc::channel();
    thread::spawn(move || {
        let runtime = tokio::runtime::Runtime::new().unwrap();
        runtime.block_on(async move {
            let enclave_listener = tokio::net::TcpListener::from_std(enclave_listener).unwrap();
            let explorer_listener = tokio::net::TcpListener::from_std(explorer_listener).unwrap();
            let explorer = Router::new()
                .route("/api/blocks/tip/height", get(explorer_tip))
                .route("/api/block-height/{height}", get(explorer_block_hash))
                .route("/api/tx/{txid}", get(explorer_tx))
                .route("/api/tx/{txid}/outspends", get(explorer_outspends))
                .route("/api/v1/fees/recommended", get(explorer_fees))
                .route("/api/v1/txs/package", post(explorer_package))
                .with_state(server_state);
            ready_tx.send(()).unwrap();
            let _ = tokio::join!(
                axum::serve(enclave_listener, workload::router(Enclave::new())),
                axum::serve(explorer_listener, explorer),
            );
        });
    });
    ready_rx.recv().unwrap();
    (
        format!("http://{enclave_address}"),
        format!("http://{explorer_address}"),
        explorer_state,
    )
}

fn funding_vout(funding: &Funding) -> u64 {
    funding
        .outpoint
        .rsplit_once(':')
        .and_then(|(_, vout)| vout.parse().ok())
        .unwrap_or(0)
}

fn funding_tx_json(state: &ExplorerState, txid: &str) -> Option<Value> {
    let funding = state.funding.lock().unwrap();
    let funding = funding.as_ref()?;
    let (funding_txid, _) = funding.outpoint.rsplit_once(':')?;
    if funding_txid != txid {
        return None;
    }
    let vout = funding_vout(funding) as usize;
    let mut outputs = vec![json!({ "value": 0, "scriptpubkey": "" }); vout];
    outputs.push(json!({
        "value": AMOUNT_SAT,
        "scriptpubkey": funding.script_hex,
    }));
    Some(json!({
        "txid": txid,
        "status": {
            "confirmed": true,
            "block_height": *state.tip.lock().unwrap() - 5,
            "block_hash": "11".repeat(32),
        },
        "vin": [{ "is_coinbase": false }],
        "vout": outputs,
    }))
}

async fn explorer_tip(State(state): State<ExplorerState>) -> String {
    state.tip.lock().unwrap().to_string()
}

async fn explorer_block_hash() -> String {
    "11".repeat(32)
}

async fn explorer_tx(
    State(state): State<ExplorerState>,
    AxumPath(txid): AxumPath<String>,
) -> Result<Json<Value>, StatusCode> {
    funding_tx_json(&state, &txid)
        .map(Json)
        .ok_or(StatusCode::NOT_FOUND)
}

async fn explorer_outspends(
    State(state): State<ExplorerState>,
    AxumPath(txid): AxumPath<String>,
) -> Result<Json<Value>, StatusCode> {
    let funding = state.funding.lock().unwrap();
    let funding = funding.as_ref().ok_or(StatusCode::NOT_FOUND)?;
    let (funding_txid, _) = funding
        .outpoint
        .rsplit_once(':')
        .ok_or(StatusCode::NOT_FOUND)?;
    if funding_txid != txid {
        return Err(StatusCode::NOT_FOUND);
    }
    let vout = funding_vout(funding);
    Ok(Json(json!(vec![
        json!({ "spent": false });
        vout as usize + 1
    ])))
}

async fn explorer_fees() -> Json<Value> {
    Json(json!({ "fastestFee": 1 }))
}

async fn explorer_package(
    State(state): State<ExplorerState>,
    Json(package): Json<Vec<String>>,
) -> Json<Value> {
    state.packages.lock().unwrap().push(package);
    Json(json!({ "package_msg": "success", "tx-results": {} }))
}

fn initialize(directory: &Path, enclave_url: &str, core_url: &str, cookie: &Path) {
    let output = run(
        directory,
        &[
            "init",
            "--network",
            "regtest",
            "--enclave-url",
            enclave_url,
            "--unsafe-plaintext",
            "--bitcoin-rpc-url",
            core_url,
            "--bitcoin-cookie-file",
            cookie.to_str().unwrap(),
            "--min-confirmations",
            "1",
        ],
    );
    assert_eq!(output["status"], "initialized");
}

fn assert_no_raw_handoff(value: &Value) {
    match value {
        Value::Array(values) => {
            for value in values {
                assert_no_raw_handoff(value);
            }
        }
        Value::Object(fields) => {
            for (name, value) in fields {
                assert!(
                    !matches!(
                        name.as_str(),
                        "current_handoff"
                            | "current_handoff_token"
                            | "next_handoff"
                            | "next_handoff_token"
                    ),
                    "raw handoff field leaked into output: {name}"
                );
                assert_no_raw_handoff(value);
            }
        }
        _ => {}
    }
}

fn run(directory: &Path, arguments: &[&str]) -> Value {
    let output = Command::new(env!("CARGO_BIN_EXE_tinylayer-wallet"))
        .arg("--data-dir")
        .arg(directory)
        .arg("--json")
        .args(arguments)
        .env("ENCLAVIA_WALLET_PASSWORD", PASSWORD)
        .output()
        .unwrap();
    assert!(
        output.status.success(),
        "command {arguments:?} failed:\nstdout: {}\nstderr: {}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );
    serde_json::from_slice(&output.stdout).unwrap()
}

fn run_failure(directory: &Path, arguments: &[&str]) -> Value {
    let output = Command::new(env!("CARGO_BIN_EXE_tinylayer-wallet"))
        .arg("--data-dir")
        .arg(directory)
        .arg("--json")
        .args(arguments)
        .env("ENCLAVIA_WALLET_PASSWORD", PASSWORD)
        .output()
        .unwrap();
    assert!(!output.status.success(), "command unexpectedly succeeded");
    serde_json::from_slice(&output.stderr).unwrap()
}

fn run_failure_with_env(directory: &Path, arguments: &[&str], failpoint: &str) -> Value {
    let output = Command::new(env!("CARGO_BIN_EXE_tinylayer-wallet"))
        .arg("--data-dir")
        .arg(directory)
        .arg("--json")
        .args(arguments)
        .env("ENCLAVIA_WALLET_PASSWORD", PASSWORD)
        .env("ENCLAVIA_WALLET_TEST_FAILPOINT", failpoint)
        .output()
        .unwrap();
    assert!(!output.status.success(), "command unexpectedly succeeded");
    serde_json::from_slice(&output.stderr).unwrap()
}

fn start_servers() -> (String, String, CoreState) {
    let enclave_listener = TcpListener::bind("127.0.0.1:0").unwrap();
    let core_listener = TcpListener::bind("127.0.0.1:0").unwrap();
    enclave_listener.set_nonblocking(true).unwrap();
    core_listener.set_nonblocking(true).unwrap();
    let enclave_address = enclave_listener.local_addr().unwrap();
    let core_address = core_listener.local_addr().unwrap();
    let core_state = CoreState::default();
    let server_state = core_state.clone();
    let (ready_tx, ready_rx) = mpsc::channel();
    thread::spawn(move || {
        let runtime = tokio::runtime::Runtime::new().unwrap();
        runtime.block_on(async move {
            let enclave_listener = tokio::net::TcpListener::from_std(enclave_listener).unwrap();
            let core_listener = tokio::net::TcpListener::from_std(core_listener).unwrap();
            let core = Router::new()
                .route("/", post(core_rpc))
                .with_state(server_state);
            ready_tx.send(()).unwrap();
            let _ = tokio::join!(
                axum::serve(enclave_listener, workload::router(Enclave::new())),
                axum::serve(core_listener, core),
            );
        });
    });
    ready_rx.recv().unwrap();
    (
        format!("http://{enclave_address}"),
        format!("http://{core_address}"),
        core_state,
    )
}

async fn core_rpc(State(state): State<CoreState>, Json(request): Json<RpcRequest>) -> Json<Value> {
    let result = match request.method.as_str() {
        "getblockchaininfo" => json!({
            "chain": "regtest",
            "blocks": *state.tip.lock().unwrap(),
            "bestblockhash": "00".repeat(32)
        }),
        "gettxout" => {
            let outpoint = format!(
                "{}:{}",
                request
                    .params
                    .first()
                    .and_then(Value::as_str)
                    .unwrap_or_default(),
                request
                    .params
                    .get(1)
                    .and_then(Value::as_u64)
                    .unwrap_or_default()
            );
            match state.funding.lock().unwrap().as_ref() {
                Some(funding) if funding.outpoint == outpoint => json!({
                    "bestblock": "00".repeat(32),
                    "confirmations": *state.confirmations.lock().unwrap(),
                    "value": 0.001,
                    "scriptPubKey": {
                        "asm": "",
                        "hex": funding.script_hex,
                        "type": "witness_v1_taproot"
                    },
                    "coinbase": false
                }),
                _ => Value::Null,
            }
        }
        method => {
            return Json(json!({
                "result": Value::Null,
                "error": { "code": -32601, "message": format!("unknown method {method}") },
                "id": request.id,
            }));
        }
    };
    Json(json!({ "result": result, "error": Value::Null, "id": request.id }))
}
