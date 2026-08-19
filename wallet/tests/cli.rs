use std::{
    collections::{HashMap, HashSet},
    fs,
    net::TcpListener,
    path::Path,
    process::Command,
    str::FromStr as _,
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
    Address, Amount, KnownHrp, OutPoint, ScriptBuf, Sequence, Transaction, TxIn, TxOut, Txid,
    Witness, absolute,
    address::NetworkUnchecked,
    consensus::{deserialize, encode::serialize_hex},
    hashes::Hash as _,
    secp256k1::{Secp256k1, SecretKey},
    transaction::Version,
};
use serde::Deserialize;
use serde_json::{Value, json};
use tinylayer_enclave::{Enclave, workload};

const PASSWORD: &str = "correct horse battery staple";
const AMOUNT_SAT: u64 = 100_000;

#[derive(Clone)]
struct CoreState {
    funding: Arc<Mutex<Option<Funding>>>,
    prepared: Arc<Mutex<Option<Transaction>>>,
    broadcasts: Arc<Mutex<Vec<String>>>,
    confirmed_transactions: Arc<Mutex<HashMap<Txid, Transaction>>>,
    locked_inputs: Arc<Mutex<Vec<OutPoint>>>,
    lock_calls: Arc<Mutex<u32>>,
    in_mempool: Arc<Mutex<bool>>,
    hide_wallet_transactions: Arc<Mutex<bool>>,
    tip: Arc<Mutex<u64>>,
    confirmations: Arc<Mutex<u32>>,
}

impl Default for CoreState {
    fn default() -> Self {
        Self {
            funding: Arc::new(Mutex::new(None)),
            prepared: Arc::new(Mutex::new(None)),
            broadcasts: Arc::new(Mutex::new(Vec::new())),
            confirmed_transactions: Arc::new(Mutex::new(HashMap::new())),
            locked_inputs: Arc::new(Mutex::new(Vec::new())),
            lock_calls: Arc::new(Mutex::new(0)),
            in_mempool: Arc::new(Mutex::new(false)),
            hide_wallet_transactions: Arc::new(Mutex::new(false)),
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
    let funded = run(
        &alice,
        &[
            "coin",
            "fund",
            "--amount-sat",
            &AMOUNT_SAT.to_string(),
            "--delay-blocks",
            "100",
            "--max-fee-sat",
            "1000",
        ],
    );
    assert_eq!(funded["status"], "funding_broadcast");
    assert_eq!(funded["recovery_secured"], true);
    assert_eq!(funded["delay_blocks"], 100);
    let outpoint = funded["outpoint"].as_str().unwrap().to_owned();
    assert_eq!(core_state.broadcasts.lock().unwrap().len(), 1);
    *core_state.hide_wallet_transactions.lock().unwrap() = true;

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
    assert_eq!(bob_request_json["format_version"], 1);
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
    assert_eq!(receipt_json["format_version"], 1);
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
    let bob_recovery = temporary.path().join("bob-recovery.hex");
    run(
        &bob,
        &[
            "coin",
            "recovery",
            "--output",
            bob_recovery.to_str().unwrap(),
        ],
    );
    let recovery = temporary.path().join("carol-recovery.hex");
    run(
        &carol,
        &["coin", "recovery", "--output", recovery.to_str().unwrap()],
    );
    let recovery_hex = fs::read_to_string(&recovery).unwrap();
    assert!(recovery_hex.trim().len() > 100);
    let alice_tx: Transaction =
        deserialize(&hex::decode(fs::read_to_string(&alice_recovery).unwrap().trim()).unwrap())
            .unwrap();
    let bob_tx: Transaction =
        deserialize(&hex::decode(fs::read_to_string(&bob_recovery).unwrap().trim()).unwrap())
            .unwrap();
    let carol_tx: Transaction = deserialize(&hex::decode(recovery_hex.trim()).unwrap()).unwrap();
    assert_eq!(carol_tx.input[0].witness.len(), 4);
    assert_eq!(alice_tx.lock_time, absolute::LockTime::ZERO);
    assert_eq!(bob_tx.lock_time, absolute::LockTime::ZERO);
    assert_eq!(carol_tx.lock_time, absolute::LockTime::ZERO);
    assert_eq!(alice_tx.input[0].sequence, Sequence::from_height(100));
    assert_eq!(bob_tx.input[0].sequence, Sequence::from_height(90));
    assert_eq!(carol_tx.input[0].sequence, Sequence::from_height(80));
    *core_state.confirmations.lock().unwrap() = 80;
    let mature_status = run(&carol, &["coin", "status"]);
    assert_eq!(mature_status["reaction_safe"], false);
    assert_eq!(mature_status["lifecycle"], "owned");
    assert_ne!(
        fs::read_to_string(alice_recovery).unwrap(),
        fs::read_to_string(temporary.path().join("carol-recovery.hex")).unwrap()
    );

    let encrypted_package = fs::read_to_string(alice_to_bob).unwrap();
    assert!(encrypted_package.contains("ciphertext"));
    assert!(!encrypted_package.contains("client_secret"));
    let encrypted_package_json: Value = serde_json::from_str(&encrypted_package).unwrap();
    assert_eq!(encrypted_package_json["format_version"], 1);
    assert_no_raw_handoff(&encrypted_package_json);
    assert!(
        !fs::read_to_string(alice.join("wallet.enc"))
            .unwrap()
            .contains("client_secret")
    );
}

#[test]
fn funding_is_never_broadcast_before_recovery_is_durable() {
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
    run(&alice, &["coin", "register"]);
    let fund = [
        "coin",
        "fund",
        "--amount-sat",
        "100000",
        "--delay-blocks",
        "100",
        "--max-fee-sat",
        "1000",
    ];

    assert_eq!(
        run_failure_with_env(&alice, &fund, "after_funding_prepared")["error"],
        "stopped at test failpoint after_funding_prepared"
    );
    assert!(core_state.broadcasts.lock().unwrap().is_empty());
    assert_eq!(*core_state.lock_calls.lock().unwrap(), 0);
    assert_eq!(
        run(&alice, &["coin", "status"])["lifecycle"],
        "funding_prepared"
    );

    for failpoint in ["after_prepare", "after_sign", "after_response"] {
        assert_eq!(
            run_failure_with_env(&alice, &fund, failpoint)["error"],
            format!("stopped at test failpoint {failpoint}")
        );
        assert!(core_state.broadcasts.lock().unwrap().is_empty());
    }

    assert_eq!(
        run_failure_with_env(&alice, &fund, "after_recovery_secured")["error"],
        "stopped at test failpoint after_recovery_secured"
    );
    assert!(core_state.broadcasts.lock().unwrap().is_empty());
    assert_eq!(
        run(&alice, &["coin", "status"])["lifecycle"],
        "recovery_secured"
    );
    let recovery = temporary.path().join("secured-recovery.hex");
    assert_eq!(
        run(
            &alice,
            &["coin", "recovery", "--output", recovery.to_str().unwrap()],
        )["status"],
        "recovery_exported"
    );

    assert_eq!(
        run_failure_without_enclave(&alice, &fund, "after_funding_broadcast")["error"],
        "stopped at test failpoint after_funding_broadcast"
    );
    assert_eq!(core_state.broadcasts.lock().unwrap().len(), 1);
    let completed = run_without_enclave(&alice, &fund);
    assert_eq!(completed["status"], "funding_broadcast");
    assert_eq!(core_state.broadcasts.lock().unwrap().len(), 1);
    *core_state.confirmations.lock().unwrap() = 0;
    *core_state.in_mempool.lock().unwrap() = false;
    *core_state.funding.lock().unwrap() = None;
    let lock_calls = *core_state.lock_calls.lock().unwrap();
    assert_eq!(
        run_without_enclave(&alice, &fund)["status"],
        "already_funded"
    );
    assert_eq!(*core_state.lock_calls.lock().unwrap(), lock_calls);
    let broadcasts = core_state.broadcasts.lock().unwrap();
    assert_eq!(broadcasts.len(), 2);
    assert_eq!(broadcasts[0], broadcasts[1]);
    drop(broadcasts);
    *core_state.confirmations.lock().unwrap() = 1;
    *core_state.funding.lock().unwrap() = None;
    assert_eq!(
        run_without_enclave(
            &alice,
            &[
                "coin",
                "fund",
                "--amount-sat",
                "100000",
                "--delay-blocks",
                "100",
                "--max-fee-sat",
                "1000",
            ],
        )["status"],
        "already_funded"
    );
    assert_eq!(core_state.broadcasts.lock().unwrap().len(), 2);
    assert_eq!(
        deserialize::<Transaction>(
            &hex::decode(fs::read_to_string(recovery).unwrap().trim()).unwrap()
        )
        .unwrap()
        .input[0]
            .sequence,
        Sequence::from_height(100)
    );
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
            "--bitcoin-wallet",
            "funder",
        ],
    );
    let default_config: Value =
        serde_json::from_str(&fs::read_to_string(default_wallet.join("config.json")).unwrap())
            .unwrap();
    assert_eq!(default_config["format_version"], 1);
    assert_eq!(default_config["protocol_version"], 1);
    assert_eq!(default_config["min_confirmations"], 6);
    let registered = run(&default_wallet, &["coin", "register"]);
    let funded = run(
        &default_wallet,
        &[
            "coin",
            "fund",
            "--amount-sat",
            "100000",
            "--delay-blocks",
            "100",
            "--max-fee-sat",
            "1000",
        ],
    );
    let default_outpoint = funded["outpoint"].as_str().unwrap();
    assert_eq!(
        run(&default_wallet, &["coin", "status"])["lifecycle"],
        "funding_broadcast"
    );

    let receiver = temporary.path().join("default-receiver");
    initialize(&receiver, &enclave_url, &core_url, &cookie);
    let request = temporary.path().join("default-request.json");
    let package = temporary.path().join("default-package.json");
    run(
        &receiver,
        &[
            "transfer",
            "request",
            "--coin-id",
            registered["coin_id"].as_str().unwrap(),
            "--outpoint",
            default_outpoint,
            "--amount-sat",
            "100000",
            "--output",
            request.to_str().unwrap(),
        ],
    );
    assert_eq!(
        run_failure(
            &default_wallet,
            &[
                "coin",
                "sign",
                "--request",
                request.to_str().unwrap(),
                "--output",
                package.to_str().unwrap(),
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
    run(&explicit_wallet, &["coin", "register"]);
    assert_eq!(
        run(
            &explicit_wallet,
            &[
                "coin",
                "fund",
                "--amount-sat",
                "100000",
                "--delay-blocks",
                "100",
                "--max-fee-sat",
                "1000",
            ],
        )["status"],
        "funding_broadcast"
    );
    assert_eq!(
        run(&explicit_wallet, &["coin", "status"])["lifecycle"],
        "owned"
    );
}

#[test]
fn core_exit_resumes_when_only_the_parent_is_confirmed_without_txindex() {
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
    run(&alice, &["coin", "register"]);
    run(
        &alice,
        &[
            "coin",
            "fund",
            "--amount-sat",
            "100000",
            "--delay-blocks",
            "100",
            "--max-fee-sat",
            "1000",
        ],
    );
    *core_state.confirmations.lock().unwrap() = 100;
    let destination = destination_address();
    let exit = [
        "coin",
        "exit",
        "--destination",
        &destination,
        "--fee-rate",
        "2",
        "--max-fee-sat",
        "10000",
    ];
    let dry_run = run(
        &alice,
        &[
            "coin",
            "exit",
            "--destination",
            &destination,
            "--fee-rate",
            "2",
            "--max-fee-sat",
            "10000",
            "--dry-run",
        ],
    );
    assert_eq!(
        run_failure_with_env(&alice, &exit, "after_exit_armed")["error"],
        "stopped at test failpoint after_exit_armed"
    );
    let parent: Transaction =
        deserialize(&hex::decode(dry_run["parent_hex"].as_str().unwrap()).unwrap()).unwrap();
    let child: Transaction =
        deserialize(&hex::decode(dry_run["child_hex"].as_str().unwrap()).unwrap()).unwrap();
    core_state
        .confirmed_transactions
        .lock()
        .unwrap()
        .insert(parent.compute_txid(), parent);

    let exited = run(&alice, &exit);
    assert_eq!(exited["status"], "package_submitted");
    assert_eq!(exited["exit_txid"], child.compute_txid().to_string());
    assert_eq!(core_state.broadcasts.lock().unwrap().len(), 2);
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
fn production_init_rejects_debug_pcrs_before_writing_wallet_state() {
    let temporary = tempfile::tempdir().unwrap();
    let wallet = temporary.path().join("invalid-production");
    let zero = "00".repeat(48);
    let nonzero = "11".repeat(48);
    let error = run_failure(
        &wallet,
        &[
            "init",
            "--network",
            "mutinynet",
            "--enclave-url",
            "wss://example.invalid",
            "--pcr0",
            &zero,
            "--pcr1",
            &nonzero,
            "--pcr2",
            &nonzero,
        ],
    );
    assert!(error["error"].as_str().unwrap().contains("all-zero"));
    assert!(!wallet.exists());
}

#[test]
fn explorer_wallet_funds_from_its_deposit_key_and_sweeps_exact_bytes() {
    let temporary = tempfile::tempdir().unwrap();
    let (enclave_url, explorer_url, explorer_state) = start_explorer_servers();
    let explorer_url = format!("{explorer_url}/api");
    let wallet = temporary.path().join("wallet");
    let initialized = run(
        &wallet,
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
    assert_eq!(initialized["status"], "initialized");
    let first_address = run(&wallet, &["coin", "deposit-address"]);
    let second_address = run(&wallet, &["coin", "deposit-address"]);
    assert_eq!(first_address["address"], second_address["address"]);
    let deposit_address =
        Address::<NetworkUnchecked>::from_str(first_address["address"].as_str().unwrap())
            .unwrap()
            .require_network(bitcoin::Network::Regtest)
            .unwrap();
    run(&wallet, &["coin", "register"]);

    let source = deposit_transaction(deposit_address.script_pubkey(), 160_000, 31);
    let source_outpoint = OutPoint::new(source.compute_txid(), 0);
    explorer_state.observe(source, 6);
    let fund = [
        "coin",
        "fund",
        "--amount-sat",
        "100000",
        "--delay-blocks",
        "100",
        "--fee-rate",
        "1",
        "--max-fee-sat",
        "1000",
    ];
    assert_eq!(
        run_failure_with_env(&wallet, &fund, "after_funding_broadcast")["error"],
        "stopped at test failpoint after_funding_broadcast"
    );
    assert_eq!(explorer_state.broadcasts.lock().unwrap().len(), 1);
    let pending_funding: Transaction =
        deserialize(&hex::decode(explorer_state.broadcasts.lock().unwrap()[0].clone()).unwrap())
            .unwrap();
    let pending_funding_txid = pending_funding.compute_txid();
    explorer_state
        .hidden_summaries
        .lock()
        .unwrap()
        .insert(pending_funding_txid);
    assert!(
        run_failure(&wallet, &fund)["error"]
            .as_str()
            .unwrap()
            .contains("did not expose its exact bytes")
    );
    assert_eq!(explorer_state.broadcasts.lock().unwrap().len(), 1);
    explorer_state
        .hidden_summaries
        .lock()
        .unwrap()
        .remove(&pending_funding_txid);
    let funded = run_without_enclave(&wallet, &fund);
    assert_eq!(funded["status"], "funding_broadcast");
    assert_eq!(explorer_state.broadcasts.lock().unwrap().len(), 1);
    let funding_txid: Txid = funded["funding_txid"].as_str().unwrap().parse().unwrap();
    let funding = explorer_state
        .transactions
        .lock()
        .unwrap()
        .get(&funding_txid)
        .unwrap()
        .transaction
        .clone();
    assert_eq!(funding.input[0].previous_output, source_outpoint);
    assert_eq!(funding.output[0].value.to_sat(), AMOUNT_SAT);
    assert_eq!(
        funding.output[1].script_pubkey,
        deposit_address.script_pubkey()
    );
    assert_eq!(
        run_without_enclave(&wallet, &fund)["status"],
        "already_funded"
    );
    assert_eq!(explorer_state.broadcasts.lock().unwrap().len(), 1);

    explorer_state.set_confirmations(funding_txid, 6);
    explorer_state.observe(
        deposit_transaction(deposit_address.script_pubkey(), 40_000, 32),
        3,
    );
    let destination = destination_address();
    let sweep = [
        "coin",
        "source-sweep",
        "--destination",
        &destination,
        "--fee-rate",
        "1",
        "--max-fee-sat",
        "1000",
    ];
    assert_eq!(
        run_failure_with_env(&wallet, &sweep, "after_sweep_prepared")["error"],
        "stopped at test failpoint after_sweep_prepared"
    );
    assert_eq!(explorer_state.broadcasts.lock().unwrap().len(), 1);
    let replacement_sweep = [
        "coin",
        "source-sweep",
        "--destination",
        &destination,
        "--fee-rate",
        "2",
        "--max-fee-sat",
        "1000",
    ];
    assert_eq!(
        run_failure_with_env(&wallet, &replacement_sweep, "after_sweep_broadcast")["error"],
        "stopped at test failpoint after_sweep_broadcast"
    );
    assert_eq!(explorer_state.broadcasts.lock().unwrap().len(), 2);
    let swept = run(&wallet, &replacement_sweep);
    assert_eq!(swept["status"], "source_sweep_observed");
    assert_eq!(swept["input_count"], 2);
    assert_eq!(explorer_state.broadcasts.lock().unwrap().len(), 2);
    let sweep_txid: Txid = swept["txid"].as_str().unwrap().parse().unwrap();
    let sweep_transaction = explorer_state
        .transactions
        .lock()
        .unwrap()
        .get(&sweep_txid)
        .unwrap()
        .transaction
        .clone();
    assert_eq!(sweep_transaction.input.len(), 2);
    let destination = Address::<NetworkUnchecked>::from_str(&destination)
        .unwrap()
        .require_network(bitcoin::Network::Regtest)
        .unwrap();
    assert_eq!(
        sweep_transaction.output[0].script_pubkey,
        destination.script_pubkey()
    );

    explorer_state.set_confirmations(sweep_txid, 1);
    explorer_state.observe(
        deposit_transaction(deposit_address.script_pubkey(), 25_000, 33),
        2,
    );
    let second_sweep = run(&wallet, &replacement_sweep);
    assert_eq!(second_sweep["status"], "source_sweep_broadcast");
    assert_eq!(second_sweep["input_count"], 1);
    assert_eq!(explorer_state.broadcasts.lock().unwrap().len(), 3);
}

fn deposit_transaction(script_pubkey: ScriptBuf, value_sat: u64, tag: u8) -> Transaction {
    Transaction {
        version: Version::TWO,
        lock_time: absolute::LockTime::ZERO,
        input: vec![TxIn {
            previous_output: OutPoint::new(Txid::from_byte_array([tag; 32]), 0),
            script_sig: ScriptBuf::new(),
            sequence: Sequence::MAX,
            witness: Witness::from_slice(&[[tag; 64]]),
        }],
        output: vec![TxOut {
            value: Amount::from_sat(value_sat),
            script_pubkey,
        }],
    }
}

#[test]
fn explorer_backed_wallet_exits_with_a_fee_paying_child() {
    let temporary = tempfile::tempdir().unwrap();
    let cookie = temporary.path().join("bitcoin.cookie");
    fs::write(&cookie, "user:password\n").unwrap();
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt as _;
        fs::set_permissions(&cookie, fs::Permissions::from_mode(0o600)).unwrap();
    }
    let (enclave_url, core_url, core_state) = start_servers();
    let (_unused_enclave, explorer_url, explorer_state) = start_explorer_servers();
    let explorer_url = format!("{explorer_url}/api");
    let alice = temporary.path().join("alice");
    let bob = temporary.path().join("bob");
    initialize(&alice, &enclave_url, &core_url, &cookie);
    let output = run(
        &bob,
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
    let funded = run(
        &alice,
        &[
            "coin",
            "fund",
            "--amount-sat",
            "100000",
            "--delay-blocks",
            "100",
            "--max-fee-sat",
            "1000",
        ],
    );
    let outpoint = funded["outpoint"].as_str().unwrap().to_owned();
    let funding_transaction = core_state
        .prepared
        .lock()
        .unwrap()
        .clone()
        .expect("prepared funding transaction");
    let funding_txid = funding_transaction.compute_txid();
    explorer_state.observe(funding_transaction, 6);
    let alice_recovery_path = temporary.path().join("alice-recovery.hex");
    run(
        &alice,
        &[
            "coin",
            "recovery",
            "--output",
            alice_recovery_path.to_str().unwrap(),
        ],
    );
    let alice_recovery: Transaction = deserialize(
        &hex::decode(fs::read_to_string(&alice_recovery_path).unwrap().trim()).unwrap(),
    )
    .unwrap();
    let request = temporary.path().join("bob-request.json");
    let package = temporary.path().join("alice-to-bob.json");
    run(
        &bob,
        &[
            "transfer",
            "request",
            "--coin-id",
            registered["coin_id"].as_str().unwrap(),
            "--outpoint",
            &outpoint,
            "--amount-sat",
            &AMOUNT_SAT.to_string(),
            "--output",
            request.to_str().unwrap(),
        ],
    );
    let destination = destination_address();
    let sign = [
        "coin",
        "sign",
        "--request",
        request.to_str().unwrap(),
        "--output",
        package.to_str().unwrap(),
    ];
    assert_eq!(
        run_failure_with_env(&alice, &sign, "after_sign")["error"],
        "stopped at test failpoint after_sign"
    );
    assert_eq!(
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
        )["error"],
        "wallet has a pending operation; finish it before exiting"
    );
    run(&alice, &sign);
    run(
        &bob,
        &[
            "transfer",
            "accept",
            "--request",
            request.to_str().unwrap(),
            "--package",
            package.to_str().unwrap(),
        ],
    );

    assert!(
        run_failure(
            &bob,
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
        &bob,
        &["coin", "recovery", "--output", recovery.to_str().unwrap()],
    );
    let parent_hex = fs::read_to_string(&recovery).unwrap().trim().to_owned();

    *explorer_state.tip.lock().unwrap() = 1_000;
    explorer_state.set_confirmations(funding_txid, 100);
    *core_state.confirmations.lock().unwrap() = 100;
    assert_eq!(
        run_failure_with_env(
            &alice,
            &[
                "coin",
                "exit",
                "--destination",
                &destination,
                "--max-fee-sat",
                "10000",
            ],
            "after_exit_prepared",
        )["error"],
        "stopped at test failpoint after_exit_prepared"
    );
    assert_eq!(run(&alice, &sign)["status"], "already_transferred");
    assert_eq!(
        run_failure(
            &bob,
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
            &bob,
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
            &bob,
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
    let exit = [
        "coin",
        "exit",
        "--destination",
        &destination,
        "--max-fee-sat",
        "10000",
    ];
    assert_eq!(
        run_failure_with_env(&bob, &exit, "after_exit_prepared")["error"],
        "stopped at test failpoint after_exit_prepared"
    );
    let saved_dry_run = run(
        &bob,
        &[
            "coin",
            "exit",
            "--destination",
            &destination,
            "--max-fee-sat",
            "10000",
            "--dry-run",
        ],
    );
    assert_eq!(saved_dry_run["status"], "package_prepared");
    assert_eq!(saved_dry_run["parent_hex"], parent_hex);
    explorer_state.set_confirmations(funding_txid, 50);
    assert!(
        run_failure(&bob, &exit)["error"]
            .as_str()
            .unwrap()
            .contains("not final")
    );
    assert!(explorer_state.packages.lock().unwrap().is_empty());
    explorer_state.set_confirmations(funding_txid, 100);
    explorer_state.observe(alice_recovery, 0);
    let replacement_exit = [
        "coin",
        "exit",
        "--destination",
        &destination,
        "--fee-rate",
        "2",
        "--max-fee-sat",
        "10000",
    ];
    let exited = run(&bob, &replacement_exit);
    assert_eq!(exited["status"], "package_submitted");
    assert_eq!(exited["fee_rate_sat_vb"], 2);

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
    tip: Arc<Mutex<u64>>,
    transactions: Arc<Mutex<HashMap<Txid, ExplorerTransaction>>>,
    hidden_summaries: Arc<Mutex<HashSet<Txid>>>,
    outspends: Arc<Mutex<HashMap<OutPoint, Txid>>>,
    packages: Arc<Mutex<Vec<Vec<String>>>>,
    broadcasts: Arc<Mutex<Vec<String>>>,
}

#[derive(Clone)]
struct ExplorerTransaction {
    transaction: Transaction,
    confirmations: u32,
}

impl ExplorerState {
    fn observe(&self, transaction: Transaction, confirmations: u32) {
        let txid = transaction.compute_txid();
        {
            let mut outspends = self.outspends.lock().unwrap();
            for input in &transaction.input {
                if !input.previous_output.is_null() {
                    outspends.insert(input.previous_output, txid);
                }
            }
        }
        self.transactions.lock().unwrap().insert(
            txid,
            ExplorerTransaction {
                transaction,
                confirmations,
            },
        );
    }

    fn set_confirmations(&self, txid: Txid, confirmations: u32) {
        self.transactions
            .lock()
            .unwrap()
            .get_mut(&txid)
            .expect("observed transaction")
            .confirmations = confirmations;
    }
}

fn start_explorer_servers() -> (String, String, ExplorerState) {
    let enclave_listener = TcpListener::bind("127.0.0.1:0").unwrap();
    let explorer_listener = TcpListener::bind("127.0.0.1:0").unwrap();
    enclave_listener.set_nonblocking(true).unwrap();
    explorer_listener.set_nonblocking(true).unwrap();
    let enclave_address = enclave_listener.local_addr().unwrap();
    let explorer_address = explorer_listener.local_addr().unwrap();
    let explorer_state = ExplorerState {
        tip: Arc::new(Mutex::new(900)),
        transactions: Arc::new(Mutex::new(HashMap::new())),
        hidden_summaries: Arc::new(Mutex::new(HashSet::new())),
        outspends: Arc::new(Mutex::new(HashMap::new())),
        packages: Arc::new(Mutex::new(Vec::new())),
        broadcasts: Arc::new(Mutex::new(Vec::new())),
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
                .route("/api/tx/{txid}/hex", get(explorer_tx_hex))
                .route("/api/tx/{txid}/outspend/{vout}", get(explorer_outspend))
                .route("/api/tx/{txid}/outspends", get(explorer_outspends))
                .route("/api/address/{address}/utxo", get(explorer_address_utxos))
                .route("/api/tx", post(explorer_broadcast))
                .route("/api/v1/fees/recommended", get(explorer_fees))
                .route("/api/txs/package", post(explorer_package))
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

fn explorer_status(state: &ExplorerState, confirmations: u32) -> Value {
    if confirmations == 0 {
        return json!({ "confirmed": false });
    }
    let tip = *state.tip.lock().unwrap();
    json!({
        "confirmed": true,
        "block_height": tip - u64::from(confirmations) + 1,
        "block_hash": "11".repeat(32),
    })
}

async fn explorer_tip(State(state): State<ExplorerState>) -> String {
    state.tip.lock().unwrap().to_string()
}

async fn explorer_block_hash(AxumPath(height): AxumPath<u64>) -> String {
    if height == 0 {
        bitcoin::blockdata::constants::genesis_block(bitcoin::Network::Regtest)
            .block_hash()
            .to_string()
    } else {
        "11".repeat(32)
    }
}

async fn explorer_tx(
    State(state): State<ExplorerState>,
    AxumPath(txid): AxumPath<String>,
) -> Result<Json<Value>, StatusCode> {
    let txid: Txid = txid.parse().map_err(|_| StatusCode::NOT_FOUND)?;
    if state.hidden_summaries.lock().unwrap().contains(&txid) {
        return Err(StatusCode::NOT_FOUND);
    }
    let observed = state
        .transactions
        .lock()
        .unwrap()
        .get(&txid)
        .cloned()
        .ok_or(StatusCode::NOT_FOUND)?;
    Ok(Json(json!({
        "txid": txid,
        "status": explorer_status(&state, observed.confirmations),
        "vin": [{ "is_coinbase": observed.transaction.is_coinbase() }],
        "vout": observed.transaction.output.iter().map(|output| json!({
            "value": output.value.to_sat(),
            "scriptpubkey": hex::encode(output.script_pubkey.as_bytes()),
        })).collect::<Vec<_>>(),
    })))
}

async fn explorer_tx_hex(
    State(state): State<ExplorerState>,
    AxumPath(txid): AxumPath<String>,
) -> Result<String, StatusCode> {
    let txid: Txid = txid.parse().map_err(|_| StatusCode::NOT_FOUND)?;
    state
        .transactions
        .lock()
        .unwrap()
        .get(&txid)
        .map(|observed| serialize_hex(&observed.transaction))
        .ok_or(StatusCode::NOT_FOUND)
}

async fn explorer_outspend(
    State(state): State<ExplorerState>,
    AxumPath((txid, vout)): AxumPath<(String, u32)>,
) -> Result<Json<Value>, StatusCode> {
    let txid = txid.parse().map_err(|_| StatusCode::NOT_FOUND)?;
    let outpoint = OutPoint::new(txid, vout);
    let transactions = state.transactions.lock().unwrap();
    let funding = transactions.get(&txid).ok_or(StatusCode::NOT_FOUND)?;
    if funding.transaction.output.get(vout as usize).is_none() {
        return Err(StatusCode::NOT_FOUND);
    }
    let spending_txid = state.outspends.lock().unwrap().get(&outpoint).copied();
    let Some(spending_txid) = spending_txid else {
        return Ok(Json(json!({ "spent": false })));
    };
    let spending = transactions
        .get(&spending_txid)
        .ok_or(StatusCode::INTERNAL_SERVER_ERROR)?;
    Ok(Json(json!({
        "spent": true,
        "txid": spending_txid,
        "vin": spending.transaction.input.iter().position(|input| input.previous_output == outpoint),
        "status": explorer_status(&state, spending.confirmations),
    })))
}

async fn explorer_outspends(
    State(state): State<ExplorerState>,
    AxumPath(txid): AxumPath<String>,
) -> Result<Json<Value>, StatusCode> {
    let txid: Txid = txid.parse().map_err(|_| StatusCode::NOT_FOUND)?;
    let output_count = state
        .transactions
        .lock()
        .unwrap()
        .get(&txid)
        .ok_or(StatusCode::NOT_FOUND)?
        .transaction
        .output
        .len();
    let outspends = state.outspends.lock().unwrap();
    Ok(Json(json!(
        (0..output_count)
            .map(|vout| {
                let spender = outspends.get(&OutPoint::new(txid, vout as u32));
                json!({ "spent": spender.is_some(), "txid": spender })
            })
            .collect::<Vec<_>>()
    )))
}

async fn explorer_address_utxos(
    State(state): State<ExplorerState>,
    AxumPath(address): AxumPath<String>,
) -> Result<Json<Value>, StatusCode> {
    let address = Address::<NetworkUnchecked>::from_str(&address)
        .map_err(|_| StatusCode::BAD_REQUEST)?
        .require_network(bitcoin::Network::Regtest)
        .map_err(|_| StatusCode::BAD_REQUEST)?;
    let transactions = state.transactions.lock().unwrap();
    let outspends = state.outspends.lock().unwrap();
    let mut outputs = Vec::new();
    for (txid, observed) in transactions.iter() {
        for (vout, output) in observed.transaction.output.iter().enumerate() {
            let outpoint = OutPoint::new(*txid, vout as u32);
            if output.script_pubkey == address.script_pubkey() && !outspends.contains_key(&outpoint)
            {
                outputs.push(json!({
                    "txid": txid,
                    "vout": vout,
                    "value": output.value.to_sat(),
                    "status": explorer_status(&state, observed.confirmations),
                }));
            }
        }
    }
    Ok(Json(json!(outputs)))
}

async fn explorer_broadcast(
    State(state): State<ExplorerState>,
    body: String,
) -> Result<String, (StatusCode, String)> {
    let transaction: Transaction = deserialize(
        &hex::decode(body.trim()).map_err(|error| (StatusCode::BAD_REQUEST, error.to_string()))?,
    )
    .map_err(|error| (StatusCode::BAD_REQUEST, error.to_string()))?;
    let txid = transaction.compute_txid();
    if let Some(existing) = state.transactions.lock().unwrap().get(&txid) {
        if existing.transaction != transaction {
            return Err((StatusCode::CONFLICT, "same txid has different bytes".into()));
        }
        return Ok(txid.to_string());
    }
    state.broadcasts.lock().unwrap().push(body);
    state.observe(transaction, 0);
    Ok(txid.to_string())
}

async fn explorer_fees() -> Json<Value> {
    Json(json!({ "fastestFee": 1 }))
}

async fn explorer_package(
    State(state): State<ExplorerState>,
    Json(package): Json<Vec<String>>,
) -> Json<Value> {
    let transactions: Vec<Transaction> = package
        .iter()
        .map(|raw| deserialize(&hex::decode(raw).unwrap()).unwrap())
        .collect();
    state.packages.lock().unwrap().push(package);
    for transaction in transactions {
        state.observe(transaction, 0);
    }
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
            "--bitcoin-wallet",
            "funder",
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

fn run_failure_without_enclave(directory: &Path, arguments: &[&str], failpoint: &str) -> Value {
    let output = Command::new(env!("CARGO_BIN_EXE_tinylayer-wallet"))
        .arg("--data-dir")
        .arg(directory)
        .arg("--json")
        .args(arguments)
        .env("ENCLAVIA_WALLET_PASSWORD", PASSWORD)
        .env("ENCLAVIA_WALLET_TEST_FAILPOINT", failpoint)
        .env("ENCLAVIA_WALLET_TEST_DISABLE_ENCLAVE", "1")
        .output()
        .unwrap();
    assert!(!output.status.success(), "command unexpectedly succeeded");
    serde_json::from_slice(&output.stderr).unwrap()
}

fn run_without_enclave(directory: &Path, arguments: &[&str]) -> Value {
    let output = Command::new(env!("CARGO_BIN_EXE_tinylayer-wallet"))
        .arg("--data-dir")
        .arg(directory)
        .arg("--json")
        .args(arguments)
        .env("ENCLAVIA_WALLET_PASSWORD", PASSWORD)
        .env("ENCLAVIA_WALLET_TEST_DISABLE_ENCLAVE", "1")
        .output()
        .unwrap();
    assert!(
        output.status.success(),
        "command failed without enclave:\nstdout: {}\nstderr: {}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );
    serde_json::from_slice(&output.stdout).unwrap()
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
                .route("/wallet/{wallet}", post(core_rpc))
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
        "getwalletinfo" => json!({
            "walletname": "funder",
            "private_keys_enabled": true,
        }),
        "walletcreatefundedpsbt" => {
            assert_eq!(request.params[3]["minconf"], 1);
            assert_eq!(request.params[3]["include_unsafe"], false);
            assert_eq!(request.params[3]["lockUnspents"], true);
            assert_eq!(request.params[3]["replaceable"], false);
            let outputs = request
                .params
                .get(1)
                .and_then(Value::as_object)
                .expect("funding outputs object");
            let (address, value) = outputs.iter().next().expect("one funding output");
            let address = address
                .parse::<Address<NetworkUnchecked>>()
                .unwrap()
                .require_network(bitcoin::Network::Regtest)
                .unwrap();
            let amount = Amount::from_btc(value.as_f64().unwrap()).unwrap();
            let mut witness = Witness::new();
            witness.push([1; 64]);
            let transaction = Transaction {
                version: Version::TWO,
                lock_time: absolute::LockTime::ZERO,
                input: vec![TxIn {
                    previous_output: OutPoint::new(Txid::from_byte_array([0x77; 32]), 0),
                    script_sig: ScriptBuf::new(),
                    sequence: Sequence::MAX,
                    witness,
                }],
                output: vec![TxOut {
                    value: amount,
                    script_pubkey: address.script_pubkey(),
                }],
            };
            *state.prepared.lock().unwrap() = Some(transaction);
            json!({ "psbt": "prepared-psbt", "fee": 0.000001, "changepos": -1 })
        }
        "walletprocesspsbt" => json!({ "psbt": "signed-psbt", "complete": true }),
        "finalizepsbt" => {
            let transaction = state
                .prepared
                .lock()
                .unwrap()
                .clone()
                .expect("prepared funding transaction");
            json!({ "hex": serialize_hex(&transaction), "complete": true })
        }
        "listlockunspent" => json!(
            state
                .locked_inputs
                .lock()
                .unwrap()
                .iter()
                .map(|outpoint| json!({
                    "txid": outpoint.txid.to_string(),
                    "vout": outpoint.vout,
                }))
                .collect::<Vec<_>>()
        ),
        "lockunspent" => {
            assert_eq!(request.params[0], false);
            assert_eq!(request.params[2], true);
            *state.lock_calls.lock().unwrap() += 1;
            let outputs = request.params[1].as_array().unwrap();
            let mut locked = state.locked_inputs.lock().unwrap();
            for output in outputs {
                let outpoint = OutPoint::new(
                    output["txid"].as_str().unwrap().parse().unwrap(),
                    output["vout"].as_u64().unwrap() as u32,
                );
                if !locked.contains(&outpoint) {
                    locked.push(outpoint);
                }
            }
            json!(true)
        }
        "testmempoolaccept" => {
            let raw = request.params[0][0].as_str().unwrap();
            let transaction: Transaction = deserialize(&hex::decode(raw).unwrap()).unwrap();
            json!([{
                "txid": transaction.compute_txid().to_string(),
                "allowed": true,
                "vsize": transaction.vsize(),
                "fees": { "base": 0.000001 }
            }])
        }
        "gettxspendingprevout" => {
            let requested = &request.params[0][0];
            let outpoint = OutPoint::new(
                requested["txid"].as_str().unwrap().parse().unwrap(),
                requested["vout"].as_u64().unwrap() as u32,
            );
            let spending_txid = state.broadcasts.lock().unwrap().iter().find_map(|raw| {
                let transaction: Transaction = deserialize(&hex::decode(raw).unwrap()).unwrap();
                transaction
                    .input
                    .iter()
                    .any(|input| input.previous_output == outpoint)
                    .then(|| transaction.compute_txid())
            });
            json!([{
                "txid": outpoint.txid,
                "vout": outpoint.vout,
                "spendingtxid": spending_txid,
            }])
        }
        "getrawtransaction" => {
            return Json(json!({
                "result": Value::Null,
                "error": { "code": -5, "message": "No such mempool transaction" },
                "id": request.id,
            }));
        }
        "gettransaction" => {
            if *state.hide_wallet_transactions.lock().unwrap() {
                return Json(json!({
                    "result": Value::Null,
                    "error": { "code": -5, "message": "Invalid or non-wallet transaction id" },
                    "id": request.id,
                }));
            }
            let requested = request.params[0].as_str().unwrap();
            let raw = state
                .broadcasts
                .lock()
                .unwrap()
                .iter()
                .find(|raw| {
                    deserialize::<Transaction>(&hex::decode(raw).unwrap())
                        .unwrap()
                        .compute_txid()
                        .to_string()
                        == requested
                })
                .cloned();
            let Some(raw) = raw else {
                return Json(json!({
                    "result": Value::Null,
                    "error": { "code": -5, "message": "Invalid or non-wallet transaction id" },
                    "id": request.id,
                }));
            };
            json!({
                "confirmations": *state.confirmations.lock().unwrap() as i32,
                "txid": requested,
                "walletconflicts": [],
                "hex": raw,
            })
        }
        "getmempoolentry" => {
            let requested = request.params[0].as_str().unwrap();
            let in_mempool = *state.confirmations.lock().unwrap() == 0
                && *state.in_mempool.lock().unwrap()
                && state.broadcasts.lock().unwrap().iter().any(|raw| {
                    deserialize::<Transaction>(&hex::decode(raw).unwrap())
                        .unwrap()
                        .compute_txid()
                        .to_string()
                        == requested
                });
            if !in_mempool {
                return Json(json!({
                    "result": Value::Null,
                    "error": { "code": -5, "message": "Transaction not in mempool" },
                    "id": request.id,
                }));
            }
            json!({ "vsize": 100 })
        }
        "sendrawtransaction" => {
            let raw = request.params[0].as_str().unwrap().to_owned();
            let transaction: Transaction = deserialize(&hex::decode(&raw).unwrap()).unwrap();
            let txid = transaction.compute_txid();
            let output = transaction.output.first().unwrap();
            if transaction.version == Version::TWO {
                *state.funding.lock().unwrap() = Some(Funding {
                    outpoint: OutPoint::new(txid, 0).to_string(),
                    script_hex: hex::encode(output.script_pubkey.as_bytes()),
                });
            }
            state.locked_inputs.lock().unwrap().clear();
            state.broadcasts.lock().unwrap().push(raw);
            *state.in_mempool.lock().unwrap() = true;
            json!(txid.to_string())
        }
        "getblockchaininfo" => json!({
            "chain": "regtest",
            "blocks": *state.tip.lock().unwrap(),
            "bestblockhash": "00".repeat(32)
        }),
        "gettxout" => {
            let outpoint = OutPoint::new(
                request.params[0].as_str().unwrap().parse().unwrap(),
                request.params[1].as_u64().unwrap() as u32,
            );
            let spent = state
                .broadcasts
                .lock()
                .unwrap()
                .iter()
                .map(|raw| deserialize::<Transaction>(&hex::decode(raw).unwrap()).unwrap())
                .chain(
                    state
                        .confirmed_transactions
                        .lock()
                        .unwrap()
                        .values()
                        .cloned(),
                )
                .any(|transaction| {
                    transaction
                        .input
                        .iter()
                        .any(|input| input.previous_output == outpoint)
                });
            if spent {
                return Json(json!({
                    "result": Value::Null,
                    "error": Value::Null,
                    "id": request.id,
                }));
            }
            if let Some(transaction) = state
                .confirmed_transactions
                .lock()
                .unwrap()
                .get(&outpoint.txid)
            {
                let output = &transaction.output[outpoint.vout as usize];
                json!({
                    "bestblock": "00".repeat(32),
                    "confirmations": *state.confirmations.lock().unwrap(),
                    "value": output.value.to_btc(),
                    "scriptPubKey": {
                        "asm": "",
                        "hex": hex::encode(output.script_pubkey.as_bytes()),
                        "type": "witness_v1_taproot"
                    },
                    "coinbase": false
                })
            } else {
                match state.funding.lock().unwrap().as_ref() {
                    Some(funding) if funding.outpoint == outpoint.to_string() => json!({
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
