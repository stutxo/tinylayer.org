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
    locked_inputs: Arc<Mutex<Vec<OutPoint>>>,
    lock_calls: Arc<Mutex<u32>>,
    in_mempool: Arc<Mutex<bool>>,
    tip: Arc<Mutex<u64>>,
    confirmations: Arc<Mutex<u32>>,
}

impl Default for CoreState {
    fn default() -> Self {
        Self {
            funding: Arc::new(Mutex::new(None)),
            prepared: Arc::new(Mutex::new(None)),
            broadcasts: Arc::new(Mutex::new(Vec::new())),
            locked_inputs: Arc::new(Mutex::new(Vec::new())),
            lock_calls: Arc::new(Mutex::new(0)),
            in_mempool: Arc::new(Mutex::new(false)),
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
    assert_eq!(bob_request_json["format_version"], 4);
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
    assert_eq!(receipt_json["format_version"], 4);
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
    assert_eq!(encrypted_package_json["format_version"], 4);
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
        run_failure_without_enclave(&alice, &fund, "after_recovery_secured")["error"],
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
    assert_eq!(default_config["format_version"], 4);
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
    let cookie = temporary.path().join("bitcoin.cookie");
    fs::write(&cookie, "user:password\n").unwrap();
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt as _;
        fs::set_permissions(&cookie, fs::Permissions::from_mode(0o600)).unwrap();
    }
    let (enclave_url, core_url, _core_state) = start_servers();
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
    *explorer_state.funding.lock().unwrap() = Some(Funding {
        outpoint: outpoint.clone(),
        script_hex: registered["funding_script_hex"]
            .as_str()
            .unwrap()
            .to_owned(),
    });
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
    run(
        &alice,
        &[
            "coin",
            "sign",
            "--request",
            request.to_str().unwrap(),
            "--output",
            package.to_str().unwrap(),
        ],
    );
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

    let destination = destination_address();
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
    *explorer_state.confirmations.lock().unwrap() = 90;
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
    let exited = run(
        &bob,
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
    confirmations: Arc<Mutex<u32>>,
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
        confirmations: Arc::new(Mutex::new(6)),
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
    let tip = *state.tip.lock().unwrap();
    let confirmations = u64::from(*state.confirmations.lock().unwrap());
    Some(json!({
        "txid": txid,
        "status": {
            "confirmed": true,
            "block_height": tip - confirmations + 1,
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
        "gettransaction" => {
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
            *state.funding.lock().unwrap() = Some(Funding {
                outpoint: OutPoint::new(txid, 0).to_string(),
                script_hex: hex::encode(output.script_pubkey.as_bytes()),
            });
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
