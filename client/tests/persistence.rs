mod support;

use tinylayer_client::{
    Error, INITIAL_HANDOFF, PreparedRecovery, capability_hash, complete_recovery, prepare_recovery,
    verify_recovery,
};

use support::{CAP_0, CAP_A, LOCKTIME, opened, xonly};

#[test]
fn prepared_recovery_round_trips_without_serializing_secret_or_derived_taproot_data() {
    let mut opened = opened();
    let status = opened.enclave.status(opened.metadata.keys.coin_id).unwrap();
    let (request, prepared) = prepare_recovery(
        &opened.metadata,
        &status,
        opened.client_secret,
        CAP_0,
        INITIAL_HANDOFF,
        capability_hash(&CAP_A),
        xonly(4),
        LOCKTIME,
        0,
    )
    .unwrap();
    let encoded = serde_json::to_vec(&prepared).unwrap();
    let text = String::from_utf8(encoded.clone()).unwrap();
    assert!(!text.contains("client_secret"));
    assert!(!text.contains("output_key"));
    assert!(!text.contains("control_block"));
    assert!(!text.contains("tapscript"));

    let restored: PreparedRecovery = serde_json::from_slice(&encoded).unwrap();
    assert_eq!(restored, prepared);
    let response = opened.enclave.sign(request.clone()).unwrap();
    let recovery = complete_recovery(&request, &response, restored, opened.client_secret).unwrap();
    verify_recovery(&opened.metadata, &recovery).unwrap();
}

#[test]
fn restored_preparation_rejects_unknown_and_tampered_fields() {
    let mut opened = opened();
    let status = opened.enclave.status(opened.metadata.keys.coin_id).unwrap();
    let (request, prepared) = prepare_recovery(
        &opened.metadata,
        &status,
        opened.client_secret,
        CAP_0,
        INITIAL_HANDOFF,
        capability_hash(&CAP_A),
        xonly(4),
        LOCKTIME,
        0,
    )
    .unwrap();
    let response = opened.enclave.sign(request.clone()).unwrap();
    let mut value = serde_json::to_value(&prepared).unwrap();
    value["unexpected"] = serde_json::json!(true);
    assert!(serde_json::from_value::<PreparedRecovery>(value).is_err());

    let mut value = serde_json::to_value(&prepared).unwrap();
    value["transaction"]["input"] = serde_json::json!([]);
    let malformed: PreparedRecovery = serde_json::from_value(value).unwrap();
    assert_eq!(
        complete_recovery(&request, &response, malformed, opened.client_secret,),
        Err(Error::TransactionMismatch)
    );
}
