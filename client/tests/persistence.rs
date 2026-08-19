mod support;

use tinylayer_client::{
    Error, INITIAL_HANDOFF, PreparedRecovery, capability_hash, complete_recovery, prepare_recovery,
    verify_recovery,
};

use support::{CAP_0, CAP_A, DELAY_BLOCKS, opened, xonly};

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
        DELAY_BLOCKS,
        0,
    )
    .unwrap();
    let encoded = serde_json::to_vec(&prepared).unwrap();
    let text = String::from_utf8(encoded.clone()).unwrap();
    assert!(!text.contains("client_secret"));
    assert!(!text.contains("output_key"));
    assert!(!text.contains("control_block"));
    assert!(!text.contains("tapscript"));
    assert!(text.contains("delay_blocks"));
    assert!(!text.contains("locktime"));

    let restored: PreparedRecovery = serde_json::from_slice(&encoded).unwrap();
    assert_eq!(restored, prepared);
    let maximum_recovery_size =
        serde_json::to_vec(&restored.recovery_serialization_template().unwrap())
            .unwrap()
            .len();
    let response = opened.enclave.sign(request.clone()).unwrap();
    let recovery = complete_recovery(&request, &response, restored, opened.client_secret).unwrap();
    assert!(serde_json::to_vec(&recovery).unwrap().len() <= maximum_recovery_size);
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
        DELAY_BLOCKS,
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

    let mut value = serde_json::to_value(&prepared).unwrap();
    value["delay_blocks"] = serde_json::json!(DELAY_BLOCKS + 1);
    let changed_delay: PreparedRecovery = serde_json::from_value(value).unwrap();
    assert_eq!(
        complete_recovery(&request, &response, changed_delay, opened.client_secret,),
        Err(Error::TransactionMismatch)
    );

    let mut legacy = serde_json::to_value(&prepared).unwrap();
    let delay = legacy
        .as_object_mut()
        .unwrap()
        .remove("delay_blocks")
        .unwrap();
    legacy["locktime"] = delay;
    assert!(serde_json::from_value::<PreparedRecovery>(legacy).is_err());
}
