mod support;

use bitcoin::{Amount, TxOut};
use tinylayer_client::{
    CoinKeys, Error, INITIAL_HANDOFF, NetworkId, PROTOCOL_VERSION, authorization, capability_hash,
    complete_registration, funding_script, prepare_registration, verify_funding_utxo,
    verify_status,
};
use tinylayer_enclave::Enclave;

use support::{AMOUNT, CAP_0, opened, outpoint, secret, xonly};

#[test]
fn registration_is_fresh_and_binds_initial_authorization_and_keys() {
    assert_eq!(PROTOCOL_VERSION, 1);
    let client_secret = secret(1);
    let first = prepare_registration(client_secret, capability_hash(&CAP_0));
    let second = prepare_registration(client_secret, capability_hash(&CAP_0));
    assert_eq!(first.protocol_version, 1);
    assert_ne!(first.request.coin_id, second.request.coin_id);
    assert_eq!(first.client_pubkey, xonly(1));
    let mut serialized = serde_json::to_value(&first).unwrap();
    assert_eq!(serialized["protocol_version"], 1);
    serialized
        .as_object_mut()
        .unwrap()
        .remove("protocol_version");
    assert!(serde_json::from_value::<tinylayer_client::Registration>(serialized).is_err());

    let mut enclave = Enclave::new();
    let status = enclave.register(first.request.clone()).unwrap();
    let mut incompatible = first.clone();
    incompatible.protocol_version = 2;
    assert_eq!(
        complete_registration(incompatible, &status),
        Err(Error::ProtocolVersionMismatch)
    );
    assert_eq!(status.coin_id, first.request.coin_id);
    assert_eq!(status.signature_count, 0);
    assert_eq!(
        status.authorization,
        authorization(
            &first.request.coin_id,
            &first.request.initial_capability_hash,
            &INITIAL_HANDOFF,
        )
    );
    let keys = complete_registration(first, &status).unwrap();
    assert_eq!(keys.client_pubkey, xonly(1));
    assert_eq!(keys.enclave_pubkey, status.signing_pubkey);
    assert_ne!(keys.client_pubkey, keys.enclave_pubkey);
}

#[test]
fn registration_rejects_each_inconsistent_status_binding() {
    type Mutate = fn(&mut tinylayer_client::CoinStatus);
    let mutations: [Mutate; 3] = [
        |status| status.coin_id[0] ^= 1,
        |status| status.signature_count = 1,
        |status| status.authorization[0] ^= 1,
    ];
    for mutate in mutations {
        let mut enclave = Enclave::new();
        let registration = prepare_registration(secret(1), capability_hash(&CAP_0));
        let mut status = enclave.register(registration.request.clone()).unwrap();
        mutate(&mut status);
        assert_eq!(
            complete_registration(registration, &status),
            Err(Error::ResponseMismatch)
        );
    }
}

#[test]
fn registration_and_metadata_reject_equal_party_keys() {
    let mut enclave = Enclave::new();
    let registration = prepare_registration(secret(1), capability_hash(&CAP_0));
    let mut status = enclave.register(registration.request.clone()).unwrap();
    status.signing_pubkey = registration.client_pubkey;
    assert_eq!(
        complete_registration(registration, &status),
        Err(Error::EqualSigningKeys)
    );

    let keys = CoinKeys {
        protocol_version: PROTOCOL_VERSION,
        coin_id: [1; 32],
        client_pubkey: xonly(2),
        enclave_pubkey: xonly(2),
    };
    assert_eq!(keys.validate(), Err(Error::MetadataMismatch));
}

#[test]
fn status_verification_pins_coin_id_and_enclave_key() {
    let opened = opened();
    let status = opened.enclave.status(opened.metadata.keys.coin_id).unwrap();
    verify_status(&opened.metadata.keys, &status).unwrap();

    let mut wrong_coin = status.clone();
    wrong_coin.coin_id[0] ^= 1;
    assert_eq!(
        verify_status(&opened.metadata.keys, &wrong_coin),
        Err(Error::ResponseMismatch)
    );
    let mut wrong_key = status;
    wrong_key.signing_pubkey = xonly(9);
    assert_eq!(
        verify_status(&opened.metadata.keys, &wrong_key),
        Err(Error::ResponseMismatch)
    );
}

#[test]
fn coin_keys_are_minimal_strict_metadata_and_funding_is_bound() {
    let opened = opened();
    let encoded = serde_json::to_value(&opened.metadata.keys).unwrap();
    assert_eq!(encoded.as_object().unwrap().len(), 4);
    assert_eq!(encoded["protocol_version"], 1);
    let mut missing_version = encoded.clone();
    missing_version
        .as_object_mut()
        .unwrap()
        .remove("protocol_version");
    assert!(serde_json::from_value::<CoinKeys>(missing_version).is_err());
    let mut incompatible: CoinKeys = serde_json::from_value(encoded.clone()).unwrap();
    incompatible.protocol_version = 2;
    assert_eq!(incompatible.validate(), Err(Error::ProtocolVersionMismatch));
    let mut incompatible_serialized = encoded.clone();
    incompatible_serialized["protocol_version"] = serde_json::json!(2);
    assert!(serde_json::from_value::<CoinKeys>(incompatible_serialized).is_err());
    let mut unknown = encoded;
    unknown["output_key"] = serde_json::json!(xonly(8).to_string());
    assert!(serde_json::from_value::<CoinKeys>(unknown).is_err());

    assert_eq!(opened.metadata.network, NetworkId::Regtest);
    assert_eq!(opened.metadata.outpoint, outpoint());
    let output = TxOut {
        value: Amount::from_sat(AMOUNT),
        script_pubkey: funding_script(&opened.metadata.keys),
    };
    verify_funding_utxo(&opened.metadata, outpoint(), &output).unwrap();
}
