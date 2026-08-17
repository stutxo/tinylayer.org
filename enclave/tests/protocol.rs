use secp256k1::{Keypair, Message, Secp256k1, SecretKey, XOnlyPublicKey, schnorr::Signature};
use sha2::{Digest, Sha256};
use tinylayer_enclave::{
    Capability, CoinStatus, Error, INITIAL_HANDOFF, PROTOCOL_VERSION, RegisterRequest, Request,
    Response, SignRequest, SignResponse, authorization, capability_hash,
};

fn sign_request() -> SignRequest {
    SignRequest {
        coin_id: [1; 32],
        current_capability: [2; 32],
        current_handoff: [3; 32],
        next_capability_hash: [4; 32],
        sighash: [5; 32],
    }
}

fn crypto_values() -> (XOnlyPublicKey, Signature) {
    let secp = Secp256k1::new();
    let secret = SecretKey::from_slice(&[1; 32]).unwrap();
    let keypair = Keypair::from_secret_key(&secp, &secret);
    let signature = secp.sign_schnorr_no_aux_rand(&Message::from_digest([2; 32]), &keypair);
    (keypair.x_only_public_key().0, signature)
}

fn tagged_hash(tag: &[u8], parts: &[&[u8]]) -> [u8; 32] {
    let tag_hash = Sha256::digest(tag);
    let mut hash = Sha256::new();
    hash.update(tag_hash);
    hash.update(tag_hash);
    for part in parts {
        hash.update(part);
    }
    hash.finalize().into()
}

#[test]
fn protocol_constants_are_v1_fixed_width_values() {
    let coin_id: [u8; 32] = [0; 32];
    let capability: Capability = [0; 32];
    assert_eq!(PROTOCOL_VERSION, 1);
    assert_eq!(coin_id.len(), 32);
    assert_eq!(capability.len(), 32);
    assert_eq!(INITIAL_HANDOFF, [0; 32]);
}

#[test]
fn tagged_hash_helpers_use_distinct_v1_domains_and_fixed_field_order() {
    let capability = [2; 32];
    let coin_id = [1; 32];
    let handoff = [3; 32];
    let capability_digest = capability_hash(&capability);
    assert_eq!(
        capability_digest,
        tagged_hash(b"Tinylayer/Capability/v1", &[&capability])
    );
    assert_eq!(
        authorization(&coin_id, &capability_digest, &handoff),
        tagged_hash(
            b"Tinylayer/Authorization/v1",
            &[&coin_id, &capability_digest, &handoff]
        )
    );
    assert_ne!(
        capability_digest,
        tagged_hash(b"Tinylayer/Authorization/v1", &[&capability])
    );
    assert_ne!(
        authorization(&coin_id, &capability_digest, &handoff),
        tagged_hash(
            b"Tinylayer/Authorization/v1",
            &[&handoff, &capability_digest, &coin_id]
        )
    );
}

#[test]
fn request_wire_json_has_only_the_v1_variants_and_fields() {
    let register = Request::Register(RegisterRequest {
        coin_id: [1; 32],
        initial_capability_hash: [2; 32],
    });
    let status = Request::Status { coin_id: [3; 32] };
    let sign = Request::Sign(sign_request());

    assert_eq!(
        serde_json::to_value(&register).unwrap(),
        serde_json::json!({
            "method": "register",
            "params": {
                "coin_id": vec![1; 32],
                "initial_capability_hash": vec![2; 32]
            }
        })
    );
    assert_eq!(
        serde_json::to_value(&status).unwrap(),
        serde_json::json!({"method": "status", "params": {"coin_id": vec![3; 32]}})
    );
    assert_eq!(
        serde_json::to_value(&sign).unwrap(),
        serde_json::json!({
            "method": "sign",
            "params": {
                "coin_id": vec![1; 32],
                "current_capability": vec![2; 32],
                "current_handoff": vec![3; 32],
                "next_capability_hash": vec![4; 32],
                "sighash": vec![5; 32]
            }
        })
    );

    for request in [register, status, sign] {
        let encoded = serde_json::to_vec(&request).unwrap();
        assert_eq!(
            serde_json::from_slice::<Request>(&encoded).unwrap(),
            request
        );
    }
}

#[test]
fn response_wire_json_uses_hex_crypto_values_and_exposes_the_handoff() {
    let (public_key, signature) = crypto_values();
    let status = Response::Status(CoinStatus {
        coin_id: [1; 32],
        signing_pubkey: public_key,
        authorization: [3; 32],
        signature_count: 4,
    });
    let signed = Response::Signature(SignResponse {
        signature,
        next_handoff: [5; 32],
    });
    assert_eq!(
        serde_json::to_value(&status).unwrap(),
        serde_json::json!({
            "method": "status",
            "result": {
                "coin_id": vec![1; 32],
                "signing_pubkey": public_key.to_string(),
                "authorization": vec![3; 32],
                "signature_count": 4
            }
        })
    );
    assert_eq!(
        serde_json::to_value(&signed).unwrap(),
        serde_json::json!({
            "method": "signature",
            "result": {
                "signature": signature.to_string(),
                "next_handoff": vec![5; 32]
            }
        })
    );
    for response in [status, signed] {
        let encoded = serde_json::to_vec(&response).unwrap();
        assert_eq!(
            serde_json::from_slice::<Response>(&encoded).unwrap(),
            response
        );
    }
}

#[test]
fn unsupported_and_non_fixed_width_json_is_rejected() {
    for value in [
        serde_json::json!({}),
        serde_json::json!({"method": "info"}),
        serde_json::json!({"method": "unknown"}),
        serde_json::json!({"method": "register"}),
        serde_json::json!({"method": "status", "params": {}}),
        serde_json::json!({
            "method": "register",
            "params": {
                "coin_id": vec![0; 32],
                "initial_capability_hash": vec![0; 32],
                "key_commitment": vec![0; 32]
            }
        }),
        serde_json::json!({
            "method": "sign",
            "params": {
                "coin_id": vec![0; 32],
                "current_capability": vec![0; 32],
                "current_handoff": vec![0; 32],
                "next_capability_hash": vec![1; 32],
                "sighash": vec![0; 31]
            }
        }),
        serde_json::json!({
            "method": "sign",
            "params": {
                "coin_id": vec![0; 32],
                "current_capability": vec![0; 32],
                "current_handoff": vec![0; 32],
                "next_capability_hash": vec![1; 32],
                "sighash": vec![0; 32],
                "session_id": vec![0; 32]
            }
        }),
    ] {
        assert!(serde_json::from_value::<Request>(value).is_err());
    }

    for result in [
        serde_json::json!({
            "signature": "00".repeat(63),
            "next_handoff": vec![0; 32]
        }),
        serde_json::json!({"signature": "00".repeat(64)}),
        serde_json::json!({
            "signature": "00".repeat(64),
            "next_handoff": vec![0; 31]
        }),
    ] {
        assert!(
            serde_json::from_value::<Response>(serde_json::json!({
                "method": "signature",
                "result": result
            }))
            .is_err()
        );
    }
}

#[test]
fn protocol_errors_have_stable_non_secret_messages() {
    let cases = [
        (Error::UnknownCoin, "coin is not registered"),
        (Error::CapacityReached, "enclave coin capacity is exhausted"),
        (
            Error::Unauthorized,
            "current capability or handoff is stale",
        ),
        (Error::UnchangedCapability, "next capability is unchanged"),
        (
            Error::SignatureCountOverflow,
            "signature count is exhausted",
        ),
    ];
    for (error, expected) in cases {
        assert_eq!(error.to_string(), expected);
    }
}
