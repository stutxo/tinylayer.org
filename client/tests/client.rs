mod support;

use bitcoin::secp256k1::{Message, Secp256k1, schnorr::Signature};
use tinylayer_client::{
    DELAY_STEP, INITIAL_HANDOFF, authorization, capability_hash, complete_recovery,
    funding_control_block, funding_tapscript, prepare_recovery, recovery_sighash, verify_history,
    verify_recovery, verify_signed_recovery,
};

use support::{CAP_0, CAP_A, CAP_B, CAP_C, DELAY_BLOCKS, initial_handoff, opened, sign, xonly};

#[test]
fn alice_bob_carol_transitions_preserve_bearer_key_and_history() {
    let mut opened = opened();
    let (alice, handoff_a) = sign(
        &mut opened.enclave,
        &opened.metadata,
        opened.client_secret,
        CAP_0,
        initial_handoff(),
        capability_hash(&CAP_A),
        xonly(3),
        DELAY_BLOCKS,
    );
    let (bob, handoff_b) = sign(
        &mut opened.enclave,
        &opened.metadata,
        opened.client_secret,
        CAP_A,
        handoff_a,
        capability_hash(&CAP_B),
        xonly(4),
        DELAY_BLOCKS - DELAY_STEP,
    );
    let carol_key = xonly(5);
    let (carol, handoff_c) = sign(
        &mut opened.enclave,
        &opened.metadata,
        opened.client_secret,
        CAP_B,
        handoff_b,
        capability_hash(&CAP_C),
        carol_key,
        DELAY_BLOCKS - 2 * DELAY_STEP,
    );
    let history = [alice, bob, carol];
    let status = opened.enclave.status(opened.metadata.keys.coin_id).unwrap();
    assert_eq!(status.signature_count, 3);
    assert_eq!(
        status.authorization,
        authorization(
            &opened.metadata.keys.coin_id,
            &capability_hash(&CAP_C),
            &handoff_c,
        )
    );
    verify_history(
        &opened.metadata,
        &status,
        opened.client_secret,
        CAP_C,
        handoff_c,
        carol_key,
        0,
        &history,
    )
    .unwrap();
    for recovery in &history {
        verify_recovery(&opened.metadata, recovery).unwrap();
        assert_eq!(recovery.transaction.input[0].witness.len(), 4);
    }
}

#[test]
fn recovery_contains_both_ordinary_bip340_signatures_in_script_order() {
    let mut opened = opened();
    let before = opened.enclave.status(opened.metadata.keys.coin_id).unwrap();
    let (request, prepared) = prepare_recovery(
        &opened.metadata,
        &before,
        opened.client_secret,
        CAP_0,
        INITIAL_HANDOFF,
        capability_hash(&CAP_A),
        xonly(3),
        DELAY_BLOCKS,
        0,
    )
    .unwrap();
    let response = opened.enclave.sign(request.clone()).unwrap();
    let recovery = complete_recovery(&request, &response, prepared, opened.client_secret).unwrap();
    let witness = &recovery.transaction.input[0].witness;
    assert_eq!(witness.len(), 4);
    assert_eq!(&witness[0], response.signature.as_ref().as_slice());
    assert_eq!(witness[0].len(), 64);
    assert_eq!(witness[1].len(), 64);
    assert_eq!(
        &witness[2],
        funding_tapscript(&opened.metadata.keys).as_bytes()
    );
    assert_eq!(
        &witness[3],
        funding_control_block(&opened.metadata.keys)
            .serialize()
            .as_slice()
    );

    let sighash = recovery_sighash(
        &recovery.transaction,
        opened.metadata.amount_sat,
        &opened.metadata.keys,
    )
    .unwrap();
    assert_eq!(request.sighash, sighash);
    let message = Message::from_digest(sighash);
    let secp = Secp256k1::verification_only();
    secp.verify_schnorr(
        &Signature::from_slice(&witness[0]).unwrap(),
        &message,
        &opened.metadata.keys.enclave_pubkey,
    )
    .unwrap();
    secp.verify_schnorr(
        &Signature::from_slice(&witness[1]).unwrap(),
        &message,
        &opened.metadata.keys.client_pubkey,
    )
    .unwrap();
    verify_signed_recovery(
        &recovery.transaction,
        opened.metadata.amount_sat,
        &opened.metadata.keys,
    )
    .unwrap();
}

#[test]
fn exact_sign_retries_are_idempotent_and_complete_identically() {
    let mut opened = opened();
    let status = opened.enclave.status(opened.metadata.keys.coin_id).unwrap();
    let (request, prepared) = prepare_recovery(
        &opened.metadata,
        &status,
        opened.client_secret,
        CAP_0,
        INITIAL_HANDOFF,
        capability_hash(&CAP_A),
        xonly(3),
        DELAY_BLOCKS,
        0,
    )
    .unwrap();
    let first = opened.enclave.sign(request.clone()).unwrap();
    let second = opened.enclave.sign(request.clone()).unwrap();
    assert_eq!(first, second);
    assert_eq!(
        opened
            .enclave
            .status(opened.metadata.keys.coin_id)
            .unwrap()
            .signature_count,
        1
    );
    let first_recovery =
        complete_recovery(&request, &first, prepared.clone(), opened.client_secret).unwrap();
    let second_recovery =
        complete_recovery(&request, &second, prepared, opened.client_secret).unwrap();
    assert_eq!(first_recovery, second_recovery);
}
