use secp256k1::{Message, Secp256k1};
use tinylayer_enclave::{
    CoinStatus, Enclave, Error, INITIAL_HANDOFF, RegisterRequest, Request, Response, SignRequest,
    SignResponse, Signer, authorization, capability_hash,
};

const CAP_A: [u8; 32] = [0xa1; 32];
const CAP_B: [u8; 32] = [0xb2; 32];
const CAP_C: [u8; 32] = [0xc3; 32];

fn registration(coin_id: [u8; 32], capability: [u8; 32]) -> RegisterRequest {
    RegisterRequest {
        coin_id,
        initial_capability_hash: capability_hash(&capability),
    }
}

fn sign_request(
    coin_id: [u8; 32],
    capability: [u8; 32],
    handoff: [u8; 32],
    next_capability: [u8; 32],
    sighash: [u8; 32],
) -> SignRequest {
    SignRequest {
        coin_id,
        current_capability: capability,
        current_handoff: handoff,
        next_capability_hash: capability_hash(&next_capability),
        sighash,
    }
}

fn verify(status: &CoinStatus, request: &SignRequest, response: &SignResponse) {
    Secp256k1::verification_only()
        .verify_schnorr(
            &response.signature,
            &Message::from_digest(request.sighash),
            &status.signing_pubkey,
        )
        .unwrap();
}

#[test]
fn capacity_and_duplicate_registration_return_the_live_state() {
    let mut empty = Signer::<0>::new();
    assert_eq!(
        empty.register(registration([1; 32], CAP_A)),
        Err(Error::CapacityReached)
    );
    assert_eq!(empty.status([1; 32]), Err(Error::UnknownCoin));

    let mut enclave = Signer::<1>::new();
    let request = registration([1; 32], CAP_A);
    let initial = enclave.register(request.clone()).unwrap();
    assert_eq!(initial.coin_id, request.coin_id);
    assert_eq!(initial.signature_count, 0);
    assert_eq!(
        initial.authorization,
        authorization(
            &request.coin_id,
            &request.initial_capability_hash,
            &INITIAL_HANDOFF
        )
    );
    assert_eq!(initial.signing_pubkey.serialize().len(), 32);
    assert_eq!(enclave.register(request.clone()).unwrap(), initial);

    let mut conflicting = request.clone();
    conflicting.initial_capability_hash[0] ^= 1;
    assert_eq!(enclave.register(conflicting).unwrap(), initial);
    assert_eq!(
        enclave.register(registration([2; 32], CAP_A)),
        Err(Error::CapacityReached)
    );

    enclave
        .sign(sign_request(
            request.coin_id,
            CAP_A,
            INITIAL_HANDOFF,
            CAP_B,
            [7; 32],
        ))
        .unwrap();
    assert_eq!(
        enclave.register(request).unwrap(),
        enclave.status([1; 32]).unwrap()
    );
}

#[test]
fn unknown_coin_operations_never_create_state() {
    let coin_id = [9; 32];
    let mut enclave = Enclave::new();
    assert_eq!(enclave.status(coin_id), Err(Error::UnknownCoin));
    assert_eq!(
        enclave.sign(sign_request(
            coin_id,
            CAP_A,
            INITIAL_HANDOFF,
            CAP_B,
            [1; 32]
        )),
        Err(Error::UnknownCoin)
    );
    assert_eq!(enclave.status(coin_id), Err(Error::UnknownCoin));
}

#[test]
fn signatures_are_valid_and_exact_latest_retries_return_the_cached_response() {
    let coin_id = [1; 32];
    let mut enclave = Enclave::new();
    let initial = enclave.register(registration(coin_id, CAP_A)).unwrap();
    let request = sign_request(coin_id, CAP_A, INITIAL_HANDOFF, CAP_B, [7; 32]);
    let response = enclave.sign(request.clone()).unwrap();
    verify(&initial, &request, &response);

    let after = enclave.status(coin_id).unwrap();
    assert_eq!(after.signing_pubkey, initial.signing_pubkey);
    assert_eq!(after.signature_count, 1);
    assert_eq!(
        after.authorization,
        authorization(
            &request.coin_id,
            &request.next_capability_hash,
            &response.next_handoff
        )
    );
    assert_eq!(enclave.sign(request.clone()).unwrap(), response);
    assert_eq!(enclave.status(coin_id).unwrap(), after);

    let mut conflicts = Vec::new();
    let mut changed = request.clone();
    changed.current_capability[0] ^= 1;
    conflicts.push(changed);
    let mut changed = request.clone();
    changed.current_handoff[0] ^= 1;
    conflicts.push(changed);
    let mut changed = request.clone();
    changed.next_capability_hash = capability_hash(&CAP_C);
    conflicts.push(changed);
    let mut changed = request;
    changed.sighash[0] ^= 1;
    conflicts.push(changed);

    for conflict in conflicts {
        assert_eq!(enclave.sign(conflict), Err(Error::Unauthorized));
        assert_eq!(enclave.status(coin_id).unwrap(), after);
    }
}

#[test]
fn stale_inputs_do_not_mutate_and_only_the_latest_success_is_cached() {
    let coin_id = [1; 32];
    let mut enclave = Enclave::new();
    let initial = enclave.register(registration(coin_id, CAP_A)).unwrap();

    let stale_capability = sign_request(coin_id, [0xff; 32], INITIAL_HANDOFF, CAP_B, [1; 32]);
    assert_eq!(enclave.sign(stale_capability), Err(Error::Unauthorized));
    let stale_handoff = sign_request(coin_id, CAP_A, [0xff; 32], CAP_B, [2; 32]);
    assert_eq!(enclave.sign(stale_handoff), Err(Error::Unauthorized));
    let unchanged = sign_request(coin_id, CAP_A, INITIAL_HANDOFF, CAP_A, [3; 32]);
    assert_eq!(enclave.sign(unchanged), Err(Error::UnchangedCapability));
    assert_eq!(enclave.status(coin_id).unwrap(), initial);

    let first = sign_request(coin_id, CAP_A, INITIAL_HANDOFF, CAP_B, [4; 32]);
    let first_response = enclave.sign(first.clone()).unwrap();
    let rotated = enclave.status(coin_id).unwrap();
    assert_eq!(
        enclave.sign(sign_request(
            coin_id,
            CAP_A,
            first_response.next_handoff,
            CAP_C,
            [5; 32]
        )),
        Err(Error::Unauthorized)
    );
    assert_eq!(
        enclave.sign(sign_request(
            coin_id,
            CAP_B,
            INITIAL_HANDOFF,
            CAP_C,
            [6; 32]
        )),
        Err(Error::Unauthorized)
    );
    assert_eq!(enclave.status(coin_id).unwrap(), rotated);

    let successor = sign_request(coin_id, CAP_B, first_response.next_handoff, CAP_C, [7; 32]);
    let successor_response = enclave.sign(successor.clone()).unwrap();
    let successor_state = enclave.status(coin_id).unwrap();
    assert_eq!(successor_state.signature_count, 2);
    assert_eq!(
        successor_state.authorization,
        authorization(
            &coin_id,
            &successor.next_capability_hash,
            &successor_response.next_handoff
        )
    );
    assert_eq!(enclave.sign(successor).unwrap(), successor_response);
    assert_eq!(enclave.sign(first), Err(Error::Unauthorized));
    assert_eq!(enclave.status(coin_id).unwrap(), successor_state);
}

#[test]
fn sixty_four_capability_transitions_validate_and_count_once_each() {
    let coin_id = [1; 32];
    let mut capability = [0; 32];
    let mut handoff = INITIAL_HANDOFF;
    let mut enclave = Enclave::new();
    let initial = enclave.register(registration(coin_id, capability)).unwrap();

    for index in 1..=64_u8 {
        let next_capability = [index; 32];
        let request = sign_request(
            coin_id,
            capability,
            handoff,
            next_capability,
            [index.wrapping_add(64); 32],
        );
        let response = enclave.sign(request.clone()).unwrap();
        verify(&initial, &request, &response);
        let status = enclave.status(coin_id).unwrap();
        assert_eq!(status.signing_pubkey, initial.signing_pubkey);
        assert_eq!(status.signature_count, u64::from(index));
        assert_eq!(
            status.authorization,
            authorization(
                &coin_id,
                &request.next_capability_hash,
                &response.next_handoff
            )
        );
        assert_eq!(enclave.sign(request.clone()).unwrap(), response);
        assert_eq!(enclave.status(coin_id).unwrap(), status);
        capability = next_capability;
        handoff = response.next_handoff;
    }
}

#[test]
fn coins_have_independent_random_keys_authorizations_and_state() {
    let mut enclave = Enclave::new();
    let first = enclave.register(registration([1; 32], CAP_A)).unwrap();
    let second = enclave.register(registration([2; 32], CAP_A)).unwrap();
    assert_ne!(first.signing_pubkey, second.signing_pubkey);
    assert_ne!(first.authorization, second.authorization);

    let first_request = sign_request([1; 32], CAP_A, INITIAL_HANDOFF, CAP_B, [7; 32]);
    let first_response = enclave.sign(first_request.clone()).unwrap();
    verify(&first, &first_request, &first_response);
    assert_eq!(enclave.status([1; 32]).unwrap().signature_count, 1);
    assert_eq!(enclave.status([2; 32]).unwrap(), second);

    let second_request = sign_request([2; 32], CAP_A, INITIAL_HANDOFF, CAP_B, [7; 32]);
    let second_response = enclave.sign(second_request.clone()).unwrap();
    verify(&second, &second_request, &second_response);
    assert_ne!(first_response.signature, second_response.signature);
}

#[test]
fn dispatcher_handles_every_v1_operation() {
    let coin_id = [1; 32];
    let mut enclave = Enclave::new();
    assert!(matches!(
        enclave.handle(Request::Register(registration(coin_id, CAP_A))),
        Ok(Response::Status(status)) if status.coin_id == coin_id && status.signature_count == 0
    ));
    assert!(matches!(
        enclave.handle(Request::Status { coin_id }),
        Ok(Response::Status(status)) if status.coin_id == coin_id
    ));
    assert!(matches!(
        enclave.handle(Request::Sign(sign_request(
            coin_id,
            CAP_A,
            INITIAL_HANDOFF,
            CAP_B,
            [7; 32]
        ))),
        Ok(Response::Signature(_))
    ));
    assert_eq!(
        enclave.handle(Request::Status { coin_id: [9; 32] }),
        Err(Error::UnknownCoin)
    );
}
