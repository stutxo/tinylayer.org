mod support;

use bitcoin::{
    Amount, ScriptBuf, Sequence, TxIn, TxOut, Witness, absolute, secp256k1::schnorr::Signature,
    transaction::Version,
};
use tinylayer_client::{
    CoinStatus, DELAY_STEP, Error, INITIAL_HANDOFF, SignRequest, SignResponse, SignedRecovery,
    authorization, capability_hash, complete_recovery, funding_script, prepare_recovery,
    verify_funding_utxo, verify_history, verify_recovery, verify_sign_response,
    verify_signed_recovery,
};

use support::{
    AMOUNT, CAP_0, CAP_A, CAP_B, DELAY_BLOCKS, initial_handoff, opened, outpoint, secret, sign,
    xonly,
};

fn signed() -> (support::Opened, SignedRecovery, [u8; 32]) {
    let mut opened = opened();
    let (recovery, handoff) = sign(
        &mut opened.enclave,
        &opened.metadata,
        opened.client_secret,
        CAP_0,
        initial_handoff(),
        capability_hash(&CAP_A),
        xonly(3),
        DELAY_BLOCKS,
    );
    (opened, recovery, handoff)
}

fn replace_witness(transaction: &mut bitcoin::Transaction, items: &[Vec<u8>]) {
    let mut witness = Witness::new();
    for item in items {
        witness.push(item);
    }
    transaction.input[0].witness = witness;
}

fn changed_signature(signature: Signature) -> Signature {
    let mut bytes = signature.serialize();
    bytes[63] ^= 1;
    Signature::from_slice(&bytes).unwrap()
}

#[test]
fn preparation_checks_secret_status_authorization_handoff_and_window() {
    let opened = opened();
    let status = opened.enclave.status(opened.metadata.keys.coin_id).unwrap();
    let prepare = |status: &CoinStatus,
                   client_secret,
                   capability,
                   handoff,
                   next_capability_hash,
                   funding_confirmations| {
        prepare_recovery(
            &opened.metadata,
            status,
            client_secret,
            capability,
            handoff,
            next_capability_hash,
            xonly(3),
            DELAY_BLOCKS,
            funding_confirmations,
        )
    };
    assert_eq!(
        prepare(
            &status,
            secret(2),
            CAP_0,
            INITIAL_HANDOFF,
            capability_hash(&CAP_A),
            0,
        )
        .err(),
        Some(Error::WrongClientKey)
    );
    assert_eq!(
        prepare(
            &status,
            opened.client_secret,
            CAP_A,
            INITIAL_HANDOFF,
            capability_hash(&CAP_B),
            0,
        )
        .err(),
        Some(Error::ResponseMismatch)
    );
    assert_eq!(
        prepare(
            &status,
            opened.client_secret,
            CAP_0,
            [1; 32],
            capability_hash(&CAP_A),
            0,
        )
        .err(),
        Some(Error::ResponseMismatch)
    );
    assert_eq!(
        prepare(
            &status,
            opened.client_secret,
            CAP_0,
            INITIAL_HANDOFF,
            capability_hash(&CAP_0),
            0,
        )
        .err(),
        Some(Error::ResponseMismatch)
    );
    assert_eq!(
        prepare(
            &status,
            opened.client_secret,
            CAP_0,
            INITIAL_HANDOFF,
            capability_hash(&CAP_A),
            DELAY_BLOCKS,
        )
        .err(),
        Some(Error::UnsafeDelay)
    );
    let mut wrong_key = status;
    wrong_key.signing_pubkey = xonly(9);
    assert_eq!(
        prepare(
            &wrong_key,
            opened.client_secret,
            CAP_0,
            INITIAL_HANDOFF,
            capability_hash(&CAP_A),
            0,
        )
        .err(),
        Some(Error::ResponseMismatch)
    );
}

#[test]
fn sign_response_verification_binds_count_authorization_handoff_and_signature() {
    let mut opened = opened();
    let before = opened.enclave.status(opened.metadata.keys.coin_id).unwrap();
    let (request, _) = prepare_recovery(
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
    let after = opened.enclave.status(opened.metadata.keys.coin_id).unwrap();
    verify_sign_response(&request, before.signature_count, &after, &response).unwrap();

    type Mutate = fn(&mut CoinStatus);
    let status_mutations: [Mutate; 3] = [
        |status| status.coin_id[0] ^= 1,
        |status| status.signature_count -= 1,
        |status| status.authorization[0] ^= 1,
    ];
    for mutate in status_mutations {
        let mut changed = after.clone();
        mutate(&mut changed);
        assert_eq!(
            verify_sign_response(&request, before.signature_count, &changed, &response),
            Err(Error::ResponseMismatch)
        );
    }

    let mut wrong_handoff = response;
    wrong_handoff.next_handoff[0] ^= 1;
    assert_eq!(
        verify_sign_response(&request, before.signature_count, &after, &wrong_handoff),
        Err(Error::ResponseMismatch)
    );
    let bad_signature = SignResponse {
        signature: changed_signature(response.signature),
        ..response
    };
    assert_eq!(
        verify_sign_response(&request, before.signature_count, &after, &bad_signature),
        Err(Error::InvalidEnclaveSignature)
    );
    let mut unpinned_key = after.clone();
    unpinned_key.signing_pubkey = xonly(9);
    assert_eq!(
        verify_sign_response(&request, before.signature_count, &unpinned_key, &response),
        Err(Error::InvalidEnclaveSignature)
    );
    assert_eq!(
        verify_sign_response(&request, u64::MAX, &after, &response),
        Err(Error::ResponseMismatch)
    );
}

#[test]
fn completion_revalidates_request_secret_transaction_and_pinned_enclave_key() {
    type Mutate = fn(&mut SignRequest);
    let request_mutations: [Mutate; 5] = [
        |request| request.coin_id[0] ^= 1,
        |request| request.current_capability[0] ^= 1,
        |request| request.current_handoff[0] ^= 1,
        |request| request.next_capability_hash[0] ^= 1,
        |request| request.sighash[0] ^= 1,
    ];
    for mutate in request_mutations {
        let mut opened = opened();
        let status = opened.enclave.status(opened.metadata.keys.coin_id).unwrap();
        let (mut request, prepared) = prepare_recovery(
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
        let response = opened.enclave.sign(request.clone()).unwrap();
        mutate(&mut request);
        assert_eq!(
            complete_recovery(&request, &response, prepared, opened.client_secret),
            Err(Error::ResponseMismatch)
        );
    }

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
    let response = opened.enclave.sign(request.clone()).unwrap();
    assert_eq!(
        complete_recovery(&request, &response, prepared, secret(2)),
        Err(Error::WrongClientKey)
    );

    let mut other = support::opened();
    let mut other_request = request.clone();
    other_request.coin_id = other.metadata.keys.coin_id;
    let other_response = other.enclave.sign(other_request).unwrap();
    let (_, prepared) = prepare_recovery(
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
    assert_eq!(
        complete_recovery(&request, &other_response, prepared, opened.client_secret,),
        Err(Error::InvalidEnclaveSignature)
    );
}

#[test]
fn recovery_rejects_key_paths_annexes_extra_items_and_nondefault_encodings() {
    let (opened, recovery, _) = signed();
    let valid: Vec<Vec<u8>> = recovery.transaction.input[0]
        .witness
        .iter()
        .map(<[u8]>::to_vec)
        .collect();
    let cases = [
        Vec::new(),
        vec![valid[0].clone()],
        valid[..3].to_vec(),
        {
            let mut extra = valid.clone();
            extra.push(Vec::new());
            extra
        },
        {
            let mut annex = valid.clone();
            annex.push(vec![0x50]);
            annex
        },
        {
            let mut explicit_default = valid.clone();
            explicit_default[0].push(0);
            explicit_default
        },
        {
            let mut weak_type = valid.clone();
            weak_type[1].push(0x82);
            weak_type
        },
    ];
    for items in cases {
        let mut changed = recovery.transaction.clone();
        replace_witness(&mut changed, &items);
        assert_eq!(
            verify_signed_recovery(&changed, AMOUNT, &opened.metadata.keys),
            Err(Error::InvalidWitness)
        );
    }
}

#[test]
fn recovery_rejects_altered_leaf_keys_opcodes_and_control_blocks() {
    let (opened, recovery, _) = signed();
    let valid: Vec<Vec<u8>> = recovery.transaction.input[0]
        .witness
        .iter()
        .map(<[u8]>::to_vec)
        .collect();
    let mut cases = Vec::new();
    let mut opcode = valid.clone();
    opcode[2][33] = 0xac;
    cases.push(opcode);
    let mut client_key = valid.clone();
    client_key[2][1] ^= 1;
    cases.push(client_key);
    let mut enclave_key = valid.clone();
    enclave_key[2][35] ^= 1;
    cases.push(enclave_key);
    let mut parity = valid.clone();
    parity[3][0] ^= 1;
    cases.push(parity);
    let mut internal_key = valid.clone();
    internal_key[3][1] ^= 1;
    cases.push(internal_key);
    let mut branch = valid;
    branch[3].extend_from_slice(&[0; 32]);
    cases.push(branch);

    for items in cases {
        let mut changed = recovery.transaction.clone();
        replace_witness(&mut changed, &items);
        assert_eq!(
            verify_signed_recovery(&changed, AMOUNT, &opened.metadata.keys),
            Err(Error::InvalidWitness)
        );
    }
}

#[test]
fn recovery_rejects_swapped_duplicated_and_corrupt_signatures() {
    let (opened, recovery, _) = signed();
    let valid: Vec<Vec<u8>> = recovery.transaction.input[0]
        .witness
        .iter()
        .map(<[u8]>::to_vec)
        .collect();

    let mut swapped = valid.clone();
    swapped.swap(0, 1);
    let mut changed = recovery.transaction.clone();
    replace_witness(&mut changed, &swapped);
    assert_eq!(
        verify_signed_recovery(&changed, AMOUNT, &opened.metadata.keys),
        Err(Error::InvalidEnclaveSignature)
    );

    for duplicate_index in [0, 1] {
        let mut duplicate = valid.clone();
        duplicate[1 - duplicate_index] = duplicate[duplicate_index].clone();
        let mut changed = recovery.transaction.clone();
        replace_witness(&mut changed, &duplicate);
        assert!(verify_signed_recovery(&changed, AMOUNT, &opened.metadata.keys).is_err());
    }

    let mut bad_enclave = valid.clone();
    bad_enclave[0][63] ^= 1;
    let mut changed = recovery.transaction.clone();
    replace_witness(&mut changed, &bad_enclave);
    assert_eq!(
        verify_signed_recovery(&changed, AMOUNT, &opened.metadata.keys),
        Err(Error::InvalidEnclaveSignature)
    );

    let mut bad_client = valid;
    bad_client[1][63] ^= 1;
    let mut changed = recovery.transaction;
    replace_witness(&mut changed, &bad_client);
    assert_eq!(
        verify_signed_recovery(&changed, AMOUNT, &opened.metadata.keys),
        Err(Error::InvalidClientSignature)
    );
}

#[test]
fn recovery_verification_rejects_every_canonical_transaction_mutation() {
    type Mutate = fn(&mut SignedRecovery);
    let mutations: [Mutate; 14] = [
        |recovery| recovery.transaction.version = Version::ONE,
        |recovery| recovery.transaction.lock_time = absolute::LockTime::from_height(1).unwrap(),
        |recovery| recovery.transaction.input[0].previous_output.vout ^= 1,
        |recovery| recovery.transaction.input[0].script_sig = ScriptBuf::from_bytes(vec![1]),
        |recovery| recovery.transaction.input[0].sequence = Sequence::MAX,
        |recovery| {
            recovery.transaction.input[0].sequence =
                Sequence::from_512_second_intervals(DELAY_BLOCKS as u16)
        },
        |recovery| {
            recovery.transaction.input[0].sequence =
                Sequence::from_consensus(DELAY_BLOCKS | (1 << 16))
        },
        |recovery| recovery.transaction.input.push(TxIn::default()),
        |recovery| recovery.transaction.input.clear(),
        |recovery| recovery.transaction.output[0].value = Amount::from_sat(1),
        |recovery| recovery.transaction.output[0].script_pubkey = ScriptBuf::new(),
        |recovery| recovery.transaction.output.push(TxOut::NULL),
        |recovery| recovery.withdrawal_xonly_pubkey = xonly(9),
        |recovery| recovery.delay_blocks += 1,
    ];
    for mutate in mutations {
        let (opened, mut recovery, _) = signed();
        mutate(&mut recovery);
        assert_eq!(
            verify_recovery(&opened.metadata, &recovery),
            Err(Error::TransactionMismatch)
        );
    }
}

#[test]
fn signatures_and_funding_commit_to_amount_outpoint_and_funding_script() {
    let (opened, recovery, _) = signed();
    verify_signed_recovery(&recovery.transaction, AMOUNT, &opened.metadata.keys).unwrap();
    assert_eq!(
        verify_signed_recovery(&recovery.transaction, AMOUNT + 1, &opened.metadata.keys),
        Err(Error::InvalidEnclaveSignature)
    );
    let mut wrong_keys = opened.metadata.keys.clone();
    wrong_keys.enclave_pubkey = xonly(9);
    assert_eq!(
        verify_signed_recovery(&recovery.transaction, AMOUNT, &wrong_keys),
        Err(Error::InvalidWitness)
    );
    let mut wrong_outpoint_tx = recovery.transaction.clone();
    wrong_outpoint_tx.input[0].previous_output.vout ^= 1;
    assert_eq!(
        verify_signed_recovery(&wrong_outpoint_tx, AMOUNT, &opened.metadata.keys),
        Err(Error::InvalidEnclaveSignature)
    );

    let expected = TxOut {
        value: Amount::from_sat(AMOUNT),
        script_pubkey: funding_script(&opened.metadata.keys),
    };
    verify_funding_utxo(&opened.metadata, outpoint(), &expected).unwrap();
    let mut wrong_outpoint = outpoint();
    wrong_outpoint.vout ^= 1;
    assert_eq!(
        verify_funding_utxo(&opened.metadata, wrong_outpoint, &expected),
        Err(Error::FundingMismatch)
    );
    let wrong_amount = TxOut {
        value: Amount::from_sat(AMOUNT - 1),
        ..expected.clone()
    };
    assert_eq!(
        verify_funding_utxo(&opened.metadata, outpoint(), &wrong_amount),
        Err(Error::FundingMismatch)
    );
    let wrong_script = TxOut {
        value: expected.value,
        script_pubkey: ScriptBuf::new_p2tr(
            &bitcoin::secp256k1::Secp256k1::verification_only(),
            xonly(9),
            None,
        ),
    };
    assert_eq!(
        verify_funding_utxo(&opened.metadata, outpoint(), &wrong_script),
        Err(Error::FundingMismatch)
    );
}

fn two_recoveries() -> (support::Opened, Vec<SignedRecovery>, [u8; 32]) {
    let mut opened = opened();
    let (alice, handoff_a) = sign(
        &mut opened.enclave,
        &opened.metadata,
        opened.client_secret,
        CAP_0,
        INITIAL_HANDOFF,
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
    (opened, vec![alice, bob], handoff_b)
}

#[test]
fn history_checks_count_latest_authorization_capability_handoff_and_secret() {
    let (opened, history, handoff) = two_recoveries();
    let status = opened.enclave.status(opened.metadata.keys.coin_id).unwrap();
    verify_history(
        &opened.metadata,
        &status,
        opened.client_secret,
        CAP_B,
        handoff,
        xonly(4),
        0,
        &history,
    )
    .unwrap();

    let mut wrong_count = status.clone();
    wrong_count.signature_count -= 1;
    assert_eq!(
        verify_history(
            &opened.metadata,
            &wrong_count,
            opened.client_secret,
            CAP_B,
            handoff,
            xonly(4),
            0,
            &history,
        ),
        Err(Error::HistoryMismatch)
    );
    let mut wrong_authorization = status.clone();
    wrong_authorization.authorization[0] ^= 1;
    assert_eq!(
        verify_history(
            &opened.metadata,
            &wrong_authorization,
            opened.client_secret,
            CAP_B,
            handoff,
            xonly(4),
            0,
            &history,
        ),
        Err(Error::HistoryMismatch)
    );
    for (capability, current_handoff, latest) in [
        (CAP_A, handoff, xonly(4)),
        (CAP_B, [9; 32], xonly(4)),
        (CAP_B, handoff, xonly(9)),
    ] {
        assert_eq!(
            verify_history(
                &opened.metadata,
                &status,
                opened.client_secret,
                capability,
                current_handoff,
                latest,
                0,
                &history,
            ),
            Err(Error::HistoryMismatch)
        );
    }
    assert_eq!(
        verify_history(
            &opened.metadata,
            &status,
            secret(2),
            CAP_B,
            handoff,
            xonly(4),
            0,
            &history,
        ),
        Err(Error::WrongClientKey)
    );
    assert_eq!(
        status.authorization,
        authorization(
            &opened.metadata.keys.coin_id,
            &capability_hash(&CAP_B),
            &handoff,
        )
    );
}

#[test]
fn history_rejects_missing_extra_reordered_bad_reaction_and_expired_entries() {
    let (opened, history, handoff) = two_recoveries();
    let status = opened.enclave.status(opened.metadata.keys.coin_id).unwrap();
    for invalid in [
        Vec::new(),
        history[..1].to_vec(),
        vec![history[1].clone(), history[0].clone()],
        vec![history[0].clone(), history[0].clone()],
        vec![history[0].clone(), history[1].clone(), history[1].clone()],
    ] {
        assert!(
            verify_history(
                &opened.metadata,
                &status,
                opened.client_secret,
                CAP_B,
                handoff,
                xonly(4),
                0,
                &invalid,
            )
            .is_err()
        );
    }
    assert_eq!(
        verify_history(
            &opened.metadata,
            &status,
            opened.client_secret,
            CAP_B,
            handoff,
            xonly(4),
            DELAY_BLOCKS - DELAY_STEP,
            &history,
        ),
        Err(Error::UnsafeDelay)
    );

    let mut wrong_step_opened = support::opened();
    let (wrong_step_alice, wrong_step_handoff_a) = sign(
        &mut wrong_step_opened.enclave,
        &wrong_step_opened.metadata,
        wrong_step_opened.client_secret,
        CAP_0,
        INITIAL_HANDOFF,
        capability_hash(&CAP_A),
        xonly(3),
        DELAY_BLOCKS,
    );
    let (wrong_step_bob, wrong_step_handoff_b) = sign(
        &mut wrong_step_opened.enclave,
        &wrong_step_opened.metadata,
        wrong_step_opened.client_secret,
        CAP_A,
        wrong_step_handoff_a,
        capability_hash(&CAP_B),
        xonly(4),
        DELAY_BLOCKS - DELAY_STEP - 1,
    );
    let wrong_step_status = wrong_step_opened
        .enclave
        .status(wrong_step_opened.metadata.keys.coin_id)
        .unwrap();
    assert_eq!(
        verify_history(
            &wrong_step_opened.metadata,
            &wrong_step_status,
            wrong_step_opened.client_secret,
            CAP_B,
            wrong_step_handoff_b,
            xonly(4),
            0,
            &[wrong_step_alice, wrong_step_bob],
        ),
        Err(Error::TransactionMismatch)
    );
}

#[test]
fn malformed_transactions_report_sighash_failures() {
    let opened = opened();
    let transaction = bitcoin::Transaction {
        version: Version::TWO,
        lock_time: absolute::LockTime::ZERO,
        input: vec![],
        output: vec![],
    };
    assert_eq!(
        tinylayer_client::recovery_sighash(&transaction, AMOUNT, &opened.metadata.keys),
        Err(Error::Sighash)
    );
}
