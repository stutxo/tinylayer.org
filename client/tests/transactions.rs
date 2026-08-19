mod support;

use bitcoin::{
    Amount, ScriptBuf, Sequence, TxOut, absolute,
    address::NetworkUnchecked,
    hashes::Hash as _,
    secp256k1::{Message, Secp256k1, XOnlyPublicKey},
    sighash::Prevouts,
    taproot::{ControlBlock, LeafVersion, TapLeafHash, TapNodeHash, TaprootBuilder},
    transaction::Version,
};
use tinylayer_client::{
    DELAY_STEP, Error, NUMS_INTERNAL_KEY_BYTES, NetworkId, TRUC_VERSION, build_exit_child,
    canonical_recovery, capability_hash, funding_address, funding_control_block, funding_script,
    funding_tapscript, recovery_sighash, validate_reaction_window,
};

use support::{
    AMOUNT, CAP_0, CAP_A, DELAY_BLOCKS, initial_handoff, opened, outpoint, secret, sign, xonly,
};

#[test]
fn funding_tree_uses_exact_leaf_nums_key_and_empty_branch() {
    let opened = opened();
    let keys = &opened.metadata.keys;
    let leaf = funding_tapscript(keys);
    let mut expected_leaf = Vec::with_capacity(68);
    expected_leaf.push(32);
    expected_leaf.extend_from_slice(&keys.client_pubkey.serialize());
    expected_leaf.push(0xad);
    expected_leaf.push(32);
    expected_leaf.extend_from_slice(&keys.enclave_pubkey.serialize());
    expected_leaf.push(0xac);
    assert_eq!(leaf.as_bytes(), expected_leaf);
    assert_eq!(leaf.len(), 68);

    let control = funding_control_block(keys);
    let serialized = control.serialize();
    assert_eq!(serialized.len(), 33);
    assert_eq!(&serialized[1..], NUMS_INTERNAL_KEY_BYTES);
    assert_eq!(control.leaf_version, LeafVersion::TapScript);
    assert!(control.merkle_branch.is_empty());
    assert_eq!(control.internal_key.serialize(), NUMS_INTERNAL_KEY_BYTES);
    assert_ne!(control.internal_key, keys.client_pubkey);
    assert_ne!(control.internal_key, keys.enclave_pubkey);
    assert_eq!(ControlBlock::decode(&serialized).unwrap(), control);

    let secp = Secp256k1::verification_only();
    let rebuilt = TaprootBuilder::new()
        .add_leaf(0, leaf.clone())
        .unwrap()
        .finalize(
            &secp,
            XOnlyPublicKey::from_slice(&NUMS_INTERNAL_KEY_BYTES).unwrap(),
        )
        .unwrap();
    assert_eq!(
        rebuilt.merkle_root(),
        Some(TapNodeHash::from_script(&leaf, LeafVersion::TapScript))
    );
    assert_eq!(
        funding_script(keys),
        ScriptBuf::new_p2tr_tweaked(rebuilt.output_key())
    );
    assert_eq!(
        rebuilt
            .control_block(&(leaf, LeafVersion::TapScript))
            .unwrap(),
        control
    );
}

#[test]
fn funding_addresses_match_the_single_derived_output() {
    let opened = opened();
    let keys = &opened.metadata.keys;
    for network in [NetworkId::Regtest, NetworkId::Mutinynet, NetworkId::Mainnet] {
        let address = funding_address(keys, network);
        assert_eq!(address.script_pubkey(), funding_script(keys));
        let unchecked = address
            .to_string()
            .parse::<bitcoin::Address<NetworkUnchecked>>()
            .unwrap();
        assert!(unchecked.is_valid_for_network(network.bitcoin_network()));
    }
}

#[test]
fn recovery_sighash_is_exact_bip342_default_script_spend() {
    let opened = opened();
    let tx = canonical_recovery(outpoint(), AMOUNT, xonly(3), DELAY_BLOCKS).unwrap();
    let leaf = funding_tapscript(&opened.metadata.keys);
    let leaf_hash = TapLeafHash::from_script(&leaf, LeafVersion::TapScript);
    let prevout = TxOut {
        value: Amount::from_sat(AMOUNT),
        script_pubkey: funding_script(&opened.metadata.keys),
    };
    let expected = bitcoin::sighash::SighashCache::new(&tx)
        .taproot_script_spend_signature_hash(
            0,
            &Prevouts::All(std::slice::from_ref(&prevout)),
            leaf_hash,
            bitcoin::TapSighashType::Default,
        )
        .unwrap()
        .to_byte_array();
    assert_eq!(
        recovery_sighash(&tx, AMOUNT, &opened.metadata.keys).unwrap(),
        expected
    );

    let wrong_amount = TxOut {
        value: Amount::from_sat(AMOUNT + 1),
        ..prevout.clone()
    };
    let wrong_amount_hash = bitcoin::sighash::SighashCache::new(&tx)
        .taproot_script_spend_signature_hash(
            0,
            &Prevouts::All(std::slice::from_ref(&wrong_amount)),
            leaf_hash,
            bitcoin::TapSighashType::Default,
        )
        .unwrap()
        .to_byte_array();
    assert_ne!(expected, wrong_amount_hash);

    let key_spend = bitcoin::sighash::SighashCache::new(&tx)
        .taproot_key_spend_signature_hash(
            0,
            &Prevouts::All(std::slice::from_ref(&prevout)),
            bitcoin::TapSighashType::Default,
        )
        .unwrap()
        .to_byte_array();
    assert_ne!(expected, key_spend);
}

#[test]
fn either_secret_key_parity_for_the_same_xonly_client_key_signs() {
    let mut opened = opened();
    let negated = opened.client_secret.negate();
    assert_ne!(negated.secret_bytes(), opened.client_secret.secret_bytes());
    assert_eq!(xonly(1), negated.x_only_public_key(&Secp256k1::new()).0);
    let (recovery, _) = sign(
        &mut opened.enclave,
        &opened.metadata,
        negated,
        CAP_0,
        initial_handoff(),
        capability_hash(&CAP_A),
        xonly(9),
        DELAY_BLOCKS,
    );
    assert_eq!(recovery.transaction.input[0].witness.len(), 4);
}

#[test]
fn canonical_recovery_has_all_exact_zero_fee_v3_fields() {
    let tx = canonical_recovery(outpoint(), AMOUNT, xonly(3), DELAY_BLOCKS).unwrap();
    assert_eq!(tx.version, TRUC_VERSION);
    assert_eq!(tx.version, Version(3));
    assert_eq!(tx.lock_time, absolute::LockTime::ZERO);
    assert_eq!(tx.input.len(), 1);
    assert_eq!(tx.output.len(), 1);
    assert_eq!(tx.input[0].previous_output, outpoint());
    assert!(tx.input[0].script_sig.is_empty());
    assert_eq!(
        tx.input[0].sequence,
        Sequence::from_height(DELAY_BLOCKS as u16)
    );
    assert!(tx.input[0].sequence.is_relative_lock_time());
    assert!(tx.input[0].sequence.is_height_locked());
    assert!(!tx.input[0].sequence.is_time_locked());
    assert!(tx.input[0].sequence.is_rbf());
    assert!(tx.input[0].witness.is_empty());
    assert_eq!(tx.output[0].value, Amount::from_sat(AMOUNT));
    assert_eq!(
        tx.output[0].script_pubkey,
        ScriptBuf::new_p2tr(&Secp256k1::verification_only(), xonly(3), None)
    );
}

#[test]
fn canonical_recovery_checks_outpoint_amount_dust_and_delay() {
    assert_eq!(
        canonical_recovery(bitcoin::OutPoint::null(), AMOUNT, xonly(3), DELAY_BLOCKS),
        Err(Error::InvalidOutpoint)
    );
    assert_eq!(
        canonical_recovery(
            outpoint(),
            Amount::MAX_MONEY.to_sat() + 1,
            xonly(3),
            DELAY_BLOCKS
        ),
        Err(Error::AmountTooLarge)
    );
    let script = ScriptBuf::new_p2tr(&Secp256k1::verification_only(), xonly(3), None);
    let dust = script.minimal_non_dust().to_sat();
    assert_eq!(
        canonical_recovery(outpoint(), dust - 1, xonly(3), DELAY_BLOCKS),
        Err(Error::DustOutput)
    );
    assert!(canonical_recovery(outpoint(), dust, xonly(3), DELAY_BLOCKS).is_ok());
    assert_eq!(
        canonical_recovery(outpoint(), AMOUNT, xonly(3), 0),
        Err(Error::InvalidDelay)
    );
    assert_eq!(
        canonical_recovery(outpoint(), AMOUNT, xonly(3), u16::MAX as u32 + 1),
        Err(Error::InvalidDelay)
    );
    assert!(canonical_recovery(outpoint(), AMOUNT, xonly(3), u16::MAX.into()).is_ok());
}

#[test]
fn reaction_window_requires_exact_step_and_unexpired_delay() {
    assert_eq!(validate_reaction_window(89, 100, 90), Ok(()));
    assert_eq!(
        validate_reaction_window(90, 100, 90),
        Err(Error::UnsafeDelay)
    );
    assert_eq!(
        validate_reaction_window(0, 100, 91),
        Err(Error::TransactionMismatch)
    );
    assert_eq!(
        validate_reaction_window(0, DELAY_STEP - 1, 0),
        Err(Error::TransactionMismatch)
    );
}

#[test]
fn exit_child_pays_exact_package_fee_and_has_valid_tweaked_signature() {
    let mut opened = opened();
    let (recovery, _) = sign(
        &mut opened.enclave,
        &opened.metadata,
        opened.client_secret,
        CAP_0,
        initial_handoff(),
        capability_hash(&CAP_A),
        xonly(9),
        DELAY_BLOCKS,
    );
    assert_eq!(recovery.transaction.input[0].witness.len(), 4);
    let destination = ScriptBuf::new_p2tr(&Secp256k1::verification_only(), xonly(3), None);
    let child = build_exit_child(&recovery, AMOUNT, &secret(9), destination.clone(), 2).unwrap();
    assert_eq!(child.version, TRUC_VERSION);
    assert_eq!(child.lock_time, absolute::LockTime::ZERO);
    assert_eq!(child.input.len(), 1);
    assert_eq!(child.output.len(), 1);
    assert_eq!(
        child.input[0].previous_output,
        bitcoin::OutPoint::new(recovery.transaction.compute_txid(), 0)
    );
    assert_eq!(child.input[0].sequence, Sequence::MAX);
    assert!(child.input[0].script_sig.is_empty());
    assert_eq!(child.output[0].script_pubkey, destination);
    assert_eq!(
        AMOUNT - child.output[0].value.to_sat(),
        2 * (recovery.transaction.vsize() + child.vsize()) as u64
    );

    let signature = &child.input[0].witness[0];
    assert_eq!(child.input[0].witness.len(), 1);
    assert_eq!(signature.len(), 64);
    let sighash = bitcoin::sighash::SighashCache::new(&child)
        .taproot_key_spend_signature_hash(
            0,
            &Prevouts::All(std::slice::from_ref(&recovery.transaction.output[0])),
            bitcoin::TapSighashType::Default,
        )
        .unwrap();
    let secp = Secp256k1::verification_only();
    let (output_key, _) = bitcoin::key::TapTweak::tap_tweak(xonly(9), &secp, None);
    secp.verify_schnorr(
        &bitcoin::secp256k1::schnorr::Signature::from_slice(signature).unwrap(),
        &Message::from_digest(sighash.to_byte_array()),
        &output_key.to_x_only_public_key(),
    )
    .unwrap();
}

#[test]
fn exit_child_rejects_wrong_key_amount_and_dust() {
    let recovery = tinylayer_client::SignedRecovery {
        transaction: canonical_recovery(outpoint(), AMOUNT, xonly(9), DELAY_BLOCKS).unwrap(),
        withdrawal_xonly_pubkey: xonly(9),
        delay_blocks: DELAY_BLOCKS,
    };
    let destination = ScriptBuf::new_p2tr(&Secp256k1::verification_only(), xonly(3), None);
    assert_eq!(
        build_exit_child(&recovery, AMOUNT, &secret(8), destination.clone(), 1),
        Err(Error::WithdrawalKeyMismatch)
    );
    assert_eq!(
        build_exit_child(&recovery, AMOUNT - 1, &secret(9), destination.clone(), 1),
        Err(Error::TransactionMismatch)
    );

    let dust = destination.minimal_non_dust().to_sat();
    let dusty = tinylayer_client::SignedRecovery {
        transaction: canonical_recovery(outpoint(), dust, xonly(9), DELAY_BLOCKS).unwrap(),
        withdrawal_xonly_pubkey: xonly(9),
        delay_blocks: DELAY_BLOCKS,
    };
    assert_eq!(
        build_exit_child(&dusty, dust, &secret(9), destination, 1),
        Err(Error::DustOutput)
    );
}
