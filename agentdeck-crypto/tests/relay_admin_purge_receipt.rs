//! P4.2 dedicated Relay receipt signer/verification tests。

use agentdeck_crypto::{
    CryptoError, SigningKey, ValidatedRelayReceiptVerifyKey, sign_relay_admin_purge_receipt,
    verify_relay_admin_purge_receipt,
};
use agentdeck_protocol::relay_v2::{
    MachineRouteId, PublicKeyBytes, RELAY_PROTOCOL_VERSION, RELAY_RECEIPT_FORMAT_VERSION,
    RELAY_RECEIPT_KEY_GENERATION_MVP, RelayAdminPurgeReadbackV1, RelayAdminPurgeReceiptError,
    RelayAdminPurgeReceiptExpectationV1, RelayAdminPurgeReceiptTbsV1, RelayAdminPurgeReceiptV1,
    RelayAdminPurgeTombstoneV1, RelayMachineTombstoneKindV1, RelayReceiptKeyId,
    RelayReceiptVerifyKeyV1, RelayServerId, RootKeyId, TrustEpoch, admin_purge_tombstone_hash,
    purge_request_hash,
};

fn relay_server(seed: u8) -> RelayServerId {
    RelayServerId::from_bytes([seed; 16])
}

fn wire_key(signing: &SigningKey) -> RelayReceiptVerifyKeyV1 {
    let public_key = PublicKeyBytes(signing.verifying_key().to_bytes());
    RelayReceiptVerifyKeyV1 {
        receipt_format_version: RELAY_RECEIPT_FORMAT_VERSION,
        relay_server_id: relay_server(0x11),
        key_generation: RELAY_RECEIPT_KEY_GENERATION_MVP,
        key_id: RelayReceiptKeyId::from_public_key(&public_key),
        public_key,
    }
}

fn tbs() -> RelayAdminPurgeReceiptTbsV1 {
    let machine_route = MachineRouteId::from_bytes([0x44; 16]);
    let root_fingerprint = [0x66; 32];
    let mut value = RelayAdminPurgeReceiptTbsV1 {
        receipt_format_version: RELAY_RECEIPT_FORMAT_VERSION,
        relay_protocol_version: RELAY_PROTOCOL_VERSION,
        relay_server_id: relay_server(0x11),
        receipt_key_generation: RELAY_RECEIPT_KEY_GENERATION_MVP,
        receipt_key_id: RelayReceiptKeyId::from_public_key(&PublicKeyBytes(
            SigningKey::from_seed(&[0x42; 32])
                .verifying_key()
                .to_bytes(),
        )),
        machine_route,
        root_key_id: RootKeyId::from_bytes([0x55; 16]),
        root_fingerprint,
        trust_epoch: TrustEpoch::new(7),
        enrollment_receipt_hash: [0x77; 32],
        purge_request_hash: purge_request_hash(machine_route, root_fingerprint).unwrap(),
        tombstone_kind: RelayMachineTombstoneKindV1::RootLostAdminPurge,
        readback: RelayAdminPurgeReadbackV1 {
            active_machine_routes: 0,
            retired_tombstones: 1,
            consumed_enrollment_records: 0,
            device_grants: 0,
            revocations: 0,
            streams: 0,
            frames: 0,
            subscriptions: 0,
            retirement_hash: None,
            retirement_terminal_present: false,
        },
        tombstone_hash: [0x99; 32],
    };
    refresh_derived_hashes(&mut value);
    value
}

fn refresh_derived_hashes(value: &mut RelayAdminPurgeReceiptTbsV1) {
    value.purge_request_hash =
        purge_request_hash(value.machine_route, value.root_fingerprint).unwrap();
    value.tombstone_hash = admin_purge_tombstone_hash(&RelayAdminPurgeTombstoneV1 {
        relay_server_id: value.relay_server_id,
        machine_route: value.machine_route,
        root_key_id: value.root_key_id,
        root_fingerprint: value.root_fingerprint,
        trust_epoch: value.trust_epoch,
        enrollment_receipt_hash: value.enrollment_receipt_hash,
        purge_request_hash: value.purge_request_hash,
        tombstone_kind: value.tombstone_kind,
        readback: value.readback.clone(),
    })
    .unwrap();
}

fn changed_receipt(
    receipt: &RelayAdminPurgeReceiptV1,
    change: impl FnOnce(&mut RelayAdminPurgeReceiptTbsV1),
) -> RelayAdminPurgeReceiptV1 {
    let mut tbs = receipt.to_be_signed();
    change(&mut tbs);
    refresh_derived_hashes(&mut tbs);
    RelayAdminPurgeReceiptV1::from_tbs(tbs, receipt.signature).unwrap()
}

fn validated_key(signing: &SigningKey) -> ValidatedRelayReceiptVerifyKey {
    ValidatedRelayReceiptVerifyKey::new(wire_key(signing)).unwrap()
}

fn expectation_for(tbs: &RelayAdminPurgeReceiptTbsV1) -> RelayAdminPurgeReceiptExpectationV1 {
    RelayAdminPurgeReceiptExpectationV1 {
        relay_server_id: tbs.relay_server_id,
        machine_route: tbs.machine_route,
        root_key_id: tbs.root_key_id,
        root_fingerprint: tbs.root_fingerprint,
        trust_epoch: tbs.trust_epoch,
        enrollment_receipt_hash: tbs.enrollment_receipt_hash,
        purge_request_hash: tbs.purge_request_hash,
    }
}

fn expectation() -> RelayAdminPurgeReceiptExpectationV1 {
    expectation_for(&tbs())
}

#[test]
fn dedicated_relay_receipt_signer_round_trips_and_is_deterministic() {
    let signing = SigningKey::from_seed(&[0x42; 32]);
    let verify_key = validated_key(&signing);
    let receipt = sign_relay_admin_purge_receipt(&signing, &verify_key, tbs())
        .expect("dedicated Relay receipt signer");
    verify_relay_admin_purge_receipt(&verify_key, &expectation(), &receipt)
        .expect("portable proof verifies");
    assert_eq!(
        receipt.signature.0,
        [
            0x12, 0x61, 0x64, 0xbd, 0x99, 0xc4, 0xf8, 0xf4, 0xb8, 0x19, 0x26, 0xf8, 0x83, 0x87,
            0x96, 0x70, 0x8c, 0x0b, 0x63, 0xe1, 0xa8, 0xed, 0x38, 0x2c, 0xdd, 0x9e, 0xc9, 0x3b,
            0x02, 0xa6, 0x53, 0xe9, 0x7f, 0xe2, 0x93, 0x13, 0xf3, 0xc0, 0xf8, 0xbb, 0xde, 0x4c,
            0x03, 0x0e, 0x11, 0xa9, 0xa7, 0xc6, 0x2f, 0xa4, 0x5b, 0x67, 0x25, 0x03, 0x8e, 0x4f,
            0x92, 0xf9, 0xc0, 0xe8, 0x96, 0xa7, 0x6d, 0x07,
        ],
        "dedicated Relay receipt signer golden"
    );
}

#[test]
fn receipt_verify_key_preflight_rejects_invalid_point_zero_and_wrong_key_id() {
    let signing = SigningKey::from_seed(&[0x42; 32]);
    let valid_wire = wire_key(&signing);
    let validated = ValidatedRelayReceiptVerifyKey::new(valid_wire.clone()).unwrap();
    assert_eq!(validated.wire_anchor(), &valid_wire);

    let mut weak_point = valid_wire.clone();
    let mut identity_encoding = [0; 32];
    identity_encoding[0] = 1;
    weak_point.public_key = PublicKeyBytes(identity_encoding);
    weak_point.key_id = RelayReceiptKeyId::from_public_key(&weak_point.public_key);
    assert_eq!(
        ValidatedRelayReceiptVerifyKey::new(weak_point).unwrap_err(),
        CryptoError::InvalidKey("weak ed25519 verifying key")
    );

    let mut invalid_point = valid_wire.clone();
    invalid_point.public_key = PublicKeyBytes([
        0x19, 0x46, 0x0c, 0x51, 0x3e, 0x55, 0x2e, 0xe0, 0x3a, 0x8f, 0xb9, 0x7b, 0xb5, 0xa8, 0x83,
        0x01, 0x1f, 0x6d, 0x33, 0xe6, 0x37, 0xd2, 0x89, 0xf9, 0xd0, 0x29, 0x25, 0xba, 0xbf, 0xed,
        0xfb, 0xfc,
    ]);
    invalid_point.key_id = RelayReceiptKeyId::from_public_key(&invalid_point.public_key);
    assert_eq!(
        ValidatedRelayReceiptVerifyKey::new(invalid_point).unwrap_err(),
        CryptoError::InvalidKey("ed25519 verifying key")
    );

    let mut all_zero = valid_wire.clone();
    all_zero.public_key = PublicKeyBytes([0; 32]);
    all_zero.key_id = RelayReceiptKeyId::from_public_key(&all_zero.public_key);
    assert_eq!(
        ValidatedRelayReceiptVerifyKey::new(all_zero).unwrap_err(),
        CryptoError::InvalidRelayAdminPurgeReceipt(RelayAdminPurgeReceiptError::ZeroBoundField(
            "receiptPublicKey"
        ),)
    );

    let mut wrong_key_id = valid_wire;
    wrong_key_id.key_id.0[0] ^= 1;
    assert_eq!(
        ValidatedRelayReceiptVerifyKey::new(wrong_key_id).unwrap_err(),
        CryptoError::InvalidRelayAdminPurgeReceipt(
            RelayAdminPurgeReceiptError::ReceiptKeyIdMismatch,
        )
    );
}

#[test]
fn verifier_rejects_every_bound_field_tamper() {
    let signing = SigningKey::from_seed(&[0x42; 32]);
    let verify_key = validated_key(&signing);
    let receipt = sign_relay_admin_purge_receipt(&signing, &verify_key, tbs()).unwrap();
    let mut tampered = Vec::new();

    tampered.push(changed_receipt(&receipt, |value| {
        value.relay_server_id = relay_server(0xa1);
    }));
    tampered.push(changed_receipt(&receipt, |value| {
        value.receipt_key_id = RelayReceiptKeyId::from_bytes([0xa2; 32]);
    }));
    tampered.push(changed_receipt(&receipt, |value| {
        value.machine_route = MachineRouteId::from_bytes([0xa3; 16]);
    }));
    tampered.push(changed_receipt(&receipt, |value| {
        value.root_key_id = RootKeyId::from_bytes([0xa4; 16]);
    }));
    tampered.push(changed_receipt(&receipt, |value| {
        value.root_fingerprint[0] ^= 1;
    }));
    tampered.push(changed_receipt(&receipt, |value| {
        value.trust_epoch = TrustEpoch::new(8);
    }));
    tampered.push(changed_receipt(&receipt, |value| {
        value.enrollment_receipt_hash[0] ^= 1;
    }));
    let mut value = receipt.clone();
    value.signature.0[0] ^= 1;
    tampered.push(value);

    for changed in tampered {
        assert_eq!(
            verify_relay_admin_purge_receipt(&verify_key, &expectation(), &changed),
            Err(CryptoError::BadSignature)
        );
    }

    let mut invalid = receipt.clone();
    invalid.purge_request_hash[0] ^= 1;
    assert_eq!(
        verify_relay_admin_purge_receipt(&verify_key, &expectation(), &invalid),
        Err(CryptoError::InvalidRelayAdminPurgeReceipt(
            RelayAdminPurgeReceiptError::PurgeRequestHashMismatch,
        ))
    );
    let mut invalid = receipt;
    invalid.tombstone_hash[0] ^= 1;
    assert_eq!(
        verify_relay_admin_purge_receipt(&verify_key, &expectation(), &invalid),
        Err(CryptoError::InvalidRelayAdminPurgeReceipt(
            RelayAdminPurgeReceiptError::TombstoneHashMismatch,
        ))
    );
}

#[test]
fn cross_relay_key_route_and_invalid_root_lost_shapes_fail_closed() {
    let signing = SigningKey::from_seed(&[0x42; 32]);
    let wrong_signing = SigningKey::from_seed(&[0x43; 32]);
    let verify_key = validated_key(&signing);
    let receipt = sign_relay_admin_purge_receipt(&signing, &verify_key, tbs()).unwrap();

    let mut wrong_relay = wire_key(&signing);
    wrong_relay.relay_server_id = relay_server(0xfe);
    let wrong_relay = ValidatedRelayReceiptVerifyKey::new(wrong_relay).unwrap();
    assert!(verify_relay_admin_purge_receipt(&wrong_relay, &expectation(), &receipt).is_err());

    let mut wrong_key_id = wire_key(&signing);
    wrong_key_id.key_id = RelayReceiptKeyId::from_bytes([0xfe; 32]);
    assert!(ValidatedRelayReceiptVerifyKey::new(wrong_key_id).is_err());

    let mut wrong_key = wire_key(&signing);
    wrong_key.public_key = PublicKeyBytes(wrong_signing.verifying_key().to_bytes());
    wrong_key.key_id = RelayReceiptKeyId::from_public_key(&wrong_key.public_key);
    let wrong_key = ValidatedRelayReceiptVerifyKey::new(wrong_key).unwrap();
    assert!(verify_relay_admin_purge_receipt(&wrong_key, &expectation(), &receipt).is_err());

    assert!(sign_relay_admin_purge_receipt(&wrong_signing, &verify_key, tbs()).is_err());

    let mut wrong_route = tbs();
    wrong_route.machine_route = MachineRouteId::from_bytes([0xfe; 16]);
    refresh_derived_hashes(&mut wrong_route);
    let wrong_route_expectation = expectation_for(&wrong_route);
    let wrong_route_receipt =
        sign_relay_admin_purge_receipt(&signing, &verify_key, wrong_route).unwrap();
    assert!(
        verify_relay_admin_purge_receipt(&verify_key, &expectation(), &wrong_route_receipt)
            .is_err(),
        "signature-valid proof for another route must not satisfy the caller locator"
    );
    verify_relay_admin_purge_receipt(&verify_key, &wrong_route_expectation, &wrong_route_receipt)
        .expect("same signature verifies only with the matching typed expectation");

    let mut invalid = tbs();
    invalid.readback.retirement_hash = Some([0xaa; 32]);
    assert!(sign_relay_admin_purge_receipt(&signing, &verify_key, invalid).is_err());
    let mut invalid = tbs();
    invalid.readback.retirement_terminal_present = true;
    assert!(sign_relay_admin_purge_receipt(&signing, &verify_key, invalid).is_err());
    let mut invalid = tbs();
    invalid.readback.retired_tombstones = 0;
    assert!(sign_relay_admin_purge_receipt(&signing, &verify_key, invalid).is_err());
}

#[test]
fn typed_expectation_rejects_each_locator_binding_mismatch() {
    let signing = SigningKey::from_seed(&[0x42; 32]);
    let verify_key = validated_key(&signing);
    let receipt = sign_relay_admin_purge_receipt(&signing, &verify_key, tbs()).unwrap();
    let base = expectation();
    let mut mismatches = Vec::new();

    let mut value = base.clone();
    value.relay_server_id = relay_server(0xa1);
    mismatches.push(value);
    let mut value = base.clone();
    value.machine_route = MachineRouteId::from_bytes([0xa2; 16]);
    value.purge_request_hash = purge_request_hash(value.machine_route, value.root_fingerprint)
        .expect("valid alternate route expectation");
    mismatches.push(value);
    let mut value = base.clone();
    value.root_key_id = RootKeyId::from_bytes([0xa3; 16]);
    mismatches.push(value);
    let mut value = base.clone();
    value.root_fingerprint[0] ^= 1;
    value.purge_request_hash = purge_request_hash(value.machine_route, value.root_fingerprint)
        .expect("valid alternate root expectation");
    mismatches.push(value);
    let mut value = base.clone();
    value.trust_epoch = TrustEpoch::new(8);
    mismatches.push(value);
    let mut value = base.clone();
    value.enrollment_receipt_hash[0] ^= 1;
    mismatches.push(value);
    for changed in mismatches {
        assert_eq!(
            verify_relay_admin_purge_receipt(&verify_key, &changed, &receipt),
            Err(CryptoError::InvalidRelayAdminPurgeReceipt(
                RelayAdminPurgeReceiptError::ExpectedBindingMismatch,
            ))
        );
    }

    let mut invalid_hash = base;
    invalid_hash.purge_request_hash[0] ^= 1;
    assert_eq!(
        verify_relay_admin_purge_receipt(&verify_key, &invalid_hash, &receipt),
        Err(CryptoError::InvalidRelayAdminPurgeReceipt(
            RelayAdminPurgeReceiptError::PurgeRequestHashMismatch,
        ))
    );
}
