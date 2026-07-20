//! P4.2 portable Relay admin purge receipt contract。
//!
//! 该 proof 只服务 MachineRoot 丢失后的离线 fail-close 删除路径：Relay 使用独立
//! Ed25519 receipt key 签名，不复用 TLS key，也不进入 MachineRoot `ToBeSignedV1`。
//!
//! A1 只冻结 portable contract：当前 Relay Store 尚未把 consumed enrollment row 绑定
//! `machine_route`，因此 production **不能**生成 `consumed_enrollment_records=0` proof，
//! 调用方也禁止手填 0。后续 Store slice 必须在 terminal purge 同一事务删除目标 row、
//! 读回真实 0，再交给 receipt signer。

use agentdeck_protocol::relay_v2::{
    Ed25519Signature, MachineRouteId, PublicKeyBytes, RELAY_PROTOCOL_VERSION,
    RELAY_RECEIPT_FORMAT_VERSION, RELAY_RECEIPT_KEY_GENERATION_MVP, RelayAdminPurgeReadbackV1,
    RelayAdminPurgeReceiptError, RelayAdminPurgeReceiptTbsV1, RelayAdminPurgeReceiptV1,
    RelayAdminPurgeTombstoneV1, RelayMachineTombstoneKindV1, RelayReceiptKeyId,
    RelayReceiptVerifyKeyV1, RelayServerId, RootKeyId, TrustEpoch, admin_purge_tombstone_hash,
    purge_request_hash, relay_v2_schema,
};
use sha2::{Digest, Sha256};

fn hex(bytes: &[u8]) -> String {
    bytes.iter().map(|byte| format!("{byte:02x}")).collect()
}

fn relay_server(seed: u8) -> RelayServerId {
    RelayServerId::from_bytes([seed; 16])
}

fn verify_key() -> RelayReceiptVerifyKeyV1 {
    let public_key = PublicKeyBytes([0x33; 32]);
    RelayReceiptVerifyKeyV1 {
        receipt_format_version: RELAY_RECEIPT_FORMAT_VERSION,
        relay_server_id: relay_server(0x11),
        key_generation: RELAY_RECEIPT_KEY_GENERATION_MVP,
        key_id: RelayReceiptKeyId::from_public_key(&public_key),
        public_key,
    }
}

fn readback() -> RelayAdminPurgeReadbackV1 {
    RelayAdminPurgeReadbackV1 {
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
        receipt_key_id: verify_key().key_id,
        machine_route,
        root_key_id: RootKeyId::from_bytes([0x55; 16]),
        root_fingerprint,
        trust_epoch: TrustEpoch::new(7),
        enrollment_receipt_hash: [0x77; 32],
        purge_request_hash: purge_request_hash(machine_route, root_fingerprint).unwrap(),
        tombstone_kind: RelayMachineTombstoneKindV1::RootLostAdminPurge,
        readback: readback(),
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

#[test]
fn mvp_key_generation_and_root_lost_readback_are_fail_closed() {
    verify_key().validate().expect("generation 1 verify key");
    tbs().validate().expect("exact 0-1-0 root-lost readback");

    let mut key = verify_key();
    key.key_generation = 2;
    assert_eq!(
        key.validate(),
        Err(RelayAdminPurgeReceiptError::UnsupportedReceiptKeyGeneration)
    );

    let mut unsupported = tbs();
    unsupported.receipt_format_version += 1;
    assert_eq!(
        unsupported.validate(),
        Err(RelayAdminPurgeReceiptError::UnsupportedReceiptFormatVersion)
    );
    let mut unsupported = tbs();
    unsupported.relay_protocol_version += 1;
    assert_eq!(
        unsupported.validate(),
        Err(RelayAdminPurgeReceiptError::UnsupportedRelayProtocolVersion)
    );
    let mut unsupported = tbs();
    unsupported.receipt_key_generation = 2;
    assert_eq!(
        unsupported.validate(),
        Err(RelayAdminPurgeReceiptError::UnsupportedReceiptKeyGeneration)
    );

    let mut invalid_readbacks = Vec::new();
    let mut value = readback();
    value.active_machine_routes = 1;
    invalid_readbacks.push(value);
    let mut value = readback();
    value.retired_tombstones = 0;
    invalid_readbacks.push(value);
    let mut value = readback();
    value.retired_tombstones = 2;
    invalid_readbacks.push(value);
    let mut value = readback();
    // 该负例只冻结 downstream Store 的必达 readback；不是 A1 已有 production evidence。
    value.consumed_enrollment_records = 1;
    invalid_readbacks.push(value);
    let mut value = readback();
    value.device_grants = 1;
    invalid_readbacks.push(value);
    let mut value = readback();
    value.revocations = 1;
    invalid_readbacks.push(value);
    let mut value = readback();
    value.streams = 1;
    invalid_readbacks.push(value);
    let mut value = readback();
    value.frames = 1;
    invalid_readbacks.push(value);
    let mut value = readback();
    value.subscriptions = 1;
    invalid_readbacks.push(value);
    let mut value = readback();
    value.retirement_hash = Some([0xaa; 32]);
    invalid_readbacks.push(value);
    let mut value = readback();
    value.retirement_terminal_present = true;
    invalid_readbacks.push(value);

    for changed in invalid_readbacks {
        let mut value = tbs();
        value.readback = changed;
        assert_eq!(
            value.validate(),
            Err(RelayAdminPurgeReceiptError::InvalidRootLostPurgeReadback)
        );
    }
}

#[test]
fn typed_request_and_tombstone_hash_helpers_reject_manual_drift() {
    let valid = tbs();
    assert_eq!(
        hex(&valid.purge_request_hash),
        "2779bc9790b727faa4e5127875dc3456a56e0a8ebf11d3930e86a8db88a1047f"
    );
    assert_eq!(
        hex(&valid.tombstone_hash),
        "2d33e8b63a482c409b27e8fcb0f5bc7855153fc639892fd2256eb07a0973ca70"
    );

    let mut changed = valid.clone();
    changed.purge_request_hash[0] ^= 1;
    assert_eq!(
        changed.validate(),
        Err(RelayAdminPurgeReceiptError::PurgeRequestHashMismatch)
    );
    let mut changed = valid;
    changed.tombstone_hash[0] ^= 1;
    assert_eq!(
        changed.validate(),
        Err(RelayAdminPurgeReceiptError::TombstoneHashMismatch)
    );
}

#[test]
fn key_id_derivation_and_every_required_nonzero_binding_are_enforced() {
    let key = verify_key();
    let mut hasher = Sha256::new();
    hasher.update(b"AgentDeck/RelayReceiptKeyIdV1\0");
    hasher.update(key.public_key.0);
    assert_eq!(key.key_id.as_bytes(), &<[u8; 32]>::from(hasher.finalize()));

    let mut mismatched = key.clone();
    mismatched.key_id.0[0] ^= 1;
    assert_eq!(
        mismatched.validate(),
        Err(RelayAdminPurgeReceiptError::ReceiptKeyIdMismatch)
    );

    let mut zero_key_fields = Vec::new();
    let mut value = key.clone();
    value.relay_server_id = relay_server(0);
    zero_key_fields.push((value, "relayServerId"));
    let mut value = key.clone();
    value.public_key = PublicKeyBytes([0; 32]);
    value.key_id = RelayReceiptKeyId::from_public_key(&value.public_key);
    zero_key_fields.push((value, "receiptPublicKey"));
    let mut value = key;
    value.key_id = RelayReceiptKeyId::from_bytes([0; 32]);
    zero_key_fields.push((value, "receiptKeyId"));
    for (value, field) in zero_key_fields {
        assert_eq!(
            value.validate(),
            Err(RelayAdminPurgeReceiptError::ZeroBoundField(field))
        );
    }

    let base = tbs();
    let mut zero_tbs_fields = Vec::new();
    let mut value = base.clone();
    value.relay_server_id = relay_server(0);
    zero_tbs_fields.push((value, "relayServerId"));
    let mut value = base.clone();
    value.receipt_key_id = RelayReceiptKeyId::from_bytes([0; 32]);
    zero_tbs_fields.push((value, "receiptKeyId"));
    let mut value = base.clone();
    value.machine_route = MachineRouteId::from_bytes([0; 16]);
    zero_tbs_fields.push((value, "machineRoute"));
    let mut value = base.clone();
    value.root_key_id = RootKeyId::from_bytes([0; 16]);
    zero_tbs_fields.push((value, "rootKeyId"));
    let mut value = base.clone();
    value.root_fingerprint = [0; 32];
    zero_tbs_fields.push((value, "rootFingerprint"));
    let mut value = base.clone();
    value.trust_epoch = TrustEpoch::ZERO;
    zero_tbs_fields.push((value, "trustEpoch"));
    let mut value = base.clone();
    value.enrollment_receipt_hash = [0; 32];
    zero_tbs_fields.push((value, "enrollmentReceiptHash"));
    let mut value = base.clone();
    value.purge_request_hash = [0; 32];
    zero_tbs_fields.push((value, "purgeRequestHash"));
    let mut value = base;
    value.tombstone_hash = [0; 32];
    zero_tbs_fields.push((value, "tombstoneHash"));
    for (value, field) in zero_tbs_fields {
        assert_eq!(
            value.validate(),
            Err(RelayAdminPurgeReceiptError::ZeroBoundField(field))
        );
    }
}

#[test]
fn verify_key_and_purge_tbs_have_independent_canonical_domains_and_goldens() {
    let key = verify_key();
    let key_bytes = key.canonical_bytes().expect("valid verify key");
    assert!(key_bytes.starts_with(b"AgentDeck/RelayReceiptVerifyKeyV1\0"));
    assert_eq!(
        hex(&Sha256::digest(&key_bytes)),
        "93525e49454f720c3ede69115ee7965316c512a5561165e798c788c155b7d19e"
    );

    let tbs = tbs();
    let encoded = tbs.encode().expect("valid purge receipt TBS");
    assert!(encoded.starts_with(b"AgentDeck/RelayAdminPurgeReceiptTbsV1\0"));
    assert!(!encoded.starts_with(b"AgentDeck/ToBeSignedV1"));
    assert_eq!(
        hex(&Sha256::digest(&encoded)),
        "9b78c5ff3be79178ff06ef5b7c447607e011edc8c6614ecf0d260ca3de7175fb"
    );
}

#[test]
fn every_bound_field_changes_the_canonical_tbs() {
    let base = tbs();
    let canonical = base.encode().unwrap();
    let mut changed = Vec::new();

    let mut value = base.clone();
    value.relay_server_id = relay_server(0xa1);
    changed.push(value);
    let mut value = base.clone();
    value.receipt_key_id = RelayReceiptKeyId::from_bytes([0xa2; 32]);
    changed.push(value);
    let mut value = base.clone();
    value.machine_route = MachineRouteId::from_bytes([0xa3; 16]);
    changed.push(value);
    let mut value = base.clone();
    value.root_key_id = RootKeyId::from_bytes([0xa4; 16]);
    changed.push(value);
    let mut value = base.clone();
    value.root_fingerprint[0] ^= 1;
    changed.push(value);
    let mut value = base.clone();
    value.trust_epoch = TrustEpoch::new(8);
    changed.push(value);
    let mut value = base.clone();
    value.enrollment_receipt_hash[0] ^= 1;
    changed.push(value);
    for mut value in changed {
        refresh_derived_hashes(&mut value);
        assert_ne!(value.encode().unwrap(), canonical);
    }
}

#[test]
fn receipt_json_is_strict_and_relay_schema_exposes_portable_proof() {
    let receipt = RelayAdminPurgeReceiptV1::from_tbs(tbs(), Ed25519Signature([0xab; 64]))
        .expect("valid receipt shape");
    let json = serde_json::to_value(&receipt).unwrap();
    assert_eq!(json["receiptKeyGeneration"], 1);
    assert_eq!(json["tombstoneKind"], "rootLostAdminPurge");
    assert_eq!(json["readback"]["consumedEnrollmentRecords"], 0);
    assert!(json["readback"].get("retirementHash").is_none());
    assert_eq!(
        serde_json::from_value::<RelayAdminPurgeReceiptV1>(json.clone()).unwrap(),
        receipt
    );

    let mut wrong_kind = json.clone();
    wrong_kind["tombstoneKind"] = serde_json::json!("retireMachine");
    assert!(serde_json::from_value::<RelayAdminPurgeReceiptV1>(wrong_kind).is_err());

    let mut unknown = json;
    unknown["vendorReceipt"] = serde_json::json!(true);
    assert!(serde_json::from_value::<RelayAdminPurgeReceiptV1>(unknown).is_err());

    let schema = relay_v2_schema();
    for name in [
        "RelayReceiptVerifyKeyV1",
        "RelayAdminPurgeReadbackV1",
        "RelayAdminPurgeReceiptV1",
    ] {
        assert!(schema["properties"].get(name).is_some(), "missing {name}");
    }
}
