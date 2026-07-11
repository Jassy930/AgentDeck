//! P2.5 root-signed revoke / retirement canonical contract.
//!
//! These tests intentionally exercise only public protocol APIs. Relay/store code must never
//! invent hashes for these objects: the committed hash is derived from the byte-stable full
//! canonical form, while MachineRoot signs a `ToBeSignedV1` that binds the unsigned form.

use agentdeck_protocol::e2ee::{E2EE_FORMAT_VERSION, SignedObjectType};
use agentdeck_protocol::relay_v2::RELAY_PROTOCOL_VERSION;
use agentdeck_protocol::relay_v2::auth::{
    AUTH_SIGNATURE_FORMAT_VERSION, DeviceRevocation, Ed25519Signature,
};
use agentdeck_protocol::relay_v2::frame::RetireMachine;
use agentdeck_protocol::relay_v2::id::{
    DeviceRouteId, GrantSerial, MachineRouteId, RelayServerId, RootKeyId, TrustEpoch,
};
use agentdeck_protocol::runtime::RUNTIME_PROTOCOL_VERSION;

fn hex(bytes: &[u8]) -> String {
    bytes.iter().map(|byte| format!("{byte:02x}")).collect()
}

fn revocation() -> DeviceRevocation {
    DeviceRevocation {
        machine_route: MachineRouteId::from_bytes([0x11; 16]),
        device_route: DeviceRouteId::from_bytes([0x22; 16]),
        grant_serial: GrantSerial::new(9),
        root_key_id: RootKeyId::from_bytes([0x77; 16]),
        trust_epoch: TrustEpoch::new(3),
        signature: Ed25519Signature([0xB0; 64]),
    }
}

fn retirement() -> RetireMachine {
    RetireMachine {
        machine_route: MachineRouteId::from_bytes([0x11; 16]),
        root_key_id: RootKeyId::from_bytes([0x77; 16]),
        trust_epoch: TrustEpoch::new(4),
        signature: Ed25519Signature([0xB0; 64]),
    }
}

#[test]
fn device_revocation_unsigned_and_full_canonical_golden_are_fixed() {
    let revocation = revocation();

    assert_eq!(
        hex(&revocation.unsigned_canonical_bytes()),
        "4167656e744465636b2f4465766963655265766f636174696f6e556e7369676e656456310000000010111111111111111111111111111111110000001022222222222222222222222222222222000000000000000900000010777777777777777777777777777777770000000000000003"
    );
    assert_eq!(revocation.unsigned_canonical_bytes().len(), 113);
    assert_eq!(
        hex(&revocation.unsigned_canonical_sha256()),
        "16569fad1a3d399618675b9f8c737de688a30dd0c920269d26583ec6b99ea97b"
    );
    assert_eq!(revocation.canonical_bytes().len(), 214);
    assert_eq!(
        hex(&revocation.canonical_sha256()),
        "48b5a6c6f1d890ee0a5adf810342107527aae37c4a3a605d0814cb649de67db1"
    );

    let mut changed_signature = revocation.clone();
    changed_signature.signature = Ed25519Signature([0xB1; 64]);
    assert_eq!(
        changed_signature.unsigned_canonical_bytes(),
        revocation.unsigned_canonical_bytes(),
        "root signature is excluded from the signed object hash"
    );
    assert_ne!(
        changed_signature.canonical_bytes(),
        revocation.canonical_bytes(),
        "the persisted/committed credential hash includes the root signature"
    );
}

#[test]
fn device_revocation_tbs_binds_route_root_epoch_serial_and_unsigned_hash() {
    let revocation = revocation();
    let relay_server_id = RelayServerId::from_bytes([0x88; 16]);
    let root_fingerprint = [0xA5; 32];
    let tbs = revocation.to_be_signed_v1(relay_server_id, root_fingerprint);

    assert_eq!(tbs.object_type, SignedObjectType::DeviceRevocation);
    assert_eq!(tbs.signature_format_version, AUTH_SIGNATURE_FORMAT_VERSION);
    assert_eq!(tbs.relay_protocol_version, RELAY_PROTOCOL_VERSION);
    assert_eq!(tbs.runtime_protocol_version, RUNTIME_PROTOCOL_VERSION);
    assert_eq!(tbs.e2ee_format_version, E2EE_FORMAT_VERSION);
    assert_eq!(tbs.relay_server_id, relay_server_id);
    assert_eq!(tbs.machine_route, revocation.machine_route);
    assert_eq!(tbs.device_route, Some(revocation.device_route));
    assert_eq!(tbs.stream_route, None);
    assert_eq!(tbs.request_route, None);
    assert_eq!(tbs.stream_generation, None);
    assert_eq!(tbs.stream_cursor, None);
    assert_eq!(tbs.role_scope, "relay-device-revocation");
    assert_eq!(tbs.signing_key_fingerprint, root_fingerprint);
    assert_eq!(tbs.root_key_id, revocation.root_key_id);
    assert_eq!(tbs.trust_epoch, revocation.trust_epoch);
    assert_eq!(tbs.serial_or_generation, revocation.grant_serial.value());
    assert_eq!(tbs.not_after_ms, None);
    assert_eq!(
        tbs.signed_object_sha256,
        revocation.unsigned_canonical_sha256()
    );
}

#[test]
fn retire_machine_unsigned_and_full_canonical_golden_are_fixed() {
    let retirement = retirement();

    assert_eq!(
        hex(&retirement.unsigned_canonical_bytes()),
        "4167656e744465636b2f5265746972654d616368696e65556e7369676e6564563100000000101111111111111111111111111111111100000010777777777777777777777777777777770000000000000004"
    );
    assert_eq!(retirement.unsigned_canonical_bytes().len(), 82);
    assert_eq!(
        hex(&retirement.unsigned_canonical_sha256()),
        "93bd85d58c7f8592daab563369336a47b1b94079666fc7d51e57016fbffaac1a"
    );
    assert_eq!(retirement.canonical_bytes().len(), 180);
    assert_eq!(
        hex(&retirement.canonical_sha256()),
        "251660b89c346510f961d588109a333495af462064cb7557b35ed2ebecb5e9a4"
    );

    let mut changed_signature = retirement.clone();
    changed_signature.signature = Ed25519Signature([0xB1; 64]);
    assert_eq!(
        changed_signature.unsigned_canonical_bytes(),
        retirement.unsigned_canonical_bytes()
    );
    assert_ne!(
        changed_signature.canonical_bytes(),
        retirement.canonical_bytes()
    );
}

#[test]
fn retire_machine_tbs_binds_route_root_epoch_and_unsigned_hash() {
    let retirement = retirement();
    let relay_server_id = RelayServerId::from_bytes([0x88; 16]);
    let root_fingerprint = [0xA5; 32];
    let tbs = retirement.to_be_signed_v1(relay_server_id, root_fingerprint);

    assert_eq!(tbs.object_type, SignedObjectType::RetireMachine);
    assert_eq!(tbs.signature_format_version, AUTH_SIGNATURE_FORMAT_VERSION);
    assert_eq!(tbs.relay_protocol_version, RELAY_PROTOCOL_VERSION);
    assert_eq!(tbs.runtime_protocol_version, RUNTIME_PROTOCOL_VERSION);
    assert_eq!(tbs.e2ee_format_version, E2EE_FORMAT_VERSION);
    assert_eq!(tbs.relay_server_id, relay_server_id);
    assert_eq!(tbs.machine_route, retirement.machine_route);
    assert_eq!(tbs.device_route, None);
    assert_eq!(tbs.stream_route, None);
    assert_eq!(tbs.request_route, None);
    assert_eq!(tbs.stream_generation, None);
    assert_eq!(tbs.stream_cursor, None);
    assert_eq!(tbs.role_scope, "relay-machine-retirement");
    assert_eq!(tbs.signing_key_fingerprint, root_fingerprint);
    assert_eq!(tbs.root_key_id, retirement.root_key_id);
    assert_eq!(tbs.trust_epoch, retirement.trust_epoch);
    assert_eq!(
        tbs.serial_or_generation,
        retirement.trust_epoch.value(),
        "retirement has no grant/cert serial, so the monotonic trust epoch occupies the common slot"
    );
    assert_eq!(tbs.not_after_ms, None);
    assert_eq!(
        tbs.signed_object_sha256,
        retirement.unsigned_canonical_sha256()
    );
}
