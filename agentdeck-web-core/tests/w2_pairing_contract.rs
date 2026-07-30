#![cfg(feature = "w2-test-fixture")]

use agentdeck_crypto::{SigningKey, sha256, sign_tbs};
use agentdeck_protocol::e2ee::{E2EE_FORMAT_VERSION, PairInviteV1};
use agentdeck_protocol::relay_v2::auth::{CertRole, Ed25519Signature, PublicKeyBytes};
use agentdeck_protocol::relay_v2::{
    LinkGeneration, PairRouteId, RELAY_PROTOCOL_VERSION, RelayFrameBody, RelayServerId, RootKeyId,
    SignedCertificate, TrustEpoch, decode,
};
use agentdeck_web_core::W2PairingCore;
use base64::{Engine as _, engine::general_purpose::URL_SAFE_NO_PAD};

const NOW_MS: u64 = 1_000_000;

fn invite() -> PairInviteV1 {
    let root = SigningKey::from_seed(&[0x31; 32]);
    let data = SigningKey::from_seed(&[0x32; 32]);
    let relay_server_id = RelayServerId::from_bytes([0x33; 16]);
    let machine_root_fingerprint = sha256(&root.verifying_key().to_bytes());
    let mut data_sign_cert = SignedCertificate {
        subject_pubkey: PublicKeyBytes(data.verifying_key().to_bytes()),
        cert_role: CertRole::Data,
        generation: LinkGeneration::new(1),
        root_key_id: RootKeyId::from_bytes([0x34; 16]),
        trust_epoch: TrustEpoch::new(1),
        not_after_ms: None,
        signature: Ed25519Signature([0; 64]),
    };
    data_sign_cert.signature = sign_tbs(
        &root,
        &data_sign_cert.to_be_signed_v1(
            relay_server_id,
            agentdeck_protocol::relay_v2::MachineRouteId::from_bytes([0x35; 16]),
            machine_root_fingerprint,
        ),
    )
    .into();
    PairInviteV1 {
        format_version: E2EE_FORMAT_VERSION,
        relay_protocol_version: RELAY_PROTOCOL_VERSION,
        pair_route: PairRouteId::from_bytes([0x36; 16]),
        invite_secret: [0x37; 32],
        invite_hpke_pubkey: PublicKeyBytes([0x38; 32]),
        wss_url: "wss://localhost:9443/".to_owned(),
        relay_server_id,
        current_spki_pin: [0x39; 32],
        next_spki_pin: [0x3a; 32],
        expires_at_ms: NOW_MS + 60_000,
        machine_root_pubkey: PublicKeyBytes(root.verifying_key().to_bytes()),
        machine_root_fingerprint,
        data_sign_cert,
        machine_display_name: "W2 fixture machine".to_owned(),
    }
}

#[test]
fn inspect_is_local_and_exact_confirmation_unlocks_only_pair_endpoint() {
    let invite = invite();
    let encoded = invite.encode_uri(NOW_MS).expect("canonical invite");
    let mut core = W2PairingCore::inspect(&encoded, NOW_MS).expect("local inspect");
    let preview = core.preview();
    assert_eq!(preview.machine_display_name, "W2 fixture machine");
    assert_eq!(
        preview.machine_root_fingerprint,
        invite.machine_root_fingerprint_display()
    );
    assert!(
        core.connect_url().is_err(),
        "inspect must not unlock network"
    );
    assert!(
        core.confirm("sha256:00", NOW_MS, [0x41; 32], [0x42; 32], [0x43; 32],)
            .is_err()
    );
    assert!(core.connect_url().is_err());

    core.confirm(
        &invite.machine_root_fingerprint_display(),
        NOW_MS,
        [0x41; 32],
        [0x42; 32],
        [0x43; 32],
    )
    .expect("exact confirmation");
    assert_eq!(core.connect_url().unwrap(), "wss://localhost:9443/v2/pair");

    let hello = decode(&core.start_hello().expect("single hello")).unwrap();
    assert!(matches!(hello.body, RelayFrameBody::Hello(_)));
    let pairing = decode(&core.start_pairing_hello().expect("pairing hello")).unwrap();
    assert!(matches!(pairing.body, RelayFrameBody::PairingHello(_)));
}

#[test]
fn invite_trust_anchor_tamper_and_handshake_replay_fail_closed() {
    let invite = invite();
    let mut canonical = invite.canonical_bytes().unwrap();
    let fingerprint_offset = canonical
        .windows(invite.machine_root_fingerprint.len())
        .position(|window| window == invite.machine_root_fingerprint)
        .expect("canonical invite contains root fingerprint");
    canonical[fingerprint_offset] ^= 0x01;
    let encoded = format!("agentdeck-pair:v1:{}", URL_SAFE_NO_PAD.encode(canonical));
    assert!(W2PairingCore::inspect(&encoded, NOW_MS).is_err());

    let encoded = invite.encode_uri(NOW_MS).unwrap();
    let mut core = W2PairingCore::inspect(&encoded, NOW_MS).unwrap();
    core.confirm(
        &invite.machine_root_fingerprint_display(),
        NOW_MS,
        [0x51; 32],
        [0x52; 32],
        [0x53; 32],
    )
    .unwrap();
    core.start_hello().unwrap();
    assert!(core.start_hello().is_err());
}
