//! P4.3 pairing canonical / validation contract.

use agentdeck_protocol::e2ee::PairingControlEnvelopeV1;
use agentdeck_protocol::e2ee::keys::{KeyDirectoryEntry, KeyDirectoryV1, KeyId, KeyPurpose};
use agentdeck_protocol::e2ee::pairing::{
    AuthorizationCapabilityV1, AuthorizationPermissionV1, AuthorizationRequestV1,
    DeviceAuthorizationV1, MachineDataSignerBindingV1, PAIR_INVITE_MAX_TTL_MS, PairInviteV1,
    PairPendingV1, PairRequestInfoV1, PairRequestPlaintextV1, PairRequestV1, PairResponseInfoV1,
    PairResponsePlaintextV1, PairResponseReceivedV1, PairResponseV1, PairTerminalOutcomeV1,
    PairTerminalV1, PairingError,
};
use agentdeck_protocol::e2ee::{E2EE_FORMAT_VERSION, OuterContextV1, OuterFrameKind};
use agentdeck_protocol::relay_v2::RELAY_PROTOCOL_VERSION;
use agentdeck_protocol::relay_v2::auth::{
    CertRole, Ed25519Signature, PublicKeyBytes, RelayGrant, SignedCertificate,
};
use agentdeck_protocol::relay_v2::id::{
    DeviceRouteId, GrantSerial, KeyDirectoryRevision, LinkGeneration, MachineRouteId, PairRouteId,
    RelayServerId, RootKeyId, TrustEpoch,
};
use agentdeck_protocol::runtime::RUNTIME_PROTOCOL_VERSION;
use sha2::{Digest, Sha256};

const NOW_MS: u64 = 1_700_000_000_000;

fn sig(byte: u8) -> Ed25519Signature {
    Ed25519Signature([byte; 64])
}

fn machine_route() -> MachineRouteId {
    MachineRouteId::from_bytes([0x11; 16])
}

fn device_route() -> DeviceRouteId {
    DeviceRouteId::from_bytes([0x22; 16])
}

fn pair_route(byte: u8) -> PairRouteId {
    PairRouteId::from_bytes([byte; 16])
}

fn relay_server() -> RelayServerId {
    RelayServerId::from_bytes([0x33; 16])
}

fn root_key_id() -> RootKeyId {
    RootKeyId::from_bytes([0x44; 16])
}

fn authorization_request() -> AuthorizationRequestV1 {
    AuthorizationRequestV1 {
        format_version: E2EE_FORMAT_VERSION,
        device_display_name: "Remote CLI".into(),
        capabilities: vec![
            AuthorizationCapabilityV1::Catalog,
            AuthorizationCapabilityV1::Conversation,
            AuthorizationCapabilityV1::Prompt,
            AuthorizationCapabilityV1::Command,
            AuthorizationCapabilityV1::Approval,
            AuthorizationCapabilityV1::Metadata,
            AuthorizationCapabilityV1::SelfRevocation,
        ],
        permissions: vec![
            AuthorizationPermissionV1::CatalogRead,
            AuthorizationPermissionV1::ConversationRead,
            AuthorizationPermissionV1::ConversationStart,
            AuthorizationPermissionV1::PromptSend,
            AuthorizationPermissionV1::CommandCancel,
            AuthorizationPermissionV1::ApprovalResolve,
            AuthorizationPermissionV1::ApprovalRetry,
            AuthorizationPermissionV1::MetadataWrite,
            AuthorizationPermissionV1::RevokeSelf,
        ],
    }
}

fn invite() -> PairInviteV1 {
    let root = PublicKeyBytes([0x51; 32]);
    PairInviteV1 {
        format_version: E2EE_FORMAT_VERSION,
        relay_protocol_version: RELAY_PROTOCOL_VERSION,
        pair_route: pair_route(0x55),
        invite_secret: [0x61; 32],
        invite_hpke_pubkey: PublicKeyBytes([0x62; 32]),
        wss_url: "wss://relay.example.test/".into(),
        relay_server_id: relay_server(),
        current_spki_pin: [0x63; 32],
        next_spki_pin: [0x64; 32],
        expires_at_ms: NOW_MS + PAIR_INVITE_MAX_TTL_MS,
        machine_root_pubkey: root,
        machine_root_fingerprint: Sha256::digest(root.0).into(),
        data_sign_cert: SignedCertificate {
            subject_pubkey: PublicKeyBytes([0x65; 32]),
            cert_role: CertRole::Data,
            generation: LinkGeneration::new(1),
            root_key_id: root_key_id(),
            trust_epoch: TrustEpoch::new(1),
            not_after_ms: None,
            signature: sig(0x66),
        },
        machine_display_name: "Fixture Mac".into(),
    }
}

fn pair_context(kind: OuterFrameKind) -> OuterContextV1 {
    OuterContextV1 {
        frame_kind: kind,
        relay_protocol_version: RELAY_PROTOCOL_VERSION,
        e2ee_format_version: E2EE_FORMAT_VERSION,
        machine_route: None,
        device_route: None,
        stream_route: None,
        request_route: None,
        pair_route: Some(pair_route(0x55)),
        stream_generation: None,
        stream_cursor: None,
        stream_seq: None,
        message_key_epoch: 0,
    }
}

fn request_info() -> PairRequestInfoV1 {
    PairRequestInfoV1 {
        e2ee_format_version: E2EE_FORMAT_VERSION,
        runtime_protocol_version: RUNTIME_PROTOCOL_VERSION,
        relay_server_id: relay_server(),
        pair_route: pair_route(0x55),
        invite_hash: invite().canonical_sha256().unwrap(),
        expiry_ms: NOW_MS + PAIR_INVITE_MAX_TTL_MS,
    }
}

fn request_plaintext() -> PairRequestPlaintextV1 {
    PairRequestPlaintextV1 {
        format_version: E2EE_FORMAT_VERSION,
        invite_secret: [0x61; 32],
        device_sign_pubkey: PublicKeyBytes([0x71; 32]),
        device_hpke_pubkey: PublicKeyBytes([0x72; 32]),
        authorization_request: authorization_request(),
    }
}

fn request() -> PairRequestV1 {
    PairRequestV1 {
        format_version: E2EE_FORMAT_VERSION,
        enc: vec![0x81; 32],
        ciphertext: vec![0x82; 96],
        device_proof_signature: sig(0x83),
    }
}

fn grant() -> RelayGrant {
    RelayGrant {
        machine_route: machine_route(),
        device_route: device_route(),
        device_sign_pubkey: PublicKeyBytes([0x71; 32]),
        grant_serial: GrantSerial::new(7),
        root_key_id: root_key_id(),
        trust_epoch: TrustEpoch::new(1),
        signature: sig(0x91),
    }
}

fn device_authorization() -> DeviceAuthorizationV1 {
    let grant = grant();
    DeviceAuthorizationV1 {
        format_version: E2EE_FORMAT_VERSION,
        grant_hash: grant.canonical_sha256(),
        machine_route: grant.machine_route,
        device_route: grant.device_route,
        device_sign_fingerprint: Sha256::digest(grant.device_sign_pubkey.0).into(),
        grant_serial: grant.grant_serial,
        device_hpke_pubkey: PublicKeyBytes([0x72; 32]),
        capabilities: authorization_request().capabilities,
        permissions: authorization_request().permissions,
        root_key_id: grant.root_key_id,
        trust_epoch: grant.trust_epoch,
        signature: sig(0x92),
    }
}

fn directory() -> KeyDirectoryV1 {
    KeyDirectoryV1 {
        revision: KeyDirectoryRevision::new(1),
        entries: vec![
            KeyDirectoryEntry {
                key_id: KeyId {
                    purpose: KeyPurpose::Catalog,
                    epoch: 1,
                },
                device_route: device_route(),
                stream_route: None,
                enc: vec![0x93; 32],
                wrapped_key: vec![0x94; 48],
            },
            KeyDirectoryEntry {
                key_id: KeyId {
                    purpose: KeyPurpose::DeviceCommandTx,
                    epoch: 1,
                },
                device_route: device_route(),
                stream_route: None,
                enc: vec![0x96; 32],
                wrapped_key: vec![0x97; 48],
            },
            KeyDirectoryEntry {
                key_id: KeyId {
                    purpose: KeyPurpose::DeviceReplyTx,
                    epoch: 1,
                },
                device_route: device_route(),
                stream_route: None,
                enc: vec![0x98; 32],
                wrapped_key: vec![0x99; 48],
            },
        ],
        signature: sig(0x95),
    }
}

fn response_plaintext() -> PairResponsePlaintextV1 {
    PairResponsePlaintextV1 {
        format_version: E2EE_FORMAT_VERSION,
        request_hash: request().canonical_sha256().unwrap(),
        relay_grant: grant(),
        device_authorization: device_authorization(),
        key_directory: directory(),
    }
}

fn response() -> PairResponseV1 {
    PairResponseV1 {
        format_version: E2EE_FORMAT_VERSION,
        info: response_info(),
        enc: vec![0xa1; 32],
        ciphertext: vec![0xa2; 256],
        machine_data_signature: sig(0xa3),
    }
}

fn pending() -> PairPendingV1 {
    PairPendingV1 {
        request_hash: request().canonical_sha256().unwrap(),
        signature: sig(0xb1),
    }
}

fn pair_terminal(outcome: PairTerminalOutcomeV1) -> PairTerminalV1 {
    PairTerminalV1 {
        machine_route: machine_route(),
        request_hash: request().canonical_sha256().unwrap(),
        outcome,
        signature: sig(0xb3),
    }
}

fn received() -> PairResponseReceivedV1 {
    PairResponseReceivedV1 {
        request_hash: request().canonical_sha256().unwrap(),
        grant_hash: grant().canonical_sha256(),
        response_hash: response().canonical_sha256().unwrap(),
        signature: sig(0xb2),
    }
}

fn response_info() -> PairResponseInfoV1 {
    PairResponseInfoV1 {
        e2ee_format_version: E2EE_FORMAT_VERSION,
        runtime_protocol_version: RUNTIME_PROTOCOL_VERSION,
        relay_server_id: relay_server(),
        pair_route: pair_route(0x55),
        invite_hash: invite().canonical_sha256().unwrap(),
        expiry_ms: NOW_MS + PAIR_INVITE_MAX_TTL_MS,
        request_hash: request().canonical_sha256().unwrap(),
        machine_route: machine_route(),
        device_route: device_route(),
        grant_serial: GrantSerial::new(7),
        root_trust_epoch: TrustEpoch::new(1),
    }
}

#[test]
fn invite_uri_is_canonical_base64url_no_pad_and_round_trips() {
    let invite = invite();
    invite.validate(NOW_MS).unwrap();
    let encoded = invite.encode_uri(NOW_MS).unwrap();
    assert!(encoded.starts_with("agentdeck-pair:v1:"));
    assert!(!encoded.contains('='));
    assert_eq!(PairInviteV1::decode_uri(&encoded, NOW_MS).unwrap(), invite);
    assert_eq!(
        invite.canonical_bytes().unwrap(),
        invite.canonical_bytes().unwrap()
    );
    assert!(
        invite
            .machine_root_fingerprint_display()
            .starts_with("sha256:")
    );
}

#[test]
fn invite_validation_is_fail_closed_on_expiry_url_name_and_noncanonical_text() {
    let valid = invite();
    assert!(
        PairInviteV1::decode_uri(&valid.encode_uri(NOW_MS).unwrap(), valid.expires_at_ms).is_err()
    );

    let mut too_far = valid.clone();
    too_far.expires_at_ms += 1;
    assert!(too_far.validate(NOW_MS).is_err());

    let mut url = valid.clone();
    url.wss_url = "ws://relay.example.test/v2/pair".into();
    assert!(url.validate(NOW_MS).is_err());

    let mut query = valid.clone();
    query.wss_url = "wss://relay.example.test/?pairRoute=secret".into();
    assert!(query.validate_static().is_err());
    assert!(serde_json::from_value::<PairInviteV1>(serde_json::to_value(query).unwrap()).is_err());

    let mut name = valid.clone();
    name.machine_display_name = "\n".into();
    assert!(name.validate(NOW_MS).is_err());

    let encoded = valid.encode_uri(NOW_MS).unwrap();
    assert!(PairInviteV1::decode_uri(&(encoded + "="), NOW_MS).is_err());
}

#[test]
fn authorization_request_is_typed_bounded_and_permission_implies_capability() {
    let auth = authorization_request();
    auth.validate().unwrap();
    let bytes = auth.canonical_bytes().unwrap();
    assert_eq!(
        AuthorizationRequestV1::from_canonical_bytes(&bytes).unwrap(),
        auth
    );

    let unknown = serde_json::json!({
        "formatVersion": E2EE_FORMAT_VERSION,
        "deviceDisplayName": "bad",
        "capabilities": ["machineAdmin"],
        "permissions": ["trustReset"]
    });
    assert!(serde_json::from_value::<AuthorizationRequestV1>(unknown).is_err());

    let mut missing_capability = authorization_request();
    missing_capability
        .capabilities
        .retain(|x| *x != AuthorizationCapabilityV1::Approval);
    assert!(missing_capability.validate().is_err());

    let mut duplicate = authorization_request();
    duplicate
        .permissions
        .push(AuthorizationPermissionV1::CatalogRead);
    assert!(duplicate.validate().is_err());
}

#[test]
fn request_plaintext_has_no_proof_and_envelope_exposes_no_plaintext() {
    let plaintext = request_plaintext();
    let json = serde_json::to_value(&plaintext).unwrap();
    assert!(json.get("deviceProofSignature").is_none());
    let bytes = plaintext.canonical_bytes().unwrap();
    assert_eq!(
        PairRequestPlaintextV1::from_canonical_bytes(&bytes).unwrap(),
        plaintext
    );

    let envelope = request();
    let json = serde_json::to_value(&envelope).unwrap();
    assert!(json.get("inviteSecret").is_none());
    assert!(json.get("deviceSignPubkey").is_none());
    assert!(json.get("deviceHpkePubkey").is_none());
    assert!(json.get("authorizationRequest").is_none());
    assert!(json.get("enc").is_some());
    assert!(json.get("ciphertext").is_some());
    assert!(json.get("deviceProofSignature").is_some());
    let bytes = envelope.canonical_bytes().unwrap();
    assert_eq!(
        PairRequestV1::from_canonical_bytes(&bytes).unwrap(),
        envelope
    );
}

#[test]
fn request_hash_includes_signature_but_proof_tbs_does_not_create_a_cycle() {
    let request = request();
    let signer = request_plaintext().device_sign_fingerprint();
    let tbs = request
        .proof_tbs(
            &request_info(),
            &pair_context(OuterFrameKind::PairRequest),
            signer,
        )
        .unwrap();

    let mut signature_only = request.clone();
    signature_only.device_proof_signature.0[0] ^= 1;
    assert_eq!(
        tbs.encode().unwrap(),
        signature_only
            .proof_tbs(
                &request_info(),
                &pair_context(OuterFrameKind::PairRequest),
                signer,
            )
            .unwrap()
            .encode()
            .unwrap(),
        "detached proof preimage must exclude its own signature"
    );
    assert_ne!(
        request.canonical_sha256().unwrap(),
        signature_only.canonical_sha256().unwrap(),
        "requestHash must cover the complete envelope including detached proof"
    );

    let mut ciphertext = request.clone();
    ciphertext.ciphertext[0] ^= 1;
    assert_ne!(
        tbs.encode().unwrap(),
        ciphertext
            .proof_tbs(
                &request_info(),
                &pair_context(OuterFrameKind::PairRequest),
                signer,
            )
            .unwrap()
            .encode()
            .unwrap()
    );
    let mut info = request_info();
    info.invite_hash[0] ^= 1;
    assert_ne!(
        tbs.encode().unwrap(),
        request
            .proof_tbs(&info, &pair_context(OuterFrameKind::PairRequest), signer)
            .unwrap()
            .encode()
            .unwrap()
    );
}

#[test]
fn device_authorization_binds_complete_grant_and_device_identity() {
    let grant = grant();
    let authorization = device_authorization();
    authorization.validate_for_grant(&grant).unwrap();
    let bytes = authorization.canonical_bytes().unwrap();
    assert_eq!(
        DeviceAuthorizationV1::from_canonical_bytes(&bytes).unwrap(),
        authorization
    );

    let mut bad_hash = authorization.clone();
    bad_hash.grant_hash[0] ^= 1;
    assert!(bad_hash.validate_for_grant(&grant).is_err());
    let mut bad_route = authorization.clone();
    bad_route.device_route = DeviceRouteId::from_bytes([0xff; 16]);
    assert!(bad_route.validate_for_grant(&grant).is_err());
    let mut bad_fingerprint = authorization;
    bad_fingerprint.device_sign_fingerprint[0] ^= 1;
    assert!(bad_fingerprint.validate_for_grant(&grant).is_err());
}

#[test]
fn response_plaintext_and_detached_envelope_are_canonical_and_fully_hashed() {
    let plaintext = response_plaintext();
    plaintext.validate().unwrap();
    let plaintext_bytes = plaintext.canonical_bytes().unwrap();
    assert_eq!(
        PairResponsePlaintextV1::from_canonical_bytes(&plaintext_bytes).unwrap(),
        plaintext
    );

    let response = response();
    let response_bytes = response.canonical_bytes().unwrap();
    assert_eq!(
        PairResponseV1::from_canonical_bytes(&response_bytes).unwrap(),
        response
    );
    let signer = MachineDataSignerBindingV1::from_certificate(&invite().data_sign_cert).unwrap();
    let tbs = response
        .signature_tbs(
            &response_info(),
            &pair_context(OuterFrameKind::PairResponse),
            &signer,
        )
        .unwrap();

    let mut signature_only = response.clone();
    signature_only.machine_data_signature.0[0] ^= 1;
    assert_eq!(
        tbs.encode().unwrap(),
        signature_only
            .signature_tbs(
                &response_info(),
                &pair_context(OuterFrameKind::PairResponse),
                &signer,
            )
            .unwrap()
            .encode()
            .unwrap()
    );
    assert_ne!(
        response.canonical_sha256().unwrap(),
        signature_only.canonical_sha256().unwrap(),
        "responseHash must cover the complete envelope including MachineDataSign"
    );

    let mut tampered_info = response.clone();
    tampered_info.info.request_hash[0] ^= 1;
    assert_ne!(
        response.canonical_sha256().unwrap(),
        tampered_info.canonical_sha256().unwrap(),
        "responseHash must cover the clear embedded info"
    );
    assert_eq!(
        tampered_info
            .signature_tbs(
                &response_info(),
                &pair_context(OuterFrameKind::PairResponse),
                &signer,
            )
            .unwrap_err(),
        PairingError::ContextBindingMismatch,
        "caller info must exactly match the envelope's embedded info"
    );
}

#[test]
fn response_info_is_required_and_strictly_canonical() {
    let info = response_info();
    let encoded = info.encode();
    assert_eq!(
        PairResponseInfoV1::from_canonical_bytes(&encoded).unwrap(),
        info
    );

    let mut noncanonical = encoded;
    noncanonical.push(0);
    assert!(PairResponseInfoV1::from_canonical_bytes(&noncanonical).is_err());

    let mut json = serde_json::to_value(response()).unwrap();
    json.as_object_mut().unwrap().remove("info");
    assert!(serde_json::from_value::<PairResponseV1>(json).is_err());
}

#[test]
fn pair_pending_tbs_binds_request_invite_route_and_machine_data_signer() {
    let pending = pending();
    let signer = MachineDataSignerBindingV1::from_certificate(&invite().data_sign_cert).unwrap();
    let context = pair_context(OuterFrameKind::PairPending);
    let base = pending
        .signature_tbs(&request_info(), &context, &signer)
        .unwrap()
        .encode()
        .unwrap();

    let mut request = pending.clone();
    request.request_hash[0] ^= 1;
    assert_ne!(
        base,
        request
            .signature_tbs(&request_info(), &context, &signer)
            .unwrap()
            .encode()
            .unwrap()
    );
    let mut info = request_info();
    info.invite_hash[0] ^= 1;
    assert_ne!(
        base,
        pending
            .signature_tbs(&info, &context, &signer)
            .unwrap()
            .encode()
            .unwrap()
    );
    let mut signer_generation = signer;
    signer_generation.generation = LinkGeneration::new(2);
    assert_ne!(
        base,
        pending
            .signature_tbs(&request_info(), &context, &signer_generation)
            .unwrap()
            .encode()
            .unwrap()
    );
}

#[test]
fn pair_terminal_has_independent_unsigned_full_and_tbs_domains() {
    let terminal = pair_terminal(PairTerminalOutcomeV1::Canceled);
    let unsigned = terminal.unsigned_canonical_bytes().unwrap();
    let canonical = terminal.canonical_bytes().unwrap();
    assert!(unsigned.starts_with(b"AgentDeck/PairTerminalUnsignedV1\0"));
    assert!(canonical.starts_with(b"AgentDeck/PairTerminalV1\0"));
    assert_eq!(
        unsigned.last(),
        Some(&0),
        "canceled outcome tag is frozen at 0"
    );
    assert_eq!(
        PairTerminalV1::from_canonical_bytes(&canonical).unwrap(),
        terminal
    );

    let signer = MachineDataSignerBindingV1::from_certificate(&invite().data_sign_cert).unwrap();
    let tbs = terminal
        .signature_tbs(
            &request_info(),
            &pair_context(OuterFrameKind::PairTerminal),
            &signer,
        )
        .unwrap()
        .encode()
        .unwrap();
    assert!(tbs.starts_with(b"AgentDeck/PairTerminalTbsV1\0"));

    let expired = pair_terminal(PairTerminalOutcomeV1::Expired);
    assert_eq!(
        expired.unsigned_canonical_bytes().unwrap().last(),
        Some(&1),
        "expired outcome tag is frozen at 1"
    );
    assert_ne!(
        terminal.canonical_sha256().unwrap(),
        expired.canonical_sha256().unwrap()
    );

    let mut signature_only = terminal.clone();
    signature_only.signature.0[0] ^= 1;
    assert_eq!(
        tbs,
        signature_only
            .signature_tbs(
                &request_info(),
                &pair_context(OuterFrameKind::PairTerminal),
                &signer,
            )
            .unwrap()
            .encode()
            .unwrap(),
        "TBS must exclude its own signature"
    );
    assert_ne!(
        terminal.canonical_sha256().unwrap(),
        signature_only.canonical_sha256().unwrap(),
        "full canonical hash must include the signature"
    );
}

#[test]
fn pair_terminal_tbs_binds_all_identity_trust_info_and_exact_aad_axes() {
    let terminal = pair_terminal(PairTerminalOutcomeV1::Canceled);
    let info = request_info();
    let context = pair_context(OuterFrameKind::PairTerminal);
    let signer = MachineDataSignerBindingV1::from_certificate(&invite().data_sign_cert).unwrap();
    let base = terminal
        .signature_tbs(&info, &context, &signer)
        .unwrap()
        .encode()
        .unwrap();

    let mut machine = terminal.clone();
    machine.machine_route = MachineRouteId::from_bytes([0x12; 16]);
    assert_ne!(
        base,
        machine
            .signature_tbs(&info, &context, &signer)
            .unwrap()
            .encode()
            .unwrap()
    );
    let mut request = terminal.clone();
    request.request_hash[0] ^= 1;
    assert_ne!(
        base,
        request
            .signature_tbs(&info, &context, &signer)
            .unwrap()
            .encode()
            .unwrap()
    );
    assert_ne!(
        base,
        pair_terminal(PairTerminalOutcomeV1::Expired)
            .signature_tbs(&info, &context, &signer)
            .unwrap()
            .encode()
            .unwrap()
    );

    let mut changed_info = info.clone();
    changed_info.expiry_ms += 1;
    assert_ne!(
        base,
        terminal
            .signature_tbs(&changed_info, &context, &signer)
            .unwrap()
            .encode()
            .unwrap()
    );
    let mut changed_context = context.clone();
    changed_context.e2ee_format_version += 1;
    assert_eq!(
        terminal
            .signature_tbs(&info, &changed_context, &signer)
            .unwrap_err(),
        PairingError::ContextBindingMismatch
    );
    let mut wrong_route_context = context.clone();
    wrong_route_context.pair_route = Some(pair_route(0x56));
    assert_eq!(
        terminal
            .signature_tbs(&info, &wrong_route_context, &signer)
            .unwrap_err(),
        PairingError::ContextBindingMismatch
    );
    assert_eq!(
        terminal
            .signature_tbs(&info, &pair_context(OuterFrameKind::PairPending), &signer,)
            .unwrap_err(),
        PairingError::ContextBindingMismatch
    );

    let mut generation = signer.clone();
    generation.generation = LinkGeneration::new(2);
    assert_ne!(
        base,
        terminal
            .signature_tbs(&info, &context, &generation)
            .unwrap()
            .encode()
            .unwrap()
    );
    let mut certificate = signer.clone();
    certificate.certificate_sha256[0] ^= 1;
    assert_ne!(
        base,
        terminal
            .signature_tbs(&info, &context, &certificate)
            .unwrap()
            .encode()
            .unwrap()
    );
    let mut fingerprint = signer;
    fingerprint.signing_key_fingerprint[0] ^= 1;
    assert_ne!(
        base,
        terminal
            .signature_tbs(&info, &context, &fingerprint)
            .unwrap()
            .encode()
            .unwrap()
    );
}

#[test]
fn pair_terminal_ingress_rejects_unknown_zero_oversize_and_noncanonical_values() {
    let terminal = pair_terminal(PairTerminalOutcomeV1::Canceled);
    let mut json = serde_json::to_value(&terminal).unwrap();
    json.as_object_mut()
        .unwrap()
        .insert("unknown".into(), serde_json::json!(true));
    assert!(serde_json::from_value::<PairTerminalV1>(json).is_err());

    let mut unknown_outcome = serde_json::to_value(&terminal).unwrap();
    unknown_outcome["outcome"] = serde_json::json!("revoked");
    assert!(serde_json::from_value::<PairTerminalV1>(unknown_outcome).is_err());

    for invalid in [
        PairTerminalV1 {
            machine_route: MachineRouteId::from_bytes([0; 16]),
            ..terminal.clone()
        },
        PairTerminalV1 {
            request_hash: [0; 32],
            ..terminal.clone()
        },
        PairTerminalV1 {
            signature: Ed25519Signature([0; 64]),
            ..terminal.clone()
        },
    ] {
        assert!(
            serde_json::from_value::<PairTerminalV1>(serde_json::to_value(invalid).unwrap())
                .is_err()
        );
    }

    let mut trailing = terminal.canonical_bytes().unwrap();
    trailing.push(0);
    assert!(PairTerminalV1::from_canonical_bytes(&trailing).is_err());
    assert!(PairTerminalV1::from_canonical_bytes(&vec![0; 513]).is_err());

    let unsigned = terminal.unsigned_canonical_bytes().unwrap();
    let mut unknown_tag = terminal.canonical_bytes().unwrap();
    let outcome_offset = b"AgentDeck/PairTerminalV1\0".len() + 4 + unsigned.len() - 1;
    unknown_tag[outcome_offset] = 2;
    assert!(PairTerminalV1::from_canonical_bytes(&unknown_tag).is_err());
}

#[test]
fn pairing_control_envelope_hides_pending_request_hash_from_relay_visible_shape() {
    let envelope = PairingControlEnvelopeV1 {
        format_version: E2EE_FORMAT_VERSION,
        enc: vec![0xc1; 32],
        ciphertext: vec![0xc2; 80],
    };
    let json = serde_json::to_value(&envelope).unwrap();
    assert_eq!(json.as_object().unwrap().len(), 3);
    assert!(json.get("enc").is_some());
    assert!(json.get("ciphertext").is_some());
    assert!(json.get("requestHash").is_none());
    let bytes = envelope.canonical_bytes().unwrap();
    assert_eq!(
        PairingControlEnvelopeV1::from_canonical_bytes(&bytes).unwrap(),
        envelope
    );
}

#[test]
fn pending_and_received_json_ingress_reject_zero_sensitive_material() {
    let pending_json = serde_json::to_value(PairPendingV1 {
        request_hash: [0; 32],
        signature: sig(0xd1),
    })
    .unwrap();
    assert!(serde_json::from_value::<PairPendingV1>(pending_json).is_err());

    let received_json = serde_json::to_value(PairResponseReceivedV1 {
        request_hash: [0xd2; 32],
        grant_hash: [0xd3; 32],
        response_hash: [0xd4; 32],
        signature: Ed25519Signature([0; 64]),
    })
    .unwrap();
    assert!(serde_json::from_value::<PairResponseReceivedV1>(received_json).is_err());
}

#[test]
fn bootstrap_key_directory_requires_strict_canonical_entry_order() {
    let mut plaintext = response_plaintext();
    plaintext.validate().unwrap();
    plaintext.key_directory.entries.reverse();
    assert!(plaintext.validate().is_err());
}

#[test]
fn pair_response_received_tbs_binds_all_frozen_hashes_routes_and_device_signer() {
    let receipt = received();
    let context = pair_context(OuterFrameKind::PairResponseReceived);
    let device_sign_fingerprint = request_plaintext().device_sign_fingerprint();
    let base = receipt
        .receipt_tbs(&response_info(), &context, device_sign_fingerprint)
        .unwrap()
        .encode()
        .unwrap();

    let mut tampered = receipt.clone();
    tampered.grant_hash[0] ^= 1;
    assert_ne!(
        base,
        tampered
            .receipt_tbs(&response_info(), &context, device_sign_fingerprint)
            .unwrap()
            .encode()
            .unwrap()
    );
    let mut info = response_info();
    info.device_route = DeviceRouteId::from_bytes([0xee; 16]);
    assert_ne!(
        base,
        receipt
            .receipt_tbs(&info, &context, device_sign_fingerprint)
            .unwrap()
            .encode()
            .unwrap()
    );
    let mut wrong_request = receipt;
    wrong_request.request_hash[0] ^= 1;
    assert!(
        wrong_request
            .receipt_tbs(&response_info(), &context, device_sign_fingerprint)
            .is_err()
    );
}

#[test]
fn outer_context_pair_route_is_bound_without_drifting_non_pairing_bytes() {
    let request = pair_context(OuterFrameKind::PairRequest);
    let mut other_route = request.clone();
    other_route.pair_route = Some(pair_route(0x56));
    assert_ne!(request.encode_aad(), other_route.encode_aad());

    let mut missing = request;
    missing.pair_route = None;
    assert!(missing.validate().is_err());

    let tag_offset = b"AgentDeck/OuterContextV1\0".len();
    for (kind, expected_tag) in [
        (OuterFrameKind::CatalogPublish, 0),
        (OuterFrameKind::ConversationPublish, 1),
        (OuterFrameKind::DirectedReply, 2),
        (OuterFrameKind::UplinkSend, 3),
        (OuterFrameKind::PairRequest, 4),
        (OuterFrameKind::PairResponse, 5),
        (OuterFrameKind::KeyUpdate, 6),
        (OuterFrameKind::PairPending, 7),
        (OuterFrameKind::PairResponseReceived, 8),
        (OuterFrameKind::DeviceKeyRecovery, 9),
        (OuterFrameKind::PairTerminal, 10),
    ] {
        let mut value = pair_context(kind);
        if !matches!(
            kind,
            OuterFrameKind::PairRequest
                | OuterFrameKind::PairResponse
                | OuterFrameKind::PairPending
                | OuterFrameKind::PairResponseReceived
                | OuterFrameKind::PairTerminal
        ) {
            value.pair_route = None;
        }
        assert_eq!(value.encode_aad()[tag_offset], expected_tag);
    }
}

#[test]
fn pairing_debug_is_redacted() {
    let rendered = format!(
        "{:?} {:?} {:?} {:?} {:?} {:?}",
        invite(),
        request_plaintext(),
        request(),
        device_authorization(),
        response_plaintext(),
        response()
    );
    assert!(rendered.contains("<redacted>"));
    for secret in [
        "relay.example",
        "Fixture Mac",
        "Remote CLI",
        "616161",
        "828282",
    ] {
        assert!(
            !rendered.contains(secret),
            "Debug leaked `{secret}`: {rendered}"
        );
    }
}
