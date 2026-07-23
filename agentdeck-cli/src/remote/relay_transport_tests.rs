use std::collections::VecDeque;
use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
use std::sync::{Arc, Mutex};

use agentdeck_crypto::{SignatureBytes, SigningKey, verify_authentication_transcript};
use agentdeck_protocol::relay_v2::auth::{
    AuthenticationRole, AuthenticationTranscriptV1, DeviceRevocation, Ed25519Signature,
    PublicKeyBytes, RelayGrant,
};
use agentdeck_protocol::relay_v2::frame::{
    AuthProof, Challenge, Hello, RetirementCommitted, RevocationCommitted,
};
use agentdeck_protocol::relay_v2::id::{
    ConnectionInstanceId, DeviceRouteId, GrantSerial, MachineRouteId, RelayServerId, RootKeyId,
    TrustEpoch,
};
use agentdeck_protocol::relay_v2::{
    OpaqueRouteFrame, RELAY_PROTOCOL_VERSION, RelayFrameBody, encode,
};
use agentdeck_relay_client::RelayClientError;
use async_trait::async_trait;

use super::paired_machine::{
    PairedPromotionError, device_authenticator_for_test, paired_spki_pins,
};
use super::relay_transport::{
    PairedRuntimeConnectError, PairedRuntimeHandle, RelayRuntimeConnectCompletion, RelayRuntimeIo,
    RelayRuntimeTransport, complete_paired_runtime_connect,
};
use super::runtime::{
    ExactRelayFrame, ReceivedRuntimeFrame, RemoteRuntimeTransport, RemoteRuntimeTransportError,
};

const MACHINE: MachineRouteId = MachineRouteId::from_bytes([0x11; 16]);
const DEVICE: DeviceRouteId = DeviceRouteId::from_bytes([0x22; 16]);
const RELAY: RelayServerId = RelayServerId::from_bytes([0x33; 16]);

fn device_grant(signing: &SigningKey) -> RelayGrant {
    RelayGrant {
        machine_route: MACHINE,
        device_route: DEVICE,
        device_sign_pubkey: PublicKeyBytes(signing.verifying_key().to_bytes()),
        grant_serial: GrantSerial::new(17),
        root_key_id: RootKeyId::from_bytes([0x44; 16]),
        trust_epoch: TrustEpoch::new(9),
        signature: Ed25519Signature([0x55; 64]),
    }
}

#[tokio::test]
async fn paired_device_authenticator_signs_the_complete_device_transcript() {
    let signing = SigningKey::from_seed(&[0x61; 32]);
    let verifying = signing.verifying_key();
    let grant = device_grant(&signing);
    let authenticator = device_authenticator_for_test(signing, grant.clone());
    let challenge = Challenge {
        relay_server_id: RELAY,
        connection_instance: ConnectionInstanceId::from_bytes([0x66; 16]),
        challenge_nonce: [0x77; 32],
    };

    assert_eq!(
        authenticator.proof(),
        AuthProof::Device {
            relay_grant: grant.clone(),
        }
    );
    let authenticated = authenticator
        .authenticate(&challenge)
        .await
        .expect("audited DeviceSign capability signs a fresh challenge");
    assert_eq!(authenticated.proof, authenticator.proof());

    let expected = AuthenticationTranscriptV1 {
        role: AuthenticationRole::Device,
        challenge_nonce: challenge.challenge_nonce,
        connection_instance: challenge.connection_instance,
        relay_server_id: challenge.relay_server_id,
        relay_protocol_version: RELAY_PROTOCOL_VERSION,
        machine_route: grant.machine_route,
        device_route: Some(grant.device_route),
        serial_or_generation: grant.grant_serial.value(),
        credential_sha256: grant.canonical_sha256(),
    };
    let signature = SignatureBytes(authenticated.signature.0);
    verify_authentication_transcript(&verifying, &expected, &signature)
        .expect("signature must bind the exact full-grant transcript");

    let mut mutations = Vec::new();
    mutations.push(AuthenticationTranscriptV1 {
        role: AuthenticationRole::MachineLink,
        ..expected.clone()
    });
    mutations.push(AuthenticationTranscriptV1 {
        challenge_nonce: [0x78; 32],
        ..expected.clone()
    });
    mutations.push(AuthenticationTranscriptV1 {
        connection_instance: ConnectionInstanceId::from_bytes([0x67; 16]),
        ..expected.clone()
    });
    mutations.push(AuthenticationTranscriptV1 {
        relay_server_id: RelayServerId::from_bytes([0x34; 16]),
        ..expected.clone()
    });
    mutations.push(AuthenticationTranscriptV1 {
        relay_protocol_version: RELAY_PROTOCOL_VERSION + 1,
        ..expected.clone()
    });
    mutations.push(AuthenticationTranscriptV1 {
        machine_route: MachineRouteId::from_bytes([0x12; 16]),
        ..expected.clone()
    });
    mutations.push(AuthenticationTranscriptV1 {
        device_route: Some(DeviceRouteId::from_bytes([0x23; 16])),
        ..expected.clone()
    });
    mutations.push(AuthenticationTranscriptV1 {
        serial_or_generation: expected.serial_or_generation + 1,
        ..expected.clone()
    });
    mutations.push(AuthenticationTranscriptV1 {
        credential_sha256: grant.unsigned_canonical_sha256(),
        ..expected
    });
    for changed in mutations {
        assert!(
            verify_authentication_transcript(&verifying, &changed, &signature).is_err(),
            "every Device transcript coordinate, including the full grant hash, is signed"
        );
    }
}

#[test]
fn paired_tls_pins_preserve_rotation_order_and_remove_only_an_exact_duplicate() {
    let current = [0x81; 32];
    let next = [0x82; 32];
    assert_eq!(paired_spki_pins(current, next), vec![current, next]);
    assert_eq!(paired_spki_pins(current, current), vec![current]);
}

#[derive(Default)]
struct IoState {
    sent: Vec<Vec<u8>>,
    shutdowns: usize,
}

struct FakeRelayIo {
    state: Arc<Mutex<IoState>>,
    inbound: VecDeque<Result<Option<ReceivedRuntimeFrame>, RelayClientError>>,
}

#[async_trait]
impl RelayRuntimeIo for FakeRelayIo {
    async fn send_encoded(&mut self, bytes: Vec<u8>) -> Result<(), RelayClientError> {
        self.state
            .lock()
            .expect("fake relay state")
            .sent
            .push(bytes);
        Ok(())
    }

    async fn recv_exact(&mut self) -> Result<Option<ReceivedRuntimeFrame>, RelayClientError> {
        self.inbound.pop_front().unwrap_or(Ok(None))
    }

    async fn shutdown(&mut self) {
        self.state.lock().expect("fake relay state").shutdowns += 1;
    }
}

fn hello() -> OpaqueRouteFrame {
    OpaqueRouteFrame {
        version: RELAY_PROTOCOL_VERSION,
        body: RelayFrameBody::Hello(Hello {
            protocol_version: RELAY_PROTOCOL_VERSION,
        }),
    }
}

#[tokio::test]
async fn relay_runtime_adapter_forwards_exact_bytes_frame_and_shutdown() {
    let state = Arc::new(Mutex::new(IoState::default()));
    let inbound = hello();
    let inbound_bytes = encode(&inbound);
    let io = FakeRelayIo {
        state: Arc::clone(&state),
        inbound: VecDeque::from([Ok(Some(ReceivedRuntimeFrame::from_untrusted_parts(
            inbound.clone(),
            inbound_bytes.clone(),
        )))]),
    };
    let mut transport = RelayRuntimeTransport::from_test_connector(io);
    let frozen = encode(&hello());

    RemoteRuntimeTransport::send(
        &mut transport,
        ExactRelayFrame::from_frozen_for_test(frozen.clone()).expect("valid Relay frame"),
    )
    .await
    .expect("exact send");
    assert_eq!(
        RemoteRuntimeTransport::recv(&mut transport)
            .await
            .expect("receive"),
        Some(ReceivedRuntimeFrame::from_untrusted_parts(
            inbound,
            inbound_bytes
        ))
    );
    RemoteRuntimeTransport::shutdown(&mut transport).await;

    let state = state.lock().expect("fake relay state");
    assert_eq!(state.sent, vec![frozen]);
    assert_eq!(state.shutdowns, 1);
}

#[tokio::test]
async fn relay_runtime_adapter_preserves_typed_authentication_terminal() {
    let terminal_frame = hello();
    let terminal_bytes = encode(&terminal_frame);
    let terminal = RelayClientError::AuthenticationTerminal {
        frame: Box::new(terminal_frame),
        canonical_bytes: Arc::from(terminal_bytes.clone()),
    };
    let io = FakeRelayIo {
        state: Arc::new(Mutex::new(IoState::default())),
        inbound: VecDeque::from([Err(terminal)]),
    };
    let mut transport = RelayRuntimeTransport::from_test_connector(io);

    let error = RemoteRuntimeTransport::recv(&mut transport)
        .await
        .expect_err("signed authentication terminal is not a generic string failure");
    let RemoteRuntimeTransportError::Relay(relay) = error else {
        panic!("RelayClientError must remain typed");
    };
    assert_eq!(
        relay.authentication_terminal_bytes(),
        Some(terminal_bytes.as_slice())
    );
}

#[derive(Default)]
struct ConnectState {
    verifies: AtomicUsize,
    cleanups: AtomicUsize,
    connected: AtomicUsize,
}

struct FakePairedRuntimeHandle {
    state: Arc<ConnectState>,
    connector_dropped: Arc<AtomicBool>,
    expected_frame: OpaqueRouteFrame,
    expected_bytes: Vec<u8>,
}

struct FakeVerifiedRevocation;

impl PairedRuntimeHandle for FakePairedRuntimeHandle {
    type Connected = Arc<ConnectState>;
    type VerifiedRevocation = FakeVerifiedRevocation;

    fn verify_revocation_terminal(
        &self,
        frame: &OpaqueRouteFrame,
        canonical_bytes: &[u8],
    ) -> Result<Self::VerifiedRevocation, PairedPromotionError> {
        self.state.verifies.fetch_add(1, Ordering::SeqCst);
        if frame != &self.expected_frame || canonical_bytes != self.expected_bytes {
            return Err(PairedPromotionError::Conflict);
        }
        Ok(FakeVerifiedRevocation)
    }

    fn into_connected(self, transport: RelayRuntimeTransport) -> Self::Connected {
        self.state.connected.fetch_add(1, Ordering::SeqCst);
        drop(transport);
        self.state
    }

    fn commit_revocation_cleanup(
        self,
        _verified: Self::VerifiedRevocation,
    ) -> Result<(), PairedPromotionError> {
        assert!(
            self.connector_dropped.load(Ordering::SeqCst),
            "connector/socket must be gone before cleanup can make its journal durable"
        );
        self.state.cleanups.fetch_add(1, Ordering::SeqCst);
        Ok(())
    }
}

struct ConnectorDropGuard(Arc<AtomicBool>);

impl Drop for ConnectorDropGuard {
    fn drop(&mut self) {
        self.0.store(true, Ordering::SeqCst);
    }
}

fn connect_fixture(
    expected_frame: OpaqueRouteFrame,
) -> (FakePairedRuntimeHandle, Arc<ConnectState>, Arc<AtomicBool>) {
    let state = Arc::new(ConnectState::default());
    let connector_dropped = Arc::new(AtomicBool::new(false));
    let expected_bytes = encode(&expected_frame);
    (
        FakePairedRuntimeHandle {
            state: Arc::clone(&state),
            connector_dropped: Arc::clone(&connector_dropped),
            expected_frame,
            expected_bytes,
        },
        state,
        connector_dropped,
    )
}

async fn authentication_terminal_after_connector_drop(
    connector_dropped: Arc<AtomicBool>,
    frame: OpaqueRouteFrame,
    canonical_bytes: Vec<u8>,
) -> Result<RelayRuntimeTransport, RelayClientError> {
    let _socket = ConnectorDropGuard(connector_dropped);
    Err(RelayClientError::AuthenticationTerminal {
        frame: Box::new(frame),
        canonical_bytes: Arc::from(canonical_bytes),
    })
}

fn revocation_terminal() -> OpaqueRouteFrame {
    let signed_revocation = DeviceRevocation {
        machine_route: MACHINE,
        device_route: DEVICE,
        grant_serial: GrantSerial::new(17),
        root_key_id: RootKeyId::from_bytes([0x44; 16]),
        trust_epoch: TrustEpoch::new(9),
        signature: Ed25519Signature([0x55; 64]),
    };
    OpaqueRouteFrame {
        version: RELAY_PROTOCOL_VERSION,
        body: RelayFrameBody::RevocationCommitted(RevocationCommitted {
            device_route: DEVICE,
            grant_serial: GrantSerial::new(17),
            signed_revocation,
        }),
    }
}

#[tokio::test]
async fn paired_runtime_connect_returns_a_typed_connected_outcome() {
    let expected = revocation_terminal();
    let (machine, state, _) = connect_fixture(expected);
    let transport = RelayRuntimeTransport::from_test_connector(FakeRelayIo {
        state: Arc::new(Mutex::new(IoState::default())),
        inbound: VecDeque::new(),
    });

    let outcome = complete_paired_runtime_connect(machine, async { Ok(transport) })
        .await
        .expect("ordinary authenticated connection");

    let RelayRuntimeConnectCompletion::Connected(connected_state) = outcome else {
        panic!("ordinary authentication must return Connected");
    };
    assert!(Arc::ptr_eq(&connected_state, &state));
    assert_eq!(state.connected.load(Ordering::SeqCst), 1);
    assert_eq!(state.verifies.load(Ordering::SeqCst), 0);
    assert_eq!(state.cleanups.load(Ordering::SeqCst), 0);
}

#[tokio::test]
async fn paired_runtime_connect_keeps_non_terminal_relay_failures_typed() {
    let expected = revocation_terminal();
    let (machine, state, _) = connect_fixture(expected);
    let error = complete_paired_runtime_connect(machine, async {
        Err(RelayClientError::Failure {
            code: "relay.client.handshake_rejected".to_owned(),
        })
    })
    .await
    .expect_err("ordinary Relay failure");

    assert!(matches!(error, PairedRuntimeConnectError::Relay(_)));
    assert_eq!(state.connected.load(Ordering::SeqCst), 0);
    assert_eq!(state.verifies.load(Ordering::SeqCst), 0);
    assert_eq!(state.cleanups.load(Ordering::SeqCst), 0);
}

#[tokio::test]
async fn exact_revocation_terminal_cleans_up_only_after_connector_drop() {
    let terminal = revocation_terminal();
    let terminal_bytes = encode(&terminal);
    let (machine, state, connector_dropped) = connect_fixture(terminal.clone());

    let outcome = complete_paired_runtime_connect(
        machine,
        authentication_terminal_after_connector_drop(
            Arc::clone(&connector_dropped),
            terminal,
            terminal_bytes,
        ),
    )
    .await
    .expect("exact verified revocation terminal");

    assert!(matches!(outcome, RelayRuntimeConnectCompletion::Revoked));
    assert!(connector_dropped.load(Ordering::SeqCst));
    assert_eq!(state.connected.load(Ordering::SeqCst), 0);
    assert_eq!(state.verifies.load(Ordering::SeqCst), 1);
    assert_eq!(state.cleanups.load(Ordering::SeqCst), 1);
}

#[tokio::test]
async fn non_revocation_or_non_exact_authentication_terminals_never_cleanup() {
    let valid = revocation_terminal();
    let valid_bytes = encode(&valid);
    let mut cases = Vec::new();

    cases.push((
        "retirement terminal",
        OpaqueRouteFrame {
            version: RELAY_PROTOCOL_VERSION,
            body: RelayFrameBody::RetirementCommitted(RetirementCommitted {
                machine_route: MACHINE,
                trust_epoch: TrustEpoch::new(9),
                retire_hash: [0x70; 32],
            }),
        },
        None,
    ));

    let mut forged_signature = valid.clone();
    let RelayFrameBody::RevocationCommitted(committed) = &mut forged_signature.body else {
        unreachable!()
    };
    committed.signed_revocation.signature.0[0] ^= 0x80;
    cases.push(("forged signature", forged_signature, None));

    let mut wrong_device = valid.clone();
    let RelayFrameBody::RevocationCommitted(committed) = &mut wrong_device.body else {
        unreachable!()
    };
    committed.device_route = DeviceRouteId::from_bytes([0x90; 16]);
    cases.push(("wrong device", wrong_device, None));

    let mut wrong_grant = valid.clone();
    let RelayFrameBody::RevocationCommitted(committed) = &mut wrong_grant.body else {
        unreachable!()
    };
    committed.grant_serial = GrantSerial::new(18);
    cases.push(("wrong grant", wrong_grant, None));

    let mut wrong_binding = valid.clone();
    let RelayFrameBody::RevocationCommitted(committed) = &mut wrong_binding.body else {
        unreachable!()
    };
    committed.signed_revocation.machine_route = MachineRouteId::from_bytes([0x91; 16]);
    cases.push(("wrong signed binding", wrong_binding, None));

    let mut non_exact_bytes = valid_bytes.clone();
    non_exact_bytes.push(0);
    cases.push(("non-exact bytes", valid.clone(), Some(non_exact_bytes)));

    for (label, frame, byte_override) in cases {
        let (machine, state, connector_dropped) = connect_fixture(valid.clone());
        let bytes = byte_override.unwrap_or_else(|| encode(&frame));
        let error = complete_paired_runtime_connect(
            machine,
            authentication_terminal_after_connector_drop(
                Arc::clone(&connector_dropped),
                frame,
                bytes,
            ),
        )
        .await
        .expect_err(label);

        assert!(
            matches!(error, PairedRuntimeConnectError::Paired(_)),
            "{label}: terminal verification failure must remain a paired-state error"
        );
        assert!(connector_dropped.load(Ordering::SeqCst), "{label}");
        assert_eq!(state.connected.load(Ordering::SeqCst), 0, "{label}");
        assert_eq!(state.verifies.load(Ordering::SeqCst), 1, "{label}");
        assert_eq!(state.cleanups.load(Ordering::SeqCst), 0, "{label}");
    }
}
