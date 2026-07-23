use std::collections::VecDeque;
use std::sync::{Arc, Mutex};

use agentdeck_crypto::{SignatureBytes, SigningKey, verify_authentication_transcript};
use agentdeck_protocol::relay_v2::auth::{
    AuthenticationRole, AuthenticationTranscriptV1, Ed25519Signature, PublicKeyBytes, RelayGrant,
};
use agentdeck_protocol::relay_v2::frame::{AuthProof, Challenge, Hello};
use agentdeck_protocol::relay_v2::id::{
    ConnectionInstanceId, DeviceRouteId, GrantSerial, MachineRouteId, RelayServerId, RootKeyId,
    TrustEpoch,
};
use agentdeck_protocol::relay_v2::{
    OpaqueRouteFrame, RELAY_PROTOCOL_VERSION, RelayFrameBody, encode,
};
use agentdeck_relay_client::RelayClientError;
use async_trait::async_trait;

use super::paired_machine::{device_authenticator_for_test, paired_spki_pins};
use super::relay_transport::{RelayRuntimeIo, RelayRuntimeTransport};
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
