//! W1 test-only Relay v2 principal state machine.
//!
//! 该模块只在 `w1-test-fixture` feature 下编译。固定私钥只用于本机 automatic fixture，
//! 不进入 W0 build；WASM host 只能取得 opaque frame，不能导出私钥、TBS 或明文 payload。

use agentdeck_crypto::{
    AeadSendingKey, SecretAeadKey, SenderCounter, SigningKey, seal_symmetric, sha256,
    sign_authentication_transcript, sign_sealed, sign_tbs,
};
use agentdeck_protocol::e2ee::context::{OuterContextV1, OuterFrameKind};
use agentdeck_protocol::e2ee::keys::{KeyId, KeyPurpose};
use agentdeck_protocol::e2ee::payload::SealedPayloadKind;
use agentdeck_protocol::relay_v2::auth::{AuthenticationRole, AuthenticationTranscriptV1};
use agentdeck_protocol::relay_v2::frame::{
    AcceptedRef, AuthProof, Authenticate, Hello, Pong, Publish, RegisterStream, RouteAccepted,
    SealedBlob,
};
use agentdeck_protocol::relay_v2::{
    CertRole, Ed25519Signature, LinkGeneration, MAX_FRAME_BYTES, MachineRouteId, OpaqueRouteFrame,
    PublicKeyBytes, RELAY_PROTOCOL_VERSION, RelayFrameBody, RelayServerId, RootKeyId,
    SignedCertificate, StreamGenerationId, StreamRouteId, TrustEpoch, decode, encode,
};

const ROOT_SEED: [u8; 32] = [0x41; 32];
const LINK_SEED: [u8; 32] = [0x42; 32];
const DATA_SEED: [u8; 32] = [0x43; 32];
const AEAD_KEY: [u8; 32] = [0x51; 32];
const NONCE_PREFIX: [u8; 4] = [0x52; 4];
const MACHINE_ROUTE: MachineRouteId = MachineRouteId::from_bytes([0x31; 16]);
const ROOT_KEY_ID: RootKeyId = RootKeyId::from_bytes([0x33; 16]);
const STREAM_ROUTE: StreamRouteId = StreamRouteId::from_bytes([0x61; 16]);
const STREAM_GENERATION: StreamGenerationId = StreamGenerationId::from_bytes([0x62; 16]);
const TRUST_EPOCH: TrustEpoch = TrustEpoch::new(1);
const KEY_EPOCH: u64 = 1;
const KEY_DIRECTORY_REVISION: u64 = 1;
const STREAM_SEQ: u64 = 0;

pub const W1_SENTINEL: &[u8] = b"agentdeck-w1-sentinel";

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum W1TransportFault {
    None,
    TamperChallenge,
    TamperSignature,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, thiserror::Error)]
pub enum W1TransportError {
    #[error("web.remote.origin_invalid")]
    OriginInvalid,
    #[error("web.remote.state_invalid")]
    StateInvalid,
    #[error("web.remote.frame_invalid")]
    FrameInvalid,
    #[error("web.remote.server_identity_mismatch")]
    ServerIdentityMismatch,
    #[error("web.remote.handshake_rejected")]
    HandshakeRejected,
    #[error("web.remote.crypto_failed")]
    CryptoFailed,
}

impl W1TransportError {
    pub const fn code(self) -> &'static str {
        match self {
            Self::OriginInvalid => "web.remote.origin_invalid",
            Self::StateInvalid => "web.remote.state_invalid",
            Self::FrameInvalid => "web.remote.frame_invalid",
            Self::ServerIdentityMismatch => "web.remote.server_identity_mismatch",
            Self::HandshakeRejected => "web.remote.handshake_rejected",
            Self::CryptoFailed => "web.remote.crypto_failed",
        }
    }
}

pub struct W1TestIdentity {
    pub machine_route: MachineRouteId,
    pub root_pubkey: PublicKeyBytes,
    pub link_cert: SignedCertificate,
    pub data_cert: SignedCertificate,
    link: SigningKey,
    data: SigningKey,
}

fn signed_certificate(
    root: &SigningKey,
    subject: &SigningKey,
    relay_server_id: RelayServerId,
    role: CertRole,
) -> SignedCertificate {
    let mut certificate = SignedCertificate {
        subject_pubkey: PublicKeyBytes(subject.verifying_key().to_bytes()),
        cert_role: role,
        generation: LinkGeneration::new(1),
        root_key_id: ROOT_KEY_ID,
        trust_epoch: TRUST_EPOCH,
        not_after_ms: None,
        signature: Ed25519Signature([0; 64]),
    };
    certificate.signature = sign_tbs(
        root,
        &certificate.to_be_signed_v1(
            relay_server_id,
            MACHINE_ROUTE,
            sha256(&root.verifying_key().to_bytes()),
        ),
    )
    .into();
    certificate
}

pub fn w1_test_identity(relay_server_id: RelayServerId) -> W1TestIdentity {
    let root = SigningKey::from_seed(&ROOT_SEED);
    let link = SigningKey::from_seed(&LINK_SEED);
    let data = SigningKey::from_seed(&DATA_SEED);
    W1TestIdentity {
        machine_route: MACHINE_ROUTE,
        root_pubkey: PublicKeyBytes(root.verifying_key().to_bytes()),
        link_cert: signed_certificate(&root, &link, relay_server_id, CertRole::Link),
        data_cert: signed_certificate(&root, &data, relay_server_id, CertRole::Data),
        link,
        data,
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Phase {
    Initial,
    HelloSent,
    AuthenticateSent,
    Active,
    Failed,
}

pub struct W1TransportCore {
    connect_url: String,
    expected_relay_server_id: RelayServerId,
    identity: W1TestIdentity,
    phase: Phase,
    register_issued: bool,
    publish_issued: bool,
    sentinel_accepted: bool,
}

impl W1TransportCore {
    pub fn new(
        origin: &str,
        expected_relay_server_id: RelayServerId,
    ) -> Result<Self, W1TransportError> {
        let mut parsed = url::Url::parse(origin).map_err(|_| W1TransportError::OriginInvalid)?;
        if parsed.scheme() != "wss"
            || parsed.host_str().is_none()
            || !parsed.username().is_empty()
            || parsed.password().is_some()
            || parsed.path() != "/"
            || parsed.port() == Some(0)
            || parsed.query().is_some()
            || parsed.fragment().is_some()
        {
            return Err(W1TransportError::OriginInvalid);
        }
        parsed.set_path("/v2/connect");
        let connect_url = parsed.to_string();
        Ok(Self {
            connect_url,
            expected_relay_server_id,
            identity: w1_test_identity(expected_relay_server_id),
            phase: Phase::Initial,
            register_issued: false,
            publish_issued: false,
            sentinel_accepted: false,
        })
    }

    pub fn connect_url(&self) -> &str {
        &self.connect_url
    }

    pub fn start(&mut self) -> Result<Vec<u8>, W1TransportError> {
        if self.phase != Phase::Initial {
            return Err(W1TransportError::StateInvalid);
        }
        self.phase = Phase::HelloSent;
        Ok(frame(RelayFrameBody::Hello(Hello {
            protocol_version: RELAY_PROTOCOL_VERSION,
        })))
    }

    pub fn accept_challenge(
        &mut self,
        bytes: &[u8],
        fault: W1TransportFault,
    ) -> Result<Vec<u8>, W1TransportError> {
        if self.phase != Phase::HelloSent {
            return Err(W1TransportError::StateInvalid);
        }
        let decoded = decode(bytes).map_err(|_| {
            self.phase = Phase::Failed;
            W1TransportError::FrameInvalid
        })?;
        let RelayFrameBody::Challenge(mut challenge) = decoded.body else {
            self.phase = Phase::Failed;
            return Err(W1TransportError::HandshakeRejected);
        };
        if challenge.relay_server_id != self.expected_relay_server_id {
            self.phase = Phase::Failed;
            return Err(W1TransportError::ServerIdentityMismatch);
        }
        if fault == W1TransportFault::TamperChallenge {
            challenge.challenge_nonce[0] ^= 0x01;
        }
        let transcript = AuthenticationTranscriptV1 {
            role: AuthenticationRole::MachineLink,
            challenge_nonce: challenge.challenge_nonce,
            connection_instance: challenge.connection_instance,
            relay_server_id: challenge.relay_server_id,
            relay_protocol_version: RELAY_PROTOCOL_VERSION,
            machine_route: self.identity.machine_route,
            device_route: None,
            serial_or_generation: self.identity.link_cert.generation.value(),
            credential_sha256: self.identity.link_cert.canonical_sha256(),
        };
        let mut signature: Ed25519Signature =
            sign_authentication_transcript(&self.identity.link, &transcript).into();
        if fault == W1TransportFault::TamperSignature {
            signature.0[0] ^= 0x01;
        }
        self.phase = Phase::AuthenticateSent;
        Ok(frame(RelayFrameBody::Authenticate(Authenticate {
            proof: AuthProof::MachineLink {
                machine_route: self.identity.machine_route,
                link_cert: self.identity.link_cert.clone(),
            },
            signature,
        })))
    }

    pub fn accept_authenticated(&mut self, bytes: &[u8]) -> Result<(), W1TransportError> {
        if self.phase != Phase::AuthenticateSent {
            return Err(W1TransportError::StateInvalid);
        }
        let decoded = decode(bytes).map_err(|_| W1TransportError::FrameInvalid)?;
        match decoded.body {
            RelayFrameBody::Authenticated(authenticated)
                if authenticated.heartbeat_interval_secs > 0 =>
            {
                self.phase = Phase::Active;
                Ok(())
            }
            _ => {
                self.phase = Phase::Failed;
                Err(W1TransportError::HandshakeRejected)
            }
        }
    }

    pub fn register_stream(&mut self) -> Result<Vec<u8>, W1TransportError> {
        if self.phase != Phase::Active || self.register_issued {
            return Err(W1TransportError::StateInvalid);
        }
        self.register_issued = true;
        Ok(frame(RelayFrameBody::RegisterStream(RegisterStream {
            machine_route: self.identity.machine_route,
            stream_route: STREAM_ROUTE,
            generation: STREAM_GENERATION,
        })))
    }

    pub fn publish_sentinel(&mut self) -> Result<Vec<u8>, W1TransportError> {
        if self.phase != Phase::Active || !self.register_issued || self.publish_issued {
            return Err(W1TransportError::StateInvalid);
        }
        let context = OuterContextV1 {
            frame_kind: OuterFrameKind::ConversationPublish,
            relay_protocol_version: RELAY_PROTOCOL_VERSION,
            e2ee_format_version: agentdeck_protocol::e2ee::E2EE_FORMAT_VERSION,
            machine_route: Some(self.identity.machine_route),
            device_route: None,
            stream_route: Some(STREAM_ROUTE),
            request_route: None,
            pair_route: None,
            stream_generation: Some(STREAM_GENERATION),
            stream_cursor: None,
            stream_seq: Some(STREAM_SEQ),
            message_key_epoch: KEY_EPOCH,
        };
        let unsigned = seal_symmetric(
            &AeadSendingKey::new(
                KeyId {
                    purpose: KeyPurpose::ConversationDek,
                    epoch: KEY_EPOCH,
                },
                KEY_EPOCH,
                KEY_DIRECTORY_REVISION,
                NONCE_PREFIX,
                SecretAeadKey::from_bytes(AEAD_KEY),
            ),
            &context,
            SealedPayloadKind::ConversationEvent,
            W1_SENTINEL,
            SenderCounter(0),
        )
        .map_err(|_| W1TransportError::CryptoFailed)?;
        let signed = sign_sealed(unsigned, &self.identity.data, &context);
        self.publish_issued = true;
        Ok(frame(RelayFrameBody::Publish(Publish {
            stream_route: STREAM_ROUTE,
            generation: STREAM_GENERATION,
            stream_seq: STREAM_SEQ,
            sealed_blob: SealedBlob(signed.to_wire_bytes()),
        })))
    }

    pub fn accept_active_frame(&mut self, bytes: &[u8]) -> Result<Vec<u8>, W1TransportError> {
        if self.phase != Phase::Active {
            return Err(W1TransportError::StateInvalid);
        }
        let decoded = decode(bytes).map_err(|_| W1TransportError::FrameInvalid)?;
        match decoded.body {
            RelayFrameBody::Ping(ping) => {
                Ok(frame(RelayFrameBody::Pong(Pong { nonce: ping.nonce })))
            }
            RelayFrameBody::RouteAccepted(RouteAccepted {
                accepted:
                    AcceptedRef::StreamFrame {
                        stream_route,
                        stream_seq,
                    },
            }) if self.publish_issued
                && stream_route == STREAM_ROUTE
                && stream_seq == STREAM_SEQ =>
            {
                self.sentinel_accepted = true;
                Ok(Vec::new())
            }
            _ => Err(W1TransportError::FrameInvalid),
        }
    }

    pub const fn sentinel_accepted(&self) -> bool {
        self.sentinel_accepted
    }

    pub fn oversize_fault_frame(&self) -> Vec<u8> {
        vec![0; MAX_FRAME_BYTES + 1]
    }
}

fn frame(body: RelayFrameBody) -> Vec<u8> {
    encode(&OpaqueRouteFrame {
        version: RELAY_PROTOCOL_VERSION,
        body,
    })
}
