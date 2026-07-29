//! MachineLink 的 typed Relay transport。
//!
//! 本模块不持有业务执行 core，也不公开 raw frame send/recv。主 control lane 只承载
//! root-signed retirement；一次性取出的 bounded pairing lane 只承载显式配对/授权 frame；
//! bounded business lane 只承载 `Send`、request `RouteAccepted` 与 outbound `Reply`。
//! 三条 typed lane 复用唯一 Relay session/supervisor；业务 lane 只做 transport/dispatch，
//! 不认证 Runtime payload，也不持有 canonical 业务状态。

use std::collections::{HashMap, VecDeque};
use std::convert::Infallible;
use std::fmt;
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::sync::{Arc, Mutex, Weak};
use std::time::Duration;

use agentdeck_crypto::rand_core::{TryCryptoRng, TryRng};
#[cfg(test)]
use agentdeck_crypto::{
    DeviceKeyRecoverySealAuthority,
    seal_device_key_recovery_reply as crypto_seal_device_key_recovery_reply,
};
use agentdeck_crypto::{
    HpkePublicKey, SecretAeadKey, seal_key_directory_entry as crypto_seal_key_directory_entry,
    sha256,
};
use agentdeck_protocol::e2ee::{
    DeviceAuthorizationV1, DeviceKeyRecoveryInfoV1, DeviceKeyRecoveryReplyV1, E2EE_FORMAT_VERSION,
    KeyDirectoryEntry, KeyDirectorySignatureContextV1, KeyDirectoryV1, KeyUpdateInfoV1,
    KeyUpdateSetV1, KeyUpdateV1, MachineDataSignerBindingV1, OuterContextV1, OuterFrameKind,
    PairRequestInfoV1, PairResponseInfoV1, PairResponsePlaintextV1, PairResponseV1, PairTerminalV1,
    PairingControlEnvelopeV1, SignedSealedBlobV1, UnsignedSealedBlobV1,
};
use agentdeck_protocol::relay_v2::failure::RELAY_ROUTE_NOT_FOUND;
use agentdeck_protocol::relay_v2::frame::{
    AcceptedRef, AuthProof, Authenticate, Challenge, ClosePairRoute, GrantCommitted, InstallGrant,
    OpenPairRoute, PairData, PairRouteClosed, PairRouteOpened, Publish, RegisterStream, Reply,
    RetireMachine, RetirementCommitted, RevocationCommitted, RevokeDevice, RouteAccepted,
    SealedBlob, Send as RouteSend, ServerRestarting,
};
use agentdeck_protocol::relay_v2::{
    AuthenticationRole, AuthenticationTranscriptV1, DeviceRevocation, DeviceRouteId, GrantSerial,
    KeyDirectoryRevision, MAX_FRAME_BYTES, MachineRouteId, OpaqueRouteFrame, PairRouteId,
    RELAY_PROTOCOL_VERSION, RelayFailure, RelayFrameBody, RequestRouteId, SignedCertificate,
    StreamGenerationId, StreamRouteId, TrustEpoch, encode, relay_frame_reply_reference,
};
use agentdeck_protocol::runtime::RUNTIME_PROTOCOL_VERSION;
use agentdeck_relay_client::{LinkAuthenticator, RelayClient, RelayClientConfig, RelayClientError};
use async_trait::async_trait;
use thiserror::Error;
use tokio::sync::{OwnedSemaphorePermit, Semaphore, mpsc, oneshot, watch};
use tokio::task::JoinHandle;
use zeroize::{Zeroize, Zeroizing};

use crate::local::listener::RemoteStartPermit;

use super::bootstrap::{
    ArmedRemoteIdentity, MachineLinkIdentityOwner, MachinePairingAnchor, MachinePairingError,
};
use super::certificate::MachineCertificateError;
use super::trust_reset::{FrozenMachineRetirement, MachineRetirementError};

trait MachineLinkOwner: Send + Sync {
    fn sign_authentication(
        &self,
        relay_server_id: agentdeck_protocol::relay_v2::RelayServerId,
        machine_route: MachineRouteId,
        link_cert: &SignedCertificate,
        transcript: &AuthenticationTranscriptV1,
    ) -> Result<agentdeck_protocol::relay_v2::Ed25519Signature, MachineCertificateError>;

    fn freeze_retirement(
        &self,
        relay_server_id: agentdeck_protocol::relay_v2::RelayServerId,
        machine_route: MachineRouteId,
        expected_trust_epoch: u64,
    ) -> Result<FrozenMachineRetirement, MachineRetirementError>;

    fn pairing_anchor(
        &self,
        relay_server_id: agentdeck_protocol::relay_v2::RelayServerId,
        machine_route: MachineRouteId,
        data_certificate: &SignedCertificate,
    ) -> Result<MachinePairingAnchor, MachinePairingError>;

    fn seal_pair_pending(
        &self,
        recipient: &HpkePublicKey,
        info: &PairRequestInfoV1,
        context: &OuterContextV1,
        request_hash: [u8; 32],
        signer: &MachineDataSignerBindingV1,
        rng: &mut dyn agentdeck_crypto::rand_core::CryptoRng,
    ) -> Result<PairingControlEnvelopeV1, MachinePairingError>;

    fn seal_pair_terminal(
        &self,
        _recipient: &HpkePublicKey,
        _info: &PairRequestInfoV1,
        _context: &OuterContextV1,
        _terminal: PairTerminalV1,
        _signer: &MachineDataSignerBindingV1,
        _rng: &mut dyn agentdeck_crypto::rand_core::CryptoRng,
    ) -> Result<PairingControlEnvelopeV1, MachinePairingError> {
        Err(MachinePairingError::ContextMismatch)
    }

    fn sign_relay_grant(
        &self,
        anchor: &MachinePairingAnchor,
        grant: agentdeck_protocol::relay_v2::RelayGrant,
    ) -> Result<agentdeck_protocol::relay_v2::RelayGrant, MachinePairingError>;

    fn sign_device_authorization(
        &self,
        anchor: &MachinePairingAnchor,
        grant: &agentdeck_protocol::relay_v2::RelayGrant,
        authorization: DeviceAuthorizationV1,
    ) -> Result<DeviceAuthorizationV1, MachinePairingError>;

    fn sign_key_directory(
        &self,
        anchor: &MachinePairingAnchor,
        context: &KeyDirectorySignatureContextV1,
        directory: KeyDirectoryV1,
    ) -> Result<KeyDirectoryV1, MachinePairingError>;

    fn sign_key_update(
        &self,
        anchor: &MachinePairingAnchor,
        info: &KeyUpdateInfoV1,
        context: &OuterContextV1,
        update: KeyUpdateV1,
    ) -> Result<KeyUpdateV1, MachinePairingError>;

    fn sign_sealed(
        &self,
        anchor: &MachinePairingAnchor,
        unsigned: UnsignedSealedBlobV1,
        context: &OuterContextV1,
    ) -> Result<SignedSealedBlobV1, MachinePairingError>;

    fn seal_device_key_recovery_reply(
        &self,
        _anchor: &MachinePairingAnchor,
        _recipient: &HpkePublicKey,
        _info: &DeviceKeyRecoveryInfoV1,
        _context: &OuterContextV1,
        _update_set: &KeyUpdateSetV1,
        _rng: &mut dyn agentdeck_crypto::rand_core::CryptoRng,
    ) -> Result<DeviceKeyRecoveryReplyV1, MachinePairingError> {
        Err(MachinePairingError::ContextMismatch)
    }

    fn seal_pair_response(
        &self,
        anchor: &MachinePairingAnchor,
        recipient: &HpkePublicKey,
        info: &PairResponseInfoV1,
        context: &OuterContextV1,
        plaintext: &PairResponsePlaintextV1,
        rng: &mut dyn agentdeck_crypto::rand_core::CryptoRng,
    ) -> Result<PairResponseV1, MachinePairingError>;

    fn sign_device_revocation(
        &self,
        anchor: &MachinePairingAnchor,
        revocation: DeviceRevocation,
    ) -> Result<DeviceRevocation, MachinePairingError>;
}

impl MachineLinkOwner for MachineLinkIdentityOwner {
    fn sign_authentication(
        &self,
        relay_server_id: agentdeck_protocol::relay_v2::RelayServerId,
        machine_route: MachineRouteId,
        link_cert: &SignedCertificate,
        transcript: &AuthenticationTranscriptV1,
    ) -> Result<agentdeck_protocol::relay_v2::Ed25519Signature, MachineCertificateError> {
        MachineLinkIdentityOwner::verify_link_certificate(
            self,
            relay_server_id,
            machine_route,
            link_cert,
        )?;
        Ok(MachineLinkIdentityOwner::sign_link_authentication(
            self, transcript,
        ))
    }

    fn freeze_retirement(
        &self,
        relay_server_id: agentdeck_protocol::relay_v2::RelayServerId,
        machine_route: MachineRouteId,
        expected_trust_epoch: u64,
    ) -> Result<FrozenMachineRetirement, MachineRetirementError> {
        MachineLinkIdentityOwner::freeze_retirement(
            self,
            relay_server_id,
            machine_route,
            expected_trust_epoch,
        )
    }

    fn pairing_anchor(
        &self,
        relay_server_id: agentdeck_protocol::relay_v2::RelayServerId,
        machine_route: MachineRouteId,
        data_certificate: &SignedCertificate,
    ) -> Result<MachinePairingAnchor, MachinePairingError> {
        MachineLinkIdentityOwner::pairing_anchor(
            self,
            relay_server_id,
            machine_route,
            data_certificate,
        )
    }

    fn seal_pair_pending(
        &self,
        recipient: &HpkePublicKey,
        info: &PairRequestInfoV1,
        context: &OuterContextV1,
        request_hash: [u8; 32],
        signer: &MachineDataSignerBindingV1,
        rng: &mut dyn agentdeck_crypto::rand_core::CryptoRng,
    ) -> Result<PairingControlEnvelopeV1, MachinePairingError> {
        MachineLinkIdentityOwner::seal_pair_pending(
            self,
            recipient,
            info,
            context,
            request_hash,
            signer,
            rng,
        )
    }

    fn seal_pair_terminal(
        &self,
        recipient: &HpkePublicKey,
        info: &PairRequestInfoV1,
        context: &OuterContextV1,
        terminal: PairTerminalV1,
        signer: &MachineDataSignerBindingV1,
        rng: &mut dyn agentdeck_crypto::rand_core::CryptoRng,
    ) -> Result<PairingControlEnvelopeV1, MachinePairingError> {
        MachineLinkIdentityOwner::seal_pair_terminal(
            self, recipient, info, context, terminal, signer, rng,
        )
    }

    fn sign_relay_grant(
        &self,
        anchor: &MachinePairingAnchor,
        grant: agentdeck_protocol::relay_v2::RelayGrant,
    ) -> Result<agentdeck_protocol::relay_v2::RelayGrant, MachinePairingError> {
        MachineLinkIdentityOwner::sign_relay_grant(self, anchor, grant)
    }

    fn sign_device_authorization(
        &self,
        anchor: &MachinePairingAnchor,
        grant: &agentdeck_protocol::relay_v2::RelayGrant,
        authorization: DeviceAuthorizationV1,
    ) -> Result<DeviceAuthorizationV1, MachinePairingError> {
        MachineLinkIdentityOwner::sign_device_authorization(self, anchor, grant, authorization)
    }

    fn sign_key_directory(
        &self,
        anchor: &MachinePairingAnchor,
        context: &KeyDirectorySignatureContextV1,
        directory: KeyDirectoryV1,
    ) -> Result<KeyDirectoryV1, MachinePairingError> {
        MachineLinkIdentityOwner::sign_key_directory(self, anchor, context, directory)
    }

    fn sign_key_update(
        &self,
        anchor: &MachinePairingAnchor,
        info: &KeyUpdateInfoV1,
        context: &OuterContextV1,
        update: KeyUpdateV1,
    ) -> Result<KeyUpdateV1, MachinePairingError> {
        MachineLinkIdentityOwner::sign_key_update(self, anchor, info, context, update)
    }

    fn sign_sealed(
        &self,
        anchor: &MachinePairingAnchor,
        unsigned: UnsignedSealedBlobV1,
        context: &OuterContextV1,
    ) -> Result<SignedSealedBlobV1, MachinePairingError> {
        MachineLinkIdentityOwner::sign_sealed(self, anchor, unsigned, context)
    }

    fn seal_device_key_recovery_reply(
        &self,
        anchor: &MachinePairingAnchor,
        recipient: &HpkePublicKey,
        info: &DeviceKeyRecoveryInfoV1,
        context: &OuterContextV1,
        update_set: &KeyUpdateSetV1,
        rng: &mut dyn agentdeck_crypto::rand_core::CryptoRng,
    ) -> Result<DeviceKeyRecoveryReplyV1, MachinePairingError> {
        MachineLinkIdentityOwner::seal_device_key_recovery_reply(
            self, anchor, recipient, info, context, update_set, rng,
        )
    }

    fn seal_pair_response(
        &self,
        anchor: &MachinePairingAnchor,
        recipient: &HpkePublicKey,
        info: &PairResponseInfoV1,
        context: &OuterContextV1,
        plaintext: &PairResponsePlaintextV1,
        rng: &mut dyn agentdeck_crypto::rand_core::CryptoRng,
    ) -> Result<PairResponseV1, MachinePairingError> {
        MachineLinkIdentityOwner::seal_pair_response(
            self, anchor, recipient, info, context, plaintext, rng,
        )
    }

    fn sign_device_revocation(
        &self,
        anchor: &MachinePairingAnchor,
        revocation: DeviceRevocation,
    ) -> Result<DeviceRevocation, MachinePairingError> {
        MachineLinkIdentityOwner::sign_device_revocation(self, anchor, revocation)
    }
}

/// RelayClient 只拿到这个 typed authenticator；它不能请求对任意 bytes 签名。
struct MachineLinkAuthenticator {
    owner: Box<dyn MachineLinkOwner>,
    machine_route: MachineRouteId,
    link_cert: SignedCertificate,
    authenticated_relay: Mutex<Option<agentdeck_protocol::relay_v2::RelayServerId>>,
}

impl MachineLinkAuthenticator {
    fn new(
        owner: impl MachineLinkOwner + 'static,
        machine_route: MachineRouteId,
        link_cert: SignedCertificate,
    ) -> Self {
        Self {
            owner: Box::new(owner),
            machine_route,
            link_cert,
            authenticated_relay: Mutex::new(None),
        }
    }

    fn transcript(&self, challenge: &Challenge) -> AuthenticationTranscriptV1 {
        AuthenticationTranscriptV1 {
            role: AuthenticationRole::MachineLink,
            challenge_nonce: challenge.challenge_nonce,
            connection_instance: challenge.connection_instance,
            relay_server_id: challenge.relay_server_id,
            relay_protocol_version: RELAY_PROTOCOL_VERSION,
            machine_route: self.machine_route,
            device_route: None,
            serial_or_generation: self.link_cert.generation.value(),
            credential_sha256: self.link_cert.canonical_sha256(),
        }
    }

    fn freeze_retirement(
        &self,
        relay_server_id: agentdeck_protocol::relay_v2::RelayServerId,
        expected_trust_epoch: u64,
    ) -> Result<FrozenMachineRetirement, RemoteTransportError> {
        let authenticated_relay = self
            .authenticated_relay
            .lock()
            .map_err(|_| RemoteTransportError::Closed)?;
        if *authenticated_relay != Some(relay_server_id) {
            return Err(RemoteTransportError::Retirement(
                MachineRetirementError::AuthenticatedRelayMismatch,
            ));
        }
        self.owner
            .freeze_retirement(relay_server_id, self.machine_route, expected_trust_epoch)
            .map_err(RemoteTransportError::Retirement)
    }

    fn bind_pairing_anchor(
        &self,
        data_certificate: &SignedCertificate,
    ) -> Result<MachinePairingAnchor, MachinePairingError> {
        let relay_server_id = self.authenticated_relay_id()?;
        self.owner
            .pairing_anchor(relay_server_id, self.machine_route, data_certificate)
    }

    fn verify_pairing_anchor(
        &self,
        expected: &MachinePairingAnchor,
    ) -> Result<(), MachinePairingError> {
        if expected.machine_route != self.machine_route
            || expected.relay_server_id != self.authenticated_relay_id()?
        {
            return Err(MachinePairingError::ContextMismatch);
        }
        let observed = self.owner.pairing_anchor(
            expected.relay_server_id,
            expected.machine_route,
            &expected.data_certificate,
        )?;
        if observed != *expected {
            return Err(MachinePairingError::ContextMismatch);
        }
        Ok(())
    }

    fn authenticated_relay_id(
        &self,
    ) -> Result<agentdeck_protocol::relay_v2::RelayServerId, MachinePairingError> {
        self.authenticated_relay
            .lock()
            .map_err(|_| MachinePairingError::ContextMismatch)?
            .ok_or(MachinePairingError::ContextMismatch)
    }
}

impl fmt::Debug for MachineLinkAuthenticator {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("MachineLinkAuthenticator([REDACTED])")
    }
}

#[async_trait]
impl LinkAuthenticator for MachineLinkAuthenticator {
    fn proof(&self) -> AuthProof {
        AuthProof::MachineLink {
            machine_route: self.machine_route,
            link_cert: self.link_cert.clone(),
        }
    }

    async fn authenticate(&self, challenge: &Challenge) -> Result<Authenticate, RelayClientError> {
        if challenge.challenge_nonce == [0; 32]
            || challenge.connection_instance.as_bytes() == &[0; 16]
        {
            return Err(RelayClientError::Failure {
                code: "remote.transport.challenge_invalid".to_owned(),
            });
        }
        let mut authenticated_relay =
            self.authenticated_relay
                .lock()
                .map_err(|_| RelayClientError::Failure {
                    code: "remote.transport.closed".to_owned(),
                })?;
        if authenticated_relay.is_some_and(|relay| relay != challenge.relay_server_id) {
            return Err(RelayClientError::Failure {
                code: MachineRetirementError::AuthenticatedRelayMismatch
                    .code()
                    .to_owned(),
            });
        }
        let transcript = self.transcript(challenge);
        let signature = self
            .owner
            .sign_authentication(
                challenge.relay_server_id,
                self.machine_route,
                &self.link_cert,
                &transcript,
            )
            .map_err(|error| RelayClientError::Failure {
                code: error.code().to_owned(),
            })?;
        *authenticated_relay = Some(challenge.relay_server_id);
        Ok(Authenticate {
            proof: self.proof(),
            signature,
        })
    }
}

#[async_trait]
trait ControlSession: Send {
    async fn send(&mut self, frame: OpaqueRouteFrame) -> Result<(), RelayClientError>;
    async fn next(&mut self) -> Result<Option<OpaqueRouteFrame>, RelayClientError>;
    async fn reconnect(&mut self) -> Result<(), RelayClientError>;
    async fn shutdown(&mut self);
}

#[async_trait]
trait ControlConnector: Send + Sync {
    async fn connect(
        &self,
        config: RelayClientConfig,
        authenticator: Arc<MachineLinkAuthenticator>,
    ) -> Result<Box<dyn ControlSession>, RelayClientError>;
}

struct RelayControlConnector;

#[async_trait]
impl ControlConnector for RelayControlConnector {
    async fn connect(
        &self,
        config: RelayClientConfig,
        authenticator: Arc<MachineLinkAuthenticator>,
    ) -> Result<Box<dyn ControlSession>, RelayClientError> {
        let authenticator: Arc<dyn LinkAuthenticator> = authenticator;
        let client = RelayClient::connect(config, authenticator).await?;
        Ok(Box::new(RelayControlSession { client }))
    }
}

struct RelayControlSession {
    client: RelayClient,
}

#[async_trait]
impl ControlSession for RelayControlSession {
    async fn send(&mut self, frame: OpaqueRouteFrame) -> Result<(), RelayClientError> {
        self.client.send(frame).await
    }

    async fn next(&mut self) -> Result<Option<OpaqueRouteFrame>, RelayClientError> {
        self.client.recv().await
    }

    async fn reconnect(&mut self) -> Result<(), RelayClientError> {
        self.client.reconnect_and_authenticate().await
    }

    async fn shutdown(&mut self) {
        self.client.shutdown_confirmed().await;
    }
}

/// 已剥离 Relay message/reference 的安全失败，只保留稳定 code。
#[derive(Clone, PartialEq, Eq)]
pub struct SafeFailure {
    code: String,
}

impl SafeFailure {
    #[must_use]
    pub fn code(&self) -> &str {
        &self.code
    }
}

impl fmt::Debug for SafeFailure {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("SafeFailure")
            .field("code", &self.code)
            .finish()
    }
}

/// 已冻结完整 canonical outer frame 的 retirement terminal。
#[derive(Clone, PartialEq, Eq)]
pub struct RetirementTerminal {
    committed: RetirementCommitted,
    canonical_frame_bytes: Vec<u8>,
    canonical_frame_hash: [u8; 32],
}

impl RetirementTerminal {
    #[must_use]
    pub const fn committed(&self) -> &RetirementCommitted {
        &self.committed
    }

    #[must_use]
    pub fn canonical_frame_bytes(&self) -> &[u8] {
        &self.canonical_frame_bytes
    }

    #[must_use]
    pub const fn canonical_frame_hash(&self) -> [u8; 32] {
        self.canonical_frame_hash
    }

    #[must_use]
    pub fn into_parts(self) -> (RetirementCommitted, Vec<u8>, [u8; 32]) {
        (
            self.committed,
            self.canonical_frame_bytes,
            self.canonical_frame_hash,
        )
    }
}

impl fmt::Debug for RetirementTerminal {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("RetirementTerminal([REDACTED])")
    }
}

/// RemoteTransport 唯一允许向上游交付的 control event。
#[derive(Clone, PartialEq, Eq)]
pub enum RemoteControl {
    RetirementTerminal(RetirementTerminal),
    SafeFailure(SafeFailure),
    ServerRestarting(ServerRestarting),
}

impl fmt::Debug for RemoteControl {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::RetirementTerminal(_) => {
                formatter.write_str("RemoteControl::RetirementTerminal([REDACTED])")
            }
            Self::SafeFailure(failure) => formatter
                .debug_tuple("RemoteControl::SafeFailure")
                .field(failure)
                .finish(),
            Self::ServerRestarting(restarting) => formatter
                .debug_tuple("RemoteControl::ServerRestarting")
                .field(&restarting.drain_deadline_ms)
                .finish(),
        }
    }
}

/// Pairing lane 唯一允许向上游交付的 typed event。
///
/// `PairFrameAccepted` 只证明 Relay writer 接受了对应 PairData，绝不是 endpoint
/// delivery 或 `PairResponseReceived` 证明。
#[derive(Clone, PartialEq, Eq)]
pub(crate) enum PairingTransportEvent {
    PairRouteOpened(PairRouteOpened),
    PairData(PairData),
    PairFrameAccepted(RouteAccepted),
    PairRouteClosed(PairRouteClosed),
    GrantCommitted(GrantCommitted),
    RevocationCommitted(RevocationCommitted),
}

impl fmt::Debug for PairingTransportEvent {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        let name = match self {
            Self::PairRouteOpened(_) => "PairRouteOpened",
            Self::PairData(_) => "PairData",
            Self::PairFrameAccepted(_) => "PairFrameAcceptedNotDelivered",
            Self::PairRouteClosed(_) => "PairRouteClosed",
            Self::GrantCommitted(_) => "GrantCommitted",
            Self::RevocationCommitted(_) => "RevocationCommitted",
        };
        formatter.write_str("PairingTransportEvent::")?;
        formatter.write_str(name)?;
        formatter.write_str("([REDACTED])")
    }
}

/// 构造 PairInvite 时可复制的 frozen public machine context；不含任何私钥。
#[derive(Clone, PartialEq, Eq)]
pub(crate) struct PairingInviteAnchor {
    inner: MachinePairingAnchor,
}

impl PairingInviteAnchor {
    #[must_use]
    pub(crate) const fn relay_server_id(&self) -> agentdeck_protocol::relay_v2::RelayServerId {
        self.inner.relay_server_id
    }

    #[must_use]
    pub(crate) const fn machine_route(&self) -> MachineRouteId {
        self.inner.machine_route
    }

    #[must_use]
    pub(crate) const fn root_public_key(&self) -> agentdeck_protocol::relay_v2::PublicKeyBytes {
        self.inner.root_public_key
    }

    #[must_use]
    pub(crate) const fn root_fingerprint(&self) -> [u8; 32] {
        self.inner.root_fingerprint
    }

    #[must_use]
    pub(crate) const fn root_key_id(&self) -> agentdeck_protocol::relay_v2::RootKeyId {
        self.inner.root_key_id
    }

    #[must_use]
    pub(crate) const fn trust_epoch(&self) -> agentdeck_protocol::relay_v2::TrustEpoch {
        self.inner.trust_epoch
    }

    #[must_use]
    pub(crate) const fn data_generation(&self) -> agentdeck_protocol::relay_v2::LinkGeneration {
        self.inner.data_generation
    }

    #[must_use]
    pub(crate) const fn data_sign_certificate(&self) -> &SignedCertificate {
        &self.inner.data_certificate
    }
}

impl fmt::Debug for PairingInviteAnchor {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("PairingInviteAnchor([REDACTED])")
    }
}

/// 可交给 business sealer/key-directory publisher 的最小 MachineData capability。
/// Clone 只复制 Weak owner 与已经验证的 public anchor/signer，不延长 authenticator 生命周期。
pub(crate) struct DeviceKeyRecoverySealRequest<'a> {
    pub(crate) recipient: &'a HpkePublicKey,
    pub(crate) machine_route: MachineRouteId,
    pub(crate) device_route: DeviceRouteId,
    pub(crate) request_route: RequestRouteId,
    pub(crate) grant_serial: GrantSerial,
    pub(crate) root_trust_epoch: TrustEpoch,
    pub(crate) known_revision: KeyDirectoryRevision,
    pub(crate) update_set: &'a KeyUpdateSetV1,
}

#[derive(Clone)]
pub(crate) struct MachineDataAuthority {
    owner: Weak<MachineLinkAuthenticator>,
    anchor: MachinePairingAnchor,
    data_signer: MachineDataSignerBindingV1,
}

impl MachineDataAuthority {
    /// 使用 exact Current authorization 携带的 DeviceHPKE 与当前 MachineDataSign
    /// 生成独立 recovery reply。该 capability 不接触 DeviceReplyTx key/counter。
    pub(crate) fn seal_device_key_recovery_reply(
        &self,
        request: DeviceKeyRecoverySealRequest<'_>,
    ) -> Result<DeviceKeyRecoveryReplyV1, RemoteTransportError> {
        if request.machine_route != self.anchor.machine_route
            || request.root_trust_epoch != self.anchor.trust_epoch
            || request.update_set.device_route != request.device_route
        {
            return Err(pairing_authority_mismatch());
        }
        let info = DeviceKeyRecoveryInfoV1 {
            e2ee_format_version: E2EE_FORMAT_VERSION,
            runtime_protocol_version: RUNTIME_PROTOCOL_VERSION,
            relay_protocol_version: RELAY_PROTOCOL_VERSION,
            relay_server_id: self.anchor.relay_server_id,
            machine_route: request.machine_route,
            device_route: request.device_route,
            request_route: request.request_route,
            grant_serial: request.grant_serial,
            root_trust_epoch: request.root_trust_epoch,
            known_key_directory_revision: request.known_revision,
            target_key_directory_revision: request.update_set.key_directory_revision,
            update_set_sha256: request
                .update_set
                .canonical_sha256()
                .map_err(|_| pairing_authority_mismatch())?,
            machine_data_signer: self.data_signer.clone(),
        };
        let context = OuterContextV1::device_key_recovery(
            request.machine_route,
            request.device_route,
            request.request_route,
        );
        info.validate_for_update_set(request.update_set)
            .map_err(|_| pairing_authority_mismatch())?;
        info.validate_context(&context)
            .map_err(|_| pairing_authority_mismatch())?;
        let owner = self.verified_owner()?;
        let mut rng = pairing_crypto_rng(|bytes| getrandom::fill(bytes).map_err(|_| ()))?;
        let sealed = owner.owner.seal_device_key_recovery_reply(
            &self.anchor,
            request.recipient,
            &info,
            &context,
            request.update_set,
            &mut rng,
        );
        rng.finish(sealed)?.map_err(map_pairing_authority_error)
    }

    pub(crate) fn sign_key_directory(
        &self,
        context: &KeyDirectorySignatureContextV1,
        directory: KeyDirectoryV1,
    ) -> Result<KeyDirectoryV1, RemoteTransportError> {
        let owner = self.verified_owner()?;
        owner
            .owner
            .sign_key_directory(&self.anchor, context, directory)
            .map_err(map_pairing_authority_error)
    }

    /// 使用当前 root-certified MachineDataSign 对一个完整 typed KeyUpdate 签名；
    /// raw key 与任意 preimage 均不离开 authority owner。
    pub(crate) fn sign_key_update(
        &self,
        info: &KeyUpdateInfoV1,
        context: &OuterContextV1,
        update: KeyUpdateV1,
    ) -> Result<KeyUpdateV1, RemoteTransportError> {
        self.validate_key_update_axes(info, context)?;
        let owner = self.verified_owner()?;
        owner
            .owner
            .sign_key_update(&self.anchor, info, context, update)
            .map_err(map_pairing_authority_error)
    }

    pub(crate) fn sign_sealed(
        &self,
        unsigned: UnsignedSealedBlobV1,
        context: &OuterContextV1,
    ) -> Result<SignedSealedBlobV1, RemoteTransportError> {
        if !matches!(
            context.frame_kind,
            agentdeck_protocol::e2ee::OuterFrameKind::CatalogPublish
                | agentdeck_protocol::e2ee::OuterFrameKind::ConversationPublish
                | agentdeck_protocol::e2ee::OuterFrameKind::DirectedReply
                | agentdeck_protocol::e2ee::OuterFrameKind::KeyUpdate
        ) || context.machine_route != Some(self.anchor.machine_route)
        {
            return Err(pairing_authority_mismatch());
        }
        let owner = self.verified_owner()?;
        owner
            .owner
            .sign_sealed(&self.anchor, unsigned, context)
            .map_err(map_pairing_authority_error)
    }

    pub(crate) fn seal_key_directory_entry(
        &self,
        recipient: &HpkePublicKey,
        info: &KeyUpdateInfoV1,
        context: &OuterContextV1,
        key: &SecretAeadKey,
    ) -> Result<KeyDirectoryEntry, RemoteTransportError> {
        self.seal_key_directory_entry_with_entropy_source(recipient, info, context, key, |bytes| {
            getrandom::fill(bytes).map_err(|_| ())
        })
    }

    fn seal_key_directory_entry_with_entropy_source<F>(
        &self,
        recipient: &HpkePublicKey,
        info: &KeyUpdateInfoV1,
        context: &OuterContextV1,
        key: &SecretAeadKey,
        source: F,
    ) -> Result<KeyDirectoryEntry, RemoteTransportError>
    where
        F: FnMut(&mut [u8]) -> Result<(), ()>,
    {
        self.validate_key_update_axes(info, context)?;
        let _owner = self.verified_owner()?;
        let mut rng = pairing_crypto_rng(source)?;
        let sealed = crypto_seal_key_directory_entry(recipient, info, context, key, &mut rng);
        rng.finish(sealed)?
            .map_err(|_| supervisor_failure("remote.transport.pairing_crypto_failed"))
    }

    #[cfg(test)]
    fn seal_key_directory_entry_with_rng_for_test<R: agentdeck_crypto::rand_core::CryptoRng>(
        &self,
        recipient: &HpkePublicKey,
        info: &KeyUpdateInfoV1,
        context: &OuterContextV1,
        key: &SecretAeadKey,
        rng: &mut R,
    ) -> Result<KeyDirectoryEntry, RemoteTransportError> {
        self.validate_key_update_axes(info, context)?;
        let _owner = self.verified_owner()?;
        crypto_seal_key_directory_entry(recipient, info, context, key, rng)
            .map_err(|_| supervisor_failure("remote.transport.pairing_crypto_failed"))
    }

    fn validate_key_update_axes(
        &self,
        info: &KeyUpdateInfoV1,
        context: &OuterContextV1,
    ) -> Result<(), RemoteTransportError> {
        if info.relay_server_id != self.anchor.relay_server_id
            || info.machine_route != self.anchor.machine_route
            || info.root_trust_epoch != self.anchor.trust_epoch
            || context.frame_kind != agentdeck_protocol::e2ee::OuterFrameKind::KeyUpdate
            || context.machine_route != Some(self.anchor.machine_route)
            || context.validate().is_err()
        {
            return Err(pairing_authority_mismatch());
        }
        Ok(())
    }

    fn verified_owner(&self) -> Result<Arc<MachineLinkAuthenticator>, RemoteTransportError> {
        let owner = self.owner.upgrade().ok_or(RemoteTransportError::Closed)?;
        owner
            .verify_pairing_anchor(&self.anchor)
            .map_err(map_pairing_authority_error)?;
        let signer = MachineDataSignerBindingV1::from_certificate(&self.anchor.data_certificate)
            .map_err(|_| supervisor_failure("remote.transport.pairing_crypto_failed"))?;
        if signer != self.data_signer {
            return Err(pairing_authority_mismatch());
        }
        Ok(owner)
    }
}

impl fmt::Debug for MachineDataAuthority {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("MachineDataAuthority([REDACTED])")
    }
}

/// 只经 Weak 委托同一 transport generation key owner 的 pairing authority。
/// 它没有 raw sign/key getter，shutdown/reclaim 销毁 owner 后所有入口固定 fail-close。
pub(crate) struct PairingMachineAuthority {
    owner: Weak<MachineLinkAuthenticator>,
    anchor: MachinePairingAnchor,
    machine_data: MachineDataAuthority,
}

impl PairingMachineAuthority {
    pub(crate) fn machine_data_authority(&self) -> MachineDataAuthority {
        self.machine_data.clone()
    }

    pub(crate) fn invite_anchor(&self) -> Result<PairingInviteAnchor, RemoteTransportError> {
        self.verified_owner()?;
        Ok(PairingInviteAnchor {
            inner: self.anchor.clone(),
        })
    }

    /// 使用可失败系统熵封装 PairPending。production surface 不接受调用方 RNG；
    /// getrandom 失败在进入 HPKE 前返回 typed failure。
    pub(crate) fn seal_pair_pending(
        &self,
        recipient: &HpkePublicKey,
        info: &PairRequestInfoV1,
        context: &OuterContextV1,
        request_hash: [u8; 32],
    ) -> Result<PairingControlEnvelopeV1, RemoteTransportError> {
        self.seal_pair_pending_with_entropy_source(
            recipient,
            info,
            context,
            request_hash,
            |bytes| getrandom::fill(bytes).map_err(|_| ()),
        )
    }

    pub(crate) fn seal_pair_terminal(
        &self,
        recipient: &HpkePublicKey,
        info: &PairRequestInfoV1,
        context: &OuterContextV1,
        terminal: PairTerminalV1,
        expected_data_certificate: &SignedCertificate,
        hpke_seed: Zeroizing<[u8; 32]>,
    ) -> Result<PairingControlEnvelopeV1, RemoteTransportError> {
        let mut rng = pairing_crypto_rng_from_seed(hpke_seed);
        let sealed = self.seal_pair_terminal_with_rng(
            recipient,
            info,
            context,
            terminal,
            expected_data_certificate,
            &mut rng,
        );
        rng.finish(sealed)?
    }

    fn seal_pair_terminal_with_rng(
        &self,
        recipient: &HpkePublicKey,
        info: &PairRequestInfoV1,
        context: &OuterContextV1,
        terminal: PairTerminalV1,
        expected_data_certificate: &SignedCertificate,
        rng: &mut dyn agentdeck_crypto::rand_core::CryptoRng,
    ) -> Result<PairingControlEnvelopeV1, RemoteTransportError> {
        if expected_data_certificate != &self.anchor.data_certificate
            || info.relay_server_id != self.anchor.relay_server_id
            || info.pair_route != context.pair_route.unwrap_or(info.pair_route)
            || info.expiry_ms == 0
            || context.frame_kind != OuterFrameKind::PairTerminal
            || context.pair_route != Some(info.pair_route)
            || context.validate().is_err()
            || terminal.machine_route != self.anchor.machine_route
            || terminal.request_hash == [0; 32]
            || terminal.signature.0 != [0; 64]
        {
            return Err(pairing_authority_mismatch());
        }
        let owner = self.verified_owner()?;
        owner
            .owner
            .seal_pair_terminal(
                recipient,
                info,
                context,
                terminal,
                &self.machine_data.data_signer,
                rng,
            )
            .map_err(map_pairing_authority_error)
    }

    fn seal_pair_pending_with_entropy_source<F>(
        &self,
        recipient: &HpkePublicKey,
        info: &PairRequestInfoV1,
        context: &OuterContextV1,
        request_hash: [u8; 32],
        source: F,
    ) -> Result<PairingControlEnvelopeV1, RemoteTransportError>
    where
        F: FnMut(&mut [u8]) -> Result<(), ()>,
    {
        if info.relay_server_id != self.anchor.relay_server_id {
            return Err(pairing_authority_mismatch());
        }
        let owner = self.verified_owner()?;
        let mut rng = pairing_crypto_rng(source)?;
        let sealed = owner.owner.seal_pair_pending(
            recipient,
            info,
            context,
            request_hash,
            &self.machine_data.data_signer,
            &mut rng,
        );
        rng.finish(sealed)?.map_err(map_pairing_authority_error)
    }

    #[cfg(test)]
    fn seal_pair_pending_with_rng_for_test<R: agentdeck_crypto::rand_core::CryptoRng>(
        &self,
        recipient: &HpkePublicKey,
        info: &PairRequestInfoV1,
        context: &OuterContextV1,
        request_hash: [u8; 32],
        rng: &mut R,
    ) -> Result<PairingControlEnvelopeV1, RemoteTransportError> {
        if info.relay_server_id != self.anchor.relay_server_id {
            return Err(pairing_authority_mismatch());
        }
        let owner = self.verified_owner()?;
        owner
            .owner
            .seal_pair_pending(
                recipient,
                info,
                context,
                request_hash,
                &self.machine_data.data_signer,
                rng,
            )
            .map_err(map_pairing_authority_error)
    }

    pub(crate) fn sign_relay_grant(
        &self,
        grant: agentdeck_protocol::relay_v2::RelayGrant,
    ) -> Result<agentdeck_protocol::relay_v2::RelayGrant, RemoteTransportError> {
        let owner = self.verified_owner()?;
        owner
            .owner
            .sign_relay_grant(&self.anchor, grant)
            .map_err(map_pairing_authority_error)
    }

    pub(crate) fn sign_device_authorization(
        &self,
        grant: &agentdeck_protocol::relay_v2::RelayGrant,
        authorization: DeviceAuthorizationV1,
    ) -> Result<DeviceAuthorizationV1, RemoteTransportError> {
        let owner = self.verified_owner()?;
        owner
            .owner
            .sign_device_authorization(&self.anchor, grant, authorization)
            .map_err(map_pairing_authority_error)
    }

    /// 使用当前 MachineDataSign 对严格目录签名，不暴露 raw signing capability。
    pub(crate) fn sign_key_directory(
        &self,
        context: &KeyDirectorySignatureContextV1,
        directory: KeyDirectoryV1,
    ) -> Result<KeyDirectoryV1, RemoteTransportError> {
        self.machine_data.sign_key_directory(context, directory)
    }

    /// 使用同一 Weak key owner 的当前 MachineDataSign 对 typed sealed blob 签名。
    /// authority 只接受 protocol type-state 与 canonical context，不暴露 raw key/任意 bytes
    /// 签名入口；transport shutdown 销毁 owner 后固定返回 `Closed`。
    #[cfg_attr(
        not(test),
        allow(
            dead_code,
            reason = "compatibility delegation while business sealer composition is pending"
        )
    )]
    pub(crate) fn sign_sealed(
        &self,
        unsigned: UnsignedSealedBlobV1,
        context: &OuterContextV1,
    ) -> Result<SignedSealedBlobV1, RemoteTransportError> {
        self.machine_data.sign_sealed(unsigned, context)
    }

    /// 使用可失败系统熵把固定 32-byte 对称 key 封装为 typed directory entry。
    /// production surface 不接受调用方 RNG。
    pub(crate) fn seal_key_directory_entry(
        &self,
        recipient: &HpkePublicKey,
        info: &KeyUpdateInfoV1,
        context: &OuterContextV1,
        key: &SecretAeadKey,
    ) -> Result<KeyDirectoryEntry, RemoteTransportError> {
        self.machine_data
            .seal_key_directory_entry(recipient, info, context, key)
    }

    #[cfg(test)]
    fn seal_key_directory_entry_with_entropy_source<F>(
        &self,
        recipient: &HpkePublicKey,
        info: &KeyUpdateInfoV1,
        context: &OuterContextV1,
        key: &SecretAeadKey,
        source: F,
    ) -> Result<KeyDirectoryEntry, RemoteTransportError>
    where
        F: FnMut(&mut [u8]) -> Result<(), ()>,
    {
        self.machine_data
            .seal_key_directory_entry_with_entropy_source(recipient, info, context, key, source)
    }

    #[cfg(test)]
    fn seal_key_directory_entry_with_rng_for_test<R: agentdeck_crypto::rand_core::CryptoRng>(
        &self,
        recipient: &HpkePublicKey,
        info: &KeyUpdateInfoV1,
        context: &OuterContextV1,
        key: &SecretAeadKey,
        rng: &mut R,
    ) -> Result<KeyDirectoryEntry, RemoteTransportError> {
        self.machine_data
            .seal_key_directory_entry_with_rng_for_test(recipient, info, context, key, rng)
    }

    /// PairResponse 与 PairPending 共用相同的 fail-close 系统熵边界。
    pub(crate) fn seal_pair_response(
        &self,
        recipient: &HpkePublicKey,
        info: &PairResponseInfoV1,
        context: &OuterContextV1,
        plaintext: &PairResponsePlaintextV1,
    ) -> Result<PairResponseV1, RemoteTransportError> {
        self.seal_pair_response_with_entropy_source(recipient, info, context, plaintext, |bytes| {
            getrandom::fill(bytes).map_err(|_| ())
        })
    }

    fn seal_pair_response_with_entropy_source<F>(
        &self,
        recipient: &HpkePublicKey,
        info: &PairResponseInfoV1,
        context: &OuterContextV1,
        plaintext: &PairResponsePlaintextV1,
        source: F,
    ) -> Result<PairResponseV1, RemoteTransportError>
    where
        F: FnMut(&mut [u8]) -> Result<(), ()>,
    {
        let owner = self.verified_owner()?;
        let mut rng = pairing_crypto_rng(source)?;
        let sealed = owner.owner.seal_pair_response(
            &self.anchor,
            recipient,
            info,
            context,
            plaintext,
            &mut rng,
        );
        rng.finish(sealed)?.map_err(map_pairing_authority_error)
    }

    #[cfg(test)]
    fn seal_pair_response_with_rng_for_test<R: agentdeck_crypto::rand_core::CryptoRng>(
        &self,
        recipient: &HpkePublicKey,
        info: &PairResponseInfoV1,
        context: &OuterContextV1,
        plaintext: &PairResponsePlaintextV1,
        rng: &mut R,
    ) -> Result<PairResponseV1, RemoteTransportError> {
        let owner = self.verified_owner()?;
        owner
            .owner
            .seal_pair_response(&self.anchor, recipient, info, context, plaintext, rng)
            .map_err(map_pairing_authority_error)
    }

    pub(crate) fn sign_device_revocation(
        &self,
        revocation: DeviceRevocation,
    ) -> Result<DeviceRevocation, RemoteTransportError> {
        let owner = self.verified_owner()?;
        owner
            .owner
            .sign_device_revocation(&self.anchor, revocation)
            .map_err(map_pairing_authority_error)
    }

    fn verified_owner(&self) -> Result<Arc<MachineLinkAuthenticator>, RemoteTransportError> {
        let owner = self.owner.upgrade().ok_or(RemoteTransportError::Closed)?;
        owner
            .verify_pairing_anchor(&self.anchor)
            .map_err(map_pairing_authority_error)?;
        Ok(owner)
    }
}

/// 固定 X25519 HPKE suite 的一次性 IKM owner。
///
/// `hpke` 0.14 的 X25519 KEM 必须恰好请求一次 32-byte IKM，并会在派生 ephemeral
/// keypair 后清零其目标 buffer。本 owner 只在该 exact request 上交付 seed；任何 word
/// API、错误长度或重复请求都只返回零并记录契约违例。调用方在 seal 返回后必须调用
/// [`Self::finish`]，否则不能接受已经构造出的 artifact。
struct OneShotHpkeSeedRng {
    seed: Option<Zeroizing<[u8; 32]>>,
    request_count: u8,
    shape_mismatch: bool,
    #[cfg(test)]
    seed_wipe_observer: Option<Arc<AtomicBool>>,
}

impl OneShotHpkeSeedRng {
    fn new(seed: Zeroizing<[u8; 32]>) -> Self {
        Self {
            seed: Some(seed),
            request_count: 0,
            shape_mismatch: false,
            #[cfg(test)]
            seed_wipe_observer: None,
        }
    }

    #[cfg(test)]
    fn with_seed_wipe_observer(seed: Zeroizing<[u8; 32]>) -> (Self, Arc<AtomicBool>) {
        let observer = Arc::new(AtomicBool::new(false));
        (
            Self {
                seed: Some(seed),
                request_count: 0,
                shape_mismatch: false,
                seed_wipe_observer: Some(Arc::clone(&observer)),
            },
            observer,
        )
    }

    fn finish<T, E>(self, result: Result<T, E>) -> Result<Result<T, E>, RemoteTransportError> {
        let exact_success = self.request_count == 1 && !self.shape_mismatch && self.seed.is_none();
        if self.shape_mismatch || (result.is_ok() && !exact_success) {
            return Err(RemoteTransportError::PairingEntropyContractViolation);
        }
        Ok(result)
    }

    fn record_request(&mut self) {
        self.request_count = self.request_count.saturating_add(1);
    }

    #[cfg(test)]
    fn observe_seed_wipe(&self, seed: &[u8; 32]) {
        if let Some(observer) = &self.seed_wipe_observer {
            observer.store(seed.iter().all(|byte| *byte == 0), Ordering::SeqCst);
        }
    }
}

impl TryRng for OneShotHpkeSeedRng {
    type Error = Infallible;

    fn try_next_u32(&mut self) -> Result<u32, Self::Error> {
        self.record_request();
        self.shape_mismatch = true;
        Ok(0)
    }

    fn try_next_u64(&mut self) -> Result<u64, Self::Error> {
        self.record_request();
        self.shape_mismatch = true;
        Ok(0)
    }

    fn try_fill_bytes(&mut self, destination: &mut [u8]) -> Result<(), Self::Error> {
        self.record_request();
        if self.request_count == 1
            && destination.len() == 32
            && !self.shape_mismatch
            && let Some(mut seed) = self.seed.take()
        {
            destination.copy_from_slice(seed.as_ref());
            seed.zeroize();
            #[cfg(test)]
            self.observe_seed_wipe(&seed);
            return Ok(());
        }
        self.shape_mismatch = true;
        destination.fill(0);
        Ok(())
    }
}

impl TryCryptoRng for OneShotHpkeSeedRng {}

impl Drop for OneShotHpkeSeedRng {
    fn drop(&mut self) {
        if let Some(seed) = self.seed.as_mut() {
            seed.zeroize();
            #[cfg(test)]
            if let Some(observer) = &self.seed_wipe_observer {
                observer.store(seed.iter().all(|byte| *byte == 0), Ordering::SeqCst);
            }
        }
    }
}

/// 先以 fallible OS source 取得 X25519 HPKE 所需的 256-bit IKM。production 不使用
/// hpke 内部会 panic 的 `UnwrapErr(SysRng)`。
fn pairing_crypto_rng<F>(mut source: F) -> Result<OneShotHpkeSeedRng, RemoteTransportError>
where
    F: FnMut(&mut [u8]) -> Result<(), ()>,
{
    let mut seed = Zeroizing::new([0_u8; 32]);
    source(seed.as_mut()).map_err(|()| RemoteTransportError::PairingEntropyUnavailable)?;
    Ok(OneShotHpkeSeedRng::new(seed))
}

/// 接管 Store 对 exact PairTerminal identity 派生的用途隔离 IKM owner。seed 的
/// durable/replay 不变量由 `PairTerminalPreparation` 保证；transport 不接受 PairTerminal
/// 的系统熵路径，避免 seal 完成但 carrier COMMIT 前崩溃后产生不同密文。
fn pairing_crypto_rng_from_seed(seed: Zeroizing<[u8; 32]>) -> OneShotHpkeSeedRng {
    OneShotHpkeSeedRng::new(seed)
}

impl fmt::Debug for PairingMachineAuthority {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("PairingMachineAuthority([REDACTED])")
    }
}

pub(crate) struct PairingRuntimeParts {
    pub(crate) lane: PairingTransportLane,
    pub(crate) authority: PairingMachineAuthority,
}

impl fmt::Debug for PairingRuntimeParts {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("PairingRuntimeParts([REDACTED])")
    }
}

fn map_pairing_authority_error(error: MachinePairingError) -> RemoteTransportError {
    supervisor_failure(error.code())
}

fn pairing_authority_mismatch() -> RemoteTransportError {
    supervisor_failure("remote.transport.pairing_authority_mismatch")
}

#[derive(Debug, Error)]
pub enum RemoteTransportError {
    #[error("Relay client failed: {0}")]
    Client(#[from] RelayClientError),
    #[error("Relay frame is forbidden on the control-only machine transport")]
    FrameForbidden,
    #[error("retirement route does not match the connected machine route")]
    RouteMismatch,
    #[error("remote transport is closed")]
    Closed,
    #[error("remote start permit is unavailable")]
    StartPermitUnavailable,
    #[error("Relay still holds the machine authenticator")]
    AuthenticatorStillShared,
    #[error("pairing transport lane has already been taken")]
    PairingLaneUnavailable,
    #[error("business transport lane is unavailable or has already been taken")]
    BusinessLaneUnavailable,
    #[error("machine publication is offline until the current session authenticates again")]
    PublicationOffline,
    #[error("exclusive control is pending before pairing activation")]
    PairingActivationBlocked,
    #[error("pairing frame does not match the frozen machine/pair/device/serial binding")]
    PairingBindingMismatch,
    #[error("pairing transport binding capacity is exhausted")]
    PairingCapacity,
    #[error("pairing event consumer is lagged or unavailable")]
    PairingLagged,
    #[error("business event consumer is lagged or exceeded its byte budget")]
    BusinessLagged,
    #[error("business reply belongs to a replaced transport generation")]
    BusinessGenerationReplaced,
    #[error("publication does not match its exact machine/stream/generation/sequence/blob binding")]
    PublicationBindingMismatch,
    #[error("publication pending capacity is exhausted")]
    PublicationCapacity,
    #[error("publication ACK is wrong, stale, duplicated, or not pending on this connection")]
    PublicationAckMismatch,
    #[error("pairing transport generation is exhausted")]
    PairingGenerationExhausted,
    #[error("pairing transport could not obtain cryptographic entropy")]
    PairingEntropyUnavailable,
    #[error("pairing HPKE consumer violated the one-shot 32-byte entropy contract")]
    PairingEntropyContractViolation,
    #[error("remote supervisor failed: {code}")]
    SupervisorFailed { code: String },
    #[error("machine retirement construction failed: {0}")]
    Retirement(#[from] MachineRetirementError),
}

impl RemoteTransportError {
    #[must_use]
    pub fn code(&self) -> &str {
        match self {
            Self::Client(error) => error.code(),
            Self::FrameForbidden => "remote.transport.frame_forbidden",
            Self::RouteMismatch => "remote.transport.route_mismatch",
            Self::Closed => "remote.transport.closed",
            Self::StartPermitUnavailable => "remote.transport.start_permit_unavailable",
            Self::AuthenticatorStillShared => "remote.transport.authenticator_still_shared",
            Self::PairingLaneUnavailable => "remote.transport.pairing_lane_unavailable",
            Self::BusinessLaneUnavailable => "remote.transport.business_lane_unavailable",
            Self::PublicationOffline => "remote.transport.publication_offline",
            Self::PairingActivationBlocked => "remote.transport.pairing_activation_blocked",
            Self::PairingBindingMismatch => "remote.transport.pairing_binding_mismatch",
            Self::PairingCapacity => "remote.transport.pairing_capacity",
            Self::PairingLagged => "remote.transport.pairing_lagged",
            Self::BusinessLagged => "remote.transport.business_lagged",
            Self::BusinessGenerationReplaced => "remote.transport.business_generation_replaced",
            Self::PublicationBindingMismatch => "remote.transport.publication_binding_mismatch",
            Self::PublicationCapacity => "remote.transport.publication_capacity",
            Self::PublicationAckMismatch => "remote.transport.publication_ack_mismatch",
            Self::PairingGenerationExhausted => "remote.transport.pairing_generation_exhausted",
            Self::PairingEntropyUnavailable => "remote.transport.pairing_entropy_unavailable",
            Self::PairingEntropyContractViolation => {
                "remote.transport.pairing_entropy_contract_violation"
            }
            Self::SupervisorFailed { code } => code,
            Self::Retirement(error) => error.code(),
        }
    }
}

fn supervisor_failure(code: impl Into<String>) -> RemoteTransportError {
    RemoteTransportError::SupervisorFailed { code: code.into() }
}

/// 初次 Relay connect 失败时保留的唯一重试状态。Debug/Display 只公开稳定 code；
/// authenticator、旧 key owner、证书与 RemoteStartPermit 都保持 opaque 且不可 Clone。
pub struct RemoteTransportConnectError {
    client: RelayClientError,
    retry: RemoteTransportRetryState,
}

impl RemoteTransportConnectError {
    #[must_use]
    pub fn code(&self) -> &str {
        self.client.code()
    }

    /// 按值消费本次失败并复用完全相同的 authenticator、证书和 start permit 重拨。
    pub async fn retry(self) -> Result<RemoteTransport, Self> {
        self.retry
            .connect_with_connector(&RelayControlConnector)
            .await
    }

    #[cfg(test)]
    async fn retry_with_connector(
        self,
        connector: &dyn ControlConnector,
    ) -> Result<RemoteTransport, Self> {
        self.retry.connect_with_connector(connector).await
    }
}

impl fmt::Debug for RemoteTransportConnectError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("RemoteTransportConnectError")
            .field("code", &self.code())
            .field("retry", &"[REDACTED]")
            .finish()
    }
}

impl fmt::Display for RemoteTransportConnectError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(self.code())
    }
}

impl std::error::Error for RemoteTransportConnectError {}

struct RemoteTransportRetryState {
    config: RelayClientConfig,
    machine_route: MachineRouteId,
    authenticator: Arc<MachineLinkAuthenticator>,
    start_permit: Option<RemoteStartPermit>,
    business_startup: BusinessLaneStartup,
}

/// 决定 authenticated MachineLink reader 启动前是否已经为 Active business stack
/// 保留唯一 bounded lane。`Dormant` 仍保持未领取业务 frame 必须 fail-close；
/// `Reserved` 只用于已有 Active enrollment 的 recovery/enroll 路径，避免 device 先于
/// pairing/business owner 恢复时把合法首帧误判成未领取。
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(super) enum BusinessLaneStartup {
    Dormant,
    Reserved,
}

impl RemoteTransportRetryState {
    async fn connect_with_connector(
        self,
        connector: &dyn ControlConnector,
    ) -> Result<RemoteTransport, RemoteTransportConnectError> {
        let Self {
            config,
            machine_route,
            authenticator,
            start_permit,
            business_startup,
        } = self;
        match connect_preserving_ownership(&config, authenticator, start_permit, connector).await {
            Ok(ConnectedTransportOwnership {
                session,
                authenticator,
                start_owner: start_permit,
            }) => Ok(RemoteTransport::from_connected(
                machine_route,
                session,
                authenticator,
                start_permit,
                business_startup,
            )),
            Err(FailedTransportOwnership {
                error: client,
                authenticator,
                start_owner: start_permit,
            }) => Err(RemoteTransportConnectError {
                client,
                retry: Self {
                    config,
                    machine_route,
                    authenticator,
                    start_permit,
                    business_startup,
                },
            }),
        }
    }
}

struct ConnectedTransportOwnership<P> {
    session: Box<dyn ControlSession>,
    authenticator: Arc<MachineLinkAuthenticator>,
    start_owner: P,
}

struct FailedTransportOwnership<P> {
    error: RelayClientError,
    authenticator: Arc<MachineLinkAuthenticator>,
    start_owner: P,
}

async fn connect_preserving_ownership<P>(
    config: &RelayClientConfig,
    authenticator: Arc<MachineLinkAuthenticator>,
    start_owner: P,
    connector: &dyn ControlConnector,
) -> Result<ConnectedTransportOwnership<P>, FailedTransportOwnership<P>> {
    match connector
        .connect(config.clone(), Arc::clone(&authenticator))
        .await
    {
        Ok(session) => Ok(ConnectedTransportOwnership {
            session,
            authenticator,
            start_owner,
        }),
        Err(error) => Err(FailedTransportOwnership {
            error,
            authenticator,
            start_owner,
        }),
    }
}

const PAIRING_EVENT_CHANNEL_CAPACITY: usize = 8;
const PAIRING_BINDING_CAPACITY: usize = 8;
const PAIRING_COMPLETED_BINDING_CAPACITY: usize = 8;
const BUSINESS_EVENT_CHANNEL_CAPACITY: usize = 512;
const BUSINESS_EVENT_BYTES_CAPACITY: usize = 16 * 1024 * 1024;
const INITIAL_PAIRING_GENERATION: u64 = 1;

#[derive(Clone)]
enum PairingCommand {
    Open(OpenPairRoute),
    Data(PairData),
    TerminalData(PairData),
    InstallGrant(InstallGrant),
    Close(ClosePairRoute),
    RevokeDevice(RevokeDevice),
}

impl PairingCommand {
    fn frame(&self) -> OpaqueRouteFrame {
        let body = match self {
            Self::Open(frame) => RelayFrameBody::OpenPairRoute(frame.clone()),
            Self::Data(frame) | Self::TerminalData(frame) => {
                RelayFrameBody::PairData(frame.clone())
            }
            Self::InstallGrant(frame) => RelayFrameBody::InstallGrant(frame.clone()),
            Self::Close(frame) => RelayFrameBody::ClosePairRoute(frame.clone()),
            Self::RevokeDevice(frame) => RelayFrameBody::RevokeDevice(frame.clone()),
        };
        OpaqueRouteFrame {
            version: RELAY_PROTOCOL_VERSION,
            body,
        }
    }
}

#[derive(Clone, PartialEq, Eq)]
struct PairRouteBinding {
    pair_route: PairRouteId,
    absolute_expiry_ms: Option<u64>,
    opened: bool,
    closing: bool,
}

#[derive(Clone, PartialEq, Eq)]
struct GrantBinding {
    device_route: DeviceRouteId,
    grant_serial: GrantSerial,
    grant_hash: [u8; 32],
}

#[derive(Clone, PartialEq, Eq)]
struct RevocationBinding {
    revocation: DeviceRevocation,
}

#[derive(Clone, PartialEq, Eq)]
struct TerminalReplayBinding {
    pair_route: PairRouteId,
    reply_reference: String,
}

#[derive(Clone, Default)]
struct PairingBindings {
    routes: Vec<PairRouteBinding>,
    grants: Vec<GrantBinding>,
    revocations: Vec<RevocationBinding>,
    terminal_replays: Vec<TerminalReplayBinding>,
    completed_routes: Vec<PairRouteId>,
    completed_grants: Vec<GrantBinding>,
    completed_revocations: Vec<RevocationBinding>,
}

impl PairingBindings {
    fn prepare_outbound(
        &self,
        machine_route: MachineRouteId,
        command: &PairingCommand,
    ) -> Result<Self, RemoteTransportError> {
        let frame = command.frame();
        if encode(&frame).len() > MAX_FRAME_BYTES {
            return Err(RemoteTransportError::Client(RelayClientError::Failure {
                code: "relay.client.frame_too_large".to_owned(),
            }));
        }

        let mut next = self.clone();
        match command {
            PairingCommand::Open(open) => {
                if open.machine_route != machine_route {
                    return Err(RemoteTransportError::RouteMismatch);
                }
                if is_zero_pair_route(open.pair_route) || open.absolute_expiry_ms == 0 {
                    return Err(RemoteTransportError::PairingBindingMismatch);
                }
                if let Some(bound) = next
                    .routes
                    .iter_mut()
                    .find(|bound| bound.pair_route == open.pair_route)
                {
                    if bound.absolute_expiry_ms != Some(open.absolute_expiry_ms) || bound.closing {
                        return Err(RemoteTransportError::PairingBindingMismatch);
                    }
                } else {
                    ensure_pairing_capacity(next.routes.len())?;
                    next.routes.push(PairRouteBinding {
                        pair_route: open.pair_route,
                        absolute_expiry_ms: Some(open.absolute_expiry_ms),
                        opened: false,
                        closing: false,
                    });
                }
            }
            PairingCommand::Data(data) => {
                let Some(bound) = next
                    .routes
                    .iter()
                    .find(|bound| bound.pair_route == data.pair_route)
                else {
                    return Err(RemoteTransportError::PairingBindingMismatch);
                };
                if !bound.opened || bound.closing {
                    return Err(RemoteTransportError::PairingBindingMismatch);
                }
                if next
                    .terminal_replays
                    .iter()
                    .any(|replay| replay.pair_route == data.pair_route)
                {
                    return Err(RemoteTransportError::PairingBindingMismatch);
                }
            }
            PairingCommand::TerminalData(data) => {
                if is_zero_pair_route(data.pair_route) {
                    return Err(RemoteTransportError::PairingBindingMismatch);
                }
                if let Some(bound) = next
                    .routes
                    .iter()
                    .find(|bound| bound.pair_route == data.pair_route)
                {
                    if bound.closing {
                        return Err(RemoteTransportError::PairingBindingMismatch);
                    }
                } else {
                    // Durable PairTerminal 必须能在 daemon/reconnect 丢失易失 route binding
                    // 后先逐字节重发，再进入 ClosePairRoute。该 typed command 只由 pairing
                    // actor 的 authenticated terminal recovery 构造。
                    ensure_pairing_capacity(next.routes.len())?;
                    next.routes.push(PairRouteBinding {
                        pair_route: data.pair_route,
                        absolute_expiry_ms: None,
                        opened: true,
                        closing: false,
                    });
                }
                let reply_reference = relay_frame_reply_reference(&frame);
                if let Some(replay) = next
                    .terminal_replays
                    .iter()
                    .find(|replay| replay.pair_route == data.pair_route)
                {
                    if replay.reply_reference != reply_reference {
                        return Err(RemoteTransportError::PairingBindingMismatch);
                    }
                } else {
                    ensure_pairing_capacity(next.terminal_replays.len())?;
                    next.terminal_replays.push(TerminalReplayBinding {
                        pair_route: data.pair_route,
                        reply_reference,
                    });
                }
            }
            PairingCommand::InstallGrant(install) => {
                let grant = &install.grant;
                if grant.machine_route != machine_route {
                    return Err(RemoteTransportError::RouteMismatch);
                }
                if is_zero_device_route(grant.device_route) || grant.grant_serial.value() == 0 {
                    return Err(RemoteTransportError::PairingBindingMismatch);
                }
                let expected = GrantBinding {
                    device_route: grant.device_route,
                    grant_serial: grant.grant_serial,
                    grant_hash: grant.canonical_sha256(),
                };
                if let Some(bound) = next
                    .grants
                    .iter()
                    .find(|bound| bound.device_route == grant.device_route)
                {
                    if bound.grant_serial != expected.grant_serial
                        || bound.grant_hash != expected.grant_hash
                    {
                        return Err(RemoteTransportError::PairingBindingMismatch);
                    }
                } else {
                    ensure_pairing_capacity(next.grants.len())?;
                    next.grants.push(expected);
                }
            }
            PairingCommand::Close(close) => {
                if close.machine_route != machine_route {
                    return Err(RemoteTransportError::RouteMismatch);
                }
                if is_zero_pair_route(close.pair_route) {
                    return Err(RemoteTransportError::PairingBindingMismatch);
                }
                if let Some(bound) = next
                    .routes
                    .iter_mut()
                    .find(|bound| bound.pair_route == close.pair_route)
                {
                    bound.closing = true;
                } else {
                    // Durable terminal close outbox must be replayable after daemon restart.
                    ensure_pairing_capacity(next.routes.len())?;
                    next.routes.push(PairRouteBinding {
                        pair_route: close.pair_route,
                        absolute_expiry_ms: None,
                        opened: false,
                        closing: true,
                    });
                }
            }
            PairingCommand::RevokeDevice(revoke) => {
                let revocation = &revoke.revocation;
                if revocation.machine_route != machine_route {
                    return Err(RemoteTransportError::RouteMismatch);
                }
                if is_zero_device_route(revocation.device_route)
                    || revocation.grant_serial.value() == 0
                {
                    return Err(RemoteTransportError::PairingBindingMismatch);
                }
                if let Some(bound) = next
                    .revocations
                    .iter()
                    .find(|bound| bound.revocation.device_route == revocation.device_route)
                {
                    if bound.revocation != *revocation {
                        return Err(RemoteTransportError::PairingBindingMismatch);
                    }
                } else {
                    ensure_pairing_capacity(next.revocations.len())?;
                    next.revocations.push(RevocationBinding {
                        revocation: revocation.clone(),
                    });
                }
            }
        }
        Ok(next)
    }

    fn accept_opened(
        &mut self,
        machine_route: MachineRouteId,
        opened: PairRouteOpened,
    ) -> Result<PairingTransportEvent, RemoteTransportError> {
        let Some(bound) = self
            .routes
            .iter_mut()
            .find(|bound| bound.pair_route == opened.pair_route)
        else {
            return Err(RemoteTransportError::FrameForbidden);
        };
        if opened.machine_route != machine_route
            || bound.absolute_expiry_ms != Some(opened.absolute_expiry_ms)
            || bound.closing
        {
            return Err(RemoteTransportError::PairingBindingMismatch);
        }
        bound.opened = true;
        Ok(PairingTransportEvent::PairRouteOpened(opened))
    }

    fn accept_data(&self, data: PairData) -> Result<PairingTransportEvent, RemoteTransportError> {
        let Some(bound) = self
            .routes
            .iter()
            .find(|bound| bound.pair_route == data.pair_route)
        else {
            return Err(RemoteTransportError::FrameForbidden);
        };
        if !bound.opened || bound.closing {
            return Err(RemoteTransportError::PairingBindingMismatch);
        }
        Ok(PairingTransportEvent::PairData(data))
    }

    fn accept_pair_frame(
        &mut self,
        accepted: RouteAccepted,
    ) -> Result<PairingTransportEvent, RemoteTransportError> {
        let AcceptedRef::PairFrame { pair_route } = accepted.accepted else {
            return Err(RemoteTransportError::FrameForbidden);
        };
        let Some(bound) = self
            .routes
            .iter()
            .find(|bound| bound.pair_route == pair_route)
        else {
            return Err(RemoteTransportError::FrameForbidden);
        };
        let terminal_closing = bound.closing
            && self
                .terminal_replays
                .iter()
                .any(|replay| replay.pair_route == pair_route);
        if !bound.opened || (bound.closing && !terminal_closing) {
            return Err(RemoteTransportError::PairingBindingMismatch);
        }
        Ok(PairingTransportEvent::PairFrameAccepted(accepted))
    }

    fn consume_expected_terminal_not_found(&mut self, failure: &RelayFailure) -> bool {
        if failure.code != RELAY_ROUTE_NOT_FOUND {
            return false;
        }
        let Some(reference) = failure.in_reply_to.as_deref() else {
            return false;
        };
        let Some(index) = self
            .terminal_replays
            .iter()
            .position(|replay| replay.reply_reference == reference)
        else {
            return false;
        };
        let pair_route = self.terminal_replays[index].pair_route;
        let closing = self
            .routes
            .iter()
            .any(|bound| bound.pair_route == pair_route && bound.opened && bound.closing);
        if !closing {
            return false;
        }
        self.terminal_replays.swap_remove(index);
        true
    }

    fn accept_closed(
        &mut self,
        closed: PairRouteClosed,
    ) -> Result<PairingTransportEvent, RemoteTransportError> {
        if let Some(index) = self
            .routes
            .iter()
            .position(|bound| bound.pair_route == closed.pair_route)
        {
            if !self.routes[index].closing {
                return Err(RemoteTransportError::PairingBindingMismatch);
            }
            self.routes.swap_remove(index);
            self.terminal_replays
                .retain(|replay| replay.pair_route != closed.pair_route);
            remember_completed(&mut self.completed_routes, closed.pair_route);
            return Ok(PairingTransportEvent::PairRouteClosed(closed));
        }
        if self.completed_routes.contains(&closed.pair_route) {
            return Ok(PairingTransportEvent::PairRouteClosed(closed));
        }
        Err(RemoteTransportError::FrameForbidden)
    }

    fn accept_grant(
        &mut self,
        committed: GrantCommitted,
    ) -> Result<PairingTransportEvent, RemoteTransportError> {
        let expected = GrantBinding {
            device_route: committed.device_route,
            grant_serial: committed.grant_serial,
            grant_hash: committed.grant_hash,
        };
        if let Some(index) = self
            .grants
            .iter()
            .position(|bound| bound.device_route == committed.device_route)
        {
            if self.grants[index] != expected {
                if self.completed_grants.contains(&expected) {
                    return Ok(PairingTransportEvent::GrantCommitted(committed));
                }
                return Err(RemoteTransportError::PairingBindingMismatch);
            }
            let completed = self.grants.swap_remove(index);
            remember_completed(&mut self.completed_grants, completed);
            return Ok(PairingTransportEvent::GrantCommitted(committed));
        }
        if self.completed_grants.contains(&expected) {
            return Ok(PairingTransportEvent::GrantCommitted(committed));
        }
        if self
            .completed_grants
            .iter()
            .any(|bound| bound.device_route == committed.device_route)
        {
            return Err(RemoteTransportError::PairingBindingMismatch);
        }
        Err(RemoteTransportError::FrameForbidden)
    }

    fn accept_revocation(
        &mut self,
        committed: RevocationCommitted,
    ) -> Result<PairingTransportEvent, RemoteTransportError> {
        let expected = RevocationBinding {
            revocation: committed.signed_revocation.clone(),
        };
        let exact_terminal = committed.device_route == expected.revocation.device_route
            && committed.grant_serial == expected.revocation.grant_serial
            && expected.revocation.machine_route != MachineRouteId::from_bytes([0; 16]);
        if !exact_terminal {
            return Err(RemoteTransportError::PairingBindingMismatch);
        }
        if let Some(index) = self
            .revocations
            .iter()
            .position(|bound| bound.revocation.device_route == committed.device_route)
        {
            if self.revocations[index] != expected {
                if self.completed_revocations.contains(&expected) {
                    return Ok(PairingTransportEvent::RevocationCommitted(committed));
                }
                return Err(RemoteTransportError::PairingBindingMismatch);
            }
            let completed = self.revocations.swap_remove(index);
            remember_completed(&mut self.completed_revocations, completed);
            return Ok(PairingTransportEvent::RevocationCommitted(committed));
        }
        if self.completed_revocations.contains(&expected) {
            return Ok(PairingTransportEvent::RevocationCommitted(committed));
        }
        if self
            .completed_revocations
            .iter()
            .any(|bound| bound.revocation.device_route == committed.device_route)
        {
            return Err(RemoteTransportError::PairingBindingMismatch);
        }
        Err(RemoteTransportError::FrameForbidden)
    }
}

fn remember_completed<T: PartialEq>(completed: &mut Vec<T>, value: T) {
    if completed.contains(&value) {
        return;
    }
    if completed.len() == PAIRING_COMPLETED_BINDING_CAPACITY {
        completed.remove(0);
    }
    completed.push(value);
}

fn ensure_pairing_capacity(current: usize) -> Result<(), RemoteTransportError> {
    if current >= PAIRING_BINDING_CAPACITY {
        Err(RemoteTransportError::PairingCapacity)
    } else {
        Ok(())
    }
}

fn is_zero_pair_route(route: PairRouteId) -> bool {
    route.as_bytes() == &[0; 16]
}

fn is_zero_device_route(route: DeviceRouteId) -> bool {
    route.as_bytes() == &[0; 16]
}

fn is_zero_request_route(route: RequestRouteId) -> bool {
    route.as_bytes() == &[0; 16]
}

fn business_reply_frame(reply: Reply) -> Result<OpaqueRouteFrame, RemoteTransportError> {
    if is_zero_device_route(reply.device_route) || is_zero_request_route(reply.request_route) {
        return Err(RemoteTransportError::FrameForbidden);
    }
    let frame = OpaqueRouteFrame {
        version: RELAY_PROTOCOL_VERSION,
        body: RelayFrameBody::Reply(reply),
    };
    if encode(&frame).len() > MAX_FRAME_BYTES {
        return Err(RemoteTransportError::Client(RelayClientError::Failure {
            code: "relay.client.frame_too_large".to_owned(),
        }));
    }
    Ok(frame)
}

const PUBLICATION_PENDING_CAPACITY: usize = 128;
const PUBLICATION_COMPLETED_CAPACITY: usize = 512;

/// Relay `Publish` COMMIT 的精确 transport receipt。它不是 local outbox ACK；publisher
/// 必须先把本 receipt 与 frozen dispatch key 完整匹配，之后才可推进本地状态。
#[derive(Clone, Copy, PartialEq, Eq)]
pub(crate) struct MachinePublicationCommit {
    pub(crate) connection_generation: u64,
    pub(crate) stream_route: StreamRouteId,
    pub(crate) stream_generation: StreamGenerationId,
    pub(crate) stream_seq: u64,
    pub(crate) blob_sha256: [u8; 32],
}

impl fmt::Debug for MachinePublicationCommit {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("MachinePublicationCommit")
            .field("connection_generation", &self.connection_generation)
            .field("stream", &self.stream_route.redacted())
            .field("stream_generation", &self.stream_generation.redacted())
            .field("stream_seq", &self.stream_seq)
            .field("blob_sha256", &"[REDACTED]")
            .finish()
    }
}

/// Publication transport 的三态结果。只有 `Committed` 表示匹配 ACK 已从同一连接读回；
/// `OutcomeUnknown` 必须复用 durable exact blob，`Offline` 表示本次未进入可写连接。
#[derive(Clone, Copy, PartialEq, Eq)]
pub(crate) enum MachinePublicationOutcome {
    Committed(MachinePublicationCommit),
    OutcomeUnknown,
    Offline,
}

impl fmt::Debug for MachinePublicationOutcome {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Committed(commit) => formatter.debug_tuple("Committed").field(commit).finish(),
            Self::OutcomeUnknown => formatter.write_str("OutcomeUnknown"),
            Self::Offline => formatter.write_str("Offline"),
        }
    }
}

struct PreparedMachinePublication {
    registration: RegisterStream,
    publish: Publish,
    exact_blob: Arc<[u8]>,
    blob_sha256: [u8; 32],
}

fn prepare_machine_stream_registration(
    machine_route: MachineRouteId,
    stream_route: StreamRouteId,
    stream_generation: StreamGenerationId,
) -> Result<RegisterStream, RemoteTransportError> {
    if machine_route.as_bytes() == &[0; 16]
        || stream_route.as_bytes() == &[0; 16]
        || stream_generation.as_bytes() == &[0; 16]
    {
        return Err(RemoteTransportError::PublicationBindingMismatch);
    }
    let registration = RegisterStream {
        machine_route,
        stream_route,
        generation: stream_generation,
    };
    if encode(&OpaqueRouteFrame {
        version: RELAY_PROTOCOL_VERSION,
        body: RelayFrameBody::RegisterStream(registration.clone()),
    })
    .len()
        > MAX_FRAME_BYTES
    {
        return Err(RemoteTransportError::Client(RelayClientError::Failure {
            code: "relay.client.frame_too_large".to_owned(),
        }));
    }
    Ok(registration)
}

fn prepare_machine_publication(
    machine_route: MachineRouteId,
    stream_route: StreamRouteId,
    stream_generation: StreamGenerationId,
    stream_seq: u64,
    exact_blob: Arc<[u8]>,
    blob_sha256: [u8; 32],
) -> Result<PreparedMachinePublication, RemoteTransportError> {
    if stream_seq == u64::MAX
        || sha256(exact_blob.as_ref()) != blob_sha256
        || SignedSealedBlobV1::from_wire_bytes(exact_blob.as_ref()).is_err()
    {
        return Err(RemoteTransportError::PublicationBindingMismatch);
    }
    let registration =
        prepare_machine_stream_registration(machine_route, stream_route, stream_generation)?;
    let publish = Publish {
        stream_route,
        generation: stream_generation,
        stream_seq,
        sealed_blob: SealedBlob(exact_blob.to_vec()),
    };
    for body in [RelayFrameBody::Publish(publish.clone())] {
        if encode(&OpaqueRouteFrame {
            version: RELAY_PROTOCOL_VERSION,
            body,
        })
        .len()
            > MAX_FRAME_BYTES
        {
            return Err(RemoteTransportError::Client(RelayClientError::Failure {
                code: "relay.client.frame_too_large".to_owned(),
            }));
        }
    }
    Ok(PreparedMachinePublication {
        registration,
        publish,
        exact_blob,
        blob_sha256,
    })
}

/// 可交给 durable publisher 的窄 handle。它只能在已经领取的 business lane 上发送
/// `RegisterStream`/`Publish`，复用现有 command channel，不能 connect 第二个 RelayClient。
#[derive(Clone)]
pub(crate) struct MachinePublicationHandle {
    machine_route: MachineRouteId,
    command_tx: mpsc::Sender<SupervisorCommand>,
    connection_generation: Arc<AtomicU64>,
    authenticated_generation_rx: watch::Receiver<u64>,
    enabled: Arc<AtomicBool>,
    activation_epoch: Arc<AtomicU64>,
    admitted_activation_epoch: u64,
}

/// 空 genesis stream 的 register-only 结果。Relay v2 没有 RegisterStream ACK；
/// `Registered` 只表示 exact frame 已在当前 authenticated MachineLink FIFO 完成 writer
/// flush，后续 directed reply 会排在它之后。其余两态必须 fail-close 并 exact retry。
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum MachineStreamRegistrationOutcome {
    Registered { connection_generation: u64 },
    OutcomeUnknown,
    Offline,
}

/// 已领取 business activation 的窄 reconnect 观察者。旧 activation 被 restore/drop
/// 后即使同一 supervisor 后续再次认证，也不能唤醒旧 publication/transition owner。
pub(crate) struct AuthenticatedBusinessReconnects {
    generation_rx: watch::Receiver<u64>,
    observed_generation: u64,
    enabled: Arc<AtomicBool>,
    activation_epoch: Arc<AtomicU64>,
    admitted_activation_epoch: u64,
}

impl AuthenticatedBusinessReconnects {
    pub(crate) fn mark_attempt_baseline(&mut self) -> Result<u64, RemoteTransportError> {
        self.check_activation()?;
        let current = *self.generation_rx.borrow_and_update();
        self.observed_generation = current;
        Ok(current)
    }

    pub(crate) async fn changed(&mut self) -> Result<u64, RemoteTransportError> {
        loop {
            self.check_activation()?;
            self.generation_rx
                .changed()
                .await
                .map_err(|_| RemoteTransportError::Closed)?;
            self.check_activation()?;
            let current = *self.generation_rx.borrow_and_update();
            if current > self.observed_generation {
                self.observed_generation = current;
                return Ok(current);
            }
        }
    }

    fn check_activation(&self) -> Result<(), RemoteTransportError> {
        if !self.enabled.load(Ordering::Acquire)
            || self.activation_epoch.load(Ordering::Acquire) != self.admitted_activation_epoch
        {
            return Err(RemoteTransportError::BusinessLaneUnavailable);
        }
        Ok(())
    }
}

impl MachinePublicationHandle {
    pub(crate) const fn machine_route(&self) -> MachineRouteId {
        self.machine_route
    }

    pub(crate) fn current_connection_generation(&self) -> u64 {
        self.connection_generation.load(Ordering::Acquire)
    }

    /// 只由同一 supervisor 完成 authenticated reconnect 后递增。克隆 receiver 不会
    /// 消费唯一 business event lane，可供 RemoteLink 启动前的 durable owner 停车等待。
    pub(crate) fn subscribe_authenticated_reconnects(&self) -> AuthenticatedBusinessReconnects {
        let mut generation_rx = self.authenticated_generation_rx.clone();
        let observed_generation = self.current_connection_generation();
        let _ = *generation_rx.borrow_and_update();
        AuthenticatedBusinessReconnects {
            generation_rx,
            observed_generation,
            enabled: Arc::clone(&self.enabled),
            activation_epoch: Arc::clone(&self.activation_epoch),
            admitted_activation_epoch: self.admitted_activation_epoch,
        }
    }

    pub(crate) async fn register_stream_exact(
        &self,
        stream_route: StreamRouteId,
        stream_generation: StreamGenerationId,
    ) -> Result<MachineStreamRegistrationOutcome, RemoteTransportError> {
        let expected_connection_generation = self.current_connection_generation();
        self.register_stream_exact_for_generation(
            expected_connection_generation,
            stream_route,
            stream_generation,
        )
        .await
    }

    pub(crate) async fn register_stream_exact_for_generation(
        &self,
        expected_connection_generation: u64,
        stream_route: StreamRouteId,
        stream_generation: StreamGenerationId,
    ) -> Result<MachineStreamRegistrationOutcome, RemoteTransportError> {
        if !self.enabled.load(Ordering::Acquire)
            || self.activation_epoch.load(Ordering::Acquire) != self.admitted_activation_epoch
        {
            return Err(RemoteTransportError::BusinessLaneUnavailable);
        }
        let registration = prepare_machine_stream_registration(
            self.machine_route,
            stream_route,
            stream_generation,
        )?;
        let (response_tx, response_rx) = oneshot::channel();
        self.command_tx
            .send(SupervisorCommand::RegisterStream {
                expected_connection_generation,
                expected_activation_epoch: self.admitted_activation_epoch,
                registration,
                response: response_tx,
            })
            .await
            .map_err(|_| RemoteTransportError::Closed)?;
        match response_rx.await {
            Ok(Ok(()))
                if self.current_connection_generation() == expected_connection_generation =>
            {
                Ok(MachineStreamRegistrationOutcome::Registered {
                    connection_generation: expected_connection_generation,
                })
            }
            Ok(Ok(())) | Ok(Err(RemoteTransportError::BusinessGenerationReplaced)) => {
                Ok(MachineStreamRegistrationOutcome::OutcomeUnknown)
            }
            Ok(Err(RemoteTransportError::PublicationOffline)) => {
                Ok(MachineStreamRegistrationOutcome::Offline)
            }
            Ok(Err(RemoteTransportError::Client(_))) => {
                Ok(MachineStreamRegistrationOutcome::OutcomeUnknown)
            }
            Ok(Err(error)) => Err(error),
            Err(_) => Err(RemoteTransportError::Closed),
        }
    }

    /// 每次 retry 都先发送完全相同的幂等 `RegisterStream`，再发送 frozen exact `Publish`。
    /// Register 的 writer flush 绝不返回 `Committed`；只有 supervisor 读回匹配
    /// `AcceptedRef::StreamFrame` 才完成本 future。
    #[cfg_attr(
        not(test),
        expect(
            dead_code,
            reason = "focused transport contract；production adapter 使用 generation-bound 入口"
        )
    )]
    pub(crate) async fn publish_exact(
        &self,
        stream_route: StreamRouteId,
        stream_generation: StreamGenerationId,
        stream_seq: u64,
        exact_blob: Arc<[u8]>,
        blob_sha256: [u8; 32],
    ) -> Result<MachinePublicationOutcome, RemoteTransportError> {
        let expected_connection_generation = self.current_connection_generation();
        self.publish_exact_for_generation(
            expected_connection_generation,
            stream_route,
            stream_generation,
            stream_seq,
            exact_blob,
            blob_sha256,
        )
        .await
    }

    pub(crate) async fn publish_exact_for_generation(
        &self,
        expected_connection_generation: u64,
        stream_route: StreamRouteId,
        stream_generation: StreamGenerationId,
        stream_seq: u64,
        exact_blob: Arc<[u8]>,
        blob_sha256: [u8; 32],
    ) -> Result<MachinePublicationOutcome, RemoteTransportError> {
        if !self.enabled.load(Ordering::Acquire)
            || self.activation_epoch.load(Ordering::Acquire) != self.admitted_activation_epoch
        {
            return Err(RemoteTransportError::BusinessLaneUnavailable);
        }
        let prepared = prepare_machine_publication(
            self.machine_route,
            stream_route,
            stream_generation,
            stream_seq,
            exact_blob,
            blob_sha256,
        )?;
        match self
            .register_stream_exact_for_generation(
                expected_connection_generation,
                prepared.registration.stream_route,
                prepared.registration.generation,
            )
            .await?
        {
            MachineStreamRegistrationOutcome::Registered { .. } => {}
            MachineStreamRegistrationOutcome::Offline => {
                return Ok(MachinePublicationOutcome::Offline);
            }
            MachineStreamRegistrationOutcome::OutcomeUnknown => {
                return Ok(MachinePublicationOutcome::OutcomeUnknown);
            }
        }

        let (publish_tx, publish_rx) = oneshot::channel();
        if self
            .command_tx
            .send(SupervisorCommand::Publish {
                expected_connection_generation,
                expected_activation_epoch: self.admitted_activation_epoch,
                publish: prepared.publish,
                exact_blob: prepared.exact_blob,
                blob_sha256: prepared.blob_sha256,
                response: publish_tx,
            })
            .await
            .is_err()
        {
            return Err(RemoteTransportError::Closed);
        }
        publish_rx
            .await
            .unwrap_or(Ok(MachinePublicationOutcome::OutcomeUnknown))
    }
}

impl fmt::Debug for MachinePublicationHandle {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("MachinePublicationHandle([REDACTED])")
    }
}

/// 唯一 MachineLink 上的 typed business ingress。
///
/// `RouteAccepted` 只表示 Relay writer 已接受 request route，不是业务内核回执。
#[derive(Clone, PartialEq, Eq)]
pub(crate) enum BusinessTransportEvent {
    Send(RouteSend),
    RouteAccepted(RouteAccepted),
    GenerationReplaced { previous: u64, current: u64 },
}

impl fmt::Debug for BusinessTransportEvent {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Send(_) => formatter.write_str("BusinessTransportEvent::Send([REDACTED])"),
            Self::RouteAccepted(_) => formatter
                .write_str("BusinessTransportEvent::RouteAcceptedNotCommandSuccess([REDACTED])"),
            Self::GenerationReplaced { previous, current } => formatter
                .debug_struct("BusinessTransportEvent::GenerationReplaced")
                .field("previous", previous)
                .field("current", current)
                .finish(),
        }
    }
}

struct BusinessTransportSignal {
    generation: u64,
    event: BusinessTransportEvent,
    _bytes: OwnedSemaphorePermit,
}

/// 一次性从 [`RemoteTransport`] 取出的 bounded business lane。
///
/// lane 只持有唯一 supervisor 的 typed command handle 与 bounded event receiver；不持有
/// authenticator、start permit、RelayClient、业务内核或 canonical 业务状态。
pub(crate) struct BusinessTransportLane {
    machine_route: MachineRouteId,
    command_tx: mpsc::Sender<SupervisorCommand>,
    event_rx: mpsc::Receiver<BusinessTransportSignal>,
    health_rx: watch::Receiver<Option<String>>,
    generation: Arc<AtomicU64>,
    generation_rx: watch::Receiver<u64>,
    observed_generation: u64,
    enabled: Arc<AtomicBool>,
    activation_epoch: Arc<AtomicU64>,
    admitted_activation_epoch: u64,
}

impl BusinessTransportLane {
    /// 派生可 Clone 的窄 publication handle；它仍受唯一 business lane activation 生命周期
    /// 约束，且只持有同一 supervisor 的 command sender，不具备 connect 能力。
    pub(crate) fn publication_handle(&self) -> MachinePublicationHandle {
        MachinePublicationHandle {
            machine_route: self.machine_route,
            command_tx: self.command_tx.clone(),
            connection_generation: Arc::clone(&self.generation),
            authenticated_generation_rx: self.generation_rx.clone(),
            enabled: Arc::clone(&self.enabled),
            activation_epoch: Arc::clone(&self.activation_epoch),
            admitted_activation_epoch: self.admitted_activation_epoch,
        }
    }

    /// 发送已经完成 endpoint sealing 的 directed reply；supervisor 的 session `send`
    /// 只有在底层 writer flush 完成后才返回。
    pub(crate) async fn send_reply(
        &self,
        expected_generation: u64,
        reply: Reply,
    ) -> Result<(), RemoteTransportError> {
        business_reply_frame(reply.clone())?;
        let (response_tx, response_rx) = oneshot::channel();
        self.command_tx
            .send(SupervisorCommand::BusinessReply {
                expected_generation,
                expected_activation_epoch: self.admitted_activation_epoch,
                reply,
                response: response_tx,
            })
            .await
            .map_err(|_| RemoteTransportError::Closed)?;
        response_rx
            .await
            .map_err(|_| RemoteTransportError::Closed)?
    }

    pub(crate) async fn next_event(
        &mut self,
    ) -> Result<Option<BusinessTransportEvent>, RemoteTransportError> {
        loop {
            let transport_impaired = self.health_rx.borrow().is_some();
            tokio::select! {
                biased;
                changed = self.health_rx.changed() => {
                    if changed.is_err() {
                        return Err(RemoteTransportError::Closed);
                    }
                }
                changed = self.generation_rx.changed() => {
                    if changed.is_err() {
                        return Err(RemoteTransportError::Closed);
                    }
                    let current = *self.generation_rx.borrow_and_update();
                    let previous = self.observed_generation;
                    if current <= previous {
                        continue;
                    }
                    self.observed_generation = current;
                    return Ok(Some(BusinessTransportEvent::GenerationReplaced {
                        previous,
                        current,
                    }));
                }
                signal = self.event_rx.recv() => {
                    let Some(signal) = signal else {
                        return Err(RemoteTransportError::Closed);
                    };
                    if transport_impaired
                        || signal.generation != self.generation.load(Ordering::Acquire)
                    {
                        continue;
                    }
                    return Ok(Some(signal.event));
                }
            }
        }
    }

    pub(crate) const fn current_generation(&self) -> u64 {
        self.observed_generation
    }
}

impl fmt::Debug for BusinessTransportLane {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("BusinessTransportLane([REDACTED])")
    }
}

impl Drop for BusinessTransportLane {
    fn drop(&mut self) {
        self.enabled.store(false, Ordering::Release);
    }
}

/// 一次性从 [`RemoteTransport`] 取出的 bounded pairing lane。
///
/// 它只持有唯一 supervisor 的 typed command handle 与唯一 event receiver；不持有
/// authenticator、start permit、RelayClient 或 raw frame API。
pub(crate) struct PairingTransportLane {
    command_tx: mpsc::Sender<SupervisorCommand>,
    event_rx: mpsc::Receiver<PairingTransportSignal>,
    retained_events: VecDeque<PairingTransportSignal>,
    health_rx: watch::Receiver<Option<String>>,
    transition: Arc<Mutex<PairingTransition>>,
    generation: Arc<AtomicU64>,
    authority_anchor: Option<MachinePairingAnchor>,
}

enum PairingTransportSignal {
    Event {
        generation: u64,
        event: PairingTransportEvent,
    },
    SharedControl {
        generation: u64,
        control: Result<Option<RemoteControl>, RemoteTransportError>,
        pairing_failure: SafeFailure,
    },
}

impl PairingTransportSignal {
    fn generation(&self) -> u64 {
        match self {
            Self::Event { generation, .. } | Self::SharedControl { generation, .. } => *generation,
        }
    }
}

#[derive(Default)]
struct PairingTransition {
    pairing_events_enabled: bool,
    pairing_owns_shared_control: bool,
    pending_exclusive_control: bool,
    retained_pairing_events: usize,
    handed_off_control: VecDeque<Result<Option<RemoteControl>, RemoteTransportError>>,
}

impl PairingTransportLane {
    pub(crate) async fn send_open_pair_route(
        &self,
        frame: OpenPairRoute,
    ) -> Result<(), RemoteTransportError> {
        self.send_command(PairingCommand::Open(frame)).await
    }

    pub(crate) async fn send_pair_data(&self, frame: PairData) -> Result<(), RemoteTransportError> {
        self.send_command(PairingCommand::Data(frame)).await
    }

    #[cfg(test)]
    async fn send_pair_terminal_data(&self, frame: PairData) -> Result<(), RemoteTransportError> {
        self.send_command(PairingCommand::TerminalData(frame)).await
    }

    /// 把 durable PairTerminal writer flush 与同 route Close 放进一个 supervisor command。
    /// 两帧仍按 PairData→Close 顺序写入唯一 session；reader 只有在 closing binding 已安装后
    /// 才继续处理 Relay 回包，避免 expected terminal miss 抢跑 matching Close ACK。
    pub(crate) async fn send_pair_terminal_and_close(
        &self,
        terminal: PairData,
        close: ClosePairRoute,
    ) -> Result<(), RemoteTransportError> {
        let (response_tx, response_rx) = oneshot::channel();
        self.command_tx
            .send(SupervisorCommand::PairingTerminal {
                terminal,
                close,
                response: response_tx,
            })
            .await
            .map_err(|_| RemoteTransportError::Closed)?;
        response_rx
            .await
            .map_err(|_| RemoteTransportError::Closed)?
    }

    pub(crate) async fn send_install_grant(
        &self,
        frame: InstallGrant,
    ) -> Result<(), RemoteTransportError> {
        let anchor = self.authority_anchor()?;
        if frame.grant.machine_route != anchor.machine_route {
            return Err(RemoteTransportError::RouteMismatch);
        }
        if is_zero_device_route(frame.grant.device_route) || frame.grant.grant_serial.value() == 0 {
            return Err(RemoteTransportError::PairingBindingMismatch);
        }
        anchor
            .verify_relay_grant(&frame.grant)
            .map_err(map_pairing_authority_error)?;
        self.send_command(PairingCommand::InstallGrant(frame)).await
    }

    pub(crate) async fn send_close_pair_route(
        &self,
        frame: ClosePairRoute,
    ) -> Result<(), RemoteTransportError> {
        self.send_command(PairingCommand::Close(frame)).await
    }

    pub(crate) async fn send_revoke_device(
        &self,
        frame: RevokeDevice,
    ) -> Result<(), RemoteTransportError> {
        let anchor = self.authority_anchor()?;
        if frame.revocation.machine_route != anchor.machine_route {
            return Err(RemoteTransportError::RouteMismatch);
        }
        if is_zero_device_route(frame.revocation.device_route)
            || frame.revocation.grant_serial.value() == 0
        {
            return Err(RemoteTransportError::PairingBindingMismatch);
        }
        anchor
            .verify_device_revocation(&frame.revocation)
            .map_err(map_pairing_authority_error)?;
        self.send_command(PairingCommand::RevokeDevice(frame)).await
    }

    /// 复用唯一 supervisor/session 重拨；成功后清空易失 pairing bindings，调用方须按
    /// durable outbox exact reopen/replay。
    pub(crate) async fn reconnect(&self) -> Result<(), RemoteTransportError> {
        let (response_tx, response_rx) = oneshot::channel();
        self.command_tx
            .send(SupervisorCommand::Reconnect {
                response: response_tx,
            })
            .await
            .map_err(|_| RemoteTransportError::Closed)?;
        response_rx
            .await
            .map_err(|_| RemoteTransportError::Closed)?
    }

    async fn send_command(&self, command: PairingCommand) -> Result<(), RemoteTransportError> {
        let (response_tx, response_rx) = oneshot::channel();
        self.command_tx
            .send(SupervisorCommand::Pairing {
                command,
                response: response_tx,
            })
            .await
            .map_err(|_| RemoteTransportError::Closed)?;
        response_rx
            .await
            .map_err(|_| RemoteTransportError::Closed)?
    }

    /// 在 pairing drain 完成线性化点，把 shared control 的唯一所有权交回 control surface。
    /// 已进入 bounded pairing FIFO 的当前 generation shared control 会原值搬入有界 handoff；
    /// typed pairing event 保持在本 lane，后续仍由 pairing actor 消费。
    pub(crate) fn yield_shared_control(&mut self) -> Result<(), RemoteTransportError> {
        let generation = self.generation.load(Ordering::Acquire);
        let mut transition = self
            .transition
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner());
        if !transition.pairing_events_enabled {
            return Err(RemoteTransportError::PairingLaneUnavailable);
        }
        if !transition.pairing_owns_shared_control {
            return Ok(());
        }

        let queued = self.event_rx.len();
        if transition
            .retained_pairing_events
            .checked_add(queued)
            .is_none_or(|total| total > PAIRING_EVENT_CHANNEL_CAPACITY)
            || transition
                .handed_off_control
                .len()
                .checked_add(queued)
                .is_none_or(|total| total > PAIRING_EVENT_CHANNEL_CAPACITY)
        {
            return Err(RemoteTransportError::PairingLagged);
        }

        while let Ok(signal) = self.event_rx.try_recv() {
            if signal.generation() != generation {
                continue;
            }
            match signal {
                signal @ PairingTransportSignal::Event { .. } => {
                    self.retained_events.push_back(signal);
                    transition.retained_pairing_events += 1;
                }
                PairingTransportSignal::SharedControl { control, .. } => {
                    transition.handed_off_control.push_back(control);
                }
            }
        }
        debug_assert!(
            transition.retained_pairing_events <= PAIRING_EVENT_CHANNEL_CAPACITY,
            "retained typed pairing events must remain bounded"
        );
        debug_assert!(
            transition.handed_off_control.len() <= PAIRING_EVENT_CHANNEL_CAPACITY,
            "shared control handoff must remain bounded"
        );
        transition.pairing_owns_shared_control = false;
        Ok(())
    }

    pub(crate) async fn next_event(
        &mut self,
    ) -> Result<Option<PairingTransportEvent>, RemoteTransportError> {
        loop {
            if let Some(code) = self.health_rx.borrow().clone() {
                return Err(supervisor_failure(code));
            }
            if let Some(signal) = self.retained_events.pop_front() {
                let mut transition = self
                    .transition
                    .lock()
                    .unwrap_or_else(|poisoned| poisoned.into_inner());
                debug_assert!(transition.retained_pairing_events > 0);
                transition.retained_pairing_events =
                    transition.retained_pairing_events.saturating_sub(1);
                drop(transition);
                if signal.generation() != self.generation.load(Ordering::Acquire) {
                    continue;
                }
                return pairing_signal_event(signal);
            }
            tokio::select! {
                biased;
                changed = self.health_rx.changed() => {
                    if changed.is_err() {
                        return Err(RemoteTransportError::Closed);
                    }
                }
                event = self.event_rx.recv() => {
                    return match event {
                        Some(signal)
                            if signal.generation() != self.generation.load(Ordering::Acquire) =>
                        {
                            continue;
                        }
                        Some(signal) => pairing_signal_event(signal),
                        None => Err(RemoteTransportError::Closed),
                    };
                }
            }
        }
    }

    fn authority_anchor(&self) -> Result<&MachinePairingAnchor, RemoteTransportError> {
        self.authority_anchor
            .as_ref()
            .ok_or_else(pairing_authority_mismatch)
    }
}

impl fmt::Debug for PairingTransportLane {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("PairingTransportLane([REDACTED])")
    }
}

impl Drop for PairingTransportLane {
    fn drop(&mut self) {
        let _ = self.yield_shared_control();
        let mut transition = self
            .transition
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner());
        transition.pairing_events_enabled = false;
        transition.pairing_owns_shared_control = false;
        transition.retained_pairing_events = 0;
    }
}

fn pairing_signal_event(
    signal: PairingTransportSignal,
) -> Result<Option<PairingTransportEvent>, RemoteTransportError> {
    match signal {
        PairingTransportSignal::Event { event, .. } => Ok(Some(event)),
        PairingTransportSignal::SharedControl {
            pairing_failure, ..
        } => Err(supervisor_failure(pairing_failure.code)),
    }
}

/// 持有 RemoteStartPermit/active link key owner 的唯一 transport。
pub struct RemoteTransport {
    machine_route: MachineRouteId,
    supervisor: Option<ControlSupervisor>,
    pairing_lane: Option<PairingTransportLane>,
    business_lane: Option<BusinessTransportLane>,
    authenticator: Option<Arc<MachineLinkAuthenticator>>,
    start_permit: Option<RemoteStartPermit>,
}

const CONTROL_CHANNEL_CAPACITY: usize = 8;
const COMMAND_CHANNEL_CAPACITY: usize = 8;
const BUSINESS_DEACTIVATION_DEADLINE: Duration = Duration::from_secs(10);

enum SupervisorCommand {
    SendRetirement {
        retirement: RetireMachine,
        response: oneshot::Sender<Result<(), RemoteTransportError>>,
    },
    Pairing {
        command: PairingCommand,
        response: oneshot::Sender<Result<(), RemoteTransportError>>,
    },
    PairingTerminal {
        terminal: PairData,
        close: ClosePairRoute,
        response: oneshot::Sender<Result<(), RemoteTransportError>>,
    },
    BusinessReply {
        expected_generation: u64,
        expected_activation_epoch: u64,
        reply: Reply,
        response: oneshot::Sender<Result<(), RemoteTransportError>>,
    },
    RegisterStream {
        expected_connection_generation: u64,
        expected_activation_epoch: u64,
        registration: RegisterStream,
        response: oneshot::Sender<Result<(), RemoteTransportError>>,
    },
    Publish {
        expected_connection_generation: u64,
        expected_activation_epoch: u64,
        publish: Publish,
        exact_blob: Arc<[u8]>,
        blob_sha256: [u8; 32],
        response: oneshot::Sender<Result<MachinePublicationOutcome, RemoteTransportError>>,
    },
    DeactivateBusiness {
        expected_activation_epoch: u64,
        response: oneshot::Sender<Result<(), RemoteTransportError>>,
    },
    Reconnect {
        response: oneshot::Sender<Result<(), RemoteTransportError>>,
    },
}

#[derive(Clone, Copy, PartialEq, Eq, Hash)]
struct PublicationAckKey {
    stream_route: StreamRouteId,
    stream_seq: u64,
}

struct PendingPublication {
    connection_generation: u64,
    stream_generation: StreamGenerationId,
    exact_blob: Arc<[u8]>,
    blob_sha256: [u8; 32],
    response: oneshot::Sender<Result<MachinePublicationOutcome, RemoteTransportError>>,
}

#[derive(Default)]
struct PublicationBindings {
    pending: HashMap<PublicationAckKey, PendingPublication>,
    completed: Vec<(u64, PublicationAckKey)>,
}

impl PublicationBindings {
    fn validate_outbound(
        &self,
        machine_route: MachineRouteId,
        connection_generation: u64,
        publish: &Publish,
        exact_blob: &[u8],
        blob_sha256: [u8; 32],
    ) -> Result<(), RemoteTransportError> {
        let prepared = prepare_machine_publication(
            machine_route,
            publish.stream_route,
            publish.generation,
            publish.stream_seq,
            Arc::from(exact_blob),
            blob_sha256,
        )?;
        if prepared.publish != *publish || self.pending.len() >= PUBLICATION_PENDING_CAPACITY {
            return Err(if self.pending.len() >= PUBLICATION_PENDING_CAPACITY {
                RemoteTransportError::PublicationCapacity
            } else {
                RemoteTransportError::PublicationBindingMismatch
            });
        }
        let key = PublicationAckKey {
            stream_route: publish.stream_route,
            stream_seq: publish.stream_seq,
        };
        if self.pending.contains_key(&key) || self.completed.contains(&(connection_generation, key))
        {
            return Err(RemoteTransportError::PublicationBindingMismatch);
        }
        Ok(())
    }

    fn insert(
        &mut self,
        connection_generation: u64,
        publish: &Publish,
        exact_blob: Arc<[u8]>,
        blob_sha256: [u8; 32],
        response: oneshot::Sender<Result<MachinePublicationOutcome, RemoteTransportError>>,
    ) {
        self.pending.insert(
            PublicationAckKey {
                stream_route: publish.stream_route,
                stream_seq: publish.stream_seq,
            },
            PendingPublication {
                connection_generation,
                stream_generation: publish.generation,
                exact_blob,
                blob_sha256,
                response,
            },
        );
    }

    fn accept(
        &mut self,
        connection_generation: u64,
        accepted: &RouteAccepted,
    ) -> Result<(), RemoteTransportError> {
        let AcceptedRef::StreamFrame {
            stream_route,
            stream_seq,
        } = &accepted.accepted
        else {
            return Err(RemoteTransportError::PublicationAckMismatch);
        };
        let key = PublicationAckKey {
            stream_route: *stream_route,
            stream_seq: *stream_seq,
        };
        let Some(pending) = self.pending.remove(&key) else {
            return Err(RemoteTransportError::PublicationAckMismatch);
        };
        if pending.connection_generation != connection_generation
            || sha256(pending.exact_blob.as_ref()) != pending.blob_sha256
        {
            let _ = pending
                .response
                .send(Ok(MachinePublicationOutcome::OutcomeUnknown));
            return Err(RemoteTransportError::PublicationAckMismatch);
        }
        let commit = MachinePublicationCommit {
            connection_generation,
            stream_route: *stream_route,
            stream_generation: pending.stream_generation,
            stream_seq: *stream_seq,
            blob_sha256: pending.blob_sha256,
        };
        remember_completed_bounded(
            &mut self.completed,
            (connection_generation, key),
            PUBLICATION_COMPLETED_CAPACITY,
        );
        let _ = pending
            .response
            .send(Ok(MachinePublicationOutcome::Committed(commit)));
        Ok(())
    }

    fn resolve_unknown(&mut self) {
        for (_, pending) in self.pending.drain() {
            let _ = pending
                .response
                .send(Ok(MachinePublicationOutcome::OutcomeUnknown));
        }
    }

    fn replace_connection(&mut self) {
        self.resolve_unknown();
        self.completed.clear();
    }
}

fn remember_completed_bounded<T: PartialEq>(completed: &mut Vec<T>, value: T, capacity: usize) {
    if completed.contains(&value) {
        return;
    }
    if completed.len() == capacity {
        completed.remove(0);
    }
    completed.push(value);
}

struct ControlSupervisor {
    command_tx: mpsc::Sender<SupervisorCommand>,
    control_rx: mpsc::Receiver<Result<Option<RemoteControl>, RemoteTransportError>>,
    retained_control: VecDeque<Result<Option<RemoteControl>, RemoteTransportError>>,
    pairing_transition: Arc<Mutex<PairingTransition>>,
    business_enabled: Arc<AtomicBool>,
    business_activation_epoch: Arc<AtomicU64>,
    cancel_tx: watch::Sender<bool>,
    task: Option<JoinHandle<()>>,
    health_rx: watch::Receiver<Option<String>>,
}

struct SupervisorSignals {
    control_tx: mpsc::Sender<Result<Option<RemoteControl>, RemoteTransportError>>,
    pairing_tx: mpsc::Sender<PairingTransportSignal>,
    pairing_transition: Arc<Mutex<PairingTransition>>,
    pairing_generation: Arc<AtomicU64>,
    business_generation: watch::Sender<u64>,
    business_tx: mpsc::Sender<BusinessTransportSignal>,
    business_bytes: Arc<Semaphore>,
    business_enabled: Arc<AtomicBool>,
    business_activation_epoch: Arc<AtomicU64>,
    health: watch::Sender<Option<String>>,
}

impl ControlSupervisor {
    fn start(
        machine_route: MachineRouteId,
        session: Box<dyn ControlSession>,
        business_startup: BusinessLaneStartup,
    ) -> (Self, PairingTransportLane, BusinessTransportLane) {
        let (command_tx, command_rx) = mpsc::channel(COMMAND_CHANNEL_CAPACITY);
        let (control_tx, control_rx) = mpsc::channel(CONTROL_CHANNEL_CAPACITY);
        let (pairing_tx, pairing_rx) = mpsc::channel(PAIRING_EVENT_CHANNEL_CAPACITY);
        let (business_tx, business_rx) = mpsc::channel(BUSINESS_EVENT_CHANNEL_CAPACITY);
        let pairing_transition = Arc::new(Mutex::new(PairingTransition::default()));
        let pairing_generation = Arc::new(AtomicU64::new(INITIAL_PAIRING_GENERATION));
        let (business_generation, business_generation_rx) =
            watch::channel(INITIAL_PAIRING_GENERATION);
        let business_bytes = Arc::new(Semaphore::new(BUSINESS_EVENT_BYTES_CAPACITY));
        // Active recovery 必须在 reader task 可见任何已重连 device 首帧前完成唯一
        // business reservation。Dormant 仍从 disabled/epoch 0 开始并 fail-close。
        let initial_business_activation_epoch = match business_startup {
            BusinessLaneStartup::Dormant => 0,
            BusinessLaneStartup::Reserved => 1,
        };
        let business_enabled = Arc::new(AtomicBool::new(matches!(
            business_startup,
            BusinessLaneStartup::Reserved
        )));
        let business_activation_epoch = Arc::new(AtomicU64::new(initial_business_activation_epoch));
        let (cancel_tx, cancel_rx) = watch::channel(false);
        let (health_tx, health_rx) = watch::channel(None);
        let task = tokio::spawn(run_control_supervisor(
            machine_route,
            session,
            command_rx,
            SupervisorSignals {
                control_tx,
                pairing_tx,
                pairing_transition: Arc::clone(&pairing_transition),
                pairing_generation: Arc::clone(&pairing_generation),
                business_generation,
                business_tx,
                business_bytes,
                business_enabled: Arc::clone(&business_enabled),
                business_activation_epoch: Arc::clone(&business_activation_epoch),
                health: health_tx,
            },
            cancel_rx,
        ));
        let pairing_lane = PairingTransportLane {
            command_tx: command_tx.clone(),
            event_rx: pairing_rx,
            retained_events: VecDeque::with_capacity(PAIRING_EVENT_CHANNEL_CAPACITY),
            health_rx: health_rx.clone(),
            transition: Arc::clone(&pairing_transition),
            generation: Arc::clone(&pairing_generation),
            authority_anchor: None,
        };
        let business_lane = BusinessTransportLane {
            machine_route,
            command_tx: command_tx.clone(),
            event_rx: business_rx,
            health_rx: health_rx.clone(),
            generation: Arc::clone(&pairing_generation),
            generation_rx: business_generation_rx,
            observed_generation: INITIAL_PAIRING_GENERATION,
            enabled: Arc::clone(&business_enabled),
            activation_epoch: Arc::clone(&business_activation_epoch),
            admitted_activation_epoch: initial_business_activation_epoch,
        };
        (
            Self {
                command_tx,
                control_rx,
                retained_control: VecDeque::with_capacity(CONTROL_CHANNEL_CAPACITY),
                pairing_transition,
                business_enabled,
                business_activation_epoch,
                cancel_tx,
                task: Some(task),
                health_rx,
            },
            pairing_lane,
            business_lane,
        )
    }

    fn activate_business(
        &self,
        lane: &mut BusinessTransportLane,
    ) -> Result<(), RemoteTransportError> {
        if self.business_enabled.load(Ordering::Acquire)
            && lane.admitted_activation_epoch != 0
            && self.business_activation_epoch.load(Ordering::Acquire)
                == lane.admitted_activation_epoch
            && Arc::ptr_eq(&self.business_enabled, &lane.enabled)
            && Arc::ptr_eq(&self.business_activation_epoch, &lane.activation_epoch)
        {
            return Ok(());
        }
        if !Arc::ptr_eq(&self.business_enabled, &lane.enabled)
            || !Arc::ptr_eq(&self.business_activation_epoch, &lane.activation_epoch)
            || self.business_enabled.load(Ordering::Acquire)
        {
            return Err(RemoteTransportError::BusinessLaneUnavailable);
        }
        let activation_epoch = self
            .business_activation_epoch
            .fetch_update(Ordering::AcqRel, Ordering::Acquire, |current| {
                current.checked_add(1).filter(|next| *next != 0)
            })
            .map_err(|_| RemoteTransportError::BusinessLaneUnavailable)?
            + 1;
        if self
            .business_enabled
            .compare_exchange(false, true, Ordering::AcqRel, Ordering::Acquire)
            .is_err()
        {
            return Err(RemoteTransportError::BusinessLaneUnavailable);
        }
        lane.admitted_activation_epoch = activation_epoch;
        Ok(())
    }

    async fn restore_business(
        &self,
        lane: &BusinessTransportLane,
    ) -> Result<(), RemoteTransportError> {
        if !Arc::ptr_eq(&self.business_enabled, &lane.enabled)
            || !Arc::ptr_eq(&self.business_activation_epoch, &lane.activation_epoch)
            || self.business_activation_epoch.load(Ordering::Acquire)
                != lane.admitted_activation_epoch
        {
            return Err(RemoteTransportError::BusinessLaneUnavailable);
        }
        let (response_tx, response_rx) = oneshot::channel();
        tokio::time::timeout(BUSINESS_DEACTIVATION_DEADLINE, async {
            self.command_tx
                .send(SupervisorCommand::DeactivateBusiness {
                    expected_activation_epoch: lane.admitted_activation_epoch,
                    response: response_tx,
                })
                .await
                .map_err(|_| RemoteTransportError::Closed)?;
            response_rx
                .await
                .map_err(|_| RemoteTransportError::Closed)?
        })
        .await
        .map_err(|_| RemoteTransportError::BusinessLaneUnavailable)?
    }

    fn failure_code(&self) -> Option<String> {
        self.health_rx.borrow().clone()
    }

    fn activate_pairing(
        &mut self,
        lane: &PairingTransportLane,
    ) -> Result<(), RemoteTransportError> {
        self.activate_pairing_transition(&lane.transition, false)
    }

    fn reacquire_pairing(&mut self) -> Result<(), RemoteTransportError> {
        let transition = Arc::clone(&self.pairing_transition);
        self.activate_pairing_transition(&transition, true)
    }

    fn activate_pairing_transition(
        &mut self,
        pairing_transition: &Mutex<PairingTransition>,
        require_yielded_lane: bool,
    ) -> Result<(), RemoteTransportError> {
        let mut transition = pairing_transition
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner());
        if require_yielded_lane
            && (!transition.pairing_events_enabled || transition.pairing_owns_shared_control)
        {
            return Err(RemoteTransportError::PairingActivationBlocked);
        }
        if transition.pending_exclusive_control {
            return Err(RemoteTransportError::PairingActivationBlocked);
        }
        if self
            .retained_control
            .len()
            .checked_add(self.control_rx.len())
            .is_none_or(|total| total > CONTROL_CHANNEL_CAPACITY)
        {
            return Err(RemoteTransportError::PairingActivationBlocked);
        }
        let mut queued = std::mem::take(&mut self.retained_control);
        while let Ok(control) = self.control_rx.try_recv() {
            queued.push_back(control);
        }
        if transition
            .handed_off_control
            .iter()
            .any(|control| !is_shared_control(control))
            || queued.iter().any(|control| !is_shared_control(control))
        {
            self.retained_control = queued;
            return Err(RemoteTransportError::PairingActivationBlocked);
        }
        transition.handed_off_control.clear();
        transition.pairing_events_enabled = true;
        transition.pairing_owns_shared_control = true;
        Ok(())
    }

    async fn next_control(&mut self) -> Result<Option<RemoteControl>, RemoteTransportError> {
        if let Some(control) = self
            .pairing_transition
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner())
            .handed_off_control
            .pop_front()
        {
            return control;
        }
        if let Some(control) = self.retained_control.pop_front() {
            return control;
        }
        self.control_rx
            .recv()
            .await
            .ok_or(RemoteTransportError::Closed)?
    }

    async fn shutdown(mut self) {
        let _ = self.cancel_tx.send(true);
        self.control_rx.close();
        if let Some(task) = self.task.as_mut() {
            let _ = task.await;
        }
        self.task = None;
    }
}

impl Drop for ControlSupervisor {
    fn drop(&mut self) {
        let _ = self.cancel_tx.send(true);
        if let Some(task) = self.task.take() {
            task.abort();
        }
    }
}

async fn run_control_supervisor(
    machine_route: MachineRouteId,
    mut session: Box<dyn ControlSession>,
    mut command_rx: mpsc::Receiver<SupervisorCommand>,
    signals: SupervisorSignals,
    mut cancel_rx: watch::Receiver<bool>,
) {
    let SupervisorSignals {
        control_tx,
        pairing_tx,
        pairing_transition,
        pairing_generation,
        business_generation,
        business_tx,
        business_bytes,
        business_enabled,
        business_activation_epoch,
        health,
    } = signals;
    let mut reader_enabled = true;
    let mut session_shutdown = false;
    let mut pending_control = None;
    let mut pairing_bindings = PairingBindings::default();
    let mut publication_bindings = PublicationBindings::default();

    loop {
        if *cancel_rx.borrow() {
            break;
        }
        if let Some(control) = pending_control.take() {
            let mut control = Some(control);
            let shared_dispatch = {
                let transition = pairing_transition
                    .lock()
                    .unwrap_or_else(|poisoned| poisoned.into_inner());
                if transition.pairing_owns_shared_control {
                    shared_control_pairing_failure(
                        control.as_ref().expect("pending control remains available"),
                    )
                    .map(|pairing_failure| {
                        try_send_pairing_signal(
                            &pairing_tx,
                            &transition,
                            PairingTransportSignal::SharedControl {
                                generation: pairing_generation.load(Ordering::Acquire),
                                control: control.take().expect("shared control moves once"),
                                pairing_failure,
                            },
                        )
                    })
                } else {
                    None
                }
            };
            if let Some(dispatch_failed) = shared_dispatch {
                if dispatch_failed {
                    set_supervisor_failure(&health, RemoteTransportError::PairingLagged.code());
                    reader_enabled = false;
                    session.shutdown().await;
                    session_shutdown = true;
                }
                continue;
            }
            let control = control.expect("control owner retains pending control");
            tokio::select! {
                biased;
                changed = cancel_rx.changed() => {
                    if changed.is_err() || *cancel_rx.borrow() {
                        break;
                    }
                    pending_control = Some(control);
                }
                command = command_rx.recv() => {
                    let Some(command) = command else { break; };
                    handle_supervisor_command(
                        command,
                        session.as_mut(),
                        &mut reader_enabled,
                        session_shutdown,
                        &health,
                        machine_route,
                        SupervisorState {
                            generation: &pairing_generation,
                            business_generation: &business_generation,
                            pairing_bindings: &mut pairing_bindings,
                            publication_bindings: &mut publication_bindings,
                            business_enabled: &business_enabled,
                            business_activation_epoch: &business_activation_epoch,
                        },
                    ).await;
                    pending_control = Some(control);
                }
                permit = control_tx.reserve() => {
                    let Ok(permit) = permit else { break; };
                    let pairing_failure = shared_control_pairing_failure(&control);
                    let mut control = Some(control);
                    let pairing_dispatch_failed = {
                        let mut transition = pairing_transition
                            .lock()
                            .unwrap_or_else(|poisoned| poisoned.into_inner());
                        if transition.pairing_owns_shared_control {
                            if let Some(failure) = pairing_failure {
                                drop(permit);
                                try_send_pairing_signal(
                                    &pairing_tx,
                                    &transition,
                                    PairingTransportSignal::SharedControl {
                                        generation: pairing_generation.load(Ordering::Acquire),
                                        control: control.take().expect("shared control moves once"),
                                        pairing_failure: failure,
                                    },
                                )
                            } else {
                                permit.send(control.take().expect("exclusive control moves once"));
                                transition.pending_exclusive_control = false;
                                false
                            }
                        } else {
                            permit.send(control.take().expect("control moves once"));
                            transition.pending_exclusive_control = false;
                            false
                        }
                    };
                    if pairing_dispatch_failed {
                        set_supervisor_failure(
                            &health,
                            RemoteTransportError::PairingLagged.code(),
                        );
                        reader_enabled = false;
                        session.shutdown().await;
                        session_shutdown = true;
                    }
                }
            }
            continue;
        }

        if !reader_enabled {
            tokio::select! {
                biased;
                changed = cancel_rx.changed() => {
                    if changed.is_err() || *cancel_rx.borrow() {
                        break;
                    }
                }
                command = command_rx.recv() => {
                    let Some(command) = command else { break; };
                    handle_supervisor_command(
                        command,
                        session.as_mut(),
                        &mut reader_enabled,
                        session_shutdown,
                        &health,
                        machine_route,
                        SupervisorState {
                            generation: &pairing_generation,
                            business_generation: &business_generation,
                            pairing_bindings: &mut pairing_bindings,
                            publication_bindings: &mut publication_bindings,
                            business_enabled: &business_enabled,
                            business_activation_epoch: &business_activation_epoch,
                        },
                    ).await;
                }
            }
            continue;
        }

        tokio::select! {
            biased;
            changed = cancel_rx.changed() => {
                if changed.is_err() || *cancel_rx.borrow() {
                    break;
                }
            }
            command = command_rx.recv() => {
                let Some(command) = command else { break; };
                handle_supervisor_command(
                    command,
                    session.as_mut(),
                    &mut reader_enabled,
                    session_shutdown,
                    &health,
                    machine_route,
                    SupervisorState {
                        generation: &pairing_generation,
                        business_generation: &business_generation,
                        pairing_bindings: &mut pairing_bindings,
                        publication_bindings: &mut publication_bindings,
                        business_enabled: &business_enabled,
                        business_activation_epoch: &business_activation_epoch,
                    },
                ).await;
            }
            received = session.next() => {
                match received {
                    Ok(Some(frame)) => match decode_inbound(
                        machine_route,
                        pairing_generation.load(Ordering::Acquire),
                        &mut pairing_bindings,
                        &mut publication_bindings,
                        frame,
                    ) {
                        Ok(InboundDispatch::Control(control)) => {
                            replace_pending_control(
                                &mut pending_control,
                                &pairing_transition,
                                Ok(Some(control)),
                            );
                        }
                        Ok(InboundDispatch::Pairing(event)) => {
                            let dispatch_failed = {
                                let transition = pairing_transition
                                    .lock()
                                    .unwrap_or_else(|poisoned| poisoned.into_inner());
                                !transition.pairing_events_enabled
                                    || try_send_pairing_signal(
                                        &pairing_tx,
                                        &transition,
                                        PairingTransportSignal::Event {
                                        generation: pairing_generation.load(Ordering::Acquire),
                                            event,
                                        },
                                    )
                            };
                            if dispatch_failed {
                                let error = RemoteTransportError::PairingLagged;
                                set_supervisor_failure(&health, error.code());
                                reader_enabled = false;
                                session.shutdown().await;
                                session_shutdown = true;
                                replace_pending_control(
                                    &mut pending_control,
                                    &pairing_transition,
                                    Err(error),
                                );
                            }
                        }
                        Ok(InboundDispatch::Business { event, encoded_len }) => {
                            if let Err(error) = try_send_business_signal(
                                &business_tx,
                                &business_bytes,
                                &business_enabled,
                                pairing_generation.load(Ordering::Acquire),
                                event,
                                encoded_len,
                            ) {
                                set_supervisor_failure(&health, error.code());
                                reader_enabled = false;
                                session.shutdown().await;
                                session_shutdown = true;
                                replace_pending_control(
                                    &mut pending_control,
                                    &pairing_transition,
                                    Err(error),
                                );
                            }
                        }
                        Ok(InboundDispatch::PublicationCommitted) => {}
                        Ok(InboundDispatch::ExpectedTerminalReplayMiss) => {}
                        Ok(InboundDispatch::Shared { control, pairing_failure }) => {
                            let mut control = Some(Ok(Some(control)));
                            let pairing_dispatch = {
                                let transition = pairing_transition
                                    .lock()
                                    .unwrap_or_else(|poisoned| poisoned.into_inner());
                                transition.pairing_owns_shared_control.then(|| {
                                    try_send_pairing_signal(
                                        &pairing_tx,
                                        &transition,
                                        PairingTransportSignal::SharedControl {
                                            generation: pairing_generation.load(Ordering::Acquire),
                                            control: control.take().expect("shared control moves once"),
                                            pairing_failure,
                                        },
                                    )
                                })
                            };
                            match pairing_dispatch {
                                Some(false) => {}
                                Some(true) => {
                                    set_supervisor_failure(
                                        &health,
                                        RemoteTransportError::PairingLagged.code(),
                                    );
                                    reader_enabled = false;
                                    session.shutdown().await;
                                    session_shutdown = true;
                                }
                                None => replace_pending_control(
                                    &mut pending_control,
                                    &pairing_transition,
                                    control.take().expect("control owner retains shared control"),
                                ),
                            }
                        }
                        Err(error) => {
                            publication_bindings.resolve_unknown();
                            set_supervisor_failure(&health, error.code());
                            reader_enabled = false;
                            session.shutdown().await;
                            session_shutdown = true;
                            replace_pending_control(
                                &mut pending_control,
                                &pairing_transition,
                                Err(error),
                            );
                        }
                    },
                    Ok(None) => {
                        publication_bindings.resolve_unknown();
                        set_supervisor_failure(&health, RemoteTransportError::Closed.code());
                        reader_enabled = false;
                        replace_pending_control(
                            &mut pending_control,
                            &pairing_transition,
                            Ok(None),
                        );
                    }
                    Err(error) => {
                        publication_bindings.resolve_unknown();
                        set_supervisor_failure(&health, error.code());
                        reader_enabled = false;
                        replace_pending_control(
                            &mut pending_control,
                            &pairing_transition,
                            Err(RemoteTransportError::Client(error)),
                        );
                    }
                }
            }
        }
    }

    if !session_shutdown {
        session.shutdown().await;
    }
    publication_bindings.resolve_unknown();
}

struct SupervisorState<'a> {
    generation: &'a AtomicU64,
    business_generation: &'a watch::Sender<u64>,
    pairing_bindings: &'a mut PairingBindings,
    publication_bindings: &'a mut PublicationBindings,
    business_enabled: &'a AtomicBool,
    business_activation_epoch: &'a AtomicU64,
}

async fn handle_supervisor_command(
    command: SupervisorCommand,
    session: &mut dyn ControlSession,
    reader_enabled: &mut bool,
    session_shutdown: bool,
    health: &watch::Sender<Option<String>>,
    machine_route: MachineRouteId,
    state: SupervisorState<'_>,
) {
    match command {
        SupervisorCommand::SendRetirement {
            retirement,
            response,
        } => {
            if session_shutdown || !*reader_enabled {
                let _ = response.send(Err(RemoteTransportError::Closed));
                return;
            }
            let result = session
                .send(OpaqueRouteFrame {
                    version: RELAY_PROTOCOL_VERSION,
                    body: RelayFrameBody::RetireMachine(retirement),
                })
                .await
                .map_err(RemoteTransportError::Client);
            if let Err(error) = &result {
                state.publication_bindings.resolve_unknown();
                set_supervisor_failure(health, error.code());
                *reader_enabled = false;
            }
            let _ = response.send(result);
        }
        SupervisorCommand::Pairing { command, response } => {
            if session_shutdown {
                let _ = response.send(Err(RemoteTransportError::Closed));
                return;
            }
            if !*reader_enabled {
                let error = health
                    .borrow()
                    .clone()
                    .map(supervisor_failure)
                    .unwrap_or(RemoteTransportError::Closed);
                let _ = response.send(Err(error));
                return;
            }
            let next_bindings = match state
                .pairing_bindings
                .prepare_outbound(machine_route, &command)
            {
                Ok(next) => next,
                Err(error) => {
                    let _ = response.send(Err(error));
                    return;
                }
            };
            let result = session
                .send(command.frame())
                .await
                .map_err(RemoteTransportError::Client);
            match &result {
                Ok(()) => *state.pairing_bindings = next_bindings,
                Err(error) => {
                    state.publication_bindings.resolve_unknown();
                    set_supervisor_failure(health, error.code());
                    *reader_enabled = false;
                }
            }
            let _ = response.send(result);
        }
        SupervisorCommand::PairingTerminal {
            terminal,
            close,
            response,
        } => {
            if session_shutdown {
                let _ = response.send(Err(RemoteTransportError::Closed));
                return;
            }
            if !*reader_enabled {
                let error = health
                    .borrow()
                    .clone()
                    .map(supervisor_failure)
                    .unwrap_or(RemoteTransportError::Closed);
                let _ = response.send(Err(error));
                return;
            }
            let terminal = PairingCommand::TerminalData(terminal);
            let close = PairingCommand::Close(close);
            let next_bindings = state
                .pairing_bindings
                .prepare_outbound(machine_route, &terminal)
                .and_then(|next| next.prepare_outbound(machine_route, &close));
            let next_bindings = match next_bindings {
                Ok(next) => next,
                Err(error) => {
                    let _ = response.send(Err(error));
                    return;
                }
            };
            let result = match session.send(terminal.frame()).await {
                Ok(()) => session
                    .send(close.frame())
                    .await
                    .map_err(RemoteTransportError::Client),
                Err(error) => Err(RemoteTransportError::Client(error)),
            };
            match &result {
                Ok(()) => *state.pairing_bindings = next_bindings,
                Err(error) => {
                    state.publication_bindings.resolve_unknown();
                    set_supervisor_failure(health, error.code());
                    *reader_enabled = false;
                }
            }
            let _ = response.send(result);
        }
        SupervisorCommand::BusinessReply {
            expected_generation,
            expected_activation_epoch,
            reply,
            response,
        } => {
            if session_shutdown || !*reader_enabled {
                let _ = response.send(Err(RemoteTransportError::Closed));
                return;
            }
            if !state.business_enabled.load(Ordering::Acquire)
                || state.business_activation_epoch.load(Ordering::Acquire)
                    != expected_activation_epoch
            {
                let _ = response.send(Err(RemoteTransportError::BusinessLaneUnavailable));
                return;
            }
            if state.generation.load(Ordering::Acquire) != expected_generation {
                let _ = response.send(Err(RemoteTransportError::BusinessGenerationReplaced));
                return;
            }
            let frame = match business_reply_frame(reply) {
                Ok(frame) => frame,
                Err(error) => {
                    let _ = response.send(Err(error));
                    return;
                }
            };
            let result = session
                .send(frame)
                .await
                .map_err(RemoteTransportError::Client);
            if let Err(error) = &result {
                state.publication_bindings.resolve_unknown();
                set_supervisor_failure(health, error.code());
                *reader_enabled = false;
            }
            let _ = response.send(result);
        }
        SupervisorCommand::RegisterStream {
            expected_connection_generation,
            expected_activation_epoch,
            registration,
            response,
        } => {
            if !state.business_enabled.load(Ordering::Acquire)
                || state.business_activation_epoch.load(Ordering::Acquire)
                    != expected_activation_epoch
            {
                let _ = response.send(Err(RemoteTransportError::BusinessLaneUnavailable));
                return;
            }
            if state.generation.load(Ordering::Acquire) != expected_connection_generation {
                let _ = response.send(Err(RemoteTransportError::BusinessGenerationReplaced));
                return;
            }
            let frame = OpaqueRouteFrame {
                version: RELAY_PROTOCOL_VERSION,
                body: RelayFrameBody::RegisterStream(registration.clone()),
            };
            if registration.machine_route != machine_route
                || registration.stream_route.as_bytes() == &[0; 16]
                || registration.generation.as_bytes() == &[0; 16]
            {
                let _ = response.send(Err(RemoteTransportError::PublicationBindingMismatch));
                return;
            }
            if encode(&frame).len() > MAX_FRAME_BYTES {
                let _ = response.send(Err(RemoteTransportError::Client(
                    RelayClientError::Failure {
                        code: "relay.client.frame_too_large".to_owned(),
                    },
                )));
                return;
            }
            if session_shutdown {
                let _ = response.send(Err(RemoteTransportError::Closed));
                return;
            }
            if !*reader_enabled {
                let _ = response.send(Err(RemoteTransportError::PublicationOffline));
                return;
            }
            let result = session
                .send(frame)
                .await
                .map_err(RemoteTransportError::Client);
            if let Err(error) = &result {
                state.publication_bindings.resolve_unknown();
                set_supervisor_failure(health, error.code());
                *reader_enabled = false;
            }
            let _ = response.send(result);
        }
        SupervisorCommand::Publish {
            expected_connection_generation,
            expected_activation_epoch,
            publish,
            exact_blob,
            blob_sha256,
            response,
        } => {
            if !state.business_enabled.load(Ordering::Acquire)
                || state.business_activation_epoch.load(Ordering::Acquire)
                    != expected_activation_epoch
            {
                let _ = response.send(Err(RemoteTransportError::BusinessLaneUnavailable));
                return;
            }
            if state.generation.load(Ordering::Acquire) != expected_connection_generation {
                let _ = response.send(Ok(MachinePublicationOutcome::OutcomeUnknown));
                return;
            }
            if session_shutdown {
                let _ = response.send(Err(RemoteTransportError::Closed));
                return;
            }
            if !*reader_enabled {
                let _ = response.send(Ok(MachinePublicationOutcome::Offline));
                return;
            }
            if let Err(error) = state.publication_bindings.validate_outbound(
                machine_route,
                expected_connection_generation,
                &publish,
                exact_blob.as_ref(),
                blob_sha256,
            ) {
                let _ = response.send(Err(error));
                return;
            }
            let frame = OpaqueRouteFrame {
                version: RELAY_PROTOCOL_VERSION,
                body: RelayFrameBody::Publish(publish.clone()),
            };
            match session.send(frame).await {
                Ok(()) => state.publication_bindings.insert(
                    expected_connection_generation,
                    &publish,
                    exact_blob,
                    blob_sha256,
                    response,
                ),
                Err(error) => {
                    state.publication_bindings.resolve_unknown();
                    set_supervisor_failure(health, error.code());
                    *reader_enabled = false;
                    let _ = response.send(Ok(MachinePublicationOutcome::OutcomeUnknown));
                }
            }
        }
        SupervisorCommand::DeactivateBusiness {
            expected_activation_epoch,
            response,
        } => {
            if state.business_activation_epoch.load(Ordering::Acquire) != expected_activation_epoch
                || state
                    .business_enabled
                    .compare_exchange(true, false, Ordering::AcqRel, Ordering::Acquire)
                    .is_err()
            {
                let _ = response.send(Err(RemoteTransportError::BusinessLaneUnavailable));
                return;
            }
            let _ = response.send(Ok(()));
        }
        SupervisorCommand::Reconnect { response } => {
            if session_shutdown {
                let _ = response.send(Err(RemoteTransportError::Closed));
                return;
            }
            state.publication_bindings.replace_connection();
            let next_generation = state
                .generation
                .load(Ordering::Acquire)
                .checked_add(1)
                .ok_or(RemoteTransportError::PairingGenerationExhausted);
            let result = match next_generation {
                Ok(next_generation) => session
                    .reconnect()
                    .await
                    .map(|()| next_generation)
                    .map_err(RemoteTransportError::Client),
                Err(error) => Err(error),
            };
            match &result {
                Ok(next_generation) => {
                    *reader_enabled = true;
                    *state.pairing_bindings = PairingBindings::default();
                    state.generation.store(*next_generation, Ordering::Release);
                    state.business_generation.send_replace(*next_generation);
                    health.send_replace(None);
                }
                Err(error) => {
                    *reader_enabled = false;
                    set_supervisor_failure(health, error.code());
                }
            }
            let _ = response.send(result.map(|_| ()));
        }
    }
}

fn set_supervisor_failure(health: &watch::Sender<Option<String>>, code: &str) {
    health.send_replace(Some(code.to_owned()));
}

fn try_send_pairing_signal(
    pairing_tx: &mpsc::Sender<PairingTransportSignal>,
    transition: &PairingTransition,
    signal: PairingTransportSignal,
) -> bool {
    if transition.retained_pairing_events >= pairing_tx.capacity() {
        return true;
    }
    pairing_tx.try_send(signal).is_err()
}

fn try_send_business_signal(
    business_tx: &mpsc::Sender<BusinessTransportSignal>,
    byte_budget: &Arc<Semaphore>,
    enabled: &AtomicBool,
    generation: u64,
    event: BusinessTransportEvent,
    encoded_len: usize,
) -> Result<(), RemoteTransportError> {
    if !enabled.load(Ordering::Acquire) {
        return Err(RemoteTransportError::BusinessLaneUnavailable);
    }
    let encoded_len =
        u32::try_from(encoded_len).map_err(|_| RemoteTransportError::BusinessLagged)?;
    let bytes = Arc::clone(byte_budget)
        .try_acquire_many_owned(encoded_len)
        .map_err(|_| RemoteTransportError::BusinessLagged)?;
    business_tx
        .try_send(BusinessTransportSignal {
            generation,
            event,
            _bytes: bytes,
        })
        .map_err(|_| RemoteTransportError::BusinessLagged)
}

fn shared_control_pairing_failure(
    control: &Result<Option<RemoteControl>, RemoteTransportError>,
) -> Option<SafeFailure> {
    match control {
        Ok(Some(RemoteControl::SafeFailure(failure))) => Some(failure.clone()),
        Ok(Some(RemoteControl::ServerRestarting(_))) => Some(SafeFailure {
            code: "remote.transport.server_restarting".to_owned(),
        }),
        Ok(Some(RemoteControl::RetirementTerminal(_))) | Ok(None) | Err(_) => None,
    }
}

fn is_shared_control(control: &Result<Option<RemoteControl>, RemoteTransportError>) -> bool {
    shared_control_pairing_failure(control).is_some()
}

fn replace_pending_control(
    pending: &mut Option<Result<Option<RemoteControl>, RemoteTransportError>>,
    transition: &Mutex<PairingTransition>,
    control: Result<Option<RemoteControl>, RemoteTransportError>,
) {
    let mut transition = transition
        .lock()
        .unwrap_or_else(|poisoned| poisoned.into_inner());
    transition.pending_exclusive_control = !is_shared_control(&control);
    *pending = Some(control);
}

enum InboundDispatch {
    Control(RemoteControl),
    Pairing(PairingTransportEvent),
    Business {
        event: BusinessTransportEvent,
        encoded_len: usize,
    },
    PublicationCommitted,
    ExpectedTerminalReplayMiss,
    Shared {
        control: RemoteControl,
        pairing_failure: SafeFailure,
    },
}

fn decode_inbound(
    machine_route: MachineRouteId,
    connection_generation: u64,
    pairing_bindings: &mut PairingBindings,
    publication_bindings: &mut PublicationBindings,
    frame: OpaqueRouteFrame,
) -> Result<InboundDispatch, RemoteTransportError> {
    if frame.version != RELAY_PROTOCOL_VERSION {
        return Err(RemoteTransportError::FrameForbidden);
    }
    let canonical_frame_bytes = encode(&frame);
    let encoded_len = canonical_frame_bytes.len();
    if encoded_len > MAX_FRAME_BYTES {
        return Err(RemoteTransportError::Client(RelayClientError::Failure {
            code: "relay.client.frame_too_large".to_owned(),
        }));
    }
    let retirement_bytes = matches!(&frame.body, RelayFrameBody::RetirementCommitted(_))
        .then_some(canonical_frame_bytes);
    match frame.body {
        RelayFrameBody::RetirementCommitted(committed)
            if committed.machine_route == machine_route =>
        {
            let canonical_frame_bytes =
                retirement_bytes.ok_or(RemoteTransportError::FrameForbidden)?;
            Ok(InboundDispatch::Control(RemoteControl::RetirementTerminal(
                RetirementTerminal {
                    committed,
                    canonical_frame_hash: sha256(&canonical_frame_bytes),
                    canonical_frame_bytes,
                },
            )))
        }
        RelayFrameBody::Error(failure)
            if failure.has_safe_code()
                && pairing_bindings.consume_expected_terminal_not_found(&failure) =>
        {
            Ok(InboundDispatch::ExpectedTerminalReplayMiss)
        }
        RelayFrameBody::Error(failure) if failure.has_safe_code() => {
            let safe = SafeFailure { code: failure.code };
            Ok(InboundDispatch::Shared {
                control: RemoteControl::SafeFailure(safe.clone()),
                pairing_failure: safe,
            })
        }
        RelayFrameBody::ServerRestarting(restarting) => Ok(InboundDispatch::Shared {
            control: RemoteControl::ServerRestarting(restarting),
            pairing_failure: SafeFailure {
                code: "remote.transport.server_restarting".to_owned(),
            },
        }),
        RelayFrameBody::PairRouteOpened(opened) => pairing_bindings
            .accept_opened(machine_route, opened)
            .map(InboundDispatch::Pairing),
        RelayFrameBody::PairData(data) => pairing_bindings
            .accept_data(data)
            .map(InboundDispatch::Pairing),
        RelayFrameBody::RouteAccepted(accepted) => match &accepted.accepted {
            AcceptedRef::Request { request_route } if !is_zero_request_route(*request_route) => {
                Ok(InboundDispatch::Business {
                    event: BusinessTransportEvent::RouteAccepted(accepted),
                    encoded_len,
                })
            }
            AcceptedRef::PairFrame { .. } => pairing_bindings
                .accept_pair_frame(accepted)
                .map(InboundDispatch::Pairing),
            AcceptedRef::StreamFrame { .. } => publication_bindings
                .accept(connection_generation, &accepted)
                .map(|()| InboundDispatch::PublicationCommitted),
            AcceptedRef::Request { .. } => Err(RemoteTransportError::FrameForbidden),
        },
        RelayFrameBody::PairRouteClosed(closed) => pairing_bindings
            .accept_closed(closed)
            .map(InboundDispatch::Pairing),
        RelayFrameBody::GrantCommitted(committed) => pairing_bindings
            .accept_grant(committed)
            .map(InboundDispatch::Pairing),
        RelayFrameBody::RevocationCommitted(committed) => pairing_bindings
            .accept_revocation(committed)
            .map(InboundDispatch::Pairing),
        RelayFrameBody::Send(send)
            if !is_zero_device_route(send.device_route)
                && !is_zero_request_route(send.request_route) =>
        {
            Ok(InboundDispatch::Business {
                event: BusinessTransportEvent::Send(send),
                encoded_len,
            })
        }
        _ => Err(RemoteTransportError::FrameForbidden),
    }
}

impl RemoteTransport {
    fn from_connected(
        machine_route: MachineRouteId,
        session: Box<dyn ControlSession>,
        authenticator: Arc<MachineLinkAuthenticator>,
        start_permit: Option<RemoteStartPermit>,
        business_startup: BusinessLaneStartup,
    ) -> Self {
        let (supervisor, pairing_lane, business_lane) =
            ControlSupervisor::start(machine_route, session, business_startup);
        Self {
            machine_route,
            supervisor: Some(supervisor),
            pairing_lane: Some(pairing_lane),
            business_lane: Some(business_lane),
            authenticator: Some(authenticator),
            start_permit,
        }
    }

    pub(super) async fn connect(
        identity: ArmedRemoteIdentity,
        config: RelayClientConfig,
        machine_route: MachineRouteId,
        link_cert: SignedCertificate,
        business_startup: BusinessLaneStartup,
    ) -> Result<Self, RemoteTransportConnectError> {
        let (identity, start_permit) = identity.into_transport_parts();
        let authenticator = Arc::new(MachineLinkAuthenticator::new(
            identity,
            machine_route,
            link_cert,
        ));
        Self::connect_with_connector(
            config,
            machine_route,
            authenticator,
            Some(start_permit),
            business_startup,
            &RelayControlConnector,
        )
        .await
    }

    async fn connect_with_connector(
        config: RelayClientConfig,
        machine_route: MachineRouteId,
        authenticator: Arc<MachineLinkAuthenticator>,
        start_permit: Option<RemoteStartPermit>,
        business_startup: BusinessLaneStartup,
        connector: &dyn ControlConnector,
    ) -> Result<Self, RemoteTransportConnectError> {
        RemoteTransportRetryState {
            config,
            machine_route,
            authenticator,
            start_permit,
            business_startup,
        }
        .connect_with_connector(connector)
        .await
    }

    pub async fn send_retirement(
        &mut self,
        retirement: RetireMachine,
    ) -> Result<(), RemoteTransportError> {
        if retirement.machine_route != self.machine_route {
            return Err(RemoteTransportError::RouteMismatch);
        }
        let supervisor = self
            .supervisor
            .as_mut()
            .ok_or(RemoteTransportError::Closed)?;
        let (response_tx, response_rx) = oneshot::channel();
        supervisor
            .command_tx
            .send(SupervisorCommand::SendRetirement {
                retirement,
                response: response_tx,
            })
            .await
            .map_err(|_| RemoteTransportError::Closed)?;
        response_rx
            .await
            .map_err(|_| RemoteTransportError::Closed)?
    }

    /// 原子领取唯一 MachineLink supervisor 上的 bounded business lane。
    /// 未领取或 lane drop 后收到业务 frame 都会关闭当前 transport generation。
    pub(crate) fn take_business_lane(
        &mut self,
    ) -> Result<BusinessTransportLane, RemoteTransportError> {
        let supervisor = self
            .supervisor
            .as_ref()
            .ok_or(RemoteTransportError::Closed)?;
        let lane = self
            .business_lane
            .as_mut()
            .ok_or(RemoteTransportError::BusinessLaneUnavailable)?;
        supervisor.activate_business(lane)?;
        self.business_lane
            .take()
            .ok_or(RemoteTransportError::BusinessLaneUnavailable)
    }

    /// startup 在触达 RemoteLink 前失败且所有派生 owner 已完成 join 后，将唯一
    /// receiver 归还同一 supervisor。归还同时关闭旧 attempt 的 publication handles；
    /// 未证明 quiescence 时 manager 绝不能调用本入口。
    pub(crate) async fn restore_business_lane(
        &mut self,
        lane: BusinessTransportLane,
    ) -> Result<(), RemoteTransportError> {
        if self.business_lane.is_some()
            || lane.machine_route != self.machine_route
            || self.supervisor.is_none()
        {
            return Err(RemoteTransportError::BusinessLaneUnavailable);
        }
        self.supervisor
            .as_ref()
            .ok_or(RemoteTransportError::Closed)?
            .restore_business(&lane)
            .await?;
        self.business_lane = Some(lane);
        Ok(())
    }

    /// 原子取出同一 transport generation 的唯一 pairing lane 与 Weak authority。
    /// data cert 全轴验证失败不会消费 lane；shutdown 后 authority 不延长 key owner 生命周期。
    pub(crate) fn take_pairing_runtime(
        &mut self,
        data_certificate: SignedCertificate,
    ) -> Result<PairingRuntimeParts, RemoteTransportError> {
        if self.supervisor.is_none() {
            return Err(RemoteTransportError::Closed);
        }
        if self.pairing_lane.is_none() {
            return Err(RemoteTransportError::PairingLaneUnavailable);
        }
        let authenticator = self
            .authenticator
            .as_ref()
            .ok_or(RemoteTransportError::Closed)?;
        let anchor = authenticator
            .bind_pairing_anchor(&data_certificate)
            .map_err(map_pairing_authority_error)?;
        let data_signer = MachineDataSignerBindingV1::from_certificate(&data_certificate)
            .map_err(|_| supervisor_failure("remote.transport.pairing_crypto_failed"))?;
        let owner = Arc::downgrade(authenticator);
        self.supervisor
            .as_mut()
            .ok_or(RemoteTransportError::Closed)?
            .activate_pairing(
                self.pairing_lane
                    .as_ref()
                    .ok_or(RemoteTransportError::PairingLaneUnavailable)?,
            )?;
        let mut lane = self
            .pairing_lane
            .take()
            .ok_or(RemoteTransportError::PairingLaneUnavailable)?;
        lane.authority_anchor = Some(anchor.clone());
        let machine_data = MachineDataAuthority {
            owner: owner.clone(),
            anchor: anchor.clone(),
            data_signer,
        };
        Ok(PairingRuntimeParts {
            lane,
            authority: PairingMachineAuthority {
                owner,
                anchor,
                machine_data,
            },
        })
    }

    #[cfg(test)]
    fn take_pairing_lane(
        &mut self,
        data_certificate: SignedCertificate,
    ) -> Result<PairingTransportLane, RemoteTransportError> {
        Ok(self.take_pairing_runtime(data_certificate)?.lane)
    }

    /// 在已经完成 MachineLink authentication 后，沿保留的 owner 冻结同 route 的
    /// typed retirement。shutdown 会先释放 owner，之后本入口固定返回 Closed。
    pub fn freeze_retirement(
        &self,
        relay_server_id: agentdeck_protocol::relay_v2::RelayServerId,
        expected_trust_epoch: u64,
    ) -> Result<FrozenMachineRetirement, RemoteTransportError> {
        self.authenticator
            .as_ref()
            .ok_or(RemoteTransportError::Closed)?
            .freeze_retirement(relay_server_id, expected_trust_epoch)
    }

    pub async fn next_control(&mut self) -> Result<Option<RemoteControl>, RemoteTransportError> {
        self.supervisor
            .as_mut()
            .ok_or(RemoteTransportError::Closed)?
            .next_control()
            .await
    }

    /// Root-present workflow 在 durable 仍为 Active 时恢复 pairing shared-control owner。
    /// 与初次 activation 共用 fail-close gate：exclusive control 保留在 control surface，
    /// 只有 stale shared backlog 可被清除。
    pub(crate) fn reacquire_pairing_shared_control(&mut self) -> Result<(), RemoteTransportError> {
        self.supervisor
            .as_mut()
            .ok_or(RemoteTransportError::Closed)?
            .reacquire_pairing()
    }

    pub async fn reconnect(&mut self) -> Result<(), RemoteTransportError> {
        let supervisor = self
            .supervisor
            .as_mut()
            .ok_or(RemoteTransportError::Closed)?;
        let (response_tx, response_rx) = oneshot::channel();
        supervisor
            .command_tx
            .send(SupervisorCommand::Reconnect {
                response: response_tx,
            })
            .await
            .map_err(|_| RemoteTransportError::Closed)?;
        response_rx
            .await
            .map_err(|_| RemoteTransportError::Closed)?
    }

    pub(super) fn observed_failure_code(&self) -> Option<String> {
        self.supervisor
            .as_ref()
            .and_then(ControlSupervisor::failure_code)
    }

    /// 销毁式关闭：等待 RelayClient reader/writer join 完成后，释放 authenticator、
    /// 旧 key owner 与 start permit。需要同 daemon re-enroll 时必须改用 consuming reclaim。
    pub async fn shutdown(&mut self) {
        shutdown_supervisor_and_owner(&mut self.supervisor, &mut self.authenticator).await;
        self.pairing_lane = None;
        self.business_lane = None;
        self.start_permit = None;
    }

    /// 按值消费旧 transport，先 join Relay session 并销毁旧 signer，再且仅再返回
    /// listener 原始签发的 RemoteStartPermit。返回值不含旧 identity 或任何私钥。
    pub async fn shutdown_and_reclaim_start_permit(
        mut self,
    ) -> Result<RemoteStartPermit, RemoteTransportError> {
        shutdown_and_take_start_permit(
            &mut self.supervisor,
            &mut self.authenticator,
            &mut self.start_permit,
        )
        .await
    }
}

async fn shutdown_supervisor_and_owner(
    supervisor: &mut Option<ControlSupervisor>,
    authenticator: &mut Option<Arc<MachineLinkAuthenticator>>,
) {
    shutdown_supervisor(supervisor).await;
    *authenticator = None;
}

async fn shutdown_supervisor(supervisor: &mut Option<ControlSupervisor>) {
    if let Some(supervisor) = supervisor.take() {
        supervisor.shutdown().await;
    }
}

async fn shutdown_and_take_start_permit<P>(
    supervisor: &mut Option<ControlSupervisor>,
    authenticator: &mut Option<Arc<MachineLinkAuthenticator>>,
    start_permit: &mut Option<P>,
) -> Result<P, RemoteTransportError> {
    shutdown_supervisor(supervisor).await;
    if let Some(owner) = authenticator.take() {
        match Arc::try_unwrap(owner) {
            Ok(owner) => drop(owner),
            Err(owner) => {
                *authenticator = Some(owner);
                return Err(RemoteTransportError::AuthenticatorStillShared);
            }
        }
    }
    start_permit
        .take()
        .ok_or(RemoteTransportError::StartPermitUnavailable)
}

impl fmt::Debug for RemoteTransport {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("RemoteTransport")
            .field("machine", &self.machine_route.redacted())
            .field("connected", &self.supervisor.is_some())
            .finish()
    }
}

#[cfg(test)]
pub(super) struct RemoteTransportTestHarness {
    incoming_tx: mpsc::Sender<Result<Option<OpaqueRouteFrame>, RelayClientError>>,
    sent: Arc<Mutex<Vec<OpaqueRouteFrame>>>,
    reconnects: Arc<std::sync::atomic::AtomicUsize>,
    received: Arc<std::sync::atomic::AtomicUsize>,
    send_started: Arc<std::sync::atomic::AtomicUsize>,
    send_ready: watch::Sender<bool>,
}

#[cfg(test)]
impl RemoteTransportTestHarness {
    pub(super) async fn push_frame(&self, frame: OpaqueRouteFrame) {
        self.incoming_tx
            .send(Ok(Some(frame)))
            .await
            .expect("test control session remains open");
    }

    pub(super) async fn push_error(&self, code: &str) {
        self.incoming_tx
            .send(Err(RelayClientError::Failure {
                code: code.to_owned(),
            }))
            .await
            .expect("test control session remains open");
    }

    pub(super) fn sent_count(&self) -> usize {
        self.sent
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner())
            .len()
    }

    pub(super) fn reconnect_count(&self) -> usize {
        self.reconnects.load(Ordering::SeqCst)
    }

    pub(super) fn received_count(&self) -> usize {
        self.received.load(Ordering::SeqCst)
    }

    pub(super) fn sent_frames(&self) -> Vec<OpaqueRouteFrame> {
        self.sent
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner())
            .clone()
    }

    pub(super) fn send_started_count(&self) -> usize {
        self.send_started.load(Ordering::SeqCst)
    }

    pub(super) fn hold_send_flush(&self) {
        self.send_ready.send_replace(false);
    }

    pub(super) fn release_send_flush(&self) {
        self.send_ready.send_replace(true);
    }
}

#[cfg(test)]
struct ChannelControlSession {
    incoming_rx: mpsc::Receiver<Result<Option<OpaqueRouteFrame>, RelayClientError>>,
    sent: Arc<Mutex<Vec<OpaqueRouteFrame>>>,
    reconnects: Arc<std::sync::atomic::AtomicUsize>,
    received: Arc<std::sync::atomic::AtomicUsize>,
    send_started: Arc<std::sync::atomic::AtomicUsize>,
    send_ready: watch::Receiver<bool>,
}

#[cfg(test)]
#[async_trait]
impl ControlSession for ChannelControlSession {
    async fn send(&mut self, frame: OpaqueRouteFrame) -> Result<(), RelayClientError> {
        self.send_started.fetch_add(1, Ordering::SeqCst);
        while !*self.send_ready.borrow() {
            self.send_ready
                .changed()
                .await
                .map_err(|_| RelayClientError::Failure {
                    code: "relay.client.connection_closed".to_owned(),
                })?;
        }
        self.sent
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner())
            .push(frame);
        Ok(())
    }

    async fn next(&mut self) -> Result<Option<OpaqueRouteFrame>, RelayClientError> {
        let frame = self.incoming_rx.recv().await.unwrap_or(Ok(None));
        if matches!(frame, Ok(Some(_))) {
            self.received.fetch_add(1, Ordering::SeqCst);
        }
        frame
    }

    async fn reconnect(&mut self) -> Result<(), RelayClientError> {
        self.reconnects.fetch_add(1, Ordering::SeqCst);
        Ok(())
    }

    async fn shutdown(&mut self) {}
}

#[cfg(test)]
pub(super) fn active_pairing_transport_for_test(
    machine_route: MachineRouteId,
) -> (
    RemoteTransport,
    PairingTransportLane,
    Arc<RemoteTransportTestHarness>,
) {
    let (incoming_tx, incoming_rx) = mpsc::channel(CONTROL_CHANNEL_CAPACITY);
    let sent = Arc::new(Mutex::new(Vec::new()));
    let reconnects = Arc::new(std::sync::atomic::AtomicUsize::new(0));
    let received = Arc::new(std::sync::atomic::AtomicUsize::new(0));
    let send_started = Arc::new(std::sync::atomic::AtomicUsize::new(0));
    let (send_ready, send_ready_rx) = watch::channel(true);
    let harness = Arc::new(RemoteTransportTestHarness {
        incoming_tx,
        sent: Arc::clone(&sent),
        reconnects: Arc::clone(&reconnects),
        received: Arc::clone(&received),
        send_started: Arc::clone(&send_started),
        send_ready,
    });
    let (mut supervisor, lane, business_lane) = ControlSupervisor::start(
        machine_route,
        Box::new(ChannelControlSession {
            incoming_rx,
            sent,
            reconnects,
            received,
            send_started,
            send_ready: send_ready_rx,
        }),
        BusinessLaneStartup::Dormant,
    );
    supervisor
        .activate_pairing(&lane)
        .expect("fresh test transport activates pairing");
    (
        RemoteTransport {
            machine_route,
            supervisor: Some(supervisor),
            pairing_lane: None,
            business_lane: Some(business_lane),
            authenticator: None,
            start_permit: None,
        },
        lane,
        harness,
    )
}

#[cfg(test)]
pub(crate) mod tests {
    use std::collections::VecDeque;
    use std::convert::Infallible;
    use std::sync::Mutex;
    use std::sync::atomic::{AtomicUsize, Ordering};

    use agentdeck_crypto::rand_core::{TryCryptoRng, TryRng};
    use agentdeck_crypto::{
        HpkePrivateKey, PairTerminalExpectedV1, SecretAeadKey, SignatureBytes, SigningKey,
        open_key_directory_entry, open_pair_pending, open_pair_response, open_pair_terminal,
        sign_authentication_transcript, sign_key_update, sign_sealed, sign_tbs,
        verify_authentication_transcript, verify_device_authorization, verify_key_directory,
        verify_key_update, verify_sealed, verify_tbs,
    };
    use agentdeck_protocol::e2ee::{
        AuthorizationCapabilityV1, AuthorizationPermissionV1, DeviceAuthorizationV1,
        E2EE_FORMAT_VERSION, KeyDirectoryEntry, KeyDirectoryV1, KeyId, KeyPurpose, KeyUpdateInfoV1,
        KeyUpdateV1, OuterContextV1, OuterFrameKind, PairRequestInfoV1, PairResponseInfoV1,
        PairResponsePlaintextV1, PairTerminalOutcomeV1, PairTerminalV1, UnsignedSealedBlobV1,
    };
    use agentdeck_protocol::relay_v2::frame::{
        AcceptedRef, ClosePairRoute, GrantCommitted, InstallGrant, OpenPairRoute, PairData,
        PairRouteCloseOutcome, PairRouteClosed, PairRouteOpened, Ping, Publish, Reply,
        RevocationCommitted, RevokeDevice, RouteAccepted, SealedBlob, Send,
    };
    use agentdeck_protocol::relay_v2::{
        ConnectionInstanceId, DeviceRevocation, DeviceRouteId, Ed25519Signature, GrantSerial,
        KeyDirectoryRevision, LinkGeneration, PairRouteId, PublicKeyBytes, RELAY_PROTOCOL_VERSION,
        RelayFailure, RelayGrant, RelayServerId, RequestRouteId, RootKeyId, StreamGenerationId,
        StreamRouteId, TrustEpoch,
    };
    use agentdeck_protocol::runtime::RUNTIME_PROTOCOL_VERSION;
    use agentdeck_relay_client::RelayTlsPolicy;
    use tokio::sync::Notify;

    use super::*;
    use crate::remote::bootstrap::validate_pairing_device_sign_key;

    const RELAY: RelayServerId = RelayServerId::from_bytes([0x11; 16]);
    const ROUTE: MachineRouteId = MachineRouteId::from_bytes([0x22; 16]);

    /// 仅为跨模块 composition test 保活 production `MachineDataAuthority` 的 Weak owner。
    pub(crate) struct MachineDataAuthorityOwnerLease {
        _owner: Arc<MachineLinkAuthenticator>,
    }

    struct TransitionAuthorityOwner {
        anchor: MachinePairingAnchor,
        data_signing_key: SigningKey,
    }

    impl MachineLinkOwner for TransitionAuthorityOwner {
        fn sign_authentication(
            &self,
            _relay_server_id: RelayServerId,
            _machine_route: MachineRouteId,
            _link_cert: &SignedCertificate,
            _transcript: &AuthenticationTranscriptV1,
        ) -> Result<Ed25519Signature, MachineCertificateError> {
            panic!("transition authority never authenticates a Relay link")
        }

        fn freeze_retirement(
            &self,
            _relay_server_id: RelayServerId,
            _machine_route: MachineRouteId,
            _expected_trust_epoch: u64,
        ) -> Result<FrozenMachineRetirement, MachineRetirementError> {
            panic!("transition authority never freezes retirement")
        }

        fn pairing_anchor(
            &self,
            relay_server_id: RelayServerId,
            machine_route: MachineRouteId,
            data_certificate: &SignedCertificate,
        ) -> Result<MachinePairingAnchor, MachinePairingError> {
            if relay_server_id != self.anchor.relay_server_id
                || machine_route != self.anchor.machine_route
                || data_certificate != &self.anchor.data_certificate
            {
                return Err(MachinePairingError::ContextMismatch);
            }
            Ok(self.anchor.clone())
        }

        fn seal_pair_pending(
            &self,
            _recipient: &HpkePublicKey,
            _info: &PairRequestInfoV1,
            _context: &OuterContextV1,
            _request_hash: [u8; 32],
            _signer: &MachineDataSignerBindingV1,
            _rng: &mut dyn agentdeck_crypto::rand_core::CryptoRng,
        ) -> Result<PairingControlEnvelopeV1, MachinePairingError> {
            panic!("transition authority never seals PairPending")
        }

        fn sign_relay_grant(
            &self,
            _anchor: &MachinePairingAnchor,
            _grant: RelayGrant,
        ) -> Result<RelayGrant, MachinePairingError> {
            panic!("transition authority never signs a RelayGrant")
        }

        fn sign_device_authorization(
            &self,
            _anchor: &MachinePairingAnchor,
            _grant: &RelayGrant,
            _authorization: DeviceAuthorizationV1,
        ) -> Result<DeviceAuthorizationV1, MachinePairingError> {
            panic!("transition authority never signs a DeviceAuthorization")
        }

        fn sign_key_directory(
            &self,
            _anchor: &MachinePairingAnchor,
            _context: &KeyDirectorySignatureContextV1,
            _directory: KeyDirectoryV1,
        ) -> Result<KeyDirectoryV1, MachinePairingError> {
            panic!("transition authority never signs a full KeyDirectory")
        }

        fn sign_key_update(
            &self,
            anchor: &MachinePairingAnchor,
            info: &KeyUpdateInfoV1,
            context: &OuterContextV1,
            update: KeyUpdateV1,
        ) -> Result<KeyUpdateV1, MachinePairingError> {
            if anchor != &self.anchor {
                return Err(MachinePairingError::ContextMismatch);
            }
            let signer = MachineDataSignerBindingV1::from_certificate(&anchor.data_certificate)
                .map_err(|_| MachinePairingError::Crypto)?;
            sign_key_update(&self.data_signing_key, &signer, info, context, update)
                .map_err(Into::into)
        }

        fn sign_sealed(
            &self,
            anchor: &MachinePairingAnchor,
            unsigned: UnsignedSealedBlobV1,
            context: &OuterContextV1,
        ) -> Result<SignedSealedBlobV1, MachinePairingError> {
            if anchor != &self.anchor {
                return Err(MachinePairingError::ContextMismatch);
            }
            Ok(sign_sealed(unsigned, &self.data_signing_key, context))
        }

        fn seal_device_key_recovery_reply(
            &self,
            anchor: &MachinePairingAnchor,
            recipient: &HpkePublicKey,
            info: &DeviceKeyRecoveryInfoV1,
            context: &OuterContextV1,
            update_set: &KeyUpdateSetV1,
            mut rng: &mut dyn agentdeck_crypto::rand_core::CryptoRng,
        ) -> Result<DeviceKeyRecoveryReplyV1, MachinePairingError> {
            if anchor != &self.anchor {
                return Err(MachinePairingError::ContextMismatch);
            }
            let signer = MachineDataSignerBindingV1::from_certificate(&anchor.data_certificate)
                .map_err(|_| MachinePairingError::Crypto)?;
            Ok(crypto_seal_device_key_recovery_reply(
                DeviceKeyRecoverySealAuthority {
                    device_hpke_public_key: recipient,
                    machine_data_signing_key: &self.data_signing_key,
                    signer: &signer,
                },
                info,
                context,
                update_set,
                &mut rng,
            )?)
        }

        fn seal_pair_terminal(
            &self,
            recipient: &HpkePublicKey,
            info: &PairRequestInfoV1,
            context: &OuterContextV1,
            terminal: PairTerminalV1,
            signer: &MachineDataSignerBindingV1,
            mut rng: &mut dyn agentdeck_crypto::rand_core::CryptoRng,
        ) -> Result<PairingControlEnvelopeV1, MachinePairingError> {
            Ok(agentdeck_crypto::seal_pair_terminal(
                recipient,
                info,
                context,
                terminal,
                &self.data_signing_key,
                signer,
                &mut rng,
            )?)
        }

        fn seal_pair_response(
            &self,
            _anchor: &MachinePairingAnchor,
            _recipient: &HpkePublicKey,
            _info: &PairResponseInfoV1,
            _context: &OuterContextV1,
            _plaintext: &PairResponsePlaintextV1,
            _rng: &mut dyn agentdeck_crypto::rand_core::CryptoRng,
        ) -> Result<PairResponseV1, MachinePairingError> {
            panic!("transition authority never seals PairResponse")
        }

        fn sign_device_revocation(
            &self,
            _anchor: &MachinePairingAnchor,
            _revocation: DeviceRevocation,
        ) -> Result<DeviceRevocation, MachinePairingError> {
            panic!("transition authority never signs DeviceRevocation")
        }
    }

    pub(in crate::remote) fn machine_data_authority_for_transition_test(
        anchor: MachinePairingAnchor,
        data_sign_seed: [u8; 32],
    ) -> (MachineDataAuthority, MachineDataAuthorityOwnerLease) {
        let data_signing_key = SigningKey::from_seed(&data_sign_seed);
        assert_eq!(
            data_signing_key.verifying_key().to_bytes(),
            anchor.data_certificate.subject_pubkey.0,
            "test MachineData private key must match the authenticated Store binding"
        );
        let relay_server_id = anchor.relay_server_id;
        let machine_route = anchor.machine_route;
        let data_certificate = anchor.data_certificate.clone();
        let owner = TransitionAuthorityOwner {
            anchor,
            data_signing_key,
        };
        let authenticator = Arc::new(MachineLinkAuthenticator::new(
            owner,
            machine_route,
            data_certificate.clone(),
        ));
        *authenticator
            .authenticated_relay
            .lock()
            .expect("bind transition authority Relay") = Some(relay_server_id);
        let anchor = authenticator
            .bind_pairing_anchor(&data_certificate)
            .expect("bind transition authority anchor");
        let data_signer = MachineDataSignerBindingV1::from_certificate(&data_certificate)
            .expect("bind transition MachineData signer");
        let authority = MachineDataAuthority {
            owner: Arc::downgrade(&authenticator),
            anchor,
            data_signer,
        };
        (
            authority,
            MachineDataAuthorityOwnerLease {
                _owner: authenticator,
            },
        )
    }

    struct DeterministicRng {
        seed: [u8; 32],
        counter: u64,
        block: [u8; 32],
        offset: usize,
    }

    impl DeterministicRng {
        fn new(seed: [u8; 32]) -> Self {
            Self {
                seed,
                counter: 0,
                block: [0; 32],
                offset: 32,
            }
        }

        fn fill(&mut self, output: &mut [u8]) {
            for byte in output {
                if self.offset == self.block.len() {
                    let mut input = b"AgentDeck/RemotePairingAuthorityTestRng\0".to_vec();
                    input.extend_from_slice(&self.seed);
                    input.extend_from_slice(&self.counter.to_be_bytes());
                    self.block = sha256(&input);
                    self.counter += 1;
                    self.offset = 0;
                }
                *byte = self.block[self.offset];
                self.offset += 1;
            }
        }
    }

    impl TryRng for DeterministicRng {
        type Error = Infallible;

        fn try_next_u32(&mut self) -> Result<u32, Self::Error> {
            let mut bytes = [0; 4];
            self.fill(&mut bytes);
            Ok(u32::from_le_bytes(bytes))
        }

        fn try_next_u64(&mut self) -> Result<u64, Self::Error> {
            let mut bytes = [0; 8];
            self.fill(&mut bytes);
            Ok(u64::from_le_bytes(bytes))
        }

        fn try_fill_bytes(&mut self, output: &mut [u8]) -> Result<(), Self::Error> {
            self.fill(output);
            Ok(())
        }
    }

    impl TryCryptoRng for DeterministicRng {}

    struct FakeOwner {
        signing_key: SigningKey,
        root_signing_key: SigningKey,
        expected_relay: RelayServerId,
        expected_route: MachineRouteId,
        expected_cert: SignedCertificate,
        observed: Arc<Mutex<Vec<AuthenticationTranscriptV1>>>,
        drops: Arc<AtomicUsize>,
    }

    impl MachineLinkOwner for FakeOwner {
        fn sign_authentication(
            &self,
            relay_server_id: RelayServerId,
            machine_route: MachineRouteId,
            link_cert: &SignedCertificate,
            transcript: &AuthenticationTranscriptV1,
        ) -> Result<Ed25519Signature, MachineCertificateError> {
            if relay_server_id != self.expected_relay
                || machine_route != self.expected_route
                || link_cert != &self.expected_cert
            {
                return Err(MachineCertificateError::TbsContextMismatch);
            }
            self.observed
                .lock()
                .expect("lock observed transcripts")
                .push(transcript.clone());
            Ok(sign_authentication_transcript(&self.signing_key, transcript).into())
        }

        fn freeze_retirement(
            &self,
            relay_server_id: RelayServerId,
            machine_route: MachineRouteId,
            expected_trust_epoch: u64,
        ) -> Result<FrozenMachineRetirement, MachineRetirementError> {
            if relay_server_id != self.expected_relay {
                return Err(MachineRetirementError::AuthenticatedRelayMismatch);
            }
            if machine_route != self.expected_route {
                return Err(MachineRetirementError::InvalidMachineRouteId);
            }
            if expected_trust_epoch != self.expected_cert.trust_epoch.value() {
                return Err(MachineRetirementError::TrustEpochMismatch);
            }
            let root_fingerprint = sha256(&self.root_signing_key.verifying_key().to_bytes());
            let mut retirement = RetireMachine {
                machine_route,
                root_key_id: self.expected_cert.root_key_id,
                trust_epoch: self.expected_cert.trust_epoch,
                signature: Ed25519Signature([0; 64]),
            };
            retirement.signature = sign_tbs(
                &self.root_signing_key,
                &retirement.to_be_signed_v1(relay_server_id, root_fingerprint),
            )
            .into();
            Ok(
                crate::remote::trust_reset::frozen_machine_retirement_for_test(
                    relay_server_id,
                    root_fingerprint,
                    retirement,
                ),
            )
        }

        fn pairing_anchor(
            &self,
            relay_server_id: RelayServerId,
            machine_route: MachineRouteId,
            data_certificate: &SignedCertificate,
        ) -> Result<MachinePairingAnchor, MachinePairingError> {
            let data = SigningKey::from_seed(&[0x33; 32]);
            let expected_root_fingerprint =
                sha256(&self.root_signing_key.verifying_key().to_bytes());
            let certificate_error =
                if data_certificate.cert_role != agentdeck_protocol::relay_v2::CertRole::Data {
                    Some(MachineCertificateError::RoleMismatch)
                } else if data_certificate.subject_pubkey.0 != data.verifying_key().to_bytes() {
                    Some(MachineCertificateError::SubjectMismatch)
                } else if data_certificate.root_key_id != RootKeyId::from_bytes([0x61; 16]) {
                    Some(MachineCertificateError::RootKeyIdMismatch)
                } else if data_certificate.trust_epoch != TrustEpoch::new(3) {
                    Some(MachineCertificateError::TrustEpochMismatch)
                } else if data_certificate.generation != LinkGeneration::new(9) {
                    Some(MachineCertificateError::GenerationMismatch)
                } else if data_certificate.not_after_ms.is_some() {
                    Some(MachineCertificateError::UnexpectedExpiry)
                } else {
                    let tbs = data_certificate.to_be_signed_v1(
                        relay_server_id,
                        machine_route,
                        expected_root_fingerprint,
                    );
                    verify_tbs(
                        &self.root_signing_key.verifying_key(),
                        &tbs,
                        &SignatureBytes::from(data_certificate.signature),
                    )
                    .err()
                    .map(|_| MachineCertificateError::SignatureInvalid)
                };
            if let Some(error) = certificate_error {
                return Err(MachinePairingError::Certificate(error));
            }
            let (_, hpke_public) = agentdeck_crypto::HpkePrivateKey::derive_keypair(&[0x34; 32]);
            Ok(MachinePairingAnchor {
                relay_server_id,
                machine_route,
                root_public_key: PublicKeyBytes(self.root_signing_key.verifying_key().to_bytes()),
                root_fingerprint: expected_root_fingerprint,
                root_key_id: data_certificate.root_key_id,
                trust_epoch: data_certificate.trust_epoch,
                machine_hpke_public_key: PublicKeyBytes(
                    hpke_public.to_bytes().try_into().expect("32-byte HPKE key"),
                ),
                data_generation: data_certificate.generation,
                data_certificate: data_certificate.clone(),
            })
        }

        fn seal_pair_pending(
            &self,
            recipient: &HpkePublicKey,
            info: &PairRequestInfoV1,
            context: &OuterContextV1,
            request_hash: [u8; 32],
            signer: &MachineDataSignerBindingV1,
            mut rng: &mut dyn agentdeck_crypto::rand_core::CryptoRng,
        ) -> Result<PairingControlEnvelopeV1, MachinePairingError> {
            Ok(agentdeck_crypto::seal_pair_pending(
                recipient,
                info,
                context,
                request_hash,
                &SigningKey::from_seed(&[0x33; 32]),
                signer,
                &mut rng,
            )?)
        }

        fn seal_pair_terminal(
            &self,
            recipient: &HpkePublicKey,
            info: &PairRequestInfoV1,
            context: &OuterContextV1,
            terminal: PairTerminalV1,
            signer: &MachineDataSignerBindingV1,
            mut rng: &mut dyn agentdeck_crypto::rand_core::CryptoRng,
        ) -> Result<PairingControlEnvelopeV1, MachinePairingError> {
            Ok(agentdeck_crypto::seal_pair_terminal(
                recipient,
                info,
                context,
                terminal,
                &SigningKey::from_seed(&[0x33; 32]),
                signer,
                &mut rng,
            )?)
        }

        fn sign_relay_grant(
            &self,
            anchor: &MachinePairingAnchor,
            mut grant: RelayGrant,
        ) -> Result<RelayGrant, MachinePairingError> {
            if grant.signature.0 != [0; 64]
                || grant.machine_route != anchor.machine_route
                || grant.device_route.as_bytes() == &[0; 16]
                || grant.grant_serial.value() == 0
                || grant.root_key_id != anchor.root_key_id
                || grant.trust_epoch != anchor.trust_epoch
            {
                return Err(MachinePairingError::ContextMismatch);
            }
            validate_pairing_device_sign_key(anchor.relay_server_id, grant.device_sign_pubkey)?;
            grant.signature = sign_tbs(
                &self.root_signing_key,
                &grant.to_be_signed_v1(anchor.relay_server_id, anchor.root_fingerprint),
            )
            .into();
            Ok(grant)
        }

        fn sign_device_authorization(
            &self,
            anchor: &MachinePairingAnchor,
            grant: &RelayGrant,
            authorization: DeviceAuthorizationV1,
        ) -> Result<DeviceAuthorizationV1, MachinePairingError> {
            if grant.machine_route != anchor.machine_route
                || grant.device_route.as_bytes() == &[0; 16]
                || grant.grant_serial.value() == 0
                || grant.root_key_id != anchor.root_key_id
                || grant.trust_epoch != anchor.trust_epoch
                || grant.signature.0 == [0; 64]
            {
                return Err(MachinePairingError::ContextMismatch);
            }
            validate_pairing_device_sign_key(anchor.relay_server_id, grant.device_sign_pubkey)?;
            verify_tbs(
                &self.root_signing_key.verifying_key(),
                &grant.to_be_signed_v1(anchor.relay_server_id, anchor.root_fingerprint),
                &SignatureBytes::from(grant.signature),
            )?;
            Ok(agentdeck_crypto::sign_device_authorization(
                &self.root_signing_key,
                anchor.relay_server_id,
                grant,
                authorization,
            )?)
        }

        fn sign_key_directory(
            &self,
            anchor: &MachinePairingAnchor,
            context: &KeyDirectorySignatureContextV1,
            directory: KeyDirectoryV1,
        ) -> Result<KeyDirectoryV1, MachinePairingError> {
            if context.relay_server_id != anchor.relay_server_id
                || context.machine_route != anchor.machine_route
                || context.root_trust_epoch != anchor.trust_epoch
                || context.device_route.as_bytes() == &[0; 16]
                || context.grant_serial.value() == 0
            {
                return Err(MachinePairingError::ContextMismatch);
            }
            let data = SigningKey::from_seed(&[0x33; 32]);
            let signer = MachineDataSignerBindingV1::from_certificate(&anchor.data_certificate)
                .map_err(|_| MachinePairingError::Crypto)?;
            Ok(agentdeck_crypto::sign_key_directory(
                &data, &signer, context, directory,
            )?)
        }

        fn sign_key_update(
            &self,
            anchor: &MachinePairingAnchor,
            info: &KeyUpdateInfoV1,
            context: &OuterContextV1,
            update: KeyUpdateV1,
        ) -> Result<KeyUpdateV1, MachinePairingError> {
            if info.relay_server_id != anchor.relay_server_id
                || info.machine_route != anchor.machine_route
                || info.root_trust_epoch != anchor.trust_epoch
            {
                return Err(MachinePairingError::ContextMismatch);
            }
            let data = SigningKey::from_seed(&[0x33; 32]);
            let signer = MachineDataSignerBindingV1::from_certificate(&anchor.data_certificate)
                .map_err(|_| MachinePairingError::Crypto)?;
            Ok(agentdeck_crypto::sign_key_update(
                &data, &signer, info, context, update,
            )?)
        }

        fn sign_sealed(
            &self,
            anchor: &MachinePairingAnchor,
            unsigned: UnsignedSealedBlobV1,
            context: &OuterContextV1,
        ) -> Result<SignedSealedBlobV1, MachinePairingError> {
            if context.machine_route != Some(anchor.machine_route)
                || context.relay_protocol_version != RELAY_PROTOCOL_VERSION
                || context.e2ee_format_version != E2EE_FORMAT_VERSION
                || context.validate().is_err()
            {
                return Err(MachinePairingError::ContextMismatch);
            }
            Ok(agentdeck_crypto::sign_sealed(
                unsigned,
                &SigningKey::from_seed(&[0x33; 32]),
                context,
            ))
        }

        fn seal_pair_response(
            &self,
            anchor: &MachinePairingAnchor,
            recipient: &HpkePublicKey,
            info: &PairResponseInfoV1,
            context: &OuterContextV1,
            plaintext: &PairResponsePlaintextV1,
            mut rng: &mut dyn agentdeck_crypto::rand_core::CryptoRng,
        ) -> Result<PairResponseV1, MachinePairingError> {
            if info.relay_server_id != anchor.relay_server_id
                || info.machine_route != anchor.machine_route
                || info.root_trust_epoch != anchor.trust_epoch
                || plaintext.relay_grant.machine_route != anchor.machine_route
                || plaintext.relay_grant.device_route.as_bytes() == &[0; 16]
                || plaintext.relay_grant.grant_serial.value() == 0
                || plaintext.relay_grant.root_key_id != anchor.root_key_id
                || plaintext.relay_grant.trust_epoch != anchor.trust_epoch
                || plaintext.relay_grant.signature.0 == [0; 64]
            {
                return Err(MachinePairingError::ContextMismatch);
            }
            validate_pairing_device_sign_key(
                anchor.relay_server_id,
                plaintext.relay_grant.device_sign_pubkey,
            )?;
            let data = SigningKey::from_seed(&[0x33; 32]);
            let signer = MachineDataSignerBindingV1::from_certificate(&anchor.data_certificate)
                .map_err(|_| MachinePairingError::Crypto)?;
            Ok(agentdeck_crypto::seal_pair_response(
                recipient,
                info,
                context,
                plaintext,
                agentdeck_crypto::PairResponseSealAuthority {
                    machine_data_signing_key: &data,
                    signer: &signer,
                    machine_root_verifying_key: &self.root_signing_key.verifying_key(),
                },
                &mut rng,
            )?)
        }

        fn sign_device_revocation(
            &self,
            anchor: &MachinePairingAnchor,
            mut revocation: DeviceRevocation,
        ) -> Result<DeviceRevocation, MachinePairingError> {
            if revocation.machine_route != anchor.machine_route
                || revocation.device_route.as_bytes() == &[0; 16]
                || revocation.grant_serial.value() == 0
                || revocation.root_key_id != anchor.root_key_id
                || revocation.trust_epoch != anchor.trust_epoch
                || revocation.signature.0 != [0; 64]
            {
                return Err(MachinePairingError::ContextMismatch);
            }
            revocation.signature = sign_tbs(
                &self.root_signing_key,
                &revocation.to_be_signed_v1(anchor.relay_server_id, anchor.root_fingerprint),
            )
            .into();
            Ok(revocation)
        }
    }

    impl Drop for FakeOwner {
        fn drop(&mut self) {
            self.drops.fetch_add(1, Ordering::SeqCst);
        }
    }

    #[derive(Default)]
    struct Harness {
        connects: AtomicUsize,
        connect_failures_remaining: AtomicUsize,
        reconnects: AtomicUsize,
        shutdowns: AtomicUsize,
        session_drops: AtomicUsize,
        business_dispatches: AtomicUsize,
        sent: Mutex<Vec<OpaqueRouteFrame>>,
        incoming: Mutex<VecDeque<OpaqueRouteFrame>>,
        incoming_error: Mutex<Option<String>>,
        incoming_ready: Notify,
        authentications: Mutex<Vec<Authenticate>>,
        shutdown_gate: Mutex<Option<Arc<ShutdownGate>>>,
        shutdown_started: Notify,
    }

    struct ShutdownGate {
        entered: Notify,
        release: Notify,
    }

    struct FakeConnector {
        harness: Arc<Harness>,
        challenge: Challenge,
    }

    #[async_trait]
    impl ControlConnector for FakeConnector {
        async fn connect(
            &self,
            _config: RelayClientConfig,
            authenticator: Arc<MachineLinkAuthenticator>,
        ) -> Result<Box<dyn ControlSession>, RelayClientError> {
            self.harness.connects.fetch_add(1, Ordering::SeqCst);
            let authenticate = authenticator.authenticate(&self.challenge).await?;
            if authenticate.proof != authenticator.proof() {
                return Err(client_error("relay.client.authenticator_invalid"));
            }
            self.harness
                .authentications
                .lock()
                .expect("lock authentications")
                .push(authenticate);
            if self
                .harness
                .connect_failures_remaining
                .load(Ordering::SeqCst)
                > 0
            {
                self.harness
                    .connect_failures_remaining
                    .fetch_sub(1, Ordering::SeqCst);
                return Err(client_error("relay.client.offline"));
            }
            Ok(Box::new(FakeSession {
                harness: Arc::clone(&self.harness),
            }))
        }
    }

    struct FakeSession {
        harness: Arc<Harness>,
    }

    #[async_trait]
    impl ControlSession for FakeSession {
        async fn send(&mut self, frame: OpaqueRouteFrame) -> Result<(), RelayClientError> {
            self.harness
                .sent
                .lock()
                .expect("lock sent frames")
                .push(frame);
            Ok(())
        }

        async fn next(&mut self) -> Result<Option<OpaqueRouteFrame>, RelayClientError> {
            loop {
                if let Some(code) = self
                    .harness
                    .incoming_error
                    .lock()
                    .expect("lock incoming error")
                    .take()
                {
                    return Err(client_error(&code));
                }
                if let Some(frame) = self
                    .harness
                    .incoming
                    .lock()
                    .expect("lock incoming frames")
                    .pop_front()
                {
                    return Ok(Some(frame));
                }
                self.harness.incoming_ready.notified().await;
            }
        }

        async fn reconnect(&mut self) -> Result<(), RelayClientError> {
            self.harness.reconnects.fetch_add(1, Ordering::SeqCst);
            Ok(())
        }

        async fn shutdown(&mut self) {
            self.harness.shutdowns.fetch_add(1, Ordering::SeqCst);
            self.harness.shutdown_started.notify_waiters();
            let gate = self
                .harness
                .shutdown_gate
                .lock()
                .expect("lock shutdown gate")
                .clone();
            if let Some(gate) = gate {
                gate.entered.notify_one();
                gate.release.notified().await;
            }
        }
    }

    impl Drop for FakeSession {
        fn drop(&mut self) {
            self.harness.session_drops.fetch_add(1, Ordering::SeqCst);
        }
    }

    impl Harness {
        fn push_incoming(&self, frame: OpaqueRouteFrame) {
            self.incoming
                .lock()
                .expect("lock incoming frames")
                .push_back(frame);
            self.incoming_ready.notify_one();
        }

        fn push_error(&self, code: &str) {
            *self.incoming_error.lock().expect("lock incoming error") = Some(code.to_owned());
            self.incoming_ready.notify_one();
        }
    }

    struct ConnectedFixture {
        transport: RemoteTransport,
        harness: Arc<Harness>,
        observed: Arc<Mutex<Vec<AuthenticationTranscriptV1>>>,
        owner_drops: Arc<AtomicUsize>,
        link_verifying_key: agentdeck_crypto::VerifyingKey,
        link_cert: SignedCertificate,
        data_cert: SignedCertificate,
        challenge: Challenge,
    }

    async fn connected_fixture(
        incoming: Vec<OpaqueRouteFrame>,
        shutdown_gate: Option<Arc<ShutdownGate>>,
    ) -> ConnectedFixture {
        connected_fixture_with_business_startup(
            incoming,
            shutdown_gate,
            BusinessLaneStartup::Dormant,
        )
        .await
    }

    async fn connected_fixture_with_business_startup(
        incoming: Vec<OpaqueRouteFrame>,
        shutdown_gate: Option<Arc<ShutdownGate>>,
        business_startup: BusinessLaneStartup,
    ) -> ConnectedFixture {
        let root = SigningKey::from_seed(&[0x31; 32]);
        let link = SigningKey::from_seed(&[0x32; 32]);
        let link_verifying_key = link.verifying_key();
        let link_cert = signed_link_certificate(&root, &link);
        let data_cert = signed_data_certificate(&root, RELAY, ROUTE);
        let observed = Arc::new(Mutex::new(Vec::new()));
        let owner_drops = Arc::new(AtomicUsize::new(0));
        let owner = FakeOwner {
            signing_key: link,
            root_signing_key: root,
            expected_relay: RELAY,
            expected_route: ROUTE,
            expected_cert: link_cert.clone(),
            observed: Arc::clone(&observed),
            drops: Arc::clone(&owner_drops),
        };
        let authenticator = Arc::new(MachineLinkAuthenticator::new(
            owner,
            ROUTE,
            link_cert.clone(),
        ));
        let harness = Arc::new(Harness {
            incoming: Mutex::new(incoming.into()),
            shutdown_gate: Mutex::new(shutdown_gate),
            ..Harness::default()
        });
        let challenge = Challenge {
            relay_server_id: RELAY,
            connection_instance: ConnectionInstanceId::from_bytes([0x41; 16]),
            challenge_nonce: [0x42; 32],
        };
        let connector = FakeConnector {
            harness: Arc::clone(&harness),
            challenge: challenge.clone(),
        };
        let config = RelayClientConfig::new(
            "wss://relay.example.test/",
            RELAY,
            RelayTlsPolicy::pinned_spki(vec![[0x51; 32]]).expect("valid pin policy"),
        )
        .expect("valid Relay config");
        let transport = RemoteTransport::connect_with_connector(
            config,
            ROUTE,
            authenticator,
            None,
            business_startup,
            &connector,
        )
        .await
        .expect("connect fake control session");
        ConnectedFixture {
            transport,
            harness,
            observed,
            owner_drops,
            link_verifying_key,
            link_cert,
            data_cert,
            challenge,
        }
    }

    fn signed_link_certificate(root: &SigningKey, link: &SigningKey) -> SignedCertificate {
        let mut certificate = SignedCertificate {
            subject_pubkey: agentdeck_protocol::relay_v2::PublicKeyBytes(
                link.verifying_key().to_bytes(),
            ),
            cert_role: agentdeck_protocol::relay_v2::CertRole::Link,
            generation: LinkGeneration::new(7),
            root_key_id: RootKeyId::from_bytes([0x61; 16]),
            trust_epoch: TrustEpoch::new(3),
            not_after_ms: None,
            signature: Ed25519Signature([0; 64]),
        };
        certificate.signature = sign_tbs(
            root,
            &certificate.to_be_signed_v1(RELAY, ROUTE, sha256(&root.verifying_key().to_bytes())),
        )
        .into();
        certificate
    }

    fn signed_data_certificate(
        root: &SigningKey,
        relay_server_id: RelayServerId,
        machine_route: MachineRouteId,
    ) -> SignedCertificate {
        let data = SigningKey::from_seed(&[0x33; 32]);
        let mut certificate = SignedCertificate {
            subject_pubkey: PublicKeyBytes(data.verifying_key().to_bytes()),
            cert_role: agentdeck_protocol::relay_v2::CertRole::Data,
            generation: LinkGeneration::new(9),
            root_key_id: RootKeyId::from_bytes([0x61; 16]),
            trust_epoch: TrustEpoch::new(3),
            not_after_ms: None,
            signature: Ed25519Signature([0; 64]),
        };
        certificate.signature = sign_tbs(
            root,
            &certificate.to_be_signed_v1(
                relay_server_id,
                machine_route,
                sha256(&root.verifying_key().to_bytes()),
            ),
        )
        .into();
        certificate
    }

    fn client_error(code: &str) -> RelayClientError {
        RelayClientError::Failure {
            code: code.to_owned(),
        }
    }

    fn frame(body: RelayFrameBody) -> OpaqueRouteFrame {
        OpaqueRouteFrame {
            version: RELAY_PROTOCOL_VERSION,
            body,
        }
    }

    fn publication_wire(seed: u8) -> Arc<[u8]> {
        Arc::from(
            UnsignedSealedBlobV1::new(
                KeyId {
                    purpose: KeyPurpose::Catalog,
                    epoch: 7,
                },
                7,
                11,
                [seed; 12],
                vec![seed.wrapping_add(1); 16],
            )
            .attach_signature(Ed25519Signature([seed.wrapping_add(2); 64]))
            .to_wire_bytes(),
        )
    }

    fn publication_context(
        machine_route: MachineRouteId,
        stream_route: StreamRouteId,
        generation: StreamGenerationId,
        stream_seq: u64,
    ) -> OuterContextV1 {
        OuterContextV1 {
            frame_kind: OuterFrameKind::CatalogPublish,
            relay_protocol_version: RELAY_PROTOCOL_VERSION,
            e2ee_format_version: E2EE_FORMAT_VERSION,
            machine_route: Some(machine_route),
            device_route: None,
            stream_route: Some(stream_route),
            request_route: None,
            pair_route: None,
            stream_generation: Some(generation),
            stream_cursor: None,
            stream_seq: Some(stream_seq),
            message_key_epoch: 7,
        }
    }

    #[tokio::test]
    async fn failed_manager_start_can_restore_and_reclaim_the_same_business_lane() {
        let mut fixture = connected_fixture(Vec::new(), None).await;
        let business = fixture
            .transport
            .take_business_lane()
            .expect("claim business lane for first startup attempt");
        let stale_publication = business.publication_handle();

        fixture
            .transport
            .restore_business_lane(business)
            .await
            .expect("joined startup rollback restores its exact lane");
        let exact_blob = publication_wire(0xb1);
        assert!(matches!(
            stale_publication
                .publish_exact(
                    StreamRouteId::from_bytes([0xb2; 16]),
                    StreamGenerationId::from_bytes([0xb3; 16]),
                    0,
                    Arc::clone(&exact_blob),
                    sha256(exact_blob.as_ref()),
                )
                .await,
            Err(RemoteTransportError::BusinessLaneUnavailable)
        ));
        assert!(
            fixture.harness.sent.lock().expect("lock sent").is_empty(),
            "restored lane must fence handles from the failed startup attempt"
        );

        let retry_lane = fixture
            .transport
            .take_business_lane()
            .expect("same process can claim a fresh startup attempt");
        let stale_retry = tokio::time::timeout(
            std::time::Duration::from_millis(100),
            stale_publication.publish_exact(
                StreamRouteId::from_bytes([0xb4; 16]),
                StreamGenerationId::from_bytes([0xb5; 16]),
                0,
                Arc::clone(&exact_blob),
                sha256(exact_blob.as_ref()),
            ),
        )
        .await;
        assert!(matches!(
            stale_retry,
            Ok(Err(RemoteTransportError::BusinessLaneUnavailable))
        ));
        assert!(
            fixture.harness.sent.lock().expect("lock sent").is_empty(),
            "a stale publication handle must never revive with a later lane activation"
        );
        drop(retry_lane);
        fixture.transport.shutdown().await;
    }

    #[tokio::test]
    async fn rollback_deactivation_serializes_inflight_publication_before_next_activation() {
        let (mut transport, _pairing_lane, harness) = active_pairing_transport_for_test(ROUTE);
        let business = transport
            .take_business_lane()
            .expect("claim first activation");
        let stale_publication = business.publication_handle();
        let stream_route = StreamRouteId::from_bytes([0xb6; 16]);
        let generation = StreamGenerationId::from_bytes([0xb7; 16]);
        let exact_blob = publication_wire(0xb8);
        let blob_sha256 = sha256(exact_blob.as_ref());

        harness.hold_send_flush();
        let old_attempt = tokio::spawn({
            let exact_blob = Arc::clone(&exact_blob);
            async move {
                stale_publication
                    .publish_exact(stream_route, generation, 0, exact_blob, blob_sha256)
                    .await
            }
        });
        tokio::time::timeout(Duration::from_secs(2), async {
            while harness.send_started_count() == 0 {
                tokio::task::yield_now().await;
            }
        })
        .await
        .expect("old RegisterStream enters the supervisor");

        {
            let restore = transport.restore_business_lane(business);
            tokio::pin!(restore);
            assert!(
                tokio::time::timeout(Duration::from_millis(50), restore.as_mut())
                    .await
                    .is_err(),
                "rollback must wait for earlier supervisor sends to quiesce"
            );
            harness.release_send_flush();
            restore
                .await
                .expect("serialized deactivation follows the old RegisterStream");
        }

        let retry_lane = transport
            .take_business_lane()
            .expect("claim a distinct retry activation");
        assert!(matches!(
            tokio::time::timeout(Duration::from_secs(2), old_attempt)
                .await
                .expect("old publication future resolves")
                .expect("join old publication future"),
            Err(RemoteTransportError::BusinessLaneUnavailable)
        ));
        let sent = harness.sent_frames();
        assert_eq!(sent.len(), 1, "old Publish must not cross retry activation");
        assert!(matches!(sent[0].body, RelayFrameBody::RegisterStream(_)));

        drop(retry_lane);
        transport.shutdown().await;
    }

    #[tokio::test]
    async fn register_only_flushes_exact_stream_on_the_existing_business_fifo() {
        let mut fixture = connected_fixture(Vec::new(), None).await;
        let business = fixture
            .transport
            .take_business_lane()
            .expect("take unique business lane");
        let registration = business.publication_handle();
        let stream_route = StreamRouteId::from_bytes([0xbe; 16]);
        let generation = StreamGenerationId::from_bytes([0xbf; 16]);

        for expected_frames in 1..=2 {
            assert_eq!(
                registration
                    .register_stream_exact(stream_route, generation)
                    .await
                    .expect("flush exact RegisterStream"),
                MachineStreamRegistrationOutcome::Registered {
                    connection_generation: INITIAL_PAIRING_GENERATION,
                }
            );
            let sent = fixture.harness.sent.lock().expect("lock sent").clone();
            assert_eq!(sent.len(), expected_frames);
            assert!(matches!(
                &sent[expected_frames - 1].body,
                RelayFrameBody::RegisterStream(register)
                    if register.machine_route == ROUTE
                        && register.stream_route == stream_route
                        && register.generation == generation
            ));
            assert!(
                sent.iter()
                    .all(|frame| !matches!(frame.body, RelayFrameBody::Publish(_)))
            );
        }
        assert_eq!(fixture.harness.connects.load(Ordering::SeqCst), 1);
        fixture.transport.shutdown().await;
    }

    #[tokio::test]
    async fn publication_handle_uses_same_session_and_waits_for_exact_stream_commit() {
        let mut fixture = connected_fixture(Vec::new(), None).await;
        let business = fixture
            .transport
            .take_business_lane()
            .expect("take unique business lane");
        let publisher = business.publication_handle();
        let stream_route = StreamRouteId::from_bytes([0xc1; 16]);
        let generation = StreamGenerationId::from_bytes([0xc2; 16]);
        let exact_blob = publication_wire(0xc3);
        let blob_sha256 = sha256(exact_blob.as_ref());
        let publish = tokio::spawn({
            let publisher = publisher.clone();
            let exact_blob = Arc::clone(&exact_blob);
            async move {
                publisher
                    .publish_exact(stream_route, generation, 0, exact_blob, blob_sha256)
                    .await
            }
        });

        tokio::time::timeout(std::time::Duration::from_secs(2), async {
            while fixture.harness.sent.lock().expect("lock sent").len() != 2 {
                tokio::task::yield_now().await;
            }
        })
        .await
        .expect("register and publish use the existing supervisor");
        let sent = fixture.harness.sent.lock().expect("lock sent").clone();
        assert!(matches!(
            &sent[0].body,
            RelayFrameBody::RegisterStream(register)
                if register.machine_route == ROUTE
                    && register.stream_route == stream_route
                    && register.generation == generation
        ));
        assert!(matches!(
            &sent[1].body,
            RelayFrameBody::Publish(frame)
                if frame.stream_route == stream_route
                    && frame.generation == generation
                    && frame.stream_seq == 0
                    && frame.sealed_blob.0.as_slice() == exact_blob.as_ref()
        ));
        assert!(!publish.is_finished(), "writer flush is not Relay COMMIT");
        assert_eq!(fixture.harness.connects.load(Ordering::SeqCst), 1);

        fixture
            .harness
            .push_incoming(frame(RelayFrameBody::RouteAccepted(RouteAccepted {
                accepted: AcceptedRef::StreamFrame {
                    stream_route,
                    stream_seq: 0,
                },
            })));
        let outcome = publish
            .await
            .expect("join publisher")
            .expect("valid publish");
        assert_eq!(
            outcome,
            MachinePublicationOutcome::Committed(MachinePublicationCommit {
                connection_generation: INITIAL_PAIRING_GENERATION,
                stream_route,
                stream_generation: generation,
                stream_seq: 0,
                blob_sha256,
            })
        );
        assert_eq!(fixture.harness.connects.load(Ordering::SeqCst), 1);
        fixture.transport.shutdown().await;
    }

    #[tokio::test]
    async fn max_publication_is_rejected_before_the_existing_session_is_touched() {
        let mut fixture = connected_fixture(Vec::new(), None).await;
        let business = fixture
            .transport
            .take_business_lane()
            .expect("take unique business lane");
        let publisher = business.publication_handle();
        let stream_route = StreamRouteId::from_bytes([0xd1; 16]);
        let generation = StreamGenerationId::from_bytes([0xd2; 16]);
        let exact_blob = publication_wire(0xd3);
        let blob_sha256 = sha256(exact_blob.as_ref());
        assert!(matches!(
            publisher
                .publish_exact(stream_route, generation, u64::MAX, exact_blob, blob_sha256)
                .await,
            Err(RemoteTransportError::PublicationBindingMismatch)
        ));
        assert!(
            fixture.harness.sent.lock().expect("lock sent").is_empty(),
            "MAX must be rejected before RegisterStream or Publish enters the existing session"
        );

        let publish = tokio::spawn({
            let publisher = publisher.clone();
            let exact_blob = publication_wire(0xd4);
            let blob_sha256 = sha256(exact_blob.as_ref());
            async move {
                publisher
                    .publish_exact(
                        stream_route,
                        generation,
                        u64::MAX - 1,
                        exact_blob,
                        blob_sha256,
                    )
                    .await
            }
        });
        tokio::time::timeout(std::time::Duration::from_secs(2), async {
            while fixture.harness.sent.lock().expect("lock sent").len() != 2 {
                tokio::task::yield_now().await;
            }
        })
        .await
        .expect("MAX - 1 reaches the existing session");
        assert!(matches!(
            &fixture.harness.sent.lock().expect("lock sent")[1].body,
            RelayFrameBody::Publish(frame)
                if frame.stream_seq == u64::MAX - 1
        ));
        fixture
            .harness
            .push_incoming(frame(RelayFrameBody::RouteAccepted(RouteAccepted {
                accepted: AcceptedRef::StreamFrame {
                    stream_route,
                    stream_seq: u64::MAX - 1,
                },
            })));
        assert!(matches!(
            publish.await.expect("join MAX - 1 publisher"),
            Ok(MachinePublicationOutcome::Committed(MachinePublicationCommit {
                stream_seq,
                ..
            })) if stream_seq == u64::MAX - 1
        ));
        fixture.transport.shutdown().await;
    }

    #[tokio::test]
    async fn pending_publication_becomes_unknown_on_reconnect_and_exact_retry_can_commit() {
        let mut fixture = connected_fixture(Vec::new(), None).await;
        let business = fixture
            .transport
            .take_business_lane()
            .expect("take unique business lane");
        let publisher = business.publication_handle();
        let stream_route = StreamRouteId::from_bytes([0xc4; 16]);
        let generation = StreamGenerationId::from_bytes([0xc5; 16]);
        let exact_blob = publication_wire(0xc6);
        let blob_sha256 = sha256(exact_blob.as_ref());
        let first = tokio::spawn({
            let publisher = publisher.clone();
            let exact_blob = Arc::clone(&exact_blob);
            async move {
                publisher
                    .publish_exact(stream_route, generation, 4, exact_blob, blob_sha256)
                    .await
            }
        });
        tokio::time::timeout(std::time::Duration::from_secs(2), async {
            while fixture.harness.sent.lock().expect("lock sent").len() != 2 {
                tokio::task::yield_now().await;
            }
        })
        .await
        .expect("first publish reaches the existing session");

        fixture
            .transport
            .reconnect()
            .await
            .expect("same RelayClient reconnects");
        assert_eq!(
            first
                .await
                .expect("join first publish")
                .expect("valid publish"),
            MachinePublicationOutcome::OutcomeUnknown
        );
        assert_eq!(fixture.harness.connects.load(Ordering::SeqCst), 1);
        assert_eq!(fixture.harness.reconnects.load(Ordering::SeqCst), 1);

        let retry = tokio::spawn({
            let publisher = publisher.clone();
            let exact_blob = Arc::clone(&exact_blob);
            async move {
                publisher
                    .publish_exact(stream_route, generation, 4, exact_blob, blob_sha256)
                    .await
            }
        });
        tokio::time::timeout(std::time::Duration::from_secs(2), async {
            while fixture.harness.sent.lock().expect("lock sent").len() != 4 {
                tokio::task::yield_now().await;
            }
        })
        .await
        .expect("retry reuses exact blob on the replacement generation");
        fixture
            .harness
            .push_incoming(frame(RelayFrameBody::RouteAccepted(RouteAccepted {
                accepted: AcceptedRef::StreamFrame {
                    stream_route,
                    stream_seq: 4,
                },
            })));
        assert_eq!(
            retry.await.expect("join retry").expect("valid retry"),
            MachinePublicationOutcome::Committed(MachinePublicationCommit {
                connection_generation: INITIAL_PAIRING_GENERATION + 1,
                stream_route,
                stream_generation: generation,
                stream_seq: 4,
                blob_sha256,
            })
        );
        {
            let sent = fixture.harness.sent.lock().expect("lock sent");
            let RelayFrameBody::Publish(first_frame) = &sent[1].body else {
                panic!("first publish frame");
            };
            let RelayFrameBody::Publish(retry_frame) = &sent[3].body else {
                panic!("retry publish frame");
            };
            assert_eq!(first_frame.sealed_blob, retry_frame.sealed_blob);
        }
        fixture.transport.shutdown().await;
    }

    #[tokio::test]
    async fn authenticated_reconnect_receiver_excludes_history_and_stale_lane_activations() {
        let (mut transport, _pairing_lane, _harness) = active_pairing_transport_for_test(ROUTE);
        let business = transport
            .take_business_lane()
            .expect("claim reconnect-observation business lane");
        let publication = business.publication_handle();

        transport
            .reconnect()
            .await
            .expect("establish historical authenticated generation");
        let mut reconnects = publication.subscribe_authenticated_reconnects();
        assert!(
            tokio::time::timeout(Duration::from_millis(20), reconnects.changed())
                .await
                .is_err(),
            "a generation completed before subscription is only the baseline"
        );

        reconnects
            .mark_attempt_baseline()
            .expect("bind the full-drive attempt to the current activation");
        transport
            .reconnect()
            .await
            .expect("replace generation after the attempt baseline");
        assert_eq!(
            tokio::time::timeout(Duration::from_secs(1), reconnects.changed())
                .await
                .expect("new authenticated generation wakes")
                .expect("same activation stays valid"),
            INITIAL_PAIRING_GENERATION + 2
        );

        transport
            .restore_business_lane(business)
            .await
            .expect("deactivate and restore the unique lane");
        assert!(matches!(
            reconnects.changed().await,
            Err(RemoteTransportError::BusinessLaneUnavailable)
        ));
        transport.shutdown().await;
    }

    #[tokio::test]
    async fn wrong_and_duplicate_stream_commits_fail_closed() {
        let mut wrong = connected_fixture(Vec::new(), None).await;
        let business = wrong
            .transport
            .take_business_lane()
            .expect("take unique business lane");
        let publisher = business.publication_handle();
        let retry_publisher = publisher.clone();
        let stream_route = StreamRouteId::from_bytes([0xc7; 16]);
        let generation = StreamGenerationId::from_bytes([0xc8; 16]);
        let exact_blob = publication_wire(0xc9);
        let blob_sha256 = sha256(exact_blob.as_ref());
        let pending = tokio::spawn({
            let publisher = publisher.clone();
            async move {
                publisher
                    .publish_exact(stream_route, generation, 8, exact_blob, blob_sha256)
                    .await
            }
        });
        tokio::time::timeout(std::time::Duration::from_secs(2), async {
            while wrong.harness.sent.lock().expect("lock sent").len() != 2 {
                tokio::task::yield_now().await;
            }
        })
        .await
        .expect("pending publication is installed");
        wrong
            .harness
            .push_incoming(frame(RelayFrameBody::RouteAccepted(RouteAccepted {
                accepted: AcceptedRef::StreamFrame {
                    stream_route,
                    stream_seq: 9,
                },
            })));
        assert_eq!(
            pending.await.expect("join pending").expect("valid publish"),
            MachinePublicationOutcome::OutcomeUnknown
        );
        assert_eq!(
            wrong.transport.observed_failure_code().as_deref(),
            Some("remote.transport.publication_ack_mismatch")
        );
        assert_eq!(wrong.harness.shutdowns.load(Ordering::SeqCst), 1);
        let retry_blob = publication_wire(0xcb);
        assert!(matches!(
            retry_publisher
                .publish_exact(
                    stream_route,
                    generation,
                    8,
                    Arc::clone(&retry_blob),
                    sha256(retry_blob.as_ref()),
                )
                .await,
            Err(RemoteTransportError::Closed)
        ));
        wrong.transport.shutdown().await;

        let mut duplicate = connected_fixture(Vec::new(), None).await;
        let business = duplicate
            .transport
            .take_business_lane()
            .expect("take unique business lane");
        let publisher = business.publication_handle();
        let exact_blob = publication_wire(0xca);
        let blob_sha256 = sha256(exact_blob.as_ref());
        let committed = tokio::spawn(async move {
            publisher
                .publish_exact(stream_route, generation, 10, exact_blob, blob_sha256)
                .await
        });
        tokio::time::timeout(std::time::Duration::from_secs(2), async {
            while duplicate.harness.sent.lock().expect("lock sent").len() != 2 {
                tokio::task::yield_now().await;
            }
        })
        .await
        .expect("publication is pending");
        let accepted = frame(RelayFrameBody::RouteAccepted(RouteAccepted {
            accepted: AcceptedRef::StreamFrame {
                stream_route,
                stream_seq: 10,
            },
        }));
        duplicate.harness.push_incoming(accepted.clone());
        assert!(matches!(
            committed
                .await
                .expect("join committed")
                .expect("valid publish"),
            MachinePublicationOutcome::Committed(_)
        ));
        duplicate.harness.push_incoming(accepted);
        tokio::time::timeout(std::time::Duration::from_secs(2), async {
            while duplicate.transport.observed_failure_code().is_none() {
                tokio::task::yield_now().await;
            }
        })
        .await
        .expect("duplicate COMMIT fails closed");
        assert_eq!(
            duplicate.transport.observed_failure_code().as_deref(),
            Some("remote.transport.publication_ack_mismatch")
        );
        assert_eq!(duplicate.harness.shutdowns.load(Ordering::SeqCst), 1);
        duplicate.transport.shutdown().await;
    }

    #[tokio::test]
    async fn machine_data_authority_signs_typed_sealed_blob_and_dies_with_owner() {
        let mut fixture = connected_fixture(Vec::new(), None).await;
        let PairingRuntimeParts {
            lane: _lane,
            authority,
        } = fixture
            .transport
            .take_pairing_runtime(fixture.data_cert.clone())
            .expect("bind Weak machine data authority");
        let business_authority = authority.machine_data_authority();
        let parallel_business_authority = business_authority.clone();
        let stream_route = StreamRouteId::from_bytes([0xcb; 16]);
        let generation = StreamGenerationId::from_bytes([0xcc; 16]);
        let context = publication_context(ROUTE, stream_route, generation, 0);
        let unsigned = UnsignedSealedBlobV1::new(
            KeyId {
                purpose: KeyPurpose::Catalog,
                epoch: 7,
            },
            7,
            11,
            [0xcd; 12],
            vec![0xce; 16],
        );
        let pairing_unsigned = unsigned.clone();
        let business_unsigned = unsigned.clone();
        let pairing_context = context.clone();
        let business_context = context.clone();
        let (pairing_signed, business_signed) = std::thread::scope(|scope| {
            let pairing = scope.spawn(|| {
                authority
                    .sign_sealed(pairing_unsigned, &pairing_context)
                    .expect("pairing path uses typed MachineDataSign")
            });
            let business = scope.spawn(move || {
                parallel_business_authority
                    .sign_sealed(business_unsigned, &business_context)
                    .expect("business sealer uses cloned narrow authority")
            });
            (
                pairing.join().expect("join pairing signer"),
                business.join().expect("join business signer"),
            )
        });
        for signed in [pairing_signed, business_signed] {
            verify_sealed(
                signed,
                &SigningKey::from_seed(&[0x33; 32]).verifying_key(),
                &context,
            )
            .expect("signature verifies with the certified MachineDataSign key");
        }

        let mismatch = publication_context(
            MachineRouteId::from_bytes([0xcf; 16]),
            stream_route,
            generation,
            0,
        );
        assert_eq!(
            business_authority
                .sign_sealed(unsigned.clone(), &mismatch)
                .expect_err("cross-machine context must fail")
                .code(),
            "remote.transport.pairing_authority_mismatch"
        );
        let mut forbidden_kind = context.clone();
        forbidden_kind.frame_kind = OuterFrameKind::PairPending;
        assert_eq!(
            business_authority
                .sign_sealed(unsigned.clone(), &forbidden_kind)
                .expect_err("pairing frame kind is outside the narrow data surface")
                .code(),
            "remote.transport.pairing_authority_mismatch"
        );

        fixture.transport.shutdown().await;
        assert_eq!(
            authority
                .sign_sealed(unsigned.clone(), &context)
                .expect_err("destroyed owner cannot sign")
                .code(),
            "remote.transport.closed"
        );
        assert_eq!(
            business_authority
                .sign_sealed(unsigned, &context)
                .expect_err("cloned narrow authority dies with the same owner")
                .code(),
            "remote.transport.closed"
        );
    }

    #[test]
    fn machine_data_authority_public_surface_is_cloneable_typed_and_narrow() {
        fn assert_capability<T: Clone + std::marker::Send + Sync>() {}
        assert_capability::<MachineDataAuthority>();

        let source = include_str!("transport.rs");
        let implementation = source
            .split("impl MachineDataAuthority {")
            .nth(1)
            .expect("MachineDataAuthority implementation")
            .split("impl fmt::Debug for MachineDataAuthority")
            .next()
            .expect("MachineDataAuthority implementation boundary");
        let public_methods = implementation
            .lines()
            .filter_map(|line| {
                line.trim()
                    .strip_prefix("pub(crate) fn ")
                    .and_then(|suffix| suffix.split('(').next())
            })
            .collect::<Vec<_>>();
        assert_eq!(
            public_methods,
            [
                "seal_device_key_recovery_reply",
                "sign_key_directory",
                "sign_key_update",
                "sign_sealed",
                "seal_key_directory_entry"
            ]
        );
        for forbidden in [
            "sign_relay_grant",
            "sign_device_authorization",
            "sign_device_revocation",
            "root_sign",
            "raw_sign",
            "signing_key",
        ] {
            assert!(
                !implementation.contains(forbidden),
                "forbidden: {forbidden}"
            );
        }
    }

    fn retirement() -> RetireMachine {
        RetireMachine {
            machine_route: ROUTE,
            root_key_id: RootKeyId::from_bytes([0x61; 16]),
            trust_epoch: TrustEpoch::new(4),
            signature: Ed25519Signature([0x71; 64]),
        }
    }

    fn open_pair_route(pair_route: PairRouteId, absolute_expiry_ms: u64) -> OpenPairRoute {
        OpenPairRoute {
            machine_route: ROUTE,
            pair_route,
            absolute_expiry_ms,
        }
    }

    fn relay_grant(
        device_route: DeviceRouteId,
        serial: u64,
    ) -> agentdeck_protocol::relay_v2::RelayGrant {
        let root = SigningKey::from_seed(&[0x31; 32]);
        let device = SigningKey::from_seed(&[0x91; 32]);
        let mut grant = RelayGrant {
            machine_route: ROUTE,
            device_route,
            device_sign_pubkey: PublicKeyBytes(device.verifying_key().to_bytes()),
            grant_serial: GrantSerial::new(serial),
            root_key_id: RootKeyId::from_bytes([0x61; 16]),
            trust_epoch: TrustEpoch::new(3),
            signature: Ed25519Signature([0; 64]),
        };
        grant.signature = sign_tbs(
            &root,
            &grant.to_be_signed_v1(RELAY, sha256(&root.verifying_key().to_bytes())),
        )
        .into();
        grant
    }

    fn device_revocation(device_route: DeviceRouteId, serial: u64) -> DeviceRevocation {
        let root = SigningKey::from_seed(&[0x31; 32]);
        let mut revocation = DeviceRevocation {
            machine_route: ROUTE,
            device_route,
            grant_serial: GrantSerial::new(serial),
            root_key_id: RootKeyId::from_bytes([0x61; 16]),
            trust_epoch: TrustEpoch::new(3),
            signature: Ed25519Signature([0; 64]),
        };
        revocation.signature = sign_tbs(
            &root,
            &revocation.to_be_signed_v1(RELAY, sha256(&root.verifying_key().to_bytes())),
        )
        .into();
        revocation
    }

    fn pairing_outer_context(kind: OuterFrameKind, pair_route: PairRouteId) -> OuterContextV1 {
        OuterContextV1 {
            frame_kind: kind,
            relay_protocol_version: RELAY_PROTOCOL_VERSION,
            e2ee_format_version: E2EE_FORMAT_VERSION,
            machine_route: None,
            device_route: None,
            stream_route: None,
            request_route: None,
            pair_route: Some(pair_route),
            stream_generation: None,
            stream_cursor: None,
            stream_seq: None,
            message_key_epoch: 0,
        }
    }

    fn pairing_request_info(pair_route: PairRouteId) -> PairRequestInfoV1 {
        PairRequestInfoV1 {
            e2ee_format_version: E2EE_FORMAT_VERSION,
            runtime_protocol_version: RUNTIME_PROTOCOL_VERSION,
            relay_server_id: RELAY,
            pair_route,
            invite_hash: [0x81; 32],
            expiry_ms: 1_700_000_300_000,
        }
    }

    fn unsigned_pairing_grant(device_signing_key: &SigningKey) -> RelayGrant {
        RelayGrant {
            machine_route: ROUTE,
            device_route: DeviceRouteId::from_bytes([0x71; 16]),
            device_sign_pubkey: PublicKeyBytes(device_signing_key.verifying_key().to_bytes()),
            grant_serial: GrantSerial::new(7),
            root_key_id: RootKeyId::from_bytes([0x61; 16]),
            trust_epoch: TrustEpoch::new(3),
            signature: Ed25519Signature([0; 64]),
        }
    }

    fn unsigned_device_authorization(
        grant: &RelayGrant,
        device_hpke_public_key: PublicKeyBytes,
    ) -> DeviceAuthorizationV1 {
        DeviceAuthorizationV1 {
            format_version: E2EE_FORMAT_VERSION,
            grant_hash: grant.canonical_sha256(),
            machine_route: grant.machine_route,
            device_route: grant.device_route,
            device_sign_fingerprint: sha256(&grant.device_sign_pubkey.0),
            grant_serial: grant.grant_serial,
            device_hpke_pubkey: device_hpke_public_key,
            capabilities: vec![AuthorizationCapabilityV1::Catalog],
            permissions: vec![AuthorizationPermissionV1::CatalogRead],
            root_key_id: grant.root_key_id,
            trust_epoch: grant.trust_epoch,
            signature: Ed25519Signature([0; 64]),
        }
    }

    fn pairing_response_info(
        pair_route: PairRouteId,
        request_hash: [u8; 32],
        grant: &RelayGrant,
    ) -> PairResponseInfoV1 {
        PairResponseInfoV1 {
            e2ee_format_version: E2EE_FORMAT_VERSION,
            runtime_protocol_version: RUNTIME_PROTOCOL_VERSION,
            relay_server_id: RELAY,
            pair_route,
            invite_hash: [0x81; 32],
            expiry_ms: 1_700_000_300_000,
            request_hash,
            machine_route: grant.machine_route,
            device_route: grant.device_route,
            grant_serial: grant.grant_serial,
            root_trust_epoch: grant.trust_epoch,
        }
    }

    fn bootstrap_key_directory(device_route: DeviceRouteId) -> KeyDirectoryV1 {
        KeyDirectoryV1 {
            revision: KeyDirectoryRevision::new(1),
            entries: vec![
                KeyDirectoryEntry {
                    key_id: KeyId {
                        purpose: KeyPurpose::Catalog,
                        epoch: 1,
                    },
                    device_route,
                    stream_route: None,
                    enc: vec![0x82; 32],
                    wrapped_key: vec![0x83; 48],
                },
                KeyDirectoryEntry {
                    key_id: KeyId {
                        purpose: KeyPurpose::DeviceCommandTx,
                        epoch: 1,
                    },
                    device_route,
                    stream_route: None,
                    enc: vec![0x85; 32],
                    wrapped_key: vec![0x86; 48],
                },
                KeyDirectoryEntry {
                    key_id: KeyId {
                        purpose: KeyPurpose::DeviceReplyTx,
                        epoch: 1,
                    },
                    device_route,
                    stream_route: None,
                    enc: vec![0x87; 32],
                    wrapped_key: vec![0x88; 48],
                },
            ],
            signature: Ed25519Signature([0; 64]),
        }
    }

    fn unsigned_pairing_revocation(grant: &RelayGrant) -> DeviceRevocation {
        DeviceRevocation {
            machine_route: grant.machine_route,
            device_route: grant.device_route,
            grant_serial: grant.grant_serial,
            root_key_id: grant.root_key_id,
            trust_epoch: grant.trust_epoch,
            signature: Ed25519Signature([0; 64]),
        }
    }

    async fn open_bound_route(
        lane: &mut PairingTransportLane,
        harness: &Harness,
        pair_route: PairRouteId,
        absolute_expiry_ms: u64,
    ) {
        lane.send_open_pair_route(open_pair_route(pair_route, absolute_expiry_ms))
            .await
            .expect("send typed open");
        harness.push_incoming(frame(RelayFrameBody::PairRouteOpened(PairRouteOpened {
            machine_route: ROUTE,
            pair_route,
            absolute_expiry_ms,
        })));
        let event = lane
            .next_event()
            .await
            .expect("opened event")
            .expect("event");
        assert!(matches!(
            event,
            PairingTransportEvent::PairRouteOpened(PairRouteOpened {
                machine_route: ROUTE,
                pair_route: observed,
                absolute_expiry_ms: observed_expiry,
            }) if observed == pair_route && observed_expiry == absolute_expiry_ms
        ));
    }

    #[tokio::test]
    async fn failed_initial_connect_preserves_exact_owner_certificate_and_start_slot_for_retry() {
        let root = SigningKey::from_seed(&[0x31; 32]);
        let link = SigningKey::from_seed(&[0x32; 32]);
        let link_cert = signed_link_certificate(&root, &link);
        let observed = Arc::new(Mutex::new(Vec::new()));
        let owner_drops = Arc::new(AtomicUsize::new(0));
        let owner = FakeOwner {
            signing_key: link,
            root_signing_key: root,
            expected_relay: RELAY,
            expected_route: ROUTE,
            expected_cert: link_cert.clone(),
            observed: Arc::clone(&observed),
            drops: Arc::clone(&owner_drops),
        };
        let authenticator = Arc::new(MachineLinkAuthenticator::new(
            owner,
            ROUTE,
            link_cert.clone(),
        ));
        let owner_pointer = Arc::as_ptr(&authenticator);
        let harness = Arc::new(Harness {
            connect_failures_remaining: AtomicUsize::new(1),
            ..Harness::default()
        });
        let connector = FakeConnector {
            harness: Arc::clone(&harness),
            challenge: Challenge {
                relay_server_id: RELAY,
                connection_instance: ConnectionInstanceId::from_bytes([0x41; 16]),
                challenge_nonce: [0x42; 32],
            },
        };
        let config = RelayClientConfig::new(
            "wss://relay.example.test/",
            RELAY,
            RelayTlsPolicy::pinned_spki(vec![[0x51; 32]]).expect("valid pin policy"),
        )
        .expect("valid Relay config");

        let first = connect_preserving_ownership(&config, authenticator, 0xA5_u8, &connector).await;
        let FailedTransportOwnership {
            error,
            authenticator,
            start_owner,
        } = match first {
            Err(failed) => failed,
            Ok(_) => panic!("first connect must fail offline"),
        };
        assert_eq!(error.code(), "relay.client.offline");
        assert_eq!(Arc::as_ptr(&authenticator), owner_pointer);
        assert_eq!(start_owner, 0xA5);
        assert_eq!(owner_drops.load(Ordering::SeqCst), 0);

        let second =
            connect_preserving_ownership(&config, authenticator, start_owner, &connector).await;
        let ConnectedTransportOwnership {
            mut session,
            authenticator,
            start_owner,
        } = match second {
            Ok(connected) => connected,
            Err(_) => panic!("same frozen owner must retry without re-enrollment"),
        };
        assert_eq!(Arc::as_ptr(&authenticator), owner_pointer);
        assert_eq!(start_owner, 0xA5);
        assert_eq!(harness.connects.load(Ordering::SeqCst), 2);
        {
            let authentications = harness
                .authentications
                .lock()
                .expect("lock retry authentications");
            assert_eq!(authentications.len(), 2);
            assert_eq!(authentications[0], authentications[1]);
            let AuthProof::MachineLink {
                link_cert: retried_cert,
                ..
            } = &authentications[1].proof
            else {
                panic!("retry must reuse MachineLink proof");
            };
            assert_eq!(retried_cert, &link_cert);
        }

        session.shutdown().await;
        drop(session);
        assert_eq!(owner_drops.load(Ordering::SeqCst), 0);
        drop(authenticator);
        assert_eq!(owner_drops.load(Ordering::SeqCst), 1);
    }

    #[tokio::test]
    async fn connect_error_retry_reuses_the_preserved_state() {
        let root = SigningKey::from_seed(&[0x31; 32]);
        let link = SigningKey::from_seed(&[0x32; 32]);
        let link_cert = signed_link_certificate(&root, &link);
        let observed = Arc::new(Mutex::new(Vec::new()));
        let owner_drops = Arc::new(AtomicUsize::new(0));
        let authenticator = Arc::new(MachineLinkAuthenticator::new(
            FakeOwner {
                signing_key: link,
                root_signing_key: root,
                expected_relay: RELAY,
                expected_route: ROUTE,
                expected_cert: link_cert.clone(),
                observed,
                drops: Arc::clone(&owner_drops),
            },
            ROUTE,
            link_cert,
        ));
        let harness = Arc::new(Harness {
            connect_failures_remaining: AtomicUsize::new(1),
            ..Harness::default()
        });
        let connector = FakeConnector {
            harness: Arc::clone(&harness),
            challenge: Challenge {
                relay_server_id: RELAY,
                connection_instance: ConnectionInstanceId::from_bytes([0x41; 16]),
                challenge_nonce: [0x42; 32],
            },
        };
        let config = RelayClientConfig::new(
            "wss://relay.example.test/",
            RELAY,
            RelayTlsPolicy::pinned_spki(vec![[0x51; 32]]).expect("valid pin policy"),
        )
        .expect("valid Relay config");
        let error = RemoteTransport::connect_with_connector(
            config,
            ROUTE,
            authenticator,
            None,
            BusinessLaneStartup::Dormant,
            &connector,
        )
        .await
        .expect_err("first connect must return retry ownership");
        assert_eq!(error.code(), "relay.client.offline");
        assert_eq!(owner_drops.load(Ordering::SeqCst), 0);

        let mut transport = error
            .retry_with_connector(&connector)
            .await
            .expect("retry same preserved state");
        assert_eq!(harness.connects.load(Ordering::SeqCst), 2);
        assert_eq!(owner_drops.load(Ordering::SeqCst), 0);
        transport.shutdown().await;
        assert_eq!(owner_drops.load(Ordering::SeqCst), 1);
    }

    #[tokio::test]
    async fn typed_authenticator_binds_every_machine_link_transcript_axis() {
        let mut fixture = connected_fixture(Vec::new(), None).await;
        assert_eq!(fixture.harness.connects.load(Ordering::SeqCst), 1);
        let observed = fixture
            .observed
            .lock()
            .expect("lock observed transcript")
            .clone();
        assert_eq!(observed.len(), 1);
        let transcript = &observed[0];
        assert_eq!(transcript.role, AuthenticationRole::MachineLink);
        assert_eq!(
            transcript.challenge_nonce,
            fixture.challenge.challenge_nonce
        );
        assert_eq!(
            transcript.connection_instance,
            fixture.challenge.connection_instance
        );
        assert_eq!(transcript.relay_server_id, RELAY);
        assert_eq!(transcript.relay_protocol_version, RELAY_PROTOCOL_VERSION);
        assert_eq!(transcript.machine_route, ROUTE);
        assert_eq!(transcript.device_route, None);
        assert_eq!(
            transcript.serial_or_generation,
            fixture.link_cert.generation.value()
        );
        assert_eq!(
            transcript.credential_sha256,
            fixture.link_cert.canonical_sha256()
        );

        {
            let authentications = fixture
                .harness
                .authentications
                .lock()
                .expect("lock authentications");
            assert_eq!(authentications.len(), 1);
            verify_authentication_transcript(
                &fixture.link_verifying_key,
                transcript,
                &SignatureBytes::from(authentications[0].signature),
            )
            .expect("MachineLink signature must verify over the exact transcript");
        }

        fixture
            .transport
            .reconnect()
            .await
            .expect("reconnect session");
        assert_eq!(fixture.harness.connects.load(Ordering::SeqCst), 1);
        assert_eq!(fixture.harness.reconnects.load(Ordering::SeqCst), 1);
        fixture.transport.shutdown().await;
        assert_eq!(fixture.owner_drops.load(Ordering::SeqCst), 1);
    }

    #[tokio::test]
    async fn typed_authenticator_rejects_zero_challenge_axes_before_signing() {
        let root = SigningKey::from_seed(&[0x31; 32]);
        let link = SigningKey::from_seed(&[0x32; 32]);
        let link_cert = signed_link_certificate(&root, &link);
        let observed = Arc::new(Mutex::new(Vec::new()));
        let owner_drops = Arc::new(AtomicUsize::new(0));
        let authenticator = MachineLinkAuthenticator::new(
            FakeOwner {
                signing_key: link,
                root_signing_key: root,
                expected_relay: RELAY,
                expected_route: ROUTE,
                expected_cert: link_cert.clone(),
                observed: Arc::clone(&observed),
                drops: Arc::clone(&owner_drops),
            },
            ROUTE,
            link_cert,
        );
        for challenge in [
            Challenge {
                relay_server_id: RELAY,
                connection_instance: ConnectionInstanceId::from_bytes([0x41; 16]),
                challenge_nonce: [0; 32],
            },
            Challenge {
                relay_server_id: RELAY,
                connection_instance: ConnectionInstanceId::from_bytes([0; 16]),
                challenge_nonce: [0x42; 32],
            },
        ] {
            let error = authenticator
                .authenticate(&challenge)
                .await
                .expect_err("zero challenge axis must fail before signing");
            assert_eq!(error.code(), "remote.transport.challenge_invalid");
        }
        assert!(
            observed
                .lock()
                .expect("lock observed transcripts")
                .is_empty(),
            "invalid challenge must never reach the link signer"
        );
        drop(authenticator);
        assert_eq!(owner_drops.load(Ordering::SeqCst), 1);
    }

    #[tokio::test]
    async fn retirement_and_three_control_events_are_the_only_typed_surface() {
        let committed = RetirementCommitted {
            machine_route: ROUTE,
            trust_epoch: TrustEpoch::new(4),
            retire_hash: retirement().canonical_sha256(),
        };
        let committed_frame = frame(RelayFrameBody::RetirementCommitted(committed.clone()));
        let expected_terminal_bytes = encode(&committed_frame);
        let mut fixture = connected_fixture(
            vec![
                committed_frame,
                frame(RelayFrameBody::Error(RelayFailure::new(
                    "relay.store.unavailable",
                    "secret relay detail",
                ))),
                frame(RelayFrameBody::ServerRestarting(ServerRestarting {
                    drain_deadline_ms: 99,
                })),
            ],
            None,
        )
        .await;
        let request = retirement();
        fixture
            .transport
            .send_retirement(request.clone())
            .await
            .expect("send only allowed outbound control");
        {
            let sent = fixture.harness.sent.lock().expect("lock sent frames");
            assert_eq!(sent.len(), 1);
            assert_eq!(sent[0], frame(RelayFrameBody::RetireMachine(request)));
        }

        let terminal = fixture.transport.next_control().await.unwrap().unwrap();
        let RemoteControl::RetirementTerminal(terminal) = terminal else {
            panic!("expected frozen retirement terminal");
        };
        assert_eq!(terminal.committed(), &committed);
        assert_eq!(terminal.canonical_frame_bytes(), expected_terminal_bytes);
        assert_eq!(
            terminal.canonical_frame_hash(),
            sha256(&expected_terminal_bytes)
        );
        assert_eq!(format!("{terminal:?}"), "RetirementTerminal([REDACTED])");
        let failure = fixture.transport.next_control().await.unwrap().unwrap();
        let RemoteControl::SafeFailure(failure) = failure else {
            panic!("expected safe failure");
        };
        assert_eq!(failure.code(), "relay.store.unavailable");
        assert!(!format!("{failure:?}").contains("secret relay detail"));
        assert_eq!(
            fixture.transport.next_control().await.unwrap(),
            Some(RemoteControl::ServerRestarting(ServerRestarting {
                drain_deadline_ms: 99,
            }))
        );
        assert_eq!(
            fixture.harness.business_dispatches.load(Ordering::SeqCst),
            0
        );

        let mut wrong_route = retirement();
        wrong_route.machine_route = MachineRouteId::from_bytes([0x99; 16]);
        assert_eq!(
            fixture
                .transport
                .send_retirement(wrong_route)
                .await
                .unwrap_err()
                .code(),
            "remote.transport.route_mismatch"
        );
        fixture.transport.shutdown().await;
    }

    #[tokio::test]
    async fn untaken_pairing_lane_does_not_backpressure_the_existing_control_surface() {
        let mut fixture = connected_fixture(Vec::new(), None).await;
        for index in 0..12 {
            fixture
                .harness
                .push_incoming(frame(RelayFrameBody::Error(RelayFailure::new(
                    "relay.store.unavailable",
                    format!("secret-{index}"),
                ))));
            let Some(RemoteControl::SafeFailure(failure)) =
                fixture.transport.next_control().await.unwrap()
            else {
                panic!("safe control event");
            };
            assert_eq!(failure.code(), "relay.store.unavailable");
        }
        assert_eq!(fixture.transport.observed_failure_code(), None);
        fixture.transport.shutdown().await;
        assert_eq!(fixture.harness.shutdowns.load(Ordering::SeqCst), 1);
    }

    #[tokio::test]
    async fn connected_transport_freezes_bound_retirement_until_shutdown() {
        let mut fixture = connected_fixture(Vec::new(), None).await;
        let frozen = fixture
            .transport
            .freeze_retirement(RELAY, 3)
            .expect("authenticated transport freezes retirement");
        assert_eq!(frozen.retirement().machine_route, ROUTE);
        assert_eq!(frozen.retirement().trust_epoch, TrustEpoch::new(3));
        assert_eq!(
            frozen.canonical_bytes(),
            frozen.retirement().canonical_bytes()
        );
        assert_eq!(
            frozen.canonical_hash(),
            frozen.retirement().canonical_sha256()
        );
        let root = SigningKey::from_seed(&[0x31; 32]).verifying_key();
        verify_tbs(
            &root,
            &frozen
                .retirement()
                .to_be_signed_v1(RELAY, sha256(&root.to_bytes())),
            &SignatureBytes::from(frozen.retirement().signature),
        )
        .expect("retirement signature binds connected Relay/route/epoch");

        let wrong_relay = fixture
            .transport
            .freeze_retirement(RelayServerId::from_bytes([0x99; 16]), 3)
            .expect_err("authenticated Relay is immutable");
        assert_eq!(
            wrong_relay.code(),
            "daemon.remote.trust_reset.authenticated_relay_mismatch"
        );
        let wrong_epoch = fixture
            .transport
            .freeze_retirement(RELAY, 4)
            .expect_err("active trust epoch is immutable");
        assert_eq!(
            wrong_epoch.code(),
            "daemon.remote.trust_reset.epoch_mismatch"
        );

        fixture.transport.shutdown().await;
        let closed = fixture
            .transport
            .freeze_retirement(RELAY, 3)
            .expect_err("shutdown releases retirement signer owner");
        assert_eq!(closed.code(), "remote.transport.closed");
    }

    #[tokio::test]
    async fn idle_supervisor_closes_business_frame_before_any_control_poll() {
        let mut fixture = connected_fixture(Vec::new(), None).await;
        let shutdown_started = fixture.harness.shutdown_started.notified();
        fixture
            .harness
            .push_incoming(frame(RelayFrameBody::Ping(Ping { nonce: 9 })));

        tokio::time::timeout(std::time::Duration::from_secs(2), shutdown_started)
            .await
            .expect("idle supervisor must close a business frame without next_control");
        assert_eq!(fixture.harness.shutdowns.load(Ordering::SeqCst), 1);
        assert_eq!(
            fixture.harness.business_dispatches.load(Ordering::SeqCst),
            0
        );
        assert_eq!(
            fixture.transport.observed_failure_code().as_deref(),
            Some("remote.transport.frame_forbidden")
        );
        assert_eq!(
            fixture.transport.next_control().await.unwrap_err().code(),
            "remote.transport.frame_forbidden"
        );
        assert_eq!(
            fixture.transport.reconnect().await.unwrap_err().code(),
            "remote.transport.closed"
        );
        fixture.transport.shutdown().await;
        assert_eq!(fixture.harness.shutdowns.load(Ordering::SeqCst), 1);
        assert_eq!(fixture.harness.session_drops.load(Ordering::SeqCst), 1);
        assert_eq!(fixture.owner_drops.load(Ordering::SeqCst), 1);
    }

    #[tokio::test]
    async fn idle_supervisor_exposes_connection_error_without_consuming_control() {
        let mut fixture = connected_fixture(Vec::new(), None).await;
        fixture.harness.push_error("relay.client.connection_lost");
        let observed = tokio::time::timeout(std::time::Duration::from_secs(2), async {
            loop {
                if let Some(code) = fixture.transport.observed_failure_code() {
                    break code;
                }
                tokio::task::yield_now().await;
            }
        })
        .await
        .expect("manager-visible health must observe the reader error");
        assert_eq!(observed, "relay.client.connection_lost");
        assert_eq!(
            fixture
                .transport
                .take_pairing_lane(fixture.data_cert.clone())
                .expect_err("pending reader error must block pairing activation")
                .code(),
            "remote.transport.pairing_activation_blocked"
        );
        assert!(fixture.transport.pairing_lane.is_some());
        assert_eq!(
            fixture.transport.next_control().await.unwrap_err().code(),
            "relay.client.connection_lost"
        );
        fixture.transport.shutdown().await;
        assert_eq!(fixture.harness.shutdowns.load(Ordering::SeqCst), 1);
        assert_eq!(fixture.harness.session_drops.load(Ordering::SeqCst), 1);
        assert_eq!(fixture.owner_drops.load(Ordering::SeqCst), 1);
    }

    #[tokio::test]
    async fn untaken_business_lane_and_forbidden_families_fail_closed_without_dispatch() {
        let device_route = DeviceRouteId::from_bytes([0x81; 16]);
        let request_route = RequestRouteId::from_bytes([0x82; 16]);
        let stream_route = StreamRouteId::from_bytes([0x83; 16]);
        let generation = StreamGenerationId::from_bytes([0x84; 16]);
        let pair_route = PairRouteId::from_bytes([0x85; 16]);
        let revocation = DeviceRevocation {
            machine_route: ROUTE,
            device_route,
            grant_serial: GrantSerial::new(2),
            root_key_id: RootKeyId::from_bytes([0x61; 16]),
            trust_epoch: TrustEpoch::new(4),
            signature: Ed25519Signature([0x86; 64]),
        };
        let cases = vec![
            (
                frame(RelayFrameBody::RouteAccepted(RouteAccepted {
                    accepted: AcceptedRef::Request { request_route },
                })),
                "remote.transport.business_lane_unavailable",
            ),
            (
                frame(RelayFrameBody::Send(Send {
                    device_route,
                    request_route,
                    sealed_blob: SealedBlob(vec![1]),
                })),
                "remote.transport.business_lane_unavailable",
            ),
            (
                frame(RelayFrameBody::Reply(Reply {
                    device_route,
                    request_route,
                    sealed_blob: SealedBlob(vec![2]),
                })),
                "remote.transport.frame_forbidden",
            ),
            (
                frame(RelayFrameBody::Publish(Publish {
                    stream_route,
                    generation,
                    stream_seq: 0,
                    sealed_blob: SealedBlob(vec![3]),
                })),
                "remote.transport.frame_forbidden",
            ),
            (
                frame(RelayFrameBody::PairData(PairData {
                    pair_route,
                    sealed_blob: SealedBlob(vec![4]),
                })),
                "remote.transport.frame_forbidden",
            ),
            (
                frame(RelayFrameBody::GrantCommitted(GrantCommitted {
                    device_route,
                    grant_serial: GrantSerial::new(2),
                    grant_hash: [0x87; 32],
                })),
                "remote.transport.frame_forbidden",
            ),
            (
                frame(RelayFrameBody::RevocationCommitted(RevocationCommitted {
                    device_route,
                    grant_serial: GrantSerial::new(2),
                    signed_revocation: revocation,
                })),
                "remote.transport.frame_forbidden",
            ),
            (
                frame(RelayFrameBody::Ping(Ping { nonce: 7 })),
                "remote.transport.frame_forbidden",
            ),
            (
                frame(RelayFrameBody::Error(RelayFailure::new(
                    "UNSAFE CODE",
                    "secret",
                ))),
                "remote.transport.frame_forbidden",
            ),
            (
                frame(RelayFrameBody::RetirementCommitted(RetirementCommitted {
                    machine_route: MachineRouteId::from_bytes([0x99; 16]),
                    trust_epoch: TrustEpoch::new(4),
                    retire_hash: [0x88; 32],
                })),
                "remote.transport.frame_forbidden",
            ),
            (
                OpaqueRouteFrame {
                    version: RELAY_PROTOCOL_VERSION + 1,
                    body: RelayFrameBody::ServerRestarting(ServerRestarting {
                        drain_deadline_ms: 1,
                    }),
                },
                "remote.transport.frame_forbidden",
            ),
        ];

        for (frame, expected_code) in cases {
            let mut fixture = connected_fixture(vec![frame], None).await;
            let error = fixture
                .transport
                .next_control()
                .await
                .expect_err("business or malformed frame must fail closed");
            assert_eq!(error.code(), expected_code);
            assert_eq!(fixture.harness.shutdowns.load(Ordering::SeqCst), 1);
            assert_eq!(
                fixture.harness.business_dispatches.load(Ordering::SeqCst),
                0
            );
            assert_eq!(fixture.owner_drops.load(Ordering::SeqCst), 0);
            assert_eq!(
                fixture.transport.reconnect().await.unwrap_err().code(),
                "remote.transport.closed"
            );
            fixture.transport.shutdown().await;
            assert_eq!(fixture.harness.session_drops.load(Ordering::SeqCst), 1);
            assert_eq!(fixture.owner_drops.load(Ordering::SeqCst), 1);
        }
    }

    #[tokio::test]
    async fn active_startup_reservation_buffers_first_business_frame_before_lane_handoff() {
        let device_route = DeviceRouteId::from_bytes([0x91; 16]);
        let request_route = RequestRouteId::from_bytes([0x92; 16]);
        let expected = Send {
            device_route,
            request_route,
            sealed_blob: SealedBlob(vec![0x93]),
        };
        let mut fixture = connected_fixture_with_business_startup(
            vec![frame(RelayFrameBody::Send(expected.clone()))],
            None,
            BusinessLaneStartup::Reserved,
        )
        .await;

        let mut lane = fixture
            .transport
            .take_business_lane()
            .expect("Active startup reservation hands off the unique business lane once");
        assert_eq!(
            tokio::time::timeout(Duration::from_secs(2), lane.next_event())
                .await
                .expect("reserved first business frame remains bounded")
                .expect("reserved business lane remains healthy"),
            Some(BusinessTransportEvent::Send(expected))
        );
        assert_eq!(fixture.transport.observed_failure_code(), None);

        let shutdown_started = fixture.harness.shutdown_started.notified();
        drop(lane);
        fixture
            .harness
            .push_incoming(frame(RelayFrameBody::Send(Send {
                device_route,
                request_route: RequestRouteId::from_bytes([0x94; 16]),
                sealed_blob: SealedBlob(vec![0x95]),
            })));
        tokio::time::timeout(Duration::from_secs(2), shutdown_started)
            .await
            .expect("dropped startup reservation restores fail-close");
        assert_eq!(
            fixture.transport.observed_failure_code().as_deref(),
            Some("remote.transport.business_lane_unavailable")
        );
        fixture.transport.shutdown().await;
    }

    #[tokio::test]
    async fn shutdown_waits_for_session_join_before_releasing_start_owner() {
        let gate = Arc::new(ShutdownGate {
            entered: Notify::new(),
            release: Notify::new(),
        });
        let fixture = connected_fixture(Vec::new(), Some(Arc::clone(&gate))).await;
        let harness = Arc::clone(&fixture.harness);
        let owner_drops = Arc::clone(&fixture.owner_drops);
        let mut transport = fixture.transport;
        let shutdown = tokio::spawn(async move {
            transport.shutdown().await;
            transport
        });

        tokio::time::timeout(std::time::Duration::from_secs(2), gate.entered.notified())
            .await
            .expect("shutdown entered session join");
        assert!(!shutdown.is_finished());
        assert_eq!(owner_drops.load(Ordering::SeqCst), 0);
        assert_eq!(harness.session_drops.load(Ordering::SeqCst), 0);

        gate.release.notify_one();
        let mut transport = shutdown.await.expect("join shutdown task");
        assert_eq!(harness.shutdowns.load(Ordering::SeqCst), 1);
        assert_eq!(harness.session_drops.load(Ordering::SeqCst), 1);
        assert_eq!(owner_drops.load(Ordering::SeqCst), 1);
        assert_eq!(
            transport.reconnect().await.unwrap_err().code(),
            "remote.transport.closed"
        );
    }

    #[tokio::test]
    async fn cancelling_shutdown_aborts_blocked_supervisor_without_detaching_session() {
        let gate = Arc::new(ShutdownGate {
            entered: Notify::new(),
            release: Notify::new(),
        });
        let fixture = connected_fixture(Vec::new(), Some(Arc::clone(&gate))).await;
        let harness = Arc::clone(&fixture.harness);
        let owner_drops = Arc::clone(&fixture.owner_drops);
        let mut transport = fixture.transport;
        let shutdown = tokio::spawn(async move {
            transport.shutdown().await;
            transport
        });

        tokio::time::timeout(std::time::Duration::from_secs(2), gate.entered.notified())
            .await
            .expect("shutdown entered the session barrier");
        assert!(!shutdown.is_finished());
        assert_eq!(harness.shutdowns.load(Ordering::SeqCst), 1);
        assert_eq!(harness.session_drops.load(Ordering::SeqCst), 0);

        shutdown.abort();
        let join_error = shutdown
            .await
            .expect_err("aborting blocked shutdown must cancel its future");
        assert!(join_error.is_cancelled());
        assert_eq!(owner_drops.load(Ordering::SeqCst), 1);

        let session_dropped = tokio::time::timeout(std::time::Duration::from_secs(2), async {
            while harness.session_drops.load(Ordering::SeqCst) == 0 {
                tokio::task::yield_now().await;
            }
        })
        .await;
        gate.release.notify_one();
        session_dropped
            .expect("cancelled shutdown must abort and drop the blocked supervisor task");
        assert_eq!(harness.session_drops.load(Ordering::SeqCst), 1);
    }

    #[tokio::test]
    async fn consuming_reclaim_joins_then_drops_old_owner_and_takes_permit_once() {
        let gate = Arc::new(ShutdownGate {
            entered: Notify::new(),
            release: Notify::new(),
        });
        let fixture = connected_fixture(Vec::new(), Some(Arc::clone(&gate))).await;
        let harness = Arc::clone(&fixture.harness);
        let owner_drops = Arc::clone(&fixture.owner_drops);
        let mut transport = fixture.transport;
        let reclaim = tokio::spawn(async move {
            let mut start_permit = Some(0xA5_u8);
            let reclaimed = shutdown_and_take_start_permit(
                &mut transport.supervisor,
                &mut transport.authenticator,
                &mut start_permit,
            )
            .await
            .expect("reclaim exact start permit");
            (transport, start_permit, reclaimed)
        });

        tokio::time::timeout(std::time::Duration::from_secs(2), gate.entered.notified())
            .await
            .expect("reclaim entered session join");
        assert!(!reclaim.is_finished(), "permit cannot escape before join");
        assert_eq!(owner_drops.load(Ordering::SeqCst), 0);
        assert_eq!(harness.session_drops.load(Ordering::SeqCst), 0);

        gate.release.notify_one();
        let (mut transport, mut start_permit, reclaimed) =
            reclaim.await.expect("join reclaim task");
        assert_eq!(reclaimed, 0xA5);
        assert!(start_permit.is_none());
        assert_eq!(harness.shutdowns.load(Ordering::SeqCst), 1);
        assert_eq!(harness.session_drops.load(Ordering::SeqCst), 1);
        assert_eq!(owner_drops.load(Ordering::SeqCst), 1);
        assert_eq!(
            transport.reconnect().await.unwrap_err().code(),
            "remote.transport.closed"
        );
        assert_eq!(
            shutdown_and_take_start_permit(
                &mut transport.supervisor,
                &mut transport.authenticator,
                &mut start_permit,
            )
            .await
            .expect_err("start permit is single-use")
            .code(),
            "remote.transport.start_permit_unavailable"
        );
    }

    #[tokio::test]
    async fn pairing_lane_is_taken_once_and_open_reuses_the_only_session() {
        let mut fixture = connected_fixture(Vec::new(), None).await;
        let mut lane = fixture
            .transport
            .take_pairing_lane(fixture.data_cert.clone())
            .expect("take sole pairing lane");
        assert_eq!(
            fixture
                .transport
                .take_pairing_lane(fixture.data_cert.clone())
                .expect_err("second take must fail")
                .code(),
            "remote.transport.pairing_lane_unavailable"
        );

        let pair_route = PairRouteId::from_bytes([0xa1; 16]);
        open_bound_route(&mut lane, &fixture.harness, pair_route, 10_000).await;
        assert_eq!(fixture.harness.connects.load(Ordering::SeqCst), 1);
        assert_eq!(
            fixture.harness.sent.lock().expect("lock sent frames")[0],
            frame(RelayFrameBody::OpenPairRoute(open_pair_route(
                pair_route, 10_000
            )))
        );
        fixture.transport.shutdown().await;
    }

    #[tokio::test]
    async fn durable_terminal_data_can_rebind_after_restart_but_never_crosses_close() {
        let mut fixture = connected_fixture(Vec::new(), None).await;
        let lane = fixture
            .transport
            .take_pairing_lane(fixture.data_cert.clone())
            .expect("take pairing lane");
        let pair_route = PairRouteId::from_bytes([0xaa; 16]);
        let carrier = PairData {
            pair_route,
            sealed_blob: SealedBlob(vec![0xab; 96]),
        };
        lane.send_pair_terminal_data(carrier.clone())
            .await
            .expect("durable terminal may restore an unbound server-side route");
        lane.send_close_pair_route(ClosePairRoute {
            machine_route: ROUTE,
            pair_route,
        })
        .await
        .expect("Close follows the terminal writer flush");
        assert_eq!(
            fixture.harness.sent.lock().expect("sent frames").as_slice(),
            &[
                frame(RelayFrameBody::PairData(carrier.clone())),
                frame(RelayFrameBody::ClosePairRoute(ClosePairRoute {
                    machine_route: ROUTE,
                    pair_route,
                })),
            ]
        );
        assert_eq!(
            lane.send_pair_terminal_data(carrier)
                .await
                .expect_err("terminal cannot cross the local Close fence")
                .code(),
            "remote.transport.pairing_binding_mismatch"
        );
        fixture.transport.shutdown().await;
    }

    #[tokio::test]
    async fn pairing_runtime_take_is_atomic_binds_data_certificate_and_is_single_use() {
        let mut fixture = connected_fixture(Vec::new(), None).await;
        let runtime = fixture
            .transport
            .take_pairing_runtime(fixture.data_cert.clone())
            .expect("take paired lane and authority atomically");
        let anchor = runtime
            .authority
            .invite_anchor()
            .expect("live authority anchor");
        assert_eq!(anchor.relay_server_id(), RELAY);
        assert_eq!(anchor.machine_route(), ROUTE);
        assert_eq!(anchor.data_sign_certificate(), &fixture.data_cert);
        assert_eq!(anchor.root_key_id(), fixture.data_cert.root_key_id);
        assert_eq!(anchor.trust_epoch(), fixture.data_cert.trust_epoch);
        assert_eq!(anchor.data_generation(), fixture.data_cert.generation);
        assert_eq!(
            fixture
                .transport
                .take_pairing_runtime(fixture.data_cert.clone())
                .expect_err("runtime parts are single-take")
                .code(),
            "remote.transport.pairing_lane_unavailable"
        );
        drop(runtime);
        fixture.transport.shutdown().await;
    }

    #[tokio::test]
    async fn pairing_authority_produces_verifiable_typed_crypto_artifacts() {
        let mut fixture = connected_fixture(Vec::new(), None).await;
        let runtime = fixture
            .transport
            .take_pairing_runtime(fixture.data_cert.clone())
            .expect("take pairing authority");
        let pair_route = PairRouteId::from_bytes([0xb1; 16]);
        let request_hash = [0xb2; 32];
        let request_info = pairing_request_info(pair_route);
        let request_context = pairing_outer_context(OuterFrameKind::PairPending, pair_route);
        let signer = MachineDataSignerBindingV1::from_certificate(&fixture.data_cert)
            .expect("validated data signer binding");
        let machine_data = SigningKey::from_seed(&[0x33; 32]);
        let machine_root = SigningKey::from_seed(&[0x31; 32]);
        let (device_hpke_private, device_hpke_public) = HpkePrivateKey::derive_keypair(&[0xb3; 32]);
        let mut pending_rng = DeterministicRng::new([0xb4; 32]);
        let pending = runtime
            .authority
            .seal_pair_pending_with_rng_for_test(
                &device_hpke_public,
                &request_info,
                &request_context,
                request_hash,
                &mut pending_rng,
            )
            .expect("seal typed PairPending");
        assert_eq!(
            open_pair_pending(
                &device_hpke_private,
                &request_info,
                &request_context,
                &pending,
                &machine_data.verifying_key(),
                &signer,
            )
            .expect("open and verify PairPending")
            .request_hash,
            request_hash
        );

        let terminal_context = pairing_outer_context(OuterFrameKind::PairTerminal, pair_route);
        let terminal_hpke_seed = [0xb6; 32];
        let terminal = runtime
            .authority
            .seal_pair_terminal(
                &device_hpke_public,
                &request_info,
                &terminal_context,
                PairTerminalV1 {
                    machine_route: ROUTE,
                    request_hash,
                    outcome: PairTerminalOutcomeV1::Canceled,
                    signature: Ed25519Signature([0; 64]),
                },
                &fixture.data_cert,
                Zeroizing::new(terminal_hpke_seed),
            )
            .expect("seal typed PairTerminal with current Data certificate");
        let terminal_replay = runtime
            .authority
            .seal_pair_terminal(
                &device_hpke_public,
                &request_info,
                &terminal_context,
                PairTerminalV1 {
                    machine_route: ROUTE,
                    request_hash,
                    outcome: PairTerminalOutcomeV1::Canceled,
                    signature: Ed25519Signature([0; 64]),
                },
                &fixture.data_cert,
                Zeroizing::new(terminal_hpke_seed),
            )
            .expect("replay typed PairTerminal from the durable HPKE seed");
        assert_eq!(
            terminal_replay, terminal,
            "the same durable terminal seed must reproduce the exact HPKE carrier"
        );
        assert_eq!(
            open_pair_terminal(
                &device_hpke_private,
                &request_info,
                &terminal_context,
                PairTerminalExpectedV1::new(ROUTE, request_hash).unwrap(),
                &terminal,
                &machine_data.verifying_key(),
                &signer,
            )
            .expect("open and verify PairTerminal")
            .outcome,
            PairTerminalOutcomeV1::Canceled
        );

        let device_signing = SigningKey::from_seed(&[0xb5; 32]);
        let grant = runtime
            .authority
            .sign_relay_grant(unsigned_pairing_grant(&device_signing))
            .expect("sign typed RelayGrant");
        verify_tbs(
            &machine_root.verifying_key(),
            &grant.to_be_signed_v1(RELAY, sha256(&machine_root.verifying_key().to_bytes())),
            &SignatureBytes::from(grant.signature),
        )
        .expect("verify root-signed RelayGrant");

        let device_hpke_public_key = PublicKeyBytes(
            device_hpke_public
                .to_bytes()
                .try_into()
                .expect("32-byte DeviceHPKE public key"),
        );
        let authorization = runtime
            .authority
            .sign_device_authorization(
                &grant,
                unsigned_device_authorization(&grant, device_hpke_public_key),
            )
            .expect("sign typed DeviceAuthorization");
        verify_device_authorization(&machine_root.verifying_key(), RELAY, &grant, &authorization)
            .expect("verify root-signed DeviceAuthorization");

        let key_context = KeyDirectorySignatureContextV1 {
            relay_server_id: RELAY,
            machine_route: grant.machine_route,
            device_route: grant.device_route,
            grant_serial: grant.grant_serial,
            root_trust_epoch: grant.trust_epoch,
        };
        let key_update_context = OuterContextV1 {
            frame_kind: OuterFrameKind::KeyUpdate,
            relay_protocol_version: RELAY_PROTOCOL_VERSION,
            e2ee_format_version: E2EE_FORMAT_VERSION,
            machine_route: Some(grant.machine_route),
            device_route: Some(grant.device_route),
            stream_route: None,
            request_route: None,
            pair_route: None,
            stream_generation: None,
            stream_cursor: None,
            stream_seq: None,
            message_key_epoch: 1,
        };
        let mut entries = Vec::new();
        for (purpose, seed) in [
            (KeyPurpose::Catalog, 0xc1),
            (KeyPurpose::DeviceCommandTx, 0xc2),
            (KeyPurpose::DeviceReplyTx, 0xc3),
        ] {
            let info = KeyUpdateInfoV1 {
                e2ee_format_version: E2EE_FORMAT_VERSION,
                runtime_protocol_version: RUNTIME_PROTOCOL_VERSION,
                relay_server_id: RELAY,
                machine_route: grant.machine_route,
                device_route: grant.device_route,
                stream_route: None,
                grant_serial: grant.grant_serial,
                root_trust_epoch: grant.trust_epoch,
                key_directory_revision: KeyDirectoryRevision::new(1),
                key_purpose: purpose,
                key_epoch: 1,
            };
            let mut rng = DeterministicRng::new([seed; 32]);
            let entry = runtime
                .authority
                .seal_key_directory_entry_with_rng_for_test(
                    &device_hpke_public,
                    &info,
                    &key_update_context,
                    &SecretAeadKey::from_bytes([seed.wrapping_add(1); 32]),
                    &mut rng,
                )
                .expect("wrap typed bootstrap key");
            assert!(
                open_key_directory_entry(&device_hpke_private, &info, &key_update_context, &entry,)
                    .is_ok()
            );
            entries.push(entry);
        }
        let mut unsigned_directory = bootstrap_key_directory(grant.device_route);
        let catalog_entry = entries[0].clone();
        unsigned_directory.entries = entries;
        let key_directory = runtime
            .authority
            .sign_key_directory(&key_context, unsigned_directory)
            .expect("sign strict bootstrap key directory");
        verify_key_directory(
            &machine_data.verifying_key(),
            &signer,
            &key_context,
            &key_directory,
        )
        .expect("verify MachineData-signed key directory");

        let update_info = KeyUpdateInfoV1 {
            e2ee_format_version: E2EE_FORMAT_VERSION,
            runtime_protocol_version: RUNTIME_PROTOCOL_VERSION,
            relay_server_id: RELAY,
            machine_route: grant.machine_route,
            device_route: grant.device_route,
            stream_route: None,
            grant_serial: grant.grant_serial,
            root_trust_epoch: grant.trust_epoch,
            key_directory_revision: KeyDirectoryRevision::new(1),
            key_purpose: KeyPurpose::Catalog,
            key_epoch: 1,
        };
        let signed_update = runtime
            .authority
            .machine_data_authority()
            .sign_key_update(
                &update_info,
                &key_update_context,
                KeyUpdateV1 {
                    key_directory_revision: KeyDirectoryRevision::new(1),
                    key_id: catalog_entry.key_id,
                    device_route: catalog_entry.device_route,
                    stream_route: catalog_entry.stream_route,
                    enc: catalog_entry.enc,
                    wrapped_key: catalog_entry.wrapped_key,
                    signature: Ed25519Signature([0; 64]),
                },
            )
            .expect("sign typed KeyUpdate with the narrow MachineData authority");
        verify_key_update(
            &machine_data.verifying_key(),
            &signer,
            &update_info,
            &key_update_context,
            &signed_update,
        )
        .expect("verify MachineData-signed KeyUpdate");

        let response_info = pairing_response_info(pair_route, request_hash, &grant);
        let response_context = pairing_outer_context(OuterFrameKind::PairResponse, pair_route);
        let plaintext = PairResponsePlaintextV1 {
            format_version: E2EE_FORMAT_VERSION,
            request_hash,
            relay_grant: grant.clone(),
            device_authorization: authorization,
            key_directory,
        };
        let mut response_rng = DeterministicRng::new([0xb6; 32]);
        let response = runtime
            .authority
            .seal_pair_response_with_rng_for_test(
                &device_hpke_public,
                &response_info,
                &response_context,
                &plaintext,
                &mut response_rng,
            )
            .expect("seal typed PairResponse");
        assert_eq!(
            open_pair_response(
                &device_hpke_private,
                &response_info,
                &response_context,
                &response,
                &machine_data.verifying_key(),
                &signer,
                &machine_root.verifying_key(),
            )
            .expect("open and verify PairResponse"),
            plaintext
        );

        let revocation = runtime
            .authority
            .sign_device_revocation(unsigned_pairing_revocation(&grant))
            .expect("sign typed DeviceRevocation");
        verify_tbs(
            &machine_root.verifying_key(),
            &revocation.to_be_signed_v1(RELAY, sha256(&machine_root.verifying_key().to_bytes())),
            &SignatureBytes::from(revocation.signature),
        )
        .expect("verify root-signed DeviceRevocation");

        drop(runtime);
        fixture.transport.shutdown().await;
    }

    #[tokio::test]
    async fn pairing_authority_entropy_failure_is_typed_and_never_panics() {
        let mut fixture = connected_fixture(Vec::new(), None).await;
        let runtime = fixture
            .transport
            .take_pairing_runtime(fixture.data_cert.clone())
            .expect("take pairing authority");
        let pair_route = PairRouteId::from_bytes([0xb7; 16]);
        let request_info = pairing_request_info(pair_route);
        let request_context = pairing_outer_context(OuterFrameKind::PairPending, pair_route);
        let (_, recipient) = HpkePrivateKey::derive_keypair(&[0xb8; 32]);
        let calls = std::cell::Cell::new(0_usize);

        let error = runtime
            .authority
            .seal_pair_pending_with_entropy_source(
                &recipient,
                &request_info,
                &request_context,
                [0xb9; 32],
                |destination| {
                    calls.set(calls.get() + 1);
                    destination.fill(0xa5);
                    Err(())
                },
            )
            .expect_err("OS entropy failure must discard the HPKE artifact");
        assert_eq!(calls.get(), 1, "authority requests one 256-bit CSPRNG seed");
        assert_eq!(error.code(), "remote.transport.pairing_entropy_unavailable");

        calls.set(0);
        let key_info = KeyUpdateInfoV1 {
            e2ee_format_version: E2EE_FORMAT_VERSION,
            runtime_protocol_version: RUNTIME_PROTOCOL_VERSION,
            relay_server_id: RELAY,
            machine_route: ROUTE,
            device_route: DeviceRouteId::from_bytes([0xba; 16]),
            stream_route: None,
            grant_serial: GrantSerial::new(7),
            root_trust_epoch: TrustEpoch::new(3),
            key_directory_revision: KeyDirectoryRevision::new(1),
            key_purpose: KeyPurpose::Catalog,
            key_epoch: 1,
        };
        let key_context = OuterContextV1 {
            frame_kind: OuterFrameKind::KeyUpdate,
            relay_protocol_version: RELAY_PROTOCOL_VERSION,
            e2ee_format_version: E2EE_FORMAT_VERSION,
            machine_route: Some(ROUTE),
            device_route: Some(key_info.device_route),
            stream_route: None,
            request_route: None,
            pair_route: None,
            stream_generation: None,
            stream_cursor: None,
            stream_seq: None,
            message_key_epoch: 1,
        };
        let error = runtime
            .authority
            .seal_key_directory_entry_with_entropy_source(
                &recipient,
                &key_info,
                &key_context,
                &SecretAeadKey::from_bytes([0xbb; 32]),
                |destination| {
                    calls.set(calls.get() + 1);
                    destination.fill(0xa5);
                    Err(())
                },
            )
            .expect_err("key-wrap entropy failure must discard the HPKE artifact");
        assert_eq!(calls.get(), 1, "key wrap requests one 256-bit CSPRNG seed");
        assert_eq!(error.code(), "remote.transport.pairing_entropy_unavailable");

        drop(runtime);
        fixture.transport.shutdown().await;
    }

    #[test]
    fn one_shot_hpke_rng_matches_real_x25519_contract_and_wipes_consumed_seed() {
        let (_, recipient) = HpkePrivateKey::derive_keypair(&[0x59; 32]);
        let (mut rng, wiped) =
            OneShotHpkeSeedRng::with_seed_wipe_observer(Zeroizing::new([0x5a; 32]));
        let sealed = agentdeck_crypto::hpke_seal_base(
            &recipient,
            b"one-shot-hpke-ikm-contract",
            b"aad",
            b"plaintext",
            &mut rng,
        );
        assert!(
            wiped.load(Ordering::SeqCst),
            "the unique seed owner must be zeroized immediately after the exact IKM request"
        );
        let sealed = rng
            .finish(sealed)
            .expect("real X25519 HPKE must request one exact 32-byte IKM")
            .expect("real HPKE seal succeeds");
        assert_eq!(sealed.enc.len(), 32);
    }

    #[test]
    fn one_shot_hpke_rng_drop_wipes_an_unconsumed_seed() {
        let (rng, wiped) = OneShotHpkeSeedRng::with_seed_wipe_observer(Zeroizing::new([0x5b; 32]));
        drop(rng);
        assert!(
            wiped.load(Ordering::SeqCst),
            "all pre-HPKE error paths must wipe the still-owned seed"
        );
    }

    #[test]
    fn one_shot_hpke_rng_rejects_wrong_repeated_and_word_requests() {
        let mut wrong_length = OneShotHpkeSeedRng::new(Zeroizing::new([0x5c; 32]));
        let mut wrong_output = [0xa5; 31];
        wrong_length
            .try_fill_bytes(&mut wrong_output)
            .expect("one-shot RNG is infallible");
        assert_eq!(wrong_output, [0; 31]);
        assert_eq!(
            wrong_length
                .finish::<(), ()>(Ok(()))
                .expect_err("wrong IKM length must discard the artifact")
                .code(),
            "remote.transport.pairing_entropy_contract_violation"
        );

        let mut repeated = OneShotHpkeSeedRng::new(Zeroizing::new([0x5d; 32]));
        let mut first = Zeroizing::new([0_u8; 32]);
        repeated
            .try_fill_bytes(first.as_mut())
            .expect("one-shot RNG is infallible");
        assert_eq!(first.as_ref(), &[0x5d; 32]);
        let mut second = [0xa5; 32];
        repeated
            .try_fill_bytes(&mut second)
            .expect("one-shot RNG is infallible");
        assert_eq!(second, [0; 32]);
        assert_eq!(
            repeated
                .finish::<(), ()>(Ok(()))
                .expect_err("a repeated request must discard the artifact")
                .code(),
            "remote.transport.pairing_entropy_contract_violation"
        );

        let mut word32 = OneShotHpkeSeedRng::new(Zeroizing::new([0x5e; 32]));
        assert_eq!(
            word32.try_next_u32().expect("one-shot RNG is infallible"),
            0
        );
        assert_eq!(
            word32
                .finish::<(), ()>(Ok(()))
                .expect_err("u32 requests must discard the artifact")
                .code(),
            "remote.transport.pairing_entropy_contract_violation"
        );

        let mut word64 = OneShotHpkeSeedRng::new(Zeroizing::new([0x5f; 32]));
        assert_eq!(
            word64.try_next_u64().expect("one-shot RNG is infallible"),
            0
        );
        assert_eq!(
            word64
                .finish::<(), ()>(Ok(()))
                .expect_err("u64 requests must discard the artifact")
                .code(),
            "remote.transport.pairing_entropy_contract_violation"
        );
    }

    #[tokio::test]
    async fn pairing_runtime_rejects_wrong_data_cert_role_relay_and_route_without_consuming_lane() {
        let root = SigningKey::from_seed(&[0x31; 32]);
        for (certificate, expected) in [
            (
                {
                    let mut certificate = signed_data_certificate(&root, RELAY, ROUTE);
                    certificate.cert_role = agentdeck_protocol::relay_v2::CertRole::Link;
                    certificate
                },
                "daemon.remote.certificate.role_mismatch",
            ),
            (
                signed_data_certificate(&root, RelayServerId::from_bytes([0xee; 16]), ROUTE),
                "daemon.remote.certificate.signature_invalid",
            ),
            (
                signed_data_certificate(&root, RELAY, MachineRouteId::from_bytes([0xef; 16])),
                "daemon.remote.certificate.signature_invalid",
            ),
        ] {
            let mut fixture = connected_fixture(Vec::new(), None).await;
            assert_eq!(
                fixture
                    .transport
                    .take_pairing_runtime(certificate)
                    .expect_err("wrong data cert context")
                    .code(),
                expected
            );
            let runtime = fixture
                .transport
                .take_pairing_runtime(fixture.data_cert.clone())
                .expect("failed validation must not consume the lane");
            drop(runtime);
            fixture.transport.shutdown().await;
        }
    }

    #[tokio::test]
    async fn pairing_authority_weak_owner_does_not_block_reclaim_and_fails_after_shutdown() {
        let mut fixture = connected_fixture(Vec::new(), None).await;
        let runtime = fixture
            .transport
            .take_pairing_runtime(fixture.data_cert.clone())
            .unwrap();
        let mut start_permit = Some(0xa5_u8);
        let reclaimed = shutdown_and_take_start_permit(
            &mut fixture.transport.supervisor,
            &mut fixture.transport.authenticator,
            &mut start_permit,
        )
        .await
        .expect("Weak authority must not keep the authenticator shared");
        assert_eq!(reclaimed, 0xa5);
        assert_eq!(
            runtime.authority.invite_anchor().unwrap_err().code(),
            "remote.transport.closed"
        );
        assert_eq!(fixture.owner_drops.load(Ordering::SeqCst), 1);
    }

    #[tokio::test]
    async fn pairing_lane_typed_reconnect_forwards_and_clears_ephemeral_route_binding() {
        let mut fixture = connected_fixture(Vec::new(), None).await;
        let PairingRuntimeParts {
            mut lane,
            authority: _,
        } = fixture
            .transport
            .take_pairing_runtime(fixture.data_cert.clone())
            .unwrap();
        let pair_route = PairRouteId::from_bytes([0xad; 16]);
        open_bound_route(&mut lane, &fixture.harness, pair_route, 10_009).await;
        lane.reconnect().await.expect("typed reconnect forwarding");
        assert_eq!(fixture.harness.reconnects.load(Ordering::SeqCst), 1);
        assert_eq!(
            lane.send_pair_data(PairData {
                pair_route,
                sealed_blob: SealedBlob(vec![1]),
            })
            .await
            .unwrap_err()
            .code(),
            "remote.transport.pairing_binding_mismatch"
        );
        fixture.transport.shutdown().await;
    }

    #[tokio::test]
    async fn pairing_data_and_route_accepted_are_typed_but_not_delivery_proof() {
        let mut fixture = connected_fixture(Vec::new(), None).await;
        let mut lane = fixture
            .transport
            .take_pairing_lane(fixture.data_cert.clone())
            .unwrap();
        let pair_route = PairRouteId::from_bytes([0xa2; 16]);
        open_bound_route(&mut lane, &fixture.harness, pair_route, 10_001).await;

        let data = PairData {
            pair_route,
            sealed_blob: SealedBlob(vec![1, 2, 3]),
        };
        lane.send_pair_data(data.clone()).await.expect("send data");
        fixture
            .harness
            .push_incoming(frame(RelayFrameBody::PairData(data.clone())));
        assert!(matches!(
            lane.next_event().await.unwrap(),
            Some(PairingTransportEvent::PairData(observed)) if observed == data
        ));

        let accepted = RouteAccepted {
            accepted: AcceptedRef::PairFrame { pair_route },
        };
        fixture
            .harness
            .push_incoming(frame(RelayFrameBody::RouteAccepted(accepted.clone())));
        let event = lane.next_event().await.unwrap().unwrap();
        assert!(matches!(
            &event,
            PairingTransportEvent::PairFrameAccepted(observed) if observed == &accepted
        ));
        assert!(
            !format!("{event:?}").contains("delivered"),
            "Relay writer acceptance is never endpoint delivery proof"
        );
        fixture.transport.shutdown().await;
    }

    #[tokio::test]
    async fn pairing_close_accepts_closed_and_already_absent_for_the_bound_route() {
        for outcome in [
            PairRouteCloseOutcome::Closed,
            PairRouteCloseOutcome::AlreadyAbsent,
        ] {
            let mut fixture = connected_fixture(Vec::new(), None).await;
            let mut lane = fixture
                .transport
                .take_pairing_lane(fixture.data_cert.clone())
                .unwrap();
            let pair_route = PairRouteId::from_bytes([0xa3; 16]);
            open_bound_route(&mut lane, &fixture.harness, pair_route, 10_002).await;
            lane.send_close_pair_route(ClosePairRoute {
                machine_route: ROUTE,
                pair_route,
            })
            .await
            .expect("send close");
            let closed = PairRouteClosed {
                pair_route,
                outcome,
            };
            fixture
                .harness
                .push_incoming(frame(RelayFrameBody::PairRouteClosed(closed.clone())));
            assert!(matches!(
                lane.next_event().await.unwrap(),
                Some(PairingTransportEvent::PairRouteClosed(observed)) if observed == closed
            ));
            fixture.transport.shutdown().await;
        }
    }

    fn terminal_data(pair_route: PairRouteId, seed: u8) -> PairData {
        PairData {
            pair_route,
            sealed_blob: SealedBlob(vec![seed; 96]),
        }
    }

    fn correlated_failure(data: &PairData, code: &str) -> OpaqueRouteFrame {
        let outbound = frame(RelayFrameBody::PairData(data.clone()));
        frame(RelayFrameBody::Error(
            RelayFailure::new(code, "redacted test failure")
                .in_reply_to(relay_frame_reply_reference(&outbound)),
        ))
    }

    async fn assert_terminal_miss_yields_matching_close(
        lane: &mut PairingTransportLane,
        harness: &Harness,
        pair_route: PairRouteId,
        outcome: PairRouteCloseOutcome,
    ) {
        let terminal = terminal_data(pair_route, 0xd1);
        lane.send_pair_terminal_and_close(
            terminal.clone(),
            ClosePairRoute {
                machine_route: ROUTE,
                pair_route,
            },
        )
        .await
        .expect("atomically flush terminal then Close");
        harness.push_incoming(correlated_failure(&terminal, RELAY_ROUTE_NOT_FOUND));
        let closed = PairRouteClosed {
            pair_route,
            outcome,
        };
        harness.push_incoming(frame(RelayFrameBody::PairRouteClosed(closed.clone())));
        assert!(matches!(
            tokio::time::timeout(Duration::from_secs(1), lane.next_event())
                .await
                .expect("matching Close ACK must not be starved")
                .expect("expected terminal miss is not a transport failure"),
            Some(PairingTransportEvent::PairRouteClosed(observed)) if observed == closed
        ));
    }

    #[tokio::test]
    async fn terminal_not_found_for_offline_pairing_peer_does_not_preempt_closed_ack() {
        let mut fixture = connected_fixture(Vec::new(), None).await;
        let mut lane = fixture
            .transport
            .take_pairing_lane(fixture.data_cert.clone())
            .unwrap();
        let pair_route = PairRouteId::from_bytes([0xd1; 16]);
        open_bound_route(&mut lane, &fixture.harness, pair_route, 10_021).await;

        assert_terminal_miss_yields_matching_close(
            &mut lane,
            &fixture.harness,
            pair_route,
            PairRouteCloseOutcome::Closed,
        )
        .await;
        assert_eq!(fixture.harness.reconnects.load(Ordering::SeqCst), 0);
        assert_eq!(
            lane.generation.load(Ordering::Acquire),
            INITIAL_PAIRING_GENERATION
        );
        fixture.transport.shutdown().await;
    }

    #[tokio::test]
    async fn terminal_not_found_after_lost_close_ack_does_not_preempt_already_absent_ack() {
        let mut fixture = connected_fixture(Vec::new(), None).await;
        let mut lane = fixture
            .transport
            .take_pairing_lane(fixture.data_cert.clone())
            .unwrap();
        lane.reconnect()
            .await
            .expect("model daemon restart with a fresh transport generation");
        let pair_route = PairRouteId::from_bytes([0xd2; 16]);

        assert_terminal_miss_yields_matching_close(
            &mut lane,
            &fixture.harness,
            pair_route,
            PairRouteCloseOutcome::AlreadyAbsent,
        )
        .await;
        assert_eq!(fixture.harness.reconnects.load(Ordering::SeqCst), 1);
        assert_eq!(
            lane.generation.load(Ordering::Acquire),
            INITIAL_PAIRING_GENERATION + 1
        );
        fixture.transport.shutdown().await;
    }

    #[test]
    fn terminal_not_found_suppression_requires_exact_current_closing_one_shot_binding() {
        let pair_route = PairRouteId::from_bytes([0xd3; 16]);
        let terminal = terminal_data(pair_route, 0xd3);
        let terminal_command = PairingCommand::TerminalData(terminal.clone());
        let close_command = PairingCommand::Close(ClosePairRoute {
            machine_route: ROUTE,
            pair_route,
        });
        let exact_failure = || correlated_failure(&terminal, RELAY_ROUTE_NOT_FOUND);
        let decode = |bindings: &mut PairingBindings, frame: OpaqueRouteFrame| {
            decode_inbound(
                ROUTE,
                INITIAL_PAIRING_GENERATION,
                bindings,
                &mut PublicationBindings::default(),
                frame,
            )
        };

        let mut nonclosing = PairingBindings::default()
            .prepare_outbound(ROUTE, &terminal_command)
            .unwrap();
        assert!(matches!(
            decode(&mut nonclosing, exact_failure()),
            Ok(InboundDispatch::Shared { .. })
        ));

        let closing = PairingBindings::default()
            .prepare_outbound(ROUTE, &terminal_command)
            .unwrap()
            .prepare_outbound(ROUTE, &close_command)
            .unwrap();
        let mut wrong_hash = closing.clone();
        assert!(matches!(
            decode(
                &mut wrong_hash,
                correlated_failure(&terminal_data(pair_route, 0xd4), RELAY_ROUTE_NOT_FOUND),
            ),
            Ok(InboundDispatch::Shared { .. })
        ));
        let mut other_code = closing.clone();
        assert!(matches!(
            decode(
                &mut other_code,
                correlated_failure(&terminal, "relay.route.forbidden"),
            ),
            Ok(InboundDispatch::Shared { .. })
        ));
        let mut normal_data = closing.clone();
        assert!(matches!(
            decode(
                &mut normal_data,
                correlated_failure(&terminal_data(pair_route, 0xd5), RELAY_ROUTE_NOT_FOUND),
            ),
            Ok(InboundDispatch::Shared { .. })
        ));

        let mut exact_once = closing;
        assert!(matches!(
            decode(&mut exact_once, exact_failure()),
            Ok(InboundDispatch::ExpectedTerminalReplayMiss)
        ));
        assert!(matches!(
            decode(&mut exact_once, exact_failure()),
            Ok(InboundDispatch::Shared { .. })
        ));
    }

    #[tokio::test]
    async fn pairing_grant_and_revocation_terminals_match_device_serial_and_frozen_bytes() {
        let mut fixture = connected_fixture(Vec::new(), None).await;
        let mut lane = fixture
            .transport
            .take_pairing_lane(fixture.data_cert.clone())
            .unwrap();
        let device_route = DeviceRouteId::from_bytes([0xb1; 16]);
        let grant = relay_grant(device_route, 7);
        lane.send_install_grant(InstallGrant {
            grant: grant.clone(),
        })
        .await
        .expect("send grant");
        let grant_commit = GrantCommitted {
            device_route,
            grant_serial: grant.grant_serial,
            grant_hash: grant.canonical_sha256(),
        };
        fixture
            .harness
            .push_incoming(frame(RelayFrameBody::GrantCommitted(grant_commit.clone())));
        assert!(matches!(
            lane.next_event().await.unwrap(),
            Some(PairingTransportEvent::GrantCommitted(observed)) if observed == grant_commit
        ));

        let revocation = device_revocation(device_route, 7);
        lane.send_revoke_device(RevokeDevice {
            revocation: revocation.clone(),
        })
        .await
        .expect("send revoke");
        let revoke_commit = RevocationCommitted {
            device_route,
            grant_serial: revocation.grant_serial,
            signed_revocation: revocation,
        };
        fixture
            .harness
            .push_incoming(frame(RelayFrameBody::RevocationCommitted(
                revoke_commit.clone(),
            )));
        assert!(matches!(
            lane.next_event().await.unwrap(),
            Some(PairingTransportEvent::RevocationCommitted(observed)) if observed == revoke_commit
        ));
        fixture.transport.shutdown().await;
    }

    #[tokio::test]
    async fn pairing_exact_duplicate_terminal_acks_are_idempotent_within_the_generation() {
        let mut fixture = connected_fixture(Vec::new(), None).await;
        let mut lane = fixture
            .transport
            .take_pairing_lane(fixture.data_cert.clone())
            .unwrap();

        let pair_route = PairRouteId::from_bytes([0xc1; 16]);
        open_bound_route(&mut lane, &fixture.harness, pair_route, 10_011).await;
        let close = ClosePairRoute {
            machine_route: ROUTE,
            pair_route,
        };
        lane.send_close_pair_route(close.clone()).await.unwrap();
        lane.send_close_pair_route(close).await.unwrap();
        for outcome in [
            PairRouteCloseOutcome::Closed,
            PairRouteCloseOutcome::AlreadyAbsent,
        ] {
            fixture
                .harness
                .push_incoming(frame(RelayFrameBody::PairRouteClosed(PairRouteClosed {
                    pair_route,
                    outcome,
                })));
            assert!(matches!(
                lane.next_event().await.unwrap(),
                Some(PairingTransportEvent::PairRouteClosed(PairRouteClosed {
                    pair_route: observed,
                    outcome: observed_outcome,
                })) if observed == pair_route && observed_outcome == outcome
            ));
        }

        let device_route = DeviceRouteId::from_bytes([0xc2; 16]);
        let grant = relay_grant(device_route, 11);
        let install = InstallGrant {
            grant: grant.clone(),
        };
        lane.send_install_grant(install.clone()).await.unwrap();
        lane.send_install_grant(install).await.unwrap();
        let grant_commit = GrantCommitted {
            device_route,
            grant_serial: grant.grant_serial,
            grant_hash: grant.canonical_sha256(),
        };
        for _ in 0..2 {
            fixture
                .harness
                .push_incoming(frame(RelayFrameBody::GrantCommitted(grant_commit.clone())));
            assert!(matches!(
                lane.next_event().await.unwrap(),
                Some(PairingTransportEvent::GrantCommitted(observed)) if observed == grant_commit
            ));
        }

        let revocation = device_revocation(device_route, 11);
        let revoke = RevokeDevice {
            revocation: revocation.clone(),
        };
        lane.send_revoke_device(revoke.clone()).await.unwrap();
        lane.send_revoke_device(revoke).await.unwrap();
        let revoke_commit = RevocationCommitted {
            device_route,
            grant_serial: revocation.grant_serial,
            signed_revocation: revocation,
        };
        for _ in 0..2 {
            fixture
                .harness
                .push_incoming(frame(RelayFrameBody::RevocationCommitted(
                    revoke_commit.clone(),
                )));
            assert!(matches!(
                lane.next_event().await.unwrap(),
                Some(PairingTransportEvent::RevocationCommitted(observed))
                    if observed == revoke_commit
            ));
        }

        assert_eq!(fixture.transport.observed_failure_code(), None);
        fixture.transport.shutdown().await;
    }

    #[tokio::test]
    async fn pairing_outbound_rejects_wrong_machine_pair_device_serial_and_oversize() {
        let mut fixture = connected_fixture(Vec::new(), None).await;
        let lane = fixture
            .transport
            .take_pairing_lane(fixture.data_cert.clone())
            .unwrap();
        let pair_route = PairRouteId::from_bytes([0xa4; 16]);
        let other_pair = PairRouteId::from_bytes([0xa5; 16]);
        let mut wrong_open = open_pair_route(pair_route, 10_003);
        wrong_open.machine_route = MachineRouteId::from_bytes([0xff; 16]);
        assert_eq!(
            lane.send_open_pair_route(wrong_open)
                .await
                .unwrap_err()
                .code(),
            "remote.transport.route_mismatch"
        );
        assert_eq!(
            lane.send_pair_data(PairData {
                pair_route: other_pair,
                sealed_blob: SealedBlob(vec![1]),
            })
            .await
            .unwrap_err()
            .code(),
            "remote.transport.pairing_binding_mismatch"
        );

        let mut wrong_grant = relay_grant(DeviceRouteId::from_bytes([0xb2; 16]), 8);
        wrong_grant.machine_route = MachineRouteId::from_bytes([0xfe; 16]);
        assert_eq!(
            lane.send_install_grant(InstallGrant { grant: wrong_grant })
                .await
                .unwrap_err()
                .code(),
            "remote.transport.route_mismatch"
        );
        let zero_serial = device_revocation(DeviceRouteId::from_bytes([0xb3; 16]), 0);
        assert_eq!(
            lane.send_revoke_device(RevokeDevice {
                revocation: zero_serial,
            })
            .await
            .unwrap_err()
            .code(),
            "remote.transport.pairing_binding_mismatch"
        );
        assert_eq!(
            lane.send_pair_data(PairData {
                pair_route,
                sealed_blob: SealedBlob(vec![0; agentdeck_protocol::relay_v2::MAX_FRAME_BYTES]),
            })
            .await
            .unwrap_err()
            .code(),
            "relay.client.frame_too_large"
        );
        assert!(fixture.harness.sent.lock().expect("lock sent").is_empty());
        fixture.transport.shutdown().await;
    }

    #[tokio::test]
    async fn pairing_lane_rejects_unsigned_wrong_root_and_wrong_trust_authority() {
        let mut fixture = connected_fixture(Vec::new(), None).await;
        let lane = fixture
            .transport
            .take_pairing_lane(fixture.data_cert.clone())
            .unwrap();
        let device_route = DeviceRouteId::from_bytes([0xc3; 16]);

        let mut unsigned_grant = relay_grant(device_route, 12);
        unsigned_grant.signature = Ed25519Signature([0; 64]);
        assert_eq!(
            lane.send_install_grant(InstallGrant {
                grant: unsigned_grant,
            })
            .await
            .unwrap_err()
            .code(),
            "remote.transport.pairing_authority_mismatch"
        );

        let mut wrong_root_grant = relay_grant(device_route, 12);
        wrong_root_grant.signature = Ed25519Signature([0xd1; 64]);
        assert_eq!(
            lane.send_install_grant(InstallGrant {
                grant: wrong_root_grant,
            })
            .await
            .unwrap_err()
            .code(),
            "remote.transport.pairing_crypto_failed"
        );

        let mut wrong_trust_grant = relay_grant(device_route, 12);
        wrong_trust_grant.trust_epoch = TrustEpoch::new(4);
        assert_eq!(
            lane.send_install_grant(InstallGrant {
                grant: wrong_trust_grant,
            })
            .await
            .unwrap_err()
            .code(),
            "remote.transport.pairing_authority_mismatch"
        );

        let mut unsigned_revocation = device_revocation(device_route, 12);
        unsigned_revocation.signature = Ed25519Signature([0; 64]);
        assert_eq!(
            lane.send_revoke_device(RevokeDevice {
                revocation: unsigned_revocation,
            })
            .await
            .unwrap_err()
            .code(),
            "remote.transport.pairing_authority_mismatch"
        );

        assert!(fixture.harness.sent.lock().expect("lock sent").is_empty());
        fixture.transport.shutdown().await;
    }

    #[tokio::test]
    async fn pairing_inbound_wrong_open_grant_or_revocation_binding_fails_closed() {
        let mut open_fixture = connected_fixture(Vec::new(), None).await;
        let mut open_lane = open_fixture
            .transport
            .take_pairing_lane(open_fixture.data_cert.clone())
            .unwrap();
        let pair_route = PairRouteId::from_bytes([0xa6; 16]);
        open_lane
            .send_open_pair_route(open_pair_route(pair_route, 10_004))
            .await
            .unwrap();
        open_fixture
            .harness
            .push_incoming(frame(RelayFrameBody::PairRouteOpened(PairRouteOpened {
                machine_route: ROUTE,
                pair_route,
                absolute_expiry_ms: 10_005,
            })));
        assert_eq!(
            open_lane.next_event().await.unwrap_err().code(),
            "remote.transport.pairing_binding_mismatch"
        );
        assert_eq!(open_fixture.harness.shutdowns.load(Ordering::SeqCst), 1);
        open_fixture.transport.shutdown().await;

        let mut grant_fixture = connected_fixture(Vec::new(), None).await;
        let mut grant_lane = grant_fixture
            .transport
            .take_pairing_lane(grant_fixture.data_cert.clone())
            .unwrap();
        let device_route = DeviceRouteId::from_bytes([0xb4; 16]);
        let grant = relay_grant(device_route, 9);
        grant_lane
            .send_install_grant(InstallGrant {
                grant: grant.clone(),
            })
            .await
            .unwrap();
        grant_fixture
            .harness
            .push_incoming(frame(RelayFrameBody::GrantCommitted(GrantCommitted {
                device_route,
                grant_serial: GrantSerial::new(10),
                grant_hash: grant.canonical_sha256(),
            })));
        assert_eq!(
            grant_lane.next_event().await.unwrap_err().code(),
            "remote.transport.pairing_binding_mismatch"
        );
        grant_fixture.transport.shutdown().await;

        let mut revoke_fixture = connected_fixture(Vec::new(), None).await;
        let mut revoke_lane = revoke_fixture
            .transport
            .take_pairing_lane(revoke_fixture.data_cert.clone())
            .unwrap();
        let revocation = device_revocation(device_route, 9);
        revoke_lane
            .send_revoke_device(RevokeDevice {
                revocation: revocation.clone(),
            })
            .await
            .unwrap();
        let mut changed = revocation;
        changed.signature = Ed25519Signature([0xee; 64]);
        revoke_fixture
            .harness
            .push_incoming(frame(RelayFrameBody::RevocationCommitted(
                RevocationCommitted {
                    device_route,
                    grant_serial: GrantSerial::new(9),
                    signed_revocation: changed,
                },
            )));
        assert_eq!(
            revoke_lane.next_event().await.unwrap_err().code(),
            "remote.transport.pairing_binding_mismatch"
        );
        revoke_fixture.transport.shutdown().await;
    }

    #[tokio::test]
    async fn pairing_ninth_unconsumed_event_fails_closed_with_stable_lag_code() {
        let mut fixture = connected_fixture(Vec::new(), None).await;
        let mut lane = fixture
            .transport
            .take_pairing_lane(fixture.data_cert.clone())
            .unwrap();
        let pair_route = PairRouteId::from_bytes([0xa7; 16]);
        lane.send_open_pair_route(open_pair_route(pair_route, 10_006))
            .await
            .unwrap();
        fixture
            .harness
            .push_incoming(frame(RelayFrameBody::PairRouteOpened(PairRouteOpened {
                machine_route: ROUTE,
                pair_route,
                absolute_expiry_ms: 10_006,
            })));
        for value in 0..8 {
            fixture
                .harness
                .push_incoming(frame(RelayFrameBody::PairData(PairData {
                    pair_route,
                    sealed_blob: SealedBlob(vec![value]),
                })));
        }
        tokio::time::timeout(std::time::Duration::from_secs(2), async {
            loop {
                if fixture.transport.observed_failure_code().as_deref()
                    == Some("remote.transport.pairing_lagged")
                {
                    break;
                }
                tokio::task::yield_now().await;
            }
        })
        .await
        .expect("lag must be observed without polling the lane");
        assert_eq!(
            lane.next_event().await.unwrap_err().code(),
            "remote.transport.pairing_lagged"
        );
        assert_eq!(fixture.harness.shutdowns.load(Ordering::SeqCst), 1);
        fixture.transport.shutdown().await;
    }

    #[tokio::test]
    async fn pairing_safe_failure_and_restart_wake_active_owner_without_leaking_detail() {
        let mut fixture = connected_fixture(Vec::new(), None).await;
        let mut lane = fixture
            .transport
            .take_pairing_lane(fixture.data_cert.clone())
            .unwrap();
        fixture
            .harness
            .push_incoming(frame(RelayFrameBody::Error(RelayFailure::new(
                "relay.pair.conflict",
                "secret pairing detail",
            ))));
        let error = lane.next_event().await.unwrap_err();
        assert_eq!(error.code(), "relay.pair.conflict");
        assert!(!format!("{error:?}").contains("secret pairing detail"));

        fixture
            .harness
            .push_incoming(frame(RelayFrameBody::ServerRestarting(ServerRestarting {
                drain_deadline_ms: 123,
            })));
        assert_eq!(
            lane.next_event().await.unwrap_err().code(),
            "remote.transport.server_restarting"
        );
        fixture.transport.shutdown().await;
    }

    #[tokio::test]
    async fn active_pairing_owns_shared_control_without_blocking_typed_terminals() {
        let mut fixture = connected_fixture(Vec::new(), None).await;
        let mut lane = fixture
            .transport
            .take_pairing_lane(fixture.data_cert.clone())
            .unwrap();
        let pair_route = PairRouteId::from_bytes([0xb7; 16]);
        let absolute_expiry_ms = 10_013;
        lane.send_open_pair_route(open_pair_route(pair_route, absolute_expiry_ms))
            .await
            .expect("bind typed open before shared control burst");

        for index in 0..=CONTROL_CHANNEL_CAPACITY {
            let (body, expected_code) = if index % 2 == 0 {
                (
                    RelayFrameBody::Error(RelayFailure::new(
                        "relay.pair.conflict",
                        format!("secret pairing detail {index}"),
                    )),
                    "relay.pair.conflict",
                )
            } else {
                (
                    RelayFrameBody::ServerRestarting(ServerRestarting {
                        drain_deadline_ms: index as u64,
                    }),
                    "remote.transport.server_restarting",
                )
            };
            fixture.harness.push_incoming(frame(body));
            let error = tokio::time::timeout(std::time::Duration::from_secs(2), lane.next_event())
                .await
                .expect("active pairing owner must receive every shared failure")
                .expect_err("safe Relay failure is a pairing failure");
            assert_eq!(error.code(), expected_code);
        }

        fixture
            .harness
            .push_incoming(frame(RelayFrameBody::PairRouteOpened(PairRouteOpened {
                machine_route: ROUTE,
                pair_route,
                absolute_expiry_ms,
            })));
        assert!(matches!(
            tokio::time::timeout(std::time::Duration::from_secs(2), lane.next_event())
                .await
                .expect("shared control burst must not block PairRouteOpened")
                .expect("pairing lane remains healthy"),
            Some(PairingTransportEvent::PairRouteOpened(PairRouteOpened {
                pair_route: observed,
                ..
            })) if observed == pair_route
        ));

        let device_route = DeviceRouteId::from_bytes([0xb8; 16]);
        let grant = relay_grant(device_route, 13);
        lane.send_install_grant(InstallGrant {
            grant: grant.clone(),
        })
        .await
        .expect("bind typed grant after shared control burst");
        let grant_commit = GrantCommitted {
            device_route,
            grant_serial: grant.grant_serial,
            grant_hash: grant.canonical_sha256(),
        };
        fixture
            .harness
            .push_incoming(frame(RelayFrameBody::GrantCommitted(grant_commit.clone())));
        assert!(matches!(
            tokio::time::timeout(std::time::Duration::from_secs(2), lane.next_event())
                .await
                .expect("shared control burst must not block GrantCommitted")
                .expect("pairing lane remains healthy"),
            Some(PairingTransportEvent::GrantCommitted(observed)) if observed == grant_commit
        ));

        let retirement = retirement();
        fixture
            .transport
            .send_retirement(retirement.clone())
            .await
            .expect("trust reset keeps the same supervisor");
        let committed = RetirementCommitted {
            machine_route: ROUTE,
            trust_epoch: retirement.trust_epoch,
            retire_hash: retirement.canonical_sha256(),
        };
        fixture
            .harness
            .push_incoming(frame(RelayFrameBody::RetirementCommitted(
                committed.clone(),
            )));
        assert!(matches!(
            tokio::time::timeout(
                std::time::Duration::from_secs(2),
                fixture.transport.next_control(),
            )
            .await
            .expect("retirement terminal must retain bounded backpressure")
            .expect("control lane remains healthy"),
            Some(RemoteControl::RetirementTerminal(terminal))
                if terminal.committed() == &committed
        ));

        fixture.transport.shutdown().await;
    }

    #[tokio::test]
    async fn pairing_yield_moves_queued_shared_control_once_and_preserves_typed_events() {
        let mut fixture = connected_fixture(Vec::new(), None).await;
        let mut lane = fixture
            .transport
            .take_pairing_lane(fixture.data_cert.clone())
            .unwrap();
        let pair_route = PairRouteId::from_bytes([0xba; 16]);
        let absolute_expiry_ms = 10_015;
        lane.send_open_pair_route(open_pair_route(pair_route, absolute_expiry_ms))
            .await
            .expect("bind typed open before ownership yield");
        fixture
            .harness
            .push_incoming(frame(RelayFrameBody::Error(RelayFailure::new(
                "relay.retirement.unavailable",
                "secret retirement detail",
            ))));
        fixture
            .harness
            .push_incoming(frame(RelayFrameBody::PairRouteOpened(PairRouteOpened {
                machine_route: ROUTE,
                pair_route,
                absolute_expiry_ms,
            })));
        tokio::time::timeout(std::time::Duration::from_secs(2), async {
            while lane.event_rx.len() != 2 {
                tokio::task::yield_now().await;
            }
        })
        .await
        .expect("shared and typed events must both enter the bounded pairing lane");

        lane.yield_shared_control()
            .expect("drain completion atomically yields shared control ownership");

        assert!(matches!(
            tokio::time::timeout(
                std::time::Duration::from_millis(250),
                fixture.transport.next_control(),
            )
            .await
            .expect("queued shared control must be handed to retirement immediately")
            .expect("control surface remains healthy"),
            Some(RemoteControl::SafeFailure(failure))
                if failure.code() == "relay.retirement.unavailable"
        ));
        assert!(matches!(
            lane.next_event().await.unwrap(),
            Some(PairingTransportEvent::PairRouteOpened(PairRouteOpened {
                pair_route: observed,
                ..
            })) if observed == pair_route
        ));
        assert!(
            tokio::time::timeout(
                std::time::Duration::from_millis(50),
                fixture.transport.next_control(),
            )
            .await
            .is_err(),
            "yielded shared control must not be duplicated"
        );

        let post_yield_route = PairRouteId::from_bytes([0xbb; 16]);
        let post_yield_expiry_ms = absolute_expiry_ms + 1;
        lane.send_open_pair_route(open_pair_route(post_yield_route, post_yield_expiry_ms))
            .await
            .expect("typed pairing commands remain enabled after shared ownership yield");
        fixture
            .harness
            .push_incoming(frame(RelayFrameBody::PairRouteOpened(PairRouteOpened {
                machine_route: ROUTE,
                pair_route: post_yield_route,
                absolute_expiry_ms: post_yield_expiry_ms,
            })));
        assert!(matches!(
            tokio::time::timeout(std::time::Duration::from_millis(250), lane.next_event())
                .await
                .expect("post-yield typed event remains readable")
                .unwrap(),
            Some(PairingTransportEvent::PairRouteOpened(PairRouteOpened {
                pair_route: observed,
                ..
            })) if observed == post_yield_route
        ));

        fixture
            .harness
            .push_incoming(frame(RelayFrameBody::ServerRestarting(ServerRestarting {
                drain_deadline_ms: 321,
            })));
        assert_eq!(
            tokio::time::timeout(
                std::time::Duration::from_millis(250),
                fixture.transport.next_control(),
            )
            .await
            .expect("post-yield restart must stay on the control surface")
            .unwrap(),
            Some(RemoteControl::ServerRestarting(ServerRestarting {
                drain_deadline_ms: 321,
            }))
        );

        fixture
            .transport
            .reacquire_pairing_shared_control()
            .expect("Active recovery may reacquire after the control backlog is empty");
        fixture
            .harness
            .push_incoming(frame(RelayFrameBody::Error(RelayFailure::new(
                "relay.pair.recovered",
                "secret recovered detail",
            ))));
        assert_eq!(
            tokio::time::timeout(std::time::Duration::from_millis(250), lane.next_event())
                .await
                .expect("reacquired pairing must receive fresh shared control")
                .unwrap_err()
                .code(),
            "relay.pair.recovered"
        );

        fixture.transport.shutdown().await;
    }

    #[tokio::test]
    async fn pairing_yield_handoff_is_bounded_at_the_pairing_fifo_capacity() {
        let mut fixture = connected_fixture(Vec::new(), None).await;
        let mut lane = fixture
            .transport
            .take_pairing_lane(fixture.data_cert.clone())
            .unwrap();
        for index in 0..PAIRING_EVENT_CHANNEL_CAPACITY {
            fixture
                .harness
                .push_incoming(frame(RelayFrameBody::Error(RelayFailure::new(
                    "relay.handoff.capacity",
                    format!("secret handoff detail {index}"),
                ))));
        }
        tokio::time::timeout(std::time::Duration::from_secs(2), async {
            while lane.event_rx.len() != PAIRING_EVENT_CHANNEL_CAPACITY {
                tokio::task::yield_now().await;
            }
        })
        .await
        .expect("pairing FIFO must reach its exact bounded capacity");

        lane.yield_shared_control()
            .expect("the exact capacity boundary must hand off without overflow");
        assert_eq!(
            lane.transition
                .lock()
                .unwrap_or_else(|poisoned| poisoned.into_inner())
                .handed_off_control
                .len(),
            PAIRING_EVENT_CHANNEL_CAPACITY
        );
        for _ in 0..PAIRING_EVENT_CHANNEL_CAPACITY {
            assert!(matches!(
                fixture.transport.next_control().await.unwrap(),
                Some(RemoteControl::SafeFailure(failure))
                    if failure.code() == "relay.handoff.capacity"
            ));
        }
        assert_eq!(fixture.transport.observed_failure_code(), None);
        fixture.transport.shutdown().await;
    }

    #[tokio::test]
    async fn pairing_reacquire_preserves_exclusive_control_and_keeps_control_ownership() {
        let mut fixture = connected_fixture(Vec::new(), None).await;
        let mut lane = fixture
            .transport
            .take_pairing_lane(fixture.data_cert.clone())
            .unwrap();
        lane.yield_shared_control().unwrap();

        let retirement = retirement();
        let committed = RetirementCommitted {
            machine_route: ROUTE,
            trust_epoch: retirement.trust_epoch,
            retire_hash: retirement.canonical_sha256(),
        };
        fixture
            .harness
            .push_incoming(frame(RelayFrameBody::RetirementCommitted(
                committed.clone(),
            )));
        tokio::time::timeout(std::time::Duration::from_secs(2), async {
            loop {
                if fixture
                    .transport
                    .supervisor
                    .as_ref()
                    .expect("connected supervisor")
                    .control_rx
                    .len()
                    == 1
                {
                    break;
                }
                tokio::task::yield_now().await;
            }
        })
        .await
        .expect("exclusive terminal must become readable on the control surface");

        assert_eq!(
            fixture
                .transport
                .reacquire_pairing_shared_control()
                .expect_err("exclusive control must fail-close pairing reacquire")
                .code(),
            "remote.transport.pairing_activation_blocked"
        );
        assert!(matches!(
            fixture.transport.next_control().await.unwrap(),
            Some(RemoteControl::RetirementTerminal(terminal))
                if terminal.committed() == &committed
        ));

        fixture
            .harness
            .push_incoming(frame(RelayFrameBody::Error(RelayFailure::new(
                "relay.control.still_owned",
                "secret control detail",
            ))));
        assert!(matches!(
            tokio::time::timeout(
                std::time::Duration::from_millis(250),
                fixture.transport.next_control(),
            )
            .await
            .expect("failed reacquire must leave control readable")
            .unwrap(),
            Some(RemoteControl::SafeFailure(failure))
                if failure.code() == "relay.control.still_owned"
        ));
        assert!(
            tokio::time::timeout(std::time::Duration::from_millis(50), lane.next_event())
                .await
                .is_err(),
            "failed reacquire must not leak shared control back to pairing"
        );

        fixture.transport.shutdown().await;
    }

    #[tokio::test]
    async fn pairing_reacquire_blocks_pending_exclusive_before_it_enters_control_fifo() {
        let mut fixture = connected_fixture(Vec::new(), None).await;
        let mut lane = fixture
            .transport
            .take_pairing_lane(fixture.data_cert.clone())
            .unwrap();
        lane.yield_shared_control().unwrap();
        for index in 0..CONTROL_CHANNEL_CAPACITY {
            fixture
                .harness
                .push_incoming(frame(RelayFrameBody::Error(RelayFailure::new(
                    "relay.control.backlog",
                    format!("secret control backlog {index}"),
                ))));
        }
        let retirement = retirement();
        let committed = RetirementCommitted {
            machine_route: ROUTE,
            trust_epoch: retirement.trust_epoch,
            retire_hash: retirement.canonical_sha256(),
        };
        fixture
            .harness
            .push_incoming(frame(RelayFrameBody::RetirementCommitted(
                committed.clone(),
            )));
        tokio::time::timeout(std::time::Duration::from_secs(2), async {
            loop {
                let supervisor = fixture
                    .transport
                    .supervisor
                    .as_ref()
                    .expect("connected supervisor");
                let pending_exclusive = supervisor
                    .pairing_transition
                    .lock()
                    .unwrap_or_else(|poisoned| poisoned.into_inner())
                    .pending_exclusive_control;
                if supervisor.control_rx.len() == CONTROL_CHANNEL_CAPACITY && pending_exclusive {
                    break;
                }
                tokio::task::yield_now().await;
            }
        })
        .await
        .expect("exclusive terminal must wait behind the full bounded control FIFO");

        assert_eq!(
            fixture
                .transport
                .reacquire_pairing_shared_control()
                .expect_err("pending exclusive control must block reacquire")
                .code(),
            "remote.transport.pairing_activation_blocked"
        );
        for _ in 0..CONTROL_CHANNEL_CAPACITY {
            assert!(matches!(
                fixture.transport.next_control().await.unwrap(),
                Some(RemoteControl::SafeFailure(failure))
                    if failure.code() == "relay.control.backlog"
            ));
        }
        assert!(matches!(
            tokio::time::timeout(
                std::time::Duration::from_millis(250),
                fixture.transport.next_control(),
            )
            .await
            .expect("pending exclusive terminal must become readable after capacity frees")
            .unwrap(),
            Some(RemoteControl::RetirementTerminal(terminal))
                if terminal.committed() == &committed
        ));

        fixture.transport.shutdown().await;
    }

    #[tokio::test]
    async fn pairing_activation_clears_stale_shared_backlog_before_fresh_open() {
        let mut fixture = connected_fixture(Vec::new(), None).await;
        for index in 0..=CONTROL_CHANNEL_CAPACITY {
            fixture
                .harness
                .push_incoming(frame(RelayFrameBody::Error(RelayFailure::new(
                    "relay.pair.pre_activation",
                    format!("secret pre-activation detail {index}"),
                ))));
        }

        tokio::time::timeout(std::time::Duration::from_secs(2), async {
            loop {
                let queued = fixture
                    .transport
                    .supervisor
                    .as_ref()
                    .expect("connected supervisor")
                    .control_rx
                    .len();
                let unread = fixture
                    .harness
                    .incoming
                    .lock()
                    .expect("lock incoming frames")
                    .len();
                if queued == CONTROL_CHANNEL_CAPACITY && unread == 0 {
                    break;
                }
                tokio::task::yield_now().await;
            }
        })
        .await
        .expect("inactive control FIFO must fill before pairing activation");

        let mut lane = fixture
            .transport
            .take_pairing_lane(fixture.data_cert.clone())
            .expect("activate pairing over the full stale control FIFO");
        let pair_route = PairRouteId::from_bytes([0xb9; 16]);
        let absolute_expiry_ms = 10_014;
        lane.send_open_pair_route(open_pair_route(pair_route, absolute_expiry_ms))
            .await
            .expect("fresh OpenPairRoute must reach the shared supervisor");
        fixture
            .harness
            .push_incoming(frame(RelayFrameBody::PairRouteOpened(PairRouteOpened {
                machine_route: ROUTE,
                pair_route,
                absolute_expiry_ms,
            })));

        let error = tokio::time::timeout(std::time::Duration::from_secs(2), lane.next_event())
            .await
            .expect("pending pre-activation shared control transfers to pairing")
            .expect_err("stale safe Relay failure remains typed");
        assert_eq!(error.code(), "relay.pair.pre_activation");
        assert!(matches!(
            tokio::time::timeout(std::time::Duration::from_secs(2), lane.next_event())
                .await
                .expect("stale control FIFO must not block fresh PairRouteOpened")
                .expect("pairing lane remains healthy"),
            Some(PairingTransportEvent::PairRouteOpened(PairRouteOpened {
                pair_route: observed,
                ..
            })) if observed == pair_route
        ));

        fixture.transport.shutdown().await;
    }

    #[tokio::test]
    async fn pre_activation_retirement_terminal_blocks_without_consuming_pairing_lane() {
        let mut fixture = connected_fixture(Vec::new(), None).await;
        let retirement = retirement();
        let committed = RetirementCommitted {
            machine_route: ROUTE,
            trust_epoch: retirement.trust_epoch,
            retire_hash: retirement.canonical_sha256(),
        };
        fixture
            .harness
            .push_incoming(frame(RelayFrameBody::RetirementCommitted(
                committed.clone(),
            )));
        tokio::time::timeout(std::time::Duration::from_secs(2), async {
            loop {
                if fixture
                    .transport
                    .supervisor
                    .as_ref()
                    .expect("connected supervisor")
                    .control_rx
                    .len()
                    == 1
                {
                    break;
                }
                tokio::task::yield_now().await;
            }
        })
        .await
        .expect("unexpected retirement terminal must enter bounded control FIFO");

        assert_eq!(
            fixture
                .transport
                .take_pairing_lane(fixture.data_cert.clone())
                .expect_err("exclusive pre-activation control must fail closed")
                .code(),
            "remote.transport.pairing_activation_blocked"
        );
        assert!(fixture.transport.pairing_lane.is_some());
        assert!(matches!(
            fixture.transport.next_control().await.unwrap(),
            Some(RemoteControl::RetirementTerminal(terminal))
                if terminal.committed() == &committed
        ));

        fixture.transport.shutdown().await;
    }

    #[tokio::test]
    async fn pairing_reader_error_wakes_waiter_and_reconnect_keeps_the_same_lane() {
        let mut fixture = connected_fixture(Vec::new(), None).await;
        let mut lane = fixture
            .transport
            .take_pairing_lane(fixture.data_cert.clone())
            .unwrap();
        fixture.harness.push_error("relay.client.connection_lost");
        assert_eq!(
            lane.next_event().await.unwrap_err().code(),
            "relay.client.connection_lost"
        );
        fixture
            .transport
            .reconnect()
            .await
            .expect("reconnect generation");
        let pair_route = PairRouteId::from_bytes([0xa8; 16]);
        open_bound_route(&mut lane, &fixture.harness, pair_route, 10_007).await;
        assert_eq!(fixture.harness.reconnects.load(Ordering::SeqCst), 1);
        fixture.transport.shutdown().await;
    }

    #[tokio::test]
    async fn pairing_reconnect_discards_queued_events_from_the_old_generation() {
        let mut fixture = connected_fixture(Vec::new(), None).await;
        let mut lane = fixture
            .transport
            .take_pairing_lane(fixture.data_cert.clone())
            .unwrap();
        let pair_route = PairRouteId::from_bytes([0xc4; 16]);
        lane.send_open_pair_route(open_pair_route(pair_route, 10_012))
            .await
            .unwrap();
        fixture
            .harness
            .push_incoming(frame(RelayFrameBody::PairRouteOpened(PairRouteOpened {
                machine_route: ROUTE,
                pair_route,
                absolute_expiry_ms: 10_012,
            })));
        tokio::time::timeout(std::time::Duration::from_secs(2), async {
            while lane.event_rx.len() != 1 {
                tokio::task::yield_now().await;
            }
        })
        .await
        .expect("old generation event entered the bounded lane");

        fixture.harness.push_error("relay.client.connection_lost");
        tokio::time::timeout(std::time::Duration::from_secs(2), async {
            while lane.health_rx.borrow().is_none() {
                tokio::task::yield_now().await;
            }
        })
        .await
        .expect("old generation failure became observable");
        lane.reconnect()
            .await
            .expect("reconnect pairing generation");
        lane.send_open_pair_route(open_pair_route(pair_route, 10_012))
            .await
            .expect("durable outbox reopens exact route");

        assert!(
            tokio::time::timeout(std::time::Duration::from_millis(50), lane.next_event(),)
                .await
                .is_err(),
            "queued PairRouteOpened from the old generation cannot satisfy reopen"
        );

        fixture
            .harness
            .push_incoming(frame(RelayFrameBody::PairRouteOpened(PairRouteOpened {
                machine_route: ROUTE,
                pair_route,
                absolute_expiry_ms: 10_012,
            })));
        assert!(matches!(
            lane.next_event().await.unwrap(),
            Some(PairingTransportEvent::PairRouteOpened(PairRouteOpened {
                pair_route: observed,
                ..
            })) if observed == pair_route
        ));
        fixture.transport.shutdown().await;
    }

    #[tokio::test]
    async fn shutdown_wakes_taken_pairing_lane_and_retirement_surface_does_not_regress() {
        let mut fixture = connected_fixture(Vec::new(), None).await;
        let mut lane = fixture
            .transport
            .take_pairing_lane(fixture.data_cert.clone())
            .unwrap();
        let committed = RetirementCommitted {
            machine_route: ROUTE,
            trust_epoch: TrustEpoch::new(4),
            retire_hash: retirement().canonical_sha256(),
        };
        fixture
            .transport
            .send_retirement(retirement())
            .await
            .expect("retirement still uses the same supervisor");
        fixture
            .harness
            .push_incoming(frame(RelayFrameBody::RetirementCommitted(
                committed.clone(),
            )));
        assert!(matches!(
            fixture.transport.next_control().await.unwrap(),
            Some(RemoteControl::RetirementTerminal(terminal)) if terminal.committed() == &committed
        ));

        let waiter = tokio::spawn(async move { lane.next_event().await });
        tokio::task::yield_now().await;
        fixture.transport.shutdown().await;
        assert_eq!(
            waiter
                .await
                .expect("join pairing waiter")
                .unwrap_err()
                .code(),
            "remote.transport.closed"
        );
        assert_eq!(fixture.harness.shutdowns.load(Ordering::SeqCst), 1);
    }
}
