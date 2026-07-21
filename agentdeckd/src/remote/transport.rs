//! MachineLink 的 typed Relay transport。
//!
//! 本模块不持有业务执行 core，也不公开 raw frame send/recv。主 control lane 只承载
//! root-signed retirement；一次性取出的 bounded pairing lane 只承载显式配对/授权 frame。
//! 两条 typed lane 复用唯一 Relay session/supervisor，均不向执行 core 派发业务 frame。

use std::collections::VecDeque;
use std::fmt;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, Mutex, Weak};

use agentdeck_crypto::rand_core::SeedableRng;
use agentdeck_crypto::{
    HpkePublicKey, SecretAeadKey, seal_key_directory_entry as crypto_seal_key_directory_entry,
    sha256,
};
use agentdeck_protocol::e2ee::{
    DeviceAuthorizationV1, KeyDirectoryEntry, KeyDirectorySignatureContextV1, KeyDirectoryV1,
    KeyUpdateInfoV1, MachineDataSignerBindingV1, OuterContextV1, PairRequestInfoV1,
    PairResponseInfoV1, PairResponsePlaintextV1, PairResponseV1, PairingControlEnvelopeV1,
};
use agentdeck_protocol::relay_v2::frame::{
    AcceptedRef, AuthProof, Authenticate, Challenge, ClosePairRoute, GrantCommitted, InstallGrant,
    OpenPairRoute, PairData, PairRouteClosed, PairRouteOpened, RetireMachine, RetirementCommitted,
    RevocationCommitted, RevokeDevice, RouteAccepted, ServerRestarting,
};
use agentdeck_protocol::relay_v2::{
    AuthenticationRole, AuthenticationTranscriptV1, DeviceRevocation, DeviceRouteId, GrantSerial,
    MAX_FRAME_BYTES, MachineRouteId, OpaqueRouteFrame, PairRouteId, RELAY_PROTOCOL_VERSION,
    RelayFrameBody, SignedCertificate, encode,
};
use agentdeck_relay_client::{LinkAuthenticator, RelayClient, RelayClientConfig, RelayClientError};
use async_trait::async_trait;
use rand_chacha::ChaCha20Rng;
use thiserror::Error;
use tokio::sync::{mpsc, oneshot, watch};
use tokio::task::JoinHandle;
use zeroize::Zeroizing;

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
        self.client.shutdown().await;
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

/// 只经 Weak 委托同一 transport generation key owner 的 pairing authority。
/// 它没有 raw sign/key getter，shutdown/reclaim 销毁 owner 后所有入口固定 fail-close。
pub(crate) struct PairingMachineAuthority {
    owner: Weak<MachineLinkAuthenticator>,
    anchor: MachinePairingAnchor,
    data_signer: MachineDataSignerBindingV1,
}

impl PairingMachineAuthority {
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
        owner
            .owner
            .seal_pair_pending(
                recipient,
                info,
                context,
                request_hash,
                &self.data_signer,
                &mut rng,
            )
            .map_err(map_pairing_authority_error)
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
                &self.data_signer,
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
        let owner = self.verified_owner()?;
        owner
            .owner
            .sign_key_directory(&self.anchor, context, directory)
            .map_err(map_pairing_authority_error)
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
        self.validate_key_update_axes(info)?;
        let _owner = self.verified_owner()?;
        let mut rng = pairing_crypto_rng(source)?;
        crypto_seal_key_directory_entry(recipient, info, context, key, &mut rng)
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
        self.validate_key_update_axes(info)?;
        let _owner = self.verified_owner()?;
        crypto_seal_key_directory_entry(recipient, info, context, key, rng)
            .map_err(|_| supervisor_failure("remote.transport.pairing_crypto_failed"))
    }

    fn validate_key_update_axes(&self, info: &KeyUpdateInfoV1) -> Result<(), RemoteTransportError> {
        if info.relay_server_id != self.anchor.relay_server_id
            || info.machine_route != self.anchor.machine_route
            || info.root_trust_epoch != self.anchor.trust_epoch
        {
            return Err(pairing_authority_mismatch());
        }
        Ok(())
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
        owner
            .owner
            .seal_pair_response(&self.anchor, recipient, info, context, plaintext, &mut rng)
            .map_err(map_pairing_authority_error)
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

/// 先以 fallible OS source 取得 256-bit seed，再交给 rand_core 0.10 的成熟
/// ChaCha20 CSPRNG。production 不使用 hpke 内部会 panic 的 `UnwrapErr(SysRng)`。
fn pairing_crypto_rng<F>(mut source: F) -> Result<ChaCha20Rng, RemoteTransportError>
where
    F: FnMut(&mut [u8]) -> Result<(), ()>,
{
    let mut seed = Zeroizing::new([0_u8; 32]);
    source(seed.as_mut()).map_err(|()| RemoteTransportError::PairingEntropyUnavailable)?;
    Ok(ChaCha20Rng::from_seed(*seed))
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
    #[error("exclusive control is pending before pairing activation")]
    PairingActivationBlocked,
    #[error("pairing frame does not match the frozen machine/pair/device/serial binding")]
    PairingBindingMismatch,
    #[error("pairing transport binding capacity is exhausted")]
    PairingCapacity,
    #[error("pairing event consumer is lagged or unavailable")]
    PairingLagged,
    #[error("pairing transport generation is exhausted")]
    PairingGenerationExhausted,
    #[error("pairing transport could not obtain cryptographic entropy")]
    PairingEntropyUnavailable,
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
            Self::PairingActivationBlocked => "remote.transport.pairing_activation_blocked",
            Self::PairingBindingMismatch => "remote.transport.pairing_binding_mismatch",
            Self::PairingCapacity => "remote.transport.pairing_capacity",
            Self::PairingLagged => "remote.transport.pairing_lagged",
            Self::PairingGenerationExhausted => "remote.transport.pairing_generation_exhausted",
            Self::PairingEntropyUnavailable => "remote.transport.pairing_entropy_unavailable",
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
const INITIAL_PAIRING_GENERATION: u64 = 1;

#[derive(Clone)]
enum PairingCommand {
    Open(OpenPairRoute),
    Data(PairData),
    InstallGrant(InstallGrant),
    Close(ClosePairRoute),
    RevokeDevice(RevokeDevice),
}

impl PairingCommand {
    fn frame(&self) -> OpaqueRouteFrame {
        let body = match self {
            Self::Open(frame) => RelayFrameBody::OpenPairRoute(frame.clone()),
            Self::Data(frame) => RelayFrameBody::PairData(frame.clone()),
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

#[derive(Clone, Default)]
struct PairingBindings {
    routes: Vec<PairRouteBinding>,
    grants: Vec<GrantBinding>,
    revocations: Vec<RevocationBinding>,
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
        &self,
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
        if !bound.opened || bound.closing {
            return Err(RemoteTransportError::PairingBindingMismatch);
        }
        Ok(PairingTransportEvent::PairFrameAccepted(accepted))
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
    authenticator: Option<Arc<MachineLinkAuthenticator>>,
    start_permit: Option<RemoteStartPermit>,
}

const CONTROL_CHANNEL_CAPACITY: usize = 8;
const COMMAND_CHANNEL_CAPACITY: usize = 8;

enum SupervisorCommand {
    SendRetirement {
        retirement: RetireMachine,
        response: oneshot::Sender<Result<(), RemoteTransportError>>,
    },
    Pairing {
        command: PairingCommand,
        response: oneshot::Sender<Result<(), RemoteTransportError>>,
    },
    Reconnect {
        response: oneshot::Sender<Result<(), RemoteTransportError>>,
    },
}

struct ControlSupervisor {
    command_tx: mpsc::Sender<SupervisorCommand>,
    control_rx: mpsc::Receiver<Result<Option<RemoteControl>, RemoteTransportError>>,
    retained_control: VecDeque<Result<Option<RemoteControl>, RemoteTransportError>>,
    pairing_transition: Arc<Mutex<PairingTransition>>,
    cancel_tx: watch::Sender<bool>,
    task: Option<JoinHandle<()>>,
    health_rx: watch::Receiver<Option<String>>,
}

struct SupervisorSignals {
    control_tx: mpsc::Sender<Result<Option<RemoteControl>, RemoteTransportError>>,
    pairing_tx: mpsc::Sender<PairingTransportSignal>,
    pairing_transition: Arc<Mutex<PairingTransition>>,
    pairing_generation: Arc<AtomicU64>,
    health: watch::Sender<Option<String>>,
}

impl ControlSupervisor {
    fn start(
        machine_route: MachineRouteId,
        session: Box<dyn ControlSession>,
    ) -> (Self, PairingTransportLane) {
        let (command_tx, command_rx) = mpsc::channel(COMMAND_CHANNEL_CAPACITY);
        let (control_tx, control_rx) = mpsc::channel(CONTROL_CHANNEL_CAPACITY);
        let (pairing_tx, pairing_rx) = mpsc::channel(PAIRING_EVENT_CHANNEL_CAPACITY);
        let pairing_transition = Arc::new(Mutex::new(PairingTransition::default()));
        let pairing_generation = Arc::new(AtomicU64::new(INITIAL_PAIRING_GENERATION));
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
            generation: pairing_generation,
            authority_anchor: None,
        };
        (
            Self {
                command_tx,
                control_rx,
                retained_control: VecDeque::with_capacity(CONTROL_CHANNEL_CAPACITY),
                pairing_transition,
                cancel_tx,
                task: Some(task),
                health_rx,
            },
            pairing_lane,
        )
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
        health,
    } = signals;
    let mut reader_enabled = true;
    let mut session_shutdown = false;
    let mut pending_control = None;
    let mut pairing_bindings = PairingBindings::default();

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
                        PairingSupervisorState {
                            generation: &pairing_generation,
                            bindings: &mut pairing_bindings,
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
                        PairingSupervisorState {
                            generation: &pairing_generation,
                            bindings: &mut pairing_bindings,
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
                    PairingSupervisorState {
                        generation: &pairing_generation,
                        bindings: &mut pairing_bindings,
                    },
                ).await;
            }
            received = session.next() => {
                match received {
                    Ok(Some(frame)) => match decode_inbound(machine_route, &mut pairing_bindings, frame) {
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
                        set_supervisor_failure(&health, RemoteTransportError::Closed.code());
                        reader_enabled = false;
                        replace_pending_control(
                            &mut pending_control,
                            &pairing_transition,
                            Ok(None),
                        );
                    }
                    Err(error) => {
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
}

struct PairingSupervisorState<'a> {
    generation: &'a AtomicU64,
    bindings: &'a mut PairingBindings,
}

async fn handle_supervisor_command(
    command: SupervisorCommand,
    session: &mut dyn ControlSession,
    reader_enabled: &mut bool,
    session_shutdown: bool,
    health: &watch::Sender<Option<String>>,
    machine_route: MachineRouteId,
    pairing: PairingSupervisorState<'_>,
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
            let next_bindings = match pairing.bindings.prepare_outbound(machine_route, &command) {
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
                Ok(()) => *pairing.bindings = next_bindings,
                Err(error) => {
                    set_supervisor_failure(health, error.code());
                    *reader_enabled = false;
                }
            }
            let _ = response.send(result);
        }
        SupervisorCommand::Reconnect { response } => {
            if session_shutdown {
                let _ = response.send(Err(RemoteTransportError::Closed));
                return;
            }
            let next_generation = pairing
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
                    *pairing.bindings = PairingBindings::default();
                    pairing
                        .generation
                        .store(*next_generation, Ordering::Release);
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
    Shared {
        control: RemoteControl,
        pairing_failure: SafeFailure,
    },
}

fn decode_inbound(
    machine_route: MachineRouteId,
    pairing_bindings: &mut PairingBindings,
    frame: OpaqueRouteFrame,
) -> Result<InboundDispatch, RemoteTransportError> {
    if frame.version != RELAY_PROTOCOL_VERSION {
        return Err(RemoteTransportError::FrameForbidden);
    }
    if encode(&frame).len() > MAX_FRAME_BYTES {
        return Err(RemoteTransportError::Client(RelayClientError::Failure {
            code: "relay.client.frame_too_large".to_owned(),
        }));
    }
    let retirement_bytes =
        matches!(&frame.body, RelayFrameBody::RetirementCommitted(_)).then(|| encode(&frame));
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
        RelayFrameBody::RouteAccepted(accepted) => pairing_bindings
            .accept_pair_frame(accepted)
            .map(InboundDispatch::Pairing),
        RelayFrameBody::PairRouteClosed(closed) => pairing_bindings
            .accept_closed(closed)
            .map(InboundDispatch::Pairing),
        RelayFrameBody::GrantCommitted(committed) => pairing_bindings
            .accept_grant(committed)
            .map(InboundDispatch::Pairing),
        RelayFrameBody::RevocationCommitted(committed) => pairing_bindings
            .accept_revocation(committed)
            .map(InboundDispatch::Pairing),
        _ => Err(RemoteTransportError::FrameForbidden),
    }
}

impl RemoteTransport {
    fn from_connected(
        machine_route: MachineRouteId,
        session: Box<dyn ControlSession>,
        authenticator: Arc<MachineLinkAuthenticator>,
        start_permit: Option<RemoteStartPermit>,
    ) -> Self {
        let (supervisor, pairing_lane) = ControlSupervisor::start(machine_route, session);
        Self {
            machine_route,
            supervisor: Some(supervisor),
            pairing_lane: Some(pairing_lane),
            authenticator: Some(authenticator),
            start_permit,
        }
    }

    pub async fn connect(
        identity: ArmedRemoteIdentity,
        config: RelayClientConfig,
        machine_route: MachineRouteId,
        link_cert: SignedCertificate,
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
            &RelayControlConnector,
        )
        .await
    }

    async fn connect_with_connector(
        config: RelayClientConfig,
        machine_route: MachineRouteId,
        authenticator: Arc<MachineLinkAuthenticator>,
        start_permit: Option<RemoteStartPermit>,
        connector: &dyn ControlConnector,
    ) -> Result<Self, RemoteTransportConnectError> {
        RemoteTransportRetryState {
            config,
            machine_route,
            authenticator,
            start_permit,
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
        Ok(PairingRuntimeParts {
            lane,
            authority: PairingMachineAuthority {
                owner,
                anchor,
                data_signer,
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
}

#[cfg(test)]
impl RemoteTransportTestHarness {
    pub(super) async fn push_frame(&self, frame: OpaqueRouteFrame) {
        self.incoming_tx
            .send(Ok(Some(frame)))
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
}

#[cfg(test)]
struct ChannelControlSession {
    incoming_rx: mpsc::Receiver<Result<Option<OpaqueRouteFrame>, RelayClientError>>,
    sent: Arc<Mutex<Vec<OpaqueRouteFrame>>>,
    reconnects: Arc<std::sync::atomic::AtomicUsize>,
}

#[cfg(test)]
#[async_trait]
impl ControlSession for ChannelControlSession {
    async fn send(&mut self, frame: OpaqueRouteFrame) -> Result<(), RelayClientError> {
        self.sent
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner())
            .push(frame);
        Ok(())
    }

    async fn next(&mut self) -> Result<Option<OpaqueRouteFrame>, RelayClientError> {
        self.incoming_rx.recv().await.unwrap_or(Ok(None))
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
    let harness = Arc::new(RemoteTransportTestHarness {
        incoming_tx,
        sent: Arc::clone(&sent),
        reconnects: Arc::clone(&reconnects),
    });
    let (mut supervisor, lane) = ControlSupervisor::start(
        machine_route,
        Box::new(ChannelControlSession {
            incoming_rx,
            sent,
            reconnects,
        }),
    );
    supervisor
        .activate_pairing(&lane)
        .expect("fresh test transport activates pairing");
    (
        RemoteTransport {
            machine_route,
            supervisor: Some(supervisor),
            pairing_lane: None,
            authenticator: None,
            start_permit: None,
        },
        lane,
        harness,
    )
}

#[cfg(test)]
mod tests {
    use std::collections::VecDeque;
    use std::convert::Infallible;
    use std::sync::Mutex;
    use std::sync::atomic::{AtomicUsize, Ordering};

    use agentdeck_crypto::rand_core::{TryCryptoRng, TryRng};
    use agentdeck_crypto::{
        HpkePrivateKey, SecretAeadKey, SignatureBytes, SigningKey, open_key_directory_entry,
        open_pair_pending, open_pair_response, sign_authentication_transcript, sign_tbs,
        verify_authentication_transcript, verify_device_authorization, verify_key_directory,
        verify_tbs,
    };
    use agentdeck_protocol::e2ee::{
        AuthorizationCapabilityV1, AuthorizationPermissionV1, DeviceAuthorizationV1,
        E2EE_FORMAT_VERSION, KeyDirectoryEntry, KeyDirectoryV1, KeyId, KeyPurpose, OuterContextV1,
        OuterFrameKind, PairRequestInfoV1, PairResponseInfoV1, PairResponsePlaintextV1,
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
        let transport =
            RemoteTransport::connect_with_connector(config, ROUTE, authenticator, None, &connector)
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
        let error =
            RemoteTransport::connect_with_connector(config, ROUTE, authenticator, None, &connector)
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
    async fn every_business_family_is_forbidden_closed_and_never_dispatched() {
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
        let forbidden = vec![
            frame(RelayFrameBody::RouteAccepted(RouteAccepted {
                accepted: AcceptedRef::Request { request_route },
            })),
            frame(RelayFrameBody::Send(Send {
                device_route,
                request_route,
                sealed_blob: SealedBlob(vec![1]),
            })),
            frame(RelayFrameBody::Reply(Reply {
                device_route,
                request_route,
                sealed_blob: SealedBlob(vec![2]),
            })),
            frame(RelayFrameBody::Publish(Publish {
                stream_route,
                generation,
                stream_seq: 0,
                sealed_blob: SealedBlob(vec![3]),
            })),
            frame(RelayFrameBody::PairData(PairData {
                pair_route,
                sealed_blob: SealedBlob(vec![4]),
            })),
            frame(RelayFrameBody::GrantCommitted(GrantCommitted {
                device_route,
                grant_serial: GrantSerial::new(2),
                grant_hash: [0x87; 32],
            })),
            frame(RelayFrameBody::RevocationCommitted(RevocationCommitted {
                device_route,
                grant_serial: GrantSerial::new(2),
                signed_revocation: revocation,
            })),
            frame(RelayFrameBody::Ping(Ping { nonce: 7 })),
            frame(RelayFrameBody::Error(RelayFailure::new(
                "UNSAFE CODE",
                "secret",
            ))),
            frame(RelayFrameBody::RetirementCommitted(RetirementCommitted {
                machine_route: MachineRouteId::from_bytes([0x99; 16]),
                trust_epoch: TrustEpoch::new(4),
                retire_hash: [0x88; 32],
            })),
            OpaqueRouteFrame {
                version: RELAY_PROTOCOL_VERSION + 1,
                body: RelayFrameBody::ServerRestarting(ServerRestarting {
                    drain_deadline_ms: 1,
                }),
            },
        ];

        for frame in forbidden {
            let mut fixture = connected_fixture(vec![frame], None).await;
            let error = fixture
                .transport
                .next_control()
                .await
                .expect_err("business or malformed frame must fail closed");
            assert_eq!(error.code(), "remote.transport.frame_forbidden");
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
