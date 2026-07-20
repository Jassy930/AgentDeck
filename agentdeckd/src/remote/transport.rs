//! MachineLink 的 control-only Relay transport。
//!
//! 本模块不持有业务执行 core，也不公开 raw frame send/recv。唯一上行是 root-signed
//! `RetireMachine`；下行只交付 retirement terminal、安全 failure code 与 restart notice。

use std::fmt;
use std::sync::{Arc, Mutex};

use agentdeck_crypto::sha256;
use agentdeck_protocol::relay_v2::frame::{
    AuthProof, Authenticate, Challenge, RetireMachine, RetirementCommitted, ServerRestarting,
};
use agentdeck_protocol::relay_v2::{
    AuthenticationRole, AuthenticationTranscriptV1, MachineRouteId, OpaqueRouteFrame,
    RELAY_PROTOCOL_VERSION, RelayFrameBody, SignedCertificate, encode,
};
use agentdeck_relay_client::{LinkAuthenticator, RelayClient, RelayClientConfig, RelayClientError};
use async_trait::async_trait;
use thiserror::Error;
use tokio::sync::{mpsc, oneshot, watch};
use tokio::task::JoinHandle;

use crate::local::listener::RemoteStartPermit;

use super::bootstrap::{ArmedRemoteIdentity, MachineLinkIdentityOwner};
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
            Self::Retirement(error) => error.code(),
        }
    }
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

/// 持有 RemoteStartPermit/active link key owner 的唯一 control-only transport。
pub struct RemoteTransport {
    machine_route: MachineRouteId,
    supervisor: Option<ControlSupervisor>,
    authenticator: Option<Arc<MachineLinkAuthenticator>>,
    start_permit: Option<RemoteStartPermit>,
}

const CONTROL_CHANNEL_CAPACITY: usize = 8;
const COMMAND_CHANNEL_CAPACITY: usize = 8;

enum SupervisorCommand {
    Send {
        frame: Box<OpaqueRouteFrame>,
        response: oneshot::Sender<Result<(), RemoteTransportError>>,
    },
    Reconnect {
        response: oneshot::Sender<Result<(), RemoteTransportError>>,
    },
}

#[derive(Clone)]
enum SupervisorHealth {
    Connected,
    Failed(String),
}

struct ControlSupervisor {
    command_tx: mpsc::Sender<SupervisorCommand>,
    control_rx: mpsc::Receiver<Result<Option<RemoteControl>, RemoteTransportError>>,
    cancel_tx: watch::Sender<bool>,
    task: Option<JoinHandle<()>>,
    health: Arc<Mutex<SupervisorHealth>>,
}

impl ControlSupervisor {
    fn start(machine_route: MachineRouteId, session: Box<dyn ControlSession>) -> Self {
        let (command_tx, command_rx) = mpsc::channel(COMMAND_CHANNEL_CAPACITY);
        let (control_tx, control_rx) = mpsc::channel(CONTROL_CHANNEL_CAPACITY);
        let (cancel_tx, cancel_rx) = watch::channel(false);
        let health = Arc::new(Mutex::new(SupervisorHealth::Connected));
        let task = tokio::spawn(run_control_supervisor(
            machine_route,
            session,
            command_rx,
            control_tx,
            cancel_rx,
            Arc::clone(&health),
        ));
        Self {
            command_tx,
            control_rx,
            cancel_tx,
            task: Some(task),
            health,
        }
    }

    fn failure_code(&self) -> Option<String> {
        match &*self.health.lock().expect("lock remote supervisor health") {
            SupervisorHealth::Connected => None,
            SupervisorHealth::Failed(code) => Some(code.clone()),
        }
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
    control_tx: mpsc::Sender<Result<Option<RemoteControl>, RemoteTransportError>>,
    mut cancel_rx: watch::Receiver<bool>,
    health: Arc<Mutex<SupervisorHealth>>,
) {
    let mut reader_enabled = true;
    let mut session_shutdown = false;
    let mut pending_control = None;

    loop {
        if *cancel_rx.borrow() {
            break;
        }
        if let Some(control) = pending_control.take() {
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
                    ).await;
                    pending_control = Some(control);
                }
                permit = control_tx.reserve() => {
                    let Ok(permit) = permit else { break; };
                    permit.send(control);
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
                ).await;
            }
            received = session.next() => {
                match received {
                    Ok(Some(frame)) => match decode_control(machine_route, frame) {
                        Ok(control) => pending_control = Some(Ok(Some(control))),
                        Err(error) => {
                            set_supervisor_failure(&health, error.code());
                            reader_enabled = false;
                            session.shutdown().await;
                            session_shutdown = true;
                            pending_control = Some(Err(error));
                        }
                    },
                    Ok(None) => {
                        set_supervisor_failure(&health, RemoteTransportError::Closed.code());
                        reader_enabled = false;
                        pending_control = Some(Ok(None));
                    }
                    Err(error) => {
                        set_supervisor_failure(&health, error.code());
                        reader_enabled = false;
                        pending_control = Some(Err(RemoteTransportError::Client(error)));
                    }
                }
            }
        }
    }

    if !session_shutdown {
        session.shutdown().await;
    }
}

async fn handle_supervisor_command(
    command: SupervisorCommand,
    session: &mut dyn ControlSession,
    reader_enabled: &mut bool,
    session_shutdown: bool,
    health: &Arc<Mutex<SupervisorHealth>>,
) {
    match command {
        SupervisorCommand::Send { frame, response } => {
            if session_shutdown || !*reader_enabled {
                let _ = response.send(Err(RemoteTransportError::Closed));
                return;
            }
            let result = session
                .send(*frame)
                .await
                .map_err(RemoteTransportError::Client);
            if let Err(error) = &result {
                set_supervisor_failure(health, error.code());
                *reader_enabled = false;
            }
            let _ = response.send(result);
        }
        SupervisorCommand::Reconnect { response } => {
            if session_shutdown {
                let _ = response.send(Err(RemoteTransportError::Closed));
                return;
            }
            let result = session
                .reconnect()
                .await
                .map_err(RemoteTransportError::Client);
            match &result {
                Ok(()) => {
                    *reader_enabled = true;
                    *health.lock().expect("lock remote supervisor health") =
                        SupervisorHealth::Connected;
                }
                Err(error) => {
                    *reader_enabled = false;
                    set_supervisor_failure(health, error.code());
                }
            }
            let _ = response.send(result);
        }
    }
}

fn set_supervisor_failure(health: &Arc<Mutex<SupervisorHealth>>, code: &str) {
    *health.lock().expect("lock remote supervisor health") =
        SupervisorHealth::Failed(code.to_owned());
}

fn decode_control(
    machine_route: MachineRouteId,
    frame: OpaqueRouteFrame,
) -> Result<RemoteControl, RemoteTransportError> {
    if frame.version != RELAY_PROTOCOL_VERSION {
        return Err(RemoteTransportError::FrameForbidden);
    }
    let retirement_bytes =
        matches!(&frame.body, RelayFrameBody::RetirementCommitted(_)).then(|| encode(&frame));
    match frame.body {
        RelayFrameBody::RetirementCommitted(committed)
            if committed.machine_route == machine_route =>
        {
            let canonical_frame_bytes =
                retirement_bytes.ok_or(RemoteTransportError::FrameForbidden)?;
            Ok(RemoteControl::RetirementTerminal(RetirementTerminal {
                committed,
                canonical_frame_hash: sha256(&canonical_frame_bytes),
                canonical_frame_bytes,
            }))
        }
        RelayFrameBody::Error(failure) if failure.has_safe_code() => {
            Ok(RemoteControl::SafeFailure(SafeFailure {
                code: failure.code,
            }))
        }
        RelayFrameBody::ServerRestarting(restarting) => {
            Ok(RemoteControl::ServerRestarting(restarting))
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
    ) -> Self {
        Self {
            machine_route,
            supervisor: Some(ControlSupervisor::start(machine_route, session)),
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
            .send(SupervisorCommand::Send {
                frame: Box::new(OpaqueRouteFrame {
                    version: RELAY_PROTOCOL_VERSION,
                    body: RelayFrameBody::RetireMachine(retirement),
                }),
                response: response_tx,
            })
            .await
            .map_err(|_| RemoteTransportError::Closed)?;
        response_rx
            .await
            .map_err(|_| RemoteTransportError::Closed)?
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
            .control_rx
            .recv()
            .await
            .ok_or(RemoteTransportError::Closed)?
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
mod tests {
    use std::collections::VecDeque;
    use std::sync::Mutex;
    use std::sync::atomic::{AtomicUsize, Ordering};

    use agentdeck_crypto::{
        SignatureBytes, SigningKey, sign_authentication_transcript, sign_tbs,
        verify_authentication_transcript, verify_tbs,
    };
    use agentdeck_protocol::relay_v2::frame::{
        AcceptedRef, GrantCommitted, PairData, Ping, Publish, Reply, RevocationCommitted,
        RouteAccepted, SealedBlob, Send,
    };
    use agentdeck_protocol::relay_v2::{
        ConnectionInstanceId, DeviceRevocation, DeviceRouteId, Ed25519Signature, GrantSerial,
        LinkGeneration, PairRouteId, RelayFailure, RelayServerId, RequestRouteId, RootKeyId,
        StreamGenerationId, StreamRouteId, TrustEpoch,
    };
    use agentdeck_relay_client::RelayTlsPolicy;
    use tokio::sync::Notify;

    use super::*;

    const RELAY: RelayServerId = RelayServerId::from_bytes([0x11; 16]);
    const ROUTE: MachineRouteId = MachineRouteId::from_bytes([0x22; 16]);

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
}
