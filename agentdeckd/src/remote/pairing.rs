//! Machine transport 上唯一的 durable pairing actor。
//!
//! C1-C5 拥有 PairInvite、OpenPairRoute ACK、PairRequest 验证、PairPending、本机确认、
//! durable InstallGrant、GrantCommitted ACK 与 byte-identical PairResponse 发送/重连恢复，
//! 以及 cancel/expiry terminal close。PairResponseReceived/delivered 仍由后续子片接入。

use std::collections::{BTreeMap, HashMap, HashSet};
use std::fmt;
use std::sync::Arc;
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use agentdeck_crypto::{
    HpkePrivateKey, HpkePublicKey, VerifiedPairRequestV1, open_pair_request_verified,
};
#[cfg(test)]
use agentdeck_protocol::e2ee::PairResponseInfoV1;
use agentdeck_protocol::e2ee::pairing::PAIR_INVITE_MAX_TTL_MS;
use agentdeck_protocol::e2ee::{
    E2EE_FORMAT_VERSION, OuterContextV1, OuterFrameKind, PairInviteV1, PairRequestInfoV1,
    PairRequestV1, PairResponseV1, PairingControlEnvelopeV1,
};
use agentdeck_protocol::relay_v2::frame::{
    ClosePairRoute, GrantCommitted, InstallGrant, OpenPairRoute, PairData, PairRouteClosed,
    PairRouteOpened, RelayFrameBody, RevocationCommitted, RevokeDevice, SealedBlob,
};
use agentdeck_protocol::relay_v2::{
    DeviceRevocation, DeviceRouteId, Digest32, GrantSerial, OpaqueRouteFrame, PairRouteId,
    PublicKeyBytes, RELAY_PROTOCOL_VERSION, RelayGrant, RelayServerId, SignedCertificate, decode,
    encode,
};
use agentdeck_protocol::runtime::RUNTIME_PROTOCOL_VERSION;
use agentdeck_protocol::runtime::identity::{
    DeviceHandle, GrantSerial as RuntimeGrantSerial, PairingId,
};
use agentdeck_protocol::runtime::{
    CreatePairInviteRequest, PairInvite, PairingDecision, PairingReceipt, PairingState,
    PendingPairing, RevocationReceipt,
};
use async_trait::async_trait;
use tokio::sync::{mpsc, oneshot, watch};
use tokio::task::JoinHandle;
use zeroize::Zeroizing;

use crate::runtime::model::RuntimeCommitOperation;
use crate::runtime::pairing_administration::{PairingAdministrationError, PairingPendingSink};
use crate::runtime::store::pairing::{
    AcceptPairRequest, AcceptPairRequestOutcome, CommitPairPending, CommitPairPendingOutcome,
    PairingInviteLifecycle, PairingInviteRecord, PreparePairingInvite, PreparePairingInviteOutcome,
};
use crate::runtime::store::pairing_grant::{ConfirmPairingGrant, PairingGrantPreparation};
use crate::runtime::store::pairing_terminal::{
    PairingCloseProjection, PairingTerminalAction, PairingTerminalRecovery,
    PairingTerminalizeOutcome,
};
use crate::runtime::store::{
    AcknowledgeGrantCommitted, AcknowledgeGrantCommittedOutcome,
    AcknowledgeOrphanGrantCommittedOutcome, AcknowledgePairResponseReceived,
    AcknowledgePairResponseReceivedOutcome, AcknowledgeRevocationCommitted,
    AcknowledgeRevocationCommittedOutcome, BeginDeviceRevocation, BeginDeviceRevocationOutcome,
    ConfirmPairingGrantOutcome, DeviceRevocationRecovery, GrantAllocationProjection,
    GrantCommittedRecovery, GrantPreparingRecovery, IdempotencyOwner, RevocationRecoveryPhase,
    RevocationTargetStatus, RuntimeId, RuntimeIdKind, RuntimeStoreError, RuntimeStoreHandle,
};
use crate::security::SecretBytes;

use super::access::{
    DeviceRevocationFreezer, PairResponseAccessBinding, VerifiedPairResponseReceipt,
};
use super::grants::GrantFreezeBuilder;
#[cfg(test)]
use super::grants::GrantFreezeError;
use super::transport::{
    PairingInviteAnchor, PairingMachineAuthority, PairingTransportEvent, PairingTransportLane,
    RemoteTransportError,
};

const PAIRING_COMMAND_CAPACITY: usize = 8;
const RECONNECT_RETRY_DELAY: Duration = Duration::from_secs(1);
const EXPIRY_RECONCILE_INTERVAL: Duration = Duration::from_secs(1);
const PAIRING_ACTOR_SHUTDOWN_DEADLINE: Duration = Duration::from_secs(10);
// Relay core 每秒刷新一次 actor-owned wall clock；再留一个 tick 的调度余量，避免
// fresh invite 的精确 5 分钟上界被稍旧的 Relay clock 判为 too-far。
const PAIR_INVITE_RELAY_TICK_GUARD_MS: u64 = 2_000;
const PAIRING_UNAVAILABLE: &str = "daemon.pairing.administration.unavailable";
const PAIRING_BUSY: &str = "daemon.pairing.actor_busy";
const PAIRING_STOPPED: &str = "daemon.pairing.actor_stopped";
const PAIRING_DRAINING: &str = "daemon.pairing.draining";
const PAIRING_ENTROPY: &str = "daemon.pairing.entropy_unavailable";
const PAIRING_CLOCK: &str = "daemon.pairing.clock_invalid";
const PAIRING_INVITE_INVALID: &str = "daemon.pairing.invite_invalid";
const PAIRING_TRANSPORT: &str = "daemon.pairing.transport_unavailable";
const PAIRING_REQUEST_INVALID: &str = "daemon.pairing.request_invalid";
const PAIRING_GRANT_RECOVERY_UNAVAILABLE: &str = "daemon.pairing.grant_recovery_unavailable";
const PAIRING_TERMINAL_INVALID: &str = "daemon.pairing.terminal_invalid";
const PAIRING_ALREADY_COMPLETED: &str = "daemon.pairing.already_completed";
const PAIRING_CANCELED: &str = "daemon.pairing.canceled";
const PAIRING_EXPIRED: &str = "daemon.pairing.expired";
const REVOCATION_TARGET_INVALID: &str = "daemon.revocation.target_invalid";
const REVOCATION_RECOVERY_UNAVAILABLE: &str = "daemon.revocation.recovery_unavailable";

/// manager 只观察可公开的 pairing actor 健康，不复制 actor 的重试所有权。
/// LocalBlocked 只能执行本地 purge→recover；它绝不能触发 Relay reconnect。
#[derive(Clone, Debug, Eq, PartialEq)]
pub(crate) enum PairingCoordinatorHealth {
    Starting,
    Healthy,
    TransportRetry(String),
    LocalBlocked(String),
}

#[derive(Clone, Debug, Eq, PartialEq)]
enum PairingRecoveryState {
    Healthy,
    TransportRetry(String),
    LocalRetry(String),
}

#[derive(Clone, Debug, Eq, PartialEq)]
struct PairingAdmissionFence {
    epoch: u64,
    failure_code: Option<String>,
}

struct PairingCoordinatorSignals {
    health_tx: watch::Sender<PairingCoordinatorHealth>,
    admission_tx: watch::Sender<PairingAdmissionFence>,
}

struct PairingCommandEnvelope {
    admission_epoch: u64,
    command: PairingCommand,
}

/// 从 active enrollment 与当前 authenticated key owner 冻结出的 invite 公共上下文。
/// 不含私钥或 invite secret；Debug 不展开 origin/pin/证书。
pub(crate) struct PairingInviteContext {
    wss_url: String,
    current_spki_pin: [u8; 32],
    next_spki_pin: [u8; 32],
    relay_server_id: RelayServerId,
    machine_root_pubkey: PublicKeyBytes,
    machine_root_fingerprint: [u8; 32],
    data_sign_cert: SignedCertificate,
}

impl PairingInviteContext {
    pub(crate) fn new(
        wss_url: String,
        spki_pins: &[Digest32],
        anchor: PairingInviteAnchor,
    ) -> Result<Self, PairingAdministrationError> {
        let current = spki_pins
            .first()
            .ok_or_else(|| pairing_error(PAIRING_INVITE_INVALID))?;
        let next = spki_pins.get(1).unwrap_or(current);
        if wss_url.is_empty() || current.0 == [0; 32] || next.0 == [0; 32] {
            return Err(pairing_error(PAIRING_INVITE_INVALID));
        }
        Ok(Self {
            wss_url,
            current_spki_pin: current.0,
            next_spki_pin: next.0,
            relay_server_id: anchor.relay_server_id(),
            machine_root_pubkey: anchor.root_public_key(),
            machine_root_fingerprint: anchor.root_fingerprint(),
            data_sign_cert: anchor.data_sign_certificate().clone(),
        })
    }
}

impl fmt::Debug for PairingInviteContext {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("PairingInviteContext([REDACTED])")
    }
}

/// 可复制的窄命令 handle。它不拥有 lane、authority 或 actor task。
#[derive(Clone)]
pub(crate) struct PairingCoordinatorHandle {
    command_tx: mpsc::Sender<PairingCommandEnvelope>,
    health_rx: watch::Receiver<PairingCoordinatorHealth>,
    admission_rx: watch::Receiver<PairingAdmissionFence>,
    _admission_tx: watch::Sender<PairingAdmissionFence>,
}

/// BeginDrain 的调用边界必须保留命令是否真正进入 actor，以及 actor 是否明确回错。
/// 未入队或 reply 被丢弃都没有足够证据证明 drain 进入 Failed，调用方不得据此 Resume。
#[derive(Debug)]
pub(crate) enum PairingDrainStartError {
    NotEnqueued(PairingAdministrationError),
    Unconfirmed(PairingAdministrationError),
    ActorBusy(PairingAdministrationError),
    ActorFailed(PairingAdministrationError),
}

impl PairingDrainStartError {
    #[cfg(test)]
    #[must_use]
    pub(crate) fn code(&self) -> &str {
        match self {
            Self::NotEnqueued(error)
            | Self::Unconfirmed(error)
            | Self::ActorBusy(error)
            | Self::ActorFailed(error) => error.code(),
        }
    }
}

enum PairingDrainActorError {
    Busy(PairingAdministrationError),
    Failed(PairingAdministrationError),
}

impl fmt::Debug for PairingCoordinatorHandle {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("PairingCoordinatorHandle([REDACTED])")
    }
}

impl PairingCoordinatorHandle {
    #[cfg(test)]
    fn for_test(command_tx: mpsc::Sender<PairingCommandEnvelope>) -> Self {
        let (_health_tx, health_rx) = watch::channel(PairingCoordinatorHealth::Healthy);
        let (admission_tx, admission_rx) = watch::channel(PairingAdmissionFence {
            epoch: 0,
            failure_code: None,
        });
        Self {
            command_tx,
            health_rx,
            admission_rx,
            _admission_tx: admission_tx,
        }
    }

    fn begin_admission(&self) -> Result<u64, PairingAdministrationError> {
        let health_error = || match &*self.health_rx.borrow() {
            PairingCoordinatorHealth::Starting => Some(pairing_error(PAIRING_STOPPED)),
            PairingCoordinatorHealth::LocalBlocked(code) => Some(pairing_error(code)),
            PairingCoordinatorHealth::Healthy | PairingCoordinatorHealth::TransportRetry(_) => None,
        };
        if let Some(error) = health_error() {
            return Err(error);
        }
        let epoch = self.admission_rx.borrow().epoch;
        // 封闭 Healthy check 与 epoch snapshot 间发生 LocalBlocked 的窗口。
        if let Some(error) = health_error() {
            return Err(error);
        }
        Ok(epoch)
    }

    fn envelope(&self, admission_epoch: u64, command: PairingCommand) -> PairingCommandEnvelope {
        PairingCommandEnvelope {
            admission_epoch,
            command,
        }
    }

    async fn await_fenced_reply<T, E>(
        &self,
        admission_epoch: u64,
        mut reply_rx: oneshot::Receiver<Result<T, E>>,
    ) -> Result<Result<T, E>, PairingAdministrationError> {
        let mut admission_rx = self.admission_rx.clone();
        match reply_rx.try_recv() {
            Ok(reply) => return Ok(reply),
            Err(oneshot::error::TryRecvError::Empty) => {}
            Err(oneshot::error::TryRecvError::Closed) => {
                let fence = admission_rx.borrow_and_update().clone();
                if fence.epoch != admission_epoch {
                    return Err(pairing_error(
                        fence.failure_code.as_deref().unwrap_or(PAIRING_STOPPED),
                    ));
                }
                return Err(pairing_error(PAIRING_STOPPED));
            }
        }
        let current = admission_rx.borrow_and_update().clone();
        if current.epoch != admission_epoch {
            return Err(pairing_error(
                current.failure_code.as_deref().unwrap_or(PAIRING_STOPPED),
            ));
        }
        tokio::select! {
            biased;
            reply = &mut reply_rx => match reply {
                Ok(reply) => Ok(reply),
                Err(_) => {
                    let fence = admission_rx.borrow_and_update().clone();
                    if fence.epoch != admission_epoch {
                        Err(pairing_error(
                            fence.failure_code.as_deref().unwrap_or(PAIRING_STOPPED),
                        ))
                    } else {
                        Err(pairing_error(PAIRING_STOPPED))
                    }
                }
            },
            changed = admission_rx.changed() => {
                if changed.is_err() {
                    return Err(pairing_error(PAIRING_STOPPED));
                }
                let fence = admission_rx.borrow_and_update().clone();
                Err(pairing_error(
                    fence.failure_code.as_deref().unwrap_or(PAIRING_STOPPED),
                ))
            }
        }
    }

    async fn send_fenced(
        &self,
        admission_epoch: u64,
        command: PairingCommand,
    ) -> Result<(), PairingAdministrationError> {
        let mut admission_rx = self.admission_rx.clone();
        let current = admission_rx.borrow_and_update().clone();
        if current.epoch != admission_epoch {
            return Err(pairing_error(
                current.failure_code.as_deref().unwrap_or(PAIRING_STOPPED),
            ));
        }
        tokio::select! {
            biased;
            result = self.command_tx.send(self.envelope(admission_epoch, command)) => {
                result.map_err(|_| pairing_error(PAIRING_STOPPED))
            }
            changed = admission_rx.changed() => {
                if changed.is_err() {
                    return Err(pairing_error(PAIRING_STOPPED));
                }
                let fence = admission_rx.borrow_and_update().clone();
                Err(pairing_error(
                    fence.failure_code.as_deref().unwrap_or(PAIRING_STOPPED),
                ))
            }
        }
    }

    pub(crate) async fn create(
        &self,
        owner: IdempotencyOwner,
        request: CreatePairInviteRequest,
    ) -> Result<PairInvite, PairingAdministrationError> {
        let admission_epoch = self.begin_admission()?;
        let (reply_tx, reply_rx) = oneshot::channel();
        self.command_tx
            .try_send(self.envelope(
                admission_epoch,
                PairingCommand::Create {
                    owner,
                    request,
                    reply: reply_tx,
                },
            ))
            .map_err(command_send_error)?;
        self.await_fenced_reply(admission_epoch, reply_rx).await?
    }

    pub(crate) async fn begin_drain(&self) -> Result<(), PairingDrainStartError> {
        let admission_epoch = self
            .begin_admission()
            .map_err(PairingDrainStartError::NotEnqueued)?;
        let (reply_tx, reply_rx) = oneshot::channel();
        self.command_tx
            .try_send(self.envelope(
                admission_epoch,
                PairingCommand::BeginDrain { reply: reply_tx },
            ))
            .map_err(command_send_error)
            .map_err(PairingDrainStartError::NotEnqueued)?;
        match self.await_fenced_reply(admission_epoch, reply_rx).await {
            Ok(Ok(())) => Ok(()),
            Ok(Err(PairingDrainActorError::Busy(error))) => {
                Err(PairingDrainStartError::ActorBusy(error))
            }
            Ok(Err(PairingDrainActorError::Failed(error))) => {
                Err(PairingDrainStartError::ActorFailed(error))
            }
            // fence/closed reply 只证明结果未确认；只有 actor 显式回
            // PairingDrainActorError::Failed 才允许 manager 执行 Resume。
            Err(error) => Err(PairingDrainStartError::Unconfirmed(error)),
        }
    }

    pub(crate) async fn cancel(
        &self,
        pairing_id: RuntimeId,
    ) -> Result<PairingReceipt, PairingAdministrationError> {
        let admission_epoch = self.begin_admission()?;
        let (reply_tx, reply_rx) = oneshot::channel();
        self.command_tx
            .try_send(self.envelope(
                admission_epoch,
                PairingCommand::Cancel {
                    pairing_id,
                    reply: reply_tx,
                },
            ))
            .map_err(command_send_error)?;
        self.await_fenced_reply(admission_epoch, reply_rx).await?
    }

    pub(crate) async fn confirm(
        &self,
        pairing_id: RuntimeId,
    ) -> Result<PairingReceipt, PairingAdministrationError> {
        let admission_epoch = self.begin_admission()?;
        let (reply_tx, reply_rx) = oneshot::channel();
        self.command_tx
            .try_send(self.envelope(
                admission_epoch,
                PairingCommand::Confirm {
                    pairing_id,
                    reply: reply_tx,
                },
            ))
            .map_err(command_send_error)?;
        self.await_fenced_reply(admission_epoch, reply_rx).await?
    }

    pub(crate) async fn revoke_device(
        &self,
        device: DeviceHandle,
        grant_serial: RuntimeGrantSerial,
    ) -> Result<RevocationReceipt, PairingAdministrationError> {
        let admission_epoch = self.begin_admission()?;
        let (reply_tx, reply_rx) = oneshot::channel();
        self.command_tx
            .try_send(self.envelope(
                admission_epoch,
                PairingCommand::RevokeDevice {
                    device,
                    grant_serial,
                    reply: reply_tx,
                },
            ))
            .map_err(command_send_error)?;
        self.await_fenced_reply(admission_epoch, reply_rx).await?
    }

    pub(crate) async fn resume_after_failed_drain(&self) -> Result<(), PairingAdministrationError> {
        let admission_epoch = self.begin_admission()?;
        let (reply_tx, reply_rx) = oneshot::channel();
        self.send_fenced(
            admission_epoch,
            PairingCommand::ResumeAfterFailedDrain { reply: reply_tx },
        )
        .await?;
        self.await_fenced_reply(admission_epoch, reply_rx).await?
    }

    pub(crate) async fn resume_after_completed_drain(
        &self,
    ) -> Result<(), PairingAdministrationError> {
        let admission_epoch = self.begin_admission()?;
        let (reply_tx, reply_rx) = oneshot::channel();
        self.send_fenced(
            admission_epoch,
            PairingCommand::ResumeAfterCompletedDrain { reply: reply_tx },
        )
        .await?;
        self.await_fenced_reply(admission_epoch, reply_rx).await?
    }

    #[cfg(test)]
    pub(super) fn revocation_test_double(
        entered: oneshot::Sender<(DeviceHandle, RuntimeGrantSerial)>,
        release: oneshot::Receiver<()>,
        receipt: RevocationReceipt,
    ) -> Self {
        let (command_tx, mut command_rx) = mpsc::channel::<PairingCommandEnvelope>(1);
        tokio::spawn(async move {
            let Some(envelope) = command_rx.recv().await else {
                return;
            };
            let PairingCommand::RevokeDevice {
                device,
                grant_serial,
                reply,
            } = envelope.command
            else {
                return;
            };
            let _ = entered.send((device, grant_serial));
            let _ = release.await;
            let _ = reply.send(Ok(receipt));
        });
        Self::for_test(command_tx)
    }

    #[cfg(test)]
    pub(super) fn drain_test_double(
        entered: oneshot::Sender<()>,
        release: oneshot::Receiver<Result<(), PairingAdministrationError>>,
        resumed: oneshot::Sender<()>,
        resume_result: Result<(), PairingAdministrationError>,
    ) -> Self {
        let (command_tx, mut command_rx) = mpsc::channel::<PairingCommandEnvelope>(2);
        tokio::spawn(async move {
            let Some(envelope) = command_rx.recv().await else {
                return;
            };
            let PairingCommand::BeginDrain { reply } = envelope.command else {
                return;
            };
            let _ = entered.send(());
            let result = release
                .await
                .unwrap_or_else(|_| Err(pairing_error(PAIRING_STOPPED)));
            let _ = reply.send(result.map_err(PairingDrainActorError::Failed));
            let Some(envelope) = command_rx.recv().await else {
                return;
            };
            let PairingCommand::ResumeAfterFailedDrain { reply } = envelope.command else {
                return;
            };
            let _ = resumed.send(());
            let _ = reply.send(resume_result);
        });
        Self::for_test(command_tx)
    }

    #[cfg(test)]
    pub(super) fn pending_drain_test_double(
        entered: mpsc::UnboundedSender<()>,
        mut release: watch::Receiver<bool>,
        resumed: mpsc::UnboundedSender<()>,
        completed: Option<oneshot::Sender<()>>,
    ) -> Self {
        let (command_tx, mut command_rx) =
            mpsc::channel::<PairingCommandEnvelope>(PAIRING_COMMAND_CAPACITY);
        tokio::spawn(async move {
            let mut complete = *release.borrow();
            let mut completed = completed;
            let mut waiters: Vec<oneshot::Sender<Result<(), PairingDrainActorError>>> = Vec::new();
            loop {
                tokio::select! {
                    changed = release.changed(), if !complete => {
                        if changed.is_err() {
                            for waiter in waiters.drain(..) {
                                let _ = waiter.send(Err(PairingDrainActorError::Failed(
                                    pairing_error(PAIRING_STOPPED),
                                )));
                            }
                            return;
                        }
                        if *release.borrow_and_update() {
                            complete = true;
                            for waiter in waiters.drain(..) {
                                let _ = waiter.send(Ok(()));
                            }
                            if let Some(completed) = completed.take() {
                                let _ = completed.send(());
                            }
                        }
                    }
                    envelope = command_rx.recv() => match envelope.map(|value| value.command) {
                        Some(PairingCommand::BeginDrain { reply }) => {
                            let _ = entered.send(());
                            waiters.retain(|waiter| !waiter.is_closed());
                            waiters.push(reply);
                            if complete || *release.borrow() {
                                complete = true;
                                for waiter in waiters.drain(..) {
                                    let _ = waiter.send(Ok(()));
                                }
                                if let Some(completed) = completed.take() {
                                    let _ = completed.send(());
                                }
                            }
                        }
                        Some(PairingCommand::ResumeAfterCompletedDrain { reply }) => {
                            let _ = resumed.send(());
                            let _ = reply.send(Ok(()));
                        }
                        Some(_) | None => return,
                    },
                }
            }
        });
        Self::for_test(command_tx)
    }

    #[cfg(test)]
    pub(super) fn saturated_drain_test_double(
        release: oneshot::Receiver<()>,
        observed_stale_command: oneshot::Sender<bool>,
    ) -> Self {
        let (command_tx, mut command_rx) = mpsc::channel::<PairingCommandEnvelope>(1);
        let handle = Self::for_test(command_tx);
        let (reply, _ignored) = oneshot::channel();
        handle
            .command_tx
            .try_send(handle.envelope(0, PairingCommand::BeginDrain { reply }))
            .expect("prefill saturated pairing command queue");
        tokio::spawn(async move {
            let _ = release.await;
            let _ = command_rx.recv().await;
            let stale = matches!(
                tokio::time::timeout(Duration::from_millis(50), command_rx.recv()).await,
                Ok(Some(_))
            );
            let _ = observed_stale_command.send(stale);
        });
        handle
    }

    #[cfg(test)]
    pub(super) fn blocked_resume_test_double(
        begin_entered: oneshot::Sender<()>,
        begin_release: oneshot::Receiver<Result<(), PairingAdministrationError>>,
        saturated: oneshot::Sender<()>,
        release: oneshot::Receiver<()>,
        observed_stale_command: oneshot::Sender<bool>,
    ) -> Self {
        let (command_tx, mut command_rx) = mpsc::channel::<PairingCommandEnvelope>(1);
        let handle = Self::for_test(command_tx);
        let filler = handle.clone();
        tokio::spawn(async move {
            let Some(envelope) = command_rx.recv().await else {
                return;
            };
            let PairingCommand::BeginDrain { reply } = envelope.command else {
                return;
            };
            let _ = begin_entered.send(());
            let begin_result = begin_release
                .await
                .unwrap_or_else(|_| Err(pairing_error(PAIRING_STOPPED)));
            let (filler_reply, _ignored) = oneshot::channel();
            filler
                .command_tx
                .try_send(filler.envelope(
                    0,
                    PairingCommand::BeginDrain {
                        reply: filler_reply,
                    },
                ))
                .expect("saturate queue before manager attempts Resume");
            let _ = saturated.send(());
            let _ = reply.send(begin_result.map_err(PairingDrainActorError::Failed));
            let _ = release.await;
            let _ = command_rx.recv().await;
            let stale = matches!(
                tokio::time::timeout(Duration::from_millis(50), command_rx.recv()).await,
                Ok(Some(_))
            );
            let _ = observed_stale_command.send(stale);
        });
        handle
    }
}

/// manager 持有的唯一 actor owner。shutdown 明确 cancel + join，不遗留 detached task。
pub(crate) struct PairingCoordinatorOwner {
    handle: PairingCoordinatorHandle,
    cancel_tx: watch::Sender<bool>,
    task: Option<JoinHandle<()>>,
    health_rx: watch::Receiver<PairingCoordinatorHealth>,
    shutdown_deadline: Option<tokio::time::Instant>,
}

impl fmt::Debug for PairingCoordinatorOwner {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("PairingCoordinatorOwner([REDACTED])")
    }
}

impl PairingCoordinatorOwner {
    pub(crate) async fn start(
        store: RuntimeStoreHandle,
        lane: PairingTransportLane,
        authority: PairingMachineAuthority,
        invite_anchor: PairingInviteAnchor,
        invite_context: PairingInviteContext,
        pending_sink: Arc<dyn PairingPendingSink>,
        shutdown_rx: watch::Receiver<bool>,
    ) -> (Self, Result<(), PairingAdministrationError>) {
        let (command_tx, command_rx) = mpsc::channel(PAIRING_COMMAND_CAPACITY);
        let (cancel_tx, cancel_rx) = watch::channel(false);
        let (ready_tx, ready_rx) = oneshot::channel();
        let (health_tx, health_rx) = watch::channel(PairingCoordinatorHealth::Starting);
        let (admission_tx, admission_rx) = watch::channel(PairingAdmissionFence {
            epoch: 0,
            failure_code: None,
        });
        let task = tokio::spawn(
            PairingCoordinator::new(
                Arc::new(ProductionPairingStore(store)),
                Box::new(ProductionPairingLane(lane)),
                authority,
                invite_anchor,
                invite_context,
                pending_sink,
                PairingCoordinatorSignals {
                    health_tx,
                    admission_tx: admission_tx.clone(),
                },
            )
            .run(command_rx, cancel_rx, ready_tx),
        );
        let mut owner = Self {
            handle: PairingCoordinatorHandle {
                command_tx,
                health_rx: health_rx.clone(),
                admission_rx,
                _admission_tx: admission_tx.clone(),
            },
            cancel_tx,
            task: Some(task),
            health_rx,
            shutdown_deadline: None,
        };
        let ready = await_pairing_startup(&mut owner, ready_rx, shutdown_rx).await;
        (owner, recoverable_startup_ready(ready))
    }

    #[must_use]
    pub(crate) fn handle(&self) -> PairingCoordinatorHandle {
        self.handle.clone()
    }

    #[must_use]
    pub(crate) fn observed_failure_code(&self) -> Option<String> {
        match &*self.health_rx.borrow() {
            PairingCoordinatorHealth::Healthy => None,
            PairingCoordinatorHealth::Starting => Some(PAIRING_STOPPED.to_owned()),
            PairingCoordinatorHealth::TransportRetry(code)
            | PairingCoordinatorHealth::LocalBlocked(code) => Some(code.clone()),
        }
    }

    #[must_use]
    pub(crate) fn local_blocked_code(&self) -> Option<String> {
        match &*self.health_rx.borrow() {
            PairingCoordinatorHealth::Starting => Some(PAIRING_STOPPED.to_owned()),
            PairingCoordinatorHealth::LocalBlocked(code) => Some(code.clone()),
            PairingCoordinatorHealth::Healthy | PairingCoordinatorHealth::TransportRetry(_) => None,
        }
    }

    pub(crate) async fn shutdown(&mut self) {
        self.cancel_tx.send_replace(true);
        let deadline = *self
            .shutdown_deadline
            .get_or_insert_with(|| tokio::time::Instant::now() + PAIRING_ACTOR_SHUTDOWN_DEADLINE);
        let Some(task) = self.task.as_mut() else {
            return;
        };
        if tokio::time::timeout_at(deadline, &mut *task).await.is_err() {
            task.abort();
            let _ = task.await;
        }
        self.task.take();
    }

    async fn abort_and_join(&mut self) {
        self.cancel_tx.send_replace(true);
        let Some(task) = self.task.as_mut() else {
            return;
        };
        task.abort();
        let _ = task.await;
        self.task.take();
    }

    #[cfg(test)]
    pub(crate) fn health_test_double(
        initial: PairingCoordinatorHealth,
    ) -> (Self, watch::Sender<PairingCoordinatorHealth>) {
        let (command_tx, mut command_rx) = mpsc::channel(PAIRING_COMMAND_CAPACITY);
        let (cancel_tx, mut cancel_rx) = watch::channel(false);
        let (health_tx, health_rx) = watch::channel(initial);
        let (_admission_tx, admission_rx) = watch::channel(PairingAdmissionFence {
            epoch: 0,
            failure_code: None,
        });
        let task = tokio::spawn(async move {
            loop {
                tokio::select! {
                    biased;
                    changed = cancel_rx.changed() => {
                        if changed.is_err() || *cancel_rx.borrow() {
                            break;
                        }
                    }
                    command = command_rx.recv() => {
                        if command.is_none() {
                            break;
                        }
                    }
                }
            }
        });
        (
            Self {
                handle: PairingCoordinatorHandle {
                    command_tx,
                    health_rx: health_rx.clone(),
                    admission_rx,
                    _admission_tx,
                },
                cancel_tx,
                task: Some(task),
                health_rx,
                shutdown_deadline: None,
            },
            health_tx,
        )
    }

    #[cfg(test)]
    pub(crate) fn pending_startup_test_double() -> (
        Self,
        oneshot::Receiver<Result<(), PairingAdministrationError>>,
    ) {
        let (command_tx, _command_rx) = mpsc::channel(PAIRING_COMMAND_CAPACITY);
        let (cancel_tx, _cancel_rx) = watch::channel(false);
        let (ready_tx, ready_rx) = oneshot::channel();
        let (_health_tx, health_rx) = watch::channel(PairingCoordinatorHealth::Starting);
        let (_admission_tx, admission_rx) = watch::channel(PairingAdmissionFence {
            epoch: 0,
            failure_code: None,
        });
        let task = tokio::spawn(async move {
            let _ready_tx = ready_tx;
            std::future::pending::<()>().await;
        });
        (
            Self {
                handle: PairingCoordinatorHandle {
                    command_tx,
                    health_rx: health_rx.clone(),
                    admission_rx,
                    _admission_tx,
                },
                cancel_tx,
                task: Some(task),
                health_rx,
                shutdown_deadline: None,
            },
            ready_rx,
        )
    }
}

pub(super) async fn await_pairing_startup(
    owner: &mut PairingCoordinatorOwner,
    ready_rx: oneshot::Receiver<Result<(), PairingAdministrationError>>,
    mut shutdown_rx: watch::Receiver<bool>,
) -> Result<(), PairingAdministrationError> {
    if *shutdown_rx.borrow() {
        owner.abort_and_join().await;
        return Err(pairing_error(PAIRING_STOPPED));
    }
    tokio::select! {
        biased;
        changed = shutdown_rx.changed() => {
            let _ = changed;
            owner.abort_and_join().await;
            Err(pairing_error(PAIRING_STOPPED))
        }
        ready = ready_rx => {
            ready.unwrap_or_else(|_| Err(pairing_error(PAIRING_STOPPED)))
        }
    }
}

impl Drop for PairingCoordinatorOwner {
    fn drop(&mut self) {
        self.cancel_tx.send_replace(true);
        if let Some(task) = self.task.as_ref() {
            task.abort();
        }
    }
}

enum PairingCommand {
    Create {
        owner: IdempotencyOwner,
        request: CreatePairInviteRequest,
        reply: oneshot::Sender<Result<PairInvite, PairingAdministrationError>>,
    },
    Cancel {
        pairing_id: RuntimeId,
        reply: oneshot::Sender<Result<PairingReceipt, PairingAdministrationError>>,
    },
    Confirm {
        pairing_id: RuntimeId,
        reply: oneshot::Sender<Result<PairingReceipt, PairingAdministrationError>>,
    },
    RevokeDevice {
        device: DeviceHandle,
        grant_serial: RuntimeGrantSerial,
        reply: oneshot::Sender<Result<RevocationReceipt, PairingAdministrationError>>,
    },
    BeginDrain {
        reply: oneshot::Sender<Result<(), PairingDrainActorError>>,
    },
    ResumeAfterFailedDrain {
        reply: oneshot::Sender<Result<(), PairingAdministrationError>>,
    },
    ResumeAfterCompletedDrain {
        reply: oneshot::Sender<Result<(), PairingAdministrationError>>,
    },
}

enum PairingDrainState {
    Idle,
    Running(Vec<oneshot::Sender<Result<(), PairingDrainActorError>>>),
    Failed,
    Complete,
}

impl PairingDrainState {
    const fn is_active(&self) -> bool {
        !matches!(self, Self::Idle)
    }

    fn resume_after_failed(&mut self) -> Result<(), PairingAdministrationError> {
        if !matches!(self, Self::Failed) {
            return Err(pairing_error(PAIRING_DRAINING));
        }
        *self = Self::Idle;
        Ok(())
    }

    fn resume_after_completed(&mut self) -> Result<(), PairingAdministrationError> {
        if !matches!(self, Self::Complete) {
            return Err(pairing_error(PAIRING_DRAINING));
        }
        *self = Self::Idle;
        Ok(())
    }
}

#[derive(Clone)]
struct DurableClose {
    pairing_id: RuntimeId,
    pair_route: PairRouteId,
    frame: ClosePairRoute,
}

impl DurableClose {
    fn from_projection(
        pairing_id: RuntimeId,
        pair_route: PairRouteId,
        canonical: &[u8],
    ) -> Result<Self, PairingAdministrationError> {
        let decoded = decode(canonical).map_err(|_| pairing_error(PAIRING_TERMINAL_INVALID))?;
        if encode(&decoded) != canonical || decoded.version != RELAY_PROTOCOL_VERSION {
            return Err(pairing_error(PAIRING_TERMINAL_INVALID));
        }
        let RelayFrameBody::ClosePairRoute(frame) = decoded.body else {
            return Err(pairing_error(PAIRING_TERMINAL_INVALID));
        };
        if frame.pair_route != pair_route {
            return Err(pairing_error(PAIRING_TERMINAL_INVALID));
        }
        Ok(Self {
            pairing_id,
            pair_route,
            frame,
        })
    }

    fn from_store(projection: &PairingCloseProjection) -> Result<Self, PairingAdministrationError> {
        Self::from_projection(
            projection.pairing_id(),
            projection.pair_route(),
            projection.canonical_frame(),
        )
    }
}

struct TerminalOutcome {
    pairing_id: RuntimeId,
    reply: PairingReceipt,
    close: Option<DurableClose>,
}

#[derive(Clone)]
struct DurableGrant {
    pairing_id: RuntimeId,
    request_hash: [u8; 32],
    receipt: PairingReceipt,
    install: InstallGrant,
    canonical_frame: Vec<u8>,
}

impl DurableGrant {
    fn from_store(recovery: &GrantPreparingRecovery) -> Result<Self, PairingAdministrationError> {
        let canonical = recovery.canonical_install_frame();
        let decoded =
            decode(canonical).map_err(|_| pairing_error(PAIRING_GRANT_RECOVERY_UNAVAILABLE))?;
        if decoded.version != RELAY_PROTOCOL_VERSION || encode(&decoded) != canonical {
            return Err(pairing_error(PAIRING_GRANT_RECOVERY_UNAVAILABLE));
        }
        let RelayFrameBody::InstallGrant(install) = decoded.body else {
            return Err(pairing_error(PAIRING_GRANT_RECOVERY_UNAVAILABLE));
        };
        let (receipt_pairing_id, decision) = terminal_receipt_identity(recovery.receipt())?;
        if receipt_pairing_id != recovery.pairing_id()
            || decision != PairingDecision::Confirm
            || recovery.request_hash() == [0; 32]
            || recovery.response_hash() == [0; 32]
            || recovery.canonical_response().is_empty()
            || install.grant.device_route != recovery.device_route()
            || install.grant.grant_serial != recovery.grant_serial()
            || install.grant.canonical_sha256() != recovery.grant_hash()
        {
            return Err(pairing_error(PAIRING_GRANT_RECOVERY_UNAVAILABLE));
        }
        Ok(Self {
            pairing_id: recovery.pairing_id(),
            request_hash: recovery.request_hash(),
            receipt: recovery.receipt().clone(),
            install,
            canonical_frame: canonical.to_vec(),
        })
    }

    #[cfg(test)]
    fn for_test(
        pairing_id: RuntimeId,
        request_hash: [u8; 32],
        receipt: PairingReceipt,
        install: InstallGrant,
    ) -> Self {
        let canonical_frame = encode(&OpaqueRouteFrame {
            version: RELAY_PROTOCOL_VERSION,
            body: RelayFrameBody::InstallGrant(install.clone()),
        });
        Self {
            pairing_id,
            request_hash,
            receipt,
            install,
            canonical_frame,
        }
    }
}

#[derive(Clone)]
struct DurableResponse {
    pairing_id: RuntimeId,
    request_hash: [u8; 32],
    pair_route: PairRouteId,
    device_route: DeviceRouteId,
    grant_serial: GrantSerial,
    grant_hash: [u8; 32],
    response_hash: [u8; 32],
    invite: PairInviteV1,
    relay_grant: RelayGrant,
    pair_response: PairResponseV1,
    invite_hpke_private_key: Zeroizing<Vec<u8>>,
    canonical_pair_response: Vec<u8>,
}

impl DurableResponse {
    fn from_store(recovery: &GrantCommittedRecovery) -> Result<Self, PairingAdministrationError> {
        let canonical = recovery.canonical_pair_response();
        let invite = recovery.invite();
        let relay_grant = recovery.relay_grant();
        let pair_response = recovery.pair_response();
        let durable = Self {
            pairing_id: recovery.pairing_id(),
            request_hash: recovery.request_hash(),
            pair_route: invite.pair_route,
            device_route: recovery.device_route(),
            grant_serial: recovery.grant_serial(),
            grant_hash: recovery.grant_hash(),
            response_hash: recovery.response_hash(),
            invite: invite.clone(),
            relay_grant: relay_grant.clone(),
            pair_response: pair_response.clone(),
            invite_hpke_private_key: Zeroizing::new(recovery.invite_hpke_private_key().to_bytes()),
            canonical_pair_response: canonical.to_vec(),
        };
        durable.validate()?;
        Ok(durable)
    }

    fn validate(&self) -> Result<(), PairingAdministrationError> {
        let response = PairResponseV1::from_canonical_bytes(&self.canonical_pair_response)
            .map_err(|_| pairing_error(PAIRING_GRANT_RECOVERY_UNAVAILABLE))?;
        let invite_private_key = HpkePrivateKey::from_bytes(&self.invite_hpke_private_key)
            .map_err(|_| pairing_error(PAIRING_GRANT_RECOVERY_UNAVAILABLE))?;
        if response
            .canonical_bytes()
            .map_err(|_| pairing_error(PAIRING_GRANT_RECOVERY_UNAVAILABLE))?
            != self.canonical_pair_response
            || response
                .canonical_sha256()
                .map_err(|_| pairing_error(PAIRING_GRANT_RECOVERY_UNAVAILABLE))?
                != self.response_hash
            || self.request_hash == [0; 32]
            || self.response_hash == [0; 32]
            || self.pair_route.as_bytes() == &[0; 16]
            || self.invite.validate_static().is_err()
            || self.invite.pair_route != self.pair_route
            || invite_private_key.public_key().to_bytes() != self.invite.invite_hpke_pubkey.0
            || self.relay_grant.device_route != self.device_route
            || self.relay_grant.grant_serial != self.grant_serial
            || self.relay_grant.canonical_sha256() != self.grant_hash
            || response != self.pair_response
        {
            return Err(pairing_error(PAIRING_GRANT_RECOVERY_UNAVAILABLE));
        }
        Ok(())
    }

    fn frame(&self) -> Result<PairData, PairingAdministrationError> {
        self.validate()?;
        Ok(PairData {
            pair_route: self.pair_route,
            sealed_blob: SealedBlob(self.canonical_pair_response.clone()),
        })
    }

    fn verify_receipt(
        &self,
        canonical_envelope: &[u8],
    ) -> Result<VerifiedPairResponseReceipt, PairingAdministrationError> {
        self.validate()?;
        let binding = PairResponseAccessBinding::from_frozen(
            &self.invite,
            self.request_hash,
            &self.relay_grant,
            &self.pair_response,
        )
        .map_err(|error| pairing_error(error.code()))?;
        let private_key = HpkePrivateKey::from_bytes(&self.invite_hpke_private_key)
            .map_err(|_| pairing_error(PAIRING_GRANT_RECOVERY_UNAVAILABLE))?;
        binding
            .open_and_verify_receipt(&private_key, canonical_envelope)
            .map_err(|error| pairing_error(error.code()))
    }

    #[cfg(test)]
    fn receipt_info(&self) -> Result<PairResponseInfoV1, PairingAdministrationError> {
        self.validate()?;
        Ok(PairResponseInfoV1 {
            e2ee_format_version: E2EE_FORMAT_VERSION,
            runtime_protocol_version: RUNTIME_PROTOCOL_VERSION,
            relay_server_id: self.invite.relay_server_id,
            pair_route: self.pair_route,
            invite_hash: self
                .invite
                .canonical_sha256()
                .map_err(|_| pairing_error(PAIRING_GRANT_RECOVERY_UNAVAILABLE))?,
            expiry_ms: self.invite.expires_at_ms,
            request_hash: self.request_hash,
            machine_route: self.relay_grant.machine_route,
            device_route: self.device_route,
            grant_serial: self.grant_serial,
            root_trust_epoch: self.relay_grant.trust_epoch,
        })
    }

    #[cfg(test)]
    fn receipt_context(&self) -> OuterContextV1 {
        pairing_context(self.pair_route, OuterFrameKind::PairResponseReceived)
    }

    #[cfg(test)]
    fn verify_receipt_for_test(
        &self,
        canonical_envelope: &[u8],
    ) -> Result<DeliveryProofInput, PairingAdministrationError> {
        let info = self.receipt_info()?;
        let context = self.receipt_context();
        let private_key = HpkePrivateKey::from_bytes(&self.invite_hpke_private_key)
            .map_err(|_| pairing_error(PAIRING_GRANT_RECOVERY_UNAVAILABLE))?;
        let device_verifying_key =
            agentdeck_crypto::VerifyingKey::from_bytes(&self.relay_grant.device_sign_pubkey.0)
                .map_err(|_| pairing_error("daemon.pairing.receipt_signature_invalid"))?;
        let envelope = PairingControlEnvelopeV1::from_canonical_bytes(canonical_envelope)
            .map_err(|_| pairing_error("daemon.pairing.receipt_encoding_invalid"))?;
        let receipt = agentdeck_crypto::open_pair_response_received(
            &private_key,
            &info,
            &context,
            &envelope,
            &device_verifying_key,
        )
        .map_err(|_| pairing_error("daemon.pairing.receipt_signature_invalid"))?;
        if receipt.request_hash != self.request_hash
            || receipt.grant_hash != self.grant_hash
            || receipt.response_hash != self.response_hash
        {
            return Err(pairing_error("daemon.pairing.receipt_binding_mismatch"));
        }
        let canonical_receipt = receipt
            .canonical_bytes()
            .map_err(|_| pairing_error("daemon.pairing.receipt_encoding_invalid"))?;
        Ok(DeliveryProofInput::for_test(
            self.pairing_id,
            self.pair_route,
            self.request_hash,
            self.grant_hash,
            self.response_hash,
            agentdeck_crypto::sha256(&canonical_receipt),
        ))
    }

    #[cfg(test)]
    fn for_test(
        pairing_id: RuntimeId,
        request_hash: [u8; 32],
        invite: &PairInviteV1,
        invite_hpke_private_key: &[u8],
        grant: &RelayGrant,
    ) -> Self {
        let info = PairResponseInfoV1 {
            e2ee_format_version: E2EE_FORMAT_VERSION,
            runtime_protocol_version: RUNTIME_PROTOCOL_VERSION,
            relay_server_id: invite.relay_server_id,
            pair_route: invite.pair_route,
            invite_hash: invite.canonical_sha256().expect("valid test invite"),
            expiry_ms: invite.expires_at_ms,
            request_hash,
            machine_route: grant.machine_route,
            device_route: grant.device_route,
            grant_serial: grant.grant_serial,
            root_trust_epoch: grant.trust_epoch,
        };
        let response = PairResponseV1 {
            format_version: E2EE_FORMAT_VERSION,
            info,
            enc: vec![0xa1; 32],
            ciphertext: request_hash.to_vec(),
            machine_data_signature: agentdeck_protocol::relay_v2::Ed25519Signature([0xa2; 64]),
        };
        let canonical_pair_response = response.canonical_bytes().expect("valid test response");
        let response_hash = response.canonical_sha256().expect("valid test response");
        Self {
            pairing_id,
            request_hash,
            pair_route: invite.pair_route,
            device_route: grant.device_route,
            grant_serial: grant.grant_serial,
            grant_hash: grant.canonical_sha256(),
            response_hash,
            invite: invite.clone(),
            relay_grant: grant.clone(),
            pair_response: response,
            invite_hpke_private_key: Zeroizing::new(invite_hpke_private_key.to_vec()),
            canonical_pair_response,
        }
    }
}

struct DeliveryProofInput {
    pairing_id: RuntimeId,
    pair_route: PairRouteId,
    request_hash: [u8; 32],
    grant_hash: [u8; 32],
    response_hash: [u8; 32],
    canonical_receipt_hash: [u8; 32],
    production: Option<VerifiedPairResponseReceipt>,
}

impl DeliveryProofInput {
    fn from_verified(pairing_id: RuntimeId, proof: VerifiedPairResponseReceipt) -> Self {
        Self {
            pairing_id,
            pair_route: proof.pair_route(),
            request_hash: proof.request_hash(),
            grant_hash: proof.grant_hash(),
            response_hash: proof.response_hash(),
            canonical_receipt_hash: agentdeck_crypto::sha256(proof.canonical_receipt()),
            production: Some(proof),
        }
    }

    #[cfg(test)]
    const fn for_test(
        pairing_id: RuntimeId,
        pair_route: PairRouteId,
        request_hash: [u8; 32],
        grant_hash: [u8; 32],
        response_hash: [u8; 32],
        canonical_receipt_hash: [u8; 32],
    ) -> Self {
        Self {
            pairing_id,
            pair_route,
            request_hash,
            grant_hash,
            response_hash,
            canonical_receipt_hash,
            production: None,
        }
    }
}

struct DeliveryOutcome {
    close: DurableClose,
}

#[derive(Clone, Copy, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
struct RevocationKey {
    device_route: [u8; 16],
    grant_serial: u64,
}

impl RevocationKey {
    fn new(device_route: DeviceRouteId, grant_serial: GrantSerial) -> Self {
        Self {
            device_route: *device_route.as_bytes(),
            grant_serial: grant_serial.value(),
        }
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum DurableRevocationPhase {
    AwaitingGrantCommit,
    ReadyToRevoke,
}

#[derive(Clone)]
struct DurableRevocation {
    pairing_id: Option<RuntimeId>,
    grant: RelayGrant,
    revocation: DeviceRevocation,
    phase: DurableRevocationPhase,
    canonical_next_frame: Vec<u8>,
}

impl DurableRevocation {
    fn from_store(recovery: &DeviceRevocationRecovery) -> Result<Self, PairingAdministrationError> {
        let phase = match recovery.phase() {
            RevocationRecoveryPhase::AwaitingGrantCommit => {
                DurableRevocationPhase::AwaitingGrantCommit
            }
            RevocationRecoveryPhase::ReadyToRevoke => DurableRevocationPhase::ReadyToRevoke,
        };
        let durable = Self {
            pairing_id: recovery.pairing_id(),
            grant: recovery.grant().clone(),
            revocation: recovery.revocation().clone(),
            phase,
            canonical_next_frame: recovery.canonical_next_frame().to_vec(),
        };
        durable.validate()?;
        Ok(durable)
    }

    fn validate(&self) -> Result<(), PairingAdministrationError> {
        if self.grant.device_route != self.revocation.device_route
            || self.grant.grant_serial != self.revocation.grant_serial
            || self.grant.device_route.as_bytes() == &[0; 16]
            || self.grant.grant_serial.value() == 0
            || self.grant.canonical_sha256() == [0; 32]
            || self.revocation.canonical_sha256() == [0; 32]
        {
            return Err(pairing_error(REVOCATION_RECOVERY_UNAVAILABLE));
        }
        let decoded = decode(&self.canonical_next_frame)
            .map_err(|_| pairing_error(REVOCATION_RECOVERY_UNAVAILABLE))?;
        if decoded.version != RELAY_PROTOCOL_VERSION
            || encode(&decoded) != self.canonical_next_frame
        {
            return Err(pairing_error(REVOCATION_RECOVERY_UNAVAILABLE));
        }
        let exact = match (&self.phase, decoded.body) {
            (
                DurableRevocationPhase::AwaitingGrantCommit,
                RelayFrameBody::InstallGrant(install),
            ) => install.grant == self.grant,
            (DurableRevocationPhase::ReadyToRevoke, RelayFrameBody::RevokeDevice(revoke)) => {
                revoke.revocation == self.revocation
            }
            _ => false,
        };
        if !exact {
            return Err(pairing_error(REVOCATION_RECOVERY_UNAVAILABLE));
        }
        Ok(())
    }

    fn key(&self) -> RevocationKey {
        RevocationKey::new(self.revocation.device_route, self.revocation.grant_serial)
    }

    fn matches_grant_committed(&self, committed: &GrantCommitted) -> bool {
        self.phase == DurableRevocationPhase::AwaitingGrantCommit
            && self.grant.device_route == committed.device_route
            && self.grant.grant_serial == committed.grant_serial
            && self.grant.canonical_sha256() == committed.grant_hash
    }

    fn matches_revocation_committed(&self, committed: &RevocationCommitted) -> bool {
        self.phase == DurableRevocationPhase::ReadyToRevoke
            && self.revocation.device_route == committed.device_route
            && self.revocation.grant_serial == committed.grant_serial
            && self.revocation == committed.signed_revocation
    }

    #[cfg(test)]
    fn for_test(
        pairing_id: Option<RuntimeId>,
        grant: RelayGrant,
        revocation: DeviceRevocation,
        phase: DurableRevocationPhase,
    ) -> Self {
        let body = match phase {
            DurableRevocationPhase::AwaitingGrantCommit => {
                RelayFrameBody::InstallGrant(InstallGrant {
                    grant: grant.clone(),
                })
            }
            DurableRevocationPhase::ReadyToRevoke => RelayFrameBody::RevokeDevice(RevokeDevice {
                revocation: revocation.clone(),
            }),
        };
        Self {
            pairing_id,
            grant,
            revocation,
            phase,
            canonical_next_frame: encode(&OpaqueRouteFrame {
                version: RELAY_PROTOCOL_VERSION,
                body,
            }),
        }
    }
}

struct RevocationTargetInput {
    pairing_id: Option<RuntimeId>,
    device: DeviceHandle,
    grant: RelayGrant,
}

enum RevocationTargetOutcome {
    Ready(RevocationTargetInput),
    Revoking(DurableRevocation),
    Revoked(DeviceRevocation),
}

struct FrozenRevocationInput {
    pairing_id: Option<RuntimeId>,
    revocation: DeviceRevocation,
}

enum BeginRevocationOutcome {
    Recovering(Box<DurableRevocation>),
    AlreadyRevoked(DeviceRevocation),
}

struct GrantPreparationInput {
    pairing_id: RuntimeId,
    request_hash: [u8; 32],
    device_sign_fingerprint: [u8; 32],
    production: Option<PairingGrantPreparation>,
}

impl GrantPreparationInput {
    fn from_store(value: PairingGrantPreparation) -> Self {
        let device_sign_fingerprint =
            agentdeck_crypto::sha256(&value.request().device_sign_pubkey.0);
        Self {
            pairing_id: value.pairing_id(),
            request_hash: value.request_hash(),
            device_sign_fingerprint,
            production: Some(value),
        }
    }

    #[cfg(test)]
    fn for_test(pairing_id: RuntimeId, request_hash: [u8; 32]) -> Self {
        Self {
            pairing_id,
            request_hash,
            device_sign_fingerprint: [0x5a; 32],
            production: None,
        }
    }
}

enum GrantAllocationInput {
    Production(GrantAllocationProjection),
    #[cfg(test)]
    Test {
        grant_serial: GrantSerial,
        key_directory_revision: agentdeck_protocol::relay_v2::KeyDirectoryRevision,
    },
}

struct FrozenGrantInput {
    pairing_id: RuntimeId,
    request_hash: [u8; 32],
    production: Option<ConfirmPairingGrant>,
}

impl FrozenGrantInput {
    #[cfg(test)]
    fn for_test(pairing_id: RuntimeId, request_hash: [u8; 32]) -> Self {
        Self {
            pairing_id,
            request_hash,
            production: None,
        }
    }
}

enum GrantCommitOutcome {
    Committed {
        reply: PairingReceipt,
        grant: Box<DurableGrant>,
    },
    Terminal {
        reply: PairingReceipt,
    },
}

fn terminal_receipt_identity(
    receipt: &PairingReceipt,
) -> Result<(RuntimeId, PairingDecision), PairingAdministrationError> {
    let (pairing_id, decision) = match receipt {
        PairingReceipt::Confirmed { pairing_id } => (pairing_id, PairingDecision::Confirm),
        PairingReceipt::Canceled { pairing_id } => (pairing_id, PairingDecision::Cancel),
        PairingReceipt::Expired { pairing_id } => (pairing_id, PairingDecision::Expire),
        PairingReceipt::Replayed { .. }
        | PairingReceipt::AlreadyHandled { .. }
        | PairingReceipt::Failed { .. } => {
            return Err(pairing_error(PAIRING_TERMINAL_INVALID));
        }
    };
    let pairing_id = RuntimeId::parse_canonical(RuntimeIdKind::Pairing, pairing_id.as_str())
        .map_err(|_| pairing_error(PAIRING_TERMINAL_INVALID))?;
    Ok((pairing_id, decision))
}

fn create_terminal_error(receipt: PairingReceipt) -> PairingAdministrationError {
    pairing_error(match receipt {
        PairingReceipt::Canceled { .. } => PAIRING_CANCELED,
        PairingReceipt::Expired { .. } => PAIRING_EXPIRED,
        PairingReceipt::Confirmed { .. } => PAIRING_ALREADY_COMPLETED,
        PairingReceipt::Replayed { .. }
        | PairingReceipt::AlreadyHandled { .. }
        | PairingReceipt::Failed { .. } => PAIRING_TERMINAL_INVALID,
    })
}

fn terminal_outcome_from_store(
    outcome: PairingTerminalizeOutcome,
) -> Result<TerminalOutcome, PairingAdministrationError> {
    let (receipt, state, close, replayed) = match outcome {
        PairingTerminalizeOutcome::Transitioned { receipt, close } => {
            (receipt, None, Some(close), None)
        }
        PairingTerminalizeOutcome::Replayed {
            receipt,
            state,
            close,
        } => (receipt, Some(state), close, Some(true)),
        PairingTerminalizeOutcome::AlreadyHandled {
            receipt,
            state,
            close,
        } => (receipt, Some(state), close, Some(false)),
    };
    let (pairing_id, decision) = terminal_receipt_identity(&receipt)?;
    let close = close.as_ref().map(DurableClose::from_store).transpose()?;
    if close
        .as_ref()
        .is_some_and(|close| close.pairing_id != pairing_id)
    {
        return Err(pairing_error(PAIRING_TERMINAL_INVALID));
    }
    let reply = match (replayed, state) {
        (None, None) => receipt,
        (Some(true), Some(state)) => PairingReceipt::Replayed {
            pairing_id: PairingId::new(pairing_id.to_canonical_string()),
            decision,
            state,
        },
        (Some(false), Some(state)) => PairingReceipt::AlreadyHandled {
            pairing_id: PairingId::new(pairing_id.to_canonical_string()),
            winner: decision,
            state,
        },
        _ => return Err(pairing_error(PAIRING_TERMINAL_INVALID)),
    };
    Ok(TerminalOutcome {
        pairing_id,
        reply,
        close,
    })
}

fn replayed_confirm_receipt(
    receipt: &PairingReceipt,
) -> Result<PairingReceipt, PairingAdministrationError> {
    let (pairing_id, decision) = terminal_receipt_identity(receipt)?;
    if decision != PairingDecision::Confirm {
        return Err(pairing_error(PAIRING_GRANT_RECOVERY_UNAVAILABLE));
    }
    Ok(PairingReceipt::Replayed {
        pairing_id: PairingId::new(pairing_id.to_canonical_string()),
        decision,
        state: PairingState::GrantPreparing,
    })
}

fn already_handled_confirm_receipt(
    receipt: &PairingReceipt,
    state: PairingState,
) -> Result<PairingReceipt, PairingAdministrationError> {
    let (pairing_id, winner) = terminal_receipt_identity(receipt)?;
    Ok(PairingReceipt::AlreadyHandled {
        pairing_id: PairingId::new(pairing_id.to_canonical_string()),
        winner,
        state,
    })
}

fn confirm_retry_receipt(
    receipt: &PairingReceipt,
    state: PairingState,
) -> Result<PairingReceipt, PairingAdministrationError> {
    let (pairing_id, winner) = terminal_receipt_identity(receipt)?;
    let pairing_id = PairingId::new(pairing_id.to_canonical_string());
    Ok(if winner == PairingDecision::Confirm {
        PairingReceipt::Replayed {
            pairing_id,
            decision: winner,
            state,
        }
    } else {
        PairingReceipt::AlreadyHandled {
            pairing_id,
            winner,
            state,
        }
    })
}

fn grant_outcome_from_store(
    outcome: ConfirmPairingGrantOutcome,
) -> Result<GrantCommitOutcome, PairingAdministrationError> {
    match outcome {
        ConfirmPairingGrantOutcome::Confirmed { receipt, recovery } => {
            let grant = DurableGrant::from_store(&recovery)?;
            if grant.receipt != receipt {
                return Err(pairing_error(PAIRING_GRANT_RECOVERY_UNAVAILABLE));
            }
            Ok(GrantCommitOutcome::Committed {
                reply: receipt,
                grant: Box::new(grant),
            })
        }
        ConfirmPairingGrantOutcome::Replayed { receipt, recovery } => {
            let grant = DurableGrant::from_store(&recovery)?;
            if grant.receipt != receipt {
                return Err(pairing_error(PAIRING_GRANT_RECOVERY_UNAVAILABLE));
            }
            Ok(GrantCommitOutcome::Committed {
                reply: replayed_confirm_receipt(&receipt)?,
                grant: Box::new(grant),
            })
        }
        ConfirmPairingGrantOutcome::AlreadyHandled { receipt, state } => {
            Ok(GrantCommitOutcome::Terminal {
                reply: already_handled_confirm_receipt(&receipt, state)?,
            })
        }
    }
}

fn committed_response_from_store(
    outcome: AcknowledgeGrantCommittedOutcome,
) -> Result<DurableResponse, PairingAdministrationError> {
    let recovery = match outcome {
        AcknowledgeGrantCommittedOutcome::Committed { recovery }
        | AcknowledgeGrantCommittedOutcome::Replayed { recovery } => recovery,
    };
    DurableResponse::from_store(&recovery)
}

fn delivery_outcome_from_store(
    outcome: AcknowledgePairResponseReceivedOutcome,
) -> Result<DeliveryOutcome, PairingAdministrationError> {
    let close = match outcome {
        AcknowledgePairResponseReceivedOutcome::Delivered { close }
        | AcknowledgePairResponseReceivedOutcome::Replayed { close } => close,
    };
    Ok(DeliveryOutcome {
        close: DurableClose::from_store(&close)?,
    })
}

fn begin_revocation_from_store(
    outcome: BeginDeviceRevocationOutcome,
    pairing_id: Option<RuntimeId>,
    expected: &DeviceRevocation,
) -> Result<BeginRevocationOutcome, PairingAdministrationError> {
    match outcome {
        BeginDeviceRevocationOutcome::Prepared { recovery }
        | BeginDeviceRevocationOutcome::Replayed { recovery } => {
            let recovery = DurableRevocation::from_store(&recovery)?;
            if pairing_id.is_some() && recovery.pairing_id != pairing_id
                || recovery.revocation != *expected
            {
                return Err(pairing_error(REVOCATION_RECOVERY_UNAVAILABLE));
            }
            Ok(BeginRevocationOutcome::Recovering(Box::new(recovery)))
        }
        BeginDeviceRevocationOutcome::AlreadyRevoked { revocation } => {
            if revocation != *expected {
                return Err(pairing_error(REVOCATION_RECOVERY_UNAVAILABLE));
            }
            Ok(BeginRevocationOutcome::AlreadyRevoked(revocation))
        }
    }
}

fn terminal_recovery_from_store(
    recovery: &PairingTerminalRecovery,
) -> Result<DurableClose, PairingAdministrationError> {
    let (pairing_id, _) = terminal_receipt_identity(recovery.receipt())?;
    let close = DurableClose::from_store(recovery.close())?;
    if close.pairing_id != pairing_id {
        return Err(pairing_error(PAIRING_TERMINAL_INVALID));
    }
    Ok(close)
}

struct DurableInvite {
    pairing_id: RuntimeId,
    pair_route: PairRouteId,
    lifecycle: PairingInviteLifecycle,
    canonical_invite: SecretBytes,
    canonical_open_frame: Vec<u8>,
    invite_hpke_private_key: Option<HpkePrivateKey>,
    request_hash: Option<[u8; 32]>,
    device_sign_fingerprint: Option<[u8; 32]>,
    request_received_at_ms: Option<u64>,
    canonical_pair_request: Option<SecretBytes>,
    pending_preparation: Option<PendingPreparation>,
    canonical_pending_frame: Option<Vec<u8>>,
}

struct PendingPreparation {
    request_hash: [u8; 32],
    info: PairRequestInfoV1,
    context: OuterContextV1,
    recipient: HpkePublicKey,
}

impl fmt::Debug for DurableInvite {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("DurableInvite")
            .field("pairing_id", &self.pairing_id)
            .field("lifecycle", &self.lifecycle)
            .field("material", &"[REDACTED]")
            .finish_non_exhaustive()
    }
}

impl DurableInvite {
    fn from_store(record: PairingInviteRecord) -> Result<Self, PairingAdministrationError> {
        let pending_preparation =
            record
                .pair_pending_preparation()
                .map_err(store_error)?
                .map(|preparation| PendingPreparation {
                    request_hash: preparation.request_hash(),
                    info: preparation.info().clone(),
                    context: preparation.context().clone(),
                    recipient: preparation.recipient().clone(),
                });
        let pairing_id = record.pairing_id();
        let pair_route = PairRouteId::from_bytes(*record.pair_route().as_bytes());
        let lifecycle = record.lifecycle();
        let canonical_invite = SecretBytes::new(record.canonical_invite().to_vec());
        let canonical_open_frame = record.canonical_open_frame().to_vec();
        let request_hash = record.request_hash();
        let device_sign_fingerprint = record.device_sign_fingerprint();
        let request_received_at_ms = record.request_received_at_ms();
        let canonical_pair_request = record
            .canonical_pair_request()
            .map(|request| SecretBytes::new(request.to_vec()));
        let canonical_pending_frame = record.canonical_pending_frame().map(<[u8]>::to_vec);
        let invite_hpke_private_key = if lifecycle == PairingInviteLifecycle::Unused {
            Some(record.into_invite_hpke_private_key().map_err(store_error)?)
        } else {
            None
        };
        Ok(Self {
            pairing_id,
            pair_route,
            lifecycle,
            canonical_invite,
            canonical_open_frame,
            invite_hpke_private_key,
            request_hash,
            device_sign_fingerprint,
            request_received_at_ms,
            canonical_pair_request,
            pending_preparation,
            canonical_pending_frame,
        })
    }

    fn wire_invite(&self) -> Result<PairInvite, PairingAdministrationError> {
        let invite = PairInviteV1::from_canonical_bytes(self.canonical_invite.expose_secret())
            .map_err(|_| pairing_error(PAIRING_INVITE_INVALID))?;
        Ok(PairInvite {
            pairing_id: PairingId::new(self.pairing_id.to_canonical_string()),
            invite: Box::new(invite),
        })
    }

    fn open(&self) -> Result<OpenPairRoute, PairingAdministrationError> {
        let frame = decode(&self.canonical_open_frame)
            .map_err(|_| pairing_error(PAIRING_INVITE_INVALID))?;
        match frame.body {
            RelayFrameBody::OpenPairRoute(open)
                if open.pair_route == self.pair_route
                    && frame.version == RELAY_PROTOCOL_VERSION =>
            {
                Ok(open)
            }
            _ => Err(pairing_error(PAIRING_INVITE_INVALID)),
        }
    }

    fn pending(&self) -> Result<PendingPairing, PairingAdministrationError> {
        Ok(PendingPairing {
            pairing_id: PairingId::new(self.pairing_id.to_canonical_string()),
            request_hash: self
                .request_hash
                .ok_or_else(|| pairing_error(PAIRING_REQUEST_INVALID))?,
            device_sign_fingerprint: self
                .device_sign_fingerprint
                .ok_or_else(|| pairing_error(PAIRING_REQUEST_INVALID))?,
            requested_at_ms: self
                .request_received_at_ms
                .ok_or_else(|| pairing_error(PAIRING_REQUEST_INVALID))?,
            expires_at_ms: self.expires_at_ms()?,
        })
    }

    fn expires_at_ms(&self) -> Result<u64, PairingAdministrationError> {
        Ok(self.open()?.absolute_expiry_ms)
    }

    fn pending_frame(&self) -> Result<PairData, PairingAdministrationError> {
        let canonical = self
            .canonical_pending_frame
            .as_deref()
            .ok_or_else(|| pairing_error(PAIRING_REQUEST_INVALID))?;
        let frame = decode(canonical).map_err(|_| pairing_error(PAIRING_REQUEST_INVALID))?;
        match frame.body {
            RelayFrameBody::PairData(data)
                if frame.version == RELAY_PROTOCOL_VERSION
                    && data.pair_route == self.pair_route =>
            {
                Ok(data)
            }
            _ => Err(pairing_error(PAIRING_REQUEST_INVALID)),
        }
    }
}

#[async_trait]
trait PairingStore: Send + Sync {
    async fn prepare(
        &self,
        owner: IdempotencyOwner,
        idempotency_key: String,
        canonical_invite: SecretBytes,
        invite_hpke_private_key: SecretBytes,
    ) -> Result<DurableInvite, PairingAdministrationError>;

    async fn acknowledge_open(
        &self,
        pairing_id: RuntimeId,
        canonical_terminal: Vec<u8>,
    ) -> Result<DurableInvite, PairingAdministrationError>;

    async fn recover(&self) -> Result<Vec<DurableInvite>, PairingAdministrationError>;

    async fn load(
        &self,
        pairing_id: RuntimeId,
    ) -> Result<Option<DurableInvite>, PairingAdministrationError>;

    async fn accept_request(
        &self,
        pairing_id: RuntimeId,
        verified: VerifiedPairRequestV1,
    ) -> Result<DurableInvite, PairingAdministrationError>;

    async fn replay_request(
        &self,
        pairing_id: RuntimeId,
        canonical_request: SecretBytes,
    ) -> Result<DurableInvite, PairingAdministrationError>;

    async fn load_winner(
        &self,
        pairing_id: RuntimeId,
    ) -> Result<Option<(PairingReceipt, PairingState)>, PairingAdministrationError>;

    async fn commit_pending(
        &self,
        pairing_id: RuntimeId,
        request_hash: [u8; 32],
        envelope: PairingControlEnvelopeV1,
    ) -> Result<DurableInvite, PairingAdministrationError>;

    async fn load_grant_preparation(
        &self,
        pairing_id: RuntimeId,
    ) -> Result<GrantPreparationInput, PairingAdministrationError>;

    async fn load_grant_allocation(
        &self,
        pairing_id: RuntimeId,
        device_sign_fingerprint: [u8; 32],
    ) -> Result<GrantAllocationInput, PairingAdministrationError>;

    async fn confirm_grant(
        &self,
        input: FrozenGrantInput,
    ) -> Result<GrantCommitOutcome, PairingAdministrationError>;

    async fn recover_grants(&self) -> Result<Vec<DurableGrant>, PairingAdministrationError>;

    async fn acknowledge_grant_committed(
        &self,
        pairing_id: RuntimeId,
        committed: GrantCommitted,
        canonical_terminal: Vec<u8>,
    ) -> Result<DurableResponse, PairingAdministrationError>;

    async fn recover_committed(&self) -> Result<Vec<DurableResponse>, PairingAdministrationError>;

    async fn acknowledge_delivery(
        &self,
        input: DeliveryProofInput,
    ) -> Result<DeliveryOutcome, PairingAdministrationError>;

    async fn load_revocation_target(
        &self,
        device: DeviceHandle,
        grant_serial: RuntimeGrantSerial,
    ) -> Result<Option<RevocationTargetOutcome>, PairingAdministrationError>;

    async fn due_revocation_targets(
        &self,
    ) -> Result<Vec<RevocationTargetInput>, PairingAdministrationError>;

    async fn drain_revocation_targets(
        &self,
    ) -> Result<Vec<RevocationTargetInput>, PairingAdministrationError>;

    async fn begin_revocation(
        &self,
        input: FrozenRevocationInput,
    ) -> Result<BeginRevocationOutcome, PairingAdministrationError>;

    async fn acknowledge_orphan_grant_committed(
        &self,
        pairing_id: RuntimeId,
        committed: GrantCommitted,
        canonical_terminal: Vec<u8>,
    ) -> Result<DurableRevocation, PairingAdministrationError>;

    async fn recover_revocations(
        &self,
    ) -> Result<Vec<DurableRevocation>, PairingAdministrationError>;

    async fn acknowledge_revocation_committed(
        &self,
        committed: RevocationCommitted,
        canonical_terminal: Vec<u8>,
    ) -> Result<DeviceRevocation, PairingAdministrationError>;

    async fn terminalize(
        &self,
        pairing_id: RuntimeId,
        action: PairingTerminalAction,
    ) -> Result<TerminalOutcome, PairingAdministrationError>;

    async fn terminalize_due(&self) -> Result<Vec<TerminalOutcome>, PairingAdministrationError>;

    async fn recover_terminals(&self) -> Result<Vec<DurableClose>, PairingAdministrationError>;

    async fn acknowledge_close(
        &self,
        pairing_id: RuntimeId,
        canonical_terminal: Vec<u8>,
    ) -> Result<PairingReceipt, PairingAdministrationError>;

    async fn purge_expired_receipts(&self) -> Result<bool, PairingAdministrationError>;
}

struct ProductionPairingStore(RuntimeStoreHandle);

#[async_trait]
impl PairingStore for ProductionPairingStore {
    async fn prepare(
        &self,
        owner: IdempotencyOwner,
        idempotency_key: String,
        canonical_invite: SecretBytes,
        invite_hpke_private_key: SecretBytes,
    ) -> Result<DurableInvite, PairingAdministrationError> {
        let outcome = self
            .0
            .prepare_pairing_invite(PreparePairingInvite::new(
                owner,
                idempotency_key,
                canonical_invite,
                invite_hpke_private_key,
            ))
            .await
            .map_err(store_error)?;
        let record = match outcome {
            PreparePairingInviteOutcome::Prepared { invite }
            | PreparePairingInviteOutcome::Replayed { invite } => invite,
            PreparePairingInviteOutcome::Terminal { receipt, state: _ } => {
                return Err(create_terminal_error(receipt));
            }
        };
        DurableInvite::from_store(record)
    }

    async fn acknowledge_open(
        &self,
        pairing_id: RuntimeId,
        canonical_terminal: Vec<u8>,
    ) -> Result<DurableInvite, PairingAdministrationError> {
        let outcome = self
            .0
            .acknowledge_pair_route_open(pairing_id, canonical_terminal)
            .await
            .map_err(store_error)?;
        // Clone-free Store API: ACK readback remains borrowed, so load the authenticated row.
        let _ = outcome.replayed();
        let record = self
            .0
            .load_pairing_invite(pairing_id)
            .await
            .map_err(store_error)?
            .ok_or_else(|| pairing_error(PAIRING_INVITE_INVALID))?;
        DurableInvite::from_store(record)
    }

    async fn recover(&self) -> Result<Vec<DurableInvite>, PairingAdministrationError> {
        let records = self.0.list_pairing_recovery().await.map_err(store_error)?;
        records.into_iter().map(DurableInvite::from_store).collect()
    }

    async fn load(
        &self,
        pairing_id: RuntimeId,
    ) -> Result<Option<DurableInvite>, PairingAdministrationError> {
        self.0
            .load_pairing_invite(pairing_id)
            .await
            .map_err(store_error)?
            .map(DurableInvite::from_store)
            .transpose()
    }

    async fn accept_request(
        &self,
        pairing_id: RuntimeId,
        verified: VerifiedPairRequestV1,
    ) -> Result<DurableInvite, PairingAdministrationError> {
        let outcome = self
            .0
            .accept_pair_request(AcceptPairRequest::new(pairing_id, verified))
            .await
            .map_err(store_error)?;
        let record = match outcome {
            AcceptPairRequestOutcome::Accepted { pairing }
            | AcceptPairRequestOutcome::Replayed { pairing } => pairing,
        };
        DurableInvite::from_store(record)
    }

    async fn replay_request(
        &self,
        pairing_id: RuntimeId,
        canonical_request: SecretBytes,
    ) -> Result<DurableInvite, PairingAdministrationError> {
        let record = self
            .0
            .replay_pair_request(pairing_id, canonical_request)
            .await
            .map_err(store_error)?;
        DurableInvite::from_store(record)
    }

    async fn load_winner(
        &self,
        pairing_id: RuntimeId,
    ) -> Result<Option<(PairingReceipt, PairingState)>, PairingAdministrationError> {
        self.0
            .load_pairing_winner(pairing_id)
            .await
            .map(|winner| winner.map(|winner| (winner.receipt().clone(), winner.state())))
            .map_err(store_error)
    }

    async fn commit_pending(
        &self,
        pairing_id: RuntimeId,
        request_hash: [u8; 32],
        envelope: PairingControlEnvelopeV1,
    ) -> Result<DurableInvite, PairingAdministrationError> {
        let outcome = self
            .0
            .commit_pair_pending(CommitPairPending::new(pairing_id, request_hash, envelope))
            .await
            .map_err(store_error)?;
        let record = match outcome {
            CommitPairPendingOutcome::Committed { pairing }
            | CommitPairPendingOutcome::Replayed { pairing } => pairing,
        };
        DurableInvite::from_store(record)
    }

    async fn load_grant_preparation(
        &self,
        pairing_id: RuntimeId,
    ) -> Result<GrantPreparationInput, PairingAdministrationError> {
        let record = self
            .0
            .load_pairing_invite(pairing_id)
            .await
            .map_err(store_error)?
            .ok_or_else(|| pairing_error(PAIRING_REQUEST_INVALID))?;
        record
            .into_grant_preparation()
            .map(GrantPreparationInput::from_store)
            .map_err(store_error)
    }

    async fn load_grant_allocation(
        &self,
        pairing_id: RuntimeId,
        device_sign_fingerprint: [u8; 32],
    ) -> Result<GrantAllocationInput, PairingAdministrationError> {
        self.0
            .load_grant_allocation(pairing_id, device_sign_fingerprint)
            .await
            .map(GrantAllocationInput::Production)
            .map_err(store_error)
    }

    async fn confirm_grant(
        &self,
        input: FrozenGrantInput,
    ) -> Result<GrantCommitOutcome, PairingAdministrationError> {
        let pairing_id = input.pairing_id;
        let request_hash = input.request_hash;
        let production = input
            .production
            .ok_or_else(|| pairing_error(PAIRING_GRANT_RECOVERY_UNAVAILABLE))?;
        match self.0.confirm_pairing_grant(production).await {
            Ok(outcome) => grant_outcome_from_store(outcome),
            Err(error)
                if matches!(
                    error,
                    RuntimeStoreError::CommitOutcomeUnknown {
                        operation: RuntimeCommitOperation::ConfirmPairingGrant
                    }
                ) =>
            {
                let recoveries = self
                    .0
                    .list_grant_preparing_recovery()
                    .await
                    .map_err(store_error)?;
                let mut matching = recoveries.iter().filter(|recovery| {
                    recovery.pairing_id() == pairing_id && recovery.request_hash() == request_hash
                });
                let Some(recovery) = matching.next() else {
                    return Err(store_error(error));
                };
                if matching.next().is_some() {
                    return Err(pairing_error(PAIRING_GRANT_RECOVERY_UNAVAILABLE));
                }
                let grant = DurableGrant::from_store(recovery)?;
                Ok(GrantCommitOutcome::Committed {
                    reply: grant.receipt.clone(),
                    grant: Box::new(grant),
                })
            }
            Err(error) => Err(store_error(error)),
        }
    }

    async fn recover_grants(&self) -> Result<Vec<DurableGrant>, PairingAdministrationError> {
        self.0
            .list_grant_preparing_recovery()
            .await
            .map_err(store_error)?
            .iter()
            .map(DurableGrant::from_store)
            .collect()
    }

    async fn acknowledge_grant_committed(
        &self,
        pairing_id: RuntimeId,
        committed: GrantCommitted,
        canonical_terminal: Vec<u8>,
    ) -> Result<DurableResponse, PairingAdministrationError> {
        match self
            .0
            .acknowledge_grant_committed(AcknowledgeGrantCommitted::new(
                pairing_id,
                canonical_terminal,
            ))
            .await
        {
            Ok(outcome) => committed_response_from_store(outcome),
            Err(error)
                if matches!(
                    error,
                    RuntimeStoreError::CommitOutcomeUnknown {
                        operation: RuntimeCommitOperation::AcknowledgeGrantCommitted
                    }
                ) =>
            {
                let recoveries = match self.0.list_grant_committed_recovery().await {
                    Ok(recoveries) => recoveries,
                    Err(_) => return Err(store_error(error)),
                };
                let mut matching = recoveries.iter().filter(|recovery| {
                    recovery.pairing_id() == pairing_id
                        && recovery.device_route() == committed.device_route
                        && recovery.grant_serial() == committed.grant_serial
                        && recovery.grant_hash() == committed.grant_hash
                });
                let Some(recovery) = matching.next() else {
                    return Err(store_error(error));
                };
                if matching.next().is_some() {
                    return Err(store_error(error));
                }
                DurableResponse::from_store(recovery)
            }
            Err(error) => Err(store_error(error)),
        }
    }

    async fn recover_committed(&self) -> Result<Vec<DurableResponse>, PairingAdministrationError> {
        self.0
            .list_grant_committed_recovery()
            .await
            .map_err(store_error)?
            .iter()
            .map(DurableResponse::from_store)
            .collect()
    }

    async fn acknowledge_delivery(
        &self,
        input: DeliveryProofInput,
    ) -> Result<DeliveryOutcome, PairingAdministrationError> {
        let proof = input
            .production
            .as_ref()
            .ok_or_else(|| pairing_error(PAIRING_GRANT_RECOVERY_UNAVAILABLE))?;
        let first = self
            .0
            .acknowledge_pair_response_received(AcknowledgePairResponseReceived::new(
                input.pairing_id,
                proof,
            ))
            .await;
        let outcome = match first {
            Err(RuntimeStoreError::CommitOutcomeUnknown {
                operation: RuntimeCommitOperation::AcknowledgePairResponseReceived,
            }) => self
                .0
                .acknowledge_pair_response_received(AcknowledgePairResponseReceived::new(
                    input.pairing_id,
                    proof,
                ))
                .await
                .map_err(store_error)?,
            Ok(outcome) => outcome,
            Err(error) => return Err(store_error(error)),
        };
        let outcome = delivery_outcome_from_store(outcome)?;
        if outcome.close.pairing_id != input.pairing_id
            || outcome.close.pair_route != input.pair_route
        {
            return Err(pairing_error(PAIRING_TERMINAL_INVALID));
        }
        Ok(outcome)
    }

    async fn load_revocation_target(
        &self,
        device: DeviceHandle,
        grant_serial: RuntimeGrantSerial,
    ) -> Result<Option<RevocationTargetOutcome>, PairingAdministrationError> {
        let Some(status) = self
            .0
            .load_revocation_target(&device, grant_serial)
            .await
            .map_err(store_error)?
        else {
            return Ok(None);
        };
        Ok(Some(match status {
            RevocationTargetStatus::Ready { target } => {
                if target.device() != &device
                    || target.grant().grant_serial.value() != grant_serial.0
                {
                    return Err(pairing_error(REVOCATION_RECOVERY_UNAVAILABLE));
                }
                RevocationTargetOutcome::Ready(RevocationTargetInput {
                    pairing_id: target.pairing_id(),
                    device,
                    grant: target.grant().clone(),
                })
            }
            RevocationTargetStatus::Revoking { recovery } => {
                let recovery = DurableRevocation::from_store(&recovery)?;
                if !device_matches_route(&device, recovery.revocation.device_route)
                    || recovery.revocation.grant_serial.value() != grant_serial.0
                {
                    return Err(pairing_error(REVOCATION_RECOVERY_UNAVAILABLE));
                }
                RevocationTargetOutcome::Revoking(recovery)
            }
            RevocationTargetStatus::Revoked { revocation } => {
                if !device_matches_route(&device, revocation.device_route)
                    || revocation.grant_serial.value() != grant_serial.0
                {
                    return Err(pairing_error(REVOCATION_RECOVERY_UNAVAILABLE));
                }
                RevocationTargetOutcome::Revoked(revocation)
            }
        }))
    }

    async fn due_revocation_targets(
        &self,
    ) -> Result<Vec<RevocationTargetInput>, PairingAdministrationError> {
        self.0
            .list_due_orphan_revocation_targets()
            .await
            .map_err(store_error)?
            .into_iter()
            .map(|target| {
                if target.pairing_id().is_none()
                    || !device_matches_route(target.device(), target.grant().device_route)
                {
                    return Err(pairing_error(REVOCATION_RECOVERY_UNAVAILABLE));
                }
                Ok(RevocationTargetInput {
                    pairing_id: target.pairing_id(),
                    device: target.device().clone(),
                    grant: target.grant().clone(),
                })
            })
            .collect()
    }

    async fn drain_revocation_targets(
        &self,
    ) -> Result<Vec<RevocationTargetInput>, PairingAdministrationError> {
        self.0
            .list_revocation_drain_targets()
            .await
            .map_err(store_error)?
            .into_iter()
            .map(|target| {
                if target.pairing_id().is_some()
                    || !device_matches_route(target.device(), target.grant().device_route)
                {
                    return Err(pairing_error(REVOCATION_RECOVERY_UNAVAILABLE));
                }
                Ok(RevocationTargetInput {
                    pairing_id: None,
                    device: target.device().clone(),
                    grant: target.grant().clone(),
                })
            })
            .collect()
    }

    async fn begin_revocation(
        &self,
        input: FrozenRevocationInput,
    ) -> Result<BeginRevocationOutcome, PairingAdministrationError> {
        let pairing_id = input.pairing_id;
        let expected = input.revocation.clone();
        let store_input = match pairing_id {
            Some(pairing_id) => BeginDeviceRevocation::orphan(pairing_id, input.revocation),
            None => BeginDeviceRevocation::local(input.revocation),
        };
        match self.0.begin_device_revocation(store_input).await {
            Ok(outcome) => begin_revocation_from_store(outcome, pairing_id, &expected),
            Err(error)
                if matches!(
                    error,
                    RuntimeStoreError::CommitOutcomeUnknown {
                        operation: RuntimeCommitOperation::BeginDeviceRevocation
                    }
                ) =>
            {
                let recoveries = self
                    .0
                    .list_revocation_recovery()
                    .await
                    .map_err(store_error)?;
                let mut matching = recoveries.iter().filter(|recovery| {
                    (pairing_id.is_none() || recovery.pairing_id() == pairing_id)
                        && recovery.device_route() == expected.device_route
                        && recovery.grant_serial() == expected.grant_serial
                        && recovery.revocation() == &expected
                });
                let Some(recovery) = matching.next() else {
                    return Err(store_error(error));
                };
                if matching.next().is_some() {
                    return Err(pairing_error(REVOCATION_RECOVERY_UNAVAILABLE));
                }
                Ok(BeginRevocationOutcome::Recovering(Box::new(
                    DurableRevocation::from_store(recovery)?,
                )))
            }
            Err(error) => Err(store_error(error)),
        }
    }

    async fn acknowledge_orphan_grant_committed(
        &self,
        pairing_id: RuntimeId,
        committed: GrantCommitted,
        canonical_terminal: Vec<u8>,
    ) -> Result<DurableRevocation, PairingAdministrationError> {
        let first = self
            .0
            .acknowledge_orphan_grant_committed(pairing_id, canonical_terminal.clone())
            .await;
        let outcome = match first {
            Err(RuntimeStoreError::CommitOutcomeUnknown {
                operation: RuntimeCommitOperation::AcknowledgeOrphanGrantCommitted,
            }) => self
                .0
                .acknowledge_orphan_grant_committed(pairing_id, canonical_terminal)
                .await
                .map_err(store_error)?,
            Ok(outcome) => outcome,
            Err(error) => return Err(store_error(error)),
        };
        let recovery = match outcome {
            AcknowledgeOrphanGrantCommittedOutcome::Advanced { recovery }
            | AcknowledgeOrphanGrantCommittedOutcome::Replayed { recovery } => recovery,
        };
        let durable = DurableRevocation::from_store(&recovery)?;
        if durable.pairing_id != Some(pairing_id)
            || durable.phase != DurableRevocationPhase::ReadyToRevoke
            || durable.grant.device_route != committed.device_route
            || durable.grant.grant_serial != committed.grant_serial
            || durable.grant.canonical_sha256() != committed.grant_hash
        {
            return Err(pairing_error(REVOCATION_RECOVERY_UNAVAILABLE));
        }
        Ok(durable)
    }

    async fn recover_revocations(
        &self,
    ) -> Result<Vec<DurableRevocation>, PairingAdministrationError> {
        self.0
            .list_revocation_recovery()
            .await
            .map_err(store_error)?
            .iter()
            .map(DurableRevocation::from_store)
            .collect()
    }

    async fn acknowledge_revocation_committed(
        &self,
        committed: RevocationCommitted,
        canonical_terminal: Vec<u8>,
    ) -> Result<DeviceRevocation, PairingAdministrationError> {
        let first = self
            .0
            .acknowledge_revocation_committed(AcknowledgeRevocationCommitted::new(
                canonical_terminal.clone(),
            ))
            .await;
        let outcome = match first {
            Err(RuntimeStoreError::CommitOutcomeUnknown {
                operation: RuntimeCommitOperation::AcknowledgeRevocationCommitted,
            }) => self
                .0
                .acknowledge_revocation_committed(AcknowledgeRevocationCommitted::new(
                    canonical_terminal,
                ))
                .await
                .map_err(store_error)?,
            Ok(outcome) => outcome,
            Err(error) => return Err(store_error(error)),
        };
        let revocation = match outcome {
            AcknowledgeRevocationCommittedOutcome::Committed { revocation }
            | AcknowledgeRevocationCommittedOutcome::Replayed { revocation } => revocation,
        };
        if revocation != committed.signed_revocation
            || revocation.device_route != committed.device_route
            || revocation.grant_serial != committed.grant_serial
        {
            return Err(pairing_error(REVOCATION_RECOVERY_UNAVAILABLE));
        }
        Ok(revocation)
    }

    async fn terminalize(
        &self,
        pairing_id: RuntimeId,
        action: PairingTerminalAction,
    ) -> Result<TerminalOutcome, PairingAdministrationError> {
        let outcome = self
            .0
            .terminalize_pairing(pairing_id, action)
            .await
            .map_err(store_error)?;
        terminal_outcome_from_store(outcome)
    }

    async fn terminalize_due(&self) -> Result<Vec<TerminalOutcome>, PairingAdministrationError> {
        self.0
            .terminalize_due_pairings()
            .await
            .map_err(store_error)?
            .into_iter()
            .map(terminal_outcome_from_store)
            .collect()
    }

    async fn recover_terminals(&self) -> Result<Vec<DurableClose>, PairingAdministrationError> {
        self.0
            .list_pairing_terminal_recovery()
            .await
            .map_err(store_error)?
            .iter()
            .map(terminal_recovery_from_store)
            .collect()
    }

    async fn acknowledge_close(
        &self,
        pairing_id: RuntimeId,
        canonical_terminal: Vec<u8>,
    ) -> Result<PairingReceipt, PairingAdministrationError> {
        let first = self
            .0
            .acknowledge_pair_route_close(pairing_id, canonical_terminal.clone())
            .await;
        let outcome = match first {
            Err(RuntimeStoreError::CommitOutcomeUnknown {
                operation: RuntimeCommitOperation::AcknowledgePairRouteClose,
            }) => self
                .0
                .acknowledge_pair_route_close(pairing_id, canonical_terminal)
                .await
                .map_err(store_error)?,
            Ok(outcome) => outcome,
            Err(error) => return Err(store_error(error)),
        };
        let _ = outcome.replayed();
        Ok(outcome.receipt().clone())
    }

    async fn purge_expired_receipts(&self) -> Result<bool, PairingAdministrationError> {
        let Some(plan) = self
            .0
            .plan_expired_pairing_receipt_purge()
            .await
            .map_err(store_error)?
        else {
            return Ok(false);
        };
        let first = self.0.apply_pairing_receipt_purge(plan.clone()).await;
        let outcome = match first {
            Err(RuntimeStoreError::CommitOutcomeUnknown {
                operation: RuntimeCommitOperation::PurgePairingReceipts,
            }) => self
                .0
                .apply_pairing_receipt_purge(plan)
                .await
                .map_err(store_error)?,
            Ok(outcome) => outcome,
            Err(error) => return Err(store_error(error)),
        };
        Ok(outcome.has_more())
    }
}

#[async_trait]
trait PairingLane: Send {
    async fn send_open(&self, frame: OpenPairRoute) -> Result<(), PairingAdministrationError>;
    async fn send_data(&self, frame: PairData) -> Result<(), PairingAdministrationError>;
    async fn send_install(&self, frame: InstallGrant) -> Result<(), PairingAdministrationError>;
    async fn send_revoke(&self, frame: RevokeDevice) -> Result<(), PairingAdministrationError>;
    async fn send_close(&self, frame: ClosePairRoute) -> Result<(), PairingAdministrationError>;
    async fn reconnect(&self) -> Result<(), PairingAdministrationError>;
    fn yield_shared_control(&mut self) -> Result<(), PairingAdministrationError>;
    async fn next_event(
        &mut self,
    ) -> Result<Option<PairingTransportEvent>, PairingAdministrationError>;
}

struct ProductionPairingLane(PairingTransportLane);

#[async_trait]
impl PairingLane for ProductionPairingLane {
    async fn send_open(&self, frame: OpenPairRoute) -> Result<(), PairingAdministrationError> {
        self.0
            .send_open_pair_route(frame)
            .await
            .map_err(transport_error)
    }

    async fn send_data(&self, frame: PairData) -> Result<(), PairingAdministrationError> {
        self.0.send_pair_data(frame).await.map_err(transport_error)
    }

    async fn send_install(&self, frame: InstallGrant) -> Result<(), PairingAdministrationError> {
        self.0
            .send_install_grant(frame)
            .await
            .map_err(transport_error)
    }

    async fn send_revoke(&self, frame: RevokeDevice) -> Result<(), PairingAdministrationError> {
        self.0
            .send_revoke_device(frame)
            .await
            .map_err(transport_error)
    }

    async fn send_close(&self, frame: ClosePairRoute) -> Result<(), PairingAdministrationError> {
        self.0
            .send_close_pair_route(frame)
            .await
            .map_err(transport_error)
    }

    async fn reconnect(&self) -> Result<(), PairingAdministrationError> {
        self.0.reconnect().await.map_err(transport_error)
    }

    fn yield_shared_control(&mut self) -> Result<(), PairingAdministrationError> {
        self.0.yield_shared_control().map_err(transport_error)
    }

    async fn next_event(
        &mut self,
    ) -> Result<Option<PairingTransportEvent>, PairingAdministrationError> {
        self.0.next_event().await.map_err(transport_error)
    }
}

trait PairingAuthority: Send {
    fn seal_pending(
        &self,
        preparation: &PendingPreparation,
    ) -> Result<PairingControlEnvelopeV1, PairingAdministrationError>;

    fn freeze_grant(
        &self,
        preparation: &GrantPreparationInput,
        allocation: GrantAllocationInput,
    ) -> Result<FrozenGrantInput, PairingAdministrationError>;

    fn verify_delivery(
        &self,
        response: &DurableResponse,
        canonical_envelope: &[u8],
    ) -> Result<DeliveryProofInput, PairingAdministrationError>;

    fn freeze_revocation(
        &self,
        grant: &RelayGrant,
    ) -> Result<DeviceRevocation, PairingAdministrationError>;
}

struct ProductionPairingAuthority {
    authority: PairingMachineAuthority,
    invite_anchor: PairingInviteAnchor,
}

impl PairingAuthority for ProductionPairingAuthority {
    fn seal_pending(
        &self,
        preparation: &PendingPreparation,
    ) -> Result<PairingControlEnvelopeV1, PairingAdministrationError> {
        self.authority
            .seal_pair_pending(
                &preparation.recipient,
                &preparation.info,
                &preparation.context,
                preparation.request_hash,
            )
            .map_err(transport_error)
    }

    fn freeze_grant(
        &self,
        preparation: &GrantPreparationInput,
        allocation: GrantAllocationInput,
    ) -> Result<FrozenGrantInput, PairingAdministrationError> {
        let production = preparation
            .production
            .as_ref()
            .ok_or_else(|| pairing_error(PAIRING_GRANT_RECOVERY_UNAVAILABLE))?;
        #[cfg(not(test))]
        let GrantAllocationInput::Production(projection) = allocation;
        #[cfg(test)]
        let projection = match allocation {
            GrantAllocationInput::Production(projection) => projection,
            GrantAllocationInput::Test { .. } => {
                return Err(pairing_error(PAIRING_GRANT_RECOVERY_UNAVAILABLE));
            }
        };
        let input = GrantFreezeBuilder::from_projection(
            production,
            &self.invite_anchor,
            &self.authority,
            projection,
        )
        .map_err(|error| pairing_error(error.code()))?
        .freeze()
        .map_err(|error| pairing_error(error.code()))?
        .into_store_input();
        Ok(FrozenGrantInput {
            pairing_id: preparation.pairing_id,
            request_hash: preparation.request_hash,
            production: Some(input),
        })
    }

    fn verify_delivery(
        &self,
        response: &DurableResponse,
        canonical_envelope: &[u8],
    ) -> Result<DeliveryProofInput, PairingAdministrationError> {
        response
            .verify_receipt(canonical_envelope)
            .map(|proof| DeliveryProofInput::from_verified(response.pairing_id, proof))
    }

    fn freeze_revocation(
        &self,
        grant: &RelayGrant,
    ) -> Result<DeviceRevocation, PairingAdministrationError> {
        DeviceRevocationFreezer::new(&self.authority, self.invite_anchor.relay_server_id(), grant)
            .freeze()
            .map(|frozen| frozen.into_revocation())
            .map_err(|error| pairing_error(error.code()))
    }
}

struct PairingCoordinator {
    store: Arc<dyn PairingStore>,
    lane: Box<dyn PairingLane>,
    authority: Box<dyn PairingAuthority>,
    invite_context: PairingInviteContext,
    pending_sink: Arc<dyn PairingPendingSink>,
    waiters:
        HashMap<RuntimeId, Vec<oneshot::Sender<Result<PairInvite, PairingAdministrationError>>>>,
    revocation_waiters: HashMap<
        RevocationKey,
        Vec<oneshot::Sender<Result<RevocationReceipt, PairingAdministrationError>>>,
    >,
    routes: BTreeMap<[u8; 16], RuntimeId>,
    opened_routes: HashSet<[u8; 16]>,
    drain: PairingDrainState,
    recovery_state: PairingRecoveryState,
    health_tx: watch::Sender<PairingCoordinatorHealth>,
    admission_epoch: u64,
    admission_tx: watch::Sender<PairingAdmissionFence>,
}

impl PairingCoordinator {
    fn new(
        store: Arc<dyn PairingStore>,
        lane: Box<dyn PairingLane>,
        authority: PairingMachineAuthority,
        invite_anchor: PairingInviteAnchor,
        invite_context: PairingInviteContext,
        pending_sink: Arc<dyn PairingPendingSink>,
        signals: PairingCoordinatorSignals,
    ) -> Self {
        let PairingCoordinatorSignals {
            health_tx,
            admission_tx,
        } = signals;
        Self {
            store,
            lane,
            authority: Box::new(ProductionPairingAuthority {
                authority,
                invite_anchor,
            }),
            invite_context,
            pending_sink,
            waiters: HashMap::new(),
            revocation_waiters: HashMap::new(),
            routes: BTreeMap::new(),
            opened_routes: HashSet::new(),
            drain: PairingDrainState::Idle,
            recovery_state: PairingRecoveryState::Healthy,
            health_tx,
            admission_epoch: 0,
            admission_tx,
        }
    }

    #[cfg(test)]
    fn new_for_test(
        store: Arc<dyn PairingStore>,
        lane: Box<dyn PairingLane>,
        authority: Box<dyn PairingAuthority>,
        invite_context: PairingInviteContext,
        pending_sink: Arc<dyn PairingPendingSink>,
        signals: PairingCoordinatorSignals,
    ) -> Self {
        let PairingCoordinatorSignals {
            health_tx,
            admission_tx,
        } = signals;
        Self {
            store,
            lane,
            authority,
            invite_context,
            pending_sink,
            waiters: HashMap::new(),
            revocation_waiters: HashMap::new(),
            routes: BTreeMap::new(),
            opened_routes: HashSet::new(),
            drain: PairingDrainState::Idle,
            recovery_state: PairingRecoveryState::Healthy,
            health_tx,
            admission_epoch: 0,
            admission_tx,
        }
    }

    async fn run(
        mut self,
        mut command_rx: mpsc::Receiver<PairingCommandEnvelope>,
        mut cancel_rx: watch::Receiver<bool>,
        ready: oneshot::Sender<Result<(), PairingAdministrationError>>,
    ) {
        let mut recovery_tick = tokio::time::interval_at(
            tokio::time::Instant::now() + RECONNECT_RETRY_DELAY,
            RECONNECT_RETRY_DELAY,
        );
        recovery_tick.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Delay);
        let mut expiry_tick = tokio::time::interval_at(
            tokio::time::Instant::now() + EXPIRY_RECONCILE_INTERVAL,
            EXPIRY_RECONCILE_INTERVAL,
        );
        expiry_tick.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Delay);
        // 所有启动/本地重试都从 retention purge 开始；purge 失败时 recover 必须为零。
        let startup = self.purge_then_recover_generation().await;
        match &startup {
            Ok(()) => self.set_healthy(),
            Err(error) => self.set_failure(error),
        }
        let _ = ready.send(startup);
        loop {
            if *cancel_rx.borrow() {
                break;
            }
            if let Some(error) = self.local_retry_error() {
                while let Ok(envelope) = command_rx.try_recv() {
                    Self::reject_command(envelope.command, error.clone());
                }
                tokio::select! {
                    biased;
                    changed = cancel_rx.changed() => {
                        if changed.is_err() || *cancel_rx.borrow() { break; }
                    }
                    envelope = command_rx.recv() => {
                        let Some(envelope) = envelope else { break; };
                        Self::reject_command(envelope.command, error);
                    }
                    _ = recovery_tick.tick() => {
                        self.try_local_recovery().await;
                    }
                }
            } else if self.is_transport_retry() {
                tokio::select! {
                    biased;
                    changed = cancel_rx.changed() => {
                        if changed.is_err() || *cancel_rx.borrow() { break; }
                    }
                    _ = recovery_tick.tick() => {
                        self.try_reconnect().await;
                    }
                    _ = expiry_tick.tick() => self.handle_expiry_tick().await,
                    envelope = command_rx.recv() => {
                        let Some(envelope) = envelope else { break; };
                        self.handle_command(envelope).await;
                    }
                }
            } else {
                tokio::select! {
                    biased;
                    changed = cancel_rx.changed() => {
                        if changed.is_err() || *cancel_rx.borrow() { break; }
                    }
                    _ = expiry_tick.tick() => self.handle_expiry_tick().await,
                    envelope = command_rx.recv() => {
                        let Some(envelope) = envelope else { break; };
                        self.handle_command(envelope).await;
                    }
                    event = self.lane.next_event() => self.handle_event(event).await,
                }
            }
        }
        self.fail_waiters(pairing_error(PAIRING_STOPPED));
        self.fail_drain(pairing_error(PAIRING_STOPPED));
    }

    fn set_healthy(&mut self) {
        self.recovery_state = PairingRecoveryState::Healthy;
        self.health_tx
            .send_replace(PairingCoordinatorHealth::Healthy);
    }

    fn set_failure(&mut self, error: &PairingAdministrationError) {
        let code = error.code().to_owned();
        if is_transport_failure(error) {
            self.recovery_state = PairingRecoveryState::TransportRetry(code.clone());
            self.health_tx
                .send_replace(PairingCoordinatorHealth::TransportRetry(code));
        } else {
            let entering_local_retry =
                !matches!(self.recovery_state, PairingRecoveryState::LocalRetry(_));
            self.recovery_state = PairingRecoveryState::LocalRetry(code.clone());
            self.health_tx
                .send_replace(PairingCoordinatorHealth::LocalBlocked(code.clone()));
            if entering_local_retry {
                self.admission_epoch = self.admission_epoch.saturating_add(1);
            }
            self.admission_tx.send_replace(PairingAdmissionFence {
                epoch: self.admission_epoch,
                failure_code: Some(code),
            });
        }
    }

    fn set_transport_failure(&mut self, error: &PairingAdministrationError) {
        debug_assert!(is_transport_failure(error));
        self.set_failure(error);
    }

    fn is_transport_retry(&self) -> bool {
        matches!(self.recovery_state, PairingRecoveryState::TransportRetry(_))
    }

    fn is_healthy(&self) -> bool {
        matches!(self.recovery_state, PairingRecoveryState::Healthy)
    }

    fn local_retry_error(&self) -> Option<PairingAdministrationError> {
        match &self.recovery_state {
            PairingRecoveryState::LocalRetry(code) => Some(pairing_error(code)),
            PairingRecoveryState::Healthy | PairingRecoveryState::TransportRetry(_) => None,
        }
    }

    fn reject_command(command: PairingCommand, error: PairingAdministrationError) {
        match command {
            PairingCommand::Create { reply, .. } => {
                let _ = reply.send(Err(error));
            }
            PairingCommand::Cancel { reply, .. } | PairingCommand::Confirm { reply, .. } => {
                let _ = reply.send(Err(error));
            }
            PairingCommand::RevokeDevice { reply, .. } => {
                let _ = reply.send(Err(error));
            }
            PairingCommand::BeginDrain { reply } => {
                let _ = reply.send(Err(PairingDrainActorError::Failed(error)));
            }
            PairingCommand::ResumeAfterFailedDrain { reply }
            | PairingCommand::ResumeAfterCompletedDrain { reply } => {
                let _ = reply.send(Err(error));
            }
        }
    }

    async fn handle_command(&mut self, envelope: PairingCommandEnvelope) {
        if envelope.admission_epoch != self.admission_epoch {
            let code = self
                .admission_tx
                .borrow()
                .failure_code
                .clone()
                .unwrap_or_else(|| PAIRING_STOPPED.to_owned());
            Self::reject_command(envelope.command, pairing_error(code));
            return;
        }
        match envelope.command {
            PairingCommand::Create {
                owner,
                request,
                reply,
            } => self.create(owner, request, reply).await,
            PairingCommand::Cancel { pairing_id, reply } => {
                let result = self.cancel(pairing_id).await;
                let _ = reply.send(result);
            }
            PairingCommand::Confirm { pairing_id, reply } => {
                let result = self.confirm(pairing_id).await;
                let _ = reply.send(result);
            }
            PairingCommand::RevokeDevice {
                device,
                grant_serial,
                reply,
            } => self.revoke_device(device, grant_serial, reply).await,
            PairingCommand::BeginDrain { reply } => self.begin_drain(reply).await,
            PairingCommand::ResumeAfterFailedDrain { reply } => {
                let _ = reply.send(self.resume_after_failed_drain());
            }
            PairingCommand::ResumeAfterCompletedDrain { reply } => {
                let _ = reply.send(self.resume_after_completed_drain());
            }
        }
    }

    async fn create(
        &mut self,
        owner: IdempotencyOwner,
        request: CreatePairInviteRequest,
        reply: oneshot::Sender<Result<PairInvite, PairingAdministrationError>>,
    ) {
        if self.drain.is_active() {
            let _ = reply.send(Err(pairing_error(PAIRING_DRAINING)));
            return;
        }
        let prepared = self.prepare_material(&request.display_name);
        let (canonical_invite, private_key) = match prepared {
            Ok(material) => material,
            Err(error) => {
                let _ = reply.send(Err(error));
                return;
            }
        };
        let durable = self
            .store
            .prepare(
                owner,
                request.idempotency_key.as_str().to_owned(),
                canonical_invite,
                private_key,
            )
            .await;
        let durable = match durable {
            Ok(value) => value,
            Err(error) => {
                let _ = reply.send(Err(error));
                return;
            }
        };
        if matches!(
            durable.lifecycle,
            PairingInviteLifecycle::Canceled | PairingInviteLifecycle::Expired
        ) {
            let _ = reply.send(Err(pairing_error(PAIRING_TERMINAL_INVALID)));
            return;
        }
        if matches!(
            durable.lifecycle,
            PairingInviteLifecycle::Delivered | PairingInviteLifecycle::OrphanRevoking
        ) {
            let _ = reply.send(Err(pairing_error(PAIRING_ALREADY_COMPLETED)));
            return;
        }
        self.routes
            .insert(*durable.pair_route.as_bytes(), durable.pairing_id);
        if self.opened_routes.contains(durable.pair_route.as_bytes()) {
            let _ = reply.send(durable.wire_invite());
            return;
        }
        let pairing_id = durable.pairing_id;
        self.prune_closed_waiters();
        if self.waiters.values().map(Vec::len).sum::<usize>() >= PAIRING_COMMAND_CAPACITY {
            let _ = reply.send(Err(pairing_error(PAIRING_BUSY)));
            return;
        }
        self.waiters.entry(pairing_id).or_default().push(reply);
        if self.is_transport_retry() {
            self.try_reconnect().await;
            if !self.is_healthy() {
                let error = self
                    .local_retry_error()
                    .unwrap_or_else(|| pairing_error(PAIRING_TRANSPORT));
                self.fail_pairing_waiters(pairing_id, error);
            }
            return;
        }
        let open = match durable.open() {
            Ok(open) => open,
            Err(error) => {
                self.fail_pairing_waiters(pairing_id, error);
                return;
            }
        };
        if let Err(error) = self.lane.send_open(open).await {
            self.set_failure(&error);
            self.fail_pairing_waiters(pairing_id, error.clone());
            if is_transport_failure(&error) {
                self.try_reconnect().await;
            }
        }
    }

    async fn begin_drain(&mut self, reply: oneshot::Sender<Result<(), PairingDrainActorError>>) {
        match &mut self.drain {
            PairingDrainState::Idle => {
                self.drain = PairingDrainState::Running(vec![reply]);
            }
            PairingDrainState::Running(waiters) => {
                waiters.retain(|waiter| !waiter.is_closed());
                if waiters.len() >= PAIRING_COMMAND_CAPACITY {
                    let _ = reply.send(Err(PairingDrainActorError::Busy(pairing_error(
                        PAIRING_BUSY,
                    ))));
                } else {
                    waiters.push(reply);
                }
                return;
            }
            PairingDrainState::Failed => {
                let _ = reply.send(Err(PairingDrainActorError::Failed(pairing_error(
                    PAIRING_DRAINING,
                ))));
                return;
            }
            PairingDrainState::Complete => {
                let result = self
                    .lane
                    .yield_shared_control()
                    .map_err(PairingDrainActorError::Busy);
                let _ = reply.send(result);
                return;
            }
        }
        self.progress_drain().await;
    }

    fn resume_after_failed_drain(&mut self) -> Result<(), PairingAdministrationError> {
        self.drain.resume_after_failed()
    }

    fn resume_after_completed_drain(&mut self) -> Result<(), PairingAdministrationError> {
        self.drain.resume_after_completed()
    }

    async fn progress_drain(&mut self) {
        if !matches!(self.drain, PairingDrainState::Running(_)) {
            return;
        }
        match self.advance_drain().await {
            Ok(true) => self.complete_drain(),
            Ok(false) => {}
            Err(error) if is_transport_failure(&error) => {
                self.set_transport_failure(&error);
            }
            Err(error) => self.fail_drain(error),
        }
    }

    async fn check_drain_completion(&mut self) {
        if !matches!(self.drain, PairingDrainState::Running(_)) {
            return;
        }
        match self.drain_is_complete().await {
            Ok(true) => self.complete_drain(),
            Ok(false) => {}
            Err(error) => self.fail_drain(error),
        }
    }

    async fn advance_drain(&mut self) -> Result<bool, PairingAdministrationError> {
        self.prepare_drain_transitions().await?;
        for close in self.store.recover_terminals().await? {
            self.send_recovered_close(close).await?;
        }
        self.drive_next_revocation().await?;
        self.drain_is_complete().await
    }

    async fn prepare_drain_transitions(&mut self) -> Result<(), PairingAdministrationError> {
        // Drain 可能落在 1s expiry tick 之前。先把已过期的 committed/grant-preparing
        // pairing 转成 orphan revocation，避免随后用 Local cause 枚举时与 Store 的
        // expiry-first CAS 冲突，并保持 Install ACK → Revoke 的既定恢复顺序。
        self.begin_due_revocations().await?;
        for target in self.store.drain_revocation_targets().await? {
            if target.pairing_id.is_some()
                || !device_matches_route(&target.device, target.grant.device_route)
            {
                return Err(pairing_error(REVOCATION_RECOVERY_UNAVAILABLE));
            }
            let revocation = self.authority.freeze_revocation(&target.grant)?;
            match self
                .store
                .begin_revocation(FrozenRevocationInput {
                    pairing_id: None,
                    revocation,
                })
                .await?
            {
                BeginRevocationOutcome::Recovering(_)
                | BeginRevocationOutcome::AlreadyRevoked(_) => {}
            }
        }

        for invite in self.store.recover().await? {
            match invite.lifecycle {
                PairingInviteLifecycle::RouteOpening
                | PairingInviteLifecycle::Unused
                | PairingInviteLifecycle::Preparing
                | PairingInviteLifecycle::AwaitingLocalConfirmation => {
                    let outcome = self
                        .store
                        .terminalize(invite.pairing_id, PairingTerminalAction::Cancel)
                        .await?;
                    self.settle_terminal_waiters(&outcome)?;
                }
                PairingInviteLifecycle::Delivered
                | PairingInviteLifecycle::OrphanRevoking
                | PairingInviteLifecycle::Canceled
                | PairingInviteLifecycle::Expired => {}
                PairingInviteLifecycle::GrantPreparing | PairingInviteLifecycle::GrantCommitted => {
                    return Err(pairing_error(REVOCATION_RECOVERY_UNAVAILABLE));
                }
            }
        }
        Ok(())
    }

    async fn drain_is_complete(&mut self) -> Result<bool, PairingAdministrationError> {
        self.prune_closed_waiters();
        if self.waiters.values().any(|waiters| !waiters.is_empty())
            || self
                .revocation_waiters
                .values()
                .any(|waiters| !waiters.is_empty())
        {
            return Ok(false);
        }
        let no_durable_pairing = self.store.recover().await?.is_empty()
            && self.store.recover_terminals().await?.is_empty();
        let all_authorizations_terminal = self.store.drain_revocation_targets().await?.is_empty()
            && self.store.recover_revocations().await?.is_empty();
        Ok(no_durable_pairing
            && all_authorizations_terminal
            && self.routes.is_empty()
            && self.opened_routes.is_empty())
    }

    fn complete_drain(&mut self) {
        if let Err(error) = self.lane.yield_shared_control() {
            self.fail_drain(error);
            return;
        }
        let PairingDrainState::Running(waiters) =
            std::mem::replace(&mut self.drain, PairingDrainState::Complete)
        else {
            return;
        };
        for waiter in waiters {
            let _ = waiter.send(Ok(()));
        }
    }

    fn fail_drain(&mut self, error: PairingAdministrationError) {
        let PairingDrainState::Running(waiters) =
            std::mem::replace(&mut self.drain, PairingDrainState::Failed)
        else {
            return;
        };
        for waiter in waiters {
            let _ = waiter.send(Err(PairingDrainActorError::Failed(error.clone())));
        }
    }

    async fn cancel(
        &mut self,
        pairing_id: RuntimeId,
    ) -> Result<PairingReceipt, PairingAdministrationError> {
        let outcome = self
            .store
            .terminalize(pairing_id, PairingTerminalAction::Cancel)
            .await?;
        let reply = outcome.reply.clone();
        if let Err(error) = self.apply_terminal(outcome).await {
            if is_transport_failure(&error) {
                self.set_transport_failure(&error);
            } else {
                return Err(error);
            }
        }
        Ok(reply)
    }

    async fn confirm(
        &mut self,
        pairing_id: RuntimeId,
    ) -> Result<PairingReceipt, PairingAdministrationError> {
        if self.drain.is_active() {
            return Err(pairing_error(PAIRING_DRAINING));
        }
        if let Some(grant) = self.recovered_grant(pairing_id).await? {
            let reply = replayed_confirm_receipt(&grant.receipt)?;
            self.send_committed_grant(grant).await?;
            return Ok(reply);
        }

        let durable = self.store.load(pairing_id).await?;
        let Some(durable) = durable else {
            return self.confirm_existing_winner(pairing_id).await;
        };
        match durable.lifecycle {
            PairingInviteLifecycle::AwaitingLocalConfirmation => {}
            PairingInviteLifecycle::GrantPreparing => {
                return Err(pairing_error(PAIRING_GRANT_RECOVERY_UNAVAILABLE));
            }
            PairingInviteLifecycle::GrantCommitted
            | PairingInviteLifecycle::Delivered
            | PairingInviteLifecycle::OrphanRevoking
            | PairingInviteLifecycle::Canceled
            | PairingInviteLifecycle::Expired => {
                return self.confirm_existing_winner(pairing_id).await;
            }
            PairingInviteLifecycle::RouteOpening
            | PairingInviteLifecycle::Unused
            | PairingInviteLifecycle::Preparing => {
                return Err(pairing_error(PAIRING_REQUEST_INVALID));
            }
        }

        let preparation = self.store.load_grant_preparation(pairing_id).await?;
        let allocation = self
            .store
            .load_grant_allocation(pairing_id, preparation.device_sign_fingerprint)
            .await?;
        let frozen = self.authority.freeze_grant(&preparation, allocation)?;
        match self.store.confirm_grant(frozen).await? {
            GrantCommitOutcome::Committed { reply, grant } => {
                self.send_committed_grant(*grant).await?;
                Ok(reply)
            }
            GrantCommitOutcome::Terminal { reply } => {
                let terminal = self
                    .store
                    .terminalize(pairing_id, PairingTerminalAction::Cancel)
                    .await?;
                if let Err(error) = self.apply_terminal(terminal).await {
                    if is_transport_failure(&error) {
                        self.set_transport_failure(&error);
                    } else {
                        return Err(error);
                    }
                }
                Ok(reply)
            }
        }
    }

    async fn revoke_device(
        &mut self,
        device: DeviceHandle,
        grant_serial: RuntimeGrantSerial,
        reply: oneshot::Sender<Result<RevocationReceipt, PairingAdministrationError>>,
    ) {
        if self.drain.is_active() {
            let _ = reply.send(Err(pairing_error(PAIRING_DRAINING)));
            return;
        }
        self.prune_closed_waiters();
        if grant_serial.0 == 0
            || self
                .revocation_waiters
                .values()
                .map(Vec::len)
                .sum::<usize>()
                >= PAIRING_COMMAND_CAPACITY
        {
            let _ = reply.send(Err(pairing_error(REVOCATION_TARGET_INVALID)));
            return;
        }
        let target = match self
            .store
            .load_revocation_target(device.clone(), grant_serial)
            .await
        {
            Ok(Some(target)) => target,
            Ok(None) => {
                let _ = reply.send(Err(pairing_error(REVOCATION_TARGET_INVALID)));
                return;
            }
            Err(error) => {
                let _ = reply.send(Err(error));
                return;
            }
        };
        let recovery = match target {
            RevocationTargetOutcome::Ready(target) => {
                if target.device != device
                    || target.grant.grant_serial.value() != grant_serial.0
                    || !device_matches_route(&device, target.grant.device_route)
                {
                    let _ = reply.send(Err(pairing_error(REVOCATION_RECOVERY_UNAVAILABLE)));
                    return;
                }
                let revocation = match self.authority.freeze_revocation(&target.grant) {
                    Ok(revocation) => revocation,
                    Err(error) => {
                        let _ = reply.send(Err(error));
                        return;
                    }
                };
                match self
                    .store
                    .begin_revocation(FrozenRevocationInput {
                        pairing_id: target.pairing_id,
                        revocation,
                    })
                    .await
                {
                    Ok(BeginRevocationOutcome::Recovering(recovery)) => *recovery,
                    Ok(BeginRevocationOutcome::AlreadyRevoked(revocation)) => {
                        let _ = reply.send(revocation_receipt(&revocation));
                        return;
                    }
                    Err(error) => {
                        let _ = reply.send(Err(error));
                        return;
                    }
                }
            }
            RevocationTargetOutcome::Revoking(recovery) => recovery,
            RevocationTargetOutcome::Revoked(revocation) => {
                let _ = reply.send(revocation_receipt(&revocation));
                return;
            }
        };
        if !device_matches_route(&device, recovery.revocation.device_route)
            || recovery.revocation.grant_serial.value() != grant_serial.0
        {
            let _ = reply.send(Err(pairing_error(REVOCATION_RECOVERY_UNAVAILABLE)));
            return;
        }
        let key = recovery.key();
        self.revocation_waiters.entry(key).or_default().push(reply);
        if let Err(error) = self.drive_next_revocation().await {
            if is_transport_failure(&error) {
                self.set_transport_failure(&error);
                self.try_reconnect().await;
            } else {
                self.fail_revocation_waiters(key, error);
            }
        }
    }

    async fn begin_due_revocations(&mut self) -> Result<(), PairingAdministrationError> {
        for target in self.store.due_revocation_targets().await? {
            let Some(pairing_id) = target.pairing_id else {
                return Err(pairing_error(REVOCATION_RECOVERY_UNAVAILABLE));
            };
            if !device_matches_route(&target.device, target.grant.device_route) {
                return Err(pairing_error(REVOCATION_RECOVERY_UNAVAILABLE));
            }
            let revocation = self.authority.freeze_revocation(&target.grant)?;
            match self
                .store
                .begin_revocation(FrozenRevocationInput {
                    pairing_id: Some(pairing_id),
                    revocation,
                })
                .await?
            {
                BeginRevocationOutcome::Recovering(_) => {}
                BeginRevocationOutcome::AlreadyRevoked(_) => {
                    return Err(pairing_error(REVOCATION_RECOVERY_UNAVAILABLE));
                }
            }
        }
        Ok(())
    }

    async fn drive_next_revocation(&mut self) -> Result<(), PairingAdministrationError> {
        let mut recoveries = self.store.recover_revocations().await?;
        recoveries.sort_by_key(DurableRevocation::key);
        for pair in recoveries.windows(2) {
            if pair[0].key() == pair[1].key() {
                return Err(pairing_error(REVOCATION_RECOVERY_UNAVAILABLE));
            }
        }
        let Some(next) = recoveries.first() else {
            return Ok(());
        };
        self.send_revocation_recovery(next).await
    }

    async fn send_revocation_recovery(
        &mut self,
        recovery: &DurableRevocation,
    ) -> Result<(), PairingAdministrationError> {
        recovery.validate()?;
        let frame = decode(&recovery.canonical_next_frame)
            .map_err(|_| pairing_error(REVOCATION_RECOVERY_UNAVAILABLE))?;
        match (recovery.phase, frame.body) {
            (
                DurableRevocationPhase::AwaitingGrantCommit,
                RelayFrameBody::InstallGrant(install),
            ) => self.lane.send_install(install).await,
            (DurableRevocationPhase::ReadyToRevoke, RelayFrameBody::RevokeDevice(revoke)) => {
                self.lane.send_revoke(revoke).await
            }
            _ => Err(pairing_error(REVOCATION_RECOVERY_UNAVAILABLE)),
        }
    }

    async fn match_orphan_grant_commit(
        &mut self,
        committed: &GrantCommitted,
    ) -> Result<Option<DurableRevocation>, PairingAdministrationError> {
        let recoveries = self.store.recover_revocations().await?;
        let mut matching = recoveries
            .into_iter()
            .filter(|recovery| recovery.matches_grant_committed(committed));
        let recovery = matching.next();
        if matching.next().is_some() {
            return Err(pairing_error(REVOCATION_RECOVERY_UNAVAILABLE));
        }
        Ok(recovery)
    }

    async fn handle_orphan_grant_committed(
        &mut self,
        recovery: DurableRevocation,
        committed: GrantCommitted,
    ) -> Result<(), PairingAdministrationError> {
        let pairing_id = recovery
            .pairing_id
            .ok_or_else(|| pairing_error(REVOCATION_RECOVERY_UNAVAILABLE))?;
        let canonical_terminal = encode(&OpaqueRouteFrame {
            version: RELAY_PROTOCOL_VERSION,
            body: RelayFrameBody::GrantCommitted(committed.clone()),
        });
        let next = self
            .store
            .acknowledge_orphan_grant_committed(pairing_id, committed, canonical_terminal)
            .await?;
        self.send_revocation_recovery(&next).await
    }

    async fn match_revocation_commit(
        &mut self,
        committed: &RevocationCommitted,
    ) -> Result<DurableRevocation, PairingAdministrationError> {
        let recoveries = self.store.recover_revocations().await?;
        let mut matching = recoveries
            .into_iter()
            .filter(|recovery| recovery.matches_revocation_committed(committed));
        let recovery = matching
            .next()
            .ok_or_else(|| pairing_error(REVOCATION_RECOVERY_UNAVAILABLE))?;
        if matching.next().is_some() {
            return Err(pairing_error(REVOCATION_RECOVERY_UNAVAILABLE));
        }
        Ok(recovery)
    }

    async fn handle_revocation_committed(
        &mut self,
        committed: RevocationCommitted,
    ) -> Result<(), PairingAdministrationError> {
        let recovery = self.match_revocation_commit(&committed).await?;
        let key = recovery.key();
        let pairing_id = recovery.pairing_id;
        let canonical_terminal = encode(&OpaqueRouteFrame {
            version: RELAY_PROTOCOL_VERSION,
            body: RelayFrameBody::RevocationCommitted(committed.clone()),
        });
        let revocation = self
            .store
            .acknowledge_revocation_committed(committed, canonical_terminal)
            .await?;
        self.reply_revocation_waiters(key, revocation_receipt(&revocation));
        if let Some(pairing_id) = pairing_id {
            let terminals = self.store.recover_terminals().await?;
            let mut matching = terminals
                .into_iter()
                .filter(|close| close.pairing_id == pairing_id);
            let close = matching
                .next()
                .ok_or_else(|| pairing_error(PAIRING_TERMINAL_INVALID))?;
            if matching.next().is_some() {
                return Err(pairing_error(PAIRING_TERMINAL_INVALID));
            }
            self.send_recovered_close(close).await?;
        }
        self.drive_next_revocation().await
    }

    async fn confirm_existing_winner(
        &mut self,
        pairing_id: RuntimeId,
    ) -> Result<PairingReceipt, PairingAdministrationError> {
        let (receipt, state) = self
            .store
            .load_winner(pairing_id)
            .await?
            .ok_or_else(|| pairing_error(PAIRING_TERMINAL_INVALID))?;
        confirm_retry_receipt(&receipt, state)
    }

    async fn recovered_grant(
        &mut self,
        pairing_id: RuntimeId,
    ) -> Result<Option<DurableGrant>, PairingAdministrationError> {
        let grants = self.store.recover_grants().await?;
        let mut matching = grants
            .into_iter()
            .filter(|grant| grant.pairing_id == pairing_id);
        let grant = matching.next();
        if matching.next().is_some() {
            return Err(pairing_error(PAIRING_GRANT_RECOVERY_UNAVAILABLE));
        }
        Ok(grant)
    }

    async fn recovered_response(
        &mut self,
        pairing_id: RuntimeId,
    ) -> Result<Option<DurableResponse>, PairingAdministrationError> {
        let responses = self.store.recover_committed().await?;
        let mut matching = responses
            .into_iter()
            .filter(|response| response.pairing_id == pairing_id);
        let response = matching.next();
        if matching.next().is_some() {
            return Err(pairing_error(PAIRING_GRANT_RECOVERY_UNAVAILABLE));
        }
        Ok(response)
    }

    async fn match_grant_commit(
        &mut self,
        committed: &GrantCommitted,
    ) -> Result<RuntimeId, PairingAdministrationError> {
        let grants = self.store.recover_grants().await?;
        let responses = self.store.recover_committed().await?;
        let mut matching = grants
            .iter()
            .filter(|grant| {
                grant.install.grant.device_route == committed.device_route
                    && grant.install.grant.grant_serial == committed.grant_serial
                    && grant.install.grant.canonical_sha256() == committed.grant_hash
            })
            .map(|grant| grant.pairing_id)
            .chain(
                responses
                    .iter()
                    .filter(|response| {
                        response.device_route == committed.device_route
                            && response.grant_serial == committed.grant_serial
                            && response.grant_hash == committed.grant_hash
                    })
                    .map(|response| response.pairing_id),
            );
        let pairing_id = matching
            .next()
            .ok_or_else(|| pairing_error(PAIRING_GRANT_RECOVERY_UNAVAILABLE))?;
        if matching.next().is_some() {
            return Err(pairing_error(PAIRING_GRANT_RECOVERY_UNAVAILABLE));
        }
        Ok(pairing_id)
    }

    async fn send_committed_grant(
        &mut self,
        grant: DurableGrant,
    ) -> Result<(), PairingAdministrationError> {
        let durable = self
            .store
            .load(grant.pairing_id)
            .await?
            .ok_or_else(|| pairing_error(PAIRING_GRANT_RECOVERY_UNAVAILABLE))?;
        if durable.lifecycle != PairingInviteLifecycle::GrantPreparing
            || durable.request_hash != Some(grant.request_hash)
        {
            return Err(pairing_error(PAIRING_GRANT_RECOVERY_UNAVAILABLE));
        }
        if !self.opened_routes.contains(durable.pair_route.as_bytes()) {
            return Ok(());
        }
        let canonical = encode(&OpaqueRouteFrame {
            version: RELAY_PROTOCOL_VERSION,
            body: RelayFrameBody::InstallGrant(grant.install.clone()),
        });
        if canonical != grant.canonical_frame {
            return Err(pairing_error(PAIRING_GRANT_RECOVERY_UNAVAILABLE));
        }
        if let Err(error) = self.lane.send_install(grant.install).await {
            if !is_transport_failure(&error) {
                return Err(error);
            }
            self.set_transport_failure(&error);
            self.try_reconnect().await;
        }
        Ok(())
    }

    async fn handle_grant_committed(
        &mut self,
        committed: GrantCommitted,
    ) -> Result<(), PairingAdministrationError> {
        if let Some(recovery) = self.match_orphan_grant_commit(&committed).await? {
            return self
                .handle_orphan_grant_committed(recovery, committed)
                .await;
        }
        let pairing_id = self.match_grant_commit(&committed).await?;
        let canonical_terminal = encode(&OpaqueRouteFrame {
            version: RELAY_PROTOCOL_VERSION,
            body: RelayFrameBody::GrantCommitted(committed.clone()),
        });
        let response = self
            .store
            .acknowledge_grant_committed(pairing_id, committed, canonical_terminal)
            .await?;
        if response.pairing_id != pairing_id {
            return Err(pairing_error(PAIRING_GRANT_RECOVERY_UNAVAILABLE));
        }
        self.send_committed_response(response).await
    }

    async fn send_committed_response(
        &mut self,
        response: DurableResponse,
    ) -> Result<(), PairingAdministrationError> {
        let durable = self
            .store
            .load(response.pairing_id)
            .await?
            .ok_or_else(|| pairing_error(PAIRING_GRANT_RECOVERY_UNAVAILABLE))?;
        if durable.lifecycle != PairingInviteLifecycle::GrantCommitted
            || durable.request_hash != Some(response.request_hash)
            || durable.pair_route != response.pair_route
            || response.response_hash == [0; 32]
        {
            return Err(pairing_error(PAIRING_GRANT_RECOVERY_UNAVAILABLE));
        }
        if !self.opened_routes.contains(response.pair_route.as_bytes()) {
            return Ok(());
        }
        if let Err(error) = self.lane.send_data(response.frame()?).await {
            if !is_transport_failure(&error) {
                return Err(error);
            }
            self.set_transport_failure(&error);
            self.try_reconnect().await;
        }
        Ok(())
    }

    async fn handle_expiry_tick(&mut self) {
        if let Err(error) = self.store.purge_expired_receipts().await {
            self.set_failure(&error);
            if matches!(self.drain, PairingDrainState::Running(_)) {
                self.fail_drain(error);
            } else {
                self.fail_waiters(error);
            }
            return;
        }
        if self.drain.is_active() {
            self.progress_drain().await;
            return;
        }
        if let Err(error) = self.begin_due_revocations().await {
            self.fail_waiters(error);
            return;
        }
        match self.store.terminalize_due().await {
            Ok(outcomes) => {
                let replay_existing = outcomes.is_empty();
                for outcome in outcomes {
                    if let Err(error) = self.apply_terminal(outcome).await {
                        if is_transport_failure(&error) {
                            self.set_transport_failure(&error);
                        } else {
                            self.fail_waiters(error);
                        }
                    }
                }
                if replay_existing {
                    match self.store.recover_terminals().await {
                        Ok(terminals) => {
                            for close in terminals {
                                if let Err(error) = self.send_recovered_close(close).await {
                                    if is_transport_failure(&error) {
                                        self.set_transport_failure(&error);
                                    } else {
                                        self.fail_waiters(error);
                                    }
                                }
                            }
                        }
                        Err(error) => self.fail_waiters(error),
                    }
                }
            }
            Err(error) => self.fail_waiters(error),
        }
        if let Err(error) = self.replay_pending_grants().await {
            if is_transport_failure(&error) {
                self.set_transport_failure(&error);
            } else {
                self.fail_waiters(error);
            }
            return;
        }
        if let Err(error) = self.drive_next_revocation().await {
            if is_transport_failure(&error) {
                self.set_transport_failure(&error);
            } else {
                self.fail_waiters(error);
            }
        }
    }

    async fn replay_pending_grants(&mut self) -> Result<(), PairingAdministrationError> {
        let grants = self.store.recover_grants().await?;
        if grants.len() > PAIRING_COMMAND_CAPACITY {
            return Err(pairing_error(PAIRING_GRANT_RECOVERY_UNAVAILABLE));
        }
        for grant in grants {
            self.send_committed_grant(grant).await?;
        }
        Ok(())
    }

    async fn apply_terminal(
        &mut self,
        outcome: TerminalOutcome,
    ) -> Result<(), PairingAdministrationError> {
        self.settle_terminal_waiters(&outcome)?;
        let Some(close) = outcome.close else {
            return Ok(());
        };
        self.send_recovered_close(close).await
    }

    fn settle_terminal_waiters(
        &mut self,
        outcome: &TerminalOutcome,
    ) -> Result<(), PairingAdministrationError> {
        let failure = match &outcome.reply {
            PairingReceipt::Canceled { .. }
            | PairingReceipt::Replayed {
                decision: PairingDecision::Cancel,
                ..
            }
            | PairingReceipt::AlreadyHandled {
                winner: PairingDecision::Cancel,
                ..
            } => pairing_error(PAIRING_CANCELED),
            PairingReceipt::Expired { .. }
            | PairingReceipt::Replayed {
                decision: PairingDecision::Expire,
                ..
            }
            | PairingReceipt::AlreadyHandled {
                winner: PairingDecision::Expire,
                ..
            } => pairing_error(PAIRING_EXPIRED),
            PairingReceipt::AlreadyHandled {
                winner: PairingDecision::Confirm,
                ..
            } => return Ok(()),
            _ => return Err(pairing_error(PAIRING_TERMINAL_INVALID)),
        };
        self.fail_pairing_waiters(outcome.pairing_id, failure);
        Ok(())
    }

    async fn send_recovered_close(
        &mut self,
        close: DurableClose,
    ) -> Result<(), PairingAdministrationError> {
        if self
            .routes
            .insert(*close.pair_route.as_bytes(), close.pairing_id)
            .is_some_and(|existing| existing != close.pairing_id)
        {
            return Err(pairing_error(PAIRING_TERMINAL_INVALID));
        }
        self.opened_routes.remove(close.pair_route.as_bytes());
        self.lane.send_close(close.frame).await
    }

    async fn handle_event(
        &mut self,
        event: Result<Option<PairingTransportEvent>, PairingAdministrationError>,
    ) {
        match event {
            Ok(Some(PairingTransportEvent::PairRouteOpened(opened))) => {
                self.handle_opened(opened).await;
            }
            Ok(Some(PairingTransportEvent::PairData(data))) => {
                if let Err(error) = self.handle_pair_data(data).await
                    && is_transport_failure(&error)
                {
                    self.set_transport_failure(&error);
                    self.try_reconnect().await;
                }
            }
            Ok(Some(PairingTransportEvent::PairRouteClosed(closed))) => {
                self.handle_closed(closed).await;
            }
            Ok(Some(PairingTransportEvent::GrantCommitted(committed))) => {
                if let Err(error) = self.handle_grant_committed(committed).await
                    && is_transport_failure(&error)
                {
                    self.set_transport_failure(&error);
                    self.try_reconnect().await;
                }
            }
            Ok(Some(PairingTransportEvent::RevocationCommitted(committed))) => {
                if let Err(error) = self.handle_revocation_committed(committed).await
                    && is_transport_failure(&error)
                {
                    self.set_transport_failure(&error);
                    self.try_reconnect().await;
                }
            }
            Ok(Some(PairingTransportEvent::PairFrameAccepted(_))) => {
                // RouteAccepted 只证明 Relay writer 接受，不能推进任何 durable terminal。
            }
            Ok(None) => {
                let error = pairing_error(PAIRING_TRANSPORT);
                self.set_transport_failure(&error);
                self.fail_waiters(error);
                self.try_reconnect().await;
            }
            Err(error) => {
                self.set_failure(&error);
                if is_transport_failure(&error) {
                    self.fail_waiters(pairing_error(PAIRING_TRANSPORT));
                    self.try_reconnect().await;
                } else {
                    self.fail_waiters(error);
                }
            }
        }
        self.check_drain_completion().await;
    }

    async fn handle_opened(&mut self, opened: PairRouteOpened) {
        let Some(pairing_id) = self.routes.get(opened.pair_route.as_bytes()).copied() else {
            let error = pairing_error(PAIRING_TRANSPORT);
            self.set_transport_failure(&error);
            self.fail_waiters(error);
            return;
        };
        let canonical_terminal = encode(&OpaqueRouteFrame {
            version: RELAY_PROTOCOL_VERSION,
            body: RelayFrameBody::PairRouteOpened(opened),
        });
        match self
            .store
            .acknowledge_open(pairing_id, canonical_terminal)
            .await
        {
            Ok(invite) => {
                self.opened_routes.insert(*invite.pair_route.as_bytes());
                let result = invite.wire_invite();
                self.reply_pairing_waiters(pairing_id, result);
                let lifecycle = invite.lifecycle;
                if matches!(
                    lifecycle,
                    PairingInviteLifecycle::Preparing
                        | PairingInviteLifecycle::AwaitingLocalConfirmation
                ) && let Err(error) = self.drive_pair_pending(invite).await
                    && is_transport_failure(&error)
                {
                    self.set_transport_failure(&error);
                    self.try_reconnect().await;
                } else if lifecycle == PairingInviteLifecycle::GrantPreparing {
                    match self.recovered_grant(pairing_id).await {
                        Ok(Some(grant)) => {
                            if let Err(error) = self.send_committed_grant(grant).await
                                && !is_transport_failure(&error)
                            {
                                self.fail_pairing_waiters(pairing_id, error);
                            }
                        }
                        Ok(None) => self.fail_pairing_waiters(
                            pairing_id,
                            pairing_error(PAIRING_GRANT_RECOVERY_UNAVAILABLE),
                        ),
                        Err(error) => self.fail_pairing_waiters(pairing_id, error),
                    }
                } else if lifecycle == PairingInviteLifecycle::GrantCommitted {
                    match self.recovered_response(pairing_id).await {
                        Ok(Some(response)) => {
                            if let Err(error) = self.send_committed_response(response).await
                                && !is_transport_failure(&error)
                            {
                                self.fail_pairing_waiters(pairing_id, error);
                            }
                        }
                        Ok(None) => self.fail_pairing_waiters(
                            pairing_id,
                            pairing_error(PAIRING_GRANT_RECOVERY_UNAVAILABLE),
                        ),
                        Err(error) => self.fail_pairing_waiters(pairing_id, error),
                    }
                }
            }
            Err(error) => self.fail_pairing_waiters(pairing_id, error),
        }
    }

    async fn handle_closed(&mut self, closed: PairRouteClosed) {
        let route = *closed.pair_route.as_bytes();
        let Some(pairing_id) = self.routes.get(&route).copied() else {
            // Transport 只会上送当前/近期 completed binding；无本地映射即重复 ACK。
            return;
        };
        let canonical_terminal = encode(&OpaqueRouteFrame {
            version: RELAY_PROTOCOL_VERSION,
            body: RelayFrameBody::PairRouteClosed(closed),
        });
        match self
            .store
            .acknowledge_close(pairing_id, canonical_terminal)
            .await
        {
            Ok(receipt)
                if terminal_receipt_identity(&receipt).is_ok_and(|value| value.0 == pairing_id) =>
            {
                self.routes.remove(&route);
                self.opened_routes.remove(&route);
            }
            Ok(_) => self.fail_pairing_waiters(pairing_id, pairing_error(PAIRING_TERMINAL_INVALID)),
            Err(_) => {
                // 保留 route 映射和 durable outbox；下一次 tick/reconnect 会重发 frozen Close。
            }
        }
    }

    async fn handle_pair_data(&mut self, data: PairData) -> Result<(), PairingAdministrationError> {
        if self.drain.is_active() {
            return Err(pairing_error(PAIRING_DRAINING));
        }
        let pairing_id = self
            .routes
            .get(data.pair_route.as_bytes())
            .copied()
            .ok_or_else(|| pairing_error(PAIRING_REQUEST_INVALID))?;
        if !self.opened_routes.contains(data.pair_route.as_bytes()) {
            return Err(pairing_error(PAIRING_REQUEST_INVALID));
        }
        let mut durable = self
            .store
            .load(pairing_id)
            .await?
            .ok_or_else(|| pairing_error(PAIRING_REQUEST_INVALID))?;
        if durable.pair_route != data.pair_route {
            return Err(pairing_error(PAIRING_REQUEST_INVALID));
        }
        if durable.lifecycle == PairingInviteLifecycle::GrantCommitted {
            let delivery_error = match self.handle_delivery(pairing_id, data.clone()).await {
                Ok(()) => return Ok(()),
                Err(error) => error,
            };
            if !is_exact_committed_request_replay(&durable, &data.sealed_blob.0)? {
                return Err(delivery_error);
            }
            let response = self
                .recovered_response(pairing_id)
                .await?
                .ok_or_else(|| pairing_error(PAIRING_GRANT_RECOVERY_UNAVAILABLE))?;
            return self.send_committed_response(response).await;
        }
        let request = PairRequestV1::from_canonical_bytes(&data.sealed_blob.0)
            .map_err(|_| pairing_error(PAIRING_REQUEST_INVALID))?;
        if request
            .canonical_bytes()
            .map_err(|_| pairing_error(PAIRING_REQUEST_INVALID))?
            != data.sealed_blob.0
        {
            return Err(pairing_error(PAIRING_REQUEST_INVALID));
        }
        durable = match durable.lifecycle {
            PairingInviteLifecycle::Unused => {
                let invite =
                    PairInviteV1::from_canonical_bytes(durable.canonical_invite.expose_secret())
                        .map_err(|_| pairing_error(PAIRING_INVITE_INVALID))?;
                let info = pair_request_info(&invite)?;
                let context = pairing_context(invite.pair_route, OuterFrameKind::PairRequest);
                let private_key = durable
                    .invite_hpke_private_key
                    .take()
                    .ok_or_else(|| pairing_error(PAIRING_REQUEST_INVALID))?;
                let verified = open_pair_request_verified(
                    &private_key,
                    &info,
                    &context,
                    &invite.invite_secret,
                    &request,
                )
                .map_err(|_| pairing_error(PAIRING_REQUEST_INVALID))?;
                self.store.accept_request(pairing_id, verified).await?
            }
            PairingInviteLifecycle::Preparing
            | PairingInviteLifecycle::AwaitingLocalConfirmation => {
                self.store
                    .replay_request(pairing_id, SecretBytes::new(data.sealed_blob.0))
                    .await?
            }
            PairingInviteLifecycle::RouteOpening
            | PairingInviteLifecycle::GrantPreparing
            | PairingInviteLifecycle::GrantCommitted
            | PairingInviteLifecycle::Delivered
            | PairingInviteLifecycle::OrphanRevoking
            | PairingInviteLifecycle::Canceled
            | PairingInviteLifecycle::Expired => {
                return Err(pairing_error(PAIRING_REQUEST_INVALID));
            }
        };
        self.drive_pair_pending(durable).await
    }

    async fn handle_delivery(
        &mut self,
        pairing_id: RuntimeId,
        data: PairData,
    ) -> Result<(), PairingAdministrationError> {
        let response = self
            .recovered_response(pairing_id)
            .await?
            .ok_or_else(|| pairing_error(PAIRING_GRANT_RECOVERY_UNAVAILABLE))?;
        if response.pair_route != data.pair_route {
            return Err(pairing_error(PAIRING_REQUEST_INVALID));
        }
        let proof = self
            .authority
            .verify_delivery(&response, &data.sealed_blob.0)?;
        if proof.pairing_id != response.pairing_id
            || proof.pair_route != response.pair_route
            || proof.request_hash != response.request_hash
            || proof.grant_hash != response.grant_hash
            || proof.response_hash != response.response_hash
            || proof.canonical_receipt_hash == [0; 32]
        {
            return Err(pairing_error(PAIRING_REQUEST_INVALID));
        }
        let outcome = self.store.acknowledge_delivery(proof).await?;
        if outcome.close.pairing_id != pairing_id || outcome.close.pair_route != response.pair_route
        {
            return Err(pairing_error(PAIRING_TERMINAL_INVALID));
        }
        self.send_recovered_close(outcome.close).await
    }

    async fn drive_pair_pending(
        &mut self,
        mut durable: DurableInvite,
    ) -> Result<(), PairingAdministrationError> {
        if durable.lifecycle == PairingInviteLifecycle::Preparing {
            let preparation = durable
                .pending_preparation
                .as_ref()
                .ok_or_else(|| pairing_error(PAIRING_REQUEST_INVALID))?;
            let request_hash = preparation.request_hash;
            let envelope = self.authority.seal_pending(preparation)?;
            durable = self
                .store
                .commit_pending(durable.pairing_id, request_hash, envelope)
                .await?;
        }
        if durable.lifecycle != PairingInviteLifecycle::AwaitingLocalConfirmation {
            return Err(pairing_error(PAIRING_REQUEST_INVALID));
        }
        let pending = durable.pending()?;
        let frame = durable.pending_frame()?;
        self.lane.send_data(frame).await?;
        // pending 已 durable，local stream 只是提示；sink failure 不得阻断远端 exact replay。
        let _ = self.pending_sink.publish(pending);
        Ok(())
    }

    async fn try_reconnect(&mut self) {
        if !self.is_transport_retry() {
            return;
        }
        if let Err(error) = self.lane.reconnect().await {
            self.set_failure(&error);
            return;
        }
        match self.purge_then_recover_generation().await {
            Ok(()) => self.set_healthy(),
            Err(error) => {
                if matches!(self.drain, PairingDrainState::Running(_))
                    && !is_transport_failure(&error)
                {
                    self.fail_drain(error.clone());
                }
                self.set_failure(&error);
            }
        }
    }

    async fn try_local_recovery(&mut self) {
        if self.local_retry_error().is_none() {
            return;
        }
        match self.purge_then_recover_generation().await {
            Ok(()) => self.set_healthy(),
            Err(error) => {
                if matches!(self.drain, PairingDrainState::Running(_))
                    && !is_transport_failure(&error)
                {
                    self.fail_drain(error.clone());
                }
                self.set_failure(&error);
            }
        }
    }

    async fn purge_then_recover_generation(&mut self) -> Result<(), PairingAdministrationError> {
        self.store.purge_expired_receipts().await?;
        self.recover_generation().await
    }

    async fn recover_generation(&mut self) -> Result<(), PairingAdministrationError> {
        // Relay session generation changed (或 daemon 刚启动)：旧 ACK 不可跨代复用。
        self.opened_routes.clear();
        if matches!(self.drain, PairingDrainState::Running(_)) {
            self.prepare_drain_transitions().await?;
        } else if !self.drain.is_active() {
            self.begin_due_revocations().await?;
            let due = self.store.terminalize_due().await?;
            for outcome in due {
                self.fail_pairing_waiters(outcome.pairing_id, pairing_error(PAIRING_EXPIRED));
            }
        }
        let invites = self.store.recover().await?;
        let grants = self.store.recover_grants().await?;
        let responses = self.store.recover_committed().await?;
        let revocations = self.store.recover_revocations().await?;
        let terminals = self.store.recover_terminals().await?;
        let mut grant_ids = HashSet::new();
        for grant in &grants {
            if !grant_ids.insert(grant.pairing_id) {
                return Err(pairing_error(PAIRING_GRANT_RECOVERY_UNAVAILABLE));
            }
        }
        let mut recovered_grant_ids = HashSet::new();
        let mut response_ids = HashSet::new();
        for response in &responses {
            if !response_ids.insert(response.pairing_id) {
                return Err(pairing_error(PAIRING_GRANT_RECOVERY_UNAVAILABLE));
            }
        }
        let mut recovered_response_ids = HashSet::new();
        let mut revocation_keys = HashSet::new();
        let mut orphan_revocation_ids = HashSet::new();
        for revocation in &revocations {
            revocation.validate()?;
            if !revocation_keys.insert(revocation.key()) {
                return Err(pairing_error(REVOCATION_RECOVERY_UNAVAILABLE));
            }
            if let Some(pairing_id) = revocation.pairing_id
                && !orphan_revocation_ids.insert(pairing_id)
            {
                return Err(pairing_error(REVOCATION_RECOVERY_UNAVAILABLE));
            }
        }
        let mut recovered_orphan_revocation_ids = HashSet::new();
        let mut terminal_ids = HashSet::new();
        for close in &terminals {
            if !terminal_ids.insert(close.pairing_id) {
                return Err(pairing_error(PAIRING_TERMINAL_INVALID));
            }
        }
        let mut recovered_terminal_ids = HashSet::new();
        let mut routes = BTreeMap::new();
        for invite in &invites {
            if routes
                .insert(*invite.pair_route.as_bytes(), invite.pairing_id)
                .is_some()
            {
                return Err(pairing_error(PAIRING_INVITE_INVALID));
            }
            match invite.lifecycle {
                PairingInviteLifecycle::RouteOpening
                | PairingInviteLifecycle::Unused
                | PairingInviteLifecycle::Preparing
                | PairingInviteLifecycle::AwaitingLocalConfirmation => {
                    if terminal_ids.contains(&invite.pairing_id) {
                        return Err(pairing_error(PAIRING_TERMINAL_INVALID));
                    }
                }
                PairingInviteLifecycle::GrantPreparing => {
                    if !grant_ids.contains(&invite.pairing_id)
                        || terminal_ids.contains(&invite.pairing_id)
                    {
                        return Err(pairing_error(PAIRING_GRANT_RECOVERY_UNAVAILABLE));
                    }
                    recovered_grant_ids.insert(invite.pairing_id);
                }
                PairingInviteLifecycle::GrantCommitted => {
                    if !response_ids.contains(&invite.pairing_id)
                        || terminal_ids.contains(&invite.pairing_id)
                    {
                        return Err(pairing_error(PAIRING_GRANT_RECOVERY_UNAVAILABLE));
                    }
                    recovered_response_ids.insert(invite.pairing_id);
                }
                PairingInviteLifecycle::Delivered => {
                    if !terminal_ids.contains(&invite.pairing_id) {
                        return Err(pairing_error(PAIRING_TERMINAL_INVALID));
                    }
                    recovered_terminal_ids.insert(invite.pairing_id);
                }
                PairingInviteLifecycle::OrphanRevoking => {
                    if terminal_ids.contains(&invite.pairing_id)
                        || !orphan_revocation_ids.contains(&invite.pairing_id)
                    {
                        return Err(pairing_error(REVOCATION_RECOVERY_UNAVAILABLE));
                    }
                    recovered_orphan_revocation_ids.insert(invite.pairing_id);
                }
                PairingInviteLifecycle::Canceled | PairingInviteLifecycle::Expired => {
                    if !terminal_ids.contains(&invite.pairing_id) {
                        return Err(pairing_error(PAIRING_TERMINAL_INVALID));
                    }
                    recovered_terminal_ids.insert(invite.pairing_id);
                }
            }
        }
        for close in &terminals {
            if routes
                .insert(*close.pair_route.as_bytes(), close.pairing_id)
                .is_some_and(|existing| existing != close.pairing_id)
            {
                return Err(pairing_error(PAIRING_TERMINAL_INVALID));
            }
        }
        if recovered_grant_ids != grant_ids
            || recovered_response_ids != response_ids
            || recovered_orphan_revocation_ids != orphan_revocation_ids
            || recovered_terminal_ids != terminal_ids
        {
            return Err(pairing_error(PAIRING_GRANT_RECOVERY_UNAVAILABLE));
        }
        for invite in &invites {
            if !self.drain.is_active()
                && matches!(
                    invite.lifecycle,
                    PairingInviteLifecycle::RouteOpening
                        | PairingInviteLifecycle::Unused
                        | PairingInviteLifecycle::Preparing
                        | PairingInviteLifecycle::AwaitingLocalConfirmation
                        | PairingInviteLifecycle::GrantPreparing
                        | PairingInviteLifecycle::GrantCommitted
                )
            {
                self.lane.send_open(invite.open()?).await?;
            }
        }
        for close in terminals {
            self.lane.send_close(close.frame).await?;
        }
        self.routes = routes;
        self.drive_next_revocation().await?;
        if matches!(self.drain, PairingDrainState::Running(_)) && self.drain_is_complete().await? {
            self.complete_drain();
        }
        Ok(())
    }

    fn prepare_material(
        &self,
        display_name: &str,
    ) -> Result<(SecretBytes, SecretBytes), PairingAdministrationError> {
        let now_ms = unix_now_ms()?;
        let invite_ttl_ms = pair_invite_ttl_ms()?;
        let expires_at_ms = now_ms
            .checked_add(invite_ttl_ms)
            .ok_or_else(|| pairing_error(PAIRING_CLOCK))?;
        let invite_secret = random_nonzero::<32>()?;
        let pair_route = PairRouteId::from_bytes(random_nonzero::<16>()?);
        let hpke_seed = Zeroizing::new(random_nonzero::<32>()?);
        let (private_key, public_key) = HpkePrivateKey::derive_keypair(hpke_seed.as_ref());
        let private_bytes = private_key.to_bytes();
        if private_bytes.len() != 32 || private_bytes.iter().all(|byte| *byte == 0) {
            return Err(pairing_error(PAIRING_ENTROPY));
        }
        let public_bytes: [u8; 32] = public_key
            .to_bytes()
            .try_into()
            .map_err(|_| pairing_error(PAIRING_INVITE_INVALID))?;
        let invite = PairInviteV1 {
            format_version: E2EE_FORMAT_VERSION,
            relay_protocol_version: RELAY_PROTOCOL_VERSION,
            pair_route,
            invite_secret,
            invite_hpke_pubkey: PublicKeyBytes(public_bytes),
            wss_url: self.invite_context.wss_url.clone(),
            relay_server_id: self.invite_context.relay_server_id,
            current_spki_pin: self.invite_context.current_spki_pin,
            next_spki_pin: self.invite_context.next_spki_pin,
            expires_at_ms,
            machine_root_pubkey: self.invite_context.machine_root_pubkey,
            machine_root_fingerprint: self.invite_context.machine_root_fingerprint,
            data_sign_cert: self.invite_context.data_sign_cert.clone(),
            machine_display_name: display_name.to_owned(),
        };
        let canonical = invite
            .canonical_bytes()
            .map_err(|_| pairing_error(PAIRING_INVITE_INVALID))?;
        Ok((SecretBytes::new(canonical), SecretBytes::new(private_bytes)))
    }

    fn reply_pairing_waiters(
        &mut self,
        pairing_id: RuntimeId,
        result: Result<PairInvite, PairingAdministrationError>,
    ) {
        let Some(waiters) = self.waiters.remove(&pairing_id) else {
            return;
        };
        for waiter in waiters {
            let replay = result.clone();
            let _ = waiter.send(replay);
        }
    }

    fn fail_pairing_waiters(&mut self, pairing_id: RuntimeId, error: PairingAdministrationError) {
        self.reply_pairing_waiters(pairing_id, Err(error));
    }

    fn reply_revocation_waiters(
        &mut self,
        key: RevocationKey,
        result: Result<RevocationReceipt, PairingAdministrationError>,
    ) {
        let Some(waiters) = self.revocation_waiters.remove(&key) else {
            return;
        };
        for waiter in waiters {
            let _ = waiter.send(result.clone());
        }
    }

    fn fail_revocation_waiters(&mut self, key: RevocationKey, error: PairingAdministrationError) {
        self.reply_revocation_waiters(key, Err(error));
    }

    fn fail_waiters(&mut self, error: PairingAdministrationError) {
        let pairing_ids: Vec<_> = self.waiters.keys().copied().collect();
        for pairing_id in pairing_ids {
            self.fail_pairing_waiters(pairing_id, error.clone());
        }
        let revocations: Vec<_> = self.revocation_waiters.keys().copied().collect();
        for key in revocations {
            self.fail_revocation_waiters(key, error.clone());
        }
    }

    fn prune_closed_waiters(&mut self) {
        self.waiters.retain(|_, waiters| {
            waiters.retain(|waiter| !waiter.is_closed());
            !waiters.is_empty()
        });
        self.revocation_waiters.retain(|_, waiters| {
            waiters.retain(|waiter| !waiter.is_closed());
            !waiters.is_empty()
        });
    }
}

fn random_nonzero<const N: usize>() -> Result<[u8; N], PairingAdministrationError> {
    for _ in 0..8 {
        let mut bytes = [0_u8; N];
        getrandom::fill(&mut bytes).map_err(|_| pairing_error(PAIRING_ENTROPY))?;
        if bytes.iter().any(|byte| *byte != 0) {
            return Ok(bytes);
        }
    }
    Err(pairing_error(PAIRING_ENTROPY))
}

fn pair_request_info(
    invite: &PairInviteV1,
) -> Result<PairRequestInfoV1, PairingAdministrationError> {
    Ok(PairRequestInfoV1 {
        e2ee_format_version: E2EE_FORMAT_VERSION,
        runtime_protocol_version: RUNTIME_PROTOCOL_VERSION,
        relay_server_id: invite.relay_server_id,
        pair_route: invite.pair_route,
        invite_hash: invite
            .canonical_sha256()
            .map_err(|_| pairing_error(PAIRING_INVITE_INVALID))?,
        expiry_ms: invite.expires_at_ms,
    })
}

fn pairing_context(pair_route: PairRouteId, frame_kind: OuterFrameKind) -> OuterContextV1 {
    OuterContextV1 {
        frame_kind,
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

fn unix_now_ms() -> Result<u64, PairingAdministrationError> {
    let millis = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_err(|_| pairing_error(PAIRING_CLOCK))?
        .as_millis();
    u64::try_from(millis).map_err(|_| pairing_error(PAIRING_CLOCK))
}

fn pair_invite_ttl_ms() -> Result<u64, PairingAdministrationError> {
    PAIR_INVITE_MAX_TTL_MS
        .checked_sub(PAIR_INVITE_RELAY_TICK_GUARD_MS)
        .filter(|ttl_ms| *ttl_ms > 0)
        .ok_or_else(|| pairing_error(PAIRING_CLOCK))
}

fn is_exact_committed_request_replay(
    durable: &DurableInvite,
    candidate: &[u8],
) -> Result<bool, PairingAdministrationError> {
    let canonical_request = durable
        .canonical_pair_request
        .as_ref()
        .ok_or_else(|| pairing_error(PAIRING_GRANT_RECOVERY_UNAVAILABLE))?;
    let request_hash = durable
        .request_hash
        .ok_or_else(|| pairing_error(PAIRING_GRANT_RECOVERY_UNAVAILABLE))?;
    if canonical_request.expose_secret() != candidate {
        return Ok(false);
    }
    let request = PairRequestV1::from_canonical_bytes(candidate)
        .map_err(|_| pairing_error(PAIRING_GRANT_RECOVERY_UNAVAILABLE))?;
    if request
        .canonical_sha256()
        .map_err(|_| pairing_error(PAIRING_GRANT_RECOVERY_UNAVAILABLE))?
        != request_hash
    {
        return Err(pairing_error(PAIRING_GRANT_RECOVERY_UNAVAILABLE));
    }
    Ok(true)
}

fn device_matches_route(device: &DeviceHandle, route: DeviceRouteId) -> bool {
    const PREFIX: &str = "device-";
    const HEX: &[u8; 16] = b"0123456789abcdef";
    let mut expected = String::with_capacity(PREFIX.len() + 32);
    expected.push_str(PREFIX);
    for byte in route.as_bytes() {
        expected.push(char::from(HEX[usize::from(byte >> 4)]));
        expected.push(char::from(HEX[usize::from(byte & 0x0f)]));
    }
    device.as_str() == expected
}

fn revocation_receipt(
    revocation: &DeviceRevocation,
) -> Result<RevocationReceipt, PairingAdministrationError> {
    if revocation.device_route.as_bytes() == &[0; 16] || revocation.grant_serial.value() == 0 {
        return Err(pairing_error(REVOCATION_RECOVERY_UNAVAILABLE));
    }
    Ok(RevocationReceipt::Committed {
        grant_serial: RuntimeGrantSerial::new(revocation.grant_serial.value()),
    })
}

fn pairing_error(code: impl AsRef<str>) -> PairingAdministrationError {
    PairingAdministrationError::new(code)
}

fn store_error(error: crate::runtime::store::RuntimeStoreError) -> PairingAdministrationError {
    pairing_error(error.code())
}

fn transport_error(error: RemoteTransportError) -> PairingAdministrationError {
    let code = error.code();
    if code.is_empty() {
        pairing_error(PAIRING_TRANSPORT)
    } else {
        pairing_error(code)
    }
}

fn command_send_error<T>(error: mpsc::error::TrySendError<T>) -> PairingAdministrationError {
    match error {
        mpsc::error::TrySendError::Full(_) => pairing_error(PAIRING_BUSY),
        mpsc::error::TrySendError::Closed(_) => pairing_error(PAIRING_STOPPED),
    }
}

fn recoverable_startup_ready(
    ready: Result<(), PairingAdministrationError>,
) -> Result<(), PairingAdministrationError> {
    match ready {
        Err(error) if is_transport_failure(&error) => {
            // transport health 是暂态真源，actor 会继续重连；不能把这次 ready 错误固化进
            // manager blocked_code，否则 transport 恢复后 status 仍永久 Blocked。
            Ok(())
        }
        other => other,
    }
}

fn is_transport_failure(error: &PairingAdministrationError) -> bool {
    error.code() == PAIRING_TRANSPORT
        || error.code().starts_with("remote.transport.")
        || error.code().starts_with("relay.")
}

pub(crate) fn unavailable() -> PairingAdministrationError {
    pairing_error(PAIRING_UNAVAILABLE)
}

#[cfg(test)]
#[path = "pairing_tests.rs"]
mod tests;
