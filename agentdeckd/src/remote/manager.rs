//! Machine remote 的唯一 daemon owner 与 Runtime administration 实现。
//!
//! manager 串行独占 identity、RemoteStartPermit、connect retry 与 control-only
//! transport。构造不拨号；只有 recovery 完成且 canonical UDS bind/readback 后的
//! [`RemoteStartPermit`] 才能 arm。所有失败只阻断 remote，本地 Runtime 继续服务。

use std::future::Future;
use std::sync::{Arc, OnceLock, Weak};
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use agentdeck_protocol::e2ee::{KeyId, KeyPurpose};
use agentdeck_protocol::relay_v2::{
    ENROLLMENT_BUNDLE_VERSION, EnrollmentBundleV2, MachineEnrollmentRequestV1, MachineRouteId,
};
use agentdeck_protocol::runtime::identity::{DeviceHandle, GrantSerial};
use agentdeck_protocol::runtime::{
    MachineEnrollRequest, MachineRemoteFailureCode,
    MachineRemoteLifecycle as WireMachineRemoteLifecycle, MachineRemoteStatus,
    MachineRootFingerprint, RevocationReceipt, TrustResetRequest, UninstallPurgePlanV1,
};
use async_trait::async_trait;
#[cfg(test)]
use tokio::sync::oneshot;
use tokio::sync::{Mutex, watch};

use crate::config::DaemonConfig;
use crate::local::listener::RemoteStartPermit;
use crate::purge_finalizer::{
    AuthenticatedPurgeAuthorization, ResumeReservedPurgeMarkerOutcome, RunningFinalizerIdentity,
    authorize_reserved_purge_marker, purge_marker_intent_present, reserve_purge_marker,
    resume_reserved_purge_marker,
};
use crate::runtime::remote_administration::{RemoteAdministration, RemoteAdministrationError};
use crate::runtime::store::key_transition::{
    KeyTransitionOperation, KeyTransitionPhase, KeyTransitionTarget,
};
use crate::runtime::store::remote_counter::{
    CounterRecoveryDisposition, CounterRecoveryStageRequest, CounterRecoveryStageTarget,
    RemoteCounterRecordKind,
};
use crate::runtime::store::{
    ActiveMachineEnrollmentState, ActiveSenderCounterBinding, MachineEnrollmentConnectionMaterial,
    MachineEnrollmentState, MachineRemoteStateRecord, RuntimeStoreError, RuntimeStoreHandle,
    machine_enrollment_prepare_input_hash,
};
use crate::runtime::{
    ConversationActivationCoordinator, ConversationActivationError, PairingAdministration,
    PairingAdministrationError, PairingPendingSink, RevocationAdministration,
    RevocationAdministrationError, RuntimeCore,
};
use crate::security::KeyStore;

use super::bootstrap::{
    ActiveMachineIdentity, RemoteBootstrapOutcome, prepare_reenrollment_identity,
};
use super::cleanup::{MachineCleanupWorkflow, MachineCleanupWorkflowError};
use super::config::{
    EnrollmentConfigError, ValidatedEnrollmentConfig, validate_sealed_relay_connection,
};
use super::counter::CounterScope;
use super::directed_reply::DeviceReplyTxSealer;
use super::enrollment::{FrozenMachineEnrollment, MachineEnrollmentError};
use super::identity::OwnedKeyStoreCounterGuardBackend;
use super::key_control::StoreBackedKeyControlIngressHandler;
use super::link::{RemoteLinkError, RemoteLinkIngressMode, RemoteLinkOwner};
use super::maintenance::{
    RemoteMaintenanceError, RemoteMaintenanceOwner, run_remote_maintenance_once,
};
#[cfg(test)]
use super::pairing::await_pairing_startup;
use super::pairing::{
    PairingCoordinatorHandle, PairingCoordinatorOwner, PairingDrainStartError,
    PairingInviteContext, unavailable as pairing_unavailable,
};
use super::publication_transport::{PublicationDriveError, PublicationDriveOwner};
use super::publisher::{SignedPublicationCoordinator, SignedPublicationError};
use super::shared_publisher::{
    RuntimeStoreSharedPublicationBackend, SharedPublisherError, SharedStreamPublisher,
};
use super::transition_owner::{
    KeyTransitionRecoveryError, KeyTransitionRecoveryHandle, KeyTransitionRecoveryOwner,
    TransitionProgress, TransitionReadiness,
};
use super::transport::{
    AuthenticatedBusinessReconnects, BusinessTransportLane, MachineDataAuthority,
    PairingRuntimeParts, RemoteTransport, RemoteTransportConnectError,
};
use super::trust_reset::{MachineTrustResetWorkflow, MachineTrustResetWorkflowError};
use super::workflow::MachineEnrollmentWorkflow;

const REMOTE_DISABLED: &str = "daemon.remote.administration.unavailable";
const REMOTE_NOT_ARMED: &str = "daemon.remote.start_not_armed";
const REMOTE_SHUTTING_DOWN: &str = "daemon.remote.shutting_down";
const REMOTE_STATE_CONFLICT: &str = "daemon.remote.enrollment.state_conflict";
const REMOTE_QUIESCENCE_UNKNOWN: &str = "daemon.remote.quiescence_unknown";
const PAIRING_DRAIN_WAIT_DEADLINE: Duration = Duration::from_secs(10);
const BUSINESS_STARTUP_DEADLINE: Duration = Duration::from_secs(30);
const PAIRING_DRAIN_PENDING: &str = "daemon.pairing.drain_pending";
const PAIRING_ACTIVE: &str = "daemon.pairing.active";
const ROOT_PRESENT_RECEIPT_FORBIDDEN: &str =
    "daemon.remote.trust_reset.root_present_receipt_forbidden";
const ROOT_LOST_RECEIPT_REQUIRED: &str = "daemon.remote.trust_reset.admin_receipt_required";
const PURGE_FINALIZER_UNAVAILABLE: &str = "daemon.purge.finalizer_unavailable";
const PURGE_RECOVERY_REQUIRED: &str = "daemon.purge.recovery_required";
const TRANSITION_OWNER_UNAVAILABLE: &str = "daemon.remote.transition.owner_unavailable";
const TRANSITION_RECOVERY_TIMED_OUT: &str = "daemon.remote.transition.recovery_timed_out";
const TRANSITION_PROGRESS_PENDING: &str = "daemon.remote.transition.progress_pending";
const TRANSITION_RECONNECT_PENDING: &str = "daemon.remote.transition.reconnect_pending";
const COUNTER_RETIRED: &str = "daemon.remote.counter.retired";
const COUNTER_RECOVERY_ENTROPY_UNAVAILABLE: &str =
    "daemon.remote.counter.recovery_entropy_unavailable";
const COUNTER_RECOVERY_ENTROPY_ATTEMPTS: usize = 16;

#[derive(Clone)]
struct ActiveSenderCounterCandidate {
    scope: CounterScope,
    key_id: KeyId,
    replacement_scope: CounterScope,
    target: CounterRecoveryStageTarget,
}

enum PairingDrainWaitError {
    NotEnqueued(PairingAdministrationError),
    Unconfirmed(PairingAdministrationError),
    ActorBusy(PairingAdministrationError),
    ActorFailed(PairingAdministrationError),
    Pending,
    ShuttingDown,
}

enum PairingCommandWaitError {
    Pending,
    ShuttingDown,
}

/// `uninstall --purge` 的 existing-only finalization marker 窄边界。
/// reserve 必须先于 trust-reset；authorize 只接受当前 Store 的 authenticated
/// remote tombstone 或明确未登记的本机 identity，并把 machine-key/DB 删除留给
/// stopped finalizer。
#[async_trait]
pub trait PurgePlanSink: Send + Sync {
    /// canonical marker 存在即代表 durable purge intent；错误必须 fail-close。
    async fn intent_readback(&self) -> Result<bool, RemoteAdministrationError>;

    async fn reserve_and_readback(
        &self,
        plan: &UninstallPurgePlanV1,
    ) -> Result<(), RemoteAdministrationError>;

    async fn authorize_and_readback(
        &self,
        plan: UninstallPurgePlanV1,
    ) -> Result<(), RemoteAdministrationError>;

    /// daemon 在 Reserved→PurgeReadbackAbsent→authorize 窗口崩溃时的 existing-only
    /// 恢复入口。Absent 代表 ordinary trust-reset，可继续普通 cleanup；Ready 代表
    /// marker 已授权，启动恢复不得删除 machine keys 或推进 LocalDeleted。
    async fn resume_reserved_and_readback(
        &self,
    ) -> Result<PurgeReservationResume, RemoteAdministrationError>;
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum PurgeReservationResume {
    Absent,
    Ready,
}

#[derive(Debug, Default)]
pub struct DisabledPurgePlanSink;

#[async_trait]
impl PurgePlanSink for DisabledPurgePlanSink {
    async fn intent_readback(&self) -> Result<bool, RemoteAdministrationError> {
        Ok(false)
    }

    async fn reserve_and_readback(
        &self,
        _plan: &UninstallPurgePlanV1,
    ) -> Result<(), RemoteAdministrationError> {
        Err(admin_error(PURGE_FINALIZER_UNAVAILABLE))
    }

    async fn authorize_and_readback(
        &self,
        _plan: UninstallPurgePlanV1,
    ) -> Result<(), RemoteAdministrationError> {
        Err(admin_error(PURGE_FINALIZER_UNAVAILABLE))
    }

    async fn resume_reserved_and_readback(
        &self,
    ) -> Result<PurgeReservationResume, RemoteAdministrationError> {
        Err(admin_error(PURGE_FINALIZER_UNAVAILABLE))
    }
}

struct KeychainPurgePlanSink {
    store: RuntimeStoreHandle,
    key_store: Arc<dyn KeyStore>,
    paths: crate::runtime::namespace::DaemonPaths,
    running_identity: RunningFinalizerIdentity,
}

impl KeychainPurgePlanSink {
    async fn load_authenticated_authorization(
        &self,
    ) -> Result<AuthenticatedPurgeAuthorization, RemoteAdministrationError> {
        let remote_state = self.store.load_machine_enrollment_state().await?;
        let authorization = match remote_state {
            Some(MachineEnrollmentState::PurgeReadbackAbsent(state)) => {
                AuthenticatedPurgeAuthorization::from_purge_readback_absent(&self.store, &state)
            }
            Some(MachineEnrollmentState::LocalDeleted(state)) => {
                AuthenticatedPurgeAuthorization::from_local_deleted(&self.store, &state)
            }
            None => {
                let identity = self
                    .store
                    .load_machine_identity_state()
                    .await?
                    .ok_or_else(|| admin_error("daemon.purge.authorization_invalid"))?;
                AuthenticatedPurgeAuthorization::from_unenrolled_identity(&self.store, &identity)
            }
            Some(
                MachineEnrollmentState::EnrollmentPrepared(_)
                | MachineEnrollmentState::EnrollmentResponseValidated(_)
                | MachineEnrollmentState::Active(_)
                | MachineEnrollmentState::RetirePending(_)
                | MachineEnrollmentState::RelayCommitted(_),
            ) => return Err(admin_error("daemon.purge.authorization_invalid")),
        };
        authorization.map_err(|error| admin_error(error.code()))
    }
}

#[async_trait]
impl PurgePlanSink for KeychainPurgePlanSink {
    async fn intent_readback(&self) -> Result<bool, RemoteAdministrationError> {
        purge_marker_intent_present(self.key_store.as_ref())
            .map_err(|error| admin_error(error.code()))
    }

    async fn reserve_and_readback(
        &self,
        plan: &UninstallPurgePlanV1,
    ) -> Result<(), RemoteAdministrationError> {
        reserve_purge_marker(
            self.key_store.as_ref(),
            &self.paths,
            &self.running_identity,
            plan,
        )
        .map_err(|error| admin_error(error.code()))?;
        Ok(())
    }

    async fn authorize_and_readback(
        &self,
        plan: UninstallPurgePlanV1,
    ) -> Result<(), RemoteAdministrationError> {
        let reservation = reserve_purge_marker(
            self.key_store.as_ref(),
            &self.paths,
            &self.running_identity,
            &plan,
        )
        .map_err(|error| admin_error(error.code()))?;
        let authorization = self.load_authenticated_authorization().await?;
        authorize_reserved_purge_marker(
            self.key_store.as_ref(),
            &self.paths,
            &self.running_identity,
            &reservation,
            authorization,
        )
        .map_err(|error| admin_error(error.code()))?;
        Ok(())
    }

    async fn resume_reserved_and_readback(
        &self,
    ) -> Result<PurgeReservationResume, RemoteAdministrationError> {
        if !self.intent_readback().await? {
            return Ok(PurgeReservationResume::Absent);
        }
        let authorization = self.load_authenticated_authorization().await?;
        let outcome = resume_reserved_purge_marker(
            self.key_store.as_ref(),
            &self.paths,
            &self.running_identity,
            authorization,
        )
        .map_err(|error| admin_error(error.code()))?;
        Ok(match outcome {
            ResumeReservedPurgeMarkerOutcome::Absent => PurgeReservationResume::Absent,
            ResumeReservedPurgeMarkerOutcome::Authorized { .. }
            | ResumeReservedPurgeMarkerOutcome::Replayed { .. } => PurgeReservationResume::Ready,
        })
    }
}

pub struct RemoteManager {
    store: RuntimeStoreHandle,
    key_store: Arc<dyn KeyStore>,
    config: DaemonConfig,
    purge_plan_sink: Arc<dyn PurgePlanSink>,
    enrollment_workflow: MachineEnrollmentWorkflow,
    pairing_pending_sink: OnceLock<Arc<dyn PairingPendingSink>>,
    runtime_core: OnceLock<Weak<RuntimeCore>>,
    shutdown_tx: watch::Sender<bool>,
    trust_reset_singleflight: Mutex<()>,
    business_start_singleflight: Mutex<()>,
    #[cfg(test)]
    pairing_startup_for_test: Mutex<Option<PairingStartupTestHook>>,
    #[cfg(test)]
    business_startup_for_test: Mutex<Option<oneshot::Sender<()>>>,
    #[cfg(test)]
    business_start_failure_after_lane_for_test: Mutex<Option<&'static str>>,
    state: Mutex<RemoteManagerState>,
}

#[cfg(test)]
struct PairingStartupTestHook {
    owner: PairingCoordinatorOwner,
    ready_rx: oneshot::Receiver<Result<(), PairingAdministrationError>>,
    entered_tx: oneshot::Sender<()>,
}

struct RemoteManagerState {
    enabled: bool,
    armed: bool,
    stopped: bool,
    /// 任一 business owner 的 stop/join 返回失败后，本进程不能再声称已证明静默。
    /// 只允许通过进程重启、重新加载 durable state 后清除此 latch。
    quiescence_unknown: bool,
    purge_pending: bool,
    identity: Option<Box<ActiveMachineIdentity>>,
    start_permit: Option<RemoteStartPermit>,
    transport: Option<RemoteTransport>,
    link: Option<Box<dyn ManagedRemoteLinkOwner>>,
    transition: Option<Box<dyn ManagedTransitionOwner>>,
    transition_handle: Option<Arc<dyn ManagedTransitionHandle>>,
    maintenance: Option<Box<dyn ManagedMaintenanceOwner>>,
    publication: Option<Box<dyn ManagedPublicationOwner>>,
    pending_business_start: Option<PendingBusinessStart>,
    pairing: Option<PairingCoordinatorOwner>,
    #[cfg(test)]
    pairing_handle_for_test: Option<super::pairing::PairingCoordinatorHandle>,
    connect_retry: Option<RemoteTransportConnectError>,
    blocked_code: Option<String>,
}

#[derive(Clone)]
struct PendingBusinessStart {
    machine_route: [u8; 16],
    machine_data: MachineDataAuthority,
}

#[async_trait]
trait ManagedRemoteLinkOwner: Send {
    async fn shutdown(&mut self) -> Result<(), RemoteLinkError>;

    fn observed_failure_code(&self) -> Option<String> {
        None
    }
}

#[async_trait]
impl ManagedRemoteLinkOwner for RemoteLinkOwner {
    async fn shutdown(&mut self) -> Result<(), RemoteLinkError> {
        RemoteLinkOwner::shutdown(self).await
    }

    fn observed_failure_code(&self) -> Option<String> {
        RemoteLinkOwner::observed_failure_code(self)
    }
}

#[async_trait]
trait ManagedPublicationOwner: Send {
    async fn shutdown(self: Box<Self>) -> Result<(), PublicationDriveError>;
}

#[async_trait]
impl ManagedPublicationOwner for PublicationDriveOwner {
    async fn shutdown(self: Box<Self>) -> Result<(), PublicationDriveError> {
        PublicationDriveOwner::shutdown(*self).await
    }
}

/// key transition 的 manager-owned 生命周期窄面。协调器的 Store/crypto/Relay
/// 语义留在 transition 模块；manager 只负责启动成功后持有 owner，并在 publication
/// drive 之前逆序回收。
#[async_trait]
trait ManagedTransitionOwner: Send {
    async fn shutdown(self: Box<Self>) -> Result<(), RemoteAdministrationError>;

    fn observed_failure_code(&self) -> Option<String> {
        None
    }
}

#[async_trait]
trait ManagedTransitionHandle: Send + Sync {
    fn request_control_plane_progress(&self) -> Result<(), RemoteAdministrationError>;

    fn subscribe_progress(&self) -> Option<watch::Receiver<TransitionProgress>> {
        None
    }

    async fn drive_to_business_ready(
        &self,
    ) -> Result<TransitionReadiness, RemoteAdministrationError>;
}

/// retention GC 的 manager-owned 生命周期窄面。任何 machine scrub 前必须先 join，
/// 防止 replay/key/transition 删除与 trust-reset 或 uninstall 并发。
#[async_trait]
trait ManagedMaintenanceOwner: Send {
    async fn shutdown(self: Box<Self>) -> Result<(), RemoteAdministrationError>;
}

#[async_trait]
impl ManagedMaintenanceOwner for RemoteMaintenanceOwner {
    async fn shutdown(self: Box<Self>) -> Result<(), RemoteAdministrationError> {
        RemoteMaintenanceOwner::shutdown(*self)
            .await
            .map_err(remote_maintenance_error)
    }
}

#[async_trait]
impl ManagedTransitionOwner for KeyTransitionRecoveryOwner {
    async fn shutdown(self: Box<Self>) -> Result<(), RemoteAdministrationError> {
        KeyTransitionRecoveryOwner::shutdown(*self)
            .await
            .map_err(transition_recovery_error)
    }

    fn observed_failure_code(&self) -> Option<String> {
        KeyTransitionRecoveryOwner::observed_failure_code(self)
    }
}

#[async_trait]
impl ManagedTransitionHandle for KeyTransitionRecoveryHandle {
    fn request_control_plane_progress(&self) -> Result<(), RemoteAdministrationError> {
        KeyTransitionRecoveryHandle::request_control_plane_progress(self)
            .map_err(transition_recovery_error)
    }

    fn subscribe_progress(&self) -> Option<watch::Receiver<TransitionProgress>> {
        Some(KeyTransitionRecoveryHandle::subscribe_progress(self))
    }

    async fn drive_to_business_ready(
        &self,
    ) -> Result<TransitionReadiness, RemoteAdministrationError> {
        KeyTransitionRecoveryHandle::drive_to_business_ready(self)
            .await
            .map_err(transition_recovery_error)
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum RemoteBusinessAdmissionPhase {
    LaneClaimed,
    CounterAudited,
    TransitionReady,
    PendingRecovered,
}

/// RemoteLink 的线性 admission capability。只有同一 business lane 的 durable pending
/// outbox 已收口，且 transition owner 已从 Store 读回 business-ready，才能生成 permit。
struct RemoteBusinessAdmission {
    phase: RemoteBusinessAdmissionPhase,
    mode: Option<RemoteLinkAdmissionMode>,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum RemoteLinkAdmissionMode {
    ControlPlaneOnly,
    BusinessReady,
}

#[derive(Debug)]
struct RemoteBusinessAdmissionPermit {
    mode: RemoteLinkAdmissionMode,
}

impl RemoteBusinessAdmission {
    const fn new() -> Self {
        Self {
            phase: RemoteBusinessAdmissionPhase::LaneClaimed,
            mode: None,
        }
    }

    fn observe_counter_audit<T>(
        &mut self,
        audit: Result<T, RemoteAdministrationError>,
    ) -> Result<T, RemoteAdministrationError> {
        let audited = audit?;
        if self.phase != RemoteBusinessAdmissionPhase::LaneClaimed {
            return Err(admin_error(REMOTE_STATE_CONFLICT));
        }
        self.phase = RemoteBusinessAdmissionPhase::CounterAudited;
        Ok(audited)
    }

    fn observe_publication_recovery(
        &mut self,
        recovery: Result<(), PublicationDriveError>,
    ) -> Result<(), RemoteAdministrationError> {
        recovery.map_err(publication_drive_error)?;
        if self.phase != RemoteBusinessAdmissionPhase::TransitionReady {
            return Err(admin_error(REMOTE_STATE_CONFLICT));
        }
        self.phase = RemoteBusinessAdmissionPhase::PendingRecovered;
        Ok(())
    }

    fn observe_transition_readiness(
        &mut self,
        readiness: Result<TransitionReadiness, RemoteAdministrationError>,
    ) -> Result<(), RemoteAdministrationError> {
        let mode = match readiness? {
            TransitionReadiness::ControlPlaneReady { .. } => {
                RemoteLinkAdmissionMode::ControlPlaneOnly
            }
            TransitionReadiness::NoActiveTransition | TransitionReadiness::BusinessReady { .. } => {
                RemoteLinkAdmissionMode::BusinessReady
            }
        };
        self.observe_transition_ready(mode)
    }

    fn observe_transition_ready(
        &mut self,
        mode: RemoteLinkAdmissionMode,
    ) -> Result<(), RemoteAdministrationError> {
        if self.phase != RemoteBusinessAdmissionPhase::CounterAudited {
            return Err(admin_error(REMOTE_STATE_CONFLICT));
        }
        self.phase = RemoteBusinessAdmissionPhase::TransitionReady;
        self.mode = Some(mode);
        Ok(())
    }

    fn into_permit(self) -> Result<RemoteBusinessAdmissionPermit, RemoteAdministrationError> {
        if self.phase != RemoteBusinessAdmissionPhase::PendingRecovered {
            return Err(admin_error("daemon.remote.link.admission_fenced"));
        }
        self.mode
            .map(|mode| RemoteBusinessAdmissionPermit { mode })
            .ok_or_else(|| admin_error("daemon.remote.link.admission_fenced"))
    }
}

#[allow(clippy::too_many_arguments)]
fn start_admitted_remote_link(
    permit: RemoteBusinessAdmissionPermit,
    machine_route: MachineRouteId,
    store: RuntimeStoreHandle,
    lane: BusinessTransportLane,
    core: Weak<RuntimeCore>,
    sealer: Arc<DeviceReplyTxSealer>,
    publisher: Arc<SharedStreamPublisher>,
    key_control: Arc<StoreBackedKeyControlIngressHandler>,
) -> Result<RemoteLinkOwner, RemoteLinkError> {
    let ingress_mode = match permit.mode {
        RemoteLinkAdmissionMode::ControlPlaneOnly => RemoteLinkIngressMode::ControlPlaneOnly,
        RemoteLinkAdmissionMode::BusinessReady => RemoteLinkIngressMode::BusinessReady,
    };
    RemoteLinkOwner::start_with_ingress_mode_and_key_control_handler(
        machine_route,
        store,
        lane,
        core,
        sealer,
        publisher,
        key_control,
        ingress_mode,
    )
}

impl RemoteManager {
    #[must_use]
    pub fn new(
        store: RuntimeStoreHandle,
        key_store: Arc<dyn KeyStore>,
        config: DaemonConfig,
        bootstrap: RemoteBootstrapOutcome,
    ) -> Self {
        let (enabled, identity, blocked_code) = match bootstrap {
            RemoteBootstrapOutcome::Disabled => (false, None, None),
            RemoteBootstrapOutcome::Active(identity) => (true, Some(identity), None),
            RemoteBootstrapOutcome::Blocked(block) => (true, None, Some(block.code().to_owned())),
        };
        let purge_plan_sink: Arc<dyn PurgePlanSink> = RunningFinalizerIdentity::production()
            .map(|running_identity| {
                Arc::new(KeychainPurgePlanSink {
                    store: store.clone(),
                    key_store: key_store.clone(),
                    paths: config.paths().clone(),
                    running_identity,
                }) as Arc<dyn PurgePlanSink>
            })
            .unwrap_or_else(|_| Arc::new(DisabledPurgePlanSink));
        Self {
            store,
            key_store,
            config,
            purge_plan_sink,
            enrollment_workflow: MachineEnrollmentWorkflow::new(),
            pairing_pending_sink: OnceLock::new(),
            runtime_core: OnceLock::new(),
            shutdown_tx: watch::channel(false).0,
            trust_reset_singleflight: Mutex::new(()),
            business_start_singleflight: Mutex::new(()),
            #[cfg(test)]
            pairing_startup_for_test: Mutex::new(None),
            #[cfg(test)]
            business_startup_for_test: Mutex::new(None),
            #[cfg(test)]
            business_start_failure_after_lane_for_test: Mutex::new(None),
            state: Mutex::new(RemoteManagerState {
                enabled,
                armed: false,
                stopped: false,
                quiescence_unknown: false,
                purge_pending: false,
                identity,
                start_permit: None,
                transport: None,
                link: None,
                transition: None,
                transition_handle: None,
                maintenance: None,
                publication: None,
                pending_business_start: None,
                pairing: None,
                #[cfg(test)]
                pairing_handle_for_test: None,
                connect_retry: None,
                blocked_code,
            }),
        }
    }

    #[must_use]
    pub fn with_purge_plan_sink(mut self, sink: Arc<dyn PurgePlanSink>) -> Self {
        self.purge_plan_sink = sink;
        self
    }

    /// RuntimeCore 构造后、remote arm 前单次安装 local-only pending sink。
    /// sink 只持 connection registry，不反向持有 Core 或 manager。
    pub fn install_pairing_pending_sink(&self, sink: Arc<dyn PairingPendingSink>) -> bool {
        self.pairing_pending_sink.set(sink).is_ok()
    }

    /// Core 强持有 manager administration capability，因此这里只安装 Weak，避免
    /// `RuntimeCore → RemoteManager → RemoteLink → RuntimeCore` 生命周期环。
    pub fn install_runtime_core(&self, core: &Arc<RuntimeCore>) -> bool {
        self.runtime_core.set(Arc::downgrade(core)).is_ok()
    }

    #[cfg(test)]
    fn with_enrollment_workflow(mut self, workflow: MachineEnrollmentWorkflow) -> Self {
        self.enrollment_workflow = workflow;
        self
    }

    #[cfg(test)]
    async fn install_pairing_startup_test_hook(
        &self,
        owner: PairingCoordinatorOwner,
        ready_rx: oneshot::Receiver<Result<(), PairingAdministrationError>>,
    ) -> oneshot::Receiver<()> {
        let (entered_tx, entered_rx) = oneshot::channel();
        *self.pairing_startup_for_test.lock().await = Some(PairingStartupTestHook {
            owner,
            ready_rx,
            entered_tx,
        });
        entered_rx
    }

    #[cfg(test)]
    async fn install_business_startup_test_hook(&self) -> oneshot::Receiver<()> {
        let (entered_tx, entered_rx) = oneshot::channel();
        *self.business_startup_for_test.lock().await = Some(entered_tx);
        entered_rx
    }

    #[cfg(test)]
    async fn install_business_start_failure_after_lane_for_test(&self, code: &'static str) {
        *self.business_start_failure_after_lane_for_test.lock().await = Some(code);
    }

    /// 唯一启动边界。调用前 manager 的 network side effect 恒为零。
    /// remote 恢复失败只形成 blocked status，不影响已绑定的 local listener。
    pub async fn arm(&self, permit: RemoteStartPermit) -> Result<(), RemoteAdministrationError> {
        let mut state = self.state.lock().await;
        if !state.enabled {
            return Err(admin_error(REMOTE_DISABLED));
        }
        if state.stopped || state.armed || state.start_permit.is_some() {
            return Err(admin_error(REMOTE_STATE_CONFLICT));
        }
        state.armed = true;
        state.start_permit = Some(permit);
        state.purge_pending = match self.purge_plan_sink.intent_readback().await {
            Ok(present) => present,
            Err(error) => {
                // malformed/unreadable marker is itself a purge fence; LocalDeleted re-enroll
                // must not treat a generic blocked code as permission to mint replacement keys.
                state.purge_pending = true;
                state.blocked_code = Some(error.code().to_owned());
                return Err(error);
            }
        };
        #[cfg(test)]
        let pairing_startup_for_test = self.pairing_startup_for_test.lock().await.take();
        #[cfg(test)]
        if let Some(mut hook) = pairing_startup_for_test {
            let _ = hook.entered_tx.send(());
            let ready =
                await_pairing_startup(&mut hook.owner, hook.ready_rx, self.shutdown_tx.subscribe())
                    .await;
            state.pairing = Some(hook.owner);
            state.blocked_code = None;
            return ready.map_err(|error| admin_error(error.code()));
        }
        if let Err(error) = self.resume_on_startup(&mut state).await {
            // pairing health 由 owner watch 动态提供；不能把一次 startup local/transport
            // 错误复制成永久 blocked_code，否则 actor 自愈后 status 仍会卡在 Blocked。
            state.blocked_code = state.pairing.is_none().then(|| error.code().to_owned());
            return Err(error);
        }
        drop(state);
        self.start_business_stack_if_ready().await
    }

    /// shutdown 没有 detached task：若 transport 存在，会先等待 Relay session join；
    /// main 只有在本 future 返回后才可停止 listener/Core。
    pub async fn shutdown(&self) {
        // 必须在等待 manager mutex 前发布取消。trust-reset 可能正持锁等待 Relay
        // terminal；先取消该 future 才能保证 SIGTERM/upgrade 有界取得 owner。
        self.shutdown_tx.send_replace(true);
        let mut state = self.state.lock().await;
        state.stopped = true;
        if let Err(error) = stop_remote_link(&mut state).await {
            crate::diag::log(
                "remote_link_shutdown",
                &format!("status=forced code={}", error.code()),
            );
            state.link.take();
        }
        if let Err(error) = stop_maintenance_owner(&mut state).await {
            log_forced_shutdown("remote_maintenance_shutdown", error.code());
        }
        if let Err(error) = stop_transition_owner(&mut state).await {
            log_forced_shutdown("remote_transition_shutdown", error.code());
        }
        if let Err(error) = stop_publication_owner(&mut state).await {
            log_forced_shutdown("remote_publication_shutdown", error.code());
        }
        stop_pairing_actor(&mut state).await;
        if let Some(mut transport) = state.transport.take() {
            transport.shutdown().await;
        }
        state.connect_retry = None;
        state.pending_business_start = None;
        state.identity = None;
        state.start_permit = None;
    }

    async fn resume_on_startup(
        &self,
        state: &mut RemoteManagerState,
    ) -> Result<(), RemoteAdministrationError> {
        let durable = self.store.load_machine_enrollment_state().await?;
        match durable {
            None => {
                if state.purge_pending {
                    return self.resume_existing_purge_intent(state).await;
                }
                if state.identity.is_some() {
                    state.blocked_code = None;
                }
                Ok(())
            }
            Some(MachineEnrollmentState::EnrollmentPrepared(_))
            | Some(MachineEnrollmentState::EnrollmentResponseValidated(_)) => {
                require_identity_and_permit(state)?;
                let active = self
                    .enrollment_workflow
                    .resume(&self.store)
                    .await
                    .map_err(|error| admin_error(error.code()))?;
                self.connect_active(state, *active).await
            }
            Some(MachineEnrollmentState::Active(active)) => {
                require_identity_and_permit(state)?;
                self.connect_active(state, *active).await
            }
            Some(MachineEnrollmentState::RetirePending(pending)) => {
                require_identity_and_permit(state)?;
                let connection = pending.connection.clone();
                let record = pending.record.clone();
                let binding = pending.binding.clone();
                let link_cert = pending.link_cert.clone();
                self.connect_parts(state, record, binding, connection, link_cert, None)
                    .await?;
                self.await_trust_reset(
                    MachineTrustResetWorkflow::new().resume_root_present_to_relay_committed(
                        &self.store,
                        state.transport.as_mut(),
                    ),
                )
                .await?;
                self.quiesce_remote_stack(state).await?;
                MachineTrustResetWorkflow::new()
                    .confirm_root_present_after_quiescence(&self.store)
                    .await
                    .map_err(|error| admin_error(error.code()))?;
                self.finish_purge_authorization(state, None).await
            }
            Some(MachineEnrollmentState::RelayCommitted(_)) => {
                // RetirementCommitted 已证明 Relay purge COMMIT+absent；这里严格零网络。
                self.quiesce_remote_stack(state).await?;
                MachineTrustResetWorkflow::new()
                    .confirm_root_present_after_quiescence(&self.store)
                    .await
                    .map_err(|error| admin_error(error.code()))?;
                self.finish_purge_authorization(state, None).await
            }
            Some(MachineEnrollmentState::PurgeReadbackAbsent(_)) => {
                self.finish_purge_authorization(state, None).await
            }
            Some(MachineEnrollmentState::LocalDeleted(_)) => {
                state.identity = None;
                if state.purge_pending {
                    return self.resume_existing_purge_intent(state).await;
                }
                state.blocked_code = None;
                Ok(())
            }
        }
    }

    async fn enroll_locked(
        &self,
        state: &mut RemoteManagerState,
        request: MachineEnrollRequest,
    ) -> Result<MachineRemoteStatus, RemoteAdministrationError> {
        require_running_armed(state)?;
        if state.purge_pending {
            return Err(admin_error(PURGE_RECOVERY_REQUIRED));
        }
        let now_ms = unix_now_ms()?;
        let durable = self.store.load_machine_enrollment_state().await?;
        match durable {
            None => {
                let config = ValidatedEnrollmentConfig::new(request.bundle, now_ms)
                    .map_err(|error| admin_error(error.code()))?;
                let identity = state.identity.as_ref().ok_or_else(|| {
                    admin_error(
                        state
                            .blocked_code
                            .as_deref()
                            .unwrap_or(REMOTE_STATE_CONFLICT),
                    )
                })?;
                if state.start_permit.is_none() {
                    return Err(admin_error(REMOTE_NOT_ARMED));
                }
                let frozen = FrozenMachineEnrollment::new(config, identity)
                    .map_err(machine_enrollment_error)?;
                let active = MachineEnrollmentWorkflow::new()
                    .run_fresh(&self.store, frozen.into_parts(), now_ms)
                    .await
                    .map_err(|error| admin_error(error.code()))?;
                self.connect_active(state, *active).await?;
            }
            Some(MachineEnrollmentState::LocalDeleted(_)) => {
                let config = ValidatedEnrollmentConfig::new(request.bundle, now_ms)
                    .map_err(|error| admin_error(error.code()))?;
                if state.transport.is_some() || state.connect_retry.is_some() {
                    return Err(admin_error(REMOTE_STATE_CONFLICT));
                }
                let pending = prepare_reenrollment_identity(&self.store, self.key_store.as_ref())
                    .await
                    .map_err(|error| admin_error(error.code()))?;
                let frozen = FrozenMachineEnrollment::new_reenrollment(config, &pending)
                    .map_err(machine_enrollment_error)?;
                let workflow = MachineEnrollmentWorkflow::new()
                    .run_fresh(&self.store, frozen.into_parts(), now_ms)
                    .await;
                let promoted = pending.activate_after_enrollment(&self.store).await;
                match (workflow, promoted) {
                    (Ok(active), Ok(identity)) => {
                        state.identity = Some(identity);
                        state.blocked_code = None;
                        self.connect_active(state, *active).await?;
                    }
                    (Err(error), Ok(identity)) => {
                        state.identity = Some(identity);
                        return Err(admin_error(error.code()));
                    }
                    (Ok(_), Err(error)) => {
                        return Err(admin_error(error.code()));
                    }
                    (Err(error), Err(_)) => return Err(admin_error(error.code())),
                }
            }
            Some(MachineEnrollmentState::EnrollmentPrepared(prepared)) => {
                // durable prepare 已拥有 exact code/origin/pins；即使带外 bundle 此刻
                // 过期，也必须继续 sealed request，不能冻结第二个 route/request。
                require_exact_enrollment_bundle(
                    &request.bundle,
                    &prepared.connection,
                    &prepared.request,
                )?;
                require_identity_and_permit(state)?;
                let active = self
                    .enrollment_workflow
                    .resume(&self.store)
                    .await
                    .map_err(|error| admin_error(error.code()))?;
                self.connect_active(state, *active).await?;
            }
            Some(MachineEnrollmentState::EnrollmentResponseValidated(validated)) => {
                require_exact_enrollment_bundle(
                    &request.bundle,
                    &validated.connection,
                    &validated.request,
                )?;
                require_identity_and_permit(state)?;
                let active = self
                    .enrollment_workflow
                    .resume(&self.store)
                    .await
                    .map_err(|error| admin_error(error.code()))?;
                self.connect_active(state, *active).await?;
            }
            Some(MachineEnrollmentState::Active(active)) => {
                let prepare_input_hash = machine_enrollment_prepare_input_hash(
                    request.bundle,
                    MachineRouteId::from_bytes(active.record.machine_route),
                    active.binding.clone(),
                    active.link_cert.clone(),
                    active.data_cert.clone(),
                )
                .map_err(|_| admin_error(REMOTE_STATE_CONFLICT))?;
                if prepare_input_hash != active.prepare_input_hash {
                    return Err(admin_error(REMOTE_STATE_CONFLICT));
                }
                if state.transport.is_none() {
                    if state.connect_retry.is_some() {
                        self.retry_connect(state).await?;
                    } else {
                        self.connect_active(state, *active).await?;
                    }
                }
            }
            Some(
                MachineEnrollmentState::RetirePending(_)
                | MachineEnrollmentState::RelayCommitted(_)
                | MachineEnrollmentState::PurgeReadbackAbsent(_),
            ) => return Err(admin_error(REMOTE_STATE_CONFLICT)),
        }
        require_pairing_owner_after_enroll(
            state.transport.is_some(),
            state.pairing.is_some(),
            state.blocked_code.as_deref(),
        )?;
        state.blocked_code = None;
        self.status_locked(state).await
    }

    async fn trust_reset_locked(
        &self,
        state: &mut RemoteManagerState,
        request: TrustResetRequest,
    ) -> Result<MachineRemoteStatus, RemoteAdministrationError> {
        require_running_armed(state)?;
        require_known_quiescence(state)?;
        let uninstall_plan = request.uninstall_purge_plan().cloned();
        let receipt = request.into_admin_purge_receipt();
        let durable = self.store.load_machine_enrollment_state().await?;
        if durable.is_none() {
            if let Some(plan) = uninstall_plan.as_ref() {
                if !state.purge_pending {
                    require_identity_and_permit(state)?;
                }
                self.reserve_purge_plan(state, plan).await?;
                self.finish_purge_authorization(state, uninstall_plan)
                    .await?;
            }
            return self.status_locked(state).await;
        }
        if matches!(durable, Some(MachineEnrollmentState::LocalDeleted(_))) {
            if let Some(plan) = uninstall_plan.as_ref() {
                self.reserve_purge_plan(state, plan).await?;
                self.finish_purge_authorization(state, uninstall_plan)
                    .await?;
            }
            return self.status_locked(state).await;
        }
        match durable.as_ref() {
            Some(MachineEnrollmentState::PurgeReadbackAbsent(_)) => {
                if let Some(plan) = uninstall_plan.as_ref() {
                    self.reserve_purge_plan(state, plan).await?;
                }
                self.finish_purge_authorization(state, uninstall_plan)
                    .await?;
                return self.status_locked(state).await;
            }
            Some(MachineEnrollmentState::RelayCommitted(_)) => {
                if let Some(plan) = uninstall_plan.as_ref() {
                    self.reserve_purge_plan(state, plan).await?;
                }
                self.quiesce_remote_stack(state).await?;
                MachineTrustResetWorkflow::new()
                    .confirm_root_present_after_quiescence(&self.store)
                    .await
                    .map_err(|error| admin_error(error.code()))?;
                self.finish_purge_authorization(state, uninstall_plan)
                    .await?;
                return self.status_locked(state).await;
            }
            _ => {}
        }
        let can_retire_online =
            state.identity.is_some() || state.transport.is_some() || state.connect_retry.is_some();
        if !can_retire_online
            && !matches!(durable.as_ref(), Some(MachineEnrollmentState::Active(_)))
        {
            // Frozen P4.2 semantics only authorize a portable root-lost receipt from
            // authenticated Active. Reject before reserving a purge marker or exposing an
            // operator action for Prepared/Validated/RetirePending.
            return Err(admin_error(REMOTE_STATE_CONFLICT));
        }
        if let Some(plan) = uninstall_plan.as_ref() {
            self.reserve_purge_plan(state, plan).await?;
        }
        if can_retire_online {
            if receipt.is_some() {
                return Err(admin_error(ROOT_PRESENT_RECEIPT_FORBIDDEN));
            }
            if state.transport.is_none() {
                if state.connect_retry.is_some() {
                    self.retry_connect(state).await?;
                } else {
                    let durable = self.store.load_machine_enrollment_state().await?;
                    let active = match durable.ok_or_else(|| admin_error(REMOTE_STATE_CONFLICT))? {
                        MachineEnrollmentState::Active(active) => active,
                        MachineEnrollmentState::EnrollmentPrepared(_)
                        | MachineEnrollmentState::EnrollmentResponseValidated(_) => {
                            require_identity_and_permit(state)?;
                            self.enrollment_workflow
                                .resume(&self.store)
                                .await
                                .map_err(|error| admin_error(error.code()))?
                        }
                        _ => return Err(admin_error(REMOTE_STATE_CONFLICT)),
                    };
                    self.connect_active(state, *active).await?;
                }
            }
            let durable = self.store.load_machine_enrollment_state().await?;
            match durable {
                Some(MachineEnrollmentState::Active(active)) => {
                    let transport = state
                        .transport
                        .as_mut()
                        .ok_or_else(|| admin_error(REMOTE_STATE_CONFLICT))?;
                    let frozen = transport
                        .freeze_retirement(
                            active.connection.relay_server_id,
                            active.record.trust_epoch,
                        )
                        .map_err(|error| admin_error(error.code()))?;
                    self.await_trust_reset(
                        MachineTrustResetWorkflow::new().run_root_present_to_relay_committed(
                            &self.store,
                            frozen,
                            transport,
                        ),
                    )
                    .await?;
                }
                Some(MachineEnrollmentState::RetirePending(_)) => {
                    self.await_trust_reset(
                        MachineTrustResetWorkflow::new().resume_root_present_to_relay_committed(
                            &self.store,
                            state.transport.as_mut(),
                        ),
                    )
                    .await?;
                }
                Some(MachineEnrollmentState::RelayCommitted(_)) => {}
                Some(MachineEnrollmentState::PurgeReadbackAbsent(_)) => {}
                _ => return Err(admin_error(REMOTE_STATE_CONFLICT)),
            }
            if !matches!(
                self.store.load_machine_enrollment_state().await?,
                Some(MachineEnrollmentState::PurgeReadbackAbsent(_))
            ) {
                self.quiesce_remote_stack(state).await?;
                MachineTrustResetWorkflow::new()
                    .confirm_root_present_after_quiescence(&self.store)
                    .await
                    .map_err(|error| admin_error(error.code()))?;
            }
        } else {
            let Some(receipt) = receipt else {
                state.blocked_code = Some(ROOT_LOST_RECEIPT_REQUIRED.to_owned());
                return self.status_locked(state).await;
            };
            // portable path 不持有/建立 transport，因此在 Store proof 前后都严格零网络。
            self.quiesce_remote_stack(state).await?;
            MachineTrustResetWorkflow::new()
                .run_root_lost(&self.store, *receipt)
                .await
                .map_err(|error| admin_error(error.code()))?;
        }
        self.finish_purge_authorization(state, uninstall_plan)
            .await?;
        self.status_locked(state).await
    }

    async fn await_trust_reset<F, T>(&self, operation: F) -> Result<T, RemoteAdministrationError>
    where
        F: Future<Output = Result<T, MachineTrustResetWorkflowError>>,
    {
        let mut shutdown_rx = self.shutdown_tx.subscribe();
        if *shutdown_rx.borrow() {
            return Err(admin_error(REMOTE_SHUTTING_DOWN));
        }
        tokio::select! {
            biased;
            changed = shutdown_rx.changed() => {
                let _ = changed;
                Err(admin_error(REMOTE_SHUTTING_DOWN))
            }
            result = operation => result.map_err(|error| admin_error(error.code())),
        }
    }

    async fn await_pairing_command<F, T>(
        &self,
        deadline: tokio::time::Instant,
        operation: F,
    ) -> Result<T, PairingCommandWaitError>
    where
        F: Future<Output = T>,
    {
        let mut shutdown_rx = self.shutdown_tx.subscribe();
        if *shutdown_rx.borrow() {
            return Err(PairingCommandWaitError::ShuttingDown);
        }
        tokio::select! {
            biased;
            changed = shutdown_rx.changed() => {
                let _ = changed;
                Err(PairingCommandWaitError::ShuttingDown)
            }
            result = tokio::time::timeout_at(deadline, operation) => {
                result.map_err(|_| PairingCommandWaitError::Pending)
            }
        }
    }

    async fn await_pairing_drain(
        &self,
        handle: &PairingCoordinatorHandle,
        deadline: tokio::time::Instant,
    ) -> Result<(), PairingDrainWaitError> {
        // deadline 只终止本次 administration 等待；被丢弃的 reply receiver 会由
        // actor 清理，durable Running drain 保持不变，后续 retry 可挂接新 waiter。
        match self
            .await_pairing_command(deadline, handle.begin_drain())
            .await
        {
            Ok(Ok(())) => Ok(()),
            Ok(Err(PairingDrainStartError::NotEnqueued(error))) => {
                Err(PairingDrainWaitError::NotEnqueued(error))
            }
            Ok(Err(PairingDrainStartError::Unconfirmed(error))) => {
                Err(PairingDrainWaitError::Unconfirmed(error))
            }
            Ok(Err(PairingDrainStartError::ActorBusy(error))) => {
                Err(PairingDrainWaitError::ActorBusy(error))
            }
            Ok(Err(PairingDrainStartError::ActorFailed(error))) => {
                Err(PairingDrainWaitError::ActorFailed(error))
            }
            Err(PairingCommandWaitError::Pending) => Err(PairingDrainWaitError::Pending),
            Err(PairingCommandWaitError::ShuttingDown) => Err(PairingDrainWaitError::ShuttingDown),
        }
    }

    async fn resume_pairing_before_deadline<F>(
        &self,
        deadline: tokio::time::Instant,
        operation: F,
    ) -> Result<(), RemoteAdministrationError>
    where
        F: Future<Output = Result<(), PairingAdministrationError>>,
    {
        match self.await_pairing_command(deadline, operation).await {
            Ok(Ok(())) => Ok(()),
            Ok(Err(error)) => Err(admin_error(error.code())),
            Err(PairingCommandWaitError::Pending) => Err(admin_error(PAIRING_DRAIN_PENDING)),
            Err(PairingCommandWaitError::ShuttingDown) => Err(admin_error(REMOTE_SHUTTING_DOWN)),
        }
    }

    async fn has_unowned_pairing_work(&self) -> Result<bool, RemoteAdministrationError> {
        let pairings = self.store.list_pairing_recovery().await?;
        let revocation_targets = self.store.list_revocation_drain_targets().await?;
        let revocations = self.store.list_revocation_recovery().await?;
        Ok(!pairings.is_empty() || !revocation_targets.is_empty() || !revocations.is_empty())
    }

    async fn finish_purge_authorization(
        &self,
        state: &mut RemoteManagerState,
        uninstall_plan: Option<UninstallPurgePlanV1>,
    ) -> Result<(), RemoteAdministrationError> {
        let resume = if let Some(plan) = uninstall_plan {
            self.purge_plan_sink.authorize_and_readback(plan).await?;
            PurgeReservationResume::Ready
        } else {
            self.purge_plan_sink.resume_reserved_and_readback().await?
        };
        match resume {
            PurgeReservationResume::Absent => {
                if state.purge_pending {
                    return Err(admin_error(PURGE_RECOVERY_REQUIRED));
                }
                self.cleanup(state).await?;
                state.purge_pending = false;
            }
            PurgeReservationResume::Ready => {
                self.quiesce_for_purge_finalizer(state).await?;
            }
        }
        state.blocked_code = None;
        Ok(())
    }

    async fn reserve_purge_plan(
        &self,
        state: &mut RemoteManagerState,
        plan: &UninstallPurgePlanV1,
    ) -> Result<(), RemoteAdministrationError> {
        self.purge_plan_sink.reserve_and_readback(plan).await?;
        // 与 reserve exact readback 在同一 manager mutex turn 内设置，任何后续 enroll
        // 都先命中 latch；授权失败也不能清除 durable intent。
        state.purge_pending = true;
        Ok(())
    }

    async fn resume_existing_purge_intent(
        &self,
        state: &mut RemoteManagerState,
    ) -> Result<(), RemoteAdministrationError> {
        match self.purge_plan_sink.resume_reserved_and_readback().await? {
            PurgeReservationResume::Ready => {
                self.quiesce_for_purge_finalizer(state).await?;
                state.blocked_code = None;
                Ok(())
            }
            PurgeReservationResume::Absent => {
                state.purge_pending = true;
                Err(admin_error(PURGE_RECOVERY_REQUIRED))
            }
        }
    }

    async fn quiesce_for_purge_finalizer(
        &self,
        state: &mut RemoteManagerState,
    ) -> Result<(), RemoteAdministrationError> {
        self.quiesce_remote_stack(state).await?;
        state.identity = None;
        state.purge_pending = true;
        Ok(())
    }

    /// 在任何本地 machine scrub / finalizer handoff 前证明所有 P4.5 业务 owner 已静默。
    /// stop/join 固定逆序为 Link → maintenance → transition → publication → pairing，
    /// 随后才消费并回收 transport。任一步无法证明 join，都会设置不可逆的进程内
    /// latch；调用方不能继续 confirm、删 Keychain 或释放 finalizer readiness。
    async fn quiesce_remote_stack(
        &self,
        state: &mut RemoteManagerState,
    ) -> Result<(), RemoteAdministrationError> {
        require_known_quiescence(state)?;
        if state.connect_retry.is_some() {
            return Err(admin_error(REMOTE_STATE_CONFLICT));
        }
        state.pending_business_start = None;

        let mut unknown = false;
        if let Err(error) = stop_remote_link(state).await {
            unknown = true;
            log_quiescence_failure("remote_link_shutdown", error.code());
        }
        if let Err(error) = stop_maintenance_owner(state).await {
            unknown = true;
            log_quiescence_failure("remote_maintenance_shutdown", error.code());
        }
        if let Err(error) = stop_transition_owner(state).await {
            unknown = true;
            log_quiescence_failure("remote_transition_shutdown", error.code());
        }
        if let Err(error) = stop_publication_owner(state).await {
            unknown = true;
            log_quiescence_failure("remote_publication_shutdown", error.code());
        }
        stop_pairing_actor(state).await;

        if let Some(transport) = state.transport.take() {
            match transport.shutdown_and_reclaim_start_permit().await {
                Ok(permit) => state.start_permit = Some(permit),
                Err(error) => {
                    unknown = true;
                    log_quiescence_failure("remote_transport_shutdown", error.code());
                }
            }
        }
        if unknown {
            state.quiescence_unknown = true;
            state.blocked_code = Some(REMOTE_QUIESCENCE_UNKNOWN.to_owned());
            return Err(admin_error(REMOTE_QUIESCENCE_UNKNOWN));
        }
        Ok(())
    }

    async fn connect_active(
        &self,
        state: &mut RemoteManagerState,
        active: ActiveMachineEnrollmentState,
    ) -> Result<(), RemoteAdministrationError> {
        let data_cert = active.data_cert;
        self.connect_parts(
            state,
            active.record,
            active.binding,
            active.connection,
            active.link_cert,
            Some(data_cert),
        )
        .await
    }

    async fn connect_parts(
        &self,
        state: &mut RemoteManagerState,
        record: MachineRemoteStateRecord,
        binding: crate::runtime::store::MachineIdentityBinding,
        connection: MachineEnrollmentConnectionMaterial,
        link_cert: agentdeck_protocol::relay_v2::SignedCertificate,
        data_cert: Option<agentdeck_protocol::relay_v2::SignedCertificate>,
    ) -> Result<(), RemoteAdministrationError> {
        if state.transport.is_some() {
            return Ok(());
        }
        let identity = state
            .identity
            .as_ref()
            .ok_or_else(|| admin_error(REMOTE_STATE_CONFLICT))?;
        if identity.binding() != &binding
            || record.relay_server_id != *connection.relay_server_id.as_bytes()
            || record.machine_route == [0; 16]
        {
            return Err(admin_error(REMOTE_STATE_CONFLICT));
        }
        let (client_config, _) = validate_sealed_relay_connection(
            &connection.public_wss_url,
            connection.relay_server_id,
            &connection.receipt_verify_key,
            &connection.spki_pins,
            connection.expires_at_ms,
        )
        .map_err(enrollment_config_error)?;
        if state.identity.is_none() || state.start_permit.is_none() {
            return Err(admin_error(REMOTE_NOT_ARMED));
        }
        let permit = state
            .start_permit
            .take()
            .ok_or_else(|| admin_error(REMOTE_NOT_ARMED))?;
        let identity = state
            .identity
            .take()
            .expect("identity presence checked under the manager mutex");
        let pairing_connection = connection.clone();
        match RemoteTransport::connect(
            identity.arm(permit),
            client_config,
            agentdeck_protocol::relay_v2::MachineRouteId::from_bytes(record.machine_route),
            link_cert,
        )
        .await
        {
            Ok(mut transport) => {
                let pairing_start = match data_cert {
                    Some(data_cert) => match self
                        .start_pairing_actor(state, &mut transport, pairing_connection, data_cert)
                        .await
                    {
                        Ok(machine_data) => {
                            stage_business_start(state, record.machine_route, machine_data)
                        }
                        Err(error) => {
                            record_pairing_start_failure(state, &error);
                            Err(error)
                        }
                    },
                    // RetirePending deliberately has no data cert/business link.
                    None => Ok(()),
                };
                state.transport = Some(transport);
                state.connect_retry = None;
                match pairing_start {
                    Ok(()) => {
                        state.blocked_code = None;
                        Ok(())
                    }
                    Err(error) => Err(error),
                }
            }
            Err(error) => {
                let code = error.code().to_owned();
                state.connect_retry = Some(error);
                state.blocked_code = Some(code.clone());
                Err(admin_error(code))
            }
        }
    }

    async fn retry_connect(
        &self,
        state: &mut RemoteManagerState,
    ) -> Result<(), RemoteAdministrationError> {
        let retry = state
            .connect_retry
            .take()
            .ok_or_else(|| admin_error(REMOTE_STATE_CONFLICT))?;
        match retry.retry().await {
            Ok(mut transport) => {
                let pairing_start = match self.store.load_machine_enrollment_state().await? {
                    Some(MachineEnrollmentState::Active(active)) => match self
                        .start_pairing_actor(
                            state,
                            &mut transport,
                            active.connection,
                            active.data_cert,
                        )
                        .await
                    {
                        Ok(machine_data) => {
                            stage_business_start(state, active.record.machine_route, machine_data)
                        }
                        Err(error) => {
                            record_pairing_start_failure(state, &error);
                            Err(error)
                        }
                    },
                    Some(MachineEnrollmentState::RetirePending(_)) => Ok(()),
                    _ => Err(admin_error(REMOTE_STATE_CONFLICT)),
                };
                state.transport = Some(transport);
                match pairing_start {
                    Ok(()) => {
                        state.blocked_code = None;
                        Ok(())
                    }
                    Err(error) => Err(error),
                }
            }
            Err(error) => {
                let code = error.code().to_owned();
                state.connect_retry = Some(error);
                state.blocked_code = Some(code.clone());
                Err(admin_error(code))
            }
        }
    }

    async fn start_pairing_actor(
        &self,
        state: &mut RemoteManagerState,
        transport: &mut RemoteTransport,
        connection: MachineEnrollmentConnectionMaterial,
        data_cert: agentdeck_protocol::relay_v2::SignedCertificate,
    ) -> Result<MachineDataAuthority, RemoteAdministrationError> {
        if state.pairing.is_some() {
            return Err(admin_error(REMOTE_STATE_CONFLICT));
        }
        let pending_sink = self
            .pairing_pending_sink
            .get()
            .cloned()
            .ok_or_else(|| admin_error("daemon.pairing.sink_unavailable"))?;
        let PairingRuntimeParts { lane, authority } = transport
            .take_pairing_runtime(data_cert)
            .map_err(|error| admin_error(error.code()))?;
        let machine_data = authority.machine_data_authority();
        let invite_anchor = authority
            .invite_anchor()
            .map_err(|error| admin_error(error.code()))?;
        let invite_context = PairingInviteContext::new(
            connection.public_wss_url,
            &connection.spki_pins,
            invite_anchor.clone(),
        )
        .map_err(|error| admin_error(error.code()))?;
        let (owner, ready) = PairingCoordinatorOwner::start(
            self.store.clone(),
            lane,
            authority,
            invite_anchor,
            invite_context,
            pending_sink,
            self.shutdown_tx.subscribe(),
        )
        .await;
        state.pairing = Some(owner);
        ready.map_err(|error| admin_error(error.code()))?;
        Ok(machine_data)
    }

    async fn start_business_stack_if_ready(&self) -> Result<(), RemoteAdministrationError> {
        let _singleflight = self.business_start_singleflight.lock().await;
        #[cfg(test)]
        if let Some(entered) = self.business_startup_for_test.lock().await.take() {
            let _ = entered.send(());
            let mut shutdown_rx = self.shutdown_tx.subscribe();
            if !*shutdown_rx.borrow() {
                let _ = shutdown_rx.changed().await;
            }
            return Err(admin_error(REMOTE_SHUTTING_DOWN));
        }

        let prepared = {
            let mut state = self.state.lock().await;
            if state.stopped {
                return Err(admin_error(REMOTE_SHUTTING_DOWN));
            }
            require_known_quiescence(&state)?;
            let Some(pending) = state.pending_business_start.as_ref().cloned() else {
                return Ok(());
            };
            if state.link.is_some()
                || state.transition.is_some()
                || state.transition_handle.is_some()
                || state.maintenance.is_some()
                || state.publication.is_some()
            {
                return Err(admin_error(REMOTE_STATE_CONFLICT));
            }
            let core = self
                .runtime_core
                .get()
                .cloned()
                .filter(|core| core.upgrade().is_some())
                .ok_or_else(|| admin_error("daemon.remote.runtime_core_unavailable"));
            let core = match core {
                Ok(core) => core,
                Err(error) => {
                    state.blocked_code = Some(error.code().to_owned());
                    return Err(error);
                }
            };
            let delivery_commit_rx = state
                .pairing
                .as_ref()
                .ok_or_else(|| admin_error(REMOTE_STATE_CONFLICT))?
                .subscribe_delivery_commits();
            let lane = match state.transport.as_mut() {
                Some(transport) => transport
                    .take_business_lane()
                    .map_err(|error| admin_error(error.code())),
                None => Err(admin_error(REMOTE_STATE_CONFLICT)),
            };
            let lane = match lane {
                Ok(lane) => lane,
                Err(error) => {
                    state.blocked_code = Some(error.code().to_owned());
                    return Err(error);
                }
            };
            (pending, lane, core, delivery_commit_rx)
        };
        let (pending, claimed_lane, core, delivery_commit_rx) = prepared;
        let mut lane = Some(claimed_lane);
        let machine_route = MachineRouteId::from_bytes(pending.machine_route);
        let machine_data = pending.machine_data;
        let mut admission = RemoteBusinessAdmission::new();
        #[cfg(test)]
        let injected_failure = self
            .business_start_failure_after_lane_for_test
            .lock()
            .await
            .take();

        let result: Result<Box<dyn ManagedRemoteLinkOwner>, RemoteAdministrationError> = async {
            #[cfg(test)]
            if let Some(code) = injected_failure {
                return Err(admin_error(code));
            }
            let machine_publication = lane
                .as_ref()
                .ok_or_else(|| admin_error(REMOTE_STATE_CONFLICT))?
                .publication_handle();
            let transition_reconnect_rx = machine_publication.subscribe_authenticated_reconnects();
            let pending_reconnect_rx = machine_publication.subscribe_authenticated_reconnects();
            let subscription_registration = machine_publication.clone();
            let publication_owner =
                PublicationDriveOwner::open(self.store.clone(), machine_publication)
                    .await
                    .map_err(publication_drive_error)?;
            let publication_drive = publication_owner.handle();
            {
                let mut state = self.state.lock().await;
                if state.stopped {
                    drop(state);
                    publication_owner
                        .shutdown()
                        .await
                        .map_err(publication_drive_error)?;
                    return Err(admin_error(REMOTE_SHUTTING_DOWN));
                }
                state.publication = Some(Box::new(publication_owner));
            }
            let deadline = tokio::time::Instant::now() + BUSINESS_STARTUP_DEADLINE;
            let guard = Arc::new(OwnedKeyStoreCounterGuardBackend::new(Arc::clone(
                &self.key_store,
            )));
            let shared_backend = Arc::new(
                RuntimeStoreSharedPublicationBackend::new(
                    self.store.clone(),
                    Arc::clone(&guard),
                    machine_route,
                )
                .map_err(shared_publisher_error)?,
            );
            let publisher = Arc::new(
                SharedStreamPublisher::new(
                    machine_route,
                    shared_backend,
                    Arc::new(publication_drive.clone()),
                    Arc::new(machine_data.clone()),
                )
                .and_then(|publisher| {
                    publisher.with_subscription_provisioning(
                        self.store.clone(),
                        subscription_registration,
                    )
                })
                .map_err(shared_publisher_error)?,
            );
            let transition_owner = KeyTransitionRecoveryOwner::start_with_authenticated_reconnect(
                self.store.clone(),
                Arc::clone(&self.key_store),
                machine_route,
                machine_data.clone(),
                publication_drive.clone(),
                transition_reconnect_rx,
                Some(delivery_commit_rx),
            )
            .map_err(transition_recovery_error)?;
            let transition_handle = transition_owner.handle();
            {
                let mut state = self.state.lock().await;
                if state.stopped {
                    drop(state);
                    transition_owner
                        .shutdown()
                        .await
                        .map_err(transition_recovery_error)?;
                    return Err(admin_error(REMOTE_SHUTTING_DOWN));
                }
                state.transition = Some(Box::new(transition_owner));
                state.transition_handle = Some(Arc::new(transition_handle.clone()));
            }
            drive_business_startup_gates(
                &self.store,
                guard.as_ref(),
                &publication_drive,
                &transition_handle,
                &mut admission,
                deadline,
                self.shutdown_tx.subscribe(),
                Some(pending_reconnect_rx),
            )
            .await?;
            let maintenance_now_ms = unix_now_ms()?;
            run_remote_maintenance_once(&self.store, self.key_store.as_ref(), maintenance_now_ms)
                .await
                .map_err(remote_maintenance_error)?;
            let maintenance_owner =
                RemoteMaintenanceOwner::start(self.store.clone(), Arc::clone(&self.key_store));
            {
                let mut state = self.state.lock().await;
                if state.stopped {
                    drop(state);
                    maintenance_owner
                        .shutdown()
                        .await
                        .map_err(remote_maintenance_error)?;
                    return Err(admin_error(REMOTE_SHUTTING_DOWN));
                }
                state.maintenance = Some(Box::new(maintenance_owner));
            }
            let sealer = Arc::new(DeviceReplyTxSealer::new(
                self.store.clone(),
                Arc::clone(&self.key_store),
                machine_data,
            ));
            let key_control =
                Arc::new(StoreBackedKeyControlIngressHandler::new(self.store.clone()));
            let admitted_lane = lane
                .take()
                .ok_or_else(|| admin_error(REMOTE_STATE_CONFLICT))?;
            start_admitted_remote_link(
                admission.into_permit()?,
                machine_route,
                self.store.clone(),
                admitted_lane,
                core,
                sealer,
                publisher,
                key_control,
            )
            .map(|owner| Box::new(owner) as Box<dyn ManagedRemoteLinkOwner>)
            .map_err(|error| admin_error(error.code()))
        }
        .await;

        match result {
            Ok(mut owner) => {
                let mut state = self.state.lock().await;
                if state.stopped {
                    drop(state);
                    let _ = owner.shutdown().await;
                    return Err(admin_error(REMOTE_SHUTTING_DOWN));
                }
                state.link = Some(owner);
                state.pending_business_start = None;
                state.blocked_code = None;
                Ok(())
            }
            Err(error) => {
                let mut state = self.state.lock().await;
                if !state.stopped {
                    state.blocked_code = Some(error.code().to_owned());
                }
                match rollback_business_start(&mut state).await {
                    Ok(()) => {
                        if !state.stopped
                            && let Some(claimed_lane) = lane.take()
                        {
                            let restored = match state.transport.as_mut() {
                                Some(transport) => transport
                                    .restore_business_lane(claimed_lane)
                                    .await
                                    .map_err(|restore| admin_error(restore.code())),
                                None => Err(admin_error(REMOTE_STATE_CONFLICT)),
                            };
                            if let Err(restore) = restored {
                                log_quiescence_failure(
                                    "remote_business_lane_start_rollback",
                                    restore.code(),
                                );
                                state.quiescence_unknown = true;
                                state.blocked_code = Some(REMOTE_QUIESCENCE_UNKNOWN.to_owned());
                                return Err(admin_error(REMOTE_QUIESCENCE_UNKNOWN));
                            }
                        }
                        Err(error)
                    }
                    Err(quiescence) => Err(quiescence),
                }
            }
        }
    }

    async fn cleanup(
        &self,
        state: &mut RemoteManagerState,
    ) -> Result<(), RemoteAdministrationError> {
        self.quiesce_remote_stack(state).await?;
        state.identity = None;
        state.connect_retry = None;
        state.pending_business_start = None;
        let transport = state.transport.take();
        match MachineCleanupWorkflow::new()
            .run(&self.store, self.key_store.as_ref(), transport)
            .await
        {
            Ok(outcome) => {
                if let Some(permit) = outcome.into_reclaimed_start_permit() {
                    state.start_permit = Some(permit);
                }
                state.blocked_code = None;
                Ok(())
            }
            Err(error) => {
                let code = error.code().to_owned();
                if let Some(permit) = error.into_reclaimed_start_permit() {
                    state.start_permit = Some(permit);
                }
                state.blocked_code = Some(code.clone());
                Err(admin_error(code))
            }
        }
    }

    async fn status_locked(
        &self,
        state: &mut RemoteManagerState,
    ) -> Result<MachineRemoteStatus, RemoteAdministrationError> {
        if state.blocked_code.as_deref() == Some(TRANSITION_RECOVERY_TIMED_OUT) {
            let transition_active = self.store.load_active_key_transition().await?.is_some();
            if transition_timeout_resolved(state.blocked_code.as_deref(), transition_active) {
                state.blocked_code = None;
            }
        }
        let enabled = state.enabled;
        let armed = state.armed;
        let stopped = state.stopped;
        let blocked_code = state
            .transport
            .as_ref()
            .and_then(RemoteTransport::observed_failure_code)
            .or_else(|| {
                state
                    .link
                    .as_ref()
                    .and_then(|link| link.observed_failure_code())
            })
            .or_else(|| {
                state
                    .pairing
                    .as_ref()
                    .and_then(PairingCoordinatorOwner::observed_failure_code)
            })
            .or_else(|| {
                state
                    .transition
                    .as_ref()
                    .and_then(|transition| transition.observed_failure_code())
            })
            .or_else(|| {
                state
                    .quiescence_unknown
                    .then(|| REMOTE_QUIESCENCE_UNKNOWN.to_owned())
            })
            .or_else(|| state.blocked_code.clone());
        if !enabled || !self.config.remote_enabled() {
            return Err(admin_error(REMOTE_DISABLED));
        }
        let counter_retired = self.store.has_retired_remote_counter().await?;
        let durable = self.store.load_machine_enrollment_state().await?;
        status_from_state(
            durable.as_ref(),
            counter_retired
                .then_some(COUNTER_RETIRED)
                .or(blocked_code.as_deref())
                .or_else(|| (!armed && !stopped).then_some(REMOTE_NOT_ARMED)),
            stopped,
        )
    }

    /// Conversation activation 已 durable COMMIT membership mutation 后，沿启动时安装的
    /// 唯一 transition owner 推进到 exact business-ready fence。等待 Store/Relay 时不持
    /// manager mutex；失败形成稳定 remote block，不能把已提交 mutation 伪装成业务可用。
    async fn drive_transition_to_business_ready(&self) -> Result<(), RemoteAdministrationError> {
        let handle = {
            let state = self.state.lock().await;
            if state.stopped {
                return Err(admin_error(REMOTE_SHUTTING_DOWN));
            }
            state
                .transition_handle
                .clone()
                .ok_or_else(|| admin_error(TRANSITION_OWNER_UNAVAILABLE))?
        };
        let result = await_exact_business_readiness(
            handle.as_ref(),
            tokio::time::Instant::now() + BUSINESS_STARTUP_DEADLINE,
            self.shutdown_tx.subscribe(),
        )
        .await;
        if let Err(error) = &result
            && error.code() == TRANSITION_RECOVERY_TIMED_OUT
        {
            let mut state = self.state.lock().await;
            if !state.stopped {
                state.blocked_code = Some(TRANSITION_RECOVERY_TIMED_OUT.to_owned());
            }
        }
        result
    }

    /// Pairing/revocation 的 durable receipt 只描述已提交的赢家/终态，不能被后续
    /// Relay barrier 或 endpoint ACK 覆写。把幂等推进交给 manager-owned transition
    /// owner 后立即返回；投递失败会稳定阻断 remote，但不改变已经提交的 receipt。
    async fn request_transition_control_plane_progress(&self) {
        let result = {
            let state = self.state.lock().await;
            if state.stopped {
                return;
            }
            state
                .transition_handle
                .clone()
                .ok_or_else(|| admin_error(TRANSITION_OWNER_UNAVAILABLE))
                .and_then(|handle| handle.request_control_plane_progress())
        };
        if let Err(error) = result {
            crate::diag::log(
                "remote_transition_progress",
                &format!("status=blocked code={}", error.code()),
            );
            let mut state = self.state.lock().await;
            if !state.stopped {
                state.blocked_code = Some(error.code().to_owned());
            }
        }
    }
}

fn transition_timeout_resolved(blocked_code: Option<&str>, transition_active: bool) -> bool {
    blocked_code == Some(TRANSITION_RECOVERY_TIMED_OUT) && !transition_active
}

async fn reconcile_active_sender_counters(
    store: &RuntimeStoreHandle,
    guard: &OwnedKeyStoreCounterGuardBackend,
) -> Result<Option<[u8; 16]>, RemoteAdministrationError> {
    if let Some(active) = store.load_active_key_transition().await?
        && active.transition.operation == KeyTransitionOperation::CounterRecovery
    {
        if active.transition.terminal.is_some() || active.transition.operation_id == [0; 16] {
            return Err(admin_error(COUNTER_RETIRED));
        }
        return Ok(Some(active.transition.operation_id));
    }

    let trust_domain = store.machine_trust_domain()?;
    let candidates = store
        .load_active_sender_counter_bindings()
        .await?
        .into_iter()
        .map(|binding| active_sender_counter_candidate(trust_domain, binding))
        .collect::<Result<Vec<_>, _>>()?;

    let mut retired = None;
    for candidate in &candidates {
        let record = store
            .load_remote_counter_record(candidate.scope.token(), candidate.key_id)
            .await?;
        match record.kind {
            RemoteCounterRecordKind::Retired => {
                if retired.replace(candidate.clone()).is_some() {
                    return Err(admin_error(COUNTER_RETIRED));
                }
            }
            RemoteCounterRecordKind::RecoveryStaged | RemoteCounterRecordKind::Recovered => {
                return Err(admin_error(COUNTER_RETIRED));
            }
            RemoteCounterRecordKind::Genesis
            | RemoteCounterRecordKind::Gap
            | RemoteCounterRecordKind::Frozen => {}
        }
    }
    if let Some(candidate) = retired {
        return stage_counter_recovery(store, candidate).await.map(Some);
    }
    // A retirement that cannot be uniquely bound to the authenticated active sender inventory
    // cannot be auto-repaired. Keep the global remote fence and require an explicit trust reset.
    if store.has_retired_remote_counter().await? {
        return Err(admin_error(COUNTER_RETIRED));
    }

    let coordinator = SignedPublicationCoordinator::new(store, guard);
    for candidate in candidates {
        match coordinator
            .audit_sender_scope(candidate.scope, candidate.key_id)
            .await
        {
            Ok(()) => {}
            Err(SignedPublicationError::RetireKey) => {
                return stage_counter_recovery(store, candidate).await.map(Some);
            }
            Err(error) => return Err(signed_publication_error(error)),
        }
    }
    Ok(None)
}

/// Business startup 的线性门禁。CounterGuard/Store reconciliation 与 pending scope
/// 审计必须先于任何可能触达 Relay 的 transition/publication drive；最终恢复前再审一次，
/// 防止 CounterRecovery 把 retired scope 的旧冻结密文混入 replacement barrier drive。
#[allow(
    clippy::too_many_arguments,
    reason = "显式绑定同一 startup 的 Store、owners、admission、absolute deadline、cancel 与 authenticated reconnect"
)]
async fn drive_business_startup_gates(
    store: &RuntimeStoreHandle,
    guard: &OwnedKeyStoreCounterGuardBackend,
    publication_drive: &super::publication_transport::PublicationDriveHandle,
    transition_handle: &dyn ManagedTransitionHandle,
    admission: &mut RemoteBusinessAdmission,
    deadline: tokio::time::Instant,
    shutdown_rx: watch::Receiver<bool>,
    pending_reconnect_rx: Option<AuthenticatedBusinessReconnects>,
) -> Result<(), RemoteAdministrationError> {
    if *shutdown_rx.borrow() {
        return Err(admin_error(REMOTE_SHUTTING_DOWN));
    }
    let counter_recovery_operation =
        admission.observe_counter_audit(reconcile_active_sender_counters(store, guard).await)?;
    if transition_may_drive_publication(store, counter_recovery_operation).await? {
        audit_pending_publication_counter_scopes(store).await?;
    }
    let mut readiness =
        await_transition_readiness(transition_handle, deadline, shutdown_rx.clone()).await?;
    if let Some(operation_id) = counter_recovery_operation {
        let recovered = store
            .mark_remote_counter_recovery_business_ready(operation_id)
            .await?;
        if recovered.kind != RemoteCounterRecordKind::Recovered {
            return Err(admin_error(COUNTER_RETIRED));
        }
        let _ = store.try_complete_key_transition(operation_id).await?;
        audit_current_sender_counters(store, guard).await?;
        readiness =
            await_transition_readiness(transition_handle, deadline, shutdown_rx.clone()).await?;
        // CounterGuard lineage 已安全切到 replacement scope，但现有设备仍需经
        // RemoteLink 控制面取得 KeyUpdate 并提交 required ACK。此时必须允许
        // ControlPlaneOnly link 启动；普通业务继续由 active transition fence 拒绝。
    }
    admission.observe_transition_readiness(Ok(readiness))?;
    audit_pending_publication_counter_scopes(store).await?;
    admission.observe_publication_recovery(
        recover_pending_after_authenticated_reconnect(
            publication_drive,
            deadline,
            shutdown_rx,
            pending_reconnect_rx,
        )
        .await,
    )?;
    Ok(())
}

async fn recover_pending_after_authenticated_reconnect(
    publication_drive: &super::publication_transport::PublicationDriveHandle,
    deadline: tokio::time::Instant,
    shutdown_rx: watch::Receiver<bool>,
    mut reconnect_rx: Option<AuthenticatedBusinessReconnects>,
) -> Result<(), PublicationDriveError> {
    loop {
        if let Some(reconnect_rx) = reconnect_rx.as_mut() {
            reconnect_rx
                .mark_attempt_baseline()
                .map_err(|_| PublicationDriveError::Closed)?;
        }
        match publication_drive
            .recover_pending_until(deadline, shutdown_rx.clone())
            .await
        {
            Ok(()) => return Ok(()),
            Err(PublicationDriveError::RecoveryOffline) => {}
            Err(error) => return Err(error),
        }
        if *shutdown_rx.borrow() {
            return Err(PublicationDriveError::RecoveryCancelled);
        }
        let Some(reconnect_rx) = reconnect_rx.as_mut() else {
            return Err(PublicationDriveError::RecoveryOffline);
        };
        let mut cancelled_rx = shutdown_rx.clone();
        tokio::select! {
            biased;
            changed = cancelled_rx.changed() => {
                if changed.is_err() || *cancelled_rx.borrow() {
                    return Err(PublicationDriveError::RecoveryCancelled);
                }
            }
            changed = tokio::time::timeout_at(deadline, reconnect_rx.changed()) => {
                match changed {
                    Ok(Ok(_)) => {}
                    Ok(Err(_)) => return Err(PublicationDriveError::Closed),
                    Err(_) => return Err(PublicationDriveError::RecoveryTimedOut),
                }
            }
        }
    }
}

async fn transition_may_drive_publication(
    store: &RuntimeStoreHandle,
    counter_recovery_operation: Option<[u8; 16]>,
) -> Result<bool, RemoteAdministrationError> {
    let Some(operation_id) = counter_recovery_operation else {
        return Ok(true);
    };
    let active = store
        .load_active_key_transition()
        .await?
        .ok_or_else(|| admin_error(COUNTER_RETIRED))?;
    if active.transition.operation_id != operation_id
        || active.transition.operation != KeyTransitionOperation::CounterRecovery
        || active.transition.terminal.is_some()
    {
        return Err(admin_error(COUNTER_RETIRED));
    }
    Ok(
        active.transition.phase != KeyTransitionPhase::BarriersCommitted
            && !matches!(active.transition.target, KeyTransitionTarget::Device(_)),
    )
}

/// `load_pending_publication_streams` 先认证完整 stream/outbox directory；逐 stream 的
/// record readback 再取得同一 parent counter scope。CounterRecovery staged 期间 Store
/// 只允许 exact replacement scope，因此 old retired blob（以及会被共享 dispatcher
/// 意外夹带的其他 fenced scope）会在任何 drive 前 fail-close。
async fn audit_pending_publication_counter_scopes(
    store: &RuntimeStoreHandle,
) -> Result<(), RemoteAdministrationError> {
    for publication_stream_id in store.load_pending_publication_streams().await? {
        let stream = store
            .load_publication_stream_record(publication_stream_id)
            .await?;
        let scope_token = stream
            .counter_scope_token
            .ok_or_else(|| admin_error(COUNTER_RETIRED))?;
        if !store.remote_counter_scope_allowed(scope_token).await? {
            return Err(admin_error(COUNTER_RETIRED));
        }
    }
    Ok(())
}

async fn audit_current_sender_counters(
    store: &RuntimeStoreHandle,
    guard: &OwnedKeyStoreCounterGuardBackend,
) -> Result<(), RemoteAdministrationError> {
    let trust_domain = store.machine_trust_domain()?;
    let coordinator = SignedPublicationCoordinator::new(store, guard);
    for binding in store.load_active_sender_counter_bindings().await? {
        let candidate = active_sender_counter_candidate(trust_domain, binding)?;
        coordinator
            .audit_sender_scope(candidate.scope, candidate.key_id)
            .await
            .map_err(signed_publication_error)?;
    }
    Ok(())
}

fn active_sender_counter_candidate(
    trust_domain: [u8; 32],
    binding: ActiveSenderCounterBinding,
) -> Result<ActiveSenderCounterCandidate, RemoteAdministrationError> {
    match binding {
        ActiveSenderCounterBinding::SharedPublication {
            publication_stream_id,
            key_id,
        } => {
            let replacement_key_id = KeyId {
                purpose: key_id.purpose,
                epoch: key_id
                    .epoch
                    .checked_add(1)
                    .ok_or_else(|| admin_error(COUNTER_RETIRED))?,
            };
            let scope = CounterScope::publication(trust_domain, key_id, publication_stream_id)
                .map_err(|error| admin_error(error.code()))?;
            let replacement_scope =
                CounterScope::publication(trust_domain, replacement_key_id, publication_stream_id)
                    .map_err(|error| admin_error(error.code()))?;
            Ok(ActiveSenderCounterCandidate {
                scope,
                key_id,
                replacement_scope,
                target: CounterRecoveryStageTarget::SharedPublication {
                    publication_stream_id,
                },
            })
        }
        ActiveSenderCounterBinding::DirectedReply { authorization } => {
            if authorization.machine_trust_domain() != trust_domain {
                return Err(admin_error(COUNTER_RETIRED));
            }
            let key_id = KeyId {
                purpose: KeyPurpose::DeviceReplyTx,
                epoch: authorization.reply_key_epoch(),
            };
            let replacement_epoch = key_id
                .epoch
                .checked_add(1)
                .ok_or_else(|| admin_error(COUNTER_RETIRED))?;
            let scope = CounterScope::directed_reply_for_trust_epoch(
                trust_domain,
                authorization.machine_route(),
                authorization.trust_epoch(),
                authorization.device_route(),
                authorization.grant_serial(),
                key_id.epoch,
            )
            .map_err(|error| admin_error(error.code()))?;
            let replacement_scope = CounterScope::directed_reply_for_trust_epoch(
                trust_domain,
                authorization.machine_route(),
                authorization.trust_epoch(),
                authorization.device_route(),
                authorization.grant_serial(),
                replacement_epoch,
            )
            .map_err(|error| admin_error(error.code()))?;
            Ok(ActiveSenderCounterCandidate {
                scope,
                key_id,
                replacement_scope,
                target: CounterRecoveryStageTarget::DirectedReply { authorization },
            })
        }
    }
}

async fn stage_counter_recovery(
    store: &RuntimeStoreHandle,
    candidate: ActiveSenderCounterCandidate,
) -> Result<[u8; 16], RemoteAdministrationError> {
    let operation_id = fresh_counter_recovery_operation_id()?;
    let expected_retired_scope = candidate.scope.token();
    let expected_replacement_scope = candidate.replacement_scope.token();
    let outcome = store
        .stage_remote_counter_recovery(CounterRecoveryStageRequest {
            operation_id,
            retired_scope_token: expected_retired_scope,
            retired_key_id: candidate.key_id,
            replacement_scope_token: expected_replacement_scope,
            target: candidate.target,
        })
        .await?;
    match outcome.disposition {
        CounterRecoveryDisposition::Staged | CounterRecoveryDisposition::AlreadyStaged => {
            let binding = outcome
                .binding
                .ok_or_else(|| admin_error(COUNTER_RETIRED))?;
            if binding.operation_id != operation_id
                || binding.retired_scope_token != expected_retired_scope
                || binding.retired_key_id != candidate.key_id
                || binding.replacement_scope_token != expected_replacement_scope
            {
                return Err(admin_error(COUNTER_RETIRED));
            }
            Ok(operation_id)
        }
        CounterRecoveryDisposition::TrustResetRequired => Err(admin_error(COUNTER_RETIRED)),
    }
}

fn fresh_counter_recovery_operation_id() -> Result<[u8; 16], RemoteAdministrationError> {
    for _ in 0..COUNTER_RECOVERY_ENTROPY_ATTEMPTS {
        let mut operation_id = [0; 16];
        getrandom::fill(&mut operation_id)
            .map_err(|_| admin_error(COUNTER_RECOVERY_ENTROPY_UNAVAILABLE))?;
        if operation_id != [0; 16] {
            return Ok(operation_id);
        }
    }
    Err(admin_error(COUNTER_RECOVERY_ENTROPY_UNAVAILABLE))
}

async fn await_transition_readiness(
    handle: &dyn ManagedTransitionHandle,
    deadline: tokio::time::Instant,
    shutdown_rx: watch::Receiver<bool>,
) -> Result<TransitionReadiness, RemoteAdministrationError> {
    await_transition_target(handle, deadline, shutdown_rx, false).await
}

/// startup 允许在 ControlPlaneReady 时先拉起只读控制面；RemoteLink 已运行后的
/// conversation activation 必须等待 required ACK 真正释放 Store transition slot，
/// 绝不能把中间态上报为 business success。Pairing/revoke 的 durable receipt 另走
/// owner-enqueue，不同步等待 endpoint ACK。
async fn await_exact_business_readiness(
    handle: &dyn ManagedTransitionHandle,
    deadline: tokio::time::Instant,
    shutdown_rx: watch::Receiver<bool>,
) -> Result<(), RemoteAdministrationError> {
    let _ = await_transition_target(handle, deadline, shutdown_rx, true).await?;
    Ok(())
}

async fn await_transition_target(
    handle: &dyn ManagedTransitionHandle,
    deadline: tokio::time::Instant,
    mut shutdown_rx: watch::Receiver<bool>,
    require_business: bool,
) -> Result<TransitionReadiness, RemoteAdministrationError> {
    if *shutdown_rx.borrow() {
        return Err(admin_error(REMOTE_SHUTTING_DOWN));
    }
    let mut progress_rx = handle.subscribe_progress();
    if let Some(progress_rx) = progress_rx.as_mut() {
        // watch 保留的是 owner 上一次 drive 的状态。先把它标成 baseline，只有本轮
        // drive 之后递增的 version 才能证明当前 transition 已推进。
        let _ = *progress_rx.borrow_and_update();
    }
    let first = tokio::select! {
        biased;
        changed = shutdown_rx.changed() => {
            let _ = changed;
            return Err(admin_error(REMOTE_SHUTTING_DOWN));
        }
        result = tokio::time::timeout_at(deadline, handle.drive_to_business_ready()) => {
            result.unwrap_or_else(|_| Err(admin_error(TRANSITION_RECOVERY_TIMED_OUT)))
        }
    };

    // drive 完成与 shutdown 同时可见时仍以关停为准；旧 Ready 不能覆盖本轮的
    // timeout、terminal error 或 shutdown。
    if *shutdown_rx.borrow() {
        return Err(admin_error(REMOTE_SHUTTING_DOWN));
    }
    if let Some(result) = transition_initial_result(&first, require_business) {
        return result;
    }

    if let Some(progress_rx) = progress_rx.as_mut() {
        match progress_rx.has_changed() {
            Ok(true) => {
                let progress = *progress_rx.borrow_and_update();
                match progress {
                    TransitionProgress::Pending => {}
                    TransitionProgress::Blocked(code) => return Err(admin_error(code)),
                    TransitionProgress::Ready(readiness) => {
                        // owner 的一次 drive 总是在回应 caller 前发布同一结果。若两者
                        // 矛盾，绝不能让 Ready 覆盖 direct error；只信任成功 drive 的
                        // fresh Ready。
                        if let Err(error) = &first {
                            return Err(error.clone());
                        }
                        if let Some(result) = transition_progress_result(
                            TransitionProgress::Ready(readiness),
                            require_business,
                        ) {
                            return result;
                        }
                    }
                    TransitionProgress::Idle => {
                        if let Err(error) = &first {
                            return Err(error.clone());
                        }
                    }
                }
            }
            Ok(false) => {
                if let Err(error) = &first
                    && !transition_error_waits_without_fresh_progress(error)
                {
                    return Err(error.clone());
                }
            }
            Err(_) => {
                if let Err(error) = &first
                    && !transition_error_waits_without_fresh_progress(error)
                {
                    return Err(error.clone());
                }
                return Err(admin_error(TRANSITION_OWNER_UNAVAILABLE));
            }
        }

        loop {
            tokio::select! {
                biased;
                changed = shutdown_rx.changed() => {
                    let _ = changed;
                    return Err(admin_error(REMOTE_SHUTTING_DOWN));
                }
                changed = tokio::time::timeout_at(deadline, progress_rx.changed()) => {
                    match changed {
                        Ok(Ok(())) => {
                            let progress = *progress_rx.borrow_and_update();
                            if let Some(result) = transition_progress_result(progress, require_business) {
                                return result;
                            }
                        }
                        Ok(Err(_)) => return Err(admin_error(TRANSITION_OWNER_UNAVAILABLE)),
                        Err(_) => return Err(admin_error(TRANSITION_RECOVERY_TIMED_OUT)),
                    }
                }
            }
        }
    }

    if let Some(result) = transition_direct_result(first, require_business) {
        return result;
    }
    tokio::select! {
        biased;
        changed = shutdown_rx.changed() => {
            let _ = changed;
            Err(admin_error(REMOTE_SHUTTING_DOWN))
        }
        () = tokio::time::sleep_until(deadline) => {
            Err(admin_error(TRANSITION_RECOVERY_TIMED_OUT))
        }
    }
}

fn transition_initial_result(
    result: &Result<TransitionReadiness, RemoteAdministrationError>,
    require_business: bool,
) -> Option<Result<TransitionReadiness, RemoteAdministrationError>> {
    match result {
        Ok(
            readiness @ (TransitionReadiness::NoActiveTransition
            | TransitionReadiness::BusinessReady { .. }),
        ) => Some(Ok(*readiness)),
        Ok(readiness @ TransitionReadiness::ControlPlaneReady { .. }) if !require_business => {
            Some(Ok(*readiness))
        }
        Ok(TransitionReadiness::ControlPlaneReady { .. }) => None,
        Err(error) if error.code() == TRANSITION_RECOVERY_TIMED_OUT => Some(Err(error.clone())),
        Err(_) => None,
    }
}

fn transition_error_waits_without_fresh_progress(error: &RemoteAdministrationError) -> bool {
    matches!(
        error.code(),
        TRANSITION_PROGRESS_PENDING | TRANSITION_RECONNECT_PENDING
    )
}

fn transition_direct_result(
    result: Result<TransitionReadiness, RemoteAdministrationError>,
    require_business: bool,
) -> Option<Result<TransitionReadiness, RemoteAdministrationError>> {
    match result {
        Ok(
            readiness @ (TransitionReadiness::NoActiveTransition
            | TransitionReadiness::BusinessReady { .. }),
        ) => Some(Ok(readiness)),
        Ok(readiness @ TransitionReadiness::ControlPlaneReady { .. }) if !require_business => {
            Some(Ok(readiness))
        }
        Ok(TransitionReadiness::ControlPlaneReady { .. }) => None,
        Err(error) => Some(Err(error)),
    }
}

fn transition_progress_result(
    progress: TransitionProgress,
    require_business: bool,
) -> Option<Result<TransitionReadiness, RemoteAdministrationError>> {
    match progress {
        TransitionProgress::Idle | TransitionProgress::Pending => None,
        TransitionProgress::Ready(readiness) => {
            transition_direct_result(Ok(readiness), require_business)
        }
        TransitionProgress::Blocked(code) => Some(Err(admin_error(code))),
    }
}

fn require_exact_enrollment_bundle(
    bundle: &EnrollmentBundleV2,
    connection: &MachineEnrollmentConnectionMaterial,
    request: &MachineEnrollmentRequestV1,
) -> Result<(), RemoteAdministrationError> {
    if bundle.version != ENROLLMENT_BUNDLE_VERSION
        || bundle.public_wss_url != connection.public_wss_url
        || bundle.relay_server_id != connection.relay_server_id
        || bundle.receipt_verify_key != connection.receipt_verify_key
        || bundle.code != request.code
        || bundle.spki_pins != connection.spki_pins
        || bundle.expires_at_ms != connection.expires_at_ms
    {
        return Err(admin_error(REMOTE_STATE_CONFLICT));
    }
    Ok(())
}

#[async_trait]
impl RemoteAdministration for RemoteManager {
    async fn enroll(
        &self,
        request: MachineEnrollRequest,
    ) -> Result<MachineRemoteStatus, RemoteAdministrationError> {
        let status = {
            let mut state = self.state.lock().await;
            self.enroll_locked(&mut state, request).await?
        };
        self.start_business_stack_if_ready().await?;
        Ok(status)
    }

    async fn status(&self) -> Result<MachineRemoteStatus, RemoteAdministrationError> {
        let mut state = self.state.lock().await;
        self.status_locked(&mut state).await
    }

    async fn trust_reset(
        &self,
        request: TrustResetRequest,
    ) -> Result<MachineRemoteStatus, RemoteAdministrationError> {
        // Drain 与后续 retirement/cleanup 是一个不可共享的 workflow。singleflight
        // 独立于 state mutex，重复请求既不会挂接同一 Complete fence，也不会阻塞
        // status/shutdown 取得 manager state。
        let _singleflight = self
            .trust_reset_singleflight
            .try_lock()
            .map_err(|_| admin_error(PAIRING_DRAIN_PENDING))?;
        let (portable_root_lost, pairing) = {
            let state = self.state.lock().await;
            require_running_armed(&state)?;
            let pairing = state.pairing.as_ref().map(PairingCoordinatorOwner::handle);
            #[cfg(test)]
            let pairing = state.pairing_handle_for_test.clone().or(pairing);
            let portable_root_lost = request.admin_purge_receipt().is_some()
                && state.identity.is_none()
                && state.transport.is_none()
                && state.connect_retry.is_none()
                && pairing.is_none();
            (portable_root_lost, pairing)
        };
        let pairing_deadline = pairing
            .as_ref()
            .map(|_| tokio::time::Instant::now() + PAIRING_DRAIN_WAIT_DEADLINE);
        if let Some(handle) = pairing.as_ref() {
            let deadline = pairing_deadline.expect("pairing handle has a drain deadline");
            match self.await_pairing_drain(handle, deadline).await {
                Ok(()) => {}
                Err(
                    PairingDrainWaitError::NotEnqueued(error)
                    | PairingDrainWaitError::Unconfirmed(error),
                ) => {
                    return Err(admin_error(error.code()));
                }
                Err(PairingDrainWaitError::ActorBusy(error)) => {
                    return Err(admin_error(error.code()));
                }
                Err(PairingDrainWaitError::ActorFailed(error)) => {
                    self.resume_pairing_before_deadline(
                        deadline,
                        handle.resume_after_failed_drain(),
                    )
                    .await?;
                    return Err(admin_error(error.code()));
                }
                Err(PairingDrainWaitError::Pending) => {
                    return Err(admin_error(PAIRING_DRAIN_PENDING));
                }
                Err(PairingDrainWaitError::ShuttingDown) => {
                    return Err(admin_error(REMOTE_SHUTTING_DOWN));
                }
            }
        } else if !portable_root_lost && self.has_unowned_pairing_work().await? {
            // 无 portable absent proof 时不能跳过 PairRoute close/revoke cleanup。
            return Err(admin_error(PAIRING_ACTIVE));
        }
        let result = {
            let mut state = self.state.lock().await;
            self.trust_reset_locked(&mut state, request).await
        };
        if result.is_err()
            && let Some(handle) = pairing.as_ref()
            && matches!(
                self.store.load_machine_enrollment_state().await,
                Ok(Some(MachineEnrollmentState::Active(_)))
            )
        {
            {
                let mut state = self.state.lock().await;
                if state.stopped {
                    return Err(admin_error(REMOTE_SHUTTING_DOWN));
                }
                state
                    .transport
                    .as_mut()
                    .ok_or_else(|| admin_error(REMOTE_STATE_CONFLICT))?
                    .reacquire_pairing_shared_control()
                    .map_err(|error| admin_error(error.code()))?;
            }
            self.resume_pairing_before_deadline(
                pairing_deadline.expect("pairing handle has a drain deadline"),
                handle.resume_after_completed_drain(),
            )
            .await?;
        }
        result
    }
}

#[async_trait]
impl ConversationActivationCoordinator for RemoteManager {
    async fn drive_to_business_ready(&self) -> Result<(), ConversationActivationError> {
        RemoteManager::drive_transition_to_business_ready(self)
            .await
            .map_err(|error| ConversationActivationError::new(error.code()))
    }
}

#[async_trait]
impl PairingAdministration for RemoteManager {
    async fn create(
        &self,
        owner: crate::runtime::store::IdempotencyOwner,
        request: agentdeck_protocol::runtime::CreatePairInviteRequest,
    ) -> Result<agentdeck_protocol::runtime::PairInvite, PairingAdministrationError> {
        let handle = {
            let state = self.state.lock().await;
            require_running_armed(&state)
                .map_err(|error| PairingAdministrationError::new(error.code()))?;
            let pairing = state.pairing.as_ref().ok_or_else(pairing_unavailable)?;
            if let Some(code) = pairing.local_blocked_code() {
                return Err(PairingAdministrationError::new(code));
            }
            pairing.handle()
        };
        // 不持 manager mutex 等 Store/Relay ACK，避免阻塞 status/shutdown/reset。
        handle.create(owner, request).await
    }

    async fn list(
        &self,
    ) -> Result<Vec<agentdeck_protocol::runtime::PendingPairing>, PairingAdministrationError> {
        let store = {
            let state = self.state.lock().await;
            require_running_armed(&state)
                .map_err(|error| PairingAdministrationError::new(error.code()))?;
            let pairing = state.pairing.as_ref().ok_or_else(pairing_unavailable)?;
            if let Some(code) = pairing.local_blocked_code() {
                return Err(PairingAdministrationError::new(code));
            }
            self.store.clone()
        };
        // 不持 manager mutex 等 authenticated Store readback。
        store
            .list_pending_pairings()
            .await
            .map_err(|error| PairingAdministrationError::new(error.code()))
    }

    async fn confirm(
        &self,
        pairing_id: crate::runtime::store::RuntimeId,
    ) -> Result<agentdeck_protocol::runtime::PairingReceipt, PairingAdministrationError> {
        let handle = {
            let state = self.state.lock().await;
            require_running_armed(&state)
                .map_err(|error| PairingAdministrationError::new(error.code()))?;
            let pairing = state.pairing.as_ref().ok_or_else(pairing_unavailable)?;
            if let Some(code) = pairing.local_blocked_code() {
                return Err(PairingAdministrationError::new(code));
            }
            pairing.handle()
        };
        // Grant freeze、Store CAS、InstallGrant send 与其后的 key transition 均不得占用
        // manager mutex。新设备收到 PairResponse 前不可能回 transition ACK；receipt
        // 产生后只向已有 owner 投递推进请求，不再同步等待 Relay/endpoint 状态。
        let receipt = handle.confirm(pairing_id).await?;
        self.request_transition_control_plane_progress().await;
        Ok(receipt)
    }

    async fn cancel(
        &self,
        pairing_id: crate::runtime::store::RuntimeId,
    ) -> Result<agentdeck_protocol::runtime::PairingReceipt, PairingAdministrationError> {
        let handle = {
            let state = self.state.lock().await;
            require_running_armed(&state)
                .map_err(|error| PairingAdministrationError::new(error.code()))?;
            let pairing = state.pairing.as_ref().ok_or_else(pairing_unavailable)?;
            if let Some(code) = pairing.local_blocked_code() {
                return Err(PairingAdministrationError::new(code));
            }
            pairing.handle()
        };
        // Store CAS 与 Close send 均不得占用 manager mutex。
        handle.cancel(pairing_id).await
    }
}

#[async_trait]
impl RevocationAdministration for RemoteManager {
    async fn revoke_device(
        &self,
        device: DeviceHandle,
        grant_serial: GrantSerial,
    ) -> Result<RevocationReceipt, RevocationAdministrationError> {
        let handle = {
            let state = self.state.lock().await;
            require_running_armed(&state)
                .map_err(|error| RevocationAdministrationError::new(error.code()))?;
            let handle = state.pairing.as_ref().map(PairingCoordinatorOwner::handle);
            #[cfg(test)]
            let handle = state.pairing_handle_for_test.clone().or(handle);
            if let Some(code) = state
                .pairing
                .as_ref()
                .and_then(PairingCoordinatorOwner::local_blocked_code)
            {
                return Err(RevocationAdministrationError::new(code));
            }
            handle.ok_or_else(|| {
                RevocationAdministrationError::new("daemon.revocation.administration.unavailable")
            })?
        };
        // 不持 manager mutex 等 durable revoke COMMIT、Relay terminal 或重连。receipt
        // 已提交后只投递 key-transition 推进，不能再被离线 endpoint ACK 覆写。
        let receipt = handle
            .revoke_device(device, grant_serial)
            .await
            .map_err(|error| RevocationAdministrationError::new(error.code()))?;
        self.request_transition_control_plane_progress().await;
        Ok(receipt)
    }
}

async fn stop_pairing_actor(state: &mut RemoteManagerState) {
    if let Some(pairing) = state.pairing.as_mut() {
        pairing.shutdown().await;
    }
    state.pairing.take();
}

fn stage_business_start(
    state: &mut RemoteManagerState,
    machine_route: [u8; 16],
    machine_data: MachineDataAuthority,
) -> Result<(), RemoteAdministrationError> {
    if state.pending_business_start.is_some()
        || state.link.is_some()
        || state.transition.is_some()
        || state.transition_handle.is_some()
        || state.maintenance.is_some()
        || state.publication.is_some()
    {
        return Err(admin_error(REMOTE_STATE_CONFLICT));
    }
    state.pending_business_start = Some(PendingBusinessStart {
        machine_route,
        machine_data,
    });
    Ok(())
}

async fn rollback_business_start(
    state: &mut RemoteManagerState,
) -> Result<(), RemoteAdministrationError> {
    let mut unknown = false;
    if let Err(error) = stop_remote_link(state).await {
        unknown = true;
        log_quiescence_failure("remote_link_start_rollback", error.code());
        state.link.take();
    }
    if let Err(error) = stop_maintenance_owner(state).await {
        unknown = true;
        log_quiescence_failure("remote_maintenance_start_rollback", error.code());
    }
    if let Err(error) = stop_transition_owner(state).await {
        unknown = true;
        log_quiescence_failure("remote_transition_start_rollback", error.code());
    }
    if let Err(error) = stop_publication_owner(state).await {
        unknown = true;
        log_quiescence_failure("remote_publication_start_rollback", error.code());
    }
    if unknown {
        state.quiescence_unknown = true;
        state.blocked_code = Some(REMOTE_QUIESCENCE_UNKNOWN.to_owned());
        return Err(admin_error(REMOTE_QUIESCENCE_UNKNOWN));
    }
    Ok(())
}

async fn stop_transition_owner(
    state: &mut RemoteManagerState,
) -> Result<(), RemoteAdministrationError> {
    state.transition_handle.take();
    if let Some(owner) = state.transition.take() {
        owner.shutdown().await?;
    }
    Ok(())
}

async fn stop_maintenance_owner(
    state: &mut RemoteManagerState,
) -> Result<(), RemoteAdministrationError> {
    if let Some(owner) = state.maintenance.take() {
        owner.shutdown().await?;
    }
    Ok(())
}

async fn stop_publication_owner(
    state: &mut RemoteManagerState,
) -> Result<(), RemoteAdministrationError> {
    if let Some(owner) = state.publication.take() {
        owner.shutdown().await.map_err(publication_drive_error)?;
    }
    Ok(())
}

const fn publication_drive_error_code(error: &PublicationDriveError) -> &'static str {
    match error {
        PublicationDriveError::Dispatch(_) => "daemon.remote.publication.dispatch_failed",
        PublicationDriveError::Closed => "daemon.remote.publication.owner_closed",
        PublicationDriveError::TaskFailed => "daemon.remote.publication.owner_failed",
        PublicationDriveError::ShutdownTimedOut => "daemon.remote.publication.shutdown_timed_out",
        PublicationDriveError::RecoveryOffline => "daemon.remote.publication.recovery_offline",
        PublicationDriveError::RecoveryStalled => "daemon.remote.publication.recovery_stalled",
        PublicationDriveError::RecoveryExhausted => "daemon.remote.publication.recovery_exhausted",
        PublicationDriveError::RecoveryCancelled => REMOTE_SHUTTING_DOWN,
        PublicationDriveError::RecoveryTimedOut => "daemon.remote.publication.recovery_timed_out",
    }
}

fn publication_drive_error(error: PublicationDriveError) -> RemoteAdministrationError {
    admin_error(publication_drive_error_code(&error))
}

fn transition_recovery_error(error: KeyTransitionRecoveryError) -> RemoteAdministrationError {
    admin_error(error.code())
}

fn remote_maintenance_error(error: RemoteMaintenanceError) -> RemoteAdministrationError {
    admin_error(error.code())
}

fn shared_publisher_error(error: SharedPublisherError) -> RemoteAdministrationError {
    admin_error(error.code())
}

fn signed_publication_error(error: SignedPublicationError) -> RemoteAdministrationError {
    admin_error(error.code())
}

async fn stop_remote_link(state: &mut RemoteManagerState) -> Result<(), RemoteAdministrationError> {
    if let Some(link) = state.link.as_mut() {
        link.shutdown()
            .await
            .map_err(|error| admin_error(error.code()))?;
    }
    state.link.take();
    Ok(())
}

fn record_pairing_start_failure(state: &mut RemoteManagerState, error: &RemoteAdministrationError) {
    // owner 存在时 health watch 是暂态真源；owner 尚未建立时必须保留稳定 block，
    // 否则 transport 已占有 permit、pairing 又 unavailable，status 却会误报 Active。
    state.blocked_code = state.pairing.is_none().then(|| error.code().to_owned());
}

fn require_pairing_owner_after_enroll(
    transport_present: bool,
    pairing_present: bool,
    blocked_code: Option<&str>,
) -> Result<(), RemoteAdministrationError> {
    if transport_present && !pairing_present {
        let code = blocked_code
            .map(str::to_owned)
            .unwrap_or_else(|| pairing_unavailable().code().to_owned());
        return Err(admin_error(code));
    }
    Ok(())
}

fn require_running_armed(state: &RemoteManagerState) -> Result<(), RemoteAdministrationError> {
    if state.stopped {
        return Err(admin_error(REMOTE_SHUTTING_DOWN));
    }
    if !state.enabled {
        return Err(admin_error(REMOTE_DISABLED));
    }
    if !state.armed {
        return Err(admin_error(REMOTE_NOT_ARMED));
    }
    if let Some(code) = state
        .link
        .as_ref()
        .and_then(|link| link.observed_failure_code())
        .or_else(|| {
            state
                .transition
                .as_ref()
                .and_then(|transition| transition.observed_failure_code())
        })
    {
        return Err(admin_error(code));
    }
    require_known_quiescence(state)
}

fn require_known_quiescence(state: &RemoteManagerState) -> Result<(), RemoteAdministrationError> {
    if state.quiescence_unknown {
        return Err(admin_error(REMOTE_QUIESCENCE_UNKNOWN));
    }
    Ok(())
}

fn log_quiescence_failure(event: &str, code: &str) {
    crate::diag::log(event, &format!("status=quiescence_unknown code={code}"));
}

fn log_forced_shutdown(event: &str, code: &str) {
    crate::diag::log(event, &format!("status=forced code={code}"));
}

fn require_identity_and_permit(
    state: &RemoteManagerState,
) -> Result<(), RemoteAdministrationError> {
    require_running_armed(state)?;
    if state.identity.is_none() || state.start_permit.is_none() {
        return Err(admin_error(
            state
                .blocked_code
                .as_deref()
                .unwrap_or(REMOTE_STATE_CONFLICT),
        ));
    }
    Ok(())
}

fn status_from_state(
    durable: Option<&MachineEnrollmentState>,
    blocked_code: Option<&str>,
    stopped: bool,
) -> Result<MachineRemoteStatus, RemoteAdministrationError> {
    let blocked_code = stopped.then_some(REMOTE_SHUTTING_DOWN).or(blocked_code);
    let record = durable.map(machine_record);
    if let Some(code) = blocked_code {
        let failure = MachineRemoteFailureCode::new(code)
            .unwrap_or_else(|_| MachineRemoteFailureCode::new(REMOTE_DISABLED).unwrap());
        return status_with_record(WireMachineRemoteLifecycle::Blocked, record, Some(failure));
    }
    let Some(durable) = durable else {
        return MachineRemoteStatus::new(
            WireMachineRemoteLifecycle::Unenrolled,
            None,
            None,
            None,
            None,
            None,
        )
        .map_err(|_| admin_error(REMOTE_STATE_CONFLICT));
    };
    let lifecycle = match durable {
        MachineEnrollmentState::EnrollmentPrepared(_) => {
            WireMachineRemoteLifecycle::EnrollmentPrepared
        }
        MachineEnrollmentState::EnrollmentResponseValidated(_) => {
            WireMachineRemoteLifecycle::EnrollmentResponseValidated
        }
        MachineEnrollmentState::Active(_) => WireMachineRemoteLifecycle::Active,
        MachineEnrollmentState::RetirePending(_) => WireMachineRemoteLifecycle::RetirePending,
        MachineEnrollmentState::RelayCommitted(_) => WireMachineRemoteLifecycle::RelayCommitted,
        MachineEnrollmentState::PurgeReadbackAbsent(_) => {
            WireMachineRemoteLifecycle::PurgeReadbackAbsent
        }
        MachineEnrollmentState::LocalDeleted(_) => WireMachineRemoteLifecycle::LocalDeleted,
    };
    status_with_record(lifecycle, record, None)
}

fn machine_record(state: &MachineEnrollmentState) -> &MachineRemoteStateRecord {
    match state {
        MachineEnrollmentState::EnrollmentPrepared(value) => &value.record,
        MachineEnrollmentState::EnrollmentResponseValidated(value) => &value.record,
        MachineEnrollmentState::Active(value) => &value.record,
        MachineEnrollmentState::RetirePending(value) => &value.record,
        MachineEnrollmentState::RelayCommitted(value) => &value.record,
        MachineEnrollmentState::PurgeReadbackAbsent(value) => &value.record,
        MachineEnrollmentState::LocalDeleted(value) => &value.record,
    }
}

fn status_with_record(
    lifecycle: WireMachineRemoteLifecycle,
    record: Option<&MachineRemoteStateRecord>,
    failure_code: Option<MachineRemoteFailureCode>,
) -> Result<MachineRemoteStatus, RemoteAdministrationError> {
    let (relay, route, fingerprint, epoch) = record.map_or((None, None, None, None), |record| {
        (
            Some(agentdeck_protocol::relay_v2::RelayServerId::from_bytes(
                record.relay_server_id,
            )),
            Some(agentdeck_protocol::relay_v2::MachineRouteId::from_bytes(
                record.machine_route,
            )),
            Some(MachineRootFingerprint::from_bytes(record.root_fingerprint)),
            Some(record.trust_epoch),
        )
    });
    MachineRemoteStatus::new(lifecycle, relay, route, fingerprint, epoch, failure_code)
        .map_err(|_| admin_error(REMOTE_STATE_CONFLICT))
}

fn unix_now_ms() -> Result<u64, RemoteAdministrationError> {
    let millis = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_err(|_| admin_error("daemon.remote.clock_invalid"))?
        .as_millis();
    u64::try_from(millis).map_err(|_| admin_error("daemon.remote.clock_invalid"))
}

fn admin_error(code: impl AsRef<str>) -> RemoteAdministrationError {
    RemoteAdministrationError::new(code)
}

fn machine_enrollment_error(error: MachineEnrollmentError) -> RemoteAdministrationError {
    let code = match error {
        MachineEnrollmentError::RouteEntropyUnavailable
        | MachineEnrollmentError::RouteZeroExhausted => {
            "daemon.remote.enrollment.route_unavailable"
        }
        MachineEnrollmentError::Certificate(error) => error.code(),
        MachineEnrollmentError::InvalidResponse(_)
        | MachineEnrollmentError::ResponseRelayMismatch
        | MachineEnrollmentError::ResponseRouteMismatch
        | MachineEnrollmentError::ResponseTrustEpochMismatch
        | MachineEnrollmentError::ResponseReceiptHashMismatch => {
            "daemon.remote.enrollment.response_invalid"
        }
    };
    admin_error(code)
}

fn enrollment_config_error(error: EnrollmentConfigError) -> RemoteAdministrationError {
    admin_error(error.code())
}

impl From<RuntimeStoreError> for RemoteAdministrationError {
    fn from(error: RuntimeStoreError) -> Self {
        admin_error(error.code())
    }
}

impl From<MachineCleanupWorkflowError> for RemoteAdministrationError {
    fn from(error: MachineCleanupWorkflowError) -> Self {
        admin_error(error.code())
    }
}

#[cfg(test)]
#[path = "manager_tests.rs"]
mod tests;
