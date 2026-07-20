//! Machine remote 的唯一 daemon owner 与 Runtime administration 实现。
//!
//! manager 串行独占 identity、RemoteStartPermit、connect retry 与 control-only
//! transport。构造不拨号；只有 recovery 完成且 canonical UDS bind/readback 后的
//! [`RemoteStartPermit`] 才能 arm。所有失败只阻断 remote，本地 Runtime 继续服务。

use std::future::Future;
use std::sync::{Arc, OnceLock};
use std::time::{SystemTime, UNIX_EPOCH};

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
use tokio::sync::{Mutex, watch};

use crate::config::DaemonConfig;
use crate::local::listener::RemoteStartPermit;
use crate::purge_finalizer::{
    AuthenticatedPurgeAuthorization, ResumeReservedPurgeMarkerOutcome, RunningFinalizerIdentity,
    authorize_reserved_purge_marker, purge_marker_intent_present, reserve_purge_marker,
    resume_reserved_purge_marker,
};
use crate::runtime::remote_administration::{RemoteAdministration, RemoteAdministrationError};
use crate::runtime::store::{
    ActiveMachineEnrollmentState, MachineEnrollmentConnectionMaterial, MachineEnrollmentState,
    MachineRemoteStateRecord, RuntimeStoreError, RuntimeStoreHandle,
    machine_enrollment_prepare_input_hash,
};
use crate::runtime::{
    PairingAdministration, PairingAdministrationError, PairingPendingSink,
    RevocationAdministration, RevocationAdministrationError,
};
use crate::security::KeyStore;

use super::bootstrap::{
    ActiveMachineIdentity, RemoteBootstrapOutcome, prepare_reenrollment_identity,
};
use super::cleanup::{MachineCleanupWorkflow, MachineCleanupWorkflowError};
use super::config::{
    EnrollmentConfigError, ValidatedEnrollmentConfig, validate_sealed_relay_connection,
};
use super::enrollment::{FrozenMachineEnrollment, MachineEnrollmentError};
use super::pairing::{
    PairingCoordinatorOwner, PairingInviteContext, unavailable as pairing_unavailable,
};
use super::transport::{PairingRuntimeParts, RemoteTransport, RemoteTransportConnectError};
use super::trust_reset::{MachineTrustResetWorkflow, MachineTrustResetWorkflowError};
use super::workflow::MachineEnrollmentWorkflow;

const REMOTE_DISABLED: &str = "daemon.remote.administration.unavailable";
const REMOTE_NOT_ARMED: &str = "daemon.remote.start_not_armed";
const REMOTE_SHUTTING_DOWN: &str = "daemon.remote.shutting_down";
const REMOTE_STATE_CONFLICT: &str = "daemon.remote.enrollment.state_conflict";
const ROOT_PRESENT_RECEIPT_FORBIDDEN: &str =
    "daemon.remote.trust_reset.root_present_receipt_forbidden";
const ROOT_LOST_RECEIPT_REQUIRED: &str = "daemon.remote.trust_reset.admin_receipt_required";
const PURGE_FINALIZER_UNAVAILABLE: &str = "daemon.purge.finalizer_unavailable";
const PURGE_RECOVERY_REQUIRED: &str = "daemon.purge.recovery_required";

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
    shutdown_tx: watch::Sender<bool>,
    state: Mutex<RemoteManagerState>,
}

struct RemoteManagerState {
    enabled: bool,
    armed: bool,
    stopped: bool,
    purge_pending: bool,
    identity: Option<Box<ActiveMachineIdentity>>,
    start_permit: Option<RemoteStartPermit>,
    transport: Option<RemoteTransport>,
    pairing: Option<PairingCoordinatorOwner>,
    #[cfg(test)]
    pairing_handle_for_test: Option<super::pairing::PairingCoordinatorHandle>,
    connect_retry: Option<RemoteTransportConnectError>,
    blocked_code: Option<String>,
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
            shutdown_tx: watch::channel(false).0,
            state: Mutex::new(RemoteManagerState {
                enabled,
                armed: false,
                stopped: false,
                purge_pending: false,
                identity,
                start_permit: None,
                transport: None,
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

    #[cfg(test)]
    fn with_enrollment_workflow(mut self, workflow: MachineEnrollmentWorkflow) -> Self {
        self.enrollment_workflow = workflow;
        self
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
        if let Err(error) = self.resume_on_startup(&mut state).await {
            state.blocked_code = Some(error.code().to_owned());
            return Err(error);
        }
        Ok(())
    }

    /// shutdown 没有 detached task：若 transport 存在，会先等待 Relay session join；
    /// main 只有在本 future 返回后才可停止 listener/Core。
    pub async fn shutdown(&self) {
        // 必须在等待 manager mutex 前发布取消。trust-reset 可能正持锁等待 Relay
        // terminal；先取消该 future 才能保证 SIGTERM/upgrade 有界取得 owner。
        self.shutdown_tx.send_replace(true);
        let mut state = self.state.lock().await;
        state.stopped = true;
        stop_pairing_actor(&mut state).await;
        if let Some(mut transport) = state.transport.take() {
            transport.shutdown().await;
        }
        state.connect_retry = None;
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
                    MachineTrustResetWorkflow::new()
                        .resume_root_present(&self.store, state.transport.as_mut()),
                )
                .await?;
                self.finish_purge_authorization(state, None).await
            }
            Some(MachineEnrollmentState::RelayCommitted(_)) => {
                // RetirementCommitted 已证明 Relay purge COMMIT+absent；这里严格零网络。
                MachineTrustResetWorkflow::new()
                    .resume_root_present(&self.store, None)
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
        state.blocked_code = None;
        self.status_locked(state).await
    }

    async fn trust_reset_locked(
        &self,
        state: &mut RemoteManagerState,
        request: TrustResetRequest,
    ) -> Result<MachineRemoteStatus, RemoteAdministrationError> {
        require_running_armed(state)?;
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
                MachineTrustResetWorkflow::new()
                    .resume_root_present(&self.store, None)
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
                    self.await_trust_reset(MachineTrustResetWorkflow::new().run_root_present(
                        &self.store,
                        frozen,
                        transport,
                    ))
                    .await?;
                }
                Some(MachineEnrollmentState::RetirePending(_)) => {
                    self.await_trust_reset(
                        MachineTrustResetWorkflow::new()
                            .resume_root_present(&self.store, state.transport.as_mut()),
                    )
                    .await?;
                }
                Some(MachineEnrollmentState::RelayCommitted(_)) => {
                    MachineTrustResetWorkflow::new()
                        .resume_root_present(&self.store, None)
                        .await
                        .map_err(|error| admin_error(error.code()))?;
                }
                Some(MachineEnrollmentState::PurgeReadbackAbsent(_)) => {}
                _ => return Err(admin_error(REMOTE_STATE_CONFLICT)),
            }
        } else {
            let Some(receipt) = receipt else {
                state.blocked_code = Some(ROOT_LOST_RECEIPT_REQUIRED.to_owned());
                return self.status_locked(state).await;
            };
            // portable path 不持有/建立 transport，因此在 Store proof 前后都严格零网络。
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
        if state.connect_retry.is_some() {
            return Err(admin_error(REMOTE_STATE_CONFLICT));
        }
        stop_pairing_actor(state).await;
        if let Some(transport) = state.transport.take() {
            let permit = transport
                .shutdown_and_reclaim_start_permit()
                .await
                .map_err(|error| admin_error(error.code()))?;
            state.start_permit = Some(permit);
        }
        state.identity = None;
        state.purge_pending = true;
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
                let pairing_start = if let Some(data_cert) = data_cert {
                    self.start_pairing_actor(state, &mut transport, pairing_connection, data_cert)
                        .await
                } else {
                    Ok(())
                };
                state.transport = Some(transport);
                state.connect_retry = None;
                match pairing_start {
                    Ok(()) => {
                        state.blocked_code = None;
                        Ok(())
                    }
                    Err(error) => {
                        state.blocked_code = Some(error.code().to_owned());
                        Err(error)
                    }
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
                    Some(MachineEnrollmentState::Active(active)) => {
                        self.start_pairing_actor(
                            state,
                            &mut transport,
                            active.connection,
                            active.data_cert,
                        )
                        .await
                    }
                    Some(MachineEnrollmentState::RetirePending(_)) => Ok(()),
                    _ => Err(admin_error(REMOTE_STATE_CONFLICT)),
                };
                state.transport = Some(transport);
                match pairing_start {
                    Ok(()) => {
                        state.blocked_code = None;
                        Ok(())
                    }
                    Err(error) => {
                        state.blocked_code = Some(error.code().to_owned());
                        Err(error)
                    }
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
    ) -> Result<(), RemoteAdministrationError> {
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
        )
        .await;
        state.pairing = Some(owner);
        ready.map_err(|error| admin_error(error.code()))
    }

    async fn cleanup(
        &self,
        state: &mut RemoteManagerState,
    ) -> Result<(), RemoteAdministrationError> {
        state.identity = None;
        state.connect_retry = None;
        stop_pairing_actor(state).await;
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
        let enabled = state.enabled;
        let armed = state.armed;
        let stopped = state.stopped;
        let blocked_code = state
            .transport
            .as_ref()
            .and_then(RemoteTransport::observed_failure_code)
            .or_else(|| state.blocked_code.clone());
        if !enabled || !self.config.remote_enabled() {
            return Err(admin_error(REMOTE_DISABLED));
        }
        let durable = self.store.load_machine_enrollment_state().await?;
        status_from_state(
            durable.as_ref(),
            blocked_code
                .as_deref()
                .or_else(|| (!armed && !stopped).then_some(REMOTE_NOT_ARMED)),
            stopped,
        )
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
        let mut state = self.state.lock().await;
        self.enroll_locked(&mut state, request).await
    }

    async fn status(&self) -> Result<MachineRemoteStatus, RemoteAdministrationError> {
        let mut state = self.state.lock().await;
        self.status_locked(&mut state).await
    }

    async fn trust_reset(
        &self,
        request: TrustResetRequest,
    ) -> Result<MachineRemoteStatus, RemoteAdministrationError> {
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
        if let Some(handle) = pairing.as_ref() {
            if let Err(error) = handle.begin_drain().await {
                let _ = handle.resume_after_failed_drain().await;
                return Err(admin_error(error.code()));
            }
        } else if !portable_root_lost && !self.store.list_pairing_recovery().await?.is_empty() {
            // 无 portable absent proof 时不能跳过 PairRoute close/revoke cleanup。
            return Err(admin_error("daemon.pairing.active"));
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
            let _ = handle.resume_after_failed_drain().await;
        }
        result
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
            state
                .pairing
                .as_ref()
                .map(PairingCoordinatorOwner::handle)
                .ok_or_else(pairing_unavailable)?
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
            if state.pairing.is_none() {
                return Err(pairing_unavailable());
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
            state
                .pairing
                .as_ref()
                .map(PairingCoordinatorOwner::handle)
                .ok_or_else(pairing_unavailable)?
        };
        // Grant freeze、Store CAS 与 InstallGrant send 均不得占用 manager mutex。
        handle.confirm(pairing_id).await
    }

    async fn cancel(
        &self,
        pairing_id: crate::runtime::store::RuntimeId,
    ) -> Result<agentdeck_protocol::runtime::PairingReceipt, PairingAdministrationError> {
        let handle = {
            let state = self.state.lock().await;
            require_running_armed(&state)
                .map_err(|error| PairingAdministrationError::new(error.code()))?;
            state
                .pairing
                .as_ref()
                .map(PairingCoordinatorOwner::handle)
                .ok_or_else(pairing_unavailable)?
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
            handle.ok_or_else(|| {
                RevocationAdministrationError::new("daemon.revocation.administration.unavailable")
            })?
        };
        // 不持 manager mutex 等 durable revoke COMMIT、Relay terminal 或重连。
        handle
            .revoke_device(device, grant_serial)
            .await
            .map_err(|error| RevocationAdministrationError::new(error.code()))
    }
}

async fn stop_pairing_actor(state: &mut RemoteManagerState) {
    if let Some(mut pairing) = state.pairing.take() {
        pairing.shutdown().await;
    }
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
    Ok(())
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
