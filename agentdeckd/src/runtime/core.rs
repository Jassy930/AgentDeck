//! transport-neutral singleton RuntimeCore。
//!
//! UDS 与 RemoteLink 只能在完成各自认证后交付 opaque
//! `AuthenticatedPrincipal + RuntimeRequest`；本层不 import socket/Relay 类型，也不按
//! transport 排序。所有 mutation 先过 recovery/lifecycle 与 authorization capability，
//! 再进入 durable store/per-conversation actor。

use std::collections::HashSet;
use std::future::Future;
use std::path::PathBuf;
use std::sync::atomic::{AtomicU8, AtomicUsize, Ordering};
use std::sync::{Arc, Mutex as StdMutex, RwLock};

use agentdeck_protocol::e2ee::AuthorizationPermissionV1;
use agentdeck_protocol::runtime::command::{HelloParams, QueryReceiptSelector, RevokeTarget};
use agentdeck_protocol::runtime::failure::{
    DAEMON_AUTHORIZATION_PERMISSION_DENIED, DAEMON_AUTHORIZATION_REVOKED,
    DAEMON_COMMAND_HISTORY_ONLY, DAEMON_COMMAND_NOT_FOUND,
    DAEMON_CONVERSATION_METADATA_MUTATION_PENDING, DAEMON_CONVERSATION_NOT_FOUND,
    DAEMON_RUNTIME_ACTOR_UNAVAILABLE, DAEMON_RUNTIME_CONNECTION_UNAVAILABLE,
    DAEMON_RUNTIME_FEATURE_UNAVAILABLE, DAEMON_RUNTIME_IDENTITY_UNAVAILABLE,
    DAEMON_RUNTIME_INVALID_REQUEST, DAEMON_RUNTIME_NOT_READY, DAEMON_RUNTIME_PROTOCOL_MISMATCH,
    DAEMON_RUNTIME_READ_UNAVAILABLE,
};
use agentdeck_protocol::runtime::identity::{
    ApprovalId, CommandId, ConversationId, DeviceHandle, GrantSerial, IdempotencyKey, TurnId,
};
use agentdeck_protocol::runtime::{
    BackfillRequest, CancellationReceipt, CommandReceipt, CommandStatus, CommandStatusReceipt,
    ConfigurationReceipt, ConversationMetadataReceipt, ConversationStartReceipt,
    RUNTIME_PROTOCOL_VERSION, RuntimeEnvelope, RuntimeFailure, RuntimeInnerCursor, RuntimeMessage,
    RuntimeReply, RuntimeRequest, RuntimeSubscriptionTarget, StageUpgradeReceipt,
    SubscriptionReceipt,
};
use tokio::sync::{Mutex, Notify, Semaphore, mpsc, oneshot};
use tokio::task::JoinSet;

use super::approval::ApprovalPrincipalCapability;
use super::catalog_snapshot::{CatalogSnapshotProvider, CatalogSnapshotProviderError};
use super::connection::{
    AuthenticatedPrincipal, ConnectionError, ConnectionId, ConnectionRegistry, ConnectionSink,
    DEFAULT_CONNECTION_WRITER_BYTES, DEFAULT_CONNECTION_WRITER_FRAMES,
    DEFAULT_RUNTIME_CONNECTION_CAPACITY, EncodedRuntimeFrame, FlushReceipt, PrincipalAccessError,
    PrincipalIssuer, RemoteSelfRevocationAdmission,
};
use super::conversation::{
    ActiveCancelResult, ConversationError, ConversationRegistry, PromptAcceptResult,
    QueuedCancelResult,
};
use super::conversation_activation::{
    ConversationActivationCoordinator, ConversationActivationError,
    DisabledConversationActivationCoordinator,
};
use super::execution::{
    DisabledExecutionCoordinator, GatedExecutionCoordinator, RuntimeExecutionCoordinator,
};
use super::history_receipt::{HistoryOnlyReceiptError, HistoryOnlyReceiptRegistry};
use super::native_metadata::{
    NativeMutationCoordinator, NativeMutationCoordinatorError, NativeMutationOutcome,
};
use super::native_projector::NativeProjector;
use super::pairing_administration::{
    DisabledPairingAdministration, PairingAdministration, PairingAdministrationError,
    PairingPendingSink, RuntimePairingPendingSink,
};
use super::process_identity::SystemProcessGroupController;
use super::read_pool::{DEFAULT_RUNTIME_READ_CONCURRENCY, ReadPool, ReadPoolError};
use super::recovery::{
    RecoveryOptions, RecoveryReadyPermit, RuntimeRecoveryCoordinator, RuntimeRecoveryError,
    RuntimeRecoveryInstallError,
};
use super::remote_administration::{
    DisabledRemoteAdministration, RemoteAdministration, RemoteAdministrationError,
};
use super::revocation_administration::{
    DisabledRevocationAdministration, RevocationAdministration, RevocationAdministrationError,
};
use super::router::AgentRouter;
use super::snapshot::SNAPSHOT_BUILD_MEMORY_BYTES;
use super::store::key_transition::{KeyTransitionStreamScope, TransitionSnapshotPermit};
use super::store::{
    ActiveRemoteIngressProof, CommandReceiptSelector, CommandState, ConfigureConversation,
    ConfigureConversationOutcome, ConversationDescriptor, CreateConversationOutcome,
    CurrentRemoteAuthorizationProof, NewConversation, QueryCommandReceipt,
    RemotePrincipalRegistration, RuntimeId, RuntimeIdKind, RuntimeStoreError, RuntimeStoreHandle,
    SnapshotOrigin, UpdateConversationMetadataOutcome, UpdateManagedConversationMetadata,
};
use super::subscription::coordinator::{SubscriptionCoordinator, SubscriptionPumpError};
use super::upgrade::{
    DisabledUpgradeService, DurableUpgradeService, PreparedUpgrade, UpgradeService,
};

const CORE_COLD: u8 = 0;
const CORE_RECOVERING: u8 = 1;
const CORE_READY: u8 = 2;
// CLOSING 是仅供 Core 内部使用的 admission fence：先拒绝新的前台 operation，
// 等待已准入 operation 退出并封住 actor 的 Accepted→Started lease，之后才发布
// 对外有语义的 DRAINING。这样 Draining 一旦可见，durable Started 就不再增长。
const CORE_CLOSING: u8 = 3;
const CORE_DRAINING: u8 = 4;
const CORE_STOPPED: u8 = 5;

const DEFAULT_ADAPTER_CONCURRENCY: usize = 8;
const DEFAULT_RECOVERY_TERM_GRACE: std::time::Duration = std::time::Duration::from_secs(5);
const DEFAULT_RECOVERY_KILL_GRACE: std::time::Duration = std::time::Duration::from_secs(5);
const ID_DERIVATION_ATTEMPTS: u8 = 16;
const MAX_IDEMPOTENCY_KEY_BYTES: usize = 1024;

/// 一次逐页恢复的有界汇总；不保留 conversation/command payload。
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub struct RecoveryReport {
    pub conversations: u64,
    pub accepted_commands: u64,
}

/// singleton daemon 的 transport-neutral 业务内核。
pub struct RuntimeCore {
    store: RuntimeStoreHandle,
    router: Arc<AgentRouter>,
    connections: ConnectionRegistry,
    subscriptions: SubscriptionCoordinator,
    history_receipts: HistoryOnlyReceiptRegistry,
    conversations: Arc<ConversationRegistry>,
    native_projector: NativeProjector,
    native_projector_enabled: bool,
    native_mutations: NativeMutationCoordinator,
    upgrade: Arc<dyn UpgradeService>,
    remote_administration: Arc<dyn RemoteAdministration>,
    pairing_administration: Arc<dyn PairingAdministration>,
    revocation_administration: Arc<dyn RevocationAdministration>,
    conversation_activation: Arc<dyn ConversationActivationCoordinator>,
    recovery_identity: Arc<()>,
    recovery: RuntimeRecoveryCoordinator,
    read_pool: ReadPool,
    #[allow(dead_code)] // P3.8 UDS peer credential adapter 才会成为 production caller。
    principal_issuer: PrincipalIssuer,
    #[cfg(test)]
    remote_registration_calls: AtomicUsize,
    recovery_blocked_conversations: RwLock<HashSet<RuntimeId>>,
    lifecycle: AtomicU8,
    operation_tracker: Arc<RuntimeOperationTracker>,
    safety_tasks: RuntimeSafetyTaskOwner,
    recovery_lock: Mutex<()>,
    shutdown_lock: Mutex<()>,
}

/// Active Store projection 已注册 exact shared lease，但尚未通过 final Store
/// recheck/replay fence。本类型不暴露 principal 操作，只能在 activation 时消费一次。
#[allow(
    dead_code,
    reason = "同一 P4.4 Task 的 outbound transport slice 消费 staged capability"
)]
pub(crate) struct RegisteredRemotePrincipal {
    principal: AuthenticatedPrincipal,
    registration: RemotePrincipalRegistration,
    core_identity: Arc<()>,
}

impl std::fmt::Debug for RegisteredRemotePrincipal {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter.write_str("RegisteredRemotePrincipal([REDACTED])")
    }
}

/// 完整 ingress 验证后的 purpose-aware principal activation。普通业务只能走
/// `NewOrExisting`；`SelfRevocationRetry` 仅由 normalized `Revoke(SelfDevice)` 在 shared
/// lease 已 Revoking 时产生，只能交回 Core 的 purpose-scoped connection 入口。
pub(crate) enum RemotePrincipalActivation {
    NewOrExisting(AuthenticatedPrincipal),
    SelfRevocationRetry(RemoteSelfRevocationAdmission),
}

/// 完整 durable replay admission 规范化后的 Core 中立分类。只有 byte-identical
/// `ExactDuplicate` 能恢复已经 Revoking 的 self-revoke；Fresh 只允许首次 Active mutation。
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum RemoteIngressReplayClass {
    Fresh,
    ExactDuplicate,
}

impl RemoteIngressReplayClass {
    const fn allows_revoking_retry(self) -> bool {
        matches!(self, Self::ExactDuplicate)
    }
}

/// caller/transport cancellation 不能撤销已经准入的安全 mutation。retained operation
/// lease 让 Core shutdown 等待 fence、durable owner 与 terminal cleanup 收口。
struct RemoteSelfRevocationWork {
    principal: AuthenticatedPrincipal,
    replay: RemoteIngressReplayClass,
    operation: RuntimeOperationGuard,
    conversations: Arc<ConversationRegistry>,
    connections: ConnectionRegistry,
    subscriptions: SubscriptionCoordinator,
    revocation_administration: Arc<dyn RevocationAdministration>,
}

impl RemoteSelfRevocationWork {
    async fn run(self) -> Result<RuntimeReply, RuntimeCoreError> {
        let Self {
            principal,
            replay,
            operation,
            conversations,
            connections,
            subscriptions,
            revocation_administration,
        } = self;
        let _operation = operation;
        let (device, grant_serial) = principal
            .admit_remote_self_revocation(replay.allows_revoking_retry())
            .await?;
        conversations
            .terminate_principal_accepted(&principal)
            .await?;
        let receipt = revocation_administration
            .revoke_device(device, grant_serial)
            .await
            .map_err(revocation_administration_error)?;
        finalize_remote_principal_revoke(&connections, &subscriptions, principal).await?;
        Ok(RuntimeReply::Revocation(receipt))
    }
}

impl RuntimeCore {
    /// Side-effect-free 构造固定安装 fail-closed coordinator；它只验证 Core
    /// contract，不会把 Accepted 推进为真实 Started，也不会放行未配置 prompt。
    pub fn new(
        store: RuntimeStoreHandle,
        router: Arc<AgentRouter>,
        machine_trust_domain: [u8; 32],
    ) -> Result<Self, RuntimeFailure> {
        Self::with_execution_coordinator(
            store,
            router,
            machine_trust_domain,
            Arc::new(DisabledExecutionCoordinator),
            DEFAULT_ADAPTER_CONCURRENCY,
            false,
        )
        .map_err(RuntimeCoreError::into_failure)
    }

    /// production daemon 的 exec-gate execution 构造。调用方仍必须先执行
    /// `recover_for_startup` 取得 RecoveryReadyPermit；constructor 本身不会开放调度。
    pub fn new_production(
        store: RuntimeStoreHandle,
        router: Arc<AgentRouter>,
    ) -> Result<Self, RuntimeFailure> {
        let machine_trust_domain = store
            .machine_trust_domain()
            .map_err(|error| RuntimeCoreError::Store(error).into_failure())?;
        let execution = Arc::new(GatedExecutionCoordinator::new(router.clone()));
        Self::with_execution_coordinator(
            store,
            router,
            machine_trust_domain,
            execution,
            DEFAULT_ADAPTER_CONCURRENCY,
            true,
        )
        .map_err(RuntimeCoreError::into_failure)
    }

    /// P4 automatic E2E 专用构造：除 synthetic vendor adapter 外仍使用 production
    /// RuntimeCore/exec-gate 组合，并把 gate 固定到 Cargo 构建出的真实 daemon binary。
    /// release build 不暴露该 seam，production 始终只允许 current-binary owner。
    #[cfg(debug_assertions)]
    #[doc(hidden)]
    pub fn new_production_for_synthetic_e2e(
        store: RuntimeStoreHandle,
        router: Arc<AgentRouter>,
        gate_binary: PathBuf,
    ) -> Result<Self, RuntimeFailure> {
        let machine_trust_domain = store
            .machine_trust_domain()
            .map_err(|error| RuntimeCoreError::Store(error).into_failure())?;
        let execution = Arc::new(GatedExecutionCoordinator::for_synthetic_e2e(
            router.clone(),
            gate_binary,
        ));
        Self::with_execution_coordinator(
            store,
            router,
            machine_trust_domain,
            execution,
            DEFAULT_ADAPTER_CONCURRENCY,
            true,
        )
        .map_err(RuntimeCoreError::into_failure)
    }

    /// daemon binary 在 main-loop exit receiver 建立后接入的 P3.10 production service。
    /// 构造只验证固定 bin root，不触碰 current、候选 artifact 或 Store。
    #[doc(hidden)]
    pub fn with_versioned_daemon_upgrade(
        mut self,
        bin_root: PathBuf,
        exit: mpsc::UnboundedSender<()>,
    ) -> Result<Self, RuntimeFailure> {
        let service = DurableUpgradeService::new(
            self.store.clone(),
            self.conversations.clone(),
            bin_root,
            exit,
        )
        .map_err(|error| RuntimeFailure::new(error.code(), "daemon upgrade path is invalid"))?;
        self.upgrade = Arc::new(service);
        Ok(self)
    }

    /// production composition 注入 daemon-private remote owner。默认保持 Disabled；
    /// 本入口只替换中立 capability，不把 Relay transport 暴露给 Core。
    #[doc(hidden)]
    pub fn with_remote_administration(
        mut self,
        remote_administration: Arc<dyn RemoteAdministration>,
    ) -> Self {
        self.remote_administration = remote_administration;
        self
    }

    /// production composition 注入 daemon-private pairing owner。Core 只保留中立
    /// local administration capability，不取得 Relay/crypto/Store 状态机类型。
    #[doc(hidden)]
    pub fn with_pairing_administration(
        mut self,
        pairing_administration: Arc<dyn PairingAdministration>,
    ) -> Self {
        self.pairing_administration = pairing_administration;
        self
    }

    /// production composition 注入 daemon-private revocation owner。Core 只保留
    /// DeviceHandle/GrantSerial 中立 capability，不取得 auth ledger 或 Relay 类型。
    #[doc(hidden)]
    pub fn with_revocation_administration(
        mut self,
        revocation_administration: Arc<dyn RevocationAdministration>,
    ) -> Self {
        self.revocation_administration = revocation_administration;
        self
    }

    /// production composition 注入 daemon-private transition owner。Core 只在 Store
    /// 已原子建立 conversation activation 后调用，不取得任何 Relay/crypto 类型。
    #[doc(hidden)]
    pub fn with_conversation_activation(
        mut self,
        conversation_activation: Arc<dyn ConversationActivationCoordinator>,
    ) -> Self {
        self.conversation_activation = conversation_activation;
        self
    }

    /// 返回只持有 bounded connection registry 的弱耦合 pending sink；RemoteManager
    /// 可在 Core 被 `Arc` 包装后单次安装，不形成 Core↔manager 强引用环。
    #[doc(hidden)]
    pub fn pairing_pending_sink(&self) -> Arc<dyn PairingPendingSink> {
        Arc::new(RuntimePairingPendingSink::new(self.connections.clone()))
    }

    /// RemoteManager 在 fresh pairing confirm 因 current durable baseline 不足而
    /// fail-close 后调用。该入口不接收 principal、不返回 snapshot 内容，只复用
    /// RuntimeCore 唯一 SubscriptionCoordinator 的共享 budget 持久化 Catalog 与全部
    /// 缺失 conversation 的 exact captured H。
    pub(crate) async fn refresh_snapshots_for_remote_membership(
        &self,
    ) -> Result<(), RuntimeFailure> {
        self.subscriptions
            .refresh_snapshots_for_remote_membership()
            .await
            .map_err(SubscriptionPumpError::into_failure)
    }

    fn with_execution_coordinator(
        store: RuntimeStoreHandle,
        router: Arc<AgentRouter>,
        machine_trust_domain: [u8; 32],
        execution: Arc<dyn RuntimeExecutionCoordinator>,
        adapter_concurrency: usize,
        enable_native_projector: bool,
    ) -> Result<Self, RuntimeCoreError> {
        if machine_trust_domain == [0; 32] {
            return Err(RuntimeCoreError::InvalidIdentityDomain);
        }
        let daemon_boot_id = random_runtime_id(RuntimeIdKind::DaemonBoot)?;
        let conversations = Arc::new(ConversationRegistry::new(
            store.clone(),
            execution,
            daemon_boot_id,
            adapter_concurrency,
        )?);
        let recovery_identity = Arc::new(());
        let recovery = RuntimeRecoveryCoordinator::new_with_core_identity(
            store.clone(),
            Arc::new(SystemProcessGroupController),
            RecoveryOptions {
                term_grace: DEFAULT_RECOVERY_TERM_GRACE,
                kill_grace: DEFAULT_RECOVERY_KILL_GRACE,
            },
            recovery_identity.clone(),
        );
        let connections = ConnectionRegistry::new(
            DEFAULT_CONNECTION_WRITER_FRAMES,
            DEFAULT_CONNECTION_WRITER_BYTES,
        );
        // 威胁场景：Catalog refresh 与 conversation snapshot 若各自拥有 128 MiB
        // build pool，会在两个慢 writer 同时保留 DTO/payload 时把实际峰值放大到
        // 约 256 MiB；RuntimeCore 因此只创建一个共享 build-retained budget。
        let snapshot_build_budget = Arc::new(Semaphore::new(SNAPSHOT_BUILD_MEMORY_BYTES));
        let catalog_snapshots =
            CatalogSnapshotProvider::new(store.clone(), snapshot_build_budget.clone())?;
        let history_receipts = HistoryOnlyReceiptRegistry::default();
        let subscriptions = SubscriptionCoordinator::new(
            store.clone(),
            router.clone(),
            connections.clone(),
            snapshot_build_budget,
            catalog_snapshots,
            history_receipts.clone(),
        );
        let native_projector = NativeProjector::new(
            router.clone(),
            store.clone(),
            conversations.clone(),
            history_receipts.clone(),
        );
        let native_mutations =
            NativeMutationCoordinator::new(store.clone(), router.clone(), daemon_boot_id)?;
        Ok(Self {
            store,
            router,
            connections,
            subscriptions,
            history_receipts,
            conversations,
            native_projector,
            native_projector_enabled: enable_native_projector,
            native_mutations,
            upgrade: Arc::new(DisabledUpgradeService),
            remote_administration: Arc::new(DisabledRemoteAdministration),
            pairing_administration: Arc::new(DisabledPairingAdministration),
            revocation_administration: Arc::new(DisabledRevocationAdministration),
            conversation_activation: Arc::new(DisabledConversationActivationCoordinator),
            recovery_identity,
            recovery,
            read_pool: ReadPool::new(DEFAULT_RUNTIME_READ_CONCURRENCY)?,
            principal_issuer: PrincipalIssuer::local_only(machine_trust_domain),
            #[cfg(test)]
            remote_registration_calls: AtomicUsize::new(0),
            recovery_blocked_conversations: RwLock::new(HashSet::new()),
            lifecycle: AtomicU8::new(CORE_COLD),
            operation_tracker: Arc::new(RuntimeOperationTracker::default()),
            safety_tasks: RuntimeSafetyTaskOwner::new(DEFAULT_RUNTIME_CONNECTION_CAPACITY),
            recovery_lock: Mutex::new(()),
            shutdown_lock: Mutex::new(()),
        })
    }

    #[cfg(test)]
    pub(crate) fn new_with_test_execution_coordinator(
        store: RuntimeStoreHandle,
        router: Arc<AgentRouter>,
        machine_trust_domain: [u8; 32],
        execution: Arc<dyn RuntimeExecutionCoordinator>,
    ) -> Result<Self, RuntimeCoreError> {
        Self::with_execution_coordinator(
            store,
            router,
            machine_trust_domain,
            execution,
            DEFAULT_ADAPTER_CONCURRENCY,
            false,
        )
    }

    #[cfg(test)]
    pub(crate) fn with_test_upgrade_service(mut self, upgrade: Arc<dyn UpgradeService>) -> Self {
        self.upgrade = upgrade;
        self
    }

    /// 只允许 transport 用本 Core 完成 recovery 时签发的 capability
    /// 开放入口；其他 Core 的 permit 即使同样已恢复也不可以混用。
    pub(crate) fn owns_recovery_ready_permit(&self, permit: &RecoveryReadyPermit) -> bool {
        permit.belongs_to(&self.recovery_identity)
    }

    pub(crate) fn stdio_compatibility_router(&self) -> Arc<AgentRouter> {
        self.router.clone()
    }

    /// 只允许 UDS peer credential 已验证为同 UID 后由 transport adapter 调用。
    #[allow(dead_code)] // 只有验证过 SO_PEERCRED/getpeereid 的 P3.8 adapter 可调用。
    pub(crate) fn issue_verified_local_principal(
        &self,
        uid: u32,
        client_installation_id: [u8; 16],
    ) -> Result<AuthenticatedPrincipal, RuntimeCoreError> {
        self.principal_issuer
            .issue_verified_local(uid, client_installation_id)
            .map_err(RuntimeCoreError::from)
    }

    /// 只允许 UDS peer credential 已验证为 same effective UID 后由本地控制面调用。
    /// 与 read-only issuer 分离，禁止请求处理路径按 `is_local()` 临时升级权限。
    pub(crate) fn issue_verified_local_control_principal(
        &self,
        uid: u32,
        client_installation_id: [u8; 16],
    ) -> Result<AuthenticatedPrincipal, RuntimeCoreError> {
        self.principal_issuer
            .issue_verified_local_control(uid, client_installation_id)
            .map_err(RuntimeCoreError::from)
    }

    /// 完整 crypto 与 Store exact current recheck 通过后，注册/复用 exact shared lease。
    /// 返回的 staged capability 仍不能直接进入 Core。
    pub(crate) fn register_remote_principal(
        &self,
        proof: &ActiveRemoteIngressProof,
    ) -> Result<RegisteredRemotePrincipal, RuntimeCoreError> {
        #[cfg(test)]
        self.remote_registration_calls
            .fetch_add(1, Ordering::AcqRel);
        let binding = proof.command_authorization_binding()?;
        let (principal, registration) = proof.register_principal_lease(|| {
            self.principal_issuer
                .issue_verified_remote(binding)
                .map_err(RuntimeCoreError::from)
        })?;
        Ok(RegisteredRemotePrincipal {
            principal,
            registration,
            core_identity: self.recovery_identity.clone(),
        })
    }

    #[cfg(test)]
    pub(crate) fn remote_registration_calls_for_test(&self) -> usize {
        self.remote_registration_calls.load(Ordering::Acquire)
    }

    #[cfg(test)]
    pub(crate) fn snapshot_sender_usage_for_test(&self) -> usize {
        let (_, _, snapshot_senders, _) = self
            .subscriptions
            .metrics_for_test()
            .expect("read RuntimeCore snapshot sender usage");
        snapshot_senders
    }

    /// 消费与 exact Current proof 同源的 staged lease；调用方只有在本 activation
    /// 成功后才发布 replay candidate，随后方可进入 Core。其它 Active material、
    /// 其它 Core 或已经 Revoking/Revoked 的 shared lease 均 fail-close。
    #[allow(
        dead_code,
        reason = "同一 P4.4 Task 的 outbound transport slice 在 replay candidate 发布前调用"
    )]
    pub(crate) fn activate_registered_remote_principal(
        &self,
        registered: RegisteredRemotePrincipal,
        proof: &CurrentRemoteAuthorizationProof,
    ) -> Result<AuthenticatedPrincipal, RuntimeCoreError> {
        let principal = self.consume_registered_remote_principal(registered, proof)?;
        let authorization = principal.try_enter()?;
        drop(authorization);
        Ok(principal)
    }

    /// 完整 ingress 验证链之后的 purpose-aware activation。只有 current Runtime
    /// `Revoke(SelfDevice)` 可以在 shared lease 已 Revoking 时取得 retry-only capability；
    /// 其它 envelope 与 generic API 仍严格要求 Active。
    pub(crate) fn activate_registered_remote_principal_for_envelope(
        &self,
        registered: RegisteredRemotePrincipal,
        proof: &CurrentRemoteAuthorizationProof,
        envelope: &RuntimeEnvelope,
        replay: RemoteIngressReplayClass,
    ) -> Result<RemotePrincipalActivation, RuntimeCoreError> {
        let principal = self.consume_registered_remote_principal(registered, proof)?;
        let is_self_revocation = envelope.version == RUNTIME_PROTOCOL_VERSION
            && matches!(
                &envelope.body,
                RuntimeMessage::Request(RuntimeRequest::Revoke(request))
                    if matches!(&request.target, RevokeTarget::SelfDevice)
            );
        if is_self_revocation {
            let admission = principal.try_enter_remote_self_revocation()?;
            let is_revoking_retry = admission.is_revoking_retry();
            return Ok(if is_revoking_retry {
                if replay != RemoteIngressReplayClass::ExactDuplicate {
                    return Err(RuntimeCoreError::AuthorizationRevoked);
                }
                RemotePrincipalActivation::SelfRevocationRetry(admission)
            } else {
                let (principal, _device, _grant_serial) = admission.into_parts();
                RemotePrincipalActivation::NewOrExisting(principal)
            });
        }
        let authorization = principal.try_enter()?;
        drop(authorization);
        Ok(RemotePrincipalActivation::NewOrExisting(principal))
    }

    fn consume_registered_remote_principal(
        &self,
        registered: RegisteredRemotePrincipal,
        proof: &CurrentRemoteAuthorizationProof,
    ) -> Result<AuthenticatedPrincipal, RuntimeCoreError> {
        if !Arc::ptr_eq(&registered.core_identity, &self.recovery_identity)
            || !proof.confirms_registered(&registered.registration)
        {
            return Err(RuntimeCoreError::AuthorizationDenied);
        }
        Ok(registered.principal)
    }

    /// 连接只接收不可伪造的认证 capability；raw route/uid 字段不是本接口输入。
    pub fn connect(
        &self,
        principal: AuthenticatedPrincipal,
        sink: ConnectionSink,
    ) -> Result<ConnectionId, RuntimeFailure> {
        let _operation = self
            .try_enter_operation()
            .map_err(RuntimeCoreError::into_failure)?;
        // 与 revoke 的 Active→Revoking CAS 线性化：已 Revoking/Revoked 的 lease
        // 不能再登记 connection；已取得 guard 的并发 connect 会被 revoke 等待，
        // 随后必然出现在 exact authorization connection 快照中。
        let _authorization = principal
            .try_enter()
            .map_err(|error| RuntimeCoreError::from(error).into_failure())?;
        self.connections
            .connect(principal, sink)
            .map_err(|error| RuntimeCoreError::Connection(error).into_failure())
    }

    /// Store-current 且完整验证后的 exact self-revoke retry 可以在 MachineLink 换代后
    /// 重新挂载一条 purpose-scoped virtual connection。普通业务仍无法构造 admission；
    /// attach 前后双读与 finalize 的 Revoked-first 顺序共同封住 connection 快照竞态。
    pub(crate) fn connect_remote_self_revocation_retry(
        &self,
        admission: RemoteSelfRevocationAdmission,
        sink: ConnectionSink,
    ) -> Result<ConnectionId, RuntimeFailure> {
        let _operation = self
            .try_enter_operation()
            .map_err(RuntimeCoreError::into_failure)?;
        let principal = admission
            .into_revoking_retry_principal()
            .map_err(RuntimeCoreError::from)
            .map_err(RuntimeCoreError::into_failure)?;
        if !principal.is_revoking() {
            return Err(RuntimeCoreError::AuthorizationRevoked.into_failure());
        }
        let connection_id = self
            .connections
            .connect(principal.clone(), sink)
            .map_err(RuntimeCoreError::Connection)
            .map_err(RuntimeCoreError::into_failure)?;
        if !principal.is_revoking() {
            self.connections
                .fail_close(connection_id)
                .map_err(RuntimeCoreError::Connection)
                .map_err(RuntimeCoreError::into_failure)?;
            return Err(RuntimeCoreError::AuthorizationRevoked.into_failure());
        }
        Ok(connection_id)
    }

    /// 所有 transport 共用的规范化请求入口。
    pub async fn handle(
        &self,
        connection_id: ConnectionId,
        request: RuntimeRequest,
    ) -> RuntimeReply {
        let operation = match self.try_enter_operation() {
            Ok(operation) => operation,
            Err(error) => return RuntimeReply::Failure(error.into_failure()),
        };
        self.handle_admitted(&operation, connection_id, request)
            .await
    }

    async fn handle_admitted(
        &self,
        operation: &RuntimeOperationGuard,
        connection_id: ConnectionId,
        request: RuntimeRequest,
    ) -> RuntimeReply {
        self.handle_admitted_with_replay(
            operation,
            connection_id,
            request,
            RemoteIngressReplayClass::Fresh,
        )
        .await
    }

    async fn handle_admitted_with_replay(
        &self,
        operation: &RuntimeOperationGuard,
        connection_id: ConnectionId,
        request: RuntimeRequest,
        replay: RemoteIngressReplayClass,
    ) -> RuntimeReply {
        let principal = match self.connections.principal(connection_id) {
            Ok(principal) => principal,
            Err(error) => {
                return RuntimeReply::Failure(RuntimeCoreError::Connection(error).into_failure());
            }
        };
        match self
            .handle_ready(operation, principal, request, replay)
            .await
        {
            Ok(reply) => reply,
            Err(error) => RuntimeReply::Failure(error.into_failure()),
        }
    }

    /// 所有 Runtime v5 transport 共用的完整 envelope 入口。directed reply 严格复用
    /// 原 request messageId，并进入 connection-owned reply pump；本方法不等待 socket。
    pub async fn handle_envelope(
        &self,
        connection_id: ConnectionId,
        envelope: RuntimeEnvelope,
    ) -> Result<(), RuntimeFailure> {
        self.handle_envelope_with_replay(connection_id, envelope, RemoteIngressReplayClass::Fresh)
            .await
    }

    /// RemoteLink 在完整 DeviceSign/AAD/replay/AEAD 与 local auth-ledger 验证后
    /// 使用的 request-scoped 入口。replay 绝不缓存到 connection；每个 frame 都必须
    /// 把自己的 durable classification 带到真正 mutation admission。
    pub(crate) async fn handle_remote_envelope(
        &self,
        connection_id: ConnectionId,
        envelope: RuntimeEnvelope,
        replay: RemoteIngressReplayClass,
    ) -> Result<(), RuntimeFailure> {
        self.handle_envelope_with_replay(connection_id, envelope, replay)
            .await
    }

    async fn handle_envelope_with_replay(
        &self,
        connection_id: ConnectionId,
        envelope: RuntimeEnvelope,
        replay: RemoteIngressReplayClass,
    ) -> Result<(), RuntimeFailure> {
        let principal = self
            .connections
            .principal(connection_id)
            .map_err(|error| RuntimeCoreError::Connection(error).into_failure())?;
        let operation = self
            .try_enter_operation()
            .map_err(RuntimeCoreError::into_failure)?;
        let RuntimeEnvelope {
            version,
            message_id,
            body,
        } = envelope;
        let reply = if version != RUNTIME_PROTOCOL_VERSION {
            RuntimeReply::Failure(RuntimeFailure::new(
                DAEMON_RUNTIME_PROTOCOL_MISMATCH,
                "runtime protocol version is incompatible",
            ))
        } else {
            match body {
                RuntimeMessage::Request(RuntimeRequest::StageUpgrade(request)) => {
                    return self
                        .handle_stage_upgrade_envelope(
                            operation,
                            connection_id,
                            principal,
                            message_id,
                            request,
                        )
                        .await;
                }
                RuntimeMessage::Request(request) => {
                    if let Some(result) = self
                        .handle_stream_envelope(
                            &operation,
                            connection_id,
                            principal,
                            message_id.clone(),
                            request,
                            replay,
                        )
                        .await
                    {
                        return result;
                    }
                    unreachable!("non-stream request is returned by handle_stream_envelope")
                }
                RuntimeMessage::Reply(_) | RuntimeMessage::Stream(_) => {
                    RuntimeReply::Failure(RuntimeFailure::new(
                        DAEMON_RUNTIME_INVALID_REQUEST,
                        "runtime ingress accepts request envelopes only",
                    ))
                }
            }
        };
        self.enqueue_admitted(
            &operation,
            connection_id,
            &RuntimeEnvelope {
                version: RUNTIME_PROTOCOL_VERSION,
                message_id,
                body: RuntimeMessage::Reply(reply),
            },
        )
    }

    /// Active Add transition 的唯一 RuntimeCore 入口。RemoteLink 已完成完整 ingress
    /// 验证与 Store permit admission；Core 仍逐轴复核 exact Subscribe(BeforeFirst)，
    /// 并把 opaque permit 交给专用 subscription capture，绝不回退 generic barrier。
    pub(crate) async fn handle_transition_snapshot_envelope(
        &self,
        connection_id: ConnectionId,
        envelope: RuntimeEnvelope,
        permit: TransitionSnapshotPermit,
    ) -> Result<(), RuntimeFailure> {
        let principal = self
            .connections
            .principal(connection_id)
            .map_err(|error| RuntimeCoreError::Connection(error).into_failure())?;
        let operation = self
            .try_enter_operation()
            .map_err(RuntimeCoreError::into_failure)?;
        let RuntimeEnvelope {
            version,
            message_id,
            body,
        } = envelope;
        if version != RUNTIME_PROTOCOL_VERSION {
            return self.enqueue_stream_failure(
                &operation,
                connection_id,
                message_id,
                RuntimeFailure::new(
                    DAEMON_RUNTIME_PROTOCOL_MISMATCH,
                    "runtime protocol version is incompatible",
                ),
            );
        }
        let RuntimeMessage::Request(RuntimeRequest::Subscribe { inner_cursor }) = body else {
            return self.enqueue_stream_failure(
                &operation,
                connection_id,
                message_id,
                RuntimeFailure::new(
                    DAEMON_RUNTIME_INVALID_REQUEST,
                    "transition snapshot accepts exact subscribe only",
                ),
            );
        };
        let expected_target = match transition_snapshot_target(&permit) {
            Ok(target) => target,
            Err(error) => {
                return self.enqueue_stream_failure(
                    &operation,
                    connection_id,
                    message_id,
                    error.into_failure(),
                );
            }
        };
        let authorization =
            principal.try_enter_runtime_permission(runtime_stream_permission(&expected_target));
        let _authorization = match authorization {
            Ok(authorization) => authorization,
            Err(error) => {
                return self.enqueue_stream_failure(
                    &operation,
                    connection_id,
                    message_id,
                    RuntimeCoreError::from(error).into_failure(),
                );
            }
        };
        let (target, cursor) = match parse_inner_cursor(inner_cursor) {
            Ok(value) => value,
            Err(error) => {
                return self.enqueue_stream_failure(
                    &operation,
                    connection_id,
                    message_id,
                    error.into_failure(),
                );
            }
        };
        if target != expected_target
            || cursor != agentdeck_protocol::runtime::StreamCursor::BeforeFirst
        {
            return self.enqueue_stream_failure(
                &operation,
                connection_id,
                message_id,
                RuntimeFailure::new(
                    DAEMON_RUNTIME_INVALID_REQUEST,
                    "transition snapshot axes do not match Store permit",
                ),
            );
        }
        match self
            .subscriptions
            .prepare_transition_snapshot(connection_id, message_id.clone(), target, permit)
            .await
        {
            Ok(prepared) => prepared
                .commit()
                .await
                .map_err(|error| error.into_failure()),
            Err(error) => self.enqueue_stream_failure(
                &operation,
                connection_id,
                message_id,
                error.into_failure(),
            ),
        }
    }

    /// StageUpgrade 是唯一把 transport flush ACK 作为副作用许可的 Runtime request。
    /// durable prepare 仍由 admitted operation 覆盖；进入 paced writer 前显式释放该
    /// guard，等待 flush 时不占用 shutdown quiescence。ACK 后同步 arm daemon-owned
    /// task，随后 connection close 不再拥有或取消 action。
    async fn handle_stage_upgrade_envelope(
        &self,
        operation: RuntimeOperationGuard,
        connection_id: ConnectionId,
        principal: AuthenticatedPrincipal,
        message_id: agentdeck_protocol::runtime::identity::MessageId,
        request: agentdeck_protocol::runtime::StageUpgradeRequest,
    ) -> Result<(), RuntimeFailure> {
        let (prepared, authorization) = match principal.try_enter_local_administration() {
            Ok(authorization) => {
                let prepared = self
                    .upgrade
                    .prepare(request)
                    .await
                    .unwrap_or_else(PreparedUpgrade::failed);
                (prepared, Some(authorization))
            }
            Err(error) => (
                PreparedUpgrade::failed(RuntimeCoreError::from(error).into_failure()),
                None,
            ),
        };
        let (receipt, deferred) = prepared.into_parts();
        let envelope = RuntimeEnvelope {
            version: RUNTIME_PROTOCOL_VERSION,
            message_id,
            body: RuntimeMessage::Reply(RuntimeReply::StageUpgrade(receipt)),
        };
        drop(authorization);
        drop(operation);

        let flushed = self.enqueue_paced(connection_id, &envelope).await?;
        flushed
            .wait()
            .await
            .map_err(|error| RuntimeCoreError::Connection(error).into_failure())?;
        if let Some(deferred) = deferred {
            deferred.arm();
        }
        Ok(())
    }

    async fn handle_stream_envelope(
        &self,
        operation: &RuntimeOperationGuard,
        connection_id: ConnectionId,
        principal: AuthenticatedPrincipal,
        message_id: agentdeck_protocol::runtime::identity::MessageId,
        request: RuntimeRequest,
        replay: RemoteIngressReplayClass,
    ) -> Option<Result<(), RuntimeFailure>> {
        let stream_result = match request {
            RuntimeRequest::Catalog(request) => {
                let _authorization = match principal
                    .try_enter_runtime_permission(AuthorizationPermissionV1::CatalogRead)
                {
                    Ok(value) => value,
                    Err(error) => {
                        return Some(self.enqueue_stream_failure(
                            operation,
                            connection_id,
                            message_id,
                            RuntimeCoreError::from(error).into_failure(),
                        ));
                    }
                };
                match self
                    .subscriptions
                    .start_catalog_request(connection_id, message_id.clone(), request)
                    .await
                {
                    Ok(()) => return Some(Ok(())),
                    Err(error) => {
                        return Some(self.enqueue_stream_failure(
                            operation,
                            connection_id,
                            message_id,
                            error.into_failure(),
                        ));
                    }
                }
            }
            RuntimeRequest::Subscribe { inner_cursor } => {
                let permission = runtime_inner_cursor_permission(&inner_cursor);
                let _authorization = match principal.try_enter_runtime_permission(permission) {
                    Ok(value) => value,
                    Err(error) => {
                        return Some(self.enqueue_stream_failure(
                            operation,
                            connection_id,
                            message_id.clone(),
                            RuntimeCoreError::from(error).into_failure(),
                        ));
                    }
                };
                let (target, cursor) = match parse_inner_cursor(inner_cursor) {
                    Ok(value) => value,
                    Err(error) => {
                        return Some(self.enqueue_stream_failure(
                            operation,
                            connection_id,
                            message_id.clone(),
                            error.into_failure(),
                        ));
                    }
                };
                match self
                    .subscriptions
                    .prepare(
                        connection_id,
                        message_id.clone(),
                        target,
                        super::backfill::subscription_barrier_request(cursor),
                        true,
                    )
                    .await
                {
                    Ok(prepared) => prepared
                        .commit()
                        .await
                        .map_err(|error| error.into_failure()),
                    Err(error) => Err(error.into_failure()),
                }
            }
            RuntimeRequest::Backfill(request) => {
                let permission = runtime_backfill_permission(&request);
                let _authorization = match principal.try_enter_runtime_permission(permission) {
                    Ok(value) => value,
                    Err(error) => {
                        return Some(self.enqueue_stream_failure(
                            operation,
                            connection_id,
                            message_id,
                            RuntimeCoreError::from(error).into_failure(),
                        ));
                    }
                };
                let (target, after) = match parse_backfill_request(request) {
                    Ok(value) => value,
                    Err(error) => {
                        return Some(self.enqueue_stream_failure(
                            operation,
                            connection_id,
                            message_id,
                            error.into_failure(),
                        ));
                    }
                };
                match self
                    .subscriptions
                    .prepare(
                        connection_id,
                        message_id.clone(),
                        target,
                        super::backfill::BarrierRequest::Backfill { after },
                        false,
                    )
                    .await
                {
                    Ok(prepared) => prepared
                        .commit()
                        .await
                        .map_err(|error| error.into_failure()),
                    Err(error) => Err(error.into_failure()),
                }
            }
            RuntimeRequest::Unsubscribe { target } => {
                let permission = runtime_subscription_permission(&target);
                let _authorization = match principal.try_enter_runtime_permission(permission) {
                    Ok(value) => value,
                    Err(error) => {
                        return Some(self.enqueue_stream_failure(
                            operation,
                            connection_id,
                            message_id,
                            RuntimeCoreError::from(error).into_failure(),
                        ));
                    }
                };
                let target = match parse_subscription_target(target) {
                    Ok(value) => value,
                    Err(error) => {
                        return Some(self.enqueue_stream_failure(
                            operation,
                            connection_id,
                            message_id,
                            error.into_failure(),
                        ));
                    }
                };
                match self.subscriptions.unsubscribe(connection_id, target).await {
                    Ok(_) => self.enqueue_admitted(
                        operation,
                        connection_id,
                        &RuntimeEnvelope {
                            version: RUNTIME_PROTOCOL_VERSION,
                            message_id: message_id.clone(),
                            body: RuntimeMessage::Reply(RuntimeReply::Subscription(
                                SubscriptionReceipt::Unsubscribed,
                            )),
                        },
                    ),
                    Err(error) => Err(error.into_failure()),
                }
            }
            other => {
                let reply = self
                    .handle_admitted_with_replay(operation, connection_id, other, replay)
                    .await;
                return Some(self.enqueue_admitted(
                    operation,
                    connection_id,
                    &RuntimeEnvelope {
                        version: RUNTIME_PROTOCOL_VERSION,
                        message_id,
                        body: RuntimeMessage::Reply(reply),
                    },
                ));
            }
        };
        Some(match stream_result {
            Ok(()) => Ok(()),
            Err(failure) => {
                self.enqueue_stream_failure(operation, connection_id, message_id, failure)
            }
        })
    }

    fn enqueue_stream_failure(
        &self,
        operation: &RuntimeOperationGuard,
        connection_id: ConnectionId,
        message_id: agentdeck_protocol::runtime::identity::MessageId,
        failure: RuntimeFailure,
    ) -> Result<(), RuntimeFailure> {
        self.enqueue_admitted(
            operation,
            connection_id,
            &RuntimeEnvelope {
                version: RUNTIME_PROTOCOL_VERSION,
                message_id,
                body: RuntimeMessage::Reply(RuntimeReply::Failure(failure)),
            },
        )
    }

    fn handle_hello(&self, params: HelloParams) -> RuntimeReply {
        if params.runtime_protocol_version == RUNTIME_PROTOCOL_VERSION {
            RuntimeReply::Hello(HelloParams {
                runtime_protocol_version: RUNTIME_PROTOCOL_VERSION,
            })
        } else {
            RuntimeReply::Failure(RuntimeFailure::new(
                DAEMON_RUNTIME_PROTOCOL_MISMATCH,
                "runtime protocol version is incompatible",
            ))
        }
    }

    async fn handle_ready(
        &self,
        operation: &RuntimeOperationGuard,
        principal: AuthenticatedPrincipal,
        request: RuntimeRequest,
        replay: RemoteIngressReplayClass,
    ) -> Result<RuntimeReply, RuntimeCoreError> {
        match request {
            RuntimeRequest::Hello(params) => Ok(self.handle_hello(params)),
            RuntimeRequest::DescribeAgents => {
                let authorization = principal
                    .try_enter_runtime_permission(AuthorizationPermissionV1::CatalogRead)?;
                let descriptions = self
                    .router
                    .agent_descriptions()
                    .map_err(|_| RuntimeCoreError::AgentDescriptionsInvalid)?;
                drop(authorization);
                Ok(RuntimeReply::Agents(descriptions))
            }
            RuntimeRequest::Start(start) => {
                let _authorization = principal
                    .try_enter_runtime_permission(AuthorizationPermissionV1::ConversationStart)?;
                if validate_idempotency_key(&start.idempotency_key).is_err()
                    || !start.cwd.is_absolute()
                {
                    return Err(RuntimeCoreError::InvalidRequest);
                }
                let owner = principal.idempotency_owner();
                let (conversation_id, adapter_state_key) = self
                    .store
                    .derive_start_identity(&owner, start.idempotency_key.as_str())?;
                let outcome = self
                    .store
                    .create_conversation_idempotent(NewConversation {
                        conversation_id,
                        adapter_state_key,
                        descriptor: ConversationDescriptor {
                            agent_kind: start.agent_kind,
                            title: start.title,
                            cwd: start.cwd,
                        },
                    })
                    .await
                    .map_err(|error| match error {
                        RuntimeStoreError::ConversationConflict => {
                            RuntimeCoreError::Store(RuntimeStoreError::IdempotencyConflict)
                        }
                        other => RuntimeCoreError::Store(other),
                    })?;
                let (conversation, replayed, conversation_activation_pending) = match outcome {
                    CreateConversationOutcome::Created {
                        conversation,
                        conversation_activation_pending,
                    } => (conversation, false, conversation_activation_pending),
                    CreateConversationOutcome::Replayed {
                        conversation,
                        conversation_activation_pending,
                    } => (conversation, true, conversation_activation_pending),
                };
                if conversation_activation_pending {
                    self.conversation_activation
                        .drive_to_business_ready()
                        .await
                        .map_err(RuntimeCoreError::ConversationActivation)?;
                }
                self.conversations
                    .install(conversation.clone(), Vec::new())
                    .await?;
                Ok(RuntimeReply::ConversationStart(ConversationStartReceipt {
                    conversation_id: wire_conversation_id(conversation.conversation_id),
                    replayed,
                }))
            }
            RuntimeRequest::ConfigureConversation(request) => {
                // Configure 的所有业务拒绝都属于 ConfigurationReceipt family；否则
                // Companion 无法区分 CAS conflict、exact replay 与 envelope failure。
                let receipt = match async {
                    validate_idempotency_key(&request.idempotency_key)?;
                    let conversation_id = parse_conversation_id(&request.conversation_id)?;
                    let authorization = principal
                        .try_enter_runtime_permission(AuthorizationPermissionV1::MetadataWrite)?;
                    self.ensure_conversation_mutation_allowed(conversation_id)?;
                    let owner = principal.idempotency_owner();
                    let outcome = self
                        .store
                        .configure_conversation_authorized(
                            ConfigureConversation {
                                conversation_id,
                                owner,
                                idempotency_key: request.idempotency_key.as_str().to_owned(),
                                expected_configuration_revision: request
                                    .expected_configuration_revision,
                                configuration: request.configuration,
                            },
                            authorization,
                        )
                        .await?;
                    Ok::<_, RuntimeCoreError>((conversation_id, outcome))
                }
                .await
                {
                    Ok((
                        conversation_id,
                        ConfigureConversationOutcome::Applied { configuration },
                    )) if configuration.conversation_id == conversation_id
                        && configuration.configuration_revision > 0 =>
                    {
                        ConfigurationReceipt::Applied {
                            conversation_id: wire_conversation_id(conversation_id),
                            configuration_revision: configuration.configuration_revision,
                        }
                    }
                    Ok((
                        conversation_id,
                        ConfigureConversationOutcome::Replayed { configuration },
                    )) if configuration.conversation_id == conversation_id
                        && configuration.configuration_revision > 0 =>
                    {
                        ConfigurationReceipt::Replayed {
                            conversation_id: wire_conversation_id(conversation_id),
                            configuration_revision: configuration.configuration_revision,
                        }
                    }
                    Ok((
                        conversation_id,
                        ConfigureConversationOutcome::Conflict {
                            current_configuration_revision,
                        },
                    )) => ConfigurationReceipt::Conflict {
                        conversation_id: wire_conversation_id(conversation_id),
                        current_configuration_revision,
                    },
                    Ok(_) => ConfigurationReceipt::Failed {
                        failure: RuntimeCoreError::Store(RuntimeStoreError::UnknownOrCorruptSchema)
                            .into_failure(),
                    },
                    Err(error) => ConfigurationReceipt::Failed {
                        failure: configuration_failure(error),
                    },
                };
                Ok(RuntimeReply::Configuration(receipt))
            }
            RuntimeRequest::UpdateConversationMetadata(request) => {
                let receipt = match async {
                    validate_idempotency_key(&request.idempotency_key)?;
                    let conversation_id = parse_conversation_id(&request.conversation_id)?;
                    let authorization = principal
                        .try_enter_runtime_permission(AuthorizationPermissionV1::MetadataWrite)?;
                    self.ensure_conversation_mutation_allowed(conversation_id)?;
                    let owner = principal.idempotency_owner();
                    let context = self
                        .store
                        .load_authenticated_conversation_snapshot_context(conversation_id)
                        .await?;
                    let input = UpdateManagedConversationMetadata {
                        conversation_id,
                        owner,
                        idempotency_key: request.idempotency_key.as_str().to_owned(),
                        expected_entry_revision: request.expected_entry_revision,
                        mutation: request.mutation,
                    };
                    let outcome = match context.origin {
                        SnapshotOrigin::Managed => {
                            self.store
                                .update_managed_conversation_metadata_authorized(
                                    input,
                                    authorization,
                                )
                                .await?
                        }
                        SnapshotOrigin::NativeProjected => {
                            // transport request 只等待 actor-owned reply；authorization、
                            // per-conversation serialization、adapter permit 与 retained Core
                            // operation lease 全部按值转入 actor control command。caller/
                            // connection cancellation 不能取消已准入的 vendor/readback/Store
                            // 收口，也不能让 shutdown 越过仍在执行的副作用。
                            match self
                                .conversations
                                .update_native_metadata(
                                    conversation_id,
                                    self.native_mutations.clone(),
                                    input,
                                    authorization,
                                    operation.retain(),
                                )
                                .await?
                            {
                                NativeMutationOutcome::Store(outcome) => outcome,
                                NativeMutationOutcome::Rejected(failure) => {
                                    UpdateConversationMetadataOutcome::Failed { failure }
                                }
                                NativeMutationOutcome::OutcomeUnknown {
                                    conversation_id: unknown,
                                } if unknown == conversation_id => {
                                    UpdateConversationMetadataOutcome::Failed {
                                        failure: RuntimeFailure::new(
                                            DAEMON_CONVERSATION_METADATA_MUTATION_PENDING,
                                            "native metadata outcome requires authenticated readback",
                                        ),
                                    }
                                }
                                NativeMutationOutcome::OutcomeUnknown { .. } => {
                                    return Err(RuntimeCoreError::Store(
                                        RuntimeStoreError::UnknownOrCorruptSchema,
                                    ));
                                }
                            }
                        }
                    };
                    Ok::<_, RuntimeCoreError>((conversation_id, outcome))
                }
                .await
                {
                    Ok((
                        conversation_id,
                        UpdateConversationMetadataOutcome::Applied { mutation },
                    )) if mutation.conversation_id == conversation_id
                        && mutation.entry_revision > 0 =>
                    {
                        ConversationMetadataReceipt::Applied {
                            conversation_id: wire_conversation_id(conversation_id),
                            entry_revision: mutation.entry_revision,
                        }
                    }
                    Ok((
                        conversation_id,
                        UpdateConversationMetadataOutcome::Replayed { mutation },
                    )) if mutation.conversation_id == conversation_id
                        && mutation.entry_revision > 0 =>
                    {
                        ConversationMetadataReceipt::Replayed {
                            conversation_id: wire_conversation_id(conversation_id),
                            entry_revision: mutation.entry_revision,
                        }
                    }
                    Ok((
                        conversation_id,
                        UpdateConversationMetadataOutcome::Conflict {
                            current_entry_revision,
                        },
                    )) => ConversationMetadataReceipt::Conflict {
                        conversation_id: wire_conversation_id(conversation_id),
                        current_entry_revision,
                    },
                    Ok((_, UpdateConversationMetadataOutcome::Failed { failure })) => {
                        ConversationMetadataReceipt::Failed { failure }
                    }
                    Ok(_) => ConversationMetadataReceipt::Failed {
                        failure: RuntimeCoreError::Store(RuntimeStoreError::UnknownOrCorruptSchema)
                            .into_failure(),
                    },
                    Err(error) => ConversationMetadataReceipt::Failed {
                        failure: metadata_failure(error),
                    },
                };
                Ok(RuntimeReply::ConversationMetadata(receipt))
            }
            RuntimeRequest::SendPrompt(request) => {
                // SendPrompt 的所有业务拒绝都属于 CommandReceipt family；否则
                // Companion 会把一次 command failure 误解成 envelope/control failure。
                let receipt = match async {
                    validate_idempotency_key(&request.idempotency_key)?;
                    let conversation_id = parse_conversation_id(&request.conversation_id)?;
                    let authorization = principal
                        .try_enter_runtime_permission(AuthorizationPermissionV1::PromptSend)?;
                    self.ensure_conversation_mutation_allowed(conversation_id)?;
                    // NativeProjected conversation 是经认证的只读历史投影。必须在 actor
                    // mailbox 前返回 typed failure；Store accept transaction 仍会独立
                    // 复核，防止 crate 内旁路或正常状态漂移越过此早期门禁。
                    let context = self
                        .store
                        .load_authenticated_conversation_snapshot_context(conversation_id)
                        .await
                        .map_err(|error| match error {
                            RuntimeStoreError::ConversationNotFound => {
                                RuntimeCoreError::Conversation(ConversationError::NotFound)
                            }
                            error => RuntimeCoreError::Store(error),
                        })?;
                    if context.origin != SnapshotOrigin::Managed {
                        return Err(RuntimeCoreError::FeatureUnavailable);
                    }
                    self.conversations
                        .submit_prompt(
                            conversation_id,
                            principal,
                            authorization,
                            request.idempotency_key.as_str().to_owned(),
                            request.expected_configuration_revision,
                            request.prompt.into_string().into_bytes(),
                        )
                        .await
                        .map_err(RuntimeCoreError::Conversation)
                }
                .await
                {
                    Ok(PromptAcceptResult::Accepted {
                        command,
                        queue_position,
                    }) => CommandReceipt::Accepted {
                        command_id: wire_command_id(command.command_id),
                        queue_position,
                        configuration_revision: command.configuration_revision,
                    },
                    Ok(PromptAcceptResult::Replayed { command }) => CommandReceipt::Replayed {
                        command_id: wire_command_id(command.command_id),
                        configuration_revision: command.configuration_revision,
                    },
                    Err(error) => CommandReceipt::Failed {
                        failure: error.into_failure(),
                    },
                };
                Ok(RuntimeReply::Command(receipt))
            }
            RuntimeRequest::CancelQueued {
                conversation_id,
                command_id,
            } => {
                let internal_conversation = parse_conversation_id(&conversation_id)?;
                let internal_command = parse_command_id(&command_id)?;
                let authorization = principal
                    .try_enter_runtime_permission(AuthorizationPermissionV1::CommandCancel)?;
                self.ensure_conversation_mutation_allowed(internal_conversation)?;
                let result = self
                    .conversations
                    .cancel_queued(
                        internal_conversation,
                        internal_command,
                        principal,
                        authorization,
                    )
                    .await?;
                match result {
                    QueuedCancelResult::Canceled { .. } | QueuedCancelResult::Replayed { .. } => {
                        Ok(RuntimeReply::Cancellation(
                            CancellationReceipt::QueuedCanceled {
                                conversation_id,
                                command_id,
                            },
                        ))
                    }
                    QueuedCancelResult::AlreadyStarted { .. } => Err(RuntimeCoreError::StaleTurn),
                }
            }
            RuntimeRequest::CancelActive {
                conversation_id,
                turn_id,
            } => {
                let internal_conversation = parse_conversation_id(&conversation_id)?;
                let internal_turn = parse_turn_id(&turn_id)?;
                let authorization = principal
                    .try_enter_runtime_permission(AuthorizationPermissionV1::CommandCancel)?;
                self.ensure_conversation_mutation_allowed(internal_conversation)?;
                match self
                    .conversations
                    .cancel_active(internal_conversation, internal_turn, authorization)
                    .await?
                {
                    ActiveCancelResult::Requested => Ok(RuntimeReply::Cancellation(
                        CancellationReceipt::ActiveCancelRequested {
                            conversation_id,
                            turn_id,
                        },
                    )),
                    ActiveCancelResult::Stale => Err(RuntimeCoreError::StaleTurn),
                }
            }
            RuntimeRequest::ResolveApproval {
                conversation_id,
                turn_id,
                approval_id,
                decision,
            } => {
                let internal_conversation = parse_conversation_id(&conversation_id)?;
                let internal_turn = parse_turn_id(&turn_id)?;
                let internal_approval = parse_approval_id(&approval_id)?;
                let _permission = principal
                    .try_enter_runtime_permission(AuthorizationPermissionV1::ApprovalResolve)?;
                self.ensure_conversation_mutation_allowed(internal_conversation)?;
                let authorization = principal.try_enter_approval()?;
                authorization.require_resolve()?;
                let receipt = self
                    .conversations
                    .resolve_approval(
                        internal_conversation,
                        internal_turn,
                        internal_approval,
                        decision,
                        authorization,
                    )
                    .await?;
                Ok(RuntimeReply::Approval(receipt))
            }
            RuntimeRequest::RetryApproval {
                conversation_id,
                approval_id,
            } => {
                let internal_conversation = parse_conversation_id(&conversation_id)?;
                let internal_approval = parse_approval_id(&approval_id)?;
                let _permission = principal
                    .try_enter_runtime_permission(AuthorizationPermissionV1::ApprovalRetry)?;
                self.ensure_conversation_mutation_allowed(internal_conversation)?;
                let authorization = principal.try_enter_approval()?;
                authorization.require_retry()?;
                let receipt = self
                    .conversations
                    .retry_approval(internal_conversation, internal_approval, authorization)
                    .await?;
                Ok(RuntimeReply::Approval(receipt))
            }
            RuntimeRequest::QueryReceipt(selector) => {
                let _authorization = principal
                    .try_enter_runtime_permission(AuthorizationPermissionV1::ConversationRead)?;
                let owner = principal.idempotency_owner();
                let (conversation_id, query, history_selector) = match selector {
                    QueryReceiptSelector::Command {
                        conversation_id,
                        command_id,
                    } => {
                        let internal_conversation = parse_conversation_id(&conversation_id)?;
                        let internal_command = parse_command_id(&command_id)?;
                        let history_selector = Some((internal_conversation, internal_command));
                        (
                            conversation_id,
                            QueryCommandReceipt {
                                expected_owner: owner,
                                selector: CommandReceiptSelector::Command {
                                    conversation_id: internal_conversation,
                                    command_id: internal_command,
                                },
                            },
                            history_selector,
                        )
                    }
                    QueryReceiptSelector::Idempotency {
                        conversation_id,
                        idempotency_key,
                    } => {
                        validate_idempotency_key(&idempotency_key)?;
                        let internal_conversation = parse_conversation_id(&conversation_id)?;
                        (
                            conversation_id,
                            QueryCommandReceipt {
                                expected_owner: owner,
                                selector: CommandReceiptSelector::Idempotency {
                                    conversation_id: internal_conversation,
                                    idempotency_key: idempotency_key.as_str().to_owned(),
                                },
                            },
                            None,
                        )
                    }
                };
                let store = self.store.clone();
                let durable = self
                    .read_pool
                    .run(async move { store.query_command_receipt(query).await })
                    .await?;
                let receipt = match durable {
                    Ok(receipt) => receipt,
                    Err(RuntimeStoreError::CommandNotFound) => {
                        if let Some((conversation_id, command_id)) = history_selector
                            && self
                                .history_receipts
                                .contains(conversation_id, command_id)?
                        {
                            return Err(RuntimeCoreError::HistoryOnlyCommand);
                        }
                        return Err(RuntimeCoreError::CommandNotFound);
                    }
                    Err(error) => return Err(error.into()),
                };
                Ok(RuntimeReply::CommandStatus(CommandStatusReceipt {
                    conversation_id,
                    command_id: wire_command_id(receipt.command_id),
                    configuration_revision: receipt.configuration_revision,
                    status: wire_command_status(receipt.state),
                    turn_id: receipt.turn_id.map(wire_turn_id),
                }))
            }
            RuntimeRequest::Subscribe { inner_cursor } => {
                let _authorization = principal
                    .try_enter_runtime_permission(runtime_inner_cursor_permission(&inner_cursor))?;
                Err(RuntimeCoreError::InvalidRequest)
            }
            RuntimeRequest::Unsubscribe { target } => {
                let _authorization = principal
                    .try_enter_runtime_permission(runtime_subscription_permission(&target))?;
                Err(RuntimeCoreError::InvalidRequest)
            }
            RuntimeRequest::Backfill(request) => {
                let _authorization = principal
                    .try_enter_runtime_permission(runtime_backfill_permission(&request))?;
                Err(RuntimeCoreError::InvalidRequest)
            }
            // Catalog page 可能超过单 frame 上限，必须携带原 messageId 进入
            // handle_envelope 的 tracked paced egress；direct handle 禁止返回大 DTO。
            RuntimeRequest::Catalog(_) => {
                let _authorization = principal
                    .try_enter_runtime_permission(AuthorizationPermissionV1::CatalogRead)?;
                Err(RuntimeCoreError::InvalidRequest)
            }
            RuntimeRequest::MachineEnroll(request) => {
                let _authorization = principal.try_enter_local_administration()?;
                self.remote_administration
                    .enroll(request)
                    .await
                    .map(RuntimeReply::MachineRemoteStatus)
                    .map_err(remote_administration_error)
            }
            RuntimeRequest::MachineRemoteStatus { .. } => {
                let _authorization = principal.try_enter_local_administration()?;
                self.remote_administration
                    .status()
                    .await
                    .map(RuntimeReply::MachineRemoteStatus)
                    .map_err(remote_administration_error)
            }
            RuntimeRequest::TrustReset(request) => {
                let _authorization = principal.try_enter_local_administration()?;
                self.remote_administration
                    .trust_reset(request)
                    .await
                    .map(RuntimeReply::MachineRemoteStatus)
                    .map_err(remote_administration_error)
            }
            RuntimeRequest::CreatePairInvite(request) => {
                let authorization = principal.try_enter_local_administration()?;
                let owner = principal.idempotency_owner();
                let result = self
                    .pairing_administration
                    .create(owner, request)
                    .await
                    .map(RuntimeReply::PairInvite)
                    .map_err(pairing_administration_error);
                drop(authorization);
                result
            }
            RuntimeRequest::ListPendingPairings { .. } => {
                let authorization = principal.try_enter_local_administration()?;
                let result = self
                    .pairing_administration
                    .list()
                    .await
                    .map(|pairings| RuntimeReply::PendingPairings { pairings })
                    .map_err(pairing_administration_error);
                drop(authorization);
                result
            }
            RuntimeRequest::ConfirmPairing { pairing_id, .. } => {
                let authorization = principal.try_enter_local_administration()?;
                let pairing_id = parse_pairing_id(&pairing_id)?;
                let result = self
                    .pairing_administration
                    .confirm(pairing_id)
                    .await
                    .map(RuntimeReply::Pairing)
                    .map_err(pairing_administration_error);
                drop(authorization);
                result
            }
            RuntimeRequest::CancelPairing { pairing_id, .. } => {
                let authorization = principal.try_enter_local_administration()?;
                let pairing_id = parse_pairing_id(&pairing_id)?;
                let result = self
                    .pairing_administration
                    .cancel(pairing_id)
                    .await
                    .map(RuntimeReply::Pairing)
                    .map_err(pairing_administration_error);
                drop(authorization);
                result
            }
            RuntimeRequest::Revoke(request) => match request.target {
                RevokeTarget::Device {
                    device,
                    grant_serial,
                    ..
                } => {
                    let authorization = principal.try_enter_local_administration()?;
                    let result = async {
                        let remote_principal = self
                            .begin_remote_principal_revoke(&device, grant_serial)
                            .await?;
                        let receipt = self
                            .revocation_administration
                            .revoke_device(device, grant_serial)
                            .await
                            .map_err(revocation_administration_error)?;
                        if let Some(remote_principal) = remote_principal {
                            self.finalize_remote_principal_revoke(remote_principal)
                                .await?;
                        }
                        Ok(RuntimeReply::Revocation(receipt))
                    }
                    .await;
                    drop(authorization);
                    result
                }
                RevokeTarget::SelfDevice => {
                    // target 只能从 authenticated remote principal 派生；request 不得
                    // 携带或覆盖 device route / grant serial。此处只读校验 identity、
                    // permission 与当前状态；真正 Active->Revoking CAS 必须等 safety
                    // task 同步登记成功后在 future 内执行，owner 拒绝不能遗留孤儿 fence。
                    principal.ensure_remote_self_revocation(replay.allows_revoking_retry())?;
                    let work = RemoteSelfRevocationWork {
                        principal,
                        replay,
                        operation: operation.retain(),
                        conversations: self.conversations.clone(),
                        connections: self.connections.clone(),
                        subscriptions: self.subscriptions.clone(),
                        revocation_administration: self.revocation_administration.clone(),
                    };
                    let result = self.safety_tasks.spawn(work.run()).map_err(|_| {
                        revocation_administration_error(RevocationAdministrationError::new(
                            "daemon.revocation.administration.unavailable",
                        ))
                    })?;
                    result.await.map_err(|_| {
                        revocation_administration_error(RevocationAdministrationError::new(
                            "daemon.revocation.administration.unavailable",
                        ))
                    })?
                }
            },
            RuntimeRequest::StageUpgrade(_) => {
                let failure = match principal.try_enter_local_administration() {
                    Ok(_authorization) => RuntimeCoreError::FeatureUnavailable,
                    Err(error) => RuntimeCoreError::from(error),
                }
                .into_failure();
                Ok(RuntimeReply::StageUpgrade(StageUpgradeReceipt::Failed {
                    failure,
                }))
            }
        }
    }

    /// RecoveryBlocked 是 conversation-scoped read-only policy，不是全 Core 故障。
    /// 集合只由 authenticated startup recovery 发布；业务 mutation 在取得 exact
    /// permission guard 后、触碰 Store/actor 前同步复核，确保拒绝零副作用。
    fn ensure_conversation_mutation_allowed(
        &self,
        conversation_id: RuntimeId,
    ) -> Result<(), RuntimeCoreError> {
        let blocked = self
            .recovery_blocked_conversations
            .read()
            .map_err(|_| RuntimeCoreError::RecoveryBlocked)?;
        if blocked.contains(&conversation_id) {
            Err(RuntimeCoreError::RecoveryBlocked)
        } else {
            Ok(())
        }
    }

    /// 完成 authenticated 两遍 recovery 与 Started orphan fencing；在 typed permit
    /// 产生前 actor scheduling gate 始终关闭。
    pub async fn recover(&self) -> Result<RecoveryReport, RuntimeFailure> {
        self.recover_for_startup()
            .await
            .map(|(report, _permit)| report)
    }

    /// daemon bootstrap 使用的 typed recovery 边界。P3.8 listener 与 P4 remote
    /// transport 只能在取得该 permit 后继续各自的 bind/start 序列。
    pub async fn recover_for_startup(
        &self,
    ) -> Result<(RecoveryReport, RecoveryReadyPermit), RuntimeFailure> {
        let _guard = self.recovery_lock.lock().await;
        self.lifecycle
            .compare_exchange(
                CORE_COLD,
                CORE_RECOVERING,
                Ordering::AcqRel,
                Ordering::Acquire,
            )
            .map_err(|_| RuntimeCoreError::InvalidLifecycle.into_failure())?;
        self.recover_inner()
            .await
            .map_err(RuntimeCoreError::into_failure)
    }

    async fn recover_inner(
        &self,
    ) -> Result<(RecoveryReport, RecoveryReadyPermit), RuntimeCoreError> {
        let (recovered, permit) = self
            .recovery
            .reconcile_and_install(|conversation, accepted| {
                self.conversations.install(conversation, accepted)
            })
            .await
            .map_err(|error| match error {
                RuntimeRecoveryInstallError::Recovery(error) => map_runtime_recovery_error(error),
                RuntimeRecoveryInstallError::Install(error) => {
                    RuntimeCoreError::Conversation(error)
                }
            })?;
        let recovery_blocked_conversations =
            recovered.blocked_conversation_ids().collect::<HashSet<_>>();
        *self
            .recovery_blocked_conversations
            .write()
            .map_err(|_| RuntimeCoreError::RecoveryBlocked)? = recovery_blocked_conversations;
        let report = RecoveryReport {
            conversations: u64::try_from(recovered.conversation_count())
                .map_err(|_| RuntimeCoreError::RecoveryBlocked)?,
            accepted_commands: u64::try_from(recovered.ready_accepted_count())
                .map_err(|_| RuntimeCoreError::RecoveryBlocked)?,
        };
        // Native metadata claim/fence 必须在 projector 可以刷新同一 conversation
        // 之前完成 authenticated recovery；startup recovery 绝不重调 vendor。
        self.native_mutations.recover().await?;
        if self.native_projector_enabled {
            // 启动慢路径只执行一个最多 2s 的固定 source round；
            // completion reconciliation 与余下 continuation 必须留到 Core Ready 后。
            self.native_projector.run_initial_round().await;
        }
        self.conversations
            .publish_ready_and_enable_scheduling(&permit, || {
                self.lifecycle.store(CORE_READY, Ordering::Release);
            })
            .await?;
        if self.native_projector_enabled {
            self.native_projector.start_background();
        }
        Ok((report, permit))
    }

    pub async fn disconnect(&self, connection_id: ConnectionId) {
        // 先取消并收割 subscription pump；否则先拆 writer 会把正常 disconnect
        // 变成 partial-transfer/fail-close，并让 watch/pin 的释放依赖错误路径。
        let _ = self.subscriptions.disconnect(connection_id).await;
        let _ = self.connections.disconnect(connection_id).await;
    }

    /// Remote transport 的 deadline fallback：先同步撤销 connection admission 并
    /// abort Core-owned writer。正常路径仍调用 [`Self::disconnect`] 收割 subscription；
    /// 本入口只用于 Link actor 已被强制 join 后保证 stale principal 不再可写。
    pub(crate) fn fail_close_connection_for_transport(&self, connection_id: ConnectionId) {
        let _ = self.connections.fail_close(connection_id);
    }

    /// 两阶段 local revoke 的 pre-COMMIT fence。issuer registry 不依赖 active
    /// connection；命中 exact target 时先把共享 lease 置为 Revoking、drain 所有
    /// inflight guard，并终止 exact authorization 尚未 Started 的 Accepted。以上
    /// actor fence 全部成功后才允许调用 durable owner。已完成 Revoked 的 retry
    /// 当作无需重复 fence，仍允许 durable owner 做 exact replay。
    async fn begin_remote_principal_revoke(
        &self,
        device: &DeviceHandle,
        grant_serial: GrantSerial,
    ) -> Result<Option<AuthenticatedPrincipal>, RuntimeCoreError> {
        let principal = match self
            .principal_issuer
            .remote_principal_for_revoke(device, grant_serial)?
        {
            Some(principal) => principal,
            None => {
                // daemon 重启后，设备重连前仍可能存在 durable ADC2 Accepted。先从 Store
                // 建立同一 exact lease，确保 issuer registry 为空时也能在 durable revoke
                // 之前阻断这些命令。
                let Some(proof) = self
                    .store
                    .load_active_remote_ingress_for_revoke(device, grant_serial)
                    .await?
                else {
                    return Ok(None);
                };
                self.register_remote_principal(&proof)?.principal
            }
        };
        if self.begin_exact_remote_principal_revoke(&principal).await? {
            Ok(Some(principal))
        } else {
            Ok(None)
        }
    }

    /// 已认证 exact remote principal 的共享 pre-COMMIT fence。Active/Revoking 都会
    /// drain permission guard 并终止尚未 Started 的 Accepted；Revoked 表示其它 exact
    /// revoke 已完成，只允许 durable owner 做幂等 replay，不重复连接清理。
    async fn begin_exact_remote_principal_revoke(
        &self,
        principal: &AuthenticatedPrincipal,
    ) -> Result<bool, RuntimeCoreError> {
        begin_exact_remote_principal_revoke(&self.conversations, principal).await
    }

    /// durable revoke 成功后的 terminal publish。Accepted 已在 pre-COMMIT fence
    /// 阶段终止；这里切连接并发布 Revoked。registry 清理即使报错，也不能把 lease
    /// 回滚到 Active。
    async fn finalize_remote_principal_revoke(
        &self,
        principal: AuthenticatedPrincipal,
    ) -> Result<(), RuntimeCoreError> {
        finalize_remote_principal_revoke(&self.connections, &self.subscriptions, principal).await
    }

    /// 事件/异步 reply 的非阻塞投递入口。真正 transport flush ACK 前 Core 仍持有
    /// frame/byte budget；Lagged 只关闭当前 connection。
    pub fn enqueue(
        &self,
        connection_id: ConnectionId,
        envelope: &RuntimeEnvelope,
    ) -> Result<(), RuntimeFailure> {
        let operation = self
            .try_enter_operation()
            .map_err(RuntimeCoreError::into_failure)?;
        self.enqueue_admitted(&operation, connection_id, envelope)
    }

    fn enqueue_admitted(
        &self,
        _operation: &RuntimeOperationGuard,
        connection_id: ConnectionId,
        envelope: &RuntimeEnvelope,
    ) -> Result<(), RuntimeFailure> {
        let frame = EncodedRuntimeFrame::from_envelope(envelope)
            .map_err(|error| RuntimeCoreError::Connection(error).into_failure())?;
        self.connections
            .try_enqueue(connection_id, frame)
            .map_err(|error| RuntimeCoreError::Connection(error).into_failure())
    }

    /// barrier/backfill job 的 paced egress。只等待有界 writer permit；调用方必须
    /// 再等待返回的 FlushReceipt，确认 transport flush ACK 后才推进 durable pin。
    pub async fn enqueue_paced(
        &self,
        connection_id: ConnectionId,
        envelope: &RuntimeEnvelope,
    ) -> Result<FlushReceipt, RuntimeFailure> {
        let frame = EncodedRuntimeFrame::from_envelope(envelope)
            .map_err(|error| RuntimeCoreError::Connection(error).into_failure())?;
        if self.lifecycle.load(Ordering::Acquire) != CORE_READY {
            return Err(RuntimeCoreError::NotReady.into_failure());
        }
        let reservation = self
            .connections
            .reserve_paced(connection_id, frame)
            .await
            .map_err(|error| RuntimeCoreError::Connection(error).into_failure())?;
        let _operation = self
            .try_enter_operation()
            .map_err(RuntimeCoreError::into_failure)?;
        self.connections
            .commit_paced(reservation)
            .map_err(|error| RuntimeCoreError::Connection(error).into_failure())
    }

    pub async fn shutdown(&self) -> Result<(), RuntimeFailure> {
        let _guard = self.shutdown_lock.lock().await;
        // recover 持有同一把锁直到 store finish 与 scheduling publish 全部完成；因此
        // shutdown 不会与最后一次 READY publish 交叉，也不会留下 recovering store。
        let _recovery = self.recovery_lock.lock().await;
        let state = self.lifecycle.load(Ordering::Acquire);
        if state == CORE_STOPPED {
            return Ok(());
        }
        let mut first_failure = None;
        if state != CORE_DRAINING {
            self.lifecycle.store(CORE_CLOSING, Ordering::Release);
            // CLOSING 必须先同步关闭新的 adapter/start admission。native metadata
            // caller 已持有 retained operation/auth/serialization guard、但仍在等待
            // 全局 permit 时，close 会让它以零 claim/零 vendor 退出；已取得 permit
            // 并移交 actor 的 operation 不受影响，仍由下方 quiescence 等到 terminal。
            self.conversations.close_admission();
            self.wait_for_operation_quiescence().await;
            // retained safety mutation 先让 operation quiescence 证明业务 future 已经
            // 返回，再显式 drain/join task wrapper；不能只凭计数器丢弃 JoinHandle。
            if self.safety_tasks.shutdown().await.is_err() {
                first_failure = Some(RuntimeFailure::new(
                    DAEMON_RUNTIME_ACTOR_UNAVAILABLE,
                    "runtime safety task owner failed to join",
                ));
            }
            // Projector 可能正在持有 per-conversation quiescence lease 或等待
            // Store exact convergence；必须先 cancel/join，再关 actor scheduling/store。
            self.native_projector.shutdown().await;
            // Background conversation runners 不计入 operation_inflight；必须在公开
            // Draining 前另行等待 close_admission 之前已取得的 start lease。不能把
            // 这个 await 提到 operation quiescence 前，否则会恢复反向等待环。
            self.conversations.wait_for_start_fence().await;
            self.lifecycle.store(CORE_DRAINING, Ordering::Release);
        } else {
            if self.safety_tasks.shutdown().await.is_err() {
                first_failure = Some(RuntimeFailure::new(
                    DAEMON_RUNTIME_ACTOR_UNAVAILABLE,
                    "runtime safety task owner failed to join",
                ));
            }
            self.native_projector.shutdown().await;
        }

        // 任一子层报错也继续拆掉其他资源，避免一次 actor/writer join failure 让
        // connection 或 SQLite worker 永久残留。只有 store 真正静默后才发布 STOPPED。
        if let Err(error) = self.conversations.shutdown().await
            && first_failure.is_none()
        {
            first_failure = Some(RuntimeCoreError::Conversation(error).into_failure());
        }
        if let Err(error) = self.subscriptions.shutdown().await
            && first_failure.is_none()
        {
            first_failure = Some(error.into_failure());
        }
        if let Err(error) = self.connections.shutdown().await
            && first_failure.is_none()
        {
            first_failure = Some(RuntimeCoreError::Connection(error).into_failure());
        }
        self.read_pool.close();
        let store_quiesced = match self.store.clone().shutdown().await {
            Ok(()) => true,
            Err(error) => {
                if first_failure.is_none() {
                    first_failure = Some(RuntimeCoreError::Store(error).into_failure());
                }
                false
            }
        };
        if store_quiesced {
            self.lifecycle.store(CORE_STOPPED, Ordering::Release);
        }
        match first_failure {
            Some(failure) => Err(failure),
            None => Ok(()),
        }
    }

    fn try_enter_operation(&self) -> Result<RuntimeOperationGuard, RuntimeCoreError> {
        if self.lifecycle.load(Ordering::Acquire) != CORE_READY {
            return Err(RuntimeCoreError::NotReady);
        }
        self.operation_tracker.enter();
        if self.lifecycle.load(Ordering::Acquire) != CORE_READY {
            self.operation_tracker.leave();
            return Err(RuntimeCoreError::NotReady);
        }
        Ok(RuntimeOperationGuard {
            tracker: self.operation_tracker.clone(),
        })
    }

    async fn wait_for_operation_quiescence(&self) {
        loop {
            // Notify 不保留 notify_waiters permit；先 enable waiter 再复查计数，避免
            // 最后一个 operation 在 load 与 await 之间 drop 造成 lost wakeup。
            let notified = self.operation_tracker.quiesced.notified();
            tokio::pin!(notified);
            notified.as_mut().enable();
            if self.operation_tracker.inflight.load(Ordering::Acquire) == 0 {
                return;
            }
            notified.await;
        }
    }

    #[cfg(test)]
    async fn actor_count(&self) -> usize {
        self.conversations.len().await
    }
}

async fn begin_exact_remote_principal_revoke(
    conversations: &ConversationRegistry,
    principal: &AuthenticatedPrincipal,
) -> Result<bool, RuntimeCoreError> {
    match conversations.begin_principal_revocation(principal).await {
        Ok(()) => {
            conversations
                .terminate_principal_accepted(principal)
                .await?;
            Ok(true)
        }
        Err(ConversationError::Principal(PrincipalAccessError::Revoked)) => Ok(false),
        Err(error) => Err(RuntimeCoreError::Conversation(error)),
    }
}

async fn finalize_remote_principal_revoke(
    connections: &ConnectionRegistry,
    subscriptions: &SubscriptionCoordinator,
    principal: AuthenticatedPrincipal,
) -> Result<(), RuntimeCoreError> {
    let authorization_key = principal.authorization_key();
    // durable backend 已成功后先发布 Revoked，阻断任何新 retry attach；随后取得的
    // exact connection 快照必然包含所有在发布前完成双读的 retry connection。
    principal.finish_revoke();
    let exact_connections = connections.connections_for_authorization(&authorization_key);
    if let Ok(exact_connections) = &exact_connections {
        for connection_id in exact_connections.iter().copied() {
            let _ = subscriptions.disconnect(connection_id).await;
            let _ = connections.disconnect(connection_id).await;
        }
    }
    exact_connections.map_err(RuntimeCoreError::Connection)?;
    Ok(())
}

#[derive(Default)]
struct RuntimeOperationTracker {
    inflight: AtomicUsize,
    quiesced: Notify,
}

impl RuntimeOperationTracker {
    fn enter(&self) {
        self.inflight.fetch_add(1, Ordering::AcqRel);
    }

    fn leave(&self) {
        if self.inflight.fetch_sub(1, Ordering::AcqRel) == 1 {
            self.quiesced.notify_waiters();
        }
    }
}

pub(crate) struct RuntimeOperationGuard {
    tracker: Arc<RuntimeOperationTracker>,
}

impl RuntimeOperationGuard {
    /// 已准入 operation 的 daemon-owned retained lease。它不重新检查 lifecycle：
    /// caller 已在 READY 时通过双读 admission，actor 只延长同一 operation 的
    /// shutdown quiescence 边界，不能借此准入新请求。
    pub(crate) fn retain(&self) -> Self {
        self.tracker.enter();
        Self {
            tracker: self.tracker.clone(),
        }
    }
}

impl Drop for RuntimeOperationGuard {
    fn drop(&mut self) {
        self.tracker.leave();
    }
}

struct RuntimeSafetyTaskState {
    accepting: bool,
    tasks: JoinSet<()>,
}

/// caller/transport 生命周期之外继续执行的安全 mutation 只能登记在此 owner。
///
/// 同步 mutex 把 capacity 检查、spawn 与 owner 登记收口在一个临界区；publication
/// handshake 保证 future 在登记完成前不会执行。正常 shutdown 显式 join，Core Drop
/// 则依赖 JoinSet 的 abort-on-drop 语义，任何路径都不会把 task detach。
struct RuntimeSafetyTaskOwner {
    capacity: usize,
    state: StdMutex<RuntimeSafetyTaskState>,
}

impl RuntimeSafetyTaskOwner {
    fn new(capacity: usize) -> Self {
        Self {
            capacity,
            state: StdMutex::new(RuntimeSafetyTaskState {
                accepting: true,
                tasks: JoinSet::new(),
            }),
        }
    }

    fn spawn<F, T>(&self, future: F) -> Result<oneshot::Receiver<T>, RuntimeSafetyTaskError>
    where
        F: Future<Output = T> + Send + 'static,
        T: Send + 'static,
    {
        let mut state = self
            .state
            .lock()
            .map_err(|_| RuntimeSafetyTaskError::OwnerUnavailable)?;
        if !state.accepting {
            return Err(RuntimeSafetyTaskError::ShuttingDown);
        }

        let mut previous_failed = false;
        while let Some(result) = state.tasks.try_join_next() {
            previous_failed |= result.is_err();
        }
        if previous_failed {
            return Err(RuntimeSafetyTaskError::TaskFailed);
        }
        if state.tasks.len() >= self.capacity {
            return Err(RuntimeSafetyTaskError::Capacity);
        }

        let (result_tx, result_rx) = oneshot::channel();
        let (publish, published) = oneshot::channel();
        state.tasks.spawn(async move {
            if published.await.is_err() {
                return;
            }
            let _ = result_tx.send(future.await);
        });
        drop(state);
        publish
            .send(())
            .map_err(|_| RuntimeSafetyTaskError::TaskFailed)?;
        Ok(result_rx)
    }

    async fn shutdown(&self) -> Result<(), RuntimeSafetyTaskError> {
        let mut tasks = {
            let mut state = self
                .state
                .lock()
                .map_err(|_| RuntimeSafetyTaskError::OwnerUnavailable)?;
            state.accepting = false;
            std::mem::take(&mut state.tasks)
        };
        let mut failed = false;
        while let Some(result) = tasks.join_next().await {
            failed |= result.is_err();
        }
        if failed {
            Err(RuntimeSafetyTaskError::TaskFailed)
        } else {
            Ok(())
        }
    }

    #[cfg(test)]
    fn task_count(&self) -> usize {
        self.state
            .lock()
            .map_or(usize::MAX, |state| state.tasks.len())
    }
}

impl Drop for RuntimeSafetyTaskOwner {
    fn drop(&mut self) {
        let state = match self.state.get_mut() {
            Ok(state) => state,
            Err(poisoned) => poisoned.into_inner(),
        };
        state.accepting = false;
        state.tasks.abort_all();
        // JoinSet 自身 Drop 会继续持有并 abort 尚未完成的所有 task；这里显式
        // abort 是为了让 owner 的兜底语义不依赖调用方记得先 shutdown。
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq, thiserror::Error)]
enum RuntimeSafetyTaskError {
    #[error("runtime safety task owner is unavailable")]
    OwnerUnavailable,
    #[error("runtime safety task owner is shutting down")]
    ShuttingDown,
    #[error("runtime safety task capacity is exhausted")]
    Capacity,
    #[error("runtime safety task failed")]
    TaskFailed,
}

fn map_runtime_recovery_error(error: RuntimeRecoveryError) -> RuntimeCoreError {
    match error {
        RuntimeRecoveryError::Store(error) => RuntimeCoreError::Store(error),
        RuntimeRecoveryError::ReconciliationInvariant => RuntimeCoreError::RecoveryBlocked,
    }
}

#[derive(Debug, thiserror::Error)]
pub(crate) enum RuntimeCoreError {
    #[error("runtime core is not ready")]
    NotReady,
    #[error("runtime core lifecycle transition is invalid")]
    InvalidLifecycle,
    #[error("runtime request is invalid")]
    InvalidRequest,
    #[error("runtime feature belongs to a later approved phase")]
    FeatureUnavailable,
    #[error("runtime principal authorization is revoked")]
    AuthorizationRevoked,
    #[error("runtime principal lacks the required permission")]
    AuthorizationDenied,
    #[error("runtime turn is stale")]
    StaleTurn,
    #[error("runtime recovery requires P3.7 orphan fencing")]
    RecoveryBlocked,
    #[error("runtime identity domain is invalid")]
    InvalidIdentityDomain,
    #[error("runtime identity entropy is unavailable")]
    EntropyUnavailable,
    #[error("runtime agent descriptions violate daemon invariants")]
    AgentDescriptionsInvalid,
    #[error("runtime command identity belongs to verified native history only")]
    HistoryOnlyCommand,
    #[error("runtime command identity was not found")]
    CommandNotFound,
    #[error("remote administration failed: {0:?}")]
    RemoteAdministration(RemoteAdministrationError),
    #[error("pairing administration failed: {0:?}")]
    PairingAdministration(PairingAdministrationError),
    #[error("revocation administration failed: {0:?}")]
    RevocationAdministration(RevocationAdministrationError),
    #[error("conversation activation failed: {0:?}")]
    ConversationActivation(ConversationActivationError),
    #[error(transparent)]
    HistoryReceipt(#[from] HistoryOnlyReceiptError),
    #[error(transparent)]
    Store(#[from] RuntimeStoreError),
    #[error(transparent)]
    Conversation(#[from] ConversationError),
    #[error(transparent)]
    Connection(#[from] ConnectionError),
    #[error(transparent)]
    ReadPool(#[from] ReadPoolError),
    #[error(transparent)]
    Catalog(#[from] CatalogSnapshotProviderError),
    #[error(transparent)]
    NativeMetadata(#[from] NativeMutationCoordinatorError),
}

impl RuntimeCoreError {
    fn into_failure(self) -> RuntimeFailure {
        match self {
            Self::NotReady | Self::InvalidLifecycle => RuntimeFailure::new(
                DAEMON_RUNTIME_NOT_READY,
                "runtime core has not completed recovery or is draining",
            ),
            Self::InvalidRequest => RuntimeFailure::new(
                DAEMON_RUNTIME_INVALID_REQUEST,
                "runtime request failed canonical validation",
            ),
            Self::FeatureUnavailable => RuntimeFailure::new(
                DAEMON_RUNTIME_FEATURE_UNAVAILABLE,
                "runtime feature is not available in this daemon phase",
            ),
            Self::AuthorizationRevoked => RuntimeFailure::new(
                DAEMON_AUTHORIZATION_REVOKED,
                "runtime principal authorization is revoked",
            ),
            Self::AuthorizationDenied => RuntimeFailure::new(
                DAEMON_AUTHORIZATION_PERMISSION_DENIED,
                "runtime principal lacks the required permission",
            ),
            Self::StaleTurn => RuntimeFailure::new(
                agentdeck_protocol::runtime::failure::DAEMON_TURN_STALE,
                "runtime command or turn is no longer cancelable by this target",
            ),
            Self::RecoveryBlocked => RuntimeFailure::new(
                agentdeck_protocol::runtime::failure::DAEMON_RUNTIME_RECOVERY_BLOCKED,
                "runtime recovery requires orphan process fencing before execution can resume",
            ),
            Self::InvalidIdentityDomain | Self::EntropyUnavailable => RuntimeFailure::new(
                DAEMON_RUNTIME_IDENTITY_UNAVAILABLE,
                "runtime stable identity is unavailable",
            ),
            Self::AgentDescriptionsInvalid => RuntimeFailure::new(
                "daemon.runtime.invalid_state",
                "runtime agent descriptions violate daemon invariants",
            ),
            Self::HistoryOnlyCommand => RuntimeFailure::new(
                DAEMON_COMMAND_HISTORY_ONLY,
                "runtime command identity belongs to verified native history, not the command journal",
            ),
            Self::CommandNotFound => RuntimeFailure::new(
                DAEMON_COMMAND_NOT_FOUND,
                "runtime command identity was not found",
            ),
            Self::RemoteAdministration(error) => {
                RuntimeFailure::new(error.code(), "machine remote administration failed")
            }
            Self::PairingAdministration(error) => {
                RuntimeFailure::new(error.code(), "pairing administration failed")
            }
            Self::RevocationAdministration(error) => {
                RuntimeFailure::new(error.code(), "device revocation administration failed")
            }
            Self::ConversationActivation(error) => RuntimeFailure::new(
                error.code(),
                "remote conversation activation did not reach business-ready",
            ),
            Self::HistoryReceipt(_) => RuntimeFailure::new(
                DAEMON_RUNTIME_READ_UNAVAILABLE,
                "runtime history receipt index is unavailable",
            ),
            Self::Store(error) => {
                RuntimeFailure::new(error.code(), "runtime durable store rejected the operation")
            }
            Self::Conversation(error) => match error {
                ConversationError::NotFound => RuntimeFailure::new(
                    agentdeck_protocol::runtime::failure::DAEMON_CONVERSATION_NOT_FOUND,
                    "runtime conversation was not found",
                ),
                ConversationError::Store(error) => RuntimeFailure::new(
                    error.code(),
                    "runtime durable store rejected the operation",
                ),
                ConversationError::Principal(_) => RuntimeFailure::new(
                    DAEMON_AUTHORIZATION_REVOKED,
                    "runtime principal authorization is revoked",
                ),
                ConversationError::MailboxFull => RuntimeFailure::new(
                    agentdeck_protocol::runtime::failure::DAEMON_COMMAND_QUEUE_FULL,
                    "runtime conversation queue is full",
                ),
                ConversationError::NativeMetadata(error) => {
                    RuntimeCoreError::NativeMetadata(error).into_failure()
                }
                ConversationError::ActorUnavailable | ConversationError::Execution(_) => {
                    RuntimeFailure::new(
                        DAEMON_RUNTIME_ACTOR_UNAVAILABLE,
                        "runtime conversation actor is unavailable",
                    )
                }
                ConversationError::ActorLimit => RuntimeFailure::new(
                    DAEMON_RUNTIME_ACTOR_UNAVAILABLE,
                    "runtime conversation actor limit is reached",
                ),
            },
            Self::Connection(ConnectionError::FrameTooLarge) => RuntimeFailure::new(
                agentdeck_protocol::runtime::failure::DAEMON_PAYLOAD_ITEM_TOO_LARGE,
                "runtime JSON/UDS frame exceeds its hard limit",
            ),
            Self::Connection(_) => RuntimeFailure::new(
                DAEMON_RUNTIME_CONNECTION_UNAVAILABLE,
                "runtime connection is unavailable or lagged",
            ),
            Self::ReadPool(_) => RuntimeFailure::new(
                DAEMON_RUNTIME_READ_UNAVAILABLE,
                "runtime read capacity is unavailable",
            ),
            Self::Catalog(error) => match error {
                CatalogSnapshotProviderError::EntropyUnavailable => RuntimeFailure::new(
                    DAEMON_RUNTIME_IDENTITY_UNAVAILABLE,
                    "runtime catalog cursor identity is unavailable",
                ),
                CatalogSnapshotProviderError::Principal(error) => {
                    RuntimeCoreError::from(error).into_failure()
                }
                CatalogSnapshotProviderError::Store(error) => RuntimeFailure::new(
                    error.code(),
                    "runtime durable catalog snapshot is unavailable",
                ),
                _ => RuntimeFailure::new(
                    DAEMON_RUNTIME_READ_UNAVAILABLE,
                    "runtime catalog snapshot request is invalid or unavailable",
                ),
            },
            Self::NativeMetadata(NativeMutationCoordinatorError::Store(error)) => {
                RuntimeFailure::new(error.code(), "native metadata Store operation failed")
            }
            Self::NativeMetadata(_) => RuntimeFailure::new(
                DAEMON_RUNTIME_ACTOR_UNAVAILABLE,
                "native metadata side effect could not be fenced or reconciled",
            ),
        }
    }
}

fn remote_administration_error(error: RemoteAdministrationError) -> RuntimeCoreError {
    RuntimeCoreError::RemoteAdministration(error)
}

fn pairing_administration_error(error: PairingAdministrationError) -> RuntimeCoreError {
    RuntimeCoreError::PairingAdministration(error)
}

fn revocation_administration_error(error: RevocationAdministrationError) -> RuntimeCoreError {
    RuntimeCoreError::RevocationAdministration(error)
}

impl From<super::connection::PrincipalAccessError> for RuntimeCoreError {
    fn from(error: super::connection::PrincipalAccessError) -> Self {
        match error {
            super::connection::PrincipalAccessError::Revoked => Self::AuthorizationRevoked,
            super::connection::PrincipalAccessError::RegistryUnavailable => {
                Self::Connection(ConnectionError::RegistryPoisoned)
            }
            super::connection::PrincipalAccessError::RegistryFull => {
                Self::Connection(ConnectionError::ConnectionLimit)
            }
            super::connection::PrincipalAccessError::PermissionDenied => Self::AuthorizationDenied,
            super::connection::PrincipalAccessError::PermissionConflict => {
                Self::Connection(ConnectionError::RegistryPoisoned)
            }
        }
    }
}

fn random_runtime_id(kind: RuntimeIdKind) -> Result<RuntimeId, RuntimeCoreError> {
    for _ in 0..ID_DERIVATION_ATTEMPTS {
        let mut bytes = [0_u8; 16];
        getrandom::fill(&mut bytes).map_err(|_| RuntimeCoreError::EntropyUnavailable)?;
        if let Ok(id) = RuntimeId::from_bytes(kind, bytes) {
            return Ok(id);
        }
    }
    Err(RuntimeCoreError::EntropyUnavailable)
}

fn transition_snapshot_target(
    permit: &TransitionSnapshotPermit,
) -> Result<super::events::RuntimeStreamTarget, RuntimeCoreError> {
    match permit.scope() {
        KeyTransitionStreamScope::Catalog => Ok(super::events::RuntimeStreamTarget::Catalog),
        KeyTransitionStreamScope::Conversation(bytes) => {
            RuntimeId::from_bytes(RuntimeIdKind::Conversation, bytes)
                .map(super::events::RuntimeStreamTarget::Conversation)
                .map_err(|_| RuntimeCoreError::InvalidRequest)
        }
    }
}

fn runtime_stream_permission(
    target: &super::events::RuntimeStreamTarget,
) -> AuthorizationPermissionV1 {
    match target {
        super::events::RuntimeStreamTarget::Catalog => AuthorizationPermissionV1::CatalogRead,
        super::events::RuntimeStreamTarget::Conversation(_) => {
            AuthorizationPermissionV1::ConversationRead
        }
    }
}

fn runtime_inner_cursor_permission(value: &RuntimeInnerCursor) -> AuthorizationPermissionV1 {
    match value {
        RuntimeInnerCursor::Catalog { .. } => AuthorizationPermissionV1::CatalogRead,
        RuntimeInnerCursor::Conversation { .. } => AuthorizationPermissionV1::ConversationRead,
    }
}

fn runtime_backfill_permission(value: &BackfillRequest) -> AuthorizationPermissionV1 {
    match value {
        BackfillRequest::Catalog { .. } => AuthorizationPermissionV1::CatalogRead,
        BackfillRequest::Conversation { .. } => AuthorizationPermissionV1::ConversationRead,
    }
}

fn runtime_subscription_permission(value: &RuntimeSubscriptionTarget) -> AuthorizationPermissionV1 {
    match value {
        RuntimeSubscriptionTarget::Catalog => AuthorizationPermissionV1::CatalogRead,
        RuntimeSubscriptionTarget::Conversation { .. } => {
            AuthorizationPermissionV1::ConversationRead
        }
    }
}

fn parse_inner_cursor(
    value: RuntimeInnerCursor,
) -> Result<
    (
        super::events::RuntimeStreamTarget,
        agentdeck_protocol::runtime::StreamCursor,
    ),
    RuntimeCoreError,
> {
    match value {
        RuntimeInnerCursor::Catalog { cursor } => {
            Ok((super::events::RuntimeStreamTarget::Catalog, cursor))
        }
        RuntimeInnerCursor::Conversation {
            conversation_id,
            cursor,
        } => Ok((
            super::events::RuntimeStreamTarget::Conversation(parse_conversation_id(
                &conversation_id,
            )?),
            cursor,
        )),
    }
}

fn parse_backfill_request(
    value: BackfillRequest,
) -> Result<
    (
        super::events::RuntimeStreamTarget,
        agentdeck_protocol::runtime::StreamCursor,
    ),
    RuntimeCoreError,
> {
    match value {
        BackfillRequest::Catalog { after } => {
            Ok((super::events::RuntimeStreamTarget::Catalog, after))
        }
        BackfillRequest::Conversation {
            conversation_id,
            after,
        } => Ok((
            super::events::RuntimeStreamTarget::Conversation(parse_conversation_id(
                &conversation_id,
            )?),
            after,
        )),
    }
}

fn parse_subscription_target(
    value: RuntimeSubscriptionTarget,
) -> Result<super::events::RuntimeStreamTarget, RuntimeCoreError> {
    match value {
        RuntimeSubscriptionTarget::Catalog => Ok(super::events::RuntimeStreamTarget::Catalog),
        RuntimeSubscriptionTarget::Conversation { conversation_id } => {
            Ok(super::events::RuntimeStreamTarget::Conversation(
                parse_conversation_id(&conversation_id)?,
            ))
        }
    }
}

fn configuration_failure(error: RuntimeCoreError) -> RuntimeFailure {
    match error {
        RuntimeCoreError::Store(RuntimeStoreError::ConversationNotFound) => RuntimeFailure::new(
            DAEMON_CONVERSATION_NOT_FOUND,
            "runtime conversation was not found",
        ),
        RuntimeCoreError::Store(RuntimeStoreError::ConfigurationAgentMismatch) => {
            RuntimeFailure::new(
                DAEMON_RUNTIME_INVALID_REQUEST,
                "configuration agent kind does not match the conversation",
            )
        }
        other => other.into_failure(),
    }
}

fn metadata_failure(error: RuntimeCoreError) -> RuntimeFailure {
    match error {
        RuntimeCoreError::Store(RuntimeStoreError::ConversationNotFound) => RuntimeFailure::new(
            DAEMON_CONVERSATION_NOT_FOUND,
            "runtime conversation was not found",
        ),
        other => other.into_failure(),
    }
}

fn parse_conversation_id(value: &ConversationId) -> Result<RuntimeId, RuntimeCoreError> {
    RuntimeId::parse_canonical(RuntimeIdKind::Conversation, value.as_str())
        .map_err(|_| RuntimeCoreError::InvalidRequest)
}

fn validate_idempotency_key(value: &IdempotencyKey) -> Result<(), RuntimeCoreError> {
    if value.as_str().is_empty() || value.as_str().len() > MAX_IDEMPOTENCY_KEY_BYTES {
        Err(RuntimeCoreError::InvalidRequest)
    } else {
        Ok(())
    }
}

fn parse_command_id(value: &CommandId) -> Result<RuntimeId, RuntimeCoreError> {
    RuntimeId::parse_canonical(RuntimeIdKind::Command, value.as_str())
        .map_err(|_| RuntimeCoreError::InvalidRequest)
}

fn parse_turn_id(value: &TurnId) -> Result<RuntimeId, RuntimeCoreError> {
    RuntimeId::parse_canonical(RuntimeIdKind::Turn, value.as_str())
        .map_err(|_| RuntimeCoreError::InvalidRequest)
}

fn parse_approval_id(value: &ApprovalId) -> Result<RuntimeId, RuntimeCoreError> {
    RuntimeId::parse_canonical(RuntimeIdKind::Approval, value.as_str())
        .map_err(|_| RuntimeCoreError::InvalidRequest)
}

fn parse_pairing_id(
    value: &agentdeck_protocol::runtime::identity::PairingId,
) -> Result<RuntimeId, RuntimeCoreError> {
    RuntimeId::parse_canonical(RuntimeIdKind::Pairing, value.as_str())
        .map_err(|_| RuntimeCoreError::InvalidRequest)
}

fn wire_conversation_id(value: RuntimeId) -> ConversationId {
    ConversationId::new(value.to_canonical_string())
}

fn wire_command_id(value: RuntimeId) -> CommandId {
    CommandId::new(value.to_canonical_string())
}

fn wire_turn_id(value: RuntimeId) -> TurnId {
    TurnId::new(value.to_canonical_string())
}

fn wire_command_status(value: CommandState) -> CommandStatus {
    match value {
        CommandState::Accepted => CommandStatus::Accepted,
        CommandState::Started => CommandStatus::Started,
        CommandState::Completed => CommandStatus::Completed,
        CommandState::Failed => CommandStatus::Failed,
        CommandState::Interrupted => CommandStatus::Interrupted,
        CommandState::Expired => CommandStatus::Expired,
        CommandState::Canceled => CommandStatus::Canceled,
        CommandState::RevokedBeforeStart => CommandStatus::RevokedBeforeStart,
    }
}

#[cfg(test)]
#[path = "core/tests.rs"]
mod tests;
