//! transport-neutral singleton RuntimeCore。
//!
//! UDS 与 RemoteLink 只能在完成各自认证后交付 opaque
//! `AuthenticatedPrincipal + RuntimeRequest`；本层不 import socket/Relay 类型，也不按
//! transport 排序。所有 mutation 先过 recovery/lifecycle 与 authorization capability，
//! 再进入 durable store/per-conversation actor。

use std::path::PathBuf;
use std::sync::Arc;
use std::sync::atomic::{AtomicU8, AtomicUsize, Ordering};

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
    ApprovalId, CommandId, ConversationId, IdempotencyKey, TurnId,
};
use agentdeck_protocol::runtime::{
    BackfillRequest, CancellationReceipt, CommandReceipt, CommandStatus, CommandStatusReceipt,
    ConfigurationReceipt, ConversationMetadataReceipt, ConversationStartReceipt,
    RUNTIME_PROTOCOL_VERSION, RuntimeEnvelope, RuntimeFailure, RuntimeInnerCursor, RuntimeMessage,
    RuntimeReply, RuntimeRequest, RuntimeSubscriptionTarget, StageUpgradeReceipt,
    SubscriptionReceipt,
};
use tokio::sync::{Mutex, Notify, Semaphore, mpsc};

use super::approval::ApprovalPrincipalCapability;
use super::catalog_snapshot::{CatalogSnapshotProvider, CatalogSnapshotProviderError};
use super::connection::{
    AuthenticatedPrincipal, ConnectionError, ConnectionId, ConnectionRegistry, ConnectionSink,
    DEFAULT_CONNECTION_WRITER_BYTES, DEFAULT_CONNECTION_WRITER_FRAMES, EncodedRuntimeFrame,
    FlushReceipt, PrincipalIssuer,
};
use super::conversation::{
    ActiveCancelResult, ConversationError, ConversationRegistry, PromptAcceptResult,
    QueuedCancelResult,
};
use super::execution::{
    DisabledExecutionCoordinator, GatedExecutionCoordinator, RuntimeExecutionCoordinator,
};
use super::history_receipt::{HistoryOnlyReceiptError, HistoryOnlyReceiptRegistry};
use super::native_metadata::{
    NativeMutationCoordinator, NativeMutationCoordinatorError, NativeMutationOutcome,
};
use super::native_projector::NativeProjector;
use super::process_identity::SystemProcessGroupController;
use super::read_pool::{DEFAULT_RUNTIME_READ_CONCURRENCY, ReadPool, ReadPoolError};
use super::recovery::{
    RecoveryOptions, RecoveryReadyPermit, RuntimeRecoveryCoordinator, RuntimeRecoveryError,
    RuntimeRecoveryInstallError,
};
use super::remote_administration::{
    DisabledRemoteAdministration, RemoteAdministration, RemoteAdministrationError,
};
use super::router::AgentRouter;
use super::snapshot::SNAPSHOT_BUILD_MEMORY_BYTES;
use super::store::{
    CommandReceiptSelector, CommandState, ConfigureConversation, ConfigureConversationOutcome,
    ConversationDescriptor, CreateConversationOutcome, NewConversation, QueryCommandReceipt,
    RuntimeId, RuntimeIdKind, RuntimeStoreError, RuntimeStoreHandle, SnapshotOrigin,
    UpdateConversationMetadataOutcome, UpdateManagedConversationMetadata,
};
use super::subscription::coordinator::SubscriptionCoordinator;
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
    recovery_identity: Arc<()>,
    recovery: RuntimeRecoveryCoordinator,
    read_pool: ReadPool,
    #[allow(dead_code)] // P3.8 UDS peer credential adapter 才会成为 production caller。
    principal_issuer: PrincipalIssuer,
    lifecycle: AtomicU8,
    operation_tracker: Arc<RuntimeOperationTracker>,
    recovery_lock: Mutex<()>,
    shutdown_lock: Mutex<()>,
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
            recovery_identity,
            recovery,
            read_pool: ReadPool::new(DEFAULT_RUNTIME_READ_CONCURRENCY)?,
            principal_issuer: PrincipalIssuer::local_only(machine_trust_domain),
            lifecycle: AtomicU8::new(CORE_COLD),
            operation_tracker: Arc::new(RuntimeOperationTracker::default()),
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

    /// 连接只接收不可伪造的认证 capability；raw route/uid 字段不是本接口输入。
    pub fn connect(
        &self,
        principal: AuthenticatedPrincipal,
        sink: ConnectionSink,
    ) -> Result<ConnectionId, RuntimeFailure> {
        let _operation = self
            .try_enter_operation()
            .map_err(RuntimeCoreError::into_failure)?;
        self.connections
            .connect(principal, sink)
            .map_err(|error| RuntimeCoreError::Connection(error).into_failure())
    }

    /// 所有 transport 共用的规范化请求入口。
    pub async fn handle(
        &self,
        connection_id: ConnectionId,
        request: RuntimeRequest,
    ) -> RuntimeReply {
        if let RuntimeRequest::Hello(params) = &request {
            return self.handle_hello(params.clone());
        }
        let operation = match self.try_enter_operation() {
            Ok(operation) => operation,
            Err(error) => return RuntimeReply::Failure(error.into_failure()),
        };
        self.handle_admitted(&operation, connection_id, request)
            .await
    }

    async fn handle_admitted(
        &self,
        _operation: &RuntimeOperationGuard,
        connection_id: ConnectionId,
        request: RuntimeRequest,
    ) -> RuntimeReply {
        if let RuntimeRequest::Hello(params) = &request {
            return self.handle_hello(params.clone());
        }
        let principal = match self.connections.principal(connection_id) {
            Ok(principal) => principal,
            Err(error) => {
                return RuntimeReply::Failure(RuntimeCoreError::Connection(error).into_failure());
            }
        };
        match self.handle_ready(_operation, principal, request).await {
            Ok(reply) => reply,
            Err(error) => RuntimeReply::Failure(error.into_failure()),
        }
    }

    /// 所有 Runtime v3 transport 共用的完整 envelope 入口。directed reply 严格复用
    /// 原 request messageId，并进入 connection-owned reply pump；本方法不等待 socket。
    pub async fn handle_envelope(
        &self,
        connection_id: ConnectionId,
        envelope: RuntimeEnvelope,
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
    ) -> Option<Result<(), RuntimeFailure>> {
        let stream_result = match request {
            RuntimeRequest::Catalog(request) => {
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
                let _authorization = match principal.try_enter() {
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
                        super::backfill::BarrierRequest::Subscribe { cursor },
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
                let _authorization = match principal.try_enter() {
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
                let _authorization = match principal.try_enter() {
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
                let reply = self.handle_admitted(operation, connection_id, other).await;
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
    ) -> Result<RuntimeReply, RuntimeCoreError> {
        match request {
            RuntimeRequest::Hello(params) => Ok(self.handle_hello(params)),
            RuntimeRequest::DescribeAgents => {
                let authorization = principal.try_enter()?;
                let descriptions = self
                    .router
                    .agent_descriptions()
                    .map_err(|_| RuntimeCoreError::AgentDescriptionsInvalid)?;
                drop(authorization);
                Ok(RuntimeReply::Agents(descriptions))
            }
            RuntimeRequest::Start(start) => {
                let _authorization = principal.try_enter()?;
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
                let (conversation, replayed) = match outcome {
                    CreateConversationOutcome::Created { conversation } => (conversation, false),
                    CreateConversationOutcome::Replayed { conversation } => (conversation, true),
                };
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
                    let authorization = principal.try_enter()?;
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
                    let authorization = principal.try_enter()?;
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
                    let authorization = principal.try_enter()?;
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
                let authorization = principal.try_enter()?;
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
                let authorization = principal.try_enter()?;
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
                let authorization = principal.try_enter_approval()?;
                authorization.require_retry()?;
                let receipt = self
                    .conversations
                    .retry_approval(internal_conversation, internal_approval, authorization)
                    .await?;
                Ok(RuntimeReply::Approval(receipt))
            }
            RuntimeRequest::QueryReceipt(selector) => {
                let _authorization = principal.try_enter()?;
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
            RuntimeRequest::Subscribe { .. }
            | RuntimeRequest::Unsubscribe { .. }
            | RuntimeRequest::Backfill(_) => Err(RuntimeCoreError::InvalidRequest),
            // Catalog page 可能超过单 frame 上限，必须携带原 messageId 进入
            // handle_envelope 的 tracked paced egress；direct handle 禁止返回大 DTO。
            RuntimeRequest::Catalog(_) => Err(RuntimeCoreError::InvalidRequest),
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
            RuntimeRequest::CreatePairInvite(_)
            | RuntimeRequest::ListPendingPairings { .. }
            | RuntimeRequest::ConfirmPairing { .. }
            | RuntimeRequest::CancelPairing { .. } => {
                let _authorization = principal.try_enter_local_administration()?;
                Err(RuntimeCoreError::FeatureUnavailable)
            }
            RuntimeRequest::Revoke(request) => {
                if matches!(request.target, RevokeTarget::Device { .. }) {
                    let _authorization = principal.try_enter_local_administration()?;
                }
                Err(RuntimeCoreError::FeatureUnavailable)
            }
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
        if state != CORE_DRAINING {
            self.lifecycle.store(CORE_CLOSING, Ordering::Release);
            // CLOSING 必须先同步关闭新的 adapter/start admission。native metadata
            // caller 已持有 retained operation/auth/serialization guard、但仍在等待
            // 全局 permit 时，close 会让它以零 claim/零 vendor 退出；已取得 permit
            // 并移交 actor 的 operation 不受影响，仍由下方 quiescence 等到 terminal。
            self.conversations.close_admission();
            self.wait_for_operation_quiescence().await;
            // Projector 可能正在持有 per-conversation quiescence lease 或等待
            // Store exact convergence；必须先 cancel/join，再关 actor scheduling/store。
            self.native_projector.shutdown().await;
            // Background conversation runners 不计入 operation_inflight；必须在公开
            // Draining 前另行等待 close_admission 之前已取得的 start lease。不能把
            // 这个 await 提到 operation quiescence 前，否则会恢复反向等待环。
            self.conversations.wait_for_start_fence().await;
            self.lifecycle.store(CORE_DRAINING, Ordering::Release);
        } else {
            self.native_projector.shutdown().await;
        }

        // 任一子层报错也继续拆掉其他资源，避免一次 actor/writer join failure 让
        // connection 或 SQLite worker 永久残留。只有 store 真正静默后才发布 STOPPED。
        let mut first_failure = None;
        if let Err(error) = self.conversations.shutdown().await {
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
