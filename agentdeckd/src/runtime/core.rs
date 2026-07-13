//! transport-neutral singleton RuntimeCore。
//!
//! UDS 与 RemoteLink 只能在完成各自认证后交付 opaque
//! `AuthenticatedPrincipal + RuntimeRequest`；本层不 import socket/Relay 类型，也不按
//! transport 排序。所有 mutation 先过 recovery/lifecycle 与 authorization capability，
//! 再进入 durable store/per-conversation actor。

use std::sync::Arc;
use std::sync::atomic::{AtomicU8, AtomicUsize, Ordering};

use agentdeck_protocol::runtime::command::{HelloParams, QueryReceiptSelector};
use agentdeck_protocol::runtime::failure::{
    DAEMON_AUTHORIZATION_PERMISSION_DENIED, DAEMON_AUTHORIZATION_REVOKED,
    DAEMON_RUNTIME_ACTOR_UNAVAILABLE, DAEMON_RUNTIME_CONNECTION_UNAVAILABLE,
    DAEMON_RUNTIME_FEATURE_UNAVAILABLE, DAEMON_RUNTIME_IDENTITY_UNAVAILABLE,
    DAEMON_RUNTIME_INVALID_REQUEST, DAEMON_RUNTIME_NOT_READY, DAEMON_RUNTIME_PROTOCOL_MISMATCH,
    DAEMON_RUNTIME_READ_UNAVAILABLE,
};
use agentdeck_protocol::runtime::identity::{
    AdapterStateKey, ApprovalId, CommandId, ConversationId, IdempotencyKey, TurnId,
};
use agentdeck_protocol::runtime::{
    CancellationReceipt, CommandReceipt, CommandStatus, CommandStatusReceipt,
    ConversationStartReceipt, RUNTIME_PROTOCOL_VERSION, RuntimeEnvelope, RuntimeFailure,
    RuntimeReply, RuntimeRequest,
};
use tokio::sync::{Mutex, Notify};

use super::approval::ApprovalPrincipalCapability;
use super::connection::{
    AuthenticatedPrincipal, ConnectionError, ConnectionId, ConnectionRegistry, ConnectionSink,
    DEFAULT_CONNECTION_WRITER_BYTES, DEFAULT_CONNECTION_WRITER_FRAMES, EncodedRuntimeFrame,
    PrincipalIssuer,
};
use super::conversation::{
    ActiveCancelResult, ConversationError, ConversationRegistry, PromptAcceptResult,
    QueuedCancelResult,
};
use super::execution::{DisabledExecutionCoordinator, RuntimeExecutionCoordinator};
use super::read_pool::{DEFAULT_RUNTIME_READ_CONCURRENCY, ReadPool, ReadPoolError};
use super::router::AgentRouter;
use super::store::{
    CommandReceiptSelector, CommandState, ConversationDescriptor, CreateConversationOutcome,
    IdempotencyOwner, NewConversation, QueryCommandReceipt, RuntimeId, RuntimeIdKind,
    RuntimeStoreError, RuntimeStoreHandle,
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
    _router: Arc<AgentRouter>,
    connections: ConnectionRegistry,
    conversations: ConversationRegistry,
    read_pool: ReadPool,
    #[allow(dead_code)] // P3.8 UDS peer credential adapter 才会成为 production caller。
    principal_issuer: PrincipalIssuer,
    lifecycle: AtomicU8,
    operation_inflight: AtomicUsize,
    operation_quiesced: Notify,
    recovery_lock: Mutex<()>,
    shutdown_lock: Mutex<()>,
}

impl RuntimeCore {
    /// P3.4 production 构造固定安装 fail-closed coordinator。P3.7 才会把真实
    /// `--exec-gate` coordinator 注入这里。
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
        )
        .map_err(RuntimeCoreError::into_failure)
    }

    fn with_execution_coordinator(
        store: RuntimeStoreHandle,
        router: Arc<AgentRouter>,
        machine_trust_domain: [u8; 32],
        execution: Arc<dyn RuntimeExecutionCoordinator>,
        adapter_concurrency: usize,
    ) -> Result<Self, RuntimeCoreError> {
        if machine_trust_domain == [0; 32] {
            return Err(RuntimeCoreError::InvalidIdentityDomain);
        }
        let daemon_boot_id = random_runtime_id(RuntimeIdKind::DaemonBoot)?;
        let conversations = ConversationRegistry::new(
            store.clone(),
            execution,
            daemon_boot_id,
            adapter_concurrency,
        )?;
        Ok(Self {
            store,
            _router: router,
            connections: ConnectionRegistry::new(
                DEFAULT_CONNECTION_WRITER_FRAMES,
                DEFAULT_CONNECTION_WRITER_BYTES,
            ),
            conversations,
            read_pool: ReadPool::new(DEFAULT_RUNTIME_READ_CONCURRENCY)?,
            principal_issuer: PrincipalIssuer::local_only(machine_trust_domain),
            lifecycle: AtomicU8::new(CORE_COLD),
            operation_inflight: AtomicUsize::new(0),
            operation_quiesced: Notify::new(),
            recovery_lock: Mutex::new(()),
            shutdown_lock: Mutex::new(()),
        })
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
        let _operation = match self.try_enter_operation() {
            Ok(operation) => operation,
            Err(error) => return RuntimeReply::Failure(error.into_failure()),
        };
        let principal = match self.connections.principal(connection_id) {
            Ok(principal) => principal,
            Err(error) => {
                return RuntimeReply::Failure(RuntimeCoreError::Connection(error).into_failure());
            }
        };
        match self.handle_ready(principal, request).await {
            Ok(reply) => reply,
            Err(error) => RuntimeReply::Failure(error.into_failure()),
        }
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
        principal: AuthenticatedPrincipal,
        request: RuntimeRequest,
    ) -> Result<RuntimeReply, RuntimeCoreError> {
        match request {
            RuntimeRequest::Hello(params) => Ok(self.handle_hello(params)),
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
                    adapter_state_key: wire_adapter_state_key(conversation.adapter_state_key),
                    replayed,
                }))
            }
            RuntimeRequest::SendPrompt(request) => {
                // SendPrompt 的所有业务拒绝都属于 CommandReceipt family；否则
                // Companion 会把一次 command failure 误解成 envelope/control failure。
                let receipt = match async {
                    validate_idempotency_key(&request.idempotency_key)?;
                    let conversation_id = parse_conversation_id(&request.conversation_id)?;
                    let authorization = principal.try_enter()?;
                    self.conversations
                        .submit_prompt(
                            conversation_id,
                            principal,
                            authorization,
                            request.idempotency_key.as_str().to_owned(),
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
                    },
                    Ok(PromptAcceptResult::Replayed { command }) => CommandReceipt::Replayed {
                        command_id: wire_command_id(command.command_id),
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
                let (conversation_id, query) = match selector {
                    QueryReceiptSelector::Command {
                        conversation_id,
                        command_id,
                    } => {
                        let internal_conversation = parse_conversation_id(&conversation_id)?;
                        let internal_command = parse_command_id(&command_id)?;
                        (
                            conversation_id,
                            QueryCommandReceipt {
                                expected_owner: owner,
                                selector: CommandReceiptSelector::Command {
                                    conversation_id: internal_conversation,
                                    command_id: internal_command,
                                },
                            },
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
                        )
                    }
                };
                let store = self.store.clone();
                let receipt = self
                    .read_pool
                    .run(async move { store.query_command_receipt(query).await })
                    .await??;
                Ok(RuntimeReply::CommandStatus(CommandStatusReceipt {
                    conversation_id,
                    command_id: wire_command_id(receipt.command_id),
                    status: wire_command_status(receipt.state),
                    turn_id: receipt.turn_id.map(wire_turn_id),
                }))
            }
            RuntimeRequest::Catalog(_)
            | RuntimeRequest::Subscribe { .. }
            | RuntimeRequest::Unsubscribe { .. }
            | RuntimeRequest::Backfill(_)
            | RuntimeRequest::CreatePairInvite(_)
            | RuntimeRequest::ListPendingPairings { .. }
            | RuntimeRequest::ConfirmPairing { .. }
            | RuntimeRequest::CancelPairing { .. }
            | RuntimeRequest::Revoke(_)
            | RuntimeRequest::TrustReset { .. } => Err(RuntimeCoreError::FeatureUnavailable),
        }
    }

    /// 逐页消费 frozen recovery catalog；在 store `finish` 返回前 actor scheduling
    /// gate 始终关闭。P3.7 未实现 Started orphan fencing，因此发现 Started 时明确
    /// recovery-blocked，绝不把后续 Accepted 自动执行。
    pub async fn recover(&self) -> Result<RecoveryReport, RuntimeFailure> {
        let _guard = self.recovery_lock.lock().await;
        self.lifecycle
            .compare_exchange(
                CORE_COLD,
                CORE_RECOVERING,
                Ordering::AcqRel,
                Ordering::Acquire,
            )
            .map_err(|_| RuntimeCoreError::InvalidLifecycle.into_failure())?;
        let result = self.recover_inner().await;
        match result {
            Ok(report) => {
                self.lifecycle.store(CORE_READY, Ordering::Release);
                Ok(report)
            }
            Err(error) => Err(error.into_failure()),
        }
    }

    async fn recover_inner(&self) -> Result<RecoveryReport, RuntimeCoreError> {
        let mut report = RecoveryReport::default();
        let mut cursor = self.store.begin_recovery_scan().await?;
        loop {
            let page = self.store.load_recovery_page(cursor).await?;
            if let Some(recovery) = page.conversation {
                if recovery.started.is_some() {
                    return Err(RuntimeCoreError::RecoveryBlocked);
                }
                // P4 durable auth ledger 尚未接线，无法把恢复出的 remote owner 重新
                // 绑定到精确 grant serial/authorization lease。发现这类记录必须阻断
                // 整个 startup recovery，禁止以 owner 近似代替授权。
                if recovery
                    .accepted
                    .iter()
                    .any(|command| matches!(&command.owner, IdempotencyOwner::Remote { .. }))
                {
                    return Err(RuntimeCoreError::RecoveryBlocked);
                }
                report.conversations = report
                    .conversations
                    .checked_add(1)
                    .ok_or(RuntimeCoreError::RecoveryBlocked)?;
                report.accepted_commands = report
                    .accepted_commands
                    .checked_add(
                        u64::try_from(recovery.accepted.len())
                            .map_err(|_| RuntimeCoreError::RecoveryBlocked)?,
                    )
                    .ok_or(RuntimeCoreError::RecoveryBlocked)?;
                self.conversations
                    .install(recovery.conversation, recovery.accepted)
                    .await?;
            }
            if let Some(next) = page.next_cursor {
                cursor = next;
                continue;
            }
            self.store
                .finish_recovery_scan(page.completion.ok_or(RuntimeCoreError::RecoveryBlocked)?)
                .await?;
            self.conversations.enable_scheduling().await?;
            return Ok(report);
        }
    }

    pub async fn disconnect(&self, connection_id: ConnectionId) {
        let _ = self.connections.disconnect(connection_id).await;
    }

    /// 事件/异步 reply 的非阻塞投递入口。真正 transport flush ACK 前 Core 仍持有
    /// frame/byte budget；Lagged 只关闭当前 connection。
    pub fn enqueue(
        &self,
        connection_id: ConnectionId,
        envelope: &RuntimeEnvelope,
    ) -> Result<(), RuntimeFailure> {
        let _operation = self
            .try_enter_operation()
            .map_err(RuntimeCoreError::into_failure)?;
        let frame = EncodedRuntimeFrame::from_envelope(envelope)
            .map_err(|error| RuntimeCoreError::Connection(error).into_failure())?;
        self.connections
            .try_enqueue(connection_id, frame)
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
            self.wait_for_operation_quiescence().await;
            // Background conversation runners 不计入 operation_inflight；必须在公开
            // Draining 前另行撤销 retained scheduling gate 并等待所有 start lease。
            self.conversations.begin_draining().await;
            self.lifecycle.store(CORE_DRAINING, Ordering::Release);
        }

        // 任一子层报错也继续拆掉其他资源，避免一次 actor/writer join failure 让
        // connection 或 SQLite worker 永久残留。只有 store 真正静默后才发布 STOPPED。
        let mut first_failure = None;
        if let Err(error) = self.conversations.shutdown().await {
            first_failure = Some(RuntimeCoreError::Conversation(error).into_failure());
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

    fn try_enter_operation(&self) -> Result<RuntimeOperationGuard<'_>, RuntimeCoreError> {
        if self.lifecycle.load(Ordering::Acquire) != CORE_READY {
            return Err(RuntimeCoreError::NotReady);
        }
        self.operation_inflight.fetch_add(1, Ordering::AcqRel);
        if self.lifecycle.load(Ordering::Acquire) != CORE_READY {
            if self.operation_inflight.fetch_sub(1, Ordering::AcqRel) == 1 {
                self.operation_quiesced.notify_waiters();
            }
            return Err(RuntimeCoreError::NotReady);
        }
        Ok(RuntimeOperationGuard { core: self })
    }

    async fn wait_for_operation_quiescence(&self) {
        loop {
            // Notify 不保留 notify_waiters permit；先 enable waiter 再复查计数，避免
            // 最后一个 operation 在 load 与 await 之间 drop 造成 lost wakeup。
            let notified = self.operation_quiesced.notified();
            tokio::pin!(notified);
            notified.as_mut().enable();
            if self.operation_inflight.load(Ordering::Acquire) == 0 {
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

struct RuntimeOperationGuard<'a> {
    core: &'a RuntimeCore,
}

impl Drop for RuntimeOperationGuard<'_> {
    fn drop(&mut self) {
        if self.core.operation_inflight.fetch_sub(1, Ordering::AcqRel) == 1 {
            self.core.operation_quiesced.notify_waiters();
        }
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
    #[error(transparent)]
    Store(#[from] RuntimeStoreError),
    #[error(transparent)]
    Conversation(#[from] ConversationError),
    #[error(transparent)]
    Connection(#[from] ConnectionError),
    #[error(transparent)]
    ReadPool(#[from] ReadPoolError),
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
        }
    }
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

fn wire_adapter_state_key(value: RuntimeId) -> AdapterStateKey {
    AdapterStateKey::new(value.to_canonical_string())
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
mod tests {
    use std::fs;
    use std::path::{Path, PathBuf};
    use std::sync::atomic::{AtomicU64, Ordering};

    use agentdeck_protocol::runtime::identity::{
        ApprovalId, ConversationId, EventId, IdempotencyKey, MessageId,
    };
    use agentdeck_protocol::runtime::{
        ConversationStart, MAX_RUNTIME_JSON_FRAME_BYTES, PromptPayload, QueryReceiptSelector,
        RuntimeEvent, RuntimeEventBody, RuntimeMessage, RuntimeStreamItem, SendPromptRequest,
    };
    use agentdeck_protocol::{ActionDecision, ActionDecisionKind, AgentKind};
    use tokio::sync::mpsc;

    use super::*;
    use crate::security::{MemoryKeyStore, StorageKek, load_or_create_storage_kek};

    static NEXT_ROOT: AtomicU64 = AtomicU64::new(1);

    struct TestRoot {
        path: PathBuf,
        keys: MemoryKeyStore,
    }

    impl TestRoot {
        fn new(label: &str) -> Self {
            let path = Path::new("/tmp").join(format!(
                "agentdeck-runtime-core-{label}-{}-{}",
                std::process::id(),
                NEXT_ROOT.fetch_add(1, Ordering::Relaxed)
            ));
            let _ = fs::remove_dir_all(&path);
            fs::create_dir(&path).expect("create core test root");
            #[cfg(unix)]
            {
                use std::os::unix::fs::PermissionsExt;
                fs::set_permissions(&path, fs::Permissions::from_mode(0o700))
                    .expect("secure core test root");
            }
            Self {
                path,
                keys: MemoryKeyStore::new(),
            }
        }

        fn kek(&self) -> StorageKek {
            load_or_create_storage_kek(&self.keys, &self.path.join("key-state.db"))
                .expect("core test StorageKEK")
        }

        async fn open_store(&self) -> RuntimeStoreHandle {
            RuntimeStoreHandle::open(
                super::super::store::RuntimeStoreConfig::new(self.path.join("runtime.db"))
                    .with_command_capacity(1_024),
                self.kek(),
            )
            .await
            .expect("open core test store")
        }
    }

    impl Drop for TestRoot {
        fn drop(&mut self) {
            let _ = fs::remove_dir_all(&self.path);
        }
    }

    async fn core(root: &TestRoot) -> Arc<RuntimeCore> {
        let store = root.open_store().await;
        let router = Arc::new(AgentRouter::with_runtime_store(store.clone()));
        Arc::new(RuntimeCore::new(store, router, [0xA1; 32]).expect("construct RuntimeCore"))
    }

    fn start_request(key: &str) -> RuntimeRequest {
        RuntimeRequest::Start(ConversationStart {
            agent_kind: AgentKind::Codex,
            idempotency_key: IdempotencyKey::new(key),
            cwd: PathBuf::from("/tmp/agentdeck-core-test"),
            title: Some("core test".to_owned()),
        })
    }

    fn start_receipt(reply: RuntimeReply) -> ConversationStartReceipt {
        match reply {
            RuntimeReply::ConversationStart(receipt) => receipt,
            other => panic!("expected conversation start receipt, got {other:?}"),
        }
    }

    async fn connect_local(core: &RuntimeCore, seed: u8) -> ConnectionId {
        let principal = core
            .issue_verified_local_principal(501, [seed; 16])
            .expect("issue local principal");
        let (sink, mut receiver) = mpsc::channel::<crate::runtime::ConnectionWrite>(8);
        tokio::spawn(async move {
            while let Some(write) = receiver.recv().await {
                let _ = write.acknowledge();
            }
        });
        core.connect(principal, ConnectionSink::new(sink))
            .expect("connect local")
    }

    async fn connect_local_with_approval_permissions(
        core: &RuntimeCore,
        seed: u8,
        permissions: crate::runtime::connection::ApprovalPermissionGrant,
    ) -> ConnectionId {
        let principal = core
            .principal_issuer
            .issue_verified_local_with_approval_permissions(501, [seed; 16], permissions)
            .expect("issue approval principal");
        let (sink, mut receiver) = mpsc::channel::<crate::runtime::ConnectionWrite>(8);
        tokio::spawn(async move {
            while let Some(write) = receiver.recv().await {
                let _ = write.acknowledge();
            }
        });
        core.connect(principal, ConnectionSink::new(sink))
            .expect("connect approval principal")
    }

    fn synthetic_wire_id(kind: RuntimeIdKind, seed: u8) -> String {
        RuntimeId::from_bytes(kind, [seed; 16])
            .expect("synthetic runtime id")
            .to_canonical_string()
    }

    #[tokio::test]
    async fn principal_without_approval_permission_cannot_claim() {
        let root = TestRoot::new("approval-permission-denied");
        let core = core(&root).await;
        core.recover().await.expect("recover");
        let connection = connect_local(&core, 41).await;

        let reply = core
            .handle(
                connection,
                RuntimeRequest::ResolveApproval {
                    conversation_id: ConversationId::new(synthetic_wire_id(
                        RuntimeIdKind::Conversation,
                        0x41,
                    )),
                    turn_id: TurnId::new(synthetic_wire_id(RuntimeIdKind::Turn, 0x42)),
                    approval_id: ApprovalId::new(synthetic_wire_id(RuntimeIdKind::Approval, 0x43)),
                    decision: ActionDecision {
                        request_id: "request-permission-denied".to_owned(),
                        decision: ActionDecisionKind::Approve,
                        persist: false,
                    },
                },
            )
            .await;

        assert!(matches!(
            reply,
            RuntimeReply::Failure(RuntimeFailure { code, .. })
                if code == DAEMON_AUTHORIZATION_PERMISSION_DENIED
        ));
        let retry = core
            .handle(
                connection,
                RuntimeRequest::RetryApproval {
                    conversation_id: ConversationId::new(synthetic_wire_id(
                        RuntimeIdKind::Conversation,
                        0x41,
                    )),
                    approval_id: ApprovalId::new(synthetic_wire_id(RuntimeIdKind::Approval, 0x43)),
                },
            )
            .await;
        assert!(matches!(
            retry,
            RuntimeReply::Failure(RuntimeFailure { code, .. })
                if code == DAEMON_AUTHORIZATION_PERMISSION_DENIED
        ));
        core.shutdown().await.expect("shutdown core");
    }

    #[tokio::test]
    async fn approval_requests_require_canonical_approval_ids() {
        let root = TestRoot::new("approval-id-validation");
        let core = core(&root).await;
        core.recover().await.expect("recover");
        let connection = connect_local_with_approval_permissions(
            &core,
            42,
            crate::runtime::connection::ApprovalPermissionGrant::ResolveOnly,
        )
        .await;

        let reply = core
            .handle(
                connection,
                RuntimeRequest::ResolveApproval {
                    conversation_id: ConversationId::new(synthetic_wire_id(
                        RuntimeIdKind::Conversation,
                        0x51,
                    )),
                    turn_id: TurnId::new(synthetic_wire_id(RuntimeIdKind::Turn, 0x52)),
                    approval_id: ApprovalId::new("not-a-canonical-approval-id"),
                    decision: ActionDecision {
                        request_id: "request-invalid-id".to_owned(),
                        decision: ActionDecisionKind::Deny,
                        persist: false,
                    },
                },
            )
            .await;

        assert!(matches!(
            reply,
            RuntimeReply::Failure(RuntimeFailure { code, .. })
                if code == DAEMON_RUNTIME_INVALID_REQUEST
        ));
        core.shutdown().await.expect("shutdown core");
    }

    #[tokio::test]
    async fn start_is_pure_durable_idempotent_then_prompt_and_query_are_separate() {
        let root = TestRoot::new("start-query");
        let core = core(&root).await;
        assert_eq!(
            core.recover().await.expect("recover"),
            RecoveryReport::default()
        );
        let connection = connect_local(&core, 1).await;

        let created = start_receipt(core.handle(connection, start_request("stable-start")).await);
        assert!(!created.replayed);
        let replayed = start_receipt(core.handle(connection, start_request("stable-start")).await);
        assert!(replayed.replayed);
        assert_eq!(created.conversation_id, replayed.conversation_id);
        assert_eq!(created.adapter_state_key, replayed.adapter_state_key);
        assert_eq!(core.actor_count().await, 1);

        let invalid_prompt = core
            .handle(
                connection,
                RuntimeRequest::SendPrompt(SendPromptRequest {
                    conversation_id: created.conversation_id.clone(),
                    idempotency_key: IdempotencyKey::new(""),
                    prompt: PromptPayload::new("must be rejected before actor admission")
                        .expect("prompt"),
                }),
            )
            .await;
        assert!(matches!(
            invalid_prompt,
            RuntimeReply::Command(CommandReceipt::Failed {
                failure: RuntimeFailure { code, .. }
            }) if code == DAEMON_RUNTIME_INVALID_REQUEST
        ));
        let missing_conversation = core
            .handle(
                connection,
                RuntimeRequest::SendPrompt(SendPromptRequest {
                    conversation_id: wire_conversation_id(
                        RuntimeId::from_bytes(RuntimeIdKind::Conversation, [0xEE; 16])
                            .expect("synthetic missing conversation"),
                    ),
                    idempotency_key: IdempotencyKey::new("missing-conversation"),
                    prompt: PromptPayload::new("must stay in command receipt family")
                        .expect("prompt"),
                }),
            )
            .await;
        assert!(matches!(
            missing_conversation,
            RuntimeReply::Command(CommandReceipt::Failed {
                failure: RuntimeFailure { code, .. }
            }) if code == agentdeck_protocol::runtime::failure::DAEMON_CONVERSATION_NOT_FOUND
        ));
        let invalid_query = core
            .handle(
                connection,
                RuntimeRequest::QueryReceipt(QueryReceiptSelector::Idempotency {
                    conversation_id: created.conversation_id.clone(),
                    idempotency_key: IdempotencyKey::new("x".repeat(1_025)),
                }),
            )
            .await;
        assert!(matches!(
            invalid_query,
            RuntimeReply::Failure(RuntimeFailure { code, .. })
                if code == DAEMON_RUNTIME_INVALID_REQUEST
        ));
        let conflict = core
            .handle(
                connection,
                RuntimeRequest::Start(ConversationStart {
                    agent_kind: AgentKind::ClaudeCode,
                    idempotency_key: IdempotencyKey::new("stable-start"),
                    cwd: PathBuf::from("/tmp/agentdeck-core-test"),
                    title: Some("conflicting descriptor".to_owned()),
                }),
            )
            .await;
        assert!(matches!(
            conflict,
            RuntimeReply::Failure(RuntimeFailure { code, .. })
                if code == agentdeck_protocol::runtime::failure::DAEMON_COMMAND_IDEMPOTENCY_CONFLICT
        ));

        let prompt_key = IdempotencyKey::new("prompt-1");
        let prompt = PromptPayload::new("hello durable queue").expect("prompt");
        let accepted = core
            .handle(
                connection,
                RuntimeRequest::SendPrompt(SendPromptRequest {
                    conversation_id: created.conversation_id.clone(),
                    idempotency_key: prompt_key.clone(),
                    prompt,
                }),
            )
            .await;
        let command_id = match accepted {
            RuntimeReply::Command(CommandReceipt::Accepted { command_id, .. }) => command_id,
            other => panic!("expected accepted command, got {other:?}"),
        };
        let status = core
            .handle(
                connection,
                RuntimeRequest::QueryReceipt(QueryReceiptSelector::Idempotency {
                    conversation_id: created.conversation_id.clone(),
                    idempotency_key: prompt_key,
                }),
            )
            .await;
        match status {
            RuntimeReply::CommandStatus(receipt) => {
                assert_eq!(receipt.conversation_id, created.conversation_id);
                assert_eq!(receipt.command_id, command_id);
                assert_eq!(receipt.status, CommandStatus::Accepted);
                assert_eq!(receipt.turn_id, None);
            }
            other => panic!("expected command status, got {other:?}"),
        }

        core.shutdown().await.expect("shutdown core");
    }

    #[tokio::test]
    async fn one_hundred_concurrent_start_retries_install_exactly_one_actor() {
        let root = TestRoot::new("start-race");
        let core = core(&root).await;
        core.recover().await.expect("recover");
        let connection = connect_local(&core, 2).await;
        let mut tasks = Vec::new();
        for _ in 0..100 {
            let core = core.clone();
            tasks.push(tokio::spawn(async move {
                start_receipt(
                    core.handle(connection, start_request("same-race-key"))
                        .await,
                )
            }));
        }
        let mut created = 0;
        let mut replayed = 0;
        let mut identity = None;
        for task in tasks {
            let receipt = task.await.expect("join start retry");
            if receipt.replayed {
                replayed += 1;
            } else {
                created += 1;
            }
            match &identity {
                Some(existing) => assert_eq!(existing, &receipt.conversation_id),
                None => identity = Some(receipt.conversation_id),
            }
        }
        assert_eq!(created, 1);
        assert_eq!(replayed, 99);
        assert_eq!(core.actor_count().await, 1);
        core.shutdown().await.expect("shutdown core");
    }

    #[tokio::test]
    async fn accepted_queue_is_recovered_paged_and_remains_unstarted_without_real_gate() {
        let root = TestRoot::new("restart");
        let first_core = core(&root).await;
        first_core.recover().await.expect("first recover");
        let first_connection = connect_local(&first_core, 3).await;
        let conversation = start_receipt(
            first_core
                .handle(first_connection, start_request("restart-start"))
                .await,
        );
        let accepted = first_core
            .handle(
                first_connection,
                RuntimeRequest::SendPrompt(SendPromptRequest {
                    conversation_id: conversation.conversation_id.clone(),
                    idempotency_key: IdempotencyKey::new("restart-prompt"),
                    prompt: PromptPayload::new("survive restart").expect("prompt"),
                }),
            )
            .await;
        assert!(matches!(
            accepted,
            RuntimeReply::Command(CommandReceipt::Accepted { .. })
        ));
        first_core.shutdown().await.expect("first shutdown");
        drop(first_core);

        let second_core = core(&root).await;
        assert_eq!(
            second_core.recover().await.expect("second recover"),
            RecoveryReport {
                conversations: 1,
                accepted_commands: 1,
            }
        );
        let second_connection = connect_local(&second_core, 3).await;
        let replayed_start = start_receipt(
            second_core
                .handle(second_connection, start_request("restart-start"))
                .await,
        );
        assert!(replayed_start.replayed);
        assert_eq!(replayed_start.conversation_id, conversation.conversation_id);
        assert_eq!(
            replayed_start.adapter_state_key,
            conversation.adapter_state_key
        );
        let status = second_core
            .handle(
                second_connection,
                RuntimeRequest::QueryReceipt(QueryReceiptSelector::Idempotency {
                    conversation_id: conversation.conversation_id,
                    idempotency_key: IdempotencyKey::new("restart-prompt"),
                }),
            )
            .await;
        assert!(matches!(
            status,
            RuntimeReply::CommandStatus(CommandStatusReceipt {
                status: CommandStatus::Accepted,
                turn_id: None,
                ..
            })
        ));
        second_core.shutdown().await.expect("second shutdown");
    }

    #[tokio::test]
    async fn shutdown_drains_admitted_operations_before_closing_subsystems() {
        let root = TestRoot::new("operation-drain");
        let core = core(&root).await;
        core.recover().await.expect("recover");
        let admitted = core
            .try_enter_operation()
            .expect("admit operation before draining");
        let shutting_core = core.clone();
        let shutdown = tokio::spawn(async move { shutting_core.shutdown().await });

        tokio::time::timeout(std::time::Duration::from_secs(1), async {
            while core.lifecycle.load(Ordering::Acquire) != CORE_CLOSING {
                tokio::task::yield_now().await;
            }
        })
        .await
        .expect("shutdown publishes internal closing fence");
        assert_ne!(
            core.lifecycle.load(Ordering::Acquire),
            CORE_DRAINING,
            "Draining is not published before admitted operations quiesce"
        );
        assert!(
            !shutdown.is_finished(),
            "shutdown must wait for the already admitted operation"
        );
        assert!(matches!(
            core.try_enter_operation(),
            Err(RuntimeCoreError::NotReady)
        ));

        drop(admitted);
        shutdown
            .await
            .expect("join shutdown")
            .expect("shutdown after quiescence");
        assert_eq!(core.lifecycle.load(Ordering::Acquire), CORE_STOPPED);
    }

    #[tokio::test]
    async fn enqueue_writes_a_complete_runtime_envelope() {
        let root = TestRoot::new("complete-envelope");
        let core = core(&root).await;
        core.recover().await.expect("recover");
        let principal = core
            .issue_verified_local_principal(501, [4; 16])
            .expect("issue local principal");
        let (sink, mut receiver) = mpsc::channel::<crate::runtime::ConnectionWrite>(1);
        let connection = core
            .connect(principal, ConnectionSink::new(sink))
            .expect("connect local");

        let outbound = agentdeck_protocol::runtime::RuntimeEnvelope {
            version: RUNTIME_PROTOCOL_VERSION,
            message_id: agentdeck_protocol::runtime::identity::MessageId::new(
                "message-core-envelope-test",
            ),
            body: RuntimeMessage::Reply(RuntimeReply::Hello(HelloParams {
                runtime_protocol_version: RUNTIME_PROTOCOL_VERSION,
            })),
        };
        core.enqueue(connection, &outbound).expect("enqueue reply");
        let write = receiver.recv().await.expect("transport write");
        let envelope: agentdeck_protocol::runtime::RuntimeEnvelope =
            serde_json::from_slice(write.bytes()).expect("complete RuntimeEnvelope");
        assert_eq!(envelope.version, RUNTIME_PROTOCOL_VERSION);
        assert_eq!(envelope.message_id.as_str(), "message-core-envelope-test");
        assert!(matches!(
            envelope.body,
            RuntimeMessage::Reply(RuntimeReply::Hello(HelloParams {
                runtime_protocol_version: RUNTIME_PROTOCOL_VERSION
            }))
        ));
        write.acknowledge().expect("ack transport write");
        core.shutdown().await.expect("shutdown core");
    }

    #[tokio::test]
    async fn enqueue_rejects_oversized_reply_and_stream_before_connection_writer() {
        let root = TestRoot::new("oversized-egress-frame");
        let core = core(&root).await;
        core.recover().await.expect("recover");
        let principal = core
            .issue_verified_local_principal(501, [5; 16])
            .expect("issue local principal");
        let (sink, mut receiver) = mpsc::channel::<crate::runtime::ConnectionWrite>(2);
        let connection = core
            .connect(principal, ConnectionSink::new(sink))
            .expect("connect local");

        let oversized_failure = || {
            RuntimeFailure::new(
                "daemon.test.oversized",
                "x".repeat(MAX_RUNTIME_JSON_FRAME_BYTES),
            )
        };
        let reply = RuntimeEnvelope {
            version: RUNTIME_PROTOCOL_VERSION,
            message_id: MessageId::new("message-core-oversized-reply"),
            body: RuntimeMessage::Reply(RuntimeReply::Failure(oversized_failure())),
        };
        let failure = core.enqueue(connection, &reply).unwrap_err();
        assert_eq!(
            failure.code,
            agentdeck_protocol::runtime::failure::DAEMON_PAYLOAD_ITEM_TOO_LARGE
        );

        let event = RuntimeEvent::new(
            ConversationId::new("conversation-core-oversized-stream"),
            EventId::new("event-core-oversized-stream"),
            0,
            None,
            None,
            None,
            RuntimeEventBody::Error {
                failure: oversized_failure(),
            },
        )
        .unwrap();
        let stream = RuntimeEnvelope {
            version: RUNTIME_PROTOCOL_VERSION,
            message_id: MessageId::new("message-core-oversized-stream"),
            body: RuntimeMessage::Stream(RuntimeStreamItem::Event(event)),
        };
        let failure = core.enqueue(connection, &stream).unwrap_err();
        assert_eq!(
            failure.code,
            agentdeck_protocol::runtime::failure::DAEMON_PAYLOAD_ITEM_TOO_LARGE
        );
        assert!(matches!(
            receiver.try_recv(),
            Err(tokio::sync::mpsc::error::TryRecvError::Empty)
        ));
        core.shutdown().await.expect("shutdown core");
    }
}
