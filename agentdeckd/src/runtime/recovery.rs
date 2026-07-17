//! Started orphan 的两遍恢复与启动许可。
//!
//! 威胁场景：daemon 在 Started 已提交后崩溃，旧 vendor process group 仍可能产生副作用；
//! 若重启直接恢复同 conversation 的 Accepted queue，新旧 turn 会并发执行。恢复因此先从
//! authenticated store page 取得 exact process identity，确认整组退出后才写 Interrupted；无法
//! 证明退出时只阻断该 conversation。`RecoveryReadyPermit` 只能在第二遍 store 审计完成后产生。

use std::collections::BTreeMap;
use std::convert::Infallible;
use std::future::Future;
use std::sync::Arc;
use std::time::Duration;

use thiserror::Error;

use super::process_identity::{
    ProcessGroupController, ProcessIdentity, ProcessObservation, ProcessSignal,
};
use super::store::{
    CommandRecord, CommandTerminal, CompleteCommand, ConversationLifecycle, ConversationRecord,
    ConversationRecoveryRecord, IdempotencyOwner, MarkConversationRecoveryBlocked,
    RecoverStartedCommand, RecoveryBlockedCommandBinding, RecoveryFenceBinding, RuntimeId,
    RuntimeStoreError, RuntimeStoreHandle, StartedBeforeReleaseTermination, StartedRecoveryRecord,
    TerminateStartedBeforeRelease,
};

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct RecoveryOptions {
    pub term_grace: Duration,
    pub kill_grace: Duration,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ConversationRecoveryState {
    Ready,
    Blocked,
}

#[derive(Debug, Eq, PartialEq)]
pub struct ConversationRecoveryOutcome {
    state: ConversationRecoveryState,
    durable_accepted_command_ids: Vec<RuntimeId>,
    interrupted_command_id: Option<RuntimeId>,
    expected_started_command_id: Option<RuntimeId>,
    expected_lifecycle: ConversationLifecycle,
}

impl ConversationRecoveryOutcome {
    #[must_use]
    pub const fn state(&self) -> ConversationRecoveryState {
        self.state
    }

    #[must_use]
    pub fn accepted_command_ids(&self) -> &[RuntimeId] {
        if self.state == ConversationRecoveryState::Ready {
            &self.durable_accepted_command_ids
        } else {
            &[]
        }
    }

    #[must_use]
    pub const fn interrupted_command_id(&self) -> Option<RuntimeId> {
        self.interrupted_command_id
    }
}

/// 只能由一次完整 reconciliation 产生的启动许可。
#[derive(Debug)]
pub struct RecoveryReadyPermit {
    core_identity: Arc<()>,
}

impl RecoveryReadyPermit {
    pub(crate) fn belongs_to(&self, core_identity: &Arc<()>) -> bool {
        Arc::ptr_eq(&self.core_identity, core_identity)
    }
}

#[derive(Debug)]
pub struct RuntimeRecoveryReport {
    conversations: BTreeMap<RuntimeId, ConversationRecoveryOutcome>,
}

type ReadyConversation = (ConversationRecord, Vec<CommandRecord>);

#[derive(Debug)]
pub(crate) enum RuntimeRecoveryInstallError<E> {
    Recovery(RuntimeRecoveryError),
    Install(E),
}

impl<E> From<RuntimeRecoveryError> for RuntimeRecoveryInstallError<E> {
    fn from(error: RuntimeRecoveryError) -> Self {
        Self::Recovery(error)
    }
}

impl RuntimeRecoveryReport {
    #[must_use]
    pub fn conversation(&self, conversation_id: RuntimeId) -> Option<&ConversationRecoveryOutcome> {
        self.conversations.get(&conversation_id)
    }

    pub(crate) fn conversation_count(&self) -> usize {
        self.conversations.len()
    }

    pub(crate) fn ready_accepted_count(&self) -> usize {
        self.conversations
            .values()
            .filter(|outcome| outcome.state == ConversationRecoveryState::Ready)
            .map(|outcome| outcome.durable_accepted_command_ids.len())
            .sum()
    }
}

#[derive(Debug, Error)]
pub enum RuntimeRecoveryError {
    #[error("runtime recovery store operation failed: {0}")]
    Store(#[from] RuntimeStoreError),
    #[error("runtime recovery reconciliation invariant failed")]
    ReconciliationInvariant,
}

pub struct RuntimeRecoveryCoordinator {
    store: RuntimeStoreHandle,
    processes: Arc<dyn ProcessGroupController>,
    options: RecoveryOptions,
    core_identity: Arc<()>,
}

impl RuntimeRecoveryCoordinator {
    #[must_use]
    pub fn new(
        store: RuntimeStoreHandle,
        processes: Arc<dyn ProcessGroupController>,
        options: RecoveryOptions,
    ) -> Self {
        Self::new_with_core_identity(store, processes, options, Arc::new(()))
    }

    pub(crate) fn new_with_core_identity(
        store: RuntimeStoreHandle,
        processes: Arc<dyn ProcessGroupController>,
        options: RecoveryOptions,
        core_identity: Arc<()>,
    ) -> Self {
        Self {
            store,
            processes,
            options,
            core_identity,
        }
    }

    /// 只读调用方使用的两遍 reconciliation；它会完成 durable orphan 处置与第二遍
    /// readback，但不会把 actor 安装许可暴露给调用方。
    pub async fn reconcile(&self) -> Result<RuntimeRecoveryReport, RuntimeRecoveryError> {
        let result = self
            .reconcile_with_install(
                |_conversation, _accepted| async { Ok::<(), Infallible>(()) },
                false,
            )
            .await;
        match result {
            Ok((report, _permit)) => Ok(report),
            Err(RuntimeRecoveryInstallError::Recovery(error)) => Err(error),
            Err(RuntimeRecoveryInstallError::Install(never)) => match never {},
        }
    }

    /// production bootstrap 的唯一恢复入口。第一遍先冻结/处置 P3 尚不能 exact 重绑的
    /// remote Accepted 与其他 conversation；第二遍使用 verify-only scan 逐页复核。
    /// 若第一遍含 remote Accepted，必须先持久化并读回同批次的安全 Interrupted/sticky
    /// blocked，且全局不安装 actor，随后才返回 unsupported。
    /// `RecoveryReadyPermit` 只能在第二遍 durable finish readback 成功后构造。
    pub(crate) async fn reconcile_and_install<F, Fut, E>(
        &self,
        install: F,
    ) -> Result<(RuntimeRecoveryReport, RecoveryReadyPermit), RuntimeRecoveryInstallError<E>>
    where
        F: FnMut(ConversationRecord, Vec<CommandRecord>) -> Fut,
        Fut: Future<Output = Result<(), E>>,
    {
        self.reconcile_with_install(install, true).await
    }

    async fn reconcile_with_install<F, Fut, E>(
        &self,
        install: F,
        reject_remote_accepted: bool,
    ) -> Result<(RuntimeRecoveryReport, RecoveryReadyPermit), RuntimeRecoveryInstallError<E>>
    where
        F: FnMut(ConversationRecord, Vec<CommandRecord>) -> Fut,
        Fut: Future<Output = Result<(), E>>,
    {
        let mut plans = self.classify_first_pass().await?;
        let remote_accepted_unsupported =
            reject_remote_accepted && plans.values().any(|plan| plan.contains_remote_accepted);
        self.persist_safe_interruptions(&plans).await?;
        let conversations = self
            .verify_second_pass_and_install(&mut plans, install, !remote_accepted_unsupported)
            .await?;
        if !plans.is_empty() {
            return Err(RuntimeRecoveryInstallError::Recovery(
                RuntimeRecoveryError::ReconciliationInvariant,
            ));
        }
        if remote_accepted_unsupported {
            return Err(RuntimeRecoveryInstallError::Recovery(
                RuntimeRecoveryError::ReconciliationInvariant,
            ));
        }
        Ok((
            RuntimeRecoveryReport { conversations },
            RecoveryReadyPermit {
                core_identity: self.core_identity.clone(),
            },
        ))
    }

    async fn classify_first_pass(
        &self,
    ) -> Result<BTreeMap<RuntimeId, ConversationPlan>, RuntimeRecoveryError> {
        let mut plans = BTreeMap::new();
        let mut cursor = self.store.begin_recovery_scan().await?;
        loop {
            let page = self.store.load_recovery_page(cursor).await?;
            if let Some(recovery) = page.conversation {
                let conversation_id = recovery.conversation.conversation_id;
                let plan = self.classify_conversation(recovery).await;
                if plans.insert(conversation_id, plan).is_some() {
                    return Err(RuntimeRecoveryError::ReconciliationInvariant);
                }
            }
            if let Some(next) = page.next_cursor {
                cursor = next;
                continue;
            }
            self.store
                .finish_recovery_scan(
                    page.completion
                        .ok_or(RuntimeRecoveryError::ReconciliationInvariant)?,
                )
                .await?;
            return Ok(plans);
        }
    }

    async fn classify_conversation(
        &self,
        recovery: ConversationRecoveryRecord,
    ) -> ConversationPlan {
        let lifecycle_blocked =
            recovery.conversation.lifecycle == ConversationLifecycle::RecoveryBlocked;
        let durable_accepted_command_ids = recovery
            .accepted
            .iter()
            .map(|command| command.command_id)
            .collect();
        let contains_remote_accepted = recovery
            .accepted
            .iter()
            .any(|command| matches!(command.owner, IdempotencyOwner::Remote { .. }));
        let Some(started) = recovery.started else {
            return ConversationPlan {
                started: None,
                blocked: lifecycle_blocked,
                durable_accepted_command_ids,
                contains_remote_accepted,
            };
        };
        let interruption = PlannedInterruption::from_started(&started);
        let blocked = lifecycle_blocked
            || match started.fence.as_ref() {
                // Started without a durable fence means no process identity was promoted. The
                // blocked gate's daemon-owned control pipe is gone after the crash, so there is
                // no known group to signal and the durable Started is conservatively Interrupted.
                None => false,
                Some(fence) => match ProcessIdentity::new(
                    fence.process_group_id,
                    fence.leader_pid,
                    fence.leader_start_time,
                ) {
                    Ok(identity) => !self.fence_process_group(identity).await,
                    Err(_) => true,
                },
            };
        ConversationPlan {
            started: Some(interruption),
            blocked,
            durable_accepted_command_ids,
            contains_remote_accepted,
        }
    }

    async fn fence_process_group(&self, identity: ProcessIdentity) -> bool {
        match self.processes.probe(identity).await {
            Ok(ProcessObservation::Exited) => return true,
            Ok(ProcessObservation::ExactAlive) => {}
            Ok(ProcessObservation::IdentityMismatch | ProcessObservation::Unknown) | Err(_) => {
                return false;
            }
        }
        if self
            .processes
            .signal(identity, ProcessSignal::Terminate)
            .await
            .is_err()
        {
            return false;
        }
        match self
            .processes
            .wait_for_exit(identity, self.options.term_grace)
            .await
        {
            Ok(ProcessObservation::Exited) => return true,
            Ok(ProcessObservation::ExactAlive) => {}
            Ok(ProcessObservation::IdentityMismatch | ProcessObservation::Unknown) | Err(_) => {
                return false;
            }
        }
        if self
            .processes
            .signal(identity, ProcessSignal::Kill)
            .await
            .is_err()
        {
            return false;
        }
        matches!(
            self.processes
                .wait_for_exit(identity, self.options.kill_grace)
                .await,
            Ok(ProcessObservation::Exited)
        )
    }

    async fn persist_safe_interruptions(
        &self,
        plans: &BTreeMap<RuntimeId, ConversationPlan>,
    ) -> Result<(), RuntimeRecoveryError> {
        for (conversation_id, plan) in plans {
            if plan.blocked {
                let input = MarkConversationRecoveryBlocked {
                    conversation_id: *conversation_id,
                    expected_command: plan
                        .started
                        .as_ref()
                        .map(|interruption| interruption.binding.clone()),
                };
                retry_mark_recovery_blocked(&self.store, input).await?;
                continue;
            }
            let Some(started) = plan.started.as_ref() else {
                continue;
            };
            if started.release_authorized() {
                let input = RecoverStartedCommand {
                    completion: CompleteCommand {
                        conversation_id: *conversation_id,
                        command_id: started.command_id(),
                        turn_id: started.turn_id(),
                        terminal: CommandTerminal::interrupted(),
                    },
                    expected_started: RecoveryBlockedCommandBinding::Started {
                        command_id: started.command_id(),
                        turn_id: started.turn_id(),
                        daemon_boot_id: started.daemon_boot_id(),
                        execution_nonce: started.execution_nonce().to_vec(),
                        fence: started.fence().cloned().map(Box::new),
                    },
                };
                retry_recover_interrupted(&self.store, input).await?;
            } else {
                let input = TerminateStartedBeforeRelease {
                    conversation_id: *conversation_id,
                    command_id: started.command_id(),
                    turn_id: started.turn_id(),
                    daemon_boot_id: started.daemon_boot_id(),
                    execution_nonce: started.execution_nonce().to_vec(),
                    reason: StartedBeforeReleaseTermination::Interrupted,
                };
                retry_terminate_before_release(&self.store, input).await?;
            }
        }
        Ok(())
    }

    async fn verify_second_pass_and_install<F, Fut, E>(
        &self,
        plans: &mut BTreeMap<RuntimeId, ConversationPlan>,
        mut install: F,
        install_ready_conversations: bool,
    ) -> Result<BTreeMap<RuntimeId, ConversationRecoveryOutcome>, RuntimeRecoveryInstallError<E>>
    where
        F: FnMut(ConversationRecord, Vec<CommandRecord>) -> Fut,
        Fut: Future<Output = Result<(), E>>,
    {
        let mut outcomes = BTreeMap::new();
        let mut cursor = self
            .store
            .begin_recovery_verification_scan()
            .await
            .map_err(RuntimeRecoveryError::from)
            .map_err(RuntimeRecoveryInstallError::Recovery)?;
        loop {
            let page = self
                .store
                .load_recovery_page(cursor)
                .await
                .map_err(RuntimeRecoveryError::from)
                .map_err(RuntimeRecoveryInstallError::Recovery)?;
            if let Some(recovery) = page.conversation {
                let conversation_id = recovery.conversation.conversation_id;
                let plan =
                    plans
                        .remove(&conversation_id)
                        .ok_or(RuntimeRecoveryInstallError::Recovery(
                            RuntimeRecoveryError::ReconciliationInvariant,
                        ))?;
                let (outcome, ready) = verify_conversation(recovery, plan)
                    .map_err(RuntimeRecoveryInstallError::Recovery)?;
                if let Some((conversation, accepted)) = ready
                    && install_ready_conversations
                {
                    install(conversation, accepted)
                        .await
                        .map_err(RuntimeRecoveryInstallError::Install)?;
                }
                if outcomes.insert(conversation_id, outcome).is_some() {
                    return Err(RuntimeRecoveryInstallError::Recovery(
                        RuntimeRecoveryError::ReconciliationInvariant,
                    ));
                }
            }
            if let Some(next) = page.next_cursor {
                cursor = next;
                continue;
            }
            self.store
                .finish_recovery_scan(page.completion.ok_or(
                    RuntimeRecoveryInstallError::Recovery(
                        RuntimeRecoveryError::ReconciliationInvariant,
                    ),
                )?)
                .await
                .map_err(RuntimeRecoveryError::from)
                .map_err(RuntimeRecoveryInstallError::Recovery)?;
            return Ok(outcomes);
        }
    }
}

struct ConversationPlan {
    started: Option<PlannedInterruption>,
    blocked: bool,
    durable_accepted_command_ids: Vec<RuntimeId>,
    contains_remote_accepted: bool,
}

#[derive(Eq, PartialEq)]
struct PlannedInterruption {
    binding: RecoveryBlockedCommandBinding,
}

impl PlannedInterruption {
    fn from_started(started: &StartedRecoveryRecord) -> Self {
        Self {
            binding: RecoveryBlockedCommandBinding::Started {
                command_id: started.command.command_id,
                turn_id: started.intent.turn_id,
                daemon_boot_id: started.intent.daemon_boot_id,
                execution_nonce: started.intent.execution_nonce.clone(),
                fence: started
                    .fence
                    .as_ref()
                    .map(RecoveryFenceBinding::from_record)
                    .map(Box::new),
            },
        }
    }

    fn command_id(&self) -> RuntimeId {
        match &self.binding {
            RecoveryBlockedCommandBinding::Started { command_id, .. } => *command_id,
            RecoveryBlockedCommandBinding::Accepted { .. } => unreachable!(),
        }
    }

    fn turn_id(&self) -> RuntimeId {
        match &self.binding {
            RecoveryBlockedCommandBinding::Started { turn_id, .. } => *turn_id,
            RecoveryBlockedCommandBinding::Accepted { .. } => unreachable!(),
        }
    }

    fn daemon_boot_id(&self) -> RuntimeId {
        match &self.binding {
            RecoveryBlockedCommandBinding::Started { daemon_boot_id, .. } => *daemon_boot_id,
            RecoveryBlockedCommandBinding::Accepted { .. } => unreachable!(),
        }
    }

    fn execution_nonce(&self) -> &[u8] {
        match &self.binding {
            RecoveryBlockedCommandBinding::Started {
                execution_nonce, ..
            } => execution_nonce,
            RecoveryBlockedCommandBinding::Accepted { .. } => unreachable!(),
        }
    }

    fn fence(&self) -> Option<&RecoveryFenceBinding> {
        match &self.binding {
            RecoveryBlockedCommandBinding::Started { fence, .. } => fence.as_deref(),
            RecoveryBlockedCommandBinding::Accepted { .. } => unreachable!(),
        }
    }

    fn release_authorized(&self) -> bool {
        self.fence()
            .is_some_and(|fence| fence.release_authorized_at_ms.is_some())
    }
}

fn verify_conversation(
    recovery: ConversationRecoveryRecord,
    plan: ConversationPlan,
) -> Result<(ConversationRecoveryOutcome, Option<ReadyConversation>), RuntimeRecoveryError> {
    let planned_started = plan.started.as_ref().map(PlannedInterruption::command_id);
    let durable_accepted_command_ids = recovery
        .accepted
        .iter()
        .map(|command| command.command_id)
        .collect::<Vec<_>>();
    let contains_remote_accepted = recovery
        .accepted
        .iter()
        .any(|command| matches!(command.owner, IdempotencyOwner::Remote { .. }));
    if durable_accepted_command_ids != plan.durable_accepted_command_ids
        || contains_remote_accepted != plan.contains_remote_accepted
    {
        return Err(RuntimeRecoveryError::ReconciliationInvariant);
    }
    if plan.blocked {
        if recovery.conversation.lifecycle != ConversationLifecycle::RecoveryBlocked
            || recovery
                .started
                .as_ref()
                .map(PlannedInterruption::from_started)
                != plan.started
        {
            return Err(RuntimeRecoveryError::ReconciliationInvariant);
        }
        return Ok((
            ConversationRecoveryOutcome {
                state: ConversationRecoveryState::Blocked,
                durable_accepted_command_ids,
                interrupted_command_id: None,
                expected_started_command_id: planned_started,
                expected_lifecycle: recovery.conversation.lifecycle,
            },
            None,
        ));
    }
    if recovery.conversation.lifecycle == ConversationLifecycle::RecoveryBlocked {
        return Err(RuntimeRecoveryError::ReconciliationInvariant);
    }
    if recovery.started.is_some() {
        return Err(RuntimeRecoveryError::ReconciliationInvariant);
    }
    let conversation = recovery.conversation;
    let accepted = recovery.accepted;
    Ok((
        ConversationRecoveryOutcome {
            state: ConversationRecoveryState::Ready,
            durable_accepted_command_ids,
            interrupted_command_id: planned_started,
            expected_started_command_id: None,
            expected_lifecycle: conversation.lifecycle,
        },
        Some((conversation, accepted)),
    ))
}

async fn retry_mark_recovery_blocked(
    store: &RuntimeStoreHandle,
    input: MarkConversationRecoveryBlocked,
) -> Result<(), RuntimeStoreError> {
    match store
        .mark_conversation_recovery_blocked(input.clone())
        .await
    {
        Ok(_) => Ok(()),
        Err(RuntimeStoreError::CommitOutcomeUnknown {
            operation: super::store::RuntimeCommitOperation::MarkConversationRecoveryBlocked,
        }) => store
            .mark_conversation_recovery_blocked(input)
            .await
            .map(|_| ()),
        Err(error) => Err(error),
    }
}

async fn retry_recover_interrupted(
    store: &RuntimeStoreHandle,
    input: RecoverStartedCommand,
) -> Result<(), RuntimeStoreError> {
    match store
        .recover_started_command_with_event(input.clone())
        .await
    {
        Ok(_) => Ok(()),
        Err(RuntimeStoreError::CommitOutcomeUnknown {
            operation: super::store::RuntimeCommitOperation::CompleteCommand,
        }) => store
            .recover_started_command_with_event(input)
            .await
            .map(|_| ()),
        Err(error) => Err(error),
    }
}

async fn retry_terminate_before_release(
    store: &RuntimeStoreHandle,
    input: TerminateStartedBeforeRelease,
) -> Result<(), RuntimeStoreError> {
    match store.terminate_started_before_release(input.clone()).await {
        Ok(_) => Ok(()),
        Err(RuntimeStoreError::CommitOutcomeUnknown { .. }) => store
            .terminate_started_before_release(input)
            .await
            .map(|_| ()),
        Err(error) => Err(error),
    }
}

#[cfg(test)]
mod tests {
    use std::collections::VecDeque;
    use std::fs;
    use std::path::PathBuf;
    use std::sync::atomic::{AtomicU64, AtomicUsize, Ordering};
    use std::sync::{Arc, Mutex};

    use agentdeck_protocol::runtime::{
        CodexConversationConfiguration, ConversationConfiguration, VendorConfigurationSnapshot,
    };
    use agentdeck_protocol::{
        AgentKind, CodexApprovalPolicy, CodexReasoningEffort, CodexSandboxMode,
    };
    use async_trait::async_trait;

    use super::*;
    use crate::runtime::model::{
        AcceptCommand, AcceptOutcome, AuthorizeExecutionRelease, CommandReceiptSelector,
        CommandState, ConversationDescriptor, ExecutionFence, NewConversation, QueryCommandReceipt,
        StartCommand, StartOutcome,
    };
    use crate::runtime::store::{
        ConfigurationRecord, ConfigureConversation, ConfigureConversationOutcome, RuntimeIdKind,
        RuntimeStoreConfig,
    };
    use crate::security::{MemoryKeyStore, load_or_create_storage_kek};

    static NEXT_TEMP_ID: AtomicU64 = AtomicU64::new(1);

    struct TestRoot {
        path: PathBuf,
        keys: MemoryKeyStore,
    }

    impl TestRoot {
        fn new() -> Self {
            let sequence = NEXT_TEMP_ID.fetch_add(1, Ordering::Relaxed);
            let path = std::env::temp_dir().join(format!(
                "agentdeckd-recovery-mixed-remote-{}-{sequence}",
                std::process::id()
            ));
            let _ = fs::remove_dir_all(&path);
            fs::create_dir(&path).expect("create mixed recovery root");
            #[cfg(unix)]
            {
                use std::os::unix::fs::PermissionsExt;
                fs::set_permissions(&path, fs::Permissions::from_mode(0o700))
                    .expect("secure mixed recovery root");
            }
            Self {
                path,
                keys: MemoryKeyStore::new(),
            }
        }

        async fn store(&self) -> RuntimeStoreHandle {
            let storage_kek =
                load_or_create_storage_kek(&self.keys, &self.path.join("key-state.db"))
                    .expect("load mixed recovery StorageKEK");
            RuntimeStoreHandle::open(
                RuntimeStoreConfig::new(self.path.join("runtime.db")),
                storage_kek,
            )
            .await
            .expect("open mixed recovery store")
        }
    }

    impl Drop for TestRoot {
        fn drop(&mut self) {
            let _ = fs::remove_dir_all(&self.path);
        }
    }

    #[derive(Clone)]
    struct ScriptedProbe {
        observations: Arc<Mutex<VecDeque<ProcessObservation>>>,
        calls: Arc<AtomicUsize>,
    }

    impl ScriptedProbe {
        fn new(observations: impl IntoIterator<Item = ProcessObservation>) -> Self {
            Self {
                observations: Arc::new(Mutex::new(observations.into_iter().collect())),
                calls: Arc::new(AtomicUsize::new(0)),
            }
        }

        fn call_count(&self) -> usize {
            self.calls.load(Ordering::SeqCst)
        }
    }

    #[async_trait]
    impl ProcessGroupController for ScriptedProbe {
        async fn probe(
            &self,
            _identity: ProcessIdentity,
        ) -> Result<ProcessObservation, super::super::process_identity::ProcessControlError>
        {
            self.calls.fetch_add(1, Ordering::SeqCst);
            Ok(self
                .observations
                .lock()
                .expect("mixed recovery observations lock")
                .pop_front()
                .expect("unexpected mixed recovery process probe"))
        }

        async fn signal(
            &self,
            _identity: ProcessIdentity,
            _signal: ProcessSignal,
        ) -> Result<(), super::super::process_identity::ProcessControlError> {
            panic!("identity mismatch must not signal")
        }

        async fn wait_for_exit(
            &self,
            _identity: ProcessIdentity,
            _timeout: Duration,
        ) -> Result<ProcessObservation, super::super::process_identity::ProcessControlError>
        {
            panic!("identity mismatch must not wait")
        }
    }

    fn runtime_id(kind: RuntimeIdKind, seed: u8) -> RuntimeId {
        RuntimeId::from_bytes(kind, [seed; 16]).expect("non-zero mixed recovery id")
    }

    fn descriptor(root: &TestRoot, title: &str) -> ConversationDescriptor {
        ConversationDescriptor {
            agent_kind: AgentKind::Codex,
            title: Some(title.to_owned()),
            cwd: root.path.clone(),
        }
    }

    fn local_owner(seed: u8) -> IdempotencyOwner {
        IdempotencyOwner::Local {
            machine_trust_domain: [seed; 32],
            uid: 501,
            client_installation_id: [seed.wrapping_add(1); 16],
        }
    }

    fn remote_owner(seed: u8) -> IdempotencyOwner {
        IdempotencyOwner::Remote {
            machine_trust_domain: [seed; 32],
            device_route: [seed.wrapping_add(1); 16],
            device_sign_fingerprint: [seed.wrapping_add(2); 32],
        }
    }

    async fn configure(
        store: &RuntimeStoreHandle,
        conversation_id: RuntimeId,
        owner: IdempotencyOwner,
        key: &str,
    ) {
        assert!(matches!(
            store
                .configure_conversation(ConfigureConversation {
                    conversation_id,
                    owner,
                    idempotency_key: key.to_owned(),
                    expected_configuration_revision: 0,
                    configuration: ConversationConfiguration::new(
                        VendorConfigurationSnapshot::Codex(CodexConversationConfiguration::new(
                            CodexApprovalPolicy::OnRequest,
                            CodexSandboxMode::WorkspaceWrite,
                            CodexReasoningEffort::Medium,
                        ),),
                    ),
                })
                .await
                .expect("configure mixed recovery conversation"),
            ConfigureConversationOutcome::Applied {
                configuration: ConfigurationRecord {
                    configuration_revision: 1,
                    event_seq: 0,
                    ..
                }
            }
        ));
    }

    async fn accept(
        store: &RuntimeStoreHandle,
        conversation_id: RuntimeId,
        owner: IdempotencyOwner,
        key: &str,
    ) -> CommandRecord {
        match store
            .accept_command(AcceptCommand {
                conversation_id,
                owner,
                idempotency_key: key.to_owned(),
                expected_configuration_revision: 1,
                payload: format!("mixed recovery prompt {key}").into_bytes(),
            })
            .await
            .expect("accept mixed recovery command")
        {
            AcceptOutcome::Accepted { command, .. } => command,
            AcceptOutcome::Replayed { .. } => panic!("fresh mixed recovery command replayed"),
        }
    }

    async fn command_state(
        store: &RuntimeStoreHandle,
        expected_owner: IdempotencyOwner,
        conversation_id: RuntimeId,
        command_id: RuntimeId,
    ) -> CommandState {
        store
            .query_command_receipt(QueryCommandReceipt {
                expected_owner,
                selector: CommandReceiptSelector::Command {
                    conversation_id,
                    command_id,
                },
            })
            .await
            .expect("query mixed recovery command")
            .state
    }

    #[tokio::test]
    async fn remote_accepted_rejection_persists_other_sticky_block_before_reopen() {
        // 威胁场景：同一第一遍 snapshot 同时含尚不支持恢复的 remote Accepted 与
        // IdentityMismatch Started。若先返回 remote 错误，blocked binding 未落库；未来
        // P4 移除 early reject 且旧进程已消失时，successor 会被误判可安全启动。
        let root = TestRoot::new();
        let store = root.store().await;

        let remote_conversation_id = runtime_id(RuntimeIdKind::Conversation, 0x11);
        let remote_owner = remote_owner(0x12);
        store
            .create_conversation(NewConversation {
                conversation_id: remote_conversation_id,
                adapter_state_key: runtime_id(RuntimeIdKind::AdapterState, 0x13),
                descriptor: descriptor(&root, "remote accepted"),
            })
            .await
            .expect("create remote accepted conversation");
        configure(
            &store,
            remote_conversation_id,
            remote_owner.clone(),
            "remote-accepted-configuration",
        )
        .await;
        let remote_command = accept(
            &store,
            remote_conversation_id,
            remote_owner.clone(),
            "remote-accepted",
        )
        .await;

        let blocked_conversation_id = runtime_id(RuntimeIdKind::Conversation, 0x21);
        let blocked_owner = local_owner(0x22);
        store
            .create_conversation(NewConversation {
                conversation_id: blocked_conversation_id,
                adapter_state_key: runtime_id(RuntimeIdKind::AdapterState, 0x23),
                descriptor: descriptor(&root, "identity mismatch"),
            })
            .await
            .expect("create blocked conversation");
        configure(
            &store,
            blocked_conversation_id,
            blocked_owner.clone(),
            "identity-mismatch-configuration",
        )
        .await;
        let started = accept(
            &store,
            blocked_conversation_id,
            blocked_owner.clone(),
            "started",
        )
        .await;
        let daemon_boot_id = runtime_id(RuntimeIdKind::DaemonBoot, 0x24);
        let execution_nonce = b"mixed-recovery-nonce".to_vec();
        assert!(matches!(
            store
                .mark_started_with_event(StartCommand {
                    conversation_id: blocked_conversation_id,
                    command_id: started.command_id,
                    daemon_boot_id,
                    execution_nonce: execution_nonce.clone(),
                })
                .await
                .expect("start blocked mixed recovery command"),
            StartOutcome::Started { .. }
        ));
        let successor = accept(
            &store,
            blocked_conversation_id,
            blocked_owner.clone(),
            "successor",
        )
        .await;
        let process = ProcessIdentity::new(8_001, 8_001, 8_002)
            .expect("valid mixed recovery process identity");
        store
            .persist_execution_fence(ExecutionFence {
                command_id: started.command_id,
                daemon_boot_id,
                execution_nonce: execution_nonce.clone(),
                process_group_id: process.process_group_id(),
                leader_pid: process.leader_pid(),
                leader_start_time: process.leader_start_time(),
                payload: b"mixed recovery fence commitment".to_vec(),
            })
            .await
            .expect("persist mixed recovery fence");
        store
            .authorize_execution_release(AuthorizeExecutionRelease {
                command_id: started.command_id,
                daemon_boot_id,
                execution_nonce,
            })
            .await
            .expect("authorize mixed recovery release");

        let first_processes = ScriptedProbe::new([ProcessObservation::IdentityMismatch]);
        let installed = Arc::new(AtomicUsize::new(0));
        let installed_for_closure = installed.clone();
        let recovery = RuntimeRecoveryCoordinator::new(
            store.clone(),
            Arc::new(first_processes.clone()),
            RecoveryOptions {
                term_grace: Duration::from_millis(10),
                kill_grace: Duration::from_millis(10),
            },
        );
        let error = recovery
            .reconcile_and_install(move |_conversation, _accepted| {
                let installed = installed_for_closure.clone();
                async move {
                    installed.fetch_add(1, Ordering::SeqCst);
                    Ok::<(), ()>(())
                }
            })
            .await
            .expect_err("remote Accepted remains unsupported before P4 auth-ledger rebind");
        assert!(matches!(
            error,
            RuntimeRecoveryInstallError::Recovery(RuntimeRecoveryError::ReconciliationInvariant)
        ));
        assert_eq!(installed.load(Ordering::SeqCst), 0);
        assert_eq!(first_processes.call_count(), 1);
        assert_eq!(
            command_state(
                &store,
                remote_owner.clone(),
                remote_conversation_id,
                remote_command.command_id,
            )
            .await,
            CommandState::Accepted
        );
        store.shutdown().await.expect("shutdown first mixed store");

        let reopened = root.store().await;
        let second_processes = ScriptedProbe::new([]);
        let second_recovery = RuntimeRecoveryCoordinator::new(
            reopened.clone(),
            Arc::new(second_processes.clone()),
            RecoveryOptions {
                term_grace: Duration::from_millis(10),
                kill_grace: Duration::from_millis(10),
            },
        );
        let report = second_recovery
            .reconcile()
            .await
            .expect("read back mixed recovery state");
        let blocked = report
            .conversation(blocked_conversation_id)
            .expect("blocked conversation after reopen");
        assert_eq!(blocked.state(), ConversationRecoveryState::Blocked);
        assert_eq!(
            blocked.expected_started_command_id,
            Some(started.command_id)
        );
        assert_eq!(second_processes.call_count(), 0);
        let remote = report
            .conversation(remote_conversation_id)
            .expect("remote Accepted after reopen");
        assert_eq!(remote.state(), ConversationRecoveryState::Ready);
        assert_eq!(remote.accepted_command_ids(), &[remote_command.command_id]);
        assert_eq!(
            command_state(
                &reopened,
                remote_owner,
                remote_conversation_id,
                remote_command.command_id,
            )
            .await,
            CommandState::Accepted
        );
        assert_eq!(
            command_state(
                &reopened,
                blocked_owner.clone(),
                blocked_conversation_id,
                started.command_id,
            )
            .await,
            CommandState::Started
        );
        assert_eq!(
            command_state(
                &reopened,
                blocked_owner,
                blocked_conversation_id,
                successor.command_id,
            )
            .await,
            CommandState::Accepted
        );
        reopened
            .shutdown()
            .await
            .expect("shutdown reopened mixed store");
    }
}
