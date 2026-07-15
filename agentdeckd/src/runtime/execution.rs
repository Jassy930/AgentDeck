//! P3.4 RuntimeCore 与副作用执行边界之间的 capability contract。
//!
//! RuntimeCore 先提交 `Started + ExecutionIntent`，再调用 `prepare`。返回的
//! completion future 在 RuntimeCore 完成 Fence + release authorization COMMIT 前
//! 不会被 poll。P3.4 production coordinator 固定 fail-closed；测试用无副作用
//! fake。P3.7 才提供真实 `agentdeckd --exec-gate` 实现。

use std::future::Future;
use std::pin::Pin;
use std::sync::Arc;

use agentdeck_protocol::ActionRequest;
use tokio::sync::mpsc;

use crate::runtime::approval::SharedApprovalDelivery;
use crate::runtime::store::{
    AuthorizeExecutionRelease, CommandRecord, CommandTerminal, ConversationRecord,
    ExecutionFenceRecord, RuntimeId,
};

#[allow(dead_code)] // P3.5 conversation ApprovalSupervisor 接线后成为 production path。
pub(crate) const RUNTIME_EXECUTION_EVENT_CAPACITY: usize = 64;

#[allow(dead_code)] // P3.5 conversation ApprovalSupervisor 接线后成为 production path。
pub(crate) enum RuntimeExecutionEvent {
    ActionRequest {
        request: ActionRequest,
        delivery: SharedApprovalDelivery,
    },
}

#[allow(dead_code)] // P3.5 conversation ApprovalSupervisor 接线后成为 production path。
pub(crate) struct RuntimeExecutionEventReceiver {
    receiver: mpsc::Receiver<RuntimeExecutionEvent>,
}

#[allow(dead_code)] // P3.5 conversation ApprovalSupervisor 接线后成为 production path。
impl RuntimeExecutionEventReceiver {
    pub(crate) async fn recv(&mut self) -> Option<RuntimeExecutionEvent> {
        self.receiver.recv().await
    }
}

#[allow(dead_code)] // P3.7 exec-gate coordinator mints the production sender。
pub(crate) fn runtime_execution_event_channel() -> (
    mpsc::Sender<RuntimeExecutionEvent>,
    RuntimeExecutionEventReceiver,
) {
    let (sender, receiver) = mpsc::channel(RUNTIME_EXECUTION_EVENT_CAPACITY);
    (sender, RuntimeExecutionEventReceiver { receiver })
}

#[allow(dead_code)] // side-effect-free coordinators use a closed stream。
pub(crate) fn closed_execution_events() -> RuntimeExecutionEventReceiver {
    let (sender, receiver) = runtime_execution_event_channel();
    drop(sender);
    receiver
}

#[allow(dead_code)] // 字段由 P3.7 production exec-gate coordinator 读取。
#[derive(Clone, Debug)]
pub(crate) struct RuntimeExecutionContext {
    pub(crate) conversation: ConversationRecord,
    pub(crate) command: CommandRecord,
    pub(crate) turn_id: RuntimeId,
    pub(crate) daemon_boot_id: RuntimeId,
    pub(crate) execution_nonce: Vec<u8>,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub(crate) struct RuntimeProcessIdentity {
    pub(crate) process_group_id: i64,
    pub(crate) leader_pid: i64,
    pub(crate) leader_start_time: u64,
    pub(crate) fence_payload: Vec<u8>,
}

#[derive(Clone, Debug)]
pub(crate) struct RuntimeExecutionCompletion {
    pub(crate) terminal: CommandTerminal,
}

#[async_trait::async_trait]
pub(crate) trait RuntimeExecutionControl: Send + Sync + 'static {
    /// 请求终止并等待整个 execution process group 已不可再产生副作用。
    ///
    /// `Ok(())` 是 durable terminal transition 的 safety 前提；实现必须幂等，
    /// 不得只表示“已发送 cancel”。
    async fn cancel_and_wait_fenced(&self) -> Result<(), RuntimeExecutionError>;
}

/// `Ok(RuntimeExecutionCompletion)` 是一个 safety capability：它必须表示本次
/// execution 的精确 process group 已被 reap，或已被同等强度的 OS fence 证明不再
/// 能产生副作用。仅收到 vendor terminal event、child exit notification，或发送了
/// cancel 都不满足该契约；无法证明时必须返回 `Err`，由 actor 进入 RecoveryBlocked。
pub(crate) type RuntimeCompletionFuture = Pin<
    Box<
        dyn Future<Output = Result<RuntimeExecutionCompletion, RuntimeExecutionError>>
            + Send
            + 'static,
    >,
>;

/// 只有 durable `authorize_execution_release` 返回后才能构造的 release capability。
/// coordinator 的 `prepare` 只返回 blocked gate；真正 release 必须消费本类型。
pub(crate) struct ExecutionReleasePermit {
    command_id: RuntimeId,
    daemon_boot_id: RuntimeId,
    execution_nonce: Vec<u8>,
    release_authorized_at_ms: u64,
}

#[allow(dead_code)] // accessors 由 P3.7 release token implementation 读取。
impl ExecutionReleasePermit {
    pub(super) fn from_committed_store(
        request: &AuthorizeExecutionRelease,
        record: &ExecutionFenceRecord,
    ) -> Result<Self, RuntimeExecutionError> {
        let release_authorized_at_ms = record
            .release_authorized_at_ms
            .ok_or(RuntimeExecutionError::ReleaseAuthorizationInvalid)?;
        if record.command_id != request.command_id
            || record.daemon_boot_id != request.daemon_boot_id
            || record.execution_nonce != request.execution_nonce
            || request.execution_nonce.is_empty()
        {
            return Err(RuntimeExecutionError::ReleaseAuthorizationInvalid);
        }
        Ok(Self {
            command_id: request.command_id,
            daemon_boot_id: request.daemon_boot_id,
            execution_nonce: record.execution_nonce.clone(),
            release_authorized_at_ms,
        })
    }

    pub(crate) fn command_id(&self) -> RuntimeId {
        self.command_id
    }

    pub(crate) fn daemon_boot_id(&self) -> RuntimeId {
        self.daemon_boot_id
    }

    pub(crate) fn execution_nonce(&self) -> &[u8] {
        &self.execution_nonce
    }

    pub(crate) fn release_authorized_at_ms(&self) -> u64 {
        self.release_authorized_at_ms
    }
}

impl std::fmt::Debug for ExecutionReleasePermit {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("ExecutionReleasePermit")
            .field("command_id", &self.command_id)
            .field("daemon_boot_id", &self.daemon_boot_id)
            .field("execution_nonce", &"[REDACTED]")
            .field("release_authorized_at_ms", &self.release_authorized_at_ms)
            .finish()
    }
}

#[async_trait::async_trait]
pub(crate) trait RuntimeExecutionRelease: Send + 'static {
    /// 消费 committed permit 后才允许 gate release，并且只在 release 成功后返回
    /// completion future。实现不得在本调用前越过 vendor/tool 副作用边界。
    async fn release(
        self: Box<Self>,
        permit: ExecutionReleasePermit,
    ) -> Result<RuntimeCompletionFuture, RuntimeExecutionError>;
}

pub(crate) struct PreparedRuntimeExecution {
    pub(crate) process: RuntimeProcessIdentity,
    pub(crate) control: Arc<dyn RuntimeExecutionControl>,
    pub(crate) release: Box<dyn RuntimeExecutionRelease>,
    #[allow(dead_code)] // P3.5 conversation ApprovalSupervisor consumes this stream。
    pub(crate) events: RuntimeExecutionEventReceiver,
}

#[async_trait::async_trait]
pub(crate) trait RuntimeExecutionCoordinator: Send + Sync + 'static {
    /// P3.7 两阶段 gate 尚未安装时必须返回 false。RuntimeCore 据此让已经
    /// Accepted 的命令留在 durable queue，禁止为了得到测试绿灯而写入 Started
    /// 或伪造 process fence。
    fn is_ready(&self) -> bool;

    /// 必须只准备 blocked child / side-effect-free fake；在 completion future 被
    /// poll 前不得越过 vendor/tool 副作用边界。
    async fn prepare(
        &self,
        context: RuntimeExecutionContext,
    ) -> Result<PreparedRuntimeExecution, RuntimeExecutionError>;
}

#[derive(Clone, Copy, Debug, Default)]
pub(crate) struct DisabledExecutionCoordinator;

#[async_trait::async_trait]
impl RuntimeExecutionCoordinator for DisabledExecutionCoordinator {
    fn is_ready(&self) -> bool {
        false
    }

    async fn prepare(
        &self,
        _context: RuntimeExecutionContext,
    ) -> Result<PreparedRuntimeExecution, RuntimeExecutionError> {
        Err(RuntimeExecutionError::GateUnavailable)
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq, thiserror::Error)]
pub(crate) enum RuntimeExecutionError {
    #[error("the two-phase execution gate is not installed")]
    GateUnavailable,
    #[error("execution preparation failed")]
    PrepareFailed,
    #[error("execution cancel failed")]
    CancelFailed,
    #[error("execution completion channel closed")]
    #[allow(dead_code)] // P3.7 gate IPC completion path。
    CompletionClosed,
    #[error("durable execution release authorization is invalid")]
    ReleaseAuthorizationInvalid,
    #[error("execution gate release failed")]
    #[allow(dead_code)] // P3.7 gate IPC release path。
    ReleaseFailed,
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::runtime::store::RuntimeIdKind;

    fn runtime_id(kind: RuntimeIdKind, seed: u8) -> RuntimeId {
        RuntimeId::from_bytes(kind, [seed; 16]).expect("non-zero runtime id")
    }

    #[test]
    fn release_permit_requires_the_exact_committed_execution_nonce() {
        let command_id = runtime_id(RuntimeIdKind::Command, 1);
        let daemon_boot_id = runtime_id(RuntimeIdKind::DaemonBoot, 2);
        let request = AuthorizeExecutionRelease {
            command_id,
            daemon_boot_id,
            execution_nonce: b"request-nonce".to_vec(),
        };
        let mismatched = ExecutionFenceRecord {
            command_id,
            daemon_boot_id,
            execution_nonce: b"other-nonce".to_vec(),
            process_group_id: 41,
            leader_pid: 42,
            leader_start_time: 43,
            release_authorized_at_ms: Some(44),
            payload: Vec::new(),
        };
        assert!(matches!(
            ExecutionReleasePermit::from_committed_store(&request, &mismatched),
            Err(RuntimeExecutionError::ReleaseAuthorizationInvalid)
        ));

        let committed = ExecutionFenceRecord {
            execution_nonce: request.execution_nonce.clone(),
            ..mismatched
        };
        let permit = ExecutionReleasePermit::from_committed_store(&request, &committed)
            .expect("exact committed nonce mints permit");
        assert_eq!(permit.command_id(), command_id);
        assert_eq!(permit.daemon_boot_id(), daemon_boot_id);
        assert_eq!(permit.execution_nonce(), request.execution_nonce);
        assert_eq!(permit.release_authorized_at_ms(), 44);
    }

    #[tokio::test]
    async fn execution_approval_event_channel_is_bounded_and_closed_stream_terminates() {
        assert_eq!(RUNTIME_EXECUTION_EVENT_CAPACITY, 64);
        let mut events = closed_execution_events();
        assert!(events.recv().await.is_none());
    }
}
