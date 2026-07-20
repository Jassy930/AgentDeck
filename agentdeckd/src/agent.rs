//! Agent trait — the contract every adapter (CodexAdapter, ClaudeCodeAdapter,
//! future community adapters) must implement.
//!
//! N3 守护：Adapter 实现彼此不可见。共享逻辑只能下沉到此 trait 的 default
//! 方法，或 daemon 层。

use agentdeck_protocol::runtime::{
    ConfigurationError, ConversationConfiguration, ConversationMetadataMutation, PromptPayload,
};
use agentdeck_protocol::{
    ActionDecision, ActionRequest, AgentItem, AgentKind, HistoryRequest, HistoryResponse,
    HistoryTurn, ProtocolError, ServerEvent, SessionCapabilities, SessionId, SessionStart,
    ThreadId, TurnSummary, VendorControlPayload, VendorPanelPayload,
};
use std::collections::HashSet;
use std::ffi::{OsStr, OsString};
use std::fmt;
use std::future::Future;
use std::path::{Path, PathBuf};
use std::pin::Pin;
use std::sync::Arc;
use std::time::Duration;
use tokio::sync::{mpsc, oneshot};

use crate::exec_gate::{GatedChild, GatedChildIo};
use crate::runtime::approval::SharedApprovalDelivery;
use crate::runtime::store::{ConversationDescriptor, RuntimeId, RuntimeIdKind};
use crate::security::SecretBytes;

/// exec-gate control frame 内的 program/cwd 单路径原始平台编码字节上界。
pub const MAX_EXEC_PATH_BYTES: usize = 16 * 1024;
/// exec-gate control frame 内的 argv 固定个数上界。
pub const MAX_EXEC_ARGUMENTS: usize = 256;
/// exec-gate control frame 内单个 argv 原始平台编码字节上界。
pub const MAX_EXEC_SINGLE_ARGUMENT_BYTES: usize = 16 * 1024;
/// exec-gate control frame 内全部 argv 原始平台编码的总字节上界。
pub const MAX_EXEC_ARGUMENT_BYTES: usize = 256 * 1024;
/// program、cwd、argv 内容与长度前缀合计的完整结构上界。
pub const MAX_EXEC_CONTROL_FRAME_BYTES: usize = 288 * 1024;
pub const MAX_ADAPTER_ITEM_KEY_BYTES: usize = 1024;
const ADAPTER_EVENT_CAPACITY: usize = 64;
const ADAPTER_APPROVAL_CAPACITY: usize = 64;
const EXEC_SPEC_LENGTH_PREFIX_BYTES: usize = std::mem::size_of::<u64>();

pub(crate) fn exec_spec_control_frame_bytes(
    program_bytes: usize,
    cwd_bytes: usize,
    argument_count: usize,
    argument_bytes: usize,
) -> Option<usize> {
    3_usize
        .checked_add(argument_count)
        .and_then(|field_count| EXEC_SPEC_LENGTH_PREFIX_BYTES.checked_mul(field_count))
        .and_then(|overhead| overhead.checked_add(program_bytes))
        .and_then(|total| total.checked_add(cwd_bytes))
        .and_then(|total| total.checked_add(argument_bytes))
}

#[derive(Debug, thiserror::Error, Eq, PartialEq)]
pub enum AgentTurnContractError {
    #[error("turn working directory must be absolute")]
    RelativeWorkingDirectory,
    #[error("execution handle requires command id, got {actual}")]
    InvalidExecutionKind { actual: RuntimeIdKind },
    #[error("exec program must be absolute")]
    RelativeProgram,
    #[error("exec working directory must be absolute")]
    RelativeExecWorkingDirectory,
    #[error("path or argument contains NUL")]
    ContainsNul,
    #[error("exec path bytes exceed {MAX_EXEC_PATH_BYTES}")]
    PathTooLarge,
    #[error("adapter state handle requires adapter-state id, got {actual}")]
    InvalidAdapterStateKind { actual: RuntimeIdKind },
    #[error("exec argument count exceeds {MAX_EXEC_ARGUMENTS}")]
    TooManyArguments,
    #[error("one exec argument exceeds {MAX_EXEC_SINGLE_ARGUMENT_BYTES} bytes")]
    ArgumentTooLarge,
    #[error("exec argument bytes exceed {MAX_EXEC_ARGUMENT_BYTES}")]
    ArgumentsTooLarge,
    #[error("exec control frame exceeds {MAX_EXEC_CONTROL_FRAME_BYTES} bytes")]
    ControlFrameTooLarge,
}

/// 一次 adapter execution 的 opaque 身份，精确包装 durable command id。
///
/// 它不能替代 conversation、turn、event 或 vendor session identity；这些身份必须
/// 继续由各自的 typed Runtime 类型表达，禁止仅凭相同字节跨 family 比较。
#[derive(Clone, Copy, Eq, Hash, PartialEq)]
pub struct ExecutionId(RuntimeId);

impl ExecutionId {
    #[allow(
        dead_code,
        reason = "P3.7 production coordinator constructs typed executions"
    )]
    pub(crate) fn from_command_id(command_id: RuntimeId) -> Result<Self, AgentTurnContractError> {
        if command_id.kind() != RuntimeIdKind::Command {
            return Err(AgentTurnContractError::InvalidExecutionKind {
                actual: command_id.kind(),
            });
        }
        Ok(Self(command_id))
    }

    #[must_use]
    #[allow(
        dead_code,
        reason = "P3.7 production coordinator binds the exact command"
    )]
    pub(crate) const fn command_id(self) -> RuntimeId {
        self.0
    }
}

impl fmt::Debug for ExecutionId {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("ExecutionId([REDACTED])")
    }
}

/// RuntimeCore 交给 adapter 的冷准备请求。只含 exact execution、绝对 cwd、
/// 已通过 Runtime v3 256 KiB gate 的 prompt，以及 Store 按 command pin 认证并
/// 冻结的 configuration revision/value；不携带 session/thread 或 vendor identity。
/// revision 0 只表达上层已实体化的 migration-era frozen defaults，adapter 不自行
/// 查询 current head，也不解释 missing configuration。
pub struct AgentTurnRequest {
    execution_id: ExecutionId,
    cwd: PathBuf,
    prompt: PromptPayload,
    configuration_revision: u64,
    execution_configuration: ConversationConfiguration,
}

impl AgentTurnRequest {
    #[allow(
        dead_code,
        reason = "P3.7 production coordinator constructs typed turn requests"
    )]
    pub(crate) fn new(
        execution_id: ExecutionId,
        cwd: impl Into<PathBuf>,
        prompt: PromptPayload,
        configuration_revision: u64,
        execution_configuration: ConversationConfiguration,
    ) -> Result<Self, AgentTurnContractError> {
        let cwd = cwd.into();
        if !cwd.is_absolute() {
            return Err(AgentTurnContractError::RelativeWorkingDirectory);
        }
        encoded_bytes(cwd.as_os_str())?;
        Ok(Self {
            execution_id,
            cwd,
            prompt,
            configuration_revision,
            execution_configuration,
        })
    }

    #[must_use]
    #[allow(
        dead_code,
        reason = "P3.7 adapter migration consumes the exact execution"
    )]
    pub(crate) const fn execution_id(&self) -> ExecutionId {
        self.execution_id
    }

    #[must_use]
    #[allow(dead_code, reason = "P3.7 adapter migration consumes the turn cwd")]
    pub(crate) fn cwd(&self) -> &Path {
        &self.cwd
    }

    #[must_use]
    #[allow(
        dead_code,
        reason = "P3.7 adapter migration consumes the prompt over private IO"
    )]
    pub(crate) fn prompt(&self) -> &str {
        self.prompt.as_str()
    }

    #[must_use]
    pub(crate) const fn configuration_revision(&self) -> u64 {
        self.configuration_revision
    }

    #[must_use]
    pub(crate) const fn execution_configuration(&self) -> &ConversationConfiguration {
        &self.execution_configuration
    }

    #[must_use]
    pub(crate) fn into_parts(
        self,
    ) -> (
        ExecutionId,
        PathBuf,
        PromptPayload,
        u64,
        ConversationConfiguration,
    ) {
        (
            self.execution_id,
            self.cwd,
            self.prompt,
            self.configuration_revision,
            self.execution_configuration,
        )
    }
}

impl fmt::Debug for AgentTurnRequest {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("AgentTurnRequest")
            .field("prompt_bytes", &self.prompt.as_str().len())
            .field("configuration_revision", &self.configuration_revision)
            .finish_non_exhaustive()
    }
}

/// 只允许 Runtime `AdapterState` kind 进入 adapter 私域。
#[derive(Clone, Copy, Eq, PartialEq)]
pub struct AdapterStateHandle {
    key: RuntimeId,
}

impl AdapterStateHandle {
    #[allow(
        dead_code,
        reason = "P3.7 production coordinator constructs typed adapter state"
    )]
    pub(crate) fn new(key: RuntimeId) -> Result<Self, AgentTurnContractError> {
        if key.kind() != RuntimeIdKind::AdapterState {
            return Err(AgentTurnContractError::InvalidAdapterStateKind { actual: key.kind() });
        }
        Ok(Self { key })
    }

    #[must_use]
    #[allow(
        dead_code,
        reason = "P3.7 adapter migration resolves private state by this key"
    )]
    pub(crate) const fn key(self) -> RuntimeId {
        self.key
    }
}

impl fmt::Debug for AdapterStateHandle {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("AdapterStateHandle([REDACTED])")
    }
}

/// adapter 冷准备得到的进程描述。
///
/// 威胁场景：adapter 若把 prompt、credential 或 release capability 放进 argv，
/// 同机进程可经进程表/诊断日志读到它们并泄漏用户内容或越过 release 边界。因此本
/// 类型只提供受审计的非敏感 argv，constructor/accessor 保持 crate-private；具体
/// adapter 迁移时还必须用 exact argv fixture 锁定 builder，字段名本身不构成证明。
///
/// 本类型故意没有环境变量字段，但这不会自动阻止子进程继承 daemon 环境。exec-gate
/// 切片必须 `env_clear` 后仅恢复固定的非秘密 allowlist；在该验收完成前不能宣称
/// K9 或 gate spawn 已闭环。
pub struct ExecSpec {
    execution_id: ExecutionId,
    adapter_state: AdapterStateHandle,
    program: PathBuf,
    non_sensitive_args: Vec<OsString>,
    cwd: PathBuf,
}

impl ExecSpec {
    #[allow(
        dead_code,
        reason = "P3.7 adapter-specific audited builders construct exec specs"
    )]
    pub(crate) fn new(
        request: &AgentTurnRequest,
        adapter_state: AdapterStateHandle,
        program: impl Into<PathBuf>,
        non_sensitive_args: impl IntoIterator<Item = impl Into<OsString>>,
        cwd: impl Into<PathBuf>,
    ) -> Result<Self, AgentTurnContractError> {
        let program = program.into();
        if !program.is_absolute() {
            return Err(AgentTurnContractError::RelativeProgram);
        }
        let cwd = cwd.into();
        if !cwd.is_absolute() {
            return Err(AgentTurnContractError::RelativeExecWorkingDirectory);
        }
        let program_bytes = encoded_bytes(program.as_os_str())?;
        let cwd_bytes = encoded_bytes(cwd.as_os_str())?;
        if program_bytes > MAX_EXEC_PATH_BYTES || cwd_bytes > MAX_EXEC_PATH_BYTES {
            return Err(AgentTurnContractError::PathTooLarge);
        }
        let non_sensitive_args = non_sensitive_args
            .into_iter()
            .map(Into::into)
            .collect::<Vec<_>>();
        if non_sensitive_args.len() > MAX_EXEC_ARGUMENTS {
            return Err(AgentTurnContractError::TooManyArguments);
        }
        let mut argument_bytes = 0_usize;
        for argument in &non_sensitive_args {
            let encoded = encoded_bytes(argument.as_os_str())?;
            if encoded > MAX_EXEC_SINGLE_ARGUMENT_BYTES {
                return Err(AgentTurnContractError::ArgumentTooLarge);
            }
            argument_bytes = argument_bytes
                .checked_add(encoded)
                .ok_or(AgentTurnContractError::ArgumentsTooLarge)?;
            if argument_bytes > MAX_EXEC_ARGUMENT_BYTES {
                return Err(AgentTurnContractError::ArgumentsTooLarge);
            }
        }
        let control_frame_bytes = exec_spec_control_frame_bytes(
            program_bytes,
            cwd_bytes,
            non_sensitive_args.len(),
            argument_bytes,
        )
        .ok_or(AgentTurnContractError::ControlFrameTooLarge)?;
        if control_frame_bytes > MAX_EXEC_CONTROL_FRAME_BYTES {
            return Err(AgentTurnContractError::ControlFrameTooLarge);
        }
        Ok(Self {
            execution_id: request.execution_id(),
            adapter_state,
            program,
            non_sensitive_args,
            cwd,
        })
    }

    #[must_use]
    #[allow(dead_code, reason = "P3.7 exec gate consumes the validated program")]
    pub(crate) fn program(&self) -> &Path {
        &self.program
    }

    #[must_use]
    #[allow(
        dead_code,
        reason = "P3.7 exec gate consumes audited non-sensitive argv"
    )]
    pub(crate) fn non_sensitive_args(&self) -> &[OsString] {
        &self.non_sensitive_args
    }

    #[must_use]
    #[allow(dead_code, reason = "P3.7 exec gate consumes the validated cwd")]
    pub(crate) fn cwd(&self) -> &Path {
        &self.cwd
    }

    fn is_bound_to(&self, execution_id: ExecutionId, adapter_state: AdapterStateHandle) -> bool {
        self.execution_id == execution_id && self.adapter_state == adapter_state
    }

    #[cfg(test)]
    pub(crate) fn checked_for_test(&self) -> CheckedExecSpec<'_> {
        CheckedExecSpec {
            execution_id: self.execution_id,
            program: &self.program,
            non_sensitive_args: &self.non_sensitive_args,
            cwd: &self.cwd,
        }
    }
}

impl fmt::Debug for ExecSpec {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("ExecSpec")
            .field("program", &"[REDACTED]")
            .field("cwd", &"[REDACTED]")
            .field("argument_count", &self.non_sensitive_args.len())
            .finish_non_exhaustive()
    }
}

fn encoded_bytes(value: &OsStr) -> Result<usize, AgentTurnContractError> {
    let bytes = value.as_encoded_bytes();
    if bytes.contains(&0) {
        return Err(AgentTurnContractError::ContainsNul);
    }
    Ok(bytes.len())
}

pub type AdapterCompletionFuture =
    Pin<Box<dyn Future<Output = Result<TurnSummary, ProtocolError>> + Send + 'static>>;

/// P3.7 cold prepare + blocked-gate attach capability。adapter 只能消费私有 stdio
/// 并向 daemon ACK sink 发送中立事件；release token 与 child owner 不跨越该边界。
pub trait PreparedAgentTurn: Send + 'static {
    fn exec_spec(&self) -> &ExecSpec;

    fn attach(
        self: Box<Self>,
        _child: GatedChildIo,
        _events: AdapterEventSink,
        _approvals: AdapterApprovalSink,
    ) -> Result<AdapterCompletionFuture, ProtocolError> {
        Err(ProtocolError {
            code: "adapter-attach-not-migrated".to_owned(),
            message: "adapter has not implemented the blocked exec-gate attach contract".to_owned(),
            diagnostic_ref: None,
        })
    }
}

/// daemon 调用 adapter cold-prepare hook 时借出的不可构造 capability。
///
/// 威胁场景：crate 外调用者若能通过 trait method 或 UFCS 直接调用 adapter hook，
/// 就能拿到尚未绑定 daemon-owned `ExecutionId` 的 prepared turn，并绕过 attach 前的
/// identity fence。字段与 constructor 因此保持 private，且 hook 只借用 capability；
/// adapter 可以实现 hook，但不能从 safe public API 构造或留存调用权限。
#[doc(hidden)]
pub struct PrepareAdapterTurnCapability {
    _private: (),
}

impl PrepareAdapterTurnCapability {
    const fn for_daemon() -> Self {
        Self { _private: () }
    }
}

/// daemon-owned cold prepare binding。adapter 只产出 opaque inner；exact execution
/// identity 在进入 adapter 前由 daemon 保存，并与 `ExecSpec` 内不可由 crate 外构造的
/// binding 逐项复核，禁止信任 adapter 回传或重建 identity。
///
/// attach 必须消费整个 handle，并核对 `GatedChild.execution_id` 与这里保存的 identity
/// 完全一致；exec spawn 只能借用下方 checked capability，不能拆出或 clone 原始 spec。
pub(crate) struct PreparedAgentTurnHandle {
    execution_id: ExecutionId,
    configuration_revision: u64,
    adapter_state: AdapterStateHandle,
    inner: Box<dyn PreparedAgentTurn>,
}

/// daemon-only、借用自完整 prepared handle 的二次校验后 exec capability。
///
/// 威胁场景：若 gate 分开接受 caller 提供的 `ExecutionId` 与任意 `ExecSpec`，一次普通
/// wiring 错误就能把 execution A 的 vendor argv 绑定到 execution B 的 durable journal。
/// capability 因此只能从 handle 的 consumption-time 虚 getter 复核后产生，并借用而不
/// 消费 handle；后续 attach 仍可消费原 handle，不能用本类型替代 adapter continuation。
pub(crate) struct CheckedExecSpec<'a> {
    execution_id: ExecutionId,
    program: &'a Path,
    non_sensitive_args: &'a [OsString],
    cwd: &'a Path,
}

impl<'a> CheckedExecSpec<'a> {
    pub(crate) const fn execution_id(&self) -> ExecutionId {
        self.execution_id
    }

    pub(crate) const fn program(&self) -> &'a Path {
        self.program
    }

    pub(crate) const fn non_sensitive_args(&self) -> &'a [OsString] {
        self.non_sensitive_args
    }

    pub(crate) const fn cwd(&self) -> &'a Path {
        self.cwd
    }
}

impl fmt::Debug for CheckedExecSpec<'_> {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("CheckedExecSpec")
            .field("execution_id", &"[REDACTED]")
            .field("program", &"[REDACTED]")
            .field("cwd", &"[REDACTED]")
            .field("argument_count", &self.non_sensitive_args.len())
            .finish_non_exhaustive()
    }
}

impl PreparedAgentTurnHandle {
    #[must_use]
    #[allow(
        dead_code,
        reason = "P3.7 production coordinator binds and verifies the exact execution"
    )]
    pub(crate) const fn execution_id(&self) -> ExecutionId {
        self.execution_id
    }

    #[allow(dead_code, reason = "P3.7 exec gate consumes the bound exec spec")]
    pub(crate) fn exec_spec(&self) -> Result<&ExecSpec, ProtocolError> {
        let spec = self.inner.exec_spec();
        if spec.is_bound_to(self.execution_id, self.adapter_state) {
            Ok(spec)
        } else {
            Err(adapter_prepare_binding_mismatch())
        }
    }

    pub(crate) fn attach(
        self,
        child: &mut GatedChild,
        events: AdapterEventSink,
        approvals: AdapterApprovalSink,
    ) -> Result<AdapterCompletionFuture, ProtocolError> {
        if child.execution_id() != self.execution_id
            || !self
                .inner
                .exec_spec()
                .is_bound_to(self.execution_id, self.adapter_state)
        {
            return Err(adapter_prepare_binding_mismatch());
        }
        let io = child.take_io().map_err(|_| ProtocolError {
            code: "adapter-gate-stdio-unavailable".to_owned(),
            message: "blocked exec gate did not expose the complete private stdio set".to_owned(),
            diagnostic_ref: None,
        })?;
        self.inner.attach(io, events, approvals)
    }

    /// 对 adapter 的虚 getter 做 consumption-time 二次校验，并借出唯一可交给 exec gate
    /// 的 capability。该调用不消费 handle，确保后续 `attach` 仍拥有完整 adapter 状态。
    pub(crate) fn checked_exec_spec(&self) -> Result<CheckedExecSpec<'_>, ProtocolError> {
        let spec = self.exec_spec()?;
        Ok(CheckedExecSpec {
            execution_id: self.execution_id,
            program: spec.program(),
            non_sensitive_args: spec.non_sensitive_args(),
            cwd: spec.cwd(),
        })
    }
}

impl fmt::Debug for PreparedAgentTurnHandle {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("PreparedAgentTurnHandle")
            .field("execution_id", &"[REDACTED]")
            .field("configuration_revision", &self.configuration_revision)
            .field("inner", &"[REDACTED]")
            .finish_non_exhaustive()
    }
}

/// Canonical daemon prepare 入口。production coordinator 只能调用本 helper，不能直接
/// 调用 adapter 的 unbound hook。
#[allow(
    dead_code,
    reason = "P3.7 production coordinator will install the typed adapter path"
)]
pub(crate) async fn prepare_turn(
    agent: &dyn Agent,
    request: AgentTurnRequest,
    state: AdapterStateHandle,
) -> Result<PreparedAgentTurnHandle, ProtocolError> {
    if request.execution_configuration().agent_kind() != agent.kind() {
        return Err(adapter_configuration_agent_mismatch());
    }
    let execution_id = request.execution_id();
    let configuration_revision = request.configuration_revision();
    let mut capability = PrepareAdapterTurnCapability::for_daemon();
    let inner = agent
        .prepare_adapter_turn(&mut capability, request, state)
        .await?;
    if !inner.exec_spec().is_bound_to(execution_id, state) {
        return Err(adapter_prepare_binding_mismatch());
    }
    Ok(PreparedAgentTurnHandle {
        execution_id,
        configuration_revision,
        adapter_state: state,
        inner,
    })
}

fn adapter_configuration_agent_mismatch() -> ProtocolError {
    ProtocolError {
        code: "adapter-configuration-agent-mismatch".to_owned(),
        message: "adapter route does not match the frozen execution configuration".to_owned(),
        diagnostic_ref: None,
    }
}

fn adapter_prepare_binding_mismatch() -> ProtocolError {
    ProtocolError {
        code: "adapter-prepare-binding-mismatch".to_owned(),
        message: "adapter prepared turn does not match the daemon execution binding".to_owned(),
        diagnostic_ref: None,
    }
}

/// 新 Runtime execution 的中立 adapter 输出。ActionRequest 不在此枚举中：canonical
/// approval 继续只走 P3.5 daemon-owned bound delivery，禁止退回 execution-id lookup。
/// `Error` 也只是一条 transient adapter 信号；Store 端必须先映射到固定 allowlist，
/// 禁止直接持久化 adapter message 或 diagnostic reference。
#[derive(Clone, Eq, Hash, PartialEq)]
pub struct AdapterItemKey(String);

impl AdapterItemKey {
    pub fn new(value: impl Into<String>) -> Result<Self, ProtocolError> {
        let value = value.into();
        if value.is_empty()
            || value.len() > MAX_ADAPTER_ITEM_KEY_BYTES
            || value.as_bytes().contains(&0)
        {
            return Err(ProtocolError {
                code: "adapter-item-key-invalid".to_owned(),
                message: "adapter item correlation key is empty or exceeds its fixed bound"
                    .to_owned(),
                diagnostic_ref: None,
            });
        }
        Ok(Self(value))
    }

    #[must_use]
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

impl fmt::Debug for AdapterItemKey {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("AdapterItemKey([REDACTED])")
    }
}

pub enum AdapterEvent {
    Item {
        key: AdapterItemKey,
        item: AgentItem,
    },
    TurnComplete(TurnSummary),
    Error(ProtocolError),
    VendorControl(VendorControlPayload),
    VendorPanelEvent(VendorPanelPayload),
}

impl fmt::Debug for AdapterEvent {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        let variant = match self {
            Self::Item { .. } => "Item",
            Self::TurnComplete(_) => "TurnComplete",
            Self::Error(_) => "Error",
            Self::VendorControl(_) => "VendorControl",
            Self::VendorPanelEvent(_) => "VendorPanelEvent",
        };
        formatter
            .debug_struct("AdapterEvent")
            .field("variant", &variant)
            .field("payload", &"[REDACTED]")
            .finish()
    }
}

pub struct AdapterEventSink {
    sender: mpsc::Sender<AdapterEventDelivery>,
}

impl Clone for AdapterEventSink {
    fn clone(&self) -> Self {
        Self {
            sender: self.sender.clone(),
        }
    }
}

impl AdapterEventSink {
    /// 只有 daemon 确认 exact Store COMMIT 后才返回；channel close 或 negative ACK
    /// 都会让 adapter completion fail-close，禁止 terminal 越过未落盘事件。
    pub async fn send(&self, event: AdapterEvent) -> Result<(), ProtocolError> {
        let (acknowledge, committed) = oneshot::channel();
        self.sender
            .send(AdapterEventDelivery { event, acknowledge })
            .await
            .map_err(|_| adapter_event_commit_failed())?;
        match committed.await {
            Ok(Ok(())) => Ok(()),
            Ok(Err(())) | Err(_) => Err(adapter_event_commit_failed()),
        }
    }
}

pub(crate) struct AdapterEventDelivery {
    pub(crate) event: AdapterEvent,
    acknowledge: oneshot::Sender<Result<(), ()>>,
}

impl AdapterEventDelivery {
    pub(crate) fn into_parts(self) -> (AdapterEvent, AdapterEventAcknowledgement) {
        (self.event, AdapterEventAcknowledgement(self.acknowledge))
    }
}

pub(crate) struct AdapterEventAcknowledgement(oneshot::Sender<Result<(), ()>>);

impl AdapterEventAcknowledgement {
    pub(crate) fn acknowledge(self, result: Result<(), ()>) {
        let _ = self.0.send(result);
    }
}

pub(crate) struct AdapterEventReceiver {
    receiver: mpsc::Receiver<AdapterEventDelivery>,
}

impl AdapterEventReceiver {
    pub(crate) async fn recv(&mut self) -> Option<AdapterEventDelivery> {
        self.receiver.recv().await
    }
}

pub(crate) fn adapter_event_channel() -> (AdapterEventSink, AdapterEventReceiver) {
    let (sender, receiver) = mpsc::channel(ADAPTER_EVENT_CAPACITY);
    (
        AdapterEventSink { sender },
        AdapterEventReceiver { receiver },
    )
}

fn adapter_event_commit_failed() -> ProtocolError {
    ProtocolError {
        code: "adapter-event-commit-failed".to_owned(),
        message: "daemon did not durably commit the adapter event".to_owned(),
        diagnostic_ref: None,
    }
}

/// approval 与普通 AdapterEvent 分离；只有 conversation actor 完成 exact durable
/// registration 后 `register` 才返回，terminal barrier 因而覆盖所有已接收 approval。
pub struct AdapterApprovalSink {
    sender: mpsc::Sender<AdapterApprovalDelivery>,
}

impl Clone for AdapterApprovalSink {
    fn clone(&self) -> Self {
        Self {
            sender: self.sender.clone(),
        }
    }
}

impl AdapterApprovalSink {
    pub(crate) async fn register(
        &self,
        request: ActionRequest,
        delivery: SharedApprovalDelivery,
    ) -> Result<(), ProtocolError> {
        let (acknowledge, registered) = oneshot::channel();
        self.sender
            .send(AdapterApprovalDelivery {
                request,
                delivery,
                acknowledge,
            })
            .await
            .map_err(|_| adapter_approval_registration_failed())?;
        match registered.await {
            Ok(Ok(())) => Ok(()),
            Ok(Err(())) | Err(_) => Err(adapter_approval_registration_failed()),
        }
    }
}

pub(crate) struct AdapterApprovalDelivery {
    request: ActionRequest,
    delivery: SharedApprovalDelivery,
    acknowledge: oneshot::Sender<Result<(), ()>>,
}

impl AdapterApprovalDelivery {
    pub(crate) fn into_parts(
        self,
    ) -> (
        ActionRequest,
        SharedApprovalDelivery,
        AdapterApprovalAcknowledgement,
    ) {
        (
            self.request,
            self.delivery,
            AdapterApprovalAcknowledgement(self.acknowledge),
        )
    }
}

pub(crate) struct AdapterApprovalAcknowledgement(oneshot::Sender<Result<(), ()>>);

impl AdapterApprovalAcknowledgement {
    pub(crate) fn acknowledge(self, result: Result<(), ()>) {
        let _ = self.0.send(result);
    }
}

pub(crate) struct AdapterApprovalReceiver {
    receiver: mpsc::Receiver<AdapterApprovalDelivery>,
}

impl AdapterApprovalReceiver {
    pub(crate) async fn recv(&mut self) -> Option<AdapterApprovalDelivery> {
        self.receiver.recv().await
    }
}

pub(crate) fn adapter_approval_channel() -> (AdapterApprovalSink, AdapterApprovalReceiver) {
    let (sender, receiver) = mpsc::channel(ADAPTER_APPROVAL_CAPACITY);
    (
        AdapterApprovalSink { sender },
        AdapterApprovalReceiver { receiver },
    )
}

fn adapter_approval_registration_failed() -> ProtocolError {
    ProtocolError {
        code: "adapter-approval-registration-failed".to_owned(),
        message: "daemon did not durably register the adapter approval".to_owned(),
        diagnostic_ref: None,
    }
}

pub type AgentEventSender = mpsc::Sender<ServerEvent>;

/// Canonical Runtime 从 adapter 接收的中立事件。旧 `ServerEvent` 强制携带
/// `ThreadId`，因此只能留在 stdio compatibility 路径；本类型在结构上没有 vendor
/// resume identity，也不允许透传未经建模的 raw vendor frame。
#[derive(Debug, Clone)]
pub enum CanonicalAgentEvent {
    Capabilities(SessionCapabilities),
    Item(AgentItem),
    ActionRequest(ActionRequest),
    TurnComplete(TurnSummary),
    Error(ProtocolError),
    VendorControl(VendorControlPayload),
    VendorPanelEvent(VendorPanelPayload),
}

pub type CanonicalAgentEventSender = mpsc::Sender<CanonicalAgentEvent>;

/// Canonical Runtime handle。只回传 daemon-owned transient session 与 neutral
/// `adapterStateKey`；vendor resume reference 永远留在 adapter 私域。
pub struct CanonicalAgentSessionHandle {
    pub session_id: SessionId,
    pub adapter_state_key: RuntimeId,
    pub agent_kind: AgentKind,
    pub abort_handle: tokio::task::AbortHandle,
}

/// Canonical history readback；不包含 stdio `HistoryReadResponse.thread_id`。
#[derive(Debug, Clone)]
pub struct CanonicalHistoryRead {
    pub agent_kind: AgentKind,
    pub turns: Vec<HistoryTurn>,
}

pub(crate) const MAX_CANONICAL_NATIVE_HISTORY_ITEMS: usize = 10_000;
pub(crate) const MAX_CANONICAL_NATIVE_HISTORY_BYTES: u64 = 64 * 1024 * 1024;
/// Native JSONL decode 与 canonical read document 共用的单次 retained-memory 上界。
/// Dynamic snapshot 虽持有同尺寸共享 permit，adapter 仍必须在分配 `Value` DOM 前
/// 内容感知地证明本次 read 不会越界；permit 本身只隔离并发，不是内存计量器。
pub(crate) const MAX_CANONICAL_NATIVE_HISTORY_RETAINED_BYTES: usize = 128 * 1024 * 1024;

/// Adapter 私域验证后交给 daemon Runtime 的中立原生 turn key。
///
/// 具体 vendor 的 UUID、path、session id 与 private reference 不跨越此边界；
/// Runtime 只能消费固定 32-byte stable key，并按 conversation 再做域分离派生。
#[derive(Clone, Copy, Eq, Hash, PartialEq)]
pub(crate) struct NativeTurnKey([u8; 32]);

impl NativeTurnKey {
    pub(crate) fn from_verified_bytes(bytes: [u8; 32]) -> Result<Self, ProtocolError> {
        if bytes == [0; 32] {
            return Err(invalid_native_history_key());
        }
        Ok(Self(bytes))
    }

    pub(crate) const fn derivation_material(&self) -> &[u8; 32] {
        &self.0
    }
}

impl fmt::Debug for NativeTurnKey {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("NativeTurnKey([REDACTED])")
    }
}

/// 与 `NativeTurnKey` 分型的单项 key；类型系统禁止在 identity 域之间误接线。
#[derive(Clone, Copy, Eq, Hash, PartialEq)]
pub(crate) struct NativeItemKey([u8; 32]);

impl NativeItemKey {
    pub(crate) fn from_verified_bytes(bytes: [u8; 32]) -> Result<Self, ProtocolError> {
        if bytes == [0; 32] {
            return Err(invalid_native_history_key());
        }
        Ok(Self(bytes))
    }

    pub(crate) const fn derivation_material(&self) -> &[u8; 32] {
        &self.0
    }
}

impl fmt::Debug for NativeItemKey {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("NativeItemKey([REDACTED])")
    }
}

fn invalid_native_history_key() -> ProtocolError {
    ProtocolError {
        code: "adapter-native-history-invalid".into(),
        message: "native history contains an invalid stable key".into(),
        diagnostic_ref: None,
    }
}

/// 已建模的单个原生历史 item；turn/item key 都是 daemon-private opaque key。
pub(crate) struct CanonicalNativeHistoryItem {
    turn_key: NativeTurnKey,
    item_key: NativeItemKey,
    item: AgentItem,
}

impl CanonicalNativeHistoryItem {
    pub(crate) fn new(
        turn_key: NativeTurnKey,
        item_key: NativeItemKey,
        item: AgentItem,
    ) -> Result<Self, ProtocolError> {
        if matches!(&item, AgentItem::Raw { .. }) {
            return Err(ProtocolError {
                code: "adapter-raw-history-blocked".into(),
                message: "native history contains an unmodeled vendor frame".into(),
                diagnostic_ref: None,
            });
        }
        Ok(Self {
            turn_key,
            item_key,
            item,
        })
    }

    #[cfg(test)]
    pub(crate) const fn turn_key(&self) -> NativeTurnKey {
        self.turn_key
    }

    #[cfg(test)]
    pub(crate) const fn item_key(&self) -> NativeItemKey {
        self.item_key
    }

    #[cfg(test)]
    pub(crate) const fn item(&self) -> &AgentItem {
        &self.item
    }

    pub(crate) fn into_parts(self) -> (NativeTurnKey, NativeItemKey, AgentItem) {
        (self.turn_key, self.item_key, self.item)
    }
}

impl fmt::Debug for CanonicalNativeHistoryItem {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("CanonicalNativeHistoryItem([REDACTED])")
    }
}

/// 一次重新验证并读取出的完整原生 transcript 投影。
///
/// 构造器是 adapter→Runtime 的 fail-close 门：只接受建模 item、全局唯一 item
/// key，并同时锁住 10,000 items 与 64 MiB source-read 上界。
pub(crate) struct CanonicalNativeHistoryRead {
    agent_kind: AgentKind,
    items: Vec<CanonicalNativeHistoryItem>,
    source_bytes: u64,
}

impl CanonicalNativeHistoryRead {
    pub(crate) fn new(
        agent_kind: AgentKind,
        items: Vec<CanonicalNativeHistoryItem>,
        source_bytes: u64,
    ) -> Result<Self, ProtocolError> {
        if items.len() > MAX_CANONICAL_NATIVE_HISTORY_ITEMS
            || source_bytes > MAX_CANONICAL_NATIVE_HISTORY_BYTES
        {
            return Err(ProtocolError {
                code: "adapter-native-history-too-large".into(),
                message: "native history exceeds the daemon projection bound".into(),
                diagnostic_ref: None,
            });
        }
        if items.is_empty() {
            return Err(ProtocolError {
                code: "adapter-native-history-invalid".into(),
                message: "native history contains no modeled items".into(),
                diagnostic_ref: None,
            });
        }
        let mut item_keys = HashSet::with_capacity(items.len());
        if items.iter().any(|item| !item_keys.insert(item.item_key)) {
            return Err(ProtocolError {
                code: "adapter-native-history-invalid".into(),
                message: "native history contains a duplicate item key".into(),
                diagnostic_ref: None,
            });
        }
        Ok(Self {
            agent_kind,
            items,
            source_bytes,
        })
    }

    pub(crate) const fn agent_kind(&self) -> AgentKind {
        self.agent_kind
    }

    #[cfg(test)]
    pub(crate) fn items(&self) -> &[CanonicalNativeHistoryItem] {
        &self.items
    }

    #[cfg(test)]
    pub(crate) const fn source_bytes(&self) -> u64 {
        self.source_bytes
    }

    pub(crate) fn into_parts(self) -> (AgentKind, Vec<CanonicalNativeHistoryItem>, u64) {
        (self.agent_kind, self.items, self.source_bytes)
    }
}

impl fmt::Debug for CanonicalNativeHistoryRead {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("CanonicalNativeHistoryRead")
            .field("agent_kind", &self.agent_kind)
            .field("item_count", &self.items.len())
            .field("source_bytes", &self.source_bytes)
            .finish()
    }
}

/// Adapter 私域错误在跨入 Runtime 前收敛到中立、无私有上下文的分类。
#[derive(Clone, Copy, Debug, Eq, PartialEq, thiserror::Error)]
pub(crate) enum NativeHistoryReadError {
    #[error("native history capability is unavailable")]
    Unavailable,
    #[error("native history exceeds the bounded snapshot limit")]
    PayloadTooLarge,
    #[error("native history source failed canonical validation")]
    InvalidSource,
    #[error("native history source could not be read")]
    ReadUnavailable,
}

/// Public `Agent` trait 之外的 daemon-private extension seam。只有真实原生
/// backend 才注册实现；缺失实现由 Router 明确映射为 typed unavailable。
#[async_trait::async_trait]
pub(crate) trait NativeHistoryReader: Send + Sync + 'static {
    async fn read_native_history(
        &self,
        adapter_state_key: RuntimeId,
    ) -> Result<CanonicalNativeHistoryRead, NativeHistoryReadError>;
}

pub(crate) type DynNativeHistoryReader = Arc<dyn NativeHistoryReader>;

/// 单轮 native projector 的硬上界。opaque continuation 只能跨轮保存在 daemon
/// 内存中；adapter 不接受调用方放宽这些 production 值。
pub(crate) const NATIVE_PROJECTION_ROUND_CANDIDATE_LIMIT: u32 = 2_000;
pub(crate) const NATIVE_PROJECTION_ROUND_IMPORT_LIMIT: u32 = 500;
pub(crate) const NATIVE_PROJECTION_ROUND_BYTE_LIMIT: u64 = 64 * 1024 * 1024;
pub(crate) const NATIVE_PROJECTION_ROUND_TIME_LIMIT: Duration = Duration::from_secs(2);
const MIN_NATIVE_PROJECTION_PRIVATE_REFERENCE_BYTES: usize = 20;
const MAX_NATIVE_PROJECTION_PRIVATE_REFERENCE_BYTES: usize = 523;

/// Adapter 私域 native source 在进入 Runtime 前收敛出的中立失败分类。
#[derive(Clone, Copy, Debug, Eq, PartialEq, thiserror::Error)]
pub(crate) enum NativeProjectionSourceError {
    #[error("native projection capability is unavailable")]
    Unavailable,
    #[error("native projection scan generation is invalid")]
    InvalidGeneration,
    #[error("native projection source failed canonical validation")]
    InvalidSource,
    #[error("native projection source exceeds a fixed resource bound")]
    PayloadTooLarge,
    #[error("native projection source could not be read")]
    ReadUnavailable,
    #[error("native projection candidate acknowledgement is invalid")]
    InvalidAcknowledgement,
    #[error("native projection scan is not ready for that transition")]
    InvalidState,
    #[error("native projection scan did not reach authenticated completion")]
    ScanIncomplete,
}

/// 单轮达到硬预算后的中立暂停原因。暂停本身绝不是 completed generation。
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum NativeProjectionYieldReason {
    CandidateLimit,
    ImportLimit,
    ByteLimit,
    Deadline,
}

/// 只有 source 当前 pending candidate 才能签发的 ACK capability。
///
/// 本类型不可 Clone/Serialize，Debug 也不显示 generation/token；Runtime 必须先把
/// candidate 交给 Store，再按值把 ACK 归还原 scanner，失败重试则不 ACK。
pub(crate) struct NativeProjectionAcknowledgement {
    generation: [u8; 16],
    issuer_token: [u8; 16],
    token: [u8; 16],
}

impl NativeProjectionAcknowledgement {
    fn new(
        generation: [u8; 16],
        issuer_token: [u8; 16],
        token: [u8; 16],
    ) -> Result<Self, NativeProjectionSourceError> {
        if generation == [0; 16] || issuer_token == [0; 16] || token == [0; 16] {
            return Err(NativeProjectionSourceError::InvalidAcknowledgement);
        }
        Ok(Self {
            generation,
            issuer_token,
            token,
        })
    }
}

impl fmt::Debug for NativeProjectionAcknowledgement {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("NativeProjectionAcknowledgement([REDACTED])")
    }
}

/// 真实 native JSONL 已经 no-follow、有界读取并完成 canonical metadata 校验后，
/// adapter 才能交给 Runtime 的中立 candidate。原始 project component、transcript
/// filename 与 session id 只存在于会清零且 Debug-redacted 的 private reference。
pub(crate) struct NativeProjectionCandidate {
    descriptor: ConversationDescriptor,
    default_configuration: ConversationConfiguration,
    private_reference: SecretBytes,
    acknowledgement: NativeProjectionAcknowledgement,
}

impl NativeProjectionCandidate {
    fn from_verified_source(
        descriptor: ConversationDescriptor,
        default_configuration: ConversationConfiguration,
        private_reference: SecretBytes,
        acknowledgement: NativeProjectionAcknowledgement,
    ) -> Result<Self, NativeProjectionSourceError> {
        let reference_bytes = private_reference.expose_secret().len();
        let descriptor_path_is_valid = encoded_bytes(descriptor.cwd.as_os_str())
            .is_ok_and(|bytes| bytes <= MAX_EXEC_PATH_BYTES);
        let descriptor_title_is_valid = descriptor
            .title
            .as_ref()
            .is_none_or(|title| ConversationMetadataMutation::rename(Some(title.clone())).is_ok());
        if descriptor.agent_kind != default_configuration.agent_kind()
            || !descriptor.cwd.is_absolute()
            || !descriptor_path_is_valid
            || !descriptor_title_is_valid
            || !(MIN_NATIVE_PROJECTION_PRIVATE_REFERENCE_BYTES
                ..=MAX_NATIVE_PROJECTION_PRIVATE_REFERENCE_BYTES)
                .contains(&reference_bytes)
        {
            return Err(NativeProjectionSourceError::InvalidSource);
        }
        Ok(Self {
            descriptor,
            default_configuration,
            private_reference,
            acknowledgement,
        })
    }

    pub(crate) fn into_parts(
        self,
    ) -> (
        ConversationDescriptor,
        ConversationConfiguration,
        SecretBytes,
        NativeProjectionAcknowledgement,
    ) {
        (
            self.descriptor,
            self.default_configuration,
            self.private_reference,
            self.acknowledgement,
        )
    }
}

impl fmt::Debug for NativeProjectionCandidate {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("NativeProjectionCandidate")
            .field("descriptor", &"[REDACTED]")
            .field("default_configuration", &"[REDACTED]")
            .field("private_reference", &"[REDACTED]")
            .field("acknowledgement", &"[REDACTED]")
            .finish()
    }
}

/// `Complete` 只表示 scanner 已观察到目录 EOF；删除型 reconciliation 还必须消费
/// `into_completed` 返回的 witness。yield/error/drop 路径拿不到该 witness。
pub(crate) enum NativeProjectionStep {
    Candidate(Box<NativeProjectionCandidate>),
    Yielded(NativeProjectionYieldReason),
    Complete,
}

impl fmt::Debug for NativeProjectionStep {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        let variant = match self {
            Self::Candidate(_) => "Candidate",
            Self::Yielded(_) => "Yielded",
            Self::Complete => "Complete",
        };
        formatter
            .debug_struct("NativeProjectionStep")
            .field("variant", &variant)
            .field("payload", &"[REDACTED]")
            .finish()
    }
}

/// 完整耗尽真实 source 且全部交付 candidate 已 ACK 后才能取得的中立 witness。
/// 字段私有、不可 Clone/Serialize；Core 后续只能按值把它交给固定 namespace Store。
pub(crate) struct CompletedNativeProjectionScan {
    generation: [u8; 16],
    inspected_candidates: u64,
    imported_candidates: u64,
}

impl CompletedNativeProjectionScan {
    pub(crate) const fn into_parts(self) -> ([u8; 16], u64, u64) {
        (
            self.generation,
            self.inspected_candidates,
            self.imported_candidates,
        )
    }
}

/// Router 经 daemon helper 为一次 scan 私下签发的 issuer。constructor 留在
/// `agent` 模块，Runtime/adapter 都不能自行创建；concrete scanner 必须一直按值
/// 持有它，只有真实 EOF + 全部 ACK 后才能消费为 completed witness。
pub(crate) struct NativeProjectionScanIssuer {
    generation: [u8; 16],
    issuer_token: [u8; 16],
}

impl NativeProjectionScanIssuer {
    fn new(generation: [u8; 16]) -> Result<Self, NativeProjectionSourceError> {
        if generation == [0; 16] {
            return Err(NativeProjectionSourceError::InvalidGeneration);
        }
        let mut issuer_token = *uuid::Uuid::new_v4().as_bytes();
        if issuer_token == [0; 16] {
            issuer_token[0] = 1;
        }
        Ok(Self {
            generation,
            issuer_token,
        })
    }

    pub(crate) const fn generation(&self) -> [u8; 16] {
        self.generation
    }

    pub(crate) fn issue_candidate(
        &self,
        descriptor: ConversationDescriptor,
        default_configuration: ConversationConfiguration,
        private_reference: SecretBytes,
        acknowledgement_token: [u8; 16],
    ) -> Result<NativeProjectionCandidate, NativeProjectionSourceError> {
        let acknowledgement = NativeProjectionAcknowledgement::new(
            self.generation,
            self.issuer_token,
            acknowledgement_token,
        )?;
        NativeProjectionCandidate::from_verified_source(
            descriptor,
            default_configuration,
            private_reference,
            acknowledgement,
        )
    }

    pub(crate) fn matches_acknowledgement(
        &self,
        acknowledgement: &NativeProjectionAcknowledgement,
        pending_token: &[u8; 16],
    ) -> bool {
        acknowledgement.generation == self.generation
            && acknowledgement.issuer_token == self.issuer_token
            && acknowledgement.token == *pending_token
    }

    pub(crate) fn complete(
        self,
        generation: [u8; 16],
        inspected_candidates: u64,
        imported_candidates: u64,
    ) -> Result<CompletedNativeProjectionScan, NativeProjectionSourceError> {
        if generation != self.generation || imported_candidates > inspected_candidates {
            return Err(NativeProjectionSourceError::ScanIncomplete);
        }
        Ok(CompletedNativeProjectionScan {
            generation,
            inspected_candidates,
            imported_candidates,
        })
    }
}

impl fmt::Debug for NativeProjectionScanIssuer {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("NativeProjectionScanIssuer([REDACTED])")
    }
}

impl fmt::Debug for CompletedNativeProjectionScan {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("CompletedNativeProjectionScan")
            .field("generation", &"[REDACTED]")
            .field("inspected_candidates", &self.inspected_candidates)
            .field("imported_candidates", &self.imported_candidates)
            .finish()
    }
}

/// 一次 scan 的 opaque continuation。方法是同步的，C-f Core 必须把它放在
/// daemon-owned blocking worker 上；不得在 conversation actor 内直接做文件 IO。
pub(crate) trait NativeProjectionScan: Send + 'static {
    fn next(&mut self) -> Result<NativeProjectionStep, NativeProjectionSourceError>;

    fn acknowledge(
        &mut self,
        acknowledgement: NativeProjectionAcknowledgement,
    ) -> Result<(), NativeProjectionSourceError>;

    fn resume_after_yield(&mut self) -> Result<(), NativeProjectionSourceError>;

    fn into_completed(
        self: Box<Self>,
    ) -> Result<CompletedNativeProjectionScan, NativeProjectionSourceError>;
}

pub(crate) type DynNativeProjectionScan = Box<dyn NativeProjectionScan>;

/// Public `Agent` trait 之外的 daemon-private projector source seam。
/// Codex/未注册 backend 不实现，Router 稳定返回 typed unavailable。
pub(crate) trait NativeProjectionSource: Send + Sync + 'static {
    fn agent_kind(&self) -> AgentKind;

    fn begin_native_projection_scan(
        &self,
        issuer: NativeProjectionScanIssuer,
    ) -> Result<DynNativeProjectionScan, NativeProjectionSourceError>;
}

pub(crate) type DynNativeProjectionSource = Arc<dyn NativeProjectionSource>;

/// 唯一 production issuer 入口：Router 只给出 non-zero generation 与已注册 source，
/// issuer 在本函数内创建后立即按值移交 concrete scanner，不向 Runtime 返回。
pub(crate) fn begin_native_projection_scan(
    source: &dyn NativeProjectionSource,
    generation: [u8; 16],
) -> Result<DynNativeProjectionScan, NativeProjectionSourceError> {
    source.begin_native_projection_scan(NativeProjectionScanIssuer::new(generation)?)
}

#[cfg(test)]
pub(crate) fn native_projection_scan_issuer_for_test(
    generation: [u8; 16],
) -> Result<NativeProjectionScanIssuer, NativeProjectionSourceError> {
    NativeProjectionScanIssuer::new(generation)
}

#[derive(Clone)]
pub(crate) struct NativeMetadataEffectRequest {
    adapter_state: AdapterStateHandle,
    mutation: ConversationMetadataMutation,
}

impl NativeMetadataEffectRequest {
    pub(crate) const fn new(
        adapter_state: AdapterStateHandle,
        mutation: ConversationMetadataMutation,
    ) -> Self {
        Self {
            adapter_state,
            mutation,
        }
    }

    pub(crate) const fn parts(&self) -> (AdapterStateHandle, &ConversationMetadataMutation) {
        (self.adapter_state, &self.mutation)
    }
}

impl fmt::Debug for NativeMetadataEffectRequest {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("NativeMetadataEffectRequest([REDACTED])")
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq, thiserror::Error)]
pub(crate) enum NativeMetadataEffectError {
    #[error("native metadata capability is unavailable")]
    Unavailable,
    #[error("native metadata mutation is unsupported")]
    Unsupported,
    #[error("native metadata source failed canonical validation")]
    InvalidSource,
    #[error("native metadata vendor program is unavailable")]
    ProgramUnavailable,
    #[error("native metadata effect spec is invalid")]
    InvalidSpec,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum NativeMetadataReadback {
    Applied,
    Unknown,
}

/// 只含 absolute program/cwd 与有界 argv；不含 env/spawn/release 能力。
pub(crate) struct NativeMetadataEffectSpec {
    program: PathBuf,
    args: Vec<OsString>,
    cwd: PathBuf,
}

impl NativeMetadataEffectSpec {
    pub(crate) fn new(
        program: impl Into<PathBuf>,
        args: impl IntoIterator<Item = impl Into<OsString>>,
        cwd: impl Into<PathBuf>,
    ) -> Result<Self, NativeMetadataEffectError> {
        let program = program.into();
        let cwd = cwd.into();
        if !program.is_absolute() || !cwd.is_absolute() {
            return Err(NativeMetadataEffectError::InvalidSpec);
        }
        let encoded = |value: &OsStr| {
            encoded_bytes(value).map_err(|_| NativeMetadataEffectError::InvalidSpec)
        };
        let program_bytes = encoded(program.as_os_str())?;
        let cwd_bytes = encoded(cwd.as_os_str())?;
        if program_bytes > MAX_EXEC_PATH_BYTES || cwd_bytes > MAX_EXEC_PATH_BYTES {
            return Err(NativeMetadataEffectError::InvalidSpec);
        }
        let args = args.into_iter().map(Into::into).collect::<Vec<_>>();
        if args.len() > MAX_EXEC_ARGUMENTS {
            return Err(NativeMetadataEffectError::InvalidSpec);
        }
        let argument_bytes = args.iter().try_fold(0_usize, |total, argument| {
            let bytes = encoded(argument.as_os_str())?;
            total
                .checked_add(bytes)
                .filter(|sum| {
                    bytes <= MAX_EXEC_SINGLE_ARGUMENT_BYTES && *sum <= MAX_EXEC_ARGUMENT_BYTES
                })
                .ok_or(NativeMetadataEffectError::InvalidSpec)
        })?;
        if exec_spec_control_frame_bytes(program_bytes, cwd_bytes, args.len(), argument_bytes)
            .is_none_or(|bytes| bytes > MAX_EXEC_CONTROL_FRAME_BYTES)
        {
            return Err(NativeMetadataEffectError::InvalidSpec);
        }
        Ok(Self { program, args, cwd })
    }

    pub(crate) fn parts(&self) -> (&Path, &[OsString], &Path) {
        (&self.program, &self.args, &self.cwd)
    }
}

impl fmt::Debug for NativeMetadataEffectSpec {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("NativeMetadataEffectSpec([REDACTED])")
    }
}

/// Adapter 只能冷准备 spec/readback；spawn、release、fence 归 Runtime。
#[async_trait::async_trait]
pub(crate) trait NativeMetadataEffectAdapter: Send + Sync + 'static {
    fn agent_kind(&self) -> AgentKind;

    async fn prepare_native_metadata_effect(
        &self,
        request: &NativeMetadataEffectRequest,
    ) -> Result<NativeMetadataEffectSpec, NativeMetadataEffectError>;

    async fn readback_native_metadata_effect(
        &self,
        request: &NativeMetadataEffectRequest,
    ) -> Result<NativeMetadataReadback, NativeMetadataEffectError>;
}

pub(crate) type DynNativeMetadataEffectAdapter = Arc<dyn NativeMetadataEffectAdapter>;

/// Handle returned when a session is started. The hub uses it to send
/// follow-up prompts / decisions / cancels to the same session.
pub struct AgentSessionHandle {
    pub session_id: SessionId,
    /// 仅供旧 IPC v2/stdin compatibility 回写；RuntimeCore 不得用它做主键或
    /// continue lookup。canonical 路径只携带 neutral adapterStateKey。
    pub thread_id: Option<ThreadId>,
    pub agent_kind: AgentKind,
    /// Used by RuntimeHub to drop the session and release the per-session lock.
    pub abort_handle: tokio::task::AbortHandle,
}

#[async_trait::async_trait]
pub trait Agent: Send + Sync + 'static {
    /// Static agent kind. Must match the discriminant used in protocol
    /// AgentKind for routing.
    fn kind(&self) -> AgentKind;

    /// Probe and return current capabilities. Called by daemon BEFORE
    /// emitting SessionCapabilities event. Implementation may invoke
    /// vendor CLI (e.g. `claude --version`, `claude auth status`) to
    /// determine accurate values; must complete within ~2s or return
    /// minimal capabilities + log a diagnostic.
    fn capabilities(&self) -> SessionCapabilities;

    /// 返回该 adapter 冻结的 Runtime v3 新会话默认配置。
    ///
    /// 威胁场景：若 daemon 在 adapter 缺失或构造错误时回退到共享默认值，会把
    /// 一个 vendor 的权限配置绑定给另一个 vendor。该方法因此是 required，且
    /// 保留受检构造错误给 Router fail-close，禁止 trait fallback。
    fn default_configuration(&self) -> Result<ConversationConfiguration, ConfigurationError>;

    /// Adapter-only cold prepare hook。默认 fail-closed；production coordinator
    /// 禁止直接调用，必须经 daemon-owned `prepare_turn` helper 绑定 ExecutionId。
    ///
    /// crate 外调用者即使通过 UFCS 指定 trait method，也无法从 safe API 构造调用
    /// 所需的 capability，因此拿不到 unbound prepared turn：
    ///
    /// ```compile_fail
    /// use agentdeckd::agent::{
    ///     AdapterStateHandle, Agent, AgentTurnRequest, PrepareAdapterTurnCapability,
    /// };
    ///
    /// fn bypass(
    ///     agent: &dyn Agent,
    ///     request: AgentTurnRequest,
    ///     state: AdapterStateHandle,
    /// ) {
    ///     let mut capability = PrepareAdapterTurnCapability { _private: () };
    ///     let _unbound = Agent::prepare_adapter_turn(
    ///         agent,
    ///         &mut capability,
    ///         request,
    ///         state,
    ///     );
    /// }
    /// ```
    async fn prepare_adapter_turn(
        &self,
        _capability: &mut PrepareAdapterTurnCapability,
        _request: AgentTurnRequest,
        _state: AdapterStateHandle,
    ) -> Result<Box<dyn PreparedAgentTurn>, ProtocolError> {
        Err(adapter_turn_not_migrated(self.kind()))
    }

    /// 旧 IPC v2/stdin compatibility：start a new session and stream events. The
    /// adapter must:
    ///   1. Send SessionStarted FIRST.
    ///   2. Send SessionCapabilities BEFORE any AgentItem (N7).
    ///   3. Emit AgentItem / ActionRequest / VendorPanelEvent / TurnComplete
    ///      / Error as appropriate.
    async fn start_session(
        &self,
        start: SessionStart,
        events: AgentEventSender,
    ) -> Result<AgentSessionHandle, ProtocolError>;

    /// Canonical Runtime 路径：由 daemon 先生成并持久化 neutral
    /// `adapterStateKey`，adapter 再把 vendor resume reference 写入自己的私有
    /// namespace。默认拒绝，只有注入 typed repository 的 adapter 才能启用。
    async fn start_adapter_state(
        &self,
        _adapter_state_key: RuntimeId,
        _start: SessionStart,
        _events: CanonicalAgentEventSender,
    ) -> Result<CanonicalAgentSessionHandle, ProtocolError> {
        Err(ProtocolError {
            code: "adapter-state-not-configured".into(),
            message: "adapter private state repository is not configured".into(),
            diagnostic_ref: None,
        })
    }

    /// Continue an existing thread with a new prompt. `cwd` MUST be the
    /// working directory associated with the thread — vendors like
    /// Claude Code look up resume files under
    /// `~/.claude/projects/<encoded_cwd>/<id>.jsonl`, and tool_use runs
    /// in this directory. The hub passes the cwd from the original
    /// `SessionStart` (the Swift UI / CLI carries it forward).
    /// 旧 IPC v2/stdin compatibility 入口；raw ThreadId 不得进入 RuntimeCore。
    async fn continue_thread(
        &self,
        thread_id: ThreadId,
        cwd: std::path::PathBuf,
        prompt: String,
        events: AgentEventSender,
    ) -> Result<AgentSessionHandle, ProtocolError>;

    /// Canonical Runtime 路径：只按 neutral adapterStateKey 继续，vendor ref
    /// 的解密与解释必须完全留在具体 adapter 模块。
    async fn continue_adapter_state(
        &self,
        _adapter_state_key: RuntimeId,
        _cwd: std::path::PathBuf,
        _prompt: String,
        _events: CanonicalAgentEventSender,
    ) -> Result<CanonicalAgentSessionHandle, ProtocolError> {
        Err(ProtocolError {
            code: "adapter-state-not-configured".into(),
            message: "adapter private state repository is not configured".into(),
            diagnostic_ref: None,
        })
    }

    /// Canonical history lookup：common 只给 neutral adapterStateKey；adapter
    /// 在私域解析 native ref，返回不含 ThreadId 的中立 turns。
    async fn read_adapter_history(
        &self,
        _adapter_state_key: RuntimeId,
    ) -> Result<CanonicalHistoryRead, ProtocolError> {
        Err(ProtocolError {
            code: "adapter-state-not-configured".into(),
            message: "adapter private history repository is not configured".into(),
            diagnostic_ref: None,
        })
    }

    /// 旧 IPC v2/stdin compatibility：submit a user decision。Canonical approval
    /// 必须继续走 daemon-owned bound delivery，不得按 execution/session lookup。
    async fn submit_decision(
        &self,
        session_id: &SessionId,
        decision: ActionDecision,
    ) -> Result<(), ProtocolError>;

    /// Submit a vendor-specific control update mid-session.
    async fn submit_vendor_control(
        &self,
        session_id: &SessionId,
        payload: VendorControlPayload,
    ) -> Result<(), ProtocolError>;

    /// 旧 IPC v2/stdin compatibility：cancel a running session by SessionId。
    async fn cancel(&self, session_id: &SessionId) -> Result<(), ProtocolError>;

    /// Serve a compatibility `HistoryRequest` (List / Read / Archive / Unarchive /
    /// Rename) for this adapter's own threads. The default returns a
    /// structured "not-supported" error so older / partial adapters
    /// don't break compilation when this trait grows. CC and Codex
    /// override this; the router merges cross-agent `List` results
    /// across all registered adapters (see `AgentRouter::handle_history`). Raw
    /// ThreadId stays on this stdio compatibility surface; P3 RuntimeCore imports
    /// native history through adapter-private reconciliation instead.
    ///
    /// Added by Task 4C — Phase 4 finalization.
    async fn handle_history(
        &self,
        _request: HistoryRequest,
    ) -> Result<HistoryResponse, ProtocolError> {
        Err(ProtocolError {
            code: "history-not-supported".into(),
            message: format!("agent {:?} does not implement history", self.kind()),
            diagnostic_ref: None,
        })
    }
}

/// Newtype wrapper to allow `dyn Agent` in maps.
pub type DynAgent = Arc<dyn Agent>;

fn adapter_turn_not_migrated(agent_kind: AgentKind) -> ProtocolError {
    ProtocolError {
        code: "adapter-turn-not-migrated".into(),
        message: format!("agent {agent_kind:?} has not migrated to the typed turn boundary"),
        diagnostic_ref: None,
    }
}

#[cfg(test)]
mod typed_boundary_tests {
    use super::*;
    use crate::claude_code::ClaudeCodeAdapter;
    use crate::codex::CodexAdapter;
    use agentdeck_protocol::runtime::{
        CodexConversationConfiguration, ConversationMetadataMutation, VendorConfigurationSnapshot,
    };
    use agentdeck_protocol::{CodexApprovalPolicy, CodexReasoningEffort, CodexSandboxMode};
    use std::sync::Mutex;
    use std::sync::atomic::{AtomicUsize, Ordering};

    struct StubPreparedTurn {
        spec: ExecSpec,
    }

    impl PreparedAgentTurn for StubPreparedTurn {
        fn exec_spec(&self) -> &ExecSpec {
            &self.spec
        }
    }

    struct SwitchingPreparedTurn {
        first: ExecSpec,
        second: ExecSpec,
        calls: AtomicUsize,
    }

    impl PreparedAgentTurn for SwitchingPreparedTurn {
        fn exec_spec(&self) -> &ExecSpec {
            if self.calls.fetch_add(1, Ordering::SeqCst) == 0 {
                &self.first
            } else {
                &self.second
            }
        }
    }

    struct PreparedOnlyAgent {
        replay_previous: bool,
        switch_after_validation: bool,
        saved: Mutex<Option<Box<dyn PreparedAgentTurn>>>,
    }

    impl PreparedOnlyAgent {
        fn new() -> Self {
            Self {
                replay_previous: false,
                switch_after_validation: false,
                saved: Mutex::new(None),
            }
        }

        fn replaying() -> Self {
            Self {
                replay_previous: true,
                switch_after_validation: false,
                saved: Mutex::new(None),
            }
        }

        fn switching() -> Self {
            Self {
                replay_previous: false,
                switch_after_validation: true,
                saved: Mutex::new(None),
            }
        }
    }

    #[async_trait::async_trait]
    impl Agent for PreparedOnlyAgent {
        fn kind(&self) -> AgentKind {
            AgentKind::Codex
        }

        fn capabilities(&self) -> SessionCapabilities {
            unreachable!("binding test never probes capabilities")
        }

        fn default_configuration(&self) -> Result<ConversationConfiguration, ConfigurationError> {
            Ok(ConversationConfiguration::new(
                VendorConfigurationSnapshot::Codex(CodexConversationConfiguration::new(
                    CodexApprovalPolicy::OnRequest,
                    CodexSandboxMode::WorkspaceWrite,
                    CodexReasoningEffort::Medium,
                )),
            ))
        }

        async fn prepare_adapter_turn(
            &self,
            _capability: &mut PrepareAdapterTurnCapability,
            request: AgentTurnRequest,
            state: AdapterStateHandle,
        ) -> Result<Box<dyn PreparedAgentTurn>, ProtocolError> {
            if self.switch_after_validation {
                let other_request = AgentTurnRequest::new(
                    execution_id(0xE1),
                    std::env::current_dir().expect("current directory"),
                    PromptPayload::new("other execution").expect("bounded prompt"),
                    9,
                    codex_configuration(),
                )
                .expect("other request");
                return Ok(Box::new(SwitchingPreparedTurn {
                    first: ExecSpec::new(
                        &request,
                        state,
                        "/usr/bin/true",
                        Vec::<OsString>::new(),
                        "/tmp",
                    )
                    .expect("first bound spec"),
                    second: ExecSpec::new(
                        &other_request,
                        adapter_state(0xE2),
                        "/usr/bin/false",
                        Vec::<OsString>::new(),
                        "/tmp",
                    )
                    .expect("second foreign spec"),
                    calls: AtomicUsize::new(0),
                }));
            }
            if self.replay_previous {
                let mut saved = self
                    .saved
                    .lock()
                    .unwrap_or_else(|poisoned| poisoned.into_inner());
                if let Some(previous) = saved.take() {
                    return Ok(previous);
                }
                *saved = Some(Box::new(StubPreparedTurn {
                    spec: ExecSpec::new(
                        &request,
                        state,
                        "/usr/bin/true",
                        Vec::<OsString>::new(),
                        "/tmp",
                    )
                    .expect("saved stub exec spec"),
                }));
            }
            Ok(Box::new(StubPreparedTurn {
                spec: ExecSpec::new(
                    &request,
                    state,
                    "/usr/bin/true",
                    Vec::<OsString>::new(),
                    "/tmp",
                )
                .expect("stub exec spec"),
            }))
        }

        async fn start_session(
            &self,
            _start: SessionStart,
            _events: AgentEventSender,
        ) -> Result<AgentSessionHandle, ProtocolError> {
            unreachable!("binding test never starts a compatibility session")
        }

        async fn continue_thread(
            &self,
            _thread_id: ThreadId,
            _cwd: PathBuf,
            _prompt: String,
            _events: AgentEventSender,
        ) -> Result<AgentSessionHandle, ProtocolError> {
            unreachable!("binding test never continues a compatibility session")
        }

        async fn submit_decision(
            &self,
            _session_id: &SessionId,
            _decision: ActionDecision,
        ) -> Result<(), ProtocolError> {
            unreachable!("binding test never resolves a compatibility approval")
        }

        async fn submit_vendor_control(
            &self,
            _session_id: &SessionId,
            _payload: VendorControlPayload,
        ) -> Result<(), ProtocolError> {
            unreachable!("binding test never submits compatibility vendor control")
        }

        async fn cancel(&self, _session_id: &SessionId) -> Result<(), ProtocolError> {
            unreachable!("binding test never cancels a compatibility session")
        }
    }

    fn runtime_id(kind: RuntimeIdKind, seed: u8) -> RuntimeId {
        RuntimeId::from_bytes(kind, [seed; 16]).expect("non-zero runtime id")
    }

    fn execution_id(seed: u8) -> ExecutionId {
        ExecutionId::from_command_id(runtime_id(RuntimeIdKind::Command, seed))
            .expect("command execution id")
    }

    fn request(seed: u8, prompt: &str) -> AgentTurnRequest {
        AgentTurnRequest::new(
            execution_id(seed),
            std::env::current_dir().expect("current directory"),
            PromptPayload::new(prompt).expect("bounded prompt"),
            7,
            codex_configuration(),
        )
        .expect("absolute request cwd")
    }

    fn codex_configuration() -> ConversationConfiguration {
        ConversationConfiguration::new(VendorConfigurationSnapshot::Codex(
            CodexConversationConfiguration::new(
                CodexApprovalPolicy::Never,
                CodexSandboxMode::ReadOnly,
                CodexReasoningEffort::High,
            ),
        ))
    }

    fn claude_code_configuration() -> ConversationConfiguration {
        ConversationConfiguration::new(VendorConfigurationSnapshot::ClaudeCode(
            agentdeck_protocol::runtime::ClaudeCodeConversationConfiguration::new(
                agentdeck_protocol::ClaudeCodePermissionMode::Plan,
                None,
                None,
                None,
            )
            .expect("bounded Claude Code configuration"),
        ))
    }

    fn adapter_state(seed: u8) -> AdapterStateHandle {
        AdapterStateHandle::new(runtime_id(RuntimeIdKind::AdapterState, seed))
            .expect("adapter state handle")
    }

    fn exec_spec(
        program: impl Into<PathBuf>,
        non_sensitive_args: impl IntoIterator<Item = impl Into<OsString>>,
        cwd: impl Into<PathBuf>,
    ) -> Result<ExecSpec, AgentTurnContractError> {
        let request = request(0xD1, "exec spec structural test");
        ExecSpec::new(
            &request,
            adapter_state(0xD2),
            program,
            non_sensitive_args,
            cwd,
        )
    }

    #[test]
    fn identity_handles_reject_other_runtime_families_and_redact_debug() {
        assert!(matches!(
            ExecutionId::from_command_id(runtime_id(RuntimeIdKind::Turn, 1)),
            Err(AgentTurnContractError::InvalidExecutionKind {
                actual: RuntimeIdKind::Turn
            })
        ));
        assert!(matches!(
            AdapterStateHandle::new(runtime_id(RuntimeIdKind::Conversation, 2)),
            Err(AgentTurnContractError::InvalidAdapterStateKind {
                actual: RuntimeIdKind::Conversation
            })
        ));

        let execution = execution_id(3);
        let state = adapter_state(4);
        assert_eq!(execution.command_id().kind(), RuntimeIdKind::Command);
        assert_eq!(state.key().kind(), RuntimeIdKind::AdapterState);
        assert_eq!(format!("{execution:?}"), "ExecutionId([REDACTED])");
        assert_eq!(format!("{state:?}"), "AdapterStateHandle([REDACTED])");
    }

    #[test]
    fn native_history_boundary_is_bounded_typed_and_redacted() {
        let turn_key =
            NativeTurnKey::from_verified_bytes([0x31; 32]).expect("nonzero native turn key");
        let item_key =
            NativeItemKey::from_verified_bytes([0x32; 32]).expect("nonzero native item key");
        let item = CanonicalNativeHistoryItem::new(
            turn_key,
            item_key,
            AgentItem::AssistantMessage {
                text: "private native history sentinel".to_owned(),
                meta: Default::default(),
            },
        )
        .expect("modeled native item");
        let read = CanonicalNativeHistoryRead::new(
            AgentKind::ClaudeCode,
            vec![item],
            MAX_CANONICAL_NATIVE_HISTORY_BYTES,
        )
        .expect("exact native history byte bound");

        assert_eq!(read.agent_kind(), AgentKind::ClaudeCode);
        assert_eq!(read.source_bytes(), MAX_CANONICAL_NATIVE_HISTORY_BYTES);
        assert_eq!(read.items().len(), 1);
        assert_eq!(read.items()[0].turn_key(), turn_key);
        assert_eq!(read.items()[0].item_key(), item_key);
        assert!(matches!(
            read.items()[0].item(),
            AgentItem::AssistantMessage { .. }
        ));
        let debug = format!("{read:?}");
        assert!(!debug.contains("private native history sentinel"));
        assert!(!debug.contains("31"));
        assert!(!debug.contains("32"));

        let oversized = CanonicalNativeHistoryRead::new(
            AgentKind::ClaudeCode,
            Vec::new(),
            MAX_CANONICAL_NATIVE_HISTORY_BYTES + 1,
        )
        .expect_err("native history byte bound is fail-closed");
        assert_eq!(oversized.code, "adapter-native-history-too-large");

        let too_many_items = (0..=MAX_CANONICAL_NATIVE_HISTORY_ITEMS)
            .map(|index| {
                let mut key = [0_u8; 32];
                key[..8].copy_from_slice(&((index as u64) + 1).to_be_bytes());
                CanonicalNativeHistoryItem::new(
                    turn_key,
                    NativeItemKey::from_verified_bytes(key).expect("nonzero bounded item key"),
                    AgentItem::AssistantMessage {
                        text: String::new(),
                        meta: Default::default(),
                    },
                )
                .expect("modeled bounded item fixture")
            })
            .collect();
        let oversized = CanonicalNativeHistoryRead::new(AgentKind::ClaudeCode, too_many_items, 1)
            .expect_err("native history item bound is fail-closed");
        assert_eq!(oversized.code, "adapter-native-history-too-large");

        let raw = CanonicalNativeHistoryItem::new(
            turn_key,
            item_key,
            AgentItem::Raw {
                raw_kind: "private-vendor-kind".to_owned(),
                raw_payload: "private-vendor-payload".to_owned(),
                meta: Default::default(),
            },
        )
        .expect_err("raw vendor frames cannot cross the native history boundary");
        assert_eq!(raw.code, "adapter-raw-history-blocked");

        assert_eq!(
            NativeTurnKey::from_verified_bytes([0; 32])
                .expect_err("zero turn key must fail closed")
                .code,
            "adapter-native-history-invalid"
        );
        assert_eq!(
            NativeItemKey::from_verified_bytes([0; 32])
                .expect_err("zero item key must fail closed")
                .code,
            "adapter-native-history-invalid"
        );
    }

    #[test]
    fn native_projection_candidate_ack_issuer_and_completion_are_typed_and_redacted() {
        let private_title = "private projector title sentinel";
        let private_cwd = "/private/projector/cwd-sentinel";
        let private_reference = b"private-project/session-sentinel.jsonl";
        let generation = [0xA4; 16];
        let issuer = NativeProjectionScanIssuer::new(generation).expect("nonzero scan issuer");
        let issuer_debug = format!("{issuer:?}");
        let candidate = issuer
            .issue_candidate(
                ConversationDescriptor {
                    agent_kind: AgentKind::ClaudeCode,
                    title: Some(private_title.to_owned()),
                    cwd: PathBuf::from(private_cwd),
                },
                claude_code_configuration(),
                SecretBytes::new(private_reference.to_vec()),
                [0xA5; 16],
            )
            .expect("verified neutral candidate");
        let candidate_debug = format!("{candidate:?}");
        let (_, _, private_reference, acknowledgement) = candidate.into_parts();
        assert_eq!(
            private_reference.expose_secret(),
            b"private-project/session-sentinel.jsonl"
        );
        assert!(issuer.matches_acknowledgement(&acknowledgement, &[0xA5; 16]));
        let acknowledgement_debug = format!("{acknowledgement:?}");
        let completed = issuer
            .complete(generation, 1, 1)
            .expect("issuer is consumed into completion");
        let completed_debug = format!("{completed:?}");
        assert_eq!(completed.into_parts(), (generation, 1, 1));

        for surface in [
            issuer_debug,
            candidate_debug,
            acknowledgement_debug,
            completed_debug,
            format!("{private_reference:?}"),
        ] {
            for sentinel in [
                private_title,
                private_cwd,
                "private-project",
                "session-sentinel",
                ".jsonl",
            ] {
                assert!(
                    !surface.contains(sentinel),
                    "Debug leaked {sentinel}: {surface}"
                );
            }
        }
    }

    #[test]
    fn native_projection_issuer_and_candidate_constructors_have_static_ownership() {
        let agent = include_str!("agent.rs");
        let production_agent = agent
            .split("#[cfg(test)]\npub(crate) fn native_projection_scan_issuer_for_test")
            .next()
            .expect("production agent seam precedes test issuer");
        assert_eq!(
            production_agent
                .matches("NativeProjectionScanIssuer::new(generation)?")
                .count(),
            1,
            "only the daemon begin helper may mint a production issuer"
        );
        assert_eq!(
            production_agent
                .matches("NativeProjectionCandidate::from_verified_source(")
                .count(),
            1,
            "only the issuer may construct a neutral candidate"
        );
        assert_eq!(
            production_agent
                .matches("NativeProjectionAcknowledgement::new(")
                .count(),
            1,
            "only the issuer may sign a candidate ACK"
        );

        let router = include_str!("runtime/router.rs");
        let production_router = router
            .split("#[cfg(test)]\nmod typed_prepare_tests")
            .next()
            .expect("production router precedes tests");
        for (name, source) in [
            ("router", production_router),
            ("core", include_str!("runtime/core.rs") as &str),
            (
                "conversation",
                include_str!("runtime/conversation.rs") as &str,
            ),
            ("execution", include_str!("runtime/execution.rs") as &str),
            (
                "store worker",
                include_str!("runtime/store/worker.rs") as &str,
            ),
        ] {
            assert!(
                !source.contains("NativeProjectionScanIssuer"),
                "{name} must never receive or mint the source completion issuer"
            );
            if name != "router" {
                assert!(
                    !source.contains("register_native_projection_source("),
                    "{name} must not install an alternate production projector source"
                );
            }
        }
        assert_eq!(
            production_router
                .matches("register_native_projection_source(")
                .count(),
            2,
            "production router has one registration call and one private registry method"
        );
        let history = include_str!("claude_code/history.rs");
        assert_eq!(history.matches("self.issuer.complete(").count(), 1);
        assert_eq!(history.matches("issuer.issue_candidate(").count(), 1);
        let adapter = include_str!("claude_code/adapter.rs");
        let source_impl = adapter
            .split("impl NativeProjectionSource for ClaudeCodeAdapter")
            .nth(1)
            .and_then(|tail| tail.split("impl NativeMetadataEffectAdapter").next())
            .expect("isolated Claude Code projector source impl");
        assert!(source_impl.contains("history::begin_native_projection_scan"));
        assert!(!source_impl.contains(".complete("));
    }

    #[test]
    fn turn_request_keeps_prompt_and_runtime_ids_out_of_debug() {
        let prompt = "private prompt sentinel";
        let request = request(5, prompt);
        assert_eq!(
            request.execution_id().command_id().kind(),
            RuntimeIdKind::Command
        );
        assert!(request.cwd().is_absolute());
        assert_eq!(request.prompt(), prompt);
        assert_eq!(request.configuration_revision(), 7);
        assert_eq!(request.execution_configuration(), &codex_configuration());

        let debug = format!("{request:?}");
        assert!(!debug.contains(prompt));
        assert!(!debug.contains(&runtime_id(RuntimeIdKind::Command, 5).to_string()));
        assert!(debug.contains(&format!("prompt_bytes: {}", prompt.len())));

        assert!(matches!(
            AgentTurnRequest::new(
                execution_id(6),
                "relative",
                PromptPayload::new("prompt").expect("bounded prompt"),
                0,
                codex_configuration(),
            ),
            Err(AgentTurnContractError::RelativeWorkingDirectory)
        ));
    }

    #[tokio::test]
    async fn daemon_rejects_frozen_configuration_for_another_agent_before_prepare() {
        let request = AgentTurnRequest::new(
            execution_id(0xC1),
            std::env::current_dir().expect("current directory"),
            PromptPayload::new("must not reach adapter").expect("bounded prompt"),
            4,
            claude_code_configuration(),
        )
        .expect("absolute request cwd");
        let error = prepare_turn(&PreparedOnlyAgent::new(), request, adapter_state(0xC2))
            .await
            .expect_err("route/configuration mismatch must fail before adapter prepare");
        assert_eq!(error.code, "adapter-configuration-agent-mismatch");
        assert!(error.diagnostic_ref.is_none());
    }

    #[test]
    fn exec_spec_validates_every_structural_bound_and_redacts_debug() {
        let cwd = std::env::current_dir().expect("current directory");
        let private_cwd = PathBuf::from("/private/sentinel/worktree");
        let spec = exec_spec(
            "/private/sentinel/bin/vendor",
            [OsString::from("--model"), OsString::from("private-alias")],
            private_cwd.clone(),
        )
        .expect("valid exec spec");
        assert_eq!(spec.program(), Path::new("/private/sentinel/bin/vendor"));
        assert_eq!(spec.cwd(), private_cwd);
        assert_eq!(spec.non_sensitive_args().len(), 2);

        let debug = format!("{spec:?}");
        assert!(!debug.contains("/private/sentinel/bin/vendor"));
        assert!(!debug.contains("/private/sentinel/worktree"));
        assert!(!debug.contains("private-alias"));
        assert!(debug.contains("argument_count: 2"));

        assert!(matches!(
            exec_spec("relative/vendor", Vec::<OsString>::new(), cwd.clone()),
            Err(AgentTurnContractError::RelativeProgram)
        ));
        assert!(matches!(
            exec_spec("/usr/bin/vendor", Vec::<OsString>::new(), "relative"),
            Err(AgentTurnContractError::RelativeExecWorkingDirectory)
        ));
        assert!(matches!(
            exec_spec(
                "/usr/bin/vendor",
                [OsString::from("contains\0nul")],
                cwd.clone(),
            ),
            Err(AgentTurnContractError::ContainsNul)
        ));
        assert!(matches!(
            exec_spec(
                format!("/{}", "x".repeat(MAX_EXEC_PATH_BYTES)),
                Vec::<OsString>::new(),
                cwd.clone(),
            ),
            Err(AgentTurnContractError::PathTooLarge)
        ));
        assert!(matches!(
            exec_spec(
                "/usr/bin/vendor",
                [OsString::from(
                    "x".repeat(MAX_EXEC_SINGLE_ARGUMENT_BYTES + 1)
                )],
                cwd.clone(),
            ),
            Err(AgentTurnContractError::ArgumentTooLarge)
        ));
        assert!(matches!(
            exec_spec(
                "/usr/bin/vendor",
                std::iter::repeat_n(OsString::from("x"), MAX_EXEC_ARGUMENTS + 1),
                cwd.clone(),
            ),
            Err(AgentTurnContractError::TooManyArguments)
        ));
        assert!(matches!(
            exec_spec(
                "/usr/bin/vendor",
                std::iter::repeat_n(
                    OsString::from("x".repeat(MAX_EXEC_SINGLE_ARGUMENT_BYTES)),
                    MAX_EXEC_ARGUMENT_BYTES / MAX_EXEC_SINGLE_ARGUMENT_BYTES + 1,
                ),
                cwd,
            ),
            Err(AgentTurnContractError::ArgumentsTooLarge)
        ));
        assert!(matches!(
            exec_spec(
                format!("/{}", "p".repeat(MAX_EXEC_PATH_BYTES - 1)),
                std::iter::repeat_n(
                    OsString::from("x".repeat(MAX_EXEC_SINGLE_ARGUMENT_BYTES)),
                    MAX_EXEC_ARGUMENT_BYTES / MAX_EXEC_SINGLE_ARGUMENT_BYTES,
                ),
                format!("/{}", "w".repeat(MAX_EXEC_PATH_BYTES - 1)),
            ),
            Err(AgentTurnContractError::ControlFrameTooLarge)
        ));
    }

    #[test]
    fn native_metadata_request_and_effect_spec_are_typed_bounded_and_redacted() {
        let private_title = "private native title sentinel";
        let private_program = "/private/native/bin/claude";
        let private_cwd = "/private/native/worktree";
        let private_session = "private-native-session-sentinel";
        let request = NativeMetadataEffectRequest::new(
            adapter_state(0xA1),
            ConversationMetadataMutation::rename(Some(private_title.to_owned()))
                .expect("bounded title"),
        );
        let spec = NativeMetadataEffectSpec::new(
            private_program,
            [
                OsString::from("--resume"),
                OsString::from(private_session),
                OsString::from("-n"),
                OsString::from(private_title),
            ],
            private_cwd,
        )
        .expect("absolute bounded native effect spec");

        assert_eq!(request.parts().0.key().kind(), RuntimeIdKind::AdapterState);
        let (program, args, cwd) = spec.parts();
        assert_eq!(program, Path::new(private_program));
        assert_eq!(cwd, Path::new(private_cwd));
        assert_eq!(args.len(), 4);
        for debug in [format!("{request:?}"), format!("{spec:?}")] {
            for sentinel in [private_title, private_program, private_cwd, private_session] {
                assert!(
                    !debug.contains(sentinel),
                    "Debug leaked {sentinel}: {debug}"
                );
            }
        }

        assert_eq!(
            NativeMetadataEffectSpec::new("relative/claude", Vec::<OsString>::new(), private_cwd,)
                .expect_err("relative program must fail closed"),
            NativeMetadataEffectError::InvalidSpec,
        );
        assert_eq!(
            NativeMetadataEffectSpec::new(
                private_program,
                [OsString::from("contains\0nul")],
                private_cwd,
            )
            .expect_err("NUL argv must fail closed"),
            NativeMetadataEffectError::InvalidSpec,
        );
    }

    #[test]
    fn adapter_event_debug_never_exposes_adapter_payloads() {
        let event = AdapterEvent::Error(ProtocolError {
            code: "vendor-private-code".into(),
            message: "vendor private diagnostic sentinel".into(),
            diagnostic_ref: Some("vendor-private-reference".into()),
        });
        let debug = format!("{event:?}");
        assert!(debug.contains("Error"));
        for private in [
            "vendor-private-code",
            "vendor private diagnostic sentinel",
            "vendor-private-reference",
        ] {
            assert!(
                !debug.contains(private),
                "AdapterEvent Debug leaked {private}"
            );
        }
    }

    #[tokio::test]
    async fn daemon_prepare_binds_the_saved_execution_to_the_opaque_inner() {
        let request = request(9, "bound prompt");
        let expected = request.execution_id();
        let agent = PreparedOnlyAgent::new();
        let prepared = prepare_turn(&agent, request, adapter_state(10))
            .await
            .expect("daemon binds prepared turn");

        assert_eq!(prepared.execution_id(), expected);
        assert_eq!(
            prepared
                .exec_spec()
                .expect("validated prepared spec")
                .program(),
            Path::new("/usr/bin/true")
        );
        let debug = format!("{prepared:?}");
        assert!(!debug.contains(&expected.command_id().to_string()));
        assert!(!debug.contains("/usr/bin/true"));
    }

    #[tokio::test]
    async fn daemon_rejects_a_prepared_inner_saved_from_another_execution() {
        // 威胁场景：外部 Agent 实现可在 execution A 保存 built-in prepared inner，并在
        // execution B 收到合法 capability 后返回 A；若只把 outer request ID 写进 handle，
        // gate 会把 A 的 prompt/spec 错绑到 B。
        let agent = PreparedOnlyAgent::replaying();
        prepare_turn(&agent, request(0x31, "execution A"), adapter_state(0x32))
            .await
            .expect("first execution returns its own bound inner");

        let error = prepare_turn(&agent, request(0x41, "execution B"), adapter_state(0x42))
            .await
            .expect_err("saved execution A inner must not bind to execution B");
        assert_eq!(error.code, "adapter-prepare-binding-mismatch");
        assert!(error.diagnostic_ref.is_none());
    }

    #[tokio::test]
    async fn daemon_revalidates_the_exact_spec_returned_at_consumption_time() {
        // 威胁场景：恶意 adapter 的虚 getter 首次返回正确 spec 通过 prepare，随后切到另一
        // execution/state；若 handle 直接二次信任 getter，gate 会执行错误产物。
        let agent = PreparedOnlyAgent::switching();
        let prepared = prepare_turn(
            &agent,
            request(0xD3, "bound execution"),
            adapter_state(0xD4),
        )
        .await
        .expect("first spec passes prepare-time validation");

        let error = prepared
            .exec_spec()
            .expect_err("consumption-time spec switch must fail closed");
        assert_eq!(error.code, "adapter-prepare-binding-mismatch");
        assert!(error.diagnostic_ref.is_none());
    }

    #[tokio::test]
    async fn both_adapters_without_runtime_vault_fail_before_any_typed_spawn_path() {
        let codex = CodexAdapter::new_for_test();
        let claude_code = ClaudeCodeAdapter::new_for_test();

        for (agent, expected) in [
            (&codex as &dyn Agent, "codex-state-vault-unavailable"),
            (&claude_code as &dyn Agent, "cc-state-vault-unavailable"),
        ] {
            let configuration = match agent.kind() {
                AgentKind::Codex => codex_configuration(),
                AgentKind::ClaudeCode => claude_code_configuration(),
            };
            let request = AgentTurnRequest::new(
                execution_id(7),
                std::env::current_dir().expect("current directory"),
                PromptPayload::new("never spawn").expect("bounded prompt"),
                7,
                configuration,
            )
            .expect("absolute request cwd");
            let prepare_error = match prepare_turn(agent, request, adapter_state(8)).await {
                Err(error) => error,
                Ok(_) => panic!("adapter without runtime vault must not prepare a typed turn"),
            };
            assert_eq!(prepare_error.code, expected);
        }
    }
}
