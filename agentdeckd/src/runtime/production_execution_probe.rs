//! current-binary production execution 的 debug-only 集成门禁。
//!
//! 公开入口只存在于 debug build，并且只能由真实 `agentdeckd` binary 的隐藏 one-shot
//! 子模式调用。这样 coordinator 必然走 `spawn_current`，adapter/request/gate capability
//! 仍保持 crate-private；release build 不包含此 seam。

use std::ffi::OsString;
use std::fs;
use std::io;
use std::path::PathBuf;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Condvar, Mutex as StdMutex};
use std::time::Duration;

use agentdeck_protocol::runtime::identity::{ConversationId, TurnId};
use agentdeck_protocol::runtime::{
    CancellationReceipt, CodexConversationConfiguration, ConfigurationError,
    ConversationConfiguration, RuntimeEventBody, RuntimeReply, RuntimeRequest,
    VendorConfigurationSnapshot,
};
use agentdeck_protocol::{
    ActionDecision, AgentItem, AgentItemMeta, AgentKind, CodexApprovalPolicy, CodexReasoningEffort,
    CodexSandboxMode, ProtocolError, SessionCapabilities, SessionId, SessionStart, ThreadId,
    TurnSummary, VendorCapabilities, VendorControlPayload,
};
use tokio::io::{AsyncBufReadExt, AsyncReadExt, AsyncWriteExt, BufReader};

use crate::agent::{
    AdapterApprovalSink, AdapterCompletionFuture, AdapterEvent, AdapterEventSink, AdapterItemKey,
    AdapterStateHandle, Agent, AgentEventSender, AgentSessionHandle, AgentTurnRequest, ExecSpec,
    PrepareAdapterTurnCapability, PreparedAgentTurn,
};
use crate::exec_gate::GatedChildIo;
use crate::runtime::process_identity::{
    ProcessGroupController, ProcessIdentity, ProcessObservation, SystemProcessGroupController,
};
use crate::runtime::store::{
    AcceptCommand, AcceptOutcome, CommandReceiptRecord, CommandReceiptSelector, CommandState,
    ConversationDescriptor, IdempotencyOwner, NewConversation, QueryCommandReceipt,
    RuntimeBackfillPlan, RuntimeBackfillTarget, RuntimeId, RuntimeIdKind, RuntimeStoreConfig,
    RuntimeStoreError, RuntimeStoreFaultInjector, RuntimeStoreHandle, RuntimeStoreOperation,
};
use crate::runtime::{ConnectionSink, RuntimeCore};
use crate::security::{MemoryKeyStore, load_or_create_storage_kek};

const HELPER_RESPONSE: &str = "production-helper-response";
const PROBE_TIMEOUT: Duration = Duration::from_secs(15);
const PROBE_HARD_TIMEOUT: Duration = Duration::from_secs(30);

#[derive(Clone, Copy, Debug, Eq, PartialEq, serde::Serialize)]
#[serde(rename_all = "camelCase")]
pub struct ProductionExecutionProbeEvidence {
    pub command_completed: bool,
    pub command_canceled: bool,
    pub durable_item_count_after_reopen: usize,
    pub durable_terminal_count_after_reopen: usize,
    pub vendor_prompt_matched: bool,
    pub adapter_observed_durable_ack: bool,
    pub cancel_requested: bool,
    pub vendor_side_effect_absent: bool,
    pub gate_group_exited_after_cancel: bool,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum ProbeMode {
    Complete,
    CancelBeforeRelease,
}

#[derive(Debug)]
struct PersistFenceBlocker {
    entered: AtomicBool,
    released: StdMutex<bool>,
    released_changed: Condvar,
}

impl PersistFenceBlocker {
    fn new() -> Self {
        Self {
            entered: AtomicBool::new(false),
            released: StdMutex::new(false),
            released_changed: Condvar::new(),
        }
    }

    async fn wait_until_entered(&self) -> Result<(), String> {
        tokio::time::timeout(PROBE_TIMEOUT, async {
            while !self.entered.load(Ordering::SeqCst) {
                tokio::time::sleep(Duration::from_millis(10)).await;
            }
        })
        .await
        .map_err(|_| "production cancel probe never reached the release fence".to_owned())
    }

    fn release(&self) {
        *self.released.lock().expect("probe fence blocker lock") = true;
        self.released_changed.notify_all();
    }
}

impl RuntimeStoreFaultInjector for PersistFenceBlocker {
    fn before_operation(&self, operation: RuntimeStoreOperation) -> Result<(), RuntimeStoreError> {
        if operation == RuntimeStoreOperation::PersistFenceBeforeCommit {
            self.entered.store(true, Ordering::SeqCst);
            let mut released = self.released.lock().expect("probe fence blocker lock");
            while !*released {
                released = self
                    .released_changed
                    .wait(released)
                    .expect("probe fence blocker wait");
            }
        }
        Ok(())
    }
}

struct PersistFenceReleaseGuard(Arc<PersistFenceBlocker>);

impl Drop for PersistFenceReleaseGuard {
    fn drop(&mut self) {
        self.0.release();
    }
}

struct ProbeRoot(PathBuf);

impl ProbeRoot {
    fn create() -> Result<Self, String> {
        for _ in 0..16 {
            let mut entropy = [0_u8; 16];
            getrandom::fill(&mut entropy)
                .map_err(|error| format!("create probe root entropy: {error}"))?;
            let path = std::env::temp_dir().join(format!(
                "agentdeckd-production-execution-probe-{}-{:032x}",
                std::process::id(),
                u128::from_be_bytes(entropy)
            ));
            match fs::create_dir(&path) {
                Ok(()) => {
                    #[cfg(unix)]
                    {
                        use std::os::unix::fs::PermissionsExt;
                        if let Err(error) =
                            fs::set_permissions(&path, fs::Permissions::from_mode(0o700))
                        {
                            let _ = fs::remove_dir(&path);
                            return Err(format!("secure probe root: {error}"));
                        }
                    }
                    return Ok(Self(path));
                }
                Err(error) if error.kind() == io::ErrorKind::AlreadyExists => continue,
                Err(error) => return Err(format!("create probe root: {error}")),
            }
        }
        Err("could not allocate a unique probe root".to_owned())
    }
}

impl Drop for ProbeRoot {
    fn drop(&mut self) {
        let _ = fs::remove_dir_all(&self.0);
    }
}

/// 让一个无副作用真实进程穿过 RuntimeCore recovery、production coordinator、
/// `agentdeckd --exec-gate`、typed adapter driver、durable event ACK、terminal COMMIT 与 reopen。
///
/// 威胁场景：gate/driver/store 各层测试都可能通过，但普通接线仍可能绑错 execution、漏转 ACK，
/// 或在 current-binary child 越过已提交 release barrier 前就完成。本 probe 覆盖这条组合路径。
pub async fn run_production_execution_probe() -> Result<ProductionExecutionProbeEvidence, String> {
    tokio::time::timeout(
        PROBE_HARD_TIMEOUT,
        run_production_execution_probe_mode(ProbeMode::Complete),
    )
    .await
    .map_err(|_| "production execution probe exceeded its hard deadline".to_owned())?
}

/// 让真实 current-binary gate 停在 Ready→release 之间，再经 RuntimeCore 发起用户取消。
/// 该阶段 sentinel 仍使用默认 TERM disposition，因此本 probe 证明 production owner 的
/// current-binary TERM/reap；TERM-resistant KILL escalation 由 execution 层独立真实组测试覆盖。
pub async fn run_production_execution_cancel_probe()
-> Result<ProductionExecutionProbeEvidence, String> {
    tokio::time::timeout(
        PROBE_HARD_TIMEOUT,
        run_production_execution_probe_mode(ProbeMode::CancelBeforeRelease),
    )
    .await
    .map_err(|_| "production execution cancel probe exceeded its hard deadline".to_owned())?
}

async fn run_production_execution_probe_mode(
    mode: ProbeMode,
) -> Result<ProductionExecutionProbeEvidence, String> {
    // 威胁场景：测试 API 接受任意绝对 root 并先递归删除时，调用方误传工作区即可造成
    // 数据破坏。probe 只删除自己以强随机名原子创建并用 RAII 持有的临时目录。
    let root_owner = ProbeRoot::create()?;
    let root = root_owner.0.clone();

    let database = root.join("runtime.db");
    let key_state = root.join("key-state.db");
    let vendor_prompt_path = root.join("vendor-prompt.txt");
    let durable_ack_path = root.join("durable-ack.txt");
    let keys = MemoryKeyStore::new();
    let storage_kek = load_or_create_storage_kek(&keys, &key_state)
        .map_err(|error| format!("create probe StorageKEK: {error}"))?;
    let fence_blocker =
        (mode == ProbeMode::CancelBeforeRelease).then(|| Arc::new(PersistFenceBlocker::new()));
    let _fence_release_guard = fence_blocker
        .as_ref()
        .map(|blocker| PersistFenceReleaseGuard(blocker.clone()));
    let config = match &fence_blocker {
        Some(blocker) => {
            RuntimeStoreConfig::new(database.clone()).with_fault_injector(blocker.clone())
        }
        None => RuntimeStoreConfig::new(database.clone()),
    };
    let store = RuntimeStoreHandle::open(config.clone(), storage_kek)
        .await
        .map_err(|error| format!("open probe store: {error}"))?;

    let conversation_id = runtime_id(RuntimeIdKind::Conversation, 0x71)?;
    let adapter_state_key = runtime_id(RuntimeIdKind::AdapterState, 0x72)?;
    let owner = IdempotencyOwner::Local {
        machine_trust_domain: store
            .machine_trust_domain()
            .map_err(|error| format!("read probe trust domain: {error}"))?,
        uid: 501,
        client_installation_id: [0x73; 16],
    };
    store
        .create_conversation(NewConversation {
            conversation_id,
            adapter_state_key,
            descriptor: ConversationDescriptor {
                agent_kind: AgentKind::Codex,
                title: Some("production execution probe".to_owned()),
                cwd: root.clone(),
            },
        })
        .await
        .map_err(|error| format!("create probe conversation: {error}"))?;
    let prompt = "private production wiring prompt";
    let command = match store
        .accept_command(AcceptCommand {
            conversation_id,
            owner: owner.clone(),
            idempotency_key: "production-execution-probe".to_owned(),
            expected_configuration_revision: 0,
            payload: prompt.as_bytes().to_vec(),
        })
        .await
        .map_err(|error| format!("accept probe command: {error}"))?
    {
        AcceptOutcome::Accepted { command, .. } => command,
        AcceptOutcome::Replayed { .. } => return Err("fresh probe command replayed".to_owned()),
    };

    let mut router = crate::runtime::AgentRouter::new();
    router.register(Arc::new(ProbeAgent {
        vendor_prompt_path: vendor_prompt_path.clone(),
        durable_ack_path: durable_ack_path.clone(),
    }));
    let core = RuntimeCore::new_production(store.clone(), Arc::new(router))
        .map_err(|error| format!("construct production probe core: {error:?}"))?;
    let (report, _permit) = core
        .recover_for_startup()
        .await
        .map_err(|error| format!("recover production probe core: {error:?}"))?;
    if report.conversations != 1 || report.accepted_commands != 1 {
        return Err(format!("unexpected recovery report: {report:?}"));
    }

    let (cancel_requested, vendor_side_effect_absent, gate_group_exited_after_cancel) = match mode {
        ProbeMode::Complete => {
            wait_for_command_state(
                &store,
                &owner,
                conversation_id,
                command.command_id,
                CommandState::Completed,
            )
            .await?;
            (false, false, false)
        }
        ProbeMode::CancelBeforeRelease => {
            let blocker = fence_blocker
                .as_ref()
                .ok_or_else(|| "cancel probe release blocker is missing".to_owned())?;
            blocker.wait_until_entered().await?;
            let gate_identity = capture_single_current_binary_gate()?;
            let turn_id = read_started_turn_id(&database, command.command_id)?;
            let principal = core
                .issue_verified_local_principal(501, [0x73; 16])
                .map_err(|error| format!("issue cancel probe principal: {error:?}"))?;
            let (sink_tx, _sink_rx) = tokio::sync::mpsc::channel(1);
            let connection_id = core
                .connect(principal, ConnectionSink::new(sink_tx))
                .map_err(|error| format!("connect cancel probe principal: {error:?}"))?;
            let reply = core
                .handle(
                    connection_id,
                    RuntimeRequest::CancelActive {
                        conversation_id: ConversationId::new(conversation_id.to_canonical_string()),
                        turn_id: TurnId::new(turn_id.to_canonical_string()),
                    },
                )
                .await;
            if !matches!(
                reply,
                RuntimeReply::Cancellation(CancellationReceipt::ActiveCancelRequested { .. })
            ) {
                return Err(format!("cancel probe returned unexpected reply: {reply:?}"));
            }
            let group_exited = SystemProcessGroupController
                .probe(gate_identity)
                .await
                .map_err(|error| format!("probe canceled gate group: {error}"))?
                == ProcessObservation::Exited;
            let side_effect_absent = !vendor_prompt_path.exists() && !durable_ack_path.exists();
            blocker.release();
            wait_for_command_state(
                &store,
                &owner,
                conversation_id,
                command.command_id,
                CommandState::Canceled,
            )
            .await?;
            (true, side_effect_absent, group_exited)
        }
    };

    let vendor_prompt = if mode == ProbeMode::Complete {
        Some(
            fs::read_to_string(&vendor_prompt_path)
                .map_err(|error| format!("read vendor prompt marker: {error}"))?,
        )
    } else {
        None
    };
    let adapter_ack = if mode == ProbeMode::Complete {
        Some(
            fs::read_to_string(&durable_ack_path)
                .map_err(|error| format!("read durable ACK marker: {error}"))?,
        )
    } else {
        None
    };
    core.shutdown()
        .await
        .map_err(|error| format!("shutdown production probe core: {error:?}"))?;
    drop(core);
    drop(store);

    let reopened = RuntimeStoreHandle::open(
        config,
        load_or_create_storage_kek(&keys, &key_state)
            .map_err(|error| format!("reload probe StorageKEK: {error}"))?,
    )
    .await
    .map_err(|error| format!("reopen production probe store: {error}"))?;
    let receipt = reopened
        .query_command_receipt(QueryCommandReceipt {
            expected_owner: owner,
            selector: CommandReceiptSelector::Command {
                conversation_id,
                command_id: command.command_id,
            },
        })
        .await
        .map_err(|error| format!("query reopened probe command: {error}"))?;
    let (item_count, terminal_count) =
        count_reopened_events(&reopened, conversation_id, command.command_id, mode).await?;
    reopened
        .shutdown()
        .await
        .map_err(|error| format!("shutdown reopened probe store: {error}"))?;

    Ok(ProductionExecutionProbeEvidence {
        command_completed: receipt.state == CommandState::Completed,
        command_canceled: receipt.state == CommandState::Canceled,
        durable_item_count_after_reopen: item_count,
        durable_terminal_count_after_reopen: terminal_count,
        vendor_prompt_matched: vendor_prompt.as_deref() == Some(prompt),
        adapter_observed_durable_ack: adapter_ack.as_deref() == Some("durable-event-ack"),
        cancel_requested,
        vendor_side_effect_absent,
        gate_group_exited_after_cancel,
    })
}

async fn wait_for_command_state(
    store: &RuntimeStoreHandle,
    owner: &IdempotencyOwner,
    conversation_id: RuntimeId,
    command_id: RuntimeId,
    expected: CommandState,
) -> Result<CommandReceiptRecord, String> {
    tokio::time::timeout(PROBE_TIMEOUT, async {
        loop {
            let receipt = store
                .query_command_receipt(QueryCommandReceipt {
                    expected_owner: owner.clone(),
                    selector: CommandReceiptSelector::Command {
                        conversation_id,
                        command_id,
                    },
                })
                .await
                .map_err(|error| format!("query probe command: {error}"))?;
            if receipt.state == expected {
                return Ok::<CommandReceiptRecord, String>(receipt);
            }
            if receipt.state.is_terminal() {
                return Err(format!(
                    "probe command terminated as {:?}, expected {expected:?}",
                    receipt.state
                ));
            }
            tokio::time::sleep(Duration::from_millis(10)).await;
        }
    })
    .await
    .map_err(|_| format!("production execution probe timed out waiting for {expected:?}"))?
}

fn capture_single_current_binary_gate() -> Result<ProcessIdentity, String> {
    let children = current_direct_child_pids()?;
    let [leader_pid] = children.as_slice() else {
        return Err(format!(
            "cancel probe expected one current-binary gate child, found {children:?}"
        ));
    };
    ProcessIdentity::for_process_group_leader(i64::from(*leader_pid))
        .map_err(|error| format!("capture current-binary gate identity: {error}"))
}

fn read_started_turn_id(
    database: &std::path::Path,
    command_id: RuntimeId,
) -> Result<RuntimeId, String> {
    // PersistFenceBeforeCommit 故意阻塞唯一 Store writer；通过同一 actor 查询 receipt
    // 会排在 blocker 后形成 harness 自锁。只读 WAL 连接只读取此前已经 durable 的
    // Started/turn_id，不推进或伪造任何产品状态。
    let connection =
        rusqlite::Connection::open_with_flags(database, rusqlite::OpenFlags::SQLITE_OPEN_READ_ONLY)
            .map_err(|error| format!("open cancel probe DB read-only: {error}"))?;
    let (state, turn_bytes): (String, Vec<u8>) = connection
        .query_row(
            "SELECT state, turn_id FROM commands WHERE command_id = ?1",
            rusqlite::params![command_id.as_bytes().as_slice()],
            |row| Ok((row.get(0)?, row.get(1)?)),
        )
        .map_err(|error| format!("read cancel probe Started row: {error}"))?;
    if state != "started" {
        return Err(format!(
            "cancel probe command state changed before release: {state}"
        ));
    }
    let turn_bytes = <[u8; 16]>::try_from(turn_bytes.as_slice())
        .map_err(|_| "cancel probe turn id is not 16 bytes".to_owned())?;
    RuntimeId::from_bytes(RuntimeIdKind::Turn, turn_bytes)
        .map_err(|error| format!("decode cancel probe turn id: {error}"))
}

#[cfg(target_os = "macos")]
fn current_direct_child_pids() -> Result<Vec<i32>, String> {
    let parent = i32::try_from(std::process::id())
        .map_err(|_| "cancel probe parent pid does not fit pid_t".to_owned())?;
    let mut children = [0_i32; 16];
    let buffer_size = i32::try_from(std::mem::size_of_val(&children))
        .map_err(|_| "cancel probe child buffer is too large".to_owned())?;
    // SAFETY: `children` 是固定大小、正确对齐的 pid_t 输出缓冲区；libproc 只写入
    // `buffer_size` 范围，返回写入的 PID 数量。
    let count =
        unsafe { libc::proc_listchildpids(parent, children.as_mut_ptr().cast(), buffer_size) };
    if count < 0 {
        return Err(format!(
            "list current-binary gate child: {}",
            io::Error::last_os_error()
        ));
    }
    let count =
        usize::try_from(count).map_err(|_| "cancel probe child count is invalid".to_owned())?;
    if count > children.len() {
        return Err("cancel probe child list exceeded its fixed bound".to_owned());
    }
    Ok(children[..count]
        .iter()
        .copied()
        .filter(|pid| *pid > 1)
        .collect())
}

#[cfg(target_os = "linux")]
fn current_direct_child_pids() -> Result<Vec<i32>, String> {
    let mut children = Vec::new();
    let tasks = fs::read_dir("/proc/self/task")
        .map_err(|error| format!("list cancel probe threads: {error}"))?;
    for task in tasks {
        let task = task.map_err(|error| format!("read cancel probe thread entry: {error}"))?;
        let path = task.path().join("children");
        let content = fs::read_to_string(&path).map_err(|error| {
            format!(
                "read current-binary gate children from {}: {error}",
                path.display()
            )
        })?;
        for value in content.split_whitespace() {
            let pid = value
                .parse::<i32>()
                .map_err(|error| format!("parse current-binary gate child pid: {error}"))?;
            if pid > 1 {
                children.push(pid);
            }
        }
    }
    children.sort_unstable();
    children.dedup();
    Ok(children)
}

#[cfg(not(any(target_os = "macos", target_os = "linux")))]
fn current_direct_child_pids() -> Result<Vec<i32>, String> {
    Err("current-binary gate child enumeration is unsupported on this platform".to_owned())
}

async fn count_reopened_events(
    store: &RuntimeStoreHandle,
    conversation_id: RuntimeId,
    command_id: RuntimeId,
    mode: ProbeMode,
) -> Result<(usize, usize), String> {
    let RuntimeBackfillPlan::Pinned(pin) = store
        .acquire_backfill_pin(
            RuntimeBackfillTarget::Conversation(conversation_id),
            Some(0),
        )
        .await
        .map_err(|error| format!("pin reopened probe backfill: {error}"))?
    else {
        return Err("probe event suffix was unexpectedly empty".to_owned());
    };
    let mut after = Some(0);
    let mut item_count = 0_usize;
    let mut terminal_count = 0_usize;
    let command_id_text = command_id.to_canonical_string();
    loop {
        let page = store
            .load_event_backfill_page(pin.clone(), after)
            .await
            .map_err(|error| format!("load reopened probe backfill: {error}"))?;
        for event in &page.events {
            if event.command_id.as_ref().map(|id| id.as_str()) != Some(command_id_text.as_str()) {
                return Err("reopened probe event command binding changed".to_owned());
            }
            match (mode, &event.body) {
                (
                    ProbeMode::Complete,
                    RuntimeEventBody::Item {
                        item: AgentItem::AssistantMessage { text, .. },
                    },
                ) if text == HELPER_RESPONSE => item_count += 1,
                (ProbeMode::Complete, RuntimeEventBody::TurnCompleted { .. })
                | (ProbeMode::CancelBeforeRelease, RuntimeEventBody::TurnInterrupted { .. }) => {
                    terminal_count += 1;
                }
                (_, other) => {
                    return Err(format!("unexpected reopened probe event: {other:?}"));
                }
            }
        }
        let complete = page.complete;
        let next_after = page.next_after;
        let completion = page.completion().clone();
        drop(page);
        store
            .complete_backfill_page(completion)
            .await
            .map_err(|error| format!("complete reopened probe backfill: {error}"))?;
        if complete {
            return Ok((item_count, terminal_count));
        }
        after = Some(next_after);
    }
}

struct ProbeAgent {
    vendor_prompt_path: PathBuf,
    durable_ack_path: PathBuf,
}

#[async_trait::async_trait]
impl Agent for ProbeAgent {
    fn kind(&self) -> AgentKind {
        AgentKind::Codex
    }

    fn capabilities(&self) -> SessionCapabilities {
        SessionCapabilities {
            agent_kind: AgentKind::Codex,
            agent_version: "production-probe".to_owned(),
            features: Default::default(),
            vendor: VendorCapabilities::Codex(Default::default()),
        }
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
        let prompt = request.prompt().to_owned();
        let cwd = request.cwd().to_path_buf();
        let script = "IFS= read -r line || exit 31; printf '%s' \"$line\" > \"$1\"; printf '%s\\n' 'production-helper-response'";
        let spec = ExecSpec::new(
            &request,
            state,
            "/bin/sh",
            [
                OsString::from("-c"),
                OsString::from(script),
                OsString::from("agentdeck-production-probe"),
                self.vendor_prompt_path.as_os_str().to_owned(),
            ],
            cwd,
        )
        .map_err(|error| probe_error("probe-exec-spec", &error.to_string()))?;
        Ok(Box::new(ProbePreparedTurn {
            spec,
            prompt,
            durable_ack_path: self.durable_ack_path.clone(),
        }))
    }

    async fn start_session(
        &self,
        _start: SessionStart,
        _events: AgentEventSender,
    ) -> Result<AgentSessionHandle, ProtocolError> {
        Err(probe_error(
            "probe-legacy-disabled",
            "legacy start is disabled",
        ))
    }

    async fn continue_thread(
        &self,
        _thread_id: ThreadId,
        _cwd: PathBuf,
        _prompt: String,
        _events: AgentEventSender,
    ) -> Result<AgentSessionHandle, ProtocolError> {
        Err(probe_error(
            "probe-legacy-disabled",
            "legacy continue is disabled",
        ))
    }

    async fn submit_decision(
        &self,
        _session_id: &SessionId,
        _decision: ActionDecision,
    ) -> Result<(), ProtocolError> {
        Err(probe_error(
            "probe-legacy-disabled",
            "legacy approval is disabled",
        ))
    }

    async fn submit_vendor_control(
        &self,
        _session_id: &SessionId,
        _payload: VendorControlPayload,
    ) -> Result<(), ProtocolError> {
        Err(probe_error(
            "probe-legacy-disabled",
            "legacy vendor control is disabled",
        ))
    }

    async fn cancel(&self, _session_id: &SessionId) -> Result<(), ProtocolError> {
        Err(probe_error(
            "probe-legacy-disabled",
            "legacy cancel is disabled",
        ))
    }
}

struct ProbePreparedTurn {
    spec: ExecSpec,
    prompt: String,
    durable_ack_path: PathBuf,
}

impl PreparedAgentTurn for ProbePreparedTurn {
    fn exec_spec(&self) -> &ExecSpec {
        &self.spec
    }

    fn attach(
        self: Box<Self>,
        child: GatedChildIo,
        events: AdapterEventSink,
        _approvals: AdapterApprovalSink,
    ) -> Result<AdapterCompletionFuture, ProtocolError> {
        let Self {
            prompt,
            durable_ack_path,
            ..
        } = *self;
        let GatedChildIo {
            mut stdin,
            stdout,
            mut stderr,
        } = child;
        Ok(Box::pin(async move {
            let stderr_task = tokio::spawn(async move {
                let mut bytes = Vec::new();
                stderr.read_to_end(&mut bytes).await.map(|_| bytes)
            });
            stdin
                .write_all(prompt.as_bytes())
                .await
                .map_err(|error| probe_error("probe-stdin", &error.to_string()))?;
            stdin
                .write_all(b"\n")
                .await
                .map_err(|error| probe_error("probe-stdin", &error.to_string()))?;
            stdin
                .shutdown()
                .await
                .map_err(|error| probe_error("probe-stdin", &error.to_string()))?;

            let mut lines = BufReader::new(stdout).lines();
            let response = lines
                .next_line()
                .await
                .map_err(|error| probe_error("probe-stdout", &error.to_string()))?
                .ok_or_else(|| probe_error("probe-stdout", "helper produced no response"))?;
            if response != HELPER_RESPONSE {
                return Err(probe_error("probe-stdout", "helper response changed"));
            }
            if lines
                .next_line()
                .await
                .map_err(|error| probe_error("probe-stdout", &error.to_string()))?
                .is_some()
            {
                return Err(probe_error("probe-stdout", "helper produced extra output"));
            }
            events
                .send(AdapterEvent::Item {
                    key: AdapterItemKey::new("production-probe-item")?,
                    item: AgentItem::AssistantMessage {
                        text: response,
                        meta: AgentItemMeta::default(),
                    },
                })
                .await?;
            fs::write(&durable_ack_path, b"durable-event-ack")
                .map_err(|error| probe_error("probe-ack-marker", &error.to_string()))?;
            let stderr = stderr_task
                .await
                .map_err(|error| probe_error("probe-stderr", &error.to_string()))?
                .map_err(|error| probe_error("probe-stderr", &error.to_string()))?;
            if !stderr.is_empty() {
                return Err(probe_error("probe-stderr", "helper produced stderr"));
            }
            Ok(TurnSummary {
                total_input_tokens: Some(1),
                total_output_tokens: Some(1),
                elapsed_ms: 1,
            })
        }))
    }
}

fn runtime_id(kind: RuntimeIdKind, seed: u8) -> Result<RuntimeId, String> {
    RuntimeId::from_bytes(kind, [seed; 16])
        .map_err(|error| format!("construct probe {kind:?} id: {error}"))
}

fn probe_error(code: &str, message: &str) -> ProtocolError {
    ProtocolError {
        code: code.to_owned(),
        message: message.to_owned(),
        diagnostic_ref: None,
    }
}
