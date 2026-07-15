use std::ffi::OsString;
use std::fs;
use std::io;
use std::path::{Path, PathBuf};
use std::pin::Pin;
use std::process::Stdio;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, Mutex as StdMutex};
use std::task::{Context, Poll};
use std::time::Duration;

use agentdeck_protocol::runtime::PromptPayload;
use agentdeck_protocol::{
    ActionDecision, ActionDecisionKind, ActionKind, ActionRequest, ActionRequestVendor, AgentKind,
    CapabilityId, ClaudeCodePermissionMode, ThreadId,
};
use serde_json::{Value, json};
use tokio::io::AsyncWrite;
use tokio::process::{Child, Command};
use tokio::sync::Mutex;

use super::ClaudeCodeAdapter;
use super::driver::{
    ClaudeCodeBoundApprovalDelivery, ClaudeCodePreparedTurn, SharedClaudeCodeStdin,
};
use super::runtime_translate::ClaudeCodeApprovalRoute;
use super::state::ClaudeCodeStateRepository;
use crate::agent::{
    AdapterStateHandle, Agent, AgentTurnRequest, ExecSpec, ExecutionId, PreparedAgentTurn,
    adapter_approval_channel, adapter_event_channel, prepare_turn as prepare_agent_turn,
};
use crate::exec_gate::GatedChildIo;
use crate::runtime::approval::{
    ApprovalAttemptKey, ApprovalDeliveryOutcome, BoundApprovalDelivery,
};
use crate::runtime::store::{
    ConversationDescriptor, NewConversation, RuntimeId, RuntimeIdKind, RuntimeStoreConfig,
    RuntimeStoreHandle,
};
use crate::security::{MemoryKeyStore, load_or_create_storage_kek};

static NEXT_TEST_ID: AtomicU64 = AtomicU64::new(1);

struct TestStore {
    root: PathBuf,
    store: RuntimeStoreHandle,
}

impl TestStore {
    async fn open(label: &str) -> Self {
        let sequence = NEXT_TEST_ID.fetch_add(1, Ordering::Relaxed);
        let root = Path::new("/tmp").join(format!(
            "agentdeckd-cc-driver-{label}-{}-{sequence}",
            std::process::id()
        ));
        let _ = fs::remove_dir_all(&root);
        fs::create_dir(&root).expect("create CC driver test root");
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            fs::set_permissions(&root, fs::Permissions::from_mode(0o700))
                .expect("secure CC driver test root");
        }
        let keys = MemoryKeyStore::new();
        let storage_kek = load_or_create_storage_kek(&keys, &root.join("key-state.db"))
            .expect("load CC driver test StorageKEK");
        let store = RuntimeStoreHandle::open(
            RuntimeStoreConfig::new(root.join("runtime.db")),
            storage_kek,
        )
        .await
        .expect("open CC driver test store");
        store
            .create_conversation(NewConversation {
                conversation_id: runtime_id(RuntimeIdKind::Conversation, 13),
                adapter_state_key: runtime_id(RuntimeIdKind::AdapterState, 12),
                descriptor: ConversationDescriptor {
                    agent_kind: AgentKind::ClaudeCode,
                    title: Some("CC driver fixture".to_owned()),
                    cwd: std::env::current_dir().expect("CC driver cwd"),
                },
            })
            .await
            .expect("create CC driver conversation");
        Self { root, store }
    }

    async fn close(self) {
        self.store.shutdown().await.expect("shutdown CC test store");
        let _ = fs::remove_dir_all(self.root);
    }
}

#[tokio::test]
async fn canonical_adapter_capabilities_use_preseeded_version_without_vendor_probe() {
    let test = TestStore::open("canonical-capabilities").await;
    let adapter = ClaudeCodeAdapter::with_state_vault(
        crate::runtime::store::claude_code_adapter_state_vault_for_test(&test.store),
    );

    let capabilities = adapter.capabilities();
    assert_eq!(capabilities.agent_version, "claude unknown");
    assert!(capabilities.features.contains(&CapabilityId::Approval));
    assert!(
        !capabilities
            .features
            .contains(&CapabilityId::CodexApprovalPersistence)
    );

    test.close().await;
}

#[test]
fn legacy_adapter_keeps_speculative_permission_wire_hidden() {
    let capabilities = ClaudeCodeAdapter::new_for_test().capabilities();
    assert!(!capabilities.features.contains(&CapabilityId::Approval));
}

#[tokio::test]
async fn attach_is_cold_and_state_mismatch_prevents_prompt_io() {
    let test = TestStore::open("cold").await;
    let log = test.root.join("wire.jsonl");
    let (io, mut child) = spawn_peer(&log, LOG_ONLY_PEER);
    let mut prepared = prepared_turn(&test.store, "private prompt").await;
    prepared.expected_native_session = ThreadId("different-session".to_owned());
    let (events, _event_receiver) = adapter_event_channel();
    let (approvals, _approval_receiver) = adapter_approval_channel();
    let completion = Box::new(prepared)
        .attach(io, events, approvals)
        .expect("attach returns cold future");
    tokio::time::sleep(Duration::from_millis(100)).await;
    assert!(!log.exists());

    let error = completion
        .await
        .expect_err("state mismatch must fail before prompt write");
    assert_eq!(error.code, "cc-state-readback-mismatch");
    assert!(!log.exists());
    tokio::time::timeout(Duration::from_secs(2), child.wait())
        .await
        .expect("log-only peer exits")
        .expect("wait log-only peer");
    test.close().await;
}

#[tokio::test]
async fn authoritative_init_and_durable_ack_gate_completion() {
    let test = TestStore::open("ack").await;
    let log = test.root.join("wire.jsonl");
    let (io, mut child) = spawn_peer(&log, SUCCESS_PEER);
    let prepared = prepared_turn(&test.store, "fixture prompt").await;
    let (events, mut event_receiver) = adapter_event_channel();
    let (approvals, _approval_receiver) = adapter_approval_channel();
    let completion = Box::new(prepared)
        .attach(io, events, approvals)
        .expect("attach scripted CC peer");
    let mut task = tokio::spawn(completion);
    let delivery = tokio::time::timeout(Duration::from_secs(5), event_receiver.recv())
        .await
        .expect("CC item arrives")
        .expect("CC event channel open");
    let prompt: Value =
        serde_json::from_str(fs::read_to_string(&log).expect("read CC prompt log").trim())
            .expect("decode private prompt line");
    assert_eq!(prompt["type"], "user");
    assert_eq!(prompt["message"]["content"], "fixture prompt");
    assert!(
        tokio::time::timeout(Duration::from_millis(100), &mut task)
            .await
            .is_err(),
        "CC completion must wait for durable item ACK"
    );
    let (_, acknowledgement) = delivery.into_parts();
    acknowledgement.acknowledge(Ok(()));
    let summary = tokio::time::timeout(Duration::from_secs(5), task)
        .await
        .expect("CC completion after ACK")
        .expect("CC driver task joins")
        .expect("CC typed turn succeeds");
    assert_eq!(summary.elapsed_ms, 34);
    tokio::time::timeout(Duration::from_secs(2), child.wait())
        .await
        .expect("success peer exits")
        .expect("wait success peer");
    test.close().await;
}

#[tokio::test]
async fn mismatched_system_init_fails_before_any_adapter_event() {
    let test = TestStore::open("identity").await;
    let log = test.root.join("wire.jsonl");
    let (io, mut child) = spawn_peer(&log, MISMATCH_PEER);
    let prepared = prepared_turn(&test.store, "identity prompt").await;
    let (events, mut event_receiver) = adapter_event_channel();
    let (approvals, _approval_receiver) = adapter_approval_channel();
    let error = Box::new(prepared)
        .attach(io, events, approvals)
        .expect("attach mismatch CC peer")
        .await
        .expect_err("mismatched CC identity must fail closed");
    assert_eq!(error.code, "cc-session-identity-mismatch");
    assert!(event_receiver.recv().await.is_none());
    tokio::time::timeout(Duration::from_secs(2), child.wait())
        .await
        .expect("mismatch peer exits")
        .expect("wait mismatch peer");
    test.close().await;
}

#[tokio::test]
async fn typed_prepare_reuses_unmaterialized_session_id_without_spawning_preflight() {
    if which::which("claude").is_err() {
        return;
    }
    let test = TestStore::open("prepare").await;
    let adapter = ClaudeCodeAdapter::with_state_vault(
        crate::runtime::store::claude_code_adapter_state_vault_for_test(&test.store),
    );
    let state = AdapterStateHandle::new(runtime_id(RuntimeIdKind::AdapterState, 12)).unwrap();
    let first = prepare_agent_turn(&adapter, request(14, "prompt-one"), state)
        .await
        .expect("first CC typed prepare");
    let first_args = first
        .checked_exec_spec()
        .expect("first checked spec")
        .non_sensitive_args()
        .to_vec();
    let first_id = flag_value(&first_args, "--session-id");
    assert!(first.checked_exec_spec().unwrap().program().is_absolute());
    assert!(!first_args.iter().any(|arg| arg == "prompt-one"));
    // 威胁场景：production CC 若主动请求 partial message / hook opt-in，真实 CLI 会
    // 产生没有录制依据的 stream/hook frame，使本应可用的普通 turn 在 translator fail-close。
    assert!(
        !first_args
            .iter()
            .any(|arg| arg == "--include-partial-messages")
    );
    assert!(!first_args.iter().any(|arg| arg == "--include-hook-events"));
    assert_eq!(
        flag_value(&first_args, "--permission-prompt-tool"),
        OsString::from("stdio")
    );
    drop(first);

    let second = prepare_agent_turn(&adapter, request(15, "prompt-two"), state)
        .await
        .expect("retry CC typed prepare");
    let second_args = second
        .checked_exec_spec()
        .expect("second checked spec")
        .non_sensitive_args()
        .to_vec();
    assert_eq!(flag_value(&second_args, "--session-id"), first_id);
    assert!(!second_args.iter().any(|arg| arg == "--resume"));
    assert!(!second_args.iter().any(|arg| arg == "prompt-two"));
    drop(second);
    test.close().await;
}

#[tokio::test]
async fn recorded_control_request_waits_for_durable_registration_then_writes_exact_deny() {
    // 威胁场景：driver 若在 conversation durable registration ACK 前写 permission
    // response，CLI 可执行命令而 Store 中没有可审计 ActionRequest；反之 terminal 也
    // 必须等 registration 与完整 response write/newline/flush 都完成。
    let test = TestStore::open("approval-registration").await;
    let log = test.root.join("wire.jsonl");
    let (io, mut child) = spawn_peer(&log, APPROVAL_PEER);
    let prepared = prepared_turn(&test.store, "approval prompt").await;
    let (events, _event_receiver) = adapter_event_channel();
    let (approvals, mut approval_receiver) = adapter_approval_channel();
    let completion = Box::new(prepared)
        .attach(io, events, approvals)
        .expect("attach approval peer");
    let mut task = tokio::spawn(completion);

    let delivery = tokio::time::timeout(Duration::from_secs(5), approval_receiver.recv())
        .await
        .expect("CC approval arrives")
        .expect("CC approval channel open");
    let (request, delivery, registration_ack) = delivery.into_parts();
    assert_eq!(request.request_id, "cc-request-fixture-1");
    assert_eq!(request.kind, ActionKind::ExecuteCommand);
    assert_eq!(
        request.summary,
        "Claude Code 请求执行命令：\"printf approval-action-visible\""
    );
    assert!(
        tokio::time::timeout(Duration::from_millis(100), &mut task)
            .await
            .is_err(),
        "driver must wait for durable approval registration"
    );
    assert_eq!(
        fs::read_to_string(&log)
            .expect("read pre-registration wire")
            .lines()
            .count(),
        1,
        "only the private prompt may be written before registration ACK"
    );
    registration_ack.acknowledge(Ok(()));
    assert_eq!(
        delivery
            .deliver(
                approval_key(0x41),
                &approval_decision("cc-request-fixture-1", ActionDecisionKind::Deny, false,),
            )
            .await,
        ApprovalDeliveryOutcome::AppliedAck
    );

    let summary = tokio::time::timeout(Duration::from_secs(5), task)
        .await
        .expect("CC approval completion timeout")
        .expect("CC approval task joins")
        .expect("denied CC turn returns modeled result");
    assert_eq!(summary.elapsed_ms, 55);
    tokio::time::timeout(Duration::from_secs(2), child.wait())
        .await
        .expect("approval peer exits")
        .expect("wait approval peer");
    let wire = fs::read_to_string(&log).expect("read approval wire");
    let frames = wire
        .lines()
        .map(|line| serde_json::from_str::<Value>(line).expect("decode approval wire frame"))
        .collect::<Vec<_>>();
    assert_eq!(frames.len(), 2);
    assert_eq!(
        frames[1],
        json!({
            "type": "control_response",
            "response": {
                "subtype": "success",
                "request_id": "cc-request-fixture-1",
                "response": {
                    "behavior": "deny",
                    "message": "Denied by AgentDeck",
                    "interrupt": false,
                    "toolUseID": "toolu_fixture_1"
                }
            }
        })
    );
    test.close().await;
}

#[tokio::test]
async fn dropping_registered_approval_route_does_not_complete_the_waiting_driver() {
    // 威胁场景：actor 在 deadline 后只 drop transient route，却没有 fence execution；
    // Claude Code 仍在等待 control_response，driver 不能把 route drop 误判成 turn 完成。
    let test = TestStore::open("approval-route-drop").await;
    let log = test.root.join("wire.jsonl");
    let (io, mut child) = spawn_peer(&log, APPROVAL_PEER);
    let prepared = prepared_turn(&test.store, "approval route drop prompt").await;
    let (events, _event_receiver) = adapter_event_channel();
    let (approvals, mut approval_receiver) = adapter_approval_channel();
    let completion = Box::new(prepared)
        .attach(io, events, approvals)
        .expect("attach route-drop CC peer");
    let mut task = tokio::spawn(completion);

    let registration = tokio::time::timeout(Duration::from_secs(5), approval_receiver.recv())
        .await
        .expect("CC route-drop approval arrives")
        .expect("CC route-drop approval channel open");
    let (_request, delivery, registration_ack) = registration.into_parts();
    registration_ack.acknowledge(Ok(()));
    drop(delivery);

    assert!(
        tokio::time::timeout(Duration::from_millis(100), &mut task)
            .await
            .is_err(),
        "dropping the route must not synthesize a CC control_response or complete the turn"
    );
    assert_eq!(
        fs::read_to_string(&log)
            .expect("read CC route-drop wire")
            .lines()
            .count(),
        1,
        "only the private prompt may be written without an authenticated decision"
    );

    task.abort();
    let _ = task.await;
    tokio::time::timeout(Duration::from_secs(2), child.wait())
        .await
        .expect("CC route-drop peer exits after driver cancellation")
        .expect("wait CC route-drop peer");
    test.close().await;
}

#[tokio::test]
async fn bound_approval_is_single_flight_and_persist_false_only() {
    let probe = WriterProbe::success();
    let delivery = approval_delivery(probe.writer());
    let key = approval_key(0x42);
    let approve = approval_decision("cc-request-fixture-1", ActionDecisionKind::Approve, false);
    assert_eq!(
        delivery.deliver(key, &approve).await,
        ApprovalDeliveryOutcome::AppliedAck
    );
    let first = probe.bytes();
    let frame: Value = serde_json::from_slice(first.strip_suffix(b"\n").expect("JSONL newline"))
        .expect("decode allow response");
    assert_eq!(
        frame,
        json!({
            "type": "control_response",
            "response": {
                "subtype": "success",
                "request_id": "cc-request-fixture-1",
                "response": {"behavior": "allow"}
            }
        })
    );
    assert_eq!(
        delivery.deliver(key, &approve).await,
        ApprovalDeliveryOutcome::AppliedAck
    );
    assert_eq!(
        probe.bytes(),
        first,
        "idempotent replay must not write twice"
    );
    assert_eq!(
        delivery.deliver(approval_key(0x43), &approve).await,
        ApprovalDeliveryOutcome::PermanentlyRejected
    );

    let persist_probe = WriterProbe::success();
    let persist_delivery = approval_delivery(persist_probe.writer());
    assert_eq!(
        persist_delivery
            .deliver(
                approval_key(0x44),
                &approval_decision("cc-request-fixture-1", ActionDecisionKind::Approve, true,),
            )
            .await,
        ApprovalDeliveryOutcome::PermanentlyRejected
    );
    assert!(persist_probe.bytes().is_empty());

    let wrong_request_probe = WriterProbe::success();
    let wrong_request_delivery = approval_delivery(wrong_request_probe.writer());
    assert_eq!(
        wrong_request_delivery
            .deliver(
                approval_key(0x46),
                &approval_decision("other-request", ActionDecisionKind::Deny, false),
            )
            .await,
        ApprovalDeliveryOutcome::PermanentlyRejected
    );
    assert!(wrong_request_probe.bytes().is_empty());
}

#[test]
fn bound_approval_constructor_rejects_mismatched_transient_route() {
    let probe = WriterProbe::success();
    let mut route = approval_route();
    route.tool_name = "Read".to_owned();
    let error =
        match ClaudeCodeBoundApprovalDelivery::new(approval_request(), route, probe.writer()) {
            Ok(_) => panic!("tool identity mismatch must fail before registration"),
            Err(error) => error,
        };
    assert_eq!(error.code, "cc-approval-route-invalid");
    assert!(probe.bytes().is_empty());
}

#[tokio::test]
async fn partial_or_flush_failure_is_sticky_outcome_unknown_without_route_loss() {
    for probe in [WriterProbe::partial(12), WriterProbe::flush_failure()] {
        let delivery = approval_delivery(probe.writer());
        let key = approval_key(0x45);
        let deny = approval_decision("cc-request-fixture-1", ActionDecisionKind::Deny, false);
        assert_eq!(
            delivery.deliver(key, &deny).await,
            ApprovalDeliveryOutcome::OutcomeUnknown
        );
        let first = probe.bytes();
        assert_eq!(
            delivery.deliver(key, &deny).await,
            ApprovalDeliveryOutcome::OutcomeUnknown
        );
        assert_eq!(
            probe.bytes(),
            first,
            "unknown delivery keeps its exact route but never auto-retries IO"
        );
    }
}

async fn prepared_turn(store: &RuntimeStoreHandle, prompt: &str) -> ClaudeCodePreparedTurn {
    let repository = ClaudeCodeStateRepository::new_for_test(store.clone());
    let adapter_state_key = runtime_id(RuntimeIdKind::AdapterState, 12);
    let native = ThreadId("cc-fixture-session".to_owned());
    repository
        .bind(adapter_state_key, native.clone())
        .await
        .expect("bind CC driver fixture state");
    let cwd = std::env::current_dir().expect("CC driver cwd");
    let request = AgentTurnRequest::new(
        ExecutionId::from_command_id(runtime_id(RuntimeIdKind::Command, 11)).unwrap(),
        cwd.clone(),
        PromptPayload::new(prompt).unwrap(),
    )
    .unwrap();
    let state = AdapterStateHandle::new(adapter_state_key).unwrap();
    let exec_spec = ExecSpec::new(
        &request,
        state,
        "/usr/bin/true",
        Vec::<OsString>::new(),
        cwd,
    )
    .unwrap();
    ClaudeCodePreparedTurn {
        exec_spec,
        repository,
        adapter_state_key,
        expected_native_session: native,
        prompt: prompt.to_owned(),
    }
}

fn request(seed: u8, prompt: &str) -> AgentTurnRequest {
    AgentTurnRequest::new(
        ExecutionId::from_command_id(runtime_id(RuntimeIdKind::Command, seed)).unwrap(),
        std::env::current_dir().expect("CC prepare cwd"),
        PromptPayload::new(prompt).unwrap(),
    )
    .unwrap()
}

fn flag_value(args: &[OsString], flag: &str) -> OsString {
    let index = args
        .iter()
        .position(|arg| arg == flag)
        .expect("flag exists");
    args.get(index + 1).expect("flag value exists").clone()
}

fn spawn_peer(log: &Path, script: &str) -> (GatedChildIo, Child) {
    let mut command = Command::new("/bin/sh");
    command
        .arg("-c")
        .arg(script)
        .env("AGENTDECK_CC_DRIVER_LOG", log)
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped());
    let mut child = command.spawn().expect("spawn scripted CC peer");
    let io = GatedChildIo {
        stdin: child.stdin.take().expect("CC peer stdin"),
        stdout: child.stdout.take().expect("CC peer stdout"),
        stderr: child.stderr.take().expect("CC peer stderr"),
    };
    (io, child)
}

fn runtime_id(kind: RuntimeIdKind, seed: u8) -> RuntimeId {
    RuntimeId::from_bytes(kind, [seed; 16]).expect("non-zero runtime id")
}

fn approval_delivery(stdin: SharedClaudeCodeStdin) -> ClaudeCodeBoundApprovalDelivery {
    ClaudeCodeBoundApprovalDelivery::new(approval_request(), approval_route(), stdin)
        .expect("construct bound CC approval delivery")
}

fn approval_request() -> ActionRequest {
    ActionRequest {
        request_id: "cc-request-fixture-1".to_owned(),
        kind: ActionKind::ExecuteCommand,
        summary: "Claude Code 请求执行命令".to_owned(),
        vendor: ActionRequestVendor::ClaudeCode {
            permission_mode_at_decision: ClaudeCodePermissionMode::Default,
            tool_name: "Bash".to_owned(),
        },
    }
}

fn approval_route() -> ClaudeCodeApprovalRoute {
    ClaudeCodeApprovalRoute {
        request_id: "cc-request-fixture-1".to_owned(),
        tool_use_id: "toolu_fixture_1".to_owned(),
        tool_name: "Bash".to_owned(),
    }
}

fn approval_decision(
    request_id: &str,
    decision: ActionDecisionKind,
    persist: bool,
) -> ActionDecision {
    ActionDecision {
        request_id: request_id.to_owned(),
        decision,
        persist,
    }
}

fn approval_key(seed: u8) -> ApprovalAttemptKey {
    ApprovalAttemptKey {
        approval_id: runtime_id(RuntimeIdKind::Approval, seed),
        delivery_round: 1,
        attempt: 0,
    }
}

#[derive(Clone)]
struct WriterProbe {
    bytes: Arc<StdMutex<Vec<u8>>>,
    fail_after: Option<usize>,
    fail_flush: bool,
}

impl WriterProbe {
    fn success() -> Self {
        Self {
            bytes: Arc::new(StdMutex::new(Vec::new())),
            fail_after: None,
            fail_flush: false,
        }
    }

    fn partial(fail_after: usize) -> Self {
        Self {
            bytes: Arc::new(StdMutex::new(Vec::new())),
            fail_after: Some(fail_after),
            fail_flush: false,
        }
    }

    fn flush_failure() -> Self {
        Self {
            bytes: Arc::new(StdMutex::new(Vec::new())),
            fail_after: None,
            fail_flush: true,
        }
    }

    fn writer(&self) -> SharedClaudeCodeStdin {
        Arc::new(Mutex::new(Box::new(self.clone())))
    }

    fn bytes(&self) -> Vec<u8> {
        self.bytes.lock().expect("writer probe lock").clone()
    }
}

impl AsyncWrite for WriterProbe {
    fn poll_write(
        self: Pin<&mut Self>,
        _context: &mut Context<'_>,
        buffer: &[u8],
    ) -> Poll<io::Result<usize>> {
        let mut bytes = self.bytes.lock().expect("writer probe lock");
        if let Some(limit) = self.fail_after {
            if bytes.len() >= limit {
                return Poll::Ready(Err(io::Error::other("injected partial write")));
            }
            let count = buffer.len().min(limit - bytes.len());
            bytes.extend_from_slice(&buffer[..count]);
            return Poll::Ready(Ok(count));
        }
        bytes.extend_from_slice(buffer);
        Poll::Ready(Ok(buffer.len()))
    }

    fn poll_flush(self: Pin<&mut Self>, _context: &mut Context<'_>) -> Poll<io::Result<()>> {
        if self.fail_flush {
            Poll::Ready(Err(io::Error::other("injected flush failure")))
        } else {
            Poll::Ready(Ok(()))
        }
    }

    fn poll_shutdown(self: Pin<&mut Self>, _context: &mut Context<'_>) -> Poll<io::Result<()>> {
        Poll::Ready(Ok(()))
    }
}

const LOG_ONLY_PEER: &str = r#"
while IFS= read -r line; do
  printf '%s\n' "$line" >> "$AGENTDECK_CC_DRIVER_LOG"
done
"#;

const SUCCESS_PEER: &str = r#"
if IFS= read -r line; then
  printf '%s\n' "$line" >> "$AGENTDECK_CC_DRIVER_LOG"
  printf '%s\n' '{"type":"system","subtype":"init","session_id":"cc-fixture-session"}'
  printf '%s\n' '{"type":"assistant","message":{"content":[{"type":"text","text":"fixture"}]},"session_id":"cc-fixture-session"}'
  printf '%s\n' '{"type":"result","subtype":"success","is_error":false,"duration_ms":34,"terminal_reason":"completed","session_id":"cc-fixture-session","usage":{"input_tokens":1,"output_tokens":2}}'
fi
"#;

const APPROVAL_PEER: &str = r#"
if IFS= read -r line; then
  printf '%s\n' "$line" >> "$AGENTDECK_CC_DRIVER_LOG"
  printf '%s\n' '{"type":"system","subtype":"init","session_id":"cc-fixture-session"}'
  printf '%s\n' '{"type":"control_request","request_id":"cc-request-fixture-1","request":{"subtype":"can_use_tool","tool_name":"Bash","display_name":"Bash","input":{"command":"printf approval-action-visible"},"description":"raw-description-must-not-persist","permission_suggestions":[],"blocked_path":"/fixture/raw-path-must-not-persist","tool_use_id":"toolu_fixture_1"},"session_id":"cc-fixture-session"}'
  if IFS= read -r response; then
    printf '%s\n' "$response" >> "$AGENTDECK_CC_DRIVER_LOG"
    printf '%s\n' '{"type":"result","subtype":"success","is_error":false,"duration_ms":55,"terminal_reason":"completed","session_id":"cc-fixture-session","permission_denials":[{"tool_name":"Bash","tool_use_id":"toolu_fixture_1"}]}'
  fi
fi
"#;

const MISMATCH_PEER: &str = r#"
if IFS= read -r line; then
  printf '%s\n' "$line" >> "$AGENTDECK_CC_DRIVER_LOG"
  printf '%s\n' '{"type":"system","subtype":"init","session_id":"wrong-session"}'
fi
"#;
