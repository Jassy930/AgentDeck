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

use agentdeck_protocol::ThreadId;
use agentdeck_protocol::runtime::{
    CodexConversationConfiguration, ConversationConfiguration, PromptPayload,
    VendorConfigurationSnapshot,
};
use agentdeck_protocol::{
    ActionDecision, ActionDecisionKind, ActionKind, ActionRequest, ActionRequestVendor, AgentKind,
    CodexApprovalPolicy, CodexReasoningEffort, CodexSandboxMode,
};
use serde_json::{Value, json};
use tokio::io::AsyncWrite;
use tokio::process::{Child, Command};
use tokio::sync::Mutex;

use super::CodexAdapter;
use super::driver::{
    CodexBoundApprovalDelivery, CodexPreparedTurn, SharedCodexStdin, validate_initialize_version,
};
use super::runtime_translate::CodexApprovalRoute;
use super::state::CodexStateRepository;
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

#[test]
fn initialize_version_gate_accepts_exact_version_for_any_nonempty_originator() {
    for user_agent in [
        "agentdeck/0.144.1 (test)",
        "Codex Desktop/0.144.1 (test override)",
    ] {
        validate_initialize_version(&json!({"userAgent": user_agent}))
            .expect("exact schema version");
    }
    let mismatch = validate_initialize_version(&json!({
        "userAgent": "agentdeck/0.145.0 (future)"
    }))
    .expect_err("future schema drift must fail before thread/start");
    assert_eq!(mismatch.code, "codex-version-mismatch");
}

struct TestStore {
    root: PathBuf,
    store: RuntimeStoreHandle,
}

impl TestStore {
    async fn open(label: &str) -> Self {
        let sequence = NEXT_TEST_ID.fetch_add(1, Ordering::Relaxed);
        let root = Path::new("/tmp").join(format!(
            "agentdeckd-codex-driver-{label}-{}-{sequence}",
            std::process::id()
        ));
        let _ = fs::remove_dir_all(&root);
        fs::create_dir(&root).expect("create Codex driver test root");
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            fs::set_permissions(&root, fs::Permissions::from_mode(0o700))
                .expect("secure Codex driver test root");
        }
        let keys = MemoryKeyStore::new();
        let storage_kek = load_or_create_storage_kek(&keys, &root.join("key-state.db"))
            .expect("load Codex driver test StorageKEK");
        let store = RuntimeStoreHandle::open(
            RuntimeStoreConfig::new(root.join("runtime.db")),
            storage_kek,
        )
        .await
        .expect("open Codex driver test store");
        store
            .create_conversation(NewConversation {
                conversation_id: runtime_id(RuntimeIdKind::Conversation, 3),
                adapter_state_key: runtime_id(RuntimeIdKind::AdapterState, 2),
                descriptor: ConversationDescriptor {
                    agent_kind: AgentKind::Codex,
                    title: Some("Codex driver fixture".to_owned()),
                    cwd: std::env::current_dir().expect("driver test cwd"),
                },
            })
            .await
            .expect("create Codex driver conversation");
        Self { root, store }
    }

    async fn close(self) {
        self.store
            .shutdown()
            .await
            .expect("shutdown Codex driver test store");
        let _ = fs::remove_dir_all(self.root);
    }
}

#[tokio::test]
async fn canonical_adapter_capabilities_use_preseeded_version_without_vendor_probe() {
    let test = TestStore::open("canonical-capabilities").await;
    let adapter = CodexAdapter::with_state_vault(test.store.codex_adapter_state_vault_for_test());

    let capabilities = adapter.capabilities();
    assert_eq!(capabilities.agent_version, "codex-cli 0.144.1");

    test.close().await;
}

#[tokio::test]
async fn attach_is_cold_and_does_not_write_before_first_poll() {
    let test = TestStore::open("cold-attach").await;
    let log = test.root.join("wire.jsonl");
    let (io, mut child) = spawn_scripted_peer(
        &log,
        r#"
while IFS= read -r line; do
  printf '%s\n' "$line" >> "$AGENTDECK_CODEX_DRIVER_LOG"
done
"#,
    );
    let (prepared, _) = prepared_turn(&test.store, "must-not-be-written");
    let (events, _event_receiver) = adapter_event_channel();
    let (approvals, _approval_receiver) = adapter_approval_channel();

    let completion = Box::new(prepared)
        .attach(io, events, approvals)
        .expect("attach must only construct a cold future");
    tokio::time::sleep(Duration::from_millis(100)).await;
    assert!(
        !log.exists() || fs::read(&log).expect("read cold wire log").is_empty(),
        "attach without polling must perform zero vendor IO"
    );

    drop(completion);
    tokio::time::timeout(Duration::from_secs(2), child.wait())
        .await
        .expect("cold peer exits after pipes close")
        .expect("wait cold peer");
    test.close().await;
}

#[tokio::test]
async fn typed_prepare_uses_only_absolute_codex_and_app_server_argv() {
    if which::which("codex").is_err() {
        return;
    }
    let test = TestStore::open("typed-prepare").await;
    let adapter = CodexAdapter::with_state_vault(test.store.codex_adapter_state_vault_for_test());
    let execution_id = ExecutionId::from_command_id(runtime_id(RuntimeIdKind::Command, 4))
        .expect("typed prepare execution");
    let cwd = std::env::current_dir().expect("typed prepare cwd");
    let request = AgentTurnRequest::new(
        execution_id,
        cwd.clone(),
        PromptPayload::new("prompt-sentinel-must-stay-private").unwrap(),
        41,
        codex_configuration(),
    )
    .expect("typed prepare request");
    let state = AdapterStateHandle::new(runtime_id(RuntimeIdKind::AdapterState, 2))
        .expect("typed prepare state");
    let prepared = prepare_agent_turn(&adapter, request, state)
        .await
        .expect("Codex typed prepare");
    let spec = prepared
        .checked_exec_spec()
        .expect("checked Codex exec spec");
    assert!(spec.program().is_absolute());
    assert_eq!(spec.cwd(), cwd);
    assert_eq!(spec.non_sensitive_args(), [OsString::from("app-server")]);
    assert!(
        !spec
            .non_sensitive_args()
            .iter()
            .any(|value| value.to_string_lossy().contains("prompt-sentinel"))
    );
    drop(prepared);
    test.close().await;
}

#[tokio::test]
async fn durable_event_ack_blocks_completion_and_state_is_bound_before_prompt() {
    let test = TestStore::open("ack-order").await;
    let log = test.root.join("wire.jsonl");
    let (io, mut child) = spawn_scripted_peer(&log, CODEX_SUCCESS_PEER);
    let (prepared, adapter_state_key) = prepared_turn(&test.store, "fixture prompt");
    let repository = CodexStateRepository::new(test.store.codex_adapter_state_vault_for_test());
    let (events, mut event_receiver) = adapter_event_channel();
    let (approvals, _approval_receiver) = adapter_approval_channel();
    let completion = Box::new(prepared)
        .attach(io, events, approvals)
        .expect("attach scripted Codex peer");
    let mut task = tokio::spawn(completion);

    let delivery = tokio::time::timeout(Duration::from_secs(5), event_receiver.recv())
        .await
        .expect("typed item arrives");
    let delivery = match delivery {
        Some(delivery) => delivery,
        None => {
            let result = (&mut task).await;
            panic!(
                "event channel closed before item: result={result:?}, wire={:?}",
                fs::read_to_string(&log)
            );
        }
    };
    assert_eq!(
        repository
            .resolve(adapter_state_key)
            .await
            .expect("read exact Codex state")
            .expect("fresh thread is durably bound")
            .0,
        "fixture-thread"
    );
    let wire = fs::read_to_string(&log).expect("read scripted wire log");
    let requests = wire
        .lines()
        .map(|line| serde_json::from_str::<Value>(line).expect("decode outbound request"))
        .collect::<Vec<_>>();
    assert_eq!(requests.len(), 3);
    assert_eq!(requests[0]["method"], "initialize");
    assert_eq!(
        requests[0]["params"]["capabilities"]["requestAttestation"],
        false
    );
    assert!(
        requests[0]["params"]["capabilities"]["optOutNotificationMethods"]
            .as_array()
            .is_some_and(|methods| methods
                .iter()
                .any(|method| method == "remoteControl/status/changed"))
    );
    assert_eq!(requests[1]["method"], "thread/start");
    assert_eq!(requests[1]["params"]["sandbox"], "read-only");
    assert_eq!(requests[1]["params"]["approvalPolicy"], "untrusted");
    assert_eq!(requests[2]["method"], "turn/start");
    assert_eq!(requests[2]["params"]["input"][0]["text"], "fixture prompt");
    assert_eq!(requests[2]["params"]["effort"], "high");
    assert!(
        tokio::time::timeout(Duration::from_millis(100), &mut task)
            .await
            .is_err(),
        "turn completion must remain pending until Store COMMIT ACK"
    );

    let (_, acknowledgement) = delivery.into_parts();
    acknowledgement.acknowledge(Ok(()));
    let summary = tokio::time::timeout(Duration::from_secs(5), task)
        .await
        .expect("completion after durable ACK")
        .expect("driver task joins")
        .expect("typed Codex turn succeeds");
    assert_eq!(summary.elapsed_ms, 12);
    tokio::time::timeout(Duration::from_secs(2), child.wait())
        .await
        .expect("scripted peer exits")
        .expect("wait scripted peer");
    drop(repository);
    test.close().await;
}

#[tokio::test]
async fn resume_reasserts_cwd_sandbox_and_approval_policy() {
    let test = TestStore::open("resume-policy").await;
    let log = test.root.join("wire.jsonl");
    let (io, mut child) = spawn_scripted_peer(&log, CODEX_RESUME_PEER);
    let (mut prepared, adapter_state_key) = prepared_turn(&test.store, "resume prompt");
    let expected = ThreadId("fixture-thread".to_owned());
    prepared
        .repository
        .bind(adapter_state_key, expected.clone())
        .await
        .expect("bind resume fixture state");
    prepared.resume_thread_id = Some(expected);
    let (events, _event_receiver) = adapter_event_channel();
    let (approvals, _approval_receiver) = adapter_approval_channel();
    let summary = Box::new(prepared)
        .attach(io, events, approvals)
        .expect("attach resume peer")
        .await
        .expect("resume turn succeeds");
    assert_eq!(summary.elapsed_ms, 21);

    let requests = fs::read_to_string(&log)
        .expect("read resume wire")
        .lines()
        .map(|line| serde_json::from_str::<Value>(line).expect("decode resume request"))
        .collect::<Vec<_>>();
    assert_eq!(requests.len(), 3);
    assert_eq!(requests[1]["method"], "thread/resume");
    assert_eq!(requests[1]["params"]["threadId"], "fixture-thread");
    assert_eq!(requests[1]["params"]["sandbox"], "read-only");
    assert_eq!(requests[1]["params"]["approvalPolicy"], "untrusted");
    assert_eq!(requests[2]["method"], "turn/start");
    assert_eq!(requests[2]["params"]["effort"], "high");
    assert_eq!(
        requests[1]["params"]["cwd"],
        Value::String(
            std::env::current_dir()
                .unwrap()
                .to_string_lossy()
                .into_owned()
        )
    );
    tokio::time::timeout(Duration::from_secs(2), child.wait())
        .await
        .expect("resume peer exits")
        .expect("wait resume peer");
    test.close().await;
}

#[tokio::test]
async fn resume_requires_official_nested_thread_identity_shape() {
    let test = TestStore::open("resume-identity-shape").await;
    let log = test.root.join("wire.jsonl");
    let (io, mut child) = spawn_scripted_peer(&log, CODEX_LEGACY_RESUME_IDENTITY_PEER);
    let (mut prepared, adapter_state_key) = prepared_turn(&test.store, "resume prompt");
    let expected = ThreadId("fixture-thread".to_owned());
    prepared
        .repository
        .bind(adapter_state_key, expected.clone())
        .await
        .expect("bind resume fixture state");
    prepared.resume_thread_id = Some(expected);
    let (events, mut event_receiver) = adapter_event_channel();
    let (approvals, _approval_receiver) = adapter_approval_channel();
    let error = Box::new(prepared)
        .attach(io, events, approvals)
        .expect("attach legacy resume identity peer")
        .await
        .expect_err("non-schema threadId fallback must fail closed");
    assert_eq!(error.code, "codex-resume-identity-missing");
    assert!(event_receiver.recv().await.is_none());
    tokio::time::timeout(Duration::from_secs(2), child.wait())
        .await
        .expect("legacy resume identity peer exits")
        .expect("wait legacy resume identity peer");
    test.close().await;
}

#[tokio::test]
async fn turn_identity_mismatch_fails_before_any_adapter_event() {
    let test = TestStore::open("turn-mismatch").await;
    let log = test.root.join("wire.jsonl");
    let (io, mut child) = spawn_scripted_peer(&log, CODEX_TURN_MISMATCH_PEER);
    let (prepared, _) = prepared_turn(&test.store, "identity prompt");
    let (events, mut event_receiver) = adapter_event_channel();
    let (approvals, _approval_receiver) = adapter_approval_channel();
    let error = Box::new(prepared)
        .attach(io, events, approvals)
        .expect("attach mismatch peer")
        .await
        .expect_err("stale vendor turn must fail closed");
    assert_eq!(error.code, "codex-turn-identity-mismatch");
    assert!(event_receiver.recv().await.is_none());
    tokio::time::timeout(Duration::from_secs(2), child.wait())
        .await
        .expect("mismatch peer exits")
        .expect("wait mismatch peer");
    test.close().await;
}

#[tokio::test]
async fn turn_start_error_never_produces_completed_or_adapter_events() {
    let test = TestStore::open("turn-error").await;
    let log = test.root.join("wire.jsonl");
    let (io, mut child) = spawn_scripted_peer(&log, CODEX_TURN_ERROR_PEER);
    let (prepared, _) = prepared_turn(&test.store, "rejected prompt");
    let (events, mut event_receiver) = adapter_event_channel();
    let (approvals, _approval_receiver) = adapter_approval_channel();
    let error = Box::new(prepared)
        .attach(io, events, approvals)
        .expect("attach error peer")
        .await
        .expect_err("turn/start error must terminate the driver");
    assert_eq!(error.code, "codex-handshake-error");
    assert!(event_receiver.recv().await.is_none());
    tokio::time::timeout(Duration::from_secs(2), child.wait())
        .await
        .expect("error peer exits")
        .expect("wait error peer");
    test.close().await;
}

#[tokio::test]
async fn handshake_response_without_result_or_error_fails_closed() {
    let test = TestStore::open("malformed-handshake-response").await;
    let log = test.root.join("wire.jsonl");
    let (io, mut child) = spawn_scripted_peer(&log, CODEX_MALFORMED_HANDSHAKE_PEER);
    let (prepared, _) = prepared_turn(&test.store, "must-not-reach-thread-start");
    let (events, mut event_receiver) = adapter_event_channel();
    let (approvals, _approval_receiver) = adapter_approval_channel();
    let error = Box::new(prepared)
        .attach(io, events, approvals)
        .expect("attach malformed response peer")
        .await
        .expect_err("malformed JSON-RPC response must fail closed");
    assert_eq!(error.code, "codex-handshake-response-invalid");
    assert!(event_receiver.recv().await.is_none());
    tokio::time::timeout(Duration::from_secs(2), child.wait())
        .await
        .expect("malformed response peer exits")
        .expect("wait malformed response peer");
    let requests = fs::read_to_string(&log).expect("read malformed response wire");
    assert_eq!(
        requests.lines().count(),
        1,
        "driver must reject the malformed initialize response before thread/start"
    );
    test.close().await;
}

#[tokio::test]
async fn dropping_registered_approval_route_does_not_complete_the_waiting_driver() {
    // 威胁场景：actor 在 deadline 后只 drop transient route，却没有 fence execution；
    // Codex app-server 仍在等待 JSON-RPC response，driver 不能把 route drop 当作 turn 完成。
    let test = TestStore::open("approval-route-drop").await;
    let log = test.root.join("wire.jsonl");
    let (io, mut child) = spawn_scripted_peer(&log, CODEX_APPROVAL_PEER);
    let (prepared, _) = prepared_turn(&test.store, "approval route drop prompt");
    let (events, _event_receiver) = adapter_event_channel();
    let (approvals, mut approval_receiver) = adapter_approval_channel();
    let completion = Box::new(prepared)
        .attach(io, events, approvals)
        .expect("attach route-drop Codex peer");
    let mut task = tokio::spawn(completion);

    let registration = tokio::time::timeout(Duration::from_secs(5), approval_receiver.recv())
        .await
        .expect("Codex route-drop approval arrives")
        .expect("Codex route-drop approval channel open");
    let (request, delivery, registration_ack) = registration.into_parts();
    assert!(matches!(
        request.vendor,
        ActionRequestVendor::Codex {
            approval_policy_at_decision: CodexApprovalPolicy::Always,
            sandbox_at_decision: CodexSandboxMode::ReadOnly,
            ..
        }
    ));
    registration_ack.acknowledge(Ok(()));
    drop(delivery);

    assert!(
        tokio::time::timeout(Duration::from_millis(100), &mut task)
            .await
            .is_err(),
        "dropping the route must not synthesize a Codex approval response or complete the turn"
    );
    assert_eq!(
        fs::read_to_string(&log)
            .expect("read Codex route-drop wire")
            .lines()
            .count(),
        3,
        "only initialize/thread/start requests may be written without an authenticated decision"
    );

    task.abort();
    let _ = task.await;
    tokio::time::timeout(Duration::from_secs(2), child.wait())
        .await
        .expect("Codex route-drop peer exits after driver cancellation")
        .expect("wait Codex route-drop peer");
    test.close().await;
}

#[tokio::test]
async fn bound_approval_delivery_is_single_flight_and_preserves_rpc_id() {
    let probe = WriterProbe::success();
    let delivery = approval_delivery(json!("rpc-string"), probe.writer());
    let decision = approval_decision("approval-request", ActionDecisionKind::Approve, true);
    let key = approval_key(7);
    assert_eq!(
        delivery.deliver(key, &decision).await,
        ApprovalDeliveryOutcome::AppliedAck
    );
    let first = probe.bytes();
    let frame: Value = serde_json::from_slice(first.strip_suffix(b"\n").unwrap())
        .expect("decode approval response");
    assert_eq!(frame["id"], "rpc-string");
    assert_eq!(frame["result"]["decision"], "acceptForSession");

    assert_eq!(
        delivery.deliver(key, &decision).await,
        ApprovalDeliveryOutcome::AppliedAck
    );
    assert_eq!(
        probe.bytes(),
        first,
        "idempotent replay must not write twice"
    );
    assert_eq!(
        delivery.deliver(approval_key(8), &decision).await,
        ApprovalDeliveryOutcome::PermanentlyRejected
    );
}

#[tokio::test]
async fn partial_write_and_flush_failure_become_sticky_outcome_unknown() {
    for probe in [WriterProbe::partial(8), WriterProbe::flush_failure()] {
        let delivery = approval_delivery(json!(-9_i64), probe.writer());
        let decision = approval_decision("approval-request", ActionDecisionKind::Deny, false);
        let key = approval_key(9);
        assert_eq!(
            delivery.deliver(key, &decision).await,
            ApprovalDeliveryOutcome::OutcomeUnknown
        );
        let written = probe.bytes();
        assert_eq!(
            delivery.deliver(key, &decision).await,
            ApprovalDeliveryOutcome::OutcomeUnknown
        );
        assert_eq!(
            probe.bytes(),
            written,
            "unknown outcome must never auto-retry IO"
        );
    }
}

#[tokio::test]
async fn oversized_approval_response_is_rejected_before_any_write() {
    let probe = WriterProbe::success();
    let request = approval_request("approval-request");
    let route = CodexApprovalRoute {
        rpc_id: json!(11),
        method: "item/permissions/requestApproval".to_owned(),
        params: json!({
            "permissions": {
                "fileSystem": {"read": [format!("/{}", "a".repeat(4 * 1024 * 1024))]},
                "network": null
            }
        }),
    };
    let delivery = CodexBoundApprovalDelivery::new(request, route, probe.writer())
        .expect("construct oversized approval route");
    assert_eq!(
        delivery
            .deliver(
                approval_key(10),
                &approval_decision("approval-request", ActionDecisionKind::Approve, false),
            )
            .await,
        ApprovalDeliveryOutcome::PermanentlyRejected
    );
    assert!(probe.bytes().is_empty());
}

fn prepared_turn(store: &RuntimeStoreHandle, prompt: &str) -> (CodexPreparedTurn, RuntimeId) {
    let command_id = runtime_id(RuntimeIdKind::Command, 1);
    let adapter_state_key = runtime_id(RuntimeIdKind::AdapterState, 2);
    let execution_id = ExecutionId::from_command_id(command_id).expect("typed execution id");
    let cwd = std::env::current_dir().expect("absolute current directory");
    let request = AgentTurnRequest::new(
        execution_id,
        cwd.clone(),
        PromptPayload::new(prompt).expect("bounded prompt"),
        41,
        codex_configuration(),
    )
    .expect("valid typed turn request");
    let state = AdapterStateHandle::new(adapter_state_key).expect("typed adapter state");
    let exec_spec = ExecSpec::new(
        &request,
        state,
        "/usr/bin/true",
        Vec::<OsString>::new(),
        cwd.clone(),
    )
    .expect("valid test exec spec");
    (
        CodexPreparedTurn {
            exec_spec,
            repository: CodexStateRepository::new(store.codex_adapter_state_vault_for_test()),
            adapter_state_key,
            resume_thread_id: None,
            cwd,
            prompt: prompt.to_owned(),
            approval_policy: CodexApprovalPolicy::Always,
            sandbox: CodexSandboxMode::ReadOnly,
            reasoning_effort: CodexReasoningEffort::High,
        },
        adapter_state_key,
    )
}

fn codex_configuration() -> ConversationConfiguration {
    ConversationConfiguration::new(VendorConfigurationSnapshot::Codex(
        CodexConversationConfiguration::new(
            CodexApprovalPolicy::Always,
            CodexSandboxMode::ReadOnly,
            CodexReasoningEffort::High,
        ),
    ))
}

fn spawn_scripted_peer(log: &Path, script: &str) -> (GatedChildIo, Child) {
    let mut command = Command::new("/bin/sh");
    command
        .arg("-c")
        .arg(script)
        .env("AGENTDECK_CODEX_DRIVER_LOG", log)
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped());
    let mut child = command.spawn().expect("spawn scripted Codex peer");
    let io = GatedChildIo {
        stdin: child.stdin.take().expect("scripted stdin"),
        stdout: child.stdout.take().expect("scripted stdout"),
        stderr: child.stderr.take().expect("scripted stderr"),
    };
    (io, child)
}

fn runtime_id(kind: RuntimeIdKind, seed: u8) -> RuntimeId {
    RuntimeId::from_bytes(kind, [seed; 16]).expect("non-zero runtime id")
}

fn approval_delivery(rpc_id: Value, writer: SharedCodexStdin) -> CodexBoundApprovalDelivery {
    CodexBoundApprovalDelivery::new(
        approval_request("approval-request"),
        CodexApprovalRoute {
            rpc_id,
            method: "item/commandExecution/requestApproval".to_owned(),
            params: json!({}),
        },
        writer,
    )
    .expect("construct bound Codex approval delivery")
}

fn approval_request(request_id: &str) -> ActionRequest {
    ActionRequest {
        request_id: request_id.to_owned(),
        kind: ActionKind::ExecuteCommand,
        summary: "fixture approval".to_owned(),
        vendor: ActionRequestVendor::Codex {
            approval_policy_at_decision: CodexApprovalPolicy::OnRequest,
            sandbox_at_decision: CodexSandboxMode::WorkspaceWrite,
            can_persist: true,
        },
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

    fn writer(&self) -> SharedCodexStdin {
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

const CODEX_SUCCESS_PEER: &str = r#"
count=0
while IFS= read -r line; do
  printf '%s\n' "$line" >> "$AGENTDECK_CODEX_DRIVER_LOG"
  count=$((count + 1))
  case "$count" in
    1)
      printf '%s\n' '{"id":1,"result":{"userAgent":"agentdeck/0.144.1 (test)"}}'
      ;;
    2)
      printf '%s\n' '{"id":2,"result":{"thread":{"id":"fixture-thread"}}}'
      ;;
    3)
      printf '%s\n' '{"id":3,"result":{"turn":{"id":"fixture-turn"}}}'
      printf '%s\n' '{"method":"item/started","params":{"threadId":"fixture-thread","turnId":"fixture-turn","item":{"type":"agentMessage","id":"fixture-item","text":""}}}'
      printf '%s\n' '{"method":"item/agentMessage/delta","params":{"threadId":"fixture-thread","turnId":"fixture-turn","itemId":"fixture-item","delta":"fixture"}}'
      printf '%s\n' '{"method":"item/completed","params":{"threadId":"fixture-thread","turnId":"fixture-turn","item":{"type":"agentMessage","id":"fixture-item","text":"fixture"}}}'
      printf '%s\n' '{"method":"turn/completed","params":{"threadId":"fixture-thread","turn":{"id":"fixture-turn","items":[],"itemsView":"notLoaded","status":"completed","error":null,"durationMs":12}}}'
      exit 0
      ;;
  esac
done
"#;

const CODEX_APPROVAL_PEER: &str = r#"
count=0
while IFS= read -r line; do
  printf '%s\n' "$line" >> "$AGENTDECK_CODEX_DRIVER_LOG"
  count=$((count + 1))
  case "$count" in
    1)
      printf '%s\n' '{"id":1,"result":{"userAgent":"agentdeck/0.144.1 (test)"}}'
      ;;
    2)
      printf '%s\n' '{"id":2,"result":{"thread":{"id":"fixture-thread"}}}'
      ;;
    3)
      printf '%s\n' '{"id":3,"result":{"turn":{"id":"fixture-turn"}}}'
      printf '%s\n' '{"id":"rpc-route-drop","method":"item/commandExecution/requestApproval","params":{"threadId":"fixture-thread","turnId":"fixture-turn","approvalId":"approval-route-drop","command":"pwd","cwd":"/tmp"}}'
      if IFS= read -r response; then
        printf '%s\n' "$response" >> "$AGENTDECK_CODEX_DRIVER_LOG"
        printf '%s\n' '{"method":"turn/completed","params":{"threadId":"fixture-thread","turn":{"id":"fixture-turn","items":[],"itemsView":"notLoaded","status":"completed","error":null,"durationMs":18}}}'
      fi
      exit 0
      ;;
  esac
done
"#;

const CODEX_RESUME_PEER: &str = r#"
count=0
while IFS= read -r line; do
  printf '%s\n' "$line" >> "$AGENTDECK_CODEX_DRIVER_LOG"
  count=$((count + 1))
  case "$count" in
    1) printf '%s\n' '{"id":1,"result":{"userAgent":"agentdeck/0.144.1 (test)"}}' ;;
    2) printf '%s\n' '{"id":2,"result":{"thread":{"id":"fixture-thread"}}}' ;;
    3)
      printf '%s\n' '{"method":"turn/started","params":{"threadId":"fixture-thread","turn":{"id":"fixture-turn","items":[],"itemsView":"notLoaded","status":"inProgress","error":null}}}'
      printf '%s\n' '{"id":3,"result":{"turn":{"id":"fixture-turn"}}}'
      printf '%s\n' '{"method":"turn/completed","params":{"threadId":"fixture-thread","turn":{"id":"fixture-turn","items":[],"itemsView":"notLoaded","status":"completed","error":null,"durationMs":21}}}'
      exit 0
      ;;
  esac
done
"#;

const CODEX_LEGACY_RESUME_IDENTITY_PEER: &str = r#"
count=0
while IFS= read -r line; do
  printf '%s\n' "$line" >> "$AGENTDECK_CODEX_DRIVER_LOG"
  count=$((count + 1))
  case "$count" in
    1) printf '%s\n' '{"id":1,"result":{"userAgent":"agentdeck/0.144.1 (test)"}}' ;;
    2) printf '%s\n' '{"id":2,"result":{"threadId":"fixture-thread"}}'; exit 0 ;;
  esac
done
"#;

const CODEX_TURN_MISMATCH_PEER: &str = r#"
count=0
while IFS= read -r line; do
  printf '%s\n' "$line" >> "$AGENTDECK_CODEX_DRIVER_LOG"
  count=$((count + 1))
  case "$count" in
    1) printf '%s\n' '{"id":1,"result":{"userAgent":"agentdeck/0.144.1 (test)"}}' ;;
    2) printf '%s\n' '{"id":2,"result":{"thread":{"id":"fixture-thread"}}}' ;;
    3)
      printf '%s\n' '{"id":3,"result":{"turn":{"id":"fixture-turn"}}}'
      printf '%s\n' '{"method":"item/started","params":{"threadId":"fixture-thread","turnId":"stale-turn","item":{"type":"agentMessage","id":"stale-item","text":""}}}'
      exit 0
      ;;
  esac
done
"#;

const CODEX_TURN_ERROR_PEER: &str = r#"
count=0
while IFS= read -r line; do
  printf '%s\n' "$line" >> "$AGENTDECK_CODEX_DRIVER_LOG"
  count=$((count + 1))
  case "$count" in
    1) printf '%s\n' '{"id":1,"result":{"userAgent":"agentdeck/0.144.1 (test)"}}' ;;
    2) printf '%s\n' '{"id":2,"result":{"thread":{"id":"fixture-thread"}}}' ;;
    3)
      printf '%s\n' '{"id":3,"error":{"code":-32000,"message":"rejected"}}'
      exit 0
      ;;
  esac
done
"#;

const CODEX_MALFORMED_HANDSHAKE_PEER: &str = r#"
while IFS= read -r line; do
  printf '%s\n' "$line" >> "$AGENTDECK_CODEX_DRIVER_LOG"
  printf '%s\n' '{"id":1}'
  exit 0
done
"#;
