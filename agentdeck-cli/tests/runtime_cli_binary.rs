#![cfg(unix)]

use std::collections::BTreeSet;
use std::fs;
use std::io::{BufRead, BufReader, Read, Write};
use std::os::unix::fs::PermissionsExt;
use std::os::unix::net::{UnixListener, UnixStream};
use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};
use std::sync::{Arc, Mutex, MutexGuard, OnceLock};
use std::thread;
use std::time::{Duration, Instant};

use agentdeck_protocol::relay_v2::{MachineRouteId, RelayServerId};
use agentdeck_protocol::runtime::catalog::{CatalogSnapshot, ConversationEntry};
use agentdeck_protocol::runtime::command::HelloParams;
use agentdeck_protocol::runtime::configuration::{
    AgentDescription, AgentDescriptions, CodexConversationConfiguration, ConfigurationReceipt,
    ConversationConfiguration, ConversationConfigurationState, VendorConfigurationSnapshot,
};
use agentdeck_protocol::runtime::failure::RuntimeFailure;
use agentdeck_protocol::runtime::identity::{
    CommandId, ConversationId, EventId, MessageId, StreamGeneration, TurnId,
};
use agentdeck_protocol::runtime::metadata::{
    ConversationMetadataMutation, ConversationMetadataReceipt,
};
use agentdeck_protocol::runtime::receipt::{
    CommandReceipt, CommandStatus, CommandStatusReceipt, ConversationStartReceipt,
};
use agentdeck_protocol::runtime::{
    BackfillChunk, BackfillRange, ConversationSnapshot, MachineRemoteFailureCode,
    MachineRemoteLifecycle, MachineRemoteStatus, MachineRootFingerprint, QueryReceiptSelector,
    RUNTIME_PROTOCOL_VERSION, RuntimeEnvelope, RuntimeEvent, RuntimeEventBody, RuntimeInnerCursor,
    RuntimeMessage, RuntimeReply, RuntimeRequest, RuntimeSyncComplete, SnapshotItem, StreamCursor,
    SubscriptionReceipt,
};
use agentdeck_protocol::{
    AgentKind, CodexApprovalPolicy, CodexCapabilities, CodexReasoningEffort, CodexSandboxMode,
    SessionCapabilities, VendorCapabilities,
};
use tempfile::{NamedTempFile, TempDir};

fn bin() -> &'static str {
    env!("CARGO_BIN_EXE_agentdeck")
}

fn private_dir() -> TempDir {
    let root = tempfile::tempdir().expect("create private test directory");
    fs::set_permissions(root.path(), fs::Permissions::from_mode(0o700))
        .expect("secure private test directory");
    root
}

fn runtime_command(temp_root: &Path) -> Command {
    let mut command = Command::new(bin());
    command.arg("--runtime-temp-root-for-test").arg(temp_root);
    command
}

fn stdout_json(output: &std::process::Output) -> serde_json::Value {
    serde_json::from_slice(&output.stdout).unwrap_or_else(|error| {
        panic!(
            "stdout is not JSON: {error}; stdout={}; stderr={}",
            String::from_utf8_lossy(&output.stdout),
            String::from_utf8_lossy(&output.stderr)
        )
    })
}

#[test]
fn default_missing_socket_is_typed_and_never_spawns_legacy_daemon() {
    let tmp = private_dir();
    let output = runtime_command(tmp.path())
        .env("TMPDIR", tmp.path())
        .arg("ping")
        .output()
        .expect("run agentdeck ping");

    assert!(!output.status.success());
    let json = stdout_json(&output);
    assert_eq!(json["error"]["code"], "daemon.client.socket_missing");
    let spawned = fs::read_dir(tmp.path())
        .expect("read private TMPDIR")
        .filter_map(Result::ok)
        .map(|entry| entry.file_name())
        .filter_map(|name| name.into_string().ok())
        .filter(|name| name.starts_with("ad-"))
        .collect::<Vec<_>>();
    assert!(
        spawned.is_empty(),
        "socket-missing fallback unexpectedly created daemon namespaces: {spawned:?}"
    );
}

struct TestRuntimeServer {
    root: TempDir,
    listener: UnixListener,
}

impl TestRuntimeServer {
    fn bind() -> Self {
        let root = private_dir();
        let namespace = root.path().join(format!("ad-{}", uuid::Uuid::new_v4()));
        fs::create_dir(&namespace).expect("create daemon namespace");
        fs::set_permissions(&namespace, fs::Permissions::from_mode(0o700))
            .expect("secure daemon namespace");
        let socket_path = namespace.join("s");
        let listener = UnixListener::bind(&socket_path).expect("bind test Runtime UDS");
        fs::set_permissions(&socket_path, fs::Permissions::from_mode(0o600))
            .expect("secure Runtime UDS");
        Self { root, listener }
    }
}

fn read_json_line(reader: &mut BufReader<UnixStream>) -> serde_json::Value {
    let mut line = String::new();
    let size = reader.read_line(&mut line).expect("read Runtime JSONL");
    assert!(size > 0, "client closed before expected Runtime frame");
    serde_json::from_str(line.trim()).expect("decode Runtime JSONL")
}

fn read_envelope(reader: &mut BufReader<UnixStream>) -> RuntimeEnvelope {
    serde_json::from_value(read_json_line(reader)).expect("decode Runtime envelope")
}

fn write_reply(writer: &mut UnixStream, message_id: MessageId, reply: RuntimeReply) {
    let envelope = RuntimeEnvelope {
        version: RUNTIME_PROTOCOL_VERSION,
        message_id,
        body: RuntimeMessage::Reply(reply),
    };
    serde_json::to_writer(&mut *writer, &envelope).expect("encode Runtime reply");
    writer.write_all(b"\n").expect("terminate Runtime reply");
    writer.flush().expect("flush Runtime reply");
}

fn machine_status(lifecycle: MachineRemoteLifecycle, failure: Option<&str>) -> MachineRemoteStatus {
    MachineRemoteStatus::new(
        lifecycle,
        Some(RelayServerId::from_bytes([0x22; 16])),
        Some(MachineRouteId::from_bytes([0x33; 16])),
        Some(MachineRootFingerprint::from_bytes([0x44; 32])),
        Some(7),
        failure.map(|code| MachineRemoteFailureCode::new(code).expect("stable failure code")),
    )
    .expect("valid machine status")
}

fn runtime_fixture_payload(case_name: &str) -> serde_json::Value {
    include_str!("../../protocol/agentdeck/fixtures/runtime-v4-wire.jsonl")
        .lines()
        .map(|line| serde_json::from_str::<serde_json::Value>(line).expect("fixture JSON"))
        .find(|case| case["case"] == case_name)
        .unwrap_or_else(|| panic!("missing fixture {case_name}"))["value"]["body"]["payload"]
        .clone()
}

fn private_json_file(value: &serde_json::Value) -> NamedTempFile {
    let mut file = NamedTempFile::new().expect("temporary JSON input");
    serde_json::to_writer(file.as_file_mut(), value).expect("write JSON input");
    file.as_file_mut().flush().expect("flush JSON input");
    fs::set_permissions(file.path(), fs::Permissions::from_mode(0o600)).expect("private JSON mode");
    file
}

fn remote_process_test_guard() -> MutexGuard<'static, ()> {
    static GUARD: OnceLock<Mutex<()>> = OnceLock::new();
    GUARD
        .get_or_init(|| Mutex::new(()))
        .lock()
        .expect("remote process test guard")
}

fn accept_with_timeout(listener: &UnixListener, timeout: Duration) -> std::io::Result<UnixStream> {
    listener
        .set_nonblocking(true)
        .expect("set bounded Runtime accept");
    let deadline = Instant::now() + timeout;
    let result = loop {
        match listener.accept() {
            Ok((stream, _)) => break Ok(stream),
            Err(error)
                if error.kind() == std::io::ErrorKind::WouldBlock && Instant::now() < deadline =>
            {
                thread::sleep(Duration::from_millis(10));
            }
            Err(error) if error.kind() == std::io::ErrorKind::WouldBlock => {
                break Err(std::io::Error::new(
                    std::io::ErrorKind::TimedOut,
                    "Runtime client did not connect before accept deadline",
                ));
            }
            Err(error) => break Err(error),
        }
    };
    listener
        .set_nonblocking(false)
        .expect("restore blocking Runtime listener");
    let stream = result?;
    stream
        .set_nonblocking(false)
        .expect("restore blocking Runtime stream");
    Ok(stream)
}

fn accept_hello(listener: &UnixListener) -> (BufReader<UnixStream>, UnixStream, String) {
    let stream = accept_with_timeout(listener, Duration::from_secs(5))
        .expect("accept Runtime client before deadline");
    stream
        .set_read_timeout(Some(Duration::from_secs(5)))
        .expect("bound server read timeout");
    let mut reader = BufReader::new(stream.try_clone().expect("clone Runtime stream"));
    let preface = read_json_line(&mut reader);
    assert_eq!(preface["localProtocolVersion"], 1);
    let installation_id = preface["clientInstallationId"]
        .as_str()
        .expect("client installation id")
        .to_owned();
    let hello = read_envelope(&mut reader);
    assert!(matches!(
        hello.body,
        RuntimeMessage::Request(RuntimeRequest::Hello(HelloParams {
            runtime_protocol_version: RUNTIME_PROTOCOL_VERSION
        }))
    ));
    let mut writer = stream;
    write_reply(
        &mut writer,
        hello.message_id,
        RuntimeReply::Hello(HelloParams {
            runtime_protocol_version: RUNTIME_PROTOCOL_VERSION,
        }),
    );
    (reader, writer, installation_id)
}

#[test]
fn fake_runtime_listener_accept_is_bounded() {
    let server = TestRuntimeServer::bind();
    let started = Instant::now();
    let error = accept_with_timeout(&server.listener, Duration::from_millis(30))
        .expect_err("unused fake listener must time out");
    assert_eq!(error.kind(), std::io::ErrorKind::TimedOut);
    assert!(started.elapsed() < Duration::from_secs(1));
}

#[test]
fn remote_machine_status_uses_runtime_uds_and_outputs_only_allowlisted_admin_action() {
    let _guard = remote_process_test_guard();
    let server = TestRuntimeServer::bind();
    let temp_root = server.root.path().to_path_buf();
    let server_thread = thread::spawn(move || {
        let (mut reader, mut writer, _) = accept_hello(&server.listener);
        let request = read_envelope(&mut reader);
        assert!(matches!(
            request.body,
            RuntimeMessage::Request(RuntimeRequest::MachineRemoteStatus { .. })
        ));
        write_reply(
            &mut writer,
            request.message_id,
            RuntimeReply::MachineRemoteStatus(machine_status(
                MachineRemoteLifecycle::Blocked,
                Some("daemon.remote.trust_reset.admin_receipt_required"),
            )),
        );
    });
    let output = runtime_command(&temp_root)
        .args(["remote", "machine", "status"])
        .output()
        .expect("run machine status");
    server_thread.join().expect("Runtime server thread");
    assert!(
        output.status.success(),
        "stderr={}",
        String::from_utf8_lossy(&output.stderr)
    );
    let json = stdout_json(&output);
    assert_eq!(json["operation"], "remote.machine.status");
    assert_eq!(json["status"]["lifecycle"], "blocked");
    assert_eq!(
        json["relayAdminPurge"]["ndjson"]["command"],
        serde_json::Value::Null
    );
    let ndjson = json["relayAdminPurge"]["ndjson"]
        .as_str()
        .expect("NDJSON string");
    assert_eq!(
        serde_json::from_str::<serde_json::Value>(ndjson).unwrap()["command"],
        "machine_purge"
    );
}

#[test]
fn remote_machine_enroll_imports_private_bundle_over_runtime_uds_without_echoing_secrets() {
    let _guard = remote_process_test_guard();
    let bundle = private_json_file(&runtime_fixture_payload("requestMachineEnroll")["bundle"]);
    let server = TestRuntimeServer::bind();
    let temp_root = server.root.path().to_path_buf();
    let server_thread = thread::spawn(move || {
        let (mut reader, mut writer, _) = accept_hello(&server.listener);
        let request = read_envelope(&mut reader);
        let RuntimeMessage::Request(RuntimeRequest::MachineEnroll(enroll)) = request.body else {
            panic!("expected MachineEnroll request")
        };
        assert_eq!(enroll.bundle.version, 2);
        write_reply(
            &mut writer,
            request.message_id,
            RuntimeReply::MachineRemoteStatus(machine_status(MachineRemoteLifecycle::Active, None)),
        );
    });
    let output = runtime_command(&temp_root)
        .args([
            "remote",
            "machine",
            "enroll",
            "--bundle-file",
            bundle.path().to_str().expect("UTF-8 bundle path"),
        ])
        .output()
        .expect("run machine enroll");
    server_thread.join().expect("Runtime server thread");
    assert!(
        output.status.success(),
        "stderr={}",
        String::from_utf8_lossy(&output.stderr)
    );
    let stdout = String::from_utf8(output.stdout).expect("UTF-8 output");
    let json: serde_json::Value = serde_json::from_str(&stdout).expect("status JSON");
    assert_eq!(json["operation"], "remote.machine.enroll");
    assert_eq!(json["status"]["lifecycle"], "active");
    for forbidden in [
        "code",
        "spkiPins",
        "receiptVerifyKey",
        "linkCert",
        "dataCert",
    ] {
        assert!(!stdout.contains(forbidden), "leaked {forbidden}: {stdout}");
    }
}

#[test]
fn remote_trust_reset_maps_runtime_failure_through_status_fallback() {
    let _guard = remote_process_test_guard();
    let server = TestRuntimeServer::bind();
    let temp_root = server.root.path().to_path_buf();
    let server_thread = thread::spawn(move || {
        let (mut reader, mut writer, _) = accept_hello(&server.listener);
        let reset = read_envelope(&mut reader);
        let RuntimeMessage::Request(RuntimeRequest::TrustReset(request)) = reset.body else {
            panic!("expected TrustReset request")
        };
        assert!(!request.uninstall_purge());
        assert!(request.uninstall_purge_plan().is_none());
        assert!(request.admin_purge_receipt().is_none());
        write_reply(
            &mut writer,
            reset.message_id,
            RuntimeReply::Failure(RuntimeFailure::new(
                "daemon.remote.trust_reset.admin_receipt_required",
                "portable Relay admin receipt required",
            )),
        );
        let status = read_envelope(&mut reader);
        assert!(matches!(
            status.body,
            RuntimeMessage::Request(RuntimeRequest::MachineRemoteStatus { .. })
        ));
        write_reply(
            &mut writer,
            status.message_id,
            RuntimeReply::MachineRemoteStatus(machine_status(
                MachineRemoteLifecycle::Blocked,
                Some("daemon.remote.trust_reset.admin_receipt_required"),
            )),
        );
    });
    let output = runtime_command(&temp_root)
        .args(["remote", "trust-reset"])
        .output()
        .expect("run trust reset");
    server_thread.join().expect("Runtime server thread");
    assert!(
        output.status.success(),
        "stderr={}",
        String::from_utf8_lossy(&output.stderr)
    );
    let json = stdout_json(&output);
    assert_eq!(
        json["requestFailureCode"],
        "daemon.remote.trust_reset.admin_receipt_required"
    );
    assert_eq!(json["status"]["lifecycle"], "blocked");
    assert!(json["relayAdminPurge"].is_object());
}

#[test]
fn remote_machine_success_rejects_every_non_status_reply() {
    let _guard = remote_process_test_guard();
    let server = TestRuntimeServer::bind();
    let temp_root = server.root.path().to_path_buf();
    let server_thread = thread::spawn(move || {
        let (mut reader, mut writer, _) = accept_hello(&server.listener);
        let request = read_envelope(&mut reader);
        write_reply(
            &mut writer,
            request.message_id,
            RuntimeReply::Hello(HelloParams {
                runtime_protocol_version: RUNTIME_PROTOCOL_VERSION,
            }),
        );
    });
    let output = runtime_command(&temp_root)
        .args(["remote", "machine", "status"])
        .output()
        .expect("run machine status");
    server_thread.join().expect("Runtime server thread");
    assert_eq!(output.status.code(), Some(3));
    assert_eq!(
        stdout_json(&output)["error"]["code"],
        "daemon.client.unexpected_reply"
    );
}

#[test]
fn remote_machine_runtime_failure_preserves_stable_code_and_failure_exit() {
    let _guard = remote_process_test_guard();
    let server = TestRuntimeServer::bind();
    let temp_root = server.root.path().to_path_buf();
    let server_thread = thread::spawn(move || {
        let (mut reader, mut writer, _) = accept_hello(&server.listener);
        let request = read_envelope(&mut reader);
        write_reply(
            &mut writer,
            request.message_id,
            RuntimeReply::Failure(RuntimeFailure::new(
                "daemon.remote.administration.unavailable",
                "remote administration unavailable",
            )),
        );
    });
    let output = runtime_command(&temp_root)
        .args(["remote", "machine", "status"])
        .output()
        .expect("run machine status");
    server_thread.join().expect("Runtime server thread");
    assert_eq!(output.status.code(), Some(5));
    assert_eq!(
        stdout_json(&output)["error"]["code"],
        "daemon.remote.administration.unavailable"
    );
}

#[test]
fn help_keeps_clap_success_output() {
    let output = Command::new(bin())
        .arg("--help")
        .output()
        .expect("run CLI help");
    assert!(output.status.success());
    assert!(String::from_utf8_lossy(&output.stdout).contains("Usage:"));
    assert!(output.stderr.is_empty());
}

fn codex_description() -> (
    AgentDescriptions,
    SessionCapabilities,
    ConversationConfiguration,
) {
    let capabilities = SessionCapabilities {
        agent_kind: AgentKind::Codex,
        agent_version: "runtime-cli-test".to_owned(),
        features: BTreeSet::new(),
        vendor: VendorCapabilities::Codex(CodexCapabilities::default()),
    };
    let configuration = ConversationConfiguration::new(VendorConfigurationSnapshot::Codex(
        CodexConversationConfiguration::new(
            CodexApprovalPolicy::OnRequest,
            CodexSandboxMode::WorkspaceWrite,
            CodexReasoningEffort::Medium,
        ),
    ));
    let descriptions = AgentDescriptions::new(vec![
        AgentDescription::new(
            AgentKind::Codex,
            capabilities.clone(),
            configuration.clone(),
        )
        .unwrap(),
    ])
    .unwrap();
    (descriptions, capabilities, configuration)
}

#[test]
fn debug_endpoint_reuses_isolated_installation_and_ping_only_performs_hello() {
    let server = TestRuntimeServer::bind();
    let temp_root = server.root.path().to_path_buf();
    let installations = Arc::new(Mutex::new(Vec::new()));
    let observed = Arc::clone(&installations);
    let server_thread = thread::spawn(move || {
        for _ in 0..2 {
            let (mut reader, writer, installation_id) = accept_hello(&server.listener);
            observed.lock().unwrap().push(installation_id);
            drop(writer);
            let mut tail = Vec::new();
            reader
                .read_to_end(&mut tail)
                .expect("ping client closes after Hello");
            assert!(tail.is_empty(), "ping sent a post-Hello Runtime request");
        }
    });

    for _ in 0..2 {
        let output = runtime_command(&temp_root)
            .arg("ping")
            .output()
            .expect("run canonical ping");
        assert!(
            output.status.success(),
            "stderr: {}",
            String::from_utf8_lossy(&output.stderr)
        );
        assert_eq!(stdout_json(&output), serde_json::json!({"ok": true}));
    }
    server_thread.join().unwrap();
    let installations = installations.lock().unwrap();
    assert_eq!(installations.len(), 2);
    assert_eq!(installations[0], installations[1]);
}

#[test]
fn selfcheck_and_agent_commands_use_only_describe_agents_after_hello() {
    let server = TestRuntimeServer::bind();
    let temp_root = server.root.path().to_path_buf();
    let server_thread = thread::spawn(move || {
        let (descriptions, _, _) = codex_description();
        for _ in 0..3 {
            let (mut reader, mut writer, _) = accept_hello(&server.listener);
            let describe = read_envelope(&mut reader);
            assert!(matches!(
                describe.body,
                RuntimeMessage::Request(RuntimeRequest::DescribeAgents)
            ));
            write_reply(
                &mut writer,
                describe.message_id,
                RuntimeReply::Agents(descriptions.clone()),
            );
            drop(writer);
            let mut tail = Vec::new();
            reader.read_to_end(&mut tail).unwrap();
            assert!(
                tail.is_empty(),
                "DescribeAgents command sent a second request"
            );
        }
    });

    for arguments in [
        vec!["selfcheck"],
        vec!["agent", "list"],
        vec!["agent", "capabilities", "--agent", "codex"],
    ] {
        let output = runtime_command(&temp_root)
            .args(arguments)
            .output()
            .expect("run DescribeAgents CLI command");
        assert!(
            output.status.success(),
            "stderr: {}",
            String::from_utf8_lossy(&output.stderr)
        );
        let stdout = String::from_utf8(output.stdout).unwrap();
        assert!(stdout.contains("runtime-cli-test"));
        assert!(!stdout.contains("threadId"));
    }
    server_thread.join().unwrap();
}

#[test]
fn continue_accepts_pure_backfill_configuration_then_sends_prompt_directly() {
    let server = TestRuntimeServer::bind();
    let temp_root = server.root.path().to_path_buf();
    let server_thread = thread::spawn(move || {
        let (_, capabilities, configuration) = codex_description();
        let conversation_id = ConversationId::new("conversation-continue-backfill");
        let (mut reader, mut writer, _) = accept_hello(&server.listener);

        let subscribe = read_envelope(&mut reader);
        assert!(matches!(
            subscribe.body,
            RuntimeMessage::Request(RuntimeRequest::Subscribe {
                inner_cursor: RuntimeInnerCursor::Conversation {
                    ref conversation_id,
                    cursor: StreamCursor::BeforeFirst,
                }
            }) if conversation_id.as_str() == "conversation-continue-backfill"
        ));
        write_reply(
            &mut writer,
            subscribe.message_id.clone(),
            RuntimeReply::Subscription(SubscriptionReceipt::Subscribed {
                stream_generation: StreamGeneration::new("generation-continue"),
            }),
        );
        let configuration_event = RuntimeEvent::new(
            conversation_id.clone(),
            EventId::new("event-continue-configuration"),
            0,
            None,
            None,
            None,
            RuntimeEventBody::ConfigurationChanged {
                state: ConversationConfigurationState::new(7, Some(configuration)).unwrap(),
            },
        )
        .unwrap();
        write_reply(
            &mut writer,
            subscribe.message_id.clone(),
            RuntimeReply::Backfill(
                BackfillChunk::conversation(
                    conversation_id.clone(),
                    capabilities,
                    BackfillRange::new(StreamCursor::BeforeFirst, StreamCursor::At(0)).unwrap(),
                    vec![configuration_event],
                )
                .unwrap(),
            ),
        );
        write_reply(
            &mut writer,
            subscribe.message_id,
            RuntimeReply::SyncComplete(RuntimeSyncComplete {
                stream_generation: StreamGeneration::new("generation-continue"),
                stream_cursor: StreamCursor::At(0),
                inner_cursor: RuntimeInnerCursor::Conversation {
                    conversation_id: conversation_id.clone(),
                    cursor: StreamCursor::At(0),
                },
                key_directory_revision: 0,
            }),
        );

        let prompt = read_envelope(&mut reader);
        let RuntimeMessage::Request(RuntimeRequest::SendPrompt(prompt_request)) = prompt.body
        else {
            panic!("continuation must send exact SendPrompt without a receipt preflight")
        };
        assert_eq!(prompt_request.conversation_id, conversation_id);
        assert_eq!(prompt_request.expected_configuration_revision, 7);
        assert_eq!(
            prompt_request.idempotency_key.as_str(),
            "continue-stable-key"
        );
        write_reply(
            &mut writer,
            prompt.message_id,
            RuntimeReply::Command(CommandReceipt::Accepted {
                command_id: CommandId::new("command-continue-backfill"),
                queue_position: 0,
                configuration_revision: 7,
            }),
        );
    });

    let output = runtime_command(&temp_root)
        .args([
            "session",
            "continue",
            "--conversation-id",
            "conversation-continue-backfill",
            "--prompt",
            "continue canonically",
            "--idempotency-key",
            "continue-stable-key",
        ])
        .output()
        .expect("run canonical continuation");
    assert!(
        output.status.success(),
        "stderr: {}",
        String::from_utf8_lossy(&output.stderr)
    );
    let stdout = String::from_utf8(output.stdout).unwrap();
    assert!(stdout.contains("command-continue-backfill"));
    assert!(!stdout.contains("threadId"));
    server_thread.join().unwrap();
}

#[test]
fn continue_without_configuration_returns_typed_failure_after_legal_backfill() {
    let server = TestRuntimeServer::bind();
    let temp_root = server.root.path().to_path_buf();
    let server_thread = thread::spawn(move || {
        let (_, capabilities, _) = codex_description();
        let conversation_id = ConversationId::new("conversation-unconfigured");
        let (mut reader, mut writer, _) = accept_hello(&server.listener);
        let subscribe = read_envelope(&mut reader);
        write_reply(
            &mut writer,
            subscribe.message_id.clone(),
            RuntimeReply::Subscription(SubscriptionReceipt::Subscribed {
                stream_generation: StreamGeneration::new("generation-unconfigured"),
            }),
        );
        let event = RuntimeEvent::new(
            conversation_id.clone(),
            EventId::new("event-unconfigured"),
            0,
            Some(CommandId::new("command-unconfigured")),
            None,
            None,
            RuntimeEventBody::TurnStarted {
                turn_id: TurnId::new("turn-unconfigured"),
            },
        )
        .unwrap();
        write_reply(
            &mut writer,
            subscribe.message_id.clone(),
            RuntimeReply::Backfill(
                BackfillChunk::conversation(
                    conversation_id.clone(),
                    capabilities,
                    BackfillRange::new(StreamCursor::BeforeFirst, StreamCursor::At(0)).unwrap(),
                    vec![event],
                )
                .unwrap(),
            ),
        );
        write_reply(
            &mut writer,
            subscribe.message_id,
            RuntimeReply::SyncComplete(RuntimeSyncComplete {
                stream_generation: StreamGeneration::new("generation-unconfigured"),
                stream_cursor: StreamCursor::At(0),
                inner_cursor: RuntimeInnerCursor::Conversation {
                    conversation_id,
                    cursor: StreamCursor::At(0),
                },
                key_directory_revision: 0,
            }),
        );
        drop(writer);
        let mut tail = Vec::new();
        reader.read_to_end(&mut tail).unwrap();
        assert!(
            tail.is_empty(),
            "unconfigured continuation must stop before QueryReceipt/SendPrompt"
        );
    });

    let output = runtime_command(&temp_root)
        .args([
            "session",
            "continue",
            "--conversation-id",
            "conversation-unconfigured",
            "--prompt",
            "must not send",
            "--idempotency-key",
            "unconfigured-key",
        ])
        .output()
        .expect("run unconfigured continuation");
    assert_eq!(output.status.code(), Some(5));
    assert_eq!(
        stdout_json(&output)["error"]["code"],
        "daemon.conversation.configuration_required"
    );
    server_thread.join().unwrap();
}

#[test]
fn history_and_metadata_commands_keep_canonical_request_shapes() {
    let server = TestRuntimeServer::bind();
    let temp_root = server.root.path().to_path_buf();
    let server_thread = thread::spawn(move || {
        let (mut reader, mut writer, _) = accept_hello(&server.listener);
        let catalog = read_envelope(&mut reader);
        assert!(matches!(
            catalog.body,
            RuntimeMessage::Request(RuntimeRequest::Catalog(ref request))
                if request.page_cursor.is_none()
        ));
        write_reply(
            &mut writer,
            catalog.message_id,
            RuntimeReply::Catalog(
                CatalogSnapshot::new(
                    StreamCursor::At(9),
                    vec![ConversationEntry {
                        conversation_id: ConversationId::new("conversation-history"),
                        agent_kind: AgentKind::Codex,
                        title: Some("Canonical history".to_owned()),
                        cwd: Some(PathBuf::from("/tmp/history-cwd")),
                        last_active_ms: 42,
                        archived: false,
                        entry_revision: 4,
                    }],
                    None,
                )
                .unwrap(),
            ),
        );

        let (mut reader, mut writer, _) = accept_hello(&server.listener);
        let subscribe = read_envelope(&mut reader);
        assert!(matches!(
            subscribe.body,
            RuntimeMessage::Request(RuntimeRequest::Subscribe {
                inner_cursor: RuntimeInnerCursor::Conversation {
                    ref conversation_id,
                    cursor: StreamCursor::BeforeFirst,
                }
            }) if conversation_id.as_str() == "conversation-history"
        ));
        write_reply(
            &mut writer,
            subscribe.message_id.clone(),
            RuntimeReply::Subscription(SubscriptionReceipt::Subscribed {
                stream_generation: StreamGeneration::new("generation-history"),
            }),
        );
        write_reply(
            &mut writer,
            subscribe.message_id,
            RuntimeReply::SyncComplete(RuntimeSyncComplete {
                stream_generation: StreamGeneration::new("generation-history"),
                stream_cursor: StreamCursor::BeforeFirst,
                inner_cursor: RuntimeInnerCursor::Conversation {
                    conversation_id: ConversationId::new("conversation-history"),
                    cursor: StreamCursor::BeforeFirst,
                },
                key_directory_revision: 0,
            }),
        );
        let unsubscribe = read_envelope(&mut reader);
        assert!(matches!(
            unsubscribe.body,
            RuntimeMessage::Request(RuntimeRequest::Unsubscribe {
                target: agentdeck_protocol::runtime::RuntimeSubscriptionTarget::Conversation {
                    ref conversation_id,
                }
            }) if conversation_id.as_str() == "conversation-history"
        ));
        write_reply(
            &mut writer,
            unsubscribe.message_id,
            RuntimeReply::Subscription(SubscriptionReceipt::Unsubscribed),
        );

        let (mut reader, mut writer, _) = accept_hello(&server.listener);
        let metadata = read_envelope(&mut reader);
        let RuntimeMessage::Request(RuntimeRequest::UpdateConversationMetadata(request)) =
            metadata.body
        else {
            panic!("history rename must use UpdateConversationMetadata")
        };
        assert_eq!(request.conversation_id.as_str(), "conversation-history");
        assert_eq!(request.expected_entry_revision, 4);
        assert_eq!(request.idempotency_key.as_str(), "metadata-stable-key");
        assert!(matches!(
            request.mutation,
            ConversationMetadataMutation::Rename { title: Some(ref title) }
                if title == "Renamed canonically"
        ));
        write_reply(
            &mut writer,
            metadata.message_id,
            RuntimeReply::ConversationMetadata(ConversationMetadataReceipt::Applied {
                conversation_id: ConversationId::new("conversation-history"),
                entry_revision: 5,
            }),
        );
    });

    let list = runtime_command(&temp_root)
        .args([
            "history",
            "list",
            "--agent",
            "codex",
            "--cwd-filter",
            "/tmp/history-cwd",
        ])
        .output()
        .expect("run history list");
    assert!(list.status.success());
    assert!(
        String::from_utf8(list.stdout)
            .unwrap()
            .contains("conversation-history")
    );

    let read = runtime_command(&temp_root)
        .args(["history", "read", "conversation-history"])
        .output()
        .expect("run history read");
    assert!(
        read.status.success(),
        "stderr: {}",
        String::from_utf8_lossy(&read.stderr)
    );
    assert!(
        String::from_utf8(read.stdout)
            .unwrap()
            .contains("unsubscribed")
    );

    let rename = runtime_command(&temp_root)
        .args([
            "history",
            "rename",
            "conversation-history",
            "Renamed canonically",
            "--expected-entry-revision",
            "4",
            "--idempotency-key",
            "metadata-stable-key",
        ])
        .output()
        .expect("run history rename");
    assert!(
        rename.status.success(),
        "stderr: {}",
        String::from_utf8_lossy(&rename.stderr)
    );
    let rename_stdout = String::from_utf8(rename.stdout).unwrap();
    assert!(rename_stdout.contains("metadata-stable-key"));
    assert!(!rename_stdout.contains("threadId"));
    server_thread.join().unwrap();
}

#[test]
fn local_protocol_remote_and_legacy_argument_failures_never_connect_runtime() {
    let server = TestRuntimeServer::bind();
    let temp_root = server.root.path().to_path_buf();

    let protocol = runtime_command(&temp_root)
        .args(["protocol", "version"])
        .output()
        .expect("run local protocol command");
    assert!(protocol.status.success());

    let remote = runtime_command(&temp_root)
        .args(["remote", "smoke"])
        .output()
        .expect("run removed remote command");
    assert!(!remote.status.success());

    for arguments in [
        vec![
            "session",
            "continue",
            "--thread-id",
            "legacy-thread",
            "--prompt",
            "hello",
            "--idempotency-key",
            "legacy-reject-key",
        ],
        vec![
            "session",
            "run",
            "--agent",
            "codex",
            "--cwd",
            "/tmp",
            "--prompt",
            "hello",
            "--idempotency-key",
            "legacy-reject-key",
            "--persist-approval",
        ],
        vec![
            "session",
            "run",
            "--agent",
            "codex",
            "--cwd",
            "/tmp",
            "--prompt",
            "hello",
            "--idempotency-key",
            "legacy-reject-key",
            "--worktree",
            "/tmp/legacy",
        ],
        vec![
            "session",
            "run",
            "--agent",
            "codex",
            "--cwd",
            "/tmp",
            "--prompt",
            "hello",
            "--idempotency-key",
            "legacy-reject-key",
            "--session-name",
            "legacy-name",
        ],
    ] {
        let output = runtime_command(&temp_root)
            .args(arguments)
            .output()
            .expect("run legacy argument rejection");
        assert_eq!(output.status.code(), Some(2));
        let error = stdout_json(&output);
        assert_eq!(error["error"]["code"], "usage");
        assert!(
            error["error"]["message"]
                .as_str()
                .is_some_and(|message| message.contains("unexpected argument")),
            "legacy argument rejection must retain the typed parser reason: {error}"
        );
    }

    server.listener.set_nonblocking(true).unwrap();
    let error = server
        .listener
        .accept()
        .expect_err("local/remote/usage commands must not connect Runtime");
    assert_eq!(error.kind(), std::io::ErrorKind::WouldBlock);
}

#[test]
fn debug_smoke_exposes_stable_installation_owner_queries_and_sync_summary() {
    let server = TestRuntimeServer::bind();
    let temp_root = server.root.path().to_path_buf();
    let server_thread = thread::spawn(move || {
        let mut installations = Vec::new();

        let (mut reader, writer, installation_id) = accept_hello(&server.listener);
        installations.push(installation_id);
        drop(writer);
        let mut tail = Vec::new();
        reader.read_to_end(&mut tail).unwrap();
        assert!(tail.is_empty());

        let (mut reader, mut writer, installation_id) = accept_hello(&server.listener);
        installations.push(installation_id);
        let send = read_envelope(&mut reader);
        let RuntimeMessage::Request(RuntimeRequest::SendPrompt(request)) = send.body else {
            panic!("smoke send-prompt must emit SendPrompt")
        };
        assert_eq!(request.conversation_id.as_str(), "conversation-smoke");
        assert_eq!(request.idempotency_key.as_str(), "smoke-rust-key");
        assert_eq!(request.expected_configuration_revision, 1);
        write_reply(
            &mut writer,
            send.message_id,
            RuntimeReply::Command(CommandReceipt::Accepted {
                command_id: CommandId::new("command-rust"),
                queue_position: 0,
                configuration_revision: 1,
            }),
        );

        let (mut reader, mut writer, installation_id) = accept_hello(&server.listener);
        installations.push(installation_id);
        let foreign_query = read_envelope(&mut reader);
        assert!(matches!(
            foreign_query.body,
            RuntimeMessage::Request(RuntimeRequest::QueryReceipt(
                QueryReceiptSelector::Command {
                    ref conversation_id,
                    ref command_id,
                }
            )) if conversation_id.as_str() == "conversation-smoke"
                && command_id.as_str() == "command-swift"
        ));
        write_reply(
            &mut writer,
            foreign_query.message_id,
            RuntimeReply::Failure(RuntimeFailure::new(
                "daemon.runtime.invalid_state",
                "command belongs to another installation owner",
            )),
        );

        let (mut reader, mut writer, installation_id) = accept_hello(&server.listener);
        installations.push(installation_id);
        let own_query = read_envelope(&mut reader);
        assert!(matches!(
            own_query.body,
            RuntimeMessage::Request(RuntimeRequest::QueryReceipt(
                QueryReceiptSelector::Idempotency {
                    ref conversation_id,
                    ref idempotency_key,
                }
            )) if conversation_id.as_str() == "conversation-smoke"
                && idempotency_key.as_str() == "smoke-rust-key"
        ));
        write_reply(
            &mut writer,
            own_query.message_id,
            RuntimeReply::CommandStatus(CommandStatusReceipt {
                conversation_id: ConversationId::new("conversation-smoke"),
                command_id: CommandId::new("command-rust"),
                configuration_revision: 1,
                status: CommandStatus::Completed,
                turn_id: None,
            }),
        );

        let (descriptions, capabilities, configuration) = codex_description();
        drop(descriptions);
        let (mut reader, mut writer, installation_id) = accept_hello(&server.listener);
        installations.push(installation_id);
        let subscribe = read_envelope(&mut reader);
        assert!(matches!(
            subscribe.body,
            RuntimeMessage::Request(RuntimeRequest::Subscribe {
                inner_cursor: RuntimeInnerCursor::Conversation {
                    ref conversation_id,
                    cursor: StreamCursor::BeforeFirst,
                }
            }) if conversation_id.as_str() == "conversation-smoke"
        ));
        write_reply(
            &mut writer,
            subscribe.message_id.clone(),
            RuntimeReply::Subscription(SubscriptionReceipt::Subscribed {
                stream_generation: StreamGeneration::new("generation-smoke"),
            }),
        );
        write_reply(
            &mut writer,
            subscribe.message_id.clone(),
            RuntimeReply::Snapshot(
                ConversationSnapshot::new(
                    ConversationId::new("conversation-smoke"),
                    StreamCursor::BeforeFirst,
                    ConversationConfigurationState::new(1, Some(configuration)).unwrap(),
                    vec![SnapshotItem::capabilities(capabilities.clone())],
                )
                .unwrap(),
            ),
        );
        let events = vec![
            RuntimeEvent::new(
                ConversationId::new("conversation-smoke"),
                EventId::new("event-command-rust"),
                0,
                Some(CommandId::new("command-rust")),
                None,
                None,
                RuntimeEventBody::TurnStarted {
                    turn_id: TurnId::new("turn-rust"),
                },
            )
            .unwrap(),
            RuntimeEvent::new(
                ConversationId::new("conversation-smoke"),
                EventId::new("event-command-swift"),
                1,
                Some(CommandId::new("command-swift")),
                None,
                None,
                RuntimeEventBody::TurnStarted {
                    turn_id: TurnId::new("turn-swift"),
                },
            )
            .unwrap(),
        ];
        write_reply(
            &mut writer,
            subscribe.message_id.clone(),
            RuntimeReply::Backfill(
                BackfillChunk::conversation(
                    ConversationId::new("conversation-smoke"),
                    capabilities,
                    BackfillRange::new(StreamCursor::BeforeFirst, StreamCursor::At(1)).unwrap(),
                    events,
                )
                .unwrap(),
            ),
        );
        write_reply(
            &mut writer,
            subscribe.message_id,
            RuntimeReply::SyncComplete(RuntimeSyncComplete {
                stream_generation: StreamGeneration::new("generation-smoke"),
                // Relay-committed outer cursor 与 conversation inner cursor 是
                // 两条独立轴；合法 barrier 不要求二者数值相等。
                stream_cursor: StreamCursor::At(77),
                inner_cursor: RuntimeInnerCursor::Conversation {
                    conversation_id: ConversationId::new("conversation-smoke"),
                    cursor: StreamCursor::At(1),
                },
                key_directory_revision: 0,
            }),
        );

        installations
    });

    let installation = runtime_command(&temp_root)
        .args(["runtime-smoke-for-test", "installation"])
        .output()
        .expect("read smoke installation");
    assert!(installation.status.success());
    let installation_json = stdout_json(&installation);
    assert_eq!(installation_json["operation"], "installation");
    assert_eq!(installation_json["ok"], true);

    let send = runtime_command(&temp_root)
        .args([
            "runtime-smoke-for-test",
            "send-prompt",
            "--conversation-id",
            "conversation-smoke",
            "--idempotency-key",
            "smoke-rust-key",
            "--expected-configuration-revision",
            "1",
            "--prompt",
            "smoke prompt",
        ])
        .output()
        .expect("run smoke SendPrompt");
    assert!(send.status.success());
    assert_eq!(stdout_json(&send)["commandId"], "command-rust");

    let foreign_query = runtime_command(&temp_root)
        .args([
            "runtime-smoke-for-test",
            "query-receipt",
            "--conversation-id",
            "conversation-smoke",
            "--command-id",
            "command-swift",
        ])
        .output()
        .expect("run cross-owner smoke QueryReceipt");
    assert_eq!(foreign_query.status.code(), Some(5));
    assert_eq!(
        stdout_json(&foreign_query)["error"]["code"],
        "daemon.runtime.invalid_state"
    );

    let own_query = runtime_command(&temp_root)
        .args([
            "runtime-smoke-for-test",
            "query-receipt",
            "--conversation-id",
            "conversation-smoke",
            "--idempotency-key",
            "smoke-rust-key",
        ])
        .output()
        .expect("run owner-scoped smoke QueryReceipt");
    assert!(own_query.status.success());
    assert_eq!(stdout_json(&own_query)["commandId"], "command-rust");

    let subscribe = runtime_command(&temp_root)
        .args([
            "runtime-smoke-for-test",
            "subscribe",
            "--conversation-id",
            "conversation-smoke",
        ])
        .output()
        .expect("run smoke Subscribe");
    assert!(
        subscribe.status.success(),
        "stderr: {}",
        String::from_utf8_lossy(&subscribe.stderr)
    );
    let subscribe_json = stdout_json(&subscribe);
    assert_eq!(subscribe_json["operation"], "subscribe");
    assert_eq!(subscribe_json["snapshotCount"], 1);
    assert_eq!(subscribe_json["backfillCount"], 1);
    assert_eq!(
        subscribe_json["commandIds"],
        serde_json::json!(["command-rust", "command-swift"])
    );
    assert_eq!(subscribe_json["terminalStreamCursor"]["at"], 77);

    let installations = server_thread.join().unwrap();
    assert!(
        installations
            .iter()
            .all(|candidate| candidate == &installations[0])
    );
    assert_eq!(installation_json["installationId"], installations[0]);
}

#[test]
fn session_run_emits_only_canonical_runtime_v2_requests_and_ids() {
    let server = TestRuntimeServer::bind();
    let temp_root = server.root.path().to_path_buf();
    let server_thread = thread::spawn(move || {
        let (descriptions, capabilities, configuration) = codex_description();
        for attempt in 0..3 {
            let (mut reader, mut writer, _) = accept_hello(&server.listener);

            let describe = read_envelope(&mut reader);
            assert!(matches!(
                describe.body,
                RuntimeMessage::Request(RuntimeRequest::DescribeAgents)
            ));
            write_reply(
                &mut writer,
                describe.message_id,
                RuntimeReply::Agents(descriptions.clone()),
            );

            let start = read_envelope(&mut reader);
            let RuntimeMessage::Request(RuntimeRequest::Start(start_request)) = start.body else {
                panic!("DescribeAgents must be followed by Start")
            };
            assert_eq!(start_request.agent_kind, AgentKind::Codex);
            assert_eq!(start_request.cwd, PathBuf::from("/tmp/runtime-cli-cwd"));
            assert_eq!(start_request.title, None);
            assert_eq!(
                start_request.idempotency_key.as_str(),
                "stable-session-run:start"
            );
            write_reply(
                &mut writer,
                start.message_id,
                RuntimeReply::ConversationStart(ConversationStartReceipt {
                    conversation_id: ConversationId::new("conversation-cli-1"),
                    replayed: attempt == 1,
                }),
            );

            let configure = read_envelope(&mut reader);
            let RuntimeMessage::Request(RuntimeRequest::ConfigureConversation(configure_request)) =
                configure.body
            else {
                panic!("Start must be followed by ConfigureConversation")
            };
            assert_eq!(
                configure_request.conversation_id.as_str(),
                "conversation-cli-1"
            );
            assert_eq!(configure_request.expected_configuration_revision, 0);
            assert_eq!(
                configure_request.idempotency_key.as_str(),
                "stable-session-run:configure"
            );
            assert_eq!(configure_request.configuration, configuration);
            let configuration_receipt = if attempt == 0 {
                ConfigurationReceipt::Applied {
                    conversation_id: ConversationId::new("conversation-cli-1"),
                    configuration_revision: 1,
                }
            } else {
                ConfigurationReceipt::Replayed {
                    conversation_id: ConversationId::new("conversation-cli-1"),
                    configuration_revision: 1,
                }
            };
            write_reply(
                &mut writer,
                configure.message_id,
                RuntimeReply::Configuration(configuration_receipt),
            );

            let subscribe = read_envelope(&mut reader);
            assert!(matches!(
                subscribe.body,
                RuntimeMessage::Request(RuntimeRequest::Subscribe {
                    inner_cursor: RuntimeInnerCursor::Conversation {
                        ref conversation_id,
                        cursor: StreamCursor::BeforeFirst,
                    }
                }) if conversation_id.as_str() == "conversation-cli-1"
            ));
            let generation = format!("generation-cli-{attempt}");
            write_reply(
                &mut writer,
                subscribe.message_id.clone(),
                RuntimeReply::Subscription(SubscriptionReceipt::Subscribed {
                    stream_generation: StreamGeneration::new(generation.clone()),
                }),
            );
            let snapshot_revision = if attempt == 0 { 1 } else { 2 };
            write_reply(
                &mut writer,
                subscribe.message_id.clone(),
                RuntimeReply::Snapshot(
                    ConversationSnapshot::new(
                        ConversationId::new("conversation-cli-1"),
                        StreamCursor::BeforeFirst,
                        ConversationConfigurationState::new(
                            snapshot_revision,
                            Some(configuration.clone()),
                        )
                        .unwrap(),
                        vec![SnapshotItem::capabilities(capabilities.clone())],
                    )
                    .unwrap(),
                ),
            );
            write_reply(
                &mut writer,
                subscribe.message_id,
                RuntimeReply::SyncComplete(RuntimeSyncComplete {
                    stream_generation: StreamGeneration::new(generation),
                    stream_cursor: StreamCursor::BeforeFirst,
                    inner_cursor: RuntimeInnerCursor::Conversation {
                        conversation_id: ConversationId::new("conversation-cli-1"),
                        cursor: StreamCursor::BeforeFirst,
                    },
                    key_directory_revision: 0,
                }),
            );

            let prompt = read_envelope(&mut reader);
            let RuntimeMessage::Request(RuntimeRequest::SendPrompt(prompt_request)) = prompt.body
            else {
                panic!("Subscribe must be followed directly by exact SendPrompt")
            };
            assert_eq!(
                prompt_request.conversation_id.as_str(),
                "conversation-cli-1"
            );
            assert_eq!(prompt_request.expected_configuration_revision, 1);
            assert_eq!(
                prompt_request.idempotency_key.as_str(),
                "stable-session-run:prompt"
            );
            let expected_prompt = if attempt == 2 {
                "changed payload must conflict"
            } else {
                "hello canonical runtime"
            };
            assert_eq!(prompt_request.prompt.as_str(), expected_prompt);
            let receipt = match attempt {
                0 => CommandReceipt::Accepted {
                    command_id: CommandId::new("command-cli-1"),
                    queue_position: 0,
                    configuration_revision: 1,
                },
                1 => CommandReceipt::Replayed {
                    command_id: CommandId::new("command-cli-1"),
                    configuration_revision: 1,
                },
                _ => CommandReceipt::Failed {
                    failure: RuntimeFailure::new(
                        agentdeck_protocol::runtime::failure::DAEMON_COMMAND_IDEMPOTENCY_CONFLICT,
                        "same key has another prompt payload",
                    ),
                },
            };
            write_reply(
                &mut writer,
                prompt.message_id,
                RuntimeReply::Command(receipt),
            );
        }
    });

    let mut outputs = Vec::new();
    for _ in 0..2 {
        let output = runtime_command(&temp_root)
            .args([
                "session",
                "run",
                "--agent",
                "codex",
                "--cwd",
                "/tmp/runtime-cli-cwd",
                "--prompt",
                "hello canonical runtime",
                "--idempotency-key",
                "stable-session-run",
            ])
            .output()
            .expect("run canonical session");
        assert!(
            output.status.success(),
            "stderr: {}",
            String::from_utf8_lossy(&output.stderr)
        );
        outputs.push(String::from_utf8(output.stdout).unwrap());
    }
    let conflict = runtime_command(&temp_root)
        .args([
            "session",
            "run",
            "--agent",
            "codex",
            "--cwd",
            "/tmp/runtime-cli-cwd",
            "--prompt",
            "changed payload must conflict",
            "--idempotency-key",
            "stable-session-run",
        ])
        .output()
        .expect("run conflicting canonical session retry");
    assert_eq!(conflict.status.code(), Some(5));
    assert!(
        String::from_utf8_lossy(&conflict.stdout).contains("daemon.command.idempotency_conflict"),
        "payload conflict must be surfaced from SendPrompt: {}",
        String::from_utf8_lossy(&conflict.stdout)
    );
    server_thread.join().unwrap();
    for stdout in outputs {
        assert!(stdout.contains("stable-session-run:prompt"));
        assert!(stdout.contains("conversation-cli-1"));
        assert!(stdout.contains("command-cli-1"));
        for forbidden in ["threadId", "sessionId", "adapterStateKey"] {
            assert!(
                !stdout.contains(forbidden),
                "legacy identity leaked: {stdout}"
            );
        }
    }
}

#[test]
fn synchronized_subscribe_has_an_absolute_reply_deadline() {
    let server = TestRuntimeServer::bind();
    let temp_root = server.root.path().to_path_buf();
    let server_thread = thread::spawn(move || {
        let (mut reader, mut writer, _) = accept_hello(&server.listener);
        let subscribe = read_envelope(&mut reader);
        assert!(matches!(
            subscribe.body,
            RuntimeMessage::Request(RuntimeRequest::Subscribe { .. })
        ));
        write_reply(
            &mut writer,
            subscribe.message_id,
            RuntimeReply::Subscription(SubscriptionReceipt::Subscribed {
                stream_generation: StreamGeneration::new("generation-stalled"),
            }),
        );
        reader
            .get_mut()
            .set_read_timeout(Some(Duration::from_secs(40)))
            .expect("bound stalled peer lifetime");
        let mut tail = Vec::new();
        reader
            .read_to_end(&mut tail)
            .expect("client must close the timed-out Runtime connection");
        assert!(tail.is_empty(), "stalled Subscribe sent an extra request");
        drop(writer);
    });

    let mut command = runtime_command(&temp_root);
    command
        .args(["history", "read", "conversation-stalled"])
        .stdout(Stdio::piped())
        .stderr(Stdio::piped());
    let mut child = command.spawn().expect("spawn stalled Subscribe CLI");
    let deadline = Instant::now() + Duration::from_secs(35);
    loop {
        if child
            .try_wait()
            .expect("poll stalled Subscribe CLI")
            .is_some()
        {
            break;
        }
        if Instant::now() >= deadline {
            child.kill().expect("kill hung Subscribe CLI");
            let _ = child.wait();
            panic!("Subscribe CLI exceeded its absolute reply deadline");
        }
        thread::sleep(Duration::from_millis(20));
    }
    let output = child
        .wait_with_output()
        .expect("collect timed-out Subscribe CLI");
    assert_eq!(output.status.code(), Some(4));
    assert_eq!(
        stdout_json(&output)["error"]["code"],
        "daemon.client.reply_timeout"
    );
    server_thread.join().unwrap();
}
