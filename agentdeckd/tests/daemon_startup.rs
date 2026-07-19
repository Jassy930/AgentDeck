use std::fs;
use std::io::{BufRead, BufReader, Read, Write};
use std::os::fd::AsRawFd;
use std::os::unix::fs::{FileTypeExt, MetadataExt, PermissionsExt};
use std::path::{Path, PathBuf};
use std::process::{Child, Command, ExitStatus, Output, Stdio};
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

use agentdeck_protocol::AgentKind;
use agentdeck_protocol::runtime::command::{CatalogRequest, ConversationStart, HelloParams};
use agentdeck_protocol::runtime::identity::{IdempotencyKey, MessageId};
use agentdeck_protocol::runtime::{
    RUNTIME_PROTOCOL_VERSION, RuntimeEnvelope, RuntimeMessage, RuntimeReply, RuntimeRequest,
};
use agentdeckd::config::compiled_stable_keychain_access_group;

const MAIN_SOURCE: &str = include_str!("../src/main.rs");

struct TestRoot(PathBuf);

struct ChildGuard(Child);

impl ChildGuard {
    fn child_mut(&mut self) -> &mut Child {
        &mut self.0
    }
}

impl Drop for ChildGuard {
    fn drop(&mut self) {
        let _ = self.0.kill();
        let _ = self.0.wait();
    }
}

impl TestRoot {
    fn new(label: &str) -> Self {
        // macOS sockaddr_un 只有 104 bytes；测试 root 必须像生产 ephemeral
        // namespace 一样保持很短，不能让夹具路径先耗尽预算。
        let root = PathBuf::from("/tmp").join(format!(
            "ads-{label}-{}-{:x}",
            std::process::id(),
            SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .expect("system clock")
                .as_nanos()
        ));
        fs::create_dir(&root).expect("create test root");
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            fs::set_permissions(&root, fs::Permissions::from_mode(0o700))
                .expect("make test root private");
        }
        Self(root)
    }

    fn path(&self) -> &Path {
        &self.0
    }
}

impl Drop for TestRoot {
    fn drop(&mut self) {
        let _ = fs::remove_dir_all(&self.0);
    }
}

fn daemon(args: &[&str]) -> Output {
    Command::new(env!("CARGO_BIN_EXE_agentdeckd"))
        .args(args)
        .stdin(Stdio::null())
        .output()
        .expect("run agentdeckd")
}

fn assert_rejected(args: &[&str], code: &str) {
    let output = daemon(args);
    assert_eq!(
        output.status.code(),
        Some(2),
        "args {args:?}\nstdout={}\nstderr={}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );
    assert!(
        String::from_utf8_lossy(&output.stderr).contains(code),
        "args {args:?} did not expose {code}: {}",
        String::from_utf8_lossy(&output.stderr)
    );
}

fn assert_source_order(label: &str, source: &str, needles: &[&str]) {
    let mut cursor = 0;
    for needle in needles {
        let offset = source[cursor..]
            .find(needle)
            .unwrap_or_else(|| panic!("{label}: missing {needle:?}"));
        cursor += offset + needle.len();
    }
}

#[test]
fn runtime_bootstrap_quiesces_owned_resources_before_releasing_singleton() {
    // 威胁场景：Store 已打开后 Core 构造或 recovery 失败，启动路径提前返回；
    // SQLite worker/lock 未收到 shutdown 回执，singleton 却已释放，下一实例会撞上残留资源。
    let loop_start = MAIN_SOURCE
        .find("fn run_main_loop(")
        .expect("run_main_loop source");
    let loop_end = MAIN_SOURCE[loop_start..]
        .find("\nfn main()")
        .map(|offset| loop_start + offset)
        .expect("main source");
    let loop_source = &MAIN_SOURCE[loop_start..loop_end];

    assert_source_order(
        "store construction failure cleanup",
        loop_source,
        &[
            "RuntimeStoreHandle::open",
            "RuntimeCore::new_production(store.clone(), router.clone())",
            "store.shutdown().await",
            "return Err(MainLoopFailure::runtime(error))",
        ],
    );
    assert_source_order(
        "core-owned cleanup",
        loop_source,
        &[
            "let run_result = async",
            ".recover_for_startup()",
            "BoundLocalListener::bind_after_recovery(",
            ".take_remote_start_permit()",
            ".serve_until(",
            "let shutdown = core.shutdown().await",
            "run_result?",
            "shutdown.map_err(MainLoopFailure::runtime)",
        ],
    );

    let main_source = &MAIN_SOURCE[loop_end..];
    assert_source_order(
        "singleton lifetime",
        main_source,
        &[
            "match run_main_loop(&config, &singleton_guard, &*key_store, storage_kek)",
            "drop((key_store, singleton_guard))",
        ],
    );
}

#[test]
fn rejects_incomplete_or_mismatched_startup_modes_with_typed_codes() {
    assert_rejected(
        &["--ephemeral", "--profile", "dev", "--selfcheck"],
        "daemon.config.ephemeral_requires_no_remote",
    );
    assert_rejected(
        &["--no-remote", "--profile", "dev", "--selfcheck"],
        "daemon.config.no_remote_requires_ephemeral",
    );
    assert_rejected(
        &["--profile", "dev", "--selfcheck"],
        "daemon.config.dev_requires_ephemeral",
    );
    assert_rejected(
        &[
            "--ephemeral",
            "--no-remote",
            "--profile",
            "stable",
            "--selfcheck",
        ],
        "daemon.config.stable_forbids_ephemeral",
    );
    assert_rejected(
        &["--profile", "preview", "--selfcheck"],
        "daemon.cli.invalid_profile",
    );
    assert_rejected(
        &["--stdio-compat", "--selfcheck"],
        "daemon.config.stdio_compat_requires_ephemeral_no_remote",
    );
    assert_rejected(
        &[
            "--stdio-compat",
            "--ephemeral",
            "--profile",
            "dev",
            "--selfcheck",
        ],
        "daemon.config.stdio_compat_requires_ephemeral_no_remote",
    );
    assert_rejected(
        &["--socket", "/tmp/injected.sock"],
        "daemon.cli.unknown_argument",
    );
}

#[test]
fn explicit_stdio_compat_exits_on_eof() {
    let root = TestRoot::new("stdio");
    let output = Command::new(env!("CARGO_BIN_EXE_agentdeckd"))
        .args([
            "--stdio-compat",
            "--ephemeral",
            "--no-remote",
            "--profile",
            "dev",
        ])
        .env("TMPDIR", root.path())
        .stdin(Stdio::null())
        .output()
        .expect("run explicit stdio compatibility");
    assert!(
        output.status.success(),
        "stdout={}\nstderr={}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );
    assert!(
        discover_runtime_sockets(root.path()).is_empty(),
        "stdio compatibility must not bind a Runtime UDS"
    );
}

#[test]
fn explicit_stdio_compat_allows_admin_and_typed_rejects_control() {
    let root = TestRoot::new("stdio-policy");
    let child = Command::new(env!("CARGO_BIN_EXE_agentdeckd"))
        .args([
            "--stdio-compat",
            "--ephemeral",
            "--no-remote",
            "--profile",
            "dev",
        ])
        .env("TMPDIR", root.path())
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .expect("spawn stdio policy daemon");
    let mut child = ChildGuard(child);
    let mut input = child
        .child_mut()
        .stdin
        .take()
        .expect("piped stdio policy stdin");
    writeln!(input, "{{\"command\":\"ping\"}}").expect("write allowed Ping");
    writeln!(
        input,
        "{{\"command\":\"sessionCancel\",\"sessionId\":\"must-not-route\"}}"
    )
    .expect("write forbidden control");
    drop(input);

    let status = wait_for_exit(child.child_mut());
    let mut stdout = String::new();
    child
        .child_mut()
        .stdout
        .take()
        .expect("piped stdio policy stdout")
        .read_to_string(&mut stdout)
        .expect("read stdio policy stdout");
    let mut stderr = String::new();
    child
        .child_mut()
        .stderr
        .take()
        .expect("piped stdio policy stderr")
        .read_to_string(&mut stderr)
        .expect("read stdio policy stderr");
    assert!(status.success(), "stderr={stderr}");
    let replies = stdout
        .lines()
        .map(|line| serde_json::from_str::<serde_json::Value>(line).expect("stdio JSON reply"))
        .collect::<Vec<_>>();
    assert!(
        replies
            .iter()
            .any(|reply| reply.get("reply").and_then(|value| value.as_str()) == Some("ping")),
        "missing Ping reply: {replies:?}"
    );
    assert!(
        replies.iter().any(|reply| {
            reply
                .pointer("/error/code")
                .and_then(|value| value.as_str())
                == Some("daemon.runtime.stdio_command_forbidden")
        }),
        "missing typed control rejection: {replies:?}"
    );
    assert!(discover_runtime_sockets(root.path()).is_empty());
}

#[test]
fn ephemeral_uds_ignores_stdin_eof_and_env_override_then_cleans_up_on_sigterm() {
    // 威胁场景：默认 ephemeral daemon 若仍由 stdin EOF 驱动，测试客户端一关闭
    // pipe 就会误杀共享 Runtime；socket env override 还会把入口移出隔离 namespace。
    let root = TestRoot::new("uds");
    let injected = root.path().join("injected.sock");
    let child = Command::new(env!("CARGO_BIN_EXE_agentdeckd"))
        .args(["--ephemeral", "--no-remote", "--profile", "dev"])
        .env("TMPDIR", root.path())
        .env("AGENTDECK_DAEMON_SOCKET", &injected)
        .stdin(Stdio::null())
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .spawn()
        .expect("spawn ephemeral UDS daemon");
    let mut child = ChildGuard(child);
    let socket = wait_for_single_runtime_socket(child.child_mut(), root.path());
    assert!(
        !injected.exists(),
        "daemon must ignore socket path env override"
    );
    assert_runtime_hello(&socket);
    let pid = child.child_mut().id();

    // 威胁场景：一个真实 daemon 的 UDS client 停止读取大 catalog 时，
    // connection-level egress backpressure 不得终止 listener、替换 daemon PID，
    // 或阻断 sibling 的 RuntimeCore 请求。
    let mut sibling = connect_runtime(&socket, "123e4567-e89b-12d3-a456-426614174401");
    let started = runtime_roundtrip(
        &mut sibling,
        RuntimeEnvelope {
            version: RUNTIME_PROTOCOL_VERSION,
            message_id: MessageId::new("binary-large-catalog-entry"),
            body: RuntimeMessage::Request(RuntimeRequest::Start(ConversationStart {
                agent_kind: AgentKind::Codex,
                idempotency_key: IdempotencyKey::new("binary-large-catalog-entry"),
                cwd: PathBuf::from("/tmp/agentdeck-binary-backpressure"),
                title: Some("x".repeat(700 * 1024)),
            })),
        },
    );
    assert!(matches!(
        started.body,
        RuntimeMessage::Reply(RuntimeReply::ConversationStart(_))
    ));

    let mut slow = connect_runtime(&socket, "123e4567-e89b-12d3-a456-426614174402");
    set_small_runtime_receive_buffer(&slow);
    write_runtime_envelope(
        &mut slow,
        &RuntimeEnvelope {
            version: RUNTIME_PROTOCOL_VERSION,
            message_id: MessageId::new("binary-slow-catalog"),
            body: RuntimeMessage::Request(RuntimeRequest::Catalog(CatalogRequest {
                page_cursor: None,
            })),
        },
    );
    let backpressure_deadline = Instant::now() + Duration::from_secs(5);
    while runtime_readable_bytes(&slow) == 0 {
        assert!(
            Instant::now() < backpressure_deadline,
            "large catalog never reached slow client"
        );
        assert!(
            child
                .child_mut()
                .try_wait()
                .expect("probe daemon during backpressure")
                .is_none(),
            "daemon exited while one client was backpressured"
        );
        std::thread::sleep(Duration::from_millis(5));
    }
    let sibling_reply = runtime_roundtrip(&mut sibling, hello_envelope("binary-sibling-alive"));
    assert!(matches!(
        sibling_reply.body,
        RuntimeMessage::Reply(RuntimeReply::Hello(_))
    ));
    assert!(
        child
            .child_mut()
            .try_wait()
            .expect("probe daemon after stdin EOF")
            .is_none(),
        "UDS daemon must stay alive after inherited stdin EOF"
    );
    assert_eq!(child.child_mut().id(), pid);
    // SAFETY: signal 0 is a read-only existence probe for the exact child PID.
    assert_eq!(unsafe { libc::kill(pid as libc::pid_t, 0) }, 0);
    drop((slow, sibling));

    // SAFETY: pid belongs to the live child owned by ChildGuard.
    assert_eq!(unsafe { libc::kill(pid as libc::pid_t, libc::SIGTERM) }, 0);
    let status = wait_for_exit(child.child_mut());
    assert!(status.success(), "SIGTERM shutdown status: {status}");
    assert!(!socket.exists(), "exact Runtime socket must be removed");
}

#[test]
fn data_dir_override_is_diagnostics_only() {
    assert_rejected(
        &[
            "--ephemeral",
            "--no-remote",
            "--profile",
            "dev",
            "--selfcheck",
            "--data-dir",
            "/tmp/forbidden-selfcheck",
        ],
        "daemon.cli.data_dir_forbidden",
    );
    assert_rejected(
        &["--data-dir", "/tmp/forbidden-serve"],
        "daemon.cli.data_dir_forbidden",
    );
}

#[test]
fn unsigned_stable_daemon_cannot_be_provisioned_by_runtime_environment() {
    if compiled_stable_keychain_access_group().is_some() {
        // Release-signed builds exercise the real Keychain path in the gated signing test.
        return;
    }

    let output = Command::new(env!("CARGO_BIN_EXE_agentdeckd"))
        .arg("--selfcheck")
        .env(
            "AGENTDECK_DAEMON_KEYCHAIN_ACCESS_GROUP",
            "RUNTIMEENV.com.agentdeck.agentdeckd.stable",
        )
        .stdin(Stdio::null())
        .output()
        .expect("run unsigned stable daemon");

    assert!(!output.status.success());
    assert!(
        String::from_utf8_lossy(&output.stderr)
            .contains("daemon.keystore.access_group_unconfigured"),
        "stderr={}",
        String::from_utf8_lossy(&output.stderr)
    );
}

#[test]
fn ephemeral_selfcheck_uses_a_fresh_private_namespace_each_time() {
    let root = TestRoot::new("ephemeral");
    let canonical_root = fs::canonicalize(root.path()).expect("canonical selfcheck temp root");
    let first = run_ephemeral_selfcheck(root.path());
    let second = run_ephemeral_selfcheck(root.path());

    assert_ne!(first, second);
    for data_dir in [first, second] {
        assert!(
            data_dir.starts_with(&canonical_root),
            "{}",
            data_dir.display()
        );
        assert!(data_dir.join("agentdeckd.lock").is_file());
        assert!(data_dir.join("diagnostic.log").is_file());
        let runs = data_dir.join("runs");
        assert!(runs.is_dir());
        assert!(
            fs::read_dir(runs)
                .expect("read selfcheck records")
                .any(|entry| entry
                    .expect("record entry")
                    .path()
                    .extension()
                    .is_some_and(|ext| ext == "jsonl"))
        );
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            assert_eq!(
                fs::metadata(&data_dir)
                    .expect("ephemeral namespace metadata")
                    .permissions()
                    .mode()
                    & 0o777,
                0o700
            );
        }
    }
}

fn run_ephemeral_selfcheck(temp_root: &Path) -> PathBuf {
    let output = Command::new(env!("CARGO_BIN_EXE_agentdeckd"))
        .args([
            "--ephemeral",
            "--no-remote",
            "--profile",
            "dev",
            "--selfcheck",
        ])
        .env("TMPDIR", temp_root)
        .env(
            "AGENTDECK_DATA_DIR",
            temp_root.join("legacy-override-must-not-win"),
        )
        .stdin(Stdio::null())
        .output()
        .expect("run ephemeral selfcheck");
    assert!(
        output.status.success(),
        "stdout={}\nstderr={}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );
    let stdout = String::from_utf8(output.stdout).expect("UTF-8 selfcheck output");
    assert_eq!(stdout.lines().next(), Some("OK"));
    let summary: serde_json::Value =
        serde_json::from_str(stdout.lines().nth(1).expect("selfcheck JSON summary line"))
            .expect("parse selfcheck JSON");
    PathBuf::from(
        summary["dataDir"]
            .as_str()
            .expect("selfcheck dataDir string"),
    )
}

fn discover_runtime_sockets(temp_root: &Path) -> Vec<PathBuf> {
    let mut sockets = Vec::new();
    let entries = match fs::read_dir(temp_root) {
        Ok(entries) => entries,
        Err(_) => return sockets,
    };
    for entry in entries.flatten() {
        if !entry.file_name().to_string_lossy().starts_with("ad-") {
            continue;
        }
        let socket = entry.path().join("s");
        if fs::symlink_metadata(&socket).is_ok_and(|metadata| metadata.file_type().is_socket()) {
            sockets.push(socket);
        }
    }
    sockets.sort();
    sockets
}

fn wait_for_single_runtime_socket(child: &mut Child, temp_root: &Path) -> PathBuf {
    // 威胁场景：把尚未完成 pathname 权限收紧/readback 的 socket 交给客户端，
    // 会让共享 Runtime 控制面短暂暴露在预期信任边界之外。
    let deadline = Instant::now() + Duration::from_secs(30);
    loop {
        let sockets = discover_runtime_sockets(temp_root);
        assert!(
            sockets.len() <= 1,
            "ambiguous Runtime endpoints: {sockets:?}"
        );
        if let Some(socket) = sockets.into_iter().next() {
            let parent = socket.parent().expect("Runtime socket parent");
            let parent_metadata =
                fs::symlink_metadata(parent).expect("Runtime socket parent metadata");
            // SAFETY: geteuid reads only the current process credential.
            let current_uid = unsafe { libc::geteuid() };
            assert!(parent_metadata.file_type().is_dir());
            assert_eq!(parent_metadata.uid(), current_uid);
            assert_eq!(parent_metadata.permissions().mode() & 0o7777, 0o700);
            let socket_metadata =
                fs::symlink_metadata(&socket).expect("Runtime socket pathname metadata");
            assert!(socket_metadata.file_type().is_socket());
            assert_eq!(socket_metadata.uid(), current_uid);
            assert_eq!(socket_metadata.permissions().mode() & 0o7777, 0o600);
            assert_eq!(socket_metadata.nlink(), 1);
            return socket;
        }
        if let Some(status) = child.try_wait().expect("probe daemon startup") {
            panic!("daemon exited before Runtime readiness: {status}");
        }
        assert!(
            Instant::now() < deadline,
            "timed out discovering Runtime UDS"
        );
        std::thread::sleep(Duration::from_millis(20));
    }
}

fn connect_runtime(socket: &Path, installation_id: &str) -> std::os::unix::net::UnixStream {
    let mut stream =
        std::os::unix::net::UnixStream::connect(socket).expect("connect discovered Runtime UDS");
    stream
        .set_read_timeout(Some(Duration::from_secs(5)))
        .expect("set Runtime read timeout");
    stream
        .set_write_timeout(Some(Duration::from_secs(5)))
        .expect("set Runtime write timeout");
    writeln!(
        stream,
        "{{\"localProtocolVersion\":1,\"clientInstallationId\":\"{installation_id}\"}}"
    )
    .expect("write local Runtime preface");
    let reply = runtime_roundtrip(
        &mut stream,
        RuntimeEnvelope {
            version: RUNTIME_PROTOCOL_VERSION,
            message_id: MessageId::new("binary-runtime-ready"),
            body: RuntimeMessage::Request(RuntimeRequest::Hello(HelloParams {
                runtime_protocol_version: RUNTIME_PROTOCOL_VERSION,
            })),
        },
    );
    assert!(matches!(
        reply.body,
        RuntimeMessage::Reply(RuntimeReply::Hello(HelloParams {
            runtime_protocol_version: RUNTIME_PROTOCOL_VERSION
        }))
    ));
    stream
}

fn write_runtime_envelope(stream: &mut std::os::unix::net::UnixStream, envelope: &RuntimeEnvelope) {
    stream
        .write_all(
            &envelope
                .to_json_bytes_checked()
                .expect("encode binary Runtime envelope"),
        )
        .expect("write binary Runtime envelope");
    stream.write_all(b"\n").expect("terminate Runtime envelope");
    stream.flush().expect("flush Runtime envelope");
}

fn runtime_roundtrip(
    stream: &mut std::os::unix::net::UnixStream,
    envelope: RuntimeEnvelope,
) -> RuntimeEnvelope {
    let message_id = envelope.message_id.clone();
    write_runtime_envelope(stream, &envelope);
    let mut reply = Vec::new();
    BufReader::new(stream.try_clone().expect("clone Runtime read handle"))
        .read_until(b'\n', &mut reply)
        .expect("read Runtime reply");
    assert_eq!(reply.pop(), Some(b'\n'));
    let reply: RuntimeEnvelope = serde_json::from_slice(&reply).expect("decode Runtime reply");
    assert_eq!(reply.message_id, message_id);
    reply
}

fn hello_envelope(message_id: &str) -> RuntimeEnvelope {
    RuntimeEnvelope {
        version: RUNTIME_PROTOCOL_VERSION,
        message_id: MessageId::new(message_id),
        body: RuntimeMessage::Request(RuntimeRequest::Hello(HelloParams {
            runtime_protocol_version: RUNTIME_PROTOCOL_VERSION,
        })),
    }
}

fn assert_runtime_hello(socket: &Path) {
    drop(connect_runtime(
        socket,
        "123e4567-e89b-12d3-a456-426614174038",
    ));
}

fn set_small_runtime_receive_buffer(stream: &std::os::unix::net::UnixStream) {
    let size: libc::c_int = 4_096;
    // SAFETY: stream owns a live socket fd and size points to a valid c_int.
    assert_eq!(
        unsafe {
            libc::setsockopt(
                stream.as_raw_fd(),
                libc::SOL_SOCKET,
                libc::SO_RCVBUF,
                (&raw const size).cast(),
                std::mem::size_of_val(&size) as libc::socklen_t,
            )
        },
        0
    );
}

fn runtime_readable_bytes(stream: &std::os::unix::net::UnixStream) -> libc::c_int {
    let mut available: libc::c_int = 0;
    // SAFETY: stream owns a live socket fd and available is writable ioctl storage.
    assert_eq!(
        unsafe { libc::ioctl(stream.as_raw_fd(), libc::FIONREAD, &raw mut available) },
        0
    );
    available
}

fn wait_for_exit(child: &mut Child) -> ExitStatus {
    let deadline = Instant::now() + Duration::from_secs(10);
    loop {
        if let Some(status) = child.try_wait().expect("probe daemon shutdown") {
            return status;
        }
        assert!(
            Instant::now() < deadline,
            "timed out waiting for daemon exit"
        );
        std::thread::sleep(Duration::from_millis(20));
    }
}
