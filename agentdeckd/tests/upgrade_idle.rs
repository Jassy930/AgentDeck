use std::fs::{self, File};
use std::io::{BufRead, BufReader, Write};
use std::os::unix::fs::{DirBuilderExt, FileTypeExt, MetadataExt, PermissionsExt};
use std::path::{Path, PathBuf};
use std::process::{Child, Command, ExitStatus, Stdio};
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

use agentdeck_protocol::runtime::command::{HelloParams, LocalOnlyAdministration};
use agentdeck_protocol::runtime::identity::{IdempotencyKey, MessageId};
use agentdeck_protocol::runtime::{
    ArtifactSha256, RUNTIME_PROTOCOL_VERSION, RuntimeEnvelope, RuntimeMessage, RuntimeReply,
    RuntimeRequest, StageUpgradeReceipt, StageUpgradeRequest,
};
use rusqlite::{Connection, OpenFlags};
use sha2::{Digest, Sha256};

struct TestRoot(PathBuf);

impl TestRoot {
    fn new(label: &str) -> Self {
        let root = PathBuf::from("/tmp").join(format!(
            "adu-{label}-{}-{:x}",
            std::process::id(),
            SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .expect("system clock")
                .as_nanos()
        ));
        let mut builder = fs::DirBuilder::new();
        builder.mode(0o700);
        builder.create(&root).expect("create private test root");
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

#[test]
fn real_uds_flush_ack_arms_idle_switch_exit_and_current_restart() {
    let root = TestRoot::new("idle");
    let child = spawn_ephemeral_daemon(env!("CARGO_BIN_EXE_agentdeckd"), root.path());
    let mut child = ChildGuard(child);
    let original_pid = child.child_mut().id();
    let socket = wait_for_single_runtime_socket(child.child_mut(), root.path());
    let namespace = socket.parent().expect("Runtime namespace").to_path_buf();

    let version = "p3.10-real-uds";
    let bin_root = namespace.join("bin");
    let version_root = bin_root.join(version);
    create_private_directory(&bin_root);
    create_private_directory(&version_root);
    let candidate = version_root.join("agentdeckd");
    fs::copy(env!("CARGO_BIN_EXE_agentdeckd"), &candidate).expect("copy staged daemon candidate");
    fs::set_permissions(&candidate, fs::Permissions::from_mode(0o500))
        .expect("set candidate executable mode");
    File::open(&candidate)
        .expect("open staged candidate")
        .sync_all()
        .expect("sync staged candidate");
    File::open(&version_root)
        .expect("open staged version directory")
        .sync_all()
        .expect("sync staged version directory");
    let candidate_sha256 = Sha256::digest(fs::read(&candidate).expect("read staged candidate"));
    let candidate_sha256 = ArtifactSha256::new(
        candidate_sha256
            .iter()
            .map(|byte| format!("{byte:02x}"))
            .collect::<String>(),
    )
    .expect("canonical candidate SHA-256");
    let current = bin_root.join("current");

    assert!(
        !current.exists(),
        "current must not exist before StageUpgrade"
    );
    assert!(
        child
            .child_mut()
            .try_wait()
            .expect("probe original daemon")
            .is_none(),
        "original daemon must be alive before Runtime ACK"
    );
    assert_eq!(child.child_mut().id(), original_pid);

    let mut stream = connect_runtime(&socket, "123e4567-e89b-12d3-a456-426614174310");
    let reply = runtime_roundtrip(
        &mut stream,
        RuntimeEnvelope {
            version: RUNTIME_PROTOCOL_VERSION,
            message_id: MessageId::new("upgrade-real-uds-stage"),
            body: RuntimeMessage::Request(RuntimeRequest::StageUpgrade(
                StageUpgradeRequest::new(
                    version.to_owned(),
                    candidate_sha256,
                    IdempotencyKey::new("upgrade-real-uds-idempotency"),
                    LocalOnlyAdministration::LocalOnly,
                )
                .expect("valid StageUpgrade request"),
            )),
        },
    );
    assert!(matches!(
        reply.body,
        RuntimeMessage::Reply(RuntimeReply::StageUpgrade(StageUpgradeReceipt::Staged {
            target_version
        })) if target_version == version
    ));
    drop(stream);

    let status = wait_for_exit(child.child_mut());
    assert!(status.success(), "upgrade-triggered exit status: {status}");
    assert!(!socket.exists(), "graceful exit must remove the exact UDS");
    assert_eq!(
        fs::read_link(&current).expect("read switched current link"),
        PathBuf::from(version),
        "current must use the exact relative target"
    );
    let ledger = Connection::open_with_flags(
        namespace.join("runtime.db"),
        OpenFlags::SQLITE_OPEN_READ_ONLY | OpenFlags::SQLITE_OPEN_NO_MUTEX,
    )
    .expect("open cleanly-shut-down Runtime DB read-only");
    let state: String = ledger
        .query_row("SELECT state FROM admin_commands", [], |row| row.get(0))
        .expect("read upgrade ledger state");
    assert_eq!(state, "completed");
    drop(ledger);

    let restart_root = TestRoot::new("restart");
    let restarted = spawn_ephemeral_daemon(current.join("agentdeckd"), restart_root.path());
    let mut restarted = ChildGuard(restarted);
    let restarted_socket =
        wait_for_single_runtime_socket(restarted.child_mut(), restart_root.path());
    assert_runtime_hello(&restarted_socket);
    let restarted_pid = restarted.child_mut().id();
    // SAFETY: restarted_pid belongs to the live child owned by ChildGuard.
    assert_eq!(
        unsafe { libc::kill(restarted_pid as libc::pid_t, libc::SIGTERM) },
        0
    );
    let restarted_status = wait_for_exit(restarted.child_mut());
    assert!(
        restarted_status.success(),
        "current-linked daemon restart status: {restarted_status}"
    );
}

fn create_private_directory(path: &Path) {
    let mut builder = fs::DirBuilder::new();
    builder.mode(0o700);
    builder
        .create(path)
        .expect("create private upgrade directory");
}

fn spawn_ephemeral_daemon(binary: impl AsRef<Path>, root: &Path) -> Child {
    Command::new(binary.as_ref())
        .args(["--ephemeral", "--no-remote", "--profile", "dev"])
        .env("TMPDIR", root)
        .stdin(Stdio::null())
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .spawn()
        .expect("spawn real ephemeral daemon")
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
    let deadline = Instant::now() + Duration::from_secs(30);
    loop {
        let sockets = discover_runtime_sockets(temp_root);
        assert!(
            sockets.len() <= 1,
            "ambiguous Runtime endpoints: {sockets:?}"
        );
        if let Some(socket) = sockets.into_iter().next() {
            let parent = socket.parent().expect("Runtime socket parent");
            let parent_metadata = fs::symlink_metadata(parent).expect("Runtime namespace metadata");
            // SAFETY: geteuid only reads the current process credentials.
            let uid = unsafe { libc::geteuid() };
            assert_eq!(parent_metadata.uid(), uid);
            assert_eq!(parent_metadata.permissions().mode() & 0o7777, 0o700);
            let socket_metadata = fs::symlink_metadata(&socket).expect("Runtime socket metadata");
            assert!(socket_metadata.file_type().is_socket());
            assert_eq!(socket_metadata.uid(), uid);
            assert_eq!(socket_metadata.permissions().mode() & 0o7777, 0o600);
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
        std::os::unix::net::UnixStream::connect(socket).expect("connect real Runtime UDS");
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
    let hello = runtime_roundtrip(
        &mut stream,
        RuntimeEnvelope {
            version: RUNTIME_PROTOCOL_VERSION,
            message_id: MessageId::new("upgrade-real-uds-hello"),
            body: RuntimeMessage::Request(RuntimeRequest::Hello(HelloParams {
                runtime_protocol_version: RUNTIME_PROTOCOL_VERSION,
            })),
        },
    );
    assert!(matches!(
        hello.body,
        RuntimeMessage::Reply(RuntimeReply::Hello(HelloParams {
            runtime_protocol_version: RUNTIME_PROTOCOL_VERSION
        }))
    ));
    stream
}

fn runtime_roundtrip(
    stream: &mut std::os::unix::net::UnixStream,
    envelope: RuntimeEnvelope,
) -> RuntimeEnvelope {
    let message_id = envelope.message_id.clone();
    stream
        .write_all(
            &envelope
                .to_json_bytes_checked()
                .expect("encode Runtime envelope"),
        )
        .expect("write Runtime envelope");
    stream.write_all(b"\n").expect("terminate Runtime envelope");
    stream.flush().expect("flush Runtime request");
    let mut reply = Vec::new();
    BufReader::new(stream.try_clone().expect("clone Runtime read handle"))
        .read_until(b'\n', &mut reply)
        .expect("read Runtime reply");
    assert_eq!(reply.pop(), Some(b'\n'));
    let reply: RuntimeEnvelope = serde_json::from_slice(&reply).expect("decode Runtime reply");
    assert_eq!(reply.message_id, message_id);
    reply
}

fn assert_runtime_hello(socket: &Path) {
    drop(connect_runtime(
        socket,
        "123e4567-e89b-12d3-a456-426614174311",
    ));
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
