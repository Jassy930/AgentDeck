//! P1.3 — 四层协议 schema CLI 拆分集成测试。
//!
//! 断言：
//!  1. `protocol schema|runtime-schema|relay-schema|e2ee-schema` 的 stdout 与
//!     四份 committed snapshot byte-identical。
//!  2. `protocol version` 打印的 `protocolVersion` 等于 IPC `PROTOCOL_VERSION`。
//!  3. 全部五个 `protocol <op>` 子命令都不连接 Runtime 或 spawn daemon —— 在一个
//!     没有 UDS 的 private debug root 中运行仍全部成功且输出不变；作为对照，同一
//!     root 下 `ping` 必须返回 typed socket-missing，且不能创建 `ad-*` namespace。
//!
//! 不受 `AGENTDECK_E2E` 门控：这四个 schema 子命令 + `version` 按设计根本不
//! 需要 daemon，此文件本身就是那条不变量的证明，因此常规 `cargo test` 就跑。

use std::path::{Path, PathBuf};
use std::process::{Command, Output};

fn bin() -> &'static str {
    env!("CARGO_BIN_EXE_agentdeck")
}

fn snapshot(name: &str) -> String {
    let path = Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("../protocol/agentdeck")
        .join(name);
    std::fs::read_to_string(&path)
        .unwrap_or_else(|e| panic!("failed to read snapshot {}: {e}", path.display()))
}

fn run(args: &[&str]) -> Output {
    Command::new(bin())
        .args(args)
        .output()
        .expect("spawn agentdeck")
}

fn assert_success(label: &str, out: &Output) {
    assert!(
        out.status.success(),
        "{label} failed (status={:?}); stderr: {}",
        out.status,
        String::from_utf8_lossy(&out.stderr)
    );
}

#[test]
fn protocol_schema_matches_ipc_snapshot() {
    let out = run(&["protocol", "schema"]);
    assert_success("protocol schema", &out);
    assert_eq!(
        String::from_utf8_lossy(&out.stdout),
        snapshot("agentdeck-protocol.schema.json"),
        "protocol schema stdout must be byte-identical to the committed IPC snapshot"
    );
}

#[test]
fn protocol_runtime_schema_matches_runtime_snapshot() {
    let out = run(&["protocol", "runtime-schema"]);
    assert_success("protocol runtime-schema", &out);
    assert_eq!(
        String::from_utf8_lossy(&out.stdout),
        snapshot("runtime-protocol.schema.json"),
        "protocol runtime-schema stdout must be byte-identical to the committed Runtime v2 snapshot"
    );
}

#[test]
fn protocol_relay_schema_matches_relay_v2_snapshot() {
    let out = run(&["protocol", "relay-schema"]);
    assert_success("protocol relay-schema", &out);
    assert_eq!(
        String::from_utf8_lossy(&out.stdout),
        snapshot("relay-v2.schema.json"),
        "protocol relay-schema stdout must be byte-identical to the committed Relay v2 snapshot"
    );
}

#[test]
fn protocol_e2ee_schema_matches_e2ee_snapshot() {
    let out = run(&["protocol", "e2ee-schema"]);
    assert_success("protocol e2ee-schema", &out);
    assert_eq!(
        String::from_utf8_lossy(&out.stdout),
        snapshot("e2ee-v1.schema.json"),
        "protocol e2ee-schema stdout must be byte-identical to the committed E2EE v1 snapshot"
    );
}

#[test]
fn protocol_version_prints_ipc_protocol_version() {
    let out = run(&["protocol", "version"]);
    assert_success("protocol version", &out);
    let json: serde_json::Value =
        serde_json::from_slice(&out.stdout).expect("protocol version stdout must be valid JSON");
    assert_eq!(json["protocolVersion"], 2);
}

/// 隔离沙盒：只拷贝 `agentdeck` 二进制，并给所有命令传同一个 exact-0700、
/// 无 `ad-*` endpoint 的 DEBUG root。这样测试不依赖当前 OS account 是否正在运行
/// stable daemon，也不会把旧 stdio daemon lookup 当成新 shared-UDS 事实。
struct Sandbox {
    bin: PathBuf,
    cwd: PathBuf,
    runtime_root: PathBuf,
}

impl Sandbox {
    fn new(tag: &str) -> Self {
        let root = std::env::temp_dir().join(format!(
            "agentdeck-cli-test-nodaemon-{tag}-{}",
            std::process::id()
        ));
        let _ = std::fs::remove_dir_all(&root);
        let bin_dir = root.join("bin");
        let cwd = root.join("work");
        let runtime_root = root.join("runtime");
        std::fs::create_dir_all(&bin_dir).expect("create sandbox bin dir");
        std::fs::create_dir_all(&cwd).expect("create sandbox cwd");
        std::fs::create_dir_all(&runtime_root).expect("create sandbox Runtime root");
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            std::fs::set_permissions(&runtime_root, std::fs::Permissions::from_mode(0o700))
                .expect("make sandbox Runtime root private");
        }
        let dest = bin_dir.join("agentdeck");
        std::fs::copy(bin(), &dest).expect("copy agentdeck binary into sandbox");
        Self {
            bin: dest,
            cwd,
            runtime_root,
        }
    }

    fn run(&self, args: &[&str]) -> Output {
        let mut command = Command::new(&self.bin);
        command
            .arg("--runtime-temp-root-for-test")
            .arg(&self.runtime_root)
            .args(args)
            .current_dir(&self.cwd)
            .env("PATH", "");
        command.output().expect("spawn sandboxed agentdeck")
    }
}

#[test]
fn protocol_schema_subcommands_do_not_spawn_daemon() {
    let sandbox = Sandbox::new("main");

    // 对照：`ping` 真正需要 shared Runtime，在没有 endpoint 的 private root 中
    // 必须 typed fail，且不能 fallback spawn 一个新 namespace。
    let ping = sandbox.run(&["ping"]);
    assert!(
        !ping.status.success(),
        "sandbox assumption violated: `ping` unexpectedly succeeded without a Runtime endpoint; \
         stdout: {}",
        String::from_utf8_lossy(&ping.stdout)
    );
    let ping_json: serde_json::Value =
        serde_json::from_slice(&ping.stdout).expect("ping failure stdout must be typed JSON");
    assert_eq!(ping_json["error"]["code"], "daemon.client.socket_missing");
    assert!(
        std::fs::read_dir(&sandbox.runtime_root)
            .expect("read sandbox Runtime root")
            .all(|entry| !entry
                .expect("read sandbox Runtime entry")
                .file_name()
                .to_string_lossy()
                .starts_with("ad-")),
        "ping fallback created an unexpected daemon namespace"
    );

    // 四个 schema 子命令 + version：同一沙盒环境下必须全部成功，且输出与
    // committed snapshot / IPC 协议版本一致——唯一合理的解释是它们压根没有
    // 尝试连接 daemon。
    let schema = sandbox.run(&["protocol", "schema"]);
    assert_success("sandboxed protocol schema", &schema);
    assert_eq!(
        String::from_utf8_lossy(&schema.stdout),
        snapshot("agentdeck-protocol.schema.json")
    );

    let runtime_schema = sandbox.run(&["protocol", "runtime-schema"]);
    assert_success("sandboxed protocol runtime-schema", &runtime_schema);
    assert_eq!(
        String::from_utf8_lossy(&runtime_schema.stdout),
        snapshot("runtime-protocol.schema.json")
    );

    let relay_schema = sandbox.run(&["protocol", "relay-schema"]);
    assert_success("sandboxed protocol relay-schema", &relay_schema);
    assert_eq!(
        String::from_utf8_lossy(&relay_schema.stdout),
        snapshot("relay-v2.schema.json")
    );

    let e2ee_schema = sandbox.run(&["protocol", "e2ee-schema"]);
    assert_success("sandboxed protocol e2ee-schema", &e2ee_schema);
    assert_eq!(
        String::from_utf8_lossy(&e2ee_schema.stdout),
        snapshot("e2ee-v1.schema.json")
    );

    let version = sandbox.run(&["protocol", "version"]);
    assert_success("sandboxed protocol version", &version);
    let json: serde_json::Value = serde_json::from_slice(&version.stdout)
        .expect("sandboxed protocol version stdout must be valid JSON");
    assert_eq!(json["protocolVersion"], 2);

    let _ = std::fs::remove_dir_all(sandbox.cwd.parent().unwrap());
}
