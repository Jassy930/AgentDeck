//! P1.3 — 四层协议 schema CLI 拆分集成测试。
//!
//! 断言：
//!  1. `protocol schema|runtime-schema|relay-schema|e2ee-schema` 的 stdout 与
//!     四份 committed snapshot byte-identical。
//!  2. `protocol version` 打印的 `protocolVersion` 等于 IPC `PROTOCOL_VERSION`。
//!  3. 全部五个 `protocol <op>` 子命令都不 spawn daemon —— 在一个刻意隔离出的、
//!     `agentdeckd` 二进制必然探测不到的沙盒环境（只拷贝 `agentdeck` 单个二进制、
//!     cwd 指向没有 `target/` 的空目录、清空 PATH）中运行，仍然全部成功且输出
//!     不变；作为对照，同一沙盒环境下 `ping`（真正需要 daemon 的命令）必须失败，
//!     用来证明沙盒本身确实让 daemon 探测不到（而不是侥幸绕过）。
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

/// 隔离沙盒：只拷贝 `agentdeck` 单个二进制到一个既没有 `agentdeckd` 兄弟文件、
/// 也没有 `target/` 子目录的空目录里，并清空 PATH。
///
/// `locate_daemon()`（`agentdeck-cli/src/transport.rs`）依次探测：
///   1. 当前可执行文件同目录下的 `agentdeckd`（sibling）——沙盒里只有 `agentdeck`
///      自己，没有 sibling。
///   2/3. cwd 相对的 `target/debug/agentdeckd` / `target/release/agentdeckd`——
///      沙盒 cwd 是空目录，没有 `target/`。
///   4/5. `/usr/local/bin/agentdeckd` / `/opt/homebrew/bin/agentdeckd`——假定
///      开发/CI 机器上没有全局安装 `agentdeckd`；下面的 `ping` 对照用例会
///      直接验证这一假设是否成立，假设不成立时该用例会给出明确失败信息而
///      不是静默误判。
struct Sandbox {
    bin: PathBuf,
    cwd: PathBuf,
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
        std::fs::create_dir_all(&bin_dir).expect("create sandbox bin dir");
        std::fs::create_dir_all(&cwd).expect("create sandbox cwd");
        let dest = bin_dir.join("agentdeck");
        std::fs::copy(bin(), &dest).expect("copy agentdeck binary into sandbox");
        Self { bin: dest, cwd }
    }

    fn run(&self, args: &[&str]) -> Output {
        Command::new(&self.bin)
            .args(args)
            .current_dir(&self.cwd)
            .env("PATH", "")
            .output()
            .expect("spawn sandboxed agentdeck")
    }
}

#[test]
fn protocol_schema_subcommands_do_not_spawn_daemon() {
    let sandbox = Sandbox::new("main");

    // 对照：`ping` 真正需要 daemon，在沙盒里必须失败——证明沙盒本身确实让
    // `locate_daemon()` 找不到 `agentdeckd`（而不是因为别的原因侥幸探测到）。
    let ping = sandbox.run(&["ping"]);
    assert!(
        !ping.status.success(),
        "sandbox assumption violated: `ping` unexpectedly succeeded without a discoverable \
         daemon (an agentdeckd may be installed at /usr/local/bin or /opt/homebrew/bin on this \
         machine, or `locate_daemon()` grew a new fallback path); stdout: {}",
        String::from_utf8_lossy(&ping.stdout)
    );
    let ping_stderr = String::from_utf8_lossy(&ping.stderr);
    assert!(
        ping_stderr.contains("agentdeckd not found"),
        "expected a daemon-not-found failure from the sandboxed `ping`, got stderr: {ping_stderr}"
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
