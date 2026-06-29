//! 契约级 E2E：直打真实 codex（需 `codex login`）。默认跳过；
//! `AGENTDECK_E2E=1 cargo test -p agentdeck-cli --test e2e` 才运行。
//! 断言收敛到契约形态（事件 kind / JSON 字段 / 退出码），不断言 agent 文本。

use std::process::Command;

fn gated() -> bool {
    std::env::var("AGENTDECK_E2E").is_ok()
}

fn agentdeck() -> Command {
    // cargo 为本 crate 的 bin 注入此 env；agentdeckd 由 ProcessTransport
    // 按同目录/target 路径定位（需先 `cargo build`）。
    Command::new(env!("CARGO_BIN_EXE_agentdeck"))
}

#[test]
fn ping_returns_pong() {
    if !gated() {
        eprintln!("skipped: set AGENTDECK_E2E=1 to run");
        return;
    }
    let out = agentdeck().arg("ping").output().expect("spawn");
    assert!(out.status.success(), "ping exit: {:?}", out.status);
    let stdout = String::from_utf8_lossy(&out.stdout);
    assert!(stdout.contains("\"kind\":\"pong\""), "stdout: {stdout}");
}

#[test]
fn protocol_version_is_json() {
    if !gated() {
        eprintln!("skipped: set AGENTDECK_E2E=1 to run");
        return;
    }
    let out = agentdeck().args(["protocol", "version"]).output().expect("spawn");
    assert!(out.status.success());
    let v: serde_json::Value = serde_json::from_slice(&out.stdout).expect("json");
    assert!(v["protocolVersion"].as_u64().is_some());
}

#[test]
fn session_run_streams_to_turn_complete() {
    if !gated() {
        eprintln!("skipped: set AGENTDECK_E2E=1 to run");
        return;
    }
    let out = agentdeck()
        .args(["session", "run", "--cwd", ".", "--prompt", "say hello in one word", "--approval-policy", "auto-approve"])
        .output()
        .expect("spawn");
    let stdout = String::from_utf8_lossy(&out.stdout);
    // 契约形态：流以 turnComplete 收尾，进程退出码 0。
    assert!(out.status.success(), "exit: {:?} stderr: {}", out.status, String::from_utf8_lossy(&out.stderr));
    assert!(stdout.lines().any(|l| l.contains("\"kind\":\"turnComplete\"")), "stdout: {stdout}");
    // 每行应是合法 JSON（逐行中立事件）。
    for line in stdout.lines().filter(|l| !l.trim().is_empty()) {
        serde_json::from_str::<serde_json::Value>(line).unwrap_or_else(|_| panic!("non-JSON line: {line}"));
    }
}
