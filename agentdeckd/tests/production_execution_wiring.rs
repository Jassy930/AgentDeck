#![cfg(debug_assertions)]

use std::process::Command;

#[test]
fn runtime_core_recovery_drives_current_binary_gate_typed_driver_and_durable_terminal() {
    // 威胁场景：integration test 注入 binary 路径时只覆盖 spawn_with_binary，production
    // `spawn_current` 分支即使损坏仍会绿灯。probe 必须在真实 daemon binary 内构造 Core，
    // 再由该 binary 以 current_exe 启动自己的 --exec-gate 子模式。
    let output = Command::new(env!("CARGO_BIN_EXE_agentdeckd"))
        .arg("--production-execution-probe")
        .output()
        .expect("spawn current-binary production execution probe");
    assert!(
        output.status.success(),
        "production probe failed: {}",
        String::from_utf8_lossy(&output.stderr)
    );
    let evidence: serde_json::Value =
        serde_json::from_slice(&output.stdout).expect("decode production probe evidence");

    assert_eq!(evidence["commandCompleted"], true);
    assert_eq!(evidence["durableItemCountAfterReopen"], 1);
    assert_eq!(evidence["durableTerminalCountAfterReopen"], 1);
    assert_eq!(evidence["vendorPromptMatched"], true);
    assert_eq!(evidence["adapterObservedDurableAck"], true);
}
