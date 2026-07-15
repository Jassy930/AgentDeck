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
    assert_eq!(evidence["commandCanceled"], false);
    assert_eq!(evidence["durableItemCountAfterReopen"], 1);
    assert_eq!(evidence["durableTerminalCountAfterReopen"], 1);
    assert_eq!(evidence["vendorPromptMatched"], true);
    assert_eq!(evidence["adapterObservedDurableAck"], true);
}

#[test]
fn runtime_core_cancel_reaps_current_binary_gate_before_release_without_vendor_side_effect() {
    // 威胁场景：prepare-time owner 若只在手造 GatedChild 测试里存在，production
    // spawn_current 路径可能在 Ready 后丢失唯一 reaper；用户取消会返回成功，却留下
    // TERM-resistant gate/PGID 或让 vendor 越过 release 前边界产生副作用。
    let output = Command::new(env!("CARGO_BIN_EXE_agentdeckd"))
        .arg("--production-execution-cancel-probe")
        .output()
        .expect("spawn current-binary production cancel probe");
    assert!(
        output.status.success(),
        "production cancel probe failed: {}",
        String::from_utf8_lossy(&output.stderr)
    );
    let evidence: serde_json::Value =
        serde_json::from_slice(&output.stdout).expect("decode production cancel probe evidence");

    assert_eq!(evidence["commandCompleted"], false);
    assert_eq!(evidence["commandCanceled"], true);
    assert_eq!(evidence["cancelRequested"], true);
    assert_eq!(evidence["vendorSideEffectAbsent"], true);
    assert_eq!(evidence["gateGroupExitedAfterCancel"], true);
    assert_eq!(evidence["durableItemCountAfterReopen"], 0);
    assert_eq!(evidence["durableTerminalCountAfterReopen"], 1);
    assert_eq!(evidence["vendorPromptMatched"], false);
    assert_eq!(evidence["adapterObservedDurableAck"], false);
}
