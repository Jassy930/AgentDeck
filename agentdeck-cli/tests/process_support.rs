mod support;

use std::ffi::OsStr;
use std::process::Command;
use std::time::{Duration, Instant};

use support::{RunError, e2e_gate_value, run_command};

#[test]
fn e2e_gate_requires_exactly_one() {
    for value in [
        None,
        Some(""),
        Some("0"),
        Some("false"),
        Some("true"),
        Some("2"),
    ] {
        assert!(!e2e_gate_value(value.map(OsStr::new)), "value={value:?}");
    }
    assert!(e2e_gate_value(Some(OsStr::new("1"))));
}

#[test]
fn hard_timeout_interrupts_process_with_no_output() {
    let mut command = Command::new("/bin/sh");
    command.args(["-c", "sleep 30"]);
    let started = Instant::now();
    let error =
        run_command(command, Duration::from_millis(150)).expect_err("silent process must time out");
    assert!(matches!(error, RunError::TimedOut { .. }));
    assert!(started.elapsed() < Duration::from_secs(3));
}

#[test]
fn hard_timeout_preserves_partial_output_for_diagnostics() {
    let mut command = Command::new("/bin/sh");
    command.args(["-c", "printf 'partial-output\\n'; sleep 30"]);
    let error = run_command(command, Duration::from_millis(150))
        .expect_err("partially responsive process must time out");
    match error {
        RunError::TimedOut { stdout, .. } => {
            assert_eq!(String::from_utf8_lossy(&stdout), "partial-output\n");
        }
        other => panic!("expected timeout, got {other:?}"),
    }
}

#[cfg(unix)]
#[test]
fn hard_timeout_still_applies_after_root_exits_with_inherited_pipe_open() {
    let mut command = Command::new("/bin/sh");
    command.args(["-c", "sleep 30 &"]);
    let started = Instant::now();
    let error = run_command(command, Duration::from_millis(150))
        .expect_err("a surviving descendant that holds the pipe open must time out");
    assert!(matches!(error, RunError::TimedOut { .. }));
    assert!(started.elapsed() < Duration::from_secs(3));
}

#[cfg(unix)]
#[test]
fn timeout_cleans_nested_child_before_it_can_write_marker() {
    let marker = std::env::temp_dir().join(format!(
        "agentdeck-process-helper-marker-{}",
        std::process::id()
    ));
    let _ = std::fs::remove_file(&marker);

    let mut command = Command::new("/bin/sh");
    command.args([
        "-c",
        "set -m; (sleep 1; printf leaked > \"$1\") & wait",
        "agentdeck-timeout-fixture",
        marker.to_str().expect("temporary marker path is UTF-8"),
    ]);
    let error =
        run_command(command, Duration::from_millis(150)).expect_err("nested fixture must time out");
    assert!(matches!(error, RunError::TimedOut { .. }));

    std::thread::sleep(Duration::from_millis(1200));
    assert!(
        !marker.exists(),
        "nested child survived timeout and wrote {}",
        marker.display()
    );
}
