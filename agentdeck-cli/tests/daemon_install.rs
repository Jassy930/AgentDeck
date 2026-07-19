use std::fs;
use std::os::unix::fs::PermissionsExt;
use std::process::{Command, Output};

fn cli() -> &'static str {
    env!("CARGO_BIN_EXE_agentdeck")
}

fn output(args: &[&str]) -> Output {
    Command::new(cli())
        .args(args)
        .output()
        .expect("run agentdeck daemon command")
}

fn error_code(output: &Output) -> String {
    let value: serde_json::Value =
        serde_json::from_slice(&output.stdout).expect("decode CLI error envelope");
    value["error"]["code"]
        .as_str()
        .expect("typed error code")
        .to_owned()
}

#[test]
fn purge_is_typed_fail_close_before_any_lifecycle_mutation() {
    let output = output(&["daemon", "uninstall", "--purge"]);
    assert_eq!(output.status.code(), Some(5));
    assert_eq!(error_code(&output), "daemon.purge.remote_not_ready");
}

#[test]
fn production_daemon_commands_reject_the_ephemeral_runtime_seam_without_mutation() {
    let root = tempfile::tempdir().expect("private Runtime harness root");
    fs::set_permissions(root.path(), fs::Permissions::from_mode(0o700))
        .expect("harden Runtime harness root");
    let before = fs::read_dir(root.path())
        .expect("read empty harness root")
        .count();

    let output = output(&[
        "--runtime-temp-root-for-test",
        root.path().to_str().expect("UTF-8 temp path"),
        "daemon",
        "status",
    ]);

    assert_eq!(output.status.code(), Some(2));
    assert_eq!(error_code(&output), "usage");
    assert_eq!(
        fs::read_dir(root.path())
            .expect("read unchanged harness root")
            .count(),
        before
    );
}
