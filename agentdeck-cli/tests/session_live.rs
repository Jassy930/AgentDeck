//! Actual CLI → current daemon → deterministic Codex fixture. No real vendor I/O.
mod support;

use agentdeck_protocol::{ClientCommand, SessionId, TurnId};
use std::path::Path;
use std::process::Command;
use std::time::Duration;
use support::live::{LiveCli, four_turn_scenario, session_start, temp_root};

fn fixture_command(root: &Path, args: &[&str]) -> Command {
    use std::os::unix::fs::PermissionsExt;
    let bin = root.join("bin");
    std::fs::create_dir_all(&bin).unwrap();
    let codex = bin.join("codex");
    std::fs::write(&codex, include_str!("fixtures/codex-live.sh")).unwrap();
    std::fs::set_permissions(&codex, std::fs::Permissions::from_mode(0o700)).unwrap();
    let mut command = support::cli_command(args);
    let inherited_path = std::env::var_os("PATH").unwrap_or_default();
    let paths = std::iter::once(bin).chain(std::env::split_paths(&inherited_path));
    command
        .env("PATH", std::env::join_paths(paths).unwrap())
        .env(
            "AGENTDECK_FIXTURE_VERSION",
            include_str!("../../protocol/CODEX_VERSION.txt").trim(),
        )
        .arg("--data-dir")
        .arg(root);
    command
}

fn daemon_bound() -> bool {
    if std::env::var_os("AGENTDECK_DAEMON_BIN").is_some() {
        return true;
    }
    eprintln!(
        "SKIP: bind AGENTDECK_DAEMON_BIN to the current checkout; verify-offline-tests.sh does this"
    );
    false
}

#[test]
fn cli_live_reuses_child_streams_cancels_recovers_and_records() {
    if !daemon_bound() {
        return;
    }
    let root = temp_root("cli-live-offline");
    four_turn_scenario(
        fixture_command(&root, &["session", "live"]),
        &root,
        Duration::from_secs(20),
    );
    std::fs::remove_dir_all(root).unwrap();
}

#[test]
fn cli_live_eof_closes_session_and_record_failure_is_nonterminal() {
    assert_record_failure_is_nonterminal(true);
}

#[test]
fn cli_live_unwritable_diagnostics_omit_reference_and_preserve_session() {
    assert_record_failure_is_nonterminal(false);
}

#[test]
fn cli_live_failed_start_with_unwritable_diagnostics_has_no_reference() {
    if !daemon_bound() {
        return;
    }
    let root = temp_root("cli-live-start-diagnostic-failure");
    std::fs::create_dir(root.join("diagnostic.log")).unwrap();
    let mut command = fixture_command(&root, &["session", "live"]);
    command.env("AGENTDECK_FIXTURE_START_ERROR", "1");
    let mut cli = LiveCli::spawn(command, Duration::from_secs(20));
    cli.send(session_start(&root));
    loop {
        let event = cli.next();
        assert_ne!(
            event["type"], "sessionStarted",
            "failed handshake must not start"
        );
        if event["type"] == "sessionClosed" {
            assert_eq!(event["outcome"], "failed");
            assert_eq!(event["error"]["code"], "codex-protocol-error");
            assert!(event["error"]["diagnosticRef"].is_null());
            break;
        }
    }
    assert!(!cli.finish().success());
    std::fs::remove_dir_all(root).unwrap();
}

fn assert_record_failure_is_nonterminal(diagnostics_writable: bool) {
    if !daemon_bound() {
        return;
    }
    let root = temp_root("cli-live-record-failure");
    std::fs::write(root.join("runs"), "cannot create a record directory here").unwrap();
    if !diagnostics_writable {
        std::fs::create_dir(root.join("diagnostic.log")).unwrap();
    }
    let mut cli = LiveCli::spawn(
        fixture_command(&root, &["session", "live"]),
        Duration::from_secs(20),
    );
    cli.send(session_start(&root));
    loop {
        let event = cli.next();
        assert_ne!(
            event["type"], "sessionClosed",
            "session failed before turn: {event}"
        );
        if event["type"] == "turnFinished" {
            assert_eq!(event["outcome"], "succeeded");
            break;
        }
    }
    assert!(cli.finish().success());
    assert_eq!(cli.events.last().unwrap()["type"], "sessionClosed");
    let warning = cli
        .events
        .iter()
        .find(|v| v["error"]["code"] == "record_write_failed")
        .unwrap();
    if diagnostics_writable {
        let reference = warning["error"]["diagnosticRef"].as_str().unwrap();
        let (run_id, sequence) = reference.rsplit_once(':').unwrap();
        let diagnostics = std::fs::read_to_string(root.join("diagnostic.log")).unwrap();
        assert!(
            diagnostics
                .lines()
                .map(|line| serde_json::from_str::<serde_json::Value>(line).unwrap())
                .any(|event| event["runId"] == run_id
                    && event["eventSeq"] == sequence.parse::<u64>().unwrap())
        );
    } else {
        assert!(warning["error"]["diagnosticRef"].is_null());
    }
    std::fs::remove_dir_all(root).unwrap();
}

#[test]
fn cli_live_invalid_input_still_reaps_the_session() {
    if !daemon_bound() {
        return;
    }
    let root = temp_root("cli-live-invalid-input");
    let mut cli = LiveCli::spawn(
        fixture_command(&root, &["session", "live"]),
        Duration::from_secs(20),
    );
    cli.send(session_start(&root));
    loop {
        let event = cli.next();
        assert_ne!(
            event["type"], "sessionClosed",
            "session failed before turn: {event}"
        );
        if event["type"] == "turnFinished" {
            break;
        }
    }
    cli.send_raw("not json");
    assert_eq!(cli.finish().code(), Some(3));
    assert!(
        cli.events
            .iter()
            .any(|v| v["type"] == "sessionClosed" && v["outcome"] == "closed")
    );
    std::fs::remove_dir_all(root).unwrap();
}

#[test]
fn one_shot_record_warning_does_not_replace_turn_terminal() {
    if !daemon_bound() {
        return;
    }
    let root = temp_root("cli-run-record-failure");
    std::fs::write(root.join("runs"), "blocked").unwrap();
    let command = fixture_command(
        &root,
        &[
            "session",
            "run",
            "--agent",
            "codex",
            "--cwd",
            root.to_str().unwrap(),
            "--prompt",
            "hello",
        ],
    );
    let output = support::run_command(command, Duration::from_secs(20)).unwrap();
    assert!(
        output.status.success(),
        "{}",
        String::from_utf8_lossy(&output.stderr)
    );
    let events: Vec<serde_json::Value> = String::from_utf8(output.stdout)
        .unwrap()
        .lines()
        .map(|line| serde_json::from_str(line).unwrap())
        .collect();
    assert!(
        events
            .iter()
            .any(|v| v["error"]["code"] == "record_write_failed")
    );
    assert_eq!(events.last().unwrap()["type"], "turnFinished");
    std::fs::remove_dir_all(root).unwrap();
}

#[test]
fn cli_live_record_append_and_close_failure_preserve_lifecycle() {
    if !daemon_bound() {
        return;
    }
    let root = temp_root("cli-live-append-failure");
    let mut cli = LiveCli::spawn(
        fixture_command(&root, &["session", "live"]),
        Duration::from_secs(20),
    );
    cli.send(session_start(&root));
    loop {
        let event = cli.next();
        assert_ne!(event["type"], "sessionClosed", "{event}");
        if event["type"] == "turnFinished" {
            break;
        }
    }
    let record = std::fs::read_dir(root.join("runs"))
        .unwrap()
        .next()
        .unwrap()
        .unwrap()
        .path();
    std::fs::rename(&record, root.join("saved-record.jsonl")).unwrap();
    std::fs::create_dir(&record).unwrap();
    cli.send(ClientCommand::TurnStart {
        session_id: SessionId("cli-live-m0".into()),
        turn_id: TurnId("turn-2".into()),
        prompt: "hello again".into(),
    });
    loop {
        let event = cli.next();
        assert_ne!(event["type"], "sessionClosed", "{event}");
        if event["type"] == "turnFinished" {
            assert_eq!(event["outcome"], "succeeded");
            break;
        }
    }
    assert!(cli.finish().success());
    let closed = cli.events.last().unwrap();
    assert_eq!(closed["type"], "sessionClosed");
    assert_eq!(closed["outcome"], "closed");
    assert_eq!(
        cli.events[cli.events.len() - 2]["error"]["code"],
        "record_write_failed"
    );
    assert_eq!(
        cli.events
            .iter()
            .filter(|v| v["error"]["code"] == "record_write_failed")
            .count(),
        2
    );
    std::fs::remove_dir_all(root).unwrap();
}

#[test]
fn cli_live_closed_stdout_still_finishes_record_and_reaps_child() {
    if !daemon_bound() {
        return;
    }
    let root = temp_root("cli-live-stdout-closed");
    let mut cli = LiveCli::spawn_with_output_limit(
        fixture_command(&root, &["session", "live"]),
        Duration::from_secs(10),
        1,
    );
    cli.send(session_start(&root));
    assert_eq!(cli.next()["type"], "sessionStarted");
    assert_eq!(
        cli.finish().code(),
        Some(4),
        "broken stdout is a transport error, not a panic"
    );
    let record = std::fs::read_dir(root.join("runs"))
        .unwrap()
        .next()
        .unwrap()
        .unwrap()
        .path();
    let lines: Vec<serde_json::Value> = std::fs::read_to_string(record)
        .unwrap()
        .lines()
        .map(|line| serde_json::from_str(line).unwrap())
        .collect();
    assert_eq!(lines.last().unwrap()["kind"], "runFooter");
    assert_eq!(lines[lines.len() - 2]["type"], "sessionClosed");
    assert_eq!(lines[lines.len() - 2]["outcome"], "closed");
    let diagnostics = std::fs::read_to_string(root.join("diagnostic.log")).unwrap();
    let cleanup = diagnostics
        .lines()
        .map(|line| serde_json::from_str::<serde_json::Value>(line).unwrap())
        .find(|event| event["event"] == "codex_cleanup_completed")
        .unwrap();
    let detail: serde_json::Value =
        serde_json::from_str(cleanup["detail"].as_str().unwrap()).unwrap();
    assert_eq!(detail["childWaited"], true);
    assert_eq!(detail["processGroupGone"], true);
    let pid = detail["childPid"].as_i64().unwrap() as i32;
    for target in [pid, -pid] {
        assert_eq!(unsafe { libc::kill(target, 0) }, -1);
        assert_eq!(
            std::io::Error::last_os_error().raw_os_error(),
            Some(libc::ESRCH)
        );
    }
    std::fs::remove_dir_all(root).unwrap();
}
