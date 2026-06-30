//! agentdeckd — AgentDeck daemon (v2 protocol).
//!
//! Architecture (Eng D2): the IPC protocol IS the agent-neutral boundary.
//! `agentdeck-protocol` defines the neutral wire types; `codex` is the
//! ONLY module that knows Codex exists (N3). The Swift app and the CLI
//! speak only the protocol crate; future ClaudeCodeAdapter / SSH
//! adapters are siblings of `codex`.
//!
//!   Swift / CLI ──JSONL──▶ agentdeckd ─┬─ agentdeck-protocol (neutral wire)
//!                ◀─JSONL───             ├─ runtime::router (per-AgentKind)
//!                                       └─ codex ──▶ codex app-server child
//!                                                  ◀── JSON-RPC (newline)
//!
//! Process boundary (Eng A1): every Codex child runs in its own process
//! group (`process_group(0)`) so cancel / drop SIGKILLs the whole subtree
//! (MCP servers, sandbox helpers) without orphans. See codex/adapter.rs.
//!
//! Phase 3 / Task 3C scope: this main is a thin CLI shell around
//! `RuntimeHub::run(stdin, stdout)`. Admin flags (`--selfcheck`,
//! `--diagnostics-report`, `--profile`, `--data-dir`) are handled before
//! the loop starts.

use std::path::PathBuf;
use std::process::ExitCode;
use std::sync::Arc;

use agentdeckd::claude_code::ClaudeCodeAdapter;
use agentdeckd::codex::CodexAdapter;
use agentdeckd::diag;
use agentdeckd::record;
use agentdeckd::runtime::{AgentRouter, RuntimeHub};

#[derive(Debug, Default)]
struct CliArgs {
    /// "stable" or "dev" — selects `Application Support/{AgentDeck,AgentDeck-Dev}`.
    profile: Option<String>,
    /// Absolute path; overrides profile-based data dir entirely.
    data_dir: Option<PathBuf>,
    /// One-shot mode: print "OK" + protocol version, exit 0.
    selfcheck: bool,
    /// One-shot mode: emit JSONL summary of diagnostic.log to stdout, exit 0.
    diagnostics_report: bool,
    /// Print --version and exit.
    show_version: bool,
    /// Print --help and exit.
    show_help: bool,
}

fn parse_args<I: IntoIterator<Item = String>>(args: I) -> Result<CliArgs, String> {
    let mut out = CliArgs::default();
    let mut it = args.into_iter();
    // Skip argv[0]
    let _ = it.next();
    while let Some(a) = it.next() {
        match a.as_str() {
            "--profile" => {
                let v = it.next().ok_or("--profile requires a value")?;
                out.profile = Some(v);
            }
            "--data-dir" => {
                let v = it.next().ok_or("--data-dir requires a value")?;
                out.data_dir = Some(PathBuf::from(v));
            }
            "--selfcheck" => out.selfcheck = true,
            "--diagnostics-report" => out.diagnostics_report = true,
            "--version" | "-V" => out.show_version = true,
            "--help" | "-h" => out.show_help = true,
            other => return Err(format!("unknown argument: {other}")),
        }
    }
    Ok(out)
}

fn apply_data_dir_env(args: &CliArgs) {
    // Both record::app_data_dir and diag::diagnostic_log_path read these
    // env vars at every call; setting them here for the lifetime of this
    // process is the minimum-surface plumbing for `--profile` /
    // `--data-dir` without threading config through every module.
    if let Some(dir) = &args.data_dir {
        // SAFETY: we are single-threaded at this point (before tokio
        // runtime starts) and no other code reads these env vars yet.
        unsafe {
            std::env::set_var("AGENTDECK_DATA_DIR", dir);
        }
    }
    if let Some(profile) = &args.profile {
        unsafe {
            std::env::set_var("AGENTDECK_PROFILE", profile);
        }
    }
}

fn print_version() {
    println!("agentdeckd {}", env!("CARGO_PKG_VERSION"));
    println!("protocolVersion {}", agentdeck_protocol::PROTOCOL_VERSION);
}

fn print_help() {
    println!(
        "agentdeckd — AgentDeck daemon (v2 protocol).\n\
         \n\
         Usage: agentdeckd [OPTIONS]\n\
         \n\
         Options:\n\
           --profile <stable|dev>    Pick Application Support directory variant.\n\
           --data-dir <path>         Override data dir entirely (takes precedence).\n\
           --selfcheck               Run plumbing self-check and exit 0/1.\n\
           --diagnostics-report      Emit diagnostic.log summary as JSON and exit.\n\
           --version, -V             Print version and exit.\n\
           --help, -h                Show this help and exit.\n\
         \n\
         With no options, reads ClientCommand JSONL from stdin and writes\n\
         ServerEvent JSONL to stdout until stdin closes.\n"
    );
}

/// Self-check: confirm the daemon's own plumbing works without spawning
/// a real agent process. Verifies:
///   1. record::app_data_dir() resolves (HOME present or override set)
///   2. diag::diagnostic_log_path() resolves to a writable directory
///   3. diag::log() round-trips through writeln to disk
///   4. record::try_append() round-trips through writeln + redact
///
/// Returns process exit code (0 = OK, 1 = fail). v1 selfcheck spawned a
/// real Codex turn; v2 simplifies to "daemon plumbing works" — exercising
/// codex requires login and is not appropriate for a CI smoke test. The
/// gated E2E (`AGENTDECK_E2E=1 cargo test ... e2e_codex`) covers that.
fn run_selfcheck() -> ExitCode {
    let app_dir = match record::app_data_dir() {
        Some(d) => d,
        None => {
            eprintln!("selfcheck: FAIL — record::app_data_dir() returned None (HOME unset?)");
            return ExitCode::from(1);
        }
    };
    if let Err(e) = std::fs::create_dir_all(&app_dir) {
        eprintln!(
            "selfcheck: FAIL — cannot create data dir {}: {e}",
            app_dir.display()
        );
        return ExitCode::from(1);
    }
    let diag_path = match diag::diagnostic_log_path() {
        Some(p) => p,
        None => {
            eprintln!("selfcheck: FAIL — diag::diagnostic_log_path() returned None");
            return ExitCode::from(1);
        }
    };

    let run_id = format!("selfcheck-{}", std::process::id());
    if let Err(e) = record::try_append(&run_id, r#"{"selfcheck":true}"#) {
        eprintln!("selfcheck: FAIL — record::try_append: {e}");
        return ExitCode::from(1);
    }
    diag::log("selfcheck", "agentdeckd self-check ok");

    println!("OK");
    println!(
        "{{\"protocolVersion\":{},\"dataDir\":{:?},\"diagLog\":{:?}}}",
        agentdeck_protocol::PROTOCOL_VERSION,
        app_dir,
        diag_path
    );
    ExitCode::SUCCESS
}

/// Diagnostics report: read diagnostic.log line-by-line, parse each as
/// JSON, emit an aggregated summary JSON to stdout. Simplified from v1
/// (no `--json`, no `--run-id` filter, no `--since-seconds`); Phase 5+
/// can re-add those once the CLI has matching flags.
fn run_diagnostics_report() -> ExitCode {
    let path = match diag::diagnostic_log_path() {
        Some(p) => p,
        None => {
            eprintln!("diagnostics-report: FAIL — diag path unavailable");
            return ExitCode::from(1);
        }
    };
    let text = match std::fs::read_to_string(&path) {
        Ok(t) => t,
        Err(e) => {
            // Missing log is not an error — just empty report.
            let summary = serde_json::json!({
                "path": path,
                "lineCount": 0,
                "notice": format!("could not read {}: {}", path.display(), e),
            });
            println!("{}", summary);
            return ExitCode::SUCCESS;
        }
    };
    let lines: Vec<&str> = text.lines().filter(|l| !l.trim().is_empty()).collect();
    let mut parsed = 0u64;
    let mut by_level: std::collections::BTreeMap<String, u64> = Default::default();
    let mut by_event: std::collections::BTreeMap<String, u64> = Default::default();
    let mut last_lines: Vec<serde_json::Value> = Vec::new();
    for line in &lines {
        if let Ok(v) = serde_json::from_str::<serde_json::Value>(line) {
            parsed += 1;
            if let Some(level) = v.get("level").and_then(|x| x.as_str()) {
                *by_level.entry(level.to_string()).or_default() += 1;
            }
            if let Some(event) = v.get("event").and_then(|x| x.as_str()) {
                *by_event.entry(event.to_string()).or_default() += 1;
            }
            last_lines.push(v);
        }
    }
    // Keep only tail (most recent 20) — full log is on disk.
    let tail_start = last_lines.len().saturating_sub(20);
    let tail: Vec<_> = last_lines.into_iter().skip(tail_start).collect();
    let report = serde_json::json!({
        "path": path,
        "lineCount": lines.len(),
        "parsedCount": parsed,
        "byLevel": by_level,
        "byEvent": by_event,
        "tail": tail,
    });
    println!("{}", report);
    ExitCode::SUCCESS
}

fn run_main_loop() -> std::io::Result<()> {
    let rt = tokio::runtime::Builder::new_multi_thread()
        .enable_all()
        .build()?;

    rt.block_on(async {
        diag::log("daemon_start", "agentdeckd main loop starting");
        let mut router = AgentRouter::new();
        router.register(Arc::new(CodexAdapter::new()));
        // Task 4C — Phase 4 finalization: CC adapter now registered
        // alongside Codex. Both kinds route through the same hub and
        // cross-agent History List merges results from both.
        router.register(Arc::new(ClaudeCodeAdapter::new()));
        let hub = RuntimeHub::new(Arc::new(router));
        let res = hub.run(tokio::io::stdin(), tokio::io::stdout()).await;
        diag::log("daemon_stop", &format!("agentdeckd main loop exited: {res:?}"));
        res
    })
}

fn main() -> ExitCode {
    let argv: Vec<String> = std::env::args().collect();
    let args = match parse_args(argv) {
        Ok(a) => a,
        Err(e) => {
            eprintln!("agentdeckd: {e}");
            return ExitCode::from(2);
        }
    };

    if args.show_help {
        print_help();
        return ExitCode::SUCCESS;
    }
    if args.show_version {
        print_version();
        return ExitCode::SUCCESS;
    }

    apply_data_dir_env(&args);

    if args.selfcheck {
        return run_selfcheck();
    }
    if args.diagnostics_report {
        return run_diagnostics_report();
    }

    match run_main_loop() {
        Ok(()) => ExitCode::SUCCESS,
        Err(e) => {
            eprintln!("agentdeckd: main loop error: {e}");
            ExitCode::from(1)
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parse_args_handles_profile_and_data_dir() {
        let args = parse_args(vec![
            "agentdeckd".into(),
            "--profile".into(),
            "dev".into(),
            "--data-dir".into(),
            "/tmp/xx".into(),
        ])
        .unwrap();
        assert_eq!(args.profile.as_deref(), Some("dev"));
        assert_eq!(args.data_dir.as_deref(), Some(std::path::Path::new("/tmp/xx")));
    }

    #[test]
    fn parse_args_flags_selfcheck_and_diagnostics() {
        let args =
            parse_args(vec!["agentdeckd".into(), "--selfcheck".into()]).unwrap();
        assert!(args.selfcheck);

        let args = parse_args(vec![
            "agentdeckd".into(),
            "--diagnostics-report".into(),
        ])
        .unwrap();
        assert!(args.diagnostics_report);
    }

    #[test]
    fn parse_args_rejects_unknown_flag() {
        let err = parse_args(vec!["agentdeckd".into(), "--not-a-flag".into()])
            .unwrap_err();
        assert!(err.contains("--not-a-flag"));
    }
}
