//! Dispatch implementations for all CLI subcommands.
//!
//! Each handler takes a `&mut Client` (or builds its own for session streaming)
//! and returns `Result<(), CliError>`. The `main.rs` `run()` function owns the
//! `Client` and calls these.

use crate::client::{self, Client, session_continue_cmd, session_start_cmd};
use crate::main_types::{
    AgentKindArg, ApprovalArg, EffortArg, PermissionArg, SandboxArg, SessionRunArgs,
};
use crate::output::{CliError, render};
use crate::transport;
use agentdeck_protocol::{
    ActionDecision, ActionDecisionKind, AgentKind, ClaudeCodePermissionMode,
    ClaudeCodeSessionOptions, CodexApprovalPolicy, CodexReasoningEffort, CodexSandboxMode,
    CodexSessionOptions, HistoryRequest, ServerEvent, SessionStart, VendorSessionOptions,
};

// ── Ping ──────────────────────────────────────────────────────────────────────

pub fn handle_ping(c: &mut Client, pretty: bool) -> Result<(), CliError> {
    c.ping()?;
    println!("{}", render(&serde_json::json!({"ok": true}), pretty));
    Ok(())
}

// ── Selfcheck ─────────────────────────────────────────────────────────────────

pub fn handle_selfcheck(c: &mut Client, pretty: bool) -> Result<(), CliError> {
    let v = c.selfcheck()?;
    println!("{}", render(&v, pretty));
    let ok = v.get("ok").and_then(|b| b.as_bool()).unwrap_or(false);
    if ok {
        Ok(())
    } else {
        Err(CliError::Session {
            code: None,
            message: "selfcheck failed".into(),
        })
    }
}

// ── Diagnostics ───────────────────────────────────────────────────────────────

pub fn handle_diagnostics_report(
    profile: &str,
    data_dir: Option<&str>,
    pretty: bool,
) -> Result<(), CliError> {
    let raw = transport::run_daemon_diagnostics_report(profile, data_dir)
        .map_err(|e| CliError::Transport(e.to_string()))?;
    let report: serde_json::Value = serde_json::from_str(&raw)?;
    println!("{}", render(&report, pretty));
    Ok(())
}

// ── Protocol ─────────────────────────────────────────────────────────────────
//
// All four schema exports are pure local data — each version axis
// (IPC/Runtime/Relay v2/E2EE) owns an aggregate schema function in
// `agentdeck-protocol` that these handlers call directly. None of them touch
// `Client`/the daemon (see `main.rs::run_sync`, which dispatches `Cmd::Protocol`
// before any `Client::connect`).

/// Print a schema JSON value pretty-printed with a trailing newline — schema
/// output is always pretty (it's a documentation artifact), independent of
/// the `--pretty` flag.
fn print_schema(schema: &serde_json::Value) {
    println!("{}", serde_json::to_string_pretty(schema).unwrap());
}

pub fn handle_protocol_schema(pretty: bool) -> Result<(), CliError> {
    let _ = pretty;
    print_schema(&agentdeck_protocol::protocol_schema());
    Ok(())
}

pub fn handle_protocol_runtime_schema(pretty: bool) -> Result<(), CliError> {
    let _ = pretty;
    print_schema(&agentdeck_protocol::runtime::runtime_schema());
    Ok(())
}

pub fn handle_protocol_relay_schema(pretty: bool) -> Result<(), CliError> {
    let _ = pretty;
    print_schema(&agentdeck_protocol::relay_v2::relay_v2_schema());
    Ok(())
}

pub fn handle_protocol_e2ee_schema(pretty: bool) -> Result<(), CliError> {
    let _ = pretty;
    print_schema(&agentdeck_protocol::e2ee::e2ee_schema());
    Ok(())
}

pub fn handle_protocol_version(pretty: bool) -> Result<(), CliError> {
    println!(
        "{}",
        render(
            &serde_json::json!({"protocolVersion": agentdeck_protocol::PROTOCOL_VERSION}),
            pretty
        )
    );
    Ok(())
}

// ── Agent ─────────────────────────────────────────────────────────────────────

pub fn handle_agent_list(c: &mut Client, pretty: bool) -> Result<(), CliError> {
    let kinds = c.agent_list()?;
    println!("{}", render(&serde_json::json!({"agents": kinds}), pretty));
    Ok(())
}

pub fn handle_agent_capabilities(
    c: &mut Client,
    kind: AgentKindArg,
    pretty: bool,
) -> Result<(), CliError> {
    let caps = c.agent_capabilities(kind.into())?;
    let v = serde_json::to_value(&caps)?;
    println!("{}", render(&v, pretty));
    Ok(())
}

// ── Session run / continue ────────────────────────────────────────────────────

pub async fn handle_session_run(
    args: SessionRunArgs,
    profile: &str,
    data_dir: Option<&str>,
    pretty: bool,
) -> Result<(), CliError> {
    let vendor_options = build_vendor_options(&args)?;
    let start = SessionStart {
        agent_kind: args.agent.into(),
        cwd: args.cwd,
        prompt: Some(args.prompt),
        vendor_options,
        runtime_options: Default::default(),
    };
    let cmd = session_start_cmd(start);
    let mut events = client::stream_session(cmd, profile, data_dir).await?;
    drain_events(&mut events, pretty).await
}

pub async fn handle_session_continue(
    thread_id: String,
    agent: AgentKindArg,
    cwd: std::path::PathBuf,
    prompt: String,
    profile: &str,
    data_dir: Option<&str>,
    pretty: bool,
) -> Result<(), CliError> {
    // C3 fix: `cwd` now flows from CLI flag → daemon → vendor adapter,
    // so CC `--resume` and tool_use run in the original session's
    // directory rather than the daemon's `std::env::current_dir()`.
    let cmd = session_continue_cmd(thread_id, agent.into(), cwd, prompt);
    let mut events = client::stream_session(cmd, profile, data_dir).await?;
    drain_events(&mut events, pretty).await
}

async fn drain_events(
    events: &mut tokio::sync::mpsc::Receiver<ServerEvent>,
    pretty: bool,
) -> Result<(), CliError> {
    while let Some(ev) = events.recv().await {
        let v = serde_json::to_value(&ev)?;
        println!("{}", render(&v, pretty));
        match &ev {
            ServerEvent::TurnComplete { .. } => return Ok(()),
            ServerEvent::Error { error, .. } => {
                // C5 fix: surface the daemon's structured `error.code`
                // (e.g. `cc-not-installed`) so callers / tests can
                // discriminate failure modes without scraping the
                // message string.
                return Err(CliError::Session {
                    code: Some(error.code.clone()),
                    message: error.message.clone(),
                });
            }
            _ => {}
        }
    }
    Ok(())
}

// ── History ───────────────────────────────────────────────────────────────────

pub fn handle_history(c: &mut Client, req: HistoryRequest, pretty: bool) -> Result<(), CliError> {
    let resp = c.history(req)?;
    let v = serde_json::to_value(&resp)?;
    println!("{}", render(&v, pretty));
    Ok(())
}

// ── Vendor option builder ─────────────────────────────────────────────────────

fn build_vendor_options(args: &SessionRunArgs) -> Result<VendorSessionOptions, CliError> {
    match args.agent {
        AgentKindArg::Codex => Ok(VendorSessionOptions::Codex(CodexSessionOptions {
            approval_policy: args
                .approval
                .map(Into::into)
                .unwrap_or(CodexApprovalPolicy::OnRequest),
            sandbox: args
                .sandbox
                .map(Into::into)
                .unwrap_or(CodexSandboxMode::WorkspaceWrite),
            persist_approval: args.persist_approval,
            reasoning_effort: args
                .reasoning_effort
                .map(Into::into)
                .unwrap_or(CodexReasoningEffort::Medium),
            mcp_overrides: vec![],
        })),
        AgentKindArg::ClaudeCode => {
            Ok(VendorSessionOptions::ClaudeCode(ClaudeCodeSessionOptions {
                permission_mode: args
                    .permission
                    .map(Into::into)
                    .unwrap_or(ClaudeCodePermissionMode::Default),
                model: args.model.clone(),
                effort: args.effort.clone(),
                hooks: vec![],
                output_style: args.output_style.clone(),
                allowed_tools: None,
                disallowed_tools: None,
                mcp_config_path: None,
                plugin_dirs: vec![],
                worktree: args.worktree.clone(),
                session_name: args.session_name.clone(),
                session_id: None,
            }))
        }
    }
}

// ── ValueEnum conversions ─────────────────────────────────────────────────────

impl From<AgentKindArg> for AgentKind {
    fn from(a: AgentKindArg) -> Self {
        match a {
            AgentKindArg::Codex => AgentKind::Codex,
            AgentKindArg::ClaudeCode => AgentKind::ClaudeCode,
        }
    }
}

impl From<SandboxArg> for CodexSandboxMode {
    fn from(s: SandboxArg) -> Self {
        match s {
            SandboxArg::ReadOnly => CodexSandboxMode::ReadOnly,
            SandboxArg::WorkspaceWrite => CodexSandboxMode::WorkspaceWrite,
            SandboxArg::FullAccess => CodexSandboxMode::FullAccess,
        }
    }
}

impl From<ApprovalArg> for CodexApprovalPolicy {
    fn from(a: ApprovalArg) -> Self {
        match a {
            ApprovalArg::OnRequest => CodexApprovalPolicy::OnRequest,
            ApprovalArg::Never => CodexApprovalPolicy::Never,
            ApprovalArg::Always => CodexApprovalPolicy::Always,
        }
    }
}

impl From<EffortArg> for CodexReasoningEffort {
    fn from(e: EffortArg) -> Self {
        match e {
            EffortArg::Minimal => CodexReasoningEffort::Minimal,
            EffortArg::Low => CodexReasoningEffort::Low,
            EffortArg::Medium => CodexReasoningEffort::Medium,
            EffortArg::High => CodexReasoningEffort::High,
        }
    }
}

impl From<PermissionArg> for ClaudeCodePermissionMode {
    fn from(p: PermissionArg) -> Self {
        match p {
            PermissionArg::Default => ClaudeCodePermissionMode::Default,
            PermissionArg::AcceptEdits => ClaudeCodePermissionMode::AcceptEdits,
            PermissionArg::Plan => ClaudeCodePermissionMode::Plan,
            PermissionArg::Auto => ClaudeCodePermissionMode::Auto,
            PermissionArg::DontAsk => ClaudeCodePermissionMode::DontAsk,
            PermissionArg::BypassPermissions => ClaudeCodePermissionMode::BypassPermissions,
        }
    }
}

// ── Action decision helper (for interactive approval in streaming) ─────────────

/// Read an `ActionDecision` from a CLI arg string or stdin.
/// For automated usage pass `auto_approve` / `auto_deny`; for interactive
/// pass `None` to read from stdin.
#[allow(dead_code)]
pub fn resolve_action_decision(
    request_id: &str,
    auto: Option<&str>,
) -> Result<ActionDecision, CliError> {
    match auto {
        Some("approve") | Some("always") => Ok(ActionDecision {
            request_id: request_id.to_string(),
            decision: ActionDecisionKind::Approve,
            persist: false,
        }),
        Some("deny") | Some("never") => Ok(ActionDecision {
            request_id: request_id.to_string(),
            decision: ActionDecisionKind::Deny,
            persist: false,
        }),
        _ => {
            // Interactive: prompt on stderr, read from stdin
            eprintln!("approval request {request_id}: [approve/deny]? ",);
            use std::io::BufRead;
            let mut line = String::new();
            std::io::stdin()
                .lock()
                .read_line(&mut line)
                .map_err(|e| CliError::Transport(e.to_string()))?;
            match line.trim() {
                "approve" => Ok(ActionDecision {
                    request_id: request_id.to_string(),
                    decision: ActionDecisionKind::Approve,
                    persist: false,
                }),
                "deny" => Ok(ActionDecision {
                    request_id: request_id.to_string(),
                    decision: ActionDecisionKind::Deny,
                    persist: false,
                }),
                other => Err(CliError::Usage(format!(
                    "invalid decision '{other}', expected approve|deny"
                ))),
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::path::PathBuf;

    fn make_run_args(agent: AgentKindArg) -> SessionRunArgs {
        SessionRunArgs {
            agent,
            cwd: PathBuf::from("/tmp"),
            prompt: "test prompt".into(),
            sandbox: None,
            approval: None,
            persist_approval: false,
            reasoning_effort: None,
            permission: None,
            output_style: None,
            model: None,
            effort: None,
            worktree: None,
            session_name: None,
        }
    }

    #[test]
    fn build_vendor_options_codex_defaults() {
        let args = make_run_args(AgentKindArg::Codex);
        let opts = build_vendor_options(&args).unwrap();
        match opts {
            VendorSessionOptions::Codex(co) => {
                assert_eq!(co.sandbox, CodexSandboxMode::WorkspaceWrite);
                assert_eq!(co.approval_policy, CodexApprovalPolicy::OnRequest);
                assert_eq!(co.reasoning_effort, CodexReasoningEffort::Medium);
                assert!(!co.persist_approval);
            }
            _ => panic!("expected Codex variant"),
        }
    }

    #[test]
    fn build_vendor_options_cc_defaults() {
        let args = make_run_args(AgentKindArg::ClaudeCode);
        let opts = build_vendor_options(&args).unwrap();
        match opts {
            VendorSessionOptions::ClaudeCode(cc) => {
                assert_eq!(cc.permission_mode, ClaudeCodePermissionMode::Default);
                assert!(cc.model.is_none());
            }
            _ => panic!("expected ClaudeCode variant"),
        }
    }

    #[test]
    fn build_vendor_options_codex_with_explicit_flags() {
        let mut args = make_run_args(AgentKindArg::Codex);
        args.sandbox = Some(SandboxArg::ReadOnly);
        args.approval = Some(ApprovalArg::Never);
        args.reasoning_effort = Some(EffortArg::High);
        args.persist_approval = true;
        let opts = build_vendor_options(&args).unwrap();
        match opts {
            VendorSessionOptions::Codex(co) => {
                assert_eq!(co.sandbox, CodexSandboxMode::ReadOnly);
                assert_eq!(co.approval_policy, CodexApprovalPolicy::Never);
                assert_eq!(co.reasoning_effort, CodexReasoningEffort::High);
                assert!(co.persist_approval);
            }
            _ => panic!("expected Codex"),
        }
    }

    #[test]
    fn build_vendor_options_cc_with_explicit_flags() {
        let mut args = make_run_args(AgentKindArg::ClaudeCode);
        args.permission = Some(PermissionArg::AcceptEdits);
        args.model = Some("haiku".into());
        args.effort = Some("high".into());
        let opts = build_vendor_options(&args).unwrap();
        match opts {
            VendorSessionOptions::ClaudeCode(cc) => {
                assert_eq!(cc.permission_mode, ClaudeCodePermissionMode::AcceptEdits);
                assert_eq!(cc.model.as_deref(), Some("haiku"));
                assert_eq!(cc.effort.as_deref(), Some("high"));
            }
            _ => panic!("expected ClaudeCode"),
        }
    }

    #[test]
    fn agent_kind_arg_converts_correctly() {
        let codex: AgentKind = AgentKindArg::Codex.into();
        let cc: AgentKind = AgentKindArg::ClaudeCode.into();
        assert_eq!(codex, AgentKind::Codex);
        assert_eq!(cc, AgentKind::ClaudeCode);
    }

    #[test]
    fn sandbox_arg_converts_to_codex_sandbox_mode() {
        assert_eq!(
            CodexSandboxMode::from(SandboxArg::ReadOnly),
            CodexSandboxMode::ReadOnly
        );
        assert_eq!(
            CodexSandboxMode::from(SandboxArg::WorkspaceWrite),
            CodexSandboxMode::WorkspaceWrite
        );
        assert_eq!(
            CodexSandboxMode::from(SandboxArg::FullAccess),
            CodexSandboxMode::FullAccess
        );
    }

    #[test]
    fn approval_arg_converts_to_codex_approval_policy() {
        assert_eq!(
            CodexApprovalPolicy::from(ApprovalArg::OnRequest),
            CodexApprovalPolicy::OnRequest
        );
        assert_eq!(
            CodexApprovalPolicy::from(ApprovalArg::Never),
            CodexApprovalPolicy::Never
        );
        assert_eq!(
            CodexApprovalPolicy::from(ApprovalArg::Always),
            CodexApprovalPolicy::Always
        );
    }

    #[test]
    fn permission_arg_converts_to_cc_permission_mode() {
        use PermissionArg::*;
        assert_eq!(
            ClaudeCodePermissionMode::from(Default),
            ClaudeCodePermissionMode::Default
        );
        assert_eq!(
            ClaudeCodePermissionMode::from(AcceptEdits),
            ClaudeCodePermissionMode::AcceptEdits
        );
        assert_eq!(
            ClaudeCodePermissionMode::from(Plan),
            ClaudeCodePermissionMode::Plan
        );
        assert_eq!(
            ClaudeCodePermissionMode::from(Auto),
            ClaudeCodePermissionMode::Auto
        );
        assert_eq!(
            ClaudeCodePermissionMode::from(DontAsk),
            ClaudeCodePermissionMode::DontAsk
        );
        assert_eq!(
            ClaudeCodePermissionMode::from(BypassPermissions),
            ClaudeCodePermissionMode::BypassPermissions
        );
    }
}
