mod client;
mod commands;
mod main_types;
mod output;
mod transport;

use clap::{Parser, Subcommand};
use main_types::{AgentKindArg, ApprovalArg, EffortArg, PermissionArg, SandboxArg, SessionRunArgs};
use output::{render, CliError};
use std::path::PathBuf;
use agentdeck_protocol::{HistoryRequest, ThreadId};

// ── Top-level CLI ─────────────────────────────────────────────────────────────

#[derive(Parser)]
#[command(name = "agentdeck", about = "AgentDeck unified interface CLI (v2)")]
struct Cli {
    /// AgentDeck profile (stable|dev)
    #[arg(long, global = true, default_value = "stable")]
    profile: String,
    /// Override data directory (takes precedence over profile)
    #[arg(long, global = true)]
    data_dir: Option<String>,
    /// Human-readable pretty output
    #[arg(long, global = true)]
    pretty: bool,
    #[command(subcommand)]
    command: Cmd,
}

#[derive(Subcommand)]
enum Cmd {
    /// Round-trip liveness check
    Ping,
    /// Daemon plumbing self-check
    Selfcheck,
    /// Diagnostics
    Diagnostics {
        #[command(subcommand)]
        op: DiagOp,
    },
    /// Protocol introspection
    Protocol {
        #[command(subcommand)]
        op: ProtocolOp,
    },
    /// Agent adapter operations (list, capabilities)
    Agent {
        #[command(subcommand)]
        op: AgentOp,
    },
    /// Session operations (run, continue)
    Session {
        #[command(subcommand)]
        op: SessionOp,
    },
    /// Cross-agent history operations
    History {
        #[command(subcommand)]
        op: HistoryOp,
    },
}

// ── Subcommand enums ──────────────────────────────────────────────────────────

#[derive(Subcommand)]
enum DiagOp {
    /// Print a diagnostics report
    Report,
}

#[derive(Subcommand)]
enum ProtocolOp {
    /// Print the versioned JSON Schema
    Schema,
    /// Print the protocol version number
    Version,
}

#[derive(Subcommand)]
enum AgentOp {
    /// List registered agent adapters
    List,
    /// Show capabilities for a specific agent
    Capabilities {
        #[arg(long)]
        agent: AgentKindArg,
    },
}

#[derive(Subcommand)]
enum SessionOp {
    /// Start a new agent session
    Run {
        #[arg(long)]
        agent: AgentKindArg,
        #[arg(long)]
        cwd: PathBuf,
        #[arg(long)]
        prompt: String,
        // Codex-only flags
        #[arg(long)]
        sandbox: Option<SandboxArg>,
        #[arg(long)]
        approval: Option<ApprovalArg>,
        #[arg(long)]
        persist_approval: bool,
        #[arg(long)]
        reasoning_effort: Option<EffortArg>,
        // CC-only flags
        #[arg(long)]
        permission: Option<PermissionArg>,
        #[arg(long)]
        output_style: Option<String>,
        #[arg(long)]
        model: Option<String>,
        #[arg(long)]
        effort: Option<String>,
        #[arg(long)]
        worktree: Option<String>,
        #[arg(long)]
        session_name: Option<String>,
    },
    /// Continue an existing thread
    Continue {
        #[arg(long)]
        thread_id: String,
        #[arg(long)]
        agent: AgentKindArg,
        /// Working directory associated with the thread. Required so
        /// `claude --resume` finds the right session file under
        /// `~/.claude/projects/<encoded_cwd>/<id>.jsonl` and tool_use
        /// runs in the same directory as the original session
        /// (C3 fix, final v0.2 review).
        #[arg(long)]
        cwd: std::path::PathBuf,
        #[arg(long)]
        prompt: String,
    },
}

#[derive(Subcommand)]
enum HistoryOp {
    /// List threads (default: all agents)
    List {
        #[arg(long)]
        agent: Option<AgentKindArg>,
        #[arg(long)]
        cwd_filter: Option<PathBuf>,
    },
    /// Read thread turns
    Read {
        thread_id: String,
        #[arg(long)]
        agent: AgentKindArg,
    },
    /// Archive a thread
    Archive {
        thread_id: String,
        #[arg(long)]
        agent: AgentKindArg,
    },
    /// Unarchive a thread
    Unarchive {
        thread_id: String,
        #[arg(long)]
        agent: AgentKindArg,
    },
    /// Rename a thread
    Rename {
        thread_id: String,
        title: String,
        #[arg(long)]
        agent: AgentKindArg,
    },
}

// ── Main dispatcher ───────────────────────────────────────────────────────────

fn run_sync(cli: &Cli) -> Result<(), CliError> {
    let profile = &cli.profile;
    let data_dir = cli.data_dir.as_deref();
    let pretty = cli.pretty;

    match &cli.command {
        Cmd::Protocol { op } => {
            let mut c = client::Client::connect(profile, data_dir)?;
            match op {
                ProtocolOp::Schema => commands::handle_protocol_schema(&mut c, pretty),
                ProtocolOp::Version => commands::handle_protocol_version(&mut c, pretty),
            }
        }
        Cmd::Ping => {
            let mut c = client::Client::connect(profile, data_dir)?;
            commands::handle_ping(&mut c, pretty)
        }
        Cmd::Selfcheck => {
            let mut c = client::Client::connect(profile, data_dir)?;
            commands::handle_selfcheck(&mut c, pretty)
        }
        Cmd::Diagnostics { op } => {
            let mut c = client::Client::connect(profile, data_dir)?;
            match op {
                DiagOp::Report => commands::handle_diagnostics_schema(&mut c, pretty),
            }
        }
        Cmd::Agent { op } => {
            let mut c = client::Client::connect(profile, data_dir)?;
            match op {
                AgentOp::List => commands::handle_agent_list(&mut c, pretty),
                AgentOp::Capabilities { agent } => {
                    commands::handle_agent_capabilities(&mut c, *agent, pretty)
                }
            }
        }
        Cmd::History { op } => {
            let mut c = client::Client::connect(profile, data_dir)?;
            let req = match op {
                HistoryOp::List { agent, cwd_filter } => HistoryRequest::List {
                    agent_kind: agent.map(|a| a.into()),
                    cwd_filter: cwd_filter.clone(),
                },
                HistoryOp::Read { thread_id, agent } => HistoryRequest::Read {
                    thread_id: ThreadId(thread_id.clone()),
                    agent_kind: (*agent).into(),
                },
                HistoryOp::Archive { thread_id, agent } => HistoryRequest::Archive {
                    thread_id: ThreadId(thread_id.clone()),
                    agent_kind: (*agent).into(),
                },
                HistoryOp::Unarchive { thread_id, agent } => HistoryRequest::Unarchive {
                    thread_id: ThreadId(thread_id.clone()),
                    agent_kind: (*agent).into(),
                },
                HistoryOp::Rename { thread_id, title, agent } => HistoryRequest::Rename {
                    thread_id: ThreadId(thread_id.clone()),
                    agent_kind: (*agent).into(),
                    title: title.clone(),
                },
            };
            commands::handle_history(&mut c, req, pretty)
        }
        // Session commands need async — handled below in main()
        Cmd::Session { .. } => {
            // Should not reach here in sync path
            unreachable!("session commands handled in async path")
        }
    }
}

#[tokio::main]
async fn main() {
    let cli = Cli::parse();
    let pretty = cli.pretty;
    let profile = cli.profile.clone();
    let data_dir = cli.data_dir.clone();

    let result: Result<(), CliError> = match &cli.command {
        Cmd::Session { op } => {
            match op {
                SessionOp::Run {
                    agent,
                    cwd,
                    prompt,
                    sandbox,
                    approval,
                    persist_approval,
                    reasoning_effort,
                    permission,
                    output_style,
                    model,
                    effort,
                    worktree,
                    session_name,
                } => {
                    let args = SessionRunArgs {
                        agent: *agent,
                        cwd: cwd.clone(),
                        prompt: prompt.clone(),
                        sandbox: *sandbox,
                        approval: *approval,
                        persist_approval: *persist_approval,
                        reasoning_effort: *reasoning_effort,
                        permission: *permission,
                        output_style: output_style.clone(),
                        model: model.clone(),
                        effort: effort.clone(),
                        worktree: worktree.clone(),
                        session_name: session_name.clone(),
                    };
                    commands::handle_session_run(args, &profile, data_dir.as_deref(), pretty).await
                }
                SessionOp::Continue { thread_id, agent, cwd, prompt } => {
                    commands::handle_session_continue(
                        thread_id.clone(),
                        *agent,
                        cwd.clone(),
                        prompt.clone(),
                        &profile,
                        data_dir.as_deref(),
                        pretty,
                    )
                    .await
                }
            }
        }
        _ => run_sync(&cli),
    };

    if let Err(err) = result {
        eprintln!("agentdeck: {}", err.message());
        println!("{}", render(&output::error_envelope(&err), pretty));
        std::process::exit(err.exit_code());
    }
}
