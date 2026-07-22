mod client;
mod commands;
mod main_types;
mod output;
mod remote;
mod transport;

use agentdeck_protocol::{HistoryRequest, ThreadId};
use clap::{Parser, Subcommand};
use main_types::{AgentKindArg, ApprovalArg, EffortArg, PermissionArg, SandboxArg, SessionRunArgs};
use output::{CliError, render};
use std::path::PathBuf;

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
    /// Remote relay 客户端（R0：仅 `smoke` 可执行；其余为接口基线占位）
    Remote {
        #[command(subcommand)]
        op: RemoteOp,
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
        /// Maximum number of items to return. Defaults to the daemon's
        /// bounded history limit; values above the daemon maximum are clamped.
        #[arg(long)]
        limit: Option<usize>,
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

#[derive(Subcommand)]
enum RemoteOp {
    /// 单进程 R0 冒烟：内存 FakeRelay + 真实 daemon bridge + device 驱动
    Smoke,
    /// 用 bootstrap secret 向 relay 注册本机身份，写入凭据文件
    Pair {
        #[arg(long)]
        relay: String,
        #[arg(long)]
        bootstrap_secret: String,
        #[arg(long, value_enum, default_value = "device")]
        role: RoleArg,
    },
    /// 列出机器
    Machines {
        #[arg(long)]
        relay: String,
    },
    /// 列出某机器的会话
    Sessions {
        #[arg(long)]
        relay: String,
        machine_id: String,
    },
    /// 流式查看某 conversation
    Watch {
        #[arg(long)]
        relay: String,
        conversation_id: String,
    },
    /// 向 conversation 发 prompt
    Send {
        #[arg(long)]
        relay: String,
        conversation_id: String,
        text: String,
    },
    /// 批准某 turn 的审批
    Approve {
        #[arg(long)]
        relay: String,
        turn_session_id: String,
        request_id: String,
    },
    /// 拒绝某 turn 的审批
    Deny {
        #[arg(long)]
        relay: String,
        turn_session_id: String,
        request_id: String,
    },
    /// 机器级 admin 往返
    Ping {
        #[arg(long)]
        relay: String,
        machine_id: String,
    },
}

/// `Pair` 的 `--role` clap 值枚举；`remote::PairRole` 是逻辑层的对应类型
/// （窄化映射见 dispatch 处），避免 clap 派生类型泄漏进 remote 模块。
#[derive(clap::ValueEnum, Clone, Copy, Debug)]
enum RoleArg {
    Machine,
    Device,
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
        Cmd::Diagnostics { op } => match op {
            DiagOp::Report => commands::handle_diagnostics_report(profile, data_dir, pretty),
        },
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
                HistoryOp::List {
                    agent,
                    cwd_filter,
                    limit,
                } => HistoryRequest::List {
                    request_id: None,
                    agent_kind: agent.map(|a| a.into()),
                    cwd_filter: cwd_filter.clone(),
                    limit: *limit,
                },
                HistoryOp::Read { thread_id, agent } => HistoryRequest::Read {
                    request_id: None,
                    thread_id: ThreadId(thread_id.clone()),
                    agent_kind: (*agent).into(),
                },
                HistoryOp::Archive { thread_id, agent } => HistoryRequest::Archive {
                    request_id: None,
                    thread_id: ThreadId(thread_id.clone()),
                    agent_kind: (*agent).into(),
                },
                HistoryOp::Unarchive { thread_id, agent } => HistoryRequest::Unarchive {
                    request_id: None,
                    thread_id: ThreadId(thread_id.clone()),
                    agent_kind: (*agent).into(),
                },
                HistoryOp::Rename {
                    thread_id,
                    title,
                    agent,
                } => HistoryRequest::Rename {
                    request_id: None,
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
        // Remote commands need async — handled below in main()
        Cmd::Remote { .. } => {
            unreachable!("remote commands handled in async path")
        }
    }
}

#[tokio::main]
async fn main() {
    let cli = Cli::parse();
    let pretty = cli.pretty;
    let profile = cli.profile.clone();
    let data_dir = cli.data_dir.clone();

    // Remote commands have their own (non-CliError) exit contract — dispatch and
    // exit here rather than folding into the `Result<(), CliError>` path below.
    if let Cmd::Remote { op } = &cli.command {
        let arg = match op {
            RemoteOp::Smoke => remote::RemoteOpArg::Smoke,
            RemoteOp::Pair { relay, bootstrap_secret, role } => remote::RemoteOpArg::Pair {
                relay: relay.clone(),
                bootstrap_secret: bootstrap_secret.clone(),
                role: match role {
                    RoleArg::Machine => remote::PairRole::Machine,
                    RoleArg::Device => remote::PairRole::Device,
                },
            },
            RemoteOp::Machines { relay } => remote::RemoteOpArg::Machines { relay: relay.clone() },
            RemoteOp::Sessions { relay, machine_id } => remote::RemoteOpArg::Sessions {
                relay: relay.clone(),
                machine_id: machine_id.clone(),
            },
            RemoteOp::Watch { relay, conversation_id } => remote::RemoteOpArg::Watch {
                relay: relay.clone(),
                conversation_id: conversation_id.clone(),
            },
            RemoteOp::Send { relay, conversation_id, text } => remote::RemoteOpArg::Send {
                relay: relay.clone(),
                conversation_id: conversation_id.clone(),
                text: text.clone(),
            },
            RemoteOp::Approve { relay, turn_session_id, request_id } => remote::RemoteOpArg::Approve {
                relay: relay.clone(),
                turn_session_id: turn_session_id.clone(),
                request_id: request_id.clone(),
            },
            RemoteOp::Deny { relay, turn_session_id, request_id } => remote::RemoteOpArg::Deny {
                relay: relay.clone(),
                turn_session_id: turn_session_id.clone(),
                request_id: request_id.clone(),
            },
            RemoteOp::Ping { relay, machine_id } => remote::RemoteOpArg::Ping {
                relay: relay.clone(),
                machine_id: machine_id.clone(),
            },
        };
        let code = remote::run(arg, &profile, data_dir.as_deref()).await;
        if code == std::process::ExitCode::SUCCESS {
            return;
        }
        std::process::exit(1);
    }

    let result: Result<(), CliError> = match &cli.command {
        Cmd::Session { op } => match op {
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
            SessionOp::Continue {
                thread_id,
                agent,
                cwd,
                prompt,
            } => {
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
        },
        _ => run_sync(&cli),
    };

    if let Err(err) = result {
        eprintln!("agentdeck: {}", err.message());
        println!("{}", render(&output::error_envelope(&err), pretty));
        std::process::exit(err.exit_code());
    }
}
