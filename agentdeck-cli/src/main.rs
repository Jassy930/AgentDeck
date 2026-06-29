mod client;
mod commands;
mod output;
mod transport;

use clap::{Parser, Subcommand};
use output::{render, CliError};

#[derive(Parser)]
#[command(name = "agentdeck", about = "AgentDeck unified interface CLI")]
struct Cli {
    /// AgentDeck profile（仅影响 AgentDeck 自管理数据目录）
    #[arg(long, global = true, default_value = "stable")]
    profile: String,
    /// 覆盖数据目录（优先于 profile）
    #[arg(long, global = true)]
    data_dir: Option<String>,
    /// 人读 pretty 输出（E2E 不依赖）
    #[arg(long, global = true)]
    pretty: bool,
    #[command(subcommand)]
    command: Command,
}

#[derive(Subcommand)]
enum Command {
    /// 协议自省
    Protocol {
        #[command(subcommand)]
        what: ProtocolCmd,
    },
    /// 往返自检
    Ping,
    /// IPC 生命周期 + logging 自检
    Selfcheck,
    /// 诊断报告
    Diagnostics {
        #[command(subcommand)]
        what: DiagnosticsCmd,
    },
    /// 历史操作
    History {
        #[command(subcommand)]
        what: HistoryCmd,
    },
    /// 流式会话
    Session {
        #[command(subcommand)]
        what: SessionCmd,
    },
}

#[derive(Subcommand)]
enum SessionCmd {
    /// 新会话
    Run {
        #[arg(long)] cwd: String,
        #[arg(long)] prompt: String,
        #[arg(long, value_enum, default_value_t = ApprovalArg::Prompt)]
        approval_policy: ApprovalArg,
    },
    /// 在既有 thread 上继续
    Continue {
        #[arg(long)] thread_id: String,
        #[arg(long)] prompt: String,
        #[arg(long, value_enum, default_value_t = ApprovalArg::Prompt)]
        approval_policy: ApprovalArg,
    },
}

#[derive(Clone, Copy, clap::ValueEnum)]
enum ApprovalArg { Prompt, AutoApprove, AutoDeny }

impl From<ApprovalArg> for client::ApprovalPolicy {
    fn from(a: ApprovalArg) -> Self {
        match a {
            ApprovalArg::Prompt => client::ApprovalPolicy::Prompt,
            ApprovalArg::AutoApprove => client::ApprovalPolicy::AutoApprove,
            ApprovalArg::AutoDeny => client::ApprovalPolicy::AutoDeny,
        }
    }
}

#[derive(Subcommand)]
enum DiagnosticsCmd {
    Report {
        #[arg(long)] limit: Option<u64>,
        #[arg(long)] since_seconds: Option<u64>,
        #[arg(long)] run_id: Option<String>,
    },
}

#[derive(Subcommand)]
enum HistoryCmd {
    List {
        #[arg(long)] cwd: Option<String>,
        #[arg(long)] search: Option<String>,
        #[arg(long)] cursor: Option<String>,
        #[arg(long)] limit: Option<u64>,
    },
    Read { #[arg(long)] thread_id: String },
    Archive { #[arg(long)] thread_id: String },
    Unarchive { #[arg(long)] thread_id: String },
    Rename { #[arg(long)] thread_id: String, #[arg(long)] name: String },
}

#[derive(Subcommand)]
enum ProtocolCmd {
    /// 输出版本化 JSON Schema
    Schema,
    /// 输出协议版本号
    Version,
}

fn connect(profile: &str, data_dir: Option<&str>) -> Result<client::Client<transport::ProcessTransport>, CliError> {
    let transport = transport::ProcessTransport::spawn(profile, data_dir)
        .map_err(|e| CliError::Transport(e.to_string()))?;
    Ok(client::Client::new(transport))
}

fn run(cli: Cli) -> Result<(), CliError> {
    match cli.command {
        Command::Protocol { what } => match what {
            ProtocolCmd::Schema => {
                // schema 始终 pretty（它是文档产物），与 drift 快照一致
                println!("{}", serde_json::to_string_pretty(&agentdeck_protocol::protocol_schema()).expect("json"));
                Ok(())
            }
            ProtocolCmd::Version => {
                let v = serde_json::json!({ "protocolVersion": agentdeck_protocol::PROTOCOL_VERSION });
                println!("{}", render(&v, cli.pretty));
                Ok(())
            }
        },
        Command::Ping => {
            let mut client = connect(&cli.profile, cli.data_dir.as_deref())?;
            let reply = client.round_trip(commands::ping_request())?;
            let payload = client::Client::<transport::ProcessTransport>::expect_kind(reply, "pong")?;
            client.shutdown();
            println!("{}", render(&serde_json::json!({"kind":"pong","payload":payload}), cli.pretty));
            Ok(())
        }
        Command::Selfcheck => {
            let mut client = connect(&cli.profile, cli.data_dir.as_deref())?;
            let reply = client.round_trip(commands::selfcheck_request())?;
            let payload = client::Client::<transport::ProcessTransport>::expect_kind(reply, "loggingSelfcheck")?;
            client.shutdown();
            println!("{}", render(&payload, cli.pretty));
            commands::interpret_selfcheck(&payload)
        }
        Command::Diagnostics { what } => {
            let DiagnosticsCmd::Report { limit, since_seconds, run_id } = what;
            let mut client = connect(&cli.profile, cli.data_dir.as_deref())?;
            let reply = client.round_trip(commands::diagnostics_request(limit, since_seconds, run_id))?;
            let payload = client::Client::<transport::ProcessTransport>::expect_kind(reply, "diagnosticsReport")?;
            client.shutdown();
            println!("{}", render(&payload, cli.pretty));
            Ok(())
        }
        Command::History { what } => {
            let (request, expected) = match what {
                HistoryCmd::List { cwd, search, cursor, limit } =>
                    (commands::history_list_request(cwd, search, cursor, limit), "historyThreads"),
                HistoryCmd::Read { thread_id } =>
                    (commands::history_read_request(&thread_id), "historyThread"),
                HistoryCmd::Archive { thread_id } =>
                    (commands::history_manage_request("history/archiveThread", &thread_id, None), "historyThreadUpdated"),
                HistoryCmd::Unarchive { thread_id } =>
                    (commands::history_manage_request("history/unarchiveThread", &thread_id, None), "historyThreadUpdated"),
                HistoryCmd::Rename { thread_id, name } =>
                    (commands::history_manage_request("history/renameThread", &thread_id, Some(&name)), "historyThreadUpdated"),
            };
            let mut client = connect(&cli.profile, cli.data_dir.as_deref())?;
            let reply = client.round_trip(request)?;
            let payload = client::Client::<transport::ProcessTransport>::expect_kind(reply, expected)?;
            client.shutdown();
            println!("{}", render(&payload, cli.pretty));
            Ok(())
        }
        Command::Session { what } => {
            let session_id = format!("cli-{}", std::process::id());
            let (request, policy) = match what {
                SessionCmd::Run { cwd, prompt, approval_policy } => (
                    output::req("startSession", Some(serde_json::json!({"cwd": cwd, "prompt": prompt}))),
                    approval_policy.into(),
                ),
                SessionCmd::Continue { thread_id, prompt, approval_policy } => (
                    output::req("startTurn", Some(serde_json::json!({"threadId": thread_id, "prompt": prompt}))),
                    approval_policy.into(),
                ),
            };
            let mut client = connect(&cli.profile, cli.data_dir.as_deref())?;
            let pretty = cli.pretty;
            let mut emit = |inner: &serde_json::Value| println!("{}", render(inner, pretty));
            let result = client.run_stream(request, &session_id, policy, &mut emit);
            client.shutdown();
            result
        }
    }
}

fn main() {
    let cli = Cli::parse();
    let pretty = cli.pretty;
    if let Err(err) = run(cli) {
        eprintln!("agentdeck: {}", err.message());
        println!("{}", render(&output::error_envelope(&err), pretty));
        std::process::exit(err.exit_code());
    }
}
