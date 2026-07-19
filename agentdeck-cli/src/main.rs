mod client;
mod commands;
mod main_types;
mod output;
mod remote;
mod runtime_cli;
mod transport;

use clap::{Parser, Subcommand, error::ErrorKind};
use main_types::{AgentKindArg, ApprovalArg, EffortArg, PermissionArg, SandboxArg, SessionRunArgs};
use output::{CliError, render};
use std::ffi::OsString;
use std::path::PathBuf;

#[derive(Parser)]
#[command(name = "agentdeck", about = "AgentDeck unified interface CLI (v2)")]
struct Cli {
    /// AgentDeck profile (Runtime commands require stable)
    #[arg(long, global = true, default_value = "stable")]
    profile: String,
    /// Diagnostics/Relay data directory; rejected by Runtime commands
    #[arg(long, global = true)]
    data_dir: Option<String>,
    /// Human-readable pretty output
    #[arg(long, global = true)]
    pretty: bool,
    /// Debug smoke only: discover one ad-<UUID>/s below this private root.
    #[cfg(debug_assertions)]
    #[arg(long, global = true, hide = true, value_name = "PRIVATE_TMPDIR")]
    runtime_temp_root_for_test: Option<PathBuf>,
    #[command(subcommand)]
    command: Cmd,
}

#[derive(Subcommand)]
enum Cmd {
    /// Connect to the shared daemon and complete the Runtime Hello handshake
    Ping,
    /// Runtime Hello + DescribeAgents self-check
    Selfcheck,
    /// Diagnostics one-shot operations
    Diagnostics {
        #[command(subcommand)]
        op: DiagOp,
    },
    /// Pure local protocol introspection
    Protocol {
        #[command(subcommand)]
        op: ProtocolOp,
    },
    /// Agent adapter operations
    Agent {
        #[command(subcommand)]
        op: AgentOp,
    },
    /// Canonical conversation operations
    Session {
        #[command(subcommand)]
        op: SessionOp,
    },
    /// Canonical catalog/conversation history operations
    History {
        #[command(subcommand)]
        op: HistoryOp,
    },
    /// Remote Relay v2 diagnostics and Companion management
    Remote {
        #[command(subcommand)]
        op: RemoteOp,
    },
    /// 仅 DEBUG 构建可用的跨进程 Runtime smoke 操作。
    #[cfg(debug_assertions)]
    #[command(name = "runtime-smoke-for-test", hide = true)]
    RuntimeSmokeForTest {
        #[command(subcommand)]
        op: RuntimeSmokeOp,
    },
}

#[derive(Subcommand)]
enum DiagOp {
    /// Print a diagnostics report using an explicit one-shot daemon
    Report,
}

#[derive(Subcommand)]
enum ProtocolOp {
    /// Print the local IPC v2 aggregate JSON Schema
    Schema,
    /// Print the local IPC protocol version
    Version,
    /// Print the Runtime v2 aggregate JSON Schema
    #[command(name = "runtime-schema")]
    RuntimeSchema,
    /// Print the Relay v2 aggregate JSON Schema
    #[command(name = "relay-schema")]
    RelaySchema,
    /// Print the E2EE v1 aggregate JSON Schema
    #[command(name = "e2ee-schema")]
    E2eeSchema,
}

#[derive(Subcommand)]
enum AgentOp {
    /// List canonical agent descriptions and defaults
    List,
    /// Show one canonical agent description and default configuration
    Capabilities {
        #[arg(long)]
        agent: AgentKindArg,
    },
}

#[derive(Subcommand)]
enum SessionOp {
    /// DescribeAgents → Start → Configure(rev0) → Subscribe → optional SendPrompt
    Run {
        #[arg(long)]
        agent: AgentKindArg,
        #[arg(long)]
        cwd: PathBuf,
        #[arg(long)]
        prompt: String,
        /// Stable caller operation key; derives start/configure/prompt keys.
        #[arg(long)]
        idempotency_key: String,
        #[arg(long)]
        sandbox: Option<SandboxArg>,
        #[arg(long)]
        approval: Option<ApprovalArg>,
        #[arg(long)]
        reasoning_effort: Option<EffortArg>,
        #[arg(long)]
        permission: Option<PermissionArg>,
        #[arg(long)]
        output_style: Option<String>,
        #[arg(long)]
        model: Option<String>,
        #[arg(long)]
        effort: Option<String>,
    },
    /// Subscribe and send a prompt to a canonical conversationId
    Continue {
        #[arg(long)]
        conversation_id: String,
        #[arg(long)]
        prompt: String,
        /// Stable SendPrompt idempotency key for replay/outcome recovery.
        #[arg(long)]
        idempotency_key: String,
    },
}

#[derive(Subcommand)]
enum HistoryOp {
    /// Page through the canonical Catalog and filter locally
    List {
        #[arg(long)]
        agent: Option<AgentKindArg>,
        #[arg(long)]
        cwd_filter: Option<PathBuf>,
        #[arg(long)]
        limit: Option<usize>,
    },
    /// Subscribe(BeforeFirst) and read a canonical conversation snapshot/backfill
    Read { conversation_id: String },
    /// Archive a canonical conversation using entry-revision CAS
    Archive {
        conversation_id: String,
        #[arg(long)]
        expected_entry_revision: u64,
        #[arg(long)]
        idempotency_key: String,
    },
    /// Unarchive a canonical conversation using entry-revision CAS
    Unarchive {
        conversation_id: String,
        #[arg(long)]
        expected_entry_revision: u64,
        #[arg(long)]
        idempotency_key: String,
    },
    /// Rename a canonical conversation using entry-revision CAS
    Rename {
        conversation_id: String,
        title: String,
        #[arg(long)]
        expected_entry_revision: u64,
        #[arg(long)]
        idempotency_key: String,
    },
}

#[cfg(debug_assertions)]
#[derive(Subcommand)]
enum RuntimeSmokeOp {
    /// 输出当前连接使用的持久化 CLI installation identity。
    Installation,
    /// 不做 identity adoption，发送一条 canonical prompt。
    SendPrompt {
        #[arg(long)]
        conversation_id: String,
        #[arg(long)]
        idempotency_key: String,
        #[arg(long)]
        expected_configuration_revision: u64,
        #[arg(long)]
        prompt: String,
    },
    /// 使用且仅使用一种 owner-scoped selector 查询 receipt。
    QueryReceipt {
        #[arg(long)]
        conversation_id: String,
        #[arg(long)]
        command_id: Option<String>,
        #[arg(long)]
        idempotency_key: Option<String>,
    },
    /// 消费完整 canonical synchronization barrier 并汇总 identity。
    Subscribe {
        #[arg(long)]
        conversation_id: String,
    },
}

#[derive(Subcommand)]
enum RemoteOp {
    /// Real WSS/SPKI + ephemeral machine/device Relay v2 self-check
    Synthetic {
        #[arg(long)]
        bundle: PathBuf,
    },
    /// Removed Relay v1 smoke command (migration error only)
    Smoke,
    /// Persistent pairing is P4; legacy v1 inputs return reset-required
    Pair {
        #[arg(long)]
        relay: Option<String>,
        #[arg(long = "bootstrap-secret", hide = true)]
        legacy_secret: Option<OsString>,
        #[arg(long, value_enum)]
        role: Option<RoleArg>,
    },
    Machines {
        #[arg(long)]
        relay: String,
    },
    Sessions {
        #[arg(long)]
        relay: String,
        machine_id: String,
    },
    Watch {
        #[arg(long)]
        relay: String,
        conversation_id: String,
    },
    Send {
        #[arg(long)]
        relay: String,
        conversation_id: String,
        text: String,
    },
    Approve {
        #[arg(long)]
        relay: String,
        turn_session_id: String,
        request_id: String,
    },
    Deny {
        #[arg(long)]
        relay: String,
        turn_session_id: String,
        request_id: String,
    },
    Ping {
        #[arg(long)]
        relay: String,
        machine_id: String,
    },
}

#[derive(clap::ValueEnum, Clone, Copy, Debug)]
enum RoleArg {
    Machine,
    Device,
}

async fn connect_runtime(
    cli: &Cli,
) -> Result<agentdeck_cli::unix_transport::RuntimeUnixClient, CliError> {
    runtime_cli::validate_runtime_globals(&cli.profile, cli.data_dir.as_deref())?;
    let options = client::RuntimeConnectOptions {
        #[cfg(debug_assertions)]
        temp_root_for_test: cli.runtime_temp_root_for_test.clone(),
    };
    client::connect(&options).await
}

#[cfg(debug_assertions)]
async fn connect_runtime_smoke(
    cli: &Cli,
) -> Result<agentdeck_cli::unix_transport::RuntimeUnixClient, CliError> {
    if cli.runtime_temp_root_for_test.is_none() {
        return Err(CliError::Usage(
            "runtime-smoke-for-test requires --runtime-temp-root-for-test".to_owned(),
        ));
    }
    connect_runtime(cli).await
}

async fn run_non_remote(cli: &Cli) -> Result<(), CliError> {
    let pretty = cli.pretty;
    match &cli.command {
        Cmd::Protocol { op } => match op {
            ProtocolOp::Schema => commands::handle_protocol_schema(),
            ProtocolOp::Version => commands::handle_protocol_version(pretty),
            ProtocolOp::RuntimeSchema => commands::handle_protocol_runtime_schema(),
            ProtocolOp::RelaySchema => commands::handle_protocol_relay_schema(),
            ProtocolOp::E2eeSchema => commands::handle_protocol_e2ee_schema(),
        },
        Cmd::Diagnostics { op: DiagOp::Report } => {
            commands::handle_diagnostics_report(&cli.profile, cli.data_dir.as_deref(), pretty)
        }
        Cmd::Ping => {
            let _client = connect_runtime(cli).await?;
            runtime_cli::handle_ping(pretty);
            Ok(())
        }
        Cmd::Selfcheck => {
            let client = connect_runtime(cli).await?;
            runtime_cli::handle_selfcheck(&client, pretty).await
        }
        Cmd::Agent { op } => {
            let client = connect_runtime(cli).await?;
            match op {
                AgentOp::List => runtime_cli::handle_agent_list(&client, pretty).await,
                AgentOp::Capabilities { agent } => {
                    runtime_cli::handle_agent_capabilities(&client, *agent, pretty).await
                }
            }
        }
        Cmd::Session { op } => match op {
            SessionOp::Run {
                agent,
                cwd,
                prompt,
                idempotency_key,
                sandbox,
                approval,
                reasoning_effort,
                permission,
                output_style,
                model,
                effort,
            } => {
                let plan = runtime_cli::SessionRunPlan::new(SessionRunArgs {
                    agent: *agent,
                    cwd: cwd.clone(),
                    prompt: prompt.clone(),
                    idempotency_key: idempotency_key.clone(),
                    sandbox: *sandbox,
                    approval: *approval,
                    reasoning_effort: *reasoning_effort,
                    permission: *permission,
                    output_style: output_style.clone(),
                    model: model.clone(),
                    effort: effort.clone(),
                })?;
                let client = connect_runtime(cli).await?;
                runtime_cli::handle_session_run(&client, plan, pretty).await
            }
            SessionOp::Continue {
                conversation_id,
                prompt,
                idempotency_key,
            } => {
                let plan = runtime_cli::SessionContinuePlan::new(
                    conversation_id.clone(),
                    prompt.clone(),
                    idempotency_key.clone(),
                )?;
                let client = connect_runtime(cli).await?;
                runtime_cli::handle_session_continue(&client, plan, pretty).await
            }
        },
        Cmd::History { op } => match op {
            HistoryOp::List {
                agent,
                cwd_filter,
                limit,
            } => {
                let client = connect_runtime(cli).await?;
                runtime_cli::handle_history_list(
                    &client,
                    *agent,
                    cwd_filter.as_deref(),
                    *limit,
                    pretty,
                )
                .await
            }
            HistoryOp::Read { conversation_id } => {
                runtime_cli::validate_conversation_id(conversation_id)?;
                let client = connect_runtime(cli).await?;
                runtime_cli::handle_history_read(&client, conversation_id.clone(), pretty).await
            }
            HistoryOp::Archive {
                conversation_id,
                expected_entry_revision,
                idempotency_key,
            } => {
                let plan = runtime_cli::MetadataPlan::archived(
                    conversation_id.clone(),
                    true,
                    *expected_entry_revision,
                    idempotency_key.clone(),
                )?;
                let client = connect_runtime(cli).await?;
                runtime_cli::handle_metadata(&client, plan, pretty).await
            }
            HistoryOp::Unarchive {
                conversation_id,
                expected_entry_revision,
                idempotency_key,
            } => {
                let plan = runtime_cli::MetadataPlan::archived(
                    conversation_id.clone(),
                    false,
                    *expected_entry_revision,
                    idempotency_key.clone(),
                )?;
                let client = connect_runtime(cli).await?;
                runtime_cli::handle_metadata(&client, plan, pretty).await
            }
            HistoryOp::Rename {
                conversation_id,
                title,
                expected_entry_revision,
                idempotency_key,
            } => {
                let plan = runtime_cli::MetadataPlan::rename(
                    conversation_id.clone(),
                    title.clone(),
                    *expected_entry_revision,
                    idempotency_key.clone(),
                )?;
                let client = connect_runtime(cli).await?;
                runtime_cli::handle_metadata(&client, plan, pretty).await
            }
        },
        #[cfg(debug_assertions)]
        Cmd::RuntimeSmokeForTest { op } => match op {
            RuntimeSmokeOp::Installation => {
                let client = connect_runtime_smoke(cli).await?;
                runtime_cli::handle_smoke_installation(&client, pretty);
                Ok(())
            }
            RuntimeSmokeOp::SendPrompt {
                conversation_id,
                idempotency_key,
                expected_configuration_revision,
                prompt,
            } => {
                runtime_cli::validate_conversation_id(conversation_id)?;
                let client = connect_runtime_smoke(cli).await?;
                runtime_cli::handle_smoke_send_prompt(
                    &client,
                    conversation_id.clone(),
                    idempotency_key.clone(),
                    *expected_configuration_revision,
                    prompt.clone(),
                    pretty,
                )
                .await
            }
            RuntimeSmokeOp::QueryReceipt {
                conversation_id,
                command_id,
                idempotency_key,
            } => {
                runtime_cli::validate_conversation_id(conversation_id)?;
                let selector = runtime_cli::SmokeReceiptSelector::new(
                    command_id.clone(),
                    idempotency_key.clone(),
                )?;
                let client = connect_runtime_smoke(cli).await?;
                runtime_cli::handle_smoke_query_receipt(
                    &client,
                    conversation_id.clone(),
                    selector,
                    pretty,
                )
                .await
            }
            RuntimeSmokeOp::Subscribe { conversation_id } => {
                runtime_cli::validate_conversation_id(conversation_id)?;
                let client = connect_runtime_smoke(cli).await?;
                runtime_cli::handle_smoke_subscribe(&client, conversation_id.clone(), pretty).await
            }
        },
        Cmd::Remote { .. } => unreachable!("remote dispatch exits before Runtime dispatch"),
    }
}

#[tokio::main]
async fn main() {
    let cli = match Cli::try_parse() {
        Ok(cli) => cli,
        Err(error)
            if matches!(
                error.kind(),
                ErrorKind::DisplayHelp | ErrorKind::DisplayVersion
            ) =>
        {
            print!("{error}");
            return;
        }
        Err(error) => {
            let error = CliError::Usage(error.to_string());
            eprintln!("agentdeck: {}", error.message());
            println!("{}", render(&output::error_envelope(&error), false));
            std::process::exit(error.exit_code());
        }
    };
    if let Cmd::Remote { op } = &cli.command {
        let arg = match op {
            RemoteOp::Synthetic { bundle } => remote::RemoteOpArg::Synthetic {
                bundle: bundle.clone(),
            },
            RemoteOp::Pair {
                legacy_secret: Some(_),
                ..
            }
            | RemoteOp::Smoke => remote::RemoteOpArg::LegacyV1,
            RemoteOp::Pair { .. }
            | RemoteOp::Machines { .. }
            | RemoteOp::Sessions { .. }
            | RemoteOp::Watch { .. }
            | RemoteOp::Send { .. }
            | RemoteOp::Approve { .. }
            | RemoteOp::Deny { .. }
            | RemoteOp::Ping { .. } => remote::RemoteOpArg::PersistentUnsupported,
        };
        let code = remote::run(arg, &cli.profile, cli.data_dir.as_deref()).await;
        if code == std::process::ExitCode::SUCCESS {
            return;
        }
        std::process::exit(1);
    }

    if let Err(error) = run_non_remote(&cli).await {
        eprintln!("agentdeck: {}", error.message());
        println!("{}", render(&output::error_envelope(&error), cli.pretty));
        std::process::exit(error.exit_code());
    }
}
