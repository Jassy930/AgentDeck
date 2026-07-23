mod client;
mod commands;
mod main_types;
mod output;
mod remote_cli;
mod runtime_cli;
mod transport;

use clap::{Parser, Subcommand, error::ErrorKind};
use main_types::{AgentKindArg, ApprovalArg, EffortArg, PermissionArg, SandboxArg, SessionRunArgs};
use output::{CliError, render};
use std::ffi::OsString;
use std::future::Future;
use std::path::PathBuf;
use std::time::Duration;

use agentdeck_protocol::runtime::{
    ArtifactSha256, IdempotencyKey, LocalOnlyAdministration, RuntimeReply, RuntimeRequest,
    StageUpgradeReceipt, StageUpgradeRequest,
};

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
    /// Install, inspect, or uninstall the stable per-user daemon LaunchAgent
    Daemon {
        #[command(subcommand)]
        op: DaemonOp,
    },
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
enum DaemonOp {
    Install,
    Status,
    Uninstall {
        /// Complete remote trust-reset, then remove all local AgentDeck daemon data
        #[arg(long)]
        purge: bool,
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
    /// Print the Runtime v4 aggregate JSON Schema
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
    /// 向真实 ephemeral Runtime UDS 发送 local-only StageUpgrade。
    StageUpgrade {
        #[arg(long)]
        target_version: String,
        #[arg(long)]
        candidate_sha256: String,
        #[arg(long)]
        candidate_path: PathBuf,
    },
}

#[derive(Subcommand)]
enum RemoteOp {
    /// Same-UID machine enrollment and status over the canonical Runtime UDS
    Machine {
        #[command(subcommand)]
        op: RemoteMachineOp,
    },
    /// Same-UID pairing administration over the canonical Runtime UDS
    Pairing {
        #[command(subcommand)]
        op: RemotePairingOp,
    },
    /// Revoke one exact device grant over the same-UID Runtime UDS
    Revoke {
        #[arg(long)]
        device: String,
        #[arg(long)]
        grant_serial: u64,
    },
    /// Run ordinary machine trust-reset over the canonical Runtime UDS
    TrustReset {
        /// Portable Relay admin purge receipt for the MachineRoot-lost path
        #[arg(long)]
        admin_purge_receipt_file: Option<PathBuf>,
    },
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

#[derive(Subcommand)]
enum RemoteMachineOp {
    /// Enroll this machine from a strict Relay admin bundle file
    Enroll {
        #[arg(long)]
        bundle_file: PathBuf,
    },
    /// Read the authenticated machine remote lifecycle
    Status,
}

#[derive(Subcommand)]
enum RemotePairingOp {
    /// Create a five-minute out-of-band PairInvite after Relay open ACK
    Invite {
        #[arg(long)]
        display_name: String,
        #[arg(long)]
        idempotency_key: String,
    },
    /// List requests waiting for same-UID fingerprint confirmation
    Pending,
    /// Confirm one pending request
    Approve { pairing_id: String },
    /// Cancel one pending request
    Cancel { pairing_id: String },
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
        Cmd::Daemon { op } => handle_daemon(cli, op).await,
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
            RuntimeSmokeOp::StageUpgrade {
                target_version,
                candidate_sha256,
                candidate_path,
            } => {
                let client = connect_runtime_smoke(cli).await?;
                let artifact = agentdeck_cli::daemon::artifact::InstalledArtifact {
                    path: candidate_path.clone(),
                    version: target_version.clone(),
                    protocol_version: agentdeck_protocol::PROTOCOL_VERSION,
                    sha256: parse_sha256_hex(candidate_sha256)?,
                    team_identifier: "AUTOMATICHARNESS".to_owned(),
                    keychain_access_group: "AUTOMATICHARNESS.com.agentdeck.agentdeckd.stable"
                        .to_owned(),
                };
                let value = finish_daemon_install_with_client(
                    agentdeck_cli::daemon::launchd::DaemonInstallOutcome::Staged { artifact },
                    Some(&client),
                )
                .await?;
                println!("{}", render(&value, pretty));
                Ok(())
            }
        },
        Cmd::Remote { op } => {
            runtime_cli::validate_runtime_globals(&cli.profile, cli.data_dir.as_deref())?;
            let plan = match op {
                RemoteOp::Machine {
                    op: RemoteMachineOp::Enroll { bundle_file },
                } => remote_cli::RuntimeRemotePlan::machine_enroll(bundle_file)?,
                RemoteOp::Machine {
                    op: RemoteMachineOp::Status,
                } => remote_cli::RuntimeRemotePlan::machine_status(),
                RemoteOp::Pairing {
                    op:
                        RemotePairingOp::Invite {
                            display_name,
                            idempotency_key,
                        },
                } => remote_cli::RuntimeRemotePlan::create_pair_invite(
                    display_name.clone(),
                    idempotency_key.clone(),
                )?,
                RemoteOp::Pairing {
                    op: RemotePairingOp::Pending,
                } => remote_cli::RuntimeRemotePlan::pairing_pending(),
                RemoteOp::Pairing {
                    op: RemotePairingOp::Approve { pairing_id },
                } => remote_cli::RuntimeRemotePlan::pairing_approve(pairing_id.clone())?,
                RemoteOp::Pairing {
                    op: RemotePairingOp::Cancel { pairing_id },
                } => remote_cli::RuntimeRemotePlan::pairing_cancel(pairing_id.clone())?,
                RemoteOp::Revoke {
                    device,
                    grant_serial,
                } => remote_cli::RuntimeRemotePlan::revoke_device(device.clone(), *grant_serial)?,
                RemoteOp::TrustReset {
                    admin_purge_receipt_file,
                } => {
                    remote_cli::RuntimeRemotePlan::trust_reset(admin_purge_receipt_file.as_deref())?
                }
                _ => unreachable!("legacy remote dispatch exits before Runtime dispatch"),
            };
            let client = connect_runtime(cli).await?;
            remote_cli::run_runtime(&client, plan, pretty).await
        }
    }
}

async fn handle_daemon(cli: &Cli, op: &DaemonOp) -> Result<(), CliError> {
    runtime_cli::validate_runtime_globals(&cli.profile, cli.data_dir.as_deref())?;
    #[cfg(debug_assertions)]
    if cli.runtime_temp_root_for_test.is_some() {
        return Err(CliError::Usage(
            "daemon production commands reject the ephemeral Runtime test root".to_owned(),
        ));
    }
    let lifecycle =
        agentdeck_cli::daemon::launchd::DaemonLifecycle::production().map_err(daemon_cli_error)?;
    let value = match op {
        DaemonOp::Install => {
            let installer =
                agentdeck_cli::daemon::launchd::DaemonLifecycle::production_installer(None)
                    .map_err(daemon_cli_error)?;
            let outcome = lifecycle
                .install_bundled(&installer)
                .map_err(daemon_cli_error)?;
            finish_daemon_install(cli, outcome).await?
        }
        DaemonOp::Status => {
            let status = lifecycle.status().map_err(daemon_cli_error)?;
            serde_json::json!({"daemon":{"plistInstalled":status.plist_installed,"currentVersion":status.current_version,"launchdLoaded":status.launchd_loaded,"pid":status.pid,"runningProgram":status.running_program}})
        }
        DaemonOp::Uninstall { purge } => {
            if *purge {
                let installer =
                    agentdeck_cli::daemon::launchd::DaemonLifecycle::production_installer(None)
                        .map_err(daemon_cli_error)?;
                let launchctl = agentdeck_cli::daemon::launchd::ProcessLaunchctlRunner;
                let runtime = agentdeck_cli::daemon::purge::StablePurgeRuntimeClient;
                let sockets = agentdeck_cli::daemon::purge::FilesystemSocketProbe;
                let processes = agentdeck_cli::daemon::purge::SystemProcessProbe;
                let helper = agentdeck_cli::daemon::purge::ProcessPurgeHelperRunner;
                agentdeck_cli::daemon::purge::PurgeCoordinator::new(
                    lifecycle.paths(),
                    &launchctl,
                    &installer,
                    &runtime,
                    &sockets,
                    &processes,
                    &helper,
                )
                .run()
                .await
                .map_err(purge_cli_error)?;
                serde_json::json!({"daemon":{"state":"purged","dataPreserved":false}})
            } else {
                lifecycle.uninstall(false).map_err(daemon_cli_error)?;
                serde_json::json!({"daemon":{"state":"uninstalled","dataPreserved":true}})
            }
        }
    };
    println!("{}", render(&value, cli.pretty));
    Ok(())
}

async fn finish_daemon_install(
    cli: &Cli,
    outcome: agentdeck_cli::daemon::launchd::DaemonInstallOutcome,
) -> Result<serde_json::Value, CliError> {
    match &outcome {
        agentdeck_cli::daemon::launchd::DaemonInstallOutcome::Activated { .. } => {
            finish_daemon_install_with_client(outcome, None).await
        }
        agentdeck_cli::daemon::launchd::DaemonInstallOutcome::Staged { .. } => {
            let client = retry_daemon_upgrade_connect(
                || connect_runtime(cli),
                301,
                Duration::from_millis(50),
            )
            .await?;
            finish_daemon_install_with_client(outcome, Some(&client)).await
        }
    }
}

async fn retry_daemon_upgrade_connect<T, Connect, ConnectFuture>(
    mut connect: Connect,
    max_attempts: usize,
    retry_delay: Duration,
) -> Result<T, CliError>
where
    Connect: FnMut() -> ConnectFuture,
    ConnectFuture: Future<Output = Result<T, CliError>>,
{
    assert!(max_attempts > 0, "daemon upgrade connect needs one attempt");
    for attempt in 0..max_attempts {
        match connect().await {
            Ok(client) => return Ok(client),
            Err(error) if daemon_startup_transport_gap(&error) && attempt + 1 < max_attempts => {
                tokio::time::sleep(retry_delay).await;
            }
            Err(error) => return Err(error),
        }
    }
    unreachable!("positive bounded attempt loop always returns")
}

fn daemon_startup_transport_gap(error: &CliError) -> bool {
    matches!(
        error,
        CliError::Transport { code: Some(code), .. }
            if matches!(
                code.as_str(),
                "daemon.client.socket_missing" | "daemon.client.connect_failed"
            )
    )
}

async fn finish_daemon_install_with_client(
    outcome: agentdeck_cli::daemon::launchd::DaemonInstallOutcome,
    client: Option<&agentdeck_cli::unix_transport::RuntimeUnixClient>,
) -> Result<serde_json::Value, CliError> {
    let staged_receipt = match &outcome {
        agentdeck_cli::daemon::launchd::DaemonInstallOutcome::Activated { .. } => None,
        agentdeck_cli::daemon::launchd::DaemonInstallOutcome::Staged { artifact } => {
            let client = client.ok_or_else(|| CliError::Session {
                code: Some("daemon.upgrade.runtime_ack_required".to_owned()),
                message: "staged daemon is not successful before Runtime flush ACK".to_owned(),
            })?;
            Some(request_stage_upgrade(client, stage_upgrade_request(artifact)?).await?)
        }
    };
    daemon_install_output(outcome, staged_receipt)
}

async fn request_stage_upgrade(
    client: &agentdeck_cli::unix_transport::RuntimeUnixClient,
    request: RuntimeRequest,
) -> Result<StageUpgradeReceipt, CliError> {
    let item = client
        .request(request)
        .await
        .map_err(client::map_unix_error)?;
    decode_stage_upgrade_item(item)
}

fn decode_stage_upgrade_item(
    item: agentdeck_cli::unix_transport::ReplySequenceItem,
) -> Result<StageUpgradeReceipt, CliError> {
    match item {
        agentdeck_cli::unix_transport::ReplySequenceItem::Reply(reply) => match *reply {
            RuntimeReply::StageUpgrade(receipt) => Ok(receipt),
            RuntimeReply::Failure(failure) => Err(CliError::Session {
                code: Some(failure.code),
                message: failure.message,
            }),
            _ => Err(CliError::Session {
                code: Some("daemon.upgrade.reply_invalid".to_owned()),
                message: "daemon returned a non-upgrade reply".to_owned(),
            }),
        },
        agentdeck_cli::unix_transport::ReplySequenceItem::TransferComplete(_) => {
            Err(CliError::Session {
                code: Some("daemon.upgrade.reply_invalid".to_owned()),
                message: "daemon returned a transfer for StageUpgrade".to_owned(),
            })
        }
    }
}

fn stage_upgrade_request(
    artifact: &agentdeck_cli::daemon::artifact::InstalledArtifact,
) -> Result<RuntimeRequest, CliError> {
    use std::fmt::Write as _;

    let mut hash = String::with_capacity(64);
    for byte in artifact.sha256 {
        write!(&mut hash, "{byte:02x}").expect("writing to String cannot fail");
    }
    let candidate_sha256 = ArtifactSha256::new(hash.clone()).map_err(|error| {
        CliError::Usage(format!("installed daemon hash is not canonical: {error}"))
    })?;
    let idempotency_key =
        IdempotencyKey::new(format!("daemon-upgrade-v1:{}:{hash}", artifact.version));
    let request = StageUpgradeRequest::new(
        artifact.version.clone(),
        candidate_sha256,
        idempotency_key,
        LocalOnlyAdministration::LocalOnly,
    )
    .map_err(|error| CliError::Usage(format!("installed daemon version is invalid: {error}")))?;
    Ok(RuntimeRequest::StageUpgrade(request))
}

fn parse_sha256_hex(value: &str) -> Result<[u8; 32], CliError> {
    ArtifactSha256::new(value.to_owned()).map_err(|error| {
        CliError::Usage(format!("installed daemon hash is not canonical: {error}"))
    })?;
    let mut decoded = [0_u8; 32];
    for (index, byte) in decoded.iter_mut().enumerate() {
        *byte = u8::from_str_radix(&value[index * 2..index * 2 + 2], 16).map_err(|_| {
            CliError::Usage("installed daemon hash is not canonical lowercase hex".to_owned())
        })?;
    }
    Ok(decoded)
}

fn daemon_install_output(
    outcome: agentdeck_cli::daemon::launchd::DaemonInstallOutcome,
    staged_receipt: Option<StageUpgradeReceipt>,
) -> Result<serde_json::Value, CliError> {
    match outcome {
        agentdeck_cli::daemon::launchd::DaemonInstallOutcome::Activated { artifact } => Ok(
            serde_json::json!({"daemon":{"state":"activated","version":artifact.version,"path":artifact.path}}),
        ),
        agentdeck_cli::daemon::launchd::DaemonInstallOutcome::Staged { artifact } => {
            let Some(receipt) = staged_receipt else {
                return Err(CliError::Session {
                    code: Some("daemon.upgrade.runtime_ack_required".to_owned()),
                    message: "staged daemon is not successful before Runtime flush ACK".to_owned(),
                });
            };
            match receipt {
                StageUpgradeReceipt::Staged { target_version }
                | StageUpgradeReceipt::Replayed { target_version } => {
                    ensure_upgrade_target(&artifact.version, &target_version)?;
                    Ok(
                        serde_json::json!({"daemon":{"state":"staged","version":artifact.version,"path":artifact.path,"runtimeAcked":true}}),
                    )
                }
                StageUpgradeReceipt::AwaitingIdle {
                    target_version,
                    active_turns,
                } => {
                    ensure_upgrade_target(&artifact.version, &target_version)?;
                    Ok(
                        serde_json::json!({"daemon":{"state":"awaitingIdle","version":artifact.version,"path":artifact.path,"activeTurns":active_turns,"runtimeAcked":true}}),
                    )
                }
                StageUpgradeReceipt::Failed { failure } => Err(CliError::Session {
                    code: Some(failure.code),
                    message: failure.message,
                }),
            }
        }
    }
}

fn ensure_upgrade_target(expected: &str, observed: &str) -> Result<(), CliError> {
    if expected == observed {
        Ok(())
    } else {
        Err(CliError::Session {
            code: Some("daemon.upgrade.reply_mismatch".to_owned()),
            message: "daemon upgrade reply target does not match staged artifact".to_owned(),
        })
    }
}

fn daemon_cli_error(error: agentdeck_cli::daemon::launchd::LifecycleError) -> CliError {
    CliError::Session {
        code: Some(error.code().to_owned()),
        message: error.to_string(),
    }
}

fn purge_cli_error(error: agentdeck_cli::daemon::purge::PurgeCliError) -> CliError {
    CliError::Session {
        code: Some(error.code().to_owned()),
        message: error.to_string(),
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
            RemoteOp::Machine { .. }
            | RemoteOp::Pairing { .. }
            | RemoteOp::Revoke { .. }
            | RemoteOp::TrustReset { .. } => None,
            RemoteOp::Synthetic { bundle } => Some(remote_cli::RemoteOpArg::Synthetic {
                bundle: bundle.clone(),
            }),
            RemoteOp::Pair {
                legacy_secret: Some(_),
                ..
            }
            | RemoteOp::Smoke => Some(remote_cli::RemoteOpArg::LegacyV1),
            RemoteOp::Pair { .. }
            | RemoteOp::Machines { .. }
            | RemoteOp::Sessions { .. }
            | RemoteOp::Watch { .. }
            | RemoteOp::Send { .. }
            | RemoteOp::Approve { .. }
            | RemoteOp::Deny { .. }
            | RemoteOp::Ping { .. } => Some(remote_cli::RemoteOpArg::PersistentUnsupported),
        };
        if let Some(arg) = arg {
            let code = remote_cli::run(arg, &cli.profile, cli.data_dir.as_deref()).await;
            if code == std::process::ExitCode::SUCCESS {
                return;
            }
            std::process::exit(1);
        }
    }

    if let Err(error) = run_non_remote(&cli).await {
        eprintln!("agentdeck: {}", error.message());
        println!("{}", render(&output::error_envelope(&error), cli.pretty));
        std::process::exit(error.exit_code());
    }
}

#[cfg(test)]
mod remote_machine_cli_tests {
    use super::*;

    #[test]
    fn exact_machine_enroll_status_and_trust_reset_commands_parse() {
        let enroll = Cli::try_parse_from([
            "agentdeck",
            "remote",
            "machine",
            "enroll",
            "--bundle-file",
            "/private/tmp/enrollment.json",
        ])
        .expect("parse machine enroll");
        assert!(matches!(
            enroll.command,
            Cmd::Remote {
                op: RemoteOp::Machine {
                    op: RemoteMachineOp::Enroll { bundle_file }
                }
            } if bundle_file.as_path() == std::path::Path::new("/private/tmp/enrollment.json")
        ));

        let status = Cli::try_parse_from(["agentdeck", "remote", "machine", "status"])
            .expect("parse machine status");
        assert!(matches!(
            status.command,
            Cmd::Remote {
                op: RemoteOp::Machine {
                    op: RemoteMachineOp::Status
                }
            }
        ));

        let ordinary = Cli::try_parse_from(["agentdeck", "remote", "trust-reset"])
            .expect("parse ordinary trust reset");
        assert!(matches!(
            ordinary.command,
            Cmd::Remote {
                op: RemoteOp::TrustReset {
                    admin_purge_receipt_file: None
                }
            }
        ));

        let root_lost = Cli::try_parse_from([
            "agentdeck",
            "remote",
            "trust-reset",
            "--admin-purge-receipt-file",
            "/private/tmp/purge-receipt.json",
        ])
        .expect("parse root-lost trust reset");
        assert!(matches!(
            root_lost.command,
            Cmd::Remote {
                op: RemoteOp::TrustReset {
                    admin_purge_receipt_file: Some(path)
                }
            } if path.as_path() == std::path::Path::new("/private/tmp/purge-receipt.json")
        ));
    }

    #[test]
    fn machine_commands_reject_missing_or_opaque_input_flags() {
        assert!(Cli::try_parse_from(["agentdeck", "remote", "machine", "enroll"]).is_err());
        assert!(
            Cli::try_parse_from([
                "agentdeck",
                "remote",
                "trust-reset",
                "--admin-purge-receipt",
                "opaque",
            ])
            .is_err()
        );
    }

    #[test]
    fn pairing_administration_commands_are_explicit_and_uds_only() {
        let invite = Cli::try_parse_from([
            "agentdeck",
            "remote",
            "pairing",
            "invite",
            "--display-name",
            "workstation",
            "--idempotency-key",
            "invite-1",
        ])
        .expect("parse pairing invite");
        assert!(matches!(
            invite.command,
            Cmd::Remote {
                op: RemoteOp::Pairing {
                    op: RemotePairingOp::Invite {
                        display_name,
                        idempotency_key,
                    }
                }
            } if display_name == "workstation" && idempotency_key == "invite-1"
        ));

        assert!(matches!(
            Cli::try_parse_from(["agentdeck", "remote", "pairing", "pending"])
                .expect("parse pairing pending")
                .command,
            Cmd::Remote {
                op: RemoteOp::Pairing {
                    op: RemotePairingOp::Pending
                }
            }
        ));
        let pairing_id = "11111111-1111-1111-1111-111111111111";
        for verb in ["approve", "cancel"] {
            let parsed = Cli::try_parse_from(["agentdeck", "remote", "pairing", verb, pairing_id])
                .expect("parse pairing decision");
            assert!(matches!(
                parsed.command,
                Cmd::Remote {
                    op: RemoteOp::Pairing {
                        op: RemotePairingOp::Approve { pairing_id: ref value }
                            | RemotePairingOp::Cancel { pairing_id: ref value }
                    }
                } if value == pairing_id
            ));
        }

        assert!(
            Cli::try_parse_from([
                "agentdeck",
                "remote",
                "pairing",
                "invite",
                "--display-name",
                "workstation",
            ])
            .is_err()
        );
        assert!(Cli::try_parse_from(["agentdeck", "remote", "pairing", "approve",]).is_err());

        assert!(matches!(
            Cli::try_parse_from([
                "agentdeck",
                "remote",
                "revoke",
                "--device",
                "device-11111111111111111111111111111111",
                "--grant-serial",
                "7",
            ])
            .expect("parse exact device revocation")
            .command,
            Cmd::Remote {
                op: RemoteOp::Revoke {
                    device,
                    grant_serial: 7,
                }
            } if device == "device-11111111111111111111111111111111"
        ));
        assert!(
            Cli::try_parse_from([
                "agentdeck",
                "remote",
                "revoke",
                "--device",
                "device-11111111111111111111111111111111",
            ])
            .is_err()
        );
    }
}

#[cfg(test)]
mod daemon_cli_tests {
    use std::sync::{
        Arc,
        atomic::{AtomicUsize, Ordering},
    };

    use super::*;

    fn artifact() -> agentdeck_cli::daemon::artifact::InstalledArtifact {
        agentdeck_cli::daemon::artifact::InstalledArtifact {
            path: PathBuf::from("/private/tmp/bin/2.0.0/agentdeckd"),
            version: "2.0.0".to_owned(),
            protocol_version: 2,
            sha256: [7; 32],
            team_identifier: "REALTEAM42".to_owned(),
            keychain_access_group: "REALTEAM42.com.agentdeck.agentdeckd.stable".to_owned(),
        }
    }

    #[test]
    fn daemon_subcommands_and_purge_are_explicitly_parsed() {
        assert!(matches!(
            Cli::try_parse_from(["agentdeck", "daemon", "install"])
                .expect("install")
                .command,
            Cmd::Daemon {
                op: DaemonOp::Install
            }
        ));
        assert!(matches!(
            Cli::try_parse_from(["agentdeck", "daemon", "uninstall", "--purge"])
                .expect("purge")
                .command,
            Cmd::Daemon {
                op: DaemonOp::Uninstall { purge: true }
            }
        ));
        assert!(matches!(
            Cli::try_parse_from([
                "agentdeck",
                "--runtime-temp-root-for-test",
                "/tmp/private-runtime",
                "runtime-smoke-for-test",
                "stage-upgrade",
                "--target-version",
                "2.0.0",
                "--candidate-sha256",
                "0707070707070707070707070707070707070707070707070707070707070707",
                "--candidate-path",
                "/tmp/private-runtime/bin/2.0.0/agentdeckd",
            ])
            .expect("hidden StageUpgrade harness")
            .command,
            Cmd::RuntimeSmokeForTest {
                op: RuntimeSmokeOp::StageUpgrade { .. }
            }
        ));
    }

    #[tokio::test]
    async fn daemon_commands_reject_ephemeral_runtime_harness_flag() {
        let cli = Cli::try_parse_from([
            "agentdeck",
            "--runtime-temp-root-for-test",
            "/tmp/private-runtime",
            "daemon",
            "status",
        ])
        .expect("parse");
        let Cmd::Daemon { op } = &cli.command else {
            panic!("daemon command")
        };
        assert!(matches!(
            handle_daemon(&cli, op).await,
            Err(CliError::Usage(_))
        ));
    }

    #[tokio::test]
    async fn staged_install_retries_only_bounded_daemon_startup_transport_gaps() {
        let attempts = Arc::new(AtomicUsize::new(0));
        let observed = Arc::clone(&attempts);
        let value = retry_daemon_upgrade_connect(
            move || {
                let attempt = observed.fetch_add(1, Ordering::SeqCst);
                async move {
                    if attempt < 2 {
                        Err(CliError::Transport {
                            code: Some("daemon.client.socket_missing".to_owned()),
                            message: "daemon is starting".to_owned(),
                        })
                    } else {
                        Ok(42_u8)
                    }
                }
            },
            3,
            std::time::Duration::ZERO,
        )
        .await
        .expect("third bounded attempt connects");
        assert_eq!(value, 42);
        assert_eq!(attempts.load(Ordering::SeqCst), 3);

        let attempts = Arc::new(AtomicUsize::new(0));
        let observed = Arc::clone(&attempts);
        let error = retry_daemon_upgrade_connect(
            move || {
                observed.fetch_add(1, Ordering::SeqCst);
                async {
                    Err::<u8, _>(CliError::Transport {
                        code: Some("daemon.client.socket_unsafe".to_owned()),
                        message: "unsafe endpoint".to_owned(),
                    })
                }
            },
            3,
            std::time::Duration::ZERO,
        )
        .await
        .expect_err("security failures are never retried");
        assert!(matches!(
            error,
            CliError::Transport { code: Some(code), .. }
                if code == "daemon.client.socket_unsafe"
        ));
        assert_eq!(attempts.load(Ordering::SeqCst), 1);
    }

    #[test]
    fn staged_artifact_is_not_reported_as_upgrade_success_before_runtime_ack() {
        let error = daemon_install_output(
            agentdeck_cli::daemon::launchd::DaemonInstallOutcome::Staged {
                artifact: artifact(),
            },
            None,
        )
        .expect_err("staged is not final success");
        assert!(matches!(
            error,
            CliError::Session {
                code: Some(code),
                ..
            } if code == "daemon.upgrade.runtime_ack_required"
        ));
    }

    #[test]
    fn staged_artifact_maps_only_exact_runtime_receipts_to_success() {
        let staged_artifact = artifact();
        let value = daemon_install_output(
            agentdeck_cli::daemon::launchd::DaemonInstallOutcome::Staged {
                artifact: staged_artifact.clone(),
            },
            Some(StageUpgradeReceipt::AwaitingIdle {
                target_version: staged_artifact.version.clone(),
                active_turns: 2,
            }),
        )
        .expect("exact Runtime ACK");
        assert_eq!(value["daemon"]["state"], "awaitingIdle");
        assert_eq!(value["daemon"]["activeTurns"], 2);

        assert!(matches!(
            daemon_install_output(
                agentdeck_cli::daemon::launchd::DaemonInstallOutcome::Staged {
                    artifact: staged_artifact,
                },
                Some(StageUpgradeReceipt::Staged {
                    target_version: "other".to_owned(),
                }),
            ),
            Err(CliError::Session { code: Some(code), .. })
                if code == "daemon.upgrade.reply_mismatch"
        ));

        let error = daemon_install_output(
            agentdeck_cli::daemon::launchd::DaemonInstallOutcome::Staged {
                artifact: artifact(),
            },
            Some(StageUpgradeReceipt::Failed {
                failure: agentdeck_protocol::runtime::RuntimeFailure::new(
                    "daemon.upgrade.failed_fixture",
                    "fixture failure",
                ),
            }),
        )
        .expect_err("failed Runtime receipt must remain failed");
        assert!(matches!(
            error,
            CliError::Session { code: Some(code), .. }
                if code == "daemon.upgrade.failed_fixture"
        ));
    }

    #[test]
    fn stage_upgrade_harness_rejects_noncanonical_hash_before_connecting() {
        assert!(matches!(
            parse_sha256_hex("NOT-A-SHA256"),
            Err(CliError::Usage(message)) if message.contains("canonical")
        ));
    }

    #[test]
    fn stage_upgrade_reply_decoder_rejects_outer_failure_wrong_reply_and_transfer() {
        let outer = decode_stage_upgrade_item(
            agentdeck_cli::unix_transport::ReplySequenceItem::Reply(Box::new(
                RuntimeReply::Failure(agentdeck_protocol::runtime::RuntimeFailure::new(
                    "daemon.upgrade.outer_fixture",
                    "outer failure",
                )),
            )),
        )
        .expect_err("outer Runtime failure");
        assert!(matches!(
            outer,
            CliError::Session { code: Some(code), .. }
                if code == "daemon.upgrade.outer_fixture"
        ));

        let wrong = decode_stage_upgrade_item(
            agentdeck_cli::unix_transport::ReplySequenceItem::Reply(Box::new(RuntimeReply::Hello(
                agentdeck_protocol::runtime::command::HelloParams {
                    runtime_protocol_version: agentdeck_protocol::runtime::RUNTIME_PROTOCOL_VERSION,
                },
            ))),
        )
        .expect_err("wrong Runtime reply");
        assert!(matches!(
            wrong,
            CliError::Session { code: Some(code), .. }
                if code == "daemon.upgrade.reply_invalid"
        ));

        let transfer = decode_stage_upgrade_item(
            agentdeck_cli::unix_transport::ReplySequenceItem::TransferComplete(vec![1, 2, 3]),
        )
        .expect_err("StageUpgrade transfer is invalid");
        assert!(matches!(
            transfer,
            CliError::Session { code: Some(code), .. }
                if code == "daemon.upgrade.reply_invalid"
        ));
    }
}
