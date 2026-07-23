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
use std::ffi::OsStr;
use std::future::Future;
use std::io::IsTerminal;
use std::path::PathBuf;
use std::time::{Duration, SystemTime, UNIX_EPOCH};
use zeroize::Zeroizing;

use agentdeck_crypto::rand_core::SeedableRng;
use agentdeck_protocol::runtime::identity::{ApprovalId, TurnId};
use agentdeck_protocol::runtime::{
    ArtifactSha256, CommandReceipt, ConversationId, IdempotencyKey, LocalOnlyAdministration,
    PromptPayload, RuntimeReply, RuntimeRequest, SendPromptRequest, StageUpgradeReceipt,
    StageUpgradeRequest,
};
use agentdeck_protocol::{ActionDecision, ActionDecisionKind};
use rand_chacha::ChaCha20Rng;

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

#[derive(clap::Args)]
struct PersistentMachineSelectorArgs {
    /// Exact MachineRoot fingerprint: canonical padded STANDARD base64 for 32 bytes
    #[arg(long, value_name = "STANDARD_BASE64_32")]
    machine_root_fingerprint: String,
    /// Exact machine route: canonical padded STANDARD base64 for 16 bytes
    #[arg(long, value_name = "STANDARD_BASE64_16")]
    machine_route: String,
}

impl PersistentMachineSelectorArgs {
    fn parse(
        &self,
    ) -> Result<agentdeck_cli::remote::selector::PersistentMachineSelector, CliError> {
        agentdeck_cli::remote::selector::PersistentMachineSelector::parse(
            &self.machine_root_fingerprint,
            &self.machine_route,
        )
        .map_err(|error| CliError::Usage(error.to_string()))
    }
}

#[derive(Clone, Copy, Eq, PartialEq, clap::ValueEnum)]
enum RemoteApprovalDecisionArg {
    Approve,
    Deny,
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
    /// Pair this persistent CLI from a canonical bearer invite read outside argv
    Pair {
        /// Read the canonical PairInvite URI from a current-UID exact-0600 no-follow file
        #[arg(
            long,
            value_name = "FILE",
            required_unless_present = "invite_stdin",
            conflicts_with = "invite_stdin"
        )]
        invite_file: Option<PathBuf>,
        /// Read the canonical PairInvite URI from redirected non-interactive stdin
        #[arg(
            long,
            required_unless_present = "invite_file",
            conflicts_with = "invite_file"
        )]
        invite_stdin: bool,
        /// Exact MachineRoot fingerprint shown by the out-of-band invite source
        #[arg(long)]
        confirm_root_fingerprint: String,
    },
    /// List locally paired machines without dialing Relay or the daemon
    Machines,
    /// List canonical conversations for one exact locally paired machine
    Conversations {
        #[command(flatten)]
        selector: PersistentMachineSelectorArgs,
    },
    /// Watch one canonical conversation on one exact locally paired machine
    Watch {
        #[command(flatten)]
        selector: PersistentMachineSelectorArgs,
        #[arg(long)]
        conversation_id: String,
    },
    /// Send a canonical prompt and wait for the authenticated daemon receipt
    Prompt {
        #[command(flatten)]
        selector: PersistentMachineSelectorArgs,
        #[arg(long)]
        conversation_id: String,
        #[arg(long)]
        text: String,
        #[arg(long)]
        idempotency_key: String,
        #[arg(long)]
        expected_configuration_revision: u64,
    },
    /// Submit one first-wins approval decision and wait for its daemon receipt
    Approve {
        #[command(flatten)]
        selector: PersistentMachineSelectorArgs,
        #[arg(long)]
        conversation_id: String,
        #[arg(long)]
        turn_id: String,
        #[arg(long)]
        approval_id: String,
        #[arg(long, value_enum)]
        decision: RemoteApprovalDecisionArg,
        #[arg(long)]
        request_id: String,
        #[arg(long)]
        persist: bool,
    },
    /// Retry delivery of the already claimed decision for one exact approval
    RetryApproval {
        #[command(flatten)]
        selector: PersistentMachineSelectorArgs,
        #[arg(long)]
        conversation_id: String,
        #[arg(long)]
        approval_id: String,
    },
    /// Revoke this persistent paired device after an authenticated Relay terminal
    RevokeSelf {
        #[command(flatten)]
        selector: PersistentMachineSelectorArgs,
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
            if let RemoteOp::Pair {
                invite_file,
                invite_stdin,
                confirm_root_fingerprint,
            } = op
            {
                return run_persistent_remote_pair(
                    invite_file.as_deref(),
                    *invite_stdin,
                    confirm_root_fingerprint,
                    pretty,
                )
                .await;
            }
            if matches!(op, RemoteOp::Machines) {
                let composition =
                    agentdeck_cli::remote::production::PersistentRemoteComposition::production()
                        .map_err(persistent_remote_composition_cli_error)?;
                let output =
                    agentdeck_cli::remote::machines::list_persistent_remote_machines(&composition)
                        .map_err(persistent_remote_machines_cli_error)?;
                println!("{}", render(&output, pretty));
                return Ok(());
            }
            if let RemoteOp::Conversations { selector } = op {
                let selector = selector.parse()?;
                let composition =
                    agentdeck_cli::remote::production::PersistentRemoteComposition::production()
                        .map_err(persistent_remote_composition_cli_error)?;
                let mut rng = production_remote_mutation_rng()?;
                let outcome =
                    agentdeck_cli::remote::conversations::list_persistent_remote_conversations(
                        &composition,
                        selector,
                        &mut rng,
                    )
                    .await
                    .map_err(persistent_remote_conversations_cli_error)?;
                println!(
                    "{}",
                    render(&persistent_remote_conversations_output(&outcome), pretty)
                );
                return Ok(());
            }
            if let Some((operation, selector, mutation)) = persistent_remote_mutation_plan(op)? {
                let composition =
                    agentdeck_cli::remote::production::PersistentRemoteComposition::production()
                        .map_err(persistent_remote_composition_cli_error)?;
                let mut rng = production_remote_mutation_rng()?;
                let outcome = agentdeck_cli::remote::mutations::execute_persistent_remote_mutation(
                    &composition,
                    selector,
                    mutation,
                    &mut rng,
                )
                .await
                .map_err(persistent_remote_mutation_cli_error)?;
                let output = persistent_remote_mutation_output(operation, outcome)?;
                println!("{}", render(&output, pretty));
                return Ok(());
            }
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
                _ => unreachable!("non-UDS remote dispatch exits before Runtime dispatch"),
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

fn persistent_remote_composition_cli_error(
    error: agentdeck_cli::remote::production::PersistentRemoteCompositionError,
) -> CliError {
    CliError::Session {
        code: Some(error.code().to_owned()),
        message: error.to_string(),
    }
}

fn persistent_remote_machines_cli_error(
    error: agentdeck_cli::remote::machines::PersistentRemoteMachinesError,
) -> CliError {
    CliError::Session {
        code: Some(error.code().to_owned()),
        message: error.to_string(),
    }
}

fn persistent_remote_conversations_cli_error(
    error: agentdeck_cli::remote::conversations::PersistentRemoteConversationsError,
) -> CliError {
    use agentdeck_cli::remote::conversations::PersistentRemoteConversationsError;
    use agentdeck_cli::remote::relay_transport::PairedRuntimeConnectError;
    use agentdeck_cli::remote::runtime::RemoteRuntimeError;

    let code = Some(error.code().to_owned());
    let message = error.to_string();
    match error {
        PersistentRemoteConversationsError::Connect(PairedRuntimeConnectError::Relay(_))
        | PersistentRemoteConversationsError::Runtime(RemoteRuntimeError::Transport(_))
        | PersistentRemoteConversationsError::Runtime(RemoteRuntimeError::OutcomeUnknown) => {
            CliError::Transport { code, message }
        }
        PersistentRemoteConversationsError::Pagination(_)
        | PersistentRemoteConversationsError::Runtime(
            RemoteRuntimeError::RelayCodec(_)
            | RemoteRuntimeError::Json(_)
            | RemoteRuntimeError::InvalidReply(_)
            | RemoteRuntimeError::TransferCarrier(_)
            | RemoteRuntimeError::Transfer(_),
        ) => CliError::Protocol { code, message },
        PersistentRemoteConversationsError::Paired(_)
        | PersistentRemoteConversationsError::Connect(PairedRuntimeConnectError::Paired(_))
        | PersistentRemoteConversationsError::HandshakeRevoked
        | PersistentRemoteConversationsError::Runtime(_) => CliError::Session { code, message },
    }
}

fn persistent_remote_mutation_cli_error(
    error: agentdeck_cli::remote::mutations::PersistentRemoteMutationError,
) -> CliError {
    use agentdeck_cli::remote::mutations::PersistentRemoteMutationError;
    use agentdeck_cli::remote::relay_transport::PairedRuntimeConnectError;
    use agentdeck_cli::remote::runtime::RemoteRuntimeError;

    let code = Some(error.code().to_owned());
    let message = error.to_string();
    match error {
        PersistentRemoteMutationError::Connect(PairedRuntimeConnectError::Relay(_))
        | PersistentRemoteMutationError::Runtime(RemoteRuntimeError::Transport(_))
        | PersistentRemoteMutationError::Runtime(RemoteRuntimeError::OutcomeUnknown) => {
            CliError::Transport { code, message }
        }
        PersistentRemoteMutationError::Runtime(
            RemoteRuntimeError::RelayCodec(_)
            | RemoteRuntimeError::Json(_)
            | RemoteRuntimeError::InvalidReply(_)
            | RemoteRuntimeError::TransferCarrier(_)
            | RemoteRuntimeError::Transfer(_),
        ) => CliError::Protocol { code, message },
        PersistentRemoteMutationError::Paired(_)
        | PersistentRemoteMutationError::Connect(PairedRuntimeConnectError::Paired(_))
        | PersistentRemoteMutationError::HandshakeRevoked
        | PersistentRemoteMutationError::Runtime(_) => CliError::Session { code, message },
    }
}

fn persistent_remote_mutation_plan(
    op: &RemoteOp,
) -> Result<
    Option<(
        &'static str,
        agentdeck_cli::remote::selector::PersistentMachineSelector,
        agentdeck_cli::remote::mutations::PersistentRemoteMutation,
    )>,
    CliError,
> {
    use agentdeck_cli::remote::mutations::PersistentRemoteMutation;

    let planned = match op {
        RemoteOp::Prompt {
            selector,
            conversation_id,
            text,
            idempotency_key,
            expected_configuration_revision,
        } => {
            validate_persistent_remote_runtime_id(
                conversation_id,
                "remote prompt --conversation-id",
            )?;
            validate_persistent_remote_opaque(idempotency_key, "remote prompt --idempotency-key")?;
            if text.is_empty() {
                return Err(CliError::Usage(
                    "remote prompt --text must not be empty".to_owned(),
                ));
            }
            let prompt = PromptPayload::new(text.clone())
                .map_err(|error| CliError::Usage(error.to_string()))?;
            (
                "prompt",
                selector.parse()?,
                PersistentRemoteMutation::Prompt(SendPromptRequest {
                    conversation_id: ConversationId::new(conversation_id.clone()),
                    idempotency_key: IdempotencyKey::new(idempotency_key.clone()),
                    expected_configuration_revision: *expected_configuration_revision,
                    prompt,
                }),
            )
        }
        RemoteOp::Approve {
            selector,
            conversation_id,
            turn_id,
            approval_id,
            decision,
            request_id,
            persist,
        } => {
            validate_persistent_remote_runtime_id(
                conversation_id,
                "remote approve --conversation-id",
            )?;
            validate_persistent_remote_runtime_id(turn_id, "remote approve --turn-id")?;
            validate_persistent_remote_runtime_id(approval_id, "remote approve --approval-id")?;
            validate_persistent_remote_opaque(request_id, "remote approve --request-id")?;
            if *persist && *decision == RemoteApprovalDecisionArg::Deny {
                return Err(CliError::Usage(
                    "remote approve --persist is only valid with --decision approve".to_owned(),
                ));
            }
            (
                "approve",
                selector.parse()?,
                PersistentRemoteMutation::ResolveApproval {
                    conversation_id: ConversationId::new(conversation_id.clone()),
                    turn_id: TurnId::new(turn_id.clone()),
                    approval_id: ApprovalId::new(approval_id.clone()),
                    decision: ActionDecision {
                        request_id: request_id.clone(),
                        decision: match decision {
                            RemoteApprovalDecisionArg::Approve => ActionDecisionKind::Approve,
                            RemoteApprovalDecisionArg::Deny => ActionDecisionKind::Deny,
                        },
                        persist: *persist,
                    },
                },
            )
        }
        RemoteOp::RetryApproval {
            selector,
            conversation_id,
            approval_id,
        } => {
            validate_persistent_remote_runtime_id(
                conversation_id,
                "remote retry-approval --conversation-id",
            )?;
            validate_persistent_remote_runtime_id(
                approval_id,
                "remote retry-approval --approval-id",
            )?;
            (
                "retryApproval",
                selector.parse()?,
                PersistentRemoteMutation::RetryApproval {
                    conversation_id: ConversationId::new(conversation_id.clone()),
                    approval_id: ApprovalId::new(approval_id.clone()),
                },
            )
        }
        RemoteOp::RevokeSelf { selector } => (
            "revokeSelf",
            selector.parse()?,
            PersistentRemoteMutation::RevokeSelf,
        ),
        RemoteOp::Machine { .. }
        | RemoteOp::Pairing { .. }
        | RemoteOp::Revoke { .. }
        | RemoteOp::TrustReset { .. }
        | RemoteOp::Synthetic { .. }
        | RemoteOp::Smoke
        | RemoteOp::Pair { .. }
        | RemoteOp::Machines
        | RemoteOp::Conversations { .. }
        | RemoteOp::Watch { .. } => return Ok(None),
    };
    Ok(Some(planned))
}

fn validate_persistent_remote_opaque(value: &str, label: &str) -> Result<(), CliError> {
    if value.is_empty() || value.len() > 1_024 || value.as_bytes().contains(&0) {
        return Err(CliError::Usage(format!(
            "{label} must contain 1 to 1024 UTF-8 bytes and no NUL"
        )));
    }
    Ok(())
}

fn validate_persistent_remote_runtime_id(value: &str, label: &str) -> Result<(), CliError> {
    let valid = uuid::Uuid::parse_str(value).is_ok_and(|parsed| {
        parsed.as_bytes() != &[0; 16] && parsed.hyphenated().to_string() == value
    });
    if !valid {
        return Err(CliError::Usage(format!(
            "{label} must be a nonzero canonical lowercase hyphenated UUID"
        )));
    }
    Ok(())
}

fn persistent_remote_mutation_output(
    operation: &'static str,
    outcome: agentdeck_cli::remote::mutations::PersistentRemoteMutationOutcome,
) -> Result<serde_json::Value, CliError> {
    use agentdeck_cli::remote::mutations::PersistentRemoteMutationOutcome;

    let route_accepted = outcome.route_accepted();
    let receipt = match outcome {
        PersistentRemoteMutationOutcome::Prompt {
            receipt: CommandReceipt::Failed { failure },
            ..
        } => {
            return Err(CliError::Session {
                code: Some(failure.code),
                message: failure.message,
            });
        }
        PersistentRemoteMutationOutcome::Prompt { receipt, .. } => serde_json::to_value(receipt)?,
        PersistentRemoteMutationOutcome::Approval { receipt, .. } => serde_json::to_value(receipt)?,
        PersistentRemoteMutationOutcome::Revocation { receipt, .. } => {
            serde_json::to_value(receipt)?
        }
    };
    Ok(serde_json::json!({
        "operation": operation,
        "transport": {"routeAccepted": route_accepted},
        "receipt": receipt,
    }))
}

fn persistent_remote_conversations_output(
    outcome: &agentdeck_cli::remote::conversations::PersistentRemoteConversationsOutcome,
) -> serde_json::Value {
    serde_json::json!({
        "operation": "remote.conversations",
        "transport": {
            "routeAcceptedObserved": outcome.route_accepted_observed(),
        },
        "result": {
            "baseCatalogCursor": outcome.base_catalog_cursor(),
            "pageCount": outcome.page_count(),
            "conversations": outcome.conversations(),
        },
    })
}

async fn run_persistent_remote_pair(
    invite_file: Option<&std::path::Path>,
    invite_stdin: bool,
    confirm_root_fingerprint: &str,
    pretty: bool,
) -> Result<(), CliError> {
    // 签名、entitlement 与 production Keychain composition 必须在触碰 bearer 前收口。
    let composition = agentdeck_cli::remote::production::PersistentRemoteComposition::production()
        .map_err(persistent_remote_composition_cli_error)?;
    let now_ms = unix_now_ms();
    let invite = match (invite_file, invite_stdin) {
        (Some(path), false) => {
            agentdeck_cli::remote::pair::load_pair_invite_from_private_file(path, now_ms)
                .map_err(persistent_remote_pair_cli_error)?
        }
        (None, true) => {
            let stdin = std::io::stdin();
            require_non_tty_pair_stdin(stdin.is_terminal())?;
            agentdeck_cli::remote::pair::load_pair_invite_from_reader(stdin.lock(), now_ms)
                .map_err(persistent_remote_pair_cli_error)?
        }
        _ => {
            return Err(CliError::Usage(
                "remote pair requires exactly one of --invite-file or --invite-stdin".to_owned(),
            ));
        }
    };
    let confirmed = agentdeck_cli::remote::pair::confirm_machine_root_fingerprint(
        invite,
        confirm_root_fingerprint,
    )
    .map_err(persistent_remote_pair_cli_error)?;
    let mut rng = production_pairing_rng()?;
    let outcome = agentdeck_cli::remote::pair::pair_production(&composition, confirmed, &mut rng)
        .await
        .map_err(persistent_remote_pair_cli_error)?;
    let output = serde_json::json!({
        "operation": "remote.pair",
        "pairing": {
            "state": "paired",
            "machineRootFingerprint": outcome.machine_root_fingerprint(),
            "machineRoute": outcome.machine_route(),
            "deviceRoute": outcome.device_route(),
            "recoveredPairedMarker": outcome.recovered_paired_marker(),
        },
        "transport": {
            "routeAcceptedObserved": outcome.route_accepted_observed(),
            "durableClosed": true,
        }
    });
    println!("{}", render(&output, pretty));
    Ok(())
}

fn require_non_tty_pair_stdin(is_terminal: bool) -> Result<(), CliError> {
    if is_terminal {
        Err(CliError::Usage(
            "remote pair --invite-stdin requires redirected non-interactive stdin".to_owned(),
        ))
    } else {
        Ok(())
    }
}

fn persistent_remote_pair_cli_error(
    error: agentdeck_cli::remote::pair::DurablePairError,
) -> CliError {
    let code = Some(error.code().to_owned());
    let message = error.to_string();
    match error {
        agentdeck_cli::remote::pair::DurablePairError::Input(_)
        | agentdeck_cli::remote::pair::DurablePairError::InvalidInvite(_)
        | agentdeck_cli::remote::pair::DurablePairError::InvalidAuthorization(_)
        | agentdeck_cli::remote::pair::DurablePairError::RootFingerprintMismatch
        | agentdeck_cli::remote::pair::DurablePairError::ClosedBeforeReceipt
        | agentdeck_cli::remote::pair::DurablePairError::RouteMismatch => {
            CliError::Protocol { code, message }
        }
        agentdeck_cli::remote::pair::DurablePairError::OutcomeUnknown
        | agentdeck_cli::remote::pair::DurablePairError::TransportSecurity(_)
        | agentdeck_cli::remote::pair::DurablePairError::RelayRejected(_) => {
            CliError::Transport { code, message }
        }
        agentdeck_cli::remote::pair::DurablePairError::Pending(_)
        | agentdeck_cli::remote::pair::DurablePairError::Promotion(_) => {
            CliError::Session { code, message }
        }
    }
}

fn production_pairing_rng() -> Result<ChaCha20Rng, CliError> {
    let mut seed = Zeroizing::new([0_u8; 32]);
    getrandom::fill(seed.as_mut()).map_err(|_| pairing_entropy_cli_error())?;
    if seed.iter().all(|byte| *byte == 0) {
        return Err(pairing_entropy_cli_error());
    }
    Ok(ChaCha20Rng::from_seed(*seed))
}

fn production_remote_mutation_rng() -> Result<ChaCha20Rng, CliError> {
    let mut seed = Zeroizing::new([0_u8; 32]);
    getrandom::fill(seed.as_mut()).map_err(|_| remote_mutation_entropy_cli_error())?;
    if seed.iter().all(|byte| *byte == 0) {
        return Err(remote_mutation_entropy_cli_error());
    }
    Ok(ChaCha20Rng::from_seed(*seed))
}

fn remote_mutation_entropy_cli_error() -> CliError {
    CliError::Session {
        code: Some("remote.runtime.entropy_unavailable".to_owned()),
        message: "production remote Runtime entropy is unavailable".to_owned(),
    }
}

fn pairing_entropy_cli_error() -> CliError {
    CliError::Session {
        code: Some("remote.pairing.entropy_unavailable".to_owned()),
        message: "production pairing entropy is unavailable".to_owned(),
    }
}

fn unix_now_ms() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_millis()
        .try_into()
        .unwrap_or(u64::MAX)
}

const FORBIDDEN_PAIR_ARGV_MESSAGE: &str =
    "remote pair accepts the invite bearer only through --invite-file or --invite-stdin";

fn forbidden_remote_pair_argv<I, S>(args: I) -> bool
where
    I: IntoIterator<Item = S>,
    S: AsRef<OsStr>,
{
    let arguments = args.into_iter().skip(1).collect::<Vec<_>>();
    if arguments
        .iter()
        .any(|argument| contains_ascii(argument.as_ref().as_encoded_bytes(), b"agentdeck-pair:"))
    {
        return true;
    }

    let mut index = 0;
    if !next_argv_command_is(&arguments, &mut index, b"remote")
        || !next_argv_command_is(&arguments, &mut index, b"pair")
    {
        return false;
    }
    arguments[index..].iter().any(|argument| {
        let bytes = argument.as_ref().as_encoded_bytes();
        [
            b"--invite".as_slice(),
            b"--relay",
            b"--bootstrap-secret",
            b"--role",
        ]
        .into_iter()
        .any(|flag| is_flag_or_assignment(bytes, flag))
    })
}

fn next_argv_command_is<S>(arguments: &[S], index: &mut usize, expected: &[u8]) -> bool
where
    S: AsRef<OsStr>,
{
    while let Some(argument) = arguments.get(*index) {
        let bytes = argument.as_ref().as_encoded_bytes();
        if let Some(width) = global_argv_width(bytes) {
            if width == 2 && arguments.get(index.saturating_add(1)).is_none() {
                return false;
            }
            *index = index.saturating_add(width);
            continue;
        }
        *index = index.saturating_add(1);
        return bytes == expected;
    }
    false
}

fn global_argv_width(value: &[u8]) -> Option<usize> {
    if value == b"--pretty" {
        return Some(1);
    }
    for option in [
        b"--profile".as_slice(),
        b"--data-dir",
        b"--runtime-temp-root-for-test",
    ] {
        if value == option {
            return Some(2);
        }
        if value
            .strip_prefix(option)
            .is_some_and(|suffix| suffix.starts_with(b"="))
        {
            return Some(1);
        }
    }
    None
}

fn contains_ascii(value: &[u8], needle: &[u8]) -> bool {
    value
        .windows(needle.len())
        .any(|candidate| candidate == needle)
}

fn is_flag_or_assignment(value: &[u8], flag: &[u8]) -> bool {
    value == flag
        || value
            .strip_prefix(flag)
            .is_some_and(|suffix| suffix.starts_with(b"="))
}

fn remote_pre_dispatch(op: &RemoteOp) -> Result<Option<remote_cli::RemoteOpArg>, CliError> {
    let arg = match op {
        RemoteOp::Machine { .. }
        | RemoteOp::Pairing { .. }
        | RemoteOp::Revoke { .. }
        | RemoteOp::TrustReset { .. }
        | RemoteOp::Pair { .. }
        | RemoteOp::Machines => None,
        RemoteOp::Synthetic { bundle } => Some(remote_cli::RemoteOpArg::Synthetic {
            bundle: bundle.clone(),
        }),
        RemoteOp::Smoke => Some(remote_cli::RemoteOpArg::LegacyV1),
        RemoteOp::Conversations { selector } => {
            let _selector = selector.parse()?;
            None
        }
        RemoteOp::Watch { selector, .. } => {
            let _selector = selector.parse()?;
            Some(remote_cli::RemoteOpArg::PersistentUnsupported)
        }
        RemoteOp::Prompt { selector, .. }
        | RemoteOp::Approve { selector, .. }
        | RemoteOp::RetryApproval { selector, .. }
        | RemoteOp::RevokeSelf { selector } => {
            let _selector = selector.parse()?;
            None
        }
    };
    Ok(arg)
}

#[tokio::main]
async fn main() {
    if forbidden_remote_pair_argv(std::env::args_os()) {
        let error = CliError::Usage(FORBIDDEN_PAIR_ARGV_MESSAGE.to_owned());
        eprintln!("agentdeck: {}", error.message());
        println!("{}", render(&output::error_envelope(&error), false));
        std::process::exit(error.exit_code());
    }
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
        let arg = match remote_pre_dispatch(op) {
            Ok(arg) => arg,
            Err(error) => {
                eprintln!("agentdeck: {}", error.message());
                println!("{}", render(&output::error_envelope(&error), cli.pretty));
                std::process::exit(error.exit_code());
            }
        };
        if let Some(arg) = arg {
            if matches!(&arg, remote_cli::RemoteOpArg::PersistentUnsupported) {
                eprintln!("remote.persistent.unsupported");
                std::process::exit(1);
            }
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
    fn persistent_machines_is_local_and_rejects_legacy_relay_selector() {
        assert!(matches!(
            Cli::try_parse_from(["agentdeck", "remote", "machines"])
                .expect("parse local machines")
                .command,
            Cmd::Remote {
                op: RemoteOp::Machines
            }
        ));
        assert!(
            Cli::try_parse_from([
                "agentdeck",
                "remote",
                "machines",
                "--relay",
                "wss://relay.example/",
            ])
            .is_err()
        );
    }

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
mod remote_pair_cli_tests {
    use super::*;

    const CONFIRMATION: &str = "sha256:11:22:33";

    #[test]
    fn persistent_pair_requires_one_non_argv_invite_source_and_root_confirmation() {
        let file = Cli::try_parse_from([
            "agentdeck",
            "remote",
            "pair",
            "--invite-file",
            "/private/tmp/pair-invite.txt",
            "--confirm-root-fingerprint",
            CONFIRMATION,
        ])
        .expect("parse private invite file source");
        assert!(matches!(
            file.command,
            Cmd::Remote {
                op: RemoteOp::Pair {
                    invite_file: Some(path),
                    invite_stdin: false,
                    confirm_root_fingerprint,
                }
            } if path.as_path() == std::path::Path::new("/private/tmp/pair-invite.txt")
                && confirm_root_fingerprint == CONFIRMATION
        ));

        let stdin = Cli::try_parse_from([
            "agentdeck",
            "remote",
            "pair",
            "--invite-stdin",
            "--confirm-root-fingerprint",
            CONFIRMATION,
        ])
        .expect("parse explicit stdin source");
        assert!(matches!(
            stdin.command,
            Cmd::Remote {
                op: RemoteOp::Pair {
                    invite_file: None,
                    invite_stdin: true,
                    confirm_root_fingerprint,
                }
            } if confirm_root_fingerprint == CONFIRMATION
        ));

        assert!(
            Cli::try_parse_from([
                "agentdeck",
                "remote",
                "pair",
                "--confirm-root-fingerprint",
                CONFIRMATION,
            ])
            .is_err()
        );
        assert!(
            Cli::try_parse_from([
                "agentdeck",
                "remote",
                "pair",
                "--invite-stdin",
                "--invite-file",
                "/private/tmp/pair-invite.txt",
                "--confirm-root-fingerprint",
                CONFIRMATION,
            ])
            .is_err()
        );
        assert!(Cli::try_parse_from(["agentdeck", "remote", "pair", "--invite-stdin",]).is_err());
    }

    #[test]
    fn persistent_pair_rejects_every_legacy_or_argv_bearer_surface() {
        for forbidden in [
            vec!["--relay", "wss://relay.example/"],
            vec!["--bootstrap-secret", "secret-sentinel"],
            vec!["--role", "device"],
            vec!["--invite", "agentdeck-pair:v1:secret-sentinel"],
        ] {
            let mut args = vec!["agentdeck", "remote", "pair", "--invite-stdin"];
            args.extend(forbidden);
            args.extend(["--confirm-root-fingerprint", CONFIRMATION]);
            assert!(Cli::try_parse_from(args).is_err());
        }
        assert!(
            Cli::try_parse_from([
                "agentdeck",
                "remote",
                "pair",
                "agentdeck-pair:v1:secret-sentinel",
                "--confirm-root-fingerprint",
                CONFIRMATION,
            ])
            .is_err()
        );

        for forbidden in [
            vec![
                "agentdeck",
                "remote",
                "pair",
                "agentdeck-pair:v1:secret-sentinel",
            ],
            vec!["agentdeck", "remote", "pair", "--invite", "secret-sentinel"],
            vec![
                "agentdeck",
                "remote",
                "pair",
                "--bootstrap-secret=secret-sentinel",
            ],
            vec![
                "agentdeck",
                "remote",
                "pair",
                "--unknown=agentdeck-pair:v1:secret-sentinel",
            ],
            vec![
                "agentdeck",
                "--data-dir",
                "agentdeck-pair:v1:secret-sentinel",
                "remote",
                "pair",
                "--invite-stdin",
            ],
            vec![
                "agentdeck",
                "--profile",
                "stable",
                "remote",
                "--pretty",
                "pair",
                "--bootstrap-secret=secret-sentinel",
            ],
        ] {
            assert!(forbidden_remote_pair_argv(forbidden));
        }
        assert!(!forbidden_remote_pair_argv([
            "agentdeck",
            "remote",
            "pair",
            "--invite-file",
            "/private/tmp/pair-invite.txt",
            "--confirm-root-fingerprint",
            CONFIRMATION,
        ]));
        assert!(!forbidden_remote_pair_argv([
            "agentdeck",
            "remote",
            "conversations",
            "pair",
            "--relay",
            "wss://relay.example/",
        ]));
        assert!(!forbidden_remote_pair_argv([
            "agentdeck",
            "--data-dir",
            "remote",
            "pair",
            "--relay",
            "wss://relay.example/",
        ]));
    }

    #[test]
    fn pair_stdin_rejects_an_interactive_terminal() {
        let error = require_non_tty_pair_stdin(true).unwrap_err();
        assert_eq!(error.exit_code(), 2);
        assert!(!error.message().contains("agentdeck-pair:"));
        assert!(require_non_tty_pair_stdin(false).is_ok());
    }

    #[test]
    fn production_signature_composition_precedes_bearer_read_and_pending_pair() {
        let source = include_str!("main.rs");
        let body = source
            .split("async fn run_persistent_remote_pair(")
            .nth(1)
            .and_then(|suffix| suffix.split("fn require_non_tty_pair_stdin").next())
            .expect("persistent pair function body");
        let composition = body
            .find("PersistentRemoteComposition::production()")
            .expect("production signature composition");
        let file_read = body
            .find("load_pair_invite_from_private_file")
            .expect("private bearer file read");
        let stdin_read = body
            .find("load_pair_invite_from_reader")
            .expect("bounded stdin bearer read");
        let confirmation = body
            .find("confirm_machine_root_fingerprint")
            .expect("root fingerprint confirmation");
        let production_pair = body.find("pair_production").expect("production pair call");

        assert!(composition < file_read);
        assert!(composition < stdin_read);
        assert!(file_read < confirmation);
        assert!(stdin_read < confirmation);
        assert!(confirmation < production_pair);

        let output = body
            .split("let output = serde_json::json!")
            .nth(1)
            .and_then(|suffix| suffix.split("println!").next())
            .expect("pair success output");
        for forbidden in ["inviteUri", "inviteSecret", "wssUrl", "sealedBlob"] {
            assert!(
                !output.contains(forbidden),
                "forbidden output field {forbidden}"
            );
        }
    }

    #[test]
    fn unsafe_pair_input_preserves_typed_code_without_echoing_source() {
        let error =
            persistent_remote_pair_cli_error(agentdeck_cli::remote::pair::DurablePairError::Input(
                std::io::Error::new(std::io::ErrorKind::PermissionDenied, "secret-sentinel-path"),
            ));
        let rendered = output::error_envelope(&error).to_string();
        assert_eq!(error.exit_code(), 3);
        assert!(rendered.contains("remote.pairing.input_unsafe"));
        assert!(!rendered.contains("secret-sentinel-path"));
    }
}

#[cfg(test)]
mod persistent_remote_command_cli_tests {
    use super::*;

    const ROOT: &str = "ERERERERERERERERERERERERERERERERERERERERERE=";
    const ROUTE: &str = "IiIiIiIiIiIiIiIiIiIiIg==";
    const CONVERSATION_ID: &str = "11111111-1111-1111-1111-111111111111";
    const TURN_ID: &str = "22222222-2222-2222-2222-222222222222";
    const APPROVAL_ID: &str = "33333333-3333-3333-3333-333333333333";

    fn selector_tail() -> [&'static str; 4] {
        ["--machine-root-fingerprint", ROOT, "--machine-route", ROUTE]
    }

    #[test]
    fn planned_persistent_commands_collect_the_complete_runtime_arguments() {
        let conversations = Cli::try_parse_from(
            ["agentdeck", "remote", "conversations"]
                .into_iter()
                .chain(selector_tail()),
        )
        .expect("parse conversations");
        assert!(matches!(
            conversations.command,
            Cmd::Remote {
                op: RemoteOp::Conversations { selector }
            } if selector.parse().is_ok()
        ));

        let watch = Cli::try_parse_from(
            [
                "agentdeck",
                "remote",
                "watch",
                "--conversation-id",
                "conversation-1",
            ]
            .into_iter()
            .chain(selector_tail()),
        )
        .expect("parse watch");
        assert!(matches!(
            watch.command,
            Cmd::Remote {
                op: RemoteOp::Watch {
                    selector,
                    conversation_id,
                }
            } if selector.parse().is_ok() && conversation_id == "conversation-1"
        ));

        let prompt = Cli::try_parse_from(
            [
                "agentdeck",
                "remote",
                "prompt",
                "--conversation-id",
                "conversation-1",
                "--text",
                "continue safely",
                "--idempotency-key",
                "prompt-1",
                "--expected-configuration-revision",
                "7",
            ]
            .into_iter()
            .chain(selector_tail()),
        )
        .expect("parse prompt");
        assert!(matches!(
            prompt.command,
            Cmd::Remote {
                op: RemoteOp::Prompt {
                    selector,
                    conversation_id,
                    text,
                    idempotency_key,
                    expected_configuration_revision: 7,
                }
            } if selector.parse().is_ok()
                && conversation_id == "conversation-1"
                && text == "continue safely"
                && idempotency_key == "prompt-1"
        ));

        let approve = Cli::try_parse_from(
            [
                "agentdeck",
                "remote",
                "approve",
                "--conversation-id",
                "conversation-1",
                "--turn-id",
                "turn-1",
                "--approval-id",
                "approval-1",
                "--decision",
                "deny",
                "--request-id",
                "request-1",
                "--persist",
            ]
            .into_iter()
            .chain(selector_tail()),
        )
        .expect("parse approve");
        assert!(matches!(
            approve.command,
            Cmd::Remote {
                op: RemoteOp::Approve {
                    selector,
                    conversation_id,
                    turn_id,
                    approval_id,
                    decision: RemoteApprovalDecisionArg::Deny,
                    request_id,
                    persist: true,
                }
            } if selector.parse().is_ok()
                && conversation_id == "conversation-1"
                && turn_id == "turn-1"
                && approval_id == "approval-1"
                && request_id == "request-1"
        ));

        let retry = Cli::try_parse_from(
            [
                "agentdeck",
                "remote",
                "retry-approval",
                "--conversation-id",
                "conversation-1",
                "--approval-id",
                "approval-1",
            ]
            .into_iter()
            .chain(selector_tail()),
        )
        .expect("parse retry-approval");
        assert!(matches!(
            retry.command,
            Cmd::Remote {
                op: RemoteOp::RetryApproval {
                    selector,
                    conversation_id,
                    approval_id,
                }
            } if selector.parse().is_ok()
                && conversation_id == "conversation-1"
                && approval_id == "approval-1"
        ));

        let revoke = Cli::try_parse_from(
            ["agentdeck", "remote", "revoke-self"]
                .into_iter()
                .chain(selector_tail()),
        )
        .expect("parse revoke-self");
        assert!(matches!(
            revoke.command,
            Cmd::Remote {
                op: RemoteOp::RevokeSelf { selector }
            } if selector.parse().is_ok()
        ));
    }

    #[test]
    fn every_persistent_command_requires_both_machine_identity_components() {
        let command_tails = [
            vec!["conversations"],
            vec!["watch", "--conversation-id", "conversation-1"],
            vec![
                "prompt",
                "--conversation-id",
                "conversation-1",
                "--text",
                "hello",
                "--idempotency-key",
                "prompt-1",
                "--expected-configuration-revision",
                "1",
            ],
            vec![
                "approve",
                "--conversation-id",
                "conversation-1",
                "--turn-id",
                "turn-1",
                "--approval-id",
                "approval-1",
                "--decision",
                "approve",
                "--request-id",
                "request-1",
            ],
            vec![
                "retry-approval",
                "--conversation-id",
                "conversation-1",
                "--approval-id",
                "approval-1",
            ],
            vec!["revoke-self"],
        ];

        for tail in command_tails {
            let mut missing_root = vec!["agentdeck", "remote"];
            missing_root.extend(tail.iter().copied());
            missing_root.extend(["--machine-route", ROUTE]);
            assert!(Cli::try_parse_from(missing_root).is_err());

            let mut missing_route = vec!["agentdeck", "remote"];
            missing_route.extend(tail);
            missing_route.extend(["--machine-root-fingerprint", ROOT]);
            assert!(Cli::try_parse_from(missing_route).is_err());
        }
    }

    #[test]
    fn persistent_commands_reject_ambiguous_and_removed_selectors() {
        for forbidden in [
            vec!["--relay", "wss://relay.example/"],
            vec!["--display-name", "workstation"],
            vec!["--device-route", "device-route-secret"],
            vec!["--machine-id", "legacy-machine"],
        ] {
            let mut args = vec!["agentdeck", "remote", "conversations"];
            args.extend(selector_tail());
            args.extend(forbidden);
            assert!(Cli::try_parse_from(args).is_err());
        }
        assert!(
            Cli::try_parse_from(
                ["agentdeck", "remote", "conversations", "legacy-machine"]
                    .into_iter()
                    .chain(selector_tail())
            )
            .is_err()
        );

        for removed in ["sessions", "send", "deny", "ping"] {
            assert!(Cli::try_parse_from(["agentdeck", "remote", removed]).is_err());
        }
    }

    #[test]
    fn invalid_selector_is_rejected_without_echo_and_only_watch_stays_unsupported() {
        let cli = Cli::try_parse_from([
            "agentdeck",
            "remote",
            "conversations",
            "--machine-root-fingerprint",
            ROOT,
            "--machine-route",
            "route-secret-sentinel",
        ])
        .expect("raw selector values are validated by the redacting composite parser");
        let Cmd::Remote { op } = cli.command else {
            panic!("expected remote command");
        };
        let error = match remote_pre_dispatch(&op) {
            Ok(_) => panic!("invalid selector must fail before dispatch"),
            Err(error) => error,
        };
        assert!(!error.message().contains("route-secret-sentinel"));
        assert!(
            !output::error_envelope(&error)
                .to_string()
                .contains("route-secret-sentinel")
        );

        let valid = Cli::try_parse_from(
            ["agentdeck", "remote", "conversations"]
                .into_iter()
                .chain(selector_tail()),
        )
        .expect("valid persistent command");
        let Cmd::Remote { op } = valid.command else {
            panic!("expected remote command");
        };
        assert!(
            remote_pre_dispatch(&op).expect("valid selector").is_none(),
            "conversations must enter the production Catalog service"
        );

        let watch = Cli::try_parse_from(
            [
                "agentdeck",
                "remote",
                "watch",
                "--conversation-id",
                CONVERSATION_ID,
            ]
            .into_iter()
            .chain(selector_tail()),
        )
        .expect("valid watch command");
        let Cmd::Remote { op } = watch.command else {
            panic!("expected remote watch")
        };
        assert!(matches!(
            remote_pre_dispatch(&op).expect("valid watch selector"),
            Some(remote_cli::RemoteOpArg::PersistentUnsupported)
        ));

        let prompt = Cli::try_parse_from(
            [
                "agentdeck",
                "remote",
                "prompt",
                "--conversation-id",
                "conversation-1",
                "--text",
                "continue safely",
                "--idempotency-key",
                "prompt-1",
                "--expected-configuration-revision",
                "7",
            ]
            .into_iter()
            .chain(selector_tail()),
        )
        .expect("valid prompt command");
        let Cmd::Remote { op } = prompt.command else {
            panic!("expected remote prompt")
        };
        assert!(
            remote_pre_dispatch(&op)
                .expect("valid prompt selector")
                .is_none(),
            "mutation commands must enter the production mutation service"
        );

        let invalid_prompt = Cli::try_parse_from([
            "agentdeck",
            "remote",
            "prompt",
            "--conversation-id",
            "conversation-1",
            "--text",
            "continue safely",
            "--idempotency-key",
            "prompt-1",
            "--expected-configuration-revision",
            "7",
            "--machine-root-fingerprint",
            ROOT,
            "--machine-route",
            "route-secret-sentinel",
        ])
        .expect("raw selector is parsed before redacting validation");
        let Cmd::Remote { op } = invalid_prompt.command else {
            panic!("expected remote prompt")
        };
        let error = match remote_pre_dispatch(&op) {
            Ok(_) => panic!("invalid selector must pre-reject"),
            Err(error) => error,
        };
        assert!(!error.message().contains("route-secret-sentinel"));
    }

    #[test]
    fn mutation_plan_validates_fields_before_production_composition() {
        let empty_prompt = Cli::try_parse_from(
            [
                "agentdeck",
                "remote",
                "prompt",
                "--conversation-id",
                CONVERSATION_ID,
                "--text",
                "",
                "--idempotency-key",
                "prompt-1",
                "--expected-configuration-revision",
                "7",
            ]
            .into_iter()
            .chain(selector_tail()),
        )
        .expect("clap accepts a value for semantic validation");
        let Cmd::Remote { op } = empty_prompt.command else {
            panic!("expected remote prompt")
        };
        assert!(persistent_remote_mutation_plan(&op).is_err());

        let valid = Cli::try_parse_from(
            [
                "agentdeck",
                "remote",
                "approve",
                "--conversation-id",
                CONVERSATION_ID,
                "--turn-id",
                TURN_ID,
                "--approval-id",
                APPROVAL_ID,
                "--decision",
                "approve",
                "--request-id",
                "request-1",
                "--persist",
            ]
            .into_iter()
            .chain(selector_tail()),
        )
        .expect("valid approval command");
        let Cmd::Remote { op } = valid.command else {
            panic!("expected remote approval")
        };
        let Some((operation, selector, mutation)) =
            persistent_remote_mutation_plan(&op).expect("valid mutation plan")
        else {
            panic!("approval must produce a mutation plan")
        };
        assert_eq!(operation, "approve");
        assert_eq!(
            selector.identity(),
            super::PersistentMachineSelectorArgs {
                machine_root_fingerprint: ROOT.to_owned(),
                machine_route: ROUTE.to_owned(),
            }
            .parse()
            .expect("selector")
            .identity()
        );
        assert!(matches!(
            mutation,
            agentdeck_cli::remote::mutations::PersistentRemoteMutation::ResolveApproval {
                decision: ActionDecision {
                    decision: ActionDecisionKind::Approve,
                    persist: true,
                    ..
                },
                ..
            }
        ));
    }

    #[test]
    fn mutation_plan_rejects_noncanonical_runtime_ids_and_persistent_deny() {
        for invalid in [
            "conversation-1",
            "00000000-0000-0000-0000-000000000000",
            "AAAAAAAA-AAAA-AAAA-AAAA-AAAAAAAAAAAA",
        ] {
            let command = Cli::try_parse_from(
                [
                    "agentdeck",
                    "remote",
                    "prompt",
                    "--conversation-id",
                    invalid,
                    "--text",
                    "continue safely",
                    "--idempotency-key",
                    "prompt-1",
                    "--expected-configuration-revision",
                    "0",
                ]
                .into_iter()
                .chain(selector_tail()),
            )
            .expect("clap leaves canonical Runtime ID validation to the plan");
            let Cmd::Remote { op } = command.command else {
                panic!("expected remote prompt")
            };
            let error = persistent_remote_mutation_plan(&op)
                .expect_err("noncanonical Runtime ID must fail before production composition");
            assert_eq!(error.exit_code(), 2);
            assert!(!error.message().contains(invalid));
        }

        let persistent_deny = Cli::try_parse_from(
            [
                "agentdeck",
                "remote",
                "approve",
                "--conversation-id",
                CONVERSATION_ID,
                "--turn-id",
                TURN_ID,
                "--approval-id",
                APPROVAL_ID,
                "--decision",
                "deny",
                "--request-id",
                "request-1",
                "--persist",
            ]
            .into_iter()
            .chain(selector_tail()),
        )
        .expect("clap leaves decision invariants to the plan");
        let Cmd::Remote { op } = persistent_deny.command else {
            panic!("expected remote approval")
        };
        let error = persistent_remote_mutation_plan(&op)
            .expect_err("persistent deny has no canonical adapter meaning");
        assert_eq!(error.exit_code(), 2);

        let revision_zero = Cli::try_parse_from(
            [
                "agentdeck",
                "remote",
                "prompt",
                "--conversation-id",
                CONVERSATION_ID,
                "--text",
                "continue safely",
                "--idempotency-key",
                "prompt-1",
                "--expected-configuration-revision",
                "0",
            ]
            .into_iter()
            .chain(selector_tail()),
        )
        .expect("revision zero is a valid exact configuration revision");
        let Cmd::Remote { op } = revision_zero.command else {
            panic!("expected remote prompt")
        };
        assert!(
            persistent_remote_mutation_plan(&op)
                .expect("revision zero is not a sentinel")
                .is_some()
        );
    }

    #[test]
    fn mutation_output_keeps_transport_acceptance_distinct_from_daemon_receipt() {
        let output = persistent_remote_mutation_output(
            "prompt",
            agentdeck_cli::remote::mutations::PersistentRemoteMutationOutcome::Prompt {
                route_accepted: false,
                receipt: agentdeck_protocol::runtime::CommandReceipt::Accepted {
                    command_id: agentdeck_protocol::runtime::identity::CommandId::new("command-1"),
                    queue_position: 2,
                    configuration_revision: 7,
                },
            },
        )
        .expect("serializable terminal receipt");
        assert_eq!(output["operation"], "prompt");
        assert_eq!(output["transport"]["routeAccepted"], false);
        assert!(output.get("receipt").is_some());
        assert!(output.get("routeAccepted").is_none());
    }

    #[test]
    fn failed_command_receipt_is_a_typed_nonzero_cli_result() {
        let error = persistent_remote_mutation_output(
            "prompt",
            agentdeck_cli::remote::mutations::PersistentRemoteMutationOutcome::Prompt {
                route_accepted: true,
                receipt: CommandReceipt::Failed {
                    failure: agentdeck_protocol::runtime::RuntimeFailure::new(
                        "daemon.command.queue_full",
                        "runtime conversation queue is full",
                    ),
                },
            },
        )
        .expect_err("authenticated command failure cannot be shell success");
        assert_eq!(error.exit_code(), 5);
        assert_eq!(
            output::error_envelope(&error)["error"]["code"],
            "daemon.command.queue_full"
        );
    }

    #[test]
    fn remote_reply_integrity_errors_use_the_protocol_exit_class() {
        let error = persistent_remote_mutation_cli_error(
            agentdeck_cli::remote::mutations::PersistentRemoteMutationError::Runtime(
                agentdeck_cli::remote::runtime::RemoteRuntimeError::InvalidReply(
                    "fixture reply mismatch",
                ),
            ),
        );
        assert_eq!(error.exit_code(), 3);
        assert_eq!(
            output::error_envelope(&error)["error"]["code"],
            "remote.runtime.reply_invalid"
        );
    }

    #[test]
    fn production_composition_and_entropy_precede_the_mutation_service() {
        let source = include_str!("main.rs");
        let branch = source
            .split("if let Some((operation, selector, mutation))")
            .nth(1)
            .and_then(|suffix| suffix.split("let plan = match op").next())
            .expect("persistent mutation dispatch branch");
        let composition = branch
            .find("PersistentRemoteComposition::production()")
            .expect("production composition");
        let entropy = branch
            .find("production_remote_mutation_rng()")
            .expect("production entropy");
        let service = branch
            .find("execute_persistent_remote_mutation")
            .expect("mutation service");
        assert!(composition < entropy && entropy < service);
        for forbidden in [
            concat!("injected", "_for_test"),
            concat!("Memory", "RemoteKeyStore"),
            concat!("PairedMachineStore", "::new"),
        ] {
            assert!(
                !branch.contains(forbidden),
                "production CLI must not expose {forbidden}"
            );
        }
    }

    #[test]
    fn conversations_composition_entropy_and_output_follow_the_production_service() {
        let source = include_str!("main.rs");
        let branch = source
            .split("if let RemoteOp::Conversations { selector } = op")
            .nth(1)
            .and_then(|suffix| {
                suffix
                    .split("if let Some((operation, selector, mutation))")
                    .next()
            })
            .expect("persistent conversations dispatch branch");
        let selector = branch
            .find("selector.parse()")
            .expect("selector validation");
        let composition = branch
            .find("PersistentRemoteComposition::production()")
            .expect("production composition");
        let entropy = branch
            .find("production_remote_mutation_rng()")
            .expect("production entropy");
        let service = branch
            .find("list_persistent_remote_conversations")
            .expect("Catalog pagination service");
        let output = branch
            .find("persistent_remote_conversations_output")
            .expect("typed conversations output");
        assert!(selector < composition && composition < entropy && entropy < service);
        assert!(service < output);
        for forbidden in [
            concat!("injected", "_for_test"),
            "MemoryRemoteKeyStore",
            "--relay",
        ] {
            assert!(!branch.contains(forbidden));
        }
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
