//! agentdeckd — AgentDeck daemon (v2 protocol).
//!
//! P3.1 起，真正的 daemon 入口先建立唯一 namespace、进程锁和 StorageKEK，
//! 再进入 selfcheck 或 compatibility stdio loop。stable helper 只接受构建时注入
//! 的 daemon-only Keychain access group；开发实例必须显式使用
//! `--ephemeral --no-remote`。

use std::ffi::{OsStr, OsString};
use std::fmt;
use std::path::PathBuf;
use std::process::ExitCode;
use std::sync::Arc;

use agentdeck_protocol::runtime::RuntimeFailure;
use agentdeckd::config::{
    DaemonConfig, DaemonProfile, DaemonStartupOptions, LocalIngressMode,
    compiled_stable_keychain_access_group,
};
use agentdeckd::diag;
use agentdeckd::local::listener::{BoundLocalListener, LocalListenerError};
use agentdeckd::local::stdio_compat::{self, StdioCompatError};
use agentdeckd::record;
use agentdeckd::remote::bootstrap::{RemoteBootstrapOutcome, reconcile_machine_identity};
use agentdeckd::runtime::singleton::SingletonGuard;
use agentdeckd::runtime::store::{RuntimeStoreConfig, RuntimeStoreError, RuntimeStoreHandle};
use agentdeckd::runtime::{AgentRouter, RuntimeCore};
use agentdeckd::security::{
    KeyStore, StorageKek, key_store_for_config, load_or_create_storage_kek,
};

#[derive(Debug, Default)]
struct CliArgs {
    profile: Option<DaemonProfile>,
    /// 只保留给 diagnostics-report 的旧数据目录读取；不能改变 daemon ownership。
    data_dir: Option<PathBuf>,
    ephemeral: bool,
    no_remote: bool,
    stdio_compat: bool,
    selfcheck: bool,
    diagnostics_report: bool,
    exec_gate: bool,
    production_execution_probe: bool,
    production_execution_cancel_probe: bool,
    show_version: bool,
    show_help: bool,
}

#[derive(Debug)]
enum CliError {
    MissingValue { flag: &'static str },
    InvalidProfile { value: OsString },
    UnknownArgument { value: OsString },
    DataDirForbidden,
    ConflictingOneShotModes,
    DiagnosticsStartupFlagsForbidden,
    ExecGateModeConflict,
}

#[derive(Debug)]
struct MainLoopFailure {
    code: String,
    message: String,
}

impl MainLoopFailure {
    fn store(error: RuntimeStoreError) -> Self {
        Self {
            code: error.code().to_owned(),
            message: "runtime durable store bootstrap failed".to_owned(),
        }
    }

    fn runtime(error: RuntimeFailure) -> Self {
        Self {
            code: error.code,
            message: error.message,
        }
    }

    fn io(error: std::io::Error) -> Self {
        Self {
            code: "daemon.runtime.main_loop_failed".to_owned(),
            message: error.to_string(),
        }
    }

    fn local(error: LocalListenerError) -> Self {
        Self {
            code: error.code().to_owned(),
            message: error.to_string(),
        }
    }

    fn stdio(error: StdioCompatError) -> Self {
        Self {
            code: error.code().to_owned(),
            message: error.to_string(),
        }
    }
}

impl fmt::Display for MainLoopFailure {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(&self.message)
    }
}

impl CliError {
    const fn code(&self) -> &'static str {
        match self {
            Self::MissingValue { .. } => "daemon.cli.missing_value",
            Self::InvalidProfile { .. } => "daemon.cli.invalid_profile",
            Self::UnknownArgument { .. } => "daemon.cli.unknown_argument",
            Self::DataDirForbidden => "daemon.cli.data_dir_forbidden",
            Self::ConflictingOneShotModes => "daemon.cli.conflicting_one_shot_modes",
            Self::DiagnosticsStartupFlagsForbidden => {
                "daemon.cli.diagnostics_startup_flags_forbidden"
            }
            Self::ExecGateModeConflict => "daemon.cli.exec_gate_mode_conflict",
        }
    }
}

impl fmt::Display for CliError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::MissingValue { flag } => write!(formatter, "{flag} requires a value"),
            Self::InvalidProfile { value } => write!(
                formatter,
                "invalid --profile value {:?}; expected stable or dev",
                value.to_string_lossy()
            ),
            Self::UnknownArgument { value } => {
                write!(formatter, "unknown argument: {:?}", value.to_string_lossy())
            }
            Self::DataDirForbidden => formatter
                .write_str("--data-dir is diagnostics-only and cannot override a daemon namespace"),
            Self::ConflictingOneShotModes => {
                formatter.write_str("one-shot modes are mutually exclusive")
            }
            Self::DiagnosticsStartupFlagsForbidden => formatter.write_str(
                "--ephemeral/--no-remote are daemon startup flags, not diagnostics options",
            ),
            Self::ExecGateModeConflict => {
                formatter.write_str("--exec-gate is an internal exclusive submode")
            }
        }
    }
}

fn parse_args<I>(args: I) -> Result<CliArgs, CliError>
where
    I: IntoIterator<Item = OsString>,
{
    let mut out = CliArgs::default();
    let mut it = args.into_iter();
    let _ = it.next();
    while let Some(argument) = it.next() {
        if argument == OsStr::new("--profile") {
            let value = it
                .next()
                .ok_or(CliError::MissingValue { flag: "--profile" })?;
            out.profile = Some(match value.as_os_str() {
                value if value == OsStr::new("stable") => DaemonProfile::Stable,
                value if value == OsStr::new("dev") => DaemonProfile::Dev,
                _ => return Err(CliError::InvalidProfile { value }),
            });
        } else if argument == OsStr::new("--data-dir") {
            out.data_dir = Some(PathBuf::from(
                it.next()
                    .ok_or(CliError::MissingValue { flag: "--data-dir" })?,
            ));
        } else if argument == OsStr::new("--ephemeral") {
            out.ephemeral = true;
        } else if argument == OsStr::new("--no-remote") {
            out.no_remote = true;
        } else if argument == OsStr::new("--stdio-compat") {
            out.stdio_compat = true;
        } else if argument == OsStr::new("--selfcheck") {
            out.selfcheck = true;
        } else if argument == OsStr::new("--diagnostics-report") {
            out.diagnostics_report = true;
        } else if argument == OsStr::new("--exec-gate") {
            out.exec_gate = true;
        } else if cfg!(debug_assertions) && argument == OsStr::new("--production-execution-probe") {
            out.production_execution_probe = true;
        } else if cfg!(debug_assertions)
            && argument == OsStr::new("--production-execution-cancel-probe")
        {
            out.production_execution_cancel_probe = true;
        } else if argument == OsStr::new("--version") || argument == OsStr::new("-V") {
            out.show_version = true;
        } else if argument == OsStr::new("--help") || argument == OsStr::new("-h") {
            out.show_help = true;
        } else {
            return Err(CliError::UnknownArgument { value: argument });
        }
    }
    Ok(out)
}

fn validate_cli_args(args: &CliArgs) -> Result<(), CliError> {
    if args.exec_gate
        && (args.profile.is_some()
            || args.data_dir.is_some()
            || args.ephemeral
            || args.no_remote
            || args.stdio_compat
            || args.selfcheck
            || args.diagnostics_report
            || args.production_execution_probe
            || args.production_execution_cancel_probe
            || args.show_version
            || args.show_help)
    {
        return Err(CliError::ExecGateModeConflict);
    }
    if args.selfcheck && args.diagnostics_report {
        return Err(CliError::ConflictingOneShotModes);
    }
    if (args.production_execution_probe || args.production_execution_cancel_probe)
        && (args.profile.is_some()
            || args.data_dir.is_some()
            || args.ephemeral
            || args.no_remote
            || args.stdio_compat
            || args.selfcheck
            || args.diagnostics_report
            || args.exec_gate
            || (args.production_execution_probe && args.production_execution_cancel_probe)
            || args.show_version
            || args.show_help)
    {
        return Err(CliError::ConflictingOneShotModes);
    }
    if args.data_dir.is_some() && !args.diagnostics_report {
        return Err(CliError::DataDirForbidden);
    }
    if args.diagnostics_report && (args.ephemeral || args.no_remote || args.stdio_compat) {
        return Err(CliError::DiagnosticsStartupFlagsForbidden);
    }
    Ok(())
}

fn apply_legacy_diagnostics_env(args: &CliArgs) {
    if let Some(dir) = &args.data_dir {
        // SAFETY: diagnostics-report 是启动时的单线程 one-shot，尚未创建 runtime。
        unsafe { std::env::set_var("AGENTDECK_DATA_DIR", dir) }
    }
    if let Some(profile) = args.profile {
        let value = match profile {
            DaemonProfile::Stable => "stable",
            DaemonProfile::Dev => "dev",
        };
        // SAFETY: 同上；该 legacy override 不会进入 daemon startup 路径。
        unsafe { std::env::set_var("AGENTDECK_PROFILE", value) }
    }
}

fn print_typed_error(code: &str, error: impl fmt::Display) {
    eprintln!("agentdeckd: [{code}] {error}");
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
           --profile <stable|dev>    Select the strict startup profile.\n\
           --ephemeral               Use a fresh isolated test namespace.\n\
           --no-remote               Required together with --ephemeral.\n\
           --stdio-compat             Admin/read stdio; requires --ephemeral --no-remote.\n\
           --data-dir <path>         Legacy diagnostics-report override only.\n\
           --selfcheck               Bootstrap daemon security plumbing, then exit.\n\
           --diagnostics-report      Emit diagnostic.log summary without starting daemon.\n\
           --version, -V             Print version and exit.\n\
           --help, -h                Show this help and exit.\n\
         \n\
         The stable mode requires a release-signed helper with the compiled daemon-only\n\
         Keychain access group. Development/compatibility processes must pass\n\
         --ephemeral --no-remote explicitly; stdio additionally requires --stdio-compat.\n"
    );
}

fn run_selfcheck(config: &DaemonConfig) -> ExitCode {
    let app_dir = match record::app_data_dir() {
        Some(dir) if dir == config.paths().data_dir => dir,
        Some(dir) => {
            eprintln!(
                "selfcheck: [daemon.selfcheck.namespace_mismatch] configured {} but resolved {}",
                config.paths().data_dir.display(),
                dir.display()
            );
            return ExitCode::from(1);
        }
        None => {
            eprintln!("selfcheck: [daemon.selfcheck.namespace_unavailable] no data directory");
            return ExitCode::from(1);
        }
    };
    if !app_dir.is_dir() {
        eprintln!(
            "selfcheck: [daemon.selfcheck.namespace_unavailable] {} is not a directory",
            app_dir.display()
        );
        return ExitCode::from(1);
    }
    let diag_path = match diag::diagnostic_log_path() {
        Some(path) => path,
        None => {
            eprintln!("selfcheck: [daemon.selfcheck.diagnostics_unavailable] no log path");
            return ExitCode::from(1);
        }
    };

    let run_id = format!("selfcheck-{}", std::process::id());
    if let Err(error) = record::try_append(&run_id, r#"{"selfcheck":true}"#) {
        eprintln!("selfcheck: [daemon.selfcheck.record_failed] {error}");
        return ExitCode::from(1);
    }
    diag::log("selfcheck", "agentdeckd self-check ok");

    println!("OK");
    println!(
        "{}",
        serde_json::json!({
            "protocolVersion": agentdeck_protocol::PROTOCOL_VERSION,
            "dataDir": app_dir,
            "diagLog": diag_path,
            "remoteEnabled": config.remote_enabled(),
        })
    );
    ExitCode::SUCCESS
}

fn run_diagnostics_report() -> ExitCode {
    let path = match diag::diagnostic_log_path() {
        Some(path) => path,
        None => {
            eprintln!("diagnostics-report: [daemon.diagnostics.path_unavailable] no log path");
            return ExitCode::from(1);
        }
    };
    let text = match std::fs::read_to_string(&path) {
        Ok(text) => text,
        Err(error) => {
            println!(
                "{}",
                serde_json::json!({
                    "path": path,
                    "lineCount": 0,
                    "notice": format!("could not read {}: {error}", path.display()),
                })
            );
            return ExitCode::SUCCESS;
        }
    };
    let lines: Vec<&str> = text
        .lines()
        .filter(|line| !line.trim().is_empty())
        .collect();
    let mut parsed = 0_u64;
    let mut by_level: std::collections::BTreeMap<String, u64> = Default::default();
    let mut by_event: std::collections::BTreeMap<String, u64> = Default::default();
    let mut last_lines: Vec<serde_json::Value> = Vec::new();
    for line in &lines {
        if let Ok(value) = serde_json::from_str::<serde_json::Value>(line) {
            parsed += 1;
            if let Some(level) = value.get("level").and_then(|entry| entry.as_str()) {
                *by_level.entry(level.to_owned()).or_default() += 1;
            }
            if let Some(event) = value.get("event").and_then(|entry| entry.as_str()) {
                *by_event.entry(event.to_owned()).or_default() += 1;
            }
            last_lines.push(value);
        }
    }
    let tail_start = last_lines.len().saturating_sub(20);
    let tail: Vec<_> = last_lines.into_iter().skip(tail_start).collect();
    println!(
        "{}",
        serde_json::json!({
            "path": path,
            "lineCount": lines.len(),
            "parsedCount": parsed,
            "byLevel": by_level,
            "byEvent": by_event,
            "tail": tail,
        })
    );
    ExitCode::SUCCESS
}

#[cfg(debug_assertions)]
fn run_production_execution_probe(cancel_before_release: bool) -> ExitCode {
    let runtime = match tokio::runtime::Builder::new_multi_thread()
        .enable_all()
        .build()
    {
        Ok(runtime) => runtime,
        Err(error) => {
            print_typed_error("daemon.debug.production_probe_runtime_failed", error);
            return ExitCode::from(1);
        }
    };
    let outcome = if cancel_before_release {
        runtime.block_on(
            agentdeckd::runtime::production_execution_probe::run_production_execution_cancel_probe(
            ),
        )
    } else {
        runtime.block_on(
            agentdeckd::runtime::production_execution_probe::run_production_execution_probe(),
        )
    };
    match outcome {
        Ok(evidence) => match serde_json::to_string(&evidence) {
            Ok(encoded) => {
                println!("{encoded}");
                ExitCode::SUCCESS
            }
            Err(error) => {
                print_typed_error("daemon.debug.production_probe_encode_failed", error);
                ExitCode::from(1)
            }
        },
        Err(error) => {
            print_typed_error("daemon.debug.production_probe_failed", error);
            ExitCode::from(1)
        }
    }
}

async fn wait_for_shutdown_signal(
    upgrade_exit: &mut tokio::sync::mpsc::UnboundedReceiver<()>,
) -> Result<(), LocalListenerError> {
    #[cfg(unix)]
    {
        let mut terminate =
            tokio::signal::unix::signal(tokio::signal::unix::SignalKind::terminate())
                .map_err(LocalListenerError::Signal)?;
        tokio::select! {
            result = tokio::signal::ctrl_c() => result.map_err(LocalListenerError::Signal),
            _ = terminate.recv() => Ok(()),
            _ = upgrade_exit.recv() => Ok(()),
        }
    }
    #[cfg(not(unix))]
    {
        tokio::select! {
            result = tokio::signal::ctrl_c() => result.map_err(LocalListenerError::Signal),
            _ = upgrade_exit.recv() => Ok(()),
        }
    }
}

fn run_main_loop(
    config: &DaemonConfig,
    singleton: &SingletonGuard,
    key_store: &dyn KeyStore,
    storage_kek: StorageKek,
) -> Result<(), MainLoopFailure> {
    let runtime = tokio::runtime::Builder::new_multi_thread()
        .enable_all()
        .build()
        .map_err(MainLoopFailure::io)?;
    let runtime_db = config.paths().runtime_db.clone();

    runtime.block_on(async move {
        diag::log("daemon_start", "agentdeckd main loop starting");
        let store = RuntimeStoreHandle::open(RuntimeStoreConfig::new(runtime_db), storage_kek)
            .await
            .map_err(MainLoopFailure::store)?;
        let remote_identity =
            match reconcile_machine_identity(config.remote_enabled(), &store, key_store).await {
                Ok(outcome) => outcome,
                Err(error) => {
                    let failure = MainLoopFailure::store(error);
                    let shutdown = store.shutdown().await;
                    diag::log(
                        "daemon_stop",
                        &format!(
                            "agentdeckd machine identity bootstrap failed: \
                         code={} storeShutdown={shutdown:?}",
                            failure.code
                        ),
                    );
                    return Err(failure);
                }
            };
        match &remote_identity {
            RemoteBootstrapOutcome::Disabled => {
                diag::log("remote_identity", "status=disabled");
            }
            RemoteBootstrapOutcome::Active(_) => {
                diag::log("remote_identity", "status=active");
            }
            RemoteBootstrapOutcome::Blocked(block) => {
                diag::log(
                    "remote_identity",
                    &format!("status=blocked code={}", block.code()),
                );
            }
        }
        let router = Arc::new(AgentRouter::with_runtime_store(store.clone()));
        let (upgrade_exit, mut upgrade_exit_receiver) = tokio::sync::mpsc::unbounded_channel();
        let core =
            match RuntimeCore::new_production(store.clone(), router.clone()).and_then(|core| {
                core.with_versioned_daemon_upgrade(
                    config.paths().data_dir.join("bin"),
                    upgrade_exit,
                )
            }) {
                Ok(core) => Arc::new(core),
                Err(error) => {
                    drop(router);
                    let shutdown = store.shutdown().await;
                    diag::log(
                        "daemon_stop",
                        &format!(
                            "agentdeckd bootstrap failed before RuntimeCore ownership: \
                         error={error:?} storeShutdown={shutdown:?}"
                        ),
                    );
                    return Err(MainLoopFailure::runtime(error));
                }
            };
        drop(router);
        drop(store);

        let run_result = async {
            let (report, recovery_ready_permit) = core
                .recover_for_startup()
                .await
                .map_err(MainLoopFailure::runtime)?;
            diag::log(
                "runtime_recovery_ready",
                &format!(
                    "conversations={} acceptedCommands={}",
                    report.conversations, report.accepted_commands
                ),
            );

            match config.local_ingress_mode() {
                LocalIngressMode::Uds => {
                    let mut listener = BoundLocalListener::bind_after_recovery(
                        recovery_ready_permit,
                        config,
                        singleton,
                        core.clone(),
                    )
                    .await
                    .map_err(MainLoopFailure::local)?;
                    let socket = listener.local_ready_permit().socket_path().to_path_buf();
                    // P4 将按值消费该 capability 启动唯一 RemoteTransport；P3.8 先把
                    // stable-only mint 边界接入真实 bootstrap，并保持到 local stop 后。
                    let remote_start_permit = listener.take_remote_start_permit();
                    let armed_remote = match (remote_identity, remote_start_permit) {
                        (RemoteBootstrapOutcome::Active(identity), Some(permit)) => {
                            Some(identity.arm(permit))
                        }
                        (RemoteBootstrapOutcome::Active(identity), None) => {
                            drop(identity);
                            diag::log(
                                "remote_identity",
                                "status=blocked code=daemon.remote.identity.start_permit_missing",
                            );
                            None
                        }
                        (RemoteBootstrapOutcome::Disabled, _permit) => None,
                        (RemoteBootstrapOutcome::Blocked(block), _permit) => {
                            diag::log(
                                "remote_identity",
                                &format!("status=blocked code={}", block.code()),
                            );
                            None
                        }
                    };
                    diag::log(
                        "runtime_local_ready",
                        &format!(
                            "socket={} remotePermit={}",
                            socket.display(),
                            armed_remote.is_some()
                        ),
                    );
                    let serve_result = listener
                        .serve_until(wait_for_shutdown_signal(&mut upgrade_exit_receiver))
                        .await
                        .map_err(MainLoopFailure::local);
                    // P4.1 明确证明 active key owner 覆盖 RemoteStartPermit 与完整
                    // local serve 生命周期；P4.2 将在同一 owner 内加入 transport。
                    drop(armed_remote);
                    serve_result
                }
                LocalIngressMode::StdioCompat => {
                    drop(remote_identity);
                    let compatibility = stdio_compat::run_after_recovery(
                        config,
                        recovery_ready_permit,
                        &core,
                        tokio::io::stdin(),
                        tokio::io::stdout(),
                    );
                    tokio::select! {
                        result = compatibility => result.map_err(MainLoopFailure::stdio),
                        _ = upgrade_exit_receiver.recv() => Ok(()),
                    }
                }
            }
        }
        .await;
        let shutdown = core.shutdown().await;
        diag::log(
            "daemon_stop",
            &format!("agentdeckd main loop exited: run={run_result:?} shutdown={shutdown:?}"),
        );
        run_result?;
        shutdown.map_err(MainLoopFailure::runtime)
    })
}

fn main() -> ExitCode {
    let args = match parse_args(std::env::args_os()) {
        Ok(args) => args,
        Err(error) => {
            print_typed_error(error.code(), &error);
            return ExitCode::from(2);
        }
    };

    if args.exec_gate {
        if let Err(error) = validate_cli_args(&args) {
            print_typed_error(error.code(), &error);
            return ExitCode::from(2);
        }
        return match agentdeckd::exec_gate::run_from_private_fd() {
            Ok(()) => ExitCode::SUCCESS,
            Err(error) => {
                print_typed_error(error.code(), error);
                ExitCode::from(1)
            }
        };
    }

    #[cfg(debug_assertions)]
    if args.production_execution_probe || args.production_execution_cancel_probe {
        if let Err(error) = validate_cli_args(&args) {
            print_typed_error(error.code(), &error);
            return ExitCode::from(2);
        }
        return run_production_execution_probe(args.production_execution_cancel_probe);
    }

    if args.show_help {
        print_help();
        return ExitCode::SUCCESS;
    }
    if args.show_version {
        print_version();
        return ExitCode::SUCCESS;
    }
    if let Err(error) = validate_cli_args(&args) {
        print_typed_error(error.code(), &error);
        return ExitCode::from(2);
    }
    if args.diagnostics_report {
        apply_legacy_diagnostics_env(&args);
        return run_diagnostics_report();
    }

    // 固定启动顺序：config → private namespace/singleton → keystore → StorageKEK
    // → record namespace → selfcheck/main loop。
    let config = match DaemonConfig::resolve(DaemonStartupOptions {
        ephemeral: args.ephemeral,
        no_remote: args.no_remote,
        stdio_compat: args.stdio_compat,
        profile: args.profile,
        stable_keychain_access_group: compiled_stable_keychain_access_group(),
    }) {
        Ok(config) => config,
        Err(error) => {
            print_typed_error(error.code(), &error);
            return ExitCode::from(2);
        }
    };
    let singleton_guard = match SingletonGuard::acquire(config.paths()) {
        Ok(guard) => guard,
        Err(error) => {
            print_typed_error(error.code(), &error);
            return ExitCode::from(1);
        }
    };
    let key_store = match key_store_for_config(&config) {
        Ok(store) => store,
        Err(error) => {
            print_typed_error(error.code(), &error);
            return ExitCode::from(1);
        }
    };
    let storage_kek = match load_or_create_storage_kek(&*key_store, &config.paths().runtime_db) {
        Ok(key) => key,
        Err(error) => {
            print_typed_error(error.code(), &error);
            return ExitCode::from(1);
        }
    };
    if let Err(error) = record::configure_app_data_dir(config.paths().data_dir.clone()) {
        print_typed_error(error.code(), &error);
        return ExitCode::from(1);
    }

    let exit = if args.selfcheck {
        drop(storage_kek);
        run_selfcheck(&config)
    } else {
        match run_main_loop(&config, &singleton_guard, &*key_store, storage_kek) {
            Ok(()) => ExitCode::SUCCESS,
            Err(error) => {
                print_typed_error(&error.code, &error);
                ExitCode::from(1)
            }
        }
    };

    // lock fd 与 Keychain backend 覆盖完整 runtime 生命周期；StorageKEK 已被
    // RuntimeStore 消费并在派生完成后清零，selfcheck 分支则在执行前显式 drop。
    drop((key_store, singleton_guard));
    exit
}

#[cfg(test)]
mod tests {
    use super::*;

    fn os_args(values: &[&str]) -> Vec<OsString> {
        values.iter().map(OsString::from).collect()
    }

    #[test]
    fn parse_args_handles_strict_profiles_and_startup_flags() {
        let args = parse_args(os_args(&[
            "agentdeckd",
            "--profile",
            "dev",
            "--ephemeral",
            "--no-remote",
            "--stdio-compat",
            "--selfcheck",
        ]))
        .expect("parse args");
        assert_eq!(args.profile, Some(DaemonProfile::Dev));
        assert!(args.ephemeral);
        assert!(args.no_remote);
        assert!(args.stdio_compat);
        assert!(args.selfcheck);
    }

    #[test]
    fn parse_args_rejects_invalid_profile_and_unknown_flag_with_codes() {
        let error = parse_args(os_args(&["agentdeckd", "--profile", "preview"]))
            .expect_err("invalid profile");
        assert_eq!(error.code(), "daemon.cli.invalid_profile");

        let error = parse_args(os_args(&["agentdeckd", "--not-a-flag"])).expect_err("unknown flag");
        assert_eq!(error.code(), "daemon.cli.unknown_argument");

        let error = parse_args(os_args(&["agentdeckd", "--socket", "/tmp/injected.sock"]))
            .expect_err("production socket override must stay unknown");
        assert_eq!(error.code(), "daemon.cli.unknown_argument");
    }

    #[test]
    fn data_dir_is_only_valid_for_diagnostics() {
        let selfcheck = parse_args(os_args(&[
            "agentdeckd",
            "--selfcheck",
            "--data-dir",
            "/tmp/xx",
        ]))
        .expect("parse selfcheck");
        assert!(matches!(
            validate_cli_args(&selfcheck),
            Err(CliError::DataDirForbidden)
        ));

        let diagnostics = parse_args(os_args(&[
            "agentdeckd",
            "--diagnostics-report",
            "--data-dir",
            "/tmp/xx",
        ]))
        .expect("parse diagnostics");
        assert!(validate_cli_args(&diagnostics).is_ok());
    }

    #[cfg(unix)]
    #[test]
    fn args_os_preserves_non_utf8_diagnostics_path() {
        use std::os::unix::ffi::{OsStrExt, OsStringExt};

        let path = OsString::from_vec(b"/tmp/agentdeck-\xff".to_vec());
        let args = parse_args(vec![
            OsString::from("agentdeckd"),
            OsString::from("--diagnostics-report"),
            OsString::from("--data-dir"),
            path.clone(),
        ])
        .expect("parse non-UTF-8 path");
        assert_eq!(
            args.data_dir.expect("data dir").as_os_str().as_bytes(),
            path.as_os_str().as_bytes()
        );
    }
}
