//! P3.7 production spawn ownership source guard。
//!
//! 威胁场景：后续维护若让 typed prepare/driver 重新调用 legacy `start_inner` 或
//! `Command::spawn`，vendor 就会在 durable Fence/release 前越过唯一副作用边界。

#[test]
fn typed_adapter_prepare_cannot_call_legacy_spawn_or_preflight() {
    for (name, source) in [
        ("Codex", include_str!("../src/codex/adapter.rs") as &str),
        (
            "Claude Code",
            include_str!("../src/claude_code/adapter.rs") as &str,
        ),
    ] {
        let body = between(
            source,
            "async fn prepare_adapter_turn(",
            "async fn start_session(",
        );
        assert!(
            body.contains("resolve_trusted_program"),
            "{name} must resolve the vendor only from the exec-gate trusted path"
        );
        assert!(
            !body.contains("which::which"),
            "{name} must not resolve the vendor from inherited PATH"
        );
        for forbidden in [
            "start_inner(",
            "preflight(",
            "Command::new",
            ".spawn(",
            "probe_",
        ] {
            assert!(
                !body.contains(forbidden),
                "{name} typed prepare contains forbidden spawn path {forbidden}"
            );
        }
    }
}

#[test]
fn native_metadata_adapter_only_prepares_a_redacted_spec_and_readback() {
    let source = include_str!("../src/claude_code/adapter.rs");
    let body = between(
        source,
        "impl NativeMetadataEffectAdapter for ClaudeCodeAdapter",
        "impl NativeHistoryReader for ClaudeCodeAdapter",
    );
    assert!(body.contains("resolve_trusted_program"));
    assert!(body.contains("read_native_projection_metadata"));
    for forbidden in [
        "Command::new",
        ".spawn(",
        "decode_cwd",
        "find_session_cwd",
        "std::env::var",
    ] {
        assert!(
            !body.contains(forbidden),
            "native metadata adapter contains forbidden path {forbidden}"
        );
    }

    let agent = include_str!("../src/agent.rs");
    let seam = between(
        agent,
        "pub(crate) struct NativeMetadataEffectRequest",
        "pub(crate) type DynNativeMetadataEffectAdapter",
    );
    for forbidden in ["Serialize", "Deserialize", "JsonSchema"] {
        assert!(
            !seam.contains(forbidden),
            "daemon-private native metadata seam became wire-visible via {forbidden}"
        );
    }
    let schema = include_str!("../../protocol/agentdeck/agentdeck-protocol.schema.json");
    for private_type in [
        "NativeMetadataEffectRequest",
        "NativeMetadataEffectSpec",
        "NativeMetadataReadback",
    ] {
        assert!(
            !schema.contains(private_type),
            "{private_type} leaked to wire schema"
        );
    }
}

#[test]
fn legacy_cc_history_router_cannot_bypass_native_metadata_gate() {
    let source = include_str!("../src/claude_code/adapter.rs");
    let body = between(source, "async fn handle_history(", "async fn cancel(");
    assert!(body.contains("cc-history-mutation-requires-runtime-gate"));
    for bypass in [
        "history::archive",
        "history::rename",
        "Command::new",
        ".spawn(",
    ] {
        assert!(
            !body.contains(bypass),
            "legacy CC history router retained native mutation bypass {bypass}"
        );
    }
}

#[test]
fn typed_drivers_only_consume_gate_stdio() {
    for (name, source) in [
        ("Codex", include_str!("../src/codex/driver.rs") as &str),
        (
            "Claude Code",
            include_str!("../src/claude_code/driver.rs") as &str,
        ),
    ] {
        assert!(source.contains("GatedChildIo"));
        for forbidden in ["Command::new", "start_inner(", "SessionId", "RuntimeEvent"] {
            assert!(
                !source.contains(forbidden),
                "{name} typed driver contains forbidden ownership symbol {forbidden}"
            );
        }
    }
}

#[test]
fn production_coordinator_is_the_only_typed_vendor_spawn_owner() {
    let execution = include_str!("../src/runtime/execution.rs");
    let production = between(
        execution,
        "impl RuntimeExecutionCoordinator for GatedExecutionCoordinator",
        "struct GatedExecutionControl",
    );
    assert!(production.contains("GatedChild::spawn_current"));
    for forbidden in [
        "start_adapter_state",
        "continue_adapter_state",
        "start_session_stdio_compat",
        "continue_thread_stdio_compat",
    ] {
        assert!(!production.contains(forbidden));
    }
}

#[test]
fn exec_gate_keeps_a_stable_group_leader_without_starting_tokio() {
    // 威胁场景：vendor leader 输出 terminal 后退出、同 PGID tool child 仍活；若 gate
    // 通过 spawn/wait 跟随 vendor 生命周期，daemon 会失去可验证 leader 并只剩可复用 PGID。
    let main = include_str!("../src/main.rs");
    let main_body = between(main, "fn main() -> ExitCode {", "#[cfg(test)]");
    let gate_branch = between(main_body, "if args.exec_gate {", "if args.show_help {");
    assert!(gate_branch.contains("exec_gate::run_from_private_fd()"));
    assert!(
        !gate_branch.contains("run_main_loop("),
        "exec-gate must run before the Tokio daemon runtime is created"
    );

    let gate = include_str!("../src/exec_gate.rs");
    let released = between(
        gate,
        "let release = read_frame(&mut control)?;",
        "fn validate_prepare(",
    );
    assert!(released.contains("libc::fork()"));
    assert!(
        !released.contains("command.spawn("),
        "released vendor must be forked under the stable sentinel"
    );
    assert!(released.contains("[libc::SIGTERM, libc::SIGCHLD]"));
    assert!(released.contains("libc::SIG_IGN"));
    assert!(released.contains("libc::SIG_DFL"));
}

#[test]
fn canonical_runtime_capabilities_use_preseeded_versions_without_vendor_spawn() {
    let router = include_str!("../src/runtime/router.rs");
    let construction = between(router, "pub fn with_runtime_store(", "pub fn register(");
    assert!(construction.contains("CodexAdapter::with_state_vault"));
    assert!(construction.contains("ClaudeCodeAdapter::with_state_vault"));

    for (name, source, version_constant, stable_version) in [
        (
            "Codex",
            include_str!("../src/codex/adapter.rs") as &str,
            "CANONICAL_CODEX_VERSION",
            "codex-cli 0.144.1",
        ),
        (
            "Claude Code",
            include_str!("../src/claude_code/adapter.rs") as &str,
            "CANONICAL_CLAUDE_CODE_VERSION",
            "claude unknown",
        ),
    ] {
        let constructor = between(
            source,
            "pub(crate) fn with_state_vault(",
            "pub fn new_for_test(",
        );
        assert!(
            constructor.contains("OnceLock::from"),
            "{name} canonical constructor must preseed its version cache"
        );
        assert!(constructor.contains(version_constant));
        assert!(
            source.contains(&format!(
                "const {version_constant}: &str = \"{stable_version}\";"
            )),
            "{name} canonical version must remain a stable non-probing placeholder"
        );
    }
}

#[test]
fn main_recovers_before_either_local_ingress_and_orders_uds_permits() {
    let main = include_str!("../src/main.rs");
    let production = position(main, "RuntimeCore::new_production");
    let recovery = position(main, ".recover_for_startup()");
    let bind = position(main, "BoundLocalListener::bind_after_recovery(");
    let remote = position(main, ".take_remote_start_permit()");
    let listener = position(main, ".serve_until(");
    let compatibility = position(main, "stdio_compat::run_after_recovery(");
    assert!(production < recovery);
    assert!(recovery < bind && bind < remote && remote < listener);
    assert!(recovery < compatibility);
    let production_main = between(main, "fn run_main_loop(", "fn main()");
    assert!(
        !production_main.contains("RuntimeHub::new(router)"),
        "production main must not expose legacy adapter spawn ingress"
    );
}

#[test]
fn production_stdio_allowlist_runs_before_any_router_dispatch() {
    let hub = include_str!("../src/runtime/hub.rs");
    let dispatch = between(hub, "async fn dispatch(", "/// Single-owner stdout writer");
    let rejection = position(dispatch, "stdio_compatibility_allows(&cmd)");
    let routing = position(dispatch, "ClientCommand::History(req) =>");
    assert!(
        rejection < routing,
        "stdio rejection must precede every command-specific router branch"
    );

    let predicate = between(
        hub,
        "fn stdio_compatibility_allows(",
        "/// Single-owner stdout writer",
    );
    for classified in [
        "ClientCommand::Ping",
        "ClientCommand::Selfcheck",
        "ClientCommand::ProtocolSchema",
        "ClientCommand::ProtocolVersion",
        "ClientCommand::AgentList",
        "ClientCommand::AgentCapabilities",
        "HistoryRequest::List",
        "HistoryRequest::Read",
        "HistoryRequest::Archive",
        "HistoryRequest::Unarchive",
        "HistoryRequest::Rename",
        "ClientCommand::SessionStart",
        "ClientCommand::SessionContinue",
        "ClientCommand::SessionCancel",
        "ClientCommand::ActionDecision",
        "ClientCommand::VendorControl",
    ] {
        assert!(
            predicate.contains(classified),
            "stdio policy must explicitly classify {classified}"
        );
    }
    assert!(
        !predicate.contains("_ =>"),
        "future commands must fail compilation until stdio policy is reviewed"
    );
}

fn between<'a>(source: &'a str, start: &str, end: &str) -> &'a str {
    let start = position(source, start);
    let tail = &source[start..];
    let end = tail
        .find(end)
        .unwrap_or_else(|| panic!("missing section end marker {end}"));
    &tail[..end]
}

fn position(source: &str, needle: &str) -> usize {
    source
        .find(needle)
        .unwrap_or_else(|| panic!("missing source marker {needle}"))
}
