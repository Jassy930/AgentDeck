use std::fs;
use std::path::{Path, PathBuf};

const CLI_ACCESS_GROUP_SUFFIX: &str = ".com.agentdeck.remote.cli";
const CLI_ENTITLEMENT_GROUP: &str = "com.agentdeck.remote.cli";
const PRODUCTION_TRANSFER_CANDIDATE_LIMIT_CONSTRUCTOR: &str =
    "new_with_production_transfer_candidate_limit_for_automatic_harness";
const OBSERVED_PRODUCTION_TRANSFER_CANDIDATE_LIMIT_CONSTRUCTOR: &str =
    "new_with_production_transfer_candidate_limit_and_mutation_observer_for_automatic_harness";

fn rust_sources_under(root: &Path) -> Vec<PathBuf> {
    let mut pending = vec![root.to_path_buf()];
    let mut sources = Vec::new();
    while let Some(path) = pending.pop() {
        if path.is_dir() {
            for entry in fs::read_dir(&path).expect("read Rust source directory") {
                pending.push(entry.expect("read Rust source entry").path());
            }
        } else if path.extension().is_some_and(|extension| extension == "rs") {
            sources.push(path);
        }
    }
    sources
}

fn runtime_surface_files_under(root: &Path) -> Vec<PathBuf> {
    let mut pending = vec![root.to_path_buf()];
    let mut surfaces = Vec::new();
    while let Some(path) = pending.pop() {
        if path.is_dir() {
            for entry in fs::read_dir(&path).expect("read runtime surface directory") {
                pending.push(entry.expect("read runtime surface entry").path());
            }
        } else if path.extension().is_some_and(|extension| {
            matches!(
                extension.to_str(),
                Some("rs" | "json" | "jsonl" | "toml" | "yaml" | "yml")
            )
        }) {
            surfaces.push(path);
        }
    }
    surfaces
}

fn function_source<'a>(source: &'a str, declaration: &str) -> &'a str {
    let start = source.find(declaration).expect("find function declaration");
    let tail = &source[start..];
    let body_start = tail.find('{').expect("find function body");
    let mut depth = 0_usize;
    for (offset, character) in tail[body_start..].char_indices() {
        match character {
            '{' => depth += 1,
            '}' => {
                depth -= 1;
                if depth == 0 {
                    return &tail[..body_start + offset + 1];
                }
            }
            _ => {}
        }
    }
    panic!("function body is not balanced")
}

#[test]
fn packaging_declares_one_cli_only_keychain_group_without_signing_dev_builds() {
    let entitlements = include_str!("../../packaging/agentdeck-cli.entitlements");
    assert_eq!(entitlements.matches("keychain-access-groups").count(), 1);
    assert_eq!(entitlements.matches(CLI_ENTITLEMENT_GROUP).count(), 1);
    assert!(entitlements.contains("$(AppIdentifierPrefix)com.agentdeck.remote.cli"));
    assert!(!entitlements.contains("agentdeckd.stable"));

    let build_script = include_str!("../../script/build_and_run.sh");
    for required in [
        "AGENTDECK_CLI_CODE_IDENTIFIER",
        "AGENTDECK_CLI_TEAM_IDENTIFIER",
        "AGENTDECK_CLI_KEYCHAIN_ACCESS_GROUP",
        "com.agentdeck.agentdeck-cli",
        CLI_ACCESS_GROUP_SUFFIX,
    ] {
        assert!(
            build_script.contains(required),
            "missing release identity wiring: {required}"
        );
    }
    assert!(!build_script.contains("codesign -s -"));
    assert!(!build_script.contains("--sign -"));
}

#[test]
fn production_composition_is_the_only_binary_reachable_persistence_constructor() {
    let module = include_str!("../src/remote/production.rs");
    for required in [
        "PersistentRemoteComposition",
        "ProductionRemoteCliSignatureVerifier",
        "verify_current_remote_cli_identity",
        "MacOsRemoteKeyStore",
        "remote_state_root_for_current_user",
        "CliInstallationStore::for_os_account",
        ".load_or_create()",
        "installation_id",
    ] {
        assert!(
            module.contains(required),
            "missing composition step: {required}"
        );
    }

    let remote_mod = include_str!("../src/remote/mod.rs");
    assert!(remote_mod.contains("pub mod production;"));
    assert!(remote_mod.contains("pub mod signature;"));
    assert!(remote_mod.contains("mod macos_keychain;"));

    let cargo = include_str!("../Cargo.toml");
    assert!(cargo.contains("security-framework = { version = \"3.7\""));
    assert!(cargo.contains("security-framework-sys = \"2.17\""));

    let production_section = module
        .split("pub fn production()")
        .nth(1)
        .expect("single production constructor");
    let signature = production_section
        .find("verify_current_remote_cli_identity")
        .expect("signature guard");
    let state_root = production_section
        .find("remote_state_root_from_home(installation_store.frozen_home_path())")
        .expect("state root derived from the frozen OS-account home");
    let installation = production_section
        .find(".load_or_create()")
        .expect("stable installation identity");
    let keychain = production_section
        .find("MacOsRemoteKeyStore")
        .expect("production Keychain adapter");
    assert!(signature < state_root);
    assert!(signature < keychain);
    assert!(signature < installation);
    assert!(installation < state_root);
    assert!(installation < keychain);
}

#[test]
fn production_persistence_has_no_file_secret_or_runtime_selector_escape_hatch() {
    let files = [
        include_str!("../src/remote/production.rs"),
        include_str!("../src/remote/signature.rs"),
        include_str!("../src/remote/macos_keychain.rs"),
    ];
    let joined = files.join("\n");
    for forbidden in [
        "MemoryRemoteKeyStore::new",
        "AGENTDECK_REMOTE_FILE_KEYSTORE",
        "AGENTDECK_REMOTE_KEYSTORE",
        "std::env::var(\"HOME\")",
        "std::env::var_os(\"HOME\")",
    ] {
        assert!(
            !joined.contains(forbidden),
            "production persistence selector escaped: {forbidden}"
        );
    }

    assert!(
        Path::new(env!("CARGO_MANIFEST_DIR"))
            .join("../packaging/agentdeck-cli.entitlements")
            .is_file()
    );
}

#[test]
fn injected_composition_is_debug_library_only_and_not_a_runtime_selector() {
    let production = include_str!("../src/remote/production.rs");
    assert!(production.contains("#[cfg(debug_assertions)]"));
    assert!(production.contains("pub fn injected_for_test"));

    let binary = include_str!("../src/main.rs");
    assert!(!binary.contains("injected_for_test"));
    for forbidden in [
        "AGENTDECK_REMOTE_COMPOSITION",
        "AGENTDECK_REMOTE_INSTALLATION_HOME",
        "--remote-installation-home",
        "--remote-state-root",
    ] {
        assert!(
            !binary.contains(forbidden) && !production.contains(forbidden),
            "runtime composition selector escaped: {forbidden}"
        );
    }
}

#[test]
fn production_transfer_candidate_limit_harness_is_confined_to_one_default_integration_test() {
    let manifest = Path::new(env!("CARGO_MANIFEST_DIR"));
    let paired_machine_path = manifest.join("src/remote/paired_machine.rs");
    let paired_machine =
        fs::read_to_string(&paired_machine_path).expect("read paired-machine source");
    assert_eq!(
        paired_machine
            .matches(PRODUCTION_TRANSFER_CANDIDATE_LIMIT_CONSTRUCTOR)
            .count(),
        1,
        "the capacity harness must have one declaration and no internal call sites"
    );
    let declaration = format!("pub fn {PRODUCTION_TRANSFER_CANDIDATE_LIMIT_CONSTRUCTOR}");
    let constructor = function_source(&paired_machine, &declaration);
    assert!(
        constructor.contains("RuntimeStateMutationAuthority::Production"),
        "the bounded harness must mint Production mutation authority"
    );
    assert!(
        !constructor.contains("RuntimeStateMutationAuthority::AutomaticHarness"),
        "the bounded harness must not inherit automatic probe write authority"
    );
    let declaration_offset = paired_machine
        .find(&declaration)
        .expect("find capacity harness declaration");
    let attribute_window =
        &paired_machine[declaration_offset.saturating_sub(512)..declaration_offset];
    assert!(
        attribute_window.contains("#[doc(hidden)]"),
        "the test-only Production constructor must stay out of generated API documentation"
    );
    assert!(
        attribute_window.contains("#[cfg(debug_assertions)]"),
        "the lowered-cap constructor must not exist in release artifacts"
    );

    assert_eq!(
        paired_machine
            .matches(OBSERVED_PRODUCTION_TRANSFER_CANDIDATE_LIMIT_CONSTRUCTOR)
            .count(),
        1,
        "the observed capacity harness must have one declaration and no internal call sites"
    );
    let observed_declaration =
        format!("pub fn {OBSERVED_PRODUCTION_TRANSFER_CANDIDATE_LIMIT_CONSTRUCTOR}");
    let observed_constructor = function_source(&paired_machine, &observed_declaration);
    assert!(
        observed_constructor.contains("RuntimeStateMutationAuthority::Production")
            && observed_constructor.contains("Some(observer)"),
        "the observed bounded harness must retain Production authority and only inject its explicit observer"
    );
    assert!(
        !observed_constructor.contains("RuntimeStateMutationAuthority::AutomaticHarness"),
        "the observed bounded harness must not inherit automatic probe write authority"
    );
    let observed_declaration_offset = paired_machine
        .find(&observed_declaration)
        .expect("find observed capacity harness declaration");
    let observed_attribute_window = &paired_machine
        [observed_declaration_offset.saturating_sub(512)..observed_declaration_offset];
    assert!(
        observed_attribute_window.contains("#[doc(hidden)]")
            && observed_attribute_window.contains("#[cfg(debug_assertions)]"),
        "the observed test-only Production constructor must stay hidden and absent from release artifacts"
    );

    for path in rust_sources_under(&manifest.join("src")) {
        if path == paired_machine_path {
            continue;
        }
        let source = fs::read_to_string(&path).expect("read CLI Rust source");
        assert!(
            !source.contains(PRODUCTION_TRANSFER_CANDIDATE_LIMIT_CONSTRUCTOR)
                && !source.contains(OBSERVED_PRODUCTION_TRANSFER_CANDIDATE_LIMIT_CONSTRUCTOR),
            "capacity harness escaped into production source {}",
            path.display()
        );
    }

    let receipts_path = manifest.join("tests/remote_runtime_receipts.rs");
    let gate_path = manifest.join("tests/remote_production_composition.rs");
    for path in rust_sources_under(&manifest.join("tests")) {
        if path == gate_path {
            continue;
        }
        let source = fs::read_to_string(&path).expect("read CLI integration test source");
        let expected = usize::from(path == receipts_path);
        assert_eq!(
            source
                .matches(PRODUCTION_TRANSFER_CANDIDATE_LIMIT_CONSTRUCTOR)
                .count(),
            expected,
            "capacity harness call-site drifted in {}",
            path.display()
        );
        assert_eq!(
            source
                .matches(OBSERVED_PRODUCTION_TRANSFER_CANDIDATE_LIMIT_CONSTRUCTOR)
                .count(),
            expected,
            "observed capacity harness call-site drifted in {}",
            path.display()
        );
    }

    let workspace = manifest.parent().expect("CLI crate has a workspace parent");
    for root in [
        manifest.join("src"),
        manifest.join("Cargo.toml"),
        workspace.join("agentdeck-protocol/src"),
        workspace.join("agentdeck-protocol/Cargo.toml"),
        workspace.join("protocol/agentdeck"),
    ] {
        let surfaces = runtime_surface_files_under(&root);
        assert!(
            !surfaces.is_empty(),
            "runtime surface scan unexpectedly matched no files under {}",
            root.display()
        );
        for path in surfaces {
            let source = fs::read_to_string(&path).expect("read runtime surface source");
            for forbidden in [
                "AGENTDECK_REMOTE_TRANSFER_CANDIDATE_LIMIT",
                "--remote-transfer-candidate-limit",
                "remote_transfer_candidate_limit",
            ] {
                assert!(
                    !source.contains(forbidden),
                    "capacity runtime selector escaped into {}: {forbidden}",
                    path.display()
                );
            }
        }
    }
}
