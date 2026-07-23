use std::path::Path;

const CLI_ACCESS_GROUP_SUFFIX: &str = ".com.agentdeck.remote.cli";
const CLI_ENTITLEMENT_GROUP: &str = "com.agentdeck.remote.cli";

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
        .find("remote_state_root_for_current_user")
        .expect("OS-account state root");
    let keychain = production_section
        .find("MacOsRemoteKeyStore")
        .expect("production Keychain adapter");
    assert!(signature < state_root);
    assert!(signature < keychain);
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
