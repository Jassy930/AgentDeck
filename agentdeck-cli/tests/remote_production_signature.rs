#[allow(dead_code)]
#[path = "../src/remote/signature.rs"]
mod signature;

use std::sync::atomic::{AtomicUsize, Ordering};

use signature::{
    CurrentRemoteCliSignatureVerifier, ProductionRemoteCliSignatureVerifier,
    REMOTE_CLI_ACCESS_GROUP_SUFFIX, REMOTE_CLI_CODE_IDENTIFIER, RemoteCliSignatureAttestation,
    RemoteCliSignatureError, RemoteCliSignatureExpectation, RemoteCliSignatureKind,
    verify_current_remote_cli_identity,
};

const TEAM: &str = "A1B2C3D4E5";

fn access_group() -> String {
    format!("{TEAM}{REMOTE_CLI_ACCESS_GROUP_SUFFIX}")
}

fn expectation() -> RemoteCliSignatureExpectation {
    RemoteCliSignatureExpectation::for_test(REMOTE_CLI_CODE_IDENTIFIER, TEAM, access_group())
        .expect("valid test expectation")
}

fn production_attestation() -> RemoteCliSignatureAttestation {
    RemoteCliSignatureAttestation::new(
        RemoteCliSignatureKind::Production,
        REMOTE_CLI_CODE_IDENTIFIER,
        TEAM,
        vec![access_group()],
    )
}

struct FakeVerifier {
    calls: AtomicUsize,
    result: Result<RemoteCliSignatureAttestation, RemoteCliSignatureError>,
}

impl FakeVerifier {
    fn returning(attestation: RemoteCliSignatureAttestation) -> Self {
        Self {
            calls: AtomicUsize::new(0),
            result: Ok(attestation),
        }
    }

    fn failing(error: RemoteCliSignatureError) -> Self {
        Self {
            calls: AtomicUsize::new(0),
            result: Err(error),
        }
    }
}

impl CurrentRemoteCliSignatureVerifier for FakeVerifier {
    fn verify_current(
        &self,
        _expected: &RemoteCliSignatureExpectation,
    ) -> Result<RemoteCliSignatureAttestation, RemoteCliSignatureError> {
        self.calls.fetch_add(1, Ordering::SeqCst);
        self.result.clone()
    }
}

#[test]
fn exact_production_identity_yields_private_verified_type_state() {
    let verifier = FakeVerifier::returning(production_attestation());
    let expected = expectation();

    let verified = verify_current_remote_cli_identity(&expected, &verifier)
        .expect("exact production identity");

    assert_eq!(verified.code_identifier(), REMOTE_CLI_CODE_IDENTIFIER);
    assert_eq!(verified.team_identifier(), TEAM);
    assert_eq!(verified.keychain_access_group(), access_group());
    assert_eq!(verifier.calls.load(Ordering::SeqCst), 1);
    assert_eq!(
        format!("{verified:?}"),
        "VerifiedRemoteCliIdentity([REDACTED])"
    );
}

#[test]
fn unsigned_adhoc_and_every_identity_mismatch_fail_before_downstream_mutation() {
    let expected = expectation();
    let cases = [
        (
            "unsigned",
            RemoteCliSignatureAttestation::new(
                RemoteCliSignatureKind::Unsigned,
                REMOTE_CLI_CODE_IDENTIFIER,
                TEAM,
                vec![access_group()],
            ),
            "remote.persistent.signature_invalid",
        ),
        (
            "ad-hoc",
            RemoteCliSignatureAttestation::new(
                RemoteCliSignatureKind::AdHoc,
                REMOTE_CLI_CODE_IDENTIFIER,
                TEAM,
                vec![access_group()],
            ),
            "remote.persistent.signature_invalid",
        ),
        (
            "identifier",
            RemoteCliSignatureAttestation::new(
                RemoteCliSignatureKind::Production,
                "com.agentdeck.wrong-cli",
                TEAM,
                vec![access_group()],
            ),
            "remote.persistent.identity_invalid",
        ),
        (
            "team",
            RemoteCliSignatureAttestation::new(
                RemoteCliSignatureKind::Production,
                REMOTE_CLI_CODE_IDENTIFIER,
                "OTHERTEAM1",
                vec![access_group()],
            ),
            "remote.persistent.identity_invalid",
        ),
        (
            "missing-group",
            RemoteCliSignatureAttestation::new(
                RemoteCliSignatureKind::Production,
                REMOTE_CLI_CODE_IDENTIFIER,
                TEAM,
                Vec::new(),
            ),
            "remote.persistent.identity_invalid",
        ),
        (
            "wrong-group",
            RemoteCliSignatureAttestation::new(
                RemoteCliSignatureKind::Production,
                REMOTE_CLI_CODE_IDENTIFIER,
                TEAM,
                vec![format!("{TEAM}.com.agentdeck.agentdeckd.stable")],
            ),
            "remote.persistent.identity_invalid",
        ),
        (
            "extra-group",
            RemoteCliSignatureAttestation::new(
                RemoteCliSignatureKind::Production,
                REMOTE_CLI_CODE_IDENTIFIER,
                TEAM,
                vec![access_group(), format!("{TEAM}.com.agentdeck.shared")],
            ),
            "remote.persistent.identity_invalid",
        ),
    ];

    for (label, attestation, expected_code) in cases {
        let verifier = FakeVerifier::returning(attestation);
        let downstream_mutations = AtomicUsize::new(0);
        let result = verify_current_remote_cli_identity(&expected, &verifier).inspect(|_| {
            downstream_mutations.fetch_add(1, Ordering::SeqCst);
        });

        let error = result.unwrap_err();
        assert_eq!(error.code(), expected_code, "case={label}");
        assert_eq!(verifier.calls.load(Ordering::SeqCst), 1, "case={label}");
        assert_eq!(
            downstream_mutations.load(Ordering::SeqCst),
            0,
            "case={label}"
        );
    }
}

#[test]
fn verifier_failure_is_typed_and_never_fabricates_verified_identity() {
    let verifier = FakeVerifier::failing(RemoteCliSignatureError::VerifierTimedOut {
        operation: "test verifier",
    });
    let error = verify_current_remote_cli_identity(&expectation(), &verifier).unwrap_err();

    assert_eq!(error.code(), "remote.persistent.verifier_unavailable");
    assert_eq!(verifier.calls.load(Ordering::SeqCst), 1);
}

#[test]
fn expectation_is_fixed_to_the_cli_identifier_team_and_dedicated_group() {
    for (identifier, team, group) in [
        ("com.agentdeck.other", TEAM, access_group()),
        (
            REMOTE_CLI_CODE_IDENTIFIER,
            "TEAM-ID",
            "TEAM-ID.com.agentdeck.remote.cli".to_owned(),
        ),
        (
            REMOTE_CLI_CODE_IDENTIFIER,
            TEAM,
            format!("{TEAM}.com.agentdeck.agentdeckd.stable"),
        ),
    ] {
        let error = RemoteCliSignatureExpectation::for_test(identifier, team, group).unwrap_err();
        assert_eq!(error.code(), "remote.persistent.expectation_invalid");
    }
}

#[test]
fn production_contract_uses_compile_time_identity_and_bounded_absolute_tools_only() {
    let source = include_str!("../src/remote/signature.rs");

    for required in [
        "option_env!(\"AGENTDECK_CLI_CODE_IDENTIFIER\")",
        "option_env!(\"AGENTDECK_CLI_TEAM_IDENTIFIER\")",
        "option_env!(\"AGENTDECK_CLI_KEYCHAIN_ACCESS_GROUP\")",
        "\"/usr/bin/codesign\"",
        "\"/usr/bin/plutil\"",
        "VERIFIER_DEADLINE",
        "MAX_VERIFIER_OUTPUT_BYTES",
        "Signature=adhoc",
        "keychain-access-groups",
    ] {
        assert!(
            source.contains(required),
            "missing static contract: {required}"
        );
    }

    for forbidden in [
        "std::env::var(\"AGENTDECK_CLI_CODE_IDENTIFIER\")",
        "std::env::var(\"AGENTDECK_CLI_TEAM_IDENTIFIER\")",
        "std::env::var(\"AGENTDECK_CLI_KEYCHAIN_ACCESS_GROUP\")",
        "Command::new(\"codesign\")",
        "Command::new(\"plutil\")",
    ] {
        assert!(
            !source.contains(forbidden),
            "runtime or PATH override escaped into production verifier: {forbidden}"
        );
    }

    let verified = source
        .split("pub struct VerifiedRemoteCliIdentity")
        .nth(1)
        .expect("private verified type exists")
        .split('}')
        .next()
        .expect("verified fields");
    assert!(!verified.contains("pub code_identifier"));
    assert!(!verified.contains("pub team_identifier"));
    assert!(!verified.contains("pub keychain_access_group"));

    let cleanup = source
        .split("fn terminate_process_group")
        .nth(1)
        .expect("bounded verifier cleanup");
    let spawn = cleanup
        .find(".spawn(move ||")
        .expect("detached reaper spawn");
    let wait = cleanup.find("child.wait()").expect("owned child reaping");
    assert!(spawn < wait, "caller must not block on Child::wait");

    let _ = ProductionRemoteCliSignatureVerifier::new();
}
