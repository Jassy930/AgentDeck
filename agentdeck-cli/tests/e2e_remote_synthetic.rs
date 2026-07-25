#![cfg(unix)]

#[allow(dead_code)]
#[path = "support/remote_pairing.rs"]
mod remote_pairing;

use std::fs;
use std::path::{Path, PathBuf};
use std::process::{Command, Output};
use std::sync::Arc;

use agentdeck_cli::installation::CliInstallationStore;
use agentdeck_cli::remote::keychain::{
    MemoryRemoteKeyStore, PairedRemoteKeyPurpose, RemoteKeyAccount, RemoteKeyStore,
};
use agentdeck_cli::remote::paired_machine::{
    AutomaticRuntimeProjection, PairedMachineStore, PairedMutationObserver, PairedMutationStage,
};
use agentdeck_cli::remote::production::PersistentRemoteComposition;
use agentdeck_cli::remote::signature::{
    CurrentRemoteCliSignatureVerifier, REMOTE_CLI_ACCESS_GROUP_SUFFIX, REMOTE_CLI_CODE_IDENTIFIER,
    RemoteCliSignatureAttestation, RemoteCliSignatureError, RemoteCliSignatureExpectation,
    RemoteCliSignatureKind,
};
use agentdeck_cli::remote::stream_state::DurableStreamBindingV1;
use agentdeck_protocol::e2ee::{E2EE_FORMAT_VERSION, KeyId, KeyPurpose, StreamBindingV1};
use agentdeck_protocol::relay_v2::{
    GrantSerial, KeyDirectoryRevision, RELAY_PROTOCOL_VERSION, StreamGenerationId, StreamRouteId,
    TrustEpoch,
};
use agentdeck_protocol::runtime::{RUNTIME_PROTOCOL_VERSION, RuntimeInnerCursor, StreamCursor};
use base64::Engine as _;

use remote_pairing::{CATALOG_EPOCH, DeterministicRng, KEY_DIRECTORY_REVISION, PairingFixture};

const TEAM_IDENTIFIER: &str = "A1B2C3D4E5";
const CATALOG_ROUTE: StreamRouteId = StreamRouteId::from_bytes([0x81; 16]);
const CATALOG_GENERATION: StreamGenerationId = StreamGenerationId::from_bytes([0x91; 16]);
const BLOCKED_RECORD: &str = concat!(
    "{\"schemaVersion\":1,\"gate\":\"relay-companion-p4-real-e2e\",",
    "\"phase\":\"post-MVP\",\"status\":\"BLOCKED\",",
    "\"reasonCode\":\"missing_external_real_e2e_prerequisites\",",
    "\"missingInputs\":[\"release-signed-agentdeckd\",",
    "\"release-signed-agentdeck-cli\",\"matching-team-identifier\",",
    "\"daemon-keychain-access-group-entitlement\",",
    "\"cli-keychain-access-group-entitlement\",\"public-wss-endpoint\",",
    "\"public-wss-ca-and-spki-pin\",\"codex-login\",",
    "\"claude-code-login\",\"disposable-destructive-profile\"],",
    "\"mutations\":0,\"evidence\":[],\"summaryGenerated\":false}",
);
const BLOCKED_INPUTS: [&str; 10] = [
    "release-signed-agentdeckd",
    "release-signed-agentdeck-cli",
    "matching-team-identifier",
    "daemon-keychain-access-group-entitlement",
    "cli-keychain-access-group-entitlement",
    "public-wss-endpoint",
    "public-wss-ca-and-spki-pin",
    "codex-login",
    "claude-code-login",
    "disposable-destructive-profile",
];

struct AcceptedSignatureVerifier;

impl CurrentRemoteCliSignatureVerifier for AcceptedSignatureVerifier {
    fn verify_current(
        &self,
        _expected: &RemoteCliSignatureExpectation,
    ) -> Result<RemoteCliSignatureAttestation, RemoteCliSignatureError> {
        Ok(RemoteCliSignatureAttestation::new(
            RemoteCliSignatureKind::Production,
            REMOTE_CLI_CODE_IDENTIFIER,
            TEAM_IDENTIFIER,
            vec![access_group()],
        ))
    }
}

struct NoopMutationObserver;

impl PairedMutationObserver for NoopMutationObserver {
    fn after_stage(&self, _stage: PairedMutationStage) {}
}

#[derive(Clone, Copy)]
struct LegacyV3ReplayFixture {
    stream_seq: u64,
    sender_counter: u64,
    ciphertext_sha256: [u8; 32],
}

fn access_group() -> String {
    format!("{TEAM_IDENTIFIER}{REMOTE_CLI_ACCESS_GROUP_SUFFIX}")
}

fn expectation() -> RemoteCliSignatureExpectation {
    RemoteCliSignatureExpectation::for_test(
        REMOTE_CLI_CODE_IDENTIFIER,
        TEAM_IDENTIFIER,
        access_group(),
    )
    .expect("valid injected release identity")
}

fn real_slot_script() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR"))
        .parent()
        .expect("CLI crate has workspace parent")
        .join("scripts/run-relay-companion-p4-real-e2e.sh")
}

fn directory_snapshot(root: &Path) -> Vec<(PathBuf, Vec<u8>)> {
    fn walk(root: &Path, current: &Path, output: &mut Vec<(PathBuf, Vec<u8>)>) {
        let mut entries = fs::read_dir(current)
            .expect("read snapshot directory")
            .map(|entry| entry.expect("snapshot entry"))
            .collect::<Vec<_>>();
        entries.sort_by_key(|entry| entry.file_name());
        for entry in entries {
            let path = entry.path();
            if entry.file_type().expect("snapshot type").is_dir() {
                walk(root, &path, output);
            } else {
                output.push((
                    path.strip_prefix(root)
                        .expect("relative snapshot path")
                        .to_path_buf(),
                    fs::read(path).expect("snapshot file"),
                ));
            }
        }
    }

    let mut output = Vec::new();
    walk(root, root, &mut output);
    output
}

fn run_real_slot(current_dir: &Path, adversarial: bool) -> Output {
    let mut command = Command::new(real_slot_script());
    command.current_dir(current_dir).env_clear();
    if adversarial {
        let secret = "do-not-echo-P4-secret-$()-`touch`-\n-second-line";
        let startup_poison = current_dir.join("startup-poison");
        command
            .arg("--execute-real-destructive-body")
            .arg(secret)
            .env("PATH", "/definitely/missing")
            .env("ENV", &startup_poison)
            .env("BASH_ENV", &startup_poison)
            .env("AGENTDECK_P4_REAL_E2E", "1")
            .env("AGENTDECK_CLI_TEAM_IDENTIFIER", secret)
            .env("AGENTDECK_CLI_KEYCHAIN_ACCESS_GROUP", secret)
            .env("AGENTDECK_RELAY_URL", secret)
            .env("AGENTDECK_CODEX_LOGIN", secret)
            .env("AGENTDECK_CLAUDE_CODE_LOGIN", secret)
            .env("AGENTDECK_DESTRUCTIVE_PROFILE", secret);
    }
    command.output().expect("run read-only real-slot contract")
}

fn assert_exact_blocked_record(output: &Output) {
    assert!(output.status.success());
    assert!(
        output.stderr.is_empty(),
        "slot contract must keep stderr empty"
    );
    assert_eq!(output.stdout, format!("{BLOCKED_RECORD}\n").as_bytes());

    let record: serde_json::Value =
        serde_json::from_slice(&output.stdout).expect("one canonical NDJSON record");
    assert_eq!(record["schemaVersion"], 1);
    assert_eq!(record["gate"], "relay-companion-p4-real-e2e");
    assert_eq!(record["phase"], "post-MVP");
    assert_eq!(record["status"], "BLOCKED");
    assert_eq!(
        record["reasonCode"],
        "missing_external_real_e2e_prerequisites"
    );
    assert_eq!(record["missingInputs"], serde_json::json!(BLOCKED_INPUTS));
    assert_eq!(record["mutations"], 0);
    assert_eq!(record["evidence"], serde_json::json!([]));
    assert_eq!(record["summaryGenerated"], false);
    let keys = record
        .as_object()
        .expect("blocked record object")
        .keys()
        .map(String::as_str)
        .collect::<std::collections::BTreeSet<_>>();
    assert_eq!(
        keys,
        [
            "evidence",
            "gate",
            "missingInputs",
            "mutations",
            "phase",
            "reasonCode",
            "schemaVersion",
            "status",
            "summaryGenerated",
        ]
        .into_iter()
        .collect()
    );
}

#[test]
fn real_slot_is_one_exact_sanitized_blocked_record_with_zero_side_effects() {
    let sandbox = tempfile::tempdir().expect("slot sandbox");
    fs::write(sandbox.path().join("sentinel"), b"unchanged")
        .expect("write immutable test sentinel");
    fs::write(
        sandbox.path().join("startup-poison"),
        b"printf poisoned > startup-executed\n",
    )
    .expect("write hostile shell startup file");
    let before = directory_snapshot(sandbox.path());

    assert_exact_blocked_record(&run_real_slot(sandbox.path(), false));
    assert_eq!(directory_snapshot(sandbox.path()), before);

    let adversarial = run_real_slot(sandbox.path(), true);
    assert_exact_blocked_record(&adversarial);
    assert_eq!(directory_snapshot(sandbox.path()), before);
    let combined = [adversarial.stdout, adversarial.stderr].concat();
    assert!(!String::from_utf8_lossy(&combined).contains("do-not-echo-P4-secret"));
}

#[test]
fn real_slot_has_no_prerequisite_injection_probe_or_execution_surface() {
    let source = fs::read_to_string(real_slot_script()).expect("read real-slot runner");
    let expected = format!(
        "#!/bin/sh\nset -eu\n\n\
# P4 MVP 仅保留 post-MVP 真实链路的只读槽位。执行体、输入覆盖和证据生成均未开放。\n\
printf '%s\\n' '{BLOCKED_RECORD}'\n"
    );
    assert_eq!(
        source, expected,
        "real-slot runner 必须保持 byte-exact 单条静态输出，任何额外语句都先使 contract 失败"
    );
}

fn catalog_binding(fixture: &PairingFixture) -> StreamBindingV1 {
    StreamBindingV1 {
        format_version: E2EE_FORMAT_VERSION,
        runtime_protocol_version: RUNTIME_PROTOCOL_VERSION,
        relay_protocol_version: RELAY_PROTOCOL_VERSION,
        machine_route: fixture.machine_route(),
        device_route: fixture.device_route(),
        grant_serial: GrantSerial::new(7),
        root_trust_epoch: TrustEpoch::new(2),
        stream_route: CATALOG_ROUTE,
        stream_generation: CATALOG_GENERATION,
        stream_cursor: StreamCursor::At(40),
        inner_cursor: RuntimeInnerCursor::Catalog {
            cursor: StreamCursor::At(40),
        },
        key_directory_revision: KeyDirectoryRevision::new(KEY_DIRECTORY_REVISION),
        key_id: KeyId {
            purpose: KeyPurpose::Catalog,
            epoch: CATALOG_EPOCH,
        },
    }
}

fn put_cursor(output: &mut Vec<u8>, cursor: StreamCursor) {
    match cursor {
        StreamCursor::BeforeFirst => {
            output.push(0);
            output.extend_from_slice(&0_u64.to_be_bytes());
        }
        StreamCursor::At(value) => {
            output.push(1);
            output.extend_from_slice(&value.to_be_bytes());
        }
    }
}

fn put_inner_cursor(output: &mut Vec<u8>, cursor: &RuntimeInnerCursor) {
    match cursor {
        RuntimeInnerCursor::Catalog { cursor } => {
            output.push(0);
            put_cursor(output, *cursor);
        }
        RuntimeInnerCursor::Conversation {
            conversation_id,
            cursor,
        } => {
            output.push(1);
            let identity = conversation_id.as_str().as_bytes();
            output.extend_from_slice(&(identity.len() as u32).to_be_bytes());
            output.extend_from_slice(identity);
            put_cursor(output, *cursor);
        }
    }
}

fn legacy_v3_durable_binding_with_replay(
    binding: &StreamBindingV1,
    outer_applied: StreamCursor,
    inner_applied: RuntimeInnerCursor,
    replay: LegacyV3ReplayFixture,
) -> DurableStreamBindingV1 {
    let canonical_binding = binding.canonical_bytes().expect("canonical stream binding");
    let mut body = Vec::new();
    body.extend_from_slice(&(canonical_binding.len() as u32).to_be_bytes());
    body.extend_from_slice(&canonical_binding);
    put_cursor(&mut body, outer_applied);
    put_cursor(&mut body, StreamCursor::BeforeFirst);
    put_inner_cursor(&mut body, &inner_applied);
    put_inner_cursor(&mut body, &inner_applied);
    body.push(0);
    body.extend_from_slice(&1_u32.to_be_bytes());
    body.extend_from_slice(binding.stream_route.as_bytes());
    body.extend_from_slice(binding.stream_generation.as_bytes());
    body.extend_from_slice(&replay.stream_seq.to_be_bytes());
    body.extend_from_slice(&replay.sender_counter.to_be_bytes());
    body.extend_from_slice(&replay.ciphertext_sha256);
    body.extend_from_slice(&0_u32.to_be_bytes());

    let mut canonical = Vec::with_capacity(12 + body.len());
    canonical.extend_from_slice(b"ADSB");
    canonical.extend_from_slice(&3_u16.to_be_bytes());
    canonical.extend_from_slice(&[0, 0]);
    canonical.extend_from_slice(&(body.len() as u32).to_be_bytes());
    canonical.extend_from_slice(&body);
    DurableStreamBindingV1::from_canonical_bytes(&canonical)
        .expect("strict legacy ADSB v3 replay/cursor fixture")
}

fn paired_key_snapshot(
    store: &dyn RemoteKeyStore,
    installation_id: uuid::Uuid,
    fixture: &PairingFixture,
) -> Vec<(PairedRemoteKeyPurpose, Vec<u8>)> {
    [
        PairedRemoteKeyPurpose::DeviceSignPrivateKey,
        PairedRemoteKeyPurpose::DeviceHpkePrivateKey,
        PairedRemoteKeyPurpose::DeviceGrant,
        PairedRemoteKeyPurpose::DeviceStorageKek,
        PairedRemoteKeyPurpose::CounterGuard,
        PairedRemoteKeyPurpose::CommitMarker,
    ]
    .into_iter()
    .map(|purpose| {
        let account = RemoteKeyAccount::paired(
            installation_id,
            fixture.identity().machine_root_fingerprint(),
            fixture.machine_route(),
            purpose,
        );
        let bytes = store
            .load(&account)
            .expect("read injected Keychain item")
            .expect("paired Keychain item")
            .expose_secret()
            .to_vec();
        assert!(!bytes.is_empty());
        (purpose, bytes)
    })
    .collect()
}

fn credentials_json_under(root: &Path) -> Vec<PathBuf> {
    fn walk(current: &Path, output: &mut Vec<PathBuf>) {
        let Ok(entries) = fs::read_dir(current) else {
            return;
        };
        for entry in entries {
            let path = entry.expect("credential scan entry").path();
            if path.is_dir() {
                walk(&path, output);
            } else if path
                .file_name()
                .and_then(|name| name.to_str())
                .is_some_and(|name| name.ends_with(".credentials.json"))
            {
                output.push(path);
            }
        }
    }

    let mut output = Vec::new();
    walk(root, &mut output);
    output.sort();
    output
}

fn hex(bytes: &[u8]) -> String {
    const DIGITS: &[u8; 16] = b"0123456789abcdef";
    let mut encoded = String::with_capacity(bytes.len() * 2);
    for byte in bytes {
        encoded.push(DIGITS[usize::from(byte >> 4)] as char);
        encoded.push(DIGITS[usize::from(byte & 0x0f)] as char);
    }
    encoded
}

#[test]
fn injected_composition_restart_reads_keys_counter_cursor_and_legacy_v3_replay() {
    let home = tempfile::tempdir().expect("injected installation home");
    let state_parent = tempfile::tempdir().expect("paired state parent");
    let state_root = fs::canonicalize(state_parent.path())
        .expect("canonical state parent")
        .join("remote-state");
    let installation_store = CliInstallationStore::injected_for_test(home.path().to_path_buf());
    let key_store = Arc::new(MemoryRemoteKeyStore::new());
    let verifier = AcceptedSignatureVerifier;

    let legacy_dir = home.path().join("relay");
    fs::create_dir(&legacy_dir).expect("legacy public marker directory");
    let legacy_marker = legacy_dir.join("stable.credentials.json");
    let legacy_public_only = b"{\"schemaVersion\":1,\"machine\":\"legacy-public-only\"}\n";
    fs::write(&legacy_marker, legacy_public_only).expect("legacy public-only marker");

    let first = PersistentRemoteComposition::injected_for_test(
        &expectation(),
        &verifier,
        installation_store.clone(),
        key_store.clone(),
        state_root.clone(),
    )
    .expect("first injected composition");
    let installation_id = first.installation_id();
    let fixture = PairingFixture::new();
    fixture.promote_for_installation(
        key_store.as_ref(),
        &state_root,
        installation_id.as_uuid(),
        0x41,
    );

    let automatic_store = PairedMachineStore::new_with_mutation_observer(
        key_store.as_ref(),
        installation_id.as_uuid(),
        &state_root,
        Arc::new(NoopMutationObserver),
    );
    let mut opened = automatic_store
        .open_exact(fixture.identity())
        .expect("open injected paired machine");
    let mut first_counter_rng = DeterministicRng::new([0x42; 32]);
    let first_reservation = opened
        .reserve_command_counter_block(&mut first_counter_rng)
        .expect("durable first counter reservation");
    assert_eq!(
        (first_reservation.start(), first_reservation.end_exclusive()),
        (0, 1_024)
    );

    let wire_binding = catalog_binding(&fixture);
    let durable_cursor = RuntimeInnerCursor::Catalog {
        cursor: StreamCursor::At(41),
    };
    let replay = LegacyV3ReplayFixture {
        stream_seq: 41,
        sender_counter: 73,
        ciphertext_sha256: [0x5a; 32],
    };
    let durable_binding = legacy_v3_durable_binding_with_replay(
        &wire_binding,
        StreamCursor::At(41),
        durable_cursor.clone(),
        replay,
    );
    let initial = opened
        .automatic_runtime_projection_for_automatic_harness()
        .expect("initial automatic runtime projection");
    assert_eq!(
        initial,
        AutomaticRuntimeProjection::new(None, None, Vec::new())
    );
    let replacement = AutomaticRuntimeProjection::new(None, None, vec![durable_binding.clone()]);
    let mut state_rng = DeterministicRng::new([0x44; 32]);
    assert_eq!(
        opened
            .replace_runtime_projection_preserving_transfer_records_for_automatic_harness(
                &initial,
                &replacement,
                &mut state_rng,
            )
            .expect("persist replay/cursor projection"),
        replacement
    );
    drop(opened);

    assert_eq!(
        first
            .recovered_paired_machine_store()
            .expect("first composition recovery")
            .list()
            .expect("first composition list")
            .len(),
        1
    );
    let keys_before_restart =
        paired_key_snapshot(key_store.as_ref(), installation_id.as_uuid(), &fixture);
    drop(first);

    let second = PersistentRemoteComposition::injected_for_test(
        &expectation(),
        &verifier,
        installation_store,
        key_store.clone(),
        state_root,
    )
    .expect("recreated injected composition");
    assert_eq!(second.installation_id(), installation_id);
    assert_eq!(
        paired_key_snapshot(key_store.as_ref(), installation_id.as_uuid(), &fixture,),
        keys_before_restart,
        "DeviceSign/DeviceHPKE/grant/KEK/counter marker must survive composition drop"
    );

    let recovered = second
        .recovered_paired_machine_store()
        .expect("installation-wide recovery");
    let mut reopened = recovered
        .open_exact(fixture.identity())
        .expect("reopen exact paired machine");
    let bindings = reopened
        .durable_stream_bindings()
        .expect("read durable stream cursor");
    assert_eq!(bindings.as_slice(), std::slice::from_ref(&durable_binding));
    assert_eq!(bindings[0].binding(), &wire_binding);
    assert_eq!(bindings[0].outer_applied(), StreamCursor::At(41));
    assert_eq!(bindings[0].inner_observed(), &durable_cursor);
    assert_eq!(bindings[0].inner_applied(), &durable_cursor);
    let replay_readback = bindings[0].replay_tuple().expect("durable replay tuple");
    assert_eq!(replay_readback.key_id(), wire_binding.key_id);
    assert_eq!(
        replay_readback.key_directory_revision(),
        wire_binding.key_directory_revision
    );
    assert_eq!(replay_readback.stream_route(), CATALOG_ROUTE);
    assert_eq!(replay_readback.stream_generation(), CATALOG_GENERATION);
    assert_eq!(replay_readback.stream_seq(), replay.stream_seq);
    assert_eq!(replay_readback.sender_counter(), replay.sender_counter);
    assert_eq!(
        replay_readback.signed_frame_sha256(),
        [0; 32],
        "legacy ADSB v1-v5 replay tuples use the zero signed-frame sentinel and are not current V6 duplicate evidence"
    );
    assert_eq!(
        replay_readback.ciphertext_sha256(),
        replay.ciphertext_sha256
    );

    let mut next_counter_rng = DeterministicRng::new([0x45; 32]);
    let next_reservation = reopened
        .reserve_command_counter_block(&mut next_counter_rng)
        .expect("restart skips prior counter block");
    assert_eq!(
        (next_reservation.start(), next_reservation.end_exclusive()),
        (1_024, 2_048)
    );
    assert_eq!(
        reopened
            .durable_stream_bindings()
            .expect("counter reservation preserves cursor/replay"),
        [durable_binding]
    );

    assert_eq!(
        fs::read(&legacy_marker).expect("read legacy public marker"),
        legacy_public_only
    );
    assert_eq!(
        credentials_json_under(home.path()).as_slice(),
        std::slice::from_ref(&legacy_marker)
    );
    let legacy_bytes = fs::read(legacy_marker).expect("read legacy credential JSON");
    let legacy_text = String::from_utf8(legacy_bytes.clone()).expect("legacy JSON is UTF-8");
    for forbidden_field in ["credential", "secret", "private", "grant", "token"] {
        assert!(!legacy_text.contains(forbidden_field));
    }
    for (_, secret_record) in keys_before_restart.iter().take(3) {
        assert!(
            !legacy_bytes
                .windows(secret_record.len())
                .any(|window| window == secret_record)
        );
        assert!(!legacy_text.contains(&hex(secret_record)));
        assert!(
            !legacy_text.contains(&base64::engine::general_purpose::STANDARD.encode(secret_record))
        );
    }
}

#[test]
fn production_persistent_composition_is_linux_typed_and_macos_keychain_only() {
    let production = include_str!("../src/remote/production.rs");
    let start = production
        .find("pub fn production()")
        .expect("production composition constructor");
    let tail = &production[start..];
    let end = tail
        .find("/// Automatic/library harness")
        .expect("end of production constructor section");
    let constructor = &tail[..end];
    assert!(constructor.contains("#[cfg(not(target_os = \"macos\"))]"));
    assert!(constructor.contains("PersistentRemoteCompositionError::UnsupportedPlatform"));
    assert!(constructor.contains("#[cfg(target_os = \"macos\")]"));
    assert!(constructor.contains("MacOsRemoteKeyStore::new(&identity)"));
    for forbidden in [
        "MemoryRemoteKeyStore",
        "FileRemoteKeyStore",
        "credentials.json",
        "std::env::var",
        "std::env::var_os",
    ] {
        assert!(
            !constructor.contains(forbidden),
            "production composition gained a downgrade: {forbidden}"
        );
    }

    let this_suite = include_str!("e2e_remote_synthetic.rs");
    let fake_transport = ["Fake", "Transport"].concat();
    let transport_impl = ["impl RemoteRuntime", "Transport"].concat();
    assert!(!this_suite.contains(&fake_transport));
    assert!(!this_suite.contains(&transport_impl));
}

#[cfg(not(target_os = "macos"))]
#[test]
fn linux_production_persistent_mode_returns_typed_unsupported() {
    let error = PersistentRemoteComposition::production()
        .expect_err("Linux persistent mode must fail closed");
    assert_eq!(error.code(), "remote.persistent.unsupported");
}
