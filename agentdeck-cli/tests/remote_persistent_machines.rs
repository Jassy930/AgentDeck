#![cfg(unix)]

#[allow(dead_code)]
#[path = "support/remote_pairing.rs"]
mod remote_pairing;

use std::fs;
use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::sync::atomic::{AtomicUsize, Ordering};

use agentdeck_cli::installation::CliInstallationStore;
use agentdeck_cli::remote::keychain::{
    MemoryRemoteKeyStore, ParsedPairedRemoteKeyAccount, RemoteKeyAccount, RemoteKeyPersistence,
    RemoteKeyStore, RemoteKeyStoreError, RemoteSecret,
};
use agentdeck_cli::remote::machines::list_persistent_remote_machines;
use agentdeck_cli::remote::production::PersistentRemoteComposition;
use agentdeck_cli::remote::signature::{
    CurrentRemoteCliSignatureVerifier, REMOTE_CLI_ACCESS_GROUP_SUFFIX, REMOTE_CLI_CODE_IDENTIFIER,
    RemoteCliSignatureAttestation, RemoteCliSignatureError, RemoteCliSignatureExpectation,
    RemoteCliSignatureKind,
};

use remote_pairing::PairingFixture;

const TEAM: &str = "A1B2C3D4E5";

fn access_group() -> String {
    format!("{TEAM}{REMOTE_CLI_ACCESS_GROUP_SUFFIX}")
}

fn expectation() -> RemoteCliSignatureExpectation {
    RemoteCliSignatureExpectation::for_test(REMOTE_CLI_CODE_IDENTIFIER, TEAM, access_group())
        .expect("valid injected expectation")
}

struct FakeVerifier {
    accepted: bool,
}

impl CurrentRemoteCliSignatureVerifier for FakeVerifier {
    fn verify_current(
        &self,
        _expected: &RemoteCliSignatureExpectation,
    ) -> Result<RemoteCliSignatureAttestation, RemoteCliSignatureError> {
        if !self.accepted {
            return Err(RemoteCliSignatureError::UnsignedSignature);
        }
        Ok(RemoteCliSignatureAttestation::new(
            RemoteCliSignatureKind::Production,
            REMOTE_CLI_CODE_IDENTIFIER,
            TEAM,
            vec![access_group()],
        ))
    }
}

struct TrackingKeyStore {
    inner: MemoryRemoteKeyStore,
    mutations: AtomicUsize,
    fail_list: bool,
}

impl TrackingKeyStore {
    fn new() -> Self {
        Self {
            inner: MemoryRemoteKeyStore::new(),
            mutations: AtomicUsize::new(0),
            fail_list: false,
        }
    }

    fn failing_list() -> Self {
        Self {
            inner: MemoryRemoteKeyStore::new(),
            mutations: AtomicUsize::new(0),
            fail_list: true,
        }
    }

    fn reset_mutations(&self) {
        self.mutations.store(0, Ordering::SeqCst);
    }

    fn mutation_count(&self) -> usize {
        self.mutations.load(Ordering::SeqCst)
    }
}

impl RemoteKeyStore for TrackingKeyStore {
    fn load(
        &self,
        account: &RemoteKeyAccount,
    ) -> Result<Option<RemoteSecret>, RemoteKeyStoreError> {
        self.inner.load(account)
    }

    fn persist_immutable(
        &self,
        account: &RemoteKeyAccount,
        value: &RemoteSecret,
    ) -> Result<RemoteKeyPersistence, RemoteKeyStoreError> {
        self.mutations.fetch_add(1, Ordering::SeqCst);
        self.inner.persist_immutable(account, value)
    }

    fn compare_and_replace_exact(
        &self,
        account: &RemoteKeyAccount,
        expected: &RemoteSecret,
        replacement: &RemoteSecret,
    ) -> Result<(), RemoteKeyStoreError> {
        self.mutations.fetch_add(1, Ordering::SeqCst);
        self.inner
            .compare_and_replace_exact(account, expected, replacement)
    }

    fn delete_exact(&self, account: &RemoteKeyAccount) -> Result<(), RemoteKeyStoreError> {
        self.mutations.fetch_add(1, Ordering::SeqCst);
        self.inner.delete_exact(account)
    }

    fn list_paired_commit_markers(
        &self,
        installation_id: uuid::Uuid,
    ) -> Result<Vec<ParsedPairedRemoteKeyAccount>, RemoteKeyStoreError> {
        if self.fail_list {
            return Err(RemoteKeyStoreError::BackendUnavailable);
        }
        self.inner.list_paired_commit_markers(installation_id)
    }
}

fn canonical_root(temp: &tempfile::TempDir, component: &str) -> PathBuf {
    fs::canonicalize(temp.path())
        .expect("canonical tempdir")
        .join(component)
}

fn file_snapshot(root: &Path) -> Vec<(PathBuf, Vec<u8>)> {
    fn walk(root: &Path, current: &Path, output: &mut Vec<(PathBuf, Vec<u8>)>) {
        if !current.exists() {
            return;
        }
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
                        .expect("relative snapshot")
                        .to_path_buf(),
                    fs::read(&path).expect("read snapshot file"),
                ));
            }
        }
    }

    let mut output = Vec::new();
    walk(root, root, &mut output);
    output
}

#[test]
fn signature_failure_precedes_installation_state_and_keychain_mutation() {
    let home = tempfile::tempdir().expect("home tempdir");
    let state = tempfile::tempdir().expect("state parent");
    let state_root = canonical_root(&state, "remote-state-must-not-exist");
    let installation_store = CliInstallationStore::injected_for_test(home.path().to_path_buf());
    let record_path = installation_store.record_path();
    let key_store = Arc::new(TrackingKeyStore::new());

    let result = PersistentRemoteComposition::injected_for_test(
        &expectation(),
        &FakeVerifier { accepted: false },
        installation_store,
        key_store.clone(),
        state_root.clone(),
    );

    assert_eq!(
        result.expect_err("unsigned composition must fail").code(),
        "remote.persistent.signature_invalid"
    );
    assert!(!record_path.exists());
    assert!(!state_root.exists());
    assert_eq!(key_store.mutation_count(), 0);
}

#[test]
fn injected_composition_loads_one_stable_installation_and_exposes_it() {
    let home = tempfile::tempdir().expect("home tempdir");
    let state = tempfile::tempdir().expect("state parent");
    let state_root = canonical_root(&state, "remote-state");
    let installation_store = CliInstallationStore::injected_for_test(home.path().to_path_buf());
    let verifier = FakeVerifier { accepted: true };

    let first = PersistentRemoteComposition::injected_for_test(
        &expectation(),
        &verifier,
        installation_store.clone(),
        Arc::new(MemoryRemoteKeyStore::new()),
        state_root.clone(),
    )
    .expect("first injected composition");
    let second = PersistentRemoteComposition::injected_for_test(
        &expectation(),
        &verifier,
        installation_store,
        Arc::new(MemoryRemoteKeyStore::new()),
        state_root,
    )
    .expect("second injected composition");

    assert_eq!(first.installation_id(), second.installation_id());
    assert!(!first.installation_id().as_uuid().is_nil());
}

#[test]
fn machines_lists_only_local_paired_store_without_key_or_state_mutation() {
    let home = tempfile::tempdir().expect("home tempdir");
    let state = tempfile::tempdir().expect("state parent");
    let state_root = canonical_root(&state, "remote-state");
    let installation_store = CliInstallationStore::injected_for_test(home.path().to_path_buf());
    let installation_id = installation_store
        .load_or_create()
        .expect("stable installation id");
    let key_store = Arc::new(TrackingKeyStore::new());
    let fixture = PairingFixture::new();
    let _ = fixture.promote_for_installation(
        key_store.as_ref(),
        &state_root,
        installation_id.as_uuid(),
        0x61,
    );
    key_store.reset_mutations();

    let composition = PersistentRemoteComposition::injected_for_test(
        &expectation(),
        &FakeVerifier { accepted: true },
        installation_store,
        key_store.clone(),
        state_root.clone(),
    )
    .expect("injected composition");
    let before = file_snapshot(&state_root);

    let output = list_persistent_remote_machines(&composition).expect("local machine inventory");

    assert_eq!(key_store.mutation_count(), 0);
    assert_eq!(file_snapshot(&state_root), before);
    assert_eq!(
        output["result"]["installationId"],
        installation_id.to_string()
    );
    let machines = output["result"]["machines"]
        .as_array()
        .expect("machine array");
    assert_eq!(machines.len(), 1);
    assert_eq!(machines[0]["machineDisplayName"], "Fixture Machine");
    assert!(machines[0]["machineRootFingerprint"].is_string());
    assert!(machines[0]["machineRoute"].is_string());
    assert!(machines[0]["deviceRoute"].is_string());
}

#[test]
fn machines_module_has_no_relay_or_network_dependency() {
    let source = include_str!("../src/remote/machines.rs");
    for forbidden in [
        "agentdeck_relay_client",
        "RuntimeUnixClient",
        "TcpStream",
        "WebSocket",
        "wss://",
        ".send(",
    ] {
        assert!(
            !source.contains(forbidden),
            "local machine inventory gained network behavior: {forbidden}"
        );
    }
}

#[test]
fn machines_surfaces_a_typed_local_inventory_error() {
    let home = tempfile::tempdir().expect("home tempdir");
    let state = tempfile::tempdir().expect("state parent");
    let composition = PersistentRemoteComposition::injected_for_test(
        &expectation(),
        &FakeVerifier { accepted: true },
        CliInstallationStore::injected_for_test(home.path().to_path_buf()),
        Arc::new(TrackingKeyStore::failing_list()),
        canonical_root(&state, "remote-state"),
    )
    .expect("injected composition");

    let error = list_persistent_remote_machines(&composition)
        .expect_err("backend inventory failure must remain typed");
    assert_eq!(error.code(), "remote.pairing.paired_persistence_failed");
}
