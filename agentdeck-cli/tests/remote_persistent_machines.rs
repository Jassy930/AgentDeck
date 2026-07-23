#![cfg(unix)]

#[allow(dead_code)]
#[path = "support/remote_pairing.rs"]
mod remote_pairing;

use std::fs;
use std::panic::{AssertUnwindSafe, catch_unwind};
use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};

use agentdeck_cli::installation::CliInstallationStore;
use agentdeck_cli::remote::keychain::{
    MemoryRemoteKeyStore, PairedRemoteKeyPurpose, ParsedPairedRemoteKeyAccount, RemoteKeyAccount,
    RemoteKeyPersistence, RemoteKeyStore, RemoteKeyStoreError, RemoteSecret,
};
use agentdeck_cli::remote::machines::list_persistent_remote_machines;
use agentdeck_cli::remote::paired_machine::{
    PairedMachineStore, PairedMutationObserver, PairedMutationStage,
};
use agentdeck_cli::remote::production::PersistentRemoteComposition;
use agentdeck_cli::remote::signature::{
    CurrentRemoteCliSignatureVerifier, REMOTE_CLI_ACCESS_GROUP_SUFFIX, REMOTE_CLI_CODE_IDENTIFIER,
    RemoteCliSignatureAttestation, RemoteCliSignatureError, RemoteCliSignatureExpectation,
    RemoteCliSignatureKind,
};
use agentdeck_crypto::{sha256, sign_tbs};
use agentdeck_protocol::relay_v2::auth::{DeviceRevocation, Ed25519Signature};
use agentdeck_protocol::relay_v2::frame::RevocationCommitted;
use agentdeck_protocol::relay_v2::{
    GrantSerial, OpaqueRouteFrame, RELAY_PROTOCOL_VERSION, RelayFrameBody, TrustEpoch, encode,
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

struct PanicAfterCleanupJournal {
    reached: AtomicBool,
}

impl PanicAfterCleanupJournal {
    fn new() -> Self {
        Self {
            reached: AtomicBool::new(false),
        }
    }
}

impl PairedMutationObserver for PanicAfterCleanupJournal {
    fn after_stage(&self, stage: PairedMutationStage) {
        if stage == PairedMutationStage::CleanupJournalDurable {
            self.reached.store(true, Ordering::SeqCst);
            panic!("injected process crash after durable ADPC journal");
        }
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

fn paired_key_snapshot(
    store: &dyn RemoteKeyStore,
    installation_id: uuid::Uuid,
    fixture: &PairingFixture,
) -> Vec<(RemoteKeyAccount, Option<Vec<u8>>)> {
    let identity = fixture.identity();
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
            identity.machine_root_fingerprint(),
            identity.machine_route(),
            purpose,
        );
        let value = store
            .load(&account)
            .expect("snapshot paired Keychain value")
            .map(|secret| secret.expose_secret().to_vec());
        (account, value)
    })
    .collect()
}

fn paired_key_snapshot_for_machines(
    store: &dyn RemoteKeyStore,
    installation_id: uuid::Uuid,
    fixtures: &[&PairingFixture],
) -> Vec<(RemoteKeyAccount, Option<Vec<u8>>)> {
    let mut snapshot = fixtures
        .iter()
        .flat_map(|fixture| paired_key_snapshot(store, installation_id, fixture))
        .collect::<Vec<_>>();
    snapshot.sort_by(|left, right| left.0.as_str().cmp(right.0.as_str()));
    snapshot
}

fn marker_account(installation_id: uuid::Uuid, fixture: &PairingFixture) -> RemoteKeyAccount {
    let identity = fixture.identity();
    RemoteKeyAccount::paired(
        installation_id,
        identity.machine_root_fingerprint(),
        identity.machine_route(),
        PairedRemoteKeyPurpose::CommitMarker,
    )
}

fn signed_revocation_terminal(fixture: &PairingFixture) -> OpaqueRouteFrame {
    let root = fixture.fixture_root_signing_key();
    let root_fingerprint = sha256(&root.verifying_key().to_bytes());
    assert_eq!(root_fingerprint, fixture.invite().machine_root_fingerprint);
    let mut revocation = DeviceRevocation {
        machine_route: fixture.machine_route(),
        device_route: fixture.device_route(),
        grant_serial: GrantSerial::new(7),
        root_key_id: fixture.root_key_id(),
        trust_epoch: TrustEpoch::new(2),
        signature: Ed25519Signature([0; 64]),
    };
    revocation.signature = sign_tbs(
        &root,
        &revocation.to_be_signed_v1(fixture.invite().relay_server_id, root_fingerprint),
    )
    .into();
    OpaqueRouteFrame {
        version: RELAY_PROTOCOL_VERSION,
        body: RelayFrameBody::RevocationCommitted(RevocationCommitted {
            device_route: fixture.device_route(),
            grant_serial: GrantSerial::new(7),
            signed_revocation: revocation,
        }),
    }
}

fn leave_valid_cleanup_journal(
    store: &dyn RemoteKeyStore,
    state_root: &Path,
    installation_id: uuid::Uuid,
    fixture: &PairingFixture,
) {
    let observer = Arc::new(PanicAfterCleanupJournal::new());
    let paired = PairedMachineStore::new_with_mutation_observer(
        store,
        installation_id,
        state_root,
        observer.clone(),
    );
    let opened = paired
        .open_exact(fixture.identity())
        .expect("open real paired fixture");
    let terminal = signed_revocation_terminal(fixture);
    let verified = opened
        .verify_revocation_terminal(&terminal, &encode(&terminal))
        .expect("verify exact MachineRoot-signed terminal");
    let crashed = catch_unwind(AssertUnwindSafe(|| {
        opened
            .commit_revocation_cleanup(verified)
            .expect("cleanup reaches injected crash");
    }));
    assert!(crashed.is_err(), "fixture must stop after durable journal");
    assert!(observer.reached.load(Ordering::SeqCst));
    let journal = store
        .load(&marker_account(installation_id, fixture))
        .expect("load durable cleanup journal")
        .expect("cleanup journal remains after crash");
    assert_eq!(&journal.expose_secret()[..4], b"ADPC");
}

fn tamper_last_byte(store: &dyn RemoteKeyStore, account: &RemoteKeyAccount) {
    let original = store
        .load(account)
        .expect("load value for offline tamper")
        .expect("value exists for offline tamper");
    let mut tampered = original.expose_secret().to_vec();
    *tampered.last_mut().expect("nonempty durable value") ^= 0x01;
    store
        .compare_and_replace_exact(account, &original, &RemoteSecret::new(tampered))
        .expect("inject offline tamper");
}

fn ordered_distinct_fixtures(installation_id: uuid::Uuid) -> (PairingFixture, PairingFixture) {
    let first = PairingFixture::new();
    let second = PairingFixture::new_distinct(0x81);
    assert_ne!(first.identity(), second.identity());
    if marker_account(installation_id, &first).as_str()
        < marker_account(installation_id, &second).as_str()
    {
        (first, second)
    } else {
        (second, first)
    }
}

fn rust_sources_under(root: &Path) -> Vec<(PathBuf, String)> {
    fn walk(root: &Path, current: &Path, output: &mut Vec<(PathBuf, String)>) {
        let mut entries = fs::read_dir(current)
            .expect("read Rust source directory")
            .map(|entry| entry.expect("Rust source entry"))
            .collect::<Vec<_>>();
        entries.sort_by_key(|entry| entry.file_name());
        for entry in entries {
            let path = entry.path();
            if entry.file_type().expect("Rust source type").is_dir() {
                walk(root, &path, output);
            } else if path.extension().is_some_and(|extension| extension == "rs") {
                output.push((
                    path.strip_prefix(root)
                        .expect("relative Rust source")
                        .to_path_buf(),
                    fs::read_to_string(&path).expect("read Rust source"),
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
fn machines_recovers_a_valid_cleanup_journal_before_returning_inventory() {
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
        0x62,
    );
    leave_valid_cleanup_journal(
        key_store.as_ref(),
        &state_root,
        installation_id.as_uuid(),
        &fixture,
    );

    let composition = PersistentRemoteComposition::injected_for_test(
        &expectation(),
        &FakeVerifier { accepted: true },
        installation_store,
        key_store.clone(),
        state_root.clone(),
    )
    .expect("injected composition");
    key_store.reset_mutations();

    let output = list_persistent_remote_machines(&composition)
        .expect("startup cleanup precedes inventory output");

    assert!(
        key_store.mutation_count() > 0,
        "startup recovery must finish the durable cleanup"
    );
    assert!(
        paired_key_snapshot(key_store.as_ref(), installation_id.as_uuid(), &fixture)
            .into_iter()
            .all(|(_, value)| value.is_none()),
        "all paired Keychain material must be absent before output returns"
    );
    assert!(
        file_snapshot(&state_root).iter().all(|(path, _)| {
            let name = path.to_string_lossy();
            !name.ends_with(".crypto-state.v1") && !name.ends_with(".crypto-state-stage.v1")
        }),
        "sealed crypto state must be absent; persistent lease files may remain"
    );
    assert_eq!(
        output["result"]["machines"]
            .as_array()
            .expect("machine array")
            .len(),
        0,
        "cleanup-pending machine must not be listed"
    );
}

#[test]
fn machines_rejects_a_tampered_active_marker_without_mutation_or_output() {
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
        0x63,
    );
    tamper_last_byte(
        key_store.as_ref(),
        &marker_account(installation_id.as_uuid(), &fixture),
    );
    let composition = PersistentRemoteComposition::injected_for_test(
        &expectation(),
        &FakeVerifier { accepted: true },
        installation_store,
        key_store.clone(),
        state_root.clone(),
    )
    .expect("injected composition");
    let keys_before = paired_key_snapshot(key_store.as_ref(), installation_id.as_uuid(), &fixture);
    let files_before = file_snapshot(&state_root);
    key_store.reset_mutations();

    let error = list_persistent_remote_machines(&composition)
        .expect_err("tampered active marker must return Err without output value");

    assert_eq!(error.code(), "remote.pairing.paired_conflict");
    assert_eq!(key_store.mutation_count(), 0);
    assert_eq!(
        paired_key_snapshot(key_store.as_ref(), installation_id.as_uuid(), &fixture),
        keys_before
    );
    assert_eq!(file_snapshot(&state_root), files_before);
}

#[test]
fn machines_rejects_a_tampered_cleanup_journal_without_mutation_or_output() {
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
        0x64,
    );
    leave_valid_cleanup_journal(
        key_store.as_ref(),
        &state_root,
        installation_id.as_uuid(),
        &fixture,
    );
    tamper_last_byte(
        key_store.as_ref(),
        &marker_account(installation_id.as_uuid(), &fixture),
    );
    let composition = PersistentRemoteComposition::injected_for_test(
        &expectation(),
        &FakeVerifier { accepted: true },
        installation_store,
        key_store.clone(),
        state_root.clone(),
    )
    .expect("injected composition");
    let keys_before = paired_key_snapshot(key_store.as_ref(), installation_id.as_uuid(), &fixture);
    let files_before = file_snapshot(&state_root);
    key_store.reset_mutations();

    let error = list_persistent_remote_machines(&composition)
        .expect_err("tampered ADPC journal must return Err without output value");

    assert_eq!(error.code(), "remote.pairing.paired_invalid");
    assert_eq!(key_store.mutation_count(), 0);
    assert_eq!(
        paired_key_snapshot(key_store.as_ref(), installation_id.as_uuid(), &fixture),
        keys_before
    );
    assert_eq!(file_snapshot(&state_root), files_before);
}

#[test]
fn global_recovery_audits_later_active_tamper_before_cleaning_an_earlier_journal() {
    let home = tempfile::tempdir().expect("home tempdir");
    let state = tempfile::tempdir().expect("state parent");
    let state_root = canonical_root(&state, "remote-state");
    let installation_store = CliInstallationStore::injected_for_test(home.path().to_path_buf());
    let installation_id = installation_store
        .load_or_create()
        .expect("stable installation id");
    let key_store = Arc::new(TrackingKeyStore::new());
    let (cleanup_first, tampered_second) = ordered_distinct_fixtures(installation_id.as_uuid());
    assert!(
        marker_account(installation_id.as_uuid(), &cleanup_first).as_str()
            < marker_account(installation_id.as_uuid(), &tampered_second).as_str(),
        "valid ADPC fixture must sort before the later tampered active marker"
    );
    let _ = cleanup_first.promote_for_installation(
        key_store.as_ref(),
        &state_root,
        installation_id.as_uuid(),
        0x71,
    );
    let _ = tampered_second.promote_for_installation(
        key_store.as_ref(),
        &state_root,
        installation_id.as_uuid(),
        0x75,
    );
    leave_valid_cleanup_journal(
        key_store.as_ref(),
        &state_root,
        installation_id.as_uuid(),
        &cleanup_first,
    );
    tamper_last_byte(
        key_store.as_ref(),
        &marker_account(installation_id.as_uuid(), &tampered_second),
    );
    let composition = PersistentRemoteComposition::injected_for_test(
        &expectation(),
        &FakeVerifier { accepted: true },
        installation_store,
        key_store.clone(),
        state_root.clone(),
    )
    .expect("injected composition");
    let machines = [&cleanup_first, &tampered_second];
    let keys_before =
        paired_key_snapshot_for_machines(key_store.as_ref(), installation_id.as_uuid(), &machines);
    let files_before = file_snapshot(&state_root);
    key_store.reset_mutations();

    let error = list_persistent_remote_machines(&composition)
        .expect_err("later active tamper must prevent any earlier cleanup and return no value");

    assert_eq!(error.code(), "remote.pairing.paired_conflict");
    assert_eq!(key_store.mutation_count(), 0);
    assert_eq!(
        paired_key_snapshot_for_machines(key_store.as_ref(), installation_id.as_uuid(), &machines,),
        keys_before
    );
    assert_eq!(file_snapshot(&state_root), files_before);
}

#[test]
fn global_recovery_audits_later_cleanup_tamper_before_cleaning_an_earlier_journal() {
    let home = tempfile::tempdir().expect("home tempdir");
    let state = tempfile::tempdir().expect("state parent");
    let state_root = canonical_root(&state, "remote-state");
    let installation_store = CliInstallationStore::injected_for_test(home.path().to_path_buf());
    let installation_id = installation_store
        .load_or_create()
        .expect("stable installation id");
    let key_store = Arc::new(TrackingKeyStore::new());
    let (cleanup_first, tampered_second) = ordered_distinct_fixtures(installation_id.as_uuid());
    assert!(
        marker_account(installation_id.as_uuid(), &cleanup_first).as_str()
            < marker_account(installation_id.as_uuid(), &tampered_second).as_str(),
        "valid ADPC fixture must sort before the later tampered ADPC"
    );
    let _ = cleanup_first.promote_for_installation(
        key_store.as_ref(),
        &state_root,
        installation_id.as_uuid(),
        0x79,
    );
    let _ = tampered_second.promote_for_installation(
        key_store.as_ref(),
        &state_root,
        installation_id.as_uuid(),
        0x7d,
    );
    leave_valid_cleanup_journal(
        key_store.as_ref(),
        &state_root,
        installation_id.as_uuid(),
        &cleanup_first,
    );
    leave_valid_cleanup_journal(
        key_store.as_ref(),
        &state_root,
        installation_id.as_uuid(),
        &tampered_second,
    );
    tamper_last_byte(
        key_store.as_ref(),
        &marker_account(installation_id.as_uuid(), &tampered_second),
    );
    let composition = PersistentRemoteComposition::injected_for_test(
        &expectation(),
        &FakeVerifier { accepted: true },
        installation_store,
        key_store.clone(),
        state_root.clone(),
    )
    .expect("injected composition");
    let machines = [&cleanup_first, &tampered_second];
    let keys_before =
        paired_key_snapshot_for_machines(key_store.as_ref(), installation_id.as_uuid(), &machines);
    let files_before = file_snapshot(&state_root);
    key_store.reset_mutations();

    let error = list_persistent_remote_machines(&composition)
        .expect_err("later ADPC tamper must prevent any earlier cleanup and return no value");

    assert_eq!(error.code(), "remote.pairing.paired_invalid");
    assert_eq!(key_store.mutation_count(), 0);
    assert_eq!(
        paired_key_snapshot_for_machines(key_store.as_ref(), installation_id.as_uuid(), &machines,),
        keys_before
    );
    assert_eq!(file_snapshot(&state_root), files_before);
}

#[test]
fn persistent_composition_raw_capabilities_are_crate_private_and_branded() {
    let production = include_str!("../src/remote/production.rs");
    let machines = include_str!("../src/remote/machines.rs");
    assert!(production.contains("pub(crate) fn key_store(&self)"));
    assert!(production.contains("pub(crate) fn state_root(&self)"));
    assert!(!production.contains("pub fn key_store(&self)"));
    assert!(!production.contains("pub fn state_root(&self)"));
    assert!(production.contains("pub struct RecoveredPairedMachineStore"));
    assert!(!production.contains("impl Deref for RecoveredPairedMachineStore"));
    assert!(machines.contains("paired_store: RecoveredPairedMachineStore<'a>"));
    assert!(!machines.contains("PairedMachineStore::new("));

    let source_root = Path::new(env!("CARGO_MANIFEST_DIR")).join("src");
    for (path, source) in rust_sources_under(&source_root) {
        let is_pair_creation_exception = path == Path::new("remote/pair.rs");
        let raw_getter_calls =
            source.matches(".key_store()").count() + source.matches(".state_root()").count();
        let raw_store_constructors = source.matches("PairedMachineStore::new").count();
        if is_pair_creation_exception {
            assert_eq!(
                raw_getter_calls,
                2,
                "pair creation is the only explicit raw composition exception: {}",
                path.display()
            );
            assert_eq!(raw_store_constructors, 0);
        } else if path == Path::new("remote/production.rs") {
            assert_eq!(raw_getter_calls, 0);
            assert_eq!(
                raw_store_constructors, 1,
                "only the branded recovery gateway may construct a raw paired store"
            );
        } else {
            assert_eq!(
                raw_getter_calls,
                0,
                "raw composition capability escaped into {}",
                path.display()
            );
            assert_eq!(
                raw_store_constructors,
                0,
                "raw paired-store construction bypassed recovery in {}",
                path.display()
            );
        }
    }
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
