#![cfg(unix)]
#![allow(dead_code)]

#[path = "support/remote_pairing.rs"]
mod remote_pairing;

use std::fs;
use std::panic::{AssertUnwindSafe, catch_unwind};
use std::path::Path;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex};

use agentdeck_cli::remote::keychain::{
    MemoryRemoteKeyStore, PairedRemoteKeyPurpose, ParsedPairedRemoteKeyAccount, RemoteKeyAccount,
    RemoteKeyPersistence, RemoteKeyStore, RemoteKeyStoreError, RemoteSecret,
};
use agentdeck_cli::remote::paired_machine::{
    PairedMachineStore, PairedMutationObserver, PairedMutationStage,
};
use agentdeck_crypto::{sha256, sign_tbs};
use agentdeck_protocol::relay_v2::auth::{DeviceRevocation, Ed25519Signature};
use agentdeck_protocol::relay_v2::frame::RevocationCommitted;
use agentdeck_protocol::relay_v2::{
    GrantSerial, OpaqueRouteFrame, RELAY_PROTOCOL_VERSION, RelayFrameBody, TrustEpoch, encode,
};

use remote_pairing::{
    DEVICE_ROUTE, INSTALLATION_ID, MACHINE_ROUTE, PairingFixture, RELAY_SERVER, ROOT_KEY_ID,
};
use uuid::Uuid;

const CLEANUP_STAGES: [PairedMutationStage; 8] = [
    PairedMutationStage::CleanupJournalDurable,
    PairedMutationStage::CleanupStateDeleted,
    PairedMutationStage::CleanupCounterGuardDeleted,
    PairedMutationStage::CleanupGrantDeleted,
    PairedMutationStage::CleanupDeviceHpkeDeleted,
    PairedMutationStage::CleanupDeviceSignDeleted,
    PairedMutationStage::CleanupStorageKekDeleted,
    PairedMutationStage::CleanupJournalDeleted,
];

struct PanicAtCleanupStage {
    target: PairedMutationStage,
    reached: AtomicBool,
}

impl PanicAtCleanupStage {
    fn new(target: PairedMutationStage) -> Self {
        Self {
            target,
            reached: AtomicBool::new(false),
        }
    }
}

impl PairedMutationObserver for PanicAtCleanupStage {
    fn after_stage(&self, stage: PairedMutationStage) {
        if stage == self.target {
            self.reached.store(true, Ordering::SeqCst);
            panic!("injected cleanup crash after {stage:?}");
        }
    }
}

struct RecordingRemoteKeyStore {
    inner: MemoryRemoteKeyStore,
    loads: Mutex<Vec<RemoteKeyAccount>>,
}

impl RecordingRemoteKeyStore {
    fn new() -> Self {
        Self {
            inner: MemoryRemoteKeyStore::new(),
            loads: Mutex::new(Vec::new()),
        }
    }

    fn clear_loads(&self) {
        self.loads.lock().expect("recording store lock").clear();
    }

    fn loads(&self) -> Vec<RemoteKeyAccount> {
        self.loads.lock().expect("recording store lock").clone()
    }
}

impl RemoteKeyStore for RecordingRemoteKeyStore {
    fn load(
        &self,
        account: &RemoteKeyAccount,
    ) -> Result<Option<RemoteSecret>, RemoteKeyStoreError> {
        self.loads
            .lock()
            .map_err(|_| RemoteKeyStoreError::Poisoned)?
            .push(account.clone());
        self.inner.load(account)
    }

    fn persist_immutable(
        &self,
        account: &RemoteKeyAccount,
        value: &RemoteSecret,
    ) -> Result<RemoteKeyPersistence, RemoteKeyStoreError> {
        self.inner.persist_immutable(account, value)
    }

    fn compare_and_replace_exact(
        &self,
        account: &RemoteKeyAccount,
        expected: &RemoteSecret,
        replacement: &RemoteSecret,
    ) -> Result<(), RemoteKeyStoreError> {
        self.inner
            .compare_and_replace_exact(account, expected, replacement)
    }

    fn delete_exact(&self, account: &RemoteKeyAccount) -> Result<(), RemoteKeyStoreError> {
        self.inner.delete_exact(account)
    }

    fn list_paired_commit_markers(
        &self,
        installation_id: Uuid,
    ) -> Result<Vec<ParsedPairedRemoteKeyAccount>, RemoteKeyStoreError> {
        self.inner.list_paired_commit_markers(installation_id)
    }
}

#[test]
fn verified_terminal_cleanup_reaches_exact_absence_and_hides_the_machine() {
    let fixture = PairingFixture::new();
    let store = MemoryRemoteKeyStore::new();
    let temp = tempfile::tempdir().expect("temp state root");
    let state_root = canonical_state_root(&temp);
    fixture.promote(&store, &state_root, 0xb1);

    let paired = PairedMachineStore::new(&store, INSTALLATION_ID, &state_root);
    let opened = paired
        .open_exact(fixture.identity())
        .expect("open paired machine");
    let terminal = signed_terminal(&fixture);
    let verified = opened
        .verify_revocation_terminal(&terminal, &encode(&terminal))
        .expect("verify exact terminal");
    opened
        .commit_revocation_cleanup(verified)
        .expect("complete cleanup");

    assert_exact_absence(&store, &state_root, &fixture);
    assert!(
        PairedMachineStore::new(&store, INSTALLATION_ID, &state_root)
            .list()
            .expect("list after cleanup")
            .is_empty()
    );
}

#[test]
fn every_cleanup_boundary_recovers_and_the_journal_is_deleted_last() {
    for (index, stage) in CLEANUP_STAGES.into_iter().enumerate() {
        let fixture = PairingFixture::new();
        let store = MemoryRemoteKeyStore::new();
        let temp = tempfile::tempdir().expect("temp state root");
        let state_root = canonical_state_root(&temp);
        fixture.promote(&store, &state_root, 0xc0 + index as u8);
        let observer = Arc::new(PanicAtCleanupStage::new(stage));
        let paired = PairedMachineStore::new_with_mutation_observer(
            &store,
            INSTALLATION_ID,
            &state_root,
            observer.clone(),
        );
        let opened = paired
            .open_exact(fixture.identity())
            .expect("open paired machine");
        let terminal = signed_terminal(&fixture);
        let verified = opened
            .verify_revocation_terminal(&terminal, &encode(&terminal))
            .expect("verify exact terminal");
        let crashed = catch_unwind(AssertUnwindSafe(|| {
            opened
                .commit_revocation_cleanup(verified)
                .expect("cleanup reaches injected crash")
        }));
        assert!(crashed.is_err(), "{stage:?} must terminate the attempt");
        assert!(observer.reached.load(Ordering::SeqCst));

        let marker = marker_value(&store, &fixture);
        if stage == PairedMutationStage::CleanupJournalDeleted {
            assert!(marker.is_none(), "cleanup journal is the final deletion");
        } else {
            assert!(marker.is_some(), "journal must survive {stage:?}");
            let reader = PairedMachineStore::new(&store, INSTALLATION_ID, &state_root);
            assert!(
                reader.list().expect("cleanup journal is valid").is_empty(),
                "cleanup-pending marker must never be listed as active"
            );
            let error = reader
                .open_exact(fixture.identity())
                .expect_err("cleanup-pending marker cannot reopen a device");
            assert_eq!(error.code(), "remote.pairing.revoked_cleanup_pending");
        }

        let recovery = PairedMachineStore::new(&store, INSTALLATION_ID, &state_root);
        recovery
            .recover_revocation_cleanups()
            .expect("restart resumes the exact cleanup journal");
        assert_exact_absence(&store, &state_root, &fixture);
    }
}

#[test]
fn cleanup_pending_open_reads_only_the_journal_marker() {
    let fixture = PairingFixture::new();
    let store = RecordingRemoteKeyStore::new();
    let temp = tempfile::tempdir().expect("temp state root");
    let state_root = canonical_state_root(&temp);
    fixture.promote(&store, &state_root, 0xd1);
    leave_cleanup_journal(&store, &state_root, &fixture);

    store.clear_loads();
    let error = PairedMachineStore::new(&store, INSTALLATION_ID, &state_root)
        .open_exact(fixture.identity())
        .expect_err("cleanup-pending machine cannot reopen");
    assert_eq!(error.code(), "remote.pairing.revoked_cleanup_pending");
    assert_eq!(store.loads(), vec![marker_account(&fixture)]);
}

#[test]
fn cleanup_recovery_rejects_an_illegal_absence_hole_without_further_writes() {
    let fixture = PairingFixture::new();
    let store = MemoryRemoteKeyStore::new();
    let temp = tempfile::tempdir().expect("temp state root");
    let state_root = canonical_state_root(&temp);
    fixture.promote(&store, &state_root, 0xd2);
    leave_cleanup_journal(&store, &state_root, &fixture);

    let counter = paired_account(&fixture, PairedRemoteKeyPurpose::CounterGuard);
    store
        .delete_exact(&counter)
        .expect("inject offline absence hole");
    let marker_before = marker_value(&store, &fixture).expect("cleanup journal");
    let state_before = crypto_state_files(&state_root);
    let remaining_before = remaining_cleanup_values(&store, &fixture);

    assert!(
        PairedMachineStore::new(&store, INSTALLATION_ID, &state_root)
            .list()
            .is_err(),
        "inventory must fail-close on an illegal cleanup prefix"
    );
    assert!(
        PairedMachineStore::new(&store, INSTALLATION_ID, &state_root)
            .recover_revocation_cleanups()
            .is_err(),
        "recovery must reject before any further deletion"
    );
    assert_eq!(marker_value(&store, &fixture), Some(marker_before));
    assert_eq!(crypto_state_files(&state_root), state_before);
    assert_eq!(remaining_cleanup_values(&store, &fixture), remaining_before);
}

#[test]
fn cleanup_recovery_rejects_a_tampered_journal_without_deleting_material() {
    let fixture = PairingFixture::new();
    let store = MemoryRemoteKeyStore::new();
    let temp = tempfile::tempdir().expect("temp state root");
    let state_root = canonical_state_root(&temp);
    fixture.promote(&store, &state_root, 0xd3);
    leave_cleanup_journal(&store, &state_root, &fixture);

    let marker_account = marker_account(&fixture);
    let original = store
        .load(&marker_account)
        .expect("load cleanup journal")
        .expect("cleanup journal");
    let mut tampered = original.expose_secret().to_vec();
    let last = tampered.last_mut().expect("nonempty cleanup journal");
    *last ^= 0x01;
    store
        .compare_and_replace_exact(
            &marker_account,
            &original,
            &RemoteSecret::new(tampered.clone()),
        )
        .expect("inject offline journal tamper");
    let state_before = crypto_state_files(&state_root);
    let remaining_before = remaining_cleanup_values(&store, &fixture);

    assert!(
        PairedMachineStore::new(&store, INSTALLATION_ID, &state_root)
            .recover_revocation_cleanups()
            .is_err(),
        "tampered journal must fail-close"
    );
    assert_eq!(marker_value(&store, &fixture), Some(tampered));
    assert_eq!(crypto_state_files(&state_root), state_before);
    assert_eq!(remaining_cleanup_values(&store, &fixture), remaining_before);
}

#[test]
fn cleanup_tail_rejects_an_active_marker_field_tamper_without_more_deletes() {
    const JOURNAL_ACTIVE_MARKER_OFFSET: usize = 168;
    const MARKER_DIRECTORY_REVISION_OFFSET: usize = 120;

    let fixture = PairingFixture::new();
    let store = MemoryRemoteKeyStore::new();
    let temp = tempfile::tempdir().expect("temp state root");
    let state_root = canonical_state_root(&temp);
    fixture.promote(&store, &state_root, 0xd4);
    leave_cleanup_at_stage(
        &store,
        &state_root,
        &fixture,
        PairedMutationStage::CleanupStateDeleted,
    );
    assert!(
        crypto_state_files(&state_root).is_empty(),
        "state deletion must precede this tail tamper"
    );

    let marker_account = marker_account(&fixture);
    let original = store
        .load(&marker_account)
        .expect("load cleanup journal")
        .expect("cleanup journal");
    let mut tampered = original.expose_secret().to_vec();
    tampered[JOURNAL_ACTIVE_MARKER_OFFSET + MARKER_DIRECTORY_REVISION_OFFSET + 7] ^= 0x01;
    store
        .compare_and_replace_exact(
            &marker_account,
            &original,
            &RemoteSecret::new(tampered.clone()),
        )
        .expect("inject offline active-marker field tamper");
    let remaining_before = remaining_cleanup_values(&store, &fixture);

    assert!(
        PairedMachineStore::new(&store, INSTALLATION_ID, &state_root)
            .recover_revocation_cleanups()
            .is_err(),
        "DeviceSign journal authentication must reject tail tamper"
    );
    assert_eq!(marker_value(&store, &fixture), Some(tampered));
    assert_eq!(remaining_cleanup_values(&store, &fixture), remaining_before);
}

fn leave_cleanup_journal(store: &dyn RemoteKeyStore, state_root: &Path, fixture: &PairingFixture) {
    leave_cleanup_at_stage(
        store,
        state_root,
        fixture,
        PairedMutationStage::CleanupJournalDurable,
    );
}

fn leave_cleanup_at_stage(
    store: &dyn RemoteKeyStore,
    state_root: &Path,
    fixture: &PairingFixture,
    stage: PairedMutationStage,
) {
    let observer = Arc::new(PanicAtCleanupStage::new(stage));
    let paired = PairedMachineStore::new_with_mutation_observer(
        store,
        INSTALLATION_ID,
        state_root,
        observer.clone(),
    );
    let opened = paired
        .open_exact(fixture.identity())
        .expect("open paired machine");
    let terminal = signed_terminal(fixture);
    let verified = opened
        .verify_revocation_terminal(&terminal, &encode(&terminal))
        .expect("verify exact terminal");
    let crashed = catch_unwind(AssertUnwindSafe(|| {
        opened
            .commit_revocation_cleanup(verified)
            .expect("cleanup reaches journal crash")
    }));
    assert!(crashed.is_err());
    assert!(observer.reached.load(Ordering::SeqCst));
}

fn signed_terminal(fixture: &PairingFixture) -> OpaqueRouteFrame {
    let root = PairingFixture::root_signing_key();
    let root_fingerprint = sha256(&root.verifying_key().to_bytes());
    assert_eq!(root_fingerprint, fixture.invite().machine_root_fingerprint);
    let mut revocation = DeviceRevocation {
        machine_route: MACHINE_ROUTE,
        device_route: DEVICE_ROUTE,
        grant_serial: GrantSerial::new(7),
        root_key_id: ROOT_KEY_ID,
        trust_epoch: TrustEpoch::new(2),
        signature: Ed25519Signature([0; 64]),
    };
    revocation.signature = sign_tbs(
        &root,
        &revocation.to_be_signed_v1(RELAY_SERVER, root_fingerprint),
    )
    .into();
    OpaqueRouteFrame {
        version: RELAY_PROTOCOL_VERSION,
        body: RelayFrameBody::RevocationCommitted(RevocationCommitted {
            device_route: DEVICE_ROUTE,
            grant_serial: GrantSerial::new(7),
            signed_revocation: revocation,
        }),
    }
}

fn canonical_state_root(temp: &tempfile::TempDir) -> std::path::PathBuf {
    fs::canonicalize(temp.path())
        .expect("canonical tempdir")
        .join("remote-state")
}

fn marker_account(fixture: &PairingFixture) -> RemoteKeyAccount {
    paired_account(fixture, PairedRemoteKeyPurpose::CommitMarker)
}

fn paired_account(fixture: &PairingFixture, purpose: PairedRemoteKeyPurpose) -> RemoteKeyAccount {
    let identity = fixture.identity();
    RemoteKeyAccount::paired(
        INSTALLATION_ID,
        identity.machine_root_fingerprint(),
        identity.machine_route(),
        purpose,
    )
}

fn marker_value(store: &dyn RemoteKeyStore, fixture: &PairingFixture) -> Option<Vec<u8>> {
    store
        .load(&marker_account(fixture))
        .expect("load marker")
        .map(|secret| secret.expose_secret().to_vec())
}

fn remaining_cleanup_values(
    store: &dyn RemoteKeyStore,
    fixture: &PairingFixture,
) -> Vec<(PairedRemoteKeyPurpose, Option<Vec<u8>>)> {
    [
        PairedRemoteKeyPurpose::CounterGuard,
        PairedRemoteKeyPurpose::DeviceGrant,
        PairedRemoteKeyPurpose::DeviceHpkePrivateKey,
        PairedRemoteKeyPurpose::DeviceSignPrivateKey,
        PairedRemoteKeyPurpose::DeviceStorageKek,
    ]
    .into_iter()
    .map(|purpose| {
        let value = store
            .load(&paired_account(fixture, purpose))
            .expect("load cleanup material")
            .map(|secret| secret.expose_secret().to_vec());
        (purpose, value)
    })
    .collect()
}

fn crypto_state_files(root: &Path) -> Vec<(String, Vec<u8>)> {
    fn visit(root: &Path, entries: &mut Vec<(String, Vec<u8>)>) {
        if !root.exists() {
            return;
        }
        for entry in
            fs::read_dir(root).unwrap_or_else(|error| panic!("read {}: {error}", root.display()))
        {
            let path = entry.expect("read state entry").path();
            let metadata = fs::symlink_metadata(&path).expect("state entry metadata");
            if metadata.is_dir() {
                visit(&path, entries);
            } else if metadata.is_file()
                && path.file_name().is_some_and(|name| {
                    let name = name.to_string_lossy();
                    name.ends_with(".crypto-state.v1") || name.ends_with(".crypto-state-stage.v1")
                })
            {
                entries.push((
                    path.to_string_lossy().into_owned(),
                    fs::read(&path).expect("read crypto state fixture"),
                ));
            }
        }
    }

    let mut entries = Vec::new();
    visit(root, &mut entries);
    entries.sort_unstable_by(|left, right| left.0.cmp(&right.0));
    entries
}

fn assert_exact_absence(store: &dyn RemoteKeyStore, state_root: &Path, fixture: &PairingFixture) {
    let identity = fixture.identity();
    for purpose in [
        PairedRemoteKeyPurpose::DeviceSignPrivateKey,
        PairedRemoteKeyPurpose::DeviceHpkePrivateKey,
        PairedRemoteKeyPurpose::DeviceGrant,
        PairedRemoteKeyPurpose::DeviceStorageKek,
        PairedRemoteKeyPurpose::CounterGuard,
        PairedRemoteKeyPurpose::CommitMarker,
    ] {
        let account = RemoteKeyAccount::paired(
            INSTALLATION_ID,
            identity.machine_root_fingerprint(),
            identity.machine_route(),
            purpose,
        );
        assert!(
            store
                .load(&account)
                .expect("read cleanup account")
                .is_none(),
            "{purpose:?} must be absent"
        );
    }
    assert!(
        !tree_contains_suffix(state_root, ".crypto-state.v1"),
        "sealed state must be absent"
    );
    assert!(
        !tree_contains_suffix(state_root, ".crypto-state-stage.v1"),
        "prepared sidecar must be absent"
    );
}

fn tree_contains_suffix(root: &Path, suffix: &str) -> bool {
    if !root.exists() {
        return false;
    }
    let entries =
        fs::read_dir(root).unwrap_or_else(|error| panic!("read {}: {error}", root.display()));
    for entry in entries {
        let entry = entry.expect("read state entry");
        let path = entry.path();
        let metadata = fs::symlink_metadata(&path).expect("state entry metadata");
        if metadata.is_dir() {
            if tree_contains_suffix(&path, suffix) {
                return true;
            }
        } else if metadata.is_file()
            && path
                .file_name()
                .is_some_and(|name| name.to_string_lossy().ends_with(suffix))
        {
            return true;
        }
    }
    false
}
