use std::collections::HashMap;
use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
use std::sync::{Arc, Mutex};

use agentdeck_protocol::e2ee::{KeyId, KeyPurpose};
use async_trait::async_trait;

use crate::remote::identity::{
    KEY_DIRECTORY_GUARD_ACCOUNT, KeyDirectoryGuard, MACHINE_DATA_SIGN_ACCOUNT,
    MACHINE_HPKE_ACCOUNT, MACHINE_LINK_SIGN_ACCOUNT, MACHINE_ROOT_SIGN_ACCOUNT,
    advance_counter_guard, counter_guard_account, install_key_directory_guard,
    load_machine_key_material,
};
use crate::runtime::store::{
    MachineIdentityBinding, MachineRemoteLifecycle, MachineRemoteStateRecord,
    MachineTrustResetKind, RuntimeStoreError,
};
use crate::security::{KeyStore, KeyStoreError, SecretBytes};

use super::*;

const DATABASE_ID: [u8; 16] = [0x21; 16];
const RELAY_ID: [u8; 16] = [0x22; 16];
const MACHINE_ROUTE: [u8; 16] = [0x23; 16];
const ROOT_KEY_ID: [u8; 16] = [0x24; 16];
const TRUST_EPOCH: u64 = 5;

#[derive(Default)]
struct RecordingKeyStore {
    values: Mutex<HashMap<String, Vec<u8>>>,
    events: Arc<Mutex<Vec<String>>>,
    retain_after_delete: Mutex<Option<String>>,
    fail_before_delete: Mutex<Option<String>>,
}

impl RecordingKeyStore {
    fn with_events(events: Arc<Mutex<Vec<String>>>) -> Self {
        Self {
            events,
            ..Self::default()
        }
    }

    fn insert(&self, account: &str, bytes: &[u8]) {
        self.values
            .lock()
            .expect("lock values")
            .insert(account.to_owned(), bytes.to_vec());
    }

    fn remove(&self, account: &str) {
        self.values.lock().expect("lock values").remove(account);
    }

    fn clear_events(&self) {
        self.events.lock().expect("lock events").clear();
    }

    fn events(&self) -> Vec<String> {
        self.events.lock().expect("lock events").clone()
    }

    fn retain_after_next_delete(&self, account: &str) {
        *self.retain_after_delete.lock().expect("lock delete fault") = Some(account.to_owned());
    }

    fn fail_before_next_delete(&self, account: &str) {
        *self.fail_before_delete.lock().expect("lock delete failure") = Some(account.to_owned());
    }

    fn all_absent(&self, counter_axes: &[KeyId]) -> bool {
        let values = self.values.lock().expect("lock values");
        [
            MACHINE_ROOT_SIGN_ACCOUNT.to_owned(),
            MACHINE_HPKE_ACCOUNT.to_owned(),
            MACHINE_LINK_SIGN_ACCOUNT.to_owned(),
            MACHINE_DATA_SIGN_ACCOUNT.to_owned(),
            KEY_DIRECTORY_GUARD_ACCOUNT.to_owned(),
        ]
        .into_iter()
        .chain(counter_axes.iter().copied().map(counter_guard_account))
        .all(|account| !values.contains_key(&account))
    }
}

impl KeyStore for RecordingKeyStore {
    fn load(&self, account: &str) -> Result<Option<SecretBytes>, KeyStoreError> {
        self.events
            .lock()
            .expect("lock events")
            .push(format!("key.load:{account}"));
        Ok(self
            .values
            .lock()
            .expect("lock values")
            .get(account)
            .cloned()
            .map(SecretBytes::new))
    }

    fn store(&self, account: &str, value: &SecretBytes) -> Result<(), KeyStoreError> {
        self.events
            .lock()
            .expect("lock events")
            .push(format!("key.store:{account}"));
        self.values
            .lock()
            .expect("lock values")
            .insert(account.to_owned(), value.expose_secret().to_vec());
        Ok(())
    }

    fn delete(&self, account: &str) -> Result<(), KeyStoreError> {
        self.events
            .lock()
            .expect("lock events")
            .push(format!("key.delete:{account}"));
        let mut fail = self.fail_before_delete.lock().expect("lock delete failure");
        if fail.as_deref() == Some(account) {
            *fail = None;
            return Err(KeyStoreError::Backend {
                operation: "delete",
                status: -1,
            });
        }
        drop(fail);
        let mut retain = self.retain_after_delete.lock().expect("lock delete fault");
        if retain.as_deref() == Some(account) {
            *retain = None;
            return Ok(());
        }
        self.values.lock().expect("lock values").remove(account);
        Ok(())
    }
}

#[derive(Clone)]
struct Fixture {
    snapshot: AuthenticatedMachineCleanup,
    counter_axes: Vec<KeyId>,
}

impl Fixture {
    fn install(
        keys: &RecordingKeyStore,
        reset_kind: MachineTrustResetKind,
        counter_axes: Vec<KeyId>,
    ) -> Self {
        keys.insert(MACHINE_ROOT_SIGN_ACCOUNT, &[0x31; 32]);
        keys.insert(MACHINE_HPKE_ACCOUNT, &[0x32; 32]);
        keys.insert(MACHINE_LINK_SIGN_ACCOUNT, &[0x33; 32]);
        keys.insert(MACHINE_DATA_SIGN_ACCOUNT, &[0x34; 32]);
        let material = load_machine_key_material(keys).expect("load fixed machine material");
        let public = material.public_identity();
        let binding = MachineIdentityBinding {
            root_key_id: ROOT_KEY_ID,
            trust_epoch: TRUST_EPOCH,
            link_generation: 7,
            data_generation: 9,
            key_directory_revision: 11,
            root_public_key: *public.root().public_key(),
            root_fingerprint: public.root().fingerprint(),
            machine_hpke_public_key: *public.hpke().public_key(),
            machine_hpke_fingerprint: public.hpke().fingerprint(),
            link_sign_public_key: *public.link().public_key(),
            link_sign_fingerprint: public.link().fingerprint(),
            data_sign_public_key: *public.data().public_key(),
            data_sign_fingerprint: public.data().fingerprint(),
        };
        install_key_directory_guard(
            keys,
            KeyDirectoryGuard::new(
                DATABASE_ID,
                binding.root_fingerprint,
                binding.key_directory_revision,
            ),
        )
        .expect("install key-directory guard");
        for (index, key_id) in counter_axes.iter().copied().enumerate() {
            advance_counter_guard(keys, key_id, 1_024 + index as u64)
                .expect("install counter guard");
        }
        keys.clear_events();
        Self {
            snapshot: AuthenticatedMachineCleanup {
                database_id: DATABASE_ID,
                record: MachineRemoteStateRecord {
                    lifecycle: MachineRemoteLifecycle::PurgeReadbackAbsent,
                    relay_server_id: RELAY_ID,
                    machine_route: MACHINE_ROUTE,
                    root_key_id: ROOT_KEY_ID,
                    root_fingerprint: binding.root_fingerprint,
                    trust_epoch: TRUST_EPOCH,
                    request_hash: [0x41; 32],
                    response_hash: Some([0x42; 32]),
                    enrollment_receipt_hash: Some([0x43; 32]),
                    receipt_verify_key_hash: [0x44; 32],
                    sealed_state_bytes: 512,
                },
                binding,
                reset_kind,
                purge_proof_hash: [0x45; 32],
                counter_guard_axes: counter_axes.clone(),
            },
            counter_axes,
        }
    }
}

struct FakeStore {
    snapshot: AuthenticatedMachineCleanup,
    events: Arc<Mutex<Vec<String>>>,
    finalize_calls: AtomicUsize,
    fail_finalize_once: AtomicBool,
}

impl FakeStore {
    fn new(snapshot: AuthenticatedMachineCleanup, events: Arc<Mutex<Vec<String>>>) -> Self {
        Self {
            snapshot,
            events,
            finalize_calls: AtomicUsize::new(0),
            fail_finalize_once: AtomicBool::new(false),
        }
    }

    fn fail_finalize_once(&self) {
        self.fail_finalize_once.store(true, Ordering::SeqCst);
    }
}

#[async_trait]
impl MachineCleanupStore for FakeStore {
    async fn load_authenticated_cleanup(&self) -> Result<LoadedMachineCleanup, RuntimeStoreError> {
        self.events
            .lock()
            .expect("lock events")
            .push("store.load".to_owned());
        Ok(LoadedMachineCleanup::Pending(Box::new(
            self.snapshot.clone(),
        )))
    }

    async fn finalize_local_deletion(
        &self,
        reset_kind: MachineTrustResetKind,
        purge_proof_hash: [u8; 32],
        cleanup_witness_hash: [u8; 32],
    ) -> Result<(), RuntimeStoreError> {
        self.events
            .lock()
            .expect("lock events")
            .push("store.finalize".to_owned());
        self.finalize_calls.fetch_add(1, Ordering::SeqCst);
        assert_eq!(reset_kind, self.snapshot.reset_kind);
        assert_eq!(purge_proof_hash, self.snapshot.purge_proof_hash);
        assert_eq!(
            cleanup_witness_hash,
            self.snapshot.witness()?.canonical_sha256()
        );
        if self.fail_finalize_once.swap(false, Ordering::SeqCst) {
            return Err(RuntimeStoreError::MachineRemoteConflict);
        }
        Ok(())
    }
}

struct FakeDoneStore {
    events: Arc<Mutex<Vec<String>>>,
}

#[async_trait]
impl MachineCleanupStore for FakeDoneStore {
    async fn load_authenticated_cleanup(&self) -> Result<LoadedMachineCleanup, RuntimeStoreError> {
        self.events
            .lock()
            .expect("lock events")
            .push("store.load".to_owned());
        Ok(LoadedMachineCleanup::AlreadyLocalDeleted)
    }

    async fn finalize_local_deletion(
        &self,
        _reset_kind: MachineTrustResetKind,
        _purge_proof_hash: [u8; 32],
        _cleanup_witness_hash: [u8; 32],
    ) -> Result<(), RuntimeStoreError> {
        panic!("LocalDeleted replay must not finalize again")
    }
}

struct FakeRemoteOwner {
    events: Arc<Mutex<Vec<String>>>,
    key_owner: Option<FakeKeyOwner>,
}

struct FakeKeyOwner(Arc<Mutex<Vec<String>>>);

impl Drop for FakeKeyOwner {
    fn drop(&mut self) {
        self.0
            .lock()
            .expect("lock events")
            .push("owner.drop".to_owned());
    }
}

impl FakeRemoteOwner {
    fn new(events: Arc<Mutex<Vec<String>>>) -> Self {
        Self {
            key_owner: Some(FakeKeyOwner(Arc::clone(&events))),
            events,
        }
    }
}

#[async_trait]
impl MachineCleanupRemoteOwner for FakeRemoteOwner {
    async fn shutdown_and_reclaim(
        mut self,
    ) -> Result<Option<RemoteStartPermit>, RemoteTransportError> {
        self.events
            .lock()
            .expect("lock events")
            .push("transport.shutdown".to_owned());
        drop(self.key_owner.take());
        Ok(None)
    }
}

fn counter_axes() -> Vec<KeyId> {
    vec![
        KeyId {
            purpose: KeyPurpose::Catalog,
            epoch: 3,
        },
        KeyId {
            purpose: KeyPurpose::DeviceReplyTx,
            epoch: 7,
        },
    ]
}

async fn run_fixture(
    keys: &RecordingKeyStore,
    store: &FakeStore,
) -> Result<MachineCleanupOutcome, MachineCleanupWorkflowError> {
    MachineCleanupWorkflow::new()
        .run_with(store, keys, FakeRemoteOwner::new(Arc::clone(&store.events)))
        .await
}

#[tokio::test]
async fn root_present_shuts_down_owner_then_deletes_exact_axes_with_root_last() {
    let events = Arc::new(Mutex::new(Vec::new()));
    let keys = RecordingKeyStore::with_events(Arc::clone(&events));
    let fixture = Fixture::install(&keys, MachineTrustResetKind::RootPresent, counter_axes());
    let store = FakeStore::new(fixture.snapshot, Arc::clone(&events));

    assert_eq!(
        run_fixture(&keys, &store).await.unwrap().disposition(),
        MachineCleanupDisposition::Finalized
    );
    assert!(keys.all_absent(&fixture.counter_axes));

    let events = keys.events();
    assert_eq!(
        &events[..3],
        ["transport.shutdown", "owner.drop", "store.load"]
    );
    let deletes: Vec<_> = events
        .iter()
        .filter(|event| event.starts_with("key.delete:"))
        .cloned()
        .collect();
    assert_eq!(
        deletes.last().map(String::as_str),
        Some("key.delete:machine-root-sign.v1")
    );
    let finalize = events
        .iter()
        .position(|event| event == "store.finalize")
        .unwrap();
    let last_delete = events
        .iter()
        .rposition(|event| event.starts_with("key.delete:"))
        .unwrap();
    assert!(finalize > last_delete);
}

#[tokio::test]
async fn already_local_deleted_still_consumes_owner_before_readback_and_skips_keychain() {
    let events = Arc::new(Mutex::new(Vec::new()));
    let keys = RecordingKeyStore::with_events(Arc::clone(&events));
    let store = FakeDoneStore {
        events: Arc::clone(&events),
    };

    let outcome = MachineCleanupWorkflow::new()
        .run_with(&store, &keys, FakeRemoteOwner::new(Arc::clone(&events)))
        .await
        .unwrap();
    assert_eq!(
        outcome.disposition(),
        MachineCleanupDisposition::AlreadyLocalDeleted
    );
    assert_eq!(
        *events.lock().expect("lock events"),
        ["transport.shutdown", "owner.drop", "store.load"]
    );
}

#[tokio::test]
async fn cleanup_witness_must_match_authenticated_record_and_binding_before_keychain_io() {
    let events = Arc::new(Mutex::new(Vec::new()));
    let keys = RecordingKeyStore::with_events(Arc::clone(&events));
    let mut fixture = Fixture::install(&keys, MachineTrustResetKind::RootPresent, vec![]);
    fixture.snapshot.record.root_fingerprint = [0x97; 32];
    keys.clear_events();
    let store = FakeStore::new(fixture.snapshot, events);

    let error = run_fixture(&keys, &store)
        .await
        .expect_err("record/binding fork must fail before Keychain IO");
    assert_eq!(
        error.code(),
        RuntimeStoreError::MachineRemoteConflict.code()
    );
    assert_eq!(
        keys.events(),
        ["transport.shutdown", "owner.drop", "store.load"]
    );
    assert_eq!(store.finalize_calls.load(Ordering::SeqCst), 0);
}

#[tokio::test]
async fn root_lost_accepts_missing_root_with_all_remaining_material_matching() {
    let events = Arc::new(Mutex::new(Vec::new()));
    let keys = RecordingKeyStore::with_events(Arc::clone(&events));
    let fixture = Fixture::install(&keys, MachineTrustResetKind::RootLost, vec![]);
    keys.remove(MACHINE_ROOT_SIGN_ACCOUNT);
    keys.clear_events();
    let store = FakeStore::new(fixture.snapshot, events);

    run_fixture(&keys, &store).await.unwrap();
    assert!(keys.all_absent(&[]));
    assert!(
        !keys
            .events()
            .iter()
            .any(|event| { event == &format!("key.delete:{MACHINE_ROOT_SIGN_ACCOUNT}") })
    );
}

#[tokio::test]
async fn root_lost_with_matching_root_still_deletes_root_last() {
    let events = Arc::new(Mutex::new(Vec::new()));
    let keys = RecordingKeyStore::with_events(Arc::clone(&events));
    let fixture = Fixture::install(&keys, MachineTrustResetKind::RootLost, vec![]);
    let store = FakeStore::new(fixture.snapshot, events);

    run_fixture(&keys, &store).await.unwrap();
    let deletes: Vec<_> = keys
        .events()
        .into_iter()
        .filter(|event| event.starts_with("key.delete:"))
        .collect();
    assert_eq!(
        deletes.last().map(String::as_str),
        Some("key.delete:machine-root-sign.v1")
    );
}

#[tokio::test]
async fn root_lost_portable_receipt_cleanup_accepts_any_missing_identity_item() {
    for missing in [
        MACHINE_ROOT_SIGN_ACCOUNT,
        MACHINE_HPKE_ACCOUNT,
        MACHINE_LINK_SIGN_ACCOUNT,
        MACHINE_DATA_SIGN_ACCOUNT,
        KEY_DIRECTORY_GUARD_ACCOUNT,
    ] {
        let events = Arc::new(Mutex::new(Vec::new()));
        let keys = RecordingKeyStore::with_events(Arc::clone(&events));
        let fixture = Fixture::install(&keys, MachineTrustResetKind::RootLost, vec![]);
        keys.remove(missing);
        keys.clear_events();
        let store = FakeStore::new(fixture.snapshot, events);

        assert_eq!(
            run_fixture(&keys, &store).await.unwrap().disposition(),
            MachineCleanupDisposition::Finalized,
            "portable receipt must authorize existing-only cleanup after {missing} is absent"
        );
        assert!(keys.all_absent(&[]));
        assert!(
            !keys
                .events()
                .iter()
                .any(|event| event == &format!("key.store:{missing}")),
            "cleanup must not recreate {missing}"
        );
    }
}

#[tokio::test]
async fn root_lost_rejects_surviving_root_or_nonroot_fork_before_mutation() {
    for account in [MACHINE_ROOT_SIGN_ACCOUNT, MACHINE_HPKE_ACCOUNT] {
        let events = Arc::new(Mutex::new(Vec::new()));
        let keys = RecordingKeyStore::with_events(Arc::clone(&events));
        let fixture = Fixture::install(&keys, MachineTrustResetKind::RootLost, vec![]);
        keys.insert(account, &[0x99; 32]);
        keys.clear_events();
        let store = FakeStore::new(fixture.snapshot, events);

        let error = run_fixture(&keys, &store)
            .await
            .expect_err("forked material must fail closed");
        assert_eq!(
            error.code(),
            "daemon.remote.identity.cleanup_binding_mismatch"
        );
        assert!(
            !keys
                .events()
                .iter()
                .any(|event| event.starts_with("key.delete:"))
        );
        assert_eq!(store.finalize_calls.load(Ordering::SeqCst), 0);
    }
}

#[tokio::test]
async fn partial_material_or_guard_axes_fail_before_first_delete() {
    let events = Arc::new(Mutex::new(Vec::new()));
    let keys = RecordingKeyStore::with_events(Arc::clone(&events));
    let fixture = Fixture::install(&keys, MachineTrustResetKind::RootPresent, counter_axes());
    keys.remove(MACHINE_LINK_SIGN_ACCOUNT);
    keys.clear_events();
    let store = FakeStore::new(fixture.snapshot.clone(), Arc::clone(&events));
    let error = run_fixture(&keys, &store)
        .await
        .expect_err("partial material");
    assert_eq!(error.code(), "daemon.remote.identity.cleanup_partial_state");
    assert!(
        !keys
            .events()
            .iter()
            .any(|event| event.starts_with("key.delete:"))
    );

    let guard_events = Arc::new(Mutex::new(Vec::new()));
    let guard_keys = RecordingKeyStore::with_events(Arc::clone(&guard_events));
    let guard_fixture = Fixture::install(&guard_keys, MachineTrustResetKind::RootPresent, vec![]);
    guard_keys.remove(KEY_DIRECTORY_GUARD_ACCOUNT);
    guard_keys.clear_events();
    let guard_store = FakeStore::new(guard_fixture.snapshot, guard_events);
    let error = run_fixture(&guard_keys, &guard_store)
        .await
        .expect_err("missing authenticated guard axis");
    assert_eq!(error.code(), "daemon.remote.identity.cleanup_partial_state");
    assert!(
        !guard_keys
            .events()
            .iter()
            .any(|event| event.starts_with("key.delete:"))
    );

    let root_events = Arc::new(Mutex::new(Vec::new()));
    let root_keys = RecordingKeyStore::with_events(Arc::clone(&root_events));
    let root_fixture = Fixture::install(&root_keys, MachineTrustResetKind::RootPresent, vec![]);
    root_keys.remove(MACHINE_ROOT_SIGN_ACCOUNT);
    root_keys.clear_events();
    let root_store = FakeStore::new(root_fixture.snapshot, root_events);
    let error = run_fixture(&root_keys, &root_store)
        .await
        .expect_err("out-of-order root absence must fail closed");
    assert_eq!(error.code(), "daemon.remote.identity.cleanup_partial_state");
    assert!(
        !root_keys
            .events()
            .iter()
            .any(|event| event.starts_with("key.delete:"))
    );
}

#[tokio::test]
async fn wrong_directory_database_axis_fails_before_first_delete() {
    let events = Arc::new(Mutex::new(Vec::new()));
    let keys = RecordingKeyStore::with_events(Arc::clone(&events));
    let fixture = Fixture::install(&keys, MachineTrustResetKind::RootPresent, vec![]);
    crate::remote::identity::delete_key_directory_guard(
        &keys,
        fixture.snapshot.binding.root_fingerprint,
    )
    .unwrap();
    install_key_directory_guard(
        &keys,
        KeyDirectoryGuard::new(
            [0x98; 16],
            fixture.snapshot.binding.root_fingerprint,
            fixture.snapshot.binding.key_directory_revision,
        ),
    )
    .unwrap();
    keys.clear_events();
    let store = FakeStore::new(fixture.snapshot, events);

    let error = run_fixture(&keys, &store)
        .await
        .expect_err("directory database axis must match authenticated Store");
    assert_eq!(
        error.code(),
        "daemon.remote.identity.cleanup_binding_mismatch"
    );
    assert!(
        !keys
            .events()
            .iter()
            .any(|event| event.starts_with("key.delete:"))
    );
}

#[tokio::test]
async fn duplicate_authenticated_counter_axis_is_rejected_without_keychain_mutation() {
    let events = Arc::new(Mutex::new(Vec::new()));
    let keys = RecordingKeyStore::with_events(Arc::clone(&events));
    let repeated = KeyId {
        purpose: KeyPurpose::Catalog,
        epoch: 3,
    };
    let fixture = Fixture::install(
        &keys,
        MachineTrustResetKind::RootPresent,
        vec![repeated, repeated],
    );
    let store = FakeStore::new(fixture.snapshot, events);

    let error = run_fixture(&keys, &store)
        .await
        .expect_err("duplicate counter axes are not canonical");
    assert_eq!(
        error.code(),
        "daemon.remote.identity.cleanup_counter_axis_duplicate"
    );
    assert!(
        !keys
            .events()
            .iter()
            .any(|event| event.starts_with("key.delete:"))
    );
}

#[tokio::test]
async fn missing_or_transplanted_counter_guard_fails_before_mutation() {
    for transplant in [false, true] {
        let events = Arc::new(Mutex::new(Vec::new()));
        let keys = RecordingKeyStore::with_events(Arc::clone(&events));
        let fixture = Fixture::install(&keys, MachineTrustResetKind::RootPresent, counter_axes());
        let missing = fixture.counter_axes[1];
        keys.remove(&counter_guard_account(missing));
        if transplant {
            let source = counter_guard_account(fixture.counter_axes[0]);
            let bytes = keys.values.lock().unwrap().get(&source).cloned().unwrap();
            keys.insert(&counter_guard_account(missing), &bytes);
        }
        keys.clear_events();
        let store = FakeStore::new(fixture.snapshot, events);

        let error = run_fixture(&keys, &store)
            .await
            .expect_err("counter axis must be authenticated exactly");
        assert!(matches!(
            error.code(),
            "daemon.remote.identity.cleanup_partial_state" | "daemon.remote.identity.guard_invalid"
        ));
        assert!(
            !keys
                .events()
                .iter()
                .any(|event| event.starts_with("key.delete:"))
        );
    }
}

#[tokio::test]
async fn all_absent_is_retryable_and_only_finalizes_store() {
    let events = Arc::new(Mutex::new(Vec::new()));
    let keys = RecordingKeyStore::with_events(Arc::clone(&events));
    let fixture = Fixture::install(&keys, MachineTrustResetKind::RootPresent, counter_axes());
    for account in [
        MACHINE_ROOT_SIGN_ACCOUNT,
        MACHINE_HPKE_ACCOUNT,
        MACHINE_LINK_SIGN_ACCOUNT,
        MACHINE_DATA_SIGN_ACCOUNT,
        KEY_DIRECTORY_GUARD_ACCOUNT,
    ] {
        keys.remove(account);
    }
    for key_id in &fixture.counter_axes {
        keys.remove(&counter_guard_account(*key_id));
    }
    keys.clear_events();
    let store = FakeStore::new(fixture.snapshot, events);

    assert_eq!(
        run_fixture(&keys, &store).await.unwrap().disposition(),
        MachineCleanupDisposition::Finalized
    );
    assert!(
        !keys
            .events()
            .iter()
            .any(|event| event.starts_with("key.delete:"))
    );
    assert_eq!(store.finalize_calls.load(Ordering::SeqCst), 1);
}

#[tokio::test]
async fn delete_readback_failure_never_advances_store() {
    let events = Arc::new(Mutex::new(Vec::new()));
    let keys = RecordingKeyStore::with_events(Arc::clone(&events));
    let fixture = Fixture::install(&keys, MachineTrustResetKind::RootPresent, vec![]);
    keys.retain_after_next_delete(MACHINE_DATA_SIGN_ACCOUNT);
    keys.clear_events();
    let store = FakeStore::new(fixture.snapshot, events);

    let error = run_fixture(&keys, &store)
        .await
        .expect_err("delete must require absent readback");
    assert_eq!(error.code(), "daemon.remote.identity.delete_failed");
    assert_eq!(store.finalize_calls.load(Ordering::SeqCst), 0);
    assert_eq!(
        keys.events()
            .into_iter()
            .filter(|event| event.starts_with("key.delete:"))
            .collect::<Vec<_>>(),
        vec![format!("key.delete:{MACHINE_DATA_SIGN_ACCOUNT}")]
    );
}

#[tokio::test]
async fn store_finalize_failure_retries_from_all_absent_with_same_witness() {
    let events = Arc::new(Mutex::new(Vec::new()));
    let keys = RecordingKeyStore::with_events(Arc::clone(&events));
    let fixture = Fixture::install(&keys, MachineTrustResetKind::RootPresent, vec![]);
    let store = FakeStore::new(fixture.snapshot, events);
    store.fail_finalize_once();

    let first = run_fixture(&keys, &store)
        .await
        .expect_err("first finalize is injected failure");
    assert_eq!(
        first.code(),
        RuntimeStoreError::MachineRemoteConflict.code()
    );
    assert!(keys.all_absent(&[]));

    assert_eq!(
        run_fixture(&keys, &store).await.unwrap().disposition(),
        MachineCleanupDisposition::Finalized
    );
    assert_eq!(store.finalize_calls.load(Ordering::SeqCst), 2);
}

async fn assert_each_delete_boundary_is_retryable(
    reset_kind: MachineTrustResetKind,
    root_initially_absent: bool,
) {
    let axes = counter_axes();
    let mut deletion_order = axes
        .iter()
        .copied()
        .map(counter_guard_account)
        .collect::<Vec<_>>();
    deletion_order.extend([
        MACHINE_DATA_SIGN_ACCOUNT.to_owned(),
        MACHINE_LINK_SIGN_ACCOUNT.to_owned(),
        MACHINE_HPKE_ACCOUNT.to_owned(),
        KEY_DIRECTORY_GUARD_ACCOUNT.to_owned(),
    ]);
    if !root_initially_absent {
        deletion_order.push(MACHINE_ROOT_SIGN_ACCOUNT.to_owned());
    }

    for failure_account in deletion_order {
        let events = Arc::new(Mutex::new(Vec::new()));
        let keys = RecordingKeyStore::with_events(Arc::clone(&events));
        let fixture = Fixture::install(&keys, reset_kind, axes.clone());
        if root_initially_absent {
            keys.remove(MACHINE_ROOT_SIGN_ACCOUNT);
        }
        keys.fail_before_next_delete(&failure_account);
        keys.clear_events();
        let store = FakeStore::new(fixture.snapshot, events);

        let first = run_fixture(&keys, &store)
            .await
            .expect_err("injected delete boundary must stop this attempt");
        assert_eq!(
            first.code(),
            KeyStoreError::Backend {
                operation: "delete",
                status: -1,
            }
            .code()
        );
        assert_eq!(store.finalize_calls.load(Ordering::SeqCst), 0);

        keys.clear_events();
        run_fixture(&keys, &store)
            .await
            .expect("the exact prefix-deleted shape must resume safely");
        assert!(keys.all_absent(&axes));
        assert_eq!(store.finalize_calls.load(Ordering::SeqCst), 1);
    }
}

#[tokio::test]
async fn root_present_retries_every_prefix_deleted_crash_boundary() {
    assert_each_delete_boundary_is_retryable(MachineTrustResetKind::RootPresent, false).await;
}

#[tokio::test]
async fn root_lost_retries_every_prefix_deleted_crash_boundary() {
    assert_each_delete_boundary_is_retryable(MachineTrustResetKind::RootLost, true).await;
}
