use std::fs;
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::sync::{Arc, Mutex};

use agentdeck_protocol::runtime::{
    ClaudeCodeConversationConfiguration, ConversationConfiguration, ConversationMetadataMutation,
    RuntimeFailure, VendorConfigurationSnapshot,
};
use agentdeck_protocol::{AgentKind, ClaudeCodePermissionMode};

use super::admission::{
    RuntimeCapacityObservation, RuntimeCapacityProbe, RuntimeCapacityProbeError,
    SystemRuntimeCapacityProbe,
};
use super::*;
use crate::runtime::process_identity::ProcessIdentity;
use crate::security::{MemoryKeyStore, SecretBytes, StorageKek, load_or_create_storage_kek};

static NEXT_TEMP_ID: AtomicU64 = AtomicU64::new(1);

struct TestRoot(PathBuf);

impl TestRoot {
    fn new(label: &str) -> Self {
        let sequence = NEXT_TEMP_ID.fetch_add(1, Ordering::Relaxed);
        let path = Path::new("/tmp").join(format!(
            "agentdeck-native-effect-{label}-{}-{sequence}",
            std::process::id()
        ));
        let _ = fs::remove_dir_all(&path);
        fs::create_dir(&path).expect("create native effect root");
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            fs::set_permissions(&path, fs::Permissions::from_mode(0o700))
                .expect("secure native effect root");
        }
        Self(path)
    }

    fn database(&self) -> PathBuf {
        self.0.join("runtime.db")
    }

    fn storage_kek(&self, keys: &MemoryKeyStore) -> StorageKek {
        load_or_create_storage_kek(keys, &self.0.join("key-state.db"))
            .expect("load native effect StorageKEK")
    }
}

impl Drop for TestRoot {
    fn drop(&mut self) {
        let _ = fs::remove_dir_all(&self.0);
    }
}

struct ManualClockState {
    now_ms: AtomicU64,
    fail: AtomicBool,
}

#[derive(Clone)]
struct ManualClock(Arc<ManualClockState>);

impl ManualClock {
    fn new(now_ms: u64) -> Self {
        Self(Arc::new(ManualClockState {
            now_ms: AtomicU64::new(now_ms),
            fail: AtomicBool::new(false),
        }))
    }

    fn set(&self, now_ms: u64) {
        self.0.now_ms.store(now_ms, Ordering::SeqCst);
    }

    fn set_failed(&self, failed: bool) {
        self.0.fail.store(failed, Ordering::SeqCst);
    }
}

impl RuntimeClock for ManualClock {
    fn now_ms(&self) -> Result<u64, RuntimeClockError> {
        if self.0.fail.load(Ordering::SeqCst) {
            Err(RuntimeClockError::OutOfRange)
        } else {
            Ok(self.0.now_ms.load(Ordering::SeqCst))
        }
    }
}

#[derive(Default)]
struct ArmedFault(Mutex<Option<RuntimeStoreOperation>>);

impl ArmedFault {
    fn arm(&self, operation: RuntimeStoreOperation) {
        *self.0.lock().expect("fault lock") = Some(operation);
    }
}

impl RuntimeStoreFaultInjector for ArmedFault {
    fn before_operation(&self, operation: RuntimeStoreOperation) -> Result<(), RuntimeStoreError> {
        let mut armed = self.0.lock().expect("fault lock");
        if armed.as_ref() == Some(&operation) {
            armed.take();
            return Err(RuntimeStoreError::WorkerStopped);
        }
        Ok(())
    }
}

#[derive(Clone, Default)]
struct ToggleCapacityProbe(Arc<AtomicBool>);

impl ToggleCapacityProbe {
    fn set_failed(&self, failed: bool) {
        self.0.store(failed, Ordering::SeqCst);
    }
}

impl RuntimeCapacityProbe for ToggleCapacityProbe {
    fn observe(
        &self,
        database: &Path,
    ) -> Result<RuntimeCapacityObservation, RuntimeCapacityProbeError> {
        if self.0.load(Ordering::SeqCst) {
            Err(RuntimeCapacityProbeError::UnsupportedPlatform)
        } else {
            SystemRuntimeCapacityProbe.observe(database)
        }
    }
}

fn native_descriptor() -> ConversationDescriptor {
    ConversationDescriptor {
        agent_kind: AgentKind::ClaudeCode,
        title: Some("native effect baseline".to_owned()),
        cwd: PathBuf::from("/tmp/native-effect-project"),
    }
}

fn native_configuration() -> ConversationConfiguration {
    ConversationConfiguration::new(VendorConfigurationSnapshot::ClaudeCode(
        ClaudeCodeConversationConfiguration::new(
            ClaudeCodePermissionMode::Default,
            None,
            None,
            None,
        )
        .expect("valid native effect configuration"),
    ))
}

async fn open_native(
    root: &TestRoot,
    keys: &MemoryKeyStore,
    clock: ManualClock,
    faults: Arc<ArmedFault>,
    capacity: ToggleCapacityProbe,
) -> (RuntimeStoreHandle, RuntimeId) {
    let store = RuntimeStoreHandle::open(
        RuntimeStoreConfig::new(root.database())
            .with_clock(clock)
            .with_fault_injector(faults)
            .with_capacity_probe(capacity),
        root.storage_kek(keys),
    )
    .await
    .expect("open native effect store");
    let imported = store
        .claude_code_native_projection_store()
        .import(ImportNativeProjection {
            descriptor: native_descriptor(),
            default_configuration: native_configuration(),
            private_reference: SecretBytes::new(b"native-effect-reference-v1".to_vec()),
            scan_generation: [0x41; 16],
        })
        .await
        .expect("import native effect projection");
    let conversation_id = match imported {
        ImportNativeProjectionOutcome::Imported { conversation, .. } => {
            conversation.conversation_id
        }
        other => panic!("fresh native effect projection must import, got {other:?}"),
    };
    (store, conversation_id)
}

fn rename_request(conversation_id: RuntimeId) -> UpdateManagedConversationMetadata {
    UpdateManagedConversationMetadata {
        conversation_id,
        owner: IdempotencyOwner::Local {
            machine_trust_domain: [0x51; 32],
            uid: 501,
            client_installation_id: [0x52; 16],
        },
        idempotency_key: "native-effect-rename".to_owned(),
        expected_entry_revision: 0,
        mutation: ConversationMetadataMutation::rename(Some("native effect renamed".to_owned()))
            .expect("valid native effect rename"),
    }
}

fn effect_totals(path: &Path) -> (i64, i64, i64, String) {
    rusqlite::Connection::open(path)
        .expect("open native effect evidence")
        .query_row(
            "SELECT native_metadata_effect_fence_count,
                    native_metadata_effect_unreleased_count,
                    native_metadata_effect_released_count,
                    (SELECT state FROM metadata_mutation_ledger LIMIT 1)
             FROM runtime_meta WHERE singleton = 1",
            [],
            |row| Ok((row.get(0)?, row.get(1)?, row.get(2)?, row.get(3)?)),
        )
        .expect("read native effect totals")
}

fn metadata_effect_ledger_evidence(path: &Path) -> (i64, i64, i64, i64, i64, i64) {
    rusqlite::Connection::open(path)
        .expect("open native effect ledger evidence")
        .query_row(
            "SELECT active_metadata_mutation_count,
                    metadata_mutation_charged_bytes,
                    native_metadata_effect_fence_count,
                    (SELECT COUNT(*) FROM metadata_mutation_ledger
                     WHERE state IN ('claimed', 'applying', 'outcomeUnknown')),
                    (SELECT COALESCE(SUM(length(sealed_request) + charged_outcome_bytes), 0)
                     FROM metadata_mutation_ledger),
                    (SELECT COUNT(*) FROM native_metadata_effect_fences)
             FROM runtime_meta WHERE singleton = 1",
            [],
            |row| {
                Ok((
                    row.get(0)?,
                    row.get(1)?,
                    row.get(2)?,
                    row.get(3)?,
                    row.get(4)?,
                    row.get(5)?,
                ))
            },
        )
        .expect("read native effect ledger evidence")
}

fn process() -> ProcessIdentity {
    ProcessIdentity::new(71, 71, 73).expect("valid synthetic gate process identity")
}

fn clean_reap_failure() -> RuntimeFailure {
    RuntimeFailure::new(
        agentdeck_protocol::runtime::failure::DAEMON_RUNTIME_EXECUTION_FAILED,
        "native metadata exec gate failed clean before release",
    )
}

async fn persist_exact_effect(
    store: &RuntimeStoreHandle,
    mutation: NativeMetadataMutationClaim,
    daemon_boot_id: RuntimeId,
    effect_nonce: &[u8],
    effect_spec: &[u8],
    process: ProcessIdentity,
) -> PersistNativeMetadataEffectFenceOutcome {
    store
        .persist_native_metadata_effect_fence(PersistNativeMetadataEffectFence {
            mutation,
            daemon_boot_id,
            effect_nonce: effect_nonce.to_vec(),
            effect_spec: effect_spec.to_vec(),
            process,
        })
        .await
        .expect("persist exact native effect")
}

#[tokio::test]
async fn native_effect_fence_and_release_are_exact_replayable_and_survive_reopen() {
    let root = TestRoot::new("flow");
    let keys = MemoryKeyStore::new();
    let clock = ManualClock::new(100);
    let faults = Arc::new(ArmedFault::default());
    let capacity = ToggleCapacityProbe::default();
    let (store, conversation_id) =
        open_native(&root, &keys, clock.clone(), faults.clone(), capacity).await;
    clock.set(200);
    let ClaimNativeMetadataMutationOutcome::Claimed { mutation } = store
        .claim_native_conversation_metadata(rename_request(conversation_id))
        .await
        .expect("claim native effect")
    else {
        panic!("fresh native effect must claim");
    };
    let daemon_boot_id =
        RuntimeId::from_bytes(RuntimeIdKind::DaemonBoot, [0x61; 16]).expect("daemon boot id");
    let effect_nonce = b"native-effect-nonce".to_vec();
    let effect_spec = b"canonical-native-effect-spec".to_vec();

    clock.set(210);
    let original_claim = mutation.clone();
    let prepared = store
        .persist_native_metadata_effect_fence(PersistNativeMetadataEffectFence {
            mutation,
            daemon_boot_id,
            effect_nonce: effect_nonce.clone(),
            effect_spec: effect_spec.clone(),
            process: process(),
        })
        .await
        .expect("persist native effect fence");
    assert_eq!(
        prepared.mutation.status(),
        NativeMetadataMutationStatus::Applying
    );
    assert_eq!(prepared.fence.conversation_id(), conversation_id);
    assert_eq!(prepared.fence.daemon_boot_id(), daemon_boot_id);
    assert_eq!(prepared.fence.effect_nonce(), effect_nonce);
    assert_eq!(prepared.fence.effect_spec(), effect_spec);
    assert_eq!(prepared.fence.process(), process());
    assert_eq!(prepared.fence.release_authorized_at_ms(), None);
    assert_eq!(prepared.fence.release_token_commitment(), None);
    assert_eq!(
        effect_totals(&root.database()),
        (1, 1, 0, "applying".to_owned())
    );

    let replay = store
        .persist_native_metadata_effect_fence(PersistNativeMetadataEffectFence {
            mutation: original_claim,
            daemon_boot_id,
            effect_nonce: effect_nonce.clone(),
            effect_spec: effect_spec.clone(),
            process: process(),
        })
        .await
        .expect("replay native effect fence");
    assert_eq!(replay.mutation, prepared.mutation);
    assert_eq!(
        effect_totals(&root.database()),
        (1, 1, 0, "applying".to_owned())
    );
    assert!(matches!(
        store
            .persist_native_metadata_effect_fence(PersistNativeMetadataEffectFence {
                mutation: prepared.mutation.clone(),
                daemon_boot_id,
                effect_nonce: effect_nonce.clone(),
                effect_spec: b"conflicting-spec".to_vec(),
                process: process(),
            })
            .await,
        Err(RuntimeStoreError::FenceConflict)
    ));

    clock.set(220);
    let gate_commitment = [0xE7; 32];
    let released = store
        .authorize_native_metadata_effect_release(AuthorizeNativeMetadataEffectRelease {
            mutation: prepared.mutation.clone(),
            daemon_boot_id,
            effect_nonce: effect_nonce.clone(),
            release_token_commitment: gate_commitment,
        })
        .await
        .expect("authorize native effect release");
    assert_eq!(
        released.mutation.status(),
        NativeMetadataMutationStatus::Applying
    );
    assert_eq!(released.permit.conversation_id(), conversation_id);
    assert_eq!(
        released.permit.idempotency_token(),
        prepared.fence.idempotency_token()
    );
    assert_eq!(released.permit.daemon_boot_id(), daemon_boot_id);
    assert_eq!(released.permit.effect_nonce(), effect_nonce);
    assert_eq!(released.permit.process(), process());
    assert_eq!(released.permit.release_token_commitment(), &gate_commitment);
    assert_eq!(released.permit.release_authorized_at_ms(), 220);
    assert_eq!(
        effect_totals(&root.database()),
        (1, 0, 1, "applying".to_owned())
    );

    clock.set(230);
    let replayed_release = store
        .authorize_native_metadata_effect_release(AuthorizeNativeMetadataEffectRelease {
            mutation: prepared.mutation.clone(),
            daemon_boot_id,
            effect_nonce: effect_nonce.clone(),
            release_token_commitment: gate_commitment,
        })
        .await
        .expect("replay native effect release");
    assert_eq!(replayed_release.permit.release_authorized_at_ms(), 220);
    assert!(matches!(
        store
            .authorize_native_metadata_effect_release(AuthorizeNativeMetadataEffectRelease {
                mutation: prepared.mutation,
                daemon_boot_id,
                effect_nonce,
                release_token_commitment: [0xE8; 32],
            })
            .await,
        Err(RuntimeStoreError::FenceConflict)
    ));
    store
        .shutdown()
        .await
        .expect("shutdown native effect store");

    let reopened = RuntimeStoreHandle::open(
        RuntimeStoreConfig::new(root.database()).with_clock(clock),
        root.storage_kek(&keys),
    )
    .await
    .expect("reopen authenticated native effect store");
    let active = reopened
        .load_active_native_metadata_mutations(None)
        .await
        .expect("read active native effect recovery");
    assert_eq!(active.mutations().len(), 1);
    assert_eq!(
        active.mutations()[0].status(),
        NativeMetadataMutationStatus::Applying
    );
    let recovery = reopened
        .load_native_metadata_effect_recovery_record(active.mutations()[0].clone())
        .await
        .expect("read authenticated native effect recovery record");
    assert_eq!(recovery.mutation, active.mutations()[0]);
    assert!(
        recovery.unreleased_cleanup_authority.is_none(),
        "released recovery must never mint unreleased cleanup authority"
    );
    let recovered_fence = recovery
        .fence
        .expect("applying recovery must carry a fence");
    assert_eq!(recovered_fence.process(), process());
    assert_eq!(recovered_fence.effect_nonce(), b"native-effect-nonce");
    assert_eq!(
        recovered_fence.effect_spec(),
        b"canonical-native-effect-spec"
    );
    assert_eq!(recovered_fence.release_authorized_at_ms(), Some(220));
    assert_eq!(
        recovered_fence.release_token_commitment(),
        Some(&[0xE7; 32])
    );
    reopened
        .shutdown()
        .await
        .expect("shutdown reopened native effect store");
}

#[tokio::test]
async fn native_effect_commit_faults_converge_by_exact_retry_without_duplicate_fence() {
    let root = TestRoot::new("commit-faults");
    let keys = MemoryKeyStore::new();
    let clock = ManualClock::new(100);
    let faults = Arc::new(ArmedFault::default());
    let capacity = ToggleCapacityProbe::default();
    let (store, conversation_id) = open_native(
        &root,
        &keys,
        clock.clone(),
        faults.clone(),
        capacity.clone(),
    )
    .await;
    clock.set(200);
    let ClaimNativeMetadataMutationOutcome::Claimed { mutation } = store
        .claim_native_conversation_metadata(rename_request(conversation_id))
        .await
        .expect("claim native effect for faults")
    else {
        panic!("fresh native effect must claim");
    };
    let daemon_boot_id =
        RuntimeId::from_bytes(RuntimeIdKind::DaemonBoot, [0x71; 16]).expect("daemon boot id");
    let persist = |mutation| PersistNativeMetadataEffectFence {
        mutation,
        daemon_boot_id,
        effect_nonce: b"fault-effect-nonce".to_vec(),
        effect_spec: b"fault-effect-spec".to_vec(),
        process: process(),
    };

    faults.arm(RuntimeStoreOperation::PersistNativeMetadataEffectFenceBeforeCommit);
    assert!(matches!(
        store
            .persist_native_metadata_effect_fence(persist(mutation.clone()))
            .await,
        Err(RuntimeStoreError::WorkerStopped)
    ));
    assert_eq!(
        effect_totals(&root.database()),
        (0, 0, 0, "claimed".to_owned())
    );

    clock.set(210);
    faults.arm(RuntimeStoreOperation::PersistNativeMetadataEffectFenceAfterCommit);
    assert!(matches!(
        store
            .persist_native_metadata_effect_fence(persist(mutation.clone()))
            .await,
        Err(RuntimeStoreError::CommitOutcomeUnknown {
            operation: RuntimeCommitOperation::PersistNativeMetadataEffectFence
        })
    ));
    assert_eq!(
        effect_totals(&root.database()),
        (1, 1, 0, "applying".to_owned())
    );
    clock.set_failed(true);
    capacity.set_failed(true);
    let prepared = store
        .persist_native_metadata_effect_fence(persist(mutation))
        .await
        .expect("read back committed native effect fence without clock");
    clock.set_failed(false);
    capacity.set_failed(false);

    let authorize = |mutation| AuthorizeNativeMetadataEffectRelease {
        mutation,
        daemon_boot_id,
        effect_nonce: b"fault-effect-nonce".to_vec(),
        release_token_commitment: [0xF1; 32],
    };
    faults.arm(RuntimeStoreOperation::AuthorizeNativeMetadataEffectReleaseBeforeCommit);
    assert!(matches!(
        store
            .authorize_native_metadata_effect_release(authorize(prepared.mutation.clone()))
            .await,
        Err(RuntimeStoreError::WorkerStopped)
    ));
    assert_eq!(
        effect_totals(&root.database()),
        (1, 1, 0, "applying".to_owned())
    );

    clock.set(220);
    faults.arm(RuntimeStoreOperation::AuthorizeNativeMetadataEffectReleaseAfterCommit);
    assert!(matches!(
        store
            .authorize_native_metadata_effect_release(authorize(prepared.mutation.clone()))
            .await,
        Err(RuntimeStoreError::CommitOutcomeUnknown {
            operation: RuntimeCommitOperation::AuthorizeNativeMetadataEffectRelease
        })
    ));
    assert_eq!(
        effect_totals(&root.database()),
        (1, 0, 1, "applying".to_owned())
    );
    clock.set_failed(true);
    capacity.set_failed(true);
    let replayed = store
        .authorize_native_metadata_effect_release(authorize(prepared.mutation))
        .await
        .expect("read back committed native effect release without clock");
    clock.set_failed(false);
    capacity.set_failed(false);
    assert_eq!(replayed.permit.release_authorized_at_ms(), 220);
    store
        .shutdown()
        .await
        .expect("shutdown native effect fault store");
}

#[tokio::test]
async fn unreleased_native_effect_clean_reap_is_atomic_replayable_and_survives_reopen() {
    let root = TestRoot::new("clean-reap-flow");
    let keys = MemoryKeyStore::new();
    let clock = ManualClock::new(100);
    let faults = Arc::new(ArmedFault::default());
    let capacity = ToggleCapacityProbe::default();
    let (store, conversation_id) = open_native(
        &root,
        &keys,
        clock.clone(),
        faults.clone(),
        capacity.clone(),
    )
    .await;
    clock.set(200);
    let ClaimNativeMetadataMutationOutcome::Claimed { mutation } = store
        .claim_native_conversation_metadata(rename_request(conversation_id))
        .await
        .expect("claim clean-reap mutation")
    else {
        panic!("fresh clean-reap mutation must claim");
    };
    let daemon_boot_id =
        RuntimeId::from_bytes(RuntimeIdKind::DaemonBoot, [0x81; 16]).expect("daemon boot id");
    let effect_nonce = b"clean-reap-effect-nonce";
    let effect_spec = b"clean-reap-effect-spec";
    clock.set(210);
    let prepared = persist_exact_effect(
        &store,
        mutation,
        daemon_boot_id,
        effect_nonce,
        effect_spec,
        process(),
    )
    .await;
    // Store exact readback 可以签发另一枚不可 Clone、但 binding 完全相同的 capability，
    // 用来证明 COMMIT-unknown 后的按值重试。
    let replay_capability = persist_exact_effect(
        &store,
        prepared.mutation.clone(),
        daemon_boot_id,
        effect_nonce,
        effect_spec,
        process(),
    )
    .await
    .unreleased_cleanup_authority;
    let before = metadata_effect_ledger_evidence(&root.database());
    assert_eq!(before.0, 1, "fresh applying parent must be active");
    assert_eq!(before.2, 1, "fresh applying parent must own one fence");
    assert_eq!(before.0, before.3, "active ledger/physical mismatch");
    assert_eq!(before.1, before.4, "charged ledger/physical mismatch");
    assert_eq!(before.2, before.5, "fence ledger/physical mismatch");

    clock.set(220);
    let failure = clean_reap_failure();
    let outcome = store
        .fail_unreleased_native_metadata_effect(FailUnreleasedNativeMetadataEffect {
            cleanup_authority: prepared.unreleased_cleanup_authority,
            mutation: prepared.mutation.clone(),
            daemon_boot_id,
            effect_nonce: effect_nonce.to_vec(),
            effect_spec: effect_spec.to_vec(),
            process: process(),
            failure: failure.clone(),
        })
        .await
        .expect("atomically clean-reap unreleased native effect");
    assert_eq!(
        outcome,
        UpdateConversationMetadataOutcome::Failed {
            failure: failure.clone()
        }
    );
    assert_eq!(
        effect_totals(&root.database()),
        (0, 0, 0, "failed".to_owned())
    );
    let after = metadata_effect_ledger_evidence(&root.database());
    assert_eq!(after.0, 0, "clean-reap must terminalize parent");
    assert_eq!(after.2, 0, "clean-reap must delete exact fence");
    assert_eq!(after.0, after.3, "terminal active ledger/physical mismatch");
    assert_eq!(
        after.1, after.4,
        "terminal charged ledger/physical mismatch"
    );
    assert_eq!(after.2, after.5, "terminal fence ledger/physical mismatch");

    clock.set_failed(true);
    capacity.set_failed(true);
    let replayed = store
        .fail_unreleased_native_metadata_effect(FailUnreleasedNativeMetadataEffect {
            cleanup_authority: replay_capability,
            mutation: prepared.mutation,
            daemon_boot_id,
            effect_nonce: effect_nonce.to_vec(),
            effect_spec: effect_spec.to_vec(),
            process: process(),
            failure: failure.clone(),
        })
        .await
        .expect("terminal clean-reap replay must precede clock/capacity admission");
    assert_eq!(
        replayed,
        UpdateConversationMetadataOutcome::Failed {
            failure: failure.clone()
        }
    );
    clock.set_failed(false);
    capacity.set_failed(false);
    store.shutdown().await.expect("shutdown clean-reap store");

    let reopened = RuntimeStoreHandle::open(
        RuntimeStoreConfig::new(root.database()).with_clock(clock),
        root.storage_kek(&keys),
    )
    .await
    .expect("reopen clean-reaped store with full integrity audit");
    assert!(
        reopened
            .load_active_native_metadata_mutations(None)
            .await
            .expect("read clean-reap recovery page")
            .mutations()
            .is_empty(),
        "clean-reaped parent must not return to active recovery"
    );
    assert!(matches!(
        reopened
            .claim_native_conversation_metadata(rename_request(conversation_id))
            .await
            .expect("read terminal clean-reap after reopen"),
        ClaimNativeMetadataMutationOutcome::Replayed {
            outcome: UpdateConversationMetadataOutcome::Failed { failure: stored }
        } if stored == failure
    ));
    reopened
        .shutdown()
        .await
        .expect("shutdown reopened clean-reap store");
}

#[tokio::test]
async fn clean_reap_fault_boundaries_converge_without_fence_or_ledger_drift() {
    let root = TestRoot::new("clean-reap-faults");
    let keys = MemoryKeyStore::new();
    let clock = ManualClock::new(100);
    let faults = Arc::new(ArmedFault::default());
    let capacity = ToggleCapacityProbe::default();
    let (store, conversation_id) = open_native(
        &root,
        &keys,
        clock.clone(),
        faults.clone(),
        capacity.clone(),
    )
    .await;
    clock.set(200);
    let ClaimNativeMetadataMutationOutcome::Claimed { mutation } = store
        .claim_native_conversation_metadata(rename_request(conversation_id))
        .await
        .expect("claim clean-reap fault mutation")
    else {
        panic!("fresh clean-reap fault mutation must claim");
    };
    let daemon_boot_id =
        RuntimeId::from_bytes(RuntimeIdKind::DaemonBoot, [0x82; 16]).expect("daemon boot id");
    let effect_nonce = b"clean-reap-fault-nonce";
    let effect_spec = b"clean-reap-fault-spec";
    clock.set(210);
    let first = persist_exact_effect(
        &store,
        mutation,
        daemon_boot_id,
        effect_nonce,
        effect_spec,
        process(),
    )
    .await;
    let third = persist_exact_effect(
        &store,
        first.mutation.clone(),
        daemon_boot_id,
        effect_nonce,
        effect_spec,
        process(),
    )
    .await;
    let failure = clean_reap_failure();

    faults.arm(RuntimeStoreOperation::FailUnreleasedNativeMetadataEffectBeforeCommit);
    assert!(matches!(
        store
            .fail_unreleased_native_metadata_effect(FailUnreleasedNativeMetadataEffect {
                cleanup_authority: first.unreleased_cleanup_authority,
                mutation: first.mutation.clone(),
                daemon_boot_id,
                effect_nonce: effect_nonce.to_vec(),
                effect_spec: effect_spec.to_vec(),
                process: process(),
                failure: failure.clone(),
            })
            .await,
        Err(RuntimeStoreError::WorkerStopped)
    ));
    assert_eq!(
        effect_totals(&root.database()),
        (1, 1, 0, "applying".to_owned()),
        "before-COMMIT fault must preserve Applying+unreleased fence"
    );

    store
        .shutdown()
        .await
        .expect("shutdown applying clean-reap fault store");
    let store = RuntimeStoreHandle::open(
        RuntimeStoreConfig::new(root.database())
            .with_clock(clock.clone())
            .with_fault_injector(faults.clone())
            .with_capacity_probe(capacity.clone()),
        root.storage_kek(&keys),
    )
    .await
    .expect("reopen applying clean-reap fault store");
    let active = store
        .load_active_native_metadata_mutations(None)
        .await
        .expect("load applying clean-reap recovery");
    assert_eq!(active.mutations().len(), 1);
    let mut recovery = store
        .load_native_metadata_effect_recovery_record(active.mutations()[0].clone())
        .await
        .expect("authenticate applying unreleased recovery");
    let recovered_authority = recovery
        .unreleased_cleanup_authority
        .take()
        .expect("applying unreleased recovery must mint cleanup authority");
    let recovered_fence = recovery
        .fence
        .take()
        .expect("applying unreleased recovery must retain exact fence");
    assert_eq!(recovered_fence.daemon_boot_id(), daemon_boot_id);
    assert_eq!(recovered_fence.effect_nonce(), effect_nonce);
    assert_eq!(recovered_fence.effect_spec(), effect_spec);
    assert_eq!(recovered_fence.process(), process());

    clock.set(220);
    faults.arm(RuntimeStoreOperation::FailUnreleasedNativeMetadataEffectAfterCommit);
    assert!(matches!(
        store
            .fail_unreleased_native_metadata_effect(FailUnreleasedNativeMetadataEffect {
                cleanup_authority: recovered_authority,
                mutation: recovery.mutation,
                daemon_boot_id,
                effect_nonce: effect_nonce.to_vec(),
                effect_spec: effect_spec.to_vec(),
                process: process(),
                failure: failure.clone(),
            })
            .await,
        Err(RuntimeStoreError::CommitOutcomeUnknown {
            operation: RuntimeCommitOperation::FailUnreleasedNativeMetadataEffect
        })
    ));
    assert_eq!(
        effect_totals(&root.database()),
        (0, 0, 0, "failed".to_owned()),
        "after-COMMIT fault must leave exact terminal and no fence"
    );
    clock.set_failed(true);
    capacity.set_failed(true);
    assert_eq!(
        store
            .fail_unreleased_native_metadata_effect(FailUnreleasedNativeMetadataEffect {
                cleanup_authority: third.unreleased_cleanup_authority,
                mutation: third.mutation,
                daemon_boot_id,
                effect_nonce: effect_nonce.to_vec(),
                effect_spec: effect_spec.to_vec(),
                process: process(),
                failure,
            })
            .await
            .expect("after-COMMIT unknown exact replay"),
        UpdateConversationMetadataOutcome::Failed {
            failure: clean_reap_failure()
        }
    );
    store
        .shutdown()
        .await
        .expect("shutdown clean-reap fault store");
}

#[tokio::test]
async fn clean_reap_capability_rejects_every_binding_drift_and_released_fence() {
    let root = TestRoot::new("clean-reap-binding");
    let keys = MemoryKeyStore::new();
    let clock = ManualClock::new(100);
    let faults = Arc::new(ArmedFault::default());
    let capacity = ToggleCapacityProbe::default();
    let (store, conversation_id) = open_native(&root, &keys, clock.clone(), faults, capacity).await;
    clock.set(200);
    let ClaimNativeMetadataMutationOutcome::Claimed { mutation } = store
        .claim_native_conversation_metadata(rename_request(conversation_id))
        .await
        .expect("claim clean-reap binding mutation")
    else {
        panic!("fresh clean-reap binding mutation must claim");
    };
    let stale_claim = mutation.clone();
    let daemon_boot_id =
        RuntimeId::from_bytes(RuntimeIdKind::DaemonBoot, [0x83; 16]).expect("daemon boot id");
    let other_boot_id =
        RuntimeId::from_bytes(RuntimeIdKind::DaemonBoot, [0x84; 16]).expect("other boot id");
    let effect_nonce = b"clean-reap-binding-nonce";
    let effect_spec = b"clean-reap-binding-spec";
    clock.set(210);
    let prepared = persist_exact_effect(
        &store,
        mutation,
        daemon_boot_id,
        effect_nonce,
        effect_spec,
        process(),
    )
    .await;
    let applying = prepared.mutation.clone();
    let mut capabilities = Vec::new();
    capabilities.push(prepared.unreleased_cleanup_authority);
    for _ in 0..5 {
        capabilities.push(
            persist_exact_effect(
                &store,
                applying.clone(),
                daemon_boot_id,
                effect_nonce,
                effect_spec,
                process(),
            )
            .await
            .unreleased_cleanup_authority,
        );
    }
    let failure = clean_reap_failure();
    let stale_claim_error = store
        .fail_unreleased_native_metadata_effect(FailUnreleasedNativeMetadataEffect {
            cleanup_authority: capabilities.remove(0),
            mutation: stale_claim,
            daemon_boot_id,
            effect_nonce: effect_nonce.to_vec(),
            effect_spec: effect_spec.to_vec(),
            process: process(),
            failure: failure.clone(),
        })
        .await;
    assert!(matches!(
        stale_claim_error,
        Err(RuntimeStoreError::InvalidStateTransition | RuntimeStoreError::FenceConflict)
    ));
    for (label, result) in [
        (
            "boot",
            store
                .fail_unreleased_native_metadata_effect(FailUnreleasedNativeMetadataEffect {
                    cleanup_authority: capabilities.remove(0),
                    mutation: applying.clone(),
                    daemon_boot_id: other_boot_id,
                    effect_nonce: effect_nonce.to_vec(),
                    effect_spec: effect_spec.to_vec(),
                    process: process(),
                    failure: failure.clone(),
                })
                .await,
        ),
        (
            "nonce",
            store
                .fail_unreleased_native_metadata_effect(FailUnreleasedNativeMetadataEffect {
                    cleanup_authority: capabilities.remove(0),
                    mutation: applying.clone(),
                    daemon_boot_id,
                    effect_nonce: b"mismatched-nonce".to_vec(),
                    effect_spec: effect_spec.to_vec(),
                    process: process(),
                    failure: failure.clone(),
                })
                .await,
        ),
        (
            "spec",
            store
                .fail_unreleased_native_metadata_effect(FailUnreleasedNativeMetadataEffect {
                    cleanup_authority: capabilities.remove(0),
                    mutation: applying.clone(),
                    daemon_boot_id,
                    effect_nonce: effect_nonce.to_vec(),
                    effect_spec: b"mismatched-spec".to_vec(),
                    process: process(),
                    failure: failure.clone(),
                })
                .await,
        ),
        (
            "process",
            store
                .fail_unreleased_native_metadata_effect(FailUnreleasedNativeMetadataEffect {
                    cleanup_authority: capabilities.remove(0),
                    mutation: applying.clone(),
                    daemon_boot_id,
                    effect_nonce: effect_nonce.to_vec(),
                    effect_spec: effect_spec.to_vec(),
                    process: ProcessIdentity::new(75, 75, 77)
                        .expect("other synthetic process identity"),
                    failure: failure.clone(),
                })
                .await,
        ),
    ] {
        assert!(
            matches!(result, Err(RuntimeStoreError::FenceConflict)),
            "{label} drift must reject exact capability: {result:?}"
        );
    }
    assert_eq!(
        effect_totals(&root.database()),
        (1, 1, 0, "applying".to_owned()),
        "binding rejects must be zero-write"
    );

    // Fresh authorization at timestamp zero is forbidden even though exact released replay
    // remains clock/capacity independent.
    clock.set(0);
    assert!(matches!(
        store
            .authorize_native_metadata_effect_release(AuthorizeNativeMetadataEffectRelease {
                mutation: applying.clone(),
                daemon_boot_id,
                effect_nonce: effect_nonce.to_vec(),
                release_token_commitment: [0xA1; 32],
            })
            .await,
        Err(RuntimeStoreError::InvalidStateTransition)
    ));
    assert_eq!(
        effect_totals(&root.database()),
        (1, 1, 0, "applying".to_owned())
    );

    clock.set(220);
    store
        .authorize_native_metadata_effect_release(AuthorizeNativeMetadataEffectRelease {
            mutation: applying.clone(),
            daemon_boot_id,
            effect_nonce: effect_nonce.to_vec(),
            release_token_commitment: [0xA1; 32],
        })
        .await
        .expect("authorize nonzero release");
    let released_error = store
        .fail_unreleased_native_metadata_effect(FailUnreleasedNativeMetadataEffect {
            cleanup_authority: capabilities.remove(0),
            mutation: applying,
            daemon_boot_id,
            effect_nonce: effect_nonce.to_vec(),
            effect_spec: effect_spec.to_vec(),
            process: process(),
            failure,
        })
        .await;
    assert!(matches!(
        released_error,
        Err(RuntimeStoreError::InvalidStateTransition | RuntimeStoreError::FenceConflict)
    ));
    assert_eq!(
        effect_totals(&root.database()),
        (1, 0, 1, "applying".to_owned()),
        "released fence rejection must be zero-write"
    );
    store
        .shutdown()
        .await
        .expect("shutdown clean-reap binding store");
}
