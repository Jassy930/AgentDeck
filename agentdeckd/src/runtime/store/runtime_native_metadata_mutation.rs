use super::*;

use std::collections::HashSet;
use std::fs;
use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};

use agentdeck_protocol::runtime::{
    ClaudeCodeConversationConfiguration, ConversationConfiguration, RuntimeFailure,
    VendorConfigurationSnapshot,
};
use agentdeck_protocol::{AgentKind, ClaudeCodePermissionMode};

use crate::runtime::model::{
    ConversationDescriptor, NewConversation, RuntimeClock, RuntimeClockError,
    RuntimeStoreFaultInjector,
};
use crate::runtime::process_identity::ProcessIdentity;
use crate::runtime::store::RuntimeStoreHandle;
use crate::runtime::store::native_projection::{
    AuthorizeNativeMetadataEffectRelease, ImportNativeProjection, ImportNativeProjectionOutcome,
    PersistNativeMetadataEffectFence,
};
use crate::security::{MemoryKeyStore, SecretBytes, StorageKek, load_or_create_storage_kek};

static NEXT_TEMP_ID: AtomicU64 = AtomicU64::new(1);

struct TestRoot(PathBuf);

impl TestRoot {
    fn new(label: &str) -> Self {
        let sequence = NEXT_TEMP_ID.fetch_add(1, Ordering::Relaxed);
        let path = Path::new("/tmp").join(format!(
            "agentdeck-native-metadata-{label}-{}-{sequence}",
            std::process::id()
        ));
        let _ = fs::remove_dir_all(&path);
        fs::create_dir(&path).expect("create native metadata root");
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            fs::set_permissions(&path, fs::Permissions::from_mode(0o700))
                .expect("secure native metadata root");
        }
        Self(path)
    }

    fn database(&self) -> PathBuf {
        self.0.join("runtime.db")
    }

    fn storage_kek(&self, keys: &MemoryKeyStore) -> StorageKek {
        load_or_create_storage_kek(keys, &self.0.join("key-state.db"))
            .expect("load native metadata StorageKEK")
    }
}

impl Drop for TestRoot {
    fn drop(&mut self) {
        let _ = fs::remove_dir_all(&self.0);
    }
}

#[derive(Clone)]
struct ManualClock(Arc<AtomicU64>);

impl ManualClock {
    fn new(now_ms: u64) -> Self {
        Self(Arc::new(AtomicU64::new(now_ms)))
    }

    fn set(&self, now_ms: u64) {
        self.0.store(now_ms, Ordering::SeqCst);
    }
}

impl RuntimeClock for ManualClock {
    fn now_ms(&self) -> Result<u64, RuntimeClockError> {
        Ok(self.0.load(Ordering::SeqCst))
    }
}

struct OneShotFault {
    operation: RuntimeStoreOperation,
    armed: AtomicBool,
}

impl OneShotFault {
    fn new(operation: RuntimeStoreOperation) -> Self {
        Self {
            operation,
            armed: AtomicBool::new(true),
        }
    }
}

impl RuntimeStoreFaultInjector for OneShotFault {
    fn before_operation(&self, operation: RuntimeStoreOperation) -> Result<(), RuntimeStoreError> {
        if operation == self.operation && self.armed.swap(false, Ordering::SeqCst) {
            Err(RuntimeStoreError::InvalidConfig(
                "injected native metadata fault",
            ))
        } else {
            Ok(())
        }
    }
}

fn descriptor() -> ConversationDescriptor {
    ConversationDescriptor {
        agent_kind: AgentKind::ClaudeCode,
        title: Some("native baseline".to_owned()),
        cwd: PathBuf::new(),
    }
}

fn configuration() -> ConversationConfiguration {
    ConversationConfiguration::new(VendorConfigurationSnapshot::ClaudeCode(
        ClaudeCodeConversationConfiguration::new(
            ClaudeCodePermissionMode::Default,
            None,
            None,
            None,
        )
        .expect("valid native metadata configuration"),
    ))
}

async fn open_native(
    root: &TestRoot,
    keys: &MemoryKeyStore,
    clock: ManualClock,
) -> (RuntimeStoreHandle, RuntimeId) {
    open_native_with_config(
        root,
        keys,
        RuntimeStoreConfig::new(root.database()).with_clock(clock),
    )
    .await
}

async fn open_native_with_config(
    root: &TestRoot,
    keys: &MemoryKeyStore,
    config: RuntimeStoreConfig,
) -> (RuntimeStoreHandle, RuntimeId) {
    let store = RuntimeStoreHandle::open(config, root.storage_kek(keys))
        .await
        .expect("open native metadata store");
    let imported = store
        .claude_code_native_projection_store()
        .import(ImportNativeProjection {
            descriptor: descriptor(),
            default_configuration: configuration(),
            private_reference: SecretBytes::new(b"native-metadata-reference-v1".to_vec()),
            scan_generation: [0x41; 16],
        })
        .await
        .expect("import native metadata projection");
    let conversation = match imported {
        ImportNativeProjectionOutcome::Imported { conversation, .. } => conversation,
        other => panic!("fresh native projection must import, got {other:?}"),
    };
    (store, conversation.conversation_id)
}

fn request(
    conversation_id: RuntimeId,
    idempotency_key: &str,
    mutation: ConversationMetadataMutation,
) -> UpdateManagedConversationMetadata {
    UpdateManagedConversationMetadata {
        conversation_id,
        owner: IdempotencyOwner::Local {
            machine_trust_domain: [0x51; 32],
            uid: 501,
            client_installation_id: [0x52; 16],
        },
        idempotency_key: idempotency_key.to_owned(),
        expected_entry_revision: 0,
        mutation,
    }
}

fn ledger_counts(path: &Path) -> (i64, i64) {
    rusqlite::Connection::open(path)
        .expect("open native metadata evidence")
        .query_row(
            "SELECT metadata_mutation_count, active_metadata_mutation_count
             FROM runtime_meta WHERE singleton = 1",
            [],
            |row| Ok((row.get(0)?, row.get(1)?)),
        )
        .expect("read native metadata ledger counts")
}

#[tokio::test]
async fn native_claim_is_single_active_exact_pending_and_unsupported_is_zero_write() {
    let root = TestRoot::new("claim");
    let keys = MemoryKeyStore::new();
    let clock = ManualClock::new(100);
    let (store, conversation_id) = open_native(&root, &keys, clock.clone()).await;

    let baseline = ledger_counts(&root.database());
    let archive_error = store
        .claim_native_conversation_metadata(request(
            conversation_id,
            "archive",
            ConversationMetadataMutation::SetArchived { archived: true },
        ))
        .await
        .expect_err("native archive must be rejected before claim");
    assert!(matches!(
        archive_error,
        RuntimeStoreError::MetadataMutationUnsupported
    ));
    assert_eq!(ledger_counts(&root.database()), baseline);

    let managed_id = RuntimeId::from_bytes(RuntimeIdKind::Conversation, [0x61; 16])
        .expect("managed conversation id");
    store
        .create_conversation(NewConversation {
            conversation_id: managed_id,
            adapter_state_key: RuntimeId::from_bytes(RuntimeIdKind::AdapterState, [0x62; 16])
                .expect("managed adapter state id"),
            descriptor: descriptor(),
        })
        .await
        .expect("create managed unsupported fixture");
    assert!(matches!(
        store
            .claim_native_conversation_metadata(request(
                managed_id,
                "managed-rename",
                ConversationMetadataMutation::rename(Some("managed".to_owned()))
                    .expect("valid managed rename"),
            ))
            .await,
        Err(RuntimeStoreError::MetadataMutationUnsupported)
    ));
    assert_eq!(ledger_counts(&root.database()), baseline);

    clock.set(200);
    let rename = request(
        conversation_id,
        "rename",
        ConversationMetadataMutation::rename(Some("renamed".to_owned())).expect("valid rename"),
    );
    let ClaimNativeMetadataMutationOutcome::Claimed { mutation } = store
        .claim_native_conversation_metadata(rename.clone())
        .await
        .expect("claim native rename")
    else {
        panic!("fresh native rename must claim");
    };
    assert_eq!(mutation.conversation_id(), conversation_id);
    assert_eq!(mutation.expected_entry_revision(), 0);
    assert_eq!(mutation.requested_title(), Some("renamed"));
    assert_eq!(mutation.status(), NativeMetadataMutationStatus::Claimed);
    assert_eq!(
        ledger_counts(&root.database()),
        (baseline.0 + 1, baseline.1 + 1)
    );
    let (reserved_outcome, sealed_request, charged_total): (i64, i64, i64) =
        rusqlite::Connection::open(root.database())
            .expect("open claim reserve evidence")
            .query_row(
                "SELECT l.charged_outcome_bytes, length(l.sealed_request),
                        m.metadata_mutation_charged_bytes
                 FROM metadata_mutation_ledger AS l
                 JOIN runtime_meta AS m ON m.singleton = 1",
                [],
                |row| Ok((row.get(0)?, row.get(1)?, row.get(2)?)),
            )
            .expect("read claim reserve evidence");
    assert_eq!(
        reserved_outcome,
        i64::try_from(MAX_METADATA_MUTATION_OUTCOME_BYTES + ROW_BLOB_V1_OVERHEAD_LEN)
            .expect("terminal outcome reserve fits SQLite")
    );
    assert_eq!(charged_total, sealed_request + reserved_outcome);

    let after_claim = ledger_counts(&root.database());
    assert!(matches!(
        store
            .claim_native_conversation_metadata(rename.clone())
            .await,
        Err(RuntimeStoreError::MetadataMutationPending)
    ));
    assert_eq!(ledger_counts(&root.database()), after_claim);
    assert!(matches!(
        store
            .claim_native_conversation_metadata(request(
                conversation_id,
                "rename",
                ConversationMetadataMutation::rename(Some("different".to_owned()))
                    .expect("valid conflicting rename"),
            ))
            .await,
        Err(RuntimeStoreError::IdempotencyConflict)
    ));
    assert!(matches!(
        store
            .claim_native_conversation_metadata(request(
                conversation_id,
                "second-key",
                ConversationMetadataMutation::rename(Some("other".to_owned()))
                    .expect("valid second rename"),
            ))
            .await,
        Err(RuntimeStoreError::MetadataMutationPending)
    ));
    assert_eq!(ledger_counts(&root.database()), after_claim);

    store.shutdown().await.expect("shutdown native claim store");
}

#[tokio::test]
async fn claim_after_commit_unknown_is_one_durable_active_row_and_exact_retry_never_reclaims() {
    let root = TestRoot::new("claim-commit-unknown");
    let keys = MemoryKeyStore::new();
    let clock = ManualClock::new(2_000);
    let config = RuntimeStoreConfig::new(root.database())
        .with_clock(clock)
        .with_fault_injector(Arc::new(OneShotFault::new(
            RuntimeStoreOperation::ClaimNativeMetadataMutationAfterCommit,
        )));
    let (store, conversation_id) = open_native_with_config(&root, &keys, config).await;
    let rename = request(
        conversation_id,
        "claim-unknown",
        ConversationMetadataMutation::rename(Some("unknown claim".to_owned()))
            .expect("valid unknown claim rename"),
    );
    assert!(matches!(
        store
            .claim_native_conversation_metadata(rename.clone())
            .await,
        Err(RuntimeStoreError::CommitOutcomeUnknown {
            operation: RuntimeCommitOperation::ClaimNativeMetadataMutation
        })
    ));
    assert_eq!(ledger_counts(&root.database()), (1, 1));
    assert!(matches!(
        store.claim_native_conversation_metadata(rename).await,
        Err(RuntimeStoreError::MetadataMutationPending)
    ));
    let recovery = store
        .load_active_native_metadata_mutations(None)
        .await
        .expect("recover committed unknown claim");
    assert_eq!(recovery.mutations().len(), 1);
    assert_eq!(
        recovery.mutations()[0].status(),
        NativeMetadataMutationStatus::Claimed
    );
    store
        .shutdown()
        .await
        .expect("shutdown claim unknown store");
}

#[tokio::test]
async fn claimed_clean_failure_is_terminal_replayable_and_absent_from_restart_recovery() {
    let root = TestRoot::new("clean-failure-recovery");
    let keys = MemoryKeyStore::new();
    let clock = ManualClock::new(1_000);
    let (store, conversation_id) = open_native(&root, &keys, clock.clone()).await;
    let rename = request(
        conversation_id,
        "clean-failure",
        ConversationMetadataMutation::rename(Some("never applied".to_owned()))
            .expect("valid failed rename"),
    );
    let ClaimNativeMetadataMutationOutcome::Claimed { mutation } = store
        .claim_native_conversation_metadata(rename.clone())
        .await
        .expect("claim native rename before clean failure")
    else {
        panic!("fresh native rename must claim");
    };
    let active = store
        .load_active_native_metadata_mutations(None)
        .await
        .expect("read active native metadata recovery page");
    assert_eq!(active.mutations(), std::slice::from_ref(&mutation));
    assert_eq!(active.next_cursor(), None);

    clock.set(1_100);
    let failure = RuntimeFailure::new(
        "daemon.conversation.native_metadata_prepare_failed",
        "native metadata effect preparation failed cleanly",
    );
    assert_eq!(
        store
            .fail_claimed_native_metadata_mutation(mutation.clone(), failure.clone())
            .await
            .expect("terminalize claimed clean failure"),
        UpdateConversationMetadataOutcome::Failed {
            failure: failure.clone()
        }
    );
    clock.set(0);
    assert_eq!(
        store
            .fail_claimed_native_metadata_mutation(mutation, failure.clone())
            .await
            .expect("exact clean-failure replay bypasses regressed clock"),
        UpdateConversationMetadataOutcome::Failed {
            failure: failure.clone()
        }
    );
    assert_eq!(ledger_counts(&root.database()).1, 0);
    assert!(
        store
            .load_active_native_metadata_mutations(None)
            .await
            .expect("read empty active recovery page")
            .mutations()
            .is_empty()
    );
    assert_eq!(
        store
            .claim_native_conversation_metadata(rename.clone())
            .await
            .expect("exact terminal claim replay"),
        ClaimNativeMetadataMutationOutcome::Replayed {
            outcome: UpdateConversationMetadataOutcome::Failed {
                failure: failure.clone()
            }
        }
    );

    store
        .shutdown()
        .await
        .expect("shutdown clean failure store");
    let reopened = RuntimeStoreHandle::open(
        RuntimeStoreConfig::new(root.database()).with_clock(clock),
        root.storage_kek(&keys),
    )
    .await
    .expect("authenticated reopen after clean failure");
    assert!(
        reopened
            .load_active_native_metadata_mutations(None)
            .await
            .expect("reopened active recovery read")
            .mutations()
            .is_empty()
    );
    assert_eq!(
        reopened
            .claim_native_conversation_metadata(rename)
            .await
            .expect("reopened terminal claim replay"),
        ClaimNativeMetadataMutationOutcome::Replayed {
            outcome: UpdateConversationMetadataOutcome::Failed { failure }
        }
    );
    reopened
        .shutdown()
        .await
        .expect("shutdown reopened clean failure store");
}

#[tokio::test]
async fn released_outcome_unknown_readback_applies_once_without_event_or_activity_drift() {
    let root = TestRoot::new("readback-applied");
    let keys = MemoryKeyStore::new();
    let clock = ManualClock::new(3_000);
    let config = RuntimeStoreConfig::new(root.database())
        .with_clock(clock.clone())
        .with_fault_injector(Arc::new(OneShotFault::new(
            RuntimeStoreOperation::FinalizeNativeMetadataMutationReadbackAfterCommit,
        )));
    let (store, conversation_id) = open_native_with_config(&root, &keys, config).await;
    let before: (String, Option<String>, i64, i64, String) =
        rusqlite::Connection::open(root.database())
            .expect("open native readback baseline")
            .query_row(
                "SELECT c.catalog_revision, c.event_high_water, c.updated_at_ms,
                        (SELECT COUNT(*) FROM event_journal), s.entry_revision
                 FROM conversations AS c
                 JOIN conversation_state AS s USING(conversation_id)
                 WHERE c.conversation_id = ?1",
                [&conversation_id.as_bytes()[..]],
                |row| {
                    Ok((
                        row.get(0)?,
                        row.get(1)?,
                        row.get(2)?,
                        row.get(3)?,
                        row.get(4)?,
                    ))
                },
            )
            .expect("read native readback baseline");
    let rename = request(
        conversation_id,
        "readback-applied",
        ConversationMetadataMutation::rename(Some("readback title".to_owned()))
            .expect("valid readback rename"),
    );
    let ClaimNativeMetadataMutationOutcome::Claimed { mutation } = store
        .claim_native_conversation_metadata(rename.clone())
        .await
        .expect("claim readback rename")
    else {
        panic!("fresh readback rename must claim");
    };
    let daemon_boot_id = RuntimeId::from_bytes(RuntimeIdKind::DaemonBoot, [0x71; 16])
        .expect("native metadata daemon boot id");
    let effect_nonce = b"native-metadata-effect-nonce".to_vec();
    clock.set(3_100);
    let fenced = store
        .persist_native_metadata_effect_fence(PersistNativeMetadataEffectFence {
            mutation,
            daemon_boot_id,
            effect_nonce: effect_nonce.clone(),
            effect_spec: br#"{"kind":"rename","title":"[redacted]"}"#.to_vec(),
            process: ProcessIdentity::new(50_001, 50_001, 7)
                .expect("valid synthetic native effect process identity"),
        })
        .await
        .expect("persist native metadata effect fence");
    assert_eq!(
        fenced.mutation.status(),
        NativeMetadataMutationStatus::Applying
    );
    clock.set(3_200);
    let released = store
        .authorize_native_metadata_effect_release(AuthorizeNativeMetadataEffectRelease {
            mutation: fenced.mutation,
            daemon_boot_id,
            effect_nonce,
            release_token_commitment: [0x72; 32],
        })
        .await
        .expect("authorize native metadata effect release");
    assert_eq!(released.permit.conversation_id(), conversation_id);
    assert_eq!(released.permit.release_authorized_at_ms(), 3_200);

    clock.set(3_300);
    let unknown = store
        .mark_native_metadata_mutation_outcome_unknown(released.mutation)
        .await
        .expect("persist outcome unknown after released effect");
    assert_eq!(
        unknown.status(),
        NativeMetadataMutationStatus::OutcomeUnknown
    );
    clock.set(0);
    assert_eq!(
        store
            .mark_native_metadata_mutation_outcome_unknown(unknown.clone())
            .await
            .expect("exact outcomeUnknown replay bypasses regressed clock"),
        unknown
    );
    let active = store
        .load_active_native_metadata_mutations(None)
        .await
        .expect("read outcome unknown recovery page");
    assert_eq!(active.mutations(), std::slice::from_ref(&unknown));

    assert!(matches!(
        store
            .finalize_native_metadata_mutation_readback(
                unknown.clone(),
                NativeMetadataMutationReadback::Inconclusive,
            )
            .await,
        Err(RuntimeStoreError::MetadataMutationPending)
    ));
    clock.set(3_400);
    let finalize_retry = unknown.clone();
    assert!(matches!(
        store
            .finalize_native_metadata_mutation_readback(
                unknown,
                NativeMetadataMutationReadback::Applied {
                    observed_title: Some("readback title".to_owned()),
                },
            )
            .await,
        Err(RuntimeStoreError::CommitOutcomeUnknown {
            operation: RuntimeCommitOperation::FinalizeNativeMetadataMutationReadback
        })
    ));
    clock.set(0);
    let replayed_finalize = store
        .finalize_native_metadata_mutation_readback(
            finalize_retry,
            NativeMetadataMutationReadback::Applied {
                observed_title: Some("readback title".to_owned()),
            },
        )
        .await
        .expect("exact applied finalize replay bypasses regressed clock");
    let UpdateConversationMetadataOutcome::Replayed {
        mutation: replayed_applied,
    } = replayed_finalize
    else {
        panic!("exact applied finalize must replay terminal outcome");
    };
    let ClaimNativeMetadataMutationOutcome::Replayed {
        outcome: UpdateConversationMetadataOutcome::Replayed { mutation: applied },
    } = store
        .claim_native_conversation_metadata(rename.clone())
        .await
        .expect("read back applied result after COMMIT unknown")
    else {
        panic!("COMMIT unknown readback must converge to one applied terminal");
    };
    assert_eq!(applied, replayed_applied);
    assert_eq!((applied.entry_revision, applied.catalog_revision), (1, 1));
    assert_eq!(ledger_counts(&root.database()), (1, 0));

    let after: (String, Option<String>, i64, i64, String) =
        rusqlite::Connection::open(root.database())
            .expect("open native readback evidence")
            .query_row(
                "SELECT c.catalog_revision, c.event_high_water, c.updated_at_ms,
                        (SELECT COUNT(*) FROM event_journal), s.entry_revision
                 FROM conversations AS c
                 JOIN conversation_state AS s USING(conversation_id)
                 WHERE c.conversation_id = ?1",
                [&conversation_id.as_bytes()[..]],
                |row| {
                    Ok((
                        row.get(0)?,
                        row.get(1)?,
                        row.get(2)?,
                        row.get(3)?,
                        row.get(4)?,
                    ))
                },
            )
            .expect("read native readback evidence");
    assert_eq!(after.0, "00000000000000000001");
    assert_eq!(after.4, "00000000000000000001");
    assert_eq!((after.1, after.2, after.3), (before.1, before.2, before.3));
    assert_eq!(
        store
            .claim_native_conversation_metadata(rename.clone())
            .await
            .expect("replay applied native metadata claim"),
        ClaimNativeMetadataMutationOutcome::Replayed {
            outcome: UpdateConversationMetadataOutcome::Replayed {
                mutation: applied.clone()
            }
        }
    );
    assert!(
        store
            .load_active_native_metadata_mutations(None)
            .await
            .expect("read empty terminal recovery page")
            .mutations()
            .is_empty()
    );
    drop(released.permit);
    store
        .shutdown()
        .await
        .expect("shutdown applied readback store");

    let reopened = RuntimeStoreHandle::open(
        RuntimeStoreConfig::new(root.database()).with_clock(clock),
        root.storage_kek(&keys),
    )
    .await
    .expect("authenticated reopen after applied native readback");
    assert_eq!(
        reopened
            .claim_native_conversation_metadata(rename)
            .await
            .expect("reopened applied native metadata replay"),
        ClaimNativeMetadataMutationOutcome::Replayed {
            outcome: UpdateConversationMetadataOutcome::Replayed { mutation: applied }
        }
    );
    reopened
        .shutdown()
        .await
        .expect("shutdown reopened applied readback store");
}

#[tokio::test]
async fn released_failed_readback_is_terminal_without_catalog_or_event_mutation() {
    let root = TestRoot::new("readback-failed");
    let keys = MemoryKeyStore::new();
    let clock = ManualClock::new(4_000);
    let (store, conversation_id) = open_native(&root, &keys, clock.clone()).await;
    let rename = request(
        conversation_id,
        "readback-failed",
        ConversationMetadataMutation::rename(Some("not observed".to_owned()))
            .expect("valid failed readback rename"),
    );
    let ClaimNativeMetadataMutationOutcome::Claimed { mutation } = store
        .claim_native_conversation_metadata(rename.clone())
        .await
        .expect("claim failed readback rename")
    else {
        panic!("fresh failed readback rename must claim");
    };
    let daemon_boot_id = RuntimeId::from_bytes(RuntimeIdKind::DaemonBoot, [0x81; 16])
        .expect("failed readback daemon boot id");
    let nonce = b"failed-readback-effect-nonce".to_vec();
    clock.set(4_100);
    let fenced = store
        .persist_native_metadata_effect_fence(PersistNativeMetadataEffectFence {
            mutation,
            daemon_boot_id,
            effect_nonce: nonce.clone(),
            effect_spec: br#"{"kind":"rename"}"#.to_vec(),
            process: ProcessIdentity::new(50_002, 50_002, 8)
                .expect("valid failed readback process"),
        })
        .await
        .expect("persist failed readback fence");
    clock.set(4_200);
    let released = store
        .authorize_native_metadata_effect_release(AuthorizeNativeMetadataEffectRelease {
            mutation: fenced.mutation,
            daemon_boot_id,
            effect_nonce: nonce,
            release_token_commitment: [0x82; 32],
        })
        .await
        .expect("authorize failed readback release");
    clock.set(4_300);
    let unknown = store
        .mark_native_metadata_mutation_outcome_unknown(released.mutation)
        .await
        .expect("mark failed readback unknown");
    let before: (String, String, Option<String>, i64) = rusqlite::Connection::open(root.database())
        .expect("open failed readback baseline")
        .query_row(
            "SELECT c.catalog_revision, s.entry_revision, c.event_high_water,
                        (SELECT COUNT(*) FROM catalog_journal)
                 FROM conversations AS c
                 JOIN conversation_state AS s USING(conversation_id)
                 WHERE c.conversation_id = ?1",
            [&conversation_id.as_bytes()[..]],
            |row| Ok((row.get(0)?, row.get(1)?, row.get(2)?, row.get(3)?)),
        )
        .expect("read failed readback baseline");
    clock.set(4_400);
    let failure = RuntimeFailure::new(
        "daemon.conversation.native_metadata_readback_failed",
        "authenticated native metadata readback proved failure",
    );
    assert_eq!(
        store
            .finalize_native_metadata_mutation_readback(
                unknown,
                NativeMetadataMutationReadback::Failed {
                    failure: failure.clone(),
                },
            )
            .await
            .expect("finalize failed native readback"),
        UpdateConversationMetadataOutcome::Failed {
            failure: failure.clone()
        }
    );
    let after: (String, String, Option<String>, i64) = rusqlite::Connection::open(root.database())
        .expect("open failed readback evidence")
        .query_row(
            "SELECT c.catalog_revision, s.entry_revision, c.event_high_water,
                        (SELECT COUNT(*) FROM catalog_journal)
                 FROM conversations AS c
                 JOIN conversation_state AS s USING(conversation_id)
                 WHERE c.conversation_id = ?1",
            [&conversation_id.as_bytes()[..]],
            |row| Ok((row.get(0)?, row.get(1)?, row.get(2)?, row.get(3)?)),
        )
        .expect("read failed readback evidence");
    assert_eq!(after, before);
    assert_eq!(ledger_counts(&root.database()), (1, 0));
    assert_eq!(
        store
            .claim_native_conversation_metadata(rename.clone())
            .await
            .expect("replay failed readback claim"),
        ClaimNativeMetadataMutationOutcome::Replayed {
            outcome: UpdateConversationMetadataOutcome::Failed {
                failure: failure.clone()
            }
        }
    );
    drop(released.permit);
    store
        .shutdown()
        .await
        .expect("shutdown failed readback store");
    let reopened = RuntimeStoreHandle::open(
        RuntimeStoreConfig::new(root.database()).with_clock(clock),
        root.storage_kek(&keys),
    )
    .await
    .expect("authenticated reopen after failed readback");
    assert_eq!(
        reopened
            .claim_native_conversation_metadata(rename)
            .await
            .expect("reopened failed readback replay"),
        ClaimNativeMetadataMutationOutcome::Replayed {
            outcome: UpdateConversationMetadataOutcome::Failed { failure }
        }
    );
    reopened
        .shutdown()
        .await
        .expect("shutdown reopened failed readback store");
}

#[tokio::test]
async fn active_recovery_is_authenticated_keyset_paginated_and_restart_stable() {
    let root = TestRoot::new("recovery-pagination");
    let keys = MemoryKeyStore::new();
    let clock = ManualClock::new(5_000);
    let (store, first_id) = open_native(&root, &keys, clock.clone()).await;
    let first = request(
        first_id,
        "page-000",
        ConversationMetadataMutation::rename(Some("page 000".to_owned()))
            .expect("valid first paged rename"),
    );
    assert!(matches!(
        store
            .claim_native_conversation_metadata(first)
            .await
            .expect("claim first paged mutation"),
        ClaimNativeMetadataMutationOutcome::Claimed { .. }
    ));
    let projector = store.claude_code_native_projection_store();
    for index in 1_u8..65 {
        let imported = projector
            .import(ImportNativeProjection {
                descriptor: descriptor(),
                default_configuration: configuration(),
                private_reference: SecretBytes::new(
                    format!("native-metadata-page-reference-{index:03}").into_bytes(),
                ),
                scan_generation: [index.saturating_add(1); 16],
            })
            .await
            .expect("import paged native projection");
        let conversation_id = match imported {
            ImportNativeProjectionOutcome::Imported { conversation, .. } => {
                conversation.conversation_id
            }
            other => panic!("paged native projection must import, got {other:?}"),
        };
        assert!(matches!(
            store
                .claim_native_conversation_metadata(request(
                    conversation_id,
                    &format!("page-{index:03}"),
                    ConversationMetadataMutation::rename(Some(format!("page {index:03}")))
                        .expect("valid paged rename"),
                ))
                .await
                .expect("claim paged native mutation"),
            ClaimNativeMetadataMutationOutcome::Claimed { .. }
        ));
    }
    assert_eq!(ledger_counts(&root.database()), (65, 65));
    let first_page = store
        .load_active_native_metadata_mutations(None)
        .await
        .expect("load first active recovery page");
    assert_eq!(first_page.mutations().len(), 64);
    let cursor = first_page
        .next_cursor()
        .expect("65 active rows require a second page");
    let second_page = store
        .load_active_native_metadata_mutations(Some(cursor))
        .await
        .expect("load second active recovery page");
    assert_eq!(second_page.mutations().len(), 1);
    assert_eq!(second_page.next_cursor(), None);
    let unique = first_page
        .mutations()
        .iter()
        .chain(second_page.mutations())
        .map(NativeMetadataMutationClaim::conversation_id)
        .collect::<HashSet<_>>();
    assert_eq!(unique.len(), 65);
    store
        .shutdown()
        .await
        .expect("shutdown paged recovery store");

    let reopened = RuntimeStoreHandle::open(
        RuntimeStoreConfig::new(root.database()).with_clock(clock),
        root.storage_kek(&keys),
    )
    .await
    .expect("authenticated reopen with 65 active metadata rows");
    let reopened_first = reopened
        .load_active_native_metadata_mutations(None)
        .await
        .expect("load reopened first recovery page");
    let reopened_second = reopened
        .load_active_native_metadata_mutations(reopened_first.next_cursor())
        .await
        .expect("load reopened second recovery page");
    assert_eq!(
        reopened_first.mutations().len() + reopened_second.mutations().len(),
        65
    );
    reopened
        .shutdown()
        .await
        .expect("shutdown reopened paged recovery store");
}
