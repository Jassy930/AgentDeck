//! CounterGuard rollback 后的自动 sender epoch recovery focused tests。

use std::sync::{
    Arc,
    atomic::{AtomicU64, Ordering},
};

use agentdeck_protocol::e2ee::{
    AuthorizationCapabilityV1, AuthorizationPermissionV1, KeyId, KeyPurpose,
};
use agentdeck_protocol::relay_v2::{StreamGenerationId, StreamRouteId};

use crate::remote::counter::{COUNTER_BLOCK_SIZE, CounterScope};
use crate::runtime::model::{ConversationDescriptor, NewConversation};

use super::key_transition::{
    AcknowledgeKeyUpdate, BeginKeyTransition, COUNTER_RETIREMENT_RETENTION_MS,
    CounterRetirementApplyOutcome, FrozenKeyUpdate, KEY_TRANSITION_TOMBSTONE_RETENTION_MS,
    KeyTransitionGcLimits, KeyTransitionGlobalLineage, KeyTransitionOperation, KeyTransitionPhase,
    KeyTransitionRecipient, KeyTransitionTarget, canonical_update_hash,
};
use super::remote_counter::{
    CounterRecoveryDisposition, CounterRecoveryStageRequest, CounterRecoveryStageTarget,
    RemoteCounterRecordKind, RemoteCounterRetirementRequest,
};
use super::{
    ActiveSenderCounterBinding, PublicationScope, RuntimeId, RuntimeIdKind, RuntimeStoreHandle,
    active_authorization_store_with_pending_transition_for_test,
    matching_bootstrap_update_for_test,
};
use crate::runtime::model::{RuntimeClock, RuntimeClockError, RuntimeStoreConfig};
use crate::security::{MemoryKeyStore, load_or_create_storage_kek};

use super::pairing_tests::artifact_bytes;

#[derive(Clone)]
struct ManualClock(Arc<AtomicU64>);

impl RuntimeClock for ManualClock {
    fn now_ms(&self) -> Result<u64, RuntimeClockError> {
        Ok(self.0.load(Ordering::SeqCst))
    }
}

fn secure_tempdir() -> tempfile::TempDir {
    let root = tempfile::tempdir().expect("create counter recovery tempdir");
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        std::fs::set_permissions(root.path(), std::fs::Permissions::from_mode(0o700))
            .expect("secure counter recovery tempdir");
    }
    root
}

async fn retire_genesis(store: &RuntimeStoreHandle, scope: CounterScope, key_id: KeyId) {
    let genesis = store
        .load_remote_counter_record(scope.token(), key_id)
        .await
        .expect("load canonical counter genesis");
    assert_eq!(genesis.kind, RemoteCounterRecordKind::Genesis);
    let retired = store
        .retire_remote_counter(RemoteCounterRetirementRequest {
            scope_token: scope.token(),
            key_id,
            expected_reserved_end: genesis.reserved_end,
            expected_db_anchor: genesis.db_anchor,
            retired_through: COUNTER_BLOCK_SIZE,
        })
        .await
        .expect("persist rollback retirement tombstone");
    assert_eq!(retired.kind, RemoteCounterRecordKind::Retired);
}

async fn active_directed_binding(store: &RuntimeStoreHandle) -> super::RemoteReplyAuthorization {
    store
        .load_active_sender_counter_bindings()
        .await
        .expect("load authenticated sender inventory")
        .into_iter()
        .find_map(|binding| match binding {
            ActiveSenderCounterBinding::DirectedReply { authorization } => Some(authorization),
            ActiveSenderCounterBinding::SharedPublication { .. } => None,
        })
        .expect("active directed reply binding")
}

async fn complete_zero_cut_with_production_finalize(store: &RuntimeStoreHandle) {
    let recovery = store
        .load_active_key_transition()
        .await
        .expect("load pending zero-cut transition")
        .expect("pending zero-cut transition exists");
    let operation_id = recovery.transition.operation_id;
    store
        .finalize_key_directory_rotation(operation_id)
        .await
        .expect("finalize production key-directory axes");
    let mut updates = Vec::with_capacity(recovery.transition.recipients.len());
    for recipient in &recovery.transition.recipients {
        updates.push(matching_bootstrap_update_for_test(store, *recipient).await);
    }
    store
        .freeze_key_updates(operation_id, updates.clone())
        .await
        .expect("freeze fixture key updates");
    store
        .freeze_key_barriers(operation_id, Vec::new())
        .await
        .expect("freeze fixture zero-cut barriers");
    store
        .mark_key_barriers_committed(operation_id)
        .await
        .expect("commit fixture zero-cut barriers");
    let committed = store
        .load_active_key_transition()
        .await
        .expect("reload bootstrap-receipt committed transition")
        .expect("bootstrap transition remains active before explicit completion");
    for record in committed.updates {
        match record.lifecycle {
            super::key_transition::KeyUpdateLifecycle::Acked => {
                assert!(record.canonical_ack.is_some());
            }
            super::key_transition::KeyUpdateLifecycle::Frozen => {
                let update = updates
                    .iter()
                    .find(|update| update.recipient == record.recipient)
                    .expect("frozen fixture update remains in the exact input set");
                store
                    .acknowledge_key_update(AcknowledgeKeyUpdate {
                        operation_id,
                        recipient: update.recipient,
                        key_revision: update.key_revision,
                        update_hash: canonical_update_hash(&update.canonical_update_set)
                            .expect("fixture update hash"),
                        canonical_ack: format!("fixture-ack-{:?}", update.recipient).into_bytes(),
                        acknowledged_at_ms: 0,
                    })
                    .await
                    .expect("ack non-bootstrap fixture key update");
            }
            other => panic!("unexpected fixture update lifecycle: {other:?}"),
        }
    }
    store
        .complete_key_transition(operation_id)
        .await
        .expect("complete fixture zero-cut transition");
}

async fn production_aligned_authorization_store(database: &std::path::Path) -> RuntimeStoreHandle {
    production_aligned_authorization_store_with_keys(database)
        .await
        .0
}

async fn production_aligned_authorization_store_with_keys(
    database: &std::path::Path,
) -> (RuntimeStoreHandle, MemoryKeyStore) {
    let keys = MemoryKeyStore::new();
    let storage_kek =
        load_or_create_storage_kek(&keys, database).expect("create counter fixture StorageKEK");
    let store = active_authorization_store_with_pending_transition_for_test(
        database,
        storage_kek,
        vec![AuthorizationCapabilityV1::Catalog],
        vec![AuthorizationPermissionV1::CatalogRead],
    )
    .await;
    complete_zero_cut_with_production_finalize(&store).await;
    (store, keys)
}

fn directed_recovery_request(
    authorization: &super::RemoteReplyAuthorization,
    operation_id: [u8; 16],
) -> (
    CounterScope,
    KeyId,
    CounterScope,
    CounterRecoveryStageRequest,
) {
    let retired_key_id = KeyId {
        purpose: KeyPurpose::DeviceReplyTx,
        epoch: authorization.reply_key_epoch(),
    };
    let retired_scope = CounterScope::directed_reply_for_trust_epoch(
        authorization.machine_trust_domain(),
        authorization.machine_route(),
        authorization.trust_epoch(),
        authorization.device_route(),
        authorization.grant_serial(),
        retired_key_id.epoch,
    )
    .expect("derive retired directed reply scope");
    let replacement_key_id = KeyId {
        purpose: retired_key_id.purpose,
        epoch: retired_key_id
            .epoch
            .checked_add(1)
            .expect("directed reply epoch has successor"),
    };
    let replacement_scope = CounterScope::directed_reply_for_trust_epoch(
        authorization.machine_trust_domain(),
        authorization.machine_route(),
        authorization.trust_epoch(),
        authorization.device_route(),
        authorization.grant_serial(),
        replacement_key_id.epoch,
    )
    .expect("derive replacement directed reply scope");
    let request = CounterRecoveryStageRequest {
        operation_id,
        retired_scope_token: retired_scope.token(),
        retired_key_id,
        replacement_scope_token: replacement_scope.token(),
        target: CounterRecoveryStageTarget::DirectedReply {
            authorization: authorization.clone(),
        },
    };
    (retired_scope, retired_key_id, replacement_scope, request)
}

#[tokio::test]
async fn directed_reply_rollback_stages_new_epoch_and_only_business_ready_recovers_old_scope() {
    let root = secure_tempdir();
    let database = root.path().join("runtime.db");
    let (store, keys) = production_aligned_authorization_store_with_keys(&database).await;
    let authorization = active_directed_binding(&store).await;
    let old_key_id = KeyId {
        purpose: KeyPurpose::DeviceReplyTx,
        epoch: authorization.reply_key_epoch(),
    };
    let old_scope = CounterScope::directed_reply_for_trust_epoch(
        authorization.machine_trust_domain(),
        authorization.machine_route(),
        authorization.trust_epoch(),
        authorization.device_route(),
        authorization.grant_serial(),
        old_key_id.epoch,
    )
    .expect("derive old directed reply scope");
    let replacement_key_id = KeyId {
        purpose: old_key_id.purpose,
        epoch: old_key_id.epoch + 1,
    };
    let replacement_scope = CounterScope::directed_reply_for_trust_epoch(
        authorization.machine_trust_domain(),
        authorization.machine_route(),
        authorization.trust_epoch(),
        authorization.device_route(),
        authorization.grant_serial(),
        replacement_key_id.epoch,
    )
    .expect("derive replacement directed reply scope");
    assert_ne!(old_scope.token(), replacement_scope.token());
    store
        .register_remote_counter_guard_scope(old_scope.token())
        .await
        .expect("register old directed CounterGuard manifest");
    store
        .mark_remote_counter_guard_scope_materialized(old_scope.token())
        .await
        .expect("materialize old directed CounterGuard manifest");
    retire_genesis(&store, old_scope, old_key_id).await;

    let before_revision = store
        .load_global_key_state()
        .await
        .expect("load global key state")
        .expect("paired global state")
        .revision()
        .value();
    let operation_id = [0xc1; 16];
    let staged = store
        .stage_remote_counter_recovery(CounterRecoveryStageRequest {
            operation_id,
            retired_scope_token: old_scope.token(),
            retired_key_id: old_key_id,
            replacement_scope_token: replacement_scope.token(),
            target: CounterRecoveryStageTarget::DirectedReply {
                authorization: authorization.clone(),
            },
        })
        .await
        .expect("stage automatic directed reply rekey");
    assert_eq!(staged.disposition, CounterRecoveryDisposition::Staged);
    let staged_binding = staged.binding.expect("staged recovery binding");
    assert_eq!(staged_binding.replacement_key_id, replacement_key_id);
    assert_eq!(staged_binding.from_revision, before_revision);
    assert_eq!(staged_binding.to_revision, before_revision + 1);

    let transition = store
        .load_active_key_transition()
        .await
        .expect("load counter recovery transition")
        .expect("counter recovery transition is active")
        .transition;
    assert_eq!(transition.operation_id, operation_id);
    assert_eq!(
        transition.operation,
        KeyTransitionOperation::CounterRecovery
    );
    assert_eq!(transition.phase, KeyTransitionPhase::DrainingOld);
    assert_eq!(
        transition.target,
        KeyTransitionTarget::Device(transition.recipients[0])
    );
    assert!(
        store
            .has_retired_remote_counter()
            .await
            .expect("read global fence")
    );
    assert!(
        store
            .remote_counter_scope_allowed(replacement_scope.token())
            .await
            .expect("authorize replacement scope")
    );
    assert!(
        !store
            .remote_counter_scope_allowed(old_scope.token())
            .await
            .expect("old scope stays fenced")
    );
    assert!(
        !store
            .remote_counter_scope_allowed([0xee; 32])
            .await
            .expect("unrelated scope stays fenced")
    );
    assert!(
        store
            .mark_remote_counter_recovery_business_ready(operation_id)
            .await
            .is_err(),
        "DrainingOld must not clear the rollback fence"
    );

    store
        .finalize_key_directory_rotation(operation_id)
        .await
        .expect("advance guard-bound directory axes");
    let recovery = store
        .load_active_key_transition()
        .await
        .expect("reload rotated transition")
        .expect("transition remains active");
    let updates = recovery
        .transition
        .recipients
        .iter()
        .map(|recipient| FrozenKeyUpdate {
            recipient: *recipient,
            key_revision: recovery.transition.to_revision,
            canonical_update_set: format!("counter-recovery-{recipient:?}").into_bytes(),
        })
        .collect::<Vec<_>>();
    store
        .freeze_key_updates(operation_id, updates.clone())
        .await
        .expect("freeze exact recovery key updates");
    store
        .freeze_key_barriers(operation_id, Vec::new())
        .await
        .expect("directed-only recovery has no shared epoch barrier");
    store
        .mark_key_barriers_committed(operation_id)
        .await
        .expect("reach canonical BusinessReady");
    let recovered = store
        .mark_remote_counter_recovery_business_ready(operation_id)
        .await
        .expect("mark old sender scope recovered after BusinessReady");
    assert_eq!(recovered.kind, RemoteCounterRecordKind::Recovered);
    assert!(
        !store
            .has_retired_remote_counter()
            .await
            .expect("rollback fence clears after exact transition")
    );
    assert!(
        store
            .remote_counter_scope_allowed(replacement_scope.token())
            .await
            .expect("replacement remains authorized")
    );
    assert!(
        !store
            .remote_counter_scope_allowed(old_scope.token())
            .await
            .expect("recovered old scope never becomes reusable")
    );
    for update in updates {
        store
            .acknowledge_key_update(AcknowledgeKeyUpdate {
                operation_id,
                recipient: update.recipient,
                key_revision: update.key_revision,
                update_hash: canonical_update_hash(&update.canonical_update_set)
                    .expect("counter-recovery update hash"),
                canonical_ack: format!("counter-recovery-ack-{:?}", update.recipient).into_bytes(),
                acknowledged_at_ms: 0,
            })
            .await
            .expect("ack counter-recovery key update");
    }
    let completed = store
        .complete_key_transition(operation_id)
        .await
        .expect("complete counter-recovery transition after exact ACK set");
    let terminal_at_ms = completed
        .terminal_at_ms
        .expect("completed counter-recovery terminal time");
    store
        .shutdown()
        .await
        .expect("shutdown directed recovery Store");

    let clock = Arc::new(AtomicU64::new(
        terminal_at_ms + COUNTER_RETIREMENT_RETENTION_MS - 1,
    ));
    let storage_kek =
        load_or_create_storage_kek(&keys, &database).expect("reload counter fixture StorageKEK");
    let reopened = RuntimeStoreHandle::open(
        RuntimeStoreConfig::new(database.clone()).with_clock(ManualClock(clock.clone())),
        storage_kek,
    )
    .await
    .expect("reopen completed counter-recovery Store");
    assert!(
        reopened
            .load_pending_counter_retirement_plan()
            .await
            .expect("load pre-retention recovered-scope plan")
            .is_none()
    );
    clock.store(
        terminal_at_ms + COUNTER_RETIREMENT_RETENTION_MS,
        Ordering::SeqCst,
    );
    let mut activation_plans = 0_u64;
    let plan = loop {
        let plan = reopened
            .load_pending_counter_retirement_plan()
            .await
            .expect("load recovered-scope counter-retirement plan")
            .expect("an eligible counter-retirement plan remains");
        if plan.operation_id == operation_id {
            break plan;
        }
        assert!(
            plan.scope_tokens.is_empty(),
            "the initial activation fixture has no retired sender scope"
        );
        reopened
            .apply_counter_retirement_after_guard_readback(plan)
            .await
            .expect("collect earlier empty activation plan");
        activation_plans += 1;
    };
    assert_eq!(plan.operation_id, operation_id);
    assert_eq!(plan.scope_tokens, vec![old_scope.token()]);
    assert_eq!(
        reopened
            .apply_counter_retirement_after_guard_readback(plan)
            .await
            .expect("collect recovered counter and exact manifest"),
        CounterRetirementApplyOutcome::Applied {
            operation_id,
            counter_rows_deleted: 1,
            manifest_rows_deleted: 1,
        }
    );
    while let Some(plan) = reopened
        .load_pending_counter_retirement_plan()
        .await
        .expect("load trailing activation counter-retirement plan")
    {
        assert_ne!(plan.operation_id, operation_id);
        assert!(
            plan.scope_tokens.is_empty(),
            "the initial activation fixture has no retired sender scope"
        );
        reopened
            .apply_counter_retirement_after_guard_readback(plan)
            .await
            .expect("collect trailing empty activation plan");
        activation_plans += 1;
    }
    assert_eq!(activation_plans, 1);
    clock.store(
        terminal_at_ms + KEY_TRANSITION_TOMBSTONE_RETENTION_MS,
        Ordering::SeqCst,
    );
    let gc = reopened
        .gc_expired_key_transitions(KeyTransitionGcLimits::default())
        .await
        .expect("collect applied CounterRecovery transition tombstone");
    assert!(gc.transitions_deleted >= 1);
    assert!(gc.updates_deleted >= 1);
    reopened
        .shutdown()
        .await
        .expect("shutdown collected counter-recovery Store");
    let connection = rusqlite::Connection::open(&database).expect("open collected recovery DB");
    assert_eq!(
        connection
            .query_row(
                "SELECT COUNT(*) FROM remote_key_transitions WHERE operation_id = ?1",
                [&operation_id[..]],
                |row| row.get::<_, u64>(0),
            )
            .expect("read collected CounterRecovery transition"),
        0
    );
}

async fn stage_shared_recovery(scope: PublicationScope, expected_purpose: KeyPurpose) {
    let root = secure_tempdir();
    let store = production_aligned_authorization_store(&root.path().join("runtime.db")).await;
    match scope {
        PublicationScope::Catalog => {
            store
                .create_publication_stream(
                    [0xd1; 16],
                    PublicationScope::Catalog,
                    *StreamRouteId::from_bytes([0xd2; 16]).as_bytes(),
                    *StreamGenerationId::from_bytes([0xd3; 16]).as_bytes(),
                )
                .await
                .expect("create catalog publication stream");
        }
        PublicationScope::Conversation(conversation_id) => {
            store
                .create_conversation(NewConversation {
                    conversation_id,
                    adapter_state_key: RuntimeId::from_bytes(
                        RuntimeIdKind::AdapterState,
                        [0xd4; 16],
                    )
                    .expect("adapter state key"),
                    descriptor: ConversationDescriptor {
                        agent_kind: agentdeck_protocol::AgentKind::Codex,
                        title: Some("counter recovery conversation".to_owned()),
                        cwd: std::path::PathBuf::from("/tmp/counter-recovery-conversation"),
                    },
                })
                .await
                .expect("create paired conversation");
            complete_zero_cut_with_production_finalize(&store).await;
        }
    }

    let (publication_stream_id, old_key_id) = store
        .load_active_sender_counter_bindings()
        .await
        .expect("load shared sender inventory")
        .into_iter()
        .find_map(|binding| match binding {
            ActiveSenderCounterBinding::SharedPublication {
                publication_stream_id,
                key_id,
            } if key_id.purpose == expected_purpose => Some((publication_stream_id, key_id)),
            _ => None,
        })
        .expect("target shared sender binding");
    let trust_domain = store.machine_trust_domain().expect("machine trust domain");
    let old_scope = CounterScope::publication(trust_domain, old_key_id, publication_stream_id)
        .expect("derive old shared scope");
    let replacement_key_id = KeyId {
        purpose: old_key_id.purpose,
        epoch: old_key_id.epoch + 1,
    };
    let replacement_scope =
        CounterScope::publication(trust_domain, replacement_key_id, publication_stream_id)
            .expect("derive replacement shared scope");
    retire_genesis(&store, old_scope, old_key_id).await;

    let operation_id = match expected_purpose {
        KeyPurpose::Catalog => [0xd5; 16],
        KeyPurpose::ConversationDek => [0xd6; 16],
        _ => unreachable!(),
    };
    let staged = store
        .stage_remote_counter_recovery(CounterRecoveryStageRequest {
            operation_id,
            retired_scope_token: old_scope.token(),
            retired_key_id: old_key_id,
            replacement_scope_token: replacement_scope.token(),
            target: CounterRecoveryStageTarget::SharedPublication {
                publication_stream_id,
            },
        })
        .await
        .expect("stage shared sender recovery");
    assert_eq!(staged.disposition, CounterRecoveryDisposition::Staged);
    assert_eq!(
        staged
            .binding
            .expect("staged shared recovery binding")
            .replacement_key_id,
        replacement_key_id
    );
    assert!(
        store
            .has_retired_remote_counter()
            .await
            .expect("read shared fence")
    );
    assert!(
        store
            .remote_counter_scope_allowed(replacement_scope.token())
            .await
            .expect("replacement shared scope is transition-authorized")
    );
    assert!(
        !store
            .remote_counter_scope_allowed([0xef; 32])
            .await
            .expect("unrelated shared scope remains fenced")
    );
    let global = store
        .load_global_key_state()
        .await
        .expect("load rotated global state")
        .expect("rotated global state exists");
    assert!(
        global
            .current_shared_keys()
            .expect("load current shared keys")
            .iter()
            .any(|key| key.purpose == expected_purpose && key.epoch == replacement_key_id.epoch)
    );
    store
        .shutdown()
        .await
        .expect("shutdown shared recovery Store");
}

#[tokio::test]
async fn catalog_and_conversation_rollback_each_stage_exact_new_shared_sender_epoch() {
    stage_shared_recovery(PublicationScope::Catalog, KeyPurpose::Catalog).await;
    let conversation_id =
        RuntimeId::from_bytes(RuntimeIdKind::Conversation, [0xe1; 16]).expect("conversation id");
    stage_shared_recovery(
        PublicationScope::Conversation(conversation_id),
        KeyPurpose::ConversationDek,
    )
    .await;
}

#[tokio::test]
async fn occupied_transition_slot_requires_trust_reset_without_rewriting_retired_scope() {
    let root = secure_tempdir();
    let database = root.path().join("runtime.db");
    let store = production_aligned_authorization_store(&database).await;
    let authorization = active_directed_binding(&store).await;
    let (retired_scope, retired_key_id, replacement_scope, request) =
        directed_recovery_request(&authorization, [0xf1; 16]);
    retire_genesis(&store, retired_scope, retired_key_id).await;

    let global = store
        .load_global_key_state()
        .await
        .expect("load pre-conflict global state")
        .expect("pre-conflict global state exists");
    let global_canonical = global
        .canonical_bytes()
        .expect("encode pre-conflict global state");
    let recipient = KeyTransitionRecipient {
        device_route: *authorization.device_route().as_bytes(),
        grant_serial: authorization.grant_serial().value(),
    };
    let occupied = store
        .begin_key_transition_with_global_lineage_for_test(
            BeginKeyTransition {
                operation_id: [0xf2; 16],
                operation: KeyTransitionOperation::Renew,
                target: KeyTransitionTarget::Device(recipient),
                from_revision: global.revision().value(),
                to_revision: global
                    .revision()
                    .value()
                    .checked_add(1)
                    .expect("occupied transition revision has successor"),
                recipients: vec![recipient],
                replay_retirement: None,
                created_at_ms: 0,
            },
            KeyTransitionGlobalLineage {
                global_key_state_hash: [0xf3; 32],
                stable_key_lineage_hash: Some([0xf4; 32]),
            },
        )
        .await
        .expect("occupy the unique transition slot");
    let retired_before = store
        .load_remote_counter_record(retired_scope.token(), retired_key_id)
        .await
        .expect("load retired record before conflict");
    let transition_before = store
        .load_active_key_transition()
        .await
        .expect("load occupied transition before recovery");
    let artifacts_before = artifact_bytes(&database);

    let outcome = store
        .stage_remote_counter_recovery(request)
        .await
        .expect("occupied slot is a typed recovery disposition");
    assert_eq!(
        outcome.disposition,
        CounterRecoveryDisposition::TrustResetRequired
    );
    assert!(outcome.binding.is_none());
    assert_eq!(
        store
            .load_remote_counter_record(retired_scope.token(), retired_key_id)
            .await
            .expect("reload retired record after conflict"),
        retired_before
    );
    assert_eq!(
        store
            .load_active_key_transition()
            .await
            .expect("reload occupied transition after recovery refusal"),
        transition_before
    );
    let global_after = store
        .load_global_key_state()
        .await
        .expect("reload global state after recovery refusal")
        .expect("global state remains present");
    assert_eq!(
        global_after
            .canonical_bytes()
            .expect("encode global state after recovery refusal"),
        global_canonical
    );
    assert!(
        store
            .has_retired_remote_counter()
            .await
            .expect("retirement remains fenced")
    );
    assert!(
        !store
            .remote_counter_scope_allowed(replacement_scope.token())
            .await
            .expect("replacement scope is not admitted without a recovery transition")
    );
    assert_eq!(artifacts_before, artifact_bytes(&database));
    assert_eq!(occupied.operation_id, [0xf2; 16]);
    store
        .shutdown()
        .await
        .expect("shutdown occupied-transition fixture");
}

#[tokio::test]
async fn unbound_active_sender_requires_trust_reset_without_rewriting_retired_scope() {
    let root = secure_tempdir();
    let database = root.path().join("runtime.db");
    let store = production_aligned_authorization_store(&database).await;
    let publication_stream_id = [0xf3; 16];
    store
        .create_publication_stream(
            publication_stream_id,
            PublicationScope::Catalog,
            *StreamRouteId::from_bytes([0xf4; 16]).as_bytes(),
            *StreamGenerationId::from_bytes([0xf5; 16]).as_bytes(),
        )
        .await
        .expect("create active catalog sender");
    let old_key_id = store
        .load_active_sender_counter_bindings()
        .await
        .expect("load catalog sender inventory")
        .into_iter()
        .find_map(|binding| match binding {
            ActiveSenderCounterBinding::SharedPublication {
                publication_stream_id: active_stream,
                key_id,
            } if active_stream == publication_stream_id
                && key_id.purpose == KeyPurpose::Catalog =>
            {
                Some(key_id)
            }
            _ => None,
        })
        .expect("active catalog sender binding");
    let trust_domain = store.machine_trust_domain().expect("machine trust domain");
    let retired_scope = CounterScope::publication(trust_domain, old_key_id, publication_stream_id)
        .expect("derive retired catalog scope");
    retire_genesis(&store, retired_scope, old_key_id).await;

    let unbound_stream_id = [0xf6; 16];
    let replacement_key_id = KeyId {
        purpose: old_key_id.purpose,
        epoch: old_key_id
            .epoch
            .checked_add(1)
            .expect("catalog epoch has successor"),
    };
    let replacement_scope =
        CounterScope::publication(trust_domain, replacement_key_id, unbound_stream_id)
            .expect("derive unbound replacement scope");
    let retired_before = store
        .load_remote_counter_record(retired_scope.token(), old_key_id)
        .await
        .expect("load retired catalog record before refusal");
    let global_before = store
        .load_global_key_state()
        .await
        .expect("load global state before refusal")
        .expect("global state exists before refusal")
        .canonical_bytes()
        .expect("encode global state before refusal");
    let artifacts_before = artifact_bytes(&database);
    let outcome = store
        .stage_remote_counter_recovery(CounterRecoveryStageRequest {
            operation_id: [0xf7; 16],
            retired_scope_token: retired_scope.token(),
            retired_key_id: old_key_id,
            replacement_scope_token: replacement_scope.token(),
            target: CounterRecoveryStageTarget::SharedPublication {
                publication_stream_id: unbound_stream_id,
            },
        })
        .await
        .expect("unbound sender is a typed recovery disposition");
    assert_eq!(
        outcome.disposition,
        CounterRecoveryDisposition::TrustResetRequired
    );
    assert!(outcome.binding.is_none());
    assert_eq!(
        store
            .load_remote_counter_record(retired_scope.token(), old_key_id)
            .await
            .expect("reload retired catalog record after refusal"),
        retired_before
    );
    let global_after = store
        .load_global_key_state()
        .await
        .expect("reload global state after refusal")
        .expect("global state remains present after refusal")
        .canonical_bytes()
        .expect("encode global state after refusal");
    assert_eq!(global_after, global_before);
    assert!(
        store
            .load_active_key_transition()
            .await
            .expect("load transition slot after refusal")
            .is_none()
    );
    assert!(
        store
            .has_retired_remote_counter()
            .await
            .expect("retirement remains fenced")
    );
    assert!(
        !store
            .remote_counter_scope_allowed(replacement_scope.token())
            .await
            .expect("unbound replacement scope stays fenced")
    );
    assert_eq!(artifacts_before, artifact_bytes(&database));
    store
        .shutdown()
        .await
        .expect("shutdown unbound sender fixture");
}

#[tokio::test]
async fn staged_recovery_reopens_with_exact_binding_and_idempotent_retry() {
    let root = secure_tempdir();
    let database = root.path().join("runtime.db");
    let (store, keys) = production_aligned_authorization_store_with_keys(&database).await;
    let authorization = active_directed_binding(&store).await;
    let (retired_scope, retired_key_id, replacement_scope, request) =
        directed_recovery_request(&authorization, [0xf8; 16]);
    retire_genesis(&store, retired_scope, retired_key_id).await;
    let staged = store
        .stage_remote_counter_recovery(request.clone())
        .await
        .expect("stage recovery before reopen");
    assert_eq!(staged.disposition, CounterRecoveryDisposition::Staged);
    let expected_binding = staged.binding.expect("staged binding before reopen");
    let in_process_retry = store
        .stage_remote_counter_recovery(request.clone())
        .await
        .expect("retry exact staged recovery in process");
    assert_eq!(
        in_process_retry.disposition,
        CounterRecoveryDisposition::AlreadyStaged
    );
    assert_eq!(in_process_retry.binding, Some(expected_binding));
    store
        .shutdown()
        .await
        .expect("shutdown staged recovery Store");

    let reopened = RuntimeStoreHandle::open(
        RuntimeStoreConfig::new(database.clone()),
        load_or_create_storage_kek(&keys, &database).expect("reload counter recovery StorageKEK"),
    )
    .await
    .expect("reopen staged recovery through full audit");
    assert_eq!(
        reopened
            .load_remote_counter_record(retired_scope.token(), retired_key_id)
            .await
            .expect("load staged record after reopen")
            .kind,
        RemoteCounterRecordKind::RecoveryStaged
    );
    assert!(
        reopened
            .has_retired_remote_counter()
            .await
            .expect("reopened fence remains active")
    );
    assert!(
        !reopened
            .remote_counter_scope_allowed(retired_scope.token())
            .await
            .expect("retired scope stays forbidden after reopen")
    );
    assert!(
        reopened
            .remote_counter_scope_allowed(replacement_scope.token())
            .await
            .expect("exact replacement scope survives reopen")
    );
    assert!(
        !reopened
            .remote_counter_scope_allowed([0xf9; 32])
            .await
            .expect("unrelated scope stays fenced after reopen")
    );
    let transition = reopened
        .load_active_key_transition()
        .await
        .expect("load recovery transition after reopen")
        .expect("recovery transition survives reopen")
        .transition;
    assert_eq!(transition.operation_id, expected_binding.operation_id);
    assert_eq!(
        transition.operation,
        KeyTransitionOperation::CounterRecovery
    );
    assert_eq!(transition.from_revision, expected_binding.from_revision);
    assert_eq!(transition.to_revision, expected_binding.to_revision);
    let reopened_retry = reopened
        .stage_remote_counter_recovery(request)
        .await
        .expect("retry exact staged recovery after reopen");
    assert_eq!(
        reopened_retry.disposition,
        CounterRecoveryDisposition::AlreadyStaged
    );
    assert_eq!(reopened_retry.binding, Some(expected_binding));
    reopened
        .shutdown()
        .await
        .expect("shutdown reopened recovery Store");
}
