use std::sync::Arc;
use std::sync::atomic::{AtomicU64, Ordering};

use agentdeck_crypto::{SigningKey, sign_pair_response_received, sign_tbs};
use agentdeck_protocol::e2ee::{KeyPurpose, PairResponseReceivedV1};
use agentdeck_protocol::relay_v2::frame::{
    GrantCommitted, OpaqueRouteFrame, PairRouteCloseOutcome, PairRouteClosed, RelayFrameBody,
};
use agentdeck_protocol::relay_v2::{
    DeviceRevocation, DeviceRouteId, Ed25519Signature, GrantSerial, RELAY_PROTOCOL_VERSION,
    RelayGrant, encode,
};

use crate::remote::access::{PairResponseAccessBinding, VerifiedPairResponseReceipt};
use crate::runtime::model::{RuntimeStoreConfig, RuntimeStoreError};
use crate::security::{MemoryKeyStore, load_or_create_storage_kek};

use super::pairing_delivery::{
    AcknowledgePairResponseReceived, AcknowledgePairResponseReceivedOutcome,
};
use super::pairing_grant::RETIRED_KEY_RETENTION_MS;
use super::pairing_grant_allocation_tests::complete_active_membership_transition;
use super::pairing_grant_commit::AcknowledgeGrantCommitted;
use super::pairing_grant_tests::{
    awaiting_pairing, awaiting_pairing_with, grant_input, grant_input_with, secret,
};
use super::pairing_grant_tx::{ConfirmPairingGrantOutcome, GrantPreparingRecovery};
use super::pairing_revocation::{BeginDeviceRevocation, BeginDeviceRevocationOutcome};
use super::pairing_tests::{
    GenerousCapacity, NOW_MS, RELAY, TestClock, TestRoot, artifact_bytes, make_active,
};
use super::publication::PublicationScope;
use super::retired_key::{
    RetiredKeyGcOutcome, RetiredKeyMutationOutcome, acquire_owner, gc_expired, release_owner,
};
use super::{RetiredKeyOwnerKind, RetiredSharedKeyOwner, RuntimeStoreHandle};

const ROOT_SEED: [u8; 32] = [0x41; 32];

fn config(root: &TestRoot, clock: Arc<AtomicU64>) -> RuntimeStoreConfig {
    RuntimeStoreConfig::new(root.database())
        .with_capacity_probe(GenerousCapacity)
        .with_clock(TestClock(clock))
}

fn grant_committed_frame(recovery: &GrantPreparingRecovery) -> Vec<u8> {
    encode(&OpaqueRouteFrame {
        version: RELAY_PROTOCOL_VERSION,
        body: RelayFrameBody::GrantCommitted(GrantCommitted {
            device_route: recovery.device_route(),
            grant_serial: recovery.grant_serial(),
            grant_hash: recovery.grant_hash(),
        }),
    })
}

fn signed_revocation(
    grant: &RelayGrant,
    binding: &super::MachineIdentityBinding,
) -> DeviceRevocation {
    let mut revocation = DeviceRevocation {
        machine_route: grant.machine_route,
        device_route: grant.device_route,
        grant_serial: grant.grant_serial,
        root_key_id: grant.root_key_id,
        trust_epoch: grant.trust_epoch,
        signature: Ed25519Signature([0; 64]),
    };
    revocation.signature = sign_tbs(
        &SigningKey::from_seed(&ROOT_SEED),
        &revocation.to_be_signed_v1(RELAY, binding.root_fingerprint),
    )
    .into();
    revocation
}

fn pair_route_closed_frame(pair_route: agentdeck_protocol::relay_v2::PairRouteId) -> Vec<u8> {
    encode(&OpaqueRouteFrame {
        version: RELAY_PROTOCOL_VERSION,
        body: RelayFrameBody::PairRouteClosed(PairRouteClosed {
            pair_route,
            outcome: PairRouteCloseOutcome::Closed,
        }),
    })
}

fn verified_receipt(
    recovery: &super::pairing_grant_commit::GrantCommittedRecovery,
    signing_seed: &[u8; 32],
) -> VerifiedPairResponseReceipt {
    let binding = PairResponseAccessBinding::from_frozen(
        recovery.invite(),
        recovery.request_hash(),
        recovery.relay_grant(),
        recovery.pair_response(),
    )
    .expect("rebuild retired-key response binding");
    let receipt = sign_pair_response_received(
        &SigningKey::from_seed(signing_seed),
        binding.info(),
        binding.receipt_context(),
        PairResponseReceivedV1 {
            request_hash: recovery.request_hash(),
            grant_hash: recovery.grant_hash(),
            response_hash: recovery.response_hash(),
            signature: Ed25519Signature([0; 64]),
        },
    )
    .expect("sign retired-key PairResponseReceived");
    binding
        .verify_signed_receipt(
            &receipt
                .canonical_bytes()
                .expect("canonical retired-key PairResponseReceived"),
        )
        .expect("verify retired-key PairResponseReceived")
}

async fn deliver_pair_response(
    store: &RuntimeStoreHandle,
    pairing_id: super::RuntimeId,
    recovery: &super::pairing_grant_commit::GrantCommittedRecovery,
    signing_seed: &[u8; 32],
) {
    let proof = verified_receipt(recovery, signing_seed);
    let close = match store
        .acknowledge_pair_response_received(AcknowledgePairResponseReceived::new(
            pairing_id, &proof,
        ))
        .await
        .expect("acknowledge retired-key PairResponseReceived")
    {
        AcknowledgePairResponseReceivedOutcome::Delivered { close } => close,
        other => panic!("fresh retired-key response must deliver: {other:?}"),
    };
    store
        .acknowledge_pair_route_close(pairing_id, pair_route_closed_frame(close.pair_route()))
        .await
        .expect("acknowledge retired-key PairRouteClosed");
}

async fn seed_active_catalog(
    root: &TestRoot,
    keys: &MemoryKeyStore,
    clock: Arc<AtomicU64>,
) -> (
    RuntimeStoreHandle,
    super::MachineIdentityBinding,
    agentdeck_protocol::relay_v2::SignedCertificate,
    RelayGrant,
) {
    let store = RuntimeStoreHandle::open(
        config(root, clock.clone()),
        load_or_create_storage_kek(keys, &root.database()).expect("load retired-key StorageKEK"),
    )
    .await
    .expect("open retired-key fixture store");
    store
        .create_publication_stream(
            [0x21; 16],
            PublicationScope::Catalog,
            [0x22; 16],
            [0x23; 16],
        )
        .await
        .expect("create retired-key catalog publication stream");
    let (binding, data_cert) = make_active(&store).await;
    let first_preparation = awaiting_pairing(&store, &binding, &data_cert).await;
    let first_recovery = match store
        .confirm_pairing_grant(grant_input(&first_preparation, &binding, &data_cert))
        .await
        .expect("confirm first retired-key fixture member")
    {
        ConfirmPairingGrantOutcome::Confirmed { recovery, .. } => recovery,
        other => panic!("first member must confirm: {other:?}"),
    };
    let first_committed = store
        .acknowledge_grant_committed(AcknowledgeGrantCommitted::new(
            first_recovery.pairing_id(),
            grant_committed_frame(&first_recovery),
        ))
        .await
        .expect("activate first retired-key fixture member");
    let first_committed = match first_committed {
        super::pairing_grant_commit::AcknowledgeGrantCommittedOutcome::Committed { recovery } => {
            recovery
        }
        other => panic!("first retired-key grant must commit: {other:?}"),
    };
    deliver_pair_response(
        &store,
        first_recovery.pairing_id(),
        &first_committed,
        &[0xa4; 32],
    )
    .await;
    complete_active_membership_transition(&store, &clock).await;
    let grant = first_committed.relay_grant().clone();
    (store, binding, data_cert, grant)
}

async fn seed_retired_catalog(root: &TestRoot, keys: &MemoryKeyStore, clock: Arc<AtomicU64>) {
    let (store, binding, data_cert, _) = seed_active_catalog(root, keys, clock.clone()).await;

    let second_preparation = awaiting_pairing_with(
        &store,
        &binding,
        &data_cert,
        agentdeck_protocol::relay_v2::PairRouteId::from_bytes([0xb1; 16]),
        0xb2,
        0xb3,
        0xb4,
        0xb5,
        0xb6,
        0xb7,
        "retired-key-second-member",
    )
    .await;
    let second_route = DeviceRouteId::from_bytes([0xd2; 16]);
    let rotated = store
        .load_global_key_state()
        .await
        .expect("load singleton before retired-key rotation")
        .expect("singleton exists before retired-key rotation")
        .plan_add_device(
            second_route,
            secret(0xe1),
            secret(0xe2),
            secret(0xe3),
            Vec::new(),
            NOW_MS,
        )
        .expect("rotate catalog for second member")
        .into_state();
    let second_recovery = match store
        .confirm_pairing_grant(grant_input_with(
            &second_preparation,
            &binding,
            &data_cert,
            second_route,
            GrantSerial::new(1),
            rotated,
            None,
            0xe4,
        ))
        .await
        .expect("confirm second retired-key fixture member")
    {
        ConfirmPairingGrantOutcome::Confirmed { recovery, .. } => recovery,
        other => panic!("second member must confirm: {other:?}"),
    };
    let _ = clock.fetch_add(1, Ordering::SeqCst);
    let second_committed = store
        .acknowledge_grant_committed(AcknowledgeGrantCommitted::new(
            second_recovery.pairing_id(),
            grant_committed_frame(&second_recovery),
        ))
        .await
        .expect("activate second retired-key fixture member");
    let second_committed = match second_committed {
        super::pairing_grant_commit::AcknowledgeGrantCommittedOutcome::Committed { recovery } => {
            recovery
        }
        other => panic!("second retired-key grant must commit: {other:?}"),
    };
    deliver_pair_response(
        &store,
        second_recovery.pairing_id(),
        &second_committed,
        &[0xb4; 32],
    )
    .await;
    complete_active_membership_transition(&store, &clock).await;
    store
        .shutdown()
        .await
        .expect("shutdown retired-key fixture");
}

fn owner(kind: RetiredKeyOwnerKind, id: u8) -> RetiredSharedKeyOwner {
    RetiredSharedKeyOwner::new(kind, [id; 16], KeyPurpose::Catalog, None, 1)
        .expect("valid retired catalog owner")
}

fn owner_is_durable(state: &super::sqlite::RuntimeSqlite, expected: RetiredSharedKeyOwner) -> bool {
    super::pairing_grant::load_global_key_state(
        &state.connection,
        &state.key_bundle,
        state.database_id,
    )
    .expect("authenticate retired-key singleton")
    .expect("retired-key singleton exists")
    .state
    .retired_shared_keys()
    .expect("project retired-key owners")
    .iter()
    .any(|key| key.retention_owners.contains(&expected))
}

fn assert_ledger_matches_singleton(state: &super::sqlite::RuntimeSqlite) {
    let ledger =
        super::sqlite::load_runtime_ledger(&state.connection, &state.key_bundle, state.database_id)
            .expect("load authenticated retired-key ledger");
    let sealed_bytes: u64 = state
        .connection
        .query_row(
            "SELECT sealed_directory_bytes FROM remote_key_directory WHERE singleton = 1",
            [],
            |row| row.get(0),
        )
        .expect("read singleton sealed bytes");
    assert_eq!(ledger.remote_key_directory_count, 1);
    assert_eq!(ledger.remote_key_directory_sealed_bytes, sealed_bytes);
}

fn singleton_storage_evidence(state: &super::sqlite::RuntimeSqlite) -> String {
    state
        .connection
        .query_row(
            "SELECT d.revision || ':' || hex(d.directory_hash) || ':' ||
                    hex(d.sealed_directory) || ':' || d.sealed_directory_bytes || ':' ||
                    hex(d.metadata_token) || ':' || m.remote_key_directory_count || ':' ||
                    m.remote_key_directory_sealed_bytes || ':' || hex(m.metadata_token)
             FROM remote_key_directory AS d CROSS JOIN runtime_meta AS m
             WHERE d.singleton = 1 AND m.singleton = 1",
            [],
            |row| row.get(0),
        )
        .expect("read exact singleton and ledger evidence")
}

#[tokio::test]
async fn exact_owner_acquire_release_reopen_and_post_gc_retry_are_idempotent() {
    let root = TestRoot::new("retired-key-owner-lifecycle");
    let keys = MemoryKeyStore::new();
    let clock = Arc::new(AtomicU64::new(NOW_MS));
    seed_retired_catalog(&root, &keys, clock.clone()).await;
    let publication = owner(RetiredKeyOwnerKind::Publication, 0x91);
    let mut state = super::sqlite::open(
        &config(&root, clock.clone()),
        load_or_create_storage_kek(&keys, &root.database()).expect("reopen retired-key StorageKEK"),
    )
    .expect("open retired-key transaction state");

    assert_eq!(
        acquire_owner(&mut state, &config(&root, clock.clone()), publication)
            .expect("acquire publication owner before freeze"),
        RetiredKeyMutationOutcome::Applied
    );
    assert!(owner_is_durable(&state, publication));
    assert_ledger_matches_singleton(&state);
    let changes = state.connection.total_changes();
    assert_eq!(
        acquire_owner(&mut state, &config(&root, clock.clone()), publication)
            .expect("retry publication owner acquire"),
        RetiredKeyMutationOutcome::AlreadyApplied
    );
    assert_eq!(state.connection.total_changes(), changes);
    drop(state);

    let mut reopened = super::sqlite::open(
        &config(&root, clock.clone()),
        load_or_create_storage_kek(&keys, &root.database()).expect("reload retired-key StorageKEK"),
    )
    .expect("reopen with publication owner");
    assert!(owner_is_durable(&reopened, publication));
    assert_eq!(
        gc_expired(
            &mut reopened,
            &config(&root, clock.clone()),
            NOW_MS + RETIRED_KEY_RETENTION_MS,
        )
        .expect("owner blocks deadline GC"),
        RetiredKeyGcOutcome {
            mutation: RetiredKeyMutationOutcome::AlreadyApplied,
            collected: 0,
        }
    );
    assert_eq!(
        release_owner(&mut reopened, &config(&root, clock.clone()), publication)
            .expect("exact ACK releases publication owner"),
        RetiredKeyMutationOutcome::Applied
    );
    let changes = reopened.connection.total_changes();
    assert_eq!(
        release_owner(&mut reopened, &config(&root, clock.clone()), publication)
            .expect("ACK retry is idempotent"),
        RetiredKeyMutationOutcome::AlreadyApplied
    );
    assert_eq!(reopened.connection.total_changes(), changes);
    assert_eq!(
        gc_expired(
            &mut reopened,
            &config(&root, clock.clone()),
            NOW_MS + RETIRED_KEY_RETENTION_MS,
        )
        .expect("collect unowned retired key at deadline"),
        RetiredKeyGcOutcome {
            mutation: RetiredKeyMutationOutcome::Applied,
            collected: 1,
        }
    );
    assert_eq!(
        release_owner(&mut reopened, &config(&root, clock.clone()), publication)
            .expect("post-GC exact tombstone release retry"),
        RetiredKeyMutationOutcome::AlreadyApplied
    );
    let forged_target = RetiredSharedKeyOwner::new(
        RetiredKeyOwnerKind::Publication,
        [0x92; 16],
        KeyPurpose::Catalog,
        None,
        99,
    )
    .expect("well-shaped forged target");
    let changes = reopened.connection.total_changes();
    assert!(matches!(
        release_owner(&mut reopened, &config(&root, clock.clone()), forged_target,),
        Err(RuntimeStoreError::PairingConflict)
    ));
    assert_eq!(reopened.connection.total_changes(), changes);
    assert_ledger_matches_singleton(&reopened);
    drop(reopened);

    let store = RuntimeStoreHandle::open(
        config(&root, clock),
        load_or_create_storage_kek(&keys, &root.database())
            .expect("load StorageKEK for full-open audit"),
    )
    .await
    .expect("full open authenticates retired-key mutation history");
    store.shutdown().await.expect("shutdown audited store");
}

#[tokio::test]
async fn publication_and_replay_owners_all_block_gc_until_exact_release() {
    let root = TestRoot::new("retired-key-owner-kinds");
    let keys = MemoryKeyStore::new();
    let clock = Arc::new(AtomicU64::new(NOW_MS));
    seed_retired_catalog(&root, &keys, clock.clone()).await;
    let config = config(&root, clock);
    let mut state = super::sqlite::open(
        &config,
        load_or_create_storage_kek(&keys, &root.database()).expect("reopen owner-kind StorageKEK"),
    )
    .expect("open owner-kind state");
    let owners = [
        owner(RetiredKeyOwnerKind::Publication, 0xa1),
        owner(RetiredKeyOwnerKind::Replay, 0xa2),
    ];
    for exact_owner in owners {
        assert_eq!(
            acquire_owner(&mut state, &config, exact_owner).expect("acquire exact durable owner"),
            RetiredKeyMutationOutcome::Applied
        );
    }
    drop(state);

    let mut reopened = super::sqlite::open(
        &config,
        load_or_create_storage_kek(&keys, &root.database()).expect("reload owner-kind StorageKEK"),
    )
    .expect("reopen all owner kinds");
    assert!(
        owners
            .iter()
            .all(|owner| owner_is_durable(&reopened, *owner))
    );
    for exact_owner in owners {
        assert_eq!(
            release_owner(&mut reopened, &config, exact_owner).expect("release completed owner"),
            RetiredKeyMutationOutcome::Applied
        );
    }
    assert_eq!(
        gc_expired(
            &mut reopened,
            &config,
            NOW_MS + RETIRED_KEY_RETENTION_MS - 1,
        )
        .expect("25h deadline is not reached early")
        .collected,
        0
    );
    assert_eq!(
        gc_expired(&mut reopened, &config, NOW_MS + RETIRED_KEY_RETENTION_MS,)
            .expect("25h deadline collects after all releases")
            .collected,
        1
    );
    assert_ledger_matches_singleton(&reopened);
}

#[tokio::test]
async fn revoked_device_directed_secrets_gc_is_atomic_restart_safe_and_retry_is_zero_write() {
    let root = TestRoot::new("retired-key-revoked-device-directed-gc");
    let keys = MemoryKeyStore::new();
    let clock = Arc::new(AtomicU64::new(NOW_MS));
    let (store, binding, _, grant) = seed_active_catalog(&root, &keys, clock.clone()).await;
    let publication_owner = owner(RetiredKeyOwnerKind::Publication, 0xd1);
    assert_eq!(
        store
            .acquire_retired_shared_key_owner(publication_owner)
            .await
            .expect("pin current catalog before last-device revocation"),
        RetiredKeyMutationOutcome::Applied
    );

    let revoked_at_ms = NOW_MS + 100;
    clock.store(revoked_at_ms, Ordering::SeqCst);
    let revocation = signed_revocation(&grant, &binding);
    assert!(matches!(
        store
            .begin_device_revocation(BeginDeviceRevocation::local(revocation.clone()))
            .await
            .expect("begin last-device revocation"),
        BeginDeviceRevocationOutcome::Prepared { .. }
    ));
    assert!(matches!(
        store
            .acknowledge_revocation_committed(
                super::pairing_revocation_ack::AcknowledgeRevocationCommitted::new(encode(
                    &OpaqueRouteFrame {
                        version: RELAY_PROTOCOL_VERSION,
                        body: RelayFrameBody::RevocationCommitted(
                            agentdeck_protocol::relay_v2::frame::RevocationCommitted {
                                device_route: revocation.device_route,
                                grant_serial: revocation.grant_serial,
                                signed_revocation: revocation,
                            },
                        ),
                    },
                )),
            )
            .await
            .expect("acknowledge last-device revocation"),
        super::pairing_revocation_ack::AcknowledgeRevocationCommittedOutcome::Committed { .. }
    ));
    complete_active_membership_transition(&store, &clock).await;

    let retained = store
        .load_global_key_state()
        .await
        .expect("load retained revoked-device secrets")
        .expect("global key singleton remains");
    assert_eq!(
        retained.device_revoked_at_for_test(grant.device_route),
        Some(revoked_at_ms)
    );
    assert_eq!(
        retained.device_key_epochs_for_test(grant.device_route),
        Some((1, 1))
    );
    let retained_canonical = retained
        .canonical_bytes_for_test()
        .expect("encode retained revoked-device singleton");
    assert!(
        retained_canonical
            .windows(32)
            .any(|window| window == [0xc2; 32])
    );
    assert!(
        retained_canonical
            .windows(32)
            .any(|window| window == [0xc3; 32])
    );
    assert_eq!(
        retained
            .retained_retired_secret_count()
            .expect("count pinned shared and directed secrets"),
        3,
        "one pinned retired catalog key plus two revoked-device transport keys remain"
    );

    let deadline_ms = revoked_at_ms + RETIRED_KEY_RETENTION_MS;
    let before_deadline = artifact_bytes(&root.database());
    assert_eq!(
        store
            .gc_expired_retired_shared_keys(deadline_ms - 1)
            .await
            .expect("retain revoked-device secrets until the full deadline"),
        RetiredKeyGcOutcome {
            mutation: RetiredKeyMutationOutcome::AlreadyApplied,
            collected: 0,
        }
    );
    assert_eq!(artifact_bytes(&root.database()), before_deadline);

    assert_eq!(
        store
            .gc_expired_retired_shared_keys(deadline_ms)
            .await
            .expect("collect both directed secrets at the exact deadline"),
        RetiredKeyGcOutcome {
            mutation: RetiredKeyMutationOutcome::Applied,
            collected: 2,
        }
    );
    let collected = store
        .load_global_key_state()
        .await
        .expect("load collected revoked-device tombstone")
        .expect("global key singleton remains after directed GC");
    assert!(collected.contains_device_route(grant.device_route));
    assert_eq!(
        collected.device_revoked_at_for_test(grant.device_route),
        Some(revoked_at_ms)
    );
    assert_eq!(
        collected.device_key_epochs_for_test(grant.device_route),
        Some((1, 1))
    );
    let collected_canonical = collected
        .canonical_bytes_for_test()
        .expect("encode collected revoked-device tombstone");
    assert!(
        !collected_canonical
            .windows(32)
            .any(|window| window == [0xc2; 32])
    );
    assert!(
        !collected_canonical
            .windows(32)
            .any(|window| window == [0xc3; 32])
    );
    assert_eq!(
        collected
            .retained_retired_secret_count()
            .expect("count remaining pinned shared key"),
        1
    );
    store
        .shutdown()
        .await
        .expect("shutdown after directed-secret GC");

    let config = config(&root, clock.clone());
    let mut transaction_state = super::sqlite::open(
        &config,
        load_or_create_storage_kek(&keys, &root.database()).expect("reload directed-GC StorageKEK"),
    )
    .expect("reopen directed-GC transaction state");
    assert_ledger_matches_singleton(&transaction_state);
    let before_retry = singleton_storage_evidence(&transaction_state);
    let changes = transaction_state.connection.total_changes();
    assert_eq!(
        gc_expired(&mut transaction_state, &config, deadline_ms)
            .expect("retry exact directed-secret GC"),
        RetiredKeyGcOutcome {
            mutation: RetiredKeyMutationOutcome::AlreadyApplied,
            collected: 0,
        }
    );
    assert_eq!(transaction_state.connection.total_changes(), changes);
    assert_eq!(singleton_storage_evidence(&transaction_state), before_retry);
    assert_ledger_matches_singleton(&transaction_state);
    drop(transaction_state);

    let reopened = RuntimeStoreHandle::open(
        config,
        load_or_create_storage_kek(&keys, &root.database())
            .expect("reload full-audit directed-GC StorageKEK"),
    )
    .await
    .expect("full open authenticates directed-secret GC");
    let tombstone = reopened
        .load_global_key_state()
        .await
        .expect("load restart-safe device tombstone")
        .expect("global key singleton survives restart");
    assert!(tombstone.contains_device_route(grant.device_route));
    assert_eq!(
        tombstone.device_revoked_at_for_test(grant.device_route),
        Some(revoked_at_ms)
    );
    assert_eq!(
        tombstone.device_key_epochs_for_test(grant.device_route),
        Some((1, 1))
    );
    let canonical = tombstone
        .canonical_bytes_for_test()
        .expect("encode restart-safe device tombstone");
    assert!(!canonical.windows(32).any(|window| window == [0xc2; 32]));
    assert!(!canonical.windows(32).any(|window| window == [0xc3; 32]));
    reopened
        .shutdown()
        .await
        .expect("shutdown restarted directed-GC store");
}

#[test]
fn snapshot_device_reply_transport_is_not_a_shared_key_retention_owner() {
    assert!(
        RetiredSharedKeyOwner::new(
            RetiredKeyOwnerKind::Snapshot,
            [0xa3; 16],
            KeyPurpose::DeviceReplyTx,
            None,
            1,
        )
        .is_err(),
        "snapshot/backfill uses directed DeviceReplyTx and must not forge a shared-key owner"
    );
}

fn catalog_replay_scope(epoch: u64) -> [u8; super::remote_replay::REMOTE_REPLAY_SCOPE_BYTES] {
    let mut scope = [0_u8; super::remote_replay::REMOTE_REPLAY_SCOPE_BYTES];
    scope[0] = 1;
    scope[1] = 4;
    scope[2..18].fill(0x71);
    scope[18..26].copy_from_slice(&1_u64.to_be_bytes());
    scope[50..58].copy_from_slice(&epoch.to_be_bytes());
    scope
}

#[tokio::test]
async fn replay_pin_and_shared_owner_share_one_restart_safe_transaction() {
    let root = TestRoot::new("retired-key-replay-owner-atomic");
    let keys = MemoryKeyStore::new();
    let clock = Arc::new(AtomicU64::new(NOW_MS));
    seed_retired_catalog(&root, &keys, clock.clone()).await;
    let config = config(&root, clock);
    let scope = catalog_replay_scope(1);
    let pin_id = [0xb1; 16];
    let replay_owner = owner(RetiredKeyOwnerKind::Replay, 0xb1);
    let mut state = super::sqlite::open(
        &config,
        load_or_create_storage_kek(&keys, &root.database())
            .expect("reopen replay-owner StorageKEK"),
    )
    .expect("open replay-owner transaction state");
    assert_eq!(
        super::remote_replay::admit(
            &mut state,
            &config,
            super::remote_replay::RemoteReplayAdmission {
                scope,
                sender_counter: 1,
                ciphertext_sha256: [0xb2; 32],
                scope_capacity: super::remote_replay::MAX_REMOTE_REPLAY_SCOPES,
            },
        )
        .expect("admit catalog replay scope"),
        super::remote_replay::RemoteReplayStoreDecision::Fresh
    );
    super::remote_replay::retire_scope(&mut state, &config, scope, NOW_MS)
        .expect("retire catalog replay scope");
    super::remote_replay::pin_retired_scope(&mut state, &config, scope, pin_id)
        .expect("atomically pin replay row and acquire shared-key owner");
    assert!(owner_is_durable(&state, replay_owner));
    assert_ledger_matches_singleton(&state);
    drop(state);

    let mut reopened = super::sqlite::open(
        &config,
        load_or_create_storage_kek(&keys, &root.database())
            .expect("reload replay-owner StorageKEK"),
    )
    .expect("reopen durable replay owner");
    assert!(owner_is_durable(&reopened, replay_owner));
    let changes = reopened.connection.total_changes();
    super::remote_replay::pin_retired_scope(&mut reopened, &config, scope, pin_id)
        .expect("exact pin retry is idempotent");
    assert_eq!(reopened.connection.total_changes(), changes);
    assert_eq!(
        gc_expired(&mut reopened, &config, NOW_MS + RETIRED_KEY_RETENTION_MS,)
            .expect("replay owner blocks shared-key GC")
            .collected,
        0
    );

    super::remote_replay::release_retired_pin(&mut reopened, &config, scope, pin_id)
        .expect("atomically release replay pin and shared-key owner");
    assert!(!owner_is_durable(&reopened, replay_owner));
    let changes = reopened.connection.total_changes();
    super::remote_replay::release_retired_pin(&mut reopened, &config, scope, pin_id)
        .expect("exact release retry is idempotent");
    assert_eq!(reopened.connection.total_changes(), changes);
    assert_eq!(
        gc_expired(&mut reopened, &config, NOW_MS + RETIRED_KEY_RETENTION_MS,)
            .expect("released replay owner permits shared-key GC")
            .collected,
        1
    );
    assert_eq!(
        super::remote_replay::gc_retired(
            &mut reopened,
            &config,
            NOW_MS + RETIRED_KEY_RETENTION_MS,
        )
        .expect("released replay row is independently collectible"),
        1
    );
    assert_ledger_matches_singleton(&reopened);
}

#[tokio::test]
async fn handle_owner_lifecycle_survives_restart_and_obeys_recovery_barrier() {
    let root = TestRoot::new("retired-key-handle-lifecycle");
    let keys = MemoryKeyStore::new();
    let clock = Arc::new(AtomicU64::new(NOW_MS));
    seed_retired_catalog(&root, &keys, clock.clone()).await;
    let config = config(&root, clock);
    let publication = owner(RetiredKeyOwnerKind::Publication, 0xc1);

    let store = RuntimeStoreHandle::open(
        config.clone(),
        load_or_create_storage_kek(&keys, &root.database())
            .expect("load retired-key handle StorageKEK"),
    )
    .await
    .expect("open retired-key handle store");
    assert_eq!(
        store
            .acquire_retired_shared_key_owner(publication)
            .await
            .expect("acquire owner through Safety lane"),
        RetiredKeyMutationOutcome::Applied
    );
    store.shutdown().await.expect("shutdown acquired owner");

    let gated = RuntimeStoreHandle::open(
        config.clone(),
        load_or_create_storage_kek(&keys, &root.database())
            .expect("reload recovery-gated StorageKEK"),
    )
    .await
    .expect("reopen owner before recovery gate");
    let _cursor = gated
        .begin_recovery_scan()
        .await
        .expect("begin retired-key recovery barrier");
    assert!(matches!(
        gated.acquire_retired_shared_key_owner(publication).await,
        Err(RuntimeStoreError::RecoveryInProgress)
    ));
    assert!(matches!(
        gated.release_retired_shared_key_owner(publication).await,
        Err(RuntimeStoreError::RecoveryInProgress)
    ));
    assert!(matches!(
        gated
            .gc_expired_retired_shared_keys(NOW_MS + RETIRED_KEY_RETENTION_MS)
            .await,
        Err(RuntimeStoreError::RecoveryInProgress)
    ));
    gated
        .shutdown()
        .await
        .expect("shutdown recovery-gated owner store");

    let resumed = RuntimeStoreHandle::open(
        config,
        load_or_create_storage_kek(&keys, &root.database())
            .expect("reload post-recovery StorageKEK"),
    )
    .await
    .expect("reopen durable owner after recovery barrier");
    assert_eq!(
        resumed
            .release_retired_shared_key_owner(publication)
            .await
            .expect("release exact owner after restart"),
        RetiredKeyMutationOutcome::Applied
    );
    assert_eq!(
        resumed
            .release_retired_shared_key_owner(publication)
            .await
            .expect("retry exact owner release"),
        RetiredKeyMutationOutcome::AlreadyApplied
    );
    assert_eq!(
        resumed
            .gc_expired_retired_shared_keys(NOW_MS + RETIRED_KEY_RETENTION_MS)
            .await
            .expect("collect released retired key through Safety lane"),
        RetiredKeyGcOutcome {
            mutation: RetiredKeyMutationOutcome::Applied,
            collected: 1,
        }
    );
    resumed
        .shutdown()
        .await
        .expect("shutdown completed owner lifecycle");
}

#[tokio::test]
async fn singleton_revision_hash_and_token_tamper_reject_owner_mutation_without_rewrite() {
    for axis in ["revision", "directory-hash", "metadata-token"] {
        let root = TestRoot::new(&format!("retired-key-tamper-{axis}"));
        let keys = MemoryKeyStore::new();
        let clock = Arc::new(AtomicU64::new(NOW_MS));
        seed_retired_catalog(&root, &keys, clock.clone()).await;
        let config = config(&root, clock);
        let mut state = super::sqlite::open(
            &config,
            load_or_create_storage_kek(&keys, &root.database()).expect("reopen tamper StorageKEK"),
        )
        .expect("open retired-key tamper state");
        match axis {
            "revision" => {
                state
                    .connection
                    .execute(
                        "UPDATE remote_key_directory
                         SET revision = '00000000000000000003' WHERE singleton = 1",
                        [],
                    )
                    .expect("tamper singleton revision");
            }
            "directory-hash" => {
                state
                    .connection
                    .execute(
                        "UPDATE remote_key_directory SET directory_hash = ?1 WHERE singleton = 1",
                        [&[0xf1; 32][..]],
                    )
                    .expect("tamper singleton directory hash");
            }
            "metadata-token" => {
                state
                    .connection
                    .execute(
                        "UPDATE remote_key_directory SET metadata_token = ?1 WHERE singleton = 1",
                        [&[0xf2; 32][..]],
                    )
                    .expect("tamper singleton metadata token");
            }
            _ => unreachable!(),
        }
        let before = singleton_storage_evidence(&state);
        let changes = state.connection.total_changes();
        assert!(matches!(
            acquire_owner(
                &mut state,
                &config,
                owner(RetiredKeyOwnerKind::Publication, 0xb1),
            ),
            Err(RuntimeStoreError::UnknownOrCorruptSchema)
        ));
        assert_eq!(state.connection.total_changes(), changes);
        assert_eq!(singleton_storage_evidence(&state), before);
    }
}
