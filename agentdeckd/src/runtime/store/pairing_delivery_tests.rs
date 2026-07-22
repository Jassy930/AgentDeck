//! P4.3 G3 PairResponseReceived Store 子片 focused tests。

use std::path::Path;
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};

use agentdeck_crypto::{SigningKey, sign_pair_response_received, sign_tbs};
use agentdeck_protocol::e2ee::{
    AuthorizationCapabilityV1, AuthorizationPermissionV1, PairResponseReceivedV1,
};
use agentdeck_protocol::relay_v2::frame::{
    GrantCommitted, OpaqueRouteFrame, PairRouteCloseOutcome, PairRouteClosed, RelayFrameBody,
};
use agentdeck_protocol::relay_v2::{
    DeviceRevocation, DeviceRouteId, Ed25519Signature, GrantSerial, PairRouteId,
    RELAY_PROTOCOL_VERSION, StreamRouteId, encode,
};
use agentdeck_protocol::runtime::{
    CodexConversationConfiguration, ConversationConfiguration, StreamCursor,
    VendorConfigurationSnapshot,
};
use agentdeck_protocol::runtime::{PairingReceipt, PairingState};
use agentdeck_protocol::{CodexApprovalPolicy, CodexReasoningEffort, CodexSandboxMode};
use tokio::sync::Semaphore;

use crate::remote::access::{PairResponseAccessBinding, VerifiedPairResponseReceipt};
use crate::runtime::AgentRouter;
use crate::runtime::backfill::BarrierRequest;
use crate::runtime::catalog_snapshot::CatalogSnapshotProvider;
use crate::runtime::connection::PrincipalIssuer;
use crate::runtime::events::{RegisterStreamBarrier, RuntimeStreamTarget, WatchGeneration};
use crate::runtime::model::{
    MachineEnrollmentState, RuntimeCommitOperation, RuntimeStoreConfig, RuntimeStoreError,
    RuntimeStoreOperation,
};
use crate::runtime::snapshot::{
    SNAPSHOT_BUILD_MEMORY_BYTES, SnapshotMaterialization, SnapshotMaterializer,
    assemble_build_snapshot,
};
use crate::security::{MemoryKeyStore, StorageKek, load_or_create_storage_kek};

use super::RuntimeStoreHandle;
use super::pairing::{AcceptPairRequest, CommitPairPending, PairingInviteLifecycle};
use super::pairing_delivery::{
    AcknowledgePairResponseReceived, AcknowledgePairResponseReceivedOutcome,
};
use super::pairing_grant::ConversationKeyRotation;
use super::pairing_grant::PairingGrantPreparation;
use super::pairing_grant_allocation_tests::{
    complete_active_membership_transition,
    complete_active_membership_transition_with_production_finalize,
};
use super::pairing_grant_commit::{AcknowledgeGrantCommitted, GrantCommittedRecovery};
use super::pairing_grant_tests::{
    awaiting_pairing, awaiting_pairing_with_authorization, complete_active_zero_cut_transition,
    grant_input, grant_input_with, secret,
};
use super::pairing_grant_tx::ConfirmPairingGrantOutcome;
use super::pairing_revocation::{BeginDeviceRevocation, BeginDeviceRevocationOutcome};
use super::pairing_terminal::RECEIPT_RETENTION_MS;
use super::pairing_tests::{
    GenerousCapacity, NOW_MS, OneShotFault, TestClock, TestRoot, artifact_bytes, make_active,
    pending_envelope, prepare_unused_pairing, verified_request_with_authorization,
};
use super::publication::PublicationScope;
use super::{
    ConfigureConversation, ConfigureConversationOutcome, IdempotencyOwner, NewConversation,
    RuntimeBackfillPlan, RuntimeBackfillTarget, RuntimeId, RuntimeIdKind,
};
use crate::runtime::model::ConversationDescriptor;

const DEVICE_SIGN_SEED: [u8; 32] = [0xa4; 32];
const ROOT_SIGN_SEED: [u8; 32] = [0x41; 32];

fn grant_committed_frame(recovery: &super::pairing_grant_tx::GrantPreparingRecovery) -> Vec<u8> {
    encode(&OpaqueRouteFrame {
        version: RELAY_PROTOCOL_VERSION,
        body: RelayFrameBody::GrantCommitted(GrantCommitted {
            device_route: recovery.device_route(),
            grant_serial: recovery.grant_serial(),
            grant_hash: recovery.grant_hash(),
        }),
    })
}

fn close_terminal(
    pair_route: agentdeck_protocol::relay_v2::PairRouteId,
    outcome: PairRouteCloseOutcome,
) -> Vec<u8> {
    encode(&OpaqueRouteFrame {
        version: RELAY_PROTOCOL_VERSION,
        body: RelayFrameBody::PairRouteClosed(PairRouteClosed {
            pair_route,
            outcome,
        }),
    })
}

async fn prepare_committed(
    store: &RuntimeStoreHandle,
    clock: &AtomicU64,
) -> (PairingGrantPreparation, GrantCommittedRecovery) {
    prepare_committed_with_authorization(store, clock, None).await
}

async fn prepare_committed_with_authorization(
    store: &RuntimeStoreHandle,
    clock: &AtomicU64,
    authorization: Option<(
        Vec<AuthorizationCapabilityV1>,
        Vec<AuthorizationPermissionV1>,
    )>,
) -> (PairingGrantPreparation, GrantCommittedRecovery) {
    let (binding, data_cert) = make_active(store).await;
    let preparation = match authorization {
        Some((capabilities, permissions)) => {
            awaiting_pairing_with_authorization(
                store,
                &binding,
                &data_cert,
                capabilities,
                permissions,
            )
            .await
        }
        None => awaiting_pairing(store, &binding, &data_cert).await,
    };
    let confirmed = store
        .confirm_pairing_grant(grant_input(&preparation, &binding, &data_cert))
        .await
        .expect("confirm grant before delivery");
    let installing = match confirmed {
        ConfirmPairingGrantOutcome::Confirmed { recovery, .. } => recovery,
        other => panic!("fresh confirm must freeze grant: {other:?}"),
    };
    clock.store(NOW_MS + 1, Ordering::SeqCst);
    let committed = store
        .acknowledge_grant_committed(AcknowledgeGrantCommitted::new(
            preparation.pairing_id(),
            grant_committed_frame(&installing),
        ))
        .await
        .expect("commit grant before delivery");
    let recovery = match committed {
        super::pairing_grant_commit::AcknowledgeGrantCommittedOutcome::Committed { recovery } => {
            recovery
        }
        other => panic!("fresh GrantCommitted ACK must transition: {other:?}"),
    };
    (preparation, recovery)
}

fn verified_receipt(recovery: &GrantCommittedRecovery) -> VerifiedPairResponseReceipt {
    verified_receipt_with_seed(recovery, DEVICE_SIGN_SEED)
}

fn verified_receipt_with_seed(
    recovery: &GrantCommittedRecovery,
    device_sign_seed: [u8; 32],
) -> VerifiedPairResponseReceipt {
    let binding = PairResponseAccessBinding::from_frozen(
        recovery.invite(),
        recovery.request_hash(),
        recovery.relay_grant(),
        recovery.pair_response(),
    )
    .expect("rebuild authenticated response binding");
    let receipt = sign_pair_response_received(
        &SigningKey::from_seed(&device_sign_seed),
        binding.info(),
        binding.receipt_context(),
        PairResponseReceivedV1 {
            request_hash: recovery.request_hash(),
            grant_hash: recovery.grant_hash(),
            response_hash: recovery.response_hash(),
            signature: Ed25519Signature([0; 64]),
        },
    )
    .expect("sign endpoint receipt");
    binding
        .verify_signed_receipt(
            &receipt
                .canonical_bytes()
                .expect("canonical endpoint receipt"),
        )
        .expect("verify endpoint receipt")
}

fn delivery_counts(database: &std::path::Path) -> (u64, u64, u64, u64) {
    rusqlite::Connection::open(database)
        .expect("open delivery evidence DB")
        .query_row(
            "SELECT
                 (SELECT COUNT(*) FROM remote_pairings WHERE lifecycle = 'delivered'),
                 (SELECT COUNT(*) FROM remote_pairing_receipts WHERE action = 'confirmed'),
                 (SELECT COUNT(*) FROM remote_control_outbox
                    WHERE operation_kind = 'closePairRoute'),
                 remote_control_outbox_count
             FROM runtime_meta WHERE singleton = 1",
            [],
            |row| Ok((row.get(0)?, row.get(1)?, row.get(2)?, row.get(3)?)),
        )
        .expect("read delivery evidence")
}

async fn authorization_only_store_for_test(database: &Path, revoking: bool) -> RuntimeStoreHandle {
    let keys = MemoryKeyStore::new();
    let storage_kek =
        load_or_create_storage_kek(&keys, database).expect("create authorization test StorageKEK");
    authorization_store_for_test(database, storage_kek, None, revoking, true, false).await
}

async fn authorization_store_for_test(
    database: &Path,
    storage_kek: StorageKek,
    authorization: Option<(
        Vec<AuthorizationCapabilityV1>,
        Vec<AuthorizationPermissionV1>,
    )>,
    revoking: bool,
    complete_transition: bool,
    production_finalize: bool,
) -> RuntimeStoreHandle {
    let clock = Arc::new(AtomicU64::new(NOW_MS));
    let store = RuntimeStoreHandle::open(
        RuntimeStoreConfig::new(database.to_path_buf())
            .with_clock(TestClock(clock.clone()))
            .with_capacity_probe(GenerousCapacity),
        storage_kek,
    )
    .await
    .expect("open authorization-only test Store");
    let (preparation, committed) =
        prepare_committed_with_authorization(&store, &clock, authorization).await;
    let proof = verified_receipt(&committed);
    clock.store(NOW_MS + 2, Ordering::SeqCst);
    let close = match store
        .acknowledge_pair_response_received(AcknowledgePairResponseReceived::new(
            preparation.pairing_id(),
            &proof,
        ))
        .await
        .expect("deliver authorization-only test grant")
    {
        AcknowledgePairResponseReceivedOutcome::Delivered { close } => close,
        other => panic!("fresh test grant must deliver: {other:?}"),
    };
    store
        .acknowledge_pair_route_close(
            preparation.pairing_id(),
            close_terminal(close.pair_route(), PairRouteCloseOutcome::Closed),
        )
        .await
        .expect("scrub authorization-only pairing row");
    assert!(
        store
            .list_pairing_recovery()
            .await
            .expect("read scrubbed pairing recovery")
            .is_empty()
    );
    if complete_transition {
        // Initial activation now owns a real key-transition fence. Production manager recovery
        // completes this zero-cut transition before publisher admission or local revoke may start;
        // shared fixtures must model the same ordering instead of bypassing the fence.
        if production_finalize {
            complete_active_membership_transition_with_production_finalize(&store, &clock).await;
        } else {
            complete_active_zero_cut_transition(&store).await;
        }
    }

    if revoking {
        let Some(MachineEnrollmentState::Active(active)) = store
            .load_machine_enrollment_state()
            .await
            .expect("load authorization-only active enrollment")
        else {
            panic!("authorization-only test Store must remain Active")
        };
        let grant = committed.relay_grant();
        let mut revocation = DeviceRevocation {
            machine_route: grant.machine_route,
            device_route: grant.device_route,
            grant_serial: grant.grant_serial,
            root_key_id: grant.root_key_id,
            trust_epoch: grant.trust_epoch,
            signature: Ed25519Signature([0; 64]),
        };
        revocation.signature = sign_tbs(
            &SigningKey::from_seed(&ROOT_SIGN_SEED),
            &revocation.to_be_signed_v1(
                committed.invite().relay_server_id,
                active.binding.root_fingerprint,
            ),
        )
        .into();
        clock.store(NOW_MS + 3, Ordering::SeqCst);
        assert!(matches!(
            store
                .begin_device_revocation(BeginDeviceRevocation::local(revocation))
                .await
                .expect("begin authorization-only test revocation"),
            BeginDeviceRevocationOutcome::Prepared { .. }
        ));
    }
    store
}

pub(crate) async fn active_authorization_store_for_test(database: &Path) -> RuntimeStoreHandle {
    authorization_only_store_for_test(database, false).await
}

pub(crate) async fn revoking_authorization_store_for_test(database: &Path) -> RuntimeStoreHandle {
    authorization_only_store_for_test(database, true).await
}

pub(crate) async fn active_authorization_store_with_permissions_for_test(
    database: &Path,
    storage_kek: StorageKek,
    capabilities: Vec<AuthorizationCapabilityV1>,
    permissions: Vec<AuthorizationPermissionV1>,
) -> RuntimeStoreHandle {
    authorization_store_for_test(
        database,
        storage_kek,
        Some((capabilities, permissions)),
        false,
        true,
        false,
    )
    .await
}

pub(crate) async fn active_authorization_store_with_pending_transition_for_test(
    database: &Path,
    storage_kek: StorageKek,
    capabilities: Vec<AuthorizationCapabilityV1>,
    permissions: Vec<AuthorizationPermissionV1>,
) -> RuntimeStoreHandle {
    authorization_store_for_test(
        database,
        storage_kek,
        Some((capabilities, permissions)),
        false,
        false,
        false,
    )
    .await
}

pub(crate) async fn production_aligned_active_authorization_store_for_test(
    database: &Path,
    storage_kek: StorageKek,
    capabilities: Vec<AuthorizationCapabilityV1>,
    permissions: Vec<AuthorizationPermissionV1>,
) -> RuntimeStoreHandle {
    authorization_store_for_test(
        database,
        storage_kek,
        Some((capabilities, permissions)),
        false,
        true,
        true,
    )
    .await
}

pub(crate) async fn two_active_authorization_store_with_permissions_for_test(
    database: &Path,
    storage_kek: StorageKek,
    capabilities: Vec<AuthorizationCapabilityV1>,
    permissions: Vec<AuthorizationPermissionV1>,
) -> RuntimeStoreHandle {
    let clock = Arc::new(AtomicU64::new(NOW_MS));
    let store = RuntimeStoreHandle::open(
        RuntimeStoreConfig::new(database.to_path_buf()).with_clock(TestClock(clock.clone())),
        storage_kek,
    )
    .await
    .expect("open two-device authorization Store");
    let (first_preparation, first_committed) = prepare_committed_with_authorization(
        &store,
        &clock,
        Some((capabilities.clone(), permissions.clone())),
    )
    .await;
    deliver_and_close_for_test(
        &store,
        &clock,
        first_preparation,
        first_committed,
        DEVICE_SIGN_SEED,
        NOW_MS + 2,
    )
    .await;
    complete_active_zero_cut_transition(&store).await;
    store
        .create_publication_stream(
            [0x21; 16],
            PublicationScope::Catalog,
            [0x22; 16],
            [0x23; 16],
        )
        .await
        .expect("create catalog stream before second membership transition");

    let (binding, data_cert) = make_active(&store).await;
    let (pairing_id, invite) = prepare_unused_pairing(
        &store,
        &binding,
        &data_cert,
        PairRouteId::from_bytes([0xb1; 16]),
        0xb2,
        0xb3,
        "p44-second-active-device",
    )
    .await;
    let verified = verified_request_with_authorization(
        &invite,
        0xb3,
        0xb4,
        0xb5,
        0xb6,
        capabilities,
        permissions,
    );
    let request_hash = verified.request_hash();
    store
        .accept_pair_request(AcceptPairRequest::new(pairing_id, verified))
        .await
        .expect("accept second authorized request");
    store
        .commit_pair_pending(CommitPairPending::new(
            pairing_id,
            request_hash,
            pending_envelope(0xb7),
        ))
        .await
        .expect("commit second authorized pending");
    let preparation = store
        .load_pairing_invite(pairing_id)
        .await
        .expect("load second awaiting pairing")
        .expect("second pairing exists")
        .into_grant_preparation()
        .expect("second pairing is awaiting confirmation");
    let second_route = DeviceRouteId::from_bytes([0xd2; 16]);
    let global = store
        .load_global_key_state()
        .await
        .expect("load first global key state")
        .expect("first global key state exists")
        .next_for_device(second_route, secret(0xe1), secret(0xe2), secret(0xe3))
        .expect("append second device keys");
    let confirmed = store
        .confirm_pairing_grant(grant_input_with(
            &preparation,
            &binding,
            &data_cert,
            second_route,
            GrantSerial::new(1),
            global,
            None,
            0xe4,
        ))
        .await
        .expect("confirm second device");
    let installing = match confirmed {
        ConfirmPairingGrantOutcome::Confirmed { recovery, .. } => recovery,
        other => panic!("second device must confirm: {other:?}"),
    };
    clock.store(NOW_MS + 3, Ordering::SeqCst);
    let committed = match store
        .acknowledge_grant_committed(AcknowledgeGrantCommitted::new(
            preparation.pairing_id(),
            grant_committed_frame(&installing),
        ))
        .await
        .expect("commit second grant")
    {
        super::pairing_grant_commit::AcknowledgeGrantCommittedOutcome::Committed { recovery } => {
            recovery
        }
        other => panic!("second GrantCommitted must transition: {other:?}"),
    };
    deliver_and_close_for_test(
        &store,
        &clock,
        preparation,
        committed,
        [0xb4; 32],
        NOW_MS + 4,
    )
    .await;
    complete_active_membership_transition(&store, &clock).await;
    store
}

pub(crate) struct PendingNewDeviceTransitionFixture {
    pub(crate) store: RuntimeStoreHandle,
    pub(crate) device_route: DeviceRouteId,
    pub(crate) conversation_id: RuntimeId,
}

/// 本机先有 conversation/history 与 Relay-committed cut，再加入首个 remote device，
/// 且保留 membership transition 未完成。该 fixture 只供跨层 transition E2E 使用。
pub(crate) async fn pending_new_device_transition_fixture_for_test(
    database: &Path,
    storage_kek: StorageKek,
    capabilities: Vec<AuthorizationCapabilityV1>,
    permissions: Vec<AuthorizationPermissionV1>,
) -> PendingNewDeviceTransitionFixture {
    let clock = Arc::new(AtomicU64::new(NOW_MS));
    let store = RuntimeStoreHandle::open(
        RuntimeStoreConfig::new(database.to_path_buf())
            .with_clock(TestClock(clock.clone()))
            .with_capacity_probe(GenerousCapacity),
        storage_kek,
    )
    .await
    .expect("open pending new-device transition Store");
    let conversation_id =
        RuntimeId::from_bytes(RuntimeIdKind::Conversation, [0xc1; 16]).expect("conversation id");
    let descriptor = ConversationDescriptor {
        agent_kind: agentdeck_protocol::AgentKind::Codex,
        title: Some("new-device transition conversation".to_owned()),
        cwd: std::path::PathBuf::from("/tmp/agentdeck-new-device-transition"),
    };
    let created = store
        .create_conversation(NewConversation {
            conversation_id,
            adapter_state_key: RuntimeId::from_bytes(RuntimeIdKind::AdapterState, [0xc2; 16])
                .expect("adapter state key"),
            descriptor: descriptor.clone(),
        })
        .await
        .expect("create transition conversation");
    store
        .create_publication_stream(
            [0x21; 16],
            PublicationScope::Catalog,
            [0x22; 16],
            [0x23; 16],
        )
        .await
        .expect("create catalog stream before first remote-device transition");

    assert!(matches!(
        store
            .configure_conversation(ConfigureConversation {
                conversation_id,
                owner: IdempotencyOwner::Local {
                    machine_trust_domain: store
                        .machine_trust_domain()
                        .expect("load transition trust domain"),
                    uid: 501,
                    client_installation_id: [0xc3; 16],
                },
                idempotency_key: "new-device-transition-event".to_owned(),
                expected_configuration_revision: 0,
                configuration: ConversationConfiguration::new(VendorConfigurationSnapshot::Codex(
                    CodexConversationConfiguration::new(
                        CodexApprovalPolicy::OnRequest,
                        CodexSandboxMode::WorkspaceWrite,
                        CodexReasoningEffort::Medium,
                    )
                ),),
            })
            .await
            .expect("append transition conversation event"),
        ConfigureConversationOutcome::Applied { .. }
    ));
    let plan = store
        .acquire_backfill_pin(RuntimeBackfillTarget::Conversation(conversation_id), None)
        .await
        .expect("pin transition conversation event");
    let RuntimeBackfillPlan::Pinned(pin) = plan else {
        panic!("fresh transition event must require a pinned backfill page")
    };
    let page = store
        .load_event_backfill_page(pin.clone(), None)
        .await
        .expect("load transition conversation event");
    let event = page.events.last().expect("transition event exists").clone();
    drop(page);
    store
        .release_backfill_pin(pin.pin_id)
        .await
        .expect("release transition event pin");
    // 首设备 baseline 只能引用 production snapshot pipeline 已认证覆盖的 exact H。
    // Catalog 走真实 barrier/provider；conversation 走同一 linear build capability、
    // materializer、typed assembly 与 durable writer，不能用测试专用 row 注入旁路。
    let principal = PrincipalIssuer::local_only(
        store
            .machine_trust_domain()
            .expect("load snapshot principal trust domain"),
    )
    .issue_verified_local(501, [0xc4; 16])
    .expect("issue local snapshot principal");
    let catalog_provider = CatalogSnapshotProvider::with_clock(
        store.clone(),
        Arc::new(TestClock(clock.clone())),
        Arc::new(Semaphore::new(SNAPSHOT_BUILD_MEMORY_BYTES)),
    )
    .expect("create production catalog snapshot provider");
    let mut catalog_registration = store
        .register_stream_barrier(RegisterStreamBarrier {
            target: RuntimeStreamTarget::Catalog,
            generation: WatchGeneration::new(1).expect("catalog snapshot generation"),
            request: BarrierRequest::Subscribe {
                cursor: StreamCursor::BeforeFirst,
            },
        })
        .await
        .expect("capture exact catalog snapshot barrier");
    let catalog_page = catalog_provider
        .first_page(&mut catalog_registration, &principal)
        .await
        .expect("materialize exact catalog ready snapshot");
    assert_eq!(
        catalog_page.snapshot().base_catalog_cursor,
        StreamCursor::At(created.catalog_revision)
    );
    drop(catalog_page);
    drop(catalog_registration);
    drop(catalog_provider);

    let conversation_source = store
        .acquire_snapshot_build_source(conversation_id)
        .await
        .expect("capture exact conversation snapshot source");
    let materializer = SnapshotMaterializer::new(
        store.clone(),
        Arc::new(AgentRouter::with_runtime_store(store.clone())),
    );
    let SnapshotMaterialization::Build(mut conversation_build) = materializer
        .materialize(conversation_source)
        .await
        .expect("materialize exact conversation snapshot build")
    else {
        panic!("fresh managed conversation must require an exact snapshot build")
    };
    assert_eq!(
        conversation_build.base_event_cursor(),
        StreamCursor::At(event.event_seq)
    );
    let assembled = assemble_build_snapshot(&mut conversation_build, Vec::new())
        .expect("assemble typed conversation snapshot");
    let write = conversation_build
        .bind_assembled_snapshot(assembled)
        .expect("bind exact conversation snapshot write");
    store
        .store_conversation_snapshot(write)
        .await
        .expect("store exact conversation ready snapshot");

    let conversation_stream_id: Vec<u8> = rusqlite::Connection::open(database)
        .expect("open transition stream mapping")
        .query_row(
            "SELECT publication_stream_id FROM publication_streams\n             WHERE scope = 'conversation' AND conversation_id = ?1",
            [conversation_id.as_bytes().as_slice()],
            |row| row.get(0),
        )
        .expect("read transition conversation stream id");
    let conversation_stream_id: [u8; 16] = conversation_stream_id
        .as_slice()
        .try_into()
        .expect("fixed conversation stream id");
    let (binding, data_cert) = make_active(&store).await;
    let preparation = awaiting_pairing_with_authorization(
        &store,
        &binding,
        &data_cert,
        capabilities,
        permissions,
    )
    .await;
    let device_route = DeviceRouteId::from_bytes([0xd1; 16]);
    let conversation_route = StreamRouteId::from_bytes(
        store
            .load_publication_stream_record(conversation_stream_id)
            .await
            .expect("load first-device conversation publication stream")
            .stream_route,
    );
    let initial_global = super::pairing_grant::GlobalKeyStateV1::bootstrap_with_conversations(
        1,
        1,
        secret(0xdb),
        device_route,
        1,
        secret(0xdc),
        1,
        secret(0xdd),
        vec![ConversationKeyRotation::new(
            conversation_route,
            secret(0xde),
        )],
    )
    .expect("bootstrap first remote device over existing conversation");
    let confirmed = store
        .confirm_pairing_grant(grant_input_with(
            &preparation,
            &binding,
            &data_cert,
            device_route,
            GrantSerial::new(1),
            initial_global,
            None,
            0xdf,
        ))
        .await
        .expect("confirm first remote device");
    let installing = match confirmed {
        ConfirmPairingGrantOutcome::Confirmed { recovery, .. } => recovery,
        other => panic!("first remote device must confirm: {other:?}"),
    };
    clock.store(NOW_MS + 5, Ordering::SeqCst);
    let committed = match store
        .acknowledge_grant_committed(AcknowledgeGrantCommitted::new(
            preparation.pairing_id(),
            grant_committed_frame(&installing),
        ))
        .await
        .expect("commit first remote-device grant")
    {
        super::pairing_grant_commit::AcknowledgeGrantCommittedOutcome::Committed { recovery } => {
            recovery
        }
        other => panic!("first remote-device GrantCommitted must transition: {other:?}"),
    };
    deliver_and_close_for_test(
        &store,
        &clock,
        preparation,
        committed,
        DEVICE_SIGN_SEED,
        NOW_MS + 6,
    )
    .await;

    PendingNewDeviceTransitionFixture {
        store,
        device_route,
        conversation_id,
    }
}

async fn deliver_and_close_for_test(
    store: &RuntimeStoreHandle,
    clock: &AtomicU64,
    preparation: PairingGrantPreparation,
    committed: GrantCommittedRecovery,
    device_sign_seed: [u8; 32],
    now_ms: u64,
) {
    let proof = verified_receipt_with_seed(&committed, device_sign_seed);
    clock.store(now_ms, Ordering::SeqCst);
    let close = match store
        .acknowledge_pair_response_received(AcknowledgePairResponseReceived::new(
            preparation.pairing_id(),
            &proof,
        ))
        .await
        .expect("deliver active test grant")
    {
        AcknowledgePairResponseReceivedOutcome::Delivered { close } => close,
        other => panic!("fresh active test grant must deliver: {other:?}"),
    };
    store
        .acknowledge_pair_route_close(
            preparation.pairing_id(),
            close_terminal(close.pair_route(), PairRouteCloseOutcome::Closed),
        )
        .await
        .expect("scrub delivered pairing row");
}

#[tokio::test]
async fn valid_receipt_atomically_delivers_replays_and_scrubs_only_after_close_ack() {
    let root = TestRoot::new("pairing-delivery-happy");
    let keys = MemoryKeyStore::new();
    let clock = Arc::new(AtomicU64::new(NOW_MS));
    let config = || {
        RuntimeStoreConfig::new(root.database())
            .with_capacity_probe(GenerousCapacity)
            .with_clock(TestClock(clock.clone()))
    };
    let store = RuntimeStoreHandle::open(
        config(),
        load_or_create_storage_kek(&keys, &root.database()).expect("load StorageKEK"),
    )
    .await
    .expect("open delivery store");
    let (preparation, committed) = prepare_committed(&store, &clock).await;
    let proof = verified_receipt(&committed);
    let before_committed_projection = artifact_bytes(&root.database());
    let committed_winner = store
        .load_pairing_winner(preparation.pairing_id())
        .await
        .expect("load authenticated GrantCommitted winner")
        .expect("confirmed receipt must exist");
    assert!(matches!(
        committed_winner.receipt(),
        PairingReceipt::Confirmed { .. }
    ));
    assert_eq!(committed_winner.state(), PairingState::GrantCommitted);
    assert_eq!(
        artifact_bytes(&root.database()),
        before_committed_projection
    );

    clock.store(NOW_MS + 2, Ordering::SeqCst);
    let delivered = store
        .acknowledge_pair_response_received(AcknowledgePairResponseReceived::new(
            preparation.pairing_id(),
            &proof,
        ))
        .await
        .expect("commit endpoint delivery");
    let close = match delivered {
        AcknowledgePairResponseReceivedOutcome::Delivered { close } => close,
        other => panic!("first valid receipt must deliver: {other:?}"),
    };
    assert_eq!(close.pairing_id(), preparation.pairing_id());
    assert_eq!(close.pair_route(), committed.invite().pair_route);
    assert_eq!(delivery_counts(&root.database()), (1, 1, 1, 1));
    let before_delivered_projection = artifact_bytes(&root.database());
    let delivered_winner = store
        .load_pairing_winner(preparation.pairing_id())
        .await
        .expect("load authenticated Delivered winner")
        .expect("delivered confirmed receipt must exist");
    assert!(matches!(
        delivered_winner.receipt(),
        PairingReceipt::Confirmed { .. }
    ));
    assert_eq!(delivered_winner.state(), PairingState::Delivered);
    assert_eq!(
        artifact_bytes(&root.database()),
        before_delivered_projection
    );
    assert_eq!(
        store
            .load_pairing_invite(preparation.pairing_id())
            .await
            .expect("load delivered pairing")
            .expect("secret row retained before Close ACK")
            .lifecycle(),
        PairingInviteLifecycle::Delivered
    );
    assert!(
        store
            .list_grant_committed_recovery()
            .await
            .expect("committed recovery after delivery")
            .is_empty()
    );

    let before_replay = artifact_bytes(&root.database());
    assert!(matches!(
        store
            .acknowledge_pair_response_received(AcknowledgePairResponseReceived::new(
                preparation.pairing_id(),
                &proof,
            ))
            .await
            .expect("exact delivery replay"),
        AcknowledgePairResponseReceivedOutcome::Replayed { close: _ }
    ));
    assert_eq!(artifact_bytes(&root.database()), before_replay);

    store
        .acknowledge_pair_route_close(
            preparation.pairing_id(),
            close_terminal(close.pair_route(), PairRouteCloseOutcome::Closed),
        )
        .await
        .expect("acknowledge ClosePairRoute");
    assert_eq!(delivery_counts(&root.database()), (0, 1, 0, 0));
    assert!(
        store
            .load_pairing_invite(preparation.pairing_id())
            .await
            .expect("load scrubbed pairing")
            .is_none()
    );
    store.shutdown().await.expect("shutdown delivery store");

    clock.store(NOW_MS + RECEIPT_RETENTION_MS, Ordering::SeqCst);
    let reopened = RuntimeStoreHandle::open(
        config(),
        load_or_create_storage_kek(&keys, &root.database()).expect("reload StorageKEK"),
    )
    .await
    .expect("reopen scrubbed delivery store");
    let before_tombstone_projection = artifact_bytes(&root.database());
    let tombstone_winner = reopened
        .load_pairing_winner(preparation.pairing_id())
        .await
        .expect("load authenticated retained tombstone winner")
        .expect("30-day confirmed tombstone must remain readable");
    assert!(matches!(
        tombstone_winner.receipt(),
        PairingReceipt::Confirmed { .. }
    ));
    assert_eq!(tombstone_winner.state(), PairingState::ClosedTombstone);
    assert_eq!(
        artifact_bytes(&root.database()),
        before_tombstone_projection
    );
    assert!(matches!(
        reopened
            .acknowledge_pair_response_received(AcknowledgePairResponseReceived::new(
                preparation.pairing_id(),
                &proof,
            ))
            .await,
        Err(RuntimeStoreError::PairingConflict)
    ));
    reopened.shutdown().await.expect("shutdown reopened store");
}

#[tokio::test]
async fn receipt_for_unknown_pairing_and_expired_receipt_are_zero_write_conflicts() {
    let root = TestRoot::new("pairing-delivery-conflicts");
    let keys = MemoryKeyStore::new();
    let clock = Arc::new(AtomicU64::new(NOW_MS));
    let config = RuntimeStoreConfig::new(root.database())
        .with_capacity_probe(GenerousCapacity)
        .with_clock(TestClock(clock.clone()));
    let store = RuntimeStoreHandle::open(
        config,
        load_or_create_storage_kek(&keys, &root.database()).expect("load StorageKEK"),
    )
    .await
    .expect("open conflict store");
    let (preparation, committed) = prepare_committed(&store, &clock).await;
    let proof = verified_receipt(&committed);

    let before_unknown = artifact_bytes(&root.database());
    let unknown =
        super::identity::RuntimeId::from_bytes(super::identity::RuntimeIdKind::Pairing, [0xee; 16])
            .expect("nonzero pairing id");
    assert!(matches!(
        store
            .acknowledge_pair_response_received(AcknowledgePairResponseReceived::new(
                unknown, &proof,
            ))
            .await,
        Err(RuntimeStoreError::PairingConflict)
    ));
    assert_eq!(artifact_bytes(&root.database()), before_unknown);

    clock.store(committed.invite().expires_at_ms, Ordering::SeqCst);
    let before_expired = artifact_bytes(&root.database());
    assert!(matches!(
        store
            .acknowledge_pair_response_received(AcknowledgePairResponseReceived::new(
                preparation.pairing_id(),
                &proof,
            ))
            .await,
        Err(RuntimeStoreError::PairingExpired)
    ));
    assert_eq!(artifact_bytes(&root.database()), before_expired);
    store.shutdown().await.expect("shutdown conflict store");
}

#[tokio::test]
async fn delivery_commit_fault_boundaries_converge_by_restart_and_exact_retry() {
    for (label, operation, committed) in [
        (
            "pairing-delivery-before-commit",
            RuntimeStoreOperation::AcknowledgePairResponseReceivedBeforeCommit,
            false,
        ),
        (
            "pairing-delivery-after-commit",
            RuntimeStoreOperation::AcknowledgePairResponseReceivedAfterCommit,
            true,
        ),
    ] {
        let root = TestRoot::new(label);
        let keys = MemoryKeyStore::new();
        let clock = Arc::new(AtomicU64::new(NOW_MS));
        let config = || {
            RuntimeStoreConfig::new(root.database())
                .with_capacity_probe(GenerousCapacity)
                .with_clock(TestClock(clock.clone()))
        };
        let setup = RuntimeStoreHandle::open(
            config(),
            load_or_create_storage_kek(&keys, &root.database()).expect("load StorageKEK"),
        )
        .await
        .expect("open delivery fault setup");
        let (preparation, recovery) = prepare_committed(&setup, &clock).await;
        let proof = verified_receipt(&recovery);
        clock.store(NOW_MS + 2, Ordering::SeqCst);
        setup.shutdown().await.expect("shutdown delivery setup");

        let faulted = RuntimeStoreHandle::open(
            config().with_fault_injector(Arc::new(OneShotFault {
                operation,
                fired: AtomicBool::new(false),
            })),
            load_or_create_storage_kek(&keys, &root.database()).expect("reload StorageKEK"),
        )
        .await
        .expect("open faulted delivery store");
        let error = faulted
            .acknowledge_pair_response_received(AcknowledgePairResponseReceived::new(
                preparation.pairing_id(),
                &proof,
            ))
            .await
            .expect_err("delivery fault must surface");
        assert_eq!(
            matches!(
                error,
                RuntimeStoreError::CommitOutcomeUnknown {
                    operation: RuntimeCommitOperation::AcknowledgePairResponseReceived,
                }
            ),
            committed
        );
        assert_eq!(
            faulted
                .list_pairing_terminal_recovery()
                .await
                .expect("read close recovery after delivery fault")
                .len(),
            usize::from(committed)
        );
        assert_eq!(
            faulted
                .list_grant_committed_recovery()
                .await
                .expect("read response recovery after delivery fault")
                .len(),
            usize::from(!committed)
        );
        faulted.shutdown().await.expect("shutdown faulted store");

        let reopened = RuntimeStoreHandle::open(
            config(),
            load_or_create_storage_kek(&keys, &root.database()).expect("reload StorageKEK"),
        )
        .await
        .expect("reopen delivery fault store");
        let retry = reopened
            .acknowledge_pair_response_received(AcknowledgePairResponseReceived::new(
                preparation.pairing_id(),
                &proof,
            ))
            .await
            .expect("exact delivery retry after restart");
        assert!(matches!(
            (committed, retry),
            (
                true,
                AcknowledgePairResponseReceivedOutcome::Replayed { .. }
            ) | (
                false,
                AcknowledgePairResponseReceivedOutcome::Delivered { .. }
            )
        ));
        assert_eq!(delivery_counts(&root.database()), (1, 1, 1, 1));
        reopened.shutdown().await.expect("shutdown recovered store");
    }
}

#[tokio::test]
async fn offline_delivered_lifecycle_tamper_fails_full_open_without_rewriting_artifacts() {
    let root = TestRoot::new("pairing-delivery-offline-tamper");
    let keys = MemoryKeyStore::new();
    let clock = Arc::new(AtomicU64::new(NOW_MS));
    let config = || {
        RuntimeStoreConfig::new(root.database())
            .with_capacity_probe(GenerousCapacity)
            .with_clock(TestClock(clock.clone()))
    };
    let store = RuntimeStoreHandle::open(
        config(),
        load_or_create_storage_kek(&keys, &root.database()).expect("load StorageKEK"),
    )
    .await
    .expect("open tamper setup");
    let (preparation, recovery) = prepare_committed(&store, &clock).await;
    let proof = verified_receipt(&recovery);
    clock.store(NOW_MS + 2, Ordering::SeqCst);
    store
        .acknowledge_pair_response_received(AcknowledgePairResponseReceived::new(
            preparation.pairing_id(),
            &proof,
        ))
        .await
        .expect("deliver before offline tamper");
    store.shutdown().await.expect("shutdown tamper setup");

    let connection = rusqlite::Connection::open(root.database()).expect("open offline writer");
    assert_eq!(
        connection
            .execute(
                "UPDATE remote_pairings SET lifecycle = 'grantCommitted'
                 WHERE pairing_id = ?1 AND lifecycle = 'delivered'",
                [&preparation.pairing_id().as_bytes()[..]],
            )
            .expect("tamper delivered lifecycle without KEK"),
        1
    );
    drop(connection);
    let tampered = artifact_bytes(&root.database());

    let error = RuntimeStoreHandle::open(
        config(),
        load_or_create_storage_kek(&keys, &root.database()).expect("reload StorageKEK"),
    )
    .await
    .expect_err("offline lifecycle tamper must fail full open");
    assert!(matches!(error, RuntimeStoreError::UnknownOrCorruptSchema));
    assert_eq!(artifact_bytes(&root.database()), tampered);
}
