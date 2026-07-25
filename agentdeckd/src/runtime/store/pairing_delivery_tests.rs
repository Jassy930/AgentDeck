//! P4.3 G3 PairResponseReceived Store 子片 focused tests。

use std::path::Path;
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};

use agentdeck_crypto::{SigningKey, sha256, sign_pair_response_received, sign_tbs};
use agentdeck_protocol::e2ee::{
    AuthorizationCapabilityV1, AuthorizationPermissionV1, KeyDirectoryV1, KeyUpdateSetV1,
    KeyUpdateV1, PairResponseReceivedV1,
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
use super::pairing_grant::{ConversationKeyRotation, GlobalKeyStateV1, PairingGrantPreparation};
use super::pairing_grant_allocation::GrantAllocationProjection;
use super::pairing_grant_allocation_tests::{
    complete_active_membership_transition,
    complete_active_membership_transition_with_production_finalize,
};
use super::pairing_grant_commit::{AcknowledgeGrantCommitted, GrantCommittedRecovery};
use super::pairing_grant_tests::{
    awaiting_pairing, awaiting_pairing_with, awaiting_pairing_with_authorization,
    complete_active_zero_cut_transition, grant_input, grant_input_with, secret,
};
use super::pairing_grant_tx::ConfirmPairingGrantOutcome;
use super::pairing_revocation::{BeginDeviceRevocation, BeginDeviceRevocationOutcome};
use super::pairing_terminal::RECEIPT_RETENTION_MS;
use super::pairing_tests::{
    GenerousCapacity, MACHINE_ROUTE, NOW_MS, OneShotFault, TestClock, TestRoot, artifact_bytes,
    make_active, pending_envelope, prepare_unused_pairing, verified_request_with_authorization,
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
    let (preparation, recovery, _) = prepare_committed_with_directory(store, clock).await;
    (preparation, recovery)
}

async fn prepare_committed_with_directory(
    store: &RuntimeStoreHandle,
    clock: &AtomicU64,
) -> (
    PairingGrantPreparation,
    GrantCommittedRecovery,
    KeyDirectoryV1,
) {
    let (binding, data_cert) = make_active(store).await;
    let preparation = awaiting_pairing(store, &binding, &data_cert).await;
    let input = grant_input(&preparation, &binding, &data_cert);
    let directory = input.key_directory().clone();
    let confirmed = store
        .confirm_pairing_grant(input)
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
    (preparation, recovery, directory)
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

pub(crate) async fn matching_bootstrap_update_for_test(
    store: &RuntimeStoreHandle,
    recipient: super::key_transition::KeyTransitionRecipient,
) -> super::key_transition::FrozenKeyUpdate {
    let global = store
        .load_global_key_state()
        .await
        .expect("load authenticated bootstrap global key state")
        .expect("bootstrap global key state exists");
    let revision = global.revision();
    let device_route = DeviceRouteId::from_bytes(recipient.device_route);
    let updates = global
        .install_directory_view(device_route)
        .expect("derive complete bootstrap slot view")
        .into_iter()
        .map(|view| KeyUpdateV1 {
            key_directory_revision: revision,
            key_id: agentdeck_protocol::e2ee::KeyId {
                purpose: view.purpose,
                epoch: view.epoch,
            },
            device_route,
            stream_route: view.stream_route,
            enc: vec![0x51; 32],
            wrapped_key: vec![0x52; 48],
            signature: Ed25519Signature([0x53; 64]),
        })
        .collect::<Vec<_>>();
    let update_set = KeyUpdateSetV1 {
        key_directory_revision: revision,
        device_route,
        updates,
    };
    update_set
        .validate()
        .expect("bootstrap fixture update set is structurally valid");
    super::key_transition::FrozenKeyUpdate {
        recipient,
        key_revision: revision.value(),
        canonical_update_set: update_set
            .canonical_bytes()
            .expect("encode matching bootstrap update set"),
    }
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

#[derive(Clone, Debug)]
struct ZeroCutBootstrapTarget {
    operation_id: [u8; 16],
    recipient: super::key_transition::KeyTransitionRecipient,
    key_revision: u64,
}

fn canonical_update_set_from_directory(directory: &KeyDirectoryV1) -> Vec<u8> {
    KeyUpdateSetV1 {
        key_directory_revision: directory.revision,
        device_route: directory
            .entries
            .first()
            .expect("bootstrap directory has entries")
            .device_route,
        updates: directory
            .entries
            .iter()
            .map(|entry| KeyUpdateV1 {
                key_directory_revision: directory.revision,
                key_id: entry.key_id,
                device_route: entry.device_route,
                stream_route: entry.stream_route,
                enc: entry.enc.clone(),
                wrapped_key: entry.wrapped_key.clone(),
                signature: Ed25519Signature([0x5a; 64]),
            })
            .collect(),
    }
    .canonical_bytes()
    .expect("canonical bootstrap KeyUpdateSet")
}

fn canonical_update_set_with_fresh_ciphertext(directory: &KeyDirectoryV1) -> Vec<u8> {
    KeyUpdateSetV1 {
        key_directory_revision: directory.revision,
        device_route: directory
            .entries
            .first()
            .expect("bootstrap directory has entries")
            .device_route,
        updates: directory
            .entries
            .iter()
            .map(|entry| KeyUpdateV1 {
                key_directory_revision: directory.revision,
                key_id: entry.key_id,
                device_route: entry.device_route,
                stream_route: entry.stream_route,
                // 模拟后续 KeyUpdateSet 的独立随机 HPKE 封装；稳定 slot 相同，
                // ciphertext 按设计不应逐字节相同。
                enc: vec![0xc3; entry.enc.len()],
                wrapped_key: vec![0x3c; entry.wrapped_key.len()],
                signature: Ed25519Signature([0x6b; 64]),
            })
            .collect(),
    }
    .canonical_bytes()
    .expect("canonical bootstrap KeyUpdateSet with fresh ciphertext")
}

fn tick(clock: &AtomicU64) {
    let _ = clock.fetch_add(1, Ordering::SeqCst);
}

async fn freeze_zero_cut_bootstrap_target(
    store: &RuntimeStoreHandle,
    clock: &AtomicU64,
    label: &str,
    target_directory: &KeyDirectoryV1,
) -> ZeroCutBootstrapTarget {
    freeze_bootstrap_target_with_update_set(
        store,
        clock,
        label,
        canonical_update_set_from_directory(target_directory),
    )
    .await
}

async fn freeze_bootstrap_target_with_update_set(
    store: &RuntimeStoreHandle,
    clock: &AtomicU64,
    label: &str,
    target_update_set: Vec<u8>,
) -> ZeroCutBootstrapTarget {
    let recovery = store
        .load_active_key_transition()
        .await
        .expect("load bootstrap transition before update freeze")
        .expect("bootstrap transition is active");
    assert!(matches!(
        recovery.transition.operation,
        super::key_transition::KeyTransitionOperation::Add
            | super::key_transition::KeyTransitionOperation::Renew
    ));
    let super::key_transition::KeyTransitionTarget::Device(target) = recovery.transition.target
    else {
        panic!("pairing bootstrap transition must target one device")
    };
    assert!(recovery.transition.cuts.is_empty());
    assert!(recovery.updates.is_empty());
    assert!(recovery.transition.recipients.contains(&target));

    let operation_id = recovery.transition.operation_id;
    let key_revision = recovery.transition.to_revision;
    let updates = recovery
        .transition
        .recipients
        .iter()
        .map(|recipient| {
            let canonical_update_set = if *recipient == target {
                target_update_set.clone()
            } else {
                format!("{label}-{:02x}-{key_revision}", recipient.device_route[0]).into_bytes()
            };
            super::key_transition::FrozenKeyUpdate {
                recipient: *recipient,
                key_revision,
                canonical_update_set,
            }
        })
        .collect::<Vec<_>>();

    tick(clock);
    store
        .mark_key_transition_rotated(operation_id)
        .await
        .expect("mark bootstrap transition rotated");
    tick(clock);
    store
        .freeze_key_updates(operation_id, updates)
        .await
        .expect("freeze bootstrap target update");

    ZeroCutBootstrapTarget {
        operation_id,
        recipient: target,
        key_revision,
    }
}

async fn load_bootstrap_target_update(
    store: &RuntimeStoreHandle,
    target: &ZeroCutBootstrapTarget,
) -> super::key_transition::KeyUpdateRecord {
    let recovery = store
        .load_active_key_transition()
        .await
        .expect("load bootstrap transition after update freeze")
        .expect("bootstrap transition remains active");
    assert_eq!(recovery.transition.operation_id, target.operation_id);
    assert_eq!(recovery.transition.to_revision, target.key_revision);
    recovery
        .updates
        .into_iter()
        .find(|update| update.recipient == target.recipient)
        .expect("bootstrap target update exists")
}

async fn commit_zero_cut_barriers(
    store: &RuntimeStoreHandle,
    clock: &AtomicU64,
    operation_id: [u8; 16],
) {
    tick(clock);
    store
        .freeze_key_barriers(operation_id, Vec::new())
        .await
        .expect("freeze empty bootstrap barrier set");
    tick(clock);
    store
        .mark_key_barriers_committed(operation_id)
        .await
        .expect("commit empty bootstrap barrier set");
}

async fn prepare_new_device_committed_with(
    store: &RuntimeStoreHandle,
    clock: &AtomicU64,
    device_route: DeviceRouteId,
    pair_seed: u8,
    device_sign_seed: u8,
    entropy_seed: u8,
) -> (PairingGrantPreparation, GrantCommittedRecovery) {
    let (binding, data_cert) = make_active(store).await;
    let preparation = awaiting_pairing_with(
        store,
        &binding,
        &data_cert,
        PairRouteId::from_bytes([pair_seed; 16]),
        pair_seed.wrapping_add(1),
        pair_seed.wrapping_add(2),
        device_sign_seed,
        pair_seed.wrapping_add(3),
        pair_seed.wrapping_add(4),
        pair_seed.wrapping_add(5),
        "bootstrap-proof-other-target",
    )
    .await;
    let global = GlobalKeyStateV1::bootstrap(
        1,
        1,
        secret(entropy_seed),
        device_route,
        1,
        secret(entropy_seed.wrapping_add(1)),
        1,
        secret(entropy_seed.wrapping_add(2)),
    )
    .expect("bootstrap alternate target global state");
    let confirmed = store
        .confirm_pairing_grant(grant_input_with(
            &preparation,
            &binding,
            &data_cert,
            device_route,
            GrantSerial::new(1),
            global,
            None,
            entropy_seed.wrapping_add(3),
        ))
        .await
        .expect("confirm alternate target grant");
    let installing = match confirmed {
        ConfirmPairingGrantOutcome::Confirmed { recovery, .. } => recovery,
        other => panic!("alternate target grant must confirm: {other:?}"),
    };
    tick(clock);
    let committed = store
        .acknowledge_grant_committed(AcknowledgeGrantCommitted::new(
            preparation.pairing_id(),
            grant_committed_frame(&installing),
        ))
        .await
        .expect("commit alternate target grant");
    let recovery = match committed {
        super::pairing_grant_commit::AcknowledgeGrantCommittedOutcome::Committed { recovery } => {
            recovery
        }
        other => panic!("alternate target GrantCommitted must transition: {other:?}"),
    };
    (preparation, recovery)
}

async fn advance_global_revision_with_device(store: &RuntimeStoreHandle, clock: &AtomicU64) -> u64 {
    store
        .create_publication_stream(
            [0xed; 16],
            PublicationScope::Catalog,
            [0xee; 16],
            [0xef; 16],
        )
        .await
        .expect("create catalog stream before higher global revision");
    let (binding, data_cert) = make_active(store).await;
    let preparation = awaiting_pairing_with(
        store,
        &binding,
        &data_cert,
        PairRouteId::from_bytes([0xe1; 16]),
        0xe2,
        0xe3,
        0xe4,
        0xe5,
        0xe6,
        0xe7,
        "completed-bootstrap-higher-global-revision",
    )
    .await;
    let fingerprint = sha256(&preparation.request().device_sign_pubkey.0);
    let current_global = match store
        .load_grant_allocation(preparation.pairing_id(), fingerprint)
        .await
        .expect("load higher-revision device allocation")
    {
        GrantAllocationProjection::New {
            device_sign_fingerprint,
            current_global_keys: Some(current_global),
            ..
        } => {
            assert_eq!(device_sign_fingerprint, fingerprint);
            current_global
        }
        other => panic!("different DeviceSign must allocate a new device: {other:?}"),
    };
    let next_global = current_global
        .next_for_device(
            DeviceRouteId::from_bytes([0xe8; 16]),
            secret(0xe9),
            secret(0xea),
            secret(0xeb),
        )
        .expect("advance authenticated global key state");
    let next_revision = next_global.revision().value();
    let confirmed = store
        .confirm_pairing_grant(grant_input_with(
            &preparation,
            &binding,
            &data_cert,
            DeviceRouteId::from_bytes([0xe8; 16]),
            GrantSerial::new(1),
            next_global,
            None,
            0xec,
        ))
        .await
        .expect("confirm higher-revision device grant");
    let installing = match confirmed {
        ConfirmPairingGrantOutcome::Confirmed { recovery, .. } => recovery,
        other => panic!("higher-revision device grant must confirm: {other:?}"),
    };
    tick(clock);
    assert!(matches!(
        store
            .acknowledge_grant_committed(AcknowledgeGrantCommitted::new(
                preparation.pairing_id(),
                grant_committed_frame(&installing),
            ))
            .await
            .expect("commit higher-revision device grant"),
        super::pairing_grant_commit::AcknowledgeGrantCommittedOutcome::Committed { .. }
    ));
    complete_active_membership_transition(store, clock).await;
    assert_eq!(
        store
            .load_global_key_state()
            .await
            .expect("load advanced global key state")
            .expect("advanced global key state exists")
            .revision()
            .value(),
        next_revision
    );
    next_revision
}

async fn prepare_renewal_committed(
    store: &RuntimeStoreHandle,
    clock: &AtomicU64,
) -> (
    PairingGrantPreparation,
    GrantCommittedRecovery,
    KeyDirectoryV1,
) {
    // 先通过普通 KeyUpdateAck 完成首笔 Add，避免续配 fixture 自己依赖待测的
    // PairResponseReceived bootstrap proof 路径。
    let (first_preparation, first_committed) = prepare_committed(store, clock).await;
    complete_active_zero_cut_transition(store).await;
    deliver_and_close_for_test(
        store,
        clock,
        first_preparation,
        first_committed,
        DEVICE_SIGN_SEED,
        clock.load(Ordering::SeqCst).saturating_add(1),
    )
    .await;
    store
        .create_publication_stream(
            [0x71; 16],
            PublicationScope::Catalog,
            [0x72; 16],
            [0x73; 16],
        )
        .await
        .expect("create catalog stream before second bootstrap member");

    // 再加入一个不同 DeviceSign 的设备，使随后的 Renew 同时拥有 target 与
    // 既有 non-target recipient；bootstrap proof 只能豁免前者。
    let (binding, data_cert) = make_active(store).await;
    let second_preparation = awaiting_pairing_with(
        store,
        &binding,
        &data_cert,
        PairRouteId::from_bytes([0xc1; 16]),
        0xc2,
        0xc3,
        0xc4,
        0xc5,
        0xc6,
        0xc7,
        "bootstrap-proof-second-device",
    )
    .await;
    let second_fingerprint = sha256(&second_preparation.request().device_sign_pubkey.0);
    let current_global = match store
        .load_grant_allocation(second_preparation.pairing_id(), second_fingerprint)
        .await
        .expect("load second-device allocation")
    {
        GrantAllocationProjection::New {
            device_sign_fingerprint,
            current_global_keys: Some(current_global),
            ..
        } => {
            assert_eq!(device_sign_fingerprint, second_fingerprint);
            current_global
        }
        other => panic!("different DeviceSign must allocate a new device: {other:?}"),
    };
    let second_route = DeviceRouteId::from_bytes([0xd2; 16]);
    let next_global = current_global
        .next_for_device(second_route, secret(0xf1), secret(0xf2), secret(0xf3))
        .expect("append second device keys");
    let second_confirmed = store
        .confirm_pairing_grant(grant_input_with(
            &second_preparation,
            &binding,
            &data_cert,
            second_route,
            GrantSerial::new(1),
            next_global,
            None,
            0xf4,
        ))
        .await
        .expect("confirm second-device grant");
    let second_installing = match second_confirmed {
        ConfirmPairingGrantOutcome::Confirmed { recovery, .. } => recovery,
        other => panic!("second-device grant must confirm: {other:?}"),
    };
    tick(clock);
    let second_committed = match store
        .acknowledge_grant_committed(AcknowledgeGrantCommitted::new(
            second_preparation.pairing_id(),
            grant_committed_frame(&second_installing),
        ))
        .await
        .expect("commit second-device grant")
    {
        super::pairing_grant_commit::AcknowledgeGrantCommittedOutcome::Committed { recovery } => {
            recovery
        }
        other => panic!("second-device GrantCommitted must transition: {other:?}"),
    };
    complete_active_membership_transition(store, clock).await;
    deliver_and_close_for_test(
        store,
        clock,
        second_preparation,
        second_committed,
        [0xc4; 32],
        clock.load(Ordering::SeqCst).saturating_add(1),
    )
    .await;

    let (binding, data_cert) = make_active(store).await;
    let preparation = awaiting_pairing_with(
        store,
        &binding,
        &data_cert,
        PairRouteId::from_bytes([0xb1; 16]),
        0xb2,
        0xb3,
        0xa4,
        0xb5,
        0xb6,
        0xb7,
        "bootstrap-proof-renewal",
    )
    .await;
    let fingerprint = sha256(&preparation.request().device_sign_pubkey.0);
    let (device_route, next_serial, current_global) = match store
        .load_grant_allocation(preparation.pairing_id(), fingerprint)
        .await
        .expect("load renewal bootstrap allocation")
    {
        GrantAllocationProjection::Renew {
            device_sign_fingerprint,
            device_route,
            current_serial,
            next_serial,
            current_global_keys,
        } => {
            assert_eq!(device_sign_fingerprint, fingerprint);
            assert_eq!(current_serial, GrantSerial::new(1));
            assert_eq!(next_serial, GrantSerial::new(2));
            (device_route, next_serial, current_global_keys)
        }
        GrantAllocationProjection::New { .. } => panic!("same DeviceSign must renew"),
    };
    let next_global = current_global
        .renew_for_device(device_route, secret(0xe1), secret(0xe2), secret(0xe3))
        .expect("rotate renewal device keys");
    let input = grant_input_with(
        &preparation,
        &binding,
        &data_cert,
        device_route,
        next_serial,
        next_global,
        None,
        0xe4,
    );
    let directory = input.key_directory().clone();
    let confirmed = store
        .confirm_pairing_grant(input)
        .await
        .expect("confirm renewal bootstrap grant");
    let installing = match confirmed {
        ConfirmPairingGrantOutcome::Confirmed { recovery, .. } => recovery,
        other => panic!("renewal bootstrap grant must confirm: {other:?}"),
    };
    tick(clock);
    let committed = store
        .acknowledge_grant_committed(AcknowledgeGrantCommitted::new(
            preparation.pairing_id(),
            grant_committed_frame(&installing),
        ))
        .await
        .expect("commit renewal bootstrap grant");
    let recovery = match committed {
        super::pairing_grant_commit::AcknowledgeGrantCommittedOutcome::Committed { recovery } => {
            recovery
        }
        other => panic!("renewal GrantCommitted must transition: {other:?}"),
    };
    (preparation, recovery, directory)
}

#[tokio::test]
async fn close_then_restart_retains_durable_bootstrap_proof_for_update_freeze() {
    let root = TestRoot::new("pairing-bootstrap-close-restart");
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
    .expect("open bootstrap close-restart store");
    let (preparation, committed, directory) =
        prepare_committed_with_directory(&store, &clock).await;

    // GrantCommitted 已把 paired authorization/global revision 与唯一 Add target
    // 持久提升；bootstrap proof 只能在这个事实之后生效。
    store
        .load_active_remote_ingress(MACHINE_ROUTE, committed.device_route())
        .await
        .expect("paired target is durable before endpoint receipt");
    let transition = store
        .load_active_key_transition()
        .await
        .expect("load durable Add transition")
        .expect("Add transition exists");
    assert_eq!(
        transition.transition.target,
        super::key_transition::KeyTransitionTarget::Device(
            super::key_transition::KeyTransitionRecipient {
                device_route: *committed.device_route().as_bytes(),
                grant_serial: committed.grant_serial().value(),
            }
        )
    );
    assert_eq!(
        transition.transition.phase,
        super::key_transition::KeyTransitionPhase::DrainingOld
    );

    let proof = verified_receipt(&committed);
    tick(&clock);
    let close = match store
        .acknowledge_pair_response_received(AcknowledgePairResponseReceived::new(
            preparation.pairing_id(),
            &proof,
        ))
        .await
        .expect("durably retain exact bootstrap proof")
    {
        AcknowledgePairResponseReceivedOutcome::Delivered { close } => close,
        other => panic!("fresh bootstrap proof must deliver: {other:?}"),
    };
    store
        .acknowledge_pair_route_close(
            preparation.pairing_id(),
            close_terminal(close.pair_route(), PairRouteCloseOutcome::Closed),
        )
        .await
        .expect("scrub pairing after proof is durable in transition");
    assert_eq!(delivery_counts(&root.database()), (0, 1, 0, 0));
    store.shutdown().await.expect("shutdown after close scrub");

    let reopened = RuntimeStoreHandle::open(
        config(),
        load_or_create_storage_kek(&keys, &root.database()).expect("reload StorageKEK"),
    )
    .await
    .expect("reopen scrubbed bootstrap store");
    let target =
        freeze_zero_cut_bootstrap_target(&reopened, &clock, "first-device-bootstrap", &directory)
            .await;
    let update = load_bootstrap_target_update(&reopened, &target).await;
    assert_eq!(
        update.lifecycle,
        super::key_transition::KeyUpdateLifecycle::Acked,
        "freeze recovery must consume the durable exact PairResponseReceived proof"
    );
    assert_eq!(
        update.canonical_ack.as_deref(),
        Some(proof.canonical_receipt())
    );
    reopened
        .shutdown()
        .await
        .expect("shutdown reconciled store");
}

#[tokio::test]
async fn bootstrap_receipt_accepts_same_slots_with_independent_hpke_ciphertext() {
    let root = TestRoot::new("pairing-bootstrap-randomized-hpke");
    let keys = MemoryKeyStore::new();
    let clock = Arc::new(AtomicU64::new(NOW_MS));
    let store = RuntimeStoreHandle::open(
        RuntimeStoreConfig::new(root.database())
            .with_capacity_probe(GenerousCapacity)
            .with_clock(TestClock(clock.clone())),
        load_or_create_storage_kek(&keys, &root.database()).expect("load StorageKEK"),
    )
    .await
    .expect("open randomized HPKE bootstrap store");
    let (preparation, committed, directory) =
        prepare_committed_with_directory(&store, &clock).await;
    let canonical_update_set = canonical_update_set_with_fresh_ciphertext(&directory);
    let randomized = KeyUpdateSetV1::from_canonical_bytes(&canonical_update_set)
        .expect("decode randomized HPKE fixture");
    assert!(directory.entries.iter().zip(&randomized.updates).all(
        |(pair_response, key_update)| {
            pair_response.key_id == key_update.key_id
                && pair_response.stream_route == key_update.stream_route
        }
    ));
    assert!(
        directory
            .entries
            .iter()
            .zip(&randomized.updates)
            .any(|(pair_response, key_update)| {
                pair_response.enc != key_update.enc
                    || pair_response.wrapped_key != key_update.wrapped_key
            }),
        "两次随机 HPKE 封装不应被测试 fixture 误建模为相同 ciphertext"
    );
    let target = freeze_bootstrap_target_with_update_set(
        &store,
        &clock,
        "randomized-hpke",
        canonical_update_set,
    )
    .await;
    let proof = verified_receipt(&committed);
    tick(&clock);
    let close = match store
        .acknowledge_pair_response_received(AcknowledgePairResponseReceived::new(
            preparation.pairing_id(),
            &proof,
        ))
        .await
        .expect("same slot identity accepts independent HPKE ciphertext")
    {
        AcknowledgePairResponseReceivedOutcome::Delivered { close } => close,
        other => panic!("randomized HPKE bootstrap receipt must deliver: {other:?}"),
    };
    let update = load_bootstrap_target_update(&store, &target).await;
    assert_eq!(
        update.lifecycle,
        super::key_transition::KeyUpdateLifecycle::Acked
    );
    assert_eq!(
        update.canonical_ack.as_deref(),
        Some(proof.canonical_receipt())
    );
    store
        .acknowledge_pair_route_close(
            preparation.pairing_id(),
            close_terminal(close.pair_route(), PairRouteCloseOutcome::Closed),
        )
        .await
        .expect("close randomized HPKE bootstrap pairing");
    store
        .shutdown()
        .await
        .expect("shutdown randomized HPKE store");
}

#[tokio::test]
async fn bootstrap_slot_identity_mismatch_rolls_back_delivery_proof_and_ack() {
    let root = TestRoot::new("pairing-bootstrap-slot-mismatch");
    let keys = MemoryKeyStore::new();
    let clock = Arc::new(AtomicU64::new(NOW_MS));
    let store = RuntimeStoreHandle::open(
        RuntimeStoreConfig::new(root.database())
            .with_capacity_probe(GenerousCapacity)
            .with_clock(TestClock(clock.clone())),
        load_or_create_storage_kek(&keys, &root.database()).expect("load StorageKEK"),
    )
    .await
    .expect("open slot mismatch bootstrap store");
    let (preparation, committed, directory) =
        prepare_committed_with_directory(&store, &clock).await;
    let mut mismatched = KeyUpdateSetV1::from_canonical_bytes(
        &canonical_update_set_with_fresh_ciphertext(&directory),
    )
    .expect("decode slot mismatch fixture");
    mismatched.updates[0].key_id.epoch = mismatched.updates[0]
        .key_id
        .epoch
        .checked_add(1)
        .expect("test key epoch has successor");
    let target = freeze_bootstrap_target_with_update_set(
        &store,
        &clock,
        "slot-mismatch",
        mismatched
            .canonical_bytes()
            .expect("encode valid mismatched slot fixture"),
    )
    .await;
    let proof = verified_receipt(&committed);
    tick(&clock);
    let before = artifact_bytes(&root.database());
    assert!(matches!(
        store
            .acknowledge_pair_response_received(AcknowledgePairResponseReceived::new(
                preparation.pairing_id(),
                &proof,
            ))
            .await,
        Err(RuntimeStoreError::PublicationMismatch)
    ));
    assert_eq!(artifact_bytes(&root.database()), before);
    assert_eq!(
        store
            .load_pairing_invite(preparation.pairing_id())
            .await
            .expect("load pairing after slot mismatch")
            .expect("slot mismatch retains pairing row")
            .lifecycle(),
        PairingInviteLifecycle::GrantCommitted
    );
    assert!(
        store
            .list_pairing_terminal_recovery()
            .await
            .expect("load Close recovery after slot mismatch")
            .is_empty()
    );
    let recovery = store
        .load_active_key_transition()
        .await
        .expect("load transition after slot mismatch")
        .expect("slot mismatch retains active transition");
    assert!(recovery.transition.bootstrap_install_proof.is_none());
    let update = recovery
        .updates
        .into_iter()
        .find(|update| update.recipient == target.recipient)
        .expect("slot mismatch target update remains present");
    assert_eq!(
        update.lifecycle,
        super::key_transition::KeyUpdateLifecycle::Frozen
    );
    assert!(update.canonical_ack.is_none());
    store
        .shutdown()
        .await
        .expect("shutdown slot mismatch store");
}

#[tokio::test]
async fn durable_bootstrap_proof_prevents_staged_transition_cancel_without_writes() {
    let root = TestRoot::new("pairing-bootstrap-cancel-fence");
    let keys = MemoryKeyStore::new();
    let clock = Arc::new(AtomicU64::new(NOW_MS));
    let store = RuntimeStoreHandle::open(
        RuntimeStoreConfig::new(root.database())
            .with_capacity_probe(GenerousCapacity)
            .with_clock(TestClock(clock.clone())),
        load_or_create_storage_kek(&keys, &root.database()).expect("load StorageKEK"),
    )
    .await
    .expect("open bootstrap cancel-fence store");
    let (preparation, committed) = prepare_committed(&store, &clock).await;
    let operation_id = store
        .load_active_key_transition()
        .await
        .expect("load staged bootstrap transition")
        .expect("bootstrap transition exists")
        .transition
        .operation_id;
    let proof = verified_receipt(&committed);
    tick(&clock);
    let close = match store
        .acknowledge_pair_response_received(AcknowledgePairResponseReceived::new(
            preparation.pairing_id(),
            &proof,
        ))
        .await
        .expect("persist bootstrap proof before cancel attempt")
    {
        AcknowledgePairResponseReceivedOutcome::Delivered { close } => close,
        other => panic!("fresh bootstrap proof must deliver: {other:?}"),
    };
    let before = artifact_bytes(&root.database());
    assert!(matches!(
        store.cancel_key_transition(operation_id).await,
        Err(RuntimeStoreError::InvalidStateTransition)
    ));
    assert_eq!(artifact_bytes(&root.database()), before);
    let retained = store
        .load_active_key_transition()
        .await
        .expect("reload bootstrap transition after rejected cancel")
        .expect("rejected cancel keeps transition active");
    assert_eq!(
        retained.transition.phase,
        super::key_transition::KeyTransitionPhase::DrainingOld
    );
    assert_eq!(
        retained
            .transition
            .bootstrap_install_proof
            .as_ref()
            .expect("rejected cancel preserves proof")
            .binding
            .canonical_receipt
            .as_slice(),
        proof.canonical_receipt()
    );
    assert_eq!(
        store
            .load_pairing_invite(preparation.pairing_id())
            .await
            .expect("load delivered pairing after rejected cancel")
            .expect("delivered pairing remains")
            .lifecycle(),
        PairingInviteLifecycle::Delivered
    );
    assert_eq!(
        store
            .list_pairing_terminal_recovery()
            .await
            .expect("load durable Close after rejected cancel")
            .len(),
        1
    );
    store
        .acknowledge_pair_route_close(
            preparation.pairing_id(),
            close_terminal(close.pair_route(), PairRouteCloseOutcome::Closed),
        )
        .await
        .expect("close pairing after rejected cancel");
    store
        .shutdown()
        .await
        .expect("shutdown bootstrap cancel store");
}

#[tokio::test]
async fn completed_bootstrap_proof_is_gc_pinned_until_close_scrubs_pairing() {
    let root = TestRoot::new("pairing-bootstrap-gc-pin");
    let keys = MemoryKeyStore::new();
    let clock = Arc::new(AtomicU64::new(NOW_MS));
    let store = RuntimeStoreHandle::open(
        RuntimeStoreConfig::new(root.database())
            .with_capacity_probe(GenerousCapacity)
            .with_clock(TestClock(clock.clone())),
        load_or_create_storage_kek(&keys, &root.database()).expect("load StorageKEK"),
    )
    .await
    .expect("open bootstrap GC pin store");
    let (preparation, committed) = prepare_committed(&store, &clock).await;
    let proof = verified_receipt(&committed);
    tick(&clock);
    let close = match store
        .acknowledge_pair_response_received(AcknowledgePairResponseReceived::new(
            preparation.pairing_id(),
            &proof,
        ))
        .await
        .expect("deliver bootstrap receipt before transition completion")
    {
        AcknowledgePairResponseReceivedOutcome::Delivered { close } => close,
        other => panic!("fresh bootstrap receipt must deliver: {other:?}"),
    };
    complete_active_zero_cut_transition(&store).await;

    let after_retention = clock
        .load(Ordering::SeqCst)
        .checked_add(super::key_transition::KEY_TRANSITION_TOMBSTONE_RETENTION_MS)
        .and_then(|value| value.checked_add(1))
        .expect("bootstrap GC deadline fits");
    clock.store(after_retention, Ordering::SeqCst);
    let pinned = store
        .gc_expired_key_transitions(super::key_transition::KeyTransitionGcLimits::default())
        .await
        .expect("run bootstrap transition GC while Close is pending");
    assert_eq!(pinned.bootstrap_pairing_blocked, 1);
    assert_eq!(pinned.transitions_deleted, 0);
    assert_eq!(delivery_counts(&root.database()), (1, 1, 1, 1));

    store
        .acknowledge_pair_route_close(
            preparation.pairing_id(),
            close_terminal(close.pair_route(), PairRouteCloseOutcome::Closed),
        )
        .await
        .expect("late Close ACK still scrubs pairing after transition retention");
    assert_eq!(delivery_counts(&root.database()), (0, 1, 0, 0));
    assert!(
        store
            .plan_expired_pairing_receipt_purge()
            .await
            .expect("late Delivered Close refreshes the full receipt retention window")
            .is_none()
    );
    let released = store
        .gc_expired_key_transitions(super::key_transition::KeyTransitionGcLimits::default())
        .await
        .expect("rerun transition GC after Close scrub");
    assert_eq!(released.bootstrap_pairing_blocked, 0);
    assert_eq!(released.transitions_deleted, 0);
    assert_eq!(released.counter_retirement_blocked, 1);
    store
        .shutdown()
        .await
        .expect("shutdown bootstrap GC pin store");
}

#[tokio::test]
async fn legacy_delivered_pairing_pins_proofless_completed_transition_until_backfill_and_close() {
    let root = TestRoot::new("pairing-bootstrap-legacy-gc-pin");
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
    .expect("open legacy GC pin store");
    let (preparation, committed, directory) =
        prepare_committed_with_directory(&store, &clock).await;
    let target =
        freeze_zero_cut_bootstrap_target(&store, &clock, "legacy-gc-pin", &directory).await;
    let proof = verified_receipt(&committed);
    tick(&clock);
    let close = match store
        .acknowledge_pair_response_received(AcknowledgePairResponseReceived::new(
            preparation.pairing_id(),
            &proof,
        ))
        .await
        .expect("deliver legacy GC pin receipt")
    {
        AcknowledgePairResponseReceivedOutcome::Delivered { close } => close,
        other => panic!("fresh legacy GC receipt must deliver: {other:?}"),
    };
    commit_zero_cut_barriers(&store, &clock, target.operation_id).await;
    tick(&clock);
    assert!(matches!(
        store
            .try_complete_key_transition(target.operation_id)
            .await
            .expect("complete legacy GC pin transition"),
        super::key_transition::KeyTransitionCompletion::Completed(_)
    ));
    store.shutdown().await.expect("shutdown legacy GC setup");

    let mut state = super::sqlite::open(
        &config(),
        load_or_create_storage_kek(&keys, &root.database()).expect("reload StorageKEK"),
    )
    .expect("open low-level legacy GC fixture state");
    let recovery =
        super::key_transition::load_key_transition_for_capacity_test(&state, target.operation_id)
            .expect("load completed legacy GC transition");
    let mut transition = recovery.transition;
    let terminal_at_ms = transition
        .terminal_at_ms
        .expect("completed legacy GC transition has terminal time");
    transition.bootstrap_install_proof = None;
    let update = recovery
        .updates
        .into_iter()
        .find(|update| update.recipient == target.recipient)
        .expect("legacy GC target update exists");
    super::key_transition::replace_transition_and_update_for_capacity_test(
        &mut state,
        &config(),
        transition,
        update,
    )
    .expect("simulate authenticated v1/v2 completed transition without proof");
    drop(state);

    let reopened = RuntimeStoreHandle::open(
        config(),
        load_or_create_storage_kek(&keys, &root.database()).expect("reload StorageKEK"),
    )
    .await
    .expect("reopen legacy proofless GC fixture");
    let retirement_at_ms = terminal_at_ms
        .checked_add(super::key_transition::COUNTER_RETIREMENT_RETENTION_MS)
        .expect("legacy counter retirement deadline fits");
    clock.store(retirement_at_ms, Ordering::SeqCst);
    let retirement = reopened
        .load_pending_counter_retirement_plan()
        .await
        .expect("load legacy counter-retirement plan")
        .expect("completed legacy transition requires retirement finalization");
    assert_eq!(retirement.operation_id, target.operation_id);
    assert!(retirement.scope_tokens.is_empty());
    assert!(matches!(
        reopened
            .apply_counter_retirement_after_guard_readback(retirement)
            .await
            .expect("apply empty legacy counter-retirement plan"),
        super::key_transition::CounterRetirementApplyOutcome::Applied {
            operation_id,
            counter_rows_deleted: 0,
            manifest_rows_deleted: 0,
        } if operation_id == target.operation_id
    ));

    let after_retention = terminal_at_ms
        .checked_add(super::key_transition::KEY_TRANSITION_TOMBSTONE_RETENTION_MS)
        .and_then(|value| value.checked_add(1))
        .expect("legacy GC retention deadline fits");
    clock.store(after_retention, Ordering::SeqCst);
    let before_pinned_gc = artifact_bytes(&root.database());
    let pinned = reopened
        .gc_expired_key_transitions(super::key_transition::KeyTransitionGcLimits::default())
        .await
        .expect("GC must retain proofless transition while Delivered pairing remains");
    assert_eq!(pinned.bootstrap_pairing_blocked, 1);
    assert_eq!(pinned.transitions_deleted, 0);
    assert_eq!(artifact_bytes(&root.database()), before_pinned_gc);

    assert!(matches!(
        reopened
            .acknowledge_pair_response_received(AcknowledgePairResponseReceived::new(
                preparation.pairing_id(),
                &proof,
            ))
            .await
            .expect("exact receipt replay backfills legacy GC proof"),
        AcknowledgePairResponseReceivedOutcome::Replayed { .. }
    ));
    reopened
        .acknowledge_pair_route_close(
            preparation.pairing_id(),
            close_terminal(close.pair_route(), PairRouteCloseOutcome::Closed),
        )
        .await
        .expect("Close scrubs legacy pairing after proof backfill");
    let released = reopened
        .gc_expired_key_transitions(super::key_transition::KeyTransitionGcLimits::default())
        .await
        .expect("GC releases legacy transition after Close scrub");
    assert_eq!(released.bootstrap_pairing_blocked, 0);
    assert_eq!(released.transitions_deleted, 1);
    assert_eq!(released.updates_deleted, 1);
    reopened
        .shutdown()
        .await
        .expect("shutdown legacy GC pin store");
}

#[tokio::test]
async fn pre_upgrade_collected_transition_allows_exact_replay_and_close_without_forging_proof() {
    let root = TestRoot::new("pairing-bootstrap-pre-upgrade-collected");
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
    .expect("open pre-upgrade collected transition store");
    let (preparation, committed, directory) =
        prepare_committed_with_directory(&store, &clock).await;
    let target =
        freeze_zero_cut_bootstrap_target(&store, &clock, "pre-upgrade-collected", &directory).await;
    let proof = verified_receipt(&committed);
    tick(&clock);
    let close = match store
        .acknowledge_pair_response_received(AcknowledgePairResponseReceived::new(
            preparation.pairing_id(),
            &proof,
        ))
        .await
        .expect("deliver pre-upgrade collected fixture receipt")
    {
        AcknowledgePairResponseReceivedOutcome::Delivered { close } => close,
        other => panic!("fresh pre-upgrade receipt must deliver: {other:?}"),
    };
    commit_zero_cut_barriers(&store, &clock, target.operation_id).await;
    tick(&clock);
    let completed = store
        .try_complete_key_transition(target.operation_id)
        .await
        .expect("complete pre-upgrade collected transition");
    let terminal_at_ms = match completed {
        super::key_transition::KeyTransitionCompletion::Completed(record) => record
            .terminal_at_ms
            .expect("completed pre-upgrade transition has terminal time"),
        other => panic!("pre-upgrade transition must complete: {other:?}"),
    };
    clock.store(
        terminal_at_ms
            .checked_add(super::key_transition::COUNTER_RETIREMENT_RETENTION_MS)
            .expect("pre-upgrade counter retirement deadline fits"),
        Ordering::SeqCst,
    );
    let retirement = store
        .load_pending_counter_retirement_plan()
        .await
        .expect("load pre-upgrade counter-retirement plan")
        .expect("completed pre-upgrade transition requires retirement finalization");
    assert_eq!(retirement.operation_id, target.operation_id);
    assert!(retirement.scope_tokens.is_empty());
    assert!(matches!(
        store
            .apply_counter_retirement_after_guard_readback(retirement)
            .await
            .expect("apply pre-upgrade empty counter-retirement plan"),
        super::key_transition::CounterRetirementApplyOutcome::Applied {
            operation_id,
            counter_rows_deleted: 0,
            manifest_rows_deleted: 0,
        } if operation_id == target.operation_id
    ));
    clock.store(
        terminal_at_ms
            .checked_add(super::key_transition::KEY_TRANSITION_TOMBSTONE_RETENTION_MS)
            .and_then(|value| value.checked_add(1))
            .expect("pre-upgrade collection timestamp fits"),
        Ordering::SeqCst,
    );
    store
        .shutdown()
        .await
        .expect("shutdown before simulating old GC");

    let mut legacy = super::sqlite::open(
        &config(),
        load_or_create_storage_kek(&keys, &root.database()).expect("reload StorageKEK"),
    )
    .expect("open low-level pre-upgrade GC fixture");
    super::key_transition::collect_completed_key_transition_for_legacy_test(
        &mut legacy,
        &config(),
        target.operation_id,
    )
    .expect("simulate authenticated old-version GC without pairing pin");
    assert_eq!(
        legacy
            .connection
            .query_row("SELECT COUNT(*) FROM remote_key_transitions", [], |row| {
                row.get::<_, u64>(0)
            })
            .expect("count collected transitions"),
        0
    );
    assert_eq!(
        legacy
            .connection
            .query_row("SELECT COUNT(*) FROM remote_key_update_outbox", [], |row| {
                row.get::<_, u64>(0)
            })
            .expect("count collected key updates"),
        0
    );
    drop(legacy);

    let reopened = RuntimeStoreHandle::open(
        config(),
        load_or_create_storage_kek(&keys, &root.database()).expect("reload StorageKEK"),
    )
    .await
    .expect("upgrade opens authenticated already-collected legacy state");
    let before_replay = artifact_bytes(&root.database());
    assert!(matches!(
        reopened
            .acknowledge_pair_response_received(AcknowledgePairResponseReceived::new(
                preparation.pairing_id(),
                &proof,
            ))
            .await
            .expect("exact legacy receipt replay remains available without transition"),
        AcknowledgePairResponseReceivedOutcome::Replayed { .. }
    ));
    assert_eq!(
        artifact_bytes(&root.database()),
        before_replay,
        "legacy collected replay must not forge a replacement proof or transition"
    );
    let close_terminal = close_terminal(close.pair_route(), PairRouteCloseOutcome::Closed);
    let closed = reopened
        .acknowledge_pair_route_close(preparation.pairing_id(), close_terminal.clone())
        .await
        .expect("legacy collected Close scrubs the retained Delivered pairing");
    assert!(!closed.replayed());
    assert_eq!(delivery_counts(&root.database()), (0, 1, 0, 0));
    let before_close_retry = artifact_bytes(&root.database());
    let replayed = reopened
        .acknowledge_pair_route_close(preparation.pairing_id(), close_terminal)
        .await
        .expect("legacy collected Close exact retry reads the retained tombstone");
    assert!(replayed.replayed());
    assert_eq!(artifact_bytes(&root.database()), before_close_retry);
    reopened
        .shutdown()
        .await
        .expect("shutdown pre-upgrade collected transition store");
}

async fn assert_exact_receipt_replay_backfills_legacy_codec(
    codec_label: &str,
    codec: super::key_transition::LegacyTransitionCodecForTest,
    expected_legacy_version: u8,
) {
    let root = TestRoot::new(&format!("pairing-bootstrap-legacy-backfill-{codec_label}"));
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
    .expect("open legacy bootstrap backfill store");
    let (preparation, committed, directory) =
        prepare_committed_with_directory(&store, &clock).await;
    let proof = verified_receipt(&committed);
    tick(&clock);
    let receipt_at_ms = clock.load(Ordering::SeqCst);
    let close = match store
        .acknowledge_pair_response_received(AcknowledgePairResponseReceived::new(
            preparation.pairing_id(),
            &proof,
        ))
        .await
        .expect("deliver before simulating legacy missing proof")
    {
        AcknowledgePairResponseReceivedOutcome::Delivered { close } => close,
        other => panic!("fresh legacy fixture receipt must deliver: {other:?}"),
    };
    let target =
        freeze_zero_cut_bootstrap_target(&store, &clock, "legacy-backfill", &directory).await;
    let installed = load_bootstrap_target_update(&store, &target).await;
    assert_eq!(
        installed.lifecycle,
        super::key_transition::KeyUpdateLifecycle::Acked
    );
    assert!(
        installed.state_changed_at_ms > receipt_at_ms,
        "legacy fixture must model receipt-before-freeze causal order"
    );
    store.shutdown().await.expect("shutdown legacy setup");

    let mut state = super::sqlite::open(
        &config(),
        load_or_create_storage_kek(&keys, &root.database()).expect("reload StorageKEK"),
    )
    .expect("open low-level legacy fixture state");
    let recovery = super::key_transition::load_active_key_transition(&state)
        .expect("load legacy transition fixture")
        .expect("legacy transition remains active");
    let mut update = recovery
        .updates
        .into_iter()
        .find(|update| update.recipient == target.recipient)
        .expect("legacy target update exists");
    let frozen_at_ms = update.state_changed_at_ms;
    update.lifecycle = super::key_transition::KeyUpdateLifecycle::Frozen;
    update.canonical_ack = None;
    super::key_transition::replace_update_for_legacy_transition_test(&mut state, &config(), update)
        .expect("restore the target update to its pre-receipt lifecycle");
    super::key_transition::reseal_transition_with_legacy_codec_for_test(
        &mut state,
        &config(),
        target.operation_id,
        codec,
    )
    .expect("atomically project the authenticated v3 transition to a proofless legacy codec");
    assert_eq!(
        super::key_transition::transition_codec_version_for_test(&state, target.operation_id)
            .expect("read legacy transition codec version"),
        expected_legacy_version
    );
    drop(state);

    let reopened = RuntimeStoreHandle::open(
        config(),
        load_or_create_storage_kek(&keys, &root.database()).expect("reload StorageKEK"),
    )
    .await
    .expect("reopen legacy missing-proof fixture");
    let close_terminal = close_terminal(close.pair_route(), PairRouteCloseOutcome::Closed);
    let before_rejected_close = artifact_bytes(&root.database());
    assert!(matches!(
        reopened
            .acknowledge_pair_route_close(preparation.pairing_id(), close_terminal.clone(),)
            .await,
        Err(RuntimeStoreError::InvalidStateTransition)
    ));
    assert_eq!(artifact_bytes(&root.database()), before_rejected_close);

    let before_backfill = artifact_bytes(&root.database());
    assert!(matches!(
        reopened
            .acknowledge_pair_response_received(AcknowledgePairResponseReceived::new(
                preparation.pairing_id(),
                &proof,
            ))
            .await
            .expect("exact receipt replay backfills durable proof"),
        AcknowledgePairResponseReceivedOutcome::Replayed { .. }
    ));
    assert_ne!(artifact_bytes(&root.database()), before_backfill);
    let recovered = reopened
        .load_active_key_transition()
        .await
        .expect("reload backfilled transition")
        .expect("backfilled transition remains active");
    assert_eq!(
        recovered
            .transition
            .bootstrap_install_proof
            .as_ref()
            .expect("exact replay restores durable proof")
            .binding
            .canonical_receipt
            .as_slice(),
        proof.canonical_receipt()
    );
    let update = recovered
        .updates
        .into_iter()
        .find(|update| update.recipient == target.recipient)
        .expect("backfilled target update exists");
    assert_eq!(
        update.lifecycle,
        super::key_transition::KeyUpdateLifecycle::Acked
    );
    assert_eq!(
        update.state_changed_at_ms, frozen_at_ms,
        "legacy backfill must not move update causal time backwards to the earlier receipt"
    );
    let before_exact_replay = artifact_bytes(&root.database());
    assert!(matches!(
        reopened
            .acknowledge_pair_response_received(AcknowledgePairResponseReceived::new(
                preparation.pairing_id(),
                &proof,
            ))
            .await
            .expect("second exact receipt replay is read-only"),
        AcknowledgePairResponseReceivedOutcome::Replayed { .. }
    ));
    assert_eq!(artifact_bytes(&root.database()), before_exact_replay);
    reopened
        .acknowledge_pair_route_close(preparation.pairing_id(), close_terminal)
        .await
        .expect("close pairing after legacy proof backfill");
    reopened
        .shutdown()
        .await
        .expect("shutdown legacy backfill store");

    let migrated = super::sqlite::open(
        &config(),
        load_or_create_storage_kek(&keys, &root.database()).expect("reload migrated StorageKEK"),
    )
    .expect("open migrated legacy transition state");
    assert_eq!(
        super::key_transition::transition_codec_version_for_test(&migrated, target.operation_id)
            .expect("read migrated transition codec version"),
        3,
        "proof backfill must rewrite the legacy ADKT row as current v3"
    );
    assert!(
        super::key_transition::load_key_transition_for_capacity_test(
            &migrated,
            target.operation_id,
        )
        .expect("load migrated transition")
        .transition
        .bootstrap_install_proof
        .is_some()
    );
    let migrated_lineage = super::key_transition::load_key_transition_for_capacity_test(
        &migrated,
        target.operation_id,
    )
    .expect("reload migrated transition lineage")
    .transition
    .global_lineage
    .expect("legacy backfill must establish durable global lineage");
    assert!(
        migrated_lineage.stable_key_lineage_hash.is_some(),
        "same-revision exact legacy backfill must never persist stable=None"
    );
}

#[tokio::test]
async fn exact_receipt_replay_backfills_real_v1_v2_rows_and_migrates_to_v3() {
    for (label, codec, expected_version) in [
        (
            "v1",
            super::key_transition::LegacyTransitionCodecForTest::V1,
            1,
        ),
        (
            "v2",
            super::key_transition::LegacyTransitionCodecForTest::V2,
            2,
        ),
    ] {
        assert_exact_receipt_replay_backfills_legacy_codec(label, codec, expected_version).await;
    }
}

async fn assert_legacy_receipt_replay_rejects_higher_global_revision(
    codec_label: &str,
    codec: super::key_transition::LegacyTransitionCodecForTest,
    expected_legacy_version: u8,
) {
    let root = TestRoot::new(&format!(
        "pairing-bootstrap-legacy-higher-revision-{codec_label}"
    ));
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
    .expect("open legacy higher-revision store");
    let (preparation, committed, directory) =
        prepare_committed_with_directory(&store, &clock).await;
    let proof_revision = directory.revision.value();
    let receipt = verified_receipt(&committed);
    tick(&clock);
    let close = match store
        .acknowledge_pair_response_received(AcknowledgePairResponseReceived::new(
            preparation.pairing_id(),
            &receipt,
        ))
        .await
        .expect("deliver legacy higher-revision fixture")
    {
        AcknowledgePairResponseReceivedOutcome::Delivered { close } => close,
        other => panic!("fresh receipt must deliver: {other:?}"),
    };
    let target =
        freeze_zero_cut_bootstrap_target(&store, &clock, "legacy-higher-revision", &directory)
            .await;
    commit_zero_cut_barriers(&store, &clock, target.operation_id).await;
    tick(&clock);
    assert!(matches!(
        store
            .try_complete_key_transition(target.operation_id)
            .await
            .expect("complete legacy higher-revision fixture"),
        super::key_transition::KeyTransitionCompletion::Completed(_)
    ));
    let current_revision = advance_global_revision_with_device(&store, &clock).await;
    assert!(current_revision > proof_revision);
    store
        .shutdown()
        .await
        .expect("shutdown legacy higher-revision setup");

    let mut state = super::sqlite::open(
        &config(),
        load_or_create_storage_kek(&keys, &root.database()).expect("reload StorageKEK"),
    )
    .expect("open low-level legacy higher-revision state");
    super::key_transition::reseal_transition_with_legacy_codec_for_test(
        &mut state,
        &config(),
        target.operation_id,
        codec,
    )
    .expect("project completed transition to authentic proofless legacy codec");
    assert_eq!(
        super::key_transition::transition_codec_version_for_test(&state, target.operation_id)
            .expect("read proofless legacy codec version"),
        expected_legacy_version
    );
    drop(state);

    let reopened = RuntimeStoreHandle::open(
        config(),
        load_or_create_storage_kek(&keys, &root.database()).expect("reload StorageKEK"),
    )
    .await
    .expect("legacy proofless transition remains strictly readable");
    let before_replay = artifact_bytes(&root.database());
    assert!(matches!(
        reopened
            .acknowledge_pair_response_received(AcknowledgePairResponseReceived::new(
                preparation.pairing_id(),
                &receipt,
            ))
            .await,
        Err(RuntimeStoreError::PublicationMismatch)
    ));
    assert_eq!(artifact_bytes(&root.database()), before_replay);
    assert!(matches!(
        reopened
            .acknowledge_pair_route_close(
                preparation.pairing_id(),
                close_terminal(close.pair_route(), PairRouteCloseOutcome::Closed),
            )
            .await,
        Err(RuntimeStoreError::InvalidStateTransition)
    ));
    assert_eq!(artifact_bytes(&root.database()), before_replay);
    reopened
        .shutdown()
        .await
        .expect("shutdown rejected legacy higher-revision store");
}

#[tokio::test]
async fn legacy_v1_v2_without_historical_lineage_reject_higher_revision_backfill_and_close() {
    for (label, codec, expected_version) in [
        (
            "v1",
            super::key_transition::LegacyTransitionCodecForTest::V1,
            1,
        ),
        (
            "v2",
            super::key_transition::LegacyTransitionCodecForTest::V2,
            2,
        ),
    ] {
        assert_legacy_receipt_replay_rejects_higher_global_revision(label, codec, expected_version)
            .await;
    }
}

#[tokio::test]
async fn fresh_receipt_still_rejects_a_clock_before_update_freeze() {
    let root = TestRoot::new("pairing-bootstrap-fresh-receipt-clock");
    let keys = MemoryKeyStore::new();
    let clock = Arc::new(AtomicU64::new(NOW_MS));
    let store = RuntimeStoreHandle::open(
        RuntimeStoreConfig::new(root.database())
            .with_capacity_probe(GenerousCapacity)
            .with_clock(TestClock(clock.clone())),
        load_or_create_storage_kek(&keys, &root.database()).expect("load StorageKEK"),
    )
    .await
    .expect("open fresh receipt clock store");
    let (preparation, committed, directory) =
        prepare_committed_with_directory(&store, &clock).await;
    let target =
        freeze_zero_cut_bootstrap_target(&store, &clock, "fresh-receipt-clock", &directory).await;
    let frozen = load_bootstrap_target_update(&store, &target).await;
    assert_eq!(
        frozen.lifecycle,
        super::key_transition::KeyUpdateLifecycle::Frozen
    );
    let regressed_at_ms = frozen.state_changed_at_ms.saturating_sub(1);
    clock.store(regressed_at_ms, Ordering::SeqCst);
    let proof = verified_receipt(&committed);
    let before = artifact_bytes(&root.database());
    let error = store
        .acknowledge_pair_response_received(AcknowledgePairResponseReceived::new(
            preparation.pairing_id(),
            &proof,
        ))
        .await
        .expect_err("fresh delivery may not borrow the legacy replay clock exception");
    assert!(matches!(
        error,
        RuntimeStoreError::ClockRegressed {
            persisted_ms,
            observed_ms,
        } if persisted_ms == frozen.state_changed_at_ms && observed_ms == regressed_at_ms
    ));
    assert_eq!(artifact_bytes(&root.database()), before);
    store
        .shutdown()
        .await
        .expect("shutdown fresh receipt clock store");
}

#[tokio::test]
async fn completed_bootstrap_same_revision_key_lineage_fork_rejects_full_open_and_close_without_write()
 {
    let root = TestRoot::new("pairing-bootstrap-completed-global-fork");
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
    .expect("open completed global fork store");
    let (preparation, committed, directory) =
        prepare_committed_with_directory(&store, &clock).await;
    let proof = verified_receipt(&committed);
    tick(&clock);
    let close = match store
        .acknowledge_pair_response_received(AcknowledgePairResponseReceived::new(
            preparation.pairing_id(),
            &proof,
        ))
        .await
        .expect("deliver completed global fork fixture")
    {
        AcknowledgePairResponseReceivedOutcome::Delivered { close } => close,
        other => panic!("fresh receipt must deliver: {other:?}"),
    };
    let target =
        freeze_zero_cut_bootstrap_target(&store, &clock, "completed-global-fork", &directory).await;
    commit_zero_cut_barriers(&store, &clock, target.operation_id).await;
    tick(&clock);
    assert!(matches!(
        store
            .try_complete_key_transition(target.operation_id)
            .await
            .expect("complete global fork fixture"),
        super::key_transition::KeyTransitionCompletion::Completed(_)
    ));
    store.shutdown().await.expect("shutdown global fork setup");

    let mut state = super::sqlite::open(
        &config(),
        load_or_create_storage_kek(&keys, &root.database()).expect("reload StorageKEK"),
    )
    .expect("open low-level global fork state");
    let recovery =
        super::key_transition::load_key_transition_for_capacity_test(&state, target.operation_id)
            .expect("load completed global fork transition");
    let mut transition = recovery.transition;
    transition
        .global_lineage
        .as_mut()
        .expect("completed bootstrap global lineage exists")
        .stable_key_lineage_hash
        .as_mut()
        .expect("completed bootstrap stable material lineage exists")[0] ^= 0xff;
    let update = recovery
        .updates
        .into_iter()
        .find(|update| update.recipient == target.recipient)
        .expect("completed target update exists");
    super::key_transition::replace_transition_and_update_for_capacity_test(
        &mut state,
        &config(),
        transition,
        update,
    )
    .expect("persist authenticated same-revision global fork");
    let before_close = artifact_bytes(&root.database());
    assert!(matches!(
        super::pairing_terminal::acknowledge_pair_route_close(
            &mut state,
            &config(),
            preparation.pairing_id(),
            close_terminal(close.pair_route(), PairRouteCloseOutcome::Closed),
        ),
        Err(RuntimeStoreError::UnknownOrCorruptSchema)
    ));
    assert_eq!(artifact_bytes(&root.database()), before_close);
    drop(state);
    let before_full_open = artifact_bytes(&root.database());
    assert!(
        RuntimeStoreHandle::open(
            config(),
            load_or_create_storage_kek(&keys, &root.database()).expect("reload StorageKEK"),
        )
        .await
        .is_err(),
        "full open must reject a completed same-revision global hash fork"
    );
    assert_eq!(artifact_bytes(&root.database()), before_full_open);
}

#[tokio::test]
async fn completed_bootstrap_proof_allows_close_after_later_global_revision() {
    let root = TestRoot::new("pairing-bootstrap-completed-higher-global");
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
    .expect("open completed higher-global store");
    let (preparation, committed, directory) =
        prepare_committed_with_directory(&store, &clock).await;
    let proof_revision = directory.revision.value();
    tick(&clock);
    let close = match store
        .acknowledge_pair_response_received(AcknowledgePairResponseReceived::new(
            preparation.pairing_id(),
            &verified_receipt(&committed),
        ))
        .await
        .expect("deliver completed higher-global fixture")
    {
        AcknowledgePairResponseReceivedOutcome::Delivered { close } => close,
        other => panic!("fresh receipt must deliver: {other:?}"),
    };
    let target =
        freeze_zero_cut_bootstrap_target(&store, &clock, "completed-higher-global", &directory)
            .await;
    commit_zero_cut_barriers(&store, &clock, target.operation_id).await;
    tick(&clock);
    assert!(matches!(
        store
            .try_complete_key_transition(target.operation_id)
            .await
            .expect("complete retained bootstrap transition"),
        super::key_transition::KeyTransitionCompletion::Completed(_)
    ));

    let current_revision = advance_global_revision_with_device(&store, &clock).await;
    assert!(current_revision > proof_revision);
    let outcome = store
        .acknowledge_pair_route_close(
            preparation.pairing_id(),
            close_terminal(close.pair_route(), PairRouteCloseOutcome::Closed),
        )
        .await
        .expect("older completed bootstrap proof remains valid after legal global advance");
    assert!(!outcome.replayed());
    store
        .shutdown()
        .await
        .expect("shutdown completed higher-global store");
    RuntimeStoreHandle::open(
        config(),
        load_or_create_storage_kek(&keys, &root.database()).expect("reload StorageKEK"),
    )
    .await
    .expect("full open accepts older completed proof after legal global advance")
    .shutdown()
    .await
    .expect("shutdown reopened completed higher-global store");
}

#[tokio::test]
async fn active_bootstrap_reconcile_rejects_global_hash_mismatch_before_write() {
    let root = TestRoot::new("pairing-bootstrap-active-global-fork");
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
    .expect("open active global fork store");
    let (preparation, committed, _) = prepare_committed_with_directory(&store, &clock).await;
    let input = AcknowledgePairResponseReceived::new(
        preparation.pairing_id(),
        &verified_receipt(&committed),
    );
    store
        .shutdown()
        .await
        .expect("shutdown active global fork setup");

    let mut state = super::sqlite::open(
        &config(),
        load_or_create_storage_kek(&keys, &root.database()).expect("reload StorageKEK"),
    )
    .expect("open low-level active global fork state");
    let pairings =
        super::pairing::load_pairing_rows(&state.connection, &state.key_bundle, state.database_id)
            .expect("load authenticated active global fork pairing");
    let pairing = pairings
        .iter()
        .find(|pairing| pairing.record.pairing_id == preparation.pairing_id())
        .expect("active global fork pairing exists");
    let mut binding = super::pairing_delivery::bootstrap_binding_for_test(
        pairing,
        &input,
        clock.load(Ordering::SeqCst).saturating_add(1),
    )
    .expect("build authenticated bootstrap binding");
    binding.global_key_state_hash[0] ^= 0xff;

    let before = artifact_bytes(&root.database());
    let key_bundle = state.key_bundle.clone();
    let database_id = state.database_id;
    let transaction = state
        .connection
        .transaction()
        .expect("open active global fork reconcile transaction");
    let ledger = super::sqlite::load_runtime_ledger(&transaction, &key_bundle, database_id)
        .expect("load active global fork ledger");
    let mut next = ledger.clone();
    let error = super::key_transition::reconcile_pairing_bootstrap_install_proof_in_transaction(
        &transaction,
        &key_bundle,
        database_id,
        &mut next,
        binding,
        super::key_transition::PairingBootstrapProofReconcileMode::FreshDelivery,
    )
    .expect_err("active bootstrap reconcile must reject a global hash mismatch");
    assert!(matches!(error, RuntimeStoreError::PublicationMismatch));
    assert_eq!(next, ledger);
    transaction
        .rollback()
        .expect("rollback rejected active global fork reconcile");
    assert_eq!(artifact_bytes(&root.database()), before);
}

#[tokio::test]
async fn completed_bootstrap_close_rejects_receipt_hash_or_received_at_mismatch_without_write() {
    for axis in ["receipt-hash", "received-at"] {
        let root = TestRoot::new(&format!("pairing-bootstrap-close-{axis}"));
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
        .expect("open Close proof mismatch store");
        let (preparation, committed, directory) =
            prepare_committed_with_directory(&store, &clock).await;
        let proof = verified_receipt(&committed);
        tick(&clock);
        let close = match store
            .acknowledge_pair_response_received(AcknowledgePairResponseReceived::new(
                preparation.pairing_id(),
                &proof,
            ))
            .await
            .expect("deliver Close proof mismatch fixture")
        {
            AcknowledgePairResponseReceivedOutcome::Delivered { close } => close,
            other => panic!("fresh receipt must deliver: {other:?}"),
        };
        let target = freeze_zero_cut_bootstrap_target(&store, &clock, axis, &directory).await;
        commit_zero_cut_barriers(&store, &clock, target.operation_id).await;
        tick(&clock);
        assert!(matches!(
            store
                .try_complete_key_transition(target.operation_id)
                .await
                .expect("complete Close mismatch fixture"),
            super::key_transition::KeyTransitionCompletion::Completed(_)
        ));
        store
            .shutdown()
            .await
            .expect("shutdown Close mismatch setup");

        let mut state = super::sqlite::open(
            &config(),
            load_or_create_storage_kek(&keys, &root.database()).expect("reload StorageKEK"),
        )
        .expect("open low-level Close mismatch state");
        let recovery = super::key_transition::load_key_transition_for_capacity_test(
            &state,
            target.operation_id,
        )
        .expect("load completed Close mismatch transition");
        let mut transition = recovery.transition;
        let mut update = recovery
            .updates
            .into_iter()
            .find(|update| update.recipient == target.recipient)
            .expect("Close mismatch target update exists");
        let binding = &mut transition
            .bootstrap_install_proof
            .as_mut()
            .expect("completed bootstrap proof exists")
            .binding;
        match axis {
            "receipt-hash" => {
                binding.canonical_receipt[0] ^= 0xff;
                binding.receipt_hash = agentdeck_crypto::sha256(&binding.canonical_receipt);
                update.canonical_ack = Some(binding.canonical_receipt.clone());
            }
            "received-at" => binding.received_at_ms += 1,
            _ => unreachable!("bounded Close mismatch axis"),
        }
        super::key_transition::replace_transition_and_update_for_capacity_test(
            &mut state,
            &config(),
            transition,
            update,
        )
        .expect("persist authenticated Close proof mismatch");
        drop(state);

        let reopened = RuntimeStoreHandle::open(
            config(),
            load_or_create_storage_kek(&keys, &root.database()).expect("reload StorageKEK"),
        )
        .await
        .expect("full open permits pairing-only proof mismatch for Close readback");
        let before_close = artifact_bytes(&root.database());
        assert!(matches!(
            reopened
                .acknowledge_pair_route_close(
                    preparation.pairing_id(),
                    close_terminal(close.pair_route(), PairRouteCloseOutcome::Closed),
                )
                .await,
            Err(RuntimeStoreError::PairingConflict)
        ));
        assert_eq!(artifact_bytes(&root.database()), before_close);
        reopened
            .shutdown()
            .await
            .expect("shutdown Close mismatch store");
    }
}

#[tokio::test]
async fn authenticated_proof_lineage_tamper_fails_full_open_without_rewrite() {
    for axis in ["stable-global-lineage", "proof-slot-digest"] {
        let root = TestRoot::new(&format!("pairing-bootstrap-{axis}"));
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
        .expect("open bootstrap lineage tamper setup");
        let (preparation, committed, directory) =
            prepare_committed_with_directory(&store, &clock).await;
        let target = freeze_zero_cut_bootstrap_target(&store, &clock, axis, &directory).await;
        let proof = verified_receipt(&committed);
        tick(&clock);
        assert!(matches!(
            store
                .acknowledge_pair_response_received(AcknowledgePairResponseReceived::new(
                    preparation.pairing_id(),
                    &proof,
                ))
                .await
                .expect("deliver lineage tamper setup receipt"),
            AcknowledgePairResponseReceivedOutcome::Delivered { .. }
        ));
        store
            .shutdown()
            .await
            .expect("shutdown lineage tamper setup");

        let mut state = super::sqlite::open(
            &config(),
            load_or_create_storage_kek(&keys, &root.database()).expect("reload StorageKEK"),
        )
        .expect("open low-level lineage tamper state");
        let recovery = super::key_transition::load_active_key_transition(&state)
            .expect("load lineage tamper transition")
            .expect("lineage tamper transition remains active");
        let mut transition = recovery.transition;
        let update = recovery
            .updates
            .into_iter()
            .find(|update| update.recipient == target.recipient)
            .expect("lineage tamper target update exists");
        match axis {
            "stable-global-lineage" => {
                transition
                    .global_lineage
                    .as_mut()
                    .expect("lineage tamper anchor exists")
                    .stable_key_lineage_hash
                    .as_mut()
                    .expect("stable key lineage exists")[0] ^= 0xff;
            }
            "proof-slot-digest" => {
                transition
                    .bootstrap_install_proof
                    .as_mut()
                    .expect("lineage tamper proof exists")
                    .binding
                    .key_slot_digest[0] ^= 0xff;
            }
            _ => unreachable!("bounded lineage tamper axis"),
        }
        super::key_transition::replace_transition_and_update_for_capacity_test(
            &mut state,
            &config(),
            transition,
            update,
        )
        .expect("persist individually authenticated cross-row mismatch");
        drop(state);
        let tampered = artifact_bytes(&root.database());
        assert!(
            RuntimeStoreHandle::open(
                config(),
                load_or_create_storage_kek(&keys, &root.database()).expect("reload StorageKEK"),
            )
            .await
            .is_err(),
            "full open must reject authenticated {axis} cross-row mismatch"
        );
        assert_eq!(artifact_bytes(&root.database()), tampered);
    }
}

#[tokio::test]
async fn add_receipt_after_barriers_committed_reconciles_and_completes_zero_cut() {
    let root = TestRoot::new("pairing-bootstrap-add-late");
    let keys = MemoryKeyStore::new();
    let clock = Arc::new(AtomicU64::new(NOW_MS));
    let store = RuntimeStoreHandle::open(
        RuntimeStoreConfig::new(root.database())
            .with_capacity_probe(GenerousCapacity)
            .with_clock(TestClock(clock.clone())),
        load_or_create_storage_kek(&keys, &root.database()).expect("load StorageKEK"),
    )
    .await
    .expect("open late Add bootstrap store");
    let (preparation, committed, directory) =
        prepare_committed_with_directory(&store, &clock).await;
    let target =
        freeze_zero_cut_bootstrap_target(&store, &clock, "late-add-bootstrap", &directory).await;
    assert_eq!(
        load_bootstrap_target_update(&store, &target)
            .await
            .lifecycle,
        super::key_transition::KeyUpdateLifecycle::Frozen
    );
    commit_zero_cut_barriers(&store, &clock, target.operation_id).await;
    let frozen = load_bootstrap_target_update(&store, &target).await;
    let normal_ack = b"late-add-normal-key-update-ack".to_vec();
    tick(&clock);
    store
        .acknowledge_key_update(super::key_transition::AcknowledgeKeyUpdate {
            operation_id: target.operation_id,
            recipient: target.recipient,
            key_revision: target.key_revision,
            update_hash: super::key_transition::canonical_update_hash(&frozen.canonical_update_set)
                .expect("hash late Add update"),
            canonical_ack: normal_ack.clone(),
            acknowledged_at_ms: clock.load(Ordering::SeqCst),
        })
        .await
        .expect("normal KeyUpdateAck may win before PairResponse receipt");
    let proof = verified_receipt(&committed);
    let ack_time = clock.load(Ordering::SeqCst);
    clock.store(ack_time.saturating_sub(1), Ordering::SeqCst);
    let before_regressed_receipt = artifact_bytes(&root.database());
    let regressed = store
        .acknowledge_pair_response_received(AcknowledgePairResponseReceived::new(
            preparation.pairing_id(),
            &proof,
        ))
        .await
        .expect_err("fresh receipt must not predate the persisted normal ACK");
    assert!(matches!(
        regressed,
        RuntimeStoreError::ClockRegressed {
            persisted_ms,
            observed_ms,
        } if persisted_ms == ack_time && observed_ms == ack_time.saturating_sub(1)
    ));
    assert_eq!(artifact_bytes(&root.database()), before_regressed_receipt);
    clock.store(ack_time, Ordering::SeqCst);
    tick(&clock);
    let close = match store
        .acknowledge_pair_response_received(AcknowledgePairResponseReceived::new(
            preparation.pairing_id(),
            &proof,
        ))
        .await
        .expect("reconcile late Add bootstrap receipt")
    {
        AcknowledgePairResponseReceivedOutcome::Delivered { close } => close,
        other => panic!("late Add receipt must deliver: {other:?}"),
    };
    let update = load_bootstrap_target_update(&store, &target).await;
    assert_eq!(
        update.lifecycle,
        super::key_transition::KeyUpdateLifecycle::Acked
    );
    assert_eq!(
        update.canonical_ack.as_deref(),
        Some(normal_ack.as_slice()),
        "receipt 后到必须保留已经验真的正常 KeyUpdateAck"
    );
    tick(&clock);
    assert!(matches!(
        store
            .try_complete_key_transition(target.operation_id)
            .await
            .expect("complete reconciled Add transition"),
        super::key_transition::KeyTransitionCompletion::Completed(_)
    ));
    store
        .acknowledge_pair_route_close(
            preparation.pairing_id(),
            close_terminal(close.pair_route(), PairRouteCloseOutcome::Closed),
        )
        .await
        .expect("close reconciled Add pairing");
    store.shutdown().await.expect("shutdown late Add store");
}

#[tokio::test]
async fn late_normal_ack_upgrades_completed_bootstrap_evidence_without_moving_terminal_time() {
    let root = TestRoot::new("pairing-bootstrap-late-normal-ack");
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
    .expect("open late normal ACK bootstrap store");
    let (preparation, committed, directory) =
        prepare_committed_with_directory(&store, &clock).await;
    let proof = verified_receipt(&committed);
    tick(&clock);
    let close = match store
        .acknowledge_pair_response_received(AcknowledgePairResponseReceived::new(
            preparation.pairing_id(),
            &proof,
        ))
        .await
        .expect("deliver receipt before update freeze")
    {
        AcknowledgePairResponseReceivedOutcome::Delivered { close } => close,
        other => panic!("fresh receipt must deliver: {other:?}"),
    };
    let target =
        freeze_zero_cut_bootstrap_target(&store, &clock, "late-normal-ack", &directory).await;
    let placeholder = load_bootstrap_target_update(&store, &target).await;
    assert_eq!(
        placeholder.canonical_ack.as_deref(),
        Some(proof.canonical_receipt())
    );
    let placeholder_time = placeholder.state_changed_at_ms;
    commit_zero_cut_barriers(&store, &clock, target.operation_id).await;
    tick(&clock);
    assert!(matches!(
        store
            .try_complete_key_transition(target.operation_id)
            .await
            .expect("complete receipt-proven bootstrap transition"),
        super::key_transition::KeyTransitionCompletion::Completed(_)
    ));
    let completion_time = clock.load(Ordering::SeqCst);

    let normal_ack = b"completed-bootstrap-late-normal-ack".to_vec();
    let before_regression = artifact_bytes(&root.database());
    clock.store(placeholder_time.saturating_sub(1), Ordering::SeqCst);
    assert!(matches!(
        store
            .acknowledge_key_update(super::key_transition::AcknowledgeKeyUpdate {
                operation_id: target.operation_id,
                recipient: target.recipient,
                key_revision: target.key_revision,
                update_hash: super::key_transition::canonical_update_hash(
                    &placeholder.canonical_update_set,
                )
                .expect("hash completed bootstrap update"),
                canonical_ack: normal_ack.clone(),
                acknowledged_at_ms: placeholder_time.saturating_sub(1),
            })
            .await,
        Err(RuntimeStoreError::ClockRegressed { .. })
    ));
    assert_eq!(artifact_bytes(&root.database()), before_regression);

    clock.store(completion_time, Ordering::SeqCst);
    tick(&clock);
    let upgraded = store
        .acknowledge_key_update(super::key_transition::AcknowledgeKeyUpdate {
            operation_id: target.operation_id,
            recipient: target.recipient,
            key_revision: target.key_revision,
            update_hash: super::key_transition::canonical_update_hash(
                &placeholder.canonical_update_set,
            )
            .expect("hash completed bootstrap update"),
            canonical_ack: normal_ack.clone(),
            acknowledged_at_ms: clock.load(Ordering::SeqCst),
        })
        .await
        .expect("late normal ACK upgrades bootstrap placeholder");
    assert_eq!(upgraded.canonical_ack, Some(normal_ack.clone()));
    assert_eq!(
        upgraded.state_changed_at_ms, placeholder_time,
        "evidence enrichment must not move a completed transition's causal time"
    );
    store
        .shutdown()
        .await
        .expect("shutdown upgraded bootstrap store");

    let reopened = RuntimeStoreHandle::open(
        config(),
        load_or_create_storage_kek(&keys, &root.database()).expect("reload StorageKEK"),
    )
    .await
    .expect("reopen completed bootstrap ACK upgrade");
    let replayed = reopened
        .acknowledge_key_update(super::key_transition::AcknowledgeKeyUpdate {
            operation_id: target.operation_id,
            recipient: target.recipient,
            key_revision: target.key_revision,
            update_hash: super::key_transition::canonical_update_hash(
                &placeholder.canonical_update_set,
            )
            .expect("hash reopened bootstrap update"),
            canonical_ack: normal_ack,
            acknowledged_at_ms: clock.load(Ordering::SeqCst),
        })
        .await
        .expect("exact late normal ACK replays after full-open audit");
    assert_eq!(replayed.state_changed_at_ms, placeholder_time);
    reopened
        .acknowledge_pair_route_close(
            preparation.pairing_id(),
            close_terminal(close.pair_route(), PairRouteCloseOutcome::Closed),
        )
        .await
        .expect("close pairing after completed ACK upgrade");
    reopened
        .shutdown()
        .await
        .expect("shutdown late normal ACK store");
}

#[tokio::test]
async fn renewal_receipt_after_update_freeze_acks_target_only() {
    let root = TestRoot::new("pairing-bootstrap-renew-frozen");
    let keys = MemoryKeyStore::new();
    let clock = Arc::new(AtomicU64::new(NOW_MS));
    let store = RuntimeStoreHandle::open(
        RuntimeStoreConfig::new(root.database())
            .with_capacity_probe(GenerousCapacity)
            .with_clock(TestClock(clock.clone())),
        load_or_create_storage_kek(&keys, &root.database()).expect("load StorageKEK"),
    )
    .await
    .expect("open renewal bootstrap store");
    let (preparation, committed, directory) = prepare_renewal_committed(&store, &clock).await;
    let transition = store
        .load_active_key_transition()
        .await
        .expect("load renewal transition")
        .expect("renewal transition exists");
    assert_eq!(
        transition.transition.operation,
        super::key_transition::KeyTransitionOperation::Renew
    );
    assert_eq!(transition.transition.to_revision, 3);

    let target =
        freeze_zero_cut_bootstrap_target(&store, &clock, "renew-bootstrap", &directory).await;
    let proof = verified_receipt(&committed);
    tick(&clock);
    let close = match store
        .acknowledge_pair_response_received(AcknowledgePairResponseReceived::new(
            preparation.pairing_id(),
            &proof,
        ))
        .await
        .expect("reconcile renewal bootstrap receipt after update freeze")
    {
        AcknowledgePairResponseReceivedOutcome::Delivered { close } => close,
        other => panic!("renewal receipt must deliver: {other:?}"),
    };
    let recovery = store
        .load_active_key_transition()
        .await
        .expect("load reconciled renewal transition")
        .expect("renewal remains active for non-target ACK");
    let mut target_update = None;
    let mut non_target_update = None;
    for update in &recovery.updates {
        if update.recipient == target.recipient {
            assert_eq!(
                update.lifecycle,
                super::key_transition::KeyUpdateLifecycle::Acked
            );
            assert_eq!(
                update.canonical_ack.as_deref(),
                Some(proof.canonical_receipt())
            );
            target_update = Some(update.clone());
        } else {
            assert_eq!(
                update.lifecycle,
                super::key_transition::KeyUpdateLifecycle::Frozen,
                "bootstrap proof must not exempt an existing non-target device"
            );
            assert!(update.canonical_ack.is_none());
            non_target_update = Some(update.clone());
        }
    }
    let target_update = target_update.expect("renewal target update exists");
    let non_target_update = non_target_update.expect("renewal non-target update exists");
    let target_normal_ack = b"renew-target-normal-key-update-ack".to_vec();
    tick(&clock);
    store
        .acknowledge_key_update(super::key_transition::AcknowledgeKeyUpdate {
            operation_id: target.operation_id,
            recipient: target.recipient,
            key_revision: target.key_revision,
            update_hash: super::key_transition::canonical_update_hash(
                &target_update.canonical_update_set,
            )
            .expect("hash renewal target update"),
            canonical_ack: target_normal_ack.clone(),
            acknowledged_at_ms: clock.load(Ordering::SeqCst),
        })
        .await
        .expect("in-flight target KeyUpdateAck upgrades receipt placeholder");
    let non_target_normal_ack = b"renew-non-target-key-update-ack".to_vec();
    tick(&clock);
    store
        .acknowledge_key_update(super::key_transition::AcknowledgeKeyUpdate {
            operation_id: target.operation_id,
            recipient: non_target_update.recipient,
            key_revision: target.key_revision,
            update_hash: super::key_transition::canonical_update_hash(
                &non_target_update.canonical_update_set,
            )
            .expect("hash renewal non-target update"),
            canonical_ack: non_target_normal_ack.clone(),
            acknowledged_at_ms: clock.load(Ordering::SeqCst),
        })
        .await
        .expect("non-target still requires its own normal KeyUpdateAck");
    let upgraded = store
        .load_active_key_transition()
        .await
        .expect("reload renewal ACK race convergence")
        .expect("renewal remains active before barriers");
    assert_eq!(
        upgraded
            .transition
            .bootstrap_install_proof
            .as_ref()
            .expect("bootstrap proof remains durable")
            .binding
            .canonical_receipt,
        proof.canonical_receipt()
    );
    for update in upgraded.updates {
        if update.recipient == target.recipient {
            assert_eq!(update.canonical_ack, Some(target_normal_ack.clone()));
        } else {
            assert_eq!(update.canonical_ack, Some(non_target_normal_ack.clone()));
        }
    }
    store
        .acknowledge_pair_route_close(
            preparation.pairing_id(),
            close_terminal(close.pair_route(), PairRouteCloseOutcome::Closed),
        )
        .await
        .expect("close after renewal proof is durable in transition");
    store.shutdown().await.expect("shutdown renewal store");
}

#[tokio::test]
async fn bootstrap_proof_wrong_target_revision_or_device_signature_never_acks_update() {
    let root = TestRoot::new("pairing-bootstrap-proof-negative-axes");
    let keys = MemoryKeyStore::new();
    let clock = Arc::new(AtomicU64::new(NOW_MS));
    let store = RuntimeStoreHandle::open(
        RuntimeStoreConfig::new(root.database())
            .with_capacity_probe(GenerousCapacity)
            .with_clock(TestClock(clock.clone())),
        load_or_create_storage_kek(&keys, &root.database()).expect("load StorageKEK"),
    )
    .await
    .expect("open bootstrap negative-axis store");
    let (preparation, committed, directory) =
        prepare_committed_with_directory(&store, &clock).await;
    let target =
        freeze_zero_cut_bootstrap_target(&store, &clock, "negative-bootstrap", &directory).await;
    assert_eq!(
        load_bootstrap_target_update(&store, &target)
            .await
            .lifecycle,
        super::key_transition::KeyUpdateLifecycle::Frozen
    );

    let other_root = TestRoot::new("pairing-bootstrap-proof-wrong-target");
    let other_keys = MemoryKeyStore::new();
    let other_clock = Arc::new(AtomicU64::new(NOW_MS));
    let other_store = RuntimeStoreHandle::open(
        RuntimeStoreConfig::new(other_root.database())
            .with_capacity_probe(GenerousCapacity)
            .with_clock(TestClock(other_clock.clone())),
        load_or_create_storage_kek(&other_keys, &other_root.database())
            .expect("load other-target StorageKEK"),
    )
    .await
    .expect("open other-target store");
    let (_, other_committed) = prepare_new_device_committed_with(
        &other_store,
        &other_clock,
        DeviceRouteId::from_bytes([0xd9; 16]),
        0xc1,
        0xc4,
        0xd1,
    )
    .await;
    let wrong_target = verified_receipt_with_seed(&other_committed, [0xc4; 32]);

    let before_wrong_target = artifact_bytes(&root.database());
    assert!(matches!(
        store
            .acknowledge_pair_response_received(AcknowledgePairResponseReceived::new(
                preparation.pairing_id(),
                &wrong_target,
            ))
            .await,
        Err(RuntimeStoreError::PairingConflict)
    ));
    assert_eq!(artifact_bytes(&root.database()), before_wrong_target);
    other_store
        .shutdown()
        .await
        .expect("shutdown other-target store");

    let revision_root = TestRoot::new("pairing-bootstrap-proof-wrong-revision");
    let revision_keys = MemoryKeyStore::new();
    let revision_clock = Arc::new(AtomicU64::new(NOW_MS));
    let revision_store = RuntimeStoreHandle::open(
        RuntimeStoreConfig::new(revision_root.database())
            .with_capacity_probe(GenerousCapacity)
            .with_clock(TestClock(revision_clock.clone())),
        load_or_create_storage_kek(&revision_keys, &revision_root.database())
            .expect("load wrong-revision StorageKEK"),
    )
    .await
    .expect("open wrong-revision store");
    let (_, revision_committed, _) =
        prepare_renewal_committed(&revision_store, &revision_clock).await;
    assert_eq!(
        revision_store
            .load_active_key_transition()
            .await
            .expect("load wrong-revision transition")
            .expect("wrong-revision transition exists")
            .transition
            .to_revision,
        3
    );
    let wrong_revision = verified_receipt(&revision_committed);
    let before_wrong_revision = artifact_bytes(&root.database());
    assert!(matches!(
        store
            .acknowledge_pair_response_received(AcknowledgePairResponseReceived::new(
                preparation.pairing_id(),
                &wrong_revision,
            ))
            .await,
        Err(RuntimeStoreError::PairingConflict)
    ));
    assert_eq!(artifact_bytes(&root.database()), before_wrong_revision);
    revision_store
        .shutdown()
        .await
        .expect("shutdown wrong-revision store");

    let binding = PairResponseAccessBinding::from_frozen(
        committed.invite(),
        committed.request_hash(),
        committed.relay_grant(),
        committed.pair_response(),
    )
    .expect("rebuild primary bootstrap binding");
    let forged = sign_pair_response_received(
        &SigningKey::from_seed(&[0xee; 32]),
        binding.info(),
        binding.receipt_context(),
        PairResponseReceivedV1 {
            request_hash: committed.request_hash(),
            grant_hash: committed.grant_hash(),
            response_hash: committed.response_hash(),
            signature: Ed25519Signature([0; 64]),
        },
    )
    .expect("encode wrong-DeviceSign receipt");
    assert!(
        binding
            .verify_signed_receipt(
                &forged
                    .canonical_bytes()
                    .expect("canonical wrong-DeviceSign receipt"),
            )
            .is_err(),
        "unverified canonical bytes must never construct the Store input capability"
    );
    let update = load_bootstrap_target_update(&store, &target).await;
    assert_eq!(
        update.lifecycle,
        super::key_transition::KeyUpdateLifecycle::Frozen
    );
    assert!(update.canonical_ack.is_none());
    store
        .shutdown()
        .await
        .expect("shutdown negative-axis store");
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
        let (preparation, recovery, directory) =
            prepare_committed_with_directory(&setup, &clock).await;
        let target =
            freeze_zero_cut_bootstrap_target(&setup, &clock, "delivery-fault", &directory).await;
        let proof = verified_receipt(&recovery);
        tick(&clock);
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
        let after_fault = faulted
            .load_active_key_transition()
            .await
            .expect("read transition after delivery fault")
            .expect("delivery fault keeps transition active");
        let target_update = after_fault
            .updates
            .iter()
            .find(|update| update.recipient == target.recipient)
            .expect("delivery fault target update exists");
        if committed {
            assert_eq!(
                faulted
                    .load_pairing_winner(preparation.pairing_id())
                    .await
                    .expect("read Delivered winner after commit-unknown")
                    .expect("commit-unknown retains pairing winner")
                    .state(),
                PairingState::Delivered
            );
            assert_eq!(
                after_fault
                    .transition
                    .bootstrap_install_proof
                    .as_ref()
                    .expect("commit-unknown durably retains proof")
                    .binding
                    .canonical_receipt
                    .as_slice(),
                proof.canonical_receipt()
            );
            assert_eq!(
                target_update.lifecycle,
                super::key_transition::KeyUpdateLifecycle::Acked
            );
            assert_eq!(
                target_update.canonical_ack.as_deref(),
                Some(proof.canonical_receipt())
            );
        } else {
            assert!(after_fault.transition.bootstrap_install_proof.is_none());
            assert_eq!(
                target_update.lifecycle,
                super::key_transition::KeyUpdateLifecycle::Frozen
            );
            assert!(target_update.canonical_ack.is_none());
        }
        faulted.shutdown().await.expect("shutdown faulted store");

        let reopened = RuntimeStoreHandle::open(
            config(),
            load_or_create_storage_kek(&keys, &root.database()).expect("reload StorageKEK"),
        )
        .await
        .expect("reopen delivery fault store");
        let before_retry = artifact_bytes(&root.database());
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
        if committed {
            assert_eq!(
                artifact_bytes(&root.database()),
                before_retry,
                "commit-unknown exact retry must be a read-only Replayed readback"
            );
        }
        assert_eq!(delivery_counts(&root.database()), (1, 1, 1, 1));
        let converged = reopened
            .load_active_key_transition()
            .await
            .expect("read converged delivery transition")
            .expect("delivery transition remains active before barriers");
        assert_eq!(
            converged
                .transition
                .bootstrap_install_proof
                .as_ref()
                .expect("retry converges durable proof")
                .binding
                .canonical_receipt
                .as_slice(),
            proof.canonical_receipt()
        );
        let target_update = converged
            .updates
            .into_iter()
            .find(|update| update.recipient == target.recipient)
            .expect("retry converges target update");
        assert_eq!(
            target_update.lifecycle,
            super::key_transition::KeyUpdateLifecycle::Acked
        );
        assert_eq!(
            target_update.canonical_ack.as_deref(),
            Some(proof.canonical_receipt())
        );
        assert_eq!(
            reopened
                .list_pairing_terminal_recovery()
                .await
                .expect("read converged Close recovery")
                .len(),
            1
        );
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
