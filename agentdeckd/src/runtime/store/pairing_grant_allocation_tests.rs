//! P4.3 grant serial renewal 的 Store authority focused tests。
//!
//! 覆盖 authenticated allocation、同 fingerprint 单调续期、stale allocation CAS、
//! 撤销终态拒绝，以及 Superseded 历史的离线篡改 fail-close/零改写。

use std::sync::Arc;
use std::sync::atomic::{AtomicU64, Ordering};

use agentdeck_crypto::{SigningKey, sha256, sign_pair_response_received, sign_tbs};
use agentdeck_protocol::e2ee::{KeyId, KeyUpdateSetV1, KeyUpdateV1, PairResponseReceivedV1};
use agentdeck_protocol::relay_v2::frame::{
    GrantCommitted, OpaqueRouteFrame, PairRouteCloseOutcome, PairRouteClosed, RelayFrameBody,
    RetireMachine, RevocationCommitted,
};
use agentdeck_protocol::relay_v2::{
    DeviceRevocation, DeviceRouteId, Ed25519Signature, GrantSerial, KeyDirectoryRevision,
    RELAY_PROTOCOL_VERSION, RelayGrant, RootKeyId, TrustEpoch, decode, encode,
};
use agentdeck_protocol::runtime::StreamCursor;
use tokio::sync::Semaphore;

use crate::remote::access::{PairResponseAccessBinding, VerifiedPairResponseReceipt};
use crate::remote::counter::{COUNTER_BLOCK_SIZE, CounterScope};
use crate::runtime::backfill::BarrierRequest;
use crate::runtime::catalog_snapshot::CatalogSnapshotProvider;
use crate::runtime::connection::PrincipalIssuer;
use crate::runtime::events::{RegisterStreamBarrier, RuntimeStreamTarget, WatchGeneration};
use crate::runtime::model::{
    ConversationDescriptor, MachineIdentityBinding, NewConversation, RuntimeStoreConfig,
    RuntimeStoreError,
};
use crate::runtime::snapshot::SNAPSHOT_BUILD_MEMORY_BYTES;
use crate::security::{MemoryKeyStore, load_or_create_storage_kek};

use super::RuntimeStoreHandle;
use super::pairing_authorization::AuthorizationLifecycle;
use super::pairing_delivery::{
    AcknowledgePairResponseReceived, AcknowledgePairResponseReceivedOutcome,
};
use super::pairing_grant::{
    ConfirmPairingGrant, ConversationKeyRotation, GlobalKeyStateV1, PairingGrantPreparation,
};
use super::pairing_grant_allocation::GrantAllocationProjection;
use super::pairing_grant_commit::{
    AcknowledgeGrantCommitted, AcknowledgeGrantCommittedOutcome, GrantCommittedRecovery,
};
use super::pairing_grant_tests::{
    awaiting_pairing, awaiting_pairing_with, grant_input_with, secret,
};
use super::pairing_grant_tx::{ConfirmPairingGrantOutcome, GrantPreparingRecovery};
use super::pairing_revocation::{BeginDeviceRevocation, BeginDeviceRevocationOutcome};
use super::pairing_revocation_ack::{
    AcknowledgeRevocationCommitted, AcknowledgeRevocationCommittedOutcome,
};
use super::pairing_terminal::{
    CommitPairTerminal, PairingTerminalAction, PairingTerminalizeOutcome,
};
use super::pairing_tests::{
    GenerousCapacity, MACHINE_ROUTE, NOW_MS, RELAY, TestClock, TestRoot, artifact_bytes,
    make_active, pending_envelope,
};
use super::publication::{
    FreezeSignedPublicationRequest, PublicationPayloadKind, PublicationScope,
};
use super::remote_counter::RemoteCounterReservation;

const ROOT_SEED: [u8; 32] = [0x41; 32];
const DEVICE_SIGN_SEED: [u8; 32] = [0xa4; 32];
const CATALOG_PUBLICATION_STREAM_ID: [u8; 16] = [0x21; 16];
const CATALOG_STREAM_ROUTE: [u8; 16] = [0x22; 16];
const CATALOG_STREAM_GENERATION: [u8; 16] = [0x23; 16];

#[test]
fn max_serial_requires_trust_reset_without_wrapping() {
    assert!(matches!(
        super::pairing_grant_allocation::checked_next_serial(GrantSerial::new(u64::MAX)),
        Err(RuntimeStoreError::GrantSerialTrustResetRequired)
    ));
}

fn config(root: &TestRoot, clock: Arc<AtomicU64>) -> RuntimeStoreConfig {
    RuntimeStoreConfig::new(root.database())
        .with_capacity_probe(GenerousCapacity)
        .with_clock(TestClock(clock))
}

fn next_time(clock: &AtomicU64) {
    let _ = clock.fetch_add(1, Ordering::SeqCst);
}

pub(crate) async fn complete_active_membership_transition(
    store: &RuntimeStoreHandle,
    clock: &AtomicU64,
) {
    let recovery = store
        .load_active_key_transition()
        .await
        .expect("load active membership transition")
        .expect("membership transition exists");
    assert!(recovery.transition.cuts.is_empty());
    assert!(recovery.updates.is_empty());
    let transition = recovery.transition;
    let operation_id = transition.operation_id;
    let global = store
        .load_global_key_state()
        .await
        .expect("load membership key state for canonical update fixture")
        .expect("membership key state exists");
    let updates = transition
        .recipients
        .iter()
        .map(|recipient| {
            let device_route = DeviceRouteId::from_bytes(recipient.device_route);
            let entries = global
                .install_directory_view(device_route)
                .expect("render exact membership key slots")
                .into_iter()
                .map(|view| KeyUpdateV1 {
                    key_directory_revision: KeyDirectoryRevision::new(transition.to_revision),
                    key_id: KeyId {
                        purpose: view.purpose,
                        epoch: view.epoch,
                    },
                    device_route,
                    stream_route: view.stream_route,
                    // 该 Store fixture 只验证 canonical shape 与稳定 slot 轴；真实
                    // HPKE/签名 authority 由 remote::transition production tests 覆盖。
                    enc: vec![0xa5; 32],
                    wrapped_key: vec![0x5a; 48],
                    signature: Ed25519Signature([0x7f; 64]),
                })
                .collect();
            let canonical_update_set = KeyUpdateSetV1 {
                key_directory_revision: KeyDirectoryRevision::new(transition.to_revision),
                device_route,
                updates: entries,
            }
            .canonical_bytes()
            .expect("encode canonical membership key update fixture");
            (
                *recipient,
                canonical_update_set.clone(),
                super::key_transition::FrozenKeyUpdate {
                    recipient: *recipient,
                    key_revision: transition.to_revision,
                    canonical_update_set,
                },
            )
        })
        .collect::<Vec<_>>();
    next_time(clock);
    store
        .finalize_key_directory_rotation(operation_id)
        .await
        .expect("finalize membership key-directory axes");
    next_time(clock);
    store
        .freeze_key_updates(
            operation_id,
            updates
                .iter()
                .map(|(_, _, update)| update.clone())
                .collect(),
        )
        .await
        .expect("freeze membership key updates");

    assert!(matches!(
        transition.operation,
        super::key_transition::KeyTransitionOperation::Add
            | super::key_transition::KeyTransitionOperation::Renew
            | super::key_transition::KeyTransitionOperation::Revoke
    ));
    let committed_cuts = store
        .load_transition_committed_cuts(operation_id)
        .await
        .expect("load exact authenticated membership cuts");
    let current_keys = store
        .load_global_key_state()
        .await
        .expect("load membership key directory")
        .expect("membership key directory exists")
        .current_shared_keys()
        .expect("authenticate current membership shared keys");
    let mut barrier_materials = Vec::with_capacity(committed_cuts.len());
    for (index, committed) in committed_cuts.into_iter().enumerate() {
        assert_eq!(
            committed.reserved_outer_cursor, committed.committed_outer_cursor,
            "membership cut must have no uncommitted reservation"
        );
        let stream = store
            .load_publication_stream_record(committed.publication_stream_id)
            .await
            .expect("authenticate membership publication stream");
        assert_eq!(stream.stream_route, committed.stream_route);
        assert_eq!(stream.generation, committed.generation);
        assert_eq!(
            stream.committed_high_water,
            committed.committed_outer_cursor
        );
        assert_eq!(
            stream.committed_inner_cursor,
            committed.committed_inner_cursor
        );
        let expected_key = current_keys
            .iter()
            .find(|view| match committed.scope {
                super::key_transition::KeyTransitionStreamScope::Catalog => {
                    view.purpose == agentdeck_protocol::e2ee::KeyPurpose::Catalog
                        && view.stream_route.is_none()
                }
                super::key_transition::KeyTransitionStreamScope::Conversation(_) => {
                    view.purpose == agentdeck_protocol::e2ee::KeyPurpose::ConversationDek
                        && view.stream_route
                            == Some(agentdeck_protocol::relay_v2::StreamRouteId::from_bytes(
                                committed.stream_route,
                            ))
                }
            })
            .expect("match membership cut to current shared key");
        let new_epoch = expected_key.epoch;
        let old_epoch = new_epoch
            .checked_sub(1)
            .expect("membership epoch is non-zero");
        let barrier_sequence = committed
            .committed_outer_cursor
            .map_or(Ok(0), |cursor| cursor.checked_add(1).ok_or(()))
            .expect("membership barrier sequence capacity");
        let blob = format!(
            "membership-barrier-{:?}-{}-{index}-{:02x}",
            transition.operation, transition.to_revision, committed.stream_route[0]
        )
        .into_bytes();
        let cut = super::key_transition::KeyTransitionStreamCut {
            scope: committed.scope,
            publication_stream_id: committed.publication_stream_id,
            stream_route: committed.stream_route,
            generation: committed.generation,
            relay_committed_outer: committed.committed_outer_cursor,
            relay_committed_inner: committed.committed_inner_cursor,
            barrier_sequence,
            old_epoch,
            new_epoch,
            epoch_barrier_sha256: sha256(&blob),
        };
        let key_id = KeyId {
            purpose: expected_key.purpose,
            epoch: new_epoch,
        };
        let mut publication_id = [0xa0; 16];
        publication_id[0] = 0xa0_u8.wrapping_add(index as u8);
        publication_id[8..].copy_from_slice(&transition.to_revision.to_be_bytes());
        barrier_materials.push((cut, blob, key_id, publication_id));
    }
    next_time(clock);
    store
        .freeze_key_barriers(
            operation_id,
            barrier_materials
                .iter()
                .map(|(cut, _, _, _)| *cut)
                .collect(),
        )
        .await
        .expect("freeze exact membership barrier set");
    for (cut, blob, key_id, publication_id) in &barrier_materials {
        let counter_scope = CounterScope::publication(
            store
                .machine_trust_domain()
                .expect("load membership counter trust domain"),
            *key_id,
            cut.publication_stream_id,
        )
        .expect("derive membership publication counter scope");
        store
            .register_remote_counter_guard_scope(counter_scope.token())
            .await
            .expect("register membership CounterGuard scope");
        store
            .mark_remote_counter_guard_scope_materialized(counter_scope.token())
            .await
            .expect("materialize membership CounterGuard scope");
        let counter = store
            .load_remote_counter_record(counter_scope.token(), *key_id)
            .await
            .expect("load membership counter genesis");
        let reserved_end = counter
            .reserved_end
            .checked_add(COUNTER_BLOCK_SIZE)
            .expect("membership counter block capacity");
        next_time(clock);
        let sealed_blob = blob.clone();
        let frozen = store
            .freeze_signed_publication(FreezeSignedPublicationRequest {
                publication_id: *publication_id,
                publication_stream_id: cut.publication_stream_id,
                generation: cut.generation,
                counter: RemoteCounterReservation {
                    scope_token: counter_scope.token(),
                    key_id: *key_id,
                    previous_reserved_end: counter.reserved_end,
                    reserved_end,
                    previous_db_anchor: counter.db_anchor,
                    reservation_id: *publication_id,
                    publication_id: *publication_id,
                },
                inner_after: None,
                inner_through: None,
                payload_kind: PublicationPayloadKind::Control,
                shared_binding: None,
                sealer_retained_bytes: sealed_blob.capacity(),
                sealer: Box::new(move |_| Ok(sealed_blob)),
            })
            .await
            .expect("freeze membership barrier publication");
        assert_eq!(frozen.stream_seq, cut.barrier_sequence);
        next_time(clock);
        store
            .acknowledge_publication_commit(
                cut.publication_stream_id,
                cut.generation,
                frozen.stream_seq,
                frozen.blob_sha256,
            )
            .await
            .expect("record membership barrier Relay COMMIT");
        next_time(clock);
        store
            .acknowledge_publication_delivery(
                cut.publication_stream_id,
                cut.generation,
                frozen.stream_seq,
                frozen.blob_sha256,
            )
            .await
            .expect("locally acknowledge membership barrier");
    }
    next_time(clock);
    store
        .mark_key_barriers_committed(operation_id)
        .await
        .expect("commit exact membership barrier set");
    for (recipient, canonical_update_set, _) in &updates {
        let persisted = store
            .load_active_key_transition()
            .await
            .expect("load membership update before ACK")
            .expect("membership transition remains active")
            .updates
            .into_iter()
            .find(|update| update.recipient == *recipient)
            .expect("membership recipient update exists");
        if persisted.lifecycle == super::key_transition::KeyUpdateLifecycle::Frozen {
            next_time(clock);
            store
                .acknowledge_key_update(super::key_transition::AcknowledgeKeyUpdate {
                    operation_id,
                    recipient: *recipient,
                    key_revision: transition.to_revision,
                    update_hash: super::key_transition::canonical_update_hash(canonical_update_set)
                        .expect("hash membership key update"),
                    canonical_ack: format!(
                        "renewal-fixture-update-ack-{:02x}-{}",
                        recipient.device_route[0], transition.to_revision
                    )
                    .into_bytes(),
                    acknowledged_at_ms: 0,
                })
                .await
                .expect("ack membership key update");
        } else {
            assert_eq!(
                persisted.lifecycle,
                super::key_transition::KeyUpdateLifecycle::Acked,
                "PairResponseReceived 只可预先 Ack bootstrap target"
            );
            assert_eq!(
                transition.target,
                super::key_transition::KeyTransitionTarget::Device(*recipient)
            );
        }
        for (cut_index, (cut, _, _, _)) in barrier_materials.iter().enumerate() {
            let authorization_hash = if transition.operation
                == super::key_transition::KeyTransitionOperation::Add
                && transition.target
                    == super::key_transition::KeyTransitionTarget::Device(*recipient)
            {
                let ingress = store
                    .load_active_remote_ingress(
                        MACHINE_ROUTE,
                        DeviceRouteId::from_bytes(recipient.device_route),
                    )
                    .await
                    .expect("load new-device transition authorization");
                let current = store
                    .recheck_active_remote_ingress(&ingress)
                    .await
                    .expect("recheck new-device transition authorization");
                let permit = store
                    .resolve_transition_snapshot_permit(
                        super::key_transition::TransitionSnapshotRequest::new(
                            current,
                            cut.scope,
                            StreamCursor::BeforeFirst,
                        ),
                    )
                    .await
                    .expect("resolve required new-device snapshot permit");
                let authorization_hash = permit.authorization_hash();
                next_time(clock);
                store
                    .mark_transition_snapshot_flushed(
                        permit
                            .into_flush(sha256(
                                format!(
                                    "membership-fixture-sync-complete-{:02x}-{}-{cut_index}",
                                    recipient.device_route[0], transition.to_revision,
                                )
                                .as_bytes(),
                            ))
                            .expect("bind required snapshot SyncComplete hash"),
                    )
                    .await
                    .expect("record required new-device snapshot flush");
                authorization_hash
            } else {
                [0xa1; 32]
            };
            next_time(clock);
            store
                .acknowledge_stream_applied(super::key_transition::AcknowledgeStreamApplied {
                    operation_id,
                    recipient: *recipient,
                    key_revision: transition.to_revision,
                    scope: cut.scope,
                    stream_route: cut.stream_route,
                    stream_generation: cut.generation,
                    applied_stream_seq: cut.barrier_sequence,
                    inner_cursor: cut.relay_committed_inner,
                    key_epoch: cut.new_epoch,
                    epoch_barrier_sha256: cut.epoch_barrier_sha256,
                    authorization_hash,
                    canonical_ack: format!(
                        "membership-fixture-stream-ack-{:02x}-{}-{cut_index}",
                        recipient.device_route[0], transition.to_revision,
                    )
                    .into_bytes(),
                    acknowledged_at_ms: 0,
                })
                .await
                .expect("ack applied membership barrier");
        }
    }
    next_time(clock);
    store
        .complete_key_transition(operation_id)
        .await
        .expect("complete membership transition");
    store
        .apply_pending_replay_retirement()
        .await
        .expect("apply membership replay retirement before the next mutation");
}

fn grant_from_install(recovery: &GrantPreparingRecovery) -> RelayGrant {
    let frame: OpaqueRouteFrame =
        decode(recovery.canonical_install_frame()).expect("decode InstallGrant");
    match frame.body {
        RelayFrameBody::InstallGrant(install) => install.grant,
        other => panic!("expected InstallGrant, got {other:?}"),
    }
}

fn grant_committed_frame(grant: &RelayGrant) -> Vec<u8> {
    encode(&OpaqueRouteFrame {
        version: RELAY_PROTOCOL_VERSION,
        body: RelayFrameBody::GrantCommitted(GrantCommitted {
            device_route: grant.device_route,
            grant_serial: grant.grant_serial,
            grant_hash: grant.canonical_sha256(),
        }),
    })
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

fn verified_receipt(recovery: &GrantCommittedRecovery) -> VerifiedPairResponseReceipt {
    let binding = PairResponseAccessBinding::from_frozen(
        recovery.invite(),
        recovery.request_hash(),
        recovery.relay_grant(),
        recovery.pair_response(),
    )
    .expect("rebuild response binding");
    let receipt = sign_pair_response_received(
        &SigningKey::from_seed(&DEVICE_SIGN_SEED),
        binding.info(),
        binding.receipt_context(),
        PairResponseReceivedV1 {
            request_hash: recovery.request_hash(),
            grant_hash: recovery.grant_hash(),
            response_hash: recovery.response_hash(),
            signature: Ed25519Signature([0; 64]),
        },
    )
    .expect("sign PairResponseReceived");
    binding
        .verify_signed_receipt(
            &receipt
                .canonical_bytes()
                .expect("canonical PairResponseReceived"),
        )
        .expect("verify PairResponseReceived")
}

async fn confirm_and_commit(
    store: &RuntimeStoreHandle,
    clock: &AtomicU64,
    preparation: &PairingGrantPreparation,
    input: ConfirmPairingGrant,
) -> (RelayGrant, GrantCommittedRecovery) {
    let confirmed = store
        .confirm_pairing_grant(input)
        .await
        .expect("confirm grant");
    let installing = match confirmed {
        ConfirmPairingGrantOutcome::Confirmed { recovery, .. } => recovery,
        other => panic!("fresh grant must confirm: {other:?}"),
    };
    let grant = grant_from_install(&installing);
    next_time(clock);
    let committed = store
        .acknowledge_grant_committed(AcknowledgeGrantCommitted::new(
            preparation.pairing_id(),
            grant_committed_frame(&grant),
        ))
        .await
        .expect("acknowledge GrantCommitted");
    let recovery = match committed {
        AcknowledgeGrantCommittedOutcome::Committed { recovery } => recovery,
        other => panic!("fresh GrantCommitted must transition: {other:?}"),
    };
    (grant, recovery)
}

async fn confirm_commit_and_deliver(
    store: &RuntimeStoreHandle,
    clock: &AtomicU64,
    preparation: &PairingGrantPreparation,
    input: ConfirmPairingGrant,
) -> RelayGrant {
    let (grant, committed) = confirm_and_commit(store, clock, preparation, input).await;
    let proof = verified_receipt(&committed);
    next_time(clock);
    let close = match store
        .acknowledge_pair_response_received(AcknowledgePairResponseReceived::new(
            preparation.pairing_id(),
            &proof,
        ))
        .await
        .expect("acknowledge PairResponseReceived")
    {
        AcknowledgePairResponseReceivedOutcome::Delivered { close } => close,
        other => panic!("fresh PairResponseReceived must deliver: {other:?}"),
    };
    store
        .acknowledge_pair_route_close(
            preparation.pairing_id(),
            pair_route_closed_frame(close.pair_route()),
        )
        .await
        .expect("acknowledge PairRouteClosed");
    complete_active_membership_transition(store, clock).await;
    grant
}

async fn cancel_and_close(
    store: &RuntimeStoreHandle,
    clock: &AtomicU64,
    pairing_id: super::RuntimeId,
) {
    next_time(clock);
    let close = match store
        .terminalize_pairing(pairing_id, PairingTerminalAction::Cancel)
        .await
        .expect("cancel pairing")
    {
        PairingTerminalizeOutcome::Transitioned { close, .. } => close,
        other => panic!("fresh cancel must transition: {other:?}"),
    };
    let mut recovery = store
        .list_pairing_terminal_recovery()
        .await
        .expect("load canceled terminal recovery");
    if let Some(mut preparation) = recovery
        .iter_mut()
        .find(|recovery| recovery.close().pairing_id() == pairing_id)
        .and_then(|recovery| recovery.take_preparation())
    {
        drop(
            preparation
                .take_hpke_seed()
                .expect("sealing consumes the unique terminal seed owner"),
        );
        store
            .commit_pair_terminal(
                CommitPairTerminal::new(preparation, pending_envelope(0xe7))
                    .expect("freeze canceled PairTerminal carrier"),
            )
            .await
            .expect("commit canceled PairTerminal carrier");
    }
    store
        .acknowledge_pair_route_close(pairing_id, pair_route_closed_frame(close.pair_route()))
        .await
        .expect("acknowledge canceled PairRouteClosed");
}

fn renewal_projection(
    projection: GrantAllocationProjection,
) -> (
    [u8; 32],
    DeviceRouteId,
    GrantSerial,
    GrantSerial,
    super::pairing_grant::GlobalKeyStateV1,
) {
    match projection {
        GrantAllocationProjection::Renew {
            device_sign_fingerprint,
            device_route,
            current_serial,
            next_serial,
            current_global_keys,
        } => (
            device_sign_fingerprint,
            device_route,
            current_serial,
            next_serial,
            current_global_keys,
        ),
        GrantAllocationProjection::New { .. } => panic!("expected renewal allocation"),
    }
}

async fn first_delivered(
    store: &RuntimeStoreHandle,
    clock: &AtomicU64,
    binding: &MachineIdentityBinding,
    data_cert: &agentdeck_protocol::relay_v2::SignedCertificate,
) -> RelayGrant {
    store
        .create_publication_stream(
            CATALOG_PUBLICATION_STREAM_ID,
            PublicationScope::Catalog,
            CATALOG_STREAM_ROUTE,
            CATALOG_STREAM_GENERATION,
        )
        .await
        .expect("create renewal catalog publication stream");
    let conversation_id =
        super::RuntimeId::from_bytes(super::RuntimeIdKind::Conversation, [0x31; 16])
            .expect("renewal conversation id");
    store
        .create_conversation(NewConversation {
            conversation_id,
            adapter_state_key: super::RuntimeId::from_bytes(
                super::RuntimeIdKind::AdapterState,
                [0x32; 16],
            )
            .expect("renewal adapter state key"),
            descriptor: ConversationDescriptor {
                agent_kind: agentdeck_protocol::AgentKind::Codex,
                title: Some("grant renewal production stream".to_owned()),
                cwd: std::path::PathBuf::from("/tmp/grant-renewal-production-stream"),
            },
        })
        .await
        .expect("create renewal production conversation");
    let principal = PrincipalIssuer::local_only(
        store
            .machine_trust_domain()
            .expect("load renewal catalog snapshot trust domain"),
    )
    .issue_verified_local(502, [0x24; 16])
    .expect("issue renewal catalog snapshot principal");
    let catalog_provider = CatalogSnapshotProvider::with_clock(
        store.clone(),
        Arc::new(TestClock(Arc::new(AtomicU64::new(
            clock.load(Ordering::SeqCst),
        )))),
        Arc::new(Semaphore::new(SNAPSHOT_BUILD_MEMORY_BYTES)),
    )
    .expect("create renewal catalog snapshot provider");
    let mut catalog_registration = store
        .register_stream_barrier(RegisterStreamBarrier {
            target: RuntimeStreamTarget::Catalog,
            generation: WatchGeneration::new(1).expect("renewal catalog snapshot generation"),
            request: BarrierRequest::Subscribe {
                cursor: StreamCursor::BeforeFirst,
            },
        })
        .await
        .expect("capture renewal catalog snapshot barrier");
    let catalog_page = catalog_provider
        .first_page(&mut catalog_registration, &principal)
        .await
        .expect("materialize renewal catalog snapshot");
    drop(catalog_page);
    drop(catalog_registration);
    drop(catalog_provider);
    let preparation = awaiting_pairing(store, binding, data_cert).await;
    let fingerprint = sha256(&preparation.request().device_sign_pubkey.0);
    let active_conversation_routes = match store
        .load_grant_allocation(preparation.pairing_id(), fingerprint)
        .await
        .expect("load renewal bootstrap allocation")
    {
        GrantAllocationProjection::New {
            current_global_keys: None,
            active_conversation_routes,
            ..
        } => active_conversation_routes,
        _ => panic!("first renewal fixture grant must use a fresh allocation"),
    };
    assert_eq!(active_conversation_routes.len(), 1);
    let device_route = DeviceRouteId::from_bytes([0xd1; 16]);
    let global = GlobalKeyStateV1::bootstrap_with_conversations(
        1,
        1,
        secret(0xc1),
        device_route,
        1,
        secret(0xc2),
        1,
        secret(0xc3),
        vec![ConversationKeyRotation::new(
            active_conversation_routes[0],
            secret(0xc4),
        )],
    )
    .expect("bootstrap renewal global state with production conversation");
    confirm_commit_and_deliver(
        store,
        clock,
        &preparation,
        grant_input_with(
            &preparation,
            binding,
            data_cert,
            device_route,
            GrantSerial::new(1),
            global,
            None,
            0xd2,
        ),
    )
    .await
}

async fn renewal_preparation(
    store: &RuntimeStoreHandle,
    binding: &MachineIdentityBinding,
    data_cert: &agentdeck_protocol::relay_v2::SignedCertificate,
    seed: u8,
    key: &str,
) -> PairingGrantPreparation {
    awaiting_pairing_with(
        store,
        binding,
        data_cert,
        agentdeck_protocol::relay_v2::PairRouteId::from_bytes([seed; 16]),
        seed.wrapping_add(1),
        seed.wrapping_add(2),
        0xa4,
        seed.wrapping_add(3),
        seed.wrapping_add(4),
        seed.wrapping_add(5),
        key,
    )
    .await
}

fn renewal_input(
    preparation: &PairingGrantPreparation,
    binding: &MachineIdentityBinding,
    data_cert: &agentdeck_protocol::relay_v2::SignedCertificate,
    projection: GrantAllocationProjection,
    entropy_seed: u8,
) -> (DeviceRouteId, GrantSerial, ConfirmPairingGrant) {
    let (_, route, _, next_serial, current_global) = renewal_projection(projection);
    let next_global = current_global
        .renew_for_device(
            route,
            secret(entropy_seed),
            secret(entropy_seed.wrapping_add(1)),
            secret(entropy_seed.wrapping_add(2)),
        )
        .expect("renew global keys");
    let input = grant_input_with(
        preparation,
        binding,
        data_cert,
        route,
        next_serial,
        next_global,
        None,
        entropy_seed.wrapping_add(3),
    );
    (route, next_serial, input)
}

#[tokio::test]
async fn new_allocation_authenticates_fingerprint_and_wrong_fingerprint_is_zero_write() {
    let root = TestRoot::new("grant-allocation-new");
    let keys = MemoryKeyStore::new();
    let clock = Arc::new(AtomicU64::new(NOW_MS));
    let store = RuntimeStoreHandle::open(
        config(&root, clock),
        load_or_create_storage_kek(&keys, &root.database()).expect("load StorageKEK"),
    )
    .await
    .expect("open allocation store");
    let (binding, data_cert) = make_active(&store).await;
    store
        .create_conversation(crate::runtime::model::NewConversation {
            conversation_id: super::RuntimeId::from_bytes(
                super::RuntimeIdKind::Conversation,
                [0x51; 16],
            )
            .expect("conversation id"),
            adapter_state_key: super::RuntimeId::from_bytes(
                super::RuntimeIdKind::AdapterState,
                [0x52; 16],
            )
            .expect("adapter state key"),
            descriptor: crate::runtime::model::ConversationDescriptor {
                agent_kind: agentdeck_protocol::AgentKind::Codex,
                title: Some("grant allocation mapping".to_owned()),
                cwd: std::path::PathBuf::from("/tmp/grant-allocation-mapping"),
            },
        })
        .await
        .expect("create authenticated conversation mapping");
    let preparation = awaiting_pairing(&store, &binding, &data_cert).await;
    let fingerprint = sha256(&preparation.request().device_sign_pubkey.0);

    match store
        .load_grant_allocation(preparation.pairing_id(), fingerprint)
        .await
        .expect("load new allocation")
    {
        GrantAllocationProjection::New {
            device_sign_fingerprint,
            current_global_keys,
            active_conversation_routes,
        } => {
            assert_eq!(device_sign_fingerprint, fingerprint);
            assert!(current_global_keys.is_none());
            assert_eq!(active_conversation_routes.len(), 1);
            assert_ne!(active_conversation_routes[0].as_bytes(), &[0; 16]);
        }
        GrantAllocationProjection::Renew { .. } => panic!("new fingerprint must not renew"),
    }

    let mut wrong = fingerprint;
    wrong[31] ^= 1;
    let before = artifact_bytes(&root.database());
    assert!(matches!(
        store
            .load_grant_allocation(preparation.pairing_id(), wrong)
            .await,
        Err(RuntimeStoreError::PairingConflict)
    ));
    assert_eq!(artifact_bytes(&root.database()), before);
    store.shutdown().await.expect("shutdown allocation store");
}

#[tokio::test]
async fn renewal_reuses_route_increments_serial_and_atomically_supersedes_previous() {
    let root = TestRoot::new("grant-allocation-renew");
    let keys = MemoryKeyStore::new();
    let clock = Arc::new(AtomicU64::new(NOW_MS));
    let store = RuntimeStoreHandle::open(
        config(&root, clock.clone()),
        load_or_create_storage_kek(&keys, &root.database()).expect("load StorageKEK"),
    )
    .await
    .expect("open renewal store");
    let (binding, data_cert) = make_active(&store).await;
    let first = first_delivered(&store, &clock, &binding, &data_cert).await;
    let preparation =
        renewal_preparation(&store, &binding, &data_cert, 0xb1, "grant-renew-second").await;
    let fingerprint = sha256(&preparation.request().device_sign_pubkey.0);
    let projection = store
        .load_grant_allocation(preparation.pairing_id(), fingerprint)
        .await
        .expect("load renewal allocation");
    let (_, route, current_serial, next_serial, _) = renewal_projection(match projection {
        GrantAllocationProjection::Renew {
            device_sign_fingerprint,
            device_route,
            current_serial,
            next_serial,
            current_global_keys,
        } => GrantAllocationProjection::Renew {
            device_sign_fingerprint,
            device_route,
            current_serial,
            next_serial,
            current_global_keys,
        },
        GrantAllocationProjection::New { .. } => panic!("expected renewal allocation"),
    });
    assert_eq!(route, first.device_route);
    assert_eq!(current_serial, GrantSerial::new(1));
    assert_eq!(next_serial, GrantSerial::new(2));

    let projection = store
        .load_grant_allocation(preparation.pairing_id(), fingerprint)
        .await
        .expect("reload renewal allocation for consumption");
    let (route, serial, input) =
        renewal_input(&preparation, &binding, &data_cert, projection, 0x11);
    let outcome = store
        .confirm_pairing_grant(input)
        .await
        .expect("confirm renewal");
    let installing = match outcome {
        ConfirmPairingGrantOutcome::Confirmed { recovery, .. } => recovery,
        other => panic!("renewal must confirm: {other:?}"),
    };
    assert_eq!(route, first.device_route);
    assert_eq!(serial, GrantSerial::new(2));
    let transition = store
        .load_active_key_transition()
        .await
        .expect("load renewal transition")
        .expect("renewal transition is durable in the membership transaction");
    let retirement = transition
        .transition
        .replay_retirement
        .expect("renewal freezes the superseded DeviceCommandTx replay scope");
    assert_eq!(
        retirement.scope,
        super::remote_replay::canonical_device_command_scope(
            *first.machine_route.as_bytes(),
            first.trust_epoch.value(),
            *route.as_bytes(),
            1,
            1,
        )
        .expect("canonical old renewal replay scope"),
    );
    assert_eq!(retirement.old_reply_key_epoch, 1);
    assert_eq!(
        retirement.lifecycle,
        super::key_transition::ReplayRetirementLifecycle::Pending,
    );

    let rows = rusqlite::Connection::open(root.database())
        .expect("open renewal evidence DB")
        .prepare(
            "SELECT grant_serial, lifecycle FROM remote_authorization_ledger \
             ORDER BY device_route, grant_serial",
        )
        .expect("prepare renewal evidence")
        .query_map([], |row| {
            Ok((row.get::<_, String>(0)?, row.get::<_, String>(1)?))
        })
        .expect("query renewal evidence")
        .collect::<Result<Vec<_>, _>>()
        .expect("collect renewal evidence");
    assert_eq!(
        rows,
        [
            ("00000000000000000001".to_owned(), "superseded".to_owned()),
            (
                "00000000000000000002".to_owned(),
                "grantPreparing".to_owned()
            ),
        ]
    );
    let renewal_grant = grant_from_install(&installing);
    next_time(&clock);
    assert!(matches!(
        store
            .acknowledge_grant_committed(AcknowledgeGrantCommitted::new(
                preparation.pairing_id(),
                grant_committed_frame(&renewal_grant),
            ))
            .await
            .expect("acknowledge renewal GrantCommitted"),
        AcknowledgeGrantCommittedOutcome::Committed { .. }
    ));
    complete_active_membership_transition(&store, &clock).await;
    let global = store
        .load_global_key_state()
        .await
        .expect("load renewed global keys")
        .expect("global keys exist");
    assert_eq!(global.device_count(), 1);
    assert_eq!(global.revision().value(), 2);
    store.shutdown().await.expect("shutdown renewal store");
}

#[tokio::test]
async fn two_stale_allocations_allow_only_first_confirm_to_commit() {
    let root = TestRoot::new("grant-allocation-stale");
    let keys = MemoryKeyStore::new();
    let clock = Arc::new(AtomicU64::new(NOW_MS));
    let store = RuntimeStoreHandle::open(
        config(&root, clock.clone()),
        load_or_create_storage_kek(&keys, &root.database()).expect("load StorageKEK"),
    )
    .await
    .expect("open stale allocation store");
    let (binding, data_cert) = make_active(&store).await;
    let first = first_delivered(&store, &clock, &binding, &data_cert).await;
    let left = renewal_preparation(&store, &binding, &data_cert, 0xb1, "stale-left").await;
    let right = renewal_preparation(&store, &binding, &data_cert, 0xc1, "stale-right").await;
    let fingerprint = sha256(&left.request().device_sign_pubkey.0);
    assert_eq!(fingerprint, sha256(&right.request().device_sign_pubkey.0));
    let left_projection = store
        .load_grant_allocation(left.pairing_id(), fingerprint)
        .await
        .expect("load left allocation");
    let right_projection = store
        .load_grant_allocation(right.pairing_id(), fingerprint)
        .await
        .expect("load right stale allocation");
    let (left_route, left_serial, left_input) =
        renewal_input(&left, &binding, &data_cert, left_projection, 0xd1);
    let (right_route, right_serial, right_input) =
        renewal_input(&right, &binding, &data_cert, right_projection, 0xe1);
    assert_eq!(left_route, first.device_route);
    assert_eq!(right_route, first.device_route);
    assert_eq!(left_serial, GrantSerial::new(2));
    assert_eq!(right_serial, GrantSerial::new(2));
    let winner = match store
        .confirm_pairing_grant(left_input)
        .await
        .expect("first stale allocation wins")
    {
        ConfirmPairingGrantOutcome::Confirmed { recovery, .. } => recovery,
        other => panic!("first stale allocation must confirm: {other:?}"),
    };

    let before_loser = artifact_bytes(&root.database());
    assert!(matches!(
        store.confirm_pairing_grant(right_input).await,
        Err(RuntimeStoreError::PairingConflict)
    ));
    assert_eq!(artifact_bytes(&root.database()), before_loser);
    let winner_grant = grant_from_install(&winner);
    next_time(&clock);
    assert!(matches!(
        store
            .acknowledge_grant_committed(AcknowledgeGrantCommitted::new(
                left.pairing_id(),
                grant_committed_frame(&winner_grant),
            ))
            .await
            .expect("acknowledge winning stale renewal"),
        AcknowledgeGrantCommittedOutcome::Committed { .. }
    ));
    complete_active_membership_transition(&store, &clock).await;
    store
        .shutdown()
        .await
        .expect("shutdown stale allocation store");
}

#[tokio::test]
async fn restart_allocates_from_highest_serial_without_adding_a_device() {
    let root = TestRoot::new("grant-allocation-restart");
    let keys = MemoryKeyStore::new();
    let clock = Arc::new(AtomicU64::new(NOW_MS));
    let make_config = || config(&root, clock.clone());
    let store = RuntimeStoreHandle::open(
        make_config(),
        load_or_create_storage_kek(&keys, &root.database()).expect("load StorageKEK"),
    )
    .await
    .expect("open restart allocation store");
    let (binding, data_cert) = make_active(&store).await;
    let first = first_delivered(&store, &clock, &binding, &data_cert).await;
    let second = renewal_preparation(&store, &binding, &data_cert, 0xb1, "restart-second").await;
    let fingerprint = sha256(&second.request().device_sign_pubkey.0);
    let projection = store
        .load_grant_allocation(second.pairing_id(), fingerprint)
        .await
        .expect("load second allocation");
    let (_, _, second_input) = renewal_input(&second, &binding, &data_cert, projection, 0x11);
    let second_grant = confirm_commit_and_deliver(&store, &clock, &second, second_input).await;
    assert_eq!(second_grant.device_route, first.device_route);
    assert_eq!(second_grant.grant_serial, GrantSerial::new(2));
    assert_eq!(
        store
            .load_global_key_state()
            .await
            .expect("load global state")
            .expect("global state exists")
            .device_count(),
        1
    );
    store.shutdown().await.expect("shutdown before restart");

    let reopened = RuntimeStoreHandle::open(
        make_config(),
        load_or_create_storage_kek(&keys, &root.database()).expect("reload StorageKEK"),
    )
    .await
    .expect("reopen renewal store");
    let third = renewal_preparation(&reopened, &binding, &data_cert, 0xd1, "restart-third").await;
    let (_, route, current, next, global) = renewal_projection(
        reopened
            .load_grant_allocation(third.pairing_id(), fingerprint)
            .await
            .expect("load third allocation after restart"),
    );
    assert_eq!(route, first.device_route);
    assert_eq!(current, GrantSerial::new(2));
    assert_eq!(next, GrantSerial::new(3));
    assert_eq!(global.device_count(), 1);
    reopened.shutdown().await.expect("shutdown reopened store");
}

fn signed_revocation(grant: &RelayGrant, binding: &MachineIdentityBinding) -> DeviceRevocation {
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

fn revocation_committed_frame(revocation: &DeviceRevocation) -> Vec<u8> {
    encode(&OpaqueRouteFrame {
        version: RELAY_PROTOCOL_VERSION,
        body: RelayFrameBody::RevocationCommitted(RevocationCommitted {
            device_route: revocation.device_route,
            grant_serial: revocation.grant_serial,
            signed_revocation: revocation.clone(),
        }),
    })
}

fn retirement(binding: &MachineIdentityBinding) -> RetireMachine {
    let mut retirement = RetireMachine {
        machine_route: MACHINE_ROUTE,
        root_key_id: RootKeyId::from_bytes(binding.root_key_id),
        trust_epoch: TrustEpoch::new(binding.trust_epoch),
        signature: Ed25519Signature([0; 64]),
    };
    retirement.signature = sign_tbs(
        &SigningKey::from_seed(&ROOT_SEED),
        &retirement.to_be_signed_v1(RELAY, binding.root_fingerprint),
    )
    .into();
    retirement
}

#[tokio::test]
async fn revoking_and_revoked_history_refuse_renewal_and_revoked_route_reuse() {
    let root = TestRoot::new("grant-allocation-revoked");
    let keys = MemoryKeyStore::new();
    let clock = Arc::new(AtomicU64::new(NOW_MS));
    let store = RuntimeStoreHandle::open(
        config(&root, clock.clone()),
        load_or_create_storage_kek(&keys, &root.database()).expect("load StorageKEK"),
    )
    .await
    .expect("open revoked allocation store");
    let (binding, data_cert) = make_active(&store).await;
    let first = first_delivered(&store, &clock, &binding, &data_cert).await;
    let second = renewal_preparation(&store, &binding, &data_cert, 0xb1, "revoked-second").await;
    let fingerprint = sha256(&second.request().device_sign_pubkey.0);
    let projection = store
        .load_grant_allocation(second.pairing_id(), fingerprint)
        .await
        .expect("load second serial before revoke");
    let (_, _, second_input) = renewal_input(&second, &binding, &data_cert, projection, 0x11);
    let grant = confirm_commit_and_deliver(&store, &clock, &second, second_input).await;
    assert_eq!(grant.device_route, first.device_route);
    assert_eq!(grant.grant_serial, GrantSerial::new(2));
    let renewal = renewal_preparation(&store, &binding, &data_cert, 0xd1, "revoked-renewal").await;
    let fingerprint = sha256(&renewal.request().device_sign_pubkey.0);
    let drain = store
        .list_revocation_drain_targets()
        .await
        .expect("load pre-revoke drain target");
    assert_eq!(
        drain.len(),
        1,
        "Superseded history must not become a target"
    );
    assert_eq!(drain[0].grant().grant_serial, GrantSerial::new(2));
    let revocation = signed_revocation(&grant, &binding);
    next_time(&clock);
    assert!(matches!(
        store
            .begin_device_revocation(BeginDeviceRevocation::local(revocation.clone()))
            .await
            .expect("begin revocation"),
        BeginDeviceRevocationOutcome::Prepared { .. }
    ));
    assert!(
        store
            .list_revocation_drain_targets()
            .await
            .expect("load revoking drain targets")
            .is_empty(),
        "Superseded and Revoking rows are not new drain work"
    );
    assert!(matches!(
        store
            .load_grant_allocation(renewal.pairing_id(), fingerprint)
            .await,
        Err(RuntimeStoreError::GrantRouteRevoked)
    ));

    next_time(&clock);
    assert!(matches!(
        store
            .acknowledge_revocation_committed(AcknowledgeRevocationCommitted::new(
                revocation_committed_frame(&revocation),
            ))
            .await
            .expect("acknowledge revocation"),
        AcknowledgeRevocationCommittedOutcome::Committed { .. }
    ));
    complete_active_membership_transition(&store, &clock).await;
    assert!(
        store
            .list_revocation_drain_targets()
            .await
            .expect("load revoked drain targets")
            .is_empty(),
        "Superseded and Revoked rows are terminal for drain"
    );
    assert!(matches!(
        store
            .load_grant_allocation(renewal.pairing_id(), fingerprint)
            .await,
        Err(RuntimeStoreError::GrantRouteRevoked)
    ));

    let other = awaiting_pairing_with(
        &store,
        &binding,
        &data_cert,
        agentdeck_protocol::relay_v2::PairRouteId::from_bytes([0xc1; 16]),
        0xc2,
        0xc3,
        0xc4,
        0xc5,
        0xc6,
        0xc7,
        "revoked-route-reuse",
    )
    .await;
    let other_fingerprint = sha256(&other.request().device_sign_pubkey.0);
    let current_global = match store
        .load_grant_allocation(other.pairing_id(), other_fingerprint)
        .await
        .expect("new fingerprint allocation")
    {
        GrantAllocationProjection::New {
            device_sign_fingerprint,
            current_global_keys,
            active_conversation_routes,
        } => {
            assert_eq!(device_sign_fingerprint, other_fingerprint);
            let current_global = current_global_keys.expect("revoked device keeps global history");
            assert_eq!(
                active_conversation_routes,
                current_global.active_conversation_routes(),
                "device revocation does not delete the canonical conversation"
            );
            current_global
        }
        GrantAllocationProjection::Renew { .. } => panic!("different fingerprint must be new"),
    };
    assert!(current_global.contains_device_route(grant.device_route));
    assert!(
        current_global
            .device_revoked_at_for_test(grant.device_route)
            .is_some(),
        "durable global projection must retain the revoked route tombstone in DeviceKeys"
    );
    let before_reuse = artifact_bytes(&root.database());
    assert!(matches!(
        current_global.plan_add_device(
            grant.device_route,
            secret(0xd1),
            secret(0xd2),
            secret(0xd3),
            Vec::new(),
            clock.load(Ordering::SeqCst),
        ),
        Err(RuntimeStoreError::PairingConflict)
    ));
    assert_eq!(artifact_bytes(&root.database()), before_reuse);

    cancel_and_close(&store, &clock, renewal.pairing_id()).await;
    cancel_and_close(&store, &clock, other.pairing_id()).await;

    let cleanup_precondition = rusqlite::Connection::open(root.database())
        .expect("open cleanup precondition DB")
        .query_row(
            "SELECT (SELECT COUNT(*) FROM remote_pairings),
                    (SELECT COUNT(*) FROM remote_control_outbox),
                    (SELECT COUNT(*) FROM remote_authorization_ledger
                        WHERE lifecycle = 'superseded'),
                    (SELECT COUNT(*) FROM remote_authorization_ledger
                        WHERE lifecycle = 'revoked')",
            [],
            |row| {
                Ok((
                    row.get::<_, i64>(0)?,
                    row.get::<_, i64>(1)?,
                    row.get::<_, i64>(2)?,
                    row.get::<_, i64>(3)?,
                ))
            },
        )
        .expect("read cleanup precondition");
    assert_eq!(cleanup_precondition, (0, 0, 1, 1));
    store
        .prepare_machine_retirement(retirement(&binding))
        .await
        .expect("Superseded plus Revoked history permits root-present cleanup");
    let remaining = rusqlite::Connection::open(root.database())
        .expect("open post-cleanup evidence DB")
        .query_row(
            "SELECT (SELECT COUNT(*) FROM remote_pairings),
                    (SELECT COUNT(*) FROM remote_control_outbox),
                    (SELECT COUNT(*) FROM remote_authorization_ledger),
                    (SELECT COUNT(*) FROM remote_key_directory)",
            [],
            |row| {
                Ok((
                    row.get::<_, i64>(0)?,
                    row.get::<_, i64>(1)?,
                    row.get::<_, i64>(2)?,
                    row.get::<_, i64>(3)?,
                ))
            },
        )
        .expect("read post-cleanup evidence");
    assert_eq!(
        remaining,
        (0, 0, 2, 1),
        "RetirePending preserves authorization and key-directory owners until Relay terminal plus manager quiescence"
    );
    store
        .shutdown()
        .await
        .expect("shutdown revoked allocation store");
    let reopened = RuntimeStoreHandle::open(
        config(&root, clock),
        load_or_create_storage_kek(&keys, &root.database())
            .expect("reload revoked allocation StorageKEK"),
    )
    .await
    .expect("reopen and audit control-only transition cuts");
    reopened
        .shutdown()
        .await
        .expect("shutdown reopened revoked allocation store");
}

async fn prepare_two_serial_history(root: &TestRoot, keys: &MemoryKeyStore, clock: Arc<AtomicU64>) {
    let store = RuntimeStoreHandle::open(
        config(root, clock.clone()),
        load_or_create_storage_kek(keys, &root.database()).expect("load StorageKEK"),
    )
    .await
    .expect("open tamper setup");
    let (binding, data_cert) = make_active(&store).await;
    let _ = first_delivered(&store, &clock, &binding, &data_cert).await;
    let second = renewal_preparation(&store, &binding, &data_cert, 0xb1, "tamper-second").await;
    let fingerprint = sha256(&second.request().device_sign_pubkey.0);
    let projection = store
        .load_grant_allocation(second.pairing_id(), fingerprint)
        .await
        .expect("load tamper renewal allocation");
    let (_, _, input) = renewal_input(&second, &binding, &data_cert, projection, 0x11);
    let _ = confirm_commit_and_deliver(&store, &clock, &second, input).await;
    store.shutdown().await.expect("shutdown tamper setup");
}

#[tokio::test]
async fn authenticated_history_audit_rejects_route_fingerprint_serial_and_lifecycle_drift() {
    let root = TestRoot::new("grant-history-invariants");
    let keys = MemoryKeyStore::new();
    let clock = Arc::new(AtomicU64::new(NOW_MS));
    prepare_two_serial_history(&root, &keys, clock.clone()).await;
    let state = super::sqlite::open(
        &config(&root, clock),
        load_or_create_storage_kek(&keys, &root.database()).expect("reload StorageKEK"),
    )
    .expect("open authenticated history state");
    let mut directory =
        super::pairing::load_directory(&state.connection, &state.key_bundle, state.database_id)
            .expect("load authenticated history");
    let history = &mut directory.grants.authorizations;
    assert_eq!(history.len(), 2);
    super::pairing_grant::validate_authorization_histories(history)
        .expect("baseline history is valid");

    let first_fingerprint = history[0].device_sign_fingerprint;
    history[0].device_sign_fingerprint[0] ^= 1;
    assert!(matches!(
        super::pairing_grant::validate_authorization_histories(history),
        Err(RuntimeStoreError::UnknownOrCorruptSchema)
    ));
    history[0].device_sign_fingerprint = first_fingerprint;

    let second_route = history[1].device_route;
    history[1].device_route = DeviceRouteId::from_bytes([0x01; 16]);
    assert!(matches!(
        super::pairing_grant::validate_authorization_histories(history),
        Err(RuntimeStoreError::UnknownOrCorruptSchema)
    ));
    history[1].device_route = second_route;

    let first_serial = history[0].grant_serial;
    history[0].grant_serial = history[1].grant_serial;
    assert!(matches!(
        super::pairing_grant::validate_authorization_histories(history),
        Err(RuntimeStoreError::UnknownOrCorruptSchema)
    ));
    history[0].grant_serial = first_serial;

    history[0].lifecycle = AuthorizationLifecycle::Active;
    assert!(matches!(
        super::pairing_grant::validate_authorization_histories(history),
        Err(RuntimeStoreError::UnknownOrCorruptSchema)
    ));
    history[0].lifecycle = AuthorizationLifecycle::Superseded;

    history[1].lifecycle = AuthorizationLifecycle::Superseded;
    assert!(matches!(
        super::pairing_grant::validate_authorization_histories(history),
        Err(RuntimeStoreError::UnknownOrCorruptSchema)
    ));
    history[1].lifecycle = AuthorizationLifecycle::Active;

    history[0].lifecycle = AuthorizationLifecycle::Revoked;
    assert!(matches!(
        super::pairing_grant::validate_authorization_histories(history),
        Err(RuntimeStoreError::UnknownOrCorruptSchema)
    ));
}

#[tokio::test]
async fn offline_superseded_serial_and_fingerprint_tamper_fail_close_without_rewrite() {
    for (label, sql) in [
        (
            "grant-superseded-metadata-tamper",
            "UPDATE remote_authorization_ledger \
             SET state_changed_at_ms = state_changed_at_ms + 1 \
             WHERE lifecycle = 'superseded'",
        ),
        (
            "grant-superseded-serial-tamper",
            "UPDATE remote_authorization_ledger \
             SET grant_serial = '00000000000000000009' \
             WHERE lifecycle = 'superseded'",
        ),
        (
            "grant-superseded-fingerprint-tamper",
            concat!(
                "UPDATE remote_authorization_ledger SET device_sign_fingerprint = ",
                "X'0101010101010101010101010101010101010101010101010101010101010101'",
                " WHERE lifecycle = 'superseded'"
            ),
        ),
    ] {
        let root = TestRoot::new(label);
        let keys = MemoryKeyStore::new();
        let clock = Arc::new(AtomicU64::new(NOW_MS));
        prepare_two_serial_history(&root, &keys, clock.clone()).await;
        let connection = rusqlite::Connection::open(root.database()).expect("open offline DB");
        assert_eq!(connection.execute(sql, []).expect("tamper history row"), 1);
        connection
            .execute_batch("PRAGMA wal_checkpoint(TRUNCATE);")
            .expect("checkpoint offline tamper");
        drop(connection);
        let before = artifact_bytes(&root.database());
        let error = RuntimeStoreHandle::open(
            config(&root, clock),
            load_or_create_storage_kek(&keys, &root.database()).expect("reload StorageKEK"),
        )
        .await
        .expect_err("offline history tamper must fail full open");
        assert!(matches!(error, RuntimeStoreError::UnknownOrCorruptSchema));
        assert_eq!(artifact_bytes(&root.database()), before);
    }
}
