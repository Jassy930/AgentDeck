// S3 terminal focused tests live here.
use std::collections::HashMap;
use std::path::Path;
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};

use agentdeck_protocol::relay_v2::PairRouteId;
use agentdeck_protocol::relay_v2::frame::{
    ClosePairRoute, OpaqueRouteFrame, PairRouteCloseOutcome, PairRouteClosed, RelayFrameBody,
};
use agentdeck_protocol::runtime::{PairingReceipt, PairingState};
use rusqlite::Connection;
use sha2::{Digest, Sha256};

use crate::runtime::model::{
    IdempotencyOwner, RuntimeStoreConfig, RuntimeStoreError, RuntimeStoreOperation,
};
use crate::security::{MemoryKeyStore, SecretBytes, load_or_create_storage_kek};

use super::RuntimeStoreHandle;
use super::identity::{RuntimeId, RuntimeIdError, RuntimeIdKind, RuntimeIdSource};
use super::pairing::{
    AcceptPairRequest, CommitPairPending, PairingInviteLifecycle, PreparePairingInvite,
    PreparePairingInviteOutcome,
};
use super::pairing_terminal::{
    CommitPairTerminal, CommitPairTerminalOutcome, PairingTerminalAction,
    PairingTerminalizeOutcome, RECEIPT_RETENTION_MS,
};
use super::pairing_tests::{
    GenerousCapacity, NOW_MS, OneShotFault, TestClock, TestRoot, artifact_bytes,
    canonical_invite_with, make_active, open_terminal, owner, pending_envelope,
    prepare_unused_pairing, private_key, verified_request,
};

#[derive(Clone, Copy, Debug)]
enum SetupLifecycle {
    RouteOpening,
    Unused,
    Preparing,
    AwaitingLocalConfirmation,
}

impl SetupLifecycle {
    const ALL: [Self; 4] = [
        Self::RouteOpening,
        Self::Unused,
        Self::Preparing,
        Self::AwaitingLocalConfirmation,
    ];

    const fn expected(self) -> PairingInviteLifecycle {
        match self {
            Self::RouteOpening => PairingInviteLifecycle::RouteOpening,
            Self::Unused => PairingInviteLifecycle::Unused,
            Self::Preparing => PairingInviteLifecycle::Preparing,
            Self::AwaitingLocalConfirmation => PairingInviteLifecycle::AwaitingLocalConfirmation,
        }
    }
}

fn config(root: &TestRoot, clock: Arc<AtomicU64>) -> RuntimeStoreConfig {
    RuntimeStoreConfig::new(root.database())
        .with_capacity_probe(GenerousCapacity)
        .with_clock(TestClock(clock))
}

async fn open_store(
    root: &TestRoot,
    keys: &MemoryKeyStore,
    clock: Arc<AtomicU64>,
) -> RuntimeStoreHandle {
    RuntimeStoreHandle::open(
        config(root, clock),
        load_or_create_storage_kek(keys, &root.database()).expect("load test StorageKEK"),
    )
    .await
    .expect("open pairing terminal store")
}

fn closed_terminal(pair_route: PairRouteId, outcome: PairRouteCloseOutcome) -> Vec<u8> {
    agentdeck_protocol::relay_v2::encode(&OpaqueRouteFrame {
        version: agentdeck_protocol::relay_v2::RELAY_PROTOCOL_VERSION,
        body: RelayFrameBody::PairRouteClosed(PairRouteClosed {
            pair_route,
            outcome,
        }),
    })
}

fn assert_close_projection(canonical: &[u8], expected_route: PairRouteId) {
    let frame: OpaqueRouteFrame =
        agentdeck_protocol::relay_v2::decode(canonical).expect("decode ClosePairRoute projection");
    assert!(matches!(
        frame.body,
        RelayFrameBody::ClosePairRoute(ClosePairRoute { pair_route, .. })
            if pair_route == expected_route
    ));
}

fn other_owner() -> IdempotencyOwner {
    IdempotencyOwner::Local {
        machine_trust_domain: [0x91; 32],
        uid: 502,
        client_installation_id: [0x93; 16],
    }
}

#[allow(clippy::too_many_arguments)]
async fn retry_prepare(
    store: &RuntimeStoreHandle,
    binding: &crate::runtime::model::MachineIdentityBinding,
    data_cert: &agentdeck_protocol::relay_v2::SignedCertificate,
    owner: IdempotencyOwner,
    key: &str,
    display_name: &str,
    seed: u8,
    expires_at_ms: u64,
) -> Result<PreparePairingInviteOutcome, RuntimeStoreError> {
    let pair_route = PairRouteId::from_bytes([seed; 16]);
    let private_seed = seed.wrapping_add(1);
    store
        .prepare_pairing_invite(PreparePairingInvite::new(
            owner,
            key.to_owned(),
            SecretBytes::new(canonical_invite_with(
                seed,
                private_seed,
                pair_route,
                binding,
                data_cert,
                expires_at_ms,
                display_name,
            )),
            private_key(private_seed),
        ))
        .await
}

fn assert_terminal_prepare(
    outcome: PreparePairingInviteOutcome,
    action: PairingTerminalAction,
    expected_state: PairingState,
) {
    let PreparePairingInviteOutcome::Terminal { receipt, state } = outcome else {
        panic!("terminal create retry must not create or replay an invite");
    };
    assert_eq!(state, expected_state);
    assert!(matches!(
        (action, receipt),
        (
            PairingTerminalAction::Cancel,
            PairingReceipt::Canceled { .. }
        ) | (
            PairingTerminalAction::Expire,
            PairingReceipt::Expired { .. }
        )
    ));
}

#[allow(clippy::too_many_arguments)]
async fn prepare_route_opening(
    store: &RuntimeStoreHandle,
    binding: &crate::runtime::model::MachineIdentityBinding,
    data_cert: &agentdeck_protocol::relay_v2::SignedCertificate,
    pair_route: PairRouteId,
    invite_seed: u8,
    private_seed: u8,
    key: &str,
    expires_at_ms: u64,
) -> (RuntimeId, Vec<u8>) {
    let canonical = canonical_invite_with(
        invite_seed,
        private_seed,
        pair_route,
        binding,
        data_cert,
        expires_at_ms,
        "terminal-test-machine",
    );
    let outcome = store
        .prepare_pairing_invite(PreparePairingInvite::new(
            owner(),
            key.to_owned(),
            SecretBytes::new(canonical.clone()),
            private_key(private_seed),
        ))
        .await
        .expect("prepare RouteOpening pairing");
    let pairing_id = match outcome {
        PreparePairingInviteOutcome::Prepared { invite } => invite.pairing_id(),
        PreparePairingInviteOutcome::Replayed { .. } => panic!("fresh invite must prepare"),
        PreparePairingInviteOutcome::Terminal { .. } => panic!("fresh invite cannot be terminal"),
    };
    (pairing_id, canonical)
}

#[allow(clippy::too_many_arguments)]
async fn prepare_lifecycle(
    store: &RuntimeStoreHandle,
    binding: &crate::runtime::model::MachineIdentityBinding,
    data_cert: &agentdeck_protocol::relay_v2::SignedCertificate,
    lifecycle: SetupLifecycle,
    pair_route: PairRouteId,
    invite_seed: u8,
    private_seed: u8,
    key: &str,
    expires_at_ms: u64,
) -> (RuntimeId, Vec<u8>) {
    let (pairing_id, canonical_invite) = prepare_route_opening(
        store,
        binding,
        data_cert,
        pair_route,
        invite_seed,
        private_seed,
        key,
        expires_at_ms,
    )
    .await;
    if matches!(lifecycle, SetupLifecycle::RouteOpening) {
        return (pairing_id, canonical_invite);
    }
    store
        .acknowledge_pair_route_open(pairing_id, open_terminal(pair_route, expires_at_ms))
        .await
        .expect("advance pairing to Unused");
    if matches!(lifecycle, SetupLifecycle::Unused) {
        return (pairing_id, canonical_invite);
    }
    let verified = verified_request(
        &canonical_invite,
        private_seed,
        invite_seed.wrapping_add(0x21),
        invite_seed.wrapping_add(0x31),
        invite_seed.wrapping_add(0x41),
    );
    let request_hash = verified.request_hash();
    store
        .accept_pair_request(AcceptPairRequest::new(pairing_id, verified))
        .await
        .expect("advance pairing to Preparing");
    if matches!(lifecycle, SetupLifecycle::Preparing) {
        return (pairing_id, canonical_invite);
    }
    store
        .commit_pair_pending(CommitPairPending::new(
            pairing_id,
            request_hash,
            pending_envelope(invite_seed.wrapping_add(0x51)),
        ))
        .await
        .expect("advance pairing to AwaitingLocalConfirmation");
    (pairing_id, canonical_invite)
}

fn terminal_counts(database: &Path) -> (i64, i64, i64, i64) {
    Connection::open(database)
        .expect("open terminal count database")
        .query_row(
            "SELECT
                 (SELECT COUNT(*) FROM remote_pairings),
                 (SELECT COUNT(*) FROM remote_pairing_receipts),
                 (SELECT COUNT(*) FROM remote_control_outbox
                    WHERE operation_kind = 'openPairRoute'),
                 (SELECT COUNT(*) FROM remote_control_outbox
                    WHERE operation_kind = 'closePairRoute')",
            [],
            |row| Ok((row.get(0)?, row.get(1)?, row.get(2)?, row.get(3)?)),
        )
        .expect("read terminal counts")
}

#[tokio::test]
async fn cancel_terminalizes_all_pregrant_states_and_freezes_first_winner() {
    for (index, lifecycle) in SetupLifecycle::ALL.into_iter().enumerate() {
        let root = TestRoot::new(&format!("cancel-{lifecycle:?}"));
        let keys = MemoryKeyStore::new();
        let clock = Arc::new(AtomicU64::new(NOW_MS));
        let store = open_store(&root, &keys, clock).await;
        let (binding, data_cert) = make_active(&store).await;
        let seed = 0x20_u8.wrapping_add(u8::try_from(index).expect("small lifecycle index"));
        let pair_route = PairRouteId::from_bytes([seed; 16]);
        let (pairing_id, _) = prepare_lifecycle(
            &store,
            &binding,
            &data_cert,
            lifecycle,
            pair_route,
            seed,
            seed.wrapping_add(0x40),
            &format!("cancel-{index}"),
            NOW_MS + 300_000,
        )
        .await;
        assert_eq!(
            store
                .load_pairing_invite(pairing_id)
                .await
                .expect("load prepared lifecycle")
                .expect("pairing exists")
                .lifecycle(),
            lifecycle.expected()
        );

        let transitioned = store
            .terminalize_pairing(pairing_id, PairingTerminalAction::Cancel)
            .await
            .expect("cancel pairing");
        match transitioned {
            PairingTerminalizeOutcome::Transitioned { receipt, close } => {
                assert!(matches!(receipt, PairingReceipt::Canceled { .. }));
                assert_eq!(close.pairing_id(), pairing_id);
                assert_eq!(close.pair_route(), pair_route);
                assert_close_projection(close.canonical_frame(), pair_route);
            }
            other => panic!("first cancel must transition: {other:?}"),
        }
        assert_eq!(terminal_counts(&root.database()), (1, 1, 0, 1));
        assert_eq!(
            store
                .load_pairing_invite(pairing_id)
                .await
                .expect("load canceled pairing")
                .expect("canceled secret row remains until Close ACK")
                .lifecycle(),
            PairingInviteLifecycle::Canceled
        );

        assert!(matches!(
            store
                .terminalize_pairing(pairing_id, PairingTerminalAction::Cancel)
                .await
                .expect("replay same cancel"),
            PairingTerminalizeOutcome::Replayed {
                receipt: PairingReceipt::Canceled { .. },
                state: PairingState::Canceled,
                close: Some(_),
            }
        ));
        assert!(matches!(
            store
                .terminalize_pairing(pairing_id, PairingTerminalAction::Expire)
                .await
                .expect("read opposing winner"),
            PairingTerminalizeOutcome::AlreadyHandled {
                receipt: PairingReceipt::Canceled { .. },
                state: PairingState::Canceled,
                close: Some(_),
            }
        ));
        store.shutdown().await.expect("shutdown canceled store");
    }
}

#[tokio::test]
async fn request_bound_terminal_freezes_carrier_before_close_and_replays_exact_bytes() {
    let root = TestRoot::new("request-bound-terminal-carrier");
    let keys = MemoryKeyStore::new();
    let clock = Arc::new(AtomicU64::new(NOW_MS));
    let store = open_store(&root, &keys, clock).await;
    let (binding, data_cert) = make_active(&store).await;
    let pair_route = PairRouteId::from_bytes([0x5a; 16]);
    let (pairing_id, _) = prepare_lifecycle(
        &store,
        &binding,
        &data_cert,
        SetupLifecycle::AwaitingLocalConfirmation,
        pair_route,
        0x5b,
        0x5c,
        "request-bound-terminal-carrier",
        NOW_MS + 300_000,
    )
    .await;

    store
        .terminalize_pairing(pairing_id, PairingTerminalAction::Cancel)
        .await
        .expect("commit terminal winner before HPKE sealing");
    let mut recovery = store
        .list_pairing_terminal_recovery()
        .await
        .expect("load request-bound terminal preparation");
    assert_eq!(recovery.len(), 1);
    assert!(recovery[0].carrier().is_none());
    let mut preparation = recovery[0]
        .take_preparation()
        .expect("request-bound terminal must require a carrier");
    assert_eq!(preparation.pairing_id(), pairing_id);
    assert_eq!(preparation.pair_route(), pair_route);
    assert_eq!(preparation.info().pair_route, pair_route);
    assert_eq!(preparation.context().pair_route, Some(pair_route));
    assert_eq!(
        preparation.context().frame_kind,
        agentdeck_protocol::e2ee::OuterFrameKind::PairTerminal
    );
    assert_eq!(preparation.data_sign_certificate(), &data_cert);
    let expected_hpke_seed = preparation
        .take_hpke_seed()
        .expect("preparation owns one HPKE seed");
    assert_ne!(expected_hpke_seed.as_ref(), &[0; 32]);
    let expected_hpke_seed_hash: [u8; 32] = Sha256::digest(expected_hpke_seed.as_ref()).into();
    drop(expected_hpke_seed);

    let close_ack = closed_terminal(pair_route, PairRouteCloseOutcome::Closed);
    let before_early_close = artifact_bytes(&root.database());
    assert!(matches!(
        store
            .acknowledge_pair_route_close(pairing_id, close_ack.clone())
            .await,
        Err(RuntimeStoreError::InvalidStateTransition)
    ));
    assert_eq!(artifact_bytes(&root.database()), before_early_close);

    store
        .shutdown()
        .await
        .expect("crash cut after terminal preparation");
    let store = open_store(&root, &keys, Arc::new(AtomicU64::new(NOW_MS))).await;
    let mut restarted_recovery = store
        .list_pairing_terminal_recovery()
        .await
        .expect("rederive terminal preparation after restart");
    let preparation = restarted_recovery[0]
        .take_preparation()
        .expect("uncommitted carrier requires a restart preparation");
    assert_eq!(
        preparation
            .hpke_seed()
            .map(|seed| <[u8; 32]>::from(Sha256::digest(seed))),
        Some(expected_hpke_seed_hash),
        "same Runtime DB and terminal identity must rederive the exact HPKE seed"
    );
    let before_unsealed_commit = artifact_bytes(&root.database());
    let unsealed_input = CommitPairTerminal::new(preparation, pending_envelope(0x5d))
        .expect("freeze unsealed negative carrier input");
    assert!(matches!(
        unsealed_input.retry_copy(),
        Err(RuntimeStoreError::PairingConflict)
    ));
    assert!(matches!(
        store.commit_pair_terminal(unsealed_input).await,
        Err(RuntimeStoreError::PairingConflict)
    ));
    assert_eq!(artifact_bytes(&root.database()), before_unsealed_commit);

    let mut retry_recovery = store
        .list_pairing_terminal_recovery()
        .await
        .expect("rederive preparation after rejected unsealed commit");
    let mut preparation = retry_recovery[0]
        .take_preparation()
        .expect("rejected input must not consume durable recovery state");
    let committed_seed = preparation
        .take_hpke_seed()
        .expect("sealing consumes the unique rederived HPKE seed owner");
    assert_eq!(
        <[u8; 32]>::from(Sha256::digest(committed_seed.as_ref())),
        expected_hpke_seed_hash
    );

    let input = CommitPairTerminal::new(preparation, pending_envelope(0x5d))
        .expect("freeze canonical PairTerminal carrier input");
    let expected_frame = input.canonical_frame().to_vec();
    let committed = store
        .commit_pair_terminal(input.retry_copy().expect("copy seed-free retry input"))
        .await
        .expect("persist PairTerminal carrier");
    let committed_recovery = match committed {
        CommitPairTerminalOutcome::Committed { recovery } => recovery,
        CommitPairTerminalOutcome::Replayed { .. } => panic!("first carrier commit is fresh"),
    };
    assert!(committed_recovery.preparation().is_none());
    assert_eq!(
        committed_recovery
            .carrier()
            .expect("committed carrier projection")
            .canonical_frame(),
        expected_frame
    );

    let before_replay = artifact_bytes(&root.database());
    let replayed = store
        .commit_pair_terminal(input)
        .await
        .expect("exact carrier retry");
    assert!(matches!(
        replayed,
        CommitPairTerminalOutcome::Replayed { .. }
    ));
    assert_eq!(artifact_bytes(&root.database()), before_replay);

    store.shutdown().await.expect("shutdown before restart");
    let reopened = open_store(&root, &keys, Arc::new(AtomicU64::new(NOW_MS))).await;
    let restarted = reopened
        .list_pairing_terminal_recovery()
        .await
        .expect("recover frozen carrier after restart");
    assert_eq!(restarted.len(), 1);
    assert!(restarted[0].preparation().is_none());
    assert_eq!(
        restarted[0]
            .carrier()
            .expect("restart reuses frozen carrier")
            .canonical_frame(),
        expected_frame
    );
    reopened
        .acknowledge_pair_route_close(pairing_id, close_ack)
        .await
        .expect("Close ACK is admitted only after carrier durability");
    reopened.shutdown().await.expect("shutdown carrier test");
}

#[tokio::test]
async fn pair_terminal_carrier_commit_faults_converge_by_exact_retry() {
    for (label, operation, committed) in [
        (
            "pair-terminal-before-commit",
            RuntimeStoreOperation::CommitPairTerminalBeforeCommit,
            false,
        ),
        (
            "pair-terminal-after-commit",
            RuntimeStoreOperation::CommitPairTerminalAfterCommit,
            true,
        ),
    ] {
        let root = TestRoot::new(label);
        let keys = MemoryKeyStore::new();
        let clock = Arc::new(AtomicU64::new(NOW_MS));
        let setup = open_store(&root, &keys, clock.clone()).await;
        let (binding, data_cert) = make_active(&setup).await;
        let route = PairRouteId::from_bytes([if committed { 0x6a } else { 0x6b }; 16]);
        let (pairing_id, _) = prepare_lifecycle(
            &setup,
            &binding,
            &data_cert,
            SetupLifecycle::Preparing,
            route,
            0x6c,
            0x6d,
            label,
            NOW_MS + 300_000,
        )
        .await;
        setup
            .terminalize_pairing(pairing_id, PairingTerminalAction::Cancel)
            .await
            .expect("commit winner before carrier fault");
        let mut recovery = setup
            .list_pairing_terminal_recovery()
            .await
            .expect("load carrier preparation");
        let mut preparation = recovery[0]
            .take_preparation()
            .expect("request material requires PairTerminal");
        let _sealed_seed = preparation
            .take_hpke_seed()
            .expect("sealing consumes the unique HPKE seed owner");
        let input = CommitPairTerminal::new(preparation, pending_envelope(0x6e))
            .expect("freeze exact carrier input");
        let expected = input.canonical_frame().to_vec();
        setup.shutdown().await.expect("shutdown carrier setup");

        let faulted = RuntimeStoreHandle::open(
            config(&root, clock.clone()).with_fault_injector(Arc::new(OneShotFault {
                operation,
                fired: AtomicBool::new(false),
            })),
            load_or_create_storage_kek(&keys, &root.database()).expect("reload StorageKEK"),
        )
        .await
        .expect("open faulted carrier store");
        let error = faulted
            .commit_pair_terminal(input.retry_copy().expect("copy seed-free retry input"))
            .await
            .expect_err("carrier cut must surface");
        assert_eq!(
            matches!(error, RuntimeStoreError::CommitOutcomeUnknown { .. }),
            committed
        );
        let after_cut = faulted
            .list_pairing_terminal_recovery()
            .await
            .expect("audit carrier cut");
        assert_eq!(after_cut.len(), 1);
        if committed {
            assert_eq!(
                after_cut[0]
                    .carrier()
                    .expect("post-commit cut retains exact carrier")
                    .canonical_frame(),
                expected
            );
        } else {
            assert!(after_cut[0].carrier().is_none());
            assert!(after_cut[0].preparation().is_some());
        }
        let replay = faulted
            .commit_pair_terminal(input)
            .await
            .expect("retry exact frozen carrier");
        match (committed, replay) {
            (true, CommitPairTerminalOutcome::Replayed { .. })
            | (false, CommitPairTerminalOutcome::Committed { .. }) => {}
            (_, other) => panic!("unexpected exact retry outcome: {other:?}"),
        }
        let recovered = faulted
            .list_pairing_terminal_recovery()
            .await
            .expect("final carrier recovery");
        assert_eq!(
            recovered[0]
                .carrier()
                .expect("carrier durable after retry")
                .canonical_frame(),
            expected
        );
        faulted
            .shutdown()
            .await
            .expect("shutdown carrier fault store");
    }
}

#[tokio::test]
async fn expiry_sweep_covers_all_pregrant_states_and_empty_or_loser_paths_are_zero_write() {
    let root = TestRoot::new("expiry-sweep");
    let keys = MemoryKeyStore::new();
    let clock = Arc::new(AtomicU64::new(NOW_MS));
    let store = open_store(&root, &keys, clock.clone()).await;
    let (binding, data_cert) = make_active(&store).await;
    let mut due = Vec::new();
    for (index, lifecycle) in SetupLifecycle::ALL.into_iter().enumerate() {
        let seed = 0x60_u8.wrapping_add(u8::try_from(index).expect("small lifecycle index"));
        let route = PairRouteId::from_bytes([seed; 16]);
        let (pairing_id, _) = prepare_lifecycle(
            &store,
            &binding,
            &data_cert,
            lifecycle,
            route,
            seed,
            seed.wrapping_add(0x20),
            &format!("due-{index}"),
            NOW_MS + 1_000,
        )
        .await;
        due.push(pairing_id);
    }
    let future_route = PairRouteId::from_bytes([0x70; 16]);
    let (future, _) = prepare_lifecycle(
        &store,
        &binding,
        &data_cert,
        SetupLifecycle::Unused,
        future_route,
        0x71,
        0x72,
        "future",
        NOW_MS + 5_000,
    )
    .await;

    clock.store(NOW_MS + 1_000, Ordering::SeqCst);
    let outcomes = store
        .terminalize_due_pairings()
        .await
        .expect("expire all due pairings");
    assert_eq!(outcomes.len(), due.len());
    assert!(outcomes.iter().all(|outcome| matches!(
        outcome,
        PairingTerminalizeOutcome::Transitioned {
            receipt: PairingReceipt::Expired { .. },
            ..
        }
    )));
    for pairing_id in &due {
        assert_eq!(
            store
                .load_pairing_invite(*pairing_id)
                .await
                .expect("load expired pairing")
                .expect("expired secret row remains")
                .lifecycle(),
            PairingInviteLifecycle::Expired
        );
    }
    assert_eq!(
        store
            .load_pairing_invite(future)
            .await
            .expect("load future pairing")
            .expect("future pairing remains")
            .lifecycle(),
        PairingInviteLifecycle::Unused
    );

    let before_empty = artifact_bytes(&root.database());
    assert!(
        store
            .terminalize_due_pairings()
            .await
            .expect("empty expiry sweep")
            .is_empty()
    );
    assert_eq!(artifact_bytes(&root.database()), before_empty);
    let before_loser = artifact_bytes(&root.database());
    assert!(matches!(
        store
            .terminalize_pairing(due[0], PairingTerminalAction::Cancel)
            .await
            .expect("expired winner defeats late cancel"),
        PairingTerminalizeOutcome::AlreadyHandled {
            receipt: PairingReceipt::Expired { .. },
            state: PairingState::Expired,
            close: Some(_),
        }
    ));
    assert_eq!(artifact_bytes(&root.database()), before_loser);
    store.shutdown().await.expect("shutdown expiry sweep store");
}

#[tokio::test]
async fn cancel_at_expiry_records_expire_and_late_open_ack_cannot_regress_state() {
    let root = TestRoot::new("cancel-at-expiry");
    let keys = MemoryKeyStore::new();
    let clock = Arc::new(AtomicU64::new(NOW_MS));
    let store = open_store(&root, &keys, clock.clone()).await;
    let (binding, data_cert) = make_active(&store).await;
    let pair_route = PairRouteId::from_bytes([0x81; 16]);
    let expiry = NOW_MS + 1_000;
    let (pairing_id, _) = prepare_route_opening(
        &store,
        &binding,
        &data_cert,
        pair_route,
        0x82,
        0x83,
        "cancel-at-expiry",
        expiry,
    )
    .await;
    clock.store(expiry, Ordering::SeqCst);
    assert!(matches!(
        store
            .terminalize_pairing(pairing_id, PairingTerminalAction::Cancel)
            .await
            .expect("expiry wins cancel race"),
        PairingTerminalizeOutcome::AlreadyHandled {
            receipt: PairingReceipt::Expired { .. },
            state: PairingState::Expired,
            close: Some(_),
        }
    ));
    let before_late_ack = artifact_bytes(&root.database());
    assert!(matches!(
        store
            .acknowledge_pair_route_open(pairing_id, open_terminal(pair_route, expiry))
            .await,
        Err(RuntimeStoreError::PairingExpired)
    ));
    assert_eq!(artifact_bytes(&root.database()), before_late_ack);
    assert_eq!(
        store
            .load_pairing_invite(pairing_id)
            .await
            .expect("load after late Open ACK")
            .expect("terminal secret row remains")
            .lifecycle(),
        PairingInviteLifecycle::Expired
    );
    store.shutdown().await.expect("shutdown race store");
}

#[tokio::test]
async fn terminalize_fault_boundaries_converge_by_exact_retry() {
    for (label, operation, committed) in [
        (
            "terminalize-before",
            RuntimeStoreOperation::TerminalizePairingBeforeCommit,
            false,
        ),
        (
            "terminalize-after",
            RuntimeStoreOperation::TerminalizePairingAfterCommit,
            true,
        ),
    ] {
        let root = TestRoot::new(label);
        let keys = MemoryKeyStore::new();
        let clock = Arc::new(AtomicU64::new(NOW_MS));
        let setup = open_store(&root, &keys, clock.clone()).await;
        let (binding, data_cert) = make_active(&setup).await;
        let route = PairRouteId::from_bytes([if committed { 0x91 } else { 0x92 }; 16]);
        let (pairing_id, _) =
            prepare_unused_pairing(&setup, &binding, &data_cert, route, 0x93, 0x94, label).await;
        setup.shutdown().await.expect("shutdown terminalize setup");

        let faulted = RuntimeStoreHandle::open(
            config(&root, clock.clone()).with_fault_injector(Arc::new(OneShotFault {
                operation,
                fired: AtomicBool::new(false),
            })),
            load_or_create_storage_kek(&keys, &root.database()).expect("reload test StorageKEK"),
        )
        .await
        .expect("open faulted terminalize store");
        let error = faulted
            .terminalize_pairing(pairing_id, PairingTerminalAction::Cancel)
            .await
            .expect_err("terminalize fault must surface");
        assert_eq!(
            matches!(error, RuntimeStoreError::CommitOutcomeUnknown { .. }),
            committed
        );
        assert_eq!(
            terminal_counts(&root.database()),
            if committed {
                (1, 1, 0, 1)
            } else {
                (1, 0, 0, 0)
            }
        );
        assert!(
            matches!(
                faulted
                    .terminalize_pairing(pairing_id, PairingTerminalAction::Cancel)
                    .await
                    .expect("retry terminalize"),
                PairingTerminalizeOutcome::Replayed { .. } if committed
            ) || !committed
        );
        if !committed {
            assert!(matches!(
                faulted
                    .terminalize_pairing(pairing_id, PairingTerminalAction::Cancel)
                    .await
                    .expect("replay terminalize committed retry"),
                PairingTerminalizeOutcome::Replayed { .. }
            ));
        }
        faulted.shutdown().await.expect("shutdown faulted store");
    }
}

#[tokio::test]
async fn close_ack_accepts_both_terminal_outcomes_scrubs_secret_and_replays_tombstone() {
    for (index, close_outcome) in [
        PairRouteCloseOutcome::Closed,
        PairRouteCloseOutcome::AlreadyAbsent,
    ]
    .into_iter()
    .enumerate()
    {
        let root = TestRoot::new(&format!("close-ack-{close_outcome:?}"));
        let keys = MemoryKeyStore::new();
        let clock = Arc::new(AtomicU64::new(NOW_MS));
        let store = open_store(&root, &keys, clock.clone()).await;
        let (binding, data_cert) = make_active(&store).await;
        let seed = 0xa0_u8.wrapping_add(u8::try_from(index).expect("small close index"));
        let route = PairRouteId::from_bytes([seed; 16]);
        let (pairing_id, _) = prepare_unused_pairing(
            &store,
            &binding,
            &data_cert,
            route,
            seed.wrapping_add(1),
            seed.wrapping_add(2),
            &format!("close-{index}"),
        )
        .await;
        store
            .terminalize_pairing(pairing_id, PairingTerminalAction::Cancel)
            .await
            .expect("terminalize before Close ACK");
        store.shutdown().await.expect("shutdown before recovery");

        let reopened = open_store(&root, &keys, clock.clone()).await;
        let recovery = reopened
            .list_pairing_terminal_recovery()
            .await
            .expect("list terminal recovery");
        assert_eq!(recovery.len(), 1);
        assert!(matches!(
            recovery[0].receipt(),
            PairingReceipt::Canceled { .. }
        ));
        assert_eq!(recovery[0].close().pairing_id(), pairing_id);
        assert_close_projection(recovery[0].close().canonical_frame(), route);

        let canonical_terminal = closed_terminal(route, close_outcome);
        clock.store(NOW_MS.saturating_sub(1), Ordering::SeqCst);
        let before_regressed_close = artifact_bytes(&root.database());
        let regressed = reopened
            .acknowledge_pair_route_close(pairing_id, canonical_terminal.clone())
            .await
            .expect_err("fresh Close must reject a regressed retention clock");
        assert!(matches!(
            regressed,
            RuntimeStoreError::ClockRegressed {
                persisted_ms,
                observed_ms,
            } if persisted_ms == NOW_MS && observed_ms == NOW_MS.saturating_sub(1)
        ));
        assert_eq!(artifact_bytes(&root.database()), before_regressed_close);
        assert_eq!(terminal_counts(&root.database()), (1, 1, 0, 1));
        clock.store(NOW_MS, Ordering::SeqCst);
        let acknowledged = reopened
            .acknowledge_pair_route_close(pairing_id, canonical_terminal.clone())
            .await
            .expect("acknowledge ClosePairRoute");
        assert!(!acknowledged.replayed());
        assert!(matches!(
            acknowledged.receipt(),
            PairingReceipt::Canceled { .. }
        ));
        assert_eq!(terminal_counts(&root.database()), (0, 1, 0, 0));
        assert!(
            reopened
                .load_pairing_invite(pairing_id)
                .await
                .expect("load scrubbed pairing")
                .is_none()
        );
        assert!(
            reopened
                .list_pairing_terminal_recovery()
                .await
                .expect("list after Close ACK")
                .is_empty()
        );
        let replayed = reopened
            .acknowledge_pair_route_close(pairing_id, canonical_terminal)
            .await
            .expect("replay Close ACK against receipt tombstone");
        assert!(replayed.replayed());
        assert!(matches!(
            replayed.receipt(),
            PairingReceipt::Canceled { .. }
        ));

        let reused_route_invite = canonical_invite_with(
            seed.wrapping_add(3),
            seed.wrapping_add(4),
            route,
            &binding,
            &data_cert,
            NOW_MS + 300_000,
            "route-reuse-must-fail",
        );
        assert!(matches!(
            reopened
                .prepare_pairing_invite(PreparePairingInvite::new(
                    owner(),
                    format!("route-reuse-{index}"),
                    SecretBytes::new(reused_route_invite),
                    private_key(seed.wrapping_add(4)),
                ))
                .await,
            Err(RuntimeStoreError::PairingConflict)
        ));
        reopened.shutdown().await.expect("shutdown acked store");
    }
}

#[tokio::test]
async fn create_idempotency_tombstone_survives_terminal_ack_restart_and_retention_cutoff() {
    for (index, action) in [PairingTerminalAction::Cancel, PairingTerminalAction::Expire]
        .into_iter()
        .enumerate()
    {
        let root = TestRoot::new(&format!("create-tombstone-{action:?}"));
        let keys = MemoryKeyStore::new();
        let clock = Arc::new(AtomicU64::new(NOW_MS));
        let store = open_store(&root, &keys, clock.clone()).await;
        let (binding, data_cert) = make_active(&store).await;
        let seed = 0xaa_u8.wrapping_add(u8::try_from(index).expect("small action index"));
        let route = PairRouteId::from_bytes([seed; 16]);
        let terminal_at = if action == PairingTerminalAction::Expire {
            NOW_MS + 1_000
        } else {
            NOW_MS
        };
        let expires_at_ms = if action == PairingTerminalAction::Expire {
            terminal_at
        } else {
            NOW_MS + 300_000
        };
        let key = format!("create-tombstone-{index}");
        let (pairing_id, _) = prepare_lifecycle(
            &store,
            &binding,
            &data_cert,
            SetupLifecycle::Unused,
            route,
            seed,
            seed.wrapping_add(0x20),
            &key,
            expires_at_ms,
        )
        .await;
        clock.store(terminal_at, Ordering::SeqCst);
        store
            .terminalize_pairing(pairing_id, action)
            .await
            .expect("freeze terminal receipt and Close outbox");

        let before_ack_retry = artifact_bytes(&root.database());
        assert_terminal_prepare(
            retry_prepare(
                &store,
                &binding,
                &data_cert,
                owner(),
                &key,
                "terminal-test-machine",
                seed.wrapping_add(0x30),
                terminal_at + 300_000,
            )
            .await
            .expect("same create retry before Close ACK"),
            action,
            if action == PairingTerminalAction::Cancel {
                PairingState::Canceled
            } else {
                PairingState::Expired
            },
        );
        assert_eq!(artifact_bytes(&root.database()), before_ack_retry);
        assert_eq!(terminal_counts(&root.database()), (1, 1, 0, 1));

        store
            .acknowledge_pair_route_close(
                pairing_id,
                closed_terminal(route, PairRouteCloseOutcome::Closed),
            )
            .await
            .expect("Close ACK scrubs only secret material");
        store.shutdown().await.expect("shutdown terminal store");

        clock.store(terminal_at + RECEIPT_RETENTION_MS, Ordering::SeqCst);
        let reopened = open_store(&root, &keys, clock.clone()).await;
        let before_restart_retry = artifact_bytes(&root.database());
        assert_terminal_prepare(
            retry_prepare(
                &reopened,
                &binding,
                &data_cert,
                owner(),
                &key,
                "terminal-test-machine",
                seed.wrapping_add(0x40),
                terminal_at + RECEIPT_RETENTION_MS + 300_000,
            )
            .await
            .expect("same create retry after Close ACK and restart"),
            action,
            PairingState::ClosedTombstone,
        );
        assert_eq!(artifact_bytes(&root.database()), before_restart_retry);
        assert_eq!(terminal_counts(&root.database()), (0, 1, 0, 0));

        let before_conflict = artifact_bytes(&root.database());
        let conflict = retry_prepare(
            &reopened,
            &binding,
            &data_cert,
            owner(),
            &key,
            "different-input",
            seed.wrapping_add(0x50),
            terminal_at + RECEIPT_RETENTION_MS + 300_000,
        )
        .await
        .expect_err("same owner/key with different input must conflict");
        assert!(matches!(conflict, RuntimeStoreError::IdempotencyConflict));
        assert_eq!(artifact_bytes(&root.database()), before_conflict);

        let other = retry_prepare(
            &reopened,
            &binding,
            &data_cert,
            other_owner(),
            &key,
            "terminal-test-machine",
            seed.wrapping_add(0x60),
            terminal_at + RECEIPT_RETENTION_MS + 300_000,
        )
        .await
        .expect("different owner has an independent idempotency namespace");
        assert!(matches!(
            other,
            PreparePairingInviteOutcome::Prepared { .. }
        ));
        reopened.shutdown().await.expect("shutdown reopened store");
    }
}

#[tokio::test]
async fn close_ack_fault_boundaries_converge_without_resurrecting_secrets() {
    for (label, operation, committed) in [
        (
            "close-before",
            RuntimeStoreOperation::AcknowledgePairRouteCloseBeforeCommit,
            false,
        ),
        (
            "close-after",
            RuntimeStoreOperation::AcknowledgePairRouteCloseAfterCommit,
            true,
        ),
    ] {
        let root = TestRoot::new(label);
        let keys = MemoryKeyStore::new();
        let clock = Arc::new(AtomicU64::new(NOW_MS));
        let setup = open_store(&root, &keys, clock.clone()).await;
        let (binding, data_cert) = make_active(&setup).await;
        let seed = if committed { 0xb1 } else { 0xb2 };
        let route = PairRouteId::from_bytes([seed; 16]);
        let (pairing_id, _) = prepare_unused_pairing(
            &setup,
            &binding,
            &data_cert,
            route,
            seed.wrapping_add(1),
            seed.wrapping_add(2),
            label,
        )
        .await;
        setup
            .terminalize_pairing(pairing_id, PairingTerminalAction::Cancel)
            .await
            .expect("terminalize Close ACK fixture");
        setup.shutdown().await.expect("shutdown Close ACK setup");

        let faulted = RuntimeStoreHandle::open(
            config(&root, clock.clone()).with_fault_injector(Arc::new(OneShotFault {
                operation,
                fired: AtomicBool::new(false),
            })),
            load_or_create_storage_kek(&keys, &root.database()).expect("reload test StorageKEK"),
        )
        .await
        .expect("open faulted Close ACK store");
        let terminal = closed_terminal(route, PairRouteCloseOutcome::Closed);
        let error = faulted
            .acknowledge_pair_route_close(pairing_id, terminal.clone())
            .await
            .expect_err("Close ACK fault must surface");
        assert_eq!(
            matches!(error, RuntimeStoreError::CommitOutcomeUnknown { .. }),
            committed
        );
        assert_eq!(
            terminal_counts(&root.database()),
            if committed {
                (0, 1, 0, 0)
            } else {
                (1, 1, 0, 1)
            }
        );
        let retry = faulted
            .acknowledge_pair_route_close(pairing_id, terminal)
            .await
            .expect("retry Close ACK");
        assert_eq!(retry.replayed(), committed);
        assert_eq!(terminal_counts(&root.database()), (0, 1, 0, 0));
        faulted.shutdown().await.expect("shutdown Close ACK store");
    }
}

#[tokio::test]
async fn late_close_commit_unknown_refreshes_receipt_before_startup_purge_and_exact_retry() {
    let root = TestRoot::new("late-close-after-commit-retention");
    let keys = MemoryKeyStore::new();
    let clock = Arc::new(AtomicU64::new(NOW_MS));
    let setup = open_store(&root, &keys, clock.clone()).await;
    let (binding, data_cert) = make_active(&setup).await;
    let route = PairRouteId::from_bytes([0xb3; 16]);
    let (pairing_id, _) = prepare_unused_pairing(
        &setup,
        &binding,
        &data_cert,
        route,
        0xb4,
        0xb5,
        "late-close-after-commit-retention",
    )
    .await;
    setup
        .terminalize_pairing(pairing_id, PairingTerminalAction::Cancel)
        .await
        .expect("terminalize late Close retention fixture");
    let close_at_ms = NOW_MS
        .checked_add(RECEIPT_RETENTION_MS)
        .and_then(|value| value.checked_add(1))
        .expect("late Close timestamp fits");
    clock.store(close_at_ms, Ordering::SeqCst);
    assert!(
        setup
            .plan_expired_pairing_receipt_purge()
            .await
            .expect("expired live receipt remains pinned by pairing and Close outbox")
            .is_none()
    );
    setup.shutdown().await.expect("shutdown late Close setup");

    let faulted = RuntimeStoreHandle::open(
        config(&root, clock.clone()).with_fault_injector(Arc::new(OneShotFault {
            operation: RuntimeStoreOperation::AcknowledgePairRouteCloseAfterCommit,
            fired: AtomicBool::new(false),
        })),
        load_or_create_storage_kek(&keys, &root.database()).expect("reload test StorageKEK"),
    )
    .await
    .expect("open faulted late Close store");
    let terminal = closed_terminal(route, PairRouteCloseOutcome::Closed);
    assert!(matches!(
        faulted
            .acknowledge_pair_route_close(pairing_id, terminal.clone())
            .await,
        Err(RuntimeStoreError::CommitOutcomeUnknown { .. })
    ));
    assert_eq!(terminal_counts(&root.database()), (0, 1, 0, 0));
    faulted
        .shutdown()
        .await
        .expect("shutdown after unknown late Close commit");

    let reopened = open_store(&root, &keys, clock.clone()).await;
    assert!(
        reopened
            .plan_expired_pairing_receipt_purge()
            .await
            .expect("startup purge planning observes refreshed receipt retention")
            .is_none(),
        "Close commit must refresh the tombstone before startup purge can delete it"
    );
    let before_exact_retry = artifact_bytes(&root.database());
    let retry = reopened
        .acknowledge_pair_route_close(pairing_id, terminal)
        .await
        .expect("exact Close retry survives startup purge ordering");
    assert!(retry.replayed());
    assert_eq!(
        artifact_bytes(&root.database()),
        before_exact_retry,
        "exact Close replay must not extend receipt retention a second time"
    );

    let refreshed_deadline = close_at_ms
        .checked_add(RECEIPT_RETENTION_MS)
        .expect("refreshed receipt deadline fits");
    clock.store(refreshed_deadline, Ordering::SeqCst);
    assert!(
        reopened
            .plan_expired_pairing_receipt_purge()
            .await
            .expect("strict refreshed cutoff planning")
            .is_none()
    );
    clock.store(
        refreshed_deadline
            .checked_add(1)
            .expect("post-refresh purge timestamp fits"),
        Ordering::SeqCst,
    );
    let plan = reopened
        .plan_expired_pairing_receipt_purge()
        .await
        .expect("plan refreshed receipt purge")
        .expect("receipt is eligible only after the refreshed full window");
    let purged = reopened
        .apply_pairing_receipt_purge(plan)
        .await
        .expect("purge refreshed receipt tombstone");
    assert_eq!(purged.purged_count(), 1);
    assert_eq!(terminal_counts(&root.database()), (0, 0, 0, 0));
    reopened
        .shutdown()
        .await
        .expect("shutdown late Close retention store");
}

#[tokio::test]
async fn recovery_scan_barrier_rejects_all_terminal_mutations_without_writes() {
    let root = TestRoot::new("terminal-recovery-barrier");
    let keys = MemoryKeyStore::new();
    let clock = Arc::new(AtomicU64::new(NOW_MS));
    let store = open_store(&root, &keys, clock.clone()).await;
    let (binding, data_cert) = make_active(&store).await;
    let close_route = PairRouteId::from_bytes([0xba; 16]);
    let (close_pairing, _) = prepare_unused_pairing(
        &store,
        &binding,
        &data_cert,
        close_route,
        0xbb,
        0xbc,
        "barrier-close",
    )
    .await;
    store
        .terminalize_pairing(close_pairing, PairingTerminalAction::Cancel)
        .await
        .expect("terminalize Close ACK barrier fixture");
    let due_route = PairRouteId::from_bytes([0xbd; 16]);
    let due_at = NOW_MS + 1_000;
    let (due_pairing, _) = prepare_lifecycle(
        &store,
        &binding,
        &data_cert,
        SetupLifecycle::Unused,
        due_route,
        0xbe,
        0xbf,
        "barrier-due",
        due_at,
    )
    .await;
    clock.store(due_at, Ordering::SeqCst);
    let _cursor = store
        .begin_recovery_scan()
        .await
        .expect("begin recovery mutation barrier");
    let before = artifact_bytes(&root.database());
    assert!(matches!(
        store
            .terminalize_pairing(due_pairing, PairingTerminalAction::Expire)
            .await,
        Err(RuntimeStoreError::RecoveryInProgress)
    ));
    assert!(matches!(
        store.terminalize_due_pairings().await,
        Err(RuntimeStoreError::RecoveryInProgress)
    ));
    assert!(matches!(
        store
            .acknowledge_pair_route_close(
                close_pairing,
                closed_terminal(close_route, PairRouteCloseOutcome::Closed),
            )
            .await,
        Err(RuntimeStoreError::RecoveryInProgress)
    ));
    assert_eq!(artifact_bytes(&root.database()), before);
    store
        .shutdown()
        .await
        .expect("shutdown recovery barrier store");
}

#[derive(Clone, Copy, Debug)]
enum TamperTarget {
    Receipt,
    ReceiptIdempotencyToken,
    ReceiptInputHash,
    CloseOutbox,
    MissingRequestMaterial,
    PairingLifecycle,
    Ledger,
}

fn apply_offline_tamper(database: &Path, target: TamperTarget) {
    let connection = Connection::open(database).expect("open offline tamper database");
    let changed = match target {
        TamperTarget::Receipt => connection.execute(
            "UPDATE remote_pairing_receipts
             SET canonical_receipt = zeroblob(length(canonical_receipt))",
            [],
        ),
        TamperTarget::ReceiptIdempotencyToken => connection.execute(
            "UPDATE remote_pairing_receipts
             SET idempotency_token = X'0101010101010101010101010101010101010101010101010101010101010101'",
            [],
        ),
        TamperTarget::ReceiptInputHash => connection.execute(
            "UPDATE remote_pairing_receipts
             SET input_hash = X'0202020202020202020202020202020202020202020202020202020202020202'",
            [],
        ),
        TamperTarget::CloseOutbox => connection.execute(
            "UPDATE remote_control_outbox
             SET sealed_frame = zeroblob(length(sealed_frame))
             WHERE operation_kind = 'closePairRoute'",
            [],
        ),
        TamperTarget::MissingRequestMaterial => connection.execute(
            "UPDATE remote_pairings
             SET request_hash = X'0303030303030303030303030303030303030303030303030303030303030303',
                 device_sign_fingerprint = X'0404040404040404040404040404040404040404040404040404040404040404'",
            [],
        ),
        TamperTarget::PairingLifecycle => connection.execute(
            "UPDATE remote_pairings SET lifecycle = 'expired' WHERE lifecycle = 'canceled'",
            [],
        ),
        TamperTarget::Ledger => connection.execute(
            "UPDATE runtime_meta SET remote_pairing_receipt_count = 0 WHERE singleton = 1",
            [],
        ),
    }
    .expect("apply offline tamper");
    assert_eq!(changed, 1);
    connection
        .execute_batch("PRAGMA wal_checkpoint(TRUNCATE);")
        .expect("checkpoint offline tamper");
}

#[tokio::test]
async fn offline_terminal_tamper_fails_full_open_without_rewriting_artifacts() {
    for (index, target) in [
        TamperTarget::Receipt,
        TamperTarget::ReceiptIdempotencyToken,
        TamperTarget::ReceiptInputHash,
        TamperTarget::CloseOutbox,
        TamperTarget::MissingRequestMaterial,
        TamperTarget::PairingLifecycle,
        TamperTarget::Ledger,
    ]
    .into_iter()
    .enumerate()
    {
        let root = TestRoot::new(&format!("terminal-tamper-{target:?}"));
        let keys = MemoryKeyStore::new();
        let clock = Arc::new(AtomicU64::new(NOW_MS));
        let store = open_store(&root, &keys, clock.clone()).await;
        let (binding, data_cert) = make_active(&store).await;
        let seed = 0xc0_u8.wrapping_add(u8::try_from(index).expect("small tamper index"));
        let route = PairRouteId::from_bytes([seed; 16]);
        let (pairing_id, _) = prepare_unused_pairing(
            &store,
            &binding,
            &data_cert,
            route,
            seed.wrapping_add(1),
            seed.wrapping_add(2),
            &format!("tamper-{index}"),
        )
        .await;
        store
            .terminalize_pairing(pairing_id, PairingTerminalAction::Cancel)
            .await
            .expect("terminalize tamper fixture");
        store.shutdown().await.expect("shutdown tamper fixture");
        apply_offline_tamper(&root.database(), target);
        let before = artifact_bytes(&root.database());
        let error = RuntimeStoreHandle::open(
            config(&root, clock.clone()),
            load_or_create_storage_kek(&keys, &root.database()).expect("reload test StorageKEK"),
        )
        .await
        .expect_err("tampered terminal state must fail full open");
        assert!(matches!(error, RuntimeStoreError::UnknownOrCorruptSchema));
        assert_eq!(artifact_bytes(&root.database()), before);
    }
}

struct StablePairingIdSource {
    ids: HashMap<RuntimeIdKind, u8>,
    outbox_counter: u8,
}

impl StablePairingIdSource {
    fn new() -> Self {
        Self {
            ids: HashMap::from([
                (RuntimeIdKind::Database, 0xd1),
                (RuntimeIdKind::Pairing, 0xd2),
            ]),
            outbox_counter: 0xd3,
        }
    }
}

impl RuntimeIdSource for StablePairingIdSource {
    fn next_id(&mut self, kind: RuntimeIdKind) -> Result<RuntimeId, RuntimeIdError> {
        let seed = if kind == RuntimeIdKind::RemoteOutbox {
            let current = self.outbox_counter;
            self.outbox_counter = self.outbox_counter.wrapping_add(1);
            current
        } else {
            *self
                .ids
                .get(&kind)
                .ok_or(RuntimeIdError::EntropyUnavailable { kind })?
        };
        RuntimeId::from_bytes(kind, [seed; 16])
    }
}

#[tokio::test]
async fn receipt_tombstone_prevents_pairing_id_reuse() {
    let root = TestRoot::new("pairing-id-tombstone");
    let keys = MemoryKeyStore::new();
    let clock = Arc::new(AtomicU64::new(NOW_MS));
    let store = RuntimeStoreHandle::open(
        config(&root, clock.clone()).with_id_source(StablePairingIdSource::new()),
        load_or_create_storage_kek(&keys, &root.database()).expect("load test StorageKEK"),
    )
    .await
    .expect("open deterministic-id store");
    let (binding, data_cert) = make_active(&store).await;
    let first_route = PairRouteId::from_bytes([0xd4; 16]);
    let (pairing_id, _) = prepare_unused_pairing(
        &store,
        &binding,
        &data_cert,
        first_route,
        0xd5,
        0xd6,
        "first-fixed-id",
    )
    .await;
    store
        .terminalize_pairing(pairing_id, PairingTerminalAction::Cancel)
        .await
        .expect("terminalize fixed-id pairing");
    store
        .acknowledge_pair_route_close(
            pairing_id,
            closed_terminal(first_route, PairRouteCloseOutcome::Closed),
        )
        .await
        .expect("scrub fixed-id pairing secret");
    let next_route = PairRouteId::from_bytes([0xd7; 16]);
    let next_invite = canonical_invite_with(
        0xd8,
        0xd9,
        next_route,
        &binding,
        &data_cert,
        NOW_MS + 300_000,
        "id-reuse-must-fail",
    );
    let error = store
        .prepare_pairing_invite(PreparePairingInvite::new(
            owner(),
            "second-fixed-id".to_owned(),
            SecretBytes::new(next_invite),
            private_key(0xd9),
        ))
        .await
        .expect_err("receipt tombstone must prevent fixed pairing ID reuse");
    assert!(
        matches!(
            &error,
            RuntimeStoreError::IdGeneration(RuntimeIdError::CollisionExhausted {
                kind: RuntimeIdKind::Pairing,
                ..
            })
        ),
        "unexpected fixed-ID failure: {error:?}"
    );
    store.shutdown().await.expect("shutdown fixed-id store");
}
