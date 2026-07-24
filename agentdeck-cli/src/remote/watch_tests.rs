use std::collections::{BTreeSet, VecDeque};
use std::future::Future;
use std::io;
use std::pin::Pin;
use std::sync::{Arc, Mutex};

use agentdeck_crypto::rand_core::{Infallible, TryCryptoRng, TryRng};
use agentdeck_protocol::runtime::identity::{EventId, StreamGeneration, TransferId};
use agentdeck_protocol::runtime::{
    ConversationConfigurationState, ConversationId, ConversationSnapshot, RuntimeEvent,
    RuntimeEventBody, RuntimeFailure, RuntimeInnerCursor, RuntimeStreamItem, RuntimeSyncComplete,
    SnapshotItem, StreamCursor, SubscriptionReceipt,
};
use agentdeck_protocol::{AgentKind, SessionCapabilities, VendorCapabilities};
use async_trait::async_trait;
use base64::{Engine as _, engine::general_purpose::STANDARD};
use tokio::sync::oneshot;

use super::paired_machine::{PairedMachineIdentity, PairedPromotionError};
use super::runtime::{
    MAX_REMOTE_SUBSCRIPTION_REDUCER_RETAINED_BYTES, RemoteRuntimeError, RemoteRuntimeInterruptible,
    RemoteStreamFrameOutcome, RemoteSubscriptionBootstrapItem, RemoteSubscriptionReducer,
};
use super::selector::PersistentMachineSelector;
use super::watch::{
    ConnectedWatchRuntime, MAX_WATCH_BOOTSTRAP_BYTES, MAX_WATCH_BOOTSTRAP_RECORDS,
    PersistentRemoteWatchControl, PersistentRemoteWatchError, PersistentRemoteWatchExit,
    PersistentRemoteWatchRecord, WatchBootstrap, WatchReducer, WatchRuntimeConnectOutcome,
    WatchStreamOutcome, WatchSubscribeOutcome, checked_bootstrap_output_budget, execute_with,
};

#[derive(Default)]
struct DeterministicRng(u8);

impl TryRng for DeterministicRng {
    type Error = Infallible;

    fn try_next_u32(&mut self) -> Result<u32, Self::Error> {
        let mut bytes = [0_u8; 4];
        self.try_fill_bytes(&mut bytes)?;
        Ok(u32::from_le_bytes(bytes))
    }

    fn try_next_u64(&mut self) -> Result<u64, Self::Error> {
        let mut bytes = [0_u8; 8];
        self.try_fill_bytes(&mut bytes)?;
        Ok(u64::from_le_bytes(bytes))
    }

    fn try_fill_bytes(&mut self, dest: &mut [u8]) -> Result<(), Self::Error> {
        for byte in dest {
            self.0 = self.0.wrapping_add(1);
            *byte = self.0;
        }
        Ok(())
    }
}

impl TryCryptoRng for DeterministicRng {}

struct FakeRuntime {
    bootstrap_items: Vec<RemoteSubscriptionBootstrapItem>,
    sync_complete: RuntimeSyncComplete,
    subscribe_revocation: Option<&'static str>,
    restart_cursor: Option<RuntimeInnerCursor>,
    frames: VecDeque<Result<WatchStreamOutcome<&'static str>, RemoteRuntimeError>>,
    signal_after_frame: Option<oneshot::Sender<()>>,
    observed_cursors: Arc<Mutex<Vec<RuntimeInnerCursor>>>,
    events: Arc<Mutex<Vec<&'static str>>>,
}

#[async_trait(?Send)]
impl ConnectedWatchRuntime<DeterministicRng> for FakeRuntime {
    type Revocation = &'static str;

    fn subscription_restart_cursor(
        &self,
        fresh_target: RuntimeInnerCursor,
    ) -> Result<RuntimeInnerCursor, RemoteRuntimeError> {
        Ok(self.restart_cursor.clone().unwrap_or(fresh_target))
    }

    async fn subscribe<C>(
        &mut self,
        cursor: RuntimeInnerCursor,
        reducer: &mut WatchReducer,
        _rng: &mut DeterministicRng,
        _cancel: Pin<&mut C>,
    ) -> Result<
        RemoteRuntimeInterruptible<WatchSubscribeOutcome<Self::Revocation>, io::Result<()>>,
        RemoteRuntimeError,
    >
    where
        C: Future<Output = io::Result<()>> + ?Sized,
    {
        self.events
            .lock()
            .expect("event recorder")
            .push("subscribe");
        self.observed_cursors
            .lock()
            .expect("cursor recorder")
            .push(cursor);
        if let Some(terminal) = self.subscribe_revocation.take() {
            return Ok(RemoteRuntimeInterruptible::Completed(
                WatchSubscribeOutcome::RevocationCommitted(terminal),
            ));
        }
        for item in &self.bootstrap_items {
            reducer.apply(item)?;
        }
        self.events
            .lock()
            .expect("event recorder")
            .push("bootstrap_commit");
        Ok(RemoteRuntimeInterruptible::Completed(
            WatchSubscribeOutcome::Bootstrapped(WatchBootstrap::new(
                true,
                SubscriptionReceipt::Subscribed {
                    stream_generation: self.sync_complete.stream_generation.clone(),
                },
                self.sync_complete.clone(),
            )),
        ))
    }

    async fn receive<C>(
        &mut self,
        reducer: &mut WatchReducer,
        mut cancel: Pin<&mut C>,
    ) -> Result<
        RemoteRuntimeInterruptible<WatchStreamOutcome<Self::Revocation>, io::Result<()>>,
        RemoteRuntimeError,
    >
    where
        C: Future<Output = io::Result<()>> + ?Sized,
    {
        self.events.lock().expect("event recorder").push("receive");
        let Some(result) = self.frames.pop_front() else {
            return Ok(RemoteRuntimeInterruptible::Interrupted(
                cancel.as_mut().await,
            ));
        };
        if let Ok(WatchStreamOutcome::Runtime(RemoteStreamFrameOutcome::Applied(item))) = &result {
            reducer.apply_live(item)?;
            self.events
                .lock()
                .expect("event recorder")
                .push("durable_apply");
        }
        if let Some(signal) = self.signal_after_frame.take() {
            let _ = signal.send(());
            tokio::task::yield_now().await;
            self.events.lock().expect("event recorder").push("ack");
        }
        let interrupt = tokio::select! {
            biased;
            signal = cancel.as_mut() => Some(signal),
            () = std::future::ready(()) => None,
        };
        match (result, interrupt) {
            (Ok(output), Some(interrupt)) => {
                Ok(RemoteRuntimeInterruptible::CompletedAndInterrupted { output, interrupt })
            }
            (Ok(output), None) => Ok(RemoteRuntimeInterruptible::Completed(output)),
            (Err(error), Some(interrupt)) => {
                Ok(RemoteRuntimeInterruptible::FailedAndInterrupted { error, interrupt })
            }
            (Err(error), None) => Err(error),
        }
    }

    async fn commit_live_revocation(
        self,
        terminal: Self::Revocation,
    ) -> Result<(), RemoteRuntimeError> {
        assert_eq!(terminal, "verified-revocation");
        self.events
            .lock()
            .expect("event recorder")
            .push("revocation_shutdown");
        tokio::task::yield_now().await;
        self.events
            .lock()
            .expect("event recorder")
            .push("revocation_cleanup");
        Ok(())
    }

    async fn shutdown(self) {
        self.events.lock().expect("event recorder").push("shutdown");
    }
}

impl Drop for FakeRuntime {
    fn drop(&mut self) {
        self.events
            .lock()
            .expect("event recorder")
            .push("runtime_drop");
    }
}

struct ConnectDropRecorder {
    events: Arc<Mutex<Vec<&'static str>>>,
}

impl Drop for ConnectDropRecorder {
    fn drop(&mut self) {
        self.events
            .lock()
            .expect("event recorder")
            .push("connect_drop");
    }
}

fn selector() -> PersistentMachineSelector {
    PersistentMachineSelector::parse(&STANDARD.encode([0x11; 32]), &STANDARD.encode([0x22; 16]))
        .expect("canonical selector")
}

fn conversation_id() -> ConversationId {
    ConversationId::new("11111111-1111-1111-1111-111111111111")
}

fn generation() -> StreamGeneration {
    StreamGeneration::new("22222222-2222-2222-2222-222222222222")
}

fn capabilities() -> SessionCapabilities {
    SessionCapabilities {
        agent_kind: AgentKind::Codex,
        agent_version: "watch-fixture".to_owned(),
        features: BTreeSet::new(),
        vendor: VendorCapabilities::Codex(Default::default()),
    }
}

fn snapshot(base: StreamCursor) -> ConversationSnapshot {
    ConversationSnapshot::new(
        conversation_id(),
        base,
        ConversationConfigurationState::new(0, None).expect("unconfigured state"),
        vec![SnapshotItem::capabilities(capabilities())],
    )
    .expect("valid conversation snapshot")
}

fn sync_complete(cursor: StreamCursor) -> RuntimeSyncComplete {
    RuntimeSyncComplete {
        stream_generation: generation(),
        stream_cursor: StreamCursor::At(9),
        inner_cursor: RuntimeInnerCursor::Conversation {
            conversation_id: conversation_id(),
            cursor,
        },
        key_directory_revision: 7,
    }
}

fn event(sequence: u64) -> RuntimeStreamItem {
    RuntimeStreamItem::Event(
        RuntimeEvent::new(
            conversation_id(),
            EventId::new(format!("event-{sequence}")),
            sequence,
            None,
            None,
            None,
            RuntimeEventBody::Error {
                failure: RuntimeFailure::new("daemon.fixture", format!("event {sequence}")),
            },
        )
        .expect("valid event"),
    )
}

fn fake_runtime(
    frames: Vec<Result<WatchStreamOutcome<&'static str>, RemoteRuntimeError>>,
    events: Arc<Mutex<Vec<&'static str>>>,
) -> FakeRuntime {
    FakeRuntime {
        bootstrap_items: Vec::new(),
        sync_complete: sync_complete(StreamCursor::BeforeFirst),
        subscribe_revocation: None,
        restart_cursor: None,
        frames: frames.into(),
        signal_after_frame: None,
        observed_cursors: Arc::new(Mutex::new(Vec::new())),
        events,
    }
}

fn record_kind(record: &PersistentRemoteWatchRecord) -> &'static str {
    match record {
        PersistentRemoteWatchRecord::BootstrapSnapshot { .. } => "snapshot",
        PersistentRemoteWatchRecord::BootstrapBackfill { .. } => "backfill",
        PersistentRemoteWatchRecord::Synchronized { .. } => "sync",
        PersistentRemoteWatchRecord::Event { .. } => "event",
        PersistentRemoteWatchRecord::Control { control } => match control {
            PersistentRemoteWatchControl::TransferBuffered { .. } => "transfer",
            PersistentRemoteWatchControl::Gap { .. } => "gap",
            PersistentRemoteWatchControl::ReplayComplete { .. } => "replay",
            PersistentRemoteWatchControl::TransferBootstrapRequired { .. } => "marker",
            PersistentRemoteWatchControl::KeySyncRouteAccepted { .. } => "routeAcceptedControl",
            _ => "control",
        },
        PersistentRemoteWatchRecord::Stopped => "stopped",
        PersistentRemoteWatchRecord::Revoked => "revoked",
    }
}

#[tokio::test]
async fn exact_before_first_target_drains_only_after_bootstrap_commit_and_shutdown() {
    let events = Arc::new(Mutex::new(Vec::new()));
    let observed_cursors = Arc::new(Mutex::new(Vec::new()));
    let (signal_tx, signal_rx) = oneshot::channel();
    let mut runtime = fake_runtime(
        vec![Ok(WatchStreamOutcome::Runtime(
            RemoteStreamFrameOutcome::Applied(Box::new(event(0))),
        ))],
        Arc::clone(&events),
    );
    runtime.bootstrap_items = vec![RemoteSubscriptionBootstrapItem::ConversationSnapshot(
        snapshot(StreamCursor::BeforeFirst),
    )];
    runtime.signal_after_frame = Some(signal_tx);
    runtime.observed_cursors = Arc::clone(&observed_cursors);
    let expected_identity = selector().identity();
    let recover_events = Arc::clone(&events);
    let open_events = Arc::clone(&events);
    let connect_events = Arc::clone(&events);
    let emit_events = Arc::clone(&events);
    let records = Arc::new(Mutex::new(Vec::new()));
    let emitted_records = Arc::clone(&records);
    let mut emit = move |record: PersistentRemoteWatchRecord| {
        emit_events.lock().expect("event recorder").push("emit");
        emitted_records
            .lock()
            .expect("record recorder")
            .push(record_kind(&record));
        Ok(())
    };

    let exit = execute_with(
        selector(),
        conversation_id(),
        &mut DeterministicRng::default(),
        async move {
            signal_rx
                .await
                .map_err(|_| io::Error::other("signal sender dropped"))
        },
        &mut emit,
        move || {
            recover_events
                .lock()
                .expect("event recorder")
                .push("recover");
            Ok(())
        },
        move |(), identity| {
            open_events
                .lock()
                .expect("event recorder")
                .push("open_exact");
            assert_eq!(identity, expected_identity);
            Ok(identity)
        },
        move |identity: PairedMachineIdentity| async move {
            connect_events
                .lock()
                .expect("event recorder")
                .push("connect");
            assert_eq!(identity, expected_identity);
            Ok(WatchRuntimeConnectOutcome::Connected(runtime))
        },
    )
    .await
    .expect("signal-driven watch shutdown");

    assert_eq!(exit, PersistentRemoteWatchExit::Interrupted);
    assert_eq!(
        *observed_cursors.lock().expect("cursor recorder"),
        [RuntimeInnerCursor::Conversation {
            conversation_id: conversation_id(),
            cursor: StreamCursor::BeforeFirst,
        }]
    );
    drop(emit);
    assert_eq!(
        *records.lock().expect("record recorder"),
        ["snapshot", "sync", "event", "stopped"]
    );
    let observed = events.lock().expect("event recorder");
    let commit = observed
        .iter()
        .position(|event| *event == "bootstrap_commit")
        .unwrap();
    let first_emit = observed.iter().position(|event| *event == "emit").unwrap();
    let ack = observed.iter().position(|event| *event == "ack").unwrap();
    let event_emit = observed
        .iter()
        .enumerate()
        .find_map(|(index, event)| (index > ack && *event == "emit").then_some(index))
        .unwrap();
    let shutdown = observed
        .iter()
        .position(|event| *event == "shutdown")
        .unwrap();
    let stopped_emit = observed.iter().rposition(|event| *event == "emit").unwrap();
    assert!(commit < first_emit);
    assert!(ack < event_emit);
    assert!(shutdown < stopped_emit);
}

#[tokio::test]
async fn latched_signal_stops_after_completed_frame_without_draining_backlog() {
    let events = Arc::new(Mutex::new(Vec::new()));
    let (signal_tx, signal_rx) = oneshot::channel();
    let mut runtime = fake_runtime(
        vec![
            Ok(WatchStreamOutcome::Runtime(
                RemoteStreamFrameOutcome::Applied(Box::new(event(0))),
            )),
            Ok(WatchStreamOutcome::Runtime(
                RemoteStreamFrameOutcome::Applied(Box::new(event(1))),
            )),
        ],
        Arc::clone(&events),
    );
    runtime.signal_after_frame = Some(signal_tx);
    let mut records = Vec::new();
    let mut emit = |record| {
        records.push(record_kind(&record));
        Ok(())
    };

    let exit = execute_with(
        selector(),
        conversation_id(),
        &mut DeterministicRng::default(),
        async move {
            signal_rx
                .await
                .map_err(|_| io::Error::other("signal sender dropped"))
        },
        &mut emit,
        || Ok(()),
        |(), identity| Ok(identity),
        |_identity| async move { Ok(WatchRuntimeConnectOutcome::Connected(runtime)) },
    )
    .await
    .expect("latched signal stops after current frame terminal");

    assert_eq!(exit, PersistentRemoteWatchExit::Interrupted);
    assert_eq!(records, ["sync", "event", "stopped"]);
    let observed = events.lock().expect("event recorder");
    assert_eq!(
        observed
            .iter()
            .filter(|event| **event == "durable_apply")
            .count(),
        1,
        "latched signal must bound a continuously ready backlog"
    );
    let ack = observed.iter().position(|event| *event == "ack").unwrap();
    let shutdown = observed
        .iter()
        .position(|event| *event == "shutdown")
        .unwrap();
    assert!(ack < shutdown);
}

#[tokio::test]
async fn completed_transfer_control_precedes_latched_stop_without_draining_backlog() {
    let events = Arc::new(Mutex::new(Vec::new()));
    let (signal_tx, signal_rx) = oneshot::channel();
    let mut runtime = fake_runtime(
        vec![
            Ok(WatchStreamOutcome::Runtime(
                RemoteStreamFrameOutcome::TransferBuffered {
                    transfer_id: TransferId::new("transfer-current"),
                    received_parts: 1,
                    part_count: 2,
                },
            )),
            Ok(WatchStreamOutcome::Runtime(
                RemoteStreamFrameOutcome::TransferAlreadyComplete {
                    transfer_id: TransferId::new("transfer-backlog"),
                },
            )),
        ],
        Arc::clone(&events),
    );
    runtime.signal_after_frame = Some(signal_tx);
    let mut records = Vec::new();
    let mut emit = |record| {
        records.push(record_kind(&record));
        Ok(())
    };

    let exit = execute_with(
        selector(),
        conversation_id(),
        &mut DeterministicRng::default(),
        async move {
            signal_rx
                .await
                .map_err(|_| io::Error::other("signal sender dropped"))
        },
        &mut emit,
        || Ok(()),
        |(), identity| Ok(identity),
        |_identity| async move { Ok(WatchRuntimeConnectOutcome::Connected(runtime)) },
    )
    .await
    .expect("latched signal preserves the completed transfer terminal");

    assert_eq!(exit, PersistentRemoteWatchExit::Interrupted);
    assert_eq!(records, ["sync", "transfer", "stopped"]);
    let observed = events.lock().expect("event recorder");
    assert_eq!(
        observed.iter().filter(|event| **event == "receive").count(),
        1,
        "a latched signal must not consume the next transfer frame",
    );
    let ack = observed.iter().position(|event| *event == "ack").unwrap();
    let shutdown = observed
        .iter()
        .position(|event| *event == "shutdown")
        .unwrap();
    assert!(ack < shutdown);
}

#[tokio::test]
async fn durable_transfer_marker_precedes_latched_stop_without_resubscribe() {
    let events = Arc::new(Mutex::new(Vec::new()));
    let (signal_tx, signal_rx) = oneshot::channel();
    let mut runtime = fake_runtime(
        vec![Err(RemoteRuntimeError::TransferBootstrapRequired(
            super::transfer_state::DurableTransferBootstrapError::Expired,
        ))],
        Arc::clone(&events),
    );
    runtime.signal_after_frame = Some(signal_tx);
    let mut records = Vec::new();
    let mut emit = |record| {
        records.push(record_kind(&record));
        Ok(())
    };

    let exit = execute_with(
        selector(),
        conversation_id(),
        &mut DeterministicRng::default(),
        async move {
            signal_rx
                .await
                .map_err(|_| io::Error::other("signal sender dropped"))
        },
        &mut emit,
        || Ok(()),
        |(), identity| Ok(identity),
        |_identity| async move { Ok(WatchRuntimeConnectOutcome::Connected(runtime)) },
    )
    .await
    .expect("durable transfer marker must remain observable beside the latched signal");

    assert_eq!(exit, PersistentRemoteWatchExit::Interrupted);
    assert_eq!(records, ["sync", "marker", "stopped"]);
    let observed = events.lock().expect("event recorder");
    assert_eq!(
        observed
            .iter()
            .filter(|event| **event == "subscribe")
            .count(),
        1,
        "a terminal marker plus signal must not start a replacement subscription",
    );
    let marker_terminal = observed.iter().position(|event| *event == "ack").unwrap();
    let shutdown = observed
        .iter()
        .position(|event| *event == "shutdown")
        .unwrap();
    assert!(marker_terminal < shutdown);
}

#[tokio::test]
async fn restart_cursor_from_exact_pending_is_used_for_empty_reducer_retry() {
    let events = Arc::new(Mutex::new(Vec::new()));
    let observed_cursors = Arc::new(Mutex::new(Vec::new()));
    let mut runtime = fake_runtime(
        vec![Ok(WatchStreamOutcome::RevocationCommitted(
            "verified-revocation",
        ))],
        events,
    );
    let restart = RuntimeInnerCursor::Conversation {
        conversation_id: conversation_id(),
        cursor: StreamCursor::At(4),
    };
    runtime.restart_cursor = Some(restart.clone());
    runtime.sync_complete = sync_complete(StreamCursor::At(4));
    runtime.observed_cursors = Arc::clone(&observed_cursors);
    let mut emit = |_record| Ok(());

    let exit = execute_with(
        selector(),
        conversation_id(),
        &mut DeterministicRng::default(),
        std::future::pending::<io::Result<()>>(),
        &mut emit,
        || Ok(()),
        |(), identity| Ok(identity),
        |_identity| async move { Ok(WatchRuntimeConnectOutcome::Connected(runtime)) },
    )
    .await
    .expect("exact pending subscribe restart");

    assert_eq!(exit, PersistentRemoteWatchExit::Revoked);
    assert_eq!(*observed_cursors.lock().unwrap(), [restart]);
}

#[tokio::test]
async fn bootstrap_and_live_revocation_cleanup_precedes_revoked_output() {
    for during_bootstrap in [true, false] {
        let events = Arc::new(Mutex::new(Vec::new()));
        let mut runtime = fake_runtime(
            if during_bootstrap {
                Vec::new()
            } else {
                vec![Ok(WatchStreamOutcome::RevocationCommitted(
                    "verified-revocation",
                ))]
            },
            Arc::clone(&events),
        );
        runtime.subscribe_revocation = during_bootstrap.then_some("verified-revocation");
        let emit_events = Arc::clone(&events);
        let records = Arc::new(Mutex::new(Vec::new()));
        let emitted_records = Arc::clone(&records);
        let mut emit = move |record: PersistentRemoteWatchRecord| {
            emit_events.lock().expect("event recorder").push("emit");
            emitted_records
                .lock()
                .expect("record recorder")
                .push(record_kind(&record));
            Ok(())
        };
        let exit = execute_with(
            selector(),
            conversation_id(),
            &mut DeterministicRng::default(),
            std::future::pending::<io::Result<()>>(),
            &mut emit,
            || Ok(()),
            |(), identity| Ok(identity),
            |_identity| async move { Ok(WatchRuntimeConnectOutcome::Connected(runtime)) },
        )
        .await
        .expect("authenticated revocation cleanup");
        assert_eq!(exit, PersistentRemoteWatchExit::Revoked);
        drop(emit);
        assert_eq!(
            records.lock().expect("record recorder").last(),
            Some(&"revoked")
        );
        let observed = events.lock().expect("event recorder");
        let cleanup = observed
            .iter()
            .position(|event| *event == "revocation_cleanup")
            .unwrap();
        let revoked_emit = observed.iter().rposition(|event| *event == "emit").unwrap();
        assert!(cleanup < revoked_emit);
        assert!(!observed.contains(&"shutdown"));
    }
}

#[tokio::test]
async fn transfer_gap_replay_marker_and_transport_controls_are_observable() {
    let events = Arc::new(Mutex::new(Vec::new()));
    let runtime = fake_runtime(
        vec![
            Ok(WatchStreamOutcome::Runtime(
                RemoteStreamFrameOutcome::TransferBuffered {
                    transfer_id: TransferId::new("transfer-1"),
                    received_parts: 1,
                    part_count: 2,
                },
            )),
            Ok(WatchStreamOutcome::Runtime(RemoteStreamFrameOutcome::Gap {
                need_stream_seq: 10,
                oldest_stream_seq: 12,
            })),
            Ok(WatchStreamOutcome::Runtime(
                RemoteStreamFrameOutcome::ReplayComplete {
                    current_cursor: StreamCursor::At(19),
                },
            )),
            Err(RemoteRuntimeError::TransferBootstrapRequired(
                super::transfer_state::DurableTransferBootstrapError::Expired,
            )),
            Ok(WatchStreamOutcome::Runtime(
                RemoteStreamFrameOutcome::KeySyncRouteAccepted { attempt: 1 },
            )),
            Ok(WatchStreamOutcome::RevocationCommitted(
                "verified-revocation",
            )),
        ],
        events,
    );
    let mut records = Vec::new();
    let mut emit = |record: PersistentRemoteWatchRecord| {
        records.push(record_kind(&record));
        Ok(())
    };
    let exit = execute_with(
        selector(),
        conversation_id(),
        &mut DeterministicRng::default(),
        std::future::pending::<io::Result<()>>(),
        &mut emit,
        || Ok(()),
        |(), identity| Ok(identity),
        |_identity| async move { Ok(WatchRuntimeConnectOutcome::Connected(runtime)) },
    )
    .await
    .expect("control stream ends at authenticated revoke");
    assert_eq!(exit, PersistentRemoteWatchExit::Revoked);
    assert!(records.contains(&"transfer"));
    assert!(records.contains(&"gap"));
    assert!(records.contains(&"replay"));
    assert!(records.contains(&"marker"));
    assert!(records.contains(&"routeAcceptedControl"));
}

#[tokio::test]
async fn eof_and_output_failure_are_typed_and_shutdown_runtime() {
    let eof_events = Arc::new(Mutex::new(Vec::new()));
    let runtime = fake_runtime(
        vec![Err(RemoteRuntimeError::OutcomeUnknown)],
        Arc::clone(&eof_events),
    );
    let mut emit = |_record| Ok(());
    let error = execute_with(
        selector(),
        conversation_id(),
        &mut DeterministicRng::default(),
        std::future::pending::<io::Result<()>>(),
        &mut emit,
        || Ok(()),
        |(), identity| Ok(identity),
        |_identity| async move { Ok(WatchRuntimeConnectOutcome::Connected(runtime)) },
    )
    .await
    .expect_err("EOF cannot be shell success");
    assert_eq!(error.code(), "remote.runtime.outcome_unknown");
    assert!(
        eof_events
            .lock()
            .expect("event recorder")
            .contains(&"shutdown")
    );

    let output_events = Arc::new(Mutex::new(Vec::new()));
    let mut runtime = fake_runtime(Vec::new(), Arc::clone(&output_events));
    runtime.bootstrap_items = vec![RemoteSubscriptionBootstrapItem::ConversationSnapshot(
        snapshot(StreamCursor::BeforeFirst),
    )];
    let mut emit = |_record| Err(io::Error::new(io::ErrorKind::BrokenPipe, "fixture"));
    let error = execute_with(
        selector(),
        conversation_id(),
        &mut DeterministicRng::default(),
        std::future::pending::<io::Result<()>>(),
        &mut emit,
        || Ok(()),
        |(), identity| Ok(identity),
        |_identity| async move { Ok(WatchRuntimeConnectOutcome::Connected(runtime)) },
    )
    .await
    .expect_err("output failure terminates watch");
    assert_eq!(error.code(), "remote.watch.output_failed");
    assert!(
        output_events
            .lock()
            .expect("event recorder")
            .contains(&"shutdown")
    );
}

#[tokio::test]
async fn recovery_fails_closed_and_committed_handshake_revocation_is_success() {
    let calls = Arc::new(Mutex::new(0_usize));
    let connect_calls = Arc::clone(&calls);
    let mut emit = |_record| Ok(());
    let error = execute_with::<_, (), (), FakeRuntime, _, _, _, _, _, _>(
        selector(),
        conversation_id(),
        &mut DeterministicRng::default(),
        std::future::pending::<io::Result<()>>(),
        &mut emit,
        || {
            Err(PersistentRemoteWatchError::Paired(
                PairedPromotionError::InvalidState,
            ))
        },
        |(), _| Ok(()),
        move |()| async move {
            *connect_calls.lock().expect("connector calls") += 1;
            unreachable!("recovery failure cannot connect")
        },
    )
    .await
    .expect_err("recovery must fail closed");
    assert_eq!(error.code(), "remote.pairing.paired_invalid");
    assert_eq!(*calls.lock().expect("connector calls"), 0);

    let mut records = Vec::new();
    let mut emit = |record| {
        records.push(record_kind(&record));
        Ok(())
    };
    let exit = execute_with::<_, (), PairedMachineIdentity, FakeRuntime, _, _, _, _, _, _>(
        selector(),
        conversation_id(),
        &mut DeterministicRng::default(),
        std::future::pending::<io::Result<()>>(),
        &mut emit,
        || Ok(()),
        |(), identity| Ok(identity),
        |_identity| async { Ok(WatchRuntimeConnectOutcome::<FakeRuntime>::Revoked) },
    )
    .await
    .expect("verified handshake revoke is already cleaned up");
    assert_eq!(exit, PersistentRemoteWatchExit::Revoked);
    assert_eq!(records, ["revoked"]);
}

#[tokio::test]
async fn connect_result_precedes_signal_and_preconnect_stop_follows_future_drop() {
    let mut records = Vec::new();
    let mut emit = |record| {
        records.push(record_kind(&record));
        Ok(())
    };
    let exit = execute_with::<_, (), PairedMachineIdentity, FakeRuntime, _, _, _, _, _, _>(
        selector(),
        conversation_id(),
        &mut DeterministicRng::default(),
        std::future::ready(Ok(())),
        &mut emit,
        || Ok(()),
        |(), identity| Ok(identity),
        |_identity| async { Ok(WatchRuntimeConnectOutcome::<FakeRuntime>::Revoked) },
    )
    .await
    .expect("simultaneous cleaned-up revoke wins over signal");
    assert_eq!(exit, PersistentRemoteWatchExit::Revoked);
    assert_eq!(records, ["revoked"]);

    let events = Arc::new(Mutex::new(Vec::new()));
    let connect_events = Arc::clone(&events);
    let emit_events = Arc::clone(&events);
    let mut records = Vec::new();
    let mut emit = |record| {
        emit_events.lock().unwrap().push("emit");
        records.push(record_kind(&record));
        Ok(())
    };
    let exit = execute_with::<_, (), PairedMachineIdentity, FakeRuntime, _, _, _, _, _, _>(
        selector(),
        conversation_id(),
        &mut DeterministicRng::default(),
        std::future::ready(Ok(())),
        &mut emit,
        || Ok(()),
        |(), identity| Ok(identity),
        move |_identity| async move {
            let _owned_connection = ConnectDropRecorder {
                events: connect_events,
            };
            std::future::pending::<
                Result<WatchRuntimeConnectOutcome<FakeRuntime>, PersistentRemoteWatchError>,
            >()
            .await
        },
    )
    .await
    .expect("pre-connect signal is a clean stop");
    assert_eq!(exit, PersistentRemoteWatchExit::Interrupted);
    assert_eq!(records, ["stopped"]);
    assert_eq!(*events.lock().unwrap(), ["connect_drop", "emit"]);
}

#[tokio::test]
async fn simultaneous_connected_result_and_signal_stop_before_subscribe() {
    let events = Arc::new(Mutex::new(Vec::new()));
    let runtime = fake_runtime(Vec::new(), Arc::clone(&events));
    let mut records = Vec::new();
    let mut emit = |record| {
        records.push(record_kind(&record));
        Ok(())
    };

    let exit = execute_with(
        selector(),
        conversation_id(),
        &mut DeterministicRng::default(),
        std::future::ready(Ok(())),
        &mut emit,
        || Ok(()),
        |(), identity| Ok(identity),
        |_identity| async move { Ok(WatchRuntimeConnectOutcome::Connected(runtime)) },
    )
    .await
    .expect("a ready signal after connect must stop before subscription side effects");

    assert_eq!(exit, PersistentRemoteWatchExit::Interrupted);
    assert_eq!(records, ["stopped"]);
    assert_eq!(
        *events.lock().expect("event recorder"),
        ["shutdown", "runtime_drop"]
    );
}

#[test]
fn reducer_and_bootstrap_budget_reject_cross_target_discontinuity_and_growth() {
    assert_eq!(
        checked_bootstrap_output_budget(
            MAX_WATCH_BOOTSTRAP_RECORDS - 1,
            MAX_WATCH_BOOTSTRAP_BYTES - 1,
            1,
        ),
        Ok((MAX_WATCH_BOOTSTRAP_RECORDS, MAX_WATCH_BOOTSTRAP_BYTES))
    );
    assert!(checked_bootstrap_output_budget(MAX_WATCH_BOOTSTRAP_RECORDS, 0, 1).is_err());
    assert!(checked_bootstrap_output_budget(0, MAX_WATCH_BOOTSTRAP_BYTES, 1).is_err());

    let near_cap = WatchReducer::new(conversation_id())
        .checked_retain_budget(MAX_WATCH_BOOTSTRAP_BYTES)
        .expect("63 MiB payload plus derived structural overhead stays under 64 MiB");
    assert!(near_cap.2 <= MAX_REMOTE_SUBSCRIPTION_REDUCER_RETAINED_BYTES);
    assert!(
        WatchReducer::new(conversation_id())
            .checked_retain_budget(MAX_WATCH_BOOTSTRAP_BYTES + 1)
            .is_err()
    );

    let canonical_snapshot = snapshot(StreamCursor::BeforeFirst);
    let canonical_bytes = serde_json::to_vec(&canonical_snapshot).unwrap();
    let mut frozen_reducer = WatchReducer::new(conversation_id());
    frozen_reducer
        .apply(&RemoteSubscriptionBootstrapItem::ConversationSnapshot(
            canonical_snapshot,
        ))
        .expect("freeze canonical snapshot");
    let frozen_records = frozen_reducer.take_bootstrap_records();
    let [PersistentRemoteWatchRecord::BootstrapSnapshot { snapshot: frozen }] =
        frozen_records.as_slice()
    else {
        panic!("expected one frozen snapshot")
    };
    assert_eq!(frozen.canonical_json(), canonical_bytes);

    let mut reducer = WatchReducer::new(conversation_id());
    let other = ConversationSnapshot::new(
        ConversationId::new("33333333-3333-3333-3333-333333333333"),
        StreamCursor::BeforeFirst,
        ConversationConfigurationState::new(0, None).expect("unconfigured state"),
        vec![SnapshotItem::capabilities(capabilities())],
    )
    .expect("valid other-target snapshot");
    assert!(matches!(
        reducer.apply(&RemoteSubscriptionBootstrapItem::ConversationSnapshot(
            other
        )),
        Err(RemoteRuntimeError::InvalidReply(_))
    ));
    assert!(matches!(
        reducer.apply_live(&event(1)),
        Err(RemoteRuntimeError::InvalidReply(_))
    ));
    assert_eq!(
        reducer.inner_cursor(),
        &RuntimeInnerCursor::Conversation {
            conversation_id: conversation_id(),
            cursor: StreamCursor::BeforeFirst,
        }
    );
}
