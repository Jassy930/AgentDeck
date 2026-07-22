//! Durable publication dispatcher 到唯一 MachineLink publication handle 的窄适配层。

use std::sync::Arc;
use std::time::Duration;

use agentdeck_protocol::relay_v2::{StreamGenerationId, StreamRouteId};
use async_trait::async_trait;
use tokio::sync::{mpsc, oneshot, watch};
use tokio::task::JoinHandle;

use crate::runtime::publication::{
    PublicationCommitReceipt, PublicationDispatchError, PublicationDispatchKey,
    PublicationDispatcher, PublicationDriveReport, PublicationTransport,
    PublicationTransportOutcome,
};
use crate::runtime::store::{FrozenPublication, RuntimeStoreHandle};

use super::transport::{MachinePublicationHandle, MachinePublicationOutcome, RemoteTransportError};

const PUBLICATION_DRIVE_COMMAND_CAPACITY: usize = 32;
const PUBLICATION_DRIVE_SHUTDOWN_DEADLINE: Duration = Duration::from_secs(10);
const PUBLICATION_RECOVERY_MAX_ROUNDS: usize = 2_100_001;
const PUBLICATION_RECOVERY_MAX_STALLED_ROUNDS: usize = 1_000;
const PUBLICATION_RECOVERY_STALL_BACKOFF: Duration = Duration::from_millis(10);

/// 只保存调用方从唯一 business lane 派生的窄 handle；网络 session 的所有权仍在
/// MachineLink supervisor。
pub(crate) struct MachineLinkPublicationTransport {
    handle: MachinePublicationHandle,
}

impl MachineLinkPublicationTransport {
    pub(crate) fn new(handle: MachinePublicationHandle) -> Self {
        Self { handle }
    }
}

#[async_trait]
impl PublicationTransport for MachineLinkPublicationTransport {
    async fn publish(&self, publication: FrozenPublication) -> PublicationTransportOutcome {
        let expected = PublicationDispatchKey::from(&publication);
        let expected_connection_generation = self.handle.current_connection_generation();
        let result = self
            .handle
            .publish_exact_for_generation(
                expected_connection_generation,
                StreamRouteId::from_bytes(publication.stream_route),
                StreamGenerationId::from_bytes(publication.generation),
                publication.stream_seq,
                Arc::from(publication.blob),
                publication.blob_sha256,
            )
            .await;
        map_machine_result(expected, expected_connection_generation, result)
    }
}

fn map_machine_result(
    expected: PublicationDispatchKey,
    expected_connection_generation: u64,
    result: Result<MachinePublicationOutcome, RemoteTransportError>,
) -> PublicationTransportOutcome {
    match result {
        Ok(MachinePublicationOutcome::Committed(commit))
            if commit.connection_generation == expected_connection_generation
                && commit.stream_route.as_bytes() == &expected.stream_route
                && commit.stream_generation.as_bytes() == &expected.generation
                && commit.stream_seq == expected.stream_seq
                && commit.blob_sha256 == expected.blob_sha256 =>
        {
            PublicationTransportOutcome::Committed(PublicationCommitReceipt { key: expected })
        }
        Ok(MachinePublicationOutcome::Committed(_)) => PublicationTransportOutcome::Rejected,
        Ok(MachinePublicationOutcome::OutcomeUnknown)
        | Err(RemoteTransportError::BusinessGenerationReplaced) => {
            PublicationTransportOutcome::OutcomeUnknown
        }
        Ok(MachinePublicationOutcome::Offline) => PublicationTransportOutcome::Offline,
        Err(_) => PublicationTransportOutcome::Rejected,
    }
}

#[derive(Debug, thiserror::Error)]
pub(crate) enum PublicationDriveError {
    #[error(transparent)]
    Dispatch(#[from] PublicationDispatchError),
    #[error("publication drive owner is closed")]
    Closed,
    #[error("publication drive owner task failed")]
    TaskFailed,
    #[error("publication drive owner did not quiesce before its shutdown deadline")]
    ShutdownTimedOut,
    #[error("publication recovery cannot reach Relay while frozen outbox remains")]
    RecoveryOffline,
    #[error("publication recovery made no durable progress")]
    RecoveryStalled,
    #[error("publication recovery exceeded the authenticated outbox bound")]
    RecoveryExhausted,
    #[error("publication recovery was cancelled by daemon shutdown")]
    RecoveryCancelled,
    #[error("publication recovery exceeded its absolute startup deadline")]
    RecoveryTimedOut,
}

enum PublicationDriveCommand {
    DiscoverPending {
        response: oneshot::Sender<Result<usize, PublicationDispatchError>>,
    },
    NotifyFrozen {
        stream_id: [u8; 16],
        response: oneshot::Sender<()>,
    },
    NotifyReconnected {
        response: oneshot::Sender<()>,
    },
    DriveRound {
        response: oneshot::Sender<Result<PublicationDriveReport, PublicationDispatchError>>,
    },
    PendingStreamCount {
        response: oneshot::Sender<usize>,
    },
    Shutdown {
        response: oneshot::Sender<()>,
    },
}

#[derive(Clone)]
pub(crate) struct PublicationDriveHandle {
    command_tx: mpsc::Sender<PublicationDriveCommand>,
}

impl PublicationDriveHandle {
    pub(crate) async fn discover_pending(&self) -> Result<usize, PublicationDriveError> {
        self.request(|response| PublicationDriveCommand::DiscoverPending { response })
            .await?
            .map_err(Into::into)
    }

    pub(crate) async fn notify_frozen_stream(
        &self,
        stream_id: [u8; 16],
    ) -> Result<(), PublicationDriveError> {
        self.request(|response| PublicationDriveCommand::NotifyFrozen {
            stream_id,
            response,
        })
        .await
    }

    pub(crate) async fn notify_reconnected(&self) -> Result<(), PublicationDriveError> {
        self.request(|response| PublicationDriveCommand::NotifyReconnected { response })
            .await
    }

    /// startup/reconnect admission gate。所有 retry 都复用 Store 中冻结的 exact blob；
    /// offline、持续 outcome-unknown/commit-pending、terminal stream 或容量外循环都
    /// fail-close，绝不让 RemoteLink 在旧 outbox 未收口时先接收新业务。
    pub(crate) async fn recover_pending(&self) -> Result<(), PublicationDriveError> {
        self.discover_pending().await?;
        self.notify_reconnected().await?;
        let mut stalled_rounds = 0_usize;
        for _ in 0..PUBLICATION_RECOVERY_MAX_ROUNDS {
            if self.pending_stream_count().await? == 0 {
                return Ok(());
            }
            let report = self.drive_round().await?;
            if report.offline {
                return Err(PublicationDriveError::RecoveryOffline);
            }
            if report.committed > 0 {
                stalled_rounds = 0;
                continue;
            }
            stalled_rounds = stalled_rounds.saturating_add(1);
            if stalled_rounds >= PUBLICATION_RECOVERY_MAX_STALLED_ROUNDS {
                return Err(PublicationDriveError::RecoveryStalled);
            }
            tokio::time::sleep(PUBLICATION_RECOVERY_STALL_BACKOFF).await;
        }
        Err(PublicationDriveError::RecoveryExhausted)
    }

    /// 与 daemon 生命周期绑定的 startup admission gate。deadline 是调用方一次性
    /// 计算的 absolute instant；Relay 中间帧或 actor 内部进展都不得续期。取消本
    /// waiter 不会取消 actor 已取得的线性 publish round，owner shutdown 仍负责在
    /// 自己的绝对 deadline 内 join，超时后只 abort 而不再无界等待。
    pub(crate) async fn recover_pending_until(
        &self,
        deadline: tokio::time::Instant,
        mut shutdown_rx: watch::Receiver<bool>,
    ) -> Result<(), PublicationDriveError> {
        if *shutdown_rx.borrow() {
            return Err(PublicationDriveError::RecoveryCancelled);
        }
        let cancelled = async move {
            loop {
                if shutdown_rx.changed().await.is_err() || *shutdown_rx.borrow() {
                    break;
                }
            }
        };
        tokio::select! {
            biased;
            () = cancelled => Err(PublicationDriveError::RecoveryCancelled),
            result = tokio::time::timeout_at(deadline, self.recover_pending()) => {
                result.map_err(|_| PublicationDriveError::RecoveryTimedOut)?
            }
        }
    }

    pub(crate) async fn drive_round(
        &self,
    ) -> Result<PublicationDriveReport, PublicationDriveError> {
        self.request(|response| PublicationDriveCommand::DriveRound { response })
            .await?
            .map_err(Into::into)
    }

    async fn pending_stream_count(&self) -> Result<usize, PublicationDriveError> {
        self.request(|response| PublicationDriveCommand::PendingStreamCount { response })
            .await
    }

    async fn request<T>(
        &self,
        make_command: impl FnOnce(oneshot::Sender<T>) -> PublicationDriveCommand,
    ) -> Result<T, PublicationDriveError> {
        let (response_tx, response_rx) = oneshot::channel();
        self.command_tx
            .send(make_command(response_tx))
            .await
            .map_err(|_| PublicationDriveError::Closed)?;
        response_rx.await.map_err(|_| PublicationDriveError::Closed)
    }
}

pub(crate) struct PublicationDriveOwner {
    handle: PublicationDriveHandle,
    task: Option<JoinHandle<()>>,
    shutdown_timeout: Duration,
}

impl PublicationDriveOwner {
    pub(crate) async fn open(
        store: RuntimeStoreHandle,
        machine_handle: MachinePublicationHandle,
    ) -> Result<Self, PublicationDriveError> {
        Self::open_with_transport(
            store,
            Arc::new(MachineLinkPublicationTransport::new(machine_handle)),
        )
        .await
    }

    async fn open_with_transport<T>(
        store: RuntimeStoreHandle,
        transport: Arc<T>,
    ) -> Result<Self, PublicationDriveError>
    where
        T: PublicationTransport,
    {
        let dispatcher = PublicationDispatcher::open(store, transport).await?;
        let (command_tx, command_rx) = mpsc::channel(PUBLICATION_DRIVE_COMMAND_CAPACITY);
        let task = tokio::spawn(run_publication_drive(dispatcher, command_rx));
        Ok(Self {
            handle: PublicationDriveHandle { command_tx },
            task: Some(task),
            shutdown_timeout: PUBLICATION_DRIVE_SHUTDOWN_DEADLINE,
        })
    }

    pub(crate) fn handle(&self) -> PublicationDriveHandle {
        self.handle.clone()
    }

    pub(crate) async fn shutdown(mut self) -> Result<(), PublicationDriveError> {
        let deadline = tokio::time::Instant::now() + self.shutdown_timeout;
        let handle = self.handle;
        let mut task = self.task.take().expect("publication drive task is present");
        let shutdown = async {
            let request = handle
                .request(|response| PublicationDriveCommand::Shutdown { response })
                .await;
            drop(handle);
            let joined = (&mut task)
                .await
                .map_err(|_| PublicationDriveError::TaskFailed);
            request?;
            joined
        };
        match tokio::time::timeout_at(deadline, shutdown).await {
            Ok(result) => result,
            Err(_) => {
                task.abort();
                Err(PublicationDriveError::ShutdownTimedOut)
            }
        }
    }

    #[cfg(test)]
    async fn slow_task_for_shutdown_test(timeout: Duration, drop_delay: Duration) -> Self {
        let (command_tx, command_rx) = mpsc::channel(PUBLICATION_DRIVE_COMMAND_CAPACITY);
        let started = Arc::new(tokio::sync::Notify::new());
        let task = tokio::spawn({
            let started = Arc::clone(&started);
            async move {
                let _command_rx = command_rx;
                let _slow_drop = SlowPublicationShutdownDrop(drop_delay);
                started.notify_one();
                std::future::pending::<()>().await;
            }
        });
        started.notified().await;
        Self {
            handle: PublicationDriveHandle { command_tx },
            task: Some(task),
            shutdown_timeout: timeout,
        }
    }
}

#[cfg(test)]
struct SlowPublicationShutdownDrop(Duration);

#[cfg(test)]
impl Drop for SlowPublicationShutdownDrop {
    fn drop(&mut self) {
        std::thread::sleep(self.0);
    }
}

async fn run_publication_drive<T>(
    mut dispatcher: PublicationDispatcher<T>,
    mut command_rx: mpsc::Receiver<PublicationDriveCommand>,
) where
    T: PublicationTransport,
{
    while let Some(command) = command_rx.recv().await {
        match command {
            PublicationDriveCommand::DiscoverPending { response } => {
                let _ = response.send(dispatcher.discover_pending().await);
            }
            PublicationDriveCommand::NotifyFrozen {
                stream_id,
                response,
            } => {
                dispatcher.notify_frozen_stream(stream_id);
                let _ = response.send(());
            }
            PublicationDriveCommand::NotifyReconnected { response } => {
                dispatcher.notify_reconnected();
                let _ = response.send(());
            }
            PublicationDriveCommand::DriveRound { response } => {
                // 即使请求方取消等待，也必须把本轮线性状态完整推进到返回。
                let result = dispatcher.drive_round().await;
                let _ = response.send(result);
            }
            PublicationDriveCommand::PendingStreamCount { response } => {
                let _ = response.send(dispatcher.pending_stream_count());
            }
            PublicationDriveCommand::Shutdown { response } => {
                let _ = response.send(());
                break;
            }
        }
    }
}

#[cfg(test)]
pub(crate) mod tests {
    use std::collections::VecDeque;
    use std::fs;
    use std::path::{Path, PathBuf};
    use std::sync::atomic::{AtomicU64, Ordering};
    use std::sync::{Arc, Mutex};

    use agentdeck_protocol::relay_v2::{StreamGenerationId, StreamRouteId};
    use async_trait::async_trait;
    use tokio::sync::{Notify, watch};

    use crate::remote::transport::{MachinePublicationCommit, MachinePublicationOutcome};
    use crate::runtime::publication::{
        PublicationDispatchKey, PublicationTransport, PublicationTransportOutcome,
    };
    use crate::runtime::store::{
        FreezePublicationRequest, FrozenPublication, PublicationPayloadKind, PublicationScope,
        RuntimeStoreConfig, RuntimeStoreHandle,
    };
    use crate::security::{MemoryKeyStore, load_or_create_storage_kek};

    use super::{PublicationDriveOwner, map_machine_result};

    pub(crate) async fn open_owner_with_transport_for_test<T>(
        store: RuntimeStoreHandle,
        transport: Arc<T>,
    ) -> Result<PublicationDriveOwner, super::PublicationDriveError>
    where
        T: PublicationTransport,
    {
        PublicationDriveOwner::open_with_transport(store, transport).await
    }

    static NEXT_ROOT: AtomicU64 = AtomicU64::new(1);

    struct TestRoot(PathBuf);

    impl TestRoot {
        fn new(label: &str) -> Self {
            let path = Path::new("/tmp").join(format!(
                "agentdeck-publication-transport-{label}-{}-{}",
                std::process::id(),
                NEXT_ROOT.fetch_add(1, Ordering::Relaxed)
            ));
            let _ = fs::remove_dir_all(&path);
            fs::create_dir(&path).expect("create publication transport root");
            #[cfg(unix)]
            {
                use std::os::unix::fs::PermissionsExt;
                fs::set_permissions(&path, fs::Permissions::from_mode(0o700))
                    .expect("secure publication transport root");
            }
            Self(path)
        }
    }

    impl Drop for TestRoot {
        fn drop(&mut self) {
            let _ = fs::remove_dir_all(&self.0);
        }
    }

    #[derive(Clone, Copy)]
    enum Plan {
        Exact,
        Offline,
    }

    struct ScriptedTransport {
        plans: Mutex<VecDeque<Plan>>,
        sent: Mutex<Vec<(PublicationDispatchKey, Vec<u8>)>>,
    }

    impl ScriptedTransport {
        fn new(plans: impl IntoIterator<Item = Plan>) -> Self {
            Self {
                plans: Mutex::new(plans.into_iter().collect()),
                sent: Mutex::new(Vec::new()),
            }
        }
    }

    #[async_trait]
    impl PublicationTransport for ScriptedTransport {
        async fn publish(&self, publication: FrozenPublication) -> PublicationTransportOutcome {
            let key = PublicationDispatchKey::from(&publication);
            self.sent
                .lock()
                .expect("sent lock")
                .push((key, publication.blob));
            match self
                .plans
                .lock()
                .expect("plan lock")
                .pop_front()
                .unwrap_or(Plan::Exact)
            {
                Plan::Exact => PublicationTransportOutcome::Committed(
                    crate::runtime::publication::PublicationCommitReceipt { key },
                ),
                Plan::Offline => PublicationTransportOutcome::Offline,
            }
        }
    }

    struct BlockingTransport {
        started: Notify,
        release: Notify,
    }

    #[async_trait]
    impl PublicationTransport for BlockingTransport {
        async fn publish(&self, publication: FrozenPublication) -> PublicationTransportOutcome {
            let key = PublicationDispatchKey::from(&publication);
            self.started.notify_one();
            self.release.notified().await;
            PublicationTransportOutcome::Committed(
                crate::runtime::publication::PublicationCommitReceipt { key },
            )
        }
    }

    async fn open_store(label: &str) -> (TestRoot, RuntimeStoreHandle) {
        let root = TestRoot::new(label);
        let keys = MemoryKeyStore::new();
        let kek = load_or_create_storage_kek(&keys, &root.0.join("key-state.db"))
            .expect("create test KEK");
        let store =
            RuntimeStoreHandle::open(RuntimeStoreConfig::new(root.0.join("runtime.db")), kek)
                .await
                .expect("open runtime store");
        (root, store)
    }

    async fn freeze_fixture(
        store: &RuntimeStoreHandle,
        stream_id: [u8; 16],
        route: [u8; 16],
        generation: [u8; 16],
        publication_id: [u8; 16],
        blob: Vec<u8>,
    ) {
        store
            .create_publication_stream(stream_id, PublicationScope::Catalog, route, generation)
            .await
            .expect("create publication stream");
        store
            .freeze_publication(FreezePublicationRequest {
                publication_id,
                publication_stream_id: stream_id,
                generation,
                counter_scope_token: [0x41; 32],
                sender_counter: 1,
                inner_after: None,
                inner_through: Some(0),
                payload_kind: PublicationPayloadKind::Catalog,
                blob,
            })
            .await
            .expect("freeze publication");
    }

    fn key() -> PublicationDispatchKey {
        PublicationDispatchKey {
            publication_stream_id: [0x11; 16],
            stream_route: [0x22; 16],
            generation: [0x33; 16],
            stream_seq: 7,
            blob_sha256: [0x44; 32],
        }
    }

    fn committed(
        connection_generation: u64,
        stream_route: [u8; 16],
        generation: [u8; 16],
        stream_seq: u64,
        blob_sha256: [u8; 32],
    ) -> MachinePublicationOutcome {
        MachinePublicationOutcome::Committed(MachinePublicationCommit {
            connection_generation,
            stream_route: StreamRouteId::from_bytes(stream_route),
            stream_generation: StreamGenerationId::from_bytes(generation),
            stream_seq,
            blob_sha256,
        })
    }

    #[test]
    fn only_exact_machine_commit_maps_to_dispatch_commit() {
        let expected = key();
        assert_eq!(
            map_machine_result(
                expected,
                9,
                Ok(committed(
                    9,
                    expected.stream_route,
                    expected.generation,
                    expected.stream_seq,
                    expected.blob_sha256,
                )),
            ),
            PublicationTransportOutcome::Committed(
                crate::runtime::publication::PublicationCommitReceipt { key: expected }
            )
        );

        for mismatch in [
            committed(
                8,
                expected.stream_route,
                expected.generation,
                expected.stream_seq,
                expected.blob_sha256,
            ),
            committed(
                9,
                [0x55; 16],
                expected.generation,
                expected.stream_seq,
                expected.blob_sha256,
            ),
            committed(
                9,
                expected.stream_route,
                [0x66; 16],
                expected.stream_seq,
                expected.blob_sha256,
            ),
            committed(
                9,
                expected.stream_route,
                expected.generation,
                expected.stream_seq + 1,
                expected.blob_sha256,
            ),
            committed(
                9,
                expected.stream_route,
                expected.generation,
                expected.stream_seq,
                [0x77; 32],
            ),
        ] {
            assert_eq!(
                map_machine_result(expected, 9, Ok(mismatch)),
                PublicationTransportOutcome::Rejected
            );
        }
    }

    #[test]
    fn only_typed_network_absence_and_unknown_outcome_are_retryable() {
        let expected = key();
        assert_eq!(
            map_machine_result(
                expected,
                9,
                Err(crate::remote::transport::RemoteTransportError::BusinessGenerationReplaced),
            ),
            PublicationTransportOutcome::OutcomeUnknown
        );
        assert_eq!(
            map_machine_result(
                expected,
                9,
                Ok(crate::remote::transport::MachinePublicationOutcome::Offline),
            ),
            PublicationTransportOutcome::Offline
        );
        for error in [
            crate::remote::transport::RemoteTransportError::BusinessLaneUnavailable,
            crate::remote::transport::RemoteTransportError::Closed,
            crate::remote::transport::RemoteTransportError::SupervisorFailed {
                code: "remote.transport.publication_ack_mismatch".to_owned(),
            },
            crate::remote::transport::RemoteTransportError::PublicationBindingMismatch,
        ] {
            assert_eq!(
                map_machine_result(expected, 9, Err(error)),
                PublicationTransportOutcome::Rejected
            );
        }
    }

    #[tokio::test]
    async fn drive_owner_parks_offline_and_retries_the_exact_frozen_bytes_after_reconnect() {
        let (_root, store) = open_store("offline-retry").await;
        let stream_id = [0x81; 16];
        let exact = vec![0x91; 97];
        freeze_fixture(
            &store,
            stream_id,
            [0x82; 16],
            [0x83; 16],
            [0x84; 16],
            exact.clone(),
        )
        .await;
        let transport = Arc::new(ScriptedTransport::new([Plan::Offline, Plan::Exact]));
        let owner = PublicationDriveOwner::open_with_transport(store.clone(), transport.clone())
            .await
            .expect("open bounded drive owner");
        let handle = owner.handle();

        let first = handle.drive_round().await.expect("offline drive");
        assert!(first.offline);
        assert_eq!(transport.sent.lock().expect("sent lock").len(), 1);
        let parked = handle.drive_round().await.expect("parked offline drive");
        assert!(parked.offline);
        assert_eq!(transport.sent.lock().expect("sent lock").len(), 1);

        handle
            .notify_reconnected()
            .await
            .expect("notify replacement generation");
        let committed = handle.drive_round().await.expect("retry after reconnect");
        assert_eq!(committed.committed, 1);
        {
            let sent = transport.sent.lock().expect("sent lock");
            assert_eq!(sent.len(), 2);
            assert_eq!(sent[0].0, sent[1].0);
            assert_eq!(sent[0].1, exact);
            assert_eq!(sent[0].1, sent[1].1);
        }

        assert_eq!(
            handle.discover_pending().await.expect("discover pending"),
            0
        );
        owner.shutdown().await.expect("shutdown drive owner");
        assert!(matches!(
            handle.drive_round().await,
            Err(super::PublicationDriveError::Closed)
        ));
        store.shutdown().await.expect("shutdown runtime store");
    }

    #[tokio::test]
    async fn startup_recovery_drives_frozen_outbox_to_quiescent_before_returning() {
        let (_root, store) = open_store("startup-recovery").await;
        let exact = vec![0xb1; 73];
        freeze_fixture(
            &store,
            [0xb2; 16],
            [0xb3; 16],
            [0xb4; 16],
            [0xb5; 16],
            exact.clone(),
        )
        .await;
        let transport = Arc::new(ScriptedTransport::new([Plan::Exact]));
        let owner = PublicationDriveOwner::open_with_transport(store.clone(), transport.clone())
            .await
            .expect("open startup recovery owner");
        let handle = owner.handle();

        handle
            .recover_pending()
            .await
            .expect("startup recovery reaches authenticated quiescence");

        assert!(
            store
                .load_pending_publication_streams()
                .await
                .expect("read recovered outbox")
                .is_empty()
        );
        {
            let sent = transport.sent.lock().expect("read startup recovery sends");
            assert_eq!(sent.len(), 1);
            assert_eq!(sent[0].1, exact);
        }
        owner.shutdown().await.expect("shutdown recovery owner");
        store.shutdown().await.expect("shutdown recovery store");
    }

    #[tokio::test]
    async fn startup_recovery_keeps_admission_blocked_when_relay_is_offline() {
        let (_root, store) = open_store("startup-recovery-offline").await;
        freeze_fixture(
            &store,
            [0xc2; 16],
            [0xc3; 16],
            [0xc4; 16],
            [0xc5; 16],
            vec![0xc6; 31],
        )
        .await;
        let owner = PublicationDriveOwner::open_with_transport(
            store.clone(),
            Arc::new(ScriptedTransport::new([Plan::Offline])),
        )
        .await
        .expect("open offline startup recovery owner");

        assert!(matches!(
            owner.handle().recover_pending().await,
            Err(super::PublicationDriveError::RecoveryOffline)
        ));
        assert_eq!(
            store
                .load_pending_publication_streams()
                .await
                .expect("offline outbox stays frozen"),
            vec![[0xc2; 16]]
        );
        owner.shutdown().await.expect("shutdown offline owner");
        store.shutdown().await.expect("shutdown offline store");
    }

    #[tokio::test]
    async fn startup_recovery_is_cancelled_while_relay_keeps_publish_pending() {
        let (_root, store) = open_store("startup-recovery-cancelled").await;
        freeze_fixture(
            &store,
            [0xd2; 16],
            [0xd3; 16],
            [0xd4; 16],
            [0xd5; 16],
            vec![0xd6; 31],
        )
        .await;
        let transport = Arc::new(BlockingTransport {
            started: Notify::new(),
            release: Notify::new(),
        });
        let owner = PublicationDriveOwner::open_with_transport(store.clone(), transport.clone())
            .await
            .expect("open cancelled startup recovery owner");
        let (shutdown_tx, shutdown_rx) = watch::channel(false);
        let recovery = tokio::spawn({
            let handle = owner.handle();
            async move {
                handle
                    .recover_pending_until(
                        tokio::time::Instant::now() + std::time::Duration::from_secs(30),
                        shutdown_rx,
                    )
                    .await
            }
        });
        transport.started.notified().await;
        shutdown_tx.send_replace(true);
        assert!(matches!(
            tokio::time::timeout(std::time::Duration::from_secs(1), recovery)
                .await
                .expect("shutdown cancels startup recovery")
                .expect("recovery task joins"),
            Err(super::PublicationDriveError::RecoveryCancelled)
        ));
        transport.release.notify_one();
        owner.shutdown().await.expect("shutdown cancelled owner");
        store.shutdown().await.expect("shutdown cancelled store");
    }

    #[tokio::test]
    async fn startup_recovery_has_an_absolute_deadline_for_silent_relay() {
        let (_root, store) = open_store("startup-recovery-deadline").await;
        freeze_fixture(
            &store,
            [0xe2; 16],
            [0xe3; 16],
            [0xe4; 16],
            [0xe5; 16],
            vec![0xe6; 31],
        )
        .await;
        let transport = Arc::new(BlockingTransport {
            started: Notify::new(),
            release: Notify::new(),
        });
        let owner = PublicationDriveOwner::open_with_transport(store.clone(), transport.clone())
            .await
            .expect("open deadline startup recovery owner");
        let (_shutdown_tx, shutdown_rx) = watch::channel(false);
        assert!(matches!(
            owner
                .handle()
                .recover_pending_until(
                    tokio::time::Instant::now() + std::time::Duration::from_millis(25),
                    shutdown_rx,
                )
                .await,
            Err(super::PublicationDriveError::RecoveryTimedOut)
        ));
        transport.release.notify_one();
        owner.shutdown().await.expect("shutdown deadline owner");
        store.shutdown().await.expect("shutdown deadline store");
    }

    #[tokio::test]
    async fn cancelling_a_drive_waiter_does_not_cancel_the_linear_dispatch_round() {
        let (_root, store) = open_store("cancel-waiter").await;
        let stream_id = [0xa1; 16];
        freeze_fixture(
            &store,
            stream_id,
            [0xa2; 16],
            [0xa3; 16],
            [0xa4; 16],
            vec![0xa5; 41],
        )
        .await;
        let transport = Arc::new(BlockingTransport {
            started: Notify::new(),
            release: Notify::new(),
        });
        let owner = PublicationDriveOwner::open_with_transport(store.clone(), transport.clone())
            .await
            .expect("open cancellable drive owner");
        let handle = owner.handle();
        let waiter = tokio::spawn({
            let handle = handle.clone();
            async move { handle.drive_round().await }
        });
        transport.started.notified().await;
        waiter.abort();
        transport.release.notify_one();

        assert_eq!(
            handle
                .discover_pending()
                .await
                .expect("actor completes cancelled caller's drive first"),
            0
        );
        assert!(
            store
                .load_pending_publication_streams()
                .await
                .expect("read committed outbox")
                .is_empty()
        );
        owner.shutdown().await.expect("shutdown drive owner");
        store.shutdown().await.expect("shutdown runtime store");
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn shutdown_timeout_does_not_await_non_cooperative_aborted_drive_task() {
        let owner = PublicationDriveOwner::slow_task_for_shutdown_test(
            std::time::Duration::from_millis(20),
            std::time::Duration::from_millis(400),
        )
        .await;

        let result = tokio::time::timeout(std::time::Duration::from_millis(150), owner.shutdown())
            .await
            .expect("publication owner must return at its absolute deadline");
        assert!(matches!(
            result,
            Err(super::PublicationDriveError::ShutdownTimedOut)
        ));
    }

    #[test]
    fn adapter_source_has_no_second_network_owner() {
        let source = include_str!("publication_transport.rs");
        let production = source
            .split("#[cfg(test)]")
            .next()
            .expect("production prefix");
        for forbidden in [
            "RelayClient",
            "RelayClientConfig",
            "connect(",
            "wss://",
            "read_loop",
            "session.recv",
        ] {
            assert!(
                !production.contains(forbidden),
                "adapter must only retain the existing typed handle: {forbidden}"
            );
        }
    }
}
