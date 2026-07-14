//! Durable publication outbox 的公平 dispatcher。
//!
//! 具体威胁场景：transport/store outcome unknown 时若重新 seal、重复 publish，或从未经
//! 认证的 stream 目录恢复，会复用/跳过 sender counter、重复远端副作用并破坏 exactly-once
//! committed cut。dispatcher 因此只加载 durable exact frozen row，逐字节发送，并在 receipt
//! 完全匹配后才推进本地 committed cut；本地 COMMIT unknown 只重试同一 store closure。

#![cfg_attr(
    not(test),
    expect(
        dead_code,
        reason = "P3.6-C 冻结 transport-neutral dispatcher；P4 Machine RemoteTransport 接入后删除"
    )
)]

use std::collections::{HashMap, VecDeque};
use std::sync::Arc;

use super::store::{
    FrozenPublication, RuntimeCommitOperation, RuntimeStoreError, RuntimeStoreHandle,
    RuntimeStoreLane,
};
use tokio::sync::{OwnedSemaphorePermit, Semaphore};

pub(crate) const MAX_PUBLICATION_PAGE_BYTES: usize = 8 * 1024 * 1024;
pub(crate) const MAX_PUBLICATION_PAGES_IN_MEMORY: usize = 2;
pub(crate) const MAX_PUBLICATION_MEMORY_BYTES: usize =
    MAX_PUBLICATION_PAGE_BYTES * MAX_PUBLICATION_PAGES_IN_MEMORY;

#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
pub(crate) struct PublicationDispatchKey {
    pub publication_stream_id: [u8; 16],
    pub generation: [u8; 16],
    pub stream_seq: u64,
    pub blob_sha256: [u8; 32],
}

impl From<&FrozenPublication> for PublicationDispatchKey {
    fn from(publication: &FrozenPublication) -> Self {
        Self {
            publication_stream_id: publication.publication_stream_id,
            generation: publication.generation,
            stream_seq: publication.stream_seq,
            blob_sha256: publication.blob_sha256,
        }
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) struct PublicationCommitReceipt {
    pub key: PublicationDispatchKey,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum PublicationTransportOutcome {
    Committed(PublicationCommitReceipt),
    OutcomeUnknown,
    Offline,
}

#[async_trait::async_trait]
pub(crate) trait PublicationTransport: Send + Sync + 'static {
    async fn publish(&self, publication: FrozenPublication) -> PublicationTransportOutcome;
}

#[derive(Debug, thiserror::Error)]
pub(crate) enum PublicationDispatchError {
    #[error(transparent)]
    Store(#[from] RuntimeStoreError),
    #[error("publication transport receipt does not match the exact frozen row")]
    ReceiptMismatch,
    #[error("publication dispatcher child task failed")]
    ChildTaskFailed,
    #[error("publication store returned a page above the fixed 8 MiB bound")]
    PageBudgetExceeded,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum InFlightPhase {
    Publishing,
    CommitPending,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
struct InFlightPublication {
    key: PublicationDispatchKey,
    phase: InFlightPhase,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum DispatcherStreamState {
    EmptyParked,
    TerminalError,
    Ready,
    Loading,
    InFlight(InFlightPublication),
}

#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub(crate) struct PublicationDriveReport {
    pub loaded: usize,
    pub committed: usize,
    pub outcome_unknown: usize,
    pub commit_pending: usize,
    pub offline: bool,
}

struct LoadedPublication {
    publication: FrozenPublication,
    _page_permit: OwnedSemaphorePermit,
}

enum LoadResult {
    Empty([u8; 16]),
    Loaded([u8; 16], LoadedPublication),
    Failed([u8; 16], RuntimeStoreError),
}

pub(crate) struct PublicationDispatcher<T: PublicationTransport> {
    store: RuntimeStoreHandle,
    transport: Arc<T>,
    states: HashMap<[u8; 16], DispatcherStreamState>,
    ready: VecDeque<[u8; 16]>,
    commit_pending: VecDeque<[u8; 16]>,
    page_permits: Arc<Semaphore>,
    offline: bool,
}

impl<T: PublicationTransport> PublicationDispatcher<T> {
    pub(crate) async fn open(
        store: RuntimeStoreHandle,
        transport: Arc<T>,
    ) -> Result<Self, PublicationDispatchError> {
        let mut dispatcher = Self {
            store,
            transport,
            states: HashMap::new(),
            ready: VecDeque::new(),
            commit_pending: VecDeque::new(),
            page_permits: Arc::new(Semaphore::new(MAX_PUBLICATION_PAGES_IN_MEMORY)),
            offline: false,
        };
        dispatcher.discover_pending().await?;
        Ok(dispatcher)
    }

    /// 只添加经过完整 authenticated directory 枚举的新 pending stream。已知 stream 的
    /// security/error 状态不会被普通 refresh 静默重置。
    pub(crate) async fn discover_pending(&mut self) -> Result<usize, PublicationDispatchError> {
        let stream_ids = self.store.load_pending_publication_streams().await?;
        let mut added = 0;
        for stream_id in stream_ids {
            if self.states.contains_key(&stream_id) {
                continue;
            }
            self.states.insert(stream_id, DispatcherStreamState::Ready);
            self.enqueue_ready(stream_id);
            added += 1;
        }
        Ok(added)
    }

    /// freeze 成功后由 owner 显式唤醒；这也是空 stream 从 EmptyParked 重新进入 Ready 的
    /// 唯一普通路径，不需要 dispatcher 轮询数据库。
    pub(crate) fn notify_frozen_stream(&mut self, stream_id: [u8; 16]) {
        if matches!(
            self.states.get(&stream_id),
            None | Some(DispatcherStreamState::EmptyParked)
        ) {
            self.states.insert(stream_id, DispatcherStreamState::Ready);
            self.enqueue_ready(stream_id);
        }
    }

    /// Offline 不做定时自旋；只有 transport supervisor 的显式 reconnect wake 才恢复。
    pub(crate) fn notify_reconnected(&mut self) {
        self.offline = false;
        let ready = self
            .states
            .iter()
            .filter_map(|(stream_id, state)| {
                (*state == DispatcherStreamState::Ready).then_some(*stream_id)
            })
            .collect::<Vec<_>>();
        for stream_id in ready {
            self.enqueue_ready(stream_id);
        }
    }

    /// 每轮每个 stream 至多尝试一次；OutcomeUnknown 与临时 ReadPool busy 只重新排到
    /// 下一次 owner drive，确保从 DB 重载 exact bytes 且不会在本轮 hot loop。单轮最多
    /// 并发两页，因此 retained page memory 不超过 16 MiB。
    ///
    /// # Cancellation contract
    ///
    /// owner 一旦调用本方法就必须 await 到返回，不能取消或丢弃 future；`Loading` 与
    /// `InFlight` 是单 owner 的线性状态，shutdown 必须先停止新 drive，再等待当前轮收口。
    pub(crate) async fn drive_round(
        &mut self,
    ) -> Result<PublicationDriveReport, PublicationDispatchError> {
        let mut report = PublicationDriveReport {
            offline: self.offline,
            ..PublicationDriveReport::default()
        };
        if self.offline {
            return Ok(report);
        }
        self.retry_commit_closures(&mut report).await?;

        let selected = self.select_ready(MAX_PUBLICATION_PAGES_IN_MEMORY);
        if selected.is_empty() {
            return Ok(report);
        }
        let mut loads = Vec::with_capacity(selected.len());
        for stream_id in selected {
            let store = self.store.clone();
            let permits = Arc::clone(&self.page_permits);
            let task = tokio::spawn(async move {
                let Ok(permit) = permits.acquire_owned().await else {
                    return LoadResult::Failed(stream_id, RuntimeStoreError::WorkerStopped);
                };
                match store.load_pending_publications(stream_id).await {
                    Ok(page) if page.is_empty() => LoadResult::Empty(stream_id),
                    Ok(page) => {
                        let bytes = page.iter().try_fold(0_usize, |total, publication| {
                            total.checked_add(publication.blob.len())
                        });
                        if bytes.is_none_or(|bytes| bytes > MAX_PUBLICATION_PAGE_BYTES) {
                            return LoadResult::Failed(
                                stream_id,
                                RuntimeStoreError::PayloadTooLarge,
                            );
                        }
                        let publication = page.into_iter().next().expect("non-empty page");
                        LoadResult::Loaded(
                            stream_id,
                            LoadedPublication {
                                publication,
                                _page_permit: permit,
                            },
                        )
                    }
                    Err(error) => LoadResult::Failed(stream_id, error),
                }
            });
            loads.push((stream_id, task));
        }

        let mut loaded = Vec::new();
        let mut load_error = None;
        for (task_stream_id, task) in loads {
            let result = match task.await {
                Ok(result) => result,
                Err(_) => {
                    self.states
                        .insert(task_stream_id, DispatcherStreamState::TerminalError);
                    load_error.get_or_insert(PublicationDispatchError::ChildTaskFailed);
                    continue;
                }
            };
            match result {
                LoadResult::Empty(stream_id) => {
                    self.states
                        .insert(stream_id, DispatcherStreamState::EmptyParked);
                }
                LoadResult::Loaded(stream_id, publication) => {
                    let key = PublicationDispatchKey::from(&publication.publication);
                    self.states.insert(
                        stream_id,
                        DispatcherStreamState::InFlight(InFlightPublication {
                            key,
                            phase: InFlightPhase::Publishing,
                        }),
                    );
                    report.loaded += 1;
                    loaded.push((stream_id, key, publication));
                }
                LoadResult::Failed(stream_id, error) => {
                    // 威胁场景：大 snapshot 暂占整池 128 MiB 时，publication 的 8 MiB
                    // page load 只会短暂 Read busy；若把它永久 terminalize，该 stream
                    // 会在资源释放后仍停发直到 daemon 重启。
                    if matches!(
                        error,
                        RuntimeStoreError::WorkerBusy {
                            lane: RuntimeStoreLane::Read
                        }
                    ) {
                        self.mark_ready(stream_id);
                        continue;
                    }
                    self.states
                        .insert(stream_id, DispatcherStreamState::TerminalError);
                    load_error.get_or_insert(
                        if matches!(error, RuntimeStoreError::PayloadTooLarge) {
                            PublicationDispatchError::PageBudgetExceeded
                        } else {
                            error.into()
                        },
                    );
                }
            }
        }
        if let Some(error) = load_error {
            for (stream_id, _, _) in loaded {
                self.mark_ready(stream_id);
            }
            return Err(error);
        }

        let mut publishes = Vec::with_capacity(loaded.len());
        for (stream_id, key, loaded) in loaded {
            let transport = Arc::clone(&self.transport);
            let task = tokio::spawn(async move {
                let outcome = transport.publish(loaded.publication).await;
                drop(loaded._page_permit);
                (stream_id, key, outcome)
            });
            publishes.push((stream_id, task));
        }
        let mut publish_error = None;
        for (task_stream_id, task) in publishes {
            let (stream_id, key, outcome) = match task.await {
                Ok(result) => result,
                Err(_) => {
                    self.states
                        .insert(task_stream_id, DispatcherStreamState::TerminalError);
                    publish_error.get_or_insert(PublicationDispatchError::ChildTaskFailed);
                    continue;
                }
            };
            if let Err(error) = self
                .finish_transport(stream_id, key, outcome, &mut report)
                .await
            {
                publish_error.get_or_insert(error);
            }
        }
        if let Some(error) = publish_error {
            return Err(error);
        }
        report.offline = self.offline;
        Ok(report)
    }

    async fn finish_transport(
        &mut self,
        stream_id: [u8; 16],
        key: PublicationDispatchKey,
        outcome: PublicationTransportOutcome,
        report: &mut PublicationDriveReport,
    ) -> Result<(), PublicationDispatchError> {
        match outcome {
            PublicationTransportOutcome::Committed(receipt) if receipt.key == key => {
                self.commit_exact(stream_id, key, report).await
            }
            PublicationTransportOutcome::Committed(_) => {
                self.states
                    .insert(stream_id, DispatcherStreamState::TerminalError);
                Err(PublicationDispatchError::ReceiptMismatch)
            }
            PublicationTransportOutcome::OutcomeUnknown => {
                self.mark_ready(stream_id);
                report.outcome_unknown += 1;
                Ok(())
            }
            PublicationTransportOutcome::Offline => {
                self.mark_ready(stream_id);
                self.offline = true;
                report.offline = true;
                Ok(())
            }
        }
    }

    async fn commit_exact(
        &mut self,
        stream_id: [u8; 16],
        key: PublicationDispatchKey,
        report: &mut PublicationDriveReport,
    ) -> Result<(), PublicationDispatchError> {
        match self
            .store
            .acknowledge_publication_commit(
                key.publication_stream_id,
                key.generation,
                key.stream_seq,
                key.blob_sha256,
            )
            .await
        {
            Ok(_) => {
                report.committed += 1;
                self.mark_ready(stream_id);
                Ok(())
            }
            Err(RuntimeStoreError::CommitOutcomeUnknown {
                operation: RuntimeCommitOperation::CommitPublication,
            })
            | Err(RuntimeStoreError::WorkerBusy {
                lane: RuntimeStoreLane::Safety,
            }) => {
                self.states.insert(
                    stream_id,
                    DispatcherStreamState::InFlight(InFlightPublication {
                        key,
                        phase: InFlightPhase::CommitPending,
                    }),
                );
                self.commit_pending.push_back(stream_id);
                report.commit_pending += 1;
                Ok(())
            }
            Err(error) => {
                self.states
                    .insert(stream_id, DispatcherStreamState::TerminalError);
                Err(error.into())
            }
        }
    }

    async fn retry_commit_closures(
        &mut self,
        report: &mut PublicationDriveReport,
    ) -> Result<(), PublicationDispatchError> {
        let attempts = self
            .commit_pending
            .len()
            .min(MAX_PUBLICATION_PAGES_IN_MEMORY);
        for _ in 0..attempts {
            let Some(stream_id) = self.commit_pending.pop_front() else {
                break;
            };
            let Some(DispatcherStreamState::InFlight(inflight)) =
                self.states.get(&stream_id).copied()
            else {
                continue;
            };
            if inflight.phase != InFlightPhase::CommitPending {
                continue;
            }
            self.commit_exact(stream_id, inflight.key, report).await?;
        }
        Ok(())
    }

    fn select_ready(&mut self, limit: usize) -> Vec<[u8; 16]> {
        let mut selected = Vec::with_capacity(limit);
        while selected.len() < limit {
            let Some(stream_id) = self.ready.pop_front() else {
                break;
            };
            if self.states.get(&stream_id) != Some(&DispatcherStreamState::Ready) {
                continue;
            }
            self.states
                .insert(stream_id, DispatcherStreamState::Loading);
            selected.push(stream_id);
        }
        selected
    }

    fn mark_ready(&mut self, stream_id: [u8; 16]) {
        self.states.insert(stream_id, DispatcherStreamState::Ready);
        self.enqueue_ready(stream_id);
    }

    fn enqueue_ready(&mut self, stream_id: [u8; 16]) {
        if !self.ready.contains(&stream_id) {
            self.ready.push_back(stream_id);
        }
    }

    #[cfg(test)]
    fn state(&self, stream_id: [u8; 16]) -> Option<DispatcherStreamState> {
        self.states.get(&stream_id).copied()
    }
}

#[cfg(test)]
#[path = "publication/tests.rs"]
mod tests;
