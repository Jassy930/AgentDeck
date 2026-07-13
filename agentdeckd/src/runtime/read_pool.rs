//! 与 prompt/control/connection writer 相互独立的有界只读池。
//!
//! Runtime store 使用固定数量的 SQLite `mode=ro`/`query_only=ON` WAL
//! connection。每次 operation 在 blocking thread 内开启短 read transaction，复制完
//! 一页后先提交/释放 connection，再把带 memory lease 的结果交给调用方。

use std::future::Future;
use std::path::Path;
use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
use std::sync::{Arc, Mutex};
use std::time::Duration;

use rusqlite::{Connection, OpenFlags, TransactionBehavior};
use tokio::sync::{Notify, OwnedSemaphorePermit, Semaphore};

use crate::runtime::model::RuntimeStoreError;

pub(crate) const DEFAULT_RUNTIME_READ_CONCURRENCY: usize = 8;
pub(crate) const MAX_RUNTIME_READ_RETAINED_BYTES: u32 = 128 * 1024 * 1024;
pub(crate) const MAX_RUNTIME_READ_PAGE_ROWS: usize = 64;
pub(crate) const MAX_RUNTIME_READ_PAGE_BYTES: u32 = 8 * 1024 * 1024;
pub(crate) const MAX_RUNTIME_READ_SNAPSHOT_BYTES: u32 = 128 * 1024 * 1024;

#[derive(Clone)]
pub(crate) struct ReadPool {
    inner: Arc<ReadPoolInner>,
}

struct ReadPoolInner {
    permits: Arc<Semaphore>,
    retained_bytes: Arc<Semaphore>,
    connections: Option<Mutex<Vec<Connection>>>,
    closed: AtomicBool,
    active: AtomicUsize,
    quiesced: Notify,
}

impl ReadPool {
    /// P3.4 compatibility constructor。它只提供不排队的 async concurrency gate；
    /// Runtime store 必须使用 `open_sqlite`，不能把本构造器冒充 WAL read pool。
    pub(crate) fn new(concurrency: usize) -> Result<Self, ReadPoolError> {
        Self::with_connections(concurrency, None)
    }

    pub(crate) fn open_sqlite(
        path: &Path,
        concurrency: usize,
        busy_timeout_ms: u64,
    ) -> Result<Self, ReadPoolError> {
        if concurrency == 0 {
            return Err(ReadPoolError::InvalidCapacity);
        }
        let mut connections = Vec::new();
        connections
            .try_reserve_exact(concurrency)
            .map_err(|_| ReadPoolError::CapacityUnavailable)?;
        for _ in 0..concurrency {
            let connection = open_read_only_wal(path, busy_timeout_ms)?;
            connections.push(connection);
        }
        Self::with_connections(concurrency, Some(connections))
    }

    fn with_connections(
        concurrency: usize,
        connections: Option<Vec<Connection>>,
    ) -> Result<Self, ReadPoolError> {
        if concurrency == 0 {
            return Err(ReadPoolError::InvalidCapacity);
        }
        Ok(Self {
            inner: Arc::new(ReadPoolInner {
                permits: Arc::new(Semaphore::new(concurrency)),
                retained_bytes: Arc::new(Semaphore::new(
                    usize::try_from(MAX_RUNTIME_READ_RETAINED_BYTES)
                        .map_err(|_| ReadPoolError::InvalidCapacity)?,
                )),
                connections: connections.map(Mutex::new),
                closed: AtomicBool::new(false),
                active: AtomicUsize::new(0),
                quiesced: Notify::new(),
            }),
        })
    }

    pub(crate) async fn run<F, T>(&self, operation: F) -> Result<T, ReadPoolError>
    where
        F: Future<Output = T>,
    {
        let _permit = self.try_connection_permit()?;
        let _active = ActiveOperation::new(self.inner.clone());
        Ok(operation.await)
    }

    /// 在真正 read-only connection 上执行一页同步查询。`retained_bytes` 是该页返回后
    /// 仍存活的最大内存；调用方持有 `RetainedReadPage` 期间 lease 不释放。
    pub(crate) async fn run_sqlite_page<T, F>(
        &self,
        retained_bytes: u32,
        operation: F,
    ) -> Result<RetainedReadPage<T>, ReadPoolError>
    where
        T: Send + 'static,
        F: FnOnce(&Connection) -> Result<T, ReadPoolError> + Send + 'static,
    {
        if retained_bytes == 0 || retained_bytes > MAX_RUNTIME_READ_PAGE_BYTES {
            return Err(ReadPoolError::PageBudgetOutOfRange);
        }
        self.run_sqlite_retained(retained_bytes, operation).await
    }

    /// 单个 sealed snapshot 可达 64 MiB，不把它伪装成 8 MiB page。调用方必须
    /// 继续用 TransferPart 分片发送。AEAD open 的 ciphertext/plaintext 瞬时峰值可达
    /// 128 MiB，因此这里保守预留全池 128 MiB；第二个 sender 必须等首个 lease
    /// 释放或立即 overload，不能让“最多 2 sender”绕过 memory cap。
    pub(crate) async fn run_sqlite_snapshot<T, F>(
        &self,
        operation: F,
    ) -> Result<RetainedReadPage<T>, ReadPoolError>
    where
        T: Send + 'static,
        F: FnOnce(&Connection) -> Result<T, ReadPoolError> + Send + 'static,
    {
        self.run_sqlite_retained(MAX_RUNTIME_READ_SNAPSHOT_BYTES, operation)
            .await
    }

    async fn run_sqlite_retained<T, F>(
        &self,
        retained_bytes: u32,
        operation: F,
    ) -> Result<RetainedReadPage<T>, ReadPoolError>
    where
        T: Send + 'static,
        F: FnOnce(&Connection) -> Result<T, ReadPoolError> + Send + 'static,
    {
        let checkout = self.try_checkout_sqlite(retained_bytes)?;
        let result = tokio::task::spawn_blocking(move || {
            let mut checkout = checkout;
            let operation_result: Result<T, ReadPoolError> = (|| {
                let transaction = checkout
                    .connection_mut()
                    .transaction_with_behavior(TransactionBehavior::Deferred)?;
                let value = operation(&transaction)?;
                transaction.commit()?;
                Ok(value)
            })();
            let memory_permit = checkout.finish();
            (operation_result, memory_permit)
        })
        .await
        .map_err(|_| ReadPoolError::WorkerStopped)?;
        let (operation_result, memory_permit) = result;
        let value = operation_result?;
        Ok(RetainedReadPage {
            value,
            _memory_permit: Arc::new(memory_permit),
        })
    }

    fn try_checkout_sqlite(&self, retained_bytes: u32) -> Result<SqliteCheckout, ReadPoolError> {
        let connection_permit = self.try_connection_permit()?;
        let memory_permit = self
            .inner
            .retained_bytes
            .clone()
            .try_acquire_many_owned(retained_bytes)
            .map_err(|error| match error {
                tokio::sync::TryAcquireError::NoPermits => ReadPoolError::Busy,
                tokio::sync::TryAcquireError::Closed => ReadPoolError::Closed,
            })?;
        let connections = self
            .inner
            .connections
            .as_ref()
            .ok_or(ReadPoolError::SqliteNotConfigured)?;
        let mut connections = connections.lock().map_err(|_| ReadPoolError::Closed)?;

        // checkout 与 close 以 connection mutex 为线性化边界。active 必须先登记，
        // 再二次读取 closed；这样 close 即使已经看到旧 active=0，也会等待本锁，
        // 而旧 checkout 不能在 close 之后把 active 从 0 升回 1 并启动查询。
        let active = ActiveOperation::new(self.inner.clone());
        if self.inner.closed.load(Ordering::Acquire) {
            drop(active);
            return Err(ReadPoolError::Closed);
        }
        let connection = connections.pop().ok_or(ReadPoolError::Closed)?;
        drop(connections);
        Ok(SqliteCheckout {
            inner: self.inner.clone(),
            connection: Some(connection),
            connection_permit: Some(connection_permit),
            memory_permit: Some(memory_permit),
            active: Some(active),
        })
    }

    fn try_connection_permit(&self) -> Result<OwnedSemaphorePermit, ReadPoolError> {
        if self.inner.closed.load(Ordering::Acquire) {
            return Err(ReadPoolError::Closed);
        }
        self.inner
            .permits
            .clone()
            .try_acquire_owned()
            .map_err(|error| match error {
                tokio::sync::TryAcquireError::NoPermits => ReadPoolError::Busy,
                tokio::sync::TryAcquireError::Closed => ReadPoolError::Closed,
            })
    }

    pub(crate) fn close(&self) {
        if !self.inner.closed.swap(true, Ordering::AcqRel) {
            self.inner.permits.close();
            self.inner.retained_bytes.close();
        }
        if let Some(connections) = &self.inner.connections
            && let Ok(mut connections) = connections.lock()
        {
            connections.clear();
        }
    }

    pub(crate) async fn close_and_wait(&self) {
        self.close();
        loop {
            // `notify_waiters` 不保存 permit；因此每个 waiter 必须先注册，再读取
            // active。归零发生在注册前时，本次读取直接退出；发生在注册后时，
            // 所有 waiter 都会被广播唤醒。
            let notified = self.inner.quiesced.notified();
            tokio::pin!(notified);
            let _ = notified.as_mut().enable();
            if self.inner.active.load(Ordering::Acquire) == 0 {
                break;
            }
            notified.await;
        }
        if let Some(connections) = &self.inner.connections
            && let Ok(mut connections) = connections.lock()
        {
            connections.clear();
        }
    }

    #[cfg(test)]
    fn available_connections(&self) -> usize {
        self.inner
            .connections
            .as_ref()
            .and_then(|connections| connections.lock().ok().map(|value| value.len()))
            .unwrap_or(0)
    }
}

/// 一次已线性化的 SQLite checkout。它在移入 `spawn_blocking` 后独占连接、
/// connection permit、retained-memory permit 与 active registration；即使调用方
/// abort/drop JoinHandle，资源也只会在 blocking closure 真正退出时收口。
struct SqliteCheckout {
    inner: Arc<ReadPoolInner>,
    connection: Option<Connection>,
    connection_permit: Option<OwnedSemaphorePermit>,
    memory_permit: Option<OwnedSemaphorePermit>,
    active: Option<ActiveOperation>,
}

impl SqliteCheckout {
    fn connection_mut(&mut self) -> &mut Connection {
        self.connection
            .as_mut()
            .expect("checked-out SQLite connection must exist until finish")
    }

    fn finish(mut self) -> OwnedSemaphorePermit {
        self.release_blocking_resources();
        self.memory_permit
            .take()
            .expect("checked-out memory permit must exist until page handoff")
    }

    fn release_blocking_resources(&mut self) {
        if let Some(connection) = self.connection.take() {
            let mut connection = Some(connection);
            if let Some(connections) = &self.inner.connections
                && let Ok(mut connections) = connections.lock()
                && !self.inner.closed.load(Ordering::Acquire)
            {
                connections.push(
                    connection
                        .take()
                        .expect("connection is returned at most once"),
                );
            }
            drop(connection);
        }
        drop(self.connection_permit.take());
        drop(self.active.take());
    }
}

impl Drop for SqliteCheckout {
    fn drop(&mut self) {
        self.release_blocking_resources();
    }
}

fn open_read_only_wal(path: &Path, busy_timeout_ms: u64) -> Result<Connection, ReadPoolError> {
    let flags = OpenFlags::SQLITE_OPEN_READ_ONLY
        | OpenFlags::SQLITE_OPEN_NO_MUTEX
        | OpenFlags::SQLITE_OPEN_NOFOLLOW;
    let connection = Connection::open_with_flags(path, flags)?;
    connection.busy_timeout(Duration::from_millis(busy_timeout_ms))?;
    connection.pragma_update(None, "query_only", true)?;
    connection.pragma_update(None, "trusted_schema", false)?;
    connection.pragma_update(None, "temp_store", "MEMORY")?;
    let query_only: i64 = connection.query_row("PRAGMA query_only", [], |row| row.get(0))?;
    let journal_mode: String = connection.query_row("PRAGMA journal_mode", [], |row| row.get(0))?;
    if query_only != 1 || !journal_mode.eq_ignore_ascii_case("wal") {
        return Err(ReadPoolError::PragmaMismatch);
    }
    Ok(connection)
}

struct ActiveOperation {
    inner: Arc<ReadPoolInner>,
}

impl ActiveOperation {
    fn new(inner: Arc<ReadPoolInner>) -> Self {
        inner.active.fetch_add(1, Ordering::AcqRel);
        Self { inner }
    }
}

impl Drop for ActiveOperation {
    fn drop(&mut self) {
        if self.inner.active.fetch_sub(1, Ordering::AcqRel) == 1 {
            self.inner.quiesced.notify_waiters();
        }
    }
}

/// 页内容的 memory lease；clone 共享同一 lease，最后一个副本销毁才归还预算。
pub(crate) struct RetainedReadPage<T> {
    value: T,
    _memory_permit: Arc<OwnedSemaphorePermit>,
}

impl<T> RetainedReadPage<T> {
    pub(crate) fn into_parts(self) -> (T, ReadMemoryLease) {
        (self.value, ReadMemoryLease(self._memory_permit))
    }
}

#[derive(Clone)]
pub(crate) struct ReadMemoryLease(Arc<OwnedSemaphorePermit>);

impl std::fmt::Debug for ReadMemoryLease {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let _shared_holders = Arc::strong_count(&self.0);
        formatter.write_str("ReadMemoryLease([REDACTED])")
    }
}

impl PartialEq for ReadMemoryLease {
    fn eq(&self, _other: &Self) -> bool {
        true
    }
}

impl Eq for ReadMemoryLease {}

#[derive(Debug, thiserror::Error)]
pub(crate) enum ReadPoolError {
    #[error("read pool capacity must be positive")]
    InvalidCapacity,
    #[error("read pool connection capacity could not be allocated")]
    CapacityUnavailable,
    #[error("read pool is closed")]
    Closed,
    #[error("read pool is at its bounded connection or memory limit")]
    Busy,
    #[error("read pool SQLite backend is not configured")]
    SqliteNotConfigured,
    #[error("read pool page budget is outside 1..=8 MiB")]
    PageBudgetOutOfRange,
    #[error("read pool SQLite connection is not query-only WAL")]
    PragmaMismatch,
    #[error("read pool blocking worker stopped")]
    WorkerStopped,
    #[error("read pool SQLite operation failed: {0}")]
    Sqlite(#[from] rusqlite::Error),
    #[error("read pool page operation failed: {0}")]
    Operation(#[source] RuntimeStoreError),
}

#[cfg(test)]
mod tests {
    use std::fs;
    use std::sync::atomic::{AtomicU64, AtomicUsize};

    use super::*;

    static NEXT_DATABASE: AtomicU64 = AtomicU64::new(1);

    fn wal_database() -> std::path::PathBuf {
        let path = std::env::temp_dir().join(format!(
            "agentdeck-runtime-read-pool-{}-{}.db",
            std::process::id(),
            NEXT_DATABASE.fetch_add(1, Ordering::Relaxed)
        ));
        let _ = fs::remove_file(&path);
        let connection = Connection::open(&path).expect("create read pool fixture");
        connection
            .pragma_update(None, "journal_mode", "WAL")
            .expect("enable WAL");
        connection
            .execute("CREATE TABLE fixture(value INTEGER NOT NULL)", [])
            .expect("create fixture table");
        connection
            .execute("INSERT INTO fixture(value) VALUES (7)", [])
            .expect("insert fixture row");
        drop(connection);
        path.canonicalize().expect("canonical fixture path")
    }

    #[tokio::test]
    async fn read_pool_enforces_its_own_concurrency_bound() {
        let pool = ReadPool::new(2).expect("read pool");
        let active = Arc::new(AtomicUsize::new(0));
        let peak = Arc::new(AtomicUsize::new(0));
        let busy_observed = Arc::new(AtomicUsize::new(0));
        let gate = Arc::new(tokio::sync::Barrier::new(3));
        let mut tasks = Vec::new();
        for _ in 0..6 {
            let pool = pool.clone();
            let active = active.clone();
            let peak = peak.clone();
            let busy_observed = busy_observed.clone();
            let gate = gate.clone();
            tasks.push(tokio::spawn(async move {
                let result = pool
                    .run(async move {
                        let now = active.fetch_add(1, Ordering::SeqCst) + 1;
                        peak.fetch_max(now, Ordering::SeqCst);
                        gate.wait().await;
                        active.fetch_sub(1, Ordering::SeqCst);
                    })
                    .await;
                if matches!(result, Err(ReadPoolError::Busy)) {
                    busy_observed.fetch_add(1, Ordering::SeqCst);
                }
                result
            }));
        }
        while busy_observed.load(Ordering::SeqCst) != 4 {
            tokio::task::yield_now().await;
        }
        gate.wait().await;
        let mut completed = 0;
        let mut busy = 0;
        for task in tasks {
            match task.await.expect("join read") {
                Ok(()) => completed += 1,
                Err(ReadPoolError::Busy) => busy += 1,
                other => panic!("unexpected read result: {other:?}"),
            }
        }
        assert_eq!(completed, 2);
        assert_eq!(busy, 4);
        assert_eq!(peak.load(Ordering::SeqCst), 2);
    }

    #[tokio::test]
    async fn sqlite_pool_opens_exactly_eight_query_only_wal_connections() {
        let path = wal_database();
        let pool = ReadPool::open_sqlite(&path, DEFAULT_RUNTIME_READ_CONCURRENCY, 100)
            .expect("open SQLite read pool");
        assert_eq!(pool.available_connections(), 8);
        let page = pool
            .run_sqlite_page(1024, |connection| {
                let query_only: i64 =
                    connection.query_row("PRAGMA query_only", [], |row| row.get(0))?;
                let mode: String =
                    connection.query_row("PRAGMA journal_mode", [], |row| row.get(0))?;
                assert_eq!(query_only, 1);
                assert_eq!(mode.to_ascii_lowercase(), "wal");
                let value: i64 =
                    connection.query_row("SELECT value FROM fixture", [], |row| row.get(0))?;
                assert_eq!(value, 7);
                assert!(connection.execute("DELETE FROM fixture", []).is_err());
                Ok(())
            })
            .await
            .expect("query page");
        drop(page);
        assert_eq!(pool.available_connections(), 8);
        pool.close_and_wait().await;
        assert_eq!(pool.available_connections(), 0);
        let _ = fs::remove_file(path);
    }

    #[tokio::test]
    async fn page_memory_is_reserved_until_last_clone_lease_drops() {
        let path = wal_database();
        let pool = ReadPool::open_sqlite(&path, 1, 100).expect("open SQLite read pool");
        let page = pool
            .run_sqlite_page(MAX_RUNTIME_READ_PAGE_BYTES, |_| Ok(vec![0_u8; 1]))
            .await
            .expect("first page");
        let (_value, lease) = page.into_parts();
        assert_eq!(
            pool.inner.retained_bytes.available_permits(),
            usize::try_from(MAX_RUNTIME_READ_RETAINED_BYTES - MAX_RUNTIME_READ_PAGE_BYTES)
                .expect("permit count")
        );
        let second = pool
            .run_sqlite_page(MAX_RUNTIME_READ_PAGE_BYTES, |_| Ok(()))
            .await
            .expect("second page remains below 128 MiB");
        drop(second);
        drop(lease);
        assert_eq!(
            pool.inner.retained_bytes.available_permits(),
            usize::try_from(MAX_RUNTIME_READ_RETAINED_BYTES).expect("permit count")
        );
        pool.close_and_wait().await;
        let _ = fs::remove_file(path);
    }

    #[tokio::test]
    async fn one_max_snapshot_lease_exhausts_the_exact_128_mib_retained_cap() {
        let path = wal_database();
        let pool = ReadPool::open_sqlite(&path, 1, 100).expect("open SQLite read pool");
        let first = pool
            .run_sqlite_snapshot(|_| Ok(()))
            .await
            .expect("max snapshot transient lease");
        assert!(matches!(
            pool.run_sqlite_snapshot(|_| Ok(())).await,
            Err(ReadPoolError::Busy)
        ));
        drop(first);
        let replacement = pool
            .run_sqlite_snapshot(|_| Ok(()))
            .await
            .expect("released snapshot budget is reusable");
        drop(replacement);
        pool.close_and_wait().await;
        let _ = fs::remove_file(path);
    }

    #[tokio::test]
    async fn aborted_sqlite_query_retains_checkout_and_snapshot_budget_until_blocking_exit() {
        let path = wal_database();
        let pool = ReadPool::open_sqlite(&path, 1, 100).expect("open SQLite read pool");
        let (interrupt_tx, interrupt_rx) = std::sync::mpsc::channel();
        let read = tokio::spawn({
            let pool = pool.clone();
            async move {
                pool.run_sqlite_snapshot(move |connection| {
                    interrupt_tx
                        .send(connection.get_interrupt_handle())
                        .expect("publish SQLite interrupt handle");
                    let _: i64 = connection.query_row(
                        "WITH RECURSIVE counter(value) AS (
                             SELECT 0
                             UNION ALL
                             SELECT value + 1 FROM counter WHERE value < 1000000000
                         )
                         SELECT max(value) FROM counter",
                        [],
                        |row| row.get(0),
                    )?;
                    Ok(())
                })
                .await
            }
        });
        let interrupt = tokio::task::spawn_blocking(move || {
            interrupt_rx
                .recv_timeout(Duration::from_secs(2))
                .expect("SQLite query starts")
        })
        .await
        .expect("join interrupt observer");

        read.abort();
        let abort_error = match read.await {
            Err(error) => error,
            Ok(_) => panic!("outer task unexpectedly completed after abort"),
        };
        assert!(
            abort_error.is_cancelled(),
            "abort must drop the caller future without stopping SQLite"
        );
        let checkout_stayed_busy = matches!(
            pool.run_sqlite_page(1024, |_| Ok(())).await,
            Err(ReadPoolError::Busy)
        );
        let snapshot_budget_stayed_busy = matches!(
            pool.run_sqlite_snapshot(|_| Ok(())).await,
            Err(ReadPoolError::Busy)
        );

        let close = tokio::spawn({
            let pool = pool.clone();
            async move { pool.close_and_wait().await }
        });
        while !pool.inner.closed.load(Ordering::Acquire) {
            tokio::task::yield_now().await;
        }
        let close_waited_for_sqlite = !close.is_finished();

        interrupt.interrupt();
        tokio::time::timeout(Duration::from_secs(2), close)
            .await
            .expect("close completes after SQLite interrupt")
            .expect("join close waiter");

        assert!(
            checkout_stayed_busy,
            "caller cancellation must not release the checked-out connection"
        );
        assert!(
            snapshot_budget_stayed_busy,
            "caller cancellation must not release the 128 MiB snapshot budget"
        );
        assert!(
            close_waited_for_sqlite,
            "close_and_wait must include the detached blocking query"
        );
        assert_eq!(pool.available_connections(), 0);
        let _ = fs::remove_file(path);
    }

    #[tokio::test]
    async fn sqlite_checkout_registration_linearizes_before_close() {
        let path = wal_database();
        let pool = ReadPool::open_sqlite(&path, 1, 100).expect("open SQLite read pool");
        let checkout = pool
            .try_checkout_sqlite(1024)
            .expect("register checkout before close");

        let close = tokio::spawn({
            let pool = pool.clone();
            async move { pool.close_and_wait().await }
        });
        while !pool.inner.closed.load(Ordering::Acquire) {
            tokio::task::yield_now().await;
        }
        assert!(
            !close.is_finished(),
            "close cannot observe active=0 after checkout has linearized"
        );

        drop(checkout);
        tokio::time::timeout(Duration::from_secs(2), close)
            .await
            .expect("close completes after checkout cleanup")
            .expect("join close waiter");
        assert_eq!(pool.available_connections(), 0);
        let _ = fs::remove_file(path);
    }

    #[tokio::test]
    async fn close_waits_for_active_sqlite_page_without_a_lost_wake() {
        let path = wal_database();
        let pool = ReadPool::open_sqlite(&path, 1, 100).expect("open SQLite read pool");
        let (entered_tx, entered_rx) = std::sync::mpsc::channel();
        let (release_tx, release_rx) = std::sync::mpsc::channel();
        let read = tokio::spawn({
            let pool = pool.clone();
            async move {
                pool.run_sqlite_page(1024, move |_| {
                    entered_tx.send(()).expect("publish entered state");
                    release_rx.recv().expect("release active read");
                    Ok(())
                })
                .await
            }
        });
        tokio::task::spawn_blocking(move || {
            entered_rx
                .recv_timeout(Duration::from_secs(2))
                .expect("read enters blocking operation");
        })
        .await
        .expect("join entered observer");
        let close = tokio::spawn({
            let pool = pool.clone();
            async move { pool.close_and_wait().await }
        });
        tokio::task::yield_now().await;
        assert!(!close.is_finished(), "close cannot detach an active read");
        release_tx.send(()).expect("release active read");
        read.await
            .expect("join active read")
            .expect("active read finishes during close");
        close.await.expect("close observes quiescence");
        assert_eq!(pool.available_connections(), 0);
        let _ = fs::remove_file(path);
    }

    #[tokio::test]
    async fn every_concurrent_close_waiter_observes_sqlite_quiescence() {
        let path = wal_database();
        let pool = ReadPool::open_sqlite(&path, 1, 100).expect("open SQLite read pool");
        let (entered_tx, entered_rx) = std::sync::mpsc::channel();
        let (release_tx, release_rx) = std::sync::mpsc::channel();
        let read = tokio::spawn({
            let pool = pool.clone();
            async move {
                pool.run_sqlite_page(1024, move |_| {
                    entered_tx.send(()).expect("publish entered state");
                    release_rx.recv().expect("release active read");
                    Ok(())
                })
                .await
            }
        });
        tokio::task::spawn_blocking(move || {
            entered_rx
                .recv_timeout(Duration::from_secs(2))
                .expect("read enters blocking operation");
        })
        .await
        .expect("join entered observer");

        let first_close = tokio::spawn({
            let pool = pool.clone();
            async move { pool.close_and_wait().await }
        });
        let second_close = tokio::spawn({
            let pool = pool.clone();
            async move { pool.close_and_wait().await }
        });
        tokio::task::yield_now().await;
        assert!(!first_close.is_finished());
        assert!(!second_close.is_finished());

        release_tx.send(()).expect("release active read");
        read.await
            .expect("join active read")
            .expect("active read finishes during close");
        tokio::time::timeout(Duration::from_secs(2), async {
            first_close.await.expect("join first close waiter");
            second_close.await.expect("join second close waiter");
        })
        .await
        .expect("all close waiters observe quiescence");
        assert_eq!(pool.available_connections(), 0);
        let _ = fs::remove_file(path);
    }
}
