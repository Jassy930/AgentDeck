//! lib unit-test 进程内的独立 RuntimeStore fixture admission。

use std::sync::{Arc, OnceLock};

use tokio::sync::{OwnedSemaphorePermit, Semaphore};

use crate::runtime::model::RuntimeStoreError;

// macOS 默认 soft fd limit 是 256；每份真实 fixture 固定打开一个 writer 与八个
// query-only WAL reader。四份仍保留跨 Store 并发，同时给同进程 raw SQLite/tests
// 和运行时文件留出明确余量。单个 Store 内部的八路并发完全不变。
const MAX_CONCURRENT_TEST_STORES: usize = 4;

pub(super) async fn acquire() -> Result<OwnedSemaphorePermit, RuntimeStoreError> {
    static SLOTS: OnceLock<Arc<Semaphore>> = OnceLock::new();
    SLOTS
        .get_or_init(|| Arc::new(Semaphore::new(MAX_CONCURRENT_TEST_STORES)))
        .clone()
        .acquire_owned()
        .await
        .map_err(|_| RuntimeStoreError::InvalidConfig("test store admission is closed"))
}
