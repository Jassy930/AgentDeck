//! 与 prompt/control/connection writer 相互独立的有界只读池。

use std::future::Future;
use std::sync::Arc;

use tokio::sync::Semaphore;

pub(crate) const DEFAULT_RUNTIME_READ_CONCURRENCY: usize = 8;

#[derive(Clone)]
pub(crate) struct ReadPool {
    permits: Arc<Semaphore>,
}

impl ReadPool {
    pub(crate) fn new(concurrency: usize) -> Result<Self, ReadPoolError> {
        if concurrency == 0 {
            return Err(ReadPoolError::InvalidCapacity);
        }
        Ok(Self {
            permits: Arc::new(Semaphore::new(concurrency)),
        })
    }

    pub(crate) async fn run<F, T>(&self, operation: F) -> Result<T, ReadPoolError>
    where
        F: Future<Output = T>,
    {
        // 不在 semaphore 上排队：调用方 task 本身也是内存预算。满载立即返回 typed
        // overload，避免“并发只有 8，但等待 future 无界”的伪有界池。
        let _permit = self.permits.clone().try_acquire_owned().map_err(|error| {
            if self.permits.is_closed() {
                ReadPoolError::Closed
            } else {
                let _ = error;
                ReadPoolError::Busy
            }
        })?;
        Ok(operation.await)
    }

    pub(crate) fn close(&self) {
        self.permits.close();
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq, thiserror::Error)]
pub(crate) enum ReadPoolError {
    #[error("read pool capacity must be positive")]
    InvalidCapacity,
    #[error("read pool is closed")]
    Closed,
    #[error("read pool is at its bounded concurrency limit")]
    Busy,
}

#[cfg(test)]
mod tests {
    use std::sync::atomic::{AtomicUsize, Ordering};

    use super::*;

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
                if result == Err(ReadPoolError::Busy) {
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
}
