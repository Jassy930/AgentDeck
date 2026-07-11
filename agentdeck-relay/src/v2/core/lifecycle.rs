//! Core 所有后台任务的取消与确定性收尾辅助。

use std::future::Future;

use tokio::task::{JoinError, JoinSet};
use tokio_util::sync::CancellationToken;

/// RelayCore actor 独占的 structured-concurrency 根。
///
/// replay/connection 子任务只能用 [`CoreTasks::spawn`] 注册；`spawn` 自动把 future 包在
/// root cancellation 中。shutdown 先广播 cancel，再完整 join。异常退出路径可调用
/// [`CoreTasks::abort_and_join`]，保证没有任务在 Core receiver 消失后继续持有 sender。
#[derive(Debug)]
pub(crate) struct CoreTasks {
    cancel: CancellationToken,
    joins: JoinSet<()>,
}

impl CoreTasks {
    pub(crate) fn new() -> Self {
        Self {
            cancel: CancellationToken::new(),
            joins: JoinSet::new(),
        }
    }

    #[cfg(test)]
    pub(crate) fn is_cancelled(&self) -> bool {
        self.cancel.is_cancelled()
    }

    pub(crate) fn is_empty(&self) -> bool {
        self.joins.is_empty()
    }

    #[cfg(test)]
    pub(crate) fn len(&self) -> usize {
        self.joins.len()
    }

    pub(crate) fn spawn<F>(&mut self, task: F)
    where
        F: Future<Output = ()> + Send + 'static,
    {
        let cancel = self.cancel.child_token();
        self.joins.spawn(async move {
            tokio::select! {
                biased;
                _ = cancel.cancelled() => {}
                _ = task => {}
            }
        });
    }

    pub(crate) async fn join_next(&mut self) -> Option<Result<(), JoinError>> {
        self.joins.join_next().await
    }

    /// 正常 shutdown：任务必须响应共享 token；完整 join 后才返回。
    pub(crate) async fn shutdown(&mut self) -> Vec<JoinError> {
        self.cancel.cancel();
        let mut failures = Vec::new();
        while let Some(result) = self.joins.join_next().await {
            if let Err(error) = result {
                failures.push(error);
            }
        }
        failures
    }

    /// fail-closed/actor panic 路径：先 cancel，再 abort 尚未退出的任务并完整回收。
    pub(crate) async fn abort_and_join(&mut self) -> Vec<JoinError> {
        self.cancel.cancel();
        self.joins.abort_all();
        let mut failures = Vec::new();
        while let Some(result) = self.joins.join_next().await {
            if let Err(error) = result {
                failures.push(error);
            }
        }
        failures
    }
}

impl Default for CoreTasks {
    fn default() -> Self {
        Self::new()
    }
}

impl Drop for CoreTasks {
    fn drop(&mut self) {
        self.cancel.cancel();
        self.joins.abort_all();
    }
}

#[cfg(test)]
mod tests {
    use std::sync::Arc;
    use std::sync::atomic::{AtomicBool, Ordering};

    use super::*;

    struct ExitGuard(Arc<AtomicBool>);

    impl Drop for ExitGuard {
        fn drop(&mut self) {
            self.0.store(true, Ordering::Release);
        }
    }

    #[tokio::test]
    async fn shutdown_cancels_and_joins_every_child() {
        let mut tasks = CoreTasks::new();
        let exited = Arc::new(AtomicBool::new(false));
        let (started_tx, started_rx) = tokio::sync::oneshot::channel();
        let task_exited = exited.clone();
        tasks.spawn(async move {
            let _guard = ExitGuard(task_exited);
            let _ = started_tx.send(());
            std::future::pending::<()>().await;
        });
        started_rx.await.expect("child started");
        assert_eq!(tasks.len(), 1);
        assert!(!tasks.is_cancelled());

        let failures = tasks.shutdown().await;
        assert!(failures.is_empty());
        assert!(tasks.is_empty());
        assert!(tasks.is_cancelled());
        assert!(exited.load(Ordering::Acquire));
    }

    #[tokio::test]
    async fn abort_path_reaps_every_child_after_root_cancel() {
        let mut tasks = CoreTasks::new();
        tasks.spawn(std::future::pending());
        let failures = tasks.abort_and_join().await;
        assert!(failures.iter().all(tokio::task::JoinError::is_cancelled));
        assert!(tasks.is_empty());
    }
}
