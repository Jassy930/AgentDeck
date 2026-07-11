//! Revoke / machine retirement terminal drain 的硬截止语义。

use std::time::Duration;

use super::writer::{WriterCloseReason, WriterHandle};

/// 从 Relay 观察到 durable COMMIT 起，terminal 最多保留连接 2 秒。
pub(crate) const TERMINAL_DRAIN_DEADLINE: Duration = Duration::from_secs(2);

/// 等待 terminal flush/transport close；deadline 到达时直接关闭 writer。
///
/// 此 future 自己执行 `close`，不依赖可能满载的 Core command queue，因此 2 秒是硬上限。
pub(crate) async fn close_on_terminal_deadline(
    writer: WriterHandle,
    terminal_reason: WriterCloseReason,
) -> WriterCloseReason {
    tokio::select! {
        biased;
        reason = writer.closed() => reason,
        _ = tokio::time::sleep(TERMINAL_DRAIN_DEADLINE) => {
            writer.close(terminal_reason);
            writer.close_reason().unwrap_or(terminal_reason)
        }
    }
}
