//! `agentdeck-relay-client`: RelayLink 的两种客户端实现——
//! `InProcRelayClient`（把内存 `RelayClient` 包成 `RelayLink`，用于测试/进程内
//! composition）与 `WsRelayClient`（在 `agentdeck_protocol::Transport` 的
//! WS 实现之上编解码 `RemoteFrame`，用于真联网场景）。

mod inproc;
mod ws;

pub use inproc::InProcRelayClient;
pub use ws::{WsRelayClient, WsError};
