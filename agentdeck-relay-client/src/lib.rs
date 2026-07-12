//! AgentDeck Relay 的纯 outbound client。
//!
//! 默认 surface 只暴露 Relay v2 WSS/SPKI pin、machine enrollment 与受限 pairing
//! client；不依赖 Relay server/store。`v1-compat` 只是 P2.8→P2.9 之间供旧 CLI 与
//! 历史测试显式启用的短暂桥，P2.9 会连同 Relay v1 一起删除。

#[cfg(feature = "v1-compat")]
mod inproc;
pub mod v2;
#[cfg(feature = "v1-compat")]
mod ws;

#[cfg(feature = "v1-compat")]
pub use inproc::InProcRelayClient;
pub use v2::{
    EnrollmentClientConfig, LinkAuthenticator, PairingEvent, RelayClient, RelayClientConfig,
    RelayClientError, RelayEnrollmentClient, RelayPairingClient, RelayTlsPolicy,
};
#[cfg(feature = "v1-compat")]
pub use ws::{WsError, WsRelayClient};
