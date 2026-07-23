//! AgentDeck Relay 的纯 outbound client。
//!
//! 默认 surface 只暴露 Relay v2 WSS/SPKI pin、machine enrollment 与受限 pairing
//! client；不依赖 Relay server/store。

pub mod v2;

pub use v2::{
    EnrollmentClientConfig, LinkAuthenticator, PairingEvent, ReceivedRelayFrame, RelayClient,
    RelayClientConfig, RelayClientError, RelayEnrollmentClient, RelayPairingClient, RelayTlsPolicy,
};
