// agentdeck-relay/src/lib.rs
//! AgentDeck relay — R0 内存 fake relay + stdio machine bridge（无网络）。
//!
//! 控制面（RelayControlMsg）relay 可读用于路由；数据面（DataEnvelope）不可见。

mod bridge;
mod router;

pub use bridge::StdioMachineBridge;
pub use router::{FakeRelay, RelayClient};
