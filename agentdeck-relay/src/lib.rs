// agentdeck-relay/src/lib.rs
//! AgentDeck relay — R0 内存 fake relay + stdio machine bridge（无网络）。
//!
//! 控制面（RelayControlMsg）relay 可读用于路由；数据面（DataEnvelope）不可见。

// auth 的公开面在 Task 6 尚无调用方（server 层由 Task 9 引入并消费）；
// 整个模块（数据模型/密码学/enroll 纯函数）此刻只被自身单测使用。
#[allow(dead_code)]
mod auth;
mod bridge;
// config 的公开面在 Task 8 尚无调用方（server 层由 Task 9 引入并消费 RelayConfig）；
// 此刻只被自身单测使用。
#[allow(dead_code)]
mod config;
mod relay_link;
mod router;

pub use bridge::StdioMachineBridge;
pub use relay_link::RelayLink;
pub use router::{FakeRelay, RelayClient};
