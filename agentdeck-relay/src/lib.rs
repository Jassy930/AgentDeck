// agentdeck-relay/src/lib.rs
//! AgentDeck relay — R0 内存 fake relay + stdio machine bridge（无网络）。
//!
//! 控制面（RelayControlMsg）relay 可读用于路由；数据面（DataEnvelope）不可见。

// auth 的 store 子模块起本 task 起需要对外可见（main.rs 二进制 crate 构造
// `InMemoryRelayStore` 并传给 `server::serve`）；其余子模块（crypto/enroll）
// 仍是 pub(crate)，只供 crate 内部（server 层）使用。整个模块在 default（无
// server feature）构建下仍只被自身单测使用，故保留 dead_code 静默。
#[allow(dead_code)]
pub mod auth;
mod bridge;
// config 的公开面起本 task 起需要对外可见（main.rs 构造 `RelayConfig`）；
// 在 default（无 server feature）构建下仍只被自身单测使用，保留 dead_code 静默。
#[allow(dead_code)]
pub mod config;
mod relay_link;
mod router;
#[cfg(feature = "server")]
pub mod server;
// R1b Task 3：SQLite backed `RelayStore` 实现；`pub` 因 Task 9 main.rs 需要
// 跨 crate 构造（`agentdeck-relay` 二进制 crate）。default（无 server feature）
// 构建下仍只被自身单测使用，保留 dead_code 静默。
#[allow(dead_code)]
pub mod store;

pub use bridge::StdioMachineBridge;
pub use relay_link::RelayLink;
pub use router::{FakeRelay, RelayClient};
pub use store::SqliteRelayStore;
