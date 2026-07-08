// agentdeck-relay/src/auth/mod.rs
//! 身份模型 + RelayStore + 密码学 + challenge-response enroll（纯逻辑，无网络）。

pub(crate) mod crypto;
pub(crate) mod enroll;
// `store` 起 Task 9 起需要跨 crate 可见——main.rs（agentdeck-relay 二进制，
// 独立 crate）需要 `agentdeck_relay::auth::store::InMemoryRelayStore` 来构造并
// 传给 `server::serve`。`RelayStore` trait 本身仍 `pub(crate)`（只供 crate 内
// server 层用 trait 方法，main.rs 不需要按 trait 使用它）。
pub mod store;
