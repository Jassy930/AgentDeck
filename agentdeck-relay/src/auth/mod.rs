// agentdeck-relay/src/auth/mod.rs
//! 身份模型 + RelayStore + 密码学 + challenge-response enroll（纯逻辑，无网络）。

pub(crate) mod crypto;
pub(crate) mod enroll;
pub(crate) mod store;
