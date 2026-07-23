//! Persistent remote client 的可复用 library 边界。
//!
//! CLI 参数解析、终端输出与 Runtime 命令编排继续留在 binary-private `remote_cli`。

pub mod crypto_state;
pub mod device_lock;
pub mod keychain;
