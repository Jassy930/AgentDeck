//! Persistent remote client 的可复用 library 边界。
//!
//! CLI 参数解析、终端输出与 Runtime 命令编排继续留在 binary-private `remote_cli`。

#[cfg(unix)]
pub mod conversations;
#[cfg(all(test, unix))]
mod conversations_tests;
pub mod crypto_state;
pub mod device_lock;
pub mod keychain;
#[cfg(unix)]
pub mod machines;
#[cfg(target_os = "macos")]
mod macos_keychain;
#[cfg(unix)]
pub mod mutations;
#[cfg(all(test, unix))]
mod mutations_tests;
#[cfg(unix)]
pub mod pair;
#[cfg(unix)]
pub mod paired_machine;
pub mod pending;
#[cfg(unix)]
pub mod production;
#[cfg(unix)]
pub mod relay_transport;
#[cfg(all(test, unix))]
mod relay_transport_tests;
#[cfg(unix)]
pub mod runtime;
#[cfg(unix)]
pub mod selector;
pub mod signature;
#[cfg(unix)]
pub mod stream_state;
pub mod transfer_state;
