//! Codex adapter — translates codex app-server JSON-RPC into neutral
//! agent events. v4 protocol; N3 守护：本模块禁止 use claude_code::* 任何符号.

pub mod adapter;
pub(crate) mod app_server;
pub mod capabilities;
pub mod history;
pub(crate) mod session;
pub mod translate;

pub use adapter::CodexAdapter;
