//! Codex adapter — translates codex app-server JSON-RPC into neutral
//! agent events. v2 protocol; N3 守护：本模块禁止 use claude_code::* 任何符号.

pub mod adapter;
pub mod capabilities;
pub mod translate;

pub use adapter::CodexAdapter;
