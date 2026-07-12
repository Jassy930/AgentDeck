//! Codex adapter — translates codex app-server JSON-RPC into neutral
//! agent events. v2 protocol; N3 守护：本模块禁止 use claude_code::* 任何符号。
//! vendor thread id 只允许进入本模块的 typed state repository；common catalog
//! 只保存 neutral adapterStateKey。

pub mod adapter;
pub mod capabilities;
pub mod history;
mod state;
pub mod translate;

pub use adapter::CodexAdapter;
