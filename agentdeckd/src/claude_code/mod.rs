//! Claude Code adapter — spawns `claude --print --output-format stream-json`
//! per turn. Implements the v2 `Agent` trait.
//!
//! N3 守护：本模块禁止 use codex::* 任何符号。共享逻辑只能下沉到 `agent`
//!         trait 默认方法或 daemon 层；不可直接复用 codex 子模块的实现。
//! N8 守护：CC 原生 history/session 文件始终是唯一权威事实源。本模块只允许
//!         `state` 在 Runtime DB 私有 namespace 保存 StorageKEK 保护、可重建的
//!         adapterStateKey→session id 派生索引；禁止 `cc-meta/`，也不保存
//!         title/archive/status/transcript。
//!
//! Module map (Phase 4 Tasks 4A + 4B):
//!   - `adapter.rs` — `ClaudeCodeAdapter`: spawn `claude` CLI, run the
//!     pump, route permission responses (`submit_decision`) and reject
//!     vendor-control mutations with structured "requires new turn"
//!     errors (`submit_vendor_control`).
//!   - `translate.rs` — `ClaudeCodeTranslator`: full stream-json → v2
//!     `ServerEvent` mapping for the assistant / user / system / result
//!     / hook line types.
//!   - `capabilities.rs` — real `claude --version` probe + typed
//!     `SessionCapabilities` builder (N5 对称约束).
//!   - `auth.rs` — `claude auth status` probe → tri+1 `AuthState`.
//!   - `history.rs` — `.jsonl` enumeration + read + native rename /
//!     archive (no `cc-meta/` layer; N8 守护).
//!   - `state.rs` — typed private resume index；不成为 CC history 事实源。

pub mod adapter;
pub mod auth;
pub mod capabilities;
pub mod history;
mod state;
pub mod translate;

pub use adapter::ClaudeCodeAdapter;
