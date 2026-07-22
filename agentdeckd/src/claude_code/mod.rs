//! Claude Code adapter — spawns `claude --print --output-format stream-json`
//! per turn. Implements the v2 `Agent` trait.
//!
//! N3 守护：本模块禁止 use codex::* 任何符号。共享逻辑只能下沉到 `agent`
//!         trait 默认方法或 daemon 层；不可直接复用 codex 子模块的实现。
//! N8 守护：本模块禁止创建 ~/Library/Application Support/AgentDeck/cc-meta/
//!         或任何 CC 元数据层；history（在 Task 4B 实现）一律走 CC 原生接口
//!         （`claude agents --json` 与 `~/.claude/projects/*.jsonl`）。
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

pub mod adapter;
pub mod auth;
pub mod capabilities;
pub mod history;
pub mod translate;

pub use adapter::ClaudeCodeAdapter;

/// Claude Code 2.1.191 uses `Agent`; older/current-compatible tool tables may
/// still expose `Task`. Keep this vendor spelling inside the CC adapter and
/// emit only the neutral `activityKind=collaboration` marker downstream.
pub(super) fn is_collaboration_tool_name(name: &str) -> bool {
    matches!(name, "Agent" | "Task")
}
