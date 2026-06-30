//! Claude Code adapter — spawns `claude --print --output-format stream-json`
//! per turn. Implements the v2 `Agent` trait.
//!
//! N3 守护：本模块禁止 use codex::* 任何符号。共享逻辑只能下沉到 `agent`
//!         trait 默认方法或 daemon 层；不可直接复用 codex 子模块的实现。
//! N8 守护：本模块禁止创建 ~/Library/Application Support/AgentDeck/cc-meta/
//!         或任何 CC 元数据层；history（在 Task 4B 实现）一律走 CC 原生接口
//!         （`claude agents --json` 与 `~/.claude/projects/*.jsonl`）。
//!
//! Task 4A scope:
//!   - `adapter.rs` — `ClaudeCodeAdapter`: spawn `claude` CLI + initial
//!     `start_session` + cancel; `submit_decision` / `submit_vendor_control`
//!     / `continue_thread` stubbed for Task 4B.
//!   - `translate.rs` — `ClaudeCodeTranslator`: full stream-json → v2
//!     `ServerEvent` mapping for the assistant / user / system / result /
//!     hook line types.
//!   - `capabilities.rs` / `auth.rs` / `history.rs` — docstring-only stubs
//!     for Task 4B.

pub mod adapter;
pub mod auth;
pub mod capabilities;
pub mod history;
pub mod translate;

pub use adapter::ClaudeCodeAdapter;
