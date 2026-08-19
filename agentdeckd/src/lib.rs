//! Daemon library facade — exposes modules to integration tests and to
//! the bin crate `agentdeckd`.
//!
//! v4 protocol only; v1 IPC types were removed in T1.9. The codex
//! module is the only place in the daemon that knows Codex exists
//! (N3); `ClaudeCodeAdapter` is its sibling under `claude_code/`.

pub mod agent;
pub mod claude_code;
pub mod codex;
pub mod diag;
pub mod ipc;
pub mod record;
pub mod runtime;
