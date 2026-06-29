//! Neutral IPC protocol — now sourced from the `agentdeck-protocol` crate.
//!
//! The types live in `agentdeck-protocol` so daemon and CLI/clients share one
//! source of truth. This re-export keeps `crate::ipc::X` / `ipc::X` references
//! (main.rs, codex.rs) compiling unchanged.
pub use agentdeck_protocol::*;
