//! Codex history adapter — stub for v0.2.
//!
//! Phase 4 Task 4C deliberately stubs Codex history pending real
//! `codex app-server thread/list` + `thread/read` wiring. The spec
//! § 5 priority is "v0.2 CC MUST history; Codex MAY" — Codex history
//! is not on the v0.2 release-gate path (see § 8 验收清单 items
//! 7.3 "fixture replay" and 7.6 "门控 E2E" reference CC fixtures only).
//!
//! The Agent trait still surfaces these functions through
//! `CodexAdapter::handle_history` so the unified `HistoryRequest`
//! protocol works end-to-end across both adapters — Codex just
//! returns empty / "not-supported" while v0.3 wires the real
//! app-server thread/list + thread/read.
//!
//! ## v0.3 wiring sketch
//!
//! Codex app-server exposes JSON-RPC methods `thread/list` (returns
//! thread metadata array) and `thread/read(includeTurns: true)`
//! (returns turn-by-turn transcript). Real impl would spawn one
//! short-lived `codex app-server` per query, send `initialize` →
//! `thread/list`, parse, kill. `thread/archive` similarly exists.
//! The cost is per-query latency (~1s for spawn + handshake); a long-
//! running shared app-server is the v0.4+ optimization.

use agentdeck_protocol::{HistoryListItem, HistoryReadResponse, ProtocolError, ThreadId};
use std::path::Path;

/// List Codex history. v0.2 stub: returns an empty list. The router's
/// cross-agent List merger silently absorbs this (one adapter returning
/// nothing is fine) so CC history still surfaces alongside.
///
/// v0.3 will implement this by spawning `codex app-server` and sending
/// `thread/list`.
pub async fn list_history(
    _cwd_filter: Option<&Path>,
) -> Result<Vec<HistoryListItem>, ProtocolError> {
    // TODO(v0.3): spawn `codex app-server`, run initialize + thread/list,
    // map result.threads[] → HistoryListItem. For v0.2 we deliberately
    // return empty so the cross-agent merger still works — see
    // `AgentRouter::handle_history_cross_agent`.
    Ok(Vec::new())
}

/// Read one Codex thread. v0.2 stub: returns a structured "not
/// implemented yet" error. The CC reader is the v0.2 happy path.
pub async fn read_history(_thread_id: &ThreadId) -> Result<HistoryReadResponse, ProtocolError> {
    Err(ProtocolError {
        code: "codex-history-read-not-implemented".into(),
        message: "Codex thread/read not wired in v0.2; see codex/history.rs TODO(v0.3)".into(),
        diagnostic_ref: None,
    })
}

/// Archive a Codex thread. v0.2 stub: returns a structured error.
pub async fn archive(_thread_id: &ThreadId) -> Result<(), ProtocolError> {
    Err(ProtocolError {
        code: "codex-archive-not-supported".into(),
        message: "Codex thread archive not exposed in v0.2".into(),
        diagnostic_ref: None,
    })
}

/// Unarchive a Codex thread. v0.2 stub.
pub async fn unarchive(_thread_id: &ThreadId) -> Result<(), ProtocolError> {
    Err(ProtocolError {
        code: "codex-unarchive-not-supported".into(),
        message: "Codex thread unarchive not exposed in v0.2".into(),
        diagnostic_ref: None,
    })
}

/// Rename a Codex thread. v0.2 stub.
pub async fn rename(_thread_id: &ThreadId, _title: &str) -> Result<(), ProtocolError> {
    Err(ProtocolError {
        code: "codex-rename-not-supported".into(),
        message: "Codex thread rename not exposed in v0.2".into(),
        diagnostic_ref: None,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn list_history_returns_empty_for_v02_stub() {
        let items = list_history(None).await.expect("stub never errors");
        assert!(items.is_empty(), "v0.2 stub must return empty Vec");
    }

    #[tokio::test]
    async fn read_history_returns_not_implemented_error() {
        let err = read_history(&ThreadId("x".into())).await.unwrap_err();
        assert_eq!(err.code, "codex-history-read-not-implemented");
    }

    #[tokio::test]
    async fn archive_returns_structured_error() {
        let err = archive(&ThreadId("x".into())).await.unwrap_err();
        assert_eq!(err.code, "codex-archive-not-supported");
    }

    #[tokio::test]
    async fn unarchive_returns_structured_error() {
        let err = unarchive(&ThreadId("x".into())).await.unwrap_err();
        assert_eq!(err.code, "codex-unarchive-not-supported");
    }

    #[tokio::test]
    async fn rename_returns_structured_error() {
        let err = rename(&ThreadId("x".into()), "name").await.unwrap_err();
        assert_eq!(err.code, "codex-rename-not-supported");
    }
}
