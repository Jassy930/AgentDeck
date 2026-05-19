//! The agent-neutral IPC protocol.
//!
//! This module is the verifiable form of Eng premise D2: the neutral boundary
//! IS the IPC protocol. Nothing in this file may reference Codex, OpenAI, or
//! any vendor. A guard test asserts this. A future Claude Code / SSH adapter
//! produces these exact types; the Swift app never changes.
//!
//! `AgentItem` uses a per-kind structured schema (Eng D4), NOT an opaque
//! string — so the Swift renderer can show reasoning as a thinking bubble,
//! shell as a command block, fileEdit as a diff, WITHOUT parsing vendor
//! formats (which would leak the boundary back into Swift).

use serde::{Deserialize, Serialize};

/// A message on the neutral IPC wire (Swift ↔ daemon).
#[derive(Debug, Serialize, Deserialize)]
pub struct IpcMessage {
    pub kind: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub id: Option<u64>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub payload: Option<serde_json::Value>,
}

impl IpcMessage {
    pub fn pong(id: Option<u64>) -> Self {
        Self { kind: "pong".into(), id, payload: None }
    }

    pub fn error(id: Option<u64>, message: &str) -> Self {
        Self {
            kind: "error".into(),
            id,
            payload: Some(serde_json::json!({ "message": message })),
        }
    }

    /// Wrap a neutral AgentItem as an IPC message (kind = "agentItem").
    pub fn agent_item(item: &AgentItem) -> Self {
        Self {
            kind: "agentItem".into(),
            id: None,
            payload: Some(serde_json::to_value(item).expect("AgentItem serializes")),
        }
    }

    /// Neutral session-state change (Eng D9: daemon is the sole state source;
    /// Swift mirrors it, never guesses).
    pub fn session_state(state: SessionState) -> Self {
        Self {
            kind: "sessionState".into(),
            id: None,
            payload: Some(serde_json::json!({ "state": state })),
        }
    }
}

/// The neutral session state machine (Eng D9). The daemon owns this; the
/// Swift app renders a mirror and never invents transitions.
#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase")]
pub enum SessionState {
    Idle,
    Starting,
    Ready,
    Running,
    WaitingApproval,
    Draining,
    Failed,
    Closed,
}

/// Lifecycle of a streaming item (Eng D4 / front-of-mind started→delta→
/// completed). Neutral — not tied to any vendor's event names.
#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase")]
pub enum Lifecycle {
    Started,
    Delta,
    Completed,
}

/// A neutral agent item. `kind` carries a per-kind structured payload (D4),
/// never an opaque string. `raw` is the escape hatch for unknown vendor item
/// types (Eng E1 + Codex #19): unknown items are neutralized HERE, in the
/// daemon, and surface to Swift as `AgentItemKind::Raw` — the Swift app never
/// sees vendor JSON directly.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AgentItem {
    /// Stable id correlating started/delta/completed for the same item.
    pub id: String,
    pub lifecycle: Lifecycle,
    #[serde(flatten)]
    pub kind: AgentItemKind,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "camelCase")]
pub enum AgentItemKind {
    /// The agent's thinking. Secondary in the UI hierarchy (Eng D3 —
    /// default-collapsed). `text` accumulates across deltas.
    Reasoning { text: String },
    /// A shell command the agent ran. Per-kind structured (D4).
    Shell {
        command: String,
        #[serde(skip_serializing_if = "Option::is_none")]
        output: Option<String>,
        // Explicit camelCase: `rename_all` on the enum applies to variant
        // tags, NOT struct fields. D4 requires the neutral wire field name
        // be exactly what the Swift decoder expects, or it silently misses
        // (this is the bug the per-kind test caught).
        #[serde(rename = "exitCode", skip_serializing_if = "Option::is_none")]
        exit_code: Option<i64>,
    },
    /// A file the agent edited. Per-kind structured (D4).
    FileEdit {
        path: String,
        #[serde(skip_serializing_if = "Option::is_none")]
        diff: Option<String>,
    },
    /// An unknown vendor item type, NEUTRALIZED in the daemon (Codex #19):
    /// only a short, size-limited description crosses to Swift, never raw
    /// vendor JSON. Fails loud, not silent (Eng E1 / premise 9).
    Raw { description: String },
}

/// Backpressure coalescer (Eng A2).
///
/// The Codex app-server emits reasoning/shell deltas one tiny chunk at a
/// time. Forwarding every chunk as its own IPC message would (a) flood the
/// Swift renderer and (b) risk unbounded buffering. The coalescer merges
/// CONSECUTIVE delta items of the same id into one before flush — no
/// semantics lost (ordering preserved, text concatenated in arrival order),
/// no unbounded buffer (one pending item at a time; a different id or a
/// non-delta lifecycle forces a flush).
///
/// This is the simplest correct form of A2: single-pass, single pending
/// slot, no channel/thread machinery (boring-by-default). A `started` or
/// `completed` lifecycle, or a switch to a different item id, flushes.
#[derive(Default)]
pub struct Coalescer {
    pending: Option<AgentItem>,
}

impl Coalescer {
    /// Feed one translated item. Returns any item that must be flushed
    /// (emitted over IPC) BEFORE this one is absorbed. Call `take_pending`
    /// at end-of-turn to drain the final buffered delta.
    pub fn push(&mut self, item: AgentItem) -> Option<AgentItem> {
        // Only consecutive same-id deltas coalesce. Anything else flushes
        // the pending item first, then becomes the new pending (or passes
        // through if it is itself not a delta).
        match (&mut self.pending, &item.lifecycle) {
            (Some(p), Lifecycle::Delta)
                if p.id == item.id && same_delta_kind(&p.kind, &item.kind) =>
            {
                merge_delta(&mut p.kind, item.kind);
                None
            }
            _ => {
                let flush = self.pending.take();
                if matches!(item.lifecycle, Lifecycle::Delta) {
                    self.pending = Some(item);
                } else {
                    // started/completed pass straight through, but anything
                    // buffered must be flushed first to preserve order.
                    if flush.is_some() {
                        // Stash the non-delta as pending-after; caller will
                        // get `flush` now and this on the next take/push.
                        // Simpler: return flush, keep item pending as a
                        // zero-merge slot that the next push/ take emits.
                        self.pending = Some(item);
                        return flush;
                    }
                    return Some(item);
                }
                flush
            }
        }
    }

    /// Drain the final buffered item (end of turn).
    pub fn take_pending(&mut self) -> Option<AgentItem> {
        self.pending.take()
    }
}

fn same_delta_kind(a: &AgentItemKind, b: &AgentItemKind) -> bool {
    matches!(
        (a, b),
        (AgentItemKind::Reasoning { .. }, AgentItemKind::Reasoning { .. })
            | (AgentItemKind::Shell { .. }, AgentItemKind::Shell { .. })
    )
}

fn merge_delta(into: &mut AgentItemKind, from: AgentItemKind) {
    match (into, from) {
        (AgentItemKind::Reasoning { text: a }, AgentItemKind::Reasoning { text: b }) => {
            a.push_str(&b);
        }
        (
            AgentItemKind::Shell { output: a, .. },
            AgentItemKind::Shell { output: b, .. },
        ) => {
            let merged = format!(
                "{}{}",
                a.as_deref().unwrap_or(""),
                b.as_deref().unwrap_or("")
            );
            *a = Some(merged);
        }
        _ => {}
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Eng D2, verifiable form: the neutral protocol module must not contain
    /// vendor vocabulary in anything it serializes. If a future change adds a
    /// `codex`-named field or variant, the wire bytes leak it and this fails.
    #[test]
    fn neutral_protocol_serializes_without_vendor_names() {
        let samples = vec![
            serde_json::to_string(&IpcMessage::pong(Some(1))).unwrap(),
            serde_json::to_string(&IpcMessage::error(Some(1), "boom")).unwrap(),
            serde_json::to_string(&IpcMessage::session_state(SessionState::Running)).unwrap(),
            serde_json::to_string(&IpcMessage::agent_item(&AgentItem {
                id: "i1".into(),
                lifecycle: Lifecycle::Started,
                kind: AgentItemKind::Reasoning { text: "thinking".into() },
            }))
            .unwrap(),
            serde_json::to_string(&IpcMessage::agent_item(&AgentItem {
                id: "i2".into(),
                lifecycle: Lifecycle::Completed,
                kind: AgentItemKind::Shell {
                    command: "ls".into(),
                    output: Some("a\nb".into()),
                    exit_code: Some(0),
                },
            }))
            .unwrap(),
            serde_json::to_string(&IpcMessage::agent_item(&AgentItem {
                id: "i3".into(),
                lifecycle: Lifecycle::Completed,
                kind: AgentItemKind::Raw { description: "unknown item type x".into() },
            }))
            .unwrap(),
        ];
        for wire in &samples {
            let lower = wire.to_lowercase();
            assert!(!lower.contains("codex"), "vendor name on neutral wire: {wire}");
            assert!(!lower.contains("openai"), "vendor name on neutral wire: {wire}");
        }
    }

    #[test]
    fn agent_item_kinds_are_per_kind_structured_not_opaque() {
        // D4: shell carries command/output/exitCode as discrete fields, not
        // a blob string the Swift side would have to parse.
        let item = AgentItem {
            id: "x".into(),
            lifecycle: Lifecycle::Completed,
            kind: AgentItemKind::Shell {
                command: "echo hi".into(),
                output: Some("hi".into()),
                exit_code: Some(0),
            },
        };
        let v = serde_json::to_value(&item).unwrap();
        assert_eq!(v["kind"], "shell");
        assert_eq!(v["command"], "echo hi");
        assert_eq!(v["exitCode"], 0);
    }

    // --- Coalescer (Eng A2) ---

    fn reasoning_delta(id: &str, t: &str) -> AgentItem {
        AgentItem {
            id: id.into(),
            lifecycle: Lifecycle::Delta,
            kind: AgentItemKind::Reasoning { text: t.into() },
        }
    }

    #[test]
    fn consecutive_same_id_deltas_merge_in_order() {
        let mut c = Coalescer::default();
        assert!(c.push(reasoning_delta("a", "Hel")).is_none());
        assert!(c.push(reasoning_delta("a", "lo ")).is_none());
        assert!(c.push(reasoning_delta("a", "world")).is_none());
        // No flush yet — all merged into the single pending slot (bounded).
        let final_item = c.take_pending().expect("one merged item");
        match final_item.kind {
            AgentItemKind::Reasoning { text } => assert_eq!(text, "Hello world"),
            _ => panic!("expected merged Reasoning"),
        }
    }

    #[test]
    fn different_id_flushes_previous() {
        let mut c = Coalescer::default();
        assert!(c.push(reasoning_delta("a", "AAA")).is_none());
        // New id forces the buffered "a" to flush.
        let flushed = c.push(reasoning_delta("b", "BBB")).expect("flush a");
        assert_eq!(flushed.id, "a");
        match flushed.kind {
            AgentItemKind::Reasoning { text } => assert_eq!(text, "AAA"),
            _ => panic!(),
        }
        // "b" is now pending.
        assert_eq!(c.take_pending().unwrap().id, "b");
    }

    #[test]
    fn completed_lifecycle_passes_through_after_flushing_buffer() {
        let mut c = Coalescer::default();
        assert!(c.push(reasoning_delta("a", "partial")).is_none());
        let completed = AgentItem {
            id: "a".into(),
            lifecycle: Lifecycle::Completed,
            kind: AgentItemKind::Reasoning { text: "full text".into() },
        };
        // The buffered delta flushes first (order preserved); the completed
        // item becomes pending and is drained next.
        let flushed = c.push(completed).expect("buffered delta flushes first");
        assert!(matches!(flushed.lifecycle, Lifecycle::Delta));
        let next = c.take_pending().expect("completed drains");
        assert!(matches!(next.lifecycle, Lifecycle::Completed));
    }

    #[test]
    fn buffer_is_bounded_to_one_pending_item() {
        // A2's bound: no matter how many deltas arrive, only ONE item is
        // ever buffered. Feed 10_000 deltas; pending is still a single item.
        let mut c = Coalescer::default();
        for _ in 0..10_000 {
            c.push(reasoning_delta("a", "x"));
        }
        let merged = c.take_pending().unwrap();
        match merged.kind {
            AgentItemKind::Reasoning { text } => assert_eq!(text.len(), 10_000),
            _ => panic!(),
        }
        assert!(c.take_pending().is_none());
    }
}
