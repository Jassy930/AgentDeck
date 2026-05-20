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
        Self {
            kind: "pong".into(),
            id,
            payload: None,
        }
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
    /// The agent's PRIMARY user-facing answer (Codex `agentMessage`). This
    /// is the reply the user actually reads — it is NOT collapsed (corrects
    /// the D3 misread: D3's "reasoning default-collapsed" applies to the
    /// chain-of-thought below, not to the answer). `text` accumulates across
    /// deltas.
    Message { text: String },
    /// The agent's chain-of-thought (Codex internal `reasoning`). Genuinely
    /// secondary — default-collapsed in the UI per Eng D3. Distinct from
    /// `Message`: this is HOW it thought, not the answer.
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
                kind: AgentItemKind::Reasoning {
                    text: "thinking".into(),
                },
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
                kind: AgentItemKind::Raw {
                    description: "unknown item type x".into(),
                },
            }))
            .unwrap(),
        ];
        for wire in &samples {
            let lower = wire.to_lowercase();
            assert!(
                !lower.contains("codex"),
                "vendor name on neutral wire: {wire}"
            );
            assert!(
                !lower.contains("openai"),
                "vendor name on neutral wire: {wire}"
            );
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
}
