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
#[derive(Debug, Serialize, Deserialize, Clone)]
pub struct IpcMessage {
    pub kind: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub id: Option<u64>,
    #[serde(rename = "sessionId", skip_serializing_if = "Option::is_none")]
    pub session_id: Option<String>,
    #[serde(rename = "threadId", skip_serializing_if = "Option::is_none")]
    pub thread_id: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub payload: Option<serde_json::Value>,
}

impl IpcMessage {
    pub fn pong(id: Option<u64>) -> Self {
        Self {
            kind: "pong".into(),
            id,
            session_id: None,
            thread_id: None,
            payload: None,
        }
    }

    pub fn error(id: Option<u64>, message: &str) -> Self {
        Self {
            kind: "error".into(),
            id,
            session_id: None,
            thread_id: None,
            payload: Some(serde_json::json!({ "message": message })),
        }
    }

    /// Wrap a neutral AgentItem as an IPC message (kind = "agentItem").
    pub fn agent_item(item: &AgentItem) -> Self {
        Self {
            kind: "agentItem".into(),
            id: None,
            session_id: None,
            thread_id: None,
            payload: Some(serde_json::to_value(item).expect("AgentItem serializes")),
        }
    }

    /// Neutral session-state change (Eng D9: daemon is the sole state source;
    /// Swift mirrors it, never guesses).
    pub fn session_state(state: SessionState) -> Self {
        Self {
            kind: "sessionState".into(),
            id: None,
            session_id: None,
            thread_id: None,
            payload: Some(serde_json::json!({ "state": state })),
        }
    }

    pub fn session_event(session_id: &str, thread_id: Option<&str>, event: IpcMessage) -> Self {
        Self {
            kind: "session/event".into(),
            id: None,
            session_id: Some(session_id.to_string()),
            thread_id: thread_id.map(str::to_string),
            payload: Some(serde_json::json!({ "event": event })),
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
#[serde(rename_all = "camelCase")]
pub struct AgentReference {
    pub kind: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub text: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub url: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub path: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub name: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct HookFragment {
    pub hook_run_id: String,
    pub text: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct FileEditChange {
    pub path: String,
    pub diff: String,
    pub change_kind: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct ToolAction {
    pub kind: String,
    pub command: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub path: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub name: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub query: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "camelCase")]
pub enum AgentItemKind {
    /// A user prompt restored from historical thread turns.
    User {
        text: String,
        #[serde(skip_serializing_if = "Vec::is_empty")]
        attachments: Vec<AgentReference>,
    },
    /// The agent's PRIMARY user-facing answer (Codex `agentMessage`). This
    /// is the reply the user actually reads — it is NOT collapsed (corrects
    /// the D3 misread: D3's "reasoning default-collapsed" applies to the
    /// chain-of-thought below, not to the answer). `text` accumulates across
    /// deltas.
    Message {
        text: String,
        #[serde(skip_serializing_if = "Option::is_none")]
        phase: Option<String>,
        #[serde(rename = "memoryCitation", skip_serializing_if = "Option::is_none")]
        memory_citation: Option<String>,
    },
    /// The agent's chain-of-thought (Codex internal `reasoning`). Genuinely
    /// secondary — default-collapsed in the UI per Eng D3. Distinct from
    /// `Message`: this is HOW it thought, not the answer.
    Reasoning {
        text: String,
    },
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
        #[serde(skip_serializing_if = "Option::is_none")]
        cwd: Option<String>,
        #[serde(skip_serializing_if = "Option::is_none")]
        status: Option<String>,
        #[serde(rename = "durationMs", skip_serializing_if = "Option::is_none")]
        duration_ms: Option<i64>,
        #[serde(skip_serializing_if = "Option::is_none")]
        source: Option<String>,
        #[serde(rename = "processId", skip_serializing_if = "Option::is_none")]
        process_id: Option<String>,
        #[serde(skip_serializing_if = "Vec::is_empty")]
        actions: Vec<ToolAction>,
    },
    /// A file the agent edited. Per-kind structured (D4).
    FileEdit {
        path: String,
        #[serde(skip_serializing_if = "Option::is_none")]
        diff: Option<String>,
        #[serde(skip_serializing_if = "Option::is_none")]
        status: Option<String>,
        #[serde(skip_serializing_if = "Vec::is_empty")]
        changes: Vec<FileEditChange>,
    },
    /// A web search / page navigation action performed by the agent. The
    /// shape keeps the useful action fields separate so the UI can render a
    /// readable historical trace without parsing vendor JSON.
    WebSearch {
        #[serde(skip_serializing_if = "String::is_empty")]
        query: String,
        #[serde(skip_serializing_if = "String::is_empty")]
        action: String,
        #[serde(rename = "actionQuery", skip_serializing_if = "Option::is_none")]
        action_query: Option<String>,
        #[serde(skip_serializing_if = "Vec::is_empty")]
        queries: Vec<String>,
        #[serde(skip_serializing_if = "Option::is_none")]
        url: Option<String>,
        #[serde(skip_serializing_if = "Option::is_none")]
        pattern: Option<String>,
    },
    Plan {
        text: String,
    },
    HookPrompt {
        #[serde(skip_serializing_if = "Vec::is_empty")]
        fragments: Vec<HookFragment>,
    },
    ToolCall {
        #[serde(rename = "toolKind")]
        tool_kind: String,
        #[serde(skip_serializing_if = "Option::is_none")]
        server: Option<String>,
        #[serde(skip_serializing_if = "Option::is_none")]
        namespace: Option<String>,
        tool: String,
        status: String,
        arguments: String,
        #[serde(skip_serializing_if = "Option::is_none")]
        result: Option<String>,
        #[serde(skip_serializing_if = "Option::is_none")]
        error: Option<String>,
        #[serde(rename = "durationMs", skip_serializing_if = "Option::is_none")]
        duration_ms: Option<i64>,
        #[serde(skip_serializing_if = "Option::is_none")]
        success: Option<bool>,
        #[serde(rename = "resourceUri", skip_serializing_if = "Option::is_none")]
        resource_uri: Option<String>,
        #[serde(rename = "contentItems", skip_serializing_if = "Vec::is_empty")]
        content_items: Vec<AgentReference>,
    },
    CollabAgentToolCall {
        tool: String,
        status: String,
        #[serde(skip_serializing_if = "Option::is_none")]
        prompt: Option<String>,
        #[serde(skip_serializing_if = "Option::is_none")]
        model: Option<String>,
        #[serde(rename = "reasoningEffort", skip_serializing_if = "Option::is_none")]
        reasoning_effort: Option<String>,
        #[serde(rename = "senderThreadId")]
        sender_thread_id: String,
        #[serde(rename = "receiverThreadIds", skip_serializing_if = "Vec::is_empty")]
        receiver_thread_ids: Vec<String>,
        #[serde(rename = "agentsStates", skip_serializing_if = "Option::is_none")]
        agents_states: Option<String>,
    },
    Media {
        #[serde(rename = "mediaKind")]
        media_kind: String,
        #[serde(skip_serializing_if = "Option::is_none")]
        path: Option<String>,
        #[serde(skip_serializing_if = "Option::is_none")]
        status: Option<String>,
        #[serde(skip_serializing_if = "Option::is_none")]
        result: Option<String>,
        #[serde(rename = "revisedPrompt", skip_serializing_if = "Option::is_none")]
        revised_prompt: Option<String>,
        #[serde(rename = "savedPath", skip_serializing_if = "Option::is_none")]
        saved_path: Option<String>,
    },
    ReviewMode {
        action: String,
        review: String,
    },
    ContextCompaction,
    /// An unknown vendor item type, NEUTRALIZED in the daemon (Codex #19):
    /// only a short, size-limited description crosses to Swift, never raw
    /// vendor JSON. Fails loud, not silent (Eng E1 / premise 9).
    Raw {
        description: String,
    },
}

/// A neutral summary for a historical agent thread. Values such as
/// `model_provider` and `source` are metadata from the runtime; the wire shape
/// stays agent-neutral so Swift can group and render history without parsing a
/// vendor protocol.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct HistoryThreadSummary {
    pub id: String,
    pub name: Option<String>,
    pub preview: String,
    pub cwd: String,
    pub created_at: i64,
    pub updated_at: i64,
    pub status: String,
    pub model_provider: String,
    pub source: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct HistoryThreadList {
    pub threads: Vec<HistoryThreadSummary>,
    pub next_cursor: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct HistoryThreadDetail {
    pub thread: HistoryThreadSummary,
    pub items: Vec<AgentItem>,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn ipc_message_can_carry_session_and_thread_routing() {
        let msg = IpcMessage {
            kind: "session/event".into(),
            id: None,
            session_id: Some("session_1".into()),
            thread_id: Some("thread_1".into()),
            payload: Some(serde_json::json!({
                "event": { "kind": "turnComplete" }
            })),
        };

        let wire = serde_json::to_string(&msg).unwrap();
        assert!(wire.contains(r#""sessionId":"session_1""#));
        assert!(wire.contains(r#""threadId":"thread_1""#));
        assert!(!wire.to_lowercase().contains("codex"));

        let wrapped = IpcMessage::session_event(
            "session_1",
            Some("thread_1"),
            IpcMessage::session_state(SessionState::Ready),
        );
        let wrapped_wire = serde_json::to_string(&wrapped).unwrap();
        assert!(wrapped_wire.contains(r#""kind":"session/event""#));
        assert!(wrapped_wire.contains(r#""sessionId":"session_1""#));
        assert!(wrapped_wire.contains(r#""threadId":"thread_1""#));
        assert!(wrapped_wire.contains(r#""event""#));
    }

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
                    cwd: None,
                    status: None,
                    duration_ms: None,
                    source: None,
                    process_id: None,
                    actions: Vec::new(),
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
            serde_json::to_string(&IpcMessage::agent_item(&AgentItem {
                id: "i4".into(),
                lifecycle: Lifecycle::Completed,
                kind: AgentItemKind::WebSearch {
                    query: "docs".into(),
                    action: "search".into(),
                    action_query: Some("docs".into()),
                    queries: vec!["docs".into()],
                    url: None,
                    pattern: None,
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
                cwd: None,
                status: None,
                duration_ms: None,
                source: None,
                process_id: None,
                actions: Vec::new(),
            },
        };
        let v = serde_json::to_value(&item).unwrap();
        assert_eq!(v["kind"], "shell");
        assert_eq!(v["command"], "echo hi");
        assert_eq!(v["exitCode"], 0);
    }

    #[test]
    fn history_thread_summary_serializes_without_vendor_names() {
        let summary = HistoryThreadSummary {
            id: "thread_1".into(),
            name: Some("Fix tests".into()),
            preview: "please fix tests".into(),
            cwd: "/tmp/project".into(),
            created_at: 1,
            updated_at: 2,
            status: "completed".into(),
            model_provider: "openai".into(),
            source: "cli".into(),
        };
        let wire = serde_json::to_string(&summary).unwrap().to_lowercase();
        assert!(!wire.contains("codex"));
    }
}
