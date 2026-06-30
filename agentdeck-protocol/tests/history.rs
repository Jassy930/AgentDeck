use agentdeck_protocol::*;
use std::path::PathBuf;

#[test]
fn history_list_all_agents() {
    let req = HistoryRequest::List {
        agent_kind: None,
        cwd_filter: None,
    };
    let json = serde_json::to_string(&req).unwrap();
    let _: HistoryRequest = serde_json::from_str(&json).unwrap();
}

#[test]
fn history_list_only_codex() {
    let req = HistoryRequest::List {
        agent_kind: Some(AgentKind::Codex),
        cwd_filter: Some(PathBuf::from("/proj")),
    };
    let _: HistoryRequest = serde_json::from_str(&serde_json::to_string(&req).unwrap()).unwrap();
}

#[test]
fn history_archive_requires_agent_kind() {
    let req = HistoryRequest::Archive {
        thread_id: ThreadId("t1".into()),
        agent_kind: AgentKind::ClaudeCode,
    };
    let _: HistoryRequest = serde_json::from_str(&serde_json::to_string(&req).unwrap()).unwrap();
}

#[test]
fn list_item_round_trip() {
    let item = HistoryListItem {
        thread_id: ThreadId("uuid-1".into()),
        agent_kind: AgentKind::ClaudeCode,
        title: Some("auth refactor".into()),
        cwd: PathBuf::from("/proj"),
        last_active_ms: 1_700_000_000_000,
        archived: false,
    };
    let _: HistoryListItem = serde_json::from_str(&serde_json::to_string(&item).unwrap()).unwrap();
}
