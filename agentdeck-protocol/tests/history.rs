use agentdeck_protocol::*;
use std::path::PathBuf;

#[test]
fn history_list_all_agents() {
    let req = HistoryRequest::List {
        request_id: None,
        agent_kind: None,
        cwd_filter: None,
        limit: None,
    };
    let json = serde_json::to_string(&req).unwrap();
    let _: HistoryRequest = serde_json::from_str(&json).unwrap();
}

#[test]
fn history_list_only_codex() {
    let req = HistoryRequest::List {
        request_id: None,
        agent_kind: Some(AgentKind::Codex),
        cwd_filter: Some(PathBuf::from("/proj")),
        limit: None,
    };
    let _: HistoryRequest = serde_json::from_str(&serde_json::to_string(&req).unwrap()).unwrap();
}

#[test]
fn history_archive_requires_agent_kind() {
    let req = HistoryRequest::Archive {
        request_id: None,
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

#[test]
fn history_archive_wire_is_camel_case() {
    let req = HistoryRequest::Archive {
        request_id: None,
        thread_id: ThreadId("t1".into()),
        agent_kind: AgentKind::ClaudeCode,
    };
    let json = serde_json::to_string(&req).unwrap();
    assert!(
        json.contains(r#""threadId":"t1""#),
        "thread_id should be threadId in wire: {}",
        json
    );
    assert!(
        json.contains(r#""agentKind":"claude_code""#),
        "agent_kind should be agentKind in wire: {}",
        json
    );
    assert!(
        !json.contains("requestId"),
        "absent request_id should be omitted from wire: {}",
        json
    );
}

#[test]
fn legacy_history_request_without_request_id_still_decodes() {
    let json = r#"{"op":"list","agentKind":null,"cwdFilter":null,"limit":25}"#;
    let request: HistoryRequest = serde_json::from_str(json).unwrap();

    assert_eq!(request.request_id(), None);
    assert!(matches!(
        request,
        HistoryRequest::List {
            agent_kind: None,
            cwd_filter: None,
            limit: Some(25),
            ..
        }
    ));
}

#[test]
fn history_request_id_round_trips_for_every_operation() {
    let requests = [
        HistoryRequest::List {
            request_id: None,
            agent_kind: None,
            cwd_filter: Some(PathBuf::from("/proj")),
            limit: Some(25),
        },
        HistoryRequest::Read {
            request_id: None,
            thread_id: ThreadId("read-1".into()),
            agent_kind: AgentKind::Codex,
        },
        HistoryRequest::Archive {
            request_id: None,
            thread_id: ThreadId("archive-1".into()),
            agent_kind: AgentKind::ClaudeCode,
        },
        HistoryRequest::Unarchive {
            request_id: None,
            thread_id: ThreadId("unarchive-1".into()),
            agent_kind: AgentKind::Codex,
        },
        HistoryRequest::Rename {
            request_id: None,
            thread_id: ThreadId("rename-1".into()),
            agent_kind: AgentKind::ClaudeCode,
            title: "renamed".into(),
        },
    ];

    for request in requests {
        let request = request.with_request_id("history-request-42");
        assert_eq!(request.request_id(), Some("history-request-42"));

        let json = serde_json::to_string(&request).unwrap();
        assert!(
            json.contains(r#""requestId":"history-request-42""#),
            "requestId should use camelCase on the wire: {json}"
        );

        let decoded: HistoryRequest = serde_json::from_str(&json).unwrap();
        assert_eq!(decoded.request_id(), Some("history-request-42"));
    }
}
