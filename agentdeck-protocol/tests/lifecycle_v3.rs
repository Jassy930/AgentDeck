use agentdeck_protocol::{
    AgentItem, AgentItemMeta, AgentItemState, AgentKind, ClientCommand, ProtocolError, ServerEvent,
    SessionId, SessionOutcome, SessionStart, ThreadId, TurnId, TurnNextState, TurnOutcome,
    TurnSummary,
};
use schemars::schema_for;
use serde_json::Value;

fn command_round_trip(command: ClientCommand) -> ClientCommand {
    let json = serde_json::to_string(&command).expect("command should serialize");
    serde_json::from_str(&json).expect("command should deserialize")
}

fn event_round_trip(event: ServerEvent) -> ServerEvent {
    let json = serde_json::to_string(&event).expect("event should serialize");
    serde_json::from_str(&json).expect("event should deserialize")
}

fn variant_with_tag<'a>(schema: &'a Value, discriminator: &str, tag: &str) -> &'a Value {
    schema["oneOf"]
        .as_array()
        .expect("tagged enum should use oneOf")
        .iter()
        .find(|variant| variant["properties"][discriminator]["enum"][0] == tag)
        .unwrap_or_else(|| panic!("missing {discriminator}={tag} variant"))
}

fn required_fields(schema: &Value) -> Vec<&str> {
    schema["required"]
        .as_array()
        .expect("object schema should declare required fields")
        .iter()
        .map(|field| field.as_str().expect("required field should be a string"))
        .collect()
}

#[test]
fn lifecycle_commands_round_trip() {
    assert!(matches!(
        command_round_trip(ClientCommand::TurnStart {
            session_id: SessionId("session-1".into()),
            turn_id: TurnId("turn-1".into()),
            prompt: "hello".into(),
        }),
        ClientCommand::TurnStart { .. }
    ));
    assert!(matches!(
        command_round_trip(ClientCommand::TurnCancel {
            session_id: SessionId("session-1".into()),
            turn_id: TurnId("turn-1".into()),
        }),
        ClientCommand::TurnCancel { .. }
    ));
    assert!(matches!(
        command_round_trip(ClientCommand::SessionClose {
            session_id: SessionId("session-1".into()),
        }),
        ClientCommand::SessionClose { .. }
    ));
}

#[test]
fn legacy_session_lifecycle_commands_are_rejected() {
    let legacy_continue = r#"{
        "command":"sessionContinue",
        "threadId":"thread-1",
        "agentKind":"codex",
        "cwd":"/tmp",
        "prompt":"continue"
    }"#;
    let legacy_cancel = r#"{"command":"sessionCancel","sessionId":"session-1"}"#;

    assert!(serde_json::from_str::<ClientCommand>(legacy_continue).is_err());
    assert!(serde_json::from_str::<ClientCommand>(legacy_cancel).is_err());
}

#[test]
fn lifecycle_events_round_trip() {
    assert!(matches!(
        event_round_trip(ServerEvent::TurnStarted {
            session_id: SessionId("session-1".into()),
            thread_id: ThreadId("thread-1".into()),
            agent_kind: AgentKind::Codex,
            turn_id: TurnId("turn-1".into()),
        }),
        ServerEvent::TurnStarted { .. }
    ));

    let finished = event_round_trip(ServerEvent::TurnFinished {
        session_id: SessionId("session-1".into()),
        thread_id: ThreadId("thread-1".into()),
        agent_kind: AgentKind::Codex,
        turn_id: TurnId("turn-1".into()),
        outcome: TurnOutcome::Failed,
        next_state: TurnNextState::Closing,
        summary: Some(TurnSummary {
            total_input_tokens: Some(10),
            total_output_tokens: Some(20),
            elapsed_ms: 30,
        }),
        error: Some(ProtocolError {
            code: "turn-failed".into(),
            message: "failed".into(),
            diagnostic_ref: Some("diag-1".into()),
        }),
    });
    assert!(matches!(
        finished,
        ServerEvent::TurnFinished {
            outcome: TurnOutcome::Failed,
            next_state: TurnNextState::Closing,
            ..
        }
    ));

    let closed = event_round_trip(ServerEvent::SessionClosed {
        session_id: SessionId("session-1".into()),
        thread_id: None,
        agent_kind: AgentKind::Codex,
        outcome: SessionOutcome::Closed,
        error: None,
    });
    assert!(matches!(
        closed,
        ServerEvent::SessionClosed {
            thread_id: None,
            outcome: SessionOutcome::Closed,
            ..
        }
    ));
}

#[test]
fn agent_item_round_trip_preserves_streaming_identity() {
    let item = event_round_trip(ServerEvent::AgentItem {
        session_id: SessionId("session-1".into()),
        thread_id: ThreadId("thread-1".into()),
        agent_kind: AgentKind::Codex,
        turn_id: TurnId("turn-1".into()),
        item_id: "message-1".into(),
        state: AgentItemState::Streaming,
        item: AgentItem::AssistantMessage {
            text: "hello".into(),
            meta: AgentItemMeta::default(),
        },
    });
    assert!(matches!(
        item,
        ServerEvent::AgentItem {
            turn_id: TurnId(ref turn_id),
            ref item_id,
            state: AgentItemState::Streaming,
            ..
        } if turn_id == "turn-1" && item_id == "message-1"
    ));
}

#[test]
fn v4_schema_marks_lifecycle_and_item_correlation_fields_required() {
    let session_start = serde_json::to_value(schema_for!(SessionStart)).unwrap();
    let session_start_required = required_fields(&session_start);
    assert!(session_start_required.contains(&"sessionId"));
    assert!(!session_start_required.contains(&"resumeThreadId"));
    assert!(!session_start_required.contains(&"initialTurn"));

    let commands = serde_json::to_value(schema_for!(ClientCommand)).unwrap();
    for (tag, fields) in [
        (
            "turnStart",
            &["command", "sessionId", "turnId", "prompt"][..],
        ),
        ("turnCancel", &["command", "sessionId", "turnId"][..]),
        ("sessionClose", &["command", "sessionId"][..]),
    ] {
        let required = required_fields(variant_with_tag(&commands, "command", tag));
        for field in fields {
            assert!(required.contains(field), "{tag} should require {field}");
        }
    }

    let events = serde_json::to_value(schema_for!(ServerEvent)).unwrap();
    for (tag, fields) in [
        (
            "turnStarted",
            &["type", "sessionId", "threadId", "agentKind", "turnId"][..],
        ),
        (
            "turnFinished",
            &[
                "type",
                "sessionId",
                "threadId",
                "agentKind",
                "turnId",
                "outcome",
                "nextState",
            ][..],
        ),
        (
            "sessionClosed",
            &["type", "sessionId", "agentKind", "outcome"][..],
        ),
    ] {
        let required = required_fields(variant_with_tag(&events, "type", tag));
        for field in fields {
            assert!(required.contains(field), "{tag} should require {field}");
        }
    }

    let agent_item_required = required_fields(variant_with_tag(&events, "type", "agentItem"));
    for field in [
        "type",
        "sessionId",
        "threadId",
        "agentKind",
        "turnId",
        "itemId",
        "state",
        "item",
    ] {
        assert!(
            agent_item_required.contains(&field),
            "agentItem should require {field}"
        );
    }
}
