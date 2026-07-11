//! P1.1 RuntimeEnvelope v1 中立契约 —— contract / deny-unknown / limits 测试。
//!
//! RuntimeEnvelope v1 是 UDS 与解密后远程链路的共同业务 wire（design §8.2）。
//! 本 task 只定义中立契约与构造校验，不接线任何运行时行为。

use agentdeck_protocol::runtime::command::{
    LocalOnlyAdministration, MAX_PROMPT_BYTES, PromptPayload, SendPromptRequest,
};
use agentdeck_protocol::runtime::failure::{self, RuntimeFailure};
use agentdeck_protocol::runtime::identity::{
    ApprovalId, CommandId, ConversationId, EntityId, EventId, IdempotencyKey, ItemId, MessageId,
    PairingId, TransferId, TurnId,
};
use agentdeck_protocol::runtime::receipt::{
    ApprovalDeliveryState, ApprovalReceipt, CommandReceipt, RevocationReceipt,
};
use agentdeck_protocol::runtime::sync::{
    ConversationSnapshot, SnapshotError, SnapshotItem, StreamCursor,
};
use agentdeck_protocol::runtime::{
    self, MAX_RUNTIME_REQUEST_BYTES, RUNTIME_PROTOCOL_VERSION, RuntimeEnvelope, RuntimeEvent,
    RuntimeEventBody, RuntimeMessage, RuntimeReply, RuntimeRequest, RuntimeStreamItem,
    TransferEnvelope, ensure_request_within_limit,
};
use agentdeck_protocol::{
    ActionDecision, ActionDecisionKind, AgentItem, AgentKind, CapabilityId, CodexCapabilities,
    SessionCapabilities, VendorCapabilities,
};
use serde::Serialize;
use sha2::{Digest, Sha256};
use std::collections::BTreeSet;
use std::fs;
use std::path::PathBuf;

fn sample_caps() -> SessionCapabilities {
    SessionCapabilities {
        agent_kind: AgentKind::Codex,
        agent_version: "x".into(),
        features: BTreeSet::from([CapabilityId::Approval]),
        vendor: VendorCapabilities::Codex(CodexCapabilities::default()),
    }
}

fn sample_send_prompt() -> RuntimeRequest {
    RuntimeRequest::SendPrompt(SendPromptRequest {
        conversation_id: ConversationId::new("c1"),
        idempotency_key: IdempotencyKey::new("k1"),
        prompt: PromptPayload::new("hello").unwrap(),
    })
}

fn envelope(body: RuntimeMessage) -> RuntimeEnvelope {
    envelope_with_id("m1", body)
}

fn envelope_with_id(message_id: &str, body: RuntimeMessage) -> RuntimeEnvelope {
    RuntimeEnvelope {
        version: RUNTIME_PROTOCOL_VERSION,
        message_id: MessageId::new(message_id),
        body,
    }
}

fn fixture_case<T: Serialize>(name: &str, wire_type: &str, value: &T) -> serde_json::Value {
    serde_json::json!({
        "case": name,
        "wireType": wire_type,
        "value": serde_json::to_value(value).expect("fixture DTO must serialize"),
    })
}

fn runtime_fixture_path() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("../protocol/agentdeck/fixtures/runtime-v1-wire.jsonl")
}

fn render_runtime_wire_fixture() -> String {
    let mut cases = Vec::new();

    let stable_ids = envelope_with_id(
        "message-stable-1",
        RuntimeMessage::Stream(RuntimeStreamItem::Event(RuntimeEvent {
            conversation_id: ConversationId::new("conversation-stable-1"),
            event_id: EventId::new("event-stable-1"),
            event_seq: 7,
            item_id: Some(ItemId::new("item-stable-1")),
            entity_id: Some(EntityId::new("entity-stable-1")),
            body: RuntimeEventBody::TurnStarted {
                turn_id: TurnId::new("turn-stable-1"),
                command_id: CommandId::new("command-stable-1"),
            },
        })),
    );
    cases.push(fixture_case("stableIds", "runtimeEnvelope", &stable_ids));

    let command_receipts = [
        (
            "commandAccepted",
            CommandReceipt::Accepted {
                command_id: CommandId::new("command-accepted-1"),
                queue_position: 2,
            },
        ),
        (
            "commandReplayed",
            CommandReceipt::Replayed {
                command_id: CommandId::new("command-replayed-1"),
            },
        ),
        (
            "commandFailed",
            CommandReceipt::Failed {
                failure: RuntimeFailure::new(
                    failure::DAEMON_COMMAND_IDEMPOTENCY_CONFLICT,
                    "idempotency conflict",
                )
                .with_diagnostic("diag-command-1"),
            },
        ),
    ];
    for (index, (name, receipt)) in command_receipts.into_iter().enumerate() {
        let value = envelope_with_id(
            &format!("message-command-{index}"),
            RuntimeMessage::Reply(RuntimeReply::Command(receipt)),
        );
        cases.push(fixture_case(name, "runtimeEnvelope", &value));
    }

    let approval_outcomes = [
        (
            "approvalClaimed",
            ApprovalReceipt::Claimed {
                approval_id: ApprovalId::new("approval-claimed-1"),
            },
        ),
        (
            "approvalApplied",
            ApprovalReceipt::Applied {
                approval_id: ApprovalId::new("approval-applied-1"),
            },
        ),
        (
            "approvalDeliveryFailed",
            ApprovalReceipt::DeliveryFailed {
                approval_id: ApprovalId::new("approval-delivery-failed-1"),
            },
        ),
        (
            "approvalExpired",
            ApprovalReceipt::Expired {
                approval_id: ApprovalId::new("approval-expired-1"),
            },
        ),
    ];
    for (index, (name, receipt)) in approval_outcomes.into_iter().enumerate() {
        let value = envelope_with_id(
            &format!("message-approval-outcome-{index}"),
            RuntimeMessage::Reply(RuntimeReply::Approval(receipt)),
        );
        cases.push(fixture_case(name, "runtimeEnvelope", &value));
    }

    let approval_states = [
        ("claimed", ApprovalDeliveryState::Claimed),
        ("applying", ApprovalDeliveryState::Applying),
        ("applied", ApprovalDeliveryState::Applied),
        ("deliveryFailed", ApprovalDeliveryState::DeliveryFailed),
        ("expired", ApprovalDeliveryState::Expired),
    ];
    for (index, (state_name, state)) in approval_states.into_iter().enumerate() {
        let value = envelope_with_id(
            &format!("message-approval-state-{index}"),
            RuntimeMessage::Reply(RuntimeReply::Approval(ApprovalReceipt::AlreadyHandled {
                approval_id: ApprovalId::new(format!("approval-state-{state_name}")),
                decision: ActionDecisionKind::Approve,
                state,
            })),
        );
        cases.push(fixture_case(
            &format!("approvalAlreadyHandled-{state_name}"),
            "runtimeEnvelope",
            &value,
        ));
    }

    let revocation = envelope_with_id(
        "message-revocation-1",
        RuntimeMessage::Reply(RuntimeReply::Revocation(RevocationReceipt::Committed {
            grant_serial: agentdeck_protocol::runtime::identity::GrantSerial::new(11),
        })),
    );
    cases.push(fixture_case(
        "revocationCommitted",
        "runtimeEnvelope",
        &revocation,
    ));

    let snapshot = ConversationSnapshot::new(
        ConversationId::new("conversation-snapshot-1"),
        6,
        vec![
            SnapshotItem::Capabilities {
                capabilities: sample_caps(),
            },
            SnapshotItem::Item {
                item_id: ItemId::new("item-snapshot-1"),
                item: AgentItem::AssistantMessage {
                    text: "fixture assistant message".into(),
                    meta: Default::default(),
                },
            },
        ],
    )
    .expect("fixture snapshot must be capabilities-first");
    let snapshot_envelope = envelope_with_id(
        "message-snapshot-1",
        RuntimeMessage::Reply(RuntimeReply::Snapshot(snapshot)),
    );
    cases.push(fixture_case(
        "capabilitiesFirstSnapshot",
        "runtimeEnvelope",
        &snapshot_envelope,
    ));

    let part = b"runtime-transfer-fixture".to_vec();
    let total_sha256: [u8; 32] = Sha256::digest(&part).into();
    let transfer = TransferEnvelope::new(
        TransferId::new("transfer-stable-1"),
        0,
        1,
        total_sha256,
        part.len() as u64,
        part,
    )
    .expect("fixture transfer must satisfy bounds");
    cases.push(fixture_case(
        "transferEnvelope",
        "transferEnvelope",
        &transfer,
    ));

    let mut output = cases
        .into_iter()
        .map(|value| serde_json::to_string(&value).expect("fixture case must serialize"))
        .collect::<Vec<_>>()
        .join("\n");
    output.push('\n');
    output
}

#[test]
fn runtime_v1_wire_fixture_is_rust_produced_and_in_sync() {
    let expected = render_runtime_wire_fixture();
    let path = runtime_fixture_path();
    if std::env::var("UPDATE_WIRE_FIXTURES").as_deref() == Ok("1") {
        fs::create_dir_all(path.parent().expect("runtime fixture has parent directory"))
            .expect("create runtime fixture directory");
        fs::write(&path, expected.as_bytes()).expect("write runtime v1 wire fixture");
    }
    let committed = fs::read(&path).unwrap_or_else(|error| {
        panic!(
            "read committed runtime fixture {}: {error}; run with UPDATE_WIRE_FIXTURES=1",
            path.display()
        )
    });
    assert_eq!(
        committed,
        expected.as_bytes(),
        "runtime fixture drifted; review Rust DTO changes and regenerate with UPDATE_WIRE_FIXTURES=1"
    );
}

#[test]
fn runtime_protocol_version_is_one_and_independent() {
    assert_eq!(RUNTIME_PROTOCOL_VERSION, 1);
    // 与 local IPC PROTOCOL_VERSION=2 彼此独立、不联动。
    assert_eq!(agentdeck_protocol::PROTOCOL_VERSION, 2);
}

#[test]
fn envelope_round_trips_a_request() {
    let env = envelope(RuntimeMessage::Request(sample_send_prompt()));
    let json = serde_json::to_value(&env).unwrap();
    assert_eq!(json["version"], 1);
    assert_eq!(json["messageId"], "m1");
    // wire round-trip (composite DTOs embed non-PartialEq trunk types).
    let back: RuntimeEnvelope = serde_json::from_value(json.clone()).unwrap();
    assert_eq!(serde_json::to_value(&back).unwrap(), json);
}

#[test]
fn envelope_denies_unknown_fields() {
    let env = envelope(RuntimeMessage::Request(sample_send_prompt()));
    let mut json = serde_json::to_value(&env).unwrap();
    json.as_object_mut()
        .unwrap()
        .insert("bogus".into(), serde_json::json!(1));
    let res: Result<RuntimeEnvelope, _> = serde_json::from_value(json);
    assert!(res.is_err(), "unknown field must be rejected");
}

#[test]
fn request_denies_unknown_fields() {
    let req = sample_send_prompt();
    let mut json = serde_json::to_value(&req).unwrap();
    json.as_object_mut()
        .unwrap()
        .insert("bogus".into(), serde_json::json!(true));
    let res: Result<RuntimeRequest, _> = serde_json::from_value(json);
    assert!(res.is_err(), "unknown field on request must be rejected");
}

#[test]
fn stream_cursor_never_encodes_negative_one() {
    // BeforeFirst is a distinct variant; wire never carries -1 (design §9.1).
    let before = serde_json::to_value(StreamCursor::BeforeFirst).unwrap();
    assert_eq!(before, serde_json::json!("beforeFirst"));
    let at = serde_json::to_value(StreamCursor::At(7)).unwrap();
    assert_eq!(at, serde_json::json!({ "at": 7 }));
    let raw = serde_json::to_string(&StreamCursor::BeforeFirst).unwrap();
    assert!(!raw.contains("-1"));
    // round trip
    let back: StreamCursor = serde_json::from_value(serde_json::json!({ "at": 7 })).unwrap();
    assert_eq!(back, StreamCursor::At(7));
}

#[test]
fn stream_cursor_next_semantics() {
    assert_eq!(StreamCursor::BeforeFirst.next(), 0);
    assert_eq!(StreamCursor::At(0).next(), 1);
    assert_eq!(StreamCursor::At(41).next(), 42);
}

#[test]
fn runtime_request_covers_all_brief_variants() {
    // brief Step 3: hello/catalog/subscribe/start/sendPrompt/resolveApproval/
    // retryApproval/cancel/queryReceipt/createPairInvite/listPendingPairings/
    // confirmPairing/cancelPairing/revoke/trust-reset。
    let convo = ConversationId::new("c1");
    let variants = vec![
        RuntimeRequest::Hello(runtime::command::HelloParams {
            runtime_protocol_version: RUNTIME_PROTOCOL_VERSION,
        }),
        RuntimeRequest::Catalog(runtime::command::CatalogRequest {
            subscribe: true,
            since_revision: None,
        }),
        RuntimeRequest::Subscribe {
            conversation_id: convo.clone(),
            cursor: StreamCursor::BeforeFirst,
        },
        RuntimeRequest::Start(runtime::command::ConversationStart {
            agent_kind: AgentKind::Codex,
            prompt: Some(PromptPayload::new("go").unwrap()),
        }),
        sample_send_prompt(),
        RuntimeRequest::ResolveApproval {
            conversation_id: convo.clone(),
            turn_id: TurnId::new("t1"),
            approval_id: ApprovalId::new("a1"),
            decision: ActionDecision {
                request_id: "r1".into(),
                decision: ActionDecisionKind::Approve,
                persist: false,
            },
        },
        RuntimeRequest::RetryApproval {
            conversation_id: convo.clone(),
            approval_id: ApprovalId::new("a1"),
        },
        RuntimeRequest::Cancel {
            conversation_id: convo.clone(),
            turn_id: Some(TurnId::new("t1")),
        },
        RuntimeRequest::QueryReceipt(runtime::command::QueryReceiptRequest {
            conversation_id: Some(convo.clone()),
            command_id: Some(CommandId::new("cmd1")),
            idempotency_key: None,
        }),
        RuntimeRequest::CreatePairInvite(runtime::command::CreatePairInviteRequest {
            display_name: "MacBook".into(),
            ttl_secs: 300,
            scope: LocalOnlyAdministration::LocalOnly,
        }),
        RuntimeRequest::ListPendingPairings {
            scope: LocalOnlyAdministration::LocalOnly,
        },
        RuntimeRequest::ConfirmPairing {
            pairing_id: PairingId::new("p1"),
            scope: LocalOnlyAdministration::LocalOnly,
        },
        RuntimeRequest::CancelPairing {
            pairing_id: PairingId::new("p1"),
            scope: LocalOnlyAdministration::LocalOnly,
        },
        RuntimeRequest::Revoke(runtime::command::RevokeRequest {
            target: runtime::command::RevokeTarget::SelfDevice,
        }),
        RuntimeRequest::TrustReset {
            scope: LocalOnlyAdministration::LocalOnly,
        },
    ];
    assert_eq!(variants.len(), 15);
    for v in variants {
        let json = serde_json::to_value(&v).unwrap();
        assert!(
            json["request"].is_string(),
            "each request is internally tagged: {json}"
        );
        // wire round-trip (RuntimeRequest embeds non-PartialEq trunk ActionDecision).
        let back: RuntimeRequest = serde_json::from_value(json.clone()).unwrap();
        assert_eq!(serde_json::to_value(&back).unwrap(), json);
    }
}

#[test]
fn prompt_payload_enforces_256_kib() {
    assert_eq!(MAX_PROMPT_BYTES, 256 * 1024);
    let ok = "a".repeat(MAX_PROMPT_BYTES);
    assert!(PromptPayload::new(ok).is_ok());
    let too_big = "a".repeat(MAX_PROMPT_BYTES + 1);
    assert!(PromptPayload::new(too_big).is_err());
    // deserialize path must also reject oversize prompts
    let oversize = serde_json::json!("a".repeat(MAX_PROMPT_BYTES + 1));
    let res: Result<PromptPayload, _> = serde_json::from_value(oversize);
    assert!(res.is_err(), "deserialize must enforce the 256 KiB cap");
}

#[test]
fn runtime_request_size_limit_is_one_mib() {
    assert_eq!(MAX_RUNTIME_REQUEST_BYTES, 1024 * 1024);
    assert!(ensure_request_within_limit(MAX_RUNTIME_REQUEST_BYTES).is_ok());
    assert!(ensure_request_within_limit(MAX_RUNTIME_REQUEST_BYTES + 1).is_err());
    // a normal request encodes well under the cap
    let env = envelope(RuntimeMessage::Request(sample_send_prompt()));
    let len = env.check_encoded_size().unwrap();
    assert!(len < MAX_RUNTIME_REQUEST_BYTES);
}

#[test]
fn command_receipt_has_accepted_replayed_failed() {
    let accepted = CommandReceipt::Accepted {
        command_id: CommandId::new("cmd1"),
        queue_position: 0,
    };
    let replayed = CommandReceipt::Replayed {
        command_id: CommandId::new("cmd1"),
    };
    let failed = CommandReceipt::Failed {
        failure: RuntimeFailure::new(failure::DAEMON_COMMAND_IDEMPOTENCY_CONFLICT, "conflict"),
    };
    for r in [accepted, replayed, failed] {
        let json = serde_json::to_value(&r).unwrap();
        let back: CommandReceipt = serde_json::from_value(json).unwrap();
        assert_eq!(back, r);
    }
}

#[test]
fn approval_receipt_carries_five_delivery_states() {
    // design §8.5 / §13.2: alreadyHandled 的 state 精确为
    // claimed/applying/applied/deliveryFailed/expired。
    let states = [
        ApprovalDeliveryState::Claimed,
        ApprovalDeliveryState::Applying,
        ApprovalDeliveryState::Applied,
        ApprovalDeliveryState::DeliveryFailed,
        ApprovalDeliveryState::Expired,
    ];
    assert_eq!(states.len(), 5);
    for state in states {
        let receipt = ApprovalReceipt::AlreadyHandled {
            approval_id: ApprovalId::new("a1"),
            decision: ActionDecisionKind::Approve,
            state,
        };
        let json = serde_json::to_value(&receipt).unwrap();
        let back: ApprovalReceipt = serde_json::from_value(json).unwrap();
        assert_eq!(back, receipt);
    }
    // the receipt enum also exposes the other outcomes
    let others = [
        ApprovalReceipt::Claimed {
            approval_id: ApprovalId::new("a1"),
        },
        ApprovalReceipt::Applied {
            approval_id: ApprovalId::new("a1"),
        },
        ApprovalReceipt::DeliveryFailed {
            approval_id: ApprovalId::new("a1"),
        },
        ApprovalReceipt::Expired {
            approval_id: ApprovalId::new("a1"),
        },
    ];
    for r in others {
        let json = serde_json::to_value(&r).unwrap();
        let _back: ApprovalReceipt = serde_json::from_value(json).unwrap();
    }
}

#[test]
fn snapshot_requires_capabilities_first() {
    let convo = ConversationId::new("c1");
    // valid: capabilities first, then items
    let ok = ConversationSnapshot::new(
        convo.clone(),
        0,
        vec![
            SnapshotItem::Capabilities {
                capabilities: sample_caps(),
            },
            SnapshotItem::Item {
                item_id: agentdeck_protocol::runtime::identity::ItemId::new("i1"),
                item: AgentItem::AssistantMessage {
                    text: "hi".into(),
                    meta: Default::default(),
                },
            },
        ],
    );
    assert!(ok.is_ok());

    // missing capabilities
    let missing = ConversationSnapshot::new(
        convo.clone(),
        0,
        vec![SnapshotItem::Item {
            item_id: agentdeck_protocol::runtime::identity::ItemId::new("i1"),
            item: AgentItem::AssistantMessage {
                text: "hi".into(),
                meta: Default::default(),
            },
        }],
    );
    assert!(matches!(missing, Err(SnapshotError::CapabilitiesMissing)));

    // capabilities not first
    let not_first = ConversationSnapshot::new(
        convo.clone(),
        0,
        vec![
            SnapshotItem::Item {
                item_id: agentdeck_protocol::runtime::identity::ItemId::new("i1"),
                item: AgentItem::AssistantMessage {
                    text: "hi".into(),
                    meta: Default::default(),
                },
            },
            SnapshotItem::Capabilities {
                capabilities: sample_caps(),
            },
        ],
    );
    assert!(matches!(
        not_first,
        Err(SnapshotError::CapabilitiesNotFirst)
    ));

    // duplicate capabilities
    let dup = ConversationSnapshot::new(
        convo,
        0,
        vec![
            SnapshotItem::Capabilities {
                capabilities: sample_caps(),
            },
            SnapshotItem::Capabilities {
                capabilities: sample_caps(),
            },
        ],
    );
    assert!(matches!(dup, Err(SnapshotError::DuplicateCapabilities)));
}

#[test]
fn snapshot_deserialize_rejects_capabilities_not_first() {
    // the barrier invariant (RC-16) must survive the wire, not only new().
    let bad = serde_json::json!({
        "conversationId": "c1",
        "baseEventSeq": 0,
        "items": [
            { "kind": "item", "itemId": "i1",
              "item": { "kind": "assistantMessage", "text": "hi", "meta": { "vendorExtensions": {} } } },
            { "kind": "capabilities", "capabilities": {
                "agentKind": "codex", "agentVersion": "x", "features": [],
                "vendor": { "agentKind": "codex", "sandboxModes": [], "persistenceSupported": false, "reasoningEffortLevels": [] } } }
        ]
    });
    let res: Result<ConversationSnapshot, _> = serde_json::from_value(bad);
    assert!(
        res.is_err(),
        "wire snapshot must also enforce capabilities-first"
    );
}

#[test]
fn local_only_admin_marker_serializes() {
    let v = serde_json::to_value(LocalOnlyAdministration::LocalOnly).unwrap();
    assert_eq!(v, serde_json::json!("localOnly"));
}
