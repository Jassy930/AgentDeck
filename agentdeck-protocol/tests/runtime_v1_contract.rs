//! P1.1 RuntimeEnvelope v1 中立契约 —— contract / deny-unknown / limits 测试。
//!
//! RuntimeEnvelope v1 是 UDS 与解密后远程链路的共同业务 wire（design §8.2）。
//! 本 task 只定义中立契约与构造校验，不接线任何运行时行为。

use agentdeck_protocol::runtime::command::{
    LocalOnlyAdministration, MAX_PROMPT_BYTES, PromptPayload, QueryReceiptSelector,
    SendPromptRequest,
};
use agentdeck_protocol::runtime::failure::{self, RuntimeFailure};
use agentdeck_protocol::runtime::identity::{
    AdapterStateKey, ApprovalId, CommandId, ConversationId, EntityId, EventId, IdempotencyKey,
    ItemId, MessageId, PairingId, StreamGeneration, TransferId, TurnId,
};
use agentdeck_protocol::runtime::receipt::{
    ApprovalDeliveryState, ApprovalReceipt, CancellationReceipt, CommandReceipt, CommandStatus,
    CommandStatusReceipt, ConversationStartReceipt, RevocationReceipt,
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
    ActionDecision, ActionDecisionKind, ActionKind, ActionRequest, ActionRequestVendor, AgentItem,
    AgentItemMeta, AgentKind, CapabilityId, CodexApprovalPolicy, CodexCapabilities,
    CodexReasoningEffort, CodexSandboxMode, DiffFile, DiffStatus, PlanStep, PlanStepStatus,
    SessionCapabilities, ShellStatus, TurnSummary, VendorCapabilities,
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

fn sample_multi_caps() -> SessionCapabilities {
    SessionCapabilities {
        agent_kind: AgentKind::Codex,
        agent_version: "fixture-2".into(),
        features: BTreeSet::from([
            CapabilityId::CodexSkills,
            CapabilityId::Worktree,
            CapabilityId::StreamingMessages,
            CapabilityId::Approval,
        ]),
        vendor: VendorCapabilities::Codex(CodexCapabilities {
            sandbox_modes: vec![CodexSandboxMode::ReadOnly, CodexSandboxMode::WorkspaceWrite],
            persistence_supported: true,
            reasoning_effort_levels: vec![CodexReasoningEffort::Low, CodexReasoningEffort::High],
        }),
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

    let request_conversation = ConversationId::new("conversation-request-1");
    let request_variants = vec![
        (
            "requestHello",
            RuntimeRequest::Hello(runtime::command::HelloParams {
                runtime_protocol_version: RUNTIME_PROTOCOL_VERSION,
            }),
        ),
        (
            "requestCatalog",
            RuntimeRequest::Catalog(runtime::command::CatalogRequest {
                subscribe: true,
                since_revision: None,
            }),
        ),
        (
            "requestSubscribe",
            RuntimeRequest::Subscribe {
                conversation_id: request_conversation.clone(),
                cursor: StreamCursor::BeforeFirst,
            },
        ),
        (
            "requestStart",
            RuntimeRequest::Start(runtime::command::ConversationStart {
                agent_kind: AgentKind::Codex,
                idempotency_key: IdempotencyKey::new("start-key-request-1"),
                cwd: PathBuf::from("/tmp/runtime-request-1"),
                title: Some("fixture conversation".into()),
            }),
        ),
        ("requestSendPrompt", sample_send_prompt()),
        (
            "requestResolveApproval",
            RuntimeRequest::ResolveApproval {
                conversation_id: request_conversation.clone(),
                turn_id: TurnId::new("turn-request-1"),
                approval_id: ApprovalId::new("approval-request-1"),
                decision: ActionDecision {
                    request_id: "action-request-1".into(),
                    decision: ActionDecisionKind::Approve,
                    persist: false,
                },
            },
        ),
        (
            "requestRetryApproval",
            RuntimeRequest::RetryApproval {
                conversation_id: request_conversation.clone(),
                approval_id: ApprovalId::new("approval-request-1"),
            },
        ),
        (
            "requestCancelQueued",
            RuntimeRequest::CancelQueued {
                conversation_id: request_conversation.clone(),
                command_id: CommandId::new("command-request-queued-1"),
            },
        ),
        (
            "requestCancelActive",
            RuntimeRequest::CancelActive {
                conversation_id: request_conversation.clone(),
                turn_id: TurnId::new("turn-request-active-1"),
            },
        ),
        (
            "requestQueryReceiptCommand",
            RuntimeRequest::QueryReceipt(QueryReceiptSelector::Command {
                conversation_id: request_conversation.clone(),
                command_id: CommandId::new("command-query-1"),
            }),
        ),
        (
            "requestQueryReceiptIdempotency",
            RuntimeRequest::QueryReceipt(QueryReceiptSelector::Idempotency {
                conversation_id: request_conversation.clone(),
                idempotency_key: IdempotencyKey::new("idempotency-query-1"),
            }),
        ),
        (
            "requestCreatePairInvite",
            RuntimeRequest::CreatePairInvite(runtime::command::CreatePairInviteRequest {
                display_name: "fixture machine".into(),
                ttl_secs: 300,
                scope: LocalOnlyAdministration::LocalOnly,
            }),
        ),
        (
            "requestListPendingPairings",
            RuntimeRequest::ListPendingPairings {
                scope: LocalOnlyAdministration::LocalOnly,
            },
        ),
        (
            "requestConfirmPairing",
            RuntimeRequest::ConfirmPairing {
                pairing_id: PairingId::new("pairing-request-1"),
                scope: LocalOnlyAdministration::LocalOnly,
            },
        ),
        (
            "requestCancelPairing",
            RuntimeRequest::CancelPairing {
                pairing_id: PairingId::new("pairing-request-1"),
                scope: LocalOnlyAdministration::LocalOnly,
            },
        ),
        (
            "requestRevoke",
            RuntimeRequest::Revoke(runtime::command::RevokeRequest {
                target: runtime::command::RevokeTarget::SelfDevice,
            }),
        ),
        (
            "requestTrustReset",
            RuntimeRequest::TrustReset {
                scope: LocalOnlyAdministration::LocalOnly,
            },
        ),
    ];
    for (index, (name, request)) in request_variants.into_iter().enumerate() {
        cases.push(fixture_case(
            name,
            "runtimeEnvelope",
            &envelope_with_id(
                &format!("message-request-{index}"),
                RuntimeMessage::Request(request),
            ),
        ));
    }

    let hello_reply = envelope_with_id(
        "message-reply-hello",
        RuntimeMessage::Reply(RuntimeReply::Hello(runtime::command::HelloParams {
            runtime_protocol_version: RUNTIME_PROTOCOL_VERSION,
        })),
    );
    cases.push(fixture_case("replyHello", "runtimeEnvelope", &hello_reply));

    let catalog_reply = envelope_with_id(
        "message-reply-catalog",
        RuntimeMessage::Reply(RuntimeReply::Catalog(
            runtime::catalog::CatalogSnapshot::new(
                9,
                vec![runtime::catalog::ConversationEntry {
                    conversation_id: ConversationId::new("conversation-catalog-1"),
                    adapter_state_key: runtime::identity::AdapterStateKey::new(
                        "adapter-state-catalog-1",
                    ),
                    agent_kind: AgentKind::Codex,
                    title: None,
                    cwd: None,
                    last_active_ms: 123,
                    archived: false,
                }],
                false,
            )
            .expect("fixture catalog page must satisfy bounds"),
        )),
    );
    cases.push(fixture_case(
        "replyCatalog",
        "runtimeEnvelope",
        &catalog_reply,
    ));

    let sync_complete = runtime::sync::RuntimeSyncComplete {
        stream_generation: StreamGeneration::new("generation-sync-1"),
        stream_cursor: StreamCursor::At(7),
        event_seq: 7,
        key_directory_revision: 3,
    };
    let reply_only_variants = vec![
        (
            "replyBackfill",
            RuntimeReply::Backfill(runtime::sync::BackfillChunk {
                conversation_id: ConversationId::new("conversation-backfill-1"),
                events: vec![],
            }),
        ),
        (
            "replySyncComplete",
            RuntimeReply::SyncComplete(sync_complete.clone()),
        ),
        (
            "replyPairInvite",
            RuntimeReply::PairInvite(runtime::envelope::PairInvite {
                pairing_id: PairingId::new("pairing-invite-1"),
                display_name: "fixture machine".into(),
                expires_at_ms: 456,
            }),
        ),
        (
            "replyPendingPairings",
            RuntimeReply::PendingPairings {
                pairings: vec![runtime::envelope::PendingPairing {
                    pairing_id: PairingId::new("pairing-pending-1"),
                    device_fingerprint: "fixture fingerprint".into(),
                    requested_at_ms: 234,
                }],
            },
        ),
        (
            "replyFailure",
            RuntimeReply::Failure(RuntimeFailure::new(
                failure::DAEMON_CONVERSATION_NOT_FOUND,
                "conversation not found",
            )),
        ),
    ];
    for (index, (name, reply)) in reply_only_variants.into_iter().enumerate() {
        cases.push(fixture_case(
            name,
            "runtimeEnvelope",
            &envelope_with_id(
                &format!("message-reply-extra-{index}"),
                RuntimeMessage::Reply(reply),
            ),
        ));
    }

    let catalog_delta_stream = envelope_with_id(
        "message-stream-catalog-delta",
        RuntimeMessage::Stream(RuntimeStreamItem::CatalogDelta(
            runtime::catalog::CatalogDelta {
                catalog_revision: 10,
                changes: vec![runtime::catalog::CatalogChange::Removed {
                    conversation_id: ConversationId::new("conversation-removed-1"),
                }],
            },
        )),
    );
    cases.push(fixture_case(
        "streamCatalogDelta",
        "runtimeEnvelope",
        &catalog_delta_stream,
    ));
    let sync_stream = envelope_with_id(
        "message-stream-sync-complete",
        RuntimeMessage::Stream(RuntimeStreamItem::SyncComplete(sync_complete)),
    );
    cases.push(fixture_case(
        "streamSyncComplete",
        "runtimeEnvelope",
        &sync_stream,
    ));

    let event_envelope = |message_id: &str, body: RuntimeEventBody| {
        envelope_with_id(
            message_id,
            RuntimeMessage::Stream(RuntimeStreamItem::Event(RuntimeEvent {
                conversation_id: ConversationId::new("conversation-event-matrix-1"),
                event_id: EventId::new(format!("event-{message_id}")),
                event_seq: 11,
                item_id: None,
                entity_id: None,
                body,
            })),
        )
    };
    let event_body_variants = vec![
        (
            "eventCapabilitiesMulti",
            RuntimeEventBody::Capabilities {
                capabilities: sample_multi_caps(),
            },
        ),
        (
            "eventTurnStarted",
            RuntimeEventBody::TurnStarted {
                turn_id: TurnId::new("turn-event-started-1"),
                command_id: CommandId::new("command-event-started-1"),
            },
        ),
        (
            "eventActionRequest",
            RuntimeEventBody::ActionRequest {
                turn_id: TurnId::new("turn-event-action-1"),
                approval_id: ApprovalId::new("approval-event-action-1"),
                request: ActionRequest {
                    request_id: "action-event-1".into(),
                    kind: ActionKind::ExecuteCommand,
                    summary: "fixture action".into(),
                    vendor: ActionRequestVendor::Codex {
                        approval_policy_at_decision: CodexApprovalPolicy::OnRequest,
                        sandbox_at_decision: CodexSandboxMode::WorkspaceWrite,
                        can_persist: true,
                    },
                },
            },
        ),
        (
            "eventApprovalResolved",
            RuntimeEventBody::ApprovalResolved {
                turn_id: TurnId::new("turn-event-resolved-1"),
                approval_id: ApprovalId::new("approval-event-resolved-1"),
                decision: Some(ActionDecisionKind::Deny),
                state: ApprovalDeliveryState::Applied,
            },
        ),
        (
            "eventApprovalExpiredWithoutWinner",
            RuntimeEventBody::ApprovalResolved {
                turn_id: TurnId::new("turn-event-expired-1"),
                approval_id: ApprovalId::new("approval-event-expired-1"),
                decision: None,
                state: ApprovalDeliveryState::Expired,
            },
        ),
        (
            "eventTurnCompleted",
            RuntimeEventBody::TurnCompleted {
                turn_id: TurnId::new("turn-event-completed-1"),
                summary: TurnSummary {
                    total_input_tokens: None,
                    total_output_tokens: None,
                    elapsed_ms: 99,
                },
            },
        ),
        (
            "eventTurnInterrupted",
            RuntimeEventBody::TurnInterrupted {
                turn_id: TurnId::new("turn-event-interrupted-1"),
            },
        ),
        (
            "eventError",
            RuntimeEventBody::Error {
                failure: RuntimeFailure::new(
                    failure::DAEMON_COMMAND_INTERRUPTED,
                    "fixture interrupted",
                ),
            },
        ),
    ];
    for (index, (name, event_body)) in event_body_variants.into_iter().enumerate() {
        cases.push(fixture_case(
            name,
            "runtimeEnvelope",
            &event_envelope(&format!("message-event-body-{index}"), event_body),
        ));
    }

    let empty_meta = || AgentItemMeta::default();
    let agent_items = vec![
        (
            "agentItemUserMessage",
            AgentItem::UserMessage {
                text: "fixture user".into(),
                meta: empty_meta(),
            },
        ),
        (
            "agentItemAssistantMessage",
            AgentItem::AssistantMessage {
                text: "fixture assistant".into(),
                meta: empty_meta(),
            },
        ),
        (
            "agentItemReasoning",
            AgentItem::Reasoning {
                text: "fixture reasoning".into(),
                meta: empty_meta(),
            },
        ),
        (
            "agentItemShellMinExit",
            AgentItem::Shell {
                command: "fixture-shell-min".into(),
                status: ShellStatus::Completed,
                exit_code: Some(i32::MIN),
                duration_ms: None,
                meta: empty_meta(),
            },
        ),
        (
            "agentItemDiffNullPatch",
            AgentItem::Diff {
                files: vec![DiffFile {
                    path: PathBuf::from("fixture.txt"),
                    status: DiffStatus::Modified,
                    patch: None,
                }],
                meta: empty_meta(),
            },
        ),
        (
            "agentItemPlanNullDetail",
            AgentItem::Plan {
                steps: vec![PlanStep {
                    title: "fixture plan".into(),
                    status: PlanStepStatus::Pending,
                    detail: None,
                }],
                meta: empty_meta(),
            },
        ),
        (
            "agentItemImageReferenceNullPaths",
            AgentItem::ImageReference {
                saved_path: None,
                original_path: None,
                meta: empty_meta(),
            },
        ),
        (
            "agentItemToolCallNullResult",
            AgentItem::ToolCall {
                name: "fixture-tool".into(),
                args: serde_json::json!({"nested": [1, true, null]}),
                result: None,
                meta: empty_meta(),
            },
        ),
        (
            "agentItemRaw",
            AgentItem::Raw {
                raw_kind: "fixture.raw".into(),
                raw_payload: "fixture payload".into(),
                meta: empty_meta(),
            },
        ),
        (
            "agentItemShellMaxExit",
            AgentItem::Shell {
                command: "fixture-shell-max".into(),
                status: ShellStatus::Failed,
                exit_code: Some(i32::MAX),
                duration_ms: None,
                meta: empty_meta(),
            },
        ),
        (
            "agentItemShellNullOptionals",
            AgentItem::Shell {
                command: "fixture-shell-null".into(),
                status: ShellStatus::Running,
                exit_code: None,
                duration_ms: None,
                meta: empty_meta(),
            },
        ),
    ];
    for (index, (name, item)) in agent_items.into_iter().enumerate() {
        cases.push(fixture_case(
            name,
            "runtimeEnvelope",
            &event_envelope(
                &format!("message-agent-item-{index}"),
                RuntimeEventBody::Item { item },
            ),
        ));
    }

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

    let command_status_receipts = [
        (
            "commandStatusAccepted",
            CommandStatusReceipt {
                conversation_id: ConversationId::new("conversation-status-1"),
                command_id: CommandId::new("command-status-accepted-1"),
                status: CommandStatus::Accepted,
                turn_id: None,
            },
        ),
        (
            "commandStatusStarted",
            CommandStatusReceipt {
                conversation_id: ConversationId::new("conversation-status-1"),
                command_id: CommandId::new("command-status-started-1"),
                status: CommandStatus::Started,
                turn_id: Some(TurnId::new("turn-status-started-1")),
            },
        ),
    ];
    for (index, (name, receipt)) in command_status_receipts.into_iter().enumerate() {
        let value = envelope_with_id(
            &format!("message-command-status-{index}"),
            RuntimeMessage::Reply(RuntimeReply::CommandStatus(receipt)),
        );
        cases.push(fixture_case(name, "runtimeEnvelope", &value));
    }

    let conversation_start_receipts = [
        (
            "conversationStartCreated",
            ConversationStartReceipt {
                conversation_id: ConversationId::new("conversation-created-1"),
                adapter_state_key: AdapterStateKey::new("adapter-state-created-1"),
                replayed: false,
            },
        ),
        (
            "conversationStartReplayed",
            ConversationStartReceipt {
                conversation_id: ConversationId::new("conversation-created-1"),
                adapter_state_key: AdapterStateKey::new("adapter-state-created-1"),
                replayed: true,
            },
        ),
    ];
    for (index, (name, receipt)) in conversation_start_receipts.into_iter().enumerate() {
        let value = envelope_with_id(
            &format!("message-conversation-start-{index}"),
            RuntimeMessage::Reply(RuntimeReply::ConversationStart(receipt)),
        );
        cases.push(fixture_case(name, "runtimeEnvelope", &value));
    }

    let cancellation_receipts = [
        (
            "cancellationQueuedCanceled",
            CancellationReceipt::QueuedCanceled {
                conversation_id: ConversationId::new("conversation-cancel-1"),
                command_id: CommandId::new("command-cancel-1"),
            },
        ),
        (
            "cancellationActiveCancelRequested",
            CancellationReceipt::ActiveCancelRequested {
                conversation_id: ConversationId::new("conversation-cancel-1"),
                turn_id: TurnId::new("turn-cancel-1"),
            },
        ),
    ];
    for (index, (name, receipt)) in cancellation_receipts.into_iter().enumerate() {
        let value = envelope_with_id(
            &format!("message-cancellation-{index}"),
            RuntimeMessage::Reply(RuntimeReply::Cancellation(receipt)),
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
    let revocation_failed = envelope_with_id(
        "message-revocation-failed-1",
        RuntimeMessage::Reply(RuntimeReply::Revocation(RevocationReceipt::Failed {
            failure: RuntimeFailure::new(failure::REMOTE_MACHINE_OFFLINE, "machine offline"),
        })),
    );
    cases.push(fixture_case(
        "revocationFailed",
        "runtimeEnvelope",
        &revocation_failed,
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
    // retryApproval/cancelQueued/cancelActive/queryReceipt/createPairInvite/listPendingPairings/
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
            idempotency_key: IdempotencyKey::new("start-1"),
            cwd: PathBuf::from("/tmp/runtime-contract"),
            title: None,
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
        RuntimeRequest::CancelQueued {
            conversation_id: convo.clone(),
            command_id: CommandId::new("cmd1"),
        },
        RuntimeRequest::CancelActive {
            conversation_id: convo.clone(),
            turn_id: TurnId::new("t1"),
        },
        RuntimeRequest::QueryReceipt(QueryReceiptSelector::Command {
            conversation_id: convo.clone(),
            command_id: CommandId::new("cmd1"),
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
    assert_eq!(variants.len(), 16);
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
fn conversation_start_is_pure_idempotent_creation_with_explicit_context() {
    let request = RuntimeRequest::Start(runtime::command::ConversationStart {
        agent_kind: AgentKind::ClaudeCode,
        idempotency_key: IdempotencyKey::new("create-conversation-1"),
        cwd: PathBuf::from("/tmp/runtime-start"),
        title: Some("runtime title".into()),
    });
    let json = serde_json::to_value(&request).unwrap();
    assert_eq!(
        json,
        serde_json::json!({
            "request": "start",
            "agentKind": "claude_code",
            "idempotencyKey": "create-conversation-1",
            "cwd": "/tmp/runtime-start",
            "title": "runtime title",
        })
    );
    assert!(
        json.get("prompt").is_none(),
        "Start must never carry a prompt"
    );

    for required in ["idempotencyKey", "cwd"] {
        let mut missing = json.clone();
        missing.as_object_mut().unwrap().remove(required);
        assert!(
            serde_json::from_value::<RuntimeRequest>(missing).is_err(),
            "missing {required} must fail closed"
        );
    }

    let without_title = serde_json::json!({
        "request": "start",
        "agentKind": "codex",
        "idempotencyKey": "create-conversation-2",
        "cwd": "/tmp/runtime-start-2",
    });
    assert!(serde_json::from_value::<RuntimeRequest>(without_title).is_ok());
}

#[test]
fn cancellation_requests_have_explicit_non_optional_targets() {
    let conversation_id = ConversationId::new("conversation-cancel-1");
    let queued = RuntimeRequest::CancelQueued {
        conversation_id: conversation_id.clone(),
        command_id: CommandId::new("command-cancel-1"),
    };
    let active = RuntimeRequest::CancelActive {
        conversation_id,
        turn_id: TurnId::new("turn-cancel-1"),
    };
    assert_eq!(
        serde_json::to_value(queued).unwrap(),
        serde_json::json!({
            "request": "cancelQueued",
            "conversationId": "conversation-cancel-1",
            "commandId": "command-cancel-1",
        })
    );
    assert_eq!(
        serde_json::to_value(active).unwrap(),
        serde_json::json!({
            "request": "cancelActive",
            "conversationId": "conversation-cancel-1",
            "turnId": "turn-cancel-1",
        })
    );
    for legacy_or_incomplete in [
        serde_json::json!({"request":"cancel","conversationId":"conversation-cancel-1"}),
        serde_json::json!({"request":"cancelQueued","conversationId":"conversation-cancel-1"}),
        serde_json::json!({"request":"cancelActive","conversationId":"conversation-cancel-1"}),
    ] {
        assert!(serde_json::from_value::<RuntimeRequest>(legacy_or_incomplete).is_err());
    }
}

#[test]
fn query_receipt_requires_one_tagged_selector() {
    let command = RuntimeRequest::QueryReceipt(QueryReceiptSelector::Command {
        conversation_id: ConversationId::new("conversation-query-1"),
        command_id: CommandId::new("command-query-1"),
    });
    let idempotency = RuntimeRequest::QueryReceipt(QueryReceiptSelector::Idempotency {
        conversation_id: ConversationId::new("conversation-query-1"),
        idempotency_key: IdempotencyKey::new("idempotency-query-1"),
    });
    assert_eq!(
        serde_json::to_value(command).unwrap(),
        serde_json::json!({
            "request": "queryReceipt",
            "selector": "command",
            "conversationId": "conversation-query-1",
            "commandId": "command-query-1",
        })
    );
    assert_eq!(
        serde_json::to_value(idempotency).unwrap(),
        serde_json::json!({
            "request": "queryReceipt",
            "selector": "idempotency",
            "conversationId": "conversation-query-1",
            "idempotencyKey": "idempotency-query-1",
        })
    );
    for invalid in [
        serde_json::json!({"request":"queryReceipt","conversationId":"conversation-query-1"}),
        serde_json::json!({
            "request":"queryReceipt", "selector":"command",
            "conversationId":"conversation-query-1", "commandId":"command-query-1",
            "idempotencyKey":"unexpected"
        }),
        serde_json::json!({
            "request":"queryReceipt", "selector":"idempotency",
            "conversationId":"conversation-query-1"
        }),
    ] {
        assert!(serde_json::from_value::<RuntimeRequest>(invalid).is_err());
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
fn command_status_receipt_preserves_exact_journal_state_and_turn() {
    let statuses = [
        (CommandStatus::Accepted, "accepted"),
        (CommandStatus::Started, "started"),
        (CommandStatus::Completed, "completed"),
        (CommandStatus::Failed, "failed"),
        (CommandStatus::Interrupted, "interrupted"),
        (CommandStatus::Expired, "expired"),
        (CommandStatus::Canceled, "canceled"),
        (CommandStatus::RevokedBeforeStart, "revokedBeforeStart"),
    ];
    for (index, (status, wire_status)) in statuses.into_iter().enumerate() {
        let turn_id = (status != CommandStatus::Accepted)
            .then(|| TurnId::new(format!("turn-status-{index}")));
        let reply = RuntimeReply::CommandStatus(CommandStatusReceipt {
            conversation_id: ConversationId::new("conversation-status-1"),
            command_id: CommandId::new(format!("command-status-{index}")),
            status,
            turn_id: turn_id.clone(),
        });
        let json = serde_json::to_value(&reply).unwrap();
        assert_eq!(json["reply"], "commandStatus");
        assert_eq!(json["conversationId"], "conversation-status-1");
        assert_eq!(json["commandId"], format!("command-status-{index}"));
        assert_eq!(json["status"], wire_status);
        assert_eq!(
            json["turnId"],
            turn_id
                .as_ref()
                .map_or(serde_json::Value::Null, |value| serde_json::json!(value))
        );
        let decoded: RuntimeReply = serde_json::from_value(json.clone()).unwrap();
        assert_eq!(serde_json::to_value(decoded).unwrap(), json);
    }
}

#[test]
fn conversation_start_receipt_returns_daemon_ids_and_replay_state() {
    for replayed in [false, true] {
        let reply = RuntimeReply::ConversationStart(ConversationStartReceipt {
            conversation_id: ConversationId::new("conversation-started-1"),
            adapter_state_key: AdapterStateKey::new("adapter-state-started-1"),
            replayed,
        });
        let json = serde_json::to_value(&reply).unwrap();
        assert_eq!(json["reply"], "conversationStart");
        assert_eq!(json["conversationId"], "conversation-started-1");
        assert_eq!(json["adapterStateKey"], "adapter-state-started-1");
        assert_eq!(json["replayed"], replayed);
        let decoded: RuntimeReply = serde_json::from_value(json.clone()).unwrap();
        assert_eq!(serde_json::to_value(decoded).unwrap(), json);
    }
}

#[test]
fn cancellation_receipt_distinguishes_terminal_queued_from_active_request() {
    let queued = RuntimeReply::Cancellation(CancellationReceipt::QueuedCanceled {
        conversation_id: ConversationId::new("conversation-cancel-1"),
        command_id: CommandId::new("command-cancel-1"),
    });
    let active = RuntimeReply::Cancellation(CancellationReceipt::ActiveCancelRequested {
        conversation_id: ConversationId::new("conversation-cancel-1"),
        turn_id: TurnId::new("turn-cancel-1"),
    });
    assert_eq!(
        serde_json::to_value(&queued).unwrap(),
        serde_json::json!({
            "reply": "cancellation",
            "status": "queuedCanceled",
            "conversationId": "conversation-cancel-1",
            "commandId": "command-cancel-1",
        })
    );
    assert_eq!(
        serde_json::to_value(&active).unwrap(),
        serde_json::json!({
            "reply": "cancellation",
            "status": "activeCancelRequested",
            "conversationId": "conversation-cancel-1",
            "turnId": "turn-cancel-1",
        })
    );
    for reply in [queued, active] {
        let json = serde_json::to_value(&reply).unwrap();
        let decoded: RuntimeReply = serde_json::from_value(json.clone()).unwrap();
        assert_eq!(serde_json::to_value(decoded).unwrap(), json);
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
fn pending_approval_can_expire_without_fabricating_a_winner_decision() {
    // P3.5: Pending -> Expired has no first-wins decision. The canonical event must
    // represent that absence explicitly instead of inventing approve/deny.
    let json = serde_json::json!({
        "kind": "approvalResolved",
        "turn_id": "turn-expired-without-winner",
        "approval_id": "approval-expired-without-winner",
        "decision": null,
        "state": "expired",
    });
    let decoded: RuntimeEventBody =
        serde_json::from_value(json.clone()).expect("pending expiry has no winner");
    assert_eq!(serde_json::to_value(decoded).unwrap(), json);

    let mut missing = json;
    missing.as_object_mut().unwrap().remove("decision");
    serde_json::from_value::<RuntimeEventBody>(missing)
        .expect_err("decision must stay explicitly present even when its value is null");
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
