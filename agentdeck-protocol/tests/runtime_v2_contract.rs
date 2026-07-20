//! RuntimeEnvelope v4 中立契约 —— contract / deny-unknown / limits 测试。
//!
//! 文件名保留 `runtime_v2_contract` 以避免无价值的测试目标重命名；current wire 已升为 v4。
//! RuntimeEnvelope v4 是 UDS 与解密后远程链路的共同业务 wire（design §8.2.2）。

use agentdeck_protocol::e2ee::{E2EE_FORMAT_VERSION, PairInviteV1};
use agentdeck_protocol::relay_v2::enrollment::EnrollmentBundleV2;
use agentdeck_protocol::relay_v2::id::{
    LinkGeneration, MachineRouteId, PairRouteId, RelayServerId,
};
use agentdeck_protocol::relay_v2::{
    CertRole, Ed25519Signature, PublicKeyBytes, RELAY_PROTOCOL_VERSION,
    RELAY_RECEIPT_FORMAT_VERSION, RELAY_RECEIPT_KEY_GENERATION_MVP, RelayAdminPurgeReadbackV1,
    RelayAdminPurgeReceiptTbsV1, RelayAdminPurgeReceiptV1, RelayAdminPurgeTombstoneV1,
    RelayMachineTombstoneKindV1, RelayReceiptKeyId, RootKeyId, SignedCertificate, TrustEpoch,
    admin_purge_tombstone_hash, purge_request_hash,
};
use agentdeck_protocol::runtime::command::{
    LocalOnlyAdministration, MAX_PROMPT_BYTES, PromptPayload, QueryReceiptSelector,
    SendPromptRequest,
};
use agentdeck_protocol::runtime::failure::{self, RuntimeFailure};
use agentdeck_protocol::runtime::identity::{
    ApprovalId, CatalogPageCursor, CommandId, ConversationId, EntityId, EventId, IdempotencyKey,
    ItemId, MAX_MESSAGE_ID_BYTES, MAX_TRANSFER_ID_BYTES, MessageId, PairingId, StreamGeneration,
    TransferId, TurnId,
};
use agentdeck_protocol::runtime::receipt::{
    ApprovalDeliveryState, ApprovalReceipt, CancellationReceipt, CommandReceipt, CommandStatus,
    CommandStatusReceipt, ConversationStartReceipt, PairingDecision, PairingReceipt, PairingState,
    RevocationReceipt,
};
use agentdeck_protocol::runtime::sync::{
    BackfillChunk, BackfillRange, BackfillRequest, ConversationSnapshot, RuntimeInnerCursor,
    RuntimeSubscriptionTarget, RuntimeSyncComplete, SnapshotError, SnapshotItem, StreamCursor,
};
use agentdeck_protocol::runtime::{
    self, AgentDescription, AgentDescriptions, ArtifactSha256, ClaudeCodeConversationConfiguration,
    CodexConversationConfiguration, ConfigurationReceipt, ConfigureConversationRequest,
    ConversationConfiguration, ConversationConfigurationState, ConversationMetadataMutation,
    ConversationMetadataMutationRequest, ConversationMetadataReceipt, MAX_JSON_PART_BYTES,
    MAX_JSON_TRANSFER_PARTS, MAX_RUNTIME_JSON_FRAME_BYTES, MAX_RUNTIME_REQUEST_BYTES,
    MachineEnrollRequest, MachineRemoteFailureCode, MachineRemoteLifecycle, MachineRemoteStatus,
    MachineRootFingerprint, RUNTIME_PROTOCOL_VERSION, RuntimeEnvelope, RuntimeEvent,
    RuntimeEventBody, RuntimeMessage, RuntimeReply, RuntimeRequest, RuntimeSizeError,
    RuntimeStreamItem, RuntimeTransferCarrierV1, RuntimeTransferChannel, StageUpgradeReceipt,
    StageUpgradeRequest, SubscriptionReceipt, TransferEnvelope, TrustResetRequest,
    UninstallPurgePlanV1, VendorConfigurationSnapshot, ensure_request_within_limit,
};
use agentdeck_protocol::{
    ActionDecision, ActionDecisionKind, ActionKind, ActionRequest, ActionRequestVendor, AgentItem,
    AgentItemMeta, AgentKind, CapabilityId, ClaudeCodeCapabilities, ClaudeCodePermissionMode,
    ClaudeCodeVendorPanelEvent, CodexApprovalPolicy, CodexCapabilities, CodexReasoningEffort,
    CodexSandboxMode, CodexVendorPanelEvent, DiffFile, DiffStatus, PlanStep, PlanStepStatus,
    SessionCapabilities, ShellStatus, TurnSummary, VendorCapabilities, VendorPanelPayload,
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

fn sample_claude_code_caps() -> SessionCapabilities {
    SessionCapabilities {
        agent_kind: AgentKind::ClaudeCode,
        agent_version: "fixture-cc-1".into(),
        features: BTreeSet::new(),
        vendor: VendorCapabilities::ClaudeCode(ClaudeCodeCapabilities::default()),
    }
}

fn sample_send_prompt() -> RuntimeRequest {
    RuntimeRequest::SendPrompt(SendPromptRequest {
        conversation_id: ConversationId::new("c1"),
        idempotency_key: IdempotencyKey::new("k1"),
        expected_configuration_revision: 1,
        prompt: PromptPayload::new("hello").unwrap(),
    })
}

fn sample_codex_configuration() -> ConversationConfiguration {
    ConversationConfiguration::new(VendorConfigurationSnapshot::Codex(
        CodexConversationConfiguration::new(
            CodexApprovalPolicy::OnRequest,
            CodexSandboxMode::WorkspaceWrite,
            CodexReasoningEffort::High,
        ),
    ))
}

fn sample_claude_code_configuration() -> ConversationConfiguration {
    ConversationConfiguration::new(VendorConfigurationSnapshot::ClaudeCode(
        ClaudeCodeConversationConfiguration::new(
            ClaudeCodePermissionMode::Default,
            Some("sonnet".into()),
            Some("high".into()),
            Some("concise".into()),
        )
        .unwrap(),
    ))
}

fn unconfigured_state() -> ConversationConfigurationState {
    ConversationConfigurationState::new(0, None).unwrap()
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

fn hex(bytes: &[u8]) -> String {
    bytes.iter().map(|byte| format!("{byte:02x}")).collect()
}

fn runtime_fixture_path() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("../protocol/agentdeck/fixtures/runtime-v4-wire.jsonl")
}

fn sample_enrollment_bundle() -> EnrollmentBundleV2 {
    serde_json::from_value(serde_json::json!({
        "version": 2,
        "publicWssUrl": "wss://relay.example.test/",
        "relayServerId": "IiIiIiIiIiIiIiIiIiIiIg==",
        "receiptVerifyKey": {
            "receiptFormatVersion": 1,
            "relayServerId": "IiIiIiIiIiIiIiIiIiIiIg==",
            "keyGeneration": 1,
            "keyId": "9uiDt7VE9fLhOJ4F1EvvLCH5R+HGrCJpMfGxejtfq3M=",
            "publicKey": "MzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzM="
        },
        "code": "REREREREREREREREREREREREREREREREREREREREREQ=",
        "spkiPins": ["-_v7-_v7-_v7-_v7-_v7-_v7-_v7-_v7-_v7-_v7-_s"],
        "expiresAtMs": 1_700_000_000_000u64
    }))
    .expect("valid shared enrollment bundle fixture")
}

fn sample_pair_invite(machine_display_name: impl Into<String>) -> PairInviteV1 {
    PairInviteV1 {
        format_version: E2EE_FORMAT_VERSION,
        relay_protocol_version: RELAY_PROTOCOL_VERSION,
        pair_route: PairRouteId::from_bytes([0x91; 16]),
        invite_secret: [0x92; 32],
        invite_hpke_pubkey: PublicKeyBytes([0x93; 32]),
        wss_url: "wss://relay.example.test/".to_owned(),
        relay_server_id: RelayServerId::from_bytes([0x94; 16]),
        current_spki_pin: [0x95; 32],
        next_spki_pin: [0x96; 32],
        expires_at_ms: 1_700_000_300_000,
        machine_root_pubkey: PublicKeyBytes([0x97; 32]),
        machine_root_fingerprint: Sha256::digest([0x97; 32]).into(),
        data_sign_cert: SignedCertificate {
            subject_pubkey: PublicKeyBytes([0x99; 32]),
            cert_role: CertRole::Data,
            generation: LinkGeneration::new(2),
            root_key_id: RootKeyId::from_bytes([0x9a; 16]),
            trust_epoch: TrustEpoch::new(7),
            not_after_ms: Some(1_800_000_000_000),
            signature: Ed25519Signature([0x9b; 64]),
        },
        machine_display_name: machine_display_name.into(),
    }
}

fn sample_admin_purge_receipt() -> RelayAdminPurgeReceiptV1 {
    let relay_server_id = RelayServerId::from_bytes([0x22; 16]);
    let machine_route = MachineRouteId::from_bytes([0x33; 16]);
    let root_key_id = RootKeyId::from_bytes([0x55; 16]);
    let root_fingerprint = [0x44; 32];
    let trust_epoch = TrustEpoch::new(7);
    let enrollment_receipt_hash = [0x66; 32];
    let purge_request_hash = purge_request_hash(machine_route, root_fingerprint).unwrap();
    let tombstone_kind = RelayMachineTombstoneKindV1::RootLostAdminPurge;
    let readback = RelayAdminPurgeReadbackV1 {
        active_machine_routes: 0,
        retired_tombstones: 1,
        consumed_enrollment_records: 0,
        device_grants: 0,
        revocations: 0,
        streams: 0,
        frames: 0,
        subscriptions: 0,
        retirement_hash: None,
        retirement_terminal_present: false,
    };
    let tombstone_hash = admin_purge_tombstone_hash(&RelayAdminPurgeTombstoneV1 {
        relay_server_id,
        machine_route,
        root_key_id,
        root_fingerprint,
        trust_epoch,
        enrollment_receipt_hash,
        purge_request_hash,
        tombstone_kind,
        readback: readback.clone(),
    })
    .unwrap();
    RelayAdminPurgeReceiptV1::from_tbs(
        RelayAdminPurgeReceiptTbsV1 {
            receipt_format_version: RELAY_RECEIPT_FORMAT_VERSION,
            relay_protocol_version: RELAY_PROTOCOL_VERSION,
            relay_server_id,
            receipt_key_generation: RELAY_RECEIPT_KEY_GENERATION_MVP,
            receipt_key_id: RelayReceiptKeyId::from_bytes([0x77; 32]),
            machine_route,
            root_key_id,
            root_fingerprint,
            trust_epoch,
            enrollment_receipt_hash,
            purge_request_hash,
            tombstone_kind,
            readback,
            tombstone_hash,
        },
        Ed25519Signature([0x88; 64]),
    )
    .unwrap()
}

fn sample_uninstall_purge_plan() -> UninstallPurgePlanV1 {
    UninstallPurgePlanV1::new(
        PathBuf::from("/Applications/AgentDeck.app/Contents/Helpers/agentdeck-finalizer"),
        "1.2.3".to_owned(),
        ArtifactSha256::new("ab".repeat(32)).unwrap(),
        "REALTEAM42".to_owned(),
        "REALTEAM42.com.agentdeck.agentdeckd.stable".to_owned(),
    )
    .unwrap()
}

fn render_runtime_wire_fixture() -> String {
    let mut cases = Vec::new();

    let stable_ids = envelope_with_id(
        "message-stable-1",
        RuntimeMessage::Stream(RuntimeStreamItem::Event(
            RuntimeEvent::new(
                ConversationId::new("conversation-stable-1"),
                EventId::new("event-stable-1"),
                7,
                Some(CommandId::new("command-stable-1")),
                Some(ItemId::new("item-stable-1")),
                Some(EntityId::new("entity-stable-1")),
                RuntimeEventBody::Item {
                    item: AgentItem::UserMessage {
                        text: "stable user message".into(),
                        meta: Default::default(),
                    },
                },
            )
            .unwrap(),
        )),
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
        ("requestDescribeAgents", RuntimeRequest::DescribeAgents),
        (
            "requestCatalog",
            RuntimeRequest::Catalog(runtime::command::CatalogRequest { page_cursor: None }),
        ),
        (
            "requestSubscribe",
            RuntimeRequest::Subscribe {
                inner_cursor: RuntimeInnerCursor::Conversation {
                    conversation_id: request_conversation.clone(),
                    cursor: StreamCursor::BeforeFirst,
                },
            },
        ),
        (
            "requestUnsubscribe",
            RuntimeRequest::Unsubscribe {
                target: RuntimeSubscriptionTarget::Conversation {
                    conversation_id: request_conversation.clone(),
                },
            },
        ),
        (
            "requestBackfillCatalog",
            RuntimeRequest::Backfill(BackfillRequest::Catalog {
                after: StreamCursor::BeforeFirst,
            }),
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
        (
            "requestConfigureCodex",
            RuntimeRequest::ConfigureConversation(ConfigureConversationRequest::new(
                request_conversation.clone(),
                IdempotencyKey::new("configure-codex-1"),
                0,
                sample_codex_configuration(),
            )),
        ),
        (
            "requestConfigureClaudeCode",
            RuntimeRequest::ConfigureConversation(ConfigureConversationRequest::new(
                request_conversation.clone(),
                IdempotencyKey::new("configure-cc-1"),
                1,
                sample_claude_code_configuration(),
            )),
        ),
        (
            "requestUpdateMetadataRename",
            RuntimeRequest::UpdateConversationMetadata(
                ConversationMetadataMutationRequest::new(
                    request_conversation.clone(),
                    IdempotencyKey::new("metadata-rename-1"),
                    4,
                    ConversationMetadataMutation::rename(Some("renamed fixture".into())).unwrap(),
                )
                .unwrap(),
            ),
        ),
        (
            "requestUpdateMetadataArchive",
            RuntimeRequest::UpdateConversationMetadata(
                ConversationMetadataMutationRequest::new(
                    request_conversation.clone(),
                    IdempotencyKey::new("metadata-archive-1"),
                    5,
                    ConversationMetadataMutation::SetArchived { archived: true },
                )
                .unwrap(),
            ),
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
                idempotency_key: IdempotencyKey::new("pair-invite-request-1"),
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
            RuntimeRequest::TrustReset(
                TrustResetRequest::new(LocalOnlyAdministration::LocalOnly, None).unwrap(),
            ),
        ),
        (
            "requestTrustResetWithAdminPurgeReceipt",
            RuntimeRequest::TrustReset(
                TrustResetRequest::new(
                    LocalOnlyAdministration::LocalOnly,
                    Some(Box::new(sample_admin_purge_receipt())),
                )
                .unwrap(),
            ),
        ),
        (
            "requestTrustResetForUninstallPurge",
            RuntimeRequest::TrustReset(
                TrustResetRequest::for_uninstall_purge(
                    LocalOnlyAdministration::LocalOnly,
                    sample_uninstall_purge_plan(),
                    None,
                )
                .unwrap(),
            ),
        ),
        (
            "requestMachineEnroll",
            RuntimeRequest::MachineEnroll(MachineEnrollRequest {
                bundle: sample_enrollment_bundle(),
                scope: LocalOnlyAdministration::LocalOnly,
            }),
        ),
        (
            "requestMachineRemoteStatus",
            RuntimeRequest::MachineRemoteStatus {
                scope: LocalOnlyAdministration::LocalOnly,
            },
        ),
        (
            "requestStageUpgrade",
            RuntimeRequest::StageUpgrade(
                StageUpgradeRequest::new(
                    "1.2.3".into(),
                    ArtifactSha256::new("ab".repeat(32)).unwrap(),
                    IdempotencyKey::new("upgrade-request-1"),
                    LocalOnlyAdministration::LocalOnly,
                )
                .unwrap(),
            ),
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

    let agents_reply = envelope_with_id(
        "message-reply-agents",
        RuntimeMessage::Reply(RuntimeReply::Agents(
            AgentDescriptions::new(vec![
                AgentDescription::new(
                    AgentKind::Codex,
                    sample_caps(),
                    sample_codex_configuration(),
                )
                .unwrap(),
                AgentDescription::new(
                    AgentKind::ClaudeCode,
                    sample_claude_code_caps(),
                    sample_claude_code_configuration(),
                )
                .unwrap(),
            ])
            .unwrap(),
        )),
    );
    cases.push(fixture_case(
        "replyAgents",
        "runtimeEnvelope",
        &agents_reply,
    ));

    let configuration_replies = [
        (
            "configurationApplied",
            ConfigurationReceipt::Applied {
                conversation_id: ConversationId::new("conversation-configuration-1"),
                configuration_revision: 1,
            },
        ),
        (
            "configurationReplayed",
            ConfigurationReceipt::Replayed {
                conversation_id: ConversationId::new("conversation-configuration-1"),
                configuration_revision: 1,
            },
        ),
        (
            "configurationConflict",
            ConfigurationReceipt::Conflict {
                conversation_id: ConversationId::new("conversation-configuration-1"),
                current_configuration_revision: 2,
            },
        ),
        (
            "configurationFailed",
            ConfigurationReceipt::Failed {
                failure: RuntimeFailure::new("daemon.configuration.unavailable", "fixture"),
            },
        ),
    ];
    for (index, (name, receipt)) in configuration_replies.into_iter().enumerate() {
        let value = envelope_with_id(
            &format!("message-configuration-{index}"),
            RuntimeMessage::Reply(RuntimeReply::Configuration(receipt)),
        );
        cases.push(fixture_case(name, "runtimeEnvelope", &value));
    }

    let metadata_replies = [
        (
            "metadataApplied",
            ConversationMetadataReceipt::Applied {
                conversation_id: ConversationId::new("conversation-metadata-1"),
                entry_revision: 8,
            },
        ),
        (
            "metadataReplayed",
            ConversationMetadataReceipt::Replayed {
                conversation_id: ConversationId::new("conversation-metadata-1"),
                entry_revision: 8,
            },
        ),
        (
            "metadataConflict",
            ConversationMetadataReceipt::Conflict {
                conversation_id: ConversationId::new("conversation-metadata-1"),
                current_entry_revision: 9,
            },
        ),
        (
            "metadataFailed",
            ConversationMetadataReceipt::Failed {
                failure: RuntimeFailure::new("daemon.metadata.unavailable", "fixture"),
            },
        ),
    ];
    for (index, (name, receipt)) in metadata_replies.into_iter().enumerate() {
        let value = envelope_with_id(
            &format!("message-metadata-{index}"),
            RuntimeMessage::Reply(RuntimeReply::ConversationMetadata(receipt)),
        );
        cases.push(fixture_case(name, "runtimeEnvelope", &value));
    }

    let upgrade_replies = [
        (
            "stageUpgradeStaged",
            StageUpgradeReceipt::Staged {
                target_version: "1.2.3".into(),
            },
        ),
        (
            "stageUpgradeAwaitingIdle",
            StageUpgradeReceipt::AwaitingIdle {
                target_version: "1.2.3".into(),
                active_turns: 2,
            },
        ),
        (
            "stageUpgradeReplayed",
            StageUpgradeReceipt::Replayed {
                target_version: "1.2.3".into(),
            },
        ),
        (
            "stageUpgradeFailed",
            StageUpgradeReceipt::Failed {
                failure: RuntimeFailure::new("daemon.upgrade.unavailable", "fixture"),
            },
        ),
    ];
    for (index, (name, receipt)) in upgrade_replies.into_iter().enumerate() {
        let value = envelope_with_id(
            &format!("message-upgrade-{index}"),
            RuntimeMessage::Reply(RuntimeReply::StageUpgrade(receipt)),
        );
        cases.push(fixture_case(name, "runtimeEnvelope", &value));
    }

    let catalog_reply = envelope_with_id(
        "message-reply-catalog",
        RuntimeMessage::Reply(RuntimeReply::Catalog(
            runtime::catalog::CatalogSnapshot::new(
                StreamCursor::At(9),
                vec![runtime::catalog::ConversationEntry {
                    conversation_id: ConversationId::new("conversation-catalog-1"),
                    agent_kind: AgentKind::Codex,
                    title: None,
                    cwd: None,
                    last_active_ms: 123,
                    archived: false,
                    entry_revision: 3,
                }],
                None,
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
        inner_cursor: RuntimeInnerCursor::Conversation {
            conversation_id: ConversationId::new("conversation-sync-1"),
            cursor: StreamCursor::At(7),
        },
        key_directory_revision: 3,
    };
    let backfill_event = RuntimeEvent::new(
        ConversationId::new("conversation-backfill-1"),
        EventId::new("event-backfill-0"),
        0,
        Some(CommandId::new("command-backfill-0")),
        Some(ItemId::new("item-backfill-0")),
        Some(EntityId::new("entity-backfill-0")),
        RuntimeEventBody::Item {
            item: AgentItem::UserMessage {
                text: "backfilled user message".into(),
                meta: Default::default(),
            },
        },
    )
    .unwrap();
    let reply_only_variants = vec![
        (
            "replySubscriptionSubscribed",
            RuntimeReply::Subscription(SubscriptionReceipt::Subscribed {
                stream_generation: StreamGeneration::new("generation-subscribed-1"),
            }),
        ),
        (
            "replySubscriptionUnsubscribed",
            RuntimeReply::Subscription(SubscriptionReceipt::Unsubscribed),
        ),
        (
            "replyBackfill",
            RuntimeReply::Backfill(
                BackfillChunk::conversation(
                    ConversationId::new("conversation-backfill-1"),
                    sample_caps(),
                    BackfillRange::new(StreamCursor::BeforeFirst, StreamCursor::At(0)).unwrap(),
                    vec![backfill_event],
                )
                .unwrap(),
            ),
        ),
        (
            "replySyncComplete",
            RuntimeReply::SyncComplete(sync_complete.clone()),
        ),
        (
            "replyPairInvite",
            RuntimeReply::PairInvite(runtime::envelope::PairInvite {
                pairing_id: PairingId::new("pairing-invite-1"),
                invite: Box::new(sample_pair_invite("fixture machine")),
            }),
        ),
        (
            "replyPendingPairings",
            RuntimeReply::PendingPairings {
                pairings: vec![runtime::envelope::PendingPairing {
                    pairing_id: PairingId::new("pairing-pending-1"),
                    request_hash: [0xa1; 32],
                    device_sign_fingerprint: [0xa2; 32],
                    requested_at_ms: 234,
                    expires_at_ms: 456,
                }],
            },
        ),
        (
            "replyPairingConfirmed",
            RuntimeReply::Pairing(PairingReceipt::Confirmed {
                pairing_id: PairingId::new("pairing-confirmed-1"),
            }),
        ),
        (
            "replyPairingCanceled",
            RuntimeReply::Pairing(PairingReceipt::Canceled {
                pairing_id: PairingId::new("pairing-canceled-1"),
            }),
        ),
        (
            "replyPairingExpired",
            RuntimeReply::Pairing(PairingReceipt::Expired {
                pairing_id: PairingId::new("pairing-expired-1"),
            }),
        ),
        (
            "replyPairingReplayed",
            RuntimeReply::Pairing(PairingReceipt::Replayed {
                pairing_id: PairingId::new("pairing-replayed-1"),
                decision: PairingDecision::Confirm,
                state: PairingState::GrantCommitted,
            }),
        ),
        (
            "replyPairingAlreadyHandled",
            RuntimeReply::Pairing(PairingReceipt::AlreadyHandled {
                pairing_id: PairingId::new("pairing-handled-1"),
                winner: PairingDecision::Cancel,
                state: PairingState::Canceled,
            }),
        ),
        (
            "replyPairingFailed",
            RuntimeReply::Pairing(PairingReceipt::Failed {
                failure: RuntimeFailure::new(
                    "daemon.pairing.state_conflict",
                    "pairing state conflict",
                ),
            }),
        ),
        (
            "replyMachineRemoteStatus",
            RuntimeReply::MachineRemoteStatus(
                MachineRemoteStatus::new(
                    MachineRemoteLifecycle::Active,
                    Some(RelayServerId::from_bytes([0x22; 16])),
                    Some(MachineRouteId::from_bytes([0x33; 16])),
                    Some(MachineRootFingerprint::from_bytes([0x44; 32])),
                    Some(7),
                    None,
                )
                .unwrap(),
            ),
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
    let catalog_upsert_stream = envelope_with_id(
        "message-stream-catalog-upsert",
        RuntimeMessage::Stream(RuntimeStreamItem::CatalogDelta(
            runtime::catalog::CatalogDelta {
                catalog_revision: 11,
                changes: vec![runtime::catalog::CatalogChange::Upserted {
                    entry: runtime::catalog::ConversationEntry {
                        conversation_id: ConversationId::new("conversation-upserted-1"),
                        agent_kind: AgentKind::Codex,
                        title: Some("upserted fixture".into()),
                        cwd: None,
                        last_active_ms: 456,
                        archived: false,
                        entry_revision: 4,
                    },
                }],
            },
        )),
    );
    cases.push(fixture_case(
        "streamCatalogUpsert",
        "runtimeEnvelope",
        &catalog_upsert_stream,
    ));
    let event_envelope = |message_id: &str, body: RuntimeEventBody| {
        let is_item = matches!(&body, RuntimeEventBody::Item { .. });
        let needs_command = !matches!(
            &body,
            RuntimeEventBody::Capabilities { .. }
                | RuntimeEventBody::ConfigurationChanged { .. }
                | RuntimeEventBody::VendorPanelEvent { .. }
                | RuntimeEventBody::Error { .. }
        );
        envelope_with_id(
            message_id,
            RuntimeMessage::Stream(RuntimeStreamItem::Event(
                RuntimeEvent::new(
                    ConversationId::new("conversation-event-matrix-1"),
                    EventId::new(format!("event-{message_id}")),
                    11,
                    needs_command.then(|| CommandId::new(format!("command-{message_id}"))),
                    is_item.then(|| ItemId::new(format!("item-{message_id}"))),
                    is_item.then(|| EntityId::new(format!("entity-{message_id}"))),
                    body,
                )
                .unwrap(),
            )),
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
            "eventConfigurationChanged",
            RuntimeEventBody::ConfigurationChanged {
                state: ConversationConfigurationState::new(2, Some(sample_codex_configuration()))
                    .unwrap(),
            },
        ),
        (
            "eventCodexVendorPanel",
            RuntimeEventBody::VendorPanelEvent {
                vendor_panel: VendorPanelPayload::Codex(CodexVendorPanelEvent::Placeholder),
            },
        ),
        (
            "eventClaudeCodeVendorPanel",
            RuntimeEventBody::VendorPanelEvent {
                vendor_panel: VendorPanelPayload::ClaudeCode(
                    ClaudeCodeVendorPanelEvent::SystemStatus {
                        subtype: "fixture".into(),
                        status: Some("ready".into()),
                        message: None,
                        attempt: None,
                        error: None,
                        error_status: None,
                        max_retries: None,
                        retry_delay_ms: None,
                    },
                ),
            },
        ),
        (
            "eventTurnStarted",
            RuntimeEventBody::TurnStarted {
                turn_id: TurnId::new("turn-event-started-1"),
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
                configuration_revision: 3,
            },
        ),
        (
            "commandReplayed",
            CommandReceipt::Replayed {
                command_id: CommandId::new("command-replayed-1"),
                configuration_revision: 3,
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
                configuration_revision: 3,
                status: CommandStatus::Accepted,
                turn_id: None,
            },
        ),
        (
            "commandStatusStarted",
            CommandStatusReceipt {
                conversation_id: ConversationId::new("conversation-status-1"),
                command_id: CommandId::new("command-status-started-1"),
                configuration_revision: 3,
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
                replayed: false,
            },
        ),
        (
            "conversationStartReplayed",
            ConversationStartReceipt {
                conversation_id: ConversationId::new("conversation-created-1"),
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
        StreamCursor::At(6),
        ConversationConfigurationState::new(1, Some(sample_codex_configuration())).unwrap(),
        vec![
            SnapshotItem::capabilities(sample_caps()),
            SnapshotItem::Item {
                item_id: ItemId::new("item-snapshot-1"),
                entity_id: EntityId::new("entity-snapshot-1"),
                command_id: None,
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
    let unconfigured_snapshot = ConversationSnapshot::new(
        ConversationId::new("conversation-snapshot-unconfigured-1"),
        StreamCursor::BeforeFirst,
        unconfigured_state(),
        vec![SnapshotItem::capabilities(sample_caps())],
    )
    .unwrap();
    cases.push(fixture_case(
        "unconfiguredSnapshot",
        "runtimeEnvelope",
        &envelope_with_id(
            "message-snapshot-unconfigured-1",
            RuntimeMessage::Reply(RuntimeReply::Snapshot(unconfigured_snapshot)),
        ),
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
    cases.push(fixture_case(
        "replyTransferPart",
        "runtimeEnvelope",
        &envelope_with_id(
            "message-transfer-reply-1",
            RuntimeMessage::Reply(RuntimeReply::TransferPart(transfer.clone())),
        ),
    ));
    cases.push(fixture_case(
        "streamTransferPart",
        "runtimeEnvelope",
        &envelope_with_id(
            "message-transfer-stream-1",
            RuntimeMessage::Stream(RuntimeStreamItem::TransferPart(transfer.clone())),
        ),
    ));
    cases.push(fixture_case(
        "streamPairingPending",
        "runtimeEnvelope",
        &envelope_with_id(
            "message-pairing-pending-stream-1",
            RuntimeMessage::Stream(RuntimeStreamItem::PairingPending(runtime::PendingPairing {
                pairing_id: PairingId::new("pairing-pending-stream-1"),
                request_hash: [0xb1; 32],
                device_sign_fingerprint: [0xb2; 32],
                requested_at_ms: 1_700_000_000_000,
                expires_at_ms: 1_700_000_300_000,
            })),
        ),
    ));
    let compact = RuntimeTransferCarrierV1::new(
        MessageId::new("message-transfer-compact-1"),
        RuntimeTransferChannel::Stream,
        transfer,
    )
    .encode()
    .expect("fixture compact transfer carrier must encode");
    cases.push(serde_json::json!({
        "case": "compactTransferCarrier",
        "wireType": "runtimeTransferCarrierV1",
        "value": hex(&compact),
    }));

    let mut output = cases
        .into_iter()
        .map(|value| serde_json::to_string(&value).expect("fixture case must serialize"))
        .collect::<Vec<_>>()
        .join("\n");
    output.push('\n');
    output
}

#[test]
fn runtime_v4_wire_fixture_is_rust_produced_and_in_sync() {
    let expected = render_runtime_wire_fixture();
    let path = runtime_fixture_path();
    if std::env::var("UPDATE_WIRE_FIXTURES").as_deref() == Ok("1") {
        fs::create_dir_all(path.parent().expect("runtime fixture has parent directory"))
            .expect("create runtime fixture directory");
        fs::write(&path, expected.as_bytes()).expect("write runtime v3 wire fixture");
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
    for line in expected.lines() {
        let case: serde_json::Value = serde_json::from_str(line).unwrap();
        if case["wireType"] == "runtimeEnvelope" {
            serde_json::from_value::<RuntimeEnvelope>(case["value"].clone())
                .unwrap_or_else(|error| panic!("fixture {} failed decode: {error}", case["case"]));
        }
    }
}

#[test]
fn runtime_protocol_version_is_four_and_independent() {
    assert_eq!(RUNTIME_PROTOCOL_VERSION, 4);
    // 与 local IPC PROTOCOL_VERSION=2 彼此独立、不联动。
    assert_eq!(agentdeck_protocol::PROTOCOL_VERSION, 2);
}

#[test]
fn runtime_v4_is_a_hard_cutover_for_root_signed_tbs() {
    let invite = sample_pair_invite("hard-cutover");
    let current = invite.data_sign_cert.to_be_signed_v1(
        invite.relay_server_id,
        MachineRouteId::from_bytes([0xc1; 16]),
        invite.machine_root_fingerprint,
    );
    assert_eq!(current.runtime_protocol_version, 4);
    let mut legacy_v3 = current.clone();
    legacy_v3.runtime_protocol_version = 3;
    assert_ne!(
        current.encode(),
        legacy_v3.encode(),
        "v3-signed cert/grant material must not verify in the Runtime v4 trust domain"
    );
}

#[test]
fn runtime_v4_pairing_wire_is_strict_and_redacted() {
    fn schema_has_property(value: &serde_json::Value, property: &str) -> bool {
        match value {
            serde_json::Value::Array(values) => values
                .iter()
                .any(|value| schema_has_property(value, property)),
            serde_json::Value::Object(object) => {
                object
                    .get("properties")
                    .and_then(serde_json::Value::as_object)
                    .is_some_and(|properties| properties.contains_key(property))
                    || object
                        .values()
                        .any(|value| schema_has_property(value, property))
            }
            _ => false,
        }
    }

    let create = RuntimeRequest::CreatePairInvite(runtime::CreatePairInviteRequest {
        display_name: "Fixture Mac".to_owned(),
        idempotency_key: IdempotencyKey::new("pair-create-1"),
        scope: LocalOnlyAdministration::LocalOnly,
    });
    let create_json = serde_json::to_value(&create).unwrap();
    assert_eq!(create_json["idempotencyKey"], "pair-create-1");
    assert!(create_json.get("ttlSecs").is_none());
    let mut caller_ttl = create_json;
    caller_ttl["ttlSecs"] = serde_json::json!(300);
    assert!(serde_json::from_value::<RuntimeRequest>(caller_ttl).is_err());
    for invalid_name in [
        "".to_owned(),
        " leading".to_owned(),
        "trailing ".to_owned(),
        "bad\nname".to_owned(),
        "x".repeat(129),
    ] {
        let invalid = serde_json::json!({
            "request": "createPairInvite",
            "displayName": invalid_name,
            "idempotencyKey": "pair-create-invalid",
            "scope": "localOnly",
        });
        assert!(serde_json::from_value::<RuntimeRequest>(invalid).is_err());
    }

    let create_schema = serde_json::to_value(schemars::schema_for!(
        runtime::command::CreatePairInviteRequest
    ))
    .unwrap();
    assert!(schema_has_property(&create_schema, "displayName"));
    assert!(schema_has_property(&create_schema, "idempotencyKey"));
    assert!(!schema_has_property(&create_schema, "display_name"));
    assert!(!schema_has_property(&create_schema, "idempotency_key"));
    assert_eq!(create_schema["additionalProperties"], false);

    let receipt_schema = serde_json::to_value(schemars::schema_for!(PairingReceipt)).unwrap();
    assert!(schema_has_property(&receipt_schema, "pairingId"));
    assert!(!schema_has_property(&receipt_schema, "pairing_id"));

    let reply = RuntimeReply::PairInvite(runtime::PairInvite {
        pairing_id: PairingId::new("pairing-redacted-1"),
        invite: Box::new(sample_pair_invite("Secret Fixture Mac")),
    });
    let debug = format!("{reply:?}");
    assert!(debug.contains("<redacted>"));
    assert!(!debug.contains("Secret Fixture Mac"));
    assert!(!debug.contains("relay.example.test"));

    let pending = RuntimeStreamItem::PairingPending(runtime::PendingPairing {
        pairing_id: PairingId::new("pairing-pending-strict-1"),
        request_hash: [0xd1; 32],
        device_sign_fingerprint: [0xd2; 32],
        requested_at_ms: 10,
        expires_at_ms: 20,
    });
    let pending_json = serde_json::to_value(&pending).unwrap();
    let back: RuntimeStreamItem = serde_json::from_value(pending_json.clone()).unwrap();
    assert_eq!(serde_json::to_value(back).unwrap(), pending_json);
    let mut short_hash = pending_json;
    short_hash["requestHash"] = serde_json::json!("AA==");
    assert!(serde_json::from_value::<RuntimeStreamItem>(short_hash).is_err());

    for state in [
        PairingState::RouteOpening,
        PairingState::Unused,
        PairingState::Preparing,
        PairingState::AwaitingLocalConfirmation,
        PairingState::GrantPreparing,
        PairingState::GrantCommitted,
        PairingState::OrphanRevoking,
        PairingState::Delivered,
        PairingState::Expired,
        PairingState::Canceled,
        PairingState::ClosedTombstone,
    ] {
        let receipt = RuntimeReply::Pairing(PairingReceipt::Replayed {
            pairing_id: PairingId::new("pairing-state-1"),
            decision: PairingDecision::Confirm,
            state,
        });
        let wire = serde_json::to_value(&receipt).unwrap();
        serde_json::from_value::<RuntimeReply>(wire).unwrap();
    }
}

#[test]
fn trust_reset_keeps_root_present_wire_and_strictly_types_root_lost_receipt() {
    let root_present = RuntimeRequest::TrustReset(
        TrustResetRequest::new(LocalOnlyAdministration::LocalOnly, None).unwrap(),
    );
    let root_present_json = serde_json::to_value(root_present).unwrap();
    assert_eq!(
        root_present_json,
        serde_json::json!({"request":"trustReset","scope":"localOnly"})
    );

    let root_lost = RuntimeRequest::TrustReset(
        TrustResetRequest::new(
            LocalOnlyAdministration::LocalOnly,
            Some(Box::new(sample_admin_purge_receipt())),
        )
        .unwrap(),
    );
    let root_lost_json = serde_json::to_value(root_lost).unwrap();
    assert!(root_lost_json["adminPurgeReceipt"].is_object());
    let decoded: RuntimeRequest = serde_json::from_value(root_lost_json.clone()).unwrap();
    assert_eq!(serde_json::to_value(decoded).unwrap(), root_lost_json);

    let mut unknown = root_lost_json.clone();
    unknown["adminPurgeReceipt"]["opaqueProof"] = serde_json::json!("forbidden");
    assert!(serde_json::from_value::<RuntimeRequest>(unknown).is_err());

    let mut bad_shape = root_lost_json.clone();
    bad_shape["adminPurgeReceipt"]["readback"]["retiredTombstones"] = serde_json::json!(2);
    assert!(serde_json::from_value::<RuntimeRequest>(bad_shape).is_err());

    let mut bad_base64 = root_lost_json;
    bad_base64["adminPurgeReceipt"]["signature"] = serde_json::json!("AA==");
    assert!(serde_json::from_value::<RuntimeRequest>(bad_base64).is_err());

    let uninstall = RuntimeRequest::TrustReset(
        TrustResetRequest::for_uninstall_purge(
            LocalOnlyAdministration::LocalOnly,
            sample_uninstall_purge_plan(),
            None,
        )
        .unwrap(),
    );
    let uninstall_json = serde_json::to_value(uninstall).unwrap();
    assert_eq!(uninstall_json["uninstallPurge"], true);
    assert!(uninstall_json["uninstallPurgePlan"].is_object());
    let mut invalid_uninstall = uninstall_json;
    invalid_uninstall["uninstallPurge"] = serde_json::json!("true");
    assert!(serde_json::from_value::<RuntimeRequest>(invalid_uninstall).is_err());

    let mut missing_plan = serde_json::json!({
        "request": "trustReset",
        "scope": "localOnly",
        "uninstallPurge": true,
    });
    assert!(serde_json::from_value::<RuntimeRequest>(missing_plan.clone()).is_err());
    missing_plan["uninstallPurge"] = serde_json::json!(false);
    missing_plan["uninstallPurgePlan"] =
        serde_json::to_value(sample_uninstall_purge_plan()).unwrap();
    assert!(serde_json::from_value::<RuntimeRequest>(missing_plan).is_err());
}

#[test]
fn uninstall_purge_plan_id_is_deterministic_bound_and_strict() {
    let first = sample_uninstall_purge_plan();
    let second = sample_uninstall_purge_plan();
    assert_eq!(first.plan_id(), second.plan_id());
    assert_eq!(first.version(), 1);
    assert_eq!(
        first.helper_path(),
        PathBuf::from("/Applications/AgentDeck.app/Contents/Helpers/agentdeck-finalizer")
    );
    assert_eq!(first.helper_version(), "1.2.3");
    assert_eq!(first.helper_sha256().as_str(), "ab".repeat(32));
    assert_eq!(first.team_identifier(), "REALTEAM42");
    assert_eq!(
        first.keychain_access_group(),
        "REALTEAM42.com.agentdeck.agentdeckd.stable"
    );

    let changed = UninstallPurgePlanV1::new(
        first.helper_path().to_path_buf(),
        "1.2.4".to_owned(),
        first.helper_sha256().clone(),
        first.team_identifier().to_owned(),
        first.keychain_access_group().to_owned(),
    )
    .unwrap();
    assert_ne!(first.plan_id(), changed.plan_id());

    let wire = serde_json::to_value(&first).unwrap();
    let decoded: UninstallPurgePlanV1 = serde_json::from_value(wire.clone()).unwrap();
    assert_eq!(decoded, first);

    let mut mismatched_id = wire.clone();
    mismatched_id["planId"] = serde_json::json!("EREREREREREREREREREREQ==");
    assert!(serde_json::from_value::<UninstallPurgePlanV1>(mismatched_id).is_err());
    let mut unknown = wire;
    unknown["future"] = serde_json::json!(true);
    assert!(serde_json::from_value::<UninstallPurgePlanV1>(unknown).is_err());

    for path in ["relative/helper", "/tmp/../helper", "/tmp//helper", "/"] {
        assert!(
            UninstallPurgePlanV1::new(
                PathBuf::from(path),
                "1.2.3".to_owned(),
                ArtifactSha256::new("ab".repeat(32)).unwrap(),
                "REALTEAM42".to_owned(),
                "REALTEAM42.com.agentdeck.agentdeckd.stable".to_owned(),
            )
            .is_err(),
            "unsafe helper path accepted: {path}"
        );
    }
}

#[test]
fn envelope_round_trips_a_request() {
    let env = envelope(RuntimeMessage::Request(sample_send_prompt()));
    let json = serde_json::to_value(&env).unwrap();
    assert_eq!(json["version"], 4);
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
    assert_eq!(StreamCursor::BeforeFirst.next(), Ok(0));
    assert_eq!(StreamCursor::At(0).next(), Ok(1));
    assert_eq!(StreamCursor::At(41).next(), Ok(42));
}

#[test]
fn runtime_request_covers_all_brief_variants() {
    // brief Step 3 + P3.9-C0-A1: hello/describeAgents/catalog/subscribe/start/configure/
    // updateMetadata/sendPrompt/resolveApproval/retryApproval/cancelQueued/cancelActive/
    // queryReceipt/stageUpgrade/createPairInvite/listPendingPairings/confirmPairing/
    // cancelPairing/revoke/trust-reset/machine-enroll/machine-remote-status。
    let convo = ConversationId::new("c1");
    let variants = vec![
        RuntimeRequest::Hello(runtime::command::HelloParams {
            runtime_protocol_version: RUNTIME_PROTOCOL_VERSION,
        }),
        RuntimeRequest::DescribeAgents,
        RuntimeRequest::Catalog(runtime::command::CatalogRequest { page_cursor: None }),
        RuntimeRequest::Subscribe {
            inner_cursor: RuntimeInnerCursor::Conversation {
                conversation_id: convo.clone(),
                cursor: StreamCursor::BeforeFirst,
            },
        },
        RuntimeRequest::Unsubscribe {
            target: RuntimeSubscriptionTarget::Catalog,
        },
        RuntimeRequest::Backfill(BackfillRequest::Conversation {
            conversation_id: convo.clone(),
            after: StreamCursor::BeforeFirst,
        }),
        RuntimeRequest::Start(runtime::command::ConversationStart {
            agent_kind: AgentKind::Codex,
            idempotency_key: IdempotencyKey::new("start-1"),
            cwd: PathBuf::from("/tmp/runtime-contract"),
            title: None,
        }),
        RuntimeRequest::ConfigureConversation(ConfigureConversationRequest::new(
            convo.clone(),
            IdempotencyKey::new("configure-1"),
            0,
            sample_codex_configuration(),
        )),
        RuntimeRequest::UpdateConversationMetadata(
            ConversationMetadataMutationRequest::new(
                convo.clone(),
                IdempotencyKey::new("metadata-1"),
                0,
                ConversationMetadataMutation::SetArchived { archived: true },
            )
            .unwrap(),
        ),
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
        RuntimeRequest::StageUpgrade(
            StageUpgradeRequest::new(
                "0.3.0".into(),
                ArtifactSha256::new("ab".repeat(32)).unwrap(),
                IdempotencyKey::new("upgrade-1"),
                LocalOnlyAdministration::LocalOnly,
            )
            .unwrap(),
        ),
        RuntimeRequest::CreatePairInvite(runtime::command::CreatePairInviteRequest {
            display_name: "MacBook".into(),
            idempotency_key: IdempotencyKey::new("pair-invite-1"),
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
        RuntimeRequest::TrustReset(
            TrustResetRequest::new(LocalOnlyAdministration::LocalOnly, None).unwrap(),
        ),
        RuntimeRequest::TrustReset(
            TrustResetRequest::new(
                LocalOnlyAdministration::LocalOnly,
                Some(Box::new(sample_admin_purge_receipt())),
            )
            .unwrap(),
        ),
        RuntimeRequest::TrustReset(
            TrustResetRequest::for_uninstall_purge(
                LocalOnlyAdministration::LocalOnly,
                sample_uninstall_purge_plan(),
                None,
            )
            .unwrap(),
        ),
        RuntimeRequest::MachineEnroll(MachineEnrollRequest {
            bundle: sample_enrollment_bundle(),
            scope: LocalOnlyAdministration::LocalOnly,
        }),
        RuntimeRequest::MachineRemoteStatus {
            scope: LocalOnlyAdministration::LocalOnly,
        },
    ];
    assert_eq!(variants.len(), 26);
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
    assert!(ensure_request_within_limit(MAX_RUNTIME_REQUEST_BYTES - 1).is_ok());
    assert!(ensure_request_within_limit(MAX_RUNTIME_REQUEST_BYTES).is_err());
    // a normal request encodes well under the cap
    let env = envelope(RuntimeMessage::Request(sample_send_prompt()));
    let len = env.check_encoded_size().unwrap();
    assert!(len < MAX_RUNTIME_REQUEST_BYTES);
}

#[test]
fn runtime_json_frame_must_be_strictly_smaller_than_one_mib() {
    fn pair_invite_envelope(display_name: String) -> RuntimeEnvelope {
        envelope(RuntimeMessage::Reply(RuntimeReply::PairInvite(
            runtime::PairInvite {
                pairing_id: PairingId::new("pairing-frame-boundary"),
                invite: Box::new(sample_pair_invite(display_name)),
            },
        )))
    }

    let empty = pair_invite_envelope(String::new());
    let fixed_bytes = serde_json::to_vec(&empty).unwrap().len();
    let exact = pair_invite_envelope("x".repeat(MAX_RUNTIME_JSON_FRAME_BYTES - fixed_bytes));
    assert_eq!(
        serde_json::to_vec(&exact).unwrap().len(),
        MAX_RUNTIME_JSON_FRAME_BYTES
    );
    assert_eq!(
        exact.to_json_bytes_checked().unwrap_err(),
        RuntimeSizeError::FrameTooLarge
    );
}

#[test]
fn command_receipt_has_accepted_replayed_failed() {
    let accepted = CommandReceipt::Accepted {
        command_id: CommandId::new("cmd1"),
        queue_position: 0,
        configuration_revision: 1,
    };
    let replayed = CommandReceipt::Replayed {
        command_id: CommandId::new("cmd1"),
        configuration_revision: 1,
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
            configuration_revision: 1,
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
fn conversation_start_receipt_returns_public_id_and_replay_state() {
    for replayed in [false, true] {
        let reply = RuntimeReply::ConversationStart(ConversationStartReceipt {
            conversation_id: ConversationId::new("conversation-started-1"),
            replayed,
        });
        let json = serde_json::to_value(&reply).unwrap();
        assert_eq!(json["reply"], "conversationStart");
        assert_eq!(json["conversationId"], "conversation-started-1");
        assert!(json.get("adapterStateKey").is_none());
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
        StreamCursor::At(0),
        unconfigured_state(),
        vec![
            SnapshotItem::capabilities(sample_caps()),
            SnapshotItem::Item {
                item_id: agentdeck_protocol::runtime::identity::ItemId::new("i1"),
                entity_id: EntityId::new("e1"),
                command_id: None,
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
        StreamCursor::At(0),
        unconfigured_state(),
        vec![SnapshotItem::Item {
            item_id: agentdeck_protocol::runtime::identity::ItemId::new("i1"),
            entity_id: EntityId::new("e1"),
            command_id: None,
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
        StreamCursor::At(0),
        unconfigured_state(),
        vec![
            SnapshotItem::Item {
                item_id: agentdeck_protocol::runtime::identity::ItemId::new("i1"),
                entity_id: EntityId::new("e1"),
                command_id: None,
                item: AgentItem::AssistantMessage {
                    text: "hi".into(),
                    meta: Default::default(),
                },
            },
            SnapshotItem::capabilities(sample_caps()),
        ],
    );
    assert!(matches!(
        not_first,
        Err(SnapshotError::CapabilitiesNotFirst)
    ));

    // duplicate capabilities
    let dup = ConversationSnapshot::new(
        convo,
        StreamCursor::At(0),
        unconfigured_state(),
        vec![
            SnapshotItem::capabilities(sample_caps()),
            SnapshotItem::capabilities(sample_caps()),
        ],
    );
    assert!(matches!(dup, Err(SnapshotError::DuplicateCapabilities)));
}

#[test]
fn snapshot_deserialize_rejects_capabilities_not_first() {
    // the barrier invariant (RC-16) must survive the wire, not only new().
    let bad = serde_json::json!({
        "conversationId": "c1",
        "baseEventCursor": { "at": 0 },
        "configurationState": {
            "configurationRevision": 0,
            "configuration": null
        },
        "items": [
            { "kind": "item", "itemId": "i1", "entityId": "e1", "commandId": null,
              "item": { "kind": "assistantMessage", "text": "hi", "meta": { "vendorExtensions": {} } } },
            { "kind": "capabilities", "commandId": null, "itemId": null, "entityId": null,
              "capabilities": {
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
fn snapshot_rejects_configuration_and_capabilities_agent_mismatch() {
    // 威胁场景：configuration 与 capabilities 指向不同 agent 时，client 会按
    // 一家的策略渲染、daemon 却按另一家执行；构造、ingress、egress 都必须拒绝。
    let state =
        ConversationConfigurationState::new(1, Some(sample_claude_code_configuration())).unwrap();
    let items = vec![SnapshotItem::capabilities(sample_caps())];
    assert!(
        ConversationSnapshot::new(
            "conversation-agent-mismatch".into(),
            StreamCursor::BeforeFirst,
            state.clone(),
            items.clone(),
        )
        .is_err()
    );
    let wire = serde_json::json!({
        "conversationId": "conversation-agent-mismatch",
        "baseEventCursor": "beforeFirst",
        "configurationState": serde_json::to_value(&state).unwrap(),
        "items": serde_json::to_value(&items).unwrap()
    });
    assert!(serde_json::from_value::<ConversationSnapshot>(wire).is_err());

    let mut mutated = ConversationSnapshot::new(
        "conversation-agent-mismatch".into(),
        StreamCursor::BeforeFirst,
        unconfigured_state(),
        items,
    )
    .unwrap();
    mutated.configuration_state = state;
    assert!(serde_json::to_value(mutated).is_err());
}

#[test]
fn local_only_admin_marker_serializes() {
    let v = serde_json::to_value(LocalOnlyAdministration::LocalOnly).unwrap();
    assert_eq!(v, serde_json::json!("localOnly"));
}

#[test]
fn machine_remote_status_freezes_all_lifecycles_and_minimal_fields() {
    let cases = [
        (MachineRemoteLifecycle::Unenrolled, "unenrolled"),
        (
            MachineRemoteLifecycle::EnrollmentPrepared,
            "enrollmentPrepared",
        ),
        (
            MachineRemoteLifecycle::EnrollmentResponseValidated,
            "enrollmentResponseValidated",
        ),
        (MachineRemoteLifecycle::Active, "active"),
        (MachineRemoteLifecycle::RetirePending, "retirePending"),
        (MachineRemoteLifecycle::RelayCommitted, "relayCommitted"),
        (
            MachineRemoteLifecycle::PurgeReadbackAbsent,
            "purgeReadbackAbsent",
        ),
        (MachineRemoteLifecycle::LocalDeleted, "localDeleted"),
        (MachineRemoteLifecycle::Blocked, "blocked"),
    ];
    for (lifecycle, expected) in cases {
        assert_eq!(serde_json::to_value(lifecycle).unwrap(), expected);
    }

    let status = MachineRemoteStatus::new(
        MachineRemoteLifecycle::Active,
        Some(RelayServerId::from_bytes([0x11; 16])),
        Some(MachineRouteId::from_bytes([0x22; 16])),
        Some(MachineRootFingerprint::from_bytes([0x33; 32])),
        Some(4),
        None,
    )
    .unwrap();
    let encoded = serde_json::to_value(&status).unwrap();
    assert_eq!(
        encoded
            .as_object()
            .unwrap()
            .keys()
            .cloned()
            .collect::<BTreeSet<_>>(),
        BTreeSet::from([
            "lifecycle".to_owned(),
            "machineRoute".to_owned(),
            "relayServerId".to_owned(),
            "rootFingerprint".to_owned(),
            "trustEpoch".to_owned(),
        ])
    );
    let decoded: MachineRemoteStatus = serde_json::from_value(encoded.clone()).unwrap();
    assert_eq!(serde_json::to_value(decoded).unwrap(), encoded);
}

#[test]
fn machine_remote_status_rejects_unknown_or_sensitive_fields() {
    let base = serde_json::json!({
        "lifecycle": "blocked",
        "failureCode": "daemon.remote.blocked"
    });
    serde_json::from_value::<MachineRemoteStatus>(base.clone()).expect("minimal blocked status");

    for forbidden in [
        "code",
        "origin",
        "spkiPins",
        "linkCert",
        "dataCert",
        "purgeProof",
        "retirementProof",
        "message",
        "detail",
    ] {
        let mut value = base.clone();
        value
            .as_object_mut()
            .unwrap()
            .insert(forbidden.to_owned(), serde_json::json!("forbidden"));
        assert!(
            serde_json::from_value::<MachineRemoteStatus>(value).is_err(),
            "status must reject sensitive or narrative field `{forbidden}`"
        );
    }

    for invalid in [
        serde_json::json!({ "lifecycle": "active" }),
        serde_json::json!({
            "lifecycle": "unenrolled",
            "relayServerId": "EREREREREREREREREREREQ=="
        }),
        serde_json::json!({
            "lifecycle": "active",
            "relayServerId": "EREREREREREREREREREREQ==",
            "machineRoute": "IiIiIiIiIiIiIiIiIiIiIg==",
            "rootFingerprint": "MzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzM=",
            "trustEpoch": 1,
            "failureCode": "daemon.remote.unexpected"
        }),
        serde_json::json!({ "lifecycle": "blocked" }),
        serde_json::json!({
            "lifecycle": "blocked",
            "relayServerId": "EREREREREREREREREREREQ==",
            "failureCode": "daemon.remote.blocked"
        }),
        serde_json::json!({
            "lifecycle": "blocked",
            "failureCode": "Not A Stable Code"
        }),
        serde_json::json!({
            "lifecycle": "active",
            "relayServerId": "AAAAAAAAAAAAAAAAAAAAAA==",
            "machineRoute": "IiIiIiIiIiIiIiIiIiIiIg==",
            "rootFingerprint": "MzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzM=",
            "trustEpoch": 1
        }),
    ] {
        assert!(serde_json::from_value::<MachineRemoteStatus>(invalid).is_err());
    }

    assert!(MachineRemoteFailureCode::new("").is_err());
    assert!(MachineRemoteFailureCode::new("Daemon.Remote.Blocked").is_err());
    assert!(MachineRemoteFailureCode::new("a".repeat(129)).is_err());
    assert_eq!(
        MachineRemoteFailureCode::new("daemon.remote.blocked")
            .unwrap()
            .as_str(),
        "daemon.remote.blocked"
    );
}

#[test]
fn stream_cursor_checked_next_rejects_u64_max() {
    assert_eq!(StreamCursor::BeforeFirst.checked_next().unwrap(), 0);
    assert_eq!(StreamCursor::At(41).checked_next().unwrap(), 42);
    assert!(StreamCursor::At(u64::MAX).checked_next().is_err());
}

#[test]
fn sync_complete_tags_catalog_and_conversation_inner_cursor() {
    let catalog = RuntimeSyncComplete {
        stream_generation: StreamGeneration::new("generation-catalog"),
        stream_cursor: StreamCursor::BeforeFirst,
        inner_cursor: RuntimeInnerCursor::Catalog {
            cursor: StreamCursor::BeforeFirst,
        },
        key_directory_revision: 3,
    };
    let conversation = RuntimeSyncComplete {
        stream_generation: StreamGeneration::new("generation-conversation"),
        stream_cursor: StreamCursor::At(8),
        inner_cursor: RuntimeInnerCursor::Conversation {
            conversation_id: ConversationId::new("conversation-sync"),
            cursor: StreamCursor::At(6),
        },
        key_directory_revision: 4,
    };
    for value in [catalog, conversation] {
        let json = serde_json::to_value(&value).unwrap();
        assert!(json.get("eventSeq").is_none());
        let decoded: RuntimeSyncComplete = serde_json::from_value(json.clone()).unwrap();
        assert_eq!(serde_json::to_value(decoded).unwrap(), json);
    }

    let mixed = serde_json::json!({
        "streamGeneration": "generation-mixed",
        "streamCursor": "beforeFirst",
        "innerCursor": {
            "scope": "catalog",
            "cursor": "beforeFirst",
            "conversationId": "must-not-be-accepted"
        },
        "keyDirectoryRevision": 0
    });
    assert!(serde_json::from_value::<RuntimeSyncComplete>(mixed).is_err());
}

#[test]
fn unsubscribe_targets_catalog_or_conversation_and_has_typed_receipt() {
    let requests = [
        RuntimeRequest::Unsubscribe {
            target: RuntimeSubscriptionTarget::Catalog,
        },
        RuntimeRequest::Unsubscribe {
            target: RuntimeSubscriptionTarget::Conversation {
                conversation_id: ConversationId::new("conversation-unsubscribe"),
            },
        },
    ];
    for request in requests {
        let json = serde_json::to_value(&request).unwrap();
        serde_json::from_value::<RuntimeRequest>(json).unwrap();
    }

    let receipts = [
        SubscriptionReceipt::Subscribed {
            stream_generation: StreamGeneration::new("generation-subscribed"),
        },
        SubscriptionReceipt::Unsubscribed,
    ];
    for receipt in receipts {
        let reply = RuntimeReply::Subscription(receipt);
        let json = serde_json::to_value(&reply).unwrap();
        serde_json::from_value::<RuntimeReply>(json).unwrap();
    }
}

#[test]
fn empty_snapshots_use_before_first_without_fabricating_zero() {
    let snapshot = ConversationSnapshot::new(
        ConversationId::new("conversation-empty"),
        StreamCursor::BeforeFirst,
        unconfigured_state(),
        vec![SnapshotItem::capabilities(sample_caps())],
    )
    .unwrap();
    let json = serde_json::to_value(&snapshot).unwrap();
    assert_eq!(json["baseEventCursor"], serde_json::json!("beforeFirst"));
    assert!(json.get("baseEventSeq").is_none());

    let catalog =
        runtime::catalog::CatalogSnapshot::new(StreamCursor::BeforeFirst, Vec::new(), None)
            .unwrap();
    let json = serde_json::to_value(&catalog).unwrap();
    assert_eq!(json["baseCatalogCursor"], serde_json::json!("beforeFirst"));
    assert!(json["nextPageCursor"].is_null());
}

#[test]
fn snapshot_item_identity_matrix_is_explicit_and_strict() {
    let capabilities = SnapshotItem::capabilities(sample_caps());
    let capabilities_json = serde_json::to_value(capabilities).unwrap();
    for field in ["commandId", "itemId", "entityId"] {
        assert_eq!(
            capabilities_json.get(field),
            Some(&serde_json::Value::Null),
            "{field} must be present as explicit null"
        );
    }

    for field in ["commandId", "itemId", "entityId"] {
        let mut missing = capabilities_json.clone();
        missing.as_object_mut().unwrap().remove(field);
        assert!(serde_json::from_value::<SnapshotItem>(missing).is_err());
    }

    let mut wrong_capabilities = capabilities_json.clone();
    wrong_capabilities["commandId"] = serde_json::json!("must-be-null");
    assert!(serde_json::from_value::<SnapshotItem>(wrong_capabilities).is_err());

    let user_message = serde_json::json!({
        "kind": "item",
        "commandId": null,
        "itemId": "item-user-message",
        "entityId": "entity-user-message",
        "item": {
            "kind": "userMessage",
            "text": "hello",
            "meta": { "vendorExtensions": {} }
        }
    });
    assert!(serde_json::from_value::<SnapshotItem>(user_message).is_err());
}

#[test]
fn catalog_snapshot_requires_frozen_page_cursor_and_explicit_null() {
    let page = runtime::catalog::CatalogSnapshot::new(
        StreamCursor::At(9),
        Vec::new(),
        Some(CatalogPageCursor::new("frozen-page-2")),
    )
    .unwrap();
    let mut json = serde_json::to_value(&page).unwrap();
    assert_eq!(json["nextPageCursor"], "frozen-page-2");
    json.as_object_mut().unwrap().remove("nextPageCursor");
    assert!(serde_json::from_value::<runtime::catalog::CatalogSnapshot>(json).is_err());

    let request = RuntimeRequest::Catalog(runtime::command::CatalogRequest { page_cursor: None });
    let mut json = serde_json::to_value(request).unwrap();
    assert!(json["pageCursor"].is_null());
    json.as_object_mut().unwrap().remove("pageCursor");
    assert!(serde_json::from_value::<RuntimeRequest>(json).is_err());
}

#[test]
fn backfill_range_is_nonempty_contiguous_and_scoped() {
    let range = BackfillRange::new(StreamCursor::BeforeFirst, StreamCursor::At(0)).unwrap();
    let event = RuntimeEvent::new(
        ConversationId::new("conversation-backfill"),
        EventId::new("event-backfill-0"),
        0,
        Some(CommandId::new("command-backfill")),
        Some(ItemId::new("item-backfill")),
        Some(EntityId::new("entity-backfill")),
        RuntimeEventBody::Item {
            item: AgentItem::UserMessage {
                text: "hello".into(),
                meta: Default::default(),
            },
        },
    )
    .unwrap();
    let chunk = BackfillChunk::conversation(
        ConversationId::new("conversation-backfill"),
        sample_caps(),
        range,
        vec![event],
    )
    .unwrap();
    let json = serde_json::to_value(&chunk).unwrap();
    assert_eq!(json["scope"], "conversation");
    serde_json::from_value::<BackfillChunk>(json).unwrap();

    assert!(BackfillRange::new(StreamCursor::At(0), StreamCursor::At(0)).is_err());
    assert!(BackfillRange::new(StreamCursor::BeforeFirst, StreamCursor::BeforeFirst).is_err());

    let request = RuntimeRequest::Backfill(BackfillRequest::Catalog {
        after: StreamCursor::BeforeFirst,
    });
    serde_json::from_value::<RuntimeRequest>(serde_json::to_value(request).unwrap()).unwrap();
}

#[test]
fn backfill_direct_variants_cannot_bypass_egress_validation() {
    let one = BackfillRange::new(StreamCursor::BeforeFirst, StreamCursor::At(0)).unwrap();
    let empty = BackfillChunk::Catalog {
        range: one,
        deltas: Vec::new(),
    };
    assert!(serde_json::to_vec(&empty).is_err());

    let two = BackfillRange::new(StreamCursor::BeforeFirst, StreamCursor::At(1)).unwrap();
    let discontinuous = BackfillChunk::Catalog {
        range: two,
        deltas: vec![
            runtime::CatalogDelta {
                catalog_revision: 0,
                changes: Vec::new(),
            },
            runtime::CatalogDelta {
                catalog_revision: 2,
                changes: Vec::new(),
            },
        ],
    };
    assert!(serde_json::to_vec(&discontinuous).is_err());
}

#[test]
fn runtime_event_identity_matrix_is_strict() {
    let valid = RuntimeEvent::new(
        ConversationId::new("conversation-identity"),
        EventId::new("event-user-message"),
        0,
        Some(CommandId::new("command-user-message")),
        Some(ItemId::new("item-user-message")),
        Some(EntityId::new("entity-user-message")),
        RuntimeEventBody::Item {
            item: AgentItem::UserMessage {
                text: "hello".into(),
                meta: Default::default(),
            },
        },
    )
    .unwrap();
    let mut json = serde_json::to_value(valid).unwrap();
    assert!(json.get("commandId").is_some());
    assert!(json.get("itemId").is_some());
    assert!(json.get("entityId").is_some());

    for field in ["commandId", "itemId", "entityId"] {
        let mut missing = json.clone();
        missing.as_object_mut().unwrap().remove(field);
        assert!(serde_json::from_value::<RuntimeEvent>(missing).is_err());
    }

    json["commandId"] = serde_json::Value::Null;
    assert!(serde_json::from_value::<RuntimeEvent>(json).is_err());

    assert!(
        RuntimeEvent::new(
            ConversationId::new("conversation-capabilities"),
            EventId::new("event-capabilities"),
            0,
            Some(CommandId::new("must-be-null")),
            None,
            None,
            RuntimeEventBody::Capabilities {
                capabilities: sample_caps(),
            },
        )
        .is_err()
    );
}

#[test]
fn required_null_schema_properties_accept_null_and_remain_required() {
    fn allows_null(schema: &serde_json::Value) -> bool {
        match schema.get("type") {
            Some(serde_json::Value::String(value)) if value == "null" => return true,
            Some(serde_json::Value::Array(values))
                if values.iter().any(|value| value == "null") =>
            {
                return true;
            }
            _ => {}
        }
        ["anyOf", "oneOf"].into_iter().any(|key| {
            schema
                .get(key)
                .and_then(serde_json::Value::as_array)
                .is_some_and(|variants| variants.iter().any(allows_null))
        })
    }

    fn assert_required_nullable(schema: &serde_json::Value, property: &str) {
        assert!(
            schema["required"]
                .as_array()
                .unwrap()
                .iter()
                .any(|value| value == property),
            "{property} must remain required"
        );
        assert!(
            allows_null(&schema["properties"][property]),
            "{property} must accept explicit null: {}",
            schema["properties"][property]
        );
    }

    fn tagged_variant<'a>(
        schema: &'a serde_json::Value,
        tag_field: &str,
        tag: &str,
    ) -> &'a serde_json::Value {
        schema["oneOf"]
            .as_array()
            .unwrap()
            .iter()
            .find(|variant| {
                variant["properties"][tag_field]["enum"]
                    .as_array()
                    .is_some_and(|values| values.iter().any(|value| value == tag))
            })
            .unwrap()
    }

    let event = serde_json::to_value(schemars::schema_for!(RuntimeEvent)).unwrap();
    for property in ["commandId", "itemId", "entityId"] {
        assert_required_nullable(&event, property);
    }

    let snapshot = serde_json::to_value(schemars::schema_for!(SnapshotItem)).unwrap();
    assert_required_nullable(tagged_variant(&snapshot, "kind", "item"), "commandId");

    let catalog = serde_json::to_value(schemars::schema_for!(runtime::CatalogSnapshot)).unwrap();
    assert_required_nullable(&catalog, "nextPageCursor");

    let request =
        serde_json::to_value(schemars::schema_for!(runtime::command::CatalogRequest)).unwrap();
    assert_required_nullable(&request, "pageCursor");

    let body = serde_json::to_value(schemars::schema_for!(RuntimeEventBody)).unwrap();
    assert_required_nullable(
        tagged_variant(&body, "kind", "approvalResolved"),
        "decision",
    );
}

#[test]
fn runtime_reply_and_stream_carry_transfer_parts() {
    let part = b"carrier".to_vec();
    let transfer = TransferEnvelope::new(
        TransferId::new("transfer-carried"),
        0,
        1,
        Sha256::digest(&part).into(),
        part.len() as u64,
        part,
    )
    .unwrap();
    let reply = RuntimeReply::TransferPart(transfer.clone());
    let stream = RuntimeStreamItem::TransferPart(transfer);
    serde_json::from_value::<RuntimeReply>(serde_json::to_value(reply).unwrap()).unwrap();
    serde_json::from_value::<RuntimeStreamItem>(serde_json::to_value(stream).unwrap()).unwrap();
}

#[test]
fn runtime_envelope_rejects_wrong_version_on_ingress_and_egress() {
    let valid = envelope(RuntimeMessage::Request(RuntimeRequest::Hello(
        runtime::command::HelloParams {
            runtime_protocol_version: RUNTIME_PROTOCOL_VERSION,
        },
    )));
    let mut wire = serde_json::to_value(&valid).unwrap();
    wire["version"] = serde_json::json!(3);
    assert!(serde_json::from_value::<RuntimeEnvelope>(wire).is_err());

    let invalid = RuntimeEnvelope {
        version: 3,
        message_id: MessageId::new("message-wrong-version"),
        body: valid.body,
    };
    assert!(serde_json::to_vec(&invalid).is_err());
}

#[test]
fn message_and_transfer_ids_have_a_real_1024_byte_wire_cap() {
    assert_eq!(MAX_MESSAGE_ID_BYTES, 1024);
    assert_eq!(MAX_TRANSFER_ID_BYTES, 1024);

    let max_message = MessageId::new("m".repeat(MAX_MESSAGE_ID_BYTES));
    let max_transfer = TransferId::new("t".repeat(MAX_TRANSFER_ID_BYTES));
    assert!(serde_json::to_vec(&max_message).is_ok());
    assert!(serde_json::to_vec(&max_transfer).is_ok());
    assert!(serde_json::to_vec(&MessageId::new("中".repeat(341))).is_ok());
    assert!(serde_json::to_vec(&TransferId::new("中".repeat(341))).is_ok());

    let oversized_message = MessageId::new("m".repeat(MAX_MESSAGE_ID_BYTES + 1));
    let oversized_transfer = TransferId::new("t".repeat(MAX_TRANSFER_ID_BYTES + 1));
    assert!(serde_json::to_vec(&oversized_message).is_err());
    assert!(serde_json::to_vec(&oversized_transfer).is_err());
    assert!(serde_json::to_vec(&MessageId::new("")).is_err());
    assert!(serde_json::to_vec(&TransferId::new("")).is_err());
    assert!(serde_json::to_vec(&MessageId::new("中".repeat(342))).is_err());
    assert!(serde_json::to_vec(&TransferId::new("中".repeat(342))).is_err());
    assert!(
        serde_json::from_value::<MessageId>(serde_json::json!(
            "m".repeat(MAX_MESSAGE_ID_BYTES + 1)
        ))
        .is_err()
    );
    assert!(
        serde_json::from_value::<TransferId>(serde_json::json!(
            "t".repeat(MAX_TRANSFER_ID_BYTES + 1)
        ))
        .is_err()
    );

    assert!(TransferEnvelope::new(oversized_transfer, 0, 1, [0; 32], 1, vec![0]).is_err());

    let bytes = vec![0x42];
    let transfer = TransferEnvelope::new(
        TransferId::new("transfer-compact-id-cap"),
        0,
        1,
        Sha256::digest(&bytes).into(),
        1,
        bytes,
    )
    .unwrap();
    let carrier =
        RuntimeTransferCarrierV1::new(oversized_message, RuntimeTransferChannel::Reply, transfer);
    assert!(carrier.encode().is_err());
}

#[test]
fn runtime_json_limit_rejects_oversized_transfer_reply_and_stream() {
    let part = vec![0xA5; MAX_JSON_PART_BYTES + 1];
    let transfer = TransferEnvelope::new(
        TransferId::new("transfer-over-json-limit"),
        0,
        1,
        Sha256::digest(&part).into(),
        part.len() as u64,
        part,
    )
    .unwrap();

    let reply = envelope(RuntimeMessage::Reply(RuntimeReply::TransferPart(
        transfer.clone(),
    )));
    assert!(matches!(
        reply.check_encoded_size(),
        Err(RuntimeSizeError::Encode(_))
    ));

    let stream = envelope(RuntimeMessage::Stream(RuntimeStreamItem::TransferPart(
        transfer,
    )));
    assert!(matches!(
        stream.check_encoded_size(),
        Err(RuntimeSizeError::Encode(_))
    ));
}

#[test]
fn compact_transfer_carrier_rejects_wrong_channel_and_trailing_bytes() {
    let part = vec![0x5A; runtime::MAX_PART_BYTES];
    let transfer = TransferEnvelope::new(
        TransferId::new("transfer-compact-max"),
        0,
        1,
        Sha256::digest(&part).into(),
        part.len() as u64,
        part,
    )
    .unwrap();
    let carrier = RuntimeTransferCarrierV1::new(
        MessageId::new("message-compact"),
        RuntimeTransferChannel::Reply,
        transfer,
    );
    let encoded = carrier.encode().unwrap();
    assert!(encoded.len() < 4 * 1024 * 1024);
    let decoded = RuntimeTransferCarrierV1::decode(&encoded).unwrap();
    assert_eq!(decoded.channel, RuntimeTransferChannel::Reply);

    let mut trailing = encoded.clone();
    trailing.push(0);
    assert!(RuntimeTransferCarrierV1::decode(&trailing).is_err());

    let mut wrong_channel = encoded;
    wrong_channel[7] = 0xFF;
    assert!(RuntimeTransferCarrierV1::decode(&wrong_channel).is_err());
}

#[test]
fn json_uds_transfer_part_has_separate_limit_and_fits_full_frame() {
    assert_eq!(MAX_JSON_PART_BYTES, 700 * 1024);
    assert_eq!(MAX_RUNTIME_JSON_FRAME_BYTES, 1024 * 1024);
    const { assert!(MAX_JSON_PART_BYTES < runtime::MAX_PART_BYTES) };
    let part = vec![0xA5; MAX_JSON_PART_BYTES];
    let transfer = TransferEnvelope::new_json(
        TransferId::new("t".repeat(1024)),
        MAX_JSON_TRANSFER_PARTS - 1,
        MAX_JSON_TRANSFER_PARTS,
        Sha256::digest(&part).into(),
        runtime::MAX_TRANSFER_BYTES,
        part,
    )
    .unwrap();
    let envelope = envelope_with_id(
        &"m".repeat(1024),
        RuntimeMessage::Stream(RuntimeStreamItem::TransferPart(transfer)),
    );
    let encoded = serde_json::to_vec(&envelope).unwrap();
    assert!(
        encoded.len() < MAX_RUNTIME_JSON_FRAME_BYTES,
        "worst-case JSON/UDS frame is {} bytes",
        encoded.len()
    );
    assert_eq!(envelope.check_encoded_size().unwrap(), encoded.len());

    let oversize_part = vec![0x5A; MAX_JSON_PART_BYTES + 1];
    let oversize = TransferEnvelope::new(
        TransferId::new("transfer-json-oversize"),
        0,
        2,
        Sha256::digest(&oversize_part).into(),
        oversize_part.len() as u64,
        oversize_part,
    )
    .unwrap();
    assert!(serde_json::to_vec(&oversize).is_err());
}

#[test]
fn json_transfer_total_must_be_representable_by_json_parts() {
    let part = vec![0x5A; 1];
    let transfer = TransferEnvelope::new(
        TransferId::new("transfer-json-impossible-total"),
        0,
        runtime::MAX_TRANSFER_PARTS,
        Sha256::digest(&part).into(),
        runtime::MAX_TRANSFER_BYTES,
        part,
    )
    .unwrap();

    assert!(serde_json::to_vec(&transfer).is_err());

    let remote = RuntimeTransferCarrierV1::new(
        MessageId::new("message-remote-representable"),
        RuntimeTransferChannel::Stream,
        transfer,
    );
    assert!(remote.encode().is_ok());
}

#[test]
fn json_transfer_uses_a_transport_specific_count_to_cover_64mib() {
    assert_eq!(MAX_JSON_TRANSFER_PARTS, 94);
    let transfer = TransferEnvelope::new_json(
        TransferId::new("transfer-json-full-ceiling"),
        0,
        MAX_JSON_TRANSFER_PARTS,
        [0x6A; 32],
        runtime::MAX_TRANSFER_BYTES,
        vec![0x5A],
    )
    .expect("full transfer total is representable over JSON/UDS");
    serde_json::to_vec(&transfer).expect("JSON serializer accepts the transport-specific count");

    let compact = RuntimeTransferCarrierV1::new(
        MessageId::new("message-compact-keeps-64"),
        RuntimeTransferChannel::Reply,
        transfer,
    );
    assert!(compact.encode().is_err());
}

#[test]
fn terminal_execution_failure_code_is_stable_and_distinct_from_actor_failure() {
    assert_eq!(
        failure::DAEMON_RUNTIME_EXECUTION_FAILED,
        "daemon.runtime.execution_failed"
    );
    assert_ne!(
        failure::DAEMON_RUNTIME_EXECUTION_FAILED,
        failure::DAEMON_RUNTIME_ACTOR_UNAVAILABLE
    );
    let value = RuntimeFailure::new(
        failure::DAEMON_RUNTIME_EXECUTION_FAILED,
        "agent execution failed",
    );
    let encoded = serde_json::to_vec(&value).expect("encode runtime failure");
    let decoded: RuntimeFailure = serde_json::from_slice(&encoded).expect("decode runtime failure");
    assert_eq!(decoded, value);
    assert_eq!(decoded.diagnostic_ref, None);
}
