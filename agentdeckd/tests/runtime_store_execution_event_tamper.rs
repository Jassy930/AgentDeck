#[path = "support/runtime_descriptor.rs"]
mod runtime_descriptor;
#[path = "support/runtime_event_tamper.rs"]
mod runtime_event_tamper;
#[path = "support/store_admission.rs"]
mod store_admission;

use agentdeck_protocol::runtime::identity::{CommandId, EntityId, ItemId, TurnId};
use agentdeck_protocol::runtime::{RuntimeEvent, RuntimeEventBody, RuntimeFailure};
use agentdeck_protocol::{AgentItem, AgentItemMeta};
use agentdeckd::runtime::store::{RuntimeIdKind, RuntimeStoreError};

use runtime_event_tamper::{
    RuntimeEventTamperFixture, RuntimeStartedReleaseTamperFixture, runtime_id,
};

fn exact_length_error_payload(event: &RuntimeEvent, target_len: usize, code: &str) -> Vec<u8> {
    let mut candidate = event.clone();
    candidate.item_id = None;
    candidate.entity_id = None;
    candidate.body = RuntimeEventBody::Error {
        failure: RuntimeFailure::new(code, ""),
    };
    let base = serde_json::to_vec(&candidate).expect("encode base Error corruption");
    let padding = target_len
        .checked_sub(base.len())
        .expect("source event is large enough for canonical Error corruption");
    candidate.body = RuntimeEventBody::Error {
        failure: RuntimeFailure::new(code, "x".repeat(padding)),
    };
    let payload = serde_json::to_vec(&candidate).expect("encode exact-length Error corruption");
    assert_eq!(payload.len(), target_len);
    payload
}

fn exact_length_raw_item_payload(event: &RuntimeEvent, target_len: usize) -> Vec<u8> {
    let mut candidate = event.clone();
    candidate.body = RuntimeEventBody::Item {
        item: AgentItem::Raw {
            raw_kind: "recordedVendorFrame".to_owned(),
            raw_payload: String::new(),
            meta: AgentItemMeta::default(),
        },
    };
    let base = serde_json::to_vec(&candidate).expect("encode base Raw corruption");
    let padding = target_len
        .checked_sub(base.len())
        .expect("source event is large enough for canonical Raw corruption");
    candidate.body = RuntimeEventBody::Item {
        item: AgentItem::Raw {
            raw_kind: "recordedVendorFrame".to_owned(),
            raw_payload: "x".repeat(padding),
            meta: AgentItemMeta::default(),
        },
    };
    let payload = serde_json::to_vec(&candidate).expect("encode exact-length Raw corruption");
    assert_eq!(payload.len(), target_len);
    payload
}

fn exact_length_empty_item_identity_payload(event: &RuntimeEvent, target_len: usize) -> Vec<u8> {
    let mut candidate = event.clone();
    candidate.item_id = Some(ItemId::new(""));
    candidate.entity_id = Some(EntityId::new(""));
    candidate.body = RuntimeEventBody::Item {
        item: AgentItem::AssistantMessage {
            text: String::new(),
            meta: AgentItemMeta::default(),
        },
    };
    let base = serde_json::to_vec(&candidate).expect("encode base empty-identity corruption");
    let padding = target_len
        .checked_sub(base.len())
        .expect("source event is large enough for empty-identity corruption");
    candidate.body = RuntimeEventBody::Item {
        item: AgentItem::AssistantMessage {
            text: "x".repeat(padding),
            meta: AgentItemMeta::default(),
        },
    };
    let payload =
        serde_json::to_vec(&candidate).expect("encode exact-length empty-identity corruption");
    assert_eq!(payload.len(), target_len);
    payload
}

async fn assert_reopen_rejected(fixture: &RuntimeEventTamperFixture, label: &str) {
    let error = fixture.reopen_error().await;
    assert!(
        matches!(
            error,
            RuntimeStoreError::UnknownOrCorruptSchema
                | RuntimeStoreError::Cipher(_)
                | RuntimeStoreError::CommandNotFound
        ),
        "{label} must fail as authenticated corruption, got {error:?}"
    );
}

#[tokio::test]
async fn ciphertext_flip_and_deleted_audit_row_fail_closed() {
    let flipped = RuntimeEventTamperFixture::create("ciphertext-flip", 0x21).await;
    flipped.flip_item_ciphertext();
    assert_reopen_rejected(&flipped, "sealed_event bit flip").await;
    drop(flipped);

    let deleted = RuntimeEventTamperFixture::create("deleted-row", 0x31).await;
    deleted.delete_item_but_leave_stream_orphan();
    assert_reopen_rejected(&deleted, "deleted audit row with orphan stream index").await;
}

#[tokio::test]
async fn authenticated_orphan_and_authenticated_seq_hwm_gap_fail_closed() {
    let orphan = RuntimeEventTamperFixture::create("authenticated-orphan", 0x41).await;
    orphan.make_authenticated_orphan(runtime_id(RuntimeIdKind::Command, 0xE1));
    assert_reopen_rejected(&orphan, "AEAD/MAC-valid orphan command binding").await;
    drop(orphan);

    let gap = RuntimeEventTamperFixture::create("authenticated-gap", 0x51).await;
    gap.make_authenticated_sequence_gap();
    assert_reopen_rejected(&gap, "AEAD/MAC-valid seq and HWM gap").await;
}

#[tokio::test]
async fn wrong_command_and_wrong_turn_fail_closed_after_valid_aead_reseal() {
    let wrong_command = RuntimeEventTamperFixture::create("wrong-command", 0x61).await;
    let mut item: RuntimeEvent =
        serde_json::from_slice(&wrong_command.item.payload).expect("decode Item event");
    item.command_id = Some(CommandId::new(
        runtime_id(RuntimeIdKind::Command, 0xE2).to_canonical_string(),
    ));
    let payload = serde_json::to_vec(&item).expect("encode wrong-command Item");
    wrong_command.reseal_same_length(&wrong_command.item, &payload);
    assert_reopen_rejected(&wrong_command, "ciphertext-valid wrong command body").await;
    drop(wrong_command);

    let wrong_turn = RuntimeEventTamperFixture::create("wrong-turn", 0x71).await;
    let mut started: RuntimeEvent =
        serde_json::from_slice(&wrong_turn.started.payload).expect("decode TurnStarted event");
    started.body = RuntimeEventBody::TurnStarted {
        turn_id: TurnId::new(runtime_id(RuntimeIdKind::Turn, 0xE3).to_canonical_string()),
    };
    let payload = serde_json::to_vec(&started).expect("encode wrong-turn pointer body");
    wrong_turn.reseal_same_length(&wrong_turn.started, &payload);
    assert_reopen_rejected(&wrong_turn, "ciphertext-valid wrong turn pointer").await;
}

#[tokio::test]
async fn forged_pointer_and_nonpointer_noncanonical_or_unsupported_body_fail_closed() {
    let forged_pointer = RuntimeEventTamperFixture::create("forged-pointer", 0x81).await;
    let terminal: RuntimeEvent = serde_json::from_slice(&forged_pointer.terminal.payload)
        .expect("decode terminal pointer event");
    let payload = exact_length_error_payload(
        &terminal,
        forged_pointer.terminal.payload.len(),
        "daemon.test.forged_pointer",
    );
    forged_pointer.reseal_same_length(&forged_pointer.terminal, &payload);
    assert_reopen_rejected(
        &forged_pointer,
        "terminal pointer with forged canonical body",
    )
    .await;
    drop(forged_pointer);

    let noncanonical = RuntimeEventTamperFixture::create("noncanonical-body", 0x91).await;
    let payload = vec![b'!'; noncanonical.item.payload.len()];
    noncanonical.reseal_same_length(&noncanonical.item, &payload);
    assert_reopen_rejected(&noncanonical, "non-pointer NonCanonical body").await;
    drop(noncanonical);

    let unsupported = RuntimeEventTamperFixture::create("unsupported-body", 0xA1).await;
    let item: RuntimeEvent =
        serde_json::from_slice(&unsupported.item.payload).expect("decode non-pointer Item");
    let payload = exact_length_error_payload(
        &item,
        unsupported.item.payload.len(),
        "daemon.test.unsupported_execution_error",
    );
    unsupported.reseal_same_length(&unsupported.item, &payload);
    assert_reopen_rejected(&unsupported, "non-pointer unsupported canonical Error").await;
}

#[tokio::test]
async fn authenticated_raw_item_and_empty_item_identity_fail_closed() {
    // 威胁场景：持有旧 row key 的进程或错误迁移可写出 AEAD/MAC 有效的 Raw item，
    // 或把 item/entity identity 置空；重启若只信任 canonical JSON，就会把私有 vendor
    // frame 或不可关联 item 放进 durable replay。
    let raw = RuntimeEventTamperFixture::create("raw-item", 0xB1).await;
    let raw_event: RuntimeEvent =
        serde_json::from_slice(&raw.item.payload).expect("decode Raw tamper source");
    let payload = exact_length_raw_item_payload(&raw_event, raw.item.payload.len());
    raw.reseal_same_length(&raw.item, &payload);
    assert_reopen_rejected(&raw, "authenticated Raw item").await;
    drop(raw);

    let empty = RuntimeEventTamperFixture::create("empty-item-identity", 0xC1).await;
    let empty_event: RuntimeEvent =
        serde_json::from_slice(&empty.item.payload).expect("decode empty identity source");
    let payload = exact_length_empty_item_identity_payload(&empty_event, empty.item.payload.len());
    empty.reseal_same_length(&empty.item, &payload);
    assert_reopen_rejected(&empty, "authenticated empty item/entity identity").await;
}

#[tokio::test]
async fn authenticated_release_before_started_fails_closed() {
    // 威胁场景：持有旧 row key 的旧进程或错误迁移可以为任意 release 时间重算有效
    // MAC；若 reopen 只验 token、不验 Started/terminal 区间，就会把未授权或终态后
    // 的 release 冒充成可执行边界。
    let before_started =
        RuntimeStartedReleaseTamperFixture::create("release-before-started", 0xD1).await;
    before_started.resign_release_time(
        before_started
            .started
            .created_at_ms
            .checked_sub(1)
            .expect("real started timestamp is nonzero"),
    );
    let error = before_started.reopen_error().await;
    assert!(
        matches!(error, RuntimeStoreError::UnknownOrCorruptSchema),
        "authenticated release before Started event must fail closed, got {error:?}"
    );
}

#[tokio::test]
async fn authenticated_release_after_terminal_fails_closed() {
    // 威胁场景：已进入终态后重签 release 时间会伪造一个从未存在的执行授权边界；
    // reopen 必须把它视为 authenticated corruption，而不是仅凭有效 MAC 接受。
    let after_terminal =
        RuntimeStartedReleaseTamperFixture::create("release-after-terminal", 0xE1).await;
    let terminal = after_terminal.complete_without_dynamic_item().await;
    after_terminal.resign_release_time(
        terminal
            .created_at_ms
            .checked_add(1)
            .expect("real terminal timestamp has headroom"),
    );
    let error = after_terminal.reopen_error().await;
    assert!(
        matches!(error, RuntimeStoreError::UnknownOrCorruptSchema),
        "authenticated release after terminal event must fail closed, got {error:?}"
    );
}
