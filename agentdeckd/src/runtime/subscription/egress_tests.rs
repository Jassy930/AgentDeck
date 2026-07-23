use std::collections::BTreeSet;
use std::sync::Arc;
use std::time::Duration;

use agentdeck_protocol::runtime::identity::{
    ConversationId, EntityId, ItemId, MessageId, TransferId,
};
use agentdeck_protocol::runtime::{
    CatalogSnapshot, ConversationEntry, ConversationSnapshot, MAX_JSON_PART_BYTES,
    MAX_JSON_TRANSFER_PARTS, MAX_PART_BYTES, MAX_RUNTIME_JSON_FRAME_BYTES, MAX_TRANSFER_BYTES,
    MAX_TRANSFER_PARTS, RuntimeEnvelope, RuntimeMessage, RuntimeReply, RuntimeTransferCarrierV1,
    RuntimeTransferChannel, SnapshotItem, StreamCursor,
};
use agentdeck_protocol::{
    AgentItem, AgentItemMeta, AgentKind, SessionCapabilities, VendorCapabilities,
};
use tokio::sync::mpsc;
use tokio::time::{Instant, timeout};

use super::*;
use crate::runtime::connection::{
    ConnectionRegistry, ConnectionWrite, DEFAULT_CONNECTION_WRITER_BYTES,
    DEFAULT_CONNECTION_WRITER_FRAMES, PrincipalIssuer,
};
use crate::runtime::{ConnectionFramingProfile, ConnectionSink, EncodedRuntimeFrameKind};

fn registry() -> ConnectionRegistry {
    ConnectionRegistry::new(
        DEFAULT_CONNECTION_WRITER_FRAMES,
        DEFAULT_CONNECTION_WRITER_BYTES,
    )
}

fn connect(
    connections: &ConnectionRegistry,
    seed: u8,
) -> (ConnectionId, mpsc::Receiver<ConnectionWrite>) {
    let principal = PrincipalIssuer::local_only([0xA5; 32])
        .issue_verified_local(501, [seed; 16])
        .expect("issue verified local principal");
    let (sender, receiver) = mpsc::channel(1);
    let connection_id = connections
        .connect(principal, ConnectionSink::new(sender))
        .expect("connect runtime writer");
    (connection_id, receiver)
}

fn connect_compact(
    connections: &ConnectionRegistry,
    seed: u8,
) -> (ConnectionId, mpsc::Receiver<ConnectionWrite>) {
    let principal = PrincipalIssuer::local_only([0xA5; 32])
        .issue_verified_local(501, [seed; 16])
        .expect("issue verified local principal");
    let (sender, receiver) = mpsc::channel(1);
    let connection_id = connections
        .connect(
            principal,
            ConnectionSink::new(sender)
                .with_framing_profile(ConnectionFramingProfile::CompactTransfer),
        )
        .expect("connect compact runtime writer");
    (connection_id, receiver)
}

fn capabilities() -> SessionCapabilities {
    SessionCapabilities {
        agent_kind: AgentKind::Codex,
        agent_version: "transfer-egress-test".to_owned(),
        features: BTreeSet::new(),
        vendor: VendorCapabilities::Codex(Default::default()),
    }
}

fn real_snapshot_payload(text_bytes: usize) -> Vec<u8> {
    let snapshot = ConversationSnapshot::new(
        ConversationId::new("conversation-transfer-egress"),
        StreamCursor::At(0),
        agentdeck_protocol::runtime::ConversationConfigurationState::new(0, None).unwrap(),
        vec![
            SnapshotItem::capabilities(capabilities()),
            SnapshotItem::Item {
                item_id: ItemId::new("snapshot-item"),
                entity_id: EntityId::new("snapshot-entity"),
                command_id: None,
                item: AgentItem::AssistantMessage {
                    text: "x".repeat(text_bytes),
                    meta: AgentItemMeta::default(),
                },
            },
        ],
    )
    .expect("valid real snapshot DTO");
    serde_json::to_vec(&snapshot).expect("encode real snapshot DTO")
}

#[test]
fn json_uds_part_budget_covers_the_full_transfer_ceiling() {
    assert_eq!(MAX_JSON_TRANSFER_PARTS, 94);
    assert_eq!(MAX_JSON_TRANSFER_PAYLOAD_BYTES, MAX_TRANSFER_BYTES as usize);
    assert_eq!(
        (MAX_TRANSFER_BYTES as usize).div_ceil(MAX_JSON_PART_BYTES),
        MAX_JSON_TRANSFER_PARTS as usize
    );
    assert_eq!(
        json_transfer_part_count(MAX_TRANSFER_BYTES as usize).unwrap(),
        MAX_JSON_TRANSFER_PARTS
    );
    assert!(json_transfer_part_count(MAX_TRANSFER_BYTES as usize + 1).is_err());
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn compact_profile_sends_oversized_catalog_reply_as_adrt1_reply_parts() {
    let connections = registry();
    let (connection_id, mut receiver) = connect_compact(&connections, 0x36);
    let snapshot = CatalogSnapshot::new(
        StreamCursor::BeforeFirst,
        vec![ConversationEntry {
            conversation_id: ConversationId::new("catalog-compact-reply"),
            agent_kind: AgentKind::Codex,
            title: Some("x".repeat(MAX_RUNTIME_JSON_FRAME_BYTES + 64 * 1024)),
            cwd: None,
            last_active_ms: 0,
            archived: false,
            entry_revision: 0,
        }],
        None,
    )
    .expect("construct oversized valid CatalogSnapshot");
    let payload: Arc<[u8]> = serde_json::to_vec(&snapshot)
        .expect("encode CatalogSnapshot transfer payload")
        .into();
    assert!(payload.len() > MAX_RUNTIME_JSON_FRAME_BYTES);

    // JSON/UDS 需要第 65 part 的区间必须由 compact profile 继续可表示；
    // 这里不再额外分配约 44.8 MiB，只冻结两个 part-count oracle。
    let first_json_gap = MAX_JSON_PART_BYTES * MAX_TRANSFER_PARTS as usize + 1;
    assert_eq!(json_transfer_part_count(first_json_gap).unwrap(), 65);
    assert!(compact_transfer_part_count(first_json_gap).unwrap() <= MAX_TRANSFER_PARTS);

    let control = TransferEgressControl::new(Instant::now() + Duration::from_secs(10));
    let send_connections = connections.clone();
    let send_payload = Arc::clone(&payload);
    let send_snapshot = snapshot.clone();
    let sender = tokio::spawn(async move {
        super::super::pump::send_one_shot_reply(
            &send_connections,
            connection_id,
            MessageId::new("catalog-compact-message"),
            RuntimeReply::Catalog(send_snapshot),
            Some(&send_payload),
            &control,
        )
        .await
    });

    let write = timeout(Duration::from_secs(5), receiver.recv())
        .await
        .expect("compact Catalog reply timed out")
        .expect("writer closed before compact Catalog reply");
    assert_eq!(write.kind(), EncodedRuntimeFrameKind::CompactTransfer);
    let carrier = RuntimeTransferCarrierV1::decode(write.bytes()).expect("decode ADRT1 reply");
    assert_eq!(carrier.message_id.as_str(), "catalog-compact-message");
    assert_eq!(carrier.channel, RuntimeTransferChannel::Reply);
    assert_eq!(carrier.transfer.part_count, 1);
    assert_eq!(carrier.transfer.part, payload.as_ref());
    write.acknowledge().expect("ACK compact Catalog reply");

    timeout(Duration::from_secs(5), sender)
        .await
        .expect("compact Catalog egress completion timed out")
        .expect("compact Catalog egress task panicked")
        .expect("compact Catalog egress failed");
    connections.shutdown().await.expect("shutdown registry");
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn remote_compact_profile_carries_the_full_sixty_four_mib_as_adrt1_stream_parts() {
    let connections = registry();
    let (connection_id, mut receiver) = connect_compact(&connections, 0x35);
    // 不能把本门禁缩成小 fixture：它必须证明 remote 3.5 MiB / 64-part profile
    // 对完整 64 MiB payload 可表示，并且不复用 JSON/UDS 的 700 KiB 分片。
    let payload: Arc<[u8]> = vec![0x5A; MAX_TRANSFER_BYTES as usize].into();
    let expected_parts = payload.len().div_ceil(MAX_PART_BYTES) as u32;
    assert!(expected_parts <= 64);
    let control = TransferEgressControl::new(Instant::now() + Duration::from_secs(60));
    let send_connections = connections.clone();
    let send_payload = payload.clone();
    let sender = tokio::spawn(async move {
        send_stream_transfer(
            &send_connections,
            connection_id,
            MessageId::new("compact-full-message"),
            TransferId::new("compact-full-transfer"),
            &send_payload,
            &control,
        )
        .await
    });

    let mut assembled = Vec::with_capacity(payload.len());
    for expected_index in 0..expected_parts {
        let write = timeout(Duration::from_secs(5), receiver.recv())
            .await
            .expect("compact part timed out")
            .expect("writer closed before complete compact transfer");
        assert_eq!(write.kind(), EncodedRuntimeFrameKind::CompactTransfer);
        let carrier = RuntimeTransferCarrierV1::decode(write.bytes()).expect("decode ADRT1");
        assert_eq!(carrier.channel, RuntimeTransferChannel::Stream);
        assert_eq!(carrier.transfer.part_index, expected_index);
        assert_eq!(carrier.transfer.part_count, expected_parts);
        assert!(carrier.transfer.part.len() <= MAX_PART_BYTES);
        assert_eq!(carrier.transfer.total_bytes, MAX_TRANSFER_BYTES);
        assembled.extend_from_slice(&carrier.transfer.part);

        tokio::task::yield_now().await;
        assert!(receiver.try_recv().is_err(), "next part preceded flush ACK");
        write.acknowledge().expect("ACK compact part");
    }

    let report = timeout(Duration::from_secs(10), sender)
        .await
        .expect("compact egress completion timed out")
        .expect("compact egress task panicked")
        .expect("compact egress failed");
    assert_eq!(report.part_count, expected_parts);
    assert_eq!(report.total_bytes, MAX_TRANSFER_BYTES);
    assert_eq!(assembled.as_slice(), payload.as_ref());
    connections.shutdown().await.expect("shutdown registry");
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn production_egress_sends_the_sixty_fifth_json_part() {
    let connections = registry();
    let (connection_id, mut receiver) = connect(&connections, 0x34);
    let payload = Arc::new(real_snapshot_payload(MAX_JSON_PART_BYTES * 64 + 1));
    let expected_parts = json_transfer_part_count(payload.len()).unwrap();
    assert_eq!(expected_parts, 65);
    let control = TransferEgressControl::new(Instant::now() + Duration::from_secs(60));
    let send_connections = connections.clone();
    let send_payload = payload.clone();
    let sender = tokio::spawn(async move {
        send_json_transfer(
            &send_connections,
            connection_id,
            MessageId::new("json-part-65-message"),
            TransferId::new("json-part-65-transfer"),
            RuntimeTransferChannel::Reply,
            &send_payload,
            &control,
        )
        .await
    });

    for expected_index in 0..expected_parts {
        let write = timeout(Duration::from_secs(5), receiver.recv())
            .await
            .expect("JSON part timed out")
            .expect("writer closed before part 65");
        let envelope: RuntimeEnvelope = serde_json::from_slice(write.bytes()).unwrap();
        let RuntimeMessage::Reply(RuntimeReply::TransferPart(part)) = envelope.body else {
            panic!("expected reply TransferPart");
        };
        assert_eq!(part.part_index, expected_index);
        assert_eq!(part.part_count, expected_parts);
        write.acknowledge().expect("ACK JSON part");
    }

    let report = timeout(Duration::from_secs(10), sender)
        .await
        .expect("65-part egress completion timed out")
        .expect("egress task panicked")
        .expect("65-part egress failed");
    assert_eq!(report.part_count, 65);
    assert_eq!(report.total_bytes, payload.len() as u64);
    connections.shutdown().await.expect("shutdown registry");
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn snapshot_transfer_is_paced_under_the_16mib_writer_budget() {
    let connections = registry();
    let (connection_id, mut receiver) = connect(&connections, 0x31);
    // 完整 snapshot 大于 writer 的 16 MiB 总预算；若一次性排队全部 part，必然命中预算。
    let payload = Arc::new(real_snapshot_payload(17 * 1024 * 1024));
    let expected_parts = payload.len().max(1).div_ceil(MAX_JSON_PART_BYTES) as u32;
    let control = TransferEgressControl::new(Instant::now() + Duration::from_secs(30));
    let send_connections = connections.clone();
    let send_payload = payload.clone();
    let send_control = control.clone();
    let sender = tokio::spawn(async move {
        send_json_transfer(
            &send_connections,
            connection_id,
            MessageId::new("m".repeat(1024)),
            TransferId::new("t".repeat(1024)),
            RuntimeTransferChannel::Reply,
            &send_payload,
            &send_control,
        )
        .await
    });

    let mut assembled = Vec::with_capacity(payload.len());
    let mut observed_hash = None;
    for expected_index in 0..expected_parts {
        let write = timeout(Duration::from_secs(5), receiver.recv())
            .await
            .expect("paced part timed out")
            .expect("writer closed before all parts");
        assert!(write.bytes().len() < MAX_RUNTIME_JSON_FRAME_BYTES);
        let envelope: RuntimeEnvelope =
            serde_json::from_slice(write.bytes()).expect("decode real RuntimeEnvelope");
        let RuntimeMessage::Reply(RuntimeReply::TransferPart(part)) = envelope.body else {
            panic!("expected reply TransferPart");
        };
        assert_eq!(part.part_index, expected_index);
        assert_eq!(part.part_count, expected_parts);
        assert!(part.part.len() <= MAX_JSON_PART_BYTES);
        assert_eq!(part.total_bytes, payload.len() as u64);
        assert!(observed_hash.is_none_or(|hash| hash == part.total_sha256));
        observed_hash = Some(part.total_sha256);
        assembled.extend_from_slice(&part.part);

        // 当前 part 未完成真实 flush ACK 前，egress 不得让下一 part 进入 transport。
        tokio::task::yield_now().await;
        assert!(receiver.try_recv().is_err());
        write.acknowledge().expect("ACK flushed part");
    }

    let report = timeout(Duration::from_secs(5), sender)
        .await
        .expect("egress completion timed out")
        .expect("egress task panicked")
        .expect("egress failed");
    assert_eq!(report.part_count, expected_parts);
    assert_eq!(report.total_bytes, payload.len() as u64);
    assert_eq!(Some(report.total_sha256), observed_hash);
    assert_eq!(assembled, *payload);
    let decoded: ConversationSnapshot =
        serde_json::from_slice(&assembled).expect("reassemble real snapshot DTO");
    assert_eq!(decoded.items().len(), 2);
    assert!(
        connections.principal(connection_id).is_ok(),
        "dropping the detached egress capability must not close the shared registry"
    );

    connections.shutdown().await.expect("shutdown registry");
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn cancellation_interrupts_an_unacknowledged_real_writer_wait() {
    let connections = registry();
    let (connection_id, mut receiver) = connect(&connections, 0x32);
    let payload = Arc::new(real_snapshot_payload(MAX_JSON_PART_BYTES + 1));
    let control = TransferEgressControl::new(Instant::now() + Duration::from_secs(30));
    let send_connections = connections.clone();
    let send_payload = payload.clone();
    let send_control = control.clone();
    let sender = tokio::spawn(async move {
        send_json_transfer(
            &send_connections,
            connection_id,
            MessageId::new("cancel-message"),
            TransferId::new("cancel-transfer"),
            RuntimeTransferChannel::Stream,
            &send_payload,
            &send_control,
        )
        .await
    });
    let unacknowledged = timeout(Duration::from_secs(5), receiver.recv())
        .await
        .expect("first part timed out")
        .expect("writer closed before first part");

    control.cancel();
    let error = timeout(Duration::from_secs(5), sender)
        .await
        .expect("cancel did not unblock receipt wait")
        .expect("egress task panicked")
        .expect_err("cancelled egress must fail");
    assert!(matches!(error.kind(), TransferEgressErrorKind::Cancelled));
    assert_eq!(error.flushed_parts(), 0);
    assert!(receiver.try_recv().is_err());

    drop(unacknowledged);
    connections
        .disconnect(connection_id)
        .await
        .expect("disconnect cancelled writer");
    connections.shutdown().await.expect("shutdown registry");
}

#[tokio::test]
async fn absolute_deadline_fails_before_first_part_without_refresh() {
    let connections = registry();
    let (connection_id, mut receiver) = connect(&connections, 0x33);
    let control = TransferEgressControl::new(Instant::now());
    let error = send_json_transfer(
        &connections,
        connection_id,
        MessageId::new("expired-message"),
        TransferId::new("expired-transfer"),
        RuntimeTransferChannel::Reply,
        b"{}",
        &control,
    )
    .await
    .expect_err("deadline boundary must expire");
    assert!(matches!(error.kind(), TransferEgressErrorKind::Expired));
    assert_eq!(error.flushed_parts(), 0);
    assert!(receiver.try_recv().is_err());

    connections.shutdown().await.expect("shutdown registry");
}
