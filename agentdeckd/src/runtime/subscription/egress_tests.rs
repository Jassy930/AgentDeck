use std::collections::BTreeSet;
use std::sync::Arc;
use std::time::Duration;

use agentdeck_protocol::runtime::identity::{
    ConversationId, EntityId, ItemId, MessageId, TransferId,
};
use agentdeck_protocol::runtime::{
    ConversationSnapshot, MAX_JSON_PART_BYTES, MAX_RUNTIME_JSON_FRAME_BYTES, RuntimeEnvelope,
    RuntimeMessage, RuntimeReply, RuntimeTransferChannel, SnapshotItem, StreamCursor,
};
use agentdeck_protocol::{
    AgentItem, AgentItemMeta, AgentKind, SessionCapabilities, VendorCapabilities,
};
use tokio::sync::mpsc;
use tokio::time::{Instant, timeout};

use super::*;
use crate::runtime::ConnectionSink;
use crate::runtime::connection::{
    ConnectionRegistry, ConnectionWrite, DEFAULT_CONNECTION_WRITER_BYTES,
    DEFAULT_CONNECTION_WRITER_FRAMES, PrincipalIssuer,
};

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
