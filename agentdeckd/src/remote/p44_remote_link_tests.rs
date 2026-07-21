//! P4.4 RemoteLink / dispatch compile-RED。
//!
//! production 只冻结 reply sealer 的安全签名；其余组合经单个 test fixture 表达，避免为
//! RED 测试引入第二套 authorization Store/Core trait。

use std::sync::{Arc, Mutex};

use agentdeck_crypto::replay::{ReplayDisposition, ReplayWindow};
use agentdeck_protocol::e2ee::{KeyId, KeyPurpose, SignedSealedBlobV1, UnsignedSealedBlobV1};
use agentdeck_protocol::relay_v2::{
    DeviceRouteId, Ed25519Signature, MachineRouteId, OpaqueRouteFrame, RELAY_PROTOCOL_VERSION,
    RelayFrameBody, RequestRouteId,
};
use agentdeck_protocol::runtime::failure::{
    DAEMON_AUTHORIZATION_PERMISSION_DENIED, DAEMON_RUNTIME_RECOVERY_BLOCKED,
};
use agentdeck_protocol::runtime::identity::{
    ConversationId, IdempotencyKey, MessageId, StreamGeneration, TransferId,
};
use agentdeck_protocol::runtime::{
    ArtifactSha256, CatalogDelta, ConversationMetadataMutation,
    ConversationMetadataMutationRequest, ConversationMetadataReceipt, LocalOnlyAdministration,
    RUNTIME_PROTOCOL_VERSION, RuntimeEnvelope, RuntimeFailure, RuntimeInnerCursor, RuntimeMessage,
    RuntimeReply, RuntimeRequest, RuntimeStreamItem, RuntimeSyncComplete, StageUpgradeReceipt,
    StageUpgradeRequest, StreamCursor, TransferEnvelope,
};
use async_trait::async_trait;
use tokio::sync::oneshot::error::TryRecvError;

use crate::runtime::store::RemoteReplyAuthorization;
use crate::runtime::{ConnectionId, ConnectionWrite};

use super::dispatch::{
    RemoteDispatchError,
    test_support::{
        active_remote_dispatch_for_test, active_remote_dispatch_with_recovery_blocked_for_test,
        two_active_remote_dispatch_for_test,
    },
};
use super::link::{
    DirectedReplyRoute, DirectedReplySealer, RemoteLinkError, RemoteLinkOwner, RemoteReplyPump,
    RemoteStreamPublisher, ReplyRouteLifecycle, UnavailableDirectedReplySealer,
    UnavailableRemoteStreamPublisher, send_directed_reply_for_test,
};
use super::transport::active_pairing_transport_for_test;

const MACHINE: MachineRouteId = MachineRouteId::from_bytes([0x32; 16]);
const DEVICE_A: DeviceRouteId = DeviceRouteId::from_bytes([0xd1; 16]);
const DEVICE_B: DeviceRouteId = DeviceRouteId::from_bytes([0xd2; 16]);
const REQUEST_A: RequestRouteId = RequestRouteId::from_bytes([0x64; 16]);
const REQUEST_B: RequestRouteId = RequestRouteId::from_bytes([0x65; 16]);
const CONNECTION_A: ConnectionId = ConnectionId::from_test_bytes([0xa1; 16]);
const CONNECTION_B: ConnectionId = ConnectionId::from_test_bytes([0xb2; 16]);

fn business_frame(send: agentdeck_protocol::relay_v2::frame::Send) -> OpaqueRouteFrame {
    OpaqueRouteFrame {
        version: RELAY_PROTOCOL_VERSION,
        body: RelayFrameBody::Send(send),
    }
}

async fn wait_for_sent(
    harness: &super::transport::RemoteTransportTestHarness,
    expected: usize,
    context: &'static str,
) {
    tokio::time::timeout(std::time::Duration::from_secs(2), async {
        while harness.sent_count() != expected {
            tokio::task::yield_now().await;
        }
    })
    .await
    .unwrap_or_else(|_| panic!("{context}: sent={}", harness.sent_count()));
}

fn recorded_runtime_reply(call: &SealCall) -> RuntimeReply {
    let envelope: RuntimeEnvelope = serde_json::from_slice(&call.bytes)
        .expect("recorded sealer input is a canonical Runtime envelope");
    let RuntimeMessage::Reply(reply) = envelope.body else {
        panic!("recorded directed output must be a Runtime reply")
    };
    reply
}

fn replay_disposition(
    window: &ReplayWindow,
    counter: u64,
    ciphertext_hash: [u8; 32],
) -> ReplayDisposition {
    let mut probe = window.clone();
    probe
        .observe(counter, ciphertext_hash)
        .expect("test replay tuple is well formed")
}

/// 这条测试不接受由 `RemoteLinkFixture` 自报 core call/replay 数量。test support 只负责
/// 建立真实 Store authorization 与真实 DeviceSign/AEAD frame；阶段推进必须调用
/// production `dispatch.rs` 与 RuntimeCore 的两段 capability API。
#[tokio::test]
async fn production_dispatch_verifies_before_core_activation_and_commits_replay_last() {
    let fixture = active_remote_dispatch_for_test(MACHINE, DEVICE_A).await;
    let frame = fixture.signed_runtime_send(
        REQUEST_A,
        MessageId::new("p44-two-stage-success"),
        RuntimeRequest::DescribeAgents,
        11,
    );
    let mut live_replay = ReplayWindow::new();

    let verified = fixture
        .dispatcher()
        .verify_send(frame.send().clone(), &live_replay)
        .await
        .expect("real canonical/signature/AAD/AEAD/Runtime Request chain verifies");
    assert_eq!(
        replay_disposition(&live_replay, frame.counter(), frame.ciphertext_hash()),
        ReplayDisposition::Fresh,
        "crypto verification must only stage a cloned replay candidate"
    );

    let current = fixture
        .dispatcher()
        .recheck_current(verified)
        .await
        .expect("unchanged Store authorization remains Current");
    assert_eq!(
        replay_disposition(&live_replay, frame.counter(), frame.ciphertext_hash()),
        ReplayDisposition::Fresh,
        "even a successful final Store recheck must not mutate live replay before activation"
    );
    let activated = current
        .activate(fixture.core(), &mut live_replay)
        .expect("Current proof activates the shared lease only after full verification");
    assert!(matches!(
        &activated.envelope().body,
        RuntimeMessage::Request(RuntimeRequest::DescribeAgents)
    ));
    assert_eq!(
        replay_disposition(&live_replay, frame.counter(), frame.ciphertext_hash()),
        ReplayDisposition::ExactDuplicate,
        "only successful Current activation commits the replay candidate"
    );
    fixture.shutdown().await;
}

#[tokio::test]
async fn invalid_signature_aad_and_replay_reject_without_any_core_registration() {
    let fixture = active_remote_dispatch_for_test(MACHINE, DEVICE_A).await;
    let frame = fixture.signed_runtime_send(
        REQUEST_A,
        MessageId::new("p44-invalid-before-core"),
        RuntimeRequest::DescribeAgents,
        41,
    );

    let mut bad_signature = frame.send().clone();
    let mut signed = SignedSealedBlobV1::from_wire_bytes(&bad_signature.sealed_blob.0)
        .expect("parse valid frame before signature tamper");
    signed.signature.0[0] ^= 0x80;
    bad_signature.sealed_blob.0 = signed.to_wire_bytes();
    assert!(matches!(
        fixture
            .dispatcher()
            .verify_send(bad_signature, &ReplayWindow::new())
            .await,
        Err(RemoteDispatchError::InvalidSignature)
    ));
    assert_eq!(fixture.core().remote_registration_calls_for_test(), 0);

    let mut bad_aad = frame.send().clone();
    bad_aad.request_route = REQUEST_B;
    assert!(matches!(
        fixture
            .dispatcher()
            .verify_send(bad_aad, &ReplayWindow::new())
            .await,
        Err(RemoteDispatchError::InvalidSignature)
    ));
    assert_eq!(fixture.core().remote_registration_calls_for_test(), 0);

    let mut replay = ReplayWindow::new();
    replay
        .observe(frame.counter(), frame.ciphertext_hash())
        .expect("seed exact replay tuple");
    assert!(matches!(
        fixture
            .dispatcher()
            .verify_send(frame.send().clone(), &replay)
            .await,
        Err(RemoteDispatchError::ReplayRejected)
    ));
    assert_eq!(
        fixture.core().remote_registration_calls_for_test(),
        0,
        "all untrusted ingress failures must occur before the first RuntimeCore API"
    );
    fixture.shutdown().await;
}

#[tokio::test]
async fn real_remote_link_actor_isolates_two_devices_and_rejects_invalid_ingress_before_core() {
    let fixture = two_active_remote_dispatch_for_test(MACHINE, DEVICE_A, DEVICE_B).await;
    let core = fixture.core_arc();
    let (mut transport, _pairing_lane, harness) = active_pairing_transport_for_test(MACHINE);
    let business = transport
        .take_business_lane()
        .expect("take real actor business lane");
    let sealer = Arc::new(RecordingSealer {
        calls: Mutex::new(Vec::new()),
        sealed: None,
    });
    let mut owner = RemoteLinkOwner::start(
        MACHINE,
        fixture.store(),
        business,
        Arc::downgrade(&core),
        sealer.clone(),
        Arc::new(RecordingPublisher::default()),
    )
    .expect("ready P4.4 test egress starts RemoteLink");

    let mut unauthorized = fixture
        .signed_runtime_send(
            DEVICE_A,
            RequestRouteId::from_bytes([0x70; 16]),
            MessageId::new("unauthorized-device"),
            RuntimeRequest::DescribeAgents,
            1,
        )
        .send()
        .clone();
    unauthorized.device_route = DeviceRouteId::from_bytes([0xef; 16]);
    harness.push_frame(business_frame(unauthorized)).await;

    let mut bad_signature = fixture
        .signed_runtime_send(
            DEVICE_A,
            RequestRouteId::from_bytes([0x71; 16]),
            MessageId::new("bad-signature"),
            RuntimeRequest::DescribeAgents,
            2,
        )
        .send()
        .clone();
    let mut signed = SignedSealedBlobV1::from_wire_bytes(&bad_signature.sealed_blob.0)
        .expect("parse valid frame before signature tamper");
    signed.signature.0[0] ^= 0x80;
    bad_signature.sealed_blob.0 = signed.to_wire_bytes();
    harness.push_frame(business_frame(bad_signature)).await;

    let mut bad_aad = fixture
        .signed_runtime_send(
            DEVICE_A,
            RequestRouteId::from_bytes([0x72; 16]),
            MessageId::new("bad-aad"),
            RuntimeRequest::DescribeAgents,
            3,
        )
        .send()
        .clone();
    bad_aad.request_route = RequestRouteId::from_bytes([0x73; 16]);
    harness.push_frame(business_frame(bad_aad)).await;

    let bad_ciphertext = fixture.signed_runtime_send_with_tampered_ciphertext(
        DEVICE_A,
        RequestRouteId::from_bytes([0x74; 16]),
        MessageId::new("bad-aead"),
        RuntimeRequest::DescribeAgents,
        4,
    );
    harness
        .push_frame(business_frame(bad_ciphertext.send().clone()))
        .await;

    let shared_message_id = MessageId::new("same-message-real-core");
    let healthy_b = fixture.signed_runtime_send(
        DEVICE_B,
        REQUEST_B,
        shared_message_id.clone(),
        RuntimeRequest::DescribeAgents,
        1,
    );
    let healthy_a = fixture.signed_runtime_send(
        DEVICE_A,
        REQUEST_A,
        shared_message_id,
        RuntimeRequest::DescribeAgents,
        5,
    );
    harness
        .push_frame(business_frame(healthy_b.send().clone()))
        .await;
    harness
        .push_frame(business_frame(healthy_a.send().clone()))
        .await;
    let healthy = tokio::time::timeout(std::time::Duration::from_secs(2), async {
        while harness.sent_count() != 2 {
            tokio::task::yield_now().await;
        }
    })
    .await;
    assert!(
        healthy.is_ok(),
        "both healthy devices receive real Core replies: sent={}, frames={:?}, sealed={}, transport={:?}",
        harness.sent_count(),
        harness
            .sent_frames()
            .iter()
            .filter_map(|frame| match &frame.body {
                RelayFrameBody::Reply(reply) => Some((reply.device_route, reply.request_route)),
                _ => None,
            })
            .collect::<Vec<_>>(),
        sealer.calls.lock().expect("read timeout calls").len(),
        transport.observed_failure_code(),
    );

    let sent = harness.sent_frames();
    let routes = sent
        .iter()
        .map(|frame| match &frame.body {
            RelayFrameBody::Reply(reply) => (reply.device_route, reply.request_route),
            other => panic!("real RemoteLink must emit Reply, got {other:?}"),
        })
        .collect::<Vec<_>>();
    assert!(routes.contains(&(DEVICE_A, REQUEST_A)));
    assert!(routes.contains(&(DEVICE_B, REQUEST_B)));
    assert_eq!(
        sealer.calls.lock().expect("read real actor calls").len(),
        2,
        "four invalid frames must be rejected before Core/sealer"
    );

    harness
        .push_frame(business_frame(healthy_a.send().clone()))
        .await;
    let fresh_b = fixture.signed_runtime_send(
        DEVICE_B,
        RequestRouteId::from_bytes([0x75; 16]),
        MessageId::new("fresh-after-exact-replay"),
        RuntimeRequest::DescribeAgents,
        2,
    );
    harness
        .push_frame(business_frame(fresh_b.send().clone()))
        .await;
    tokio::time::timeout(std::time::Duration::from_secs(2), async {
        while harness.sent_count() != 3 {
            tokio::task::yield_now().await;
        }
    })
    .await
    .expect("healthy sibling proceeds after exact replay rejection");
    assert_eq!(
        sealer.calls.lock().expect("read replay calls").len(),
        3,
        "exact replay must not enter Core or sealer"
    );

    owner
        .shutdown()
        .await
        .expect("shutdown real RemoteLink actor");
    transport.shutdown().await;
    drop(core);
    fixture.shutdown().await;
}

#[tokio::test]
async fn real_remote_link_actor_survives_transient_failure_and_replies_after_reconnect() {
    let fixture = active_remote_dispatch_for_test(MACHINE, DEVICE_A).await;
    let core = fixture.core_arc();
    let (mut transport, _pairing_lane, harness) = active_pairing_transport_for_test(MACHINE);
    let business = transport
        .take_business_lane()
        .expect("take reconnect actor business lane");
    let sealer = Arc::new(RecordingSealer {
        calls: Mutex::new(Vec::new()),
        sealed: None,
    });
    let mut owner = RemoteLinkOwner::start(
        MACHINE,
        fixture.store(),
        business,
        Arc::downgrade(&core),
        sealer.clone(),
        Arc::new(RecordingPublisher::default()),
    )
    .expect("ready reconnect egress starts RemoteLink");

    let before_failure = fixture.signed_runtime_send(
        REQUEST_A,
        MessageId::new("before-transient-failure"),
        RuntimeRequest::DescribeAgents,
        1,
    );
    harness
        .push_frame(business_frame(before_failure.send().clone()))
        .await;
    tokio::time::timeout(std::time::Duration::from_secs(2), async {
        while harness.sent_count() != 1 {
            tokio::task::yield_now().await;
        }
    })
    .await
    .expect("real actor sends the pre-failure reply");

    harness.push_error("relay.client.connection_lost").await;
    tokio::time::timeout(std::time::Duration::from_secs(2), async {
        while transport.observed_failure_code().as_deref() != Some("relay.client.connection_lost") {
            tokio::task::yield_now().await;
        }
    })
    .await
    .expect("transient health failure becomes observable");
    transport
        .reconnect()
        .await
        .expect("replace failed MachineLink generation");
    assert_eq!(transport.observed_failure_code(), None);
    assert_eq!(harness.reconnect_count(), 1);

    let after_reconnect = fixture.signed_runtime_send(
        REQUEST_B,
        MessageId::new("fresh-after-reconnect"),
        RuntimeRequest::DescribeAgents,
        2,
    );
    harness
        .push_frame(business_frame(after_reconnect.send().clone()))
        .await;
    tokio::time::timeout(std::time::Duration::from_secs(2), async {
        while harness.sent_count() != 2 {
            tokio::task::yield_now().await;
        }
    })
    .await
    .expect("same real actor sends a fresh post-reconnect reply");

    let sent = harness.sent_frames();
    let RelayFrameBody::Reply(reply) = &sent[1].body else {
        panic!("post-reconnect frame must be a directed Reply");
    };
    assert_eq!(
        (reply.device_route, reply.request_route),
        (DEVICE_A, REQUEST_B)
    );
    assert_eq!(
        sealer
            .calls
            .lock()
            .expect("read reconnect seal calls")
            .len(),
        2
    );

    owner
        .shutdown()
        .await
        .expect("shutdown reconnected RemoteLink actor");
    transport.shutdown().await;
    drop(core);
    fixture.shutdown().await;
}

#[tokio::test]
async fn remote_stage_upgrade_failure_flushes_without_deadlocking_and_sibling_continues() {
    let fixture = two_active_remote_dispatch_for_test(MACHINE, DEVICE_A, DEVICE_B).await;
    let core = fixture.core_arc();
    let (mut transport, _pairing_lane, harness) = active_pairing_transport_for_test(MACHINE);
    let business = transport
        .take_business_lane()
        .expect("take StageUpgrade business lane");
    let sealer = Arc::new(RecordingSealer {
        calls: Mutex::new(Vec::new()),
        sealed: None,
    });
    let mut owner = RemoteLinkOwner::start(
        MACHINE,
        fixture.store(),
        business,
        Arc::downgrade(&core),
        sealer.clone(),
        Arc::new(RecordingPublisher::default()),
    )
    .expect("start concurrent-dispatch RemoteLink");

    let stage = fixture.signed_runtime_send(
        DEVICE_A,
        REQUEST_A,
        MessageId::new("remote-stage-upgrade-denied"),
        RuntimeRequest::StageUpgrade(
            StageUpgradeRequest::new(
                "1.2.3".to_owned(),
                ArtifactSha256::new("ab".repeat(32)).expect("valid artifact hash"),
                IdempotencyKey::new("remote-stage-upgrade-denied"),
                LocalOnlyAdministration::LocalOnly,
            )
            .expect("valid typed StageUpgrade request"),
        ),
        1,
    );
    harness
        .push_frame(business_frame(stage.send().clone()))
        .await;
    wait_for_sent(&harness, 1, "remote StageUpgrade failure reply must flush").await;
    {
        let calls = sealer.calls.lock().expect("read StageUpgrade reply");
        assert!(matches!(
            recorded_runtime_reply(&calls[0]),
            RuntimeReply::StageUpgrade(StageUpgradeReceipt::Failed {
                failure: RuntimeFailure { code, .. }
            }) if code == DAEMON_AUTHORIZATION_PERMISSION_DENIED
        ));
    }

    let sibling = fixture.signed_runtime_send(
        DEVICE_B,
        REQUEST_B,
        MessageId::new("sibling-after-stage-upgrade"),
        RuntimeRequest::DescribeAgents,
        1,
    );
    harness
        .push_frame(business_frame(sibling.send().clone()))
        .await;
    wait_for_sent(
        &harness,
        2,
        "sibling request must continue after StageUpgrade flush ACK",
    )
    .await;
    {
        let calls = sealer.calls.lock().expect("read sibling reply");
        assert!(matches!(
            recorded_runtime_reply(&calls[1]),
            RuntimeReply::Agents(_)
        ));
    }

    owner.shutdown().await.expect("shutdown StageUpgrade Link");
    transport.shutdown().await;
    drop(core);
    fixture.shutdown().await;
}

#[tokio::test]
async fn closed_core_writer_evicts_cached_connection_and_same_device_reconnects() {
    let fixture = active_remote_dispatch_for_test(MACHINE, DEVICE_A).await;
    let core = fixture.core_arc();
    let (mut transport, _pairing_lane, harness) = active_pairing_transport_for_test(MACHINE);
    let business = transport
        .take_business_lane()
        .expect("take writer-reconnect business lane");
    let mut owner = RemoteLinkOwner::start(
        MACHINE,
        fixture.store(),
        business,
        Arc::downgrade(&core),
        Arc::new(RecordingSealer {
            calls: Mutex::new(Vec::new()),
            sealed: None,
        }),
        Arc::new(RecordingPublisher::default()),
    )
    .expect("start writer-reconnect RemoteLink");

    let first = fixture.signed_runtime_send(
        REQUEST_A,
        MessageId::new("before-core-writer-close"),
        RuntimeRequest::DescribeAgents,
        1,
    );
    harness
        .push_frame(business_frame(first.send().clone()))
        .await;
    wait_for_sent(&harness, 1, "first connection reply").await;
    let old_connection = tokio::time::timeout(std::time::Duration::from_secs(2), async {
        loop {
            let ids = owner.connection_ids_for_test();
            if let [connection_id] = ids.as_slice() {
                break *connection_id;
            }
            tokio::task::yield_now().await;
        }
    })
    .await
    .expect("observe first cached connection");

    core.fail_close_connection_for_transport(old_connection);
    tokio::time::timeout(std::time::Duration::from_secs(2), async {
        while owner.connection_ids_for_test().contains(&old_connection) {
            tokio::task::yield_now().await;
        }
    })
    .await
    .expect("closed Core writer terminal evicts exact cached connection");

    let second = fixture.signed_runtime_send(
        REQUEST_B,
        MessageId::new("after-core-writer-close"),
        RuntimeRequest::DescribeAgents,
        2,
    );
    harness
        .push_frame(business_frame(second.send().clone()))
        .await;
    wait_for_sent(&harness, 2, "same device reconnect reply").await;
    let new_connection = tokio::time::timeout(std::time::Duration::from_secs(2), async {
        loop {
            let ids = owner.connection_ids_for_test();
            if let [connection_id] = ids.as_slice()
                && *connection_id != old_connection
            {
                break *connection_id;
            }
            tokio::task::yield_now().await;
        }
    })
    .await
    .expect("same device establishes a fresh Core connection");
    assert_ne!(new_connection, old_connection);

    owner
        .shutdown()
        .await
        .expect("shutdown writer-reconnect Link");
    transport.shutdown().await;
    drop(core);
    fixture.shutdown().await;
}

#[tokio::test]
async fn real_remote_link_keeps_recovery_blocked_read_only_and_serves_healthy_sibling() {
    let (fixture, blocked, healthy) =
        active_remote_dispatch_with_recovery_blocked_for_test(MACHINE, DEVICE_A).await;
    let core = fixture.core_arc();
    let (mut transport, _pairing_lane, harness) = active_pairing_transport_for_test(MACHINE);
    let business = transport
        .take_business_lane()
        .expect("take recovery-policy business lane");
    let sealer = Arc::new(RecordingSealer {
        calls: Mutex::new(Vec::new()),
        sealed: None,
    });
    let mut owner = RemoteLinkOwner::start(
        MACHINE,
        fixture.store(),
        business,
        Arc::downgrade(&core),
        sealer.clone(),
        Arc::new(RecordingPublisher::default()),
    )
    .expect("start recovery-policy RemoteLink");

    let blocked_mutation = fixture.signed_runtime_send(
        REQUEST_A,
        MessageId::new("blocked-metadata-over-link"),
        RuntimeRequest::UpdateConversationMetadata(
            ConversationMetadataMutationRequest::new(
                blocked,
                IdempotencyKey::new("blocked-metadata-over-link"),
                0,
                ConversationMetadataMutation::SetArchived { archived: true },
            )
            .expect("valid blocked metadata request"),
        ),
        1,
    );
    harness
        .push_frame(business_frame(blocked_mutation.send().clone()))
        .await;
    wait_for_sent(&harness, 1, "RecoveryBlocked directed failure").await;

    let healthy_mutation = fixture.signed_runtime_send(
        REQUEST_B,
        MessageId::new("healthy-metadata-over-link"),
        RuntimeRequest::UpdateConversationMetadata(
            ConversationMetadataMutationRequest::new(
                healthy,
                IdempotencyKey::new("healthy-metadata-over-link"),
                0,
                ConversationMetadataMutation::SetArchived { archived: true },
            )
            .expect("valid healthy metadata request"),
        ),
        2,
    );
    harness
        .push_frame(business_frame(healthy_mutation.send().clone()))
        .await;
    wait_for_sent(&harness, 2, "healthy sibling directed success").await;

    {
        let calls = sealer.calls.lock().expect("read recovery-policy replies");
        assert!(matches!(
            recorded_runtime_reply(&calls[0]),
            RuntimeReply::ConversationMetadata(ConversationMetadataReceipt::Failed {
                failure: RuntimeFailure { code, .. }
            }) if code == DAEMON_RUNTIME_RECOVERY_BLOCKED
        ));
        assert!(matches!(
            recorded_runtime_reply(&calls[1]),
            RuntimeReply::ConversationMetadata(ConversationMetadataReceipt::Applied {
                entry_revision: 1,
                ..
            })
        ));
    }

    owner
        .shutdown()
        .await
        .expect("shutdown recovery-policy Link");
    transport.shutdown().await;
    drop(core);
    fixture.shutdown().await;
}

#[tokio::test]
async fn remote_link_owner_rejects_each_unavailable_egress_capability_before_spawn() {
    let fixture = active_remote_dispatch_for_test(MACHINE, DEVICE_A).await;
    let core = fixture.core_arc();

    let (mut missing_sealer_transport, _pairing_lane, _harness) =
        active_pairing_transport_for_test(MACHINE);
    let missing_sealer_lane = missing_sealer_transport
        .take_business_lane()
        .expect("take missing-sealer lane");
    assert!(matches!(
        RemoteLinkOwner::start(
            MACHINE,
            fixture.store(),
            missing_sealer_lane,
            Arc::downgrade(&core),
            Arc::new(UnavailableDirectedReplySealer),
            Arc::new(RecordingPublisher::default()),
        ),
        Err(RemoteLinkError::ReplySealUnavailable)
    ));
    missing_sealer_transport.shutdown().await;

    let (mut missing_publisher_transport, _pairing_lane, _harness) =
        active_pairing_transport_for_test(MACHINE);
    let missing_publisher_lane = missing_publisher_transport
        .take_business_lane()
        .expect("take missing-publisher lane");
    assert!(matches!(
        RemoteLinkOwner::start(
            MACHINE,
            fixture.store(),
            missing_publisher_lane,
            Arc::downgrade(&core),
            Arc::new(RecordingSealer {
                calls: Mutex::new(Vec::new()),
                sealed: None,
            }),
            Arc::new(UnavailableRemoteStreamPublisher),
        ),
        Err(RemoteLinkError::StreamPublisherUnavailable)
    ));
    missing_publisher_transport.shutdown().await;

    drop(core);
    fixture.shutdown().await;
}

#[tokio::test]
async fn remote_link_shutdown_deadline_aborts_and_joins_a_stuck_actor() {
    let fixture = active_remote_dispatch_for_test(MACHINE, DEVICE_A).await;
    let core = fixture.core_arc();
    let mut owner = RemoteLinkOwner::pending_for_shutdown_test(
        Arc::downgrade(&core),
        std::time::Duration::from_millis(20),
    );
    let result = tokio::time::timeout(std::time::Duration::from_millis(250), owner.shutdown())
        .await
        .expect("shutdown deadline remains bounded");
    assert!(matches!(result, Err(RemoteLinkError::ShutdownTimedOut)));
    drop(core);
    fixture.shutdown().await;
}

#[derive(Clone)]
struct SealCall {
    route: DirectedReplyRoute,
    bytes: Arc<[u8]>,
}

struct RecordingSealer {
    calls: Mutex<Vec<SealCall>>,
    sealed: Option<SignedSealedBlobV1>,
}

struct FailingSealer;

#[derive(Default)]
struct RecordingPublisher {
    calls: Mutex<Vec<Arc<[u8]>>>,
    release: tokio::sync::Notify,
}

#[async_trait]
impl DirectedReplySealer for RecordingSealer {
    fn admission_ready(&self) -> bool {
        true
    }

    async fn seal_exact(
        &self,
        authorization: &RemoteReplyAuthorization,
        route: DirectedReplyRoute,
        runtime_bytes: Arc<[u8]>,
    ) -> Result<SignedSealedBlobV1, RemoteLinkError> {
        self.calls
            .lock()
            .expect("record sealer call")
            .push(SealCall {
                route,
                bytes: runtime_bytes,
            });
        Ok(self
            .sealed
            .clone()
            .unwrap_or_else(|| fake_signed_reply(authorization)))
    }
}

#[async_trait]
impl DirectedReplySealer for FailingSealer {
    fn admission_ready(&self) -> bool {
        true
    }

    async fn seal_exact(
        &self,
        _authorization: &RemoteReplyAuthorization,
        _route: DirectedReplyRoute,
        _runtime_bytes: Arc<[u8]>,
    ) -> Result<SignedSealedBlobV1, RemoteLinkError> {
        Err(RemoteLinkError::ReplySealFailed)
    }
}

#[async_trait]
impl RemoteStreamPublisher for RecordingPublisher {
    fn admission_ready(&self) -> bool {
        true
    }

    async fn publish_exact(&self, runtime_bytes: Arc<[u8]>) -> Result<(), RemoteLinkError> {
        self.calls
            .lock()
            .expect("record publisher call")
            .push(runtime_bytes);
        self.release.notified().await;
        Ok(())
    }
}

fn fake_signed_reply(authorization: &RemoteReplyAuthorization) -> SignedSealedBlobV1 {
    UnsignedSealedBlobV1::new(
        KeyId {
            purpose: KeyPurpose::DeviceReplyTx,
            epoch: authorization.reply_key_epoch(),
        },
        authorization.reply_key_epoch(),
        authorization.key_directory_revision().value(),
        [0x91; 12],
        vec![0x92; 16],
    )
    .attach_signature(Ed25519Signature([0x94; 64]))
}

#[tokio::test]
async fn directed_reply_binds_exact_route_and_bytes_then_acks_only_after_flush() {
    let (mut transport, _pairing_lane, harness) = active_pairing_transport_for_test(MACHINE);
    let business = transport
        .take_business_lane()
        .expect("take business lane once");
    let fixture = active_remote_dispatch_for_test(MACHINE, DEVICE_A).await;
    let authorization = fixture.reply_authorization().await;
    let route = DirectedReplyRoute {
        machine_route: MACHINE,
        device_route: DEVICE_A,
        request_route: REQUEST_A,
    };
    let runtime_bytes: Arc<[u8]> = Arc::from(&b"exact RuntimeEnvelope bytes"[..]);
    let signed = fake_signed_reply(&authorization);
    let expected_wire = signed.to_wire_bytes();
    let sealer = Arc::new(RecordingSealer {
        calls: Mutex::new(Vec::new()),
        sealed: Some(signed),
    });
    let (write, mut acknowledged) = ConnectionWrite::for_transport_test(runtime_bytes.clone());

    harness.hold_send_flush();
    let send = tokio::spawn(send_directed_reply_for_test(
        business,
        sealer.clone(),
        authorization,
        route,
        write,
    ));
    tokio::time::timeout(std::time::Duration::from_millis(250), async {
        while harness.send_started_count() != 1 {
            tokio::task::yield_now().await;
        }
    })
    .await
    .expect("writer reaches held flush");

    {
        let calls = sealer.calls.lock().expect("read sealer calls");
        assert_eq!(calls.len(), 1);
        assert_eq!(calls[0].route, route);
        assert_eq!(calls[0].bytes.as_ref(), runtime_bytes.as_ref());
    }
    assert_eq!(acknowledged.try_recv(), Err(TryRecvError::Empty));

    harness.release_send_flush();
    send.await
        .expect("reply pump joins")
        .expect("Relay flushes");
    acknowledged.await.expect("Core write ACK follows flush");
    let sent = harness.sent_frames();
    let agentdeck_protocol::relay_v2::frame::RelayFrameBody::Reply(reply) = &sent[0].body else {
        panic!("directed writer must emit Reply");
    };
    assert_eq!(reply.device_route, DEVICE_A);
    assert_eq!(reply.request_route, REQUEST_A);
    assert_eq!(reply.sealed_blob.0, expected_wire);
    transport.shutdown().await;
    fixture.shutdown().await;
}

fn runtime_write(
    message_id: &str,
    body: RuntimeMessage,
) -> (
    MessageId,
    ConnectionWrite,
    tokio::sync::oneshot::Receiver<()>,
) {
    let message_id = MessageId::new(message_id);
    let bytes: Arc<[u8]> = RuntimeEnvelope {
        version: RUNTIME_PROTOCOL_VERSION,
        message_id: message_id.clone(),
        body,
    }
    .to_json_bytes_checked()
    .expect("valid Runtime reply bytes")
    .into();
    let (write, acknowledged) = ConnectionWrite::for_transport_test(bytes);
    (message_id, write, acknowledged)
}

fn runtime_failure_write(
    message_id: &str,
) -> (
    MessageId,
    ConnectionWrite,
    tokio::sync::oneshot::Receiver<()>,
) {
    runtime_write(
        message_id,
        RuntimeMessage::Reply(RuntimeReply::Failure(RuntimeFailure::new(
            "test.remote.reply",
            "directed reply fixture",
        ))),
    )
}

#[tokio::test]
async fn directed_reply_rejects_invalid_sealer_metadata_without_send_or_ack() {
    let authorization = RemoteReplyAuthorization::for_test(MACHINE, DEVICE_A, 1);
    let route = DirectedReplyRoute {
        machine_route: MACHINE,
        device_route: DEVICE_A,
        request_route: REQUEST_A,
    };
    let valid = fake_signed_reply(&authorization);
    let mut wrong_purpose = valid.clone();
    wrong_purpose.inner.key_id.purpose = KeyPurpose::DeviceCommandTx;
    let mut wrong_epoch = valid.clone();
    wrong_epoch.inner.key_id.epoch = 2;
    wrong_epoch.inner.key_epoch = 2;
    let mut wrong_revision = valid.clone();
    wrong_revision.inner.key_directory_revision = 2;
    let mut noncanonical = valid;
    noncanonical.inner.ciphertext = vec![0x92, 0x93];

    for (name, sealed) in [
        ("wrong-purpose", wrong_purpose),
        ("wrong-epoch", wrong_epoch),
        ("wrong-revision", wrong_revision),
        ("noncanonical", noncanonical),
    ] {
        let (mut transport, _pairing_lane, harness) = active_pairing_transport_for_test(MACHINE);
        let business = transport
            .take_business_lane()
            .expect("take invalid-output business lane");
        let mut pump = RemoteReplyPump::new(
            business,
            Arc::new(RecordingSealer {
                calls: Mutex::new(Vec::new()),
                sealed: Some(sealed),
            }),
        );
        let (message_id, write, acknowledged) = runtime_failure_write(name);
        pump.bind(
            CONNECTION_A,
            message_id,
            route,
            authorization.clone(),
            ReplyRouteLifecycle::OneShot,
        )
        .expect("bind exact route before validating sealer output");
        assert!(matches!(
            pump.forward(CONNECTION_A, write).await,
            Err(RemoteLinkError::InvalidReplySeal)
        ));
        assert!(
            acknowledged.await.is_err(),
            "invalid sealer output must drop the Core write without ACK: {name}"
        );
        assert_eq!(
            harness.sent_count(),
            0,
            "invalid sealer output must never reach Relay: {name}"
        );
        transport.shutdown().await;
    }
}

/// Reply failures必须落到 production route table/pump；不能把测试直接传入一个永远
/// 正确的 `DirectedReplyRoute`，否则 unknown messageId、seal failure 与 Relay send
/// failure 都可能在真实 actor 中错误 ACK Core write。
#[tokio::test]
async fn production_reply_pump_never_acks_unknown_route_seal_failure_or_send_failure() {
    let authorization_fixture = active_remote_dispatch_for_test(MACHINE, DEVICE_A).await;
    let authorization = authorization_fixture.reply_authorization().await;
    let route = DirectedReplyRoute {
        machine_route: MACHINE,
        device_route: DEVICE_A,
        request_route: REQUEST_A,
    };

    // Unknown messageId: the sealer and Relay session must not be reached, and dropping the
    // write without ACK fail-closes the corresponding Core connection.
    let (mut unknown_transport, _pairing_lane, _harness) =
        active_pairing_transport_for_test(MACHINE);
    let unknown_business = unknown_transport
        .take_business_lane()
        .expect("take unknown-route business lane");
    let sealer = Arc::new(RecordingSealer {
        calls: Mutex::new(Vec::new()),
        sealed: None,
    });
    let mut unknown_pump = RemoteReplyPump::new(unknown_business, sealer.clone());
    let (_message_id, write, acknowledged) = runtime_failure_write("unknown-route");
    assert!(unknown_pump.forward(CONNECTION_A, write).await.is_err());
    assert!(
        acknowledged.await.is_err(),
        "unknown route must drop ConnectionWrite without ACK"
    );
    assert!(
        sealer
            .calls
            .lock()
            .expect("read unknown sealer calls")
            .is_empty(),
        "unknown route must fail before sealing"
    );
    unknown_transport.shutdown().await;

    // Sealing failure: exact mapping exists, but the failed cryptographic boundary still must
    // not ACK or attempt Relay send.
    let (mut seal_transport, _pairing_lane, seal_harness) =
        active_pairing_transport_for_test(MACHINE);
    let seal_business = seal_transport
        .take_business_lane()
        .expect("take seal-failure business lane");
    let mut seal_pump = RemoteReplyPump::new(seal_business, Arc::new(FailingSealer));
    let (message_id, write, acknowledged) = runtime_failure_write("seal-failure");
    seal_pump
        .bind(
            CONNECTION_A,
            message_id,
            route,
            authorization.clone(),
            ReplyRouteLifecycle::OneShot,
        )
        .expect("bind exact route before seal failure");
    assert!(seal_pump.forward(CONNECTION_A, write).await.is_err());
    assert!(
        acknowledged.await.is_err(),
        "seal failure must drop ConnectionWrite without ACK"
    );
    assert_eq!(seal_harness.sent_count(), 0);
    seal_transport.shutdown().await;

    // Relay send/flush failure: close the real supervisor before forwarding. A successful
    // sealer is insufficient; ACK remains forbidden until the shared MachineLink flushes.
    let (mut send_transport, _pairing_lane, send_harness) =
        active_pairing_transport_for_test(MACHINE);
    let send_business = send_transport
        .take_business_lane()
        .expect("take send-failure business lane");
    let mut send_pump = RemoteReplyPump::new(
        send_business,
        Arc::new(RecordingSealer {
            calls: Mutex::new(Vec::new()),
            sealed: None,
        }),
    );
    let (message_id, write, acknowledged) = runtime_failure_write("send-failure");
    send_pump
        .bind(
            CONNECTION_A,
            message_id,
            route,
            authorization,
            ReplyRouteLifecycle::OneShot,
        )
        .expect("bind exact route before send failure");
    send_transport.shutdown().await;
    assert!(send_pump.forward(CONNECTION_A, write).await.is_err());
    assert!(
        acknowledged.await.is_err(),
        "Relay send failure must drop ConnectionWrite without ACK"
    );
    assert_eq!(send_harness.sent_count(), 0);

    authorization_fixture.shutdown().await;
}

#[tokio::test]
async fn generation_replacement_evicts_bound_routes_before_a_stale_core_reply() {
    let authorization = RemoteReplyAuthorization::for_test(MACHINE, DEVICE_A, 1);
    let route = DirectedReplyRoute {
        machine_route: MACHINE,
        device_route: DEVICE_A,
        request_route: REQUEST_A,
    };
    let (mut transport, _pairing_lane, harness) = active_pairing_transport_for_test(MACHINE);
    let business = transport
        .take_business_lane()
        .expect("take generation-bound business lane");
    let sealer = Arc::new(RecordingSealer {
        calls: Mutex::new(Vec::new()),
        sealed: None,
    });
    let mut pump = RemoteReplyPump::new(business, sealer.clone());
    let (message_id, stale_write, stale_acknowledged) =
        runtime_failure_write("stale-generation-reply");
    pump.bind(
        CONNECTION_A,
        message_id,
        route,
        authorization,
        ReplyRouteLifecycle::OneShot,
    )
    .expect("bind current generation route");

    transport.reconnect().await.expect("replace generation");
    let replacement = tokio::time::timeout(
        std::time::Duration::from_millis(250),
        pump.next_transport_event(),
    )
    .await
    .expect("observe replacement promptly")
    .expect("healthy replacement event")
    .expect("concrete replacement event");
    let super::transport::BusinessTransportEvent::GenerationReplaced { previous, current } =
        replacement
    else {
        panic!("expected generation replacement");
    };
    assert!(current > previous);
    assert!(pump.forward(CONNECTION_A, stale_write).await.is_err());
    assert!(stale_acknowledged.await.is_err());
    assert!(sealer.calls.lock().expect("read sealer calls").is_empty());
    assert_eq!(harness.sent_count(), 0);
    transport.shutdown().await;
}

#[tokio::test]
async fn production_egress_publishes_stream_but_rejects_request_without_ack_or_relay_reply() {
    let (mut transport, _pairing_lane, harness) = active_pairing_transport_for_test(MACHINE);
    let business = transport
        .take_business_lane()
        .expect("take egress-classification business lane");
    let sealer = Arc::new(RecordingSealer {
        calls: Mutex::new(Vec::new()),
        sealed: None,
    });
    let publisher = Arc::new(RecordingPublisher::default());
    let mut pump =
        RemoteReplyPump::new(business, sealer.clone()).with_stream_publisher(publisher.clone());

    let stream_message_id = MessageId::new("publish-catalog-delta");
    let stream_body = RuntimeMessage::Stream(RuntimeStreamItem::CatalogDelta(CatalogDelta {
        catalog_revision: 17,
        changes: Vec::new(),
    }));
    let expected_stream_bytes = RuntimeEnvelope {
        version: RUNTIME_PROTOCOL_VERSION,
        message_id: stream_message_id.clone(),
        body: stream_body.clone(),
    }
    .to_json_bytes_checked()
    .expect("valid stream bytes");
    let (_message_id, stream_write, mut stream_acknowledged) =
        runtime_write(stream_message_id.as_str(), stream_body);
    let mut publish = Box::pin(pump.forward(CONNECTION_A, stream_write));
    tokio::time::timeout(std::time::Duration::from_millis(250), async {
        loop {
            if !publisher
                .calls
                .lock()
                .expect("observe publisher start")
                .is_empty()
            {
                break;
            }
            tokio::select! {
                result = publish.as_mut() => {
                    panic!("publisher returned before the held durable boundary: {result:?}");
                }
                () = tokio::task::yield_now() => {}
            }
        }
    })
    .await
    .expect("Stream reaches publisher seam");
    assert_eq!(stream_acknowledged.try_recv(), Err(TryRecvError::Empty));
    assert!(sealer.calls.lock().expect("read stream sealer").is_empty());
    assert_eq!(harness.sent_count(), 0);
    assert_eq!(
        publisher.calls.lock().expect("read publisher calls")[0].as_ref(),
        expected_stream_bytes.as_slice()
    );
    publisher.release.notify_one();
    publish.as_mut().await.expect("publisher succeeds");
    drop(publish);
    stream_acknowledged.await.expect("publisher success ACKs");

    let calls_before = publisher.calls.lock().expect("count calls").len();
    let (_message_id, request_write, request_acknowledged) = runtime_write(
        "invalid-core-egress-request",
        RuntimeMessage::Request(RuntimeRequest::DescribeAgents),
    );
    assert!(pump.forward(CONNECTION_A, request_write).await.is_err());
    assert!(request_acknowledged.await.is_err());
    assert_eq!(
        publisher.calls.lock().expect("count calls").len(),
        calls_before
    );
    assert!(sealer.calls.lock().expect("read request sealer").is_empty());
    assert_eq!(harness.sent_count(), 0);
    transport.shutdown().await;
}

fn transfer_reply(transfer_id: &str, part_index: u32, part_count: u32) -> RuntimeReply {
    RuntimeReply::TransferPart(
        TransferEnvelope::new_json(
            TransferId::new(transfer_id),
            part_index,
            part_count,
            [0x8a; 32],
            u64::from(part_count),
            vec![part_index as u8],
        )
        .expect("valid tiny JSON transfer part"),
    )
}

#[tokio::test]
async fn terminal_replies_reclaim_route_capacity_beyond_a_single_generation_window() {
    let authorization = RemoteReplyAuthorization::for_test(MACHINE, DEVICE_A, 1);
    let route = DirectedReplyRoute {
        machine_route: MACHINE,
        device_route: DEVICE_A,
        request_route: REQUEST_A,
    };
    let (mut transport, _pairing_lane, harness) = active_pairing_transport_for_test(MACHINE);
    let business = transport
        .take_business_lane()
        .expect("take capacity business lane");
    let mut pump = RemoteReplyPump::new(
        business,
        Arc::new(RecordingSealer {
            calls: Mutex::new(Vec::new()),
            sealed: None,
        }),
    );

    for index in 0..520_u32 {
        let id = format!("reclaimed-route-{index}");
        let (message_id, write, acknowledged) = runtime_failure_write(&id);
        pump.bind(
            CONNECTION_A,
            message_id,
            route,
            authorization.clone(),
            ReplyRouteLifecycle::OneShot,
        )
        .expect("completed prior replies must reclaim bounded route capacity");
        pump.forward(CONNECTION_A, write)
            .await
            .expect("terminal reply flushes");
        acknowledged.await.expect("terminal reply ACKs");
    }
    assert_eq!(harness.sent_count(), 520);
    transport.shutdown().await;
}

#[tokio::test]
async fn multipart_and_sync_routes_reclaim_only_at_their_exact_terminal() {
    let authorization = RemoteReplyAuthorization::for_test(MACHINE, DEVICE_A, 1);
    let route = DirectedReplyRoute {
        machine_route: MACHINE,
        device_route: DEVICE_A,
        request_route: REQUEST_A,
    };
    let (mut transport, _pairing_lane, _harness) = active_pairing_transport_for_test(MACHINE);
    let business = transport
        .take_business_lane()
        .expect("take lifecycle business lane");
    let mut pump = RemoteReplyPump::new(
        business,
        Arc::new(RecordingSealer {
            calls: Mutex::new(Vec::new()),
            sealed: None,
        }),
    );

    let one_shot_id = "one-shot-transfer";
    pump.bind(
        CONNECTION_A,
        MessageId::new(one_shot_id),
        route,
        authorization.clone(),
        ReplyRouteLifecycle::OneShot,
    )
    .expect("bind one-shot transfer");
    for index in 0..2 {
        let (_, write, acknowledged) = runtime_write(
            one_shot_id,
            RuntimeMessage::Reply(transfer_reply(one_shot_id, index, 2)),
        );
        pump.forward(CONNECTION_A, write)
            .await
            .expect("one-shot transfer part flushes");
        acknowledged.await.expect("one-shot transfer part ACKs");
    }
    let (_, stale_write, stale_acknowledged) = runtime_failure_write(one_shot_id);
    assert!(matches!(
        pump.forward(CONNECTION_A, stale_write).await,
        Err(RemoteLinkError::UnknownReplyRoute)
    ));
    assert!(stale_acknowledged.await.is_err());

    let sync_id = "sync-transfer";
    pump.bind(
        CONNECTION_A,
        MessageId::new(sync_id),
        route,
        authorization,
        ReplyRouteLifecycle::UntilSyncComplete,
    )
    .expect("bind sync lifecycle");
    let (_, transfer_write, transfer_acknowledged) = runtime_write(
        sync_id,
        RuntimeMessage::Reply(transfer_reply(sync_id, 0, 1)),
    );
    pump.forward(CONNECTION_A, transfer_write)
        .await
        .expect("final logical transfer part is not the sync terminal");
    transfer_acknowledged.await.expect("transfer part ACKs");
    let sync = RuntimeReply::SyncComplete(RuntimeSyncComplete {
        stream_generation: StreamGeneration::new("remote-link-sync-generation"),
        stream_cursor: StreamCursor::BeforeFirst,
        inner_cursor: RuntimeInnerCursor::Conversation {
            conversation_id: ConversationId::new("remote-link-sync-conversation"),
            cursor: StreamCursor::BeforeFirst,
        },
        key_directory_revision: 1,
    });
    let (_, sync_write, sync_acknowledged) = runtime_write(sync_id, RuntimeMessage::Reply(sync));
    pump.forward(CONNECTION_A, sync_write)
        .await
        .expect("SyncComplete closes the directed lifecycle");
    sync_acknowledged.await.expect("SyncComplete ACKs");
    let (_, stale_write, stale_acknowledged) = runtime_failure_write(sync_id);
    assert!(matches!(
        pump.forward(CONNECTION_A, stale_write).await,
        Err(RemoteLinkError::UnknownReplyRoute)
    ));
    assert!(stale_acknowledged.await.is_err());
    transport.shutdown().await;
}

#[tokio::test]
async fn identical_message_ids_on_distinct_connections_keep_exact_directed_reply_routes() {
    let authorization_a = RemoteReplyAuthorization::for_test(MACHINE, DEVICE_A, 1);
    let authorization_b = RemoteReplyAuthorization::for_test(MACHINE, DEVICE_B, 2);
    let route_a = DirectedReplyRoute {
        machine_route: MACHINE,
        device_route: DEVICE_A,
        request_route: REQUEST_A,
    };
    let route_b = DirectedReplyRoute {
        machine_route: MACHINE,
        device_route: DEVICE_B,
        request_route: REQUEST_B,
    };
    let (mut transport, _pairing_lane, harness) = active_pairing_transport_for_test(MACHINE);
    let business = transport.take_business_lane().expect("take business lane");
    let sealer = Arc::new(RecordingSealer {
        calls: Mutex::new(Vec::new()),
        sealed: None,
    });
    let mut pump = RemoteReplyPump::new(business, sealer.clone());
    let (message_a, write_a, acknowledged_a) = runtime_failure_write("same-message-id");
    let (message_b, write_b, acknowledged_b) = runtime_failure_write("same-message-id");
    assert_eq!(message_a, message_b);
    pump.bind(
        CONNECTION_A,
        message_a,
        route_a,
        authorization_a,
        ReplyRouteLifecycle::OneShot,
    )
    .expect("bind device A");
    pump.bind(
        CONNECTION_B,
        message_b,
        route_b,
        authorization_b,
        ReplyRouteLifecycle::OneShot,
    )
    .expect("bind device B with same messageId");
    pump.forward(CONNECTION_A, write_a)
        .await
        .expect("forward device A");
    acknowledged_a.await.expect("ACK device A");
    pump.forward(CONNECTION_B, write_b)
        .await
        .expect("forward device B");
    acknowledged_b.await.expect("ACK device B");
    {
        let calls = sealer.calls.lock().expect("read seal calls");
        assert_eq!(calls.len(), 2);
        assert_eq!(calls[0].route, route_a);
        assert_eq!(calls[1].route, route_b);
    }
    let sent = harness.sent_frames();
    let agentdeck_protocol::relay_v2::frame::RelayFrameBody::Reply(reply_a) = &sent[0].body else {
        panic!("device A must be Reply");
    };
    let agentdeck_protocol::relay_v2::frame::RelayFrameBody::Reply(reply_b) = &sent[1].body else {
        panic!("device B must be Reply");
    };
    assert_eq!(
        (reply_a.device_route, reply_a.request_route),
        (DEVICE_A, REQUEST_A)
    );
    assert_eq!(
        (reply_b.device_route, reply_b.request_route),
        (DEVICE_B, REQUEST_B)
    );
    transport.shutdown().await;
}
