//! P4.4 RemoteLink 边界与 P4.5 durable crypto/publication 接线回归。
//!
//! production 只冻结 reply sealer 的安全签名；其余组合经单个 test fixture 表达，避免为
//! RED 测试引入第二套 authorization Store/Core trait。

use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::{Arc, Mutex};

use agentdeck_protocol::e2ee::{KeyId, KeyPurpose, SignedSealedBlobV1, UnsignedSealedBlobV1};
use agentdeck_protocol::relay_v2::{
    DeviceRouteId, Ed25519Signature, MachineRouteId, OpaqueRouteFrame, RELAY_PROTOCOL_VERSION,
    RelayFrameBody, RequestRouteId,
};
use agentdeck_protocol::runtime::command::{RevokeRequest, RevokeTarget};
use agentdeck_protocol::runtime::failure::{
    DAEMON_AUTHORIZATION_PERMISSION_DENIED, DAEMON_RUNTIME_RECOVERY_BLOCKED,
};
use agentdeck_protocol::runtime::identity::{
    ConversationId, DeviceHandle, GrantSerial, IdempotencyKey, MessageId, StreamGeneration,
    TransferId,
};
use agentdeck_protocol::runtime::{
    ArtifactSha256, CatalogDelta, ConversationMetadataMutation,
    ConversationMetadataMutationRequest, ConversationMetadataReceipt, LocalOnlyAdministration,
    RUNTIME_PROTOCOL_VERSION, RevocationReceipt, RuntimeEnvelope, RuntimeFailure,
    RuntimeInnerCursor, RuntimeMessage, RuntimeReply, RuntimeRequest, RuntimeStreamItem,
    RuntimeSyncComplete, RuntimeTransferCarrierV1, RuntimeTransferChannel, StageUpgradeReceipt,
    StageUpgradeRequest, StreamCursor, TransferEnvelope,
};
use async_trait::async_trait;
use tokio::sync::oneshot::error::TryRecvError;

use crate::runtime::store::{RemoteReplyAuthorization, StreamBindingPermit};
use crate::runtime::{
    ConnectionId, ConnectionSink, ConnectionWrite, RemotePrincipalActivation,
    RevocationAdministration, RevocationAdministrationError,
};

use super::dispatch::{
    RemoteDispatchError,
    test_support::{
        active_remote_dispatch_for_test, active_remote_dispatch_with_recovery_blocked_for_test,
        active_remote_dispatch_with_revocation_for_test, two_active_remote_dispatch_for_test,
    },
};
use super::link::{
    DirectedReplyRoute, DirectedReplySeal, DirectedReplySealer, RemoteLinkError, RemoteLinkOwner,
    RemoteReplyPump, RemoteStreamPublisher, ReplyRouteBind, ReplyRouteLifecycle,
    UnavailableDirectedReplySealer, UnavailableRemoteStreamPublisher, send_directed_reply_for_test,
};
use super::replay::{ReplayDecision, ReplayError};
use super::transport::active_pairing_transport_for_test;

const MACHINE: MachineRouteId = MachineRouteId::from_bytes([0x32; 16]);
const DEVICE_A: DeviceRouteId = DeviceRouteId::from_bytes([0xd1; 16]);
const DEVICE_B: DeviceRouteId = DeviceRouteId::from_bytes([0xd2; 16]);
const REQUEST_A: RequestRouteId = RequestRouteId::from_bytes([0x64; 16]);
const REQUEST_B: RequestRouteId = RequestRouteId::from_bytes([0x65; 16]);
const CONNECTION_A: ConnectionId = ConnectionId::from_test_bytes([0xa1; 16]);
const CONNECTION_B: ConnectionId = ConnectionId::from_test_bytes([0xb2; 16]);

struct GatedSelfRevocationAdministration {
    entered: tokio::sync::mpsc::UnboundedSender<(DeviceHandle, GrantSerial)>,
    outcomes: tokio::sync::Mutex<tokio::sync::mpsc::UnboundedReceiver<Result<(), &'static str>>>,
}

type GatedSelfRevocationHarness = (
    Arc<GatedSelfRevocationAdministration>,
    tokio::sync::mpsc::UnboundedReceiver<(DeviceHandle, GrantSerial)>,
    tokio::sync::mpsc::UnboundedSender<Result<(), &'static str>>,
);

fn gated_self_revocation_administration() -> GatedSelfRevocationHarness {
    let (entered, entered_rx) = tokio::sync::mpsc::unbounded_channel();
    let (outcomes, outcome_rx) = tokio::sync::mpsc::unbounded_channel();
    (
        Arc::new(GatedSelfRevocationAdministration {
            entered,
            outcomes: tokio::sync::Mutex::new(outcome_rx),
        }),
        entered_rx,
        outcomes,
    )
}

#[async_trait]
impl RevocationAdministration for GatedSelfRevocationAdministration {
    async fn revoke_device(
        &self,
        device: DeviceHandle,
        grant_serial: GrantSerial,
    ) -> Result<RevocationReceipt, RevocationAdministrationError> {
        self.entered
            .send((device, grant_serial))
            .map_err(|_| RevocationAdministrationError::new("daemon.revocation.test_gate"))?;
        match self.outcomes.lock().await.recv().await {
            Some(Ok(())) => Ok(RevocationReceipt::Committed { grant_serial }),
            Some(Err(code)) => Err(RevocationAdministrationError::new(code)),
            None => Err(RevocationAdministrationError::new(
                "daemon.revocation.test_gate",
            )),
        }
    }
}

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

async fn wait_for_connection_count(
    owner: &RemoteLinkOwner,
    expected: usize,
    context: &'static str,
) {
    tokio::time::timeout(std::time::Duration::from_secs(2), async {
        while owner.connection_ids_for_test().len() != expected {
            tokio::task::yield_now().await;
        }
    })
    .await
    .unwrap_or_else(|_| {
        panic!(
            "{context}: connections={:?}",
            owner.connection_ids_for_test()
        )
    });
}

fn recorded_runtime_reply(call: &SealCall) -> RuntimeReply {
    let envelope: RuntimeEnvelope = serde_json::from_slice(&call.bytes)
        .expect("recorded sealer input is a canonical Runtime envelope");
    let RuntimeMessage::Reply(reply) = envelope.body else {
        panic!("recorded directed output must be a Runtime reply")
    };
    reply
}

/// 这条测试不接受由 `RemoteLinkFixture` 自报 core call/replay 数量。test support 只负责
/// 建立真实 Store authorization 与真实 DeviceSign/AEAD frame；阶段推进必须调用
/// production `dispatch.rs` 与 RuntimeCore 的两段 capability API。
#[tokio::test]
async fn production_dispatch_rechecks_then_durably_admits_before_core_activation() {
    let fixture = active_remote_dispatch_for_test(MACHINE, DEVICE_A).await;
    let frame = fixture.signed_runtime_send(
        REQUEST_A,
        MessageId::new("p44-two-stage-success"),
        RuntimeRequest::DescribeAgents,
        11,
    );

    let verified = fixture
        .dispatcher()
        .verify_send(frame.send().clone())
        .await
        .expect("canonical/signature/AAD/AEAD/Runtime Request chain verifies");
    assert_eq!(
        fixture.core().remote_registration_calls_for_test(),
        0,
        "crypto verification must not call RuntimeCore"
    );

    let current = fixture
        .dispatcher()
        .recheck_current(verified)
        .await
        .expect("unchanged Store authorization remains Current");
    assert_eq!(
        fixture.core().remote_registration_calls_for_test(),
        0,
        "final Store recheck still precedes RuntimeCore"
    );
    let admitted = fixture
        .dispatcher()
        .admit_replay(current)
        .await
        .expect("durable replay COMMIT succeeds after exact Active recheck");
    assert_eq!(admitted.decision(), ReplayDecision::Fresh);
    assert_eq!(fixture.core().remote_registration_calls_for_test(), 0);
    let activated = admitted
        .into_dispatchable()
        .expect("Fresh payload decrypts")
        .expect("Fresh replay tuple dispatches")
        .activate(fixture.core())
        .expect("Current proof activates the shared lease only after full verification");
    assert!(matches!(
        &activated.envelope().body,
        RuntimeMessage::Request(RuntimeRequest::DescribeAgents)
    ));
    let (_, reply_authorization, _, _, _, replay) = activated.into_parts();
    assert_eq!(replay, crate::runtime::RemoteIngressReplayClass::Fresh);
    assert_eq!(
        reply_authorization.trust_epoch().value(),
        1,
        "directed reply authorization carries the authenticated grant trust epoch"
    );
    assert_eq!(
        fixture.core().remote_registration_calls_for_test(),
        1,
        "only durable replay admission can release a Core capability"
    );
    fixture.shutdown().await;
}

#[tokio::test]
async fn two_pre_activated_fresh_self_revocations_only_enter_backend_once() {
    let (revocation, mut entered, outcomes) = gated_self_revocation_administration();
    let fixture =
        active_remote_dispatch_with_revocation_for_test(MACHINE, DEVICE_A, revocation).await;
    let core = fixture.core_arc();
    let first = fixture.signed_runtime_send(
        RequestRouteId::from_bytes([0x31; 16]),
        MessageId::new("fresh-self-revoke-pre-activated-a"),
        RuntimeRequest::Revoke(RevokeRequest {
            target: RevokeTarget::SelfDevice,
        }),
        31,
    );
    let second = fixture.signed_runtime_send(
        RequestRouteId::from_bytes([0x32; 16]),
        MessageId::new("fresh-self-revoke-pre-activated-b"),
        RuntimeRequest::Revoke(RevokeRequest {
            target: RevokeTarget::SelfDevice,
        }),
        32,
    );

    let mut activated = Vec::new();
    for send in [first.send(), second.send()] {
        let verified = fixture
            .dispatcher()
            .verify_send(send.clone())
            .await
            .expect("Fresh self-revoke passes DeviceSign/AAD/AEAD verification");
        let current = fixture
            .dispatcher()
            .recheck_current(verified)
            .await
            .expect("Fresh self-revoke remains current");
        let admitted = fixture
            .dispatcher()
            .admit_replay(current)
            .await
            .expect("Fresh self-revoke replay tuple commits");
        assert_eq!(admitted.decision(), ReplayDecision::Fresh);
        activated.push(
            admitted
                .into_dispatchable()
                .expect("Fresh self-revoke decrypts")
                .expect("Fresh self-revoke dispatches")
                .activate(fixture.core())
                .expect("both Fresh frames pre-activate while the shared lease is Active"),
        );
    }

    let first = activated.remove(0);
    let second = activated.remove(0);
    let (first_principal, _, first_envelope, _, _, first_replay) = first.into_parts();
    let (second_principal, _, second_envelope, _, _, second_replay) = second.into_parts();
    let RemotePrincipalActivation::NewOrExisting(first_principal) = first_principal else {
        panic!("Fresh Active self-revoke must use an ordinary Core connection")
    };
    let RemotePrincipalActivation::NewOrExisting(second_principal) = second_principal else {
        panic!("second Fresh Active self-revoke must also pre-activate normally")
    };
    // RemoteLink 会按 authorization key 复用既有 connection；第二个 activation 只证明
    // B 也在 Active 时越过 pre-Core 边界，真正 mutation 仍从同一 connection dispatch。
    drop(second_principal);
    let (sink, _writes) = tokio::sync::mpsc::channel::<ConnectionWrite>(2);
    let connection = core
        .connect(first_principal, ConnectionSink::new(sink))
        .expect("connect the shared pre-activated Fresh self-revoke principal");

    let first_handling = tokio::spawn({
        let core = core.clone();
        async move {
            core.handle_remote_envelope(connection, first_envelope, first_replay)
                .await
        }
    });
    let exact_target = (
        DeviceHandle::new(format!("device-{}", "d1".repeat(16))),
        GrantSerial::new(1),
    );
    assert_eq!(
        tokio::time::timeout(std::time::Duration::from_secs(2), entered.recv())
            .await
            .expect("first Fresh self-revoke backend deadline")
            .expect("first Fresh self-revoke enters backend"),
        exact_target
    );

    let mut second_handling = tokio::spawn({
        let core = core.clone();
        async move {
            core.handle_remote_envelope(connection, second_envelope, second_replay)
                .await
        }
    });
    let (second_completed, unexpected) =
        tokio::time::timeout(std::time::Duration::from_secs(2), async {
            tokio::select! {
                result = &mut second_handling => {
                    assert!(result.expect("join rejected second Fresh handler").is_ok());
                    (true, None)
                }
                observed = entered.recv() => {
                    (false, Some(observed.expect("self-revoke backend entry channel stays open")))
                }
            }
        })
        .await
        .expect("second Fresh must either be rejected or expose the duplicate backend entry");
    if let Some(unexpected) = unexpected {
        outcomes
            .send(Err("daemon.revocation.unexpected_first_fresh"))
            .expect("release first unexpected duplicate path");
        outcomes
            .send(Err("daemon.revocation.unexpected_second_fresh"))
            .expect("release second unexpected duplicate path");
        let _ = first_handling.await;
        let _ = second_handling.await;
        drop(core);
        fixture.shutdown().await;
        panic!("two distinct Fresh replay tuples entered the backend: {unexpected:?}");
    }
    assert!(
        second_completed,
        "the second Fresh handler must fail before backend"
    );
    outcomes
        .send(Err("daemon.revocation.expected_test_stop"))
        .expect("release the unique Fresh self-revoke");
    assert!(
        first_handling
            .await
            .expect("join first Fresh handler")
            .is_ok()
    );
    assert!(matches!(
        entered.try_recv(),
        Err(tokio::sync::mpsc::error::TryRecvError::Empty)
    ));

    drop(core);
    fixture.shutdown().await;
}

#[tokio::test]
async fn replay_commit_before_core_crash_retries_exact_into_runtime_idempotency() {
    let fixture = active_remote_dispatch_for_test(MACHINE, DEVICE_A).await;
    let frame = fixture.signed_runtime_send(
        REQUEST_A,
        MessageId::new("p45-replay-commit-before-core-crash"),
        RuntimeRequest::DescribeAgents,
        31,
    );

    let verified = fixture
        .dispatcher()
        .verify_send(frame.send().clone())
        .await
        .expect("first crypto chain");
    let current = fixture
        .dispatcher()
        .recheck_current(verified)
        .await
        .expect("first exact Active recheck");
    let committed_before_crash = fixture
        .dispatcher()
        .admit_replay(current)
        .await
        .expect("first durable replay COMMIT");
    assert_eq!(committed_before_crash.decision(), ReplayDecision::Fresh);
    drop(committed_before_crash);
    assert_eq!(
        fixture.core().remote_registration_calls_for_test(),
        0,
        "simulated crash point is after replay COMMIT but before Core"
    );

    let retry = fixture
        .dispatcher()
        .verify_send(frame.send().clone())
        .await
        .expect("exact retry crypto chain");
    let retry = fixture
        .dispatcher()
        .recheck_current(retry)
        .await
        .expect("exact retry Active recheck");
    let retry = fixture
        .dispatcher()
        .admit_replay(retry)
        .await
        .expect("exact retry reads durable replay state");
    assert_eq!(retry.decision(), ReplayDecision::ExactDuplicate);
    retry
        .into_dispatchable()
        .expect("ExactDuplicate payload decrypts")
        .expect("ExactDuplicate must re-enter RuntimeCore idempotency")
        .activate(fixture.core())
        .expect("exact retry activates Core capability");
    assert_eq!(fixture.core().remote_registration_calls_for_test(), 1);
    fixture.shutdown().await;
}

#[tokio::test]
async fn invalid_signature_aad_and_nonce_reuse_reject_without_wrong_core_registration() {
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
        fixture.dispatcher().verify_send(bad_signature).await,
        Err(RemoteDispatchError::InvalidSignature)
    ));
    assert_eq!(fixture.core().remote_registration_calls_for_test(), 0);

    let mut bad_aad = frame.send().clone();
    bad_aad.request_route = REQUEST_B;
    assert!(matches!(
        fixture.dispatcher().verify_send(bad_aad).await,
        Err(RemoteDispatchError::InvalidSignature)
    ));
    assert_eq!(fixture.core().remote_registration_calls_for_test(), 0);

    let verified = fixture
        .dispatcher()
        .verify_send(frame.send().clone())
        .await
        .expect("seed replay tuple crypto chain");
    let current = fixture
        .dispatcher()
        .recheck_current(verified)
        .await
        .expect("seed replay tuple Active recheck");
    let seeded = fixture
        .dispatcher()
        .admit_replay(current)
        .await
        .expect("seed replay tuple durably");
    assert_eq!(seeded.decision(), ReplayDecision::Fresh);

    let reuse = fixture.signed_runtime_send(
        RequestRouteId::from_bytes([0x66; 16]),
        MessageId::new("p45-valid-but-nonce-reused"),
        RuntimeRequest::DescribeAgents,
        frame.counter(),
    );
    let reuse = fixture
        .dispatcher()
        .verify_send(reuse.send().clone())
        .await
        .expect("nonce-reuse frame remains signature/AAD/AEAD valid");
    let reuse = fixture
        .dispatcher()
        .recheck_current(reuse)
        .await
        .expect("nonce-reuse frame remains exactly authorized");
    let reuse = fixture
        .dispatcher()
        .admit_replay(reuse)
        .await
        .expect_err("same counter with different ciphertext is isolated");
    assert!(reuse.requires_connection_isolation());
    assert_eq!(
        fixture.core().remote_registration_calls_for_test(),
        0,
        "all untrusted ingress failures must occur before the first RuntimeCore API"
    );
    fixture.shutdown().await;
}

#[tokio::test]
async fn signed_bad_tag_nonce_reuse_is_quarantined_before_aead_open() {
    let fixture = active_remote_dispatch_for_test(MACHINE, DEVICE_A).await;
    let first = fixture.signed_runtime_send(
        REQUEST_A,
        MessageId::new("p45-replay-before-aead-seed"),
        RuntimeRequest::DescribeAgents,
        42,
    );
    let verified = fixture
        .dispatcher()
        .verify_send(first.send().clone())
        .await
        .expect("seed frame verifies");
    let current = fixture
        .dispatcher()
        .recheck_current(verified)
        .await
        .expect("seed authorization remains current");
    assert_eq!(
        fixture
            .dispatcher()
            .admit_replay(current)
            .await
            .expect("seed tuple commits")
            .decision(),
        ReplayDecision::Fresh
    );

    let reuse_with_bad_tag = fixture.signed_runtime_send_with_tampered_ciphertext_for_test(
        REQUEST_B,
        MessageId::new("p45-replay-before-aead-reuse"),
        RuntimeRequest::DescribeAgents,
        first.counter(),
    );
    let verified = fixture
        .dispatcher()
        .verify_send(reuse_with_bad_tag.send().clone())
        .await
        .expect("valid DeviceSign must release the tuple before AEAD open");
    let current = fixture
        .dispatcher()
        .recheck_current(verified)
        .await
        .expect("reuse authorization remains current");
    let error =
        fixture.dispatcher().admit_replay(current).await.expect_err(
            "same counter with a different signed ciphertext must quarantine the scope",
        );
    assert!(matches!(error, ReplayError::NonceReuse));
    assert!(error.requires_connection_isolation());
    assert_eq!(fixture.core().remote_registration_calls_for_test(), 0);
    fixture.shutdown().await;
}

#[tokio::test]
async fn fresh_signed_bad_tag_consumes_counter_before_returning_ciphertext_error() {
    let fixture = active_remote_dispatch_for_test(MACHINE, DEVICE_A).await;
    let bad_tag = fixture.signed_runtime_send_with_tampered_ciphertext_for_test(
        REQUEST_A,
        MessageId::new("p45-fresh-bad-tag"),
        RuntimeRequest::DescribeAgents,
        43,
    );
    let verified = fixture
        .dispatcher()
        .verify_send(bad_tag.send().clone())
        .await
        .expect("valid DeviceSign releases fresh tuple before AEAD open");
    let current = fixture
        .dispatcher()
        .recheck_current(verified)
        .await
        .expect("fresh bad-tag authorization remains current");
    let admitted = fixture
        .dispatcher()
        .admit_replay(current)
        .await
        .expect("fresh bad-tag tuple is durably consumed");
    assert_eq!(admitted.decision(), ReplayDecision::Fresh);
    assert!(matches!(
        admitted.into_route(),
        Err(RemoteDispatchError::InvalidCiphertext)
    ));

    let verified = fixture
        .dispatcher()
        .verify_send(bad_tag.send().clone())
        .await
        .expect("exact bad-tag retry still verifies DeviceSign");
    let current = fixture
        .dispatcher()
        .recheck_current(verified)
        .await
        .expect("exact bad-tag retry remains current");
    let admitted = fixture
        .dispatcher()
        .admit_replay(current)
        .await
        .expect("exact bad-tag retry reads the consumed tuple");
    assert_eq!(admitted.decision(), ReplayDecision::ExactDuplicate);
    assert!(matches!(
        admitted.into_route(),
        Err(RemoteDispatchError::InvalidCiphertext)
    ));
    assert_eq!(fixture.core().remote_registration_calls_for_test(), 0);
    fixture.shutdown().await;
}

#[tokio::test]
async fn real_remote_link_allows_only_exact_self_revoke_after_backend_failure() {
    let (revocation, mut entered, outcomes) = gated_self_revocation_administration();
    let fixture =
        active_remote_dispatch_with_revocation_for_test(MACHINE, DEVICE_A, revocation).await;
    let core = fixture.core_arc();
    let (mut transport, _pairing_lane, harness) = active_pairing_transport_for_test(MACHINE);
    let business = transport
        .take_business_lane()
        .expect("take self-revoke retry business lane");
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
    .expect("start self-revoke retry RemoteLink");
    let exact_target = (
        DeviceHandle::new(format!("device-{}", "d1".repeat(16))),
        GrantSerial::new(1),
    );

    let first = fixture.signed_runtime_send(
        RequestRouteId::from_bytes([0x41; 16]),
        MessageId::new("remote-self-revoke-first"),
        RuntimeRequest::Revoke(RevokeRequest {
            target: RevokeTarget::SelfDevice,
        }),
        51,
    );
    harness
        .push_frame(business_frame(first.send().clone()))
        .await;
    assert_eq!(
        tokio::time::timeout(std::time::Duration::from_secs(2), entered.recv())
            .await
            .expect("first RemoteLink self-revoke backend deadline")
            .expect("first RemoteLink self-revoke backend entry"),
        exact_target
    );
    outcomes
        .send(Err("daemon.revocation.remote_self_test_failure"))
        .expect("release first RemoteLink self-revoke with failure");
    wait_for_sent(
        &harness,
        1,
        "backend failure returns one ordinary Runtime reply",
    )
    .await;
    assert!(matches!(
        recorded_runtime_reply(
            sealer
                .calls
                .lock()
                .expect("read first self-revoke reply")
                .first()
                .expect("first self-revoke reply was sealed"),
        ),
        RuntimeReply::Failure(RuntimeFailure { ref code, .. })
            if code == "daemon.revocation.remote_self_test_failure"
    ));

    transport
        .reconnect()
        .await
        .expect("replace generation after pre-owner self-revoke failure");
    wait_for_connection_count(
        &owner,
        0,
        "generation replacement removes the failed self-revoke connection",
    )
    .await;
    let blocked_business = fixture.signed_runtime_send(
        RequestRouteId::from_bytes([0x42; 16]),
        MessageId::new("business-after-self-revoke-failure"),
        RuntimeRequest::DescribeAgents,
        52,
    );
    let fresh_self_revoke = fixture.signed_runtime_send(
        RequestRouteId::from_bytes([0x43; 16]),
        MessageId::new("fresh-self-revoke-after-failure"),
        RuntimeRequest::Revoke(RevokeRequest {
            target: RevokeTarget::SelfDevice,
        }),
        53,
    );
    for rejected in [blocked_business.send(), fresh_self_revoke.send()] {
        let verified = fixture
            .dispatcher()
            .verify_send(rejected.clone())
            .await
            .expect("post-failure frame passes DeviceSign/AAD verification");
        let current = fixture
            .dispatcher()
            .recheck_current(verified)
            .await
            .expect("post-failure frame remains current");
        let admitted = fixture
            .dispatcher()
            .admit_replay(current)
            .await
            .expect("post-failure Fresh replay tuple commits");
        assert_eq!(admitted.decision(), ReplayDecision::Fresh);
        let dispatchable = admitted
            .into_dispatchable()
            .expect("post-failure frame decrypts")
            .expect("post-failure Fresh frame dispatches");
        assert!(matches!(
            dispatchable.activate(fixture.core()),
            Err(RemoteDispatchError::AuthorizationDenied)
        ));
    }
    assert!(matches!(
        entered.try_recv(),
        Err(tokio::sync::mpsc::error::TryRecvError::Empty)
    ));
    harness
        .push_frame(business_frame(first.send().clone()))
        .await;
    assert_eq!(
        tokio::time::timeout(std::time::Duration::from_secs(2), entered.recv())
            .await
            .expect("exact RemoteLink self-revoke retry deadline")
            .expect("exact RemoteLink self-revoke retry entry"),
        exact_target,
        "only the immutable exact self-revoke may cross a Revoking lease after reconnect"
    );
    assert_eq!(
        harness.sent_count(),
        1,
        "ordinary business must remain rejected before Core while the lease is Revoking"
    );
    outcomes
        .send(Ok(()))
        .expect("release exact RemoteLink self-revoke retry with success");
    wait_for_connection_count(
        &owner,
        0,
        "successful self-revoke disconnects exact principal",
    )
    .await;
    assert_eq!(
        harness.sent_count(),
        1,
        "ordinary Runtime success is not the MachineRoot-signed cleanup terminal"
    );

    owner
        .shutdown()
        .await
        .expect("shutdown self-revoke retry RemoteLink");
    transport.shutdown().await;
    drop(core);
    fixture.shutdown().await;
}

#[tokio::test]
async fn generation_replacement_cannot_cancel_admitted_self_revocation() {
    let (revocation, mut entered, outcomes) = gated_self_revocation_administration();
    let fixture =
        active_remote_dispatch_with_revocation_for_test(MACHINE, DEVICE_A, revocation).await;
    let core = fixture.core_arc();
    let ingress = fixture
        .store()
        .load_active_remote_ingress(MACHINE, DEVICE_A)
        .await
        .expect("load exact generation-cancellation principal");
    let registered = core
        .register_remote_principal(&ingress)
        .expect("register exact generation-cancellation principal");
    let current = fixture
        .store()
        .recheck_active_remote_ingress(&ingress)
        .await
        .expect("recheck exact generation-cancellation principal");
    let principal = core
        .activate_registered_remote_principal(registered, &current)
        .expect("activate exact generation-cancellation principal");
    let held_guard = principal
        .try_enter()
        .expect("hold one in-flight permission across the revoke fence");

    let (mut transport, _pairing_lane, harness) = active_pairing_transport_for_test(MACHINE);
    let business = transport
        .take_business_lane()
        .expect("take generation-cancellation business lane");
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
    .expect("start generation-cancellation RemoteLink");
    let request = fixture.signed_runtime_send(
        RequestRouteId::from_bytes([0x44; 16]),
        MessageId::new("remote-self-revoke-generation-replaced"),
        RuntimeRequest::Revoke(RevokeRequest {
            target: RevokeTarget::SelfDevice,
        }),
        61,
    );
    harness
        .push_frame(business_frame(request.send().clone()))
        .await;
    tokio::time::timeout(std::time::Duration::from_secs(2), async {
        while principal.is_active() {
            tokio::task::yield_now().await;
        }
    })
    .await
    .expect("self-revoke reaches the shared Revoking fence");
    wait_for_connection_count(&owner, 1, "self-revoke creates one exact Core connection").await;

    transport
        .reconnect()
        .await
        .expect("replace authenticated business generation");
    wait_for_connection_count(
        &owner,
        0,
        "generation replacement removes the stale virtual connection",
    )
    .await;
    drop(held_guard);
    assert_eq!(
        tokio::time::timeout(std::time::Duration::from_secs(2), entered.recv())
            .await
            .expect("generation replacement must not cancel the safety mutation")
            .expect("self-revoke backend still receives the exact target"),
        (
            DeviceHandle::new(format!("device-{}", "d1".repeat(16))),
            GrantSerial::new(1),
        )
    );
    outcomes
        .send(Ok(()))
        .expect("complete generation-safe self-revoke");
    tokio::time::timeout(std::time::Duration::from_secs(2), async {
        while !principal.is_revoked() {
            tokio::task::yield_now().await;
        }
    })
    .await
    .expect("principal publishes Revoked after durable completion");

    owner
        .shutdown()
        .await
        .expect("shutdown generation-cancellation RemoteLink");
    transport.shutdown().await;
    drop(core);
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
        while harness.sent_count() != 4 {
            tokio::task::yield_now().await;
        }
    })
    .await
    .expect("exact duplicate re-enters Core and healthy sibling also proceeds");
    assert_eq!(
        sealer.calls.lock().expect("read replay calls").len(),
        4,
        "exact duplicate must reach RuntimeCore durable idempotency and sealer"
    );

    let current_revision = fixture.key_directory_revision(DEVICE_A);
    assert!(
        current_revision > 1,
        "fixture needs a lower signed revision"
    );
    let rollback_a = fixture.signed_runtime_send_with_revision(
        DEVICE_A,
        RequestRouteId::from_bytes([0x76; 16]),
        MessageId::new("revision-rollback-isolates-only-device-a"),
        RuntimeRequest::DescribeAgents,
        6,
        current_revision - 1,
    );
    harness
        .push_frame(business_frame(rollback_a.send().clone()))
        .await;
    wait_for_connection_count(
        &owner,
        1,
        "lower signed revision disconnects only Device A logical connection",
    )
    .await;
    assert_eq!(
        harness.sent_count(),
        4,
        "revision rollback never enters Core"
    );

    let sibling_after_rollback = fixture.signed_runtime_send(
        DEVICE_B,
        RequestRouteId::from_bytes([0x77; 16]),
        MessageId::new("device-b-after-device-a-revision-rollback"),
        RuntimeRequest::DescribeAgents,
        3,
    );
    harness
        .push_frame(business_frame(sibling_after_rollback.send().clone()))
        .await;
    wait_for_sent(
        &harness,
        5,
        "Device B remains served after Device A revision rollback isolation",
    )
    .await;

    let reconnect_a = fixture.signed_runtime_send(
        DEVICE_A,
        RequestRouteId::from_bytes([0x78; 16]),
        MessageId::new("device-a-reconnect-before-nonce-reuse"),
        RuntimeRequest::DescribeAgents,
        6,
    );
    harness
        .push_frame(business_frame(reconnect_a.send().clone()))
        .await;
    wait_for_sent(&harness, 6, "Device A reconnects with a fresh tuple").await;
    wait_for_connection_count(
        &owner,
        2,
        "both logical device connections exist before nonce-reuse isolation",
    )
    .await;

    let nonce_reuse_a = fixture.signed_runtime_send(
        DEVICE_A,
        RequestRouteId::from_bytes([0x79; 16]),
        MessageId::new("nonce-reuse-retires-device-a-epoch"),
        RuntimeRequest::DescribeAgents,
        healthy_a.counter(),
    );
    harness
        .push_frame(business_frame(nonce_reuse_a.send().clone()))
        .await;
    wait_for_connection_count(&owner, 1, "nonce reuse disconnects Device A").await;
    assert_eq!(harness.sent_count(), 6, "nonce reuse never enters Core");

    let sibling_after_nonce_reuse = fixture.signed_runtime_send(
        DEVICE_B,
        RequestRouteId::from_bytes([0x7a; 16]),
        MessageId::new("device-b-after-device-a-nonce-reuse"),
        RuntimeRequest::DescribeAgents,
        4,
    );
    harness
        .push_frame(business_frame(sibling_after_nonce_reuse.send().clone()))
        .await;
    wait_for_sent(
        &harness,
        7,
        "Device B remains served after Device A nonce-reuse isolation",
    )
    .await;

    let retired_epoch_a = fixture.signed_runtime_send(
        DEVICE_A,
        RequestRouteId::from_bytes([0x7b; 16]),
        MessageId::new("device-a-same-epoch-after-nonce-reuse"),
        RuntimeRequest::DescribeAgents,
        7,
    );
    let sibling_after_retired_retry = fixture.signed_runtime_send(
        DEVICE_B,
        RequestRouteId::from_bytes([0x7c; 16]),
        MessageId::new("device-b-after-device-a-retired-retry"),
        RuntimeRequest::DescribeAgents,
        5,
    );
    harness
        .push_frame(business_frame(retired_epoch_a.send().clone()))
        .await;
    harness
        .push_frame(business_frame(sibling_after_retired_retry.send().clone()))
        .await;
    wait_for_sent(
        &harness,
        8,
        "sibling proves same-epoch retry was processed and remained blocked",
    )
    .await;
    assert_eq!(owner.connection_ids_for_test().len(), 1);
    assert!(
        !harness.sent_frames().iter().any(|frame| matches!(
            &frame.body,
            RelayFrameBody::Reply(reply)
                if reply.device_route == DEVICE_A
                    && reply.request_route == RequestRouteId::from_bytes([0x7b; 16])
        )),
        "durably retired sender epoch must never re-enter Core or emit a reply"
    );
    assert_eq!(
        sealer.calls.lock().expect("read isolation calls").len(),
        8,
        "lower revision, nonce reuse, and retired-epoch retry must not reach sealer"
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
async fn remote_link_owner_reports_unexpected_transport_exit() {
    let fixture = active_remote_dispatch_for_test(MACHINE, DEVICE_A).await;
    let core = fixture.core_arc();
    let (mut transport, _pairing_lane, _harness) = active_pairing_transport_for_test(MACHINE);
    let business = transport
        .take_business_lane()
        .expect("take health-observed business lane");
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
    .expect("start health-observed RemoteLink");

    transport.shutdown().await;
    tokio::time::timeout(std::time::Duration::from_secs(2), async {
        while owner.observed_failure_code().is_none() {
            tokio::task::yield_now().await;
        }
    })
    .await
    .expect("unexpected transport EOF must become observable");
    assert_eq!(
        owner.observed_failure_code().as_deref(),
        Some("daemon.remote.link.actor_exited")
    );
    owner
        .shutdown()
        .await
        .expect("join exited RemoteLink owner");
    fixture.shutdown().await;
}

#[tokio::test]
async fn signature_aad_and_tag_failures_disconnect_only_the_claimed_device() {
    let fixture = two_active_remote_dispatch_for_test(MACHINE, DEVICE_A, DEVICE_B).await;
    let core = fixture.core_arc();
    let (mut transport, _pairing_lane, harness) = active_pairing_transport_for_test(MACHINE);
    let business = transport
        .take_business_lane()
        .expect("take crypto-isolation business lane");
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
    .expect("start crypto-isolation RemoteLink");

    let healthy_a_1 = fixture.signed_runtime_send(
        DEVICE_A,
        RequestRouteId::from_bytes([0x81; 16]),
        MessageId::new("crypto-isolation-a-1"),
        RuntimeRequest::DescribeAgents,
        1,
    );
    let healthy_b_1 = fixture.signed_runtime_send(
        DEVICE_B,
        RequestRouteId::from_bytes([0x82; 16]),
        MessageId::new("crypto-isolation-b-1"),
        RuntimeRequest::DescribeAgents,
        1,
    );
    harness
        .push_frame(business_frame(healthy_a_1.send().clone()))
        .await;
    harness
        .push_frame(business_frame(healthy_b_1.send().clone()))
        .await;
    wait_for_sent(
        &harness,
        2,
        "both devices establish logical Core connections",
    )
    .await;
    assert_eq!(owner.connection_ids_for_test().len(), 2);

    let mut bad_signature = fixture
        .signed_runtime_send(
            DEVICE_A,
            RequestRouteId::from_bytes([0x83; 16]),
            MessageId::new("crypto-isolation-bad-signature"),
            RuntimeRequest::DescribeAgents,
            2,
        )
        .send()
        .clone();
    let mut signed = SignedSealedBlobV1::from_wire_bytes(&bad_signature.sealed_blob.0)
        .expect("parse signature isolation frame");
    signed.signature.0[0] ^= 0x80;
    bad_signature.sealed_blob.0 = signed.to_wire_bytes();
    harness.push_frame(business_frame(bad_signature)).await;
    wait_for_connection_count(&owner, 1, "bad signature isolates Device A").await;

    let healthy_a_2 = fixture.signed_runtime_send(
        DEVICE_A,
        RequestRouteId::from_bytes([0x84; 16]),
        MessageId::new("crypto-isolation-a-2"),
        RuntimeRequest::DescribeAgents,
        2,
    );
    harness
        .push_frame(business_frame(healthy_a_2.send().clone()))
        .await;
    wait_for_sent(&harness, 3, "Device A reconnects after signature isolation").await;
    wait_for_connection_count(&owner, 2, "Device A has reconnected").await;

    let mut bad_aad = fixture
        .signed_runtime_send(
            DEVICE_A,
            RequestRouteId::from_bytes([0x85; 16]),
            MessageId::new("crypto-isolation-bad-aad"),
            RuntimeRequest::DescribeAgents,
            3,
        )
        .send()
        .clone();
    bad_aad.request_route = RequestRouteId::from_bytes([0x86; 16]);
    harness.push_frame(business_frame(bad_aad)).await;
    wait_for_connection_count(&owner, 1, "bad AAD isolates Device A").await;

    let healthy_a_3 = fixture.signed_runtime_send(
        DEVICE_A,
        RequestRouteId::from_bytes([0x87; 16]),
        MessageId::new("crypto-isolation-a-3"),
        RuntimeRequest::DescribeAgents,
        3,
    );
    harness
        .push_frame(business_frame(healthy_a_3.send().clone()))
        .await;
    wait_for_sent(&harness, 4, "Device A reconnects after AAD isolation").await;
    wait_for_connection_count(&owner, 2, "Device A reconnects a second time").await;

    let bad_tag = fixture.signed_runtime_send_with_tampered_ciphertext(
        DEVICE_A,
        RequestRouteId::from_bytes([0x88; 16]),
        MessageId::new("crypto-isolation-bad-tag"),
        RuntimeRequest::DescribeAgents,
        4,
    );
    harness
        .push_frame(business_frame(bad_tag.send().clone()))
        .await;
    wait_for_connection_count(&owner, 1, "bad AEAD tag isolates Device A").await;

    let healthy_b_2 = fixture.signed_runtime_send(
        DEVICE_B,
        RequestRouteId::from_bytes([0x89; 16]),
        MessageId::new("crypto-isolation-b-2"),
        RuntimeRequest::DescribeAgents,
        2,
    );
    harness
        .push_frame(business_frame(healthy_b_2.send().clone()))
        .await;
    wait_for_sent(
        &harness,
        5,
        "healthy sibling remains available after Device A crypto isolation",
    )
    .await;
    assert_eq!(
        sealer
            .calls
            .lock()
            .expect("read crypto-isolation calls")
            .len(),
        5,
        "signature/AAD/tag failures never reach RuntimeCore or the reply sealer"
    );

    owner
        .shutdown()
        .await
        .expect("shutdown crypto-isolation RemoteLink");
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
    let publisher = Arc::new(RecordingPublisher::default());
    let mut owner = RemoteLinkOwner::start(
        MACHINE,
        fixture.store(),
        business,
        Arc::downgrade(&core),
        sealer.clone(),
        publisher.clone(),
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
    assert_eq!(
        publisher.reconnects.load(Ordering::SeqCst),
        0,
        "ordinary authenticated business frames must not forge a reconnect wake"
    );

    harness.push_error("relay.client.connection_lost").await;
    tokio::time::timeout(std::time::Duration::from_secs(2), async {
        while transport.observed_failure_code().as_deref() != Some("relay.client.connection_lost") {
            tokio::task::yield_now().await;
        }
    })
    .await
    .expect("transient health failure becomes observable");
    for _ in 0..64 {
        tokio::task::yield_now().await;
    }
    assert_eq!(
        publisher.reconnects.load(Ordering::SeqCst),
        0,
        "transport health failure alone must not forge notify_reconnected"
    );
    transport
        .reconnect()
        .await
        .expect("replace failed MachineLink generation");
    assert_eq!(transport.observed_failure_code(), None);
    assert_eq!(harness.reconnect_count(), 1);
    tokio::time::timeout(std::time::Duration::from_secs(2), async {
        while publisher.reconnects.load(Ordering::SeqCst) != 1 {
            tokio::task::yield_now().await;
        }
    })
    .await
    .expect("generation replacement wakes the durable publication drive exactly once");
    for _ in 0..64 {
        tokio::task::yield_now().await;
    }
    assert_eq!(
        publisher.reconnects.load(Ordering::SeqCst),
        1,
        "only the authenticated generation replacement may emit one reconnect wake"
    );

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
async fn remote_link_shutdown_deadline_aborts_a_stuck_actor_without_unbounded_join() {
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

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn remote_link_shutdown_deadline_does_not_await_non_cooperative_main_after_abort() {
    let mut owner = RemoteLinkOwner::slow_main_for_shutdown_test(
        std::sync::Weak::new(),
        std::time::Duration::from_millis(20),
        std::time::Duration::from_millis(400),
    )
    .await;

    let result = tokio::time::timeout(std::time::Duration::from_millis(150), owner.shutdown())
        .await
        .expect("absolute deadline must include abort cleanup");
    assert!(matches!(result, Err(RemoteLinkError::ShutdownTimedOut)));
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn remote_link_shutdown_deadline_bounds_non_quiescing_child_tracker() {
    let mut owner = RemoteLinkOwner::slow_child_for_shutdown_test(
        std::sync::Weak::new(),
        std::time::Duration::from_millis(20),
        std::time::Duration::from_millis(400),
    )
    .await;

    let result = tokio::time::timeout(std::time::Duration::from_millis(150), owner.shutdown())
        .await
        .expect("child quiescence must share the owner's absolute deadline");
    assert!(matches!(result, Err(RemoteLinkError::ShutdownTimedOut)));
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

struct LineageDriftSealer {
    authorization_used: RemoteReplyAuthorization,
}

struct FailingPublisher;

struct BindingGateSealer {
    runtime_calls: AtomicUsize,
    binding_calls: AtomicUsize,
    expected_publication_generation: [u8; 16],
    binding_started: tokio::sync::Notify,
    release_binding: tokio::sync::Notify,
}

#[derive(Default)]
struct RecordingPublisher {
    calls: Mutex<Vec<Arc<[u8]>>>,
    transfer_calls: Mutex<Vec<RuntimeTransferCarrierV1>>,
    reconnects: AtomicUsize,
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
    ) -> Result<DirectedReplySeal, RemoteLinkError> {
        self.calls
            .lock()
            .expect("record sealer call")
            .push(SealCall {
                route,
                bytes: runtime_bytes,
            });
        Ok(DirectedReplySeal {
            authorization_used: authorization.clone(),
            sealed: self
                .sealed
                .clone()
                .unwrap_or_else(|| fake_signed_reply(authorization)),
        })
    }

    async fn seal_transfer_exact(
        &self,
        authorization: &RemoteReplyAuthorization,
        route: DirectedReplyRoute,
        carrier: RuntimeTransferCarrierV1,
    ) -> Result<DirectedReplySeal, RemoteLinkError> {
        let bytes: Arc<[u8]> = carrier
            .encode()
            .map_err(|_| RemoteLinkError::InvalidCoreEgress)?
            .into();
        self.calls
            .lock()
            .expect("record compact directed sealer call")
            .push(SealCall { route, bytes });
        Ok(DirectedReplySeal {
            authorization_used: authorization.clone(),
            sealed: self
                .sealed
                .clone()
                .unwrap_or_else(|| fake_signed_reply(authorization)),
        })
    }

    async fn seal_stream_binding_exact(
        &self,
        authorization: &RemoteReplyAuthorization,
        _route: DirectedReplyRoute,
        _permit: StreamBindingPermit,
    ) -> Result<SignedSealedBlobV1, RemoteLinkError> {
        Ok(self
            .sealed
            .clone()
            .unwrap_or_else(|| fake_signed_reply(authorization)))
    }
}

#[async_trait]
impl DirectedReplySealer for BindingGateSealer {
    fn admission_ready(&self) -> bool {
        true
    }

    async fn seal_exact(
        &self,
        authorization: &RemoteReplyAuthorization,
        _route: DirectedReplyRoute,
        _runtime_bytes: Arc<[u8]>,
    ) -> Result<DirectedReplySeal, RemoteLinkError> {
        self.runtime_calls.fetch_add(1, Ordering::SeqCst);
        Ok(DirectedReplySeal {
            authorization_used: authorization.clone(),
            sealed: fake_signed_reply(authorization),
        })
    }

    async fn seal_stream_binding_exact(
        &self,
        authorization: &RemoteReplyAuthorization,
        _route: DirectedReplyRoute,
        permit: StreamBindingPermit,
    ) -> Result<SignedSealedBlobV1, RemoteLinkError> {
        assert_eq!(
            permit.generation(),
            self.expected_publication_generation,
            "binding must consume Store publication generation, not Runtime local generation"
        );
        self.binding_calls.fetch_add(1, Ordering::SeqCst);
        self.binding_started.notify_one();
        self.release_binding.notified().await;
        Ok(fake_signed_reply(authorization))
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
    ) -> Result<DirectedReplySeal, RemoteLinkError> {
        Err(RemoteLinkError::ReplySealFailed)
    }
}

#[async_trait]
impl DirectedReplySealer for LineageDriftSealer {
    fn admission_ready(&self) -> bool {
        true
    }

    async fn seal_exact(
        &self,
        _authorization: &RemoteReplyAuthorization,
        _route: DirectedReplyRoute,
        _runtime_bytes: Arc<[u8]>,
    ) -> Result<DirectedReplySeal, RemoteLinkError> {
        Ok(DirectedReplySeal {
            authorization_used: self.authorization_used.clone(),
            sealed: fake_signed_reply(&self.authorization_used),
        })
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

    async fn publish_transfer_exact(
        &self,
        carrier: RuntimeTransferCarrierV1,
    ) -> Result<(), RemoteLinkError> {
        self.transfer_calls
            .lock()
            .expect("record transfer publisher call")
            .push(carrier);
        self.release.notified().await;
        Ok(())
    }

    async fn notify_reconnected(&self) -> Result<(), RemoteLinkError> {
        self.reconnects.fetch_add(1, Ordering::SeqCst);
        Ok(())
    }
}

#[async_trait]
impl RemoteStreamPublisher for FailingPublisher {
    fn admission_ready(&self) -> bool {
        true
    }

    async fn publish_exact(&self, _runtime_bytes: Arc<[u8]>) -> Result<(), RemoteLinkError> {
        Err(RemoteLinkError::StreamPublishFailed)
    }

    async fn publish_transfer_exact(
        &self,
        _carrier: RuntimeTransferCarrierV1,
    ) -> Result<(), RemoteLinkError> {
        Err(RemoteLinkError::StreamPublishFailed)
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

#[tokio::test]
async fn sync_complete_flushes_runtime_then_exact_binding_before_core_ack() {
    let (mut transport, _pairing_lane, harness) = active_pairing_transport_for_test(MACHINE);
    let business = transport
        .take_business_lane()
        .expect("take stream-binding business lane");
    let authorization = RemoteReplyAuthorization::for_test(MACHINE, DEVICE_A, 1);
    let route = DirectedReplyRoute {
        machine_route: MACHINE,
        device_route: DEVICE_A,
        request_route: REQUEST_A,
    };
    let sealer = Arc::new(BindingGateSealer {
        runtime_calls: AtomicUsize::new(0),
        binding_calls: AtomicUsize::new(0),
        expected_publication_generation: [0x73; 16],
        binding_started: tokio::sync::Notify::new(),
        release_binding: tokio::sync::Notify::new(),
    });
    let mut pump = RemoteReplyPump::new(business, sealer.clone());
    let message_id = MessageId::new("sync-with-store-binding");
    pump.bind(
        CONNECTION_A,
        message_id.clone(),
        route,
        authorization,
        ReplyRouteLifecycle::UntilSyncComplete,
    )
    .expect("bind subscription route");
    let sync = RuntimeReply::SyncComplete(RuntimeSyncComplete {
        // 故意与 publication generation 不同；binding 绝不能从这个本地值推导。
        stream_generation: StreamGeneration::new("11111111-1111-1111-1111-111111111111"),
        stream_cursor: StreamCursor::BeforeFirst,
        inner_cursor: RuntimeInnerCursor::Catalog {
            cursor: StreamCursor::BeforeFirst,
        },
        key_directory_revision: 0,
    });
    let bytes: Arc<[u8]> = RuntimeEnvelope {
        version: RUNTIME_PROTOCOL_VERSION,
        message_id,
        body: RuntimeMessage::Reply(sync),
    }
    .to_json_bytes_checked()
    .expect("encode SyncComplete")
    .into();
    let permit = StreamBindingPermit::for_test(
        crate::runtime::events::RuntimeStreamTarget::Catalog,
        [0x71; 16],
        [0x72; 16],
        [0x73; 16],
        StreamCursor::BeforeFirst,
        StreamCursor::BeforeFirst,
        1,
        KeyId {
            purpose: KeyPurpose::Catalog,
            epoch: 1,
        },
    );
    let (write, mut acknowledged) =
        ConnectionWrite::for_transport_test_with_stream_binding(bytes, permit);

    let forward = tokio::spawn(async move { pump.forward(CONNECTION_A, write).await });
    tokio::time::timeout(
        std::time::Duration::from_secs(2),
        sealer.binding_started.notified(),
    )
    .await
    .expect("binding sealing starts after Runtime SyncComplete flush");
    assert_eq!(
        harness.sent_count(),
        1,
        "Runtime SyncComplete flushes first"
    );
    assert_eq!(sealer.runtime_calls.load(Ordering::SeqCst), 1);
    assert_eq!(sealer.binding_calls.load(Ordering::SeqCst), 1);
    assert_eq!(
        acknowledged.try_recv(),
        Err(TryRecvError::Empty),
        "Core ACK must wait for binding seal and Relay flush"
    );

    sealer.release_binding.notify_waiters();
    forward
        .await
        .expect("binding forward joins")
        .expect("both directed frames flush");
    acknowledged
        .await
        .expect("Core ACK follows both directed frames");
    assert_eq!(harness.sent_count(), 2);
    transport.shutdown().await;
}

#[tokio::test]
async fn exact_inflight_route_bind_is_coalesced_before_a_second_core_dispatch() {
    let (mut transport, _pairing_lane, _harness) = active_pairing_transport_for_test(MACHINE);
    let business = transport
        .take_business_lane()
        .expect("take in-flight duplicate business lane");
    let mut pump = RemoteReplyPump::new(
        business,
        Arc::new(RecordingSealer {
            calls: Mutex::new(Vec::new()),
            sealed: None,
        }),
    );
    let authorization = RemoteReplyAuthorization::for_test(MACHINE, DEVICE_A, 1);
    let message_id = MessageId::new("inflight-exact-duplicate");
    let route = DirectedReplyRoute {
        machine_route: MACHINE,
        device_route: DEVICE_A,
        request_route: REQUEST_A,
    };

    assert_eq!(
        pump.bind(
            CONNECTION_A,
            message_id.clone(),
            route,
            authorization.clone(),
            ReplyRouteLifecycle::OneShot,
        )
        .expect("first request installs its route"),
        ReplyRouteBind::Inserted
    );
    assert_eq!(
        pump.bind(
            CONNECTION_A,
            message_id,
            route,
            authorization,
            ReplyRouteLifecycle::OneShot,
        )
        .expect("exact in-flight retry reuses the same route"),
        ReplyRouteBind::ExistingExact
    );

    transport.shutdown().await;
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

#[tokio::test]
async fn directed_reply_rejects_sealer_authorization_lineage_drift_without_send_or_ack() {
    let frozen = RemoteReplyAuthorization::for_test(MACHINE, DEVICE_A, 1);
    let drifted = RemoteReplyAuthorization::for_test(MACHINE, DEVICE_A, 2);
    let route = DirectedReplyRoute {
        machine_route: MACHINE,
        device_route: DEVICE_A,
        request_route: REQUEST_A,
    };
    let (mut transport, _pairing_lane, harness) = active_pairing_transport_for_test(MACHINE);
    let business = transport
        .take_business_lane()
        .expect("take lineage-drift business lane");
    let mut pump = RemoteReplyPump::new(
        business,
        Arc::new(LineageDriftSealer {
            authorization_used: drifted,
        }),
    );
    let (message_id, write, acknowledged) = runtime_failure_write("lineage-drift");
    pump.bind(
        CONNECTION_A,
        message_id,
        route,
        frozen,
        ReplyRouteLifecycle::OneShot,
    )
    .expect("bind frozen route before lineage drift");
    assert!(matches!(
        pump.forward(CONNECTION_A, write).await,
        Err(RemoteLinkError::ReplyAuthorizationMismatch)
    ));
    assert!(
        acknowledged.await.is_err(),
        "lineage drift must drop the Core write without ACK"
    );
    assert_eq!(harness.sent_count(), 0);
    transport.shutdown().await;
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

#[tokio::test]
async fn compact_stream_uses_typed_publisher_and_compact_reply_uses_directed_sealer() {
    let (mut transport, _pairing_lane, harness) = active_pairing_transport_for_test(MACHINE);
    let business = transport
        .take_business_lane()
        .expect("take compact stream business lane");
    let publisher = Arc::new(RecordingPublisher::default());
    let sealer = Arc::new(RecordingSealer {
        calls: Mutex::new(Vec::new()),
        sealed: None,
    });
    let mut pump =
        RemoteReplyPump::new(business, sealer.clone()).with_stream_publisher(publisher.clone());
    let transfer = TransferEnvelope::new(
        TransferId::new("compact-stream-transfer"),
        0,
        1,
        [0x71; 32],
        3,
        vec![1, 2, 3],
    )
    .expect("valid compact part");
    let stream_carrier = RuntimeTransferCarrierV1::new(
        MessageId::new("compact-stream-message"),
        RuntimeTransferChannel::Stream,
        transfer.clone(),
    );
    let (stream_write, mut stream_acknowledged) =
        ConnectionWrite::for_compact_transfer_test(&stream_carrier)
            .expect("encode typed compact write");
    let mut publish = Box::pin(pump.forward(CONNECTION_A, stream_write));
    tokio::time::timeout(std::time::Duration::from_millis(250), async {
        loop {
            if !publisher
                .transfer_calls
                .lock()
                .expect("observe compact publisher start")
                .is_empty()
            {
                break;
            }
            tokio::select! {
                result = publish.as_mut() => {
                    panic!("compact publisher returned before held boundary: {result:?}");
                }
                () = tokio::task::yield_now() => {}
            }
        }
    })
    .await
    .expect("compact Stream reaches typed publisher");
    assert_eq!(stream_acknowledged.try_recv(), Err(TryRecvError::Empty));
    assert!(publisher.calls.lock().expect("JSON calls").is_empty());
    assert_eq!(
        publisher.transfer_calls.lock().expect("transfer calls")[0],
        stream_carrier
    );
    publisher.release.notify_one();
    publish.as_mut().await.expect("compact publisher succeeds");
    drop(publish);
    stream_acknowledged
        .await
        .expect("typed publisher success ACKs write");

    let reply_message_id = MessageId::new("compact-reply-message");
    let reply_carrier = RuntimeTransferCarrierV1::new(
        reply_message_id.clone(),
        RuntimeTransferChannel::Reply,
        transfer,
    );
    let authorization = RemoteReplyAuthorization::for_test(MACHINE, DEVICE_A, 1);
    let route = DirectedReplyRoute {
        machine_route: MACHINE,
        device_route: DEVICE_A,
        request_route: REQUEST_A,
    };
    pump.bind(
        CONNECTION_A,
        reply_message_id,
        route,
        authorization,
        ReplyRouteLifecycle::OneShot,
    )
    .expect("bind compact reply to its exact device/request route");
    let (reply_write, reply_acknowledged) =
        ConnectionWrite::for_compact_transfer_test(&reply_carrier)
            .expect("encode compact reply write");
    pump.forward(CONNECTION_A, reply_write)
        .await
        .expect("compact Reply seals with DeviceReplyTx and flushes as Relay Reply");
    reply_acknowledged
        .await
        .expect("compact Reply ACK waits for directed Relay flush");
    assert_eq!(
        publisher
            .transfer_calls
            .lock()
            .expect("transfer calls")
            .len(),
        1
    );
    assert_eq!(
        sealer.calls.lock().expect("directed transfer calls").len(),
        1
    );
    assert_eq!(harness.sent_count(), 1);
    let sent = harness.sent_frames();
    let RelayFrameBody::Reply(reply) = &sent[0].body else {
        panic!("compact Reply must use Relay Reply, never shared Publish");
    };
    assert_eq!(
        (reply.device_route, reply.request_route),
        (DEVICE_A, REQUEST_A)
    );
    transport.shutdown().await;
}

#[tokio::test]
async fn json_and_compact_publication_failures_drop_core_writes_without_ack() {
    let (mut transport, _pairing_lane, harness) = active_pairing_transport_for_test(MACHINE);
    let business = transport
        .take_business_lane()
        .expect("take publication-failure business lane");
    let mut pump = RemoteReplyPump::new(
        business,
        Arc::new(RecordingSealer {
            calls: Mutex::new(Vec::new()),
            sealed: None,
        }),
    )
    .with_stream_publisher(Arc::new(FailingPublisher));

    let (_message_id, json_write, json_acknowledged) = runtime_write(
        "json-publication-failure",
        RuntimeMessage::Stream(RuntimeStreamItem::CatalogDelta(CatalogDelta {
            catalog_revision: 23,
            changes: Vec::new(),
        })),
    );
    assert!(matches!(
        pump.forward(CONNECTION_A, json_write).await,
        Err(RemoteLinkError::StreamPublishFailed)
    ));
    assert!(
        json_acknowledged.await.is_err(),
        "JSON publication failure must drop the Core write without ACK"
    );

    let transfer = TransferEnvelope::new(
        TransferId::new("compact-publication-failure"),
        0,
        1,
        [0x72; 32],
        3,
        vec![4, 5, 6],
    )
    .expect("valid failing compact part");
    let carrier = RuntimeTransferCarrierV1::new(
        MessageId::new("compact-publication-failure"),
        RuntimeTransferChannel::Stream,
        transfer,
    );
    let (compact_write, compact_acknowledged) =
        ConnectionWrite::for_compact_transfer_test(&carrier).expect("encode failing compact write");
    assert!(matches!(
        pump.forward(CONNECTION_A, compact_write).await,
        Err(RemoteLinkError::StreamPublishFailed)
    ));
    assert!(
        compact_acknowledged.await.is_err(),
        "compact publication failure must drop the Core write without ACK"
    );
    assert_eq!(harness.sent_count(), 0, "publisher errors never emit Reply");

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
    let sync_conversation = crate::runtime::store::RuntimeId::from_bytes(
        crate::runtime::store::RuntimeIdKind::Conversation,
        [0x66; 16],
    )
    .expect("sync conversation id");
    let sync = RuntimeReply::SyncComplete(RuntimeSyncComplete {
        stream_generation: StreamGeneration::new("remote-link-sync-generation"),
        stream_cursor: StreamCursor::BeforeFirst,
        inner_cursor: RuntimeInnerCursor::Conversation {
            conversation_id: ConversationId::new(sync_conversation.to_canonical_string()),
            cursor: StreamCursor::BeforeFirst,
        },
        key_directory_revision: 1,
    });
    let sync_bytes: Arc<[u8]> = RuntimeEnvelope {
        version: RUNTIME_PROTOCOL_VERSION,
        message_id: MessageId::new(sync_id),
        body: RuntimeMessage::Reply(sync),
    }
    .to_json_bytes_checked()
    .expect("encode lifecycle SyncComplete")
    .into();
    let permit = StreamBindingPermit::for_test(
        crate::runtime::events::RuntimeStreamTarget::Conversation(sync_conversation),
        [0x67; 16],
        [0x68; 16],
        [0x69; 16],
        StreamCursor::BeforeFirst,
        StreamCursor::BeforeFirst,
        1,
        KeyId {
            purpose: KeyPurpose::ConversationDek,
            epoch: 1,
        },
    );
    let (sync_write, sync_acknowledged) =
        ConnectionWrite::for_transport_test_with_stream_binding(sync_bytes, permit);
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
