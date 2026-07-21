//! P4.4 RemoteTransport RED：唯一 MachineLink session 必须新增独立、有界的业务 lane。
//!
//! 本组先只使用 P4.2 已存在的私有 transport harness，因此在 RemoteLink API 尚未出现时
//! 仍可编译并给出行为级 RED；完整 link/dispatch RED 另见 integration contract。

use std::time::Duration;

use agentdeck_protocol::relay_v2::frame::{
    AcceptedRef, OpaqueRouteFrame, RelayFrameBody, Reply, RouteAccepted, SealedBlob, Send,
};
use agentdeck_protocol::relay_v2::{
    DeviceRouteId, MachineRouteId, RELAY_PROTOCOL_VERSION, RequestRouteId,
};

use super::transport::{BusinessTransportEvent, active_pairing_transport_for_test};

const MACHINE: MachineRouteId = MachineRouteId::from_bytes([0x41; 16]);
const DEVICE: DeviceRouteId = DeviceRouteId::from_bytes([0x42; 16]);
const REQUEST: RequestRouteId = RequestRouteId::from_bytes([0x43; 16]);

fn send(request_route: RequestRouteId, payload: u8) -> OpaqueRouteFrame {
    OpaqueRouteFrame {
        version: RELAY_PROTOCOL_VERSION,
        body: RelayFrameBody::Send(Send {
            device_route: DEVICE,
            request_route,
            sealed_blob: SealedBlob(vec![payload]),
        }),
    }
}

fn request_accepted(request_route: RequestRouteId) -> OpaqueRouteFrame {
    OpaqueRouteFrame {
        version: RELAY_PROTOCOL_VERSION,
        body: RelayFrameBody::RouteAccepted(RouteAccepted {
            accepted: AcceptedRef::Request { request_route },
        }),
    }
}

#[tokio::test]
async fn machine_link_send_is_not_rejected_by_the_existing_control_supervisor() {
    let (mut transport, _pairing_lane, harness) = active_pairing_transport_for_test(MACHINE);
    let _business = transport
        .take_business_lane()
        .expect("activate business lane before ingress");

    harness.push_frame(send(REQUEST, 0x51)).await;

    let control = tokio::time::timeout(Duration::from_millis(100), transport.next_control()).await;
    assert!(
        control.is_err(),
        "valid Send must wait in the bounded business lane, never poison the shared control supervisor: {control:?}"
    );
    assert_eq!(harness.sent_count(), 0, "ingress Send is not echoed");
    transport.shutdown().await;
}

#[tokio::test]
async fn request_route_accepted_is_not_pairing_or_runtime_command_success() {
    let (mut transport, mut pairing_lane, harness) = active_pairing_transport_for_test(MACHINE);
    let mut business = transport
        .take_business_lane()
        .expect("activate business lane before acceptance");

    harness.push_frame(request_accepted(REQUEST)).await;

    let pairing = tokio::time::timeout(Duration::from_millis(100), pairing_lane.next_event()).await;
    assert!(
        pairing.is_err(),
        "request RouteAccepted belongs to the business lane, not pairing: {pairing:?}"
    );
    assert!(matches!(
        business.next_event().await,
        Ok(Some(BusinessTransportEvent::RouteAccepted(_)))
    ));
    let control = tokio::time::timeout(Duration::from_millis(100), transport.next_control()).await;
    assert!(
        control.is_err(),
        "request RouteAccepted must not become a control failure or a Runtime reply: {control:?}"
    );
    assert_eq!(
        harness.sent_count(),
        0,
        "RouteAccepted is transport-only and must not synthesize command success"
    );
    transport.shutdown().await;
}

#[tokio::test]
async fn business_frame_without_a_taken_lane_fails_closed() {
    let (mut transport, _pairing_lane, harness) = active_pairing_transport_for_test(MACHINE);
    harness.push_frame(send(REQUEST, 0x52)).await;

    let control = tokio::time::timeout(Duration::from_millis(100), transport.next_control())
        .await
        .expect("unowned business ingress closes the generation");
    assert!(matches!(
        control,
        Err(super::transport::RemoteTransportError::BusinessLaneUnavailable)
    ));
    transport.shutdown().await;
}

#[test]
fn business_lane_reuses_the_only_relay_client_and_is_explicitly_bounded() {
    let source = include_str!("transport.rs");
    assert_eq!(
        source.matches("RelayClient::connect(").count(),
        1,
        "P4.4 must extend the existing MachineLink session, not create a second WSS/client"
    );
    assert!(
        source.contains("BUSINESS_EVENT_CHANNEL_CAPACITY"),
        "business ingress needs an explicit frame bound"
    );
    assert!(
        source.contains("BUSINESS_EVENT_BYTES_CAPACITY"),
        "business ingress needs an explicit byte bound"
    );
}

#[tokio::test]
async fn bounded_business_lane_delivers_send_and_request_acceptance_as_distinct_events() {
    let (mut transport, _pairing_lane, harness) = active_pairing_transport_for_test(MACHINE);
    let mut business = transport
        .take_business_lane()
        .expect("take business lane once");

    harness.push_frame(send(REQUEST, 0x61)).await;
    let Some(BusinessTransportEvent::Send(frame)) =
        business.next_event().await.expect("valid business frame")
    else {
        panic!("Send must retain its typed business event");
    };
    assert_eq!(frame.request_route, REQUEST);
    assert_eq!(frame.sealed_blob.0, vec![0x61]);

    harness.push_frame(request_accepted(REQUEST)).await;
    let Some(BusinessTransportEvent::RouteAccepted(accepted)) = business
        .next_event()
        .await
        .expect("valid request acceptance")
    else {
        panic!("request RouteAccepted must stay transport-only");
    };
    assert_eq!(
        accepted.accepted,
        AcceptedRef::Request {
            request_route: REQUEST
        }
    );
    transport.shutdown().await;
}

#[tokio::test]
async fn reconnect_drops_a_buffered_business_event_from_the_stale_generation() {
    let (mut transport, _pairing_lane, harness) = active_pairing_transport_for_test(MACHINE);
    let mut business = transport
        .take_business_lane()
        .expect("take business lane once");

    harness.push_frame(send(REQUEST, 0x71)).await;
    tokio::time::timeout(Duration::from_millis(250), async {
        while harness.received_count() != 1 {
            tokio::task::yield_now().await;
        }
    })
    .await
    .expect("old frame reaches generation-tagged lane queue");
    transport
        .reconnect()
        .await
        .expect("reconnect same MachineLink");

    let replacement = business
        .next_event()
        .await
        .expect("replacement remains readable")
        .expect("replacement is concrete");
    assert!(matches!(
        replacement,
        BusinessTransportEvent::GenerationReplaced { .. }
    ));

    let fresh_route = RequestRouteId::from_bytes([0x44; 16]);
    harness.push_frame(send(fresh_route, 0x72)).await;
    let Some(BusinessTransportEvent::Send(fresh)) = business
        .next_event()
        .await
        .expect("fresh generation remains readable")
    else {
        panic!("fresh Send remains typed");
    };
    assert_eq!(fresh.request_route, fresh_route);
    assert_eq!(fresh.sealed_blob.0, vec![0x72]);
    assert_eq!(harness.reconnect_count(), 1);
    transport.shutdown().await;
}

#[tokio::test]
async fn transient_transport_health_keeps_the_unique_business_lane_until_reconnect() {
    let (mut transport, _pairing_lane, harness) = active_pairing_transport_for_test(MACHINE);
    let mut business = transport
        .take_business_lane()
        .expect("take business lane once");

    harness.push_error("relay.client.connection_lost").await;
    tokio::time::timeout(Duration::from_millis(250), async {
        while transport.observed_failure_code().as_deref() != Some("relay.client.connection_lost") {
            tokio::task::yield_now().await;
        }
    })
    .await
    .expect("manager-visible health observes the transient failure");
    assert!(
        tokio::time::timeout(Duration::from_millis(100), business.next_event())
            .await
            .is_err(),
        "business lane must wait without returning an error or hot-looping while reconnect is pending"
    );

    transport
        .reconnect()
        .await
        .expect("same supervisor reconnects without reacquiring the lane");
    assert!(matches!(
        business
            .next_event()
            .await
            .expect("lane remains healthy after reconnect"),
        Some(BusinessTransportEvent::GenerationReplaced { .. })
    ));

    let fresh_route = RequestRouteId::from_bytes([0x45; 16]);
    harness.push_frame(send(fresh_route, 0x73)).await;
    let Some(BusinessTransportEvent::Send(fresh)) = business
        .next_event()
        .await
        .expect("fresh generation remains readable")
    else {
        panic!("fresh Send remains typed after recovery");
    };
    assert_eq!(fresh.request_route, fresh_route);
    assert_eq!(harness.reconnect_count(), 1);
    transport.shutdown().await;
}

#[tokio::test]
async fn successful_reconnect_explicitly_notifies_the_business_lane_of_generation_replacement() {
    let (mut transport, _pairing_lane, _harness) = active_pairing_transport_for_test(MACHINE);
    let mut business = transport
        .take_business_lane()
        .expect("take business lane before reconnect");

    transport
        .reconnect()
        .await
        .expect("replace the authenticated MachineLink generation");
    let event = tokio::time::timeout(Duration::from_millis(250), business.next_event())
        .await
        .expect("business lane must explicitly observe replacement")
        .expect("replacement observation remains healthy")
        .expect("replacement is a concrete event");
    let BusinessTransportEvent::GenerationReplaced { previous, current } = event else {
        panic!("first post-reconnect business event must be generation replacement");
    };
    assert!(current > previous);
    transport.shutdown().await;
}

#[tokio::test]
async fn outbound_reply_reuses_the_same_supervisor_session() {
    let (mut transport, _pairing_lane, harness) = active_pairing_transport_for_test(MACHINE);
    let business = transport
        .take_business_lane()
        .expect("take business lane once");

    business
        .send_reply(
            business.current_generation(),
            Reply {
                device_route: DEVICE,
                request_route: REQUEST,
                sealed_blob: SealedBlob(vec![0x81, 0x82]),
            },
        )
        .await
        .expect("typed Reply flushes through the existing session");

    let sent = harness.sent_frames();
    assert_eq!(sent.len(), 1);
    let RelayFrameBody::Reply(reply) = &sent[0].body else {
        panic!("business outbound must remain typed Reply");
    };
    assert_eq!(reply.device_route, DEVICE);
    assert_eq!(reply.request_route, REQUEST);
    assert_eq!(reply.sealed_blob.0, vec![0x81, 0x82]);
    assert_eq!(harness.reconnect_count(), 0);
    transport.shutdown().await;
}

#[tokio::test]
async fn business_lane_byte_budget_overflow_fails_closed_without_unbounded_queueing() {
    let (mut transport, _pairing_lane, harness) = active_pairing_transport_for_test(MACHINE);
    let _business = transport
        .take_business_lane()
        .expect("activate bounded business lane");

    for index in 0..5_u8 {
        harness
            .push_frame(OpaqueRouteFrame {
                version: RELAY_PROTOCOL_VERSION,
                body: RelayFrameBody::Send(Send {
                    device_route: DEVICE,
                    request_route: RequestRouteId::from_bytes([index.saturating_add(1); 16]),
                    sealed_blob: SealedBlob(vec![index; 3_500_000]),
                }),
            })
            .await;
    }

    let failure = tokio::time::timeout(Duration::from_secs(2), transport.next_control())
        .await
        .expect("byte overflow closes current generation")
        .expect_err("overflow is fail-closed");
    assert!(matches!(
        failure,
        super::transport::RemoteTransportError::BusinessLagged
    ));
    assert_eq!(harness.sent_count(), 0);
    transport.shutdown().await;
}
