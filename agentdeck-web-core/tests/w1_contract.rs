#![cfg(feature = "w1-test-fixture")]

use agentdeck_protocol::relay_v2::frame::{AcceptedRef, Authenticated, Challenge, RouteAccepted};
use agentdeck_protocol::relay_v2::{
    ConnectionInstanceId, OpaqueRouteFrame, RELAY_PROTOCOL_VERSION, RelayFrameBody, RelayServerId,
    encode,
};
use agentdeck_web_core::{W1_SENTINEL, W1TransportCore, W1TransportFault};

fn frame(body: RelayFrameBody) -> Vec<u8> {
    encode(&OpaqueRouteFrame {
        version: RELAY_PROTOCOL_VERSION,
        body,
    })
}

#[test]
fn w1_core_owns_strict_origin_handshake_and_sealed_sentinel() {
    let relay_server_id = RelayServerId::from_bytes([0x81; 16]);
    let mut core =
        W1TransportCore::new("wss://127.0.0.1:9443/", relay_server_id).expect("strict WSS origin");
    assert_eq!(core.connect_url(), "wss://127.0.0.1:9443/v2/connect");

    let hello = core.start().expect("single Hello");
    assert!(matches!(
        agentdeck_protocol::relay_v2::decode(&hello).unwrap().body,
        RelayFrameBody::Hello(_)
    ));

    let authenticate = core
        .accept_challenge(
            &frame(RelayFrameBody::Challenge(Challenge {
                relay_server_id,
                connection_instance: ConnectionInstanceId::from_bytes([0x82; 16]),
                challenge_nonce: [0x83; 32],
            })),
            W1TransportFault::None,
        )
        .expect("challenge produces canonical Authenticate");
    assert!(matches!(
        agentdeck_protocol::relay_v2::decode(&authenticate)
            .unwrap()
            .body,
        RelayFrameBody::Authenticate(_)
    ));

    core.accept_authenticated(&frame(RelayFrameBody::Authenticated(Authenticated {
        heartbeat_interval_secs: 20,
    })))
    .expect("authenticated terminal");

    let register = core.register_stream().expect("register stream");
    assert!(matches!(
        agentdeck_protocol::relay_v2::decode(&register)
            .unwrap()
            .body,
        RelayFrameBody::RegisterStream(_)
    ));
    let publish = core.publish_sentinel().expect("publish sealed sentinel");
    let published = agentdeck_protocol::relay_v2::decode(&publish).unwrap();
    let RelayFrameBody::Publish(published) = published.body else {
        panic!("expected Publish");
    };
    assert!(
        !published
            .sealed_blob
            .0
            .windows(W1_SENTINEL.len())
            .any(|window| window == W1_SENTINEL)
    );

    let action = core
        .accept_active_frame(&frame(RelayFrameBody::RouteAccepted(RouteAccepted {
            accepted: AcceptedRef::StreamFrame {
                stream_route: published.stream_route,
                stream_seq: published.stream_seq,
            },
        })))
        .expect("accept exact sentinel receipt");
    assert!(action.is_empty());
    assert!(core.sentinel_accepted());
}

#[test]
fn w1_core_rejects_ambiguous_origin_wrong_server_and_replay() {
    let relay_server_id = RelayServerId::from_bytes([0x91; 16]);
    for invalid in [
        "ws://127.0.0.1:9443/",
        "wss://127.0.0.1:9443/v2/connect",
        "wss://user@127.0.0.1:9443/",
        "wss://127.0.0.1:9443/?route=connect",
        "wss://127.0.0.1:9443/#fragment",
    ] {
        assert!(W1TransportCore::new(invalid, relay_server_id).is_err());
    }

    let mut core = W1TransportCore::new("wss://127.0.0.1:9443/", relay_server_id).unwrap();
    core.start().unwrap();
    let wrong = frame(RelayFrameBody::Challenge(Challenge {
        relay_server_id: RelayServerId::from_bytes([0x92; 16]),
        connection_instance: ConnectionInstanceId::from_bytes([0x93; 16]),
        challenge_nonce: [0x94; 32],
    }));
    assert!(
        core.accept_challenge(&wrong, W1TransportFault::None)
            .is_err()
    );

    let mut core = W1TransportCore::new("wss://127.0.0.1:9443/", relay_server_id).unwrap();
    core.start().unwrap();
    let challenge = frame(RelayFrameBody::Challenge(Challenge {
        relay_server_id,
        connection_instance: ConnectionInstanceId::from_bytes([0x95; 16]),
        challenge_nonce: [0x96; 32],
    }));
    core.accept_challenge(&challenge, W1TransportFault::None)
        .unwrap();
    assert!(
        core.accept_challenge(&challenge, W1TransportFault::None)
            .is_err()
    );
}
