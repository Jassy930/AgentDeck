use agentdeck_protocol::relay_v2::frame::RetireMachine;
use agentdeckd::local::listener::RemoteStartPermit;
use agentdeckd::remote::transport::{RemoteControl, RemoteTransport, RemoteTransportError};

#[allow(dead_code)]
async fn allowed_public_surface_compiles(
    transport: &mut RemoteTransport,
    retirement: RetireMachine,
) {
    let _: Result<(), RemoteTransportError> = transport.send_retirement(retirement).await;
    let _: Result<Option<RemoteControl>, RemoteTransportError> = transport.next_control().await;
    let _: Result<(), RemoteTransportError> = transport.reconnect().await;
    transport.shutdown().await;
}

#[allow(dead_code)]
async fn consuming_reclaim_surface_compiles(
    transport: RemoteTransport,
) -> Result<RemoteStartPermit, RemoteTransportError> {
    transport.shutdown_and_reclaim_start_permit().await
}

#[test]
fn transport_module_has_no_runtime_core_or_raw_public_frame_surface() {
    let source = include_str!("../src/remote/transport.rs");
    assert!(!source.contains("RuntimeCore"));
    assert!(!source.contains("crate::runtime"));
    assert!(!source.contains("pub async fn send("));
    assert!(!source.contains("pub async fn recv("));
    assert!(source.contains("identity: ArmedRemoteIdentity"));
    assert!(source.contains("pub async fn send_retirement"));
    assert!(source.contains("pub async fn next_control"));
    assert!(source.contains("pub async fn shutdown_and_reclaim_start_permit"));
}
