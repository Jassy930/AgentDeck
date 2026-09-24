use agentdeck_protocol::PROTOCOL_VERSION;

#[test]
fn protocol_version_is_5() {
    assert_eq!(PROTOCOL_VERSION, 5);
}
