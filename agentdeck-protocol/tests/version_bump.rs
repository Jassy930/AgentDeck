use agentdeck_protocol::PROTOCOL_VERSION;

#[test]
fn protocol_version_is_4() {
    assert_eq!(PROTOCOL_VERSION, 4);
}
