use std::fs;
use std::path::PathBuf;

#[test]
fn remote_link_keeps_network_and_vendor_dependencies_at_the_boundary() {
    let root = PathBuf::from(env!("CARGO_MANIFEST_DIR"));
    let transport = fs::read_to_string(root.join("src/remote/transport.rs"))
        .expect("read existing MachineLink transport");
    let link = fs::read_to_string(root.join("src/remote/link.rs"))
        .expect("P4.4 must add the RemoteLink boundary");
    let dispatch = fs::read_to_string(root.join("src/remote/dispatch.rs"))
        .expect("P4.4 must add transport-neutral remote dispatch");

    assert_eq!(
        transport.matches("RelayClient::connect(").count(),
        1,
        "the daemon must retain exactly one outbound MachineLink session"
    );
    assert!(!link.contains("RelayClient::connect("));
    assert!(!dispatch.contains("RelayClient::connect("));
    assert!(!link.contains("HashMap<Conversation"));
    assert!(!dispatch.contains("tokio::net"));

    for adapter in ["src/codex", "src/claude_code"] {
        for entry in fs::read_dir(root.join(adapter)).expect("read adapter directory") {
            let path = entry.expect("adapter entry").path();
            if path.extension().and_then(|value| value.to_str()) != Some("rs") {
                continue;
            }
            let source = fs::read_to_string(&path).expect("read adapter source");
            assert!(
                !source.contains("relay_v2"),
                "{} imports Relay",
                path.display()
            );
            assert!(
                !source.contains("remote::"),
                "{} imports remote",
                path.display()
            );
        }
    }
}
