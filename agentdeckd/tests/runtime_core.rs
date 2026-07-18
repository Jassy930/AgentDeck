use std::fs;
use std::path::PathBuf;

use agentdeckd::runtime::{AuthenticatedPrincipal, ConnectionId, RuntimeCore};

fn assert_send_sync<T: Send + Sync + 'static>() {}

#[test]
fn runtime_core_public_shape_is_transport_neutral_and_principal_is_opaque() {
    assert_send_sync::<RuntimeCore>();
    assert_send_sync::<ConnectionId>();
    assert_send_sync::<AuthenticatedPrincipal>();

    let root = PathBuf::from(env!("CARGO_MANIFEST_DIR"));
    let core = fs::read_to_string(root.join("src/runtime/core.rs")).expect("read RuntimeCore");
    let connection =
        fs::read_to_string(root.join("src/runtime/connection.rs")).expect("read connection layer");
    let conversation = fs::read_to_string(root.join("src/runtime/conversation.rs"))
        .expect("read conversation actor");
    let read_pool =
        fs::read_to_string(root.join("src/runtime/read_pool.rs")).expect("read read pool");

    for source in [&core, &connection, &conversation, &read_pool] {
        assert!(!source.contains("tokio::net"));
        assert!(!source.contains("relay_v2"));
        assert!(
            !source.lines().any(|line| {
                !line.trim_start().starts_with("//") && line.contains("RemoteLink")
            })
        );
    }
    assert!(core.contains("pub struct RuntimeCore"));
    assert!(connection.contains("pub struct AuthenticatedPrincipal"));
    assert!(!connection.contains("pub fn local("));
    assert!(!connection.contains("pub fn remote("));
    assert!(connection.contains("DEFAULT_CONNECTION_WRITER_FRAMES: usize = 512"));
    assert!(connection.contains("DEFAULT_CONNECTION_WRITER_BYTES: usize = 16 * 1024 * 1024"));
    assert!(conversation.contains("struct ConversationActor"));
    assert!(read_pool.contains("pub(crate) struct ReadPool"));
}

#[test]
fn core_source_has_no_direct_socket_write_or_transport_priority_branch() {
    let root = PathBuf::from(env!("CARGO_MANIFEST_DIR"));
    let core = fs::read_to_string(root.join("src/runtime/core.rs")).expect("read RuntimeCore");
    let conversation = fs::read_to_string(root.join("src/runtime/conversation.rs"))
        .expect("read conversation actor");
    let conversation = conversation
        .split("#[cfg(test)]")
        .next()
        .expect("production conversation source");

    assert!(!core.contains("AsyncWrite"));
    assert!(!core.contains("write_all"));
    assert!(!conversation.contains("AgentKind::Codex"));
    assert!(!conversation.contains("AgentKind::ClaudeCode"));
    assert!(!conversation.contains("LocalPrincipal =>"));
    assert!(!conversation.contains("RemotePrincipal =>"));
}

#[test]
fn conversation_production_tasks_are_abort_owned() {
    let root = PathBuf::from(env!("CARGO_MANIFEST_DIR"));
    let conversation = fs::read_to_string(root.join("src/runtime/conversation.rs"))
        .expect("read conversation actor");
    let production = conversation
        .split_once("#[cfg(test)]\npub(crate) mod tests")
        .expect("conversation test module boundary")
        .0;
    let compact: String = production
        .chars()
        .filter(|character| !character.is_whitespace())
        .collect();

    assert_eq!(
        compact.matches("tokio::spawn(").count(),
        compact
            .matches("AbortOnDropTask::new(tokio::spawn(")
            .count(),
        "production conversation task must be owned by AbortOnDropTask"
    );
}
