use std::path::PathBuf;

use agentdeck_protocol::AgentKind;
use agentdeckd::runtime::store::ConversationDescriptor;

pub fn descriptor(label: &[u8]) -> ConversationDescriptor {
    ConversationDescriptor {
        agent_kind: AgentKind::Codex,
        title: Some(
            String::from_utf8(label.to_vec()).expect("test conversation descriptor must be UTF-8"),
        ),
        cwd: PathBuf::from("/tmp/agentdeck-runtime-test"),
    }
}
