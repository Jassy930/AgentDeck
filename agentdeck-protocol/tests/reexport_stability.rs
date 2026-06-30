//! Guards that after the mod split, all previously public items are still
//! reachable at the crate root with the same paths. If this breaks, every
//! downstream consumer (agentdeckd, agentdeck-cli, Swift bindings) breaks.
//!
//! NOTE: The brief listed ServerEvent / ClientCommand / schemars::Schema as
//! expected types, but those do not exist in the current lib.rs (the codebase
//! evolved past that naming). This guard covers the ACTUAL public API that
//! downstream consumers depend on.

use agentdeck_protocol as proto;

#[test]
fn crate_root_reexports_are_stable() {
    let _ = proto::PROTOCOL_VERSION;
    let _: proto::IpcMessage;
    let _: proto::SessionState;
    let _: proto::ActionRequest;
    let _: proto::ActionDecision;
    let _: proto::AgentItem;
    let _: proto::AgentItemKind;
    let _: proto::Lifecycle;
    let _: proto::AgentReference;
    let _: proto::HookFragment;
    let _: proto::FileEditChange;
    let _: proto::ToolAction;
    let _: proto::HistoryThreadSummary;
    let _: proto::HistoryThreadList;
    let _: proto::HistoryThreadDetail;
    let _schema: serde_json::Value = proto::protocol_schema();
}
