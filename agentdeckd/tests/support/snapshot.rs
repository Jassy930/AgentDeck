use std::collections::BTreeSet;
use std::path::PathBuf;
use std::sync::Arc;

use agentdeck_protocol::runtime::{
    CodexConversationConfiguration, ConfigurationError, ConversationConfiguration, SnapshotItem,
    VendorConfigurationSnapshot,
};
use agentdeck_protocol::{
    ActionDecision, AgentKind, CodexApprovalPolicy, CodexReasoningEffort, CodexSandboxMode,
    ProtocolError, SessionCapabilities, SessionId, SessionStart, ThreadId, VendorCapabilities,
    VendorControlPayload,
};
use agentdeckd::agent::{Agent, AgentEventSender, AgentSessionHandle};
use agentdeckd::runtime::AgentRouter;
use agentdeckd::runtime::events::SnapshotMaterializationSource;
use agentdeckd::runtime::snapshot::{
    SnapshotMaterialization, SnapshotMaterializationError, SnapshotMaterializer,
    assemble_build_snapshot,
};
use agentdeckd::runtime::store::{
    PreparedConversationSnapshotWrite, RuntimeStoreError, RuntimeStoreHandle,
    StoreConversationSnapshotError, StoredConversationSnapshot,
};

struct SnapshotStubAgent {
    version: String,
}

#[async_trait::async_trait]
impl Agent for SnapshotStubAgent {
    fn kind(&self) -> AgentKind {
        AgentKind::Codex
    }

    fn capabilities(&self) -> SessionCapabilities {
        SessionCapabilities {
            agent_kind: AgentKind::Codex,
            agent_version: self.version.clone(),
            features: BTreeSet::new(),
            vendor: VendorCapabilities::Codex(Default::default()),
        }
    }

    fn default_configuration(&self) -> Result<ConversationConfiguration, ConfigurationError> {
        Ok(ConversationConfiguration::new(
            VendorConfigurationSnapshot::Codex(CodexConversationConfiguration::new(
                CodexApprovalPolicy::OnRequest,
                CodexSandboxMode::WorkspaceWrite,
                CodexReasoningEffort::Medium,
            )),
        ))
    }

    async fn start_session(
        &self,
        _: SessionStart,
        _: AgentEventSender,
    ) -> Result<AgentSessionHandle, ProtocolError> {
        unreachable!("snapshot store fixtures never start a vendor session")
    }

    async fn continue_thread(
        &self,
        _: ThreadId,
        _: PathBuf,
        _: String,
        _: AgentEventSender,
    ) -> Result<AgentSessionHandle, ProtocolError> {
        unreachable!("snapshot store fixtures never continue a vendor session")
    }

    async fn submit_decision(&self, _: &SessionId, _: ActionDecision) -> Result<(), ProtocolError> {
        unreachable!("snapshot store fixtures never submit approvals")
    }

    async fn submit_vendor_control(
        &self,
        _: &SessionId,
        _: VendorControlPayload,
    ) -> Result<(), ProtocolError> {
        unreachable!("snapshot store fixtures never submit vendor controls")
    }

    async fn cancel(&self, _: &SessionId) -> Result<(), ProtocolError> {
        unreachable!("snapshot store fixtures never cancel vendor sessions")
    }
}

fn materializer(store: &RuntimeStoreHandle, version: &str) -> SnapshotMaterializer {
    let mut router = AgentRouter::new();
    router.register(Arc::new(SnapshotStubAgent {
        version: version.to_owned(),
    }));
    SnapshotMaterializer::new(store.clone(), Arc::new(router))
}

#[derive(Debug, thiserror::Error)]
pub enum SafeSnapshotStoreError {
    #[error(transparent)]
    Snapshot(#[from] SnapshotMaterializationError),
    #[error(transparent)]
    Store(#[from] RuntimeStoreError),
    #[error(transparent)]
    SnapshotStore(#[from] StoreConversationSnapshotError),
}

impl SafeSnapshotStoreError {
    #[allow(dead_code)]
    pub fn code(&self) -> &'static str {
        match self {
            Self::Snapshot(error) => error.code(),
            Self::Store(error) => error.code(),
            Self::SnapshotStore(error) => error.code(),
        }
    }
}

pub async fn store_canonical_snapshot(
    store: &RuntimeStoreHandle,
    source: SnapshotMaterializationSource,
    version: &str,
) -> Result<StoredConversationSnapshot, SafeSnapshotStoreError> {
    let write = prepare_canonical_snapshot_write(store, source, version).await?;
    Ok(store.store_conversation_snapshot(write).await?)
}

pub async fn prepare_canonical_snapshot_write(
    store: &RuntimeStoreHandle,
    source: SnapshotMaterializationSource,
    version: &str,
) -> Result<PreparedConversationSnapshotWrite, SnapshotMaterializationError> {
    let materializer = materializer(store, version);
    let SnapshotMaterialization::Build(mut input) = materializer.materialize(source).await? else {
        return Err(SnapshotMaterializationError::InvalidState);
    };
    let assembled = assemble_build_snapshot(&mut input, Vec::new())?;
    input.bind_assembled_snapshot(assembled)
}

#[allow(
    dead_code,
    reason = "shared integration support is compiled into test binaries that do not use every helper"
)]
pub async fn prepare_canonical_snapshot_write_with_items(
    store: &RuntimeStoreHandle,
    source: SnapshotMaterializationSource,
    version: &str,
    items: Vec<SnapshotItem>,
) -> Result<(PreparedConversationSnapshotWrite, Vec<u8>), SnapshotMaterializationError> {
    let materializer = materializer(store, version);
    let SnapshotMaterialization::Build(mut input) = materializer.materialize(source).await? else {
        return Err(SnapshotMaterializationError::InvalidState);
    };
    let assembled = assemble_build_snapshot(&mut input, items)?;
    let canonical_payload = assembled.canonical_payload().to_vec();
    let write = input.bind_assembled_snapshot(assembled)?;
    Ok((write, canonical_payload))
}
