use agentdeck_protocol::runtime::{
    CodexConversationConfiguration, ConversationConfiguration, VendorConfigurationSnapshot,
};
use agentdeck_protocol::{CodexApprovalPolicy, CodexReasoningEffort, CodexSandboxMode};
use agentdeckd::runtime::store::{
    ConfigurationRecord, ConfigureConversation, ConfigureConversationOutcome, IdempotencyOwner,
    RuntimeId, RuntimeStoreHandle,
};

pub async fn configure_codex_revision_one(
    store: &RuntimeStoreHandle,
    conversation_id: RuntimeId,
) -> ConfigurationRecord {
    let outcome = store
        .configure_conversation(ConfigureConversation {
            conversation_id,
            owner: IdempotencyOwner::Local {
                machine_trust_domain: [0xC1; 32],
                uid: 501,
                client_installation_id: [0xC2; 16],
            },
            idempotency_key: "fixture-codex-configuration-revision-one".to_owned(),
            expected_configuration_revision: 0,
            configuration: ConversationConfiguration::new(VendorConfigurationSnapshot::Codex(
                CodexConversationConfiguration::new(
                    CodexApprovalPolicy::OnRequest,
                    CodexSandboxMode::WorkspaceWrite,
                    CodexReasoningEffort::Medium,
                ),
            )),
        })
        .await
        .expect("configure Codex fixture revision one");
    let configuration = match outcome {
        ConfigureConversationOutcome::Applied { configuration }
        | ConfigureConversationOutcome::Replayed { configuration } => configuration,
        other => panic!("expected Codex fixture revision one, got {other:?}"),
    };
    assert_eq!(configuration.configuration_revision, 1);
    assert_eq!(configuration.event_seq, 0);
    configuration
}
