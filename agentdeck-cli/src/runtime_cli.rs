//! Runtime v5 canonical CLI facade。
//!
//! 本模块只接受 canonical conversation/command/event identity，并通过
//! [`RuntimeUnixClient`] 与 shared daemon 通信。Legacy SessionStart/SessionContinue、
//! vendor thread/session identity 与 stdio spawn 不进入这里。

use std::collections::HashSet;
use std::path::{Path, PathBuf};

#[cfg(debug_assertions)]
use std::collections::BTreeSet;

use agentdeck_cli::unix_transport::{ReplySequenceItem, RuntimeUnixClient};
use agentdeck_protocol::runtime::command::CatalogRequest;
use agentdeck_protocol::runtime::failure::DAEMON_CONVERSATION_CONFIGURATION_CONFLICT;
#[cfg(debug_assertions)]
use agentdeck_protocol::runtime::identity::CommandId;
use agentdeck_protocol::runtime::identity::{CatalogPageCursor, ConversationId};
use agentdeck_protocol::runtime::{
    AgentDescription, AgentDescriptions, BackfillChunk, CatalogSnapshot,
    ClaudeCodeConversationConfiguration, CodexConversationConfiguration, CommandReceipt,
    ConfigurationReceipt, ConfigureConversationRequest, ConversationConfiguration,
    ConversationMetadataMutation, ConversationMetadataMutationRequest, ConversationMetadataReceipt,
    ConversationSnapshot, ConversationStart, IdempotencyKey, MachineRemoteStatus, PromptPayload,
    RuntimeEventBody, RuntimeFailure, RuntimeInnerCursor, RuntimeReply, RuntimeRequest,
    RuntimeSubscriptionTarget, SendPromptRequest, StreamCursor, SubscriptionReceipt,
    VendorConfigurationSnapshot,
};
#[cfg(debug_assertions)]
use agentdeck_protocol::runtime::{QueryReceiptSelector, SnapshotItem};
use agentdeck_protocol::{
    AgentKind, ClaudeCodePermissionMode, CodexApprovalPolicy, CodexReasoningEffort,
    CodexSandboxMode,
};

use crate::client::map_unix_error;
use crate::main_types::{
    AgentKindArg, ApprovalArg, EffortArg, PermissionArg, SandboxArg, SessionRunArgs,
};
use crate::output::{CliError, render};

const UNEXPECTED_REPLY: &str = "daemon.client.unexpected_reply";
const REPLY_IDENTITY_MISMATCH: &str = "daemon.client.reply_identity_mismatch";
const SYNC_INVALID: &str = "daemon.client.sync_invalid";
const TRANSFER_INVALID: &str = "daemon.client.transfer_payload_invalid";
const MAX_IDEMPOTENCY_KEY_BYTES: usize = 1024;

pub fn validate_runtime_globals(profile: &str, data_dir: Option<&str>) -> Result<(), CliError> {
    if profile != "stable" {
        return Err(CliError::Usage(
            "Runtime v5 commands only use the canonical stable shared-daemon namespace; --profile must be stable"
                .to_owned(),
        ));
    }
    if data_dir.is_some() {
        return Err(CliError::Usage(
            "--data-dir is diagnostics-only and cannot override a Runtime v5 endpoint".to_owned(),
        ));
    }
    Ok(())
}

pub fn validate_conversation_id(conversation_id: &str) -> Result<(), CliError> {
    if conversation_id.is_empty() {
        Err(CliError::Usage(
            "conversationId must not be empty".to_owned(),
        ))
    } else {
        Ok(())
    }
}

#[derive(Debug)]
pub struct SessionRunPlan {
    operation_key: String,
    agent: AgentKind,
    cwd: PathBuf,
    prompt: Option<PromptPayload>,
    sandbox: Option<CodexSandboxMode>,
    approval: Option<CodexApprovalPolicy>,
    reasoning_effort: Option<CodexReasoningEffort>,
    permission: Option<ClaudeCodePermissionMode>,
    output_style: Option<String>,
    model: Option<String>,
    effort: Option<String>,
    start_key: IdempotencyKey,
    configure_key: IdempotencyKey,
    prompt_key: IdempotencyKey,
}

impl SessionRunPlan {
    pub fn new(args: SessionRunArgs) -> Result<Self, CliError> {
        let agent = AgentKind::from(args.agent);
        validate_configuration_flags(&args)?;
        validate_idempotency_key(
            &args.idempotency_key,
            ":configure".len(),
            "session run --idempotency-key",
        )?;
        let prompt = if args.prompt.is_empty() {
            None
        } else {
            Some(
                PromptPayload::new(args.prompt)
                    .map_err(|error| CliError::Usage(error.to_string()))?,
            )
        };
        let operation_key = args.idempotency_key;
        Ok(Self {
            operation_key: operation_key.clone(),
            agent,
            cwd: args.cwd,
            prompt,
            sandbox: args.sandbox.map(Into::into),
            approval: args.approval.map(Into::into),
            reasoning_effort: args.reasoning_effort.map(Into::into),
            permission: args.permission.map(Into::into),
            output_style: args.output_style,
            model: args.model,
            effort: args.effort,
            start_key: derived_key(&operation_key, "start"),
            configure_key: derived_key(&operation_key, "configure"),
            prompt_key: derived_key(&operation_key, "prompt"),
        })
    }

    fn start_request(&self) -> RuntimeRequest {
        RuntimeRequest::Start(ConversationStart {
            agent_kind: self.agent,
            idempotency_key: self.start_key.clone(),
            cwd: self.cwd.clone(),
            title: None,
        })
    }

    fn configure_request(
        &self,
        conversation_id: ConversationId,
        configuration: ConversationConfiguration,
    ) -> RuntimeRequest {
        RuntimeRequest::ConfigureConversation(ConfigureConversationRequest::new(
            conversation_id,
            self.configure_key.clone(),
            0,
            configuration,
        ))
    }

    fn resolve_configuration(
        &self,
        description: &AgentDescription,
    ) -> Result<ConversationConfiguration, CliError> {
        if description.agent_kind() != self.agent {
            return Err(protocol_error(
                REPLY_IDENTITY_MISMATCH,
                "DescribeAgents returned a mismatched agent description",
            ));
        }
        match description.default_configuration().vendor_control() {
            VendorConfigurationSnapshot::Codex(default) if self.agent == AgentKind::Codex => {
                Ok(ConversationConfiguration::new(
                    VendorConfigurationSnapshot::Codex(CodexConversationConfiguration::new(
                        self.approval.unwrap_or(default.approval_policy()),
                        self.sandbox.unwrap_or(default.sandbox()),
                        self.reasoning_effort.unwrap_or(default.reasoning_effort()),
                    )),
                ))
            }
            VendorConfigurationSnapshot::ClaudeCode(default)
                if self.agent == AgentKind::ClaudeCode =>
            {
                let configuration = ClaudeCodeConversationConfiguration::new(
                    self.permission.unwrap_or(default.permission_mode()),
                    self.model
                        .clone()
                        .or_else(|| default.model().map(str::to_owned)),
                    self.effort
                        .clone()
                        .or_else(|| default.effort().map(str::to_owned)),
                    self.output_style
                        .clone()
                        .or_else(|| default.output_style().map(str::to_owned)),
                )
                .map_err(|error| CliError::Usage(error.to_string()))?;
                Ok(ConversationConfiguration::new(
                    VendorConfigurationSnapshot::ClaudeCode(configuration),
                ))
            }
            _ => Err(protocol_error(
                REPLY_IDENTITY_MISMATCH,
                "DescribeAgents default configuration does not match agentKind",
            )),
        }
    }

    fn prompt_request(
        &self,
        conversation_id: ConversationId,
        revision: u64,
    ) -> Option<RuntimeRequest> {
        self.prompt.clone().map(|prompt| {
            RuntimeRequest::SendPrompt(SendPromptRequest {
                conversation_id,
                idempotency_key: self.prompt_key.clone(),
                expected_configuration_revision: revision,
                prompt,
            })
        })
    }

    fn retry_context(&self) -> serde_json::Value {
        serde_json::json!({
            "operation": "sessionRun",
            "idempotencyKey": self.operation_key.as_str(),
            "derivedIdempotencyKeys": {
                "start": self.start_key.as_str(),
                "configure": self.configure_key.as_str(),
                "prompt": self.prompt_key.as_str(),
            }
        })
    }
}

#[derive(Debug)]
pub struct SessionContinuePlan {
    conversation_id: ConversationId,
    prompt: PromptPayload,
    prompt_key: IdempotencyKey,
}

impl SessionContinuePlan {
    pub fn new(
        conversation_id: String,
        prompt: String,
        idempotency_key: String,
    ) -> Result<Self, CliError> {
        validate_conversation_id(&conversation_id)?;
        if prompt.is_empty() {
            return Err(CliError::Usage(
                "session continue requires a non-empty prompt".to_owned(),
            ));
        }
        validate_idempotency_key(&idempotency_key, 0, "session continue --idempotency-key")?;
        Ok(Self {
            conversation_id: ConversationId::new(conversation_id),
            prompt: PromptPayload::new(prompt)
                .map_err(|error| CliError::Usage(error.to_string()))?,
            prompt_key: IdempotencyKey::new(idempotency_key),
        })
    }

    fn prompt_request(&self, revision: u64) -> RuntimeRequest {
        RuntimeRequest::SendPrompt(SendPromptRequest {
            conversation_id: self.conversation_id.clone(),
            idempotency_key: self.prompt_key.clone(),
            expected_configuration_revision: revision,
            prompt: self.prompt.clone(),
        })
    }

    fn retry_context(&self) -> serde_json::Value {
        serde_json::json!({
            "operation": "sessionContinue",
            "conversationId": self.conversation_id.as_str(),
            "idempotencyKey": self.prompt_key.as_str(),
        })
    }
}

#[derive(Debug)]
pub struct MetadataPlan {
    conversation_id: ConversationId,
    expected_entry_revision: u64,
    idempotency_key: IdempotencyKey,
    mutation: ConversationMetadataMutation,
}

#[cfg(debug_assertions)]
#[derive(Debug)]
pub enum SmokeReceiptSelector {
    Command(CommandId),
    Idempotency(IdempotencyKey),
}

#[cfg(debug_assertions)]
impl SmokeReceiptSelector {
    pub fn new(
        command_id: Option<String>,
        idempotency_key: Option<String>,
    ) -> Result<Self, CliError> {
        match (command_id, idempotency_key) {
            (Some(command_id), None) => {
                validate_identity(&command_id, "query-receipt --command-id")?;
                Ok(Self::Command(CommandId::new(command_id)))
            }
            (None, Some(idempotency_key)) => {
                validate_idempotency_key(&idempotency_key, 0, "query-receipt --idempotency-key")?;
                Ok(Self::Idempotency(IdempotencyKey::new(idempotency_key)))
            }
            _ => Err(CliError::Usage(
                "query-receipt requires exactly one of --command-id or --idempotency-key"
                    .to_owned(),
            )),
        }
    }

    fn into_query(self, conversation_id: ConversationId) -> QueryReceiptSelector {
        match self {
            Self::Command(command_id) => QueryReceiptSelector::Command {
                conversation_id,
                command_id,
            },
            Self::Idempotency(idempotency_key) => QueryReceiptSelector::Idempotency {
                conversation_id,
                idempotency_key,
            },
        }
    }
}

impl MetadataPlan {
    pub fn rename(
        conversation_id: String,
        title: String,
        expected_entry_revision: u64,
        idempotency_key: String,
    ) -> Result<Self, CliError> {
        Self::new(
            conversation_id,
            expected_entry_revision,
            idempotency_key,
            ConversationMetadataMutation::rename(Some(title))
                .map_err(|error| CliError::Usage(error.to_string()))?,
        )
    }

    pub fn archived(
        conversation_id: String,
        archived: bool,
        expected_entry_revision: u64,
        idempotency_key: String,
    ) -> Result<Self, CliError> {
        Self::new(
            conversation_id,
            expected_entry_revision,
            idempotency_key,
            ConversationMetadataMutation::SetArchived { archived },
        )
    }

    fn new(
        conversation_id: String,
        expected_entry_revision: u64,
        idempotency_key: String,
        mutation: ConversationMetadataMutation,
    ) -> Result<Self, CliError> {
        validate_conversation_id(&conversation_id)?;
        validate_idempotency_key(&idempotency_key, 0, "metadata --idempotency-key")?;
        Ok(Self {
            conversation_id: ConversationId::new(conversation_id),
            expected_entry_revision,
            idempotency_key: IdempotencyKey::new(idempotency_key),
            mutation,
        })
    }

    fn request(&self) -> Result<RuntimeRequest, CliError> {
        Ok(RuntimeRequest::UpdateConversationMetadata(
            ConversationMetadataMutationRequest::new(
                self.conversation_id.clone(),
                self.idempotency_key.clone(),
                self.expected_entry_revision,
                self.mutation.clone(),
            )
            .map_err(|error| CliError::Usage(error.to_string()))?,
        ))
    }

    fn retry_context(&self) -> serde_json::Value {
        serde_json::json!({
            "operation": "updateConversationMetadata",
            "conversationId": self.conversation_id.as_str(),
            "expectedEntryRevision": self.expected_entry_revision,
            "idempotencyKey": self.idempotency_key.as_str(),
        })
    }
}

pub fn handle_ping(pretty: bool) {
    print_value(&serde_json::json!({"ok": true}), pretty);
}

pub async fn handle_selfcheck(client: &RuntimeUnixClient, pretty: bool) -> Result<(), CliError> {
    let descriptions = describe_agents(client).await?;
    let mut output = serde_json::to_value(descriptions)?;
    output
        .as_object_mut()
        .expect("AgentDescriptions serializes as an object")
        .insert("ok".to_owned(), serde_json::Value::Bool(true));
    print_value(&output, pretty);
    Ok(())
}

pub async fn handle_agent_list(client: &RuntimeUnixClient, pretty: bool) -> Result<(), CliError> {
    print_value(
        &serde_json::to_value(describe_agents(client).await?)?,
        pretty,
    );
    Ok(())
}

pub async fn handle_agent_capabilities(
    client: &RuntimeUnixClient,
    agent: AgentKindArg,
    pretty: bool,
) -> Result<(), CliError> {
    let descriptions = describe_agents(client).await?;
    let expected = AgentKind::from(agent);
    let description = descriptions
        .agents()
        .iter()
        .find(|description| description.agent_kind() == expected)
        .ok_or_else(|| CliError::Session {
            code: Some("agent-not-registered".to_owned()),
            message: format!("agent {expected:?} is not registered"),
        })?;
    print_value(&serde_json::to_value(description)?, pretty);
    Ok(())
}

pub async fn handle_session_run(
    client: &RuntimeUnixClient,
    plan: SessionRunPlan,
    pretty: bool,
) -> Result<(), CliError> {
    let descriptions = describe_agents(client).await?;
    let description = descriptions
        .agents()
        .iter()
        .find(|description| description.agent_kind() == plan.agent)
        .ok_or_else(|| CliError::Session {
            code: Some("agent-not-registered".to_owned()),
            message: format!("agent {:?} is not registered", plan.agent),
        })?;
    let configuration = plan.resolve_configuration(description)?;
    print_reply(&RuntimeReply::Agents(descriptions), pretty)?;
    print_value(&plan.retry_context(), pretty);

    let start_reply = unary_reply(client, plan.start_request()).await?;
    let RuntimeReply::ConversationStart(start) = start_reply else {
        return Err(unexpected("Start did not return ConversationStart"));
    };
    let conversation_id = start.conversation_id.clone();
    print_reply(&RuntimeReply::ConversationStart(start), pretty)?;

    let configuration_reply = unary_reply(
        client,
        plan.configure_request(conversation_id.clone(), configuration),
    )
    .await?;
    let revision = configuration_revision(configuration_reply, &conversation_id, pretty)?;
    if revision != 1 {
        return Err(protocol_error(
            REPLY_IDENTITY_MISMATCH,
            format!("Configure(rev0) returned revision {revision}, expected rev1"),
        ));
    }

    let synchronized = subscribe_conversation(client, &conversation_id).await?;
    if !synchronized.snapshot_seen {
        return Err(protocol_error(
            SYNC_INVALID,
            "new managed conversation synchronization did not include a Snapshot",
        ));
    }
    if !matches!(
        synchronized.configuration_revision,
        Some(current_revision) if current_revision >= revision
    ) {
        return Err(protocol_error(
            SYNC_INVALID,
            "post-Configure snapshot is behind the committed revision",
        ));
    }
    print_values(&synchronized.outputs, pretty);

    if let Some(request) = plan.prompt_request(conversation_id, revision) {
        let command_reply = unary_reply(client, request).await?;
        print_command_reply(command_reply, revision, pretty)?;
    }
    Ok(())
}

pub async fn handle_session_continue(
    client: &RuntimeUnixClient,
    plan: SessionContinuePlan,
    pretty: bool,
) -> Result<(), CliError> {
    let synchronized = subscribe_conversation(client, &plan.conversation_id).await?;
    let revision = synchronized
        .configuration_revision
        .filter(|revision| *revision > 0)
        .ok_or_else(|| CliError::Session {
            code: Some("daemon.conversation.configuration_required".to_owned()),
            message: "conversation has no canonical configuration revision".to_owned(),
        })?;
    print_values(&synchronized.outputs, pretty);
    print_value(&plan.retry_context(), pretty);
    let command_reply = unary_reply(client, plan.prompt_request(revision)).await?;
    print_command_reply(command_reply, revision, pretty)
}

pub async fn handle_history_list(
    client: &RuntimeUnixClient,
    agent: Option<AgentKindArg>,
    cwd_filter: Option<&Path>,
    limit: Option<usize>,
    pretty: bool,
) -> Result<(), CliError> {
    let mut cursor: Option<CatalogPageCursor> = None;
    let mut seen = HashSet::new();
    let mut base = None;
    let mut entries = Vec::new();
    loop {
        let item = client
            .request(RuntimeRequest::Catalog(CatalogRequest {
                page_cursor: cursor.clone(),
            }))
            .await
            .map_err(map_unix_error)?;
        let page = decode_catalog(item, cursor.as_ref())?;
        if let Some(expected) = base {
            if page.base_catalog_cursor != expected {
                return Err(protocol_error(
                    SYNC_INVALID,
                    "Catalog pagination changed its frozen base cursor",
                ));
            }
        } else {
            base = Some(page.base_catalog_cursor);
        }
        entries.extend(page.entries().iter().cloned());
        let Some(next) = page.next_page_cursor().cloned() else {
            break;
        };
        if !seen.insert(next.as_str().to_owned()) {
            return Err(protocol_error(
                SYNC_INVALID,
                "Catalog pagination repeated a page cursor",
            ));
        }
        cursor = Some(next);
    }

    let agent = agent.map(AgentKind::from);
    entries.retain(|entry| {
        agent.is_none_or(|expected| entry.agent_kind == expected)
            && cwd_filter.is_none_or(|expected| entry.cwd.as_deref() == Some(expected))
    });
    if let Some(limit) = limit {
        entries.truncate(limit);
    }
    print_value(&serde_json::json!({"entries": entries}), pretty);
    Ok(())
}

pub async fn handle_history_read(
    client: &RuntimeUnixClient,
    conversation_id: String,
    pretty: bool,
) -> Result<(), CliError> {
    validate_conversation_id(&conversation_id)?;
    let conversation_id = ConversationId::new(conversation_id);
    let synchronized = subscribe_conversation(client, &conversation_id).await?;
    print_values(&synchronized.outputs, pretty);
    let reply = unary_reply(
        client,
        RuntimeRequest::Unsubscribe {
            target: RuntimeSubscriptionTarget::Conversation {
                conversation_id: conversation_id.clone(),
            },
        },
    )
    .await?;
    match reply {
        RuntimeReply::Subscription(SubscriptionReceipt::Unsubscribed) => {
            print_reply(
                &RuntimeReply::Subscription(SubscriptionReceipt::Unsubscribed),
                pretty,
            )?;
            Ok(())
        }
        _ => Err(unexpected("Unsubscribe did not return Unsubscribed")),
    }
}

pub async fn handle_metadata(
    client: &RuntimeUnixClient,
    plan: MetadataPlan,
    pretty: bool,
) -> Result<(), CliError> {
    print_value(&plan.retry_context(), pretty);
    let reply = unary_reply(client, plan.request()?).await?;
    let RuntimeReply::ConversationMetadata(receipt) = reply else {
        return Err(unexpected(
            "UpdateConversationMetadata did not return ConversationMetadata",
        ));
    };
    match &receipt {
        ConversationMetadataReceipt::Applied {
            conversation_id, ..
        }
        | ConversationMetadataReceipt::Replayed {
            conversation_id, ..
        } if conversation_id == &plan.conversation_id => {
            print_reply(&RuntimeReply::ConversationMetadata(receipt), pretty)?;
            Ok(())
        }
        ConversationMetadataReceipt::Conflict {
            conversation_id,
            current_entry_revision,
        } if conversation_id == &plan.conversation_id => Err(CliError::Session {
            code: Some("daemon.conversation.metadata_conflict".to_owned()),
            message: format!(
                "metadata expected entry revision {} but current revision is {}",
                plan.expected_entry_revision, current_entry_revision
            ),
        }),
        ConversationMetadataReceipt::Failed { failure } => Err(runtime_failure(failure.clone())),
        _ => Err(protocol_error(
            REPLY_IDENTITY_MISMATCH,
            "metadata receipt conversationId does not match the request",
        )),
    }
}

/// 执行一条本机 machine administration 请求，并且只接受严格
/// `MachineRemoteStatus` terminal。Runtime Failure 保留 daemon 稳定 code；任何其他
/// reply/transfer 都 fail-close。
pub async fn request_machine_remote_status(
    client: &RuntimeUnixClient,
    request: RuntimeRequest,
) -> Result<MachineRemoteStatus, CliError> {
    match unary_reply(client, request).await? {
        RuntimeReply::MachineRemoteStatus(status) => Ok(status),
        _ => Err(unexpected(
            "machine administration did not return MachineRemoteStatus",
        )),
    }
}

/// 执行一条 same-UID pairing administration 请求，只接受三种 v4 pairing reply。
/// Runtime Failure 保留 daemon 稳定 code；任何 machine/business reply 均 fail-close。
pub async fn request_pairing_administration(
    client: &RuntimeUnixClient,
    request: RuntimeRequest,
) -> Result<RuntimeReply, CliError> {
    match unary_reply(client, request).await? {
        reply @ (RuntimeReply::PairInvite(_)
        | RuntimeReply::PendingPairings { .. }
        | RuntimeReply::Pairing(_)) => Ok(reply),
        _ => Err(unexpected(
            "pairing administration returned an unrelated Runtime reply",
        )),
    }
}

/// 执行一条 same-UID 精确设备撤销，只接受中立 `RevocationReceipt`。
pub async fn request_revocation_administration(
    client: &RuntimeUnixClient,
    request: RuntimeRequest,
) -> Result<agentdeck_protocol::runtime::RevocationReceipt, CliError> {
    match unary_reply(client, request).await? {
        RuntimeReply::Revocation(receipt) => Ok(receipt),
        _ => Err(unexpected(
            "revocation administration returned an unrelated Runtime reply",
        )),
    }
}

#[cfg(debug_assertions)]
pub fn handle_smoke_installation(client: &RuntimeUnixClient, pretty: bool) {
    print_value(
        &serde_json::json!({
            "installationId": client.installation_id().to_string(),
            "ok": true,
            "operation": "installation",
        }),
        pretty,
    );
}

#[cfg(debug_assertions)]
pub async fn handle_smoke_send_prompt(
    client: &RuntimeUnixClient,
    conversation_id: String,
    idempotency_key: String,
    expected_configuration_revision: u64,
    prompt: String,
    pretty: bool,
) -> Result<(), CliError> {
    validate_conversation_id(&conversation_id)?;
    validate_idempotency_key(&idempotency_key, 0, "send-prompt --idempotency-key")?;
    let prompt = PromptPayload::new(prompt).map_err(|error| CliError::Usage(error.to_string()))?;
    let reply = unary_reply(
        client,
        RuntimeRequest::SendPrompt(SendPromptRequest {
            conversation_id: ConversationId::new(conversation_id),
            idempotency_key: IdempotencyKey::new(idempotency_key),
            expected_configuration_revision,
            prompt,
        }),
    )
    .await?;
    print_command_reply(reply, expected_configuration_revision, pretty)
}

#[cfg(debug_assertions)]
pub async fn handle_smoke_query_receipt(
    client: &RuntimeUnixClient,
    conversation_id: String,
    selector: SmokeReceiptSelector,
    pretty: bool,
) -> Result<(), CliError> {
    validate_conversation_id(&conversation_id)?;
    let conversation_id = ConversationId::new(conversation_id);
    let reply = unary_reply(
        client,
        RuntimeRequest::QueryReceipt(selector.into_query(conversation_id.clone())),
    )
    .await?;
    match reply {
        RuntimeReply::CommandStatus(receipt) if receipt.conversation_id == conversation_id => {
            print_reply(&RuntimeReply::CommandStatus(receipt), pretty)
        }
        RuntimeReply::CommandStatus(_) => Err(protocol_error(
            REPLY_IDENTITY_MISMATCH,
            "QueryReceipt returned another conversation owner/identity",
        )),
        _ => Err(unexpected("QueryReceipt did not return CommandStatus")),
    }
}

#[cfg(debug_assertions)]
pub async fn handle_smoke_subscribe(
    client: &RuntimeUnixClient,
    conversation_id: String,
    pretty: bool,
) -> Result<(), CliError> {
    validate_conversation_id(&conversation_id)?;
    let conversation_id = ConversationId::new(conversation_id);
    let synchronized = subscribe_conversation(client, &conversation_id).await?;
    let terminal_cursor = synchronized.terminal_cursor.ok_or_else(|| {
        protocol_error(
            SYNC_INVALID,
            "Subscribe ended without a canonical terminal stream cursor",
        )
    })?;
    print_value(
        &serde_json::json!({
            "backfillCount": synchronized.backfill_count,
            "commandIds": synchronized.command_ids,
            "conversationId": conversation_id.as_str(),
            "installationId": client.installation_id().to_string(),
            "ok": true,
            "operation": "subscribe",
            "snapshotCount": synchronized.snapshot_count,
            "syncComplete": true,
            "terminalStreamCursor": terminal_cursor,
        }),
        pretty,
    );
    Ok(())
}

async fn describe_agents(client: &RuntimeUnixClient) -> Result<AgentDescriptions, CliError> {
    match unary_reply(client, RuntimeRequest::DescribeAgents).await? {
        RuntimeReply::Agents(descriptions) => Ok(descriptions),
        _ => Err(unexpected("DescribeAgents did not return Agents")),
    }
}

async fn unary_reply(
    client: &RuntimeUnixClient,
    request: RuntimeRequest,
) -> Result<RuntimeReply, CliError> {
    match client.request(request).await.map_err(map_unix_error)? {
        ReplySequenceItem::Reply(reply) => match *reply {
            RuntimeReply::Failure(failure) => Err(runtime_failure(failure)),
            reply => Ok(reply),
        },
        ReplySequenceItem::TransferComplete(_) => Err(protocol_error(
            TRANSFER_INVALID,
            "this Runtime command returned an unexpected transfer payload",
        )),
    }
}

fn decode_catalog(
    item: ReplySequenceItem,
    expected_page_cursor: Option<&CatalogPageCursor>,
) -> Result<CatalogSnapshot, CliError> {
    let snapshot = match item {
        ReplySequenceItem::Reply(reply) => match *reply {
            RuntimeReply::Catalog(snapshot) => Ok(snapshot),
            RuntimeReply::Failure(failure) => Err(runtime_failure(failure)),
            _ => Err(unexpected("Catalog did not return CatalogSnapshot")),
        },
        ReplySequenceItem::TransferComplete(bytes) => canonical_json::<CatalogSnapshot>(&bytes)
            .ok_or_else(|| {
                protocol_error(
                    TRANSFER_INVALID,
                    "Catalog transfer is not a canonical CatalogSnapshot",
                )
            }),
    }?;
    if snapshot.current_page_cursor() != expected_page_cursor {
        return Err(protocol_error(
            SYNC_INVALID,
            "Catalog page does not echo the requested page cursor",
        ));
    }
    Ok(snapshot)
}

fn canonical_json<T>(payload: &[u8]) -> Option<T>
where
    T: serde::de::DeserializeOwned + serde::Serialize,
{
    let value = serde_json::from_slice::<T>(payload).ok()?;
    let mut comparator = CanonicalJsonComparator::new(payload);
    serde_json::to_writer(&mut comparator, &value).ok()?;
    comparator.is_exact().then_some(value)
}

struct CanonicalJsonComparator<'a> {
    expected: &'a [u8],
    offset: usize,
    matches: bool,
}

impl<'a> CanonicalJsonComparator<'a> {
    const fn new(expected: &'a [u8]) -> Self {
        Self {
            expected,
            offset: 0,
            matches: true,
        }
    }

    fn is_exact(&self) -> bool {
        self.matches && self.offset == self.expected.len()
    }
}

impl std::io::Write for CanonicalJsonComparator<'_> {
    fn write(&mut self, bytes: &[u8]) -> std::io::Result<usize> {
        let Some(end) = self.offset.checked_add(bytes.len()) else {
            self.matches = false;
            return Ok(bytes.len());
        };
        if self.expected.get(self.offset..end) != Some(bytes) {
            self.matches = false;
        }
        self.offset = end;
        Ok(bytes.len())
    }

    fn flush(&mut self) -> std::io::Result<()> {
        Ok(())
    }
}

struct ConversationSynchronization {
    outputs: Vec<serde_json::Value>,
    snapshot_seen: bool,
    #[cfg(debug_assertions)]
    snapshot_count: usize,
    #[cfg(debug_assertions)]
    backfill_count: usize,
    #[cfg(debug_assertions)]
    command_ids: BTreeSet<String>,
    #[cfg(debug_assertions)]
    terminal_cursor: Option<StreamCursor>,
    configuration_revision: Option<u64>,
}

struct ConversationSyncState {
    outputs: Vec<serde_json::Value>,
    subscribed_generation: Option<String>,
    snapshot_seen: bool,
    backfill_seen: bool,
    #[cfg(debug_assertions)]
    snapshot_count: usize,
    #[cfg(debug_assertions)]
    backfill_count: usize,
    #[cfg(debug_assertions)]
    command_ids: BTreeSet<String>,
    payload_cursor: StreamCursor,
    #[cfg(debug_assertions)]
    terminal_cursor: Option<StreamCursor>,
    configuration_revision: Option<u64>,
    sync_seen: bool,
}

async fn subscribe_conversation(
    client: &RuntimeUnixClient,
    conversation_id: &ConversationId,
) -> Result<ConversationSynchronization, CliError> {
    let mut sequence = client
        .begin_request(RuntimeRequest::Subscribe {
            inner_cursor: RuntimeInnerCursor::Conversation {
                conversation_id: conversation_id.clone(),
                cursor: StreamCursor::BeforeFirst,
            },
        })
        .await
        .map_err(map_unix_error)?;
    let mut state = ConversationSyncState {
        outputs: Vec::new(),
        subscribed_generation: None,
        snapshot_seen: false,
        backfill_seen: false,
        #[cfg(debug_assertions)]
        snapshot_count: 0,
        #[cfg(debug_assertions)]
        backfill_count: 0,
        #[cfg(debug_assertions)]
        command_ids: BTreeSet::new(),
        payload_cursor: StreamCursor::BeforeFirst,
        #[cfg(debug_assertions)]
        terminal_cursor: None,
        configuration_revision: None,
        sync_seen: false,
    };
    while let Some(item) = sequence.next().await.map_err(map_unix_error)? {
        match item {
            ReplySequenceItem::Reply(reply) => {
                accept_conversation_sync_reply(*reply, conversation_id, &mut state)?;
            }
            ReplySequenceItem::TransferComplete(bytes) => {
                let reply = decode_conversation_transfer(&bytes, state.snapshot_seen)?;
                accept_conversation_sync_reply(reply, conversation_id, &mut state)?;
            }
        }
    }
    if state.subscribed_generation.is_none() || !state.sync_seen {
        return Err(protocol_error(
            SYNC_INVALID,
            "Subscribe(BeforeFirst) ended without Subscribed and SyncComplete",
        ));
    }
    Ok(ConversationSynchronization {
        outputs: state.outputs,
        snapshot_seen: state.snapshot_seen,
        #[cfg(debug_assertions)]
        snapshot_count: state.snapshot_count,
        #[cfg(debug_assertions)]
        backfill_count: state.backfill_count,
        #[cfg(debug_assertions)]
        command_ids: state.command_ids,
        #[cfg(debug_assertions)]
        terminal_cursor: state.terminal_cursor,
        configuration_revision: state.configuration_revision,
    })
}

fn decode_conversation_transfer(
    bytes: &[u8],
    snapshot_seen: bool,
) -> Result<RuntimeReply, CliError> {
    if !snapshot_seen && let Ok(snapshot) = serde_json::from_slice::<ConversationSnapshot>(bytes) {
        return Ok(RuntimeReply::Snapshot(snapshot));
    }
    if let Ok(backfill) = serde_json::from_slice::<BackfillChunk>(bytes) {
        return Ok(RuntimeReply::Backfill(backfill));
    }
    if let Ok(snapshot) = serde_json::from_slice::<ConversationSnapshot>(bytes) {
        return Ok(RuntimeReply::Snapshot(snapshot));
    }
    Err(protocol_error(
        TRANSFER_INVALID,
        "conversation transfer is neither a canonical Snapshot nor Backfill",
    ))
}

fn accept_conversation_sync_reply(
    reply: RuntimeReply,
    expected: &ConversationId,
    state: &mut ConversationSyncState,
) -> Result<(), CliError> {
    match &reply {
        RuntimeReply::Subscription(SubscriptionReceipt::Subscribed { stream_generation })
            if state.subscribed_generation.is_none()
                && !state.snapshot_seen
                && !state.backfill_seen
                && !state.sync_seen =>
        {
            state.subscribed_generation = Some(stream_generation.as_str().to_owned());
        }
        RuntimeReply::Snapshot(snapshot)
            if state.subscribed_generation.is_some()
                && !state.snapshot_seen
                && !state.backfill_seen
                && !state.sync_seen
                && &snapshot.conversation_id == expected =>
        {
            state.snapshot_seen = true;
            state.payload_cursor = snapshot.base_event_cursor;
            state.configuration_revision =
                Some(snapshot.configuration_state.configuration_revision());
            #[cfg(debug_assertions)]
            {
                state.snapshot_count += 1;
                for item in snapshot.items() {
                    if let SnapshotItem::Item {
                        command_id: Some(command_id),
                        ..
                    } = item
                    {
                        state.command_ids.insert(command_id.as_str().to_owned());
                    }
                }
            }
        }
        RuntimeReply::Backfill(BackfillChunk::Conversation {
            conversation_id,
            range,
            events,
            ..
        }) if state.subscribed_generation.is_some()
            && !state.sync_seen
            && conversation_id == expected
            && range.after() == state.payload_cursor =>
        {
            state.backfill_seen = true;
            state.payload_cursor = range.through();
            #[cfg(debug_assertions)]
            {
                state.backfill_count += 1;
            }
            for event in events {
                #[cfg(debug_assertions)]
                if let Some(command_id) = &event.command_id {
                    state.command_ids.insert(command_id.as_str().to_owned());
                }
                if let RuntimeEventBody::ConfigurationChanged {
                    state: configuration_state,
                } = &event.body
                {
                    state.configuration_revision =
                        Some(configuration_state.configuration_revision());
                }
            }
        }
        RuntimeReply::SyncComplete(sync)
            if state.subscribed_generation.is_some() && !state.sync_seen =>
        {
            let RuntimeInnerCursor::Conversation {
                conversation_id,
                cursor,
            } = &sync.inner_cursor
            else {
                return Err(protocol_error(
                    SYNC_INVALID,
                    "conversation subscription ended with a catalog cursor",
                ));
            };
            if conversation_id != expected
                || *cursor != state.payload_cursor
                || state.subscribed_generation.as_deref() != Some(sync.stream_generation.as_str())
            {
                return Err(protocol_error(
                    REPLY_IDENTITY_MISMATCH,
                    "SyncComplete does not match the subscribed conversation/generation",
                ));
            }
            state.sync_seen = true;
            #[cfg(debug_assertions)]
            {
                state.terminal_cursor = Some(sync.stream_cursor);
            }
        }
        RuntimeReply::Failure(failure) => return Err(runtime_failure(failure.clone())),
        _ => {
            return Err(protocol_error(
                SYNC_INVALID,
                "conversation subscription emitted an out-of-order or mismatched reply",
            ));
        }
    }
    state.outputs.push(serde_json::to_value(reply)?);
    Ok(())
}

fn configuration_revision(
    reply: RuntimeReply,
    expected: &ConversationId,
    pretty: bool,
) -> Result<u64, CliError> {
    let RuntimeReply::Configuration(receipt) = reply else {
        return Err(unexpected(
            "ConfigureConversation did not return Configuration",
        ));
    };
    let revision = match &receipt {
        ConfigurationReceipt::Applied {
            conversation_id,
            configuration_revision,
        }
        | ConfigurationReceipt::Replayed {
            conversation_id,
            configuration_revision,
        } if conversation_id == expected => *configuration_revision,
        ConfigurationReceipt::Conflict {
            conversation_id,
            current_configuration_revision,
        } if conversation_id == expected => {
            return Err(CliError::Session {
                code: Some(DAEMON_CONVERSATION_CONFIGURATION_CONFLICT.to_owned()),
                message: format!(
                    "Configure(rev0) conflicted with current revision {current_configuration_revision}"
                ),
            });
        }
        ConfigurationReceipt::Failed { failure } => {
            return Err(runtime_failure(failure.clone()));
        }
        _ => {
            return Err(protocol_error(
                REPLY_IDENTITY_MISMATCH,
                "configuration receipt conversationId does not match Start",
            ));
        }
    };
    print_reply(&RuntimeReply::Configuration(receipt), pretty)?;
    Ok(revision)
}

fn print_command_reply(
    reply: RuntimeReply,
    expected_revision: u64,
    pretty: bool,
) -> Result<(), CliError> {
    let RuntimeReply::Command(receipt) = reply else {
        return Err(unexpected("SendPrompt did not return Command"));
    };
    match &receipt {
        CommandReceipt::Accepted {
            configuration_revision,
            ..
        }
        | CommandReceipt::Replayed {
            configuration_revision,
            ..
        } if *configuration_revision == expected_revision => {
            print_reply(&RuntimeReply::Command(receipt), pretty)?;
            Ok(())
        }
        CommandReceipt::Failed { failure } => Err(runtime_failure(failure.clone())),
        _ => Err(protocol_error(
            REPLY_IDENTITY_MISMATCH,
            "command receipt configuration revision does not match SendPrompt",
        )),
    }
}

fn validate_configuration_flags(args: &SessionRunArgs) -> Result<(), CliError> {
    match args.agent {
        AgentKindArg::Codex => {
            if args.permission.is_some()
                || args.output_style.is_some()
                || args.model.is_some()
                || args.effort.is_some()
            {
                return Err(CliError::Usage(
                    "Claude Code configuration flags cannot be used with --agent codex".to_owned(),
                ));
            }
            Ok(())
        }
        AgentKindArg::ClaudeCode => {
            if args.sandbox.is_some() || args.approval.is_some() || args.reasoning_effort.is_some()
            {
                return Err(CliError::Usage(
                    "Codex configuration flags cannot be used with --agent claude-code".to_owned(),
                ));
            }
            let _ = ClaudeCodeConversationConfiguration::new(
                args.permission
                    .map_or(ClaudeCodePermissionMode::Default, Into::into),
                args.model.clone(),
                args.effort.clone(),
                args.output_style.clone(),
            )
            .map_err(|error| CliError::Usage(error.to_string()))?;
            Ok(())
        }
    }
}

fn print_reply(reply: &RuntimeReply, pretty: bool) -> Result<(), CliError> {
    print_value(&serde_json::to_value(reply)?, pretty);
    Ok(())
}

fn print_values(values: &[serde_json::Value], pretty: bool) {
    for value in values {
        print_value(value, pretty);
    }
}

fn print_value(value: &serde_json::Value, pretty: bool) {
    println!("{}", render(value, pretty));
}

fn derived_key(base: &str, scope: &str) -> IdempotencyKey {
    IdempotencyKey::new(format!("{base}:{scope}"))
}

fn validate_idempotency_key(
    value: &str,
    derived_suffix_bytes: usize,
    label: &str,
) -> Result<(), CliError> {
    if value.is_empty()
        || value.as_bytes().contains(&0)
        || value
            .len()
            .checked_add(derived_suffix_bytes)
            .is_none_or(|length| length > MAX_IDEMPOTENCY_KEY_BYTES)
    {
        return Err(CliError::Usage(format!(
            "{label} must produce 1 to {MAX_IDEMPOTENCY_KEY_BYTES} UTF-8 bytes and contain no NUL"
        )));
    }
    Ok(())
}

#[cfg(debug_assertions)]
fn validate_identity(value: &str, label: &str) -> Result<(), CliError> {
    if value.is_empty() || value.as_bytes().contains(&0) || value.len() > MAX_IDEMPOTENCY_KEY_BYTES
    {
        return Err(CliError::Usage(format!(
            "{label} must contain 1 to {MAX_IDEMPOTENCY_KEY_BYTES} UTF-8 bytes and no NUL"
        )));
    }
    Ok(())
}

fn runtime_failure(failure: RuntimeFailure) -> CliError {
    CliError::Session {
        code: Some(failure.code),
        message: failure.message,
    }
}

fn unexpected(message: impl Into<String>) -> CliError {
    protocol_error(UNEXPECTED_REPLY, message)
}

fn protocol_error(code: &str, message: impl Into<String>) -> CliError {
    CliError::Protocol {
        code: Some(code.to_owned()),
        message: message.into(),
    }
}

impl From<AgentKindArg> for AgentKind {
    fn from(value: AgentKindArg) -> Self {
        match value {
            AgentKindArg::Codex => Self::Codex,
            AgentKindArg::ClaudeCode => Self::ClaudeCode,
        }
    }
}

impl From<SandboxArg> for CodexSandboxMode {
    fn from(value: SandboxArg) -> Self {
        match value {
            SandboxArg::ReadOnly => Self::ReadOnly,
            SandboxArg::WorkspaceWrite => Self::WorkspaceWrite,
            SandboxArg::FullAccess => Self::FullAccess,
        }
    }
}

impl From<ApprovalArg> for CodexApprovalPolicy {
    fn from(value: ApprovalArg) -> Self {
        match value {
            ApprovalArg::OnRequest => Self::OnRequest,
            ApprovalArg::Never => Self::Never,
            ApprovalArg::Always => Self::Always,
        }
    }
}

impl From<EffortArg> for CodexReasoningEffort {
    fn from(value: EffortArg) -> Self {
        match value {
            EffortArg::Minimal => Self::Minimal,
            EffortArg::Low => Self::Low,
            EffortArg::Medium => Self::Medium,
            EffortArg::High => Self::High,
        }
    }
}

impl From<PermissionArg> for ClaudeCodePermissionMode {
    fn from(value: PermissionArg) -> Self {
        match value {
            PermissionArg::Default => Self::Default,
            PermissionArg::AcceptEdits => Self::AcceptEdits,
            PermissionArg::Plan => Self::Plan,
            PermissionArg::Auto => Self::Auto,
            PermissionArg::DontAsk => Self::DontAsk,
            PermissionArg::BypassPermissions => Self::BypassPermissions,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::BTreeSet;

    use agentdeck_protocol::runtime::identity::{EventId, StreamGeneration};
    use agentdeck_protocol::runtime::{
        BackfillRange, ConversationConfigurationState, RuntimeEvent, RuntimeSyncComplete,
        SnapshotItem,
    };
    use agentdeck_protocol::{CodexCapabilities, SessionCapabilities, VendorCapabilities};

    fn run_args(agent: AgentKindArg) -> SessionRunArgs {
        SessionRunArgs {
            agent,
            cwd: PathBuf::from("/tmp/runtime-cli-test"),
            prompt: "hello".to_owned(),
            idempotency_key: "stable-run-key".to_owned(),
            sandbox: None,
            approval: None,
            reasoning_effort: None,
            permission: None,
            output_style: None,
            model: None,
            effort: None,
        }
    }

    fn codex_capabilities() -> SessionCapabilities {
        SessionCapabilities {
            agent_kind: AgentKind::Codex,
            agent_version: "runtime-cli-unit-test".to_owned(),
            features: BTreeSet::new(),
            vendor: VendorCapabilities::Codex(CodexCapabilities::default()),
        }
    }

    fn codex_configuration_state(revision: u64) -> ConversationConfigurationState {
        ConversationConfigurationState::new(
            revision,
            Some(ConversationConfiguration::new(
                VendorConfigurationSnapshot::Codex(CodexConversationConfiguration::new(
                    CodexApprovalPolicy::OnRequest,
                    CodexSandboxMode::WorkspaceWrite,
                    CodexReasoningEffort::Medium,
                )),
            )),
        )
        .unwrap()
    }

    fn subscribed_state() -> ConversationSyncState {
        ConversationSyncState {
            outputs: Vec::new(),
            subscribed_generation: Some("generation-unit".to_owned()),
            snapshot_seen: false,
            backfill_seen: false,
            #[cfg(debug_assertions)]
            snapshot_count: 0,
            #[cfg(debug_assertions)]
            backfill_count: 0,
            #[cfg(debug_assertions)]
            command_ids: BTreeSet::new(),
            payload_cursor: StreamCursor::BeforeFirst,
            #[cfg(debug_assertions)]
            terminal_cursor: None,
            configuration_revision: None,
            sync_seen: false,
        }
    }

    fn sync_complete(conversation_id: &ConversationId, cursor: StreamCursor) -> RuntimeReply {
        RuntimeReply::SyncComplete(RuntimeSyncComplete {
            stream_generation: StreamGeneration::new("generation-unit"),
            stream_cursor: cursor,
            inner_cursor: RuntimeInnerCursor::Conversation {
                conversation_id: conversation_id.clone(),
                cursor,
            },
            key_directory_revision: 0,
        })
    }

    #[test]
    fn catalog_decode_requires_canonical_bytes_and_the_exact_requested_page_cursor() {
        let expected = CatalogPageCursor::new("catalog-page-2");
        let matching = CatalogSnapshot::new(
            StreamCursor::At(9),
            Vec::new(),
            Some(expected.clone()),
            None,
        )
        .unwrap();
        let decoded = decode_catalog(
            ReplySequenceItem::Reply(Box::new(RuntimeReply::Catalog(matching.clone()))),
            Some(&expected),
        )
        .expect("direct Catalog page echoes the requested cursor");
        assert_eq!(decoded.current_page_cursor(), Some(&expected));

        let mismatched = CatalogSnapshot::new(StreamCursor::At(9), Vec::new(), None, None).unwrap();
        assert!(matches!(
            decode_catalog(
                ReplySequenceItem::Reply(Box::new(RuntimeReply::Catalog(mismatched.clone()))),
                Some(&expected),
            ),
            Err(CliError::Protocol { .. })
        ));

        let canonical = serde_json::to_vec(&matching).unwrap();
        assert!(
            decode_catalog(
                ReplySequenceItem::TransferComplete(canonical.clone()),
                Some(&expected),
            )
            .is_ok()
        );
        let mut noncanonical = canonical;
        noncanonical.insert(1, b' ');
        assert!(matches!(
            decode_catalog(
                ReplySequenceItem::TransferComplete(noncanonical),
                Some(&expected),
            ),
            Err(CliError::Protocol { .. })
        ));
        assert!(matches!(
            decode_catalog(
                ReplySequenceItem::TransferComplete(serde_json::to_vec(&mismatched).unwrap()),
                Some(&expected),
            ),
            Err(CliError::Protocol { .. })
        ));
    }

    #[test]
    fn run_plan_rejects_cross_agent_flags_before_any_request_exists() {
        let mut codex = run_args(AgentKindArg::Codex);
        codex.permission = Some(PermissionArg::Plan);
        assert!(matches!(
            SessionRunPlan::new(codex),
            Err(CliError::Usage(_))
        ));

        let mut claude = run_args(AgentKindArg::ClaudeCode);
        claude.sandbox = Some(SandboxArg::ReadOnly);
        assert!(matches!(
            SessionRunPlan::new(claude),
            Err(CliError::Usage(_))
        ));
    }

    #[test]
    fn run_plan_builds_start_configure_subscribe_send_prompt_without_legacy_identity() {
        let plan = SessionRunPlan::new(run_args(AgentKindArg::Codex)).unwrap();
        let conversation_id = ConversationId::new("conversation-canonical-1");
        let requests = [
            RuntimeRequest::DescribeAgents,
            plan.start_request(),
            plan.configure_request(
                conversation_id.clone(),
                ConversationConfiguration::new(VendorConfigurationSnapshot::Codex(
                    CodexConversationConfiguration::new(
                        CodexApprovalPolicy::OnRequest,
                        CodexSandboxMode::WorkspaceWrite,
                        CodexReasoningEffort::Medium,
                    ),
                )),
            ),
            RuntimeRequest::Subscribe {
                inner_cursor: RuntimeInnerCursor::Conversation {
                    conversation_id: conversation_id.clone(),
                    cursor: StreamCursor::BeforeFirst,
                },
            },
            plan.prompt_request(conversation_id, 1).unwrap(),
        ];
        let values = requests
            .iter()
            .map(|request| serde_json::to_value(request).unwrap())
            .collect::<Vec<_>>();
        assert_eq!(values[0]["request"], "describeAgents");
        assert_eq!(values[1]["request"], "start");
        assert_eq!(values[2]["request"], "configureConversation");
        assert_eq!(values[2]["expectedConfigurationRevision"], 0);
        assert_eq!(values[3]["request"], "subscribe");
        assert_eq!(values[4]["request"], "sendPrompt");
        assert_eq!(values[4]["expectedConfigurationRevision"], 1);
        let encoded = serde_json::to_string(&values).unwrap();
        for forbidden in [
            "threadId",
            "sessionId",
            "persistApproval",
            "worktree",
            "sessionName",
        ] {
            assert!(
                !encoded.contains(forbidden),
                "legacy field leaked: {encoded}"
            );
        }
    }

    #[test]
    fn continue_and_metadata_use_only_conversation_id_and_revisioned_idempotency() {
        let continuation = SessionContinuePlan::new(
            "conversation-continue-1".into(),
            "next".into(),
            "stable-continue-key".into(),
        )
        .unwrap();
        let prompt = serde_json::to_value(continuation.prompt_request(7)).unwrap();
        assert_eq!(prompt["conversationId"], "conversation-continue-1");
        assert_eq!(prompt["expectedConfigurationRevision"], 7);

        let metadata = MetadataPlan::archived(
            "conversation-continue-1".into(),
            true,
            4,
            "stable-metadata-key".into(),
        )
        .unwrap();
        let metadata = serde_json::to_value(metadata.request().unwrap()).unwrap();
        assert_eq!(metadata["conversationId"], "conversation-continue-1");
        assert_eq!(metadata["expectedEntryRevision"], 4);
        assert_eq!(metadata["idempotencyKey"], "stable-metadata-key");
        assert!(metadata.get("threadId").is_none());
    }

    #[test]
    fn runtime_globals_reject_legacy_namespace_overrides() {
        assert!(validate_runtime_globals("stable", None).is_ok());
        assert!(matches!(
            validate_runtime_globals("dev", None),
            Err(CliError::Usage(_))
        ));
        assert!(matches!(
            validate_runtime_globals("stable", Some("/tmp/legacy")),
            Err(CliError::Usage(_))
        ));
    }

    #[test]
    fn conversation_sync_accepts_pure_contiguous_backfill_and_extracts_configuration() {
        let conversation_id = ConversationId::new("conversation-backfill-only");
        let configuration_state = codex_configuration_state(3);
        let event = RuntimeEvent::new(
            conversation_id.clone(),
            EventId::new("event-configuration-0"),
            0,
            None,
            None,
            None,
            RuntimeEventBody::ConfigurationChanged {
                state: configuration_state,
            },
        )
        .unwrap();
        let backfill = BackfillChunk::conversation(
            conversation_id.clone(),
            codex_capabilities(),
            BackfillRange::new(StreamCursor::BeforeFirst, StreamCursor::At(0)).unwrap(),
            vec![event],
        )
        .unwrap();
        let mut state = subscribed_state();

        accept_conversation_sync_reply(
            RuntimeReply::Backfill(backfill),
            &conversation_id,
            &mut state,
        )
        .unwrap();
        accept_conversation_sync_reply(
            sync_complete(&conversation_id, StreamCursor::At(0)),
            &conversation_id,
            &mut state,
        )
        .unwrap();

        assert!(!state.snapshot_seen);
        assert!(state.backfill_seen);
        assert_eq!(state.payload_cursor, StreamCursor::At(0));
        assert_eq!(state.configuration_revision, Some(3));
        assert!(state.sync_seen);
    }

    #[test]
    fn conversation_sync_rejects_snapshot_after_backfill_and_terminal_cursor_mismatch() {
        let conversation_id = ConversationId::new("conversation-sync-order");
        let event = RuntimeEvent::new(
            conversation_id.clone(),
            EventId::new("event-configuration-0"),
            0,
            None,
            None,
            None,
            RuntimeEventBody::ConfigurationChanged {
                state: codex_configuration_state(1),
            },
        )
        .unwrap();
        let backfill = BackfillChunk::conversation(
            conversation_id.clone(),
            codex_capabilities(),
            BackfillRange::new(StreamCursor::BeforeFirst, StreamCursor::At(0)).unwrap(),
            vec![event],
        )
        .unwrap();
        let mut state = subscribed_state();
        accept_conversation_sync_reply(
            RuntimeReply::Backfill(backfill),
            &conversation_id,
            &mut state,
        )
        .unwrap();

        let snapshot = ConversationSnapshot::new(
            conversation_id.clone(),
            StreamCursor::BeforeFirst,
            codex_configuration_state(1),
            vec![SnapshotItem::capabilities(codex_capabilities())],
        )
        .unwrap();
        assert!(matches!(
            accept_conversation_sync_reply(
                RuntimeReply::Snapshot(snapshot),
                &conversation_id,
                &mut state,
            ),
            Err(CliError::Protocol { .. })
        ));
        assert!(matches!(
            accept_conversation_sync_reply(
                sync_complete(&conversation_id, StreamCursor::At(1)),
                &conversation_id,
                &mut state,
            ),
            Err(CliError::Protocol { .. })
        ));
    }

    #[test]
    fn empty_conversation_sync_requires_before_first_terminal_cursor() {
        let conversation_id = ConversationId::new("conversation-empty-sync");
        let mut valid = subscribed_state();
        accept_conversation_sync_reply(
            sync_complete(&conversation_id, StreamCursor::BeforeFirst),
            &conversation_id,
            &mut valid,
        )
        .unwrap();
        assert!(valid.sync_seen);

        let mut invalid = subscribed_state();
        assert!(matches!(
            accept_conversation_sync_reply(
                sync_complete(&conversation_id, StreamCursor::At(0)),
                &conversation_id,
                &mut invalid,
            ),
            Err(CliError::Protocol { .. })
        ));
    }
}
