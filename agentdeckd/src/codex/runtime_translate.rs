//! Codex app-server → typed Runtime execution 输出。
//!
//! 该 translator 不构造 SessionId/ThreadId，也不输出 Raw vendor frame。vendor item id
//! 只在本实例的私有 map 中关联一个中立 `AdapterItemKey`；RuntimeCore 再生成 durable
//! item/entity/event identity。

use std::collections::{HashMap, HashSet};
use std::fmt;

use agentdeck_protocol::{
    ActionKind, ActionRequest, ActionRequestVendor, AgentItem, AgentItemMeta, CodexApprovalPolicy,
    CodexSandboxMode, ProtocolError, ShellStatus, TurnSummary,
};
use serde_json::{Value, json};

use super::adapter::{validate_absolute_normal_path, validated_permission_profile};
use super::translate::{plan_steps, reasoning_text, terminal_shell_status_from, user_message_text};
use crate::agent::{AdapterEvent, AdapterItemKey};
use crate::record::redact;

const MAX_TRANSLATED_ITEMS_PER_TURN: u64 = 10_000;
const MAX_TRANSLATOR_RETAINED_BYTES: usize = 8 * 1024 * 1024;
pub(super) const MAX_APPROVAL_SUMMARY_BYTES: usize = 1024;
const MAX_APPROVAL_REDACTION_INPUT_BYTES: usize = MAX_APPROVAL_SUMMARY_BYTES * 2;
const MAX_APPROVAL_COMMAND_ACTIONS: usize = MAX_APPROVAL_SUMMARY_BYTES / 4;
const MAX_DIAGNOSTIC_SOURCE_BYTES: usize = 8 * 1024;
const MAX_DIAGNOSTIC_DETAIL_BYTES: usize = 4 * 1024;

#[derive(Clone)]
pub(super) struct CodexApprovalRoute {
    pub(super) rpc_id: Value,
    pub(super) method: String,
    pub(super) params: Value,
}

pub(super) enum CodexRuntimeOutput {
    Event(AdapterEvent),
    Diagnostic {
        code: String,
        detail: String,
    },
    Approval {
        request: ActionRequest,
        route: CodexApprovalRoute,
    },
    TurnComplete(TurnSummary),
}

impl fmt::Debug for CodexApprovalRoute {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("CodexApprovalRoute")
            .field("rpc_id", &"<redacted>")
            .field("method", &self.method)
            .field("params", &"<redacted>")
            .finish()
    }
}

impl fmt::Debug for CodexRuntimeOutput {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Event(_) => formatter.write_str("CodexRuntimeOutput::Event(<redacted>)"),
            Self::Diagnostic { code, .. } => formatter
                .debug_struct("CodexRuntimeOutput::Diagnostic")
                .field("code", code)
                .field("detail", &"<redacted>")
                .finish(),
            Self::Approval { route, .. } => formatter
                .debug_struct("CodexRuntimeOutput::Approval")
                .field("request", &"<redacted>")
                .field("route", route)
                .finish(),
            Self::TurnComplete(_) => {
                formatter.write_str("CodexRuntimeOutput::TurnComplete(<redacted>)")
            }
        }
    }
}

#[derive(Debug)]
struct RuntimeInFlightItem {
    kind: RuntimeItemKind,
    accumulated_text: String,
    file_change_approval: Option<FileChangeApprovalContext>,
    key: AdapterItemKey,
}

#[derive(Debug, Clone, Copy, Eq, PartialEq)]
enum RuntimeItemKind {
    AssistantMessage,
    Reasoning,
    Shell,
    Diff,
    Plan,
    ImageView,
    ImageGeneration,
    McpToolCall,
    DynamicToolCall,
    CollabAgentToolCall,
    WebSearch,
    UserMessage,
    SubAgentActivity,
    Sleep,
    EnteredReviewMode,
    ExitedReviewMode,
    ContextCompaction,
    IgnoredHookPrompt,
}

#[derive(Debug)]
enum FileChangeApprovalContext {
    Ready(String),
    Empty,
    TooLarge,
}

impl FileChangeApprovalContext {
    fn retained_bytes(&self) -> usize {
        match self {
            Self::Ready(value) => value.len(),
            Self::Empty | Self::TooLarge => 0,
        }
    }
}

#[derive(Debug)]
struct PendingTokenUsage {
    turn_id: String,
    input_tokens: u64,
    output_tokens: u64,
}

#[derive(Debug)]
pub(super) struct CodexRuntimeTranslator {
    in_flight: HashMap<String, RuntimeInFlightItem>,
    completed_ids: HashSet<String>,
    next_item_key: u64,
    next_request_id: u64,
    retained_bytes: usize,
    retained_byte_limit: usize,
    token_usage: Option<PendingTokenUsage>,
    approval_policy: CodexApprovalPolicy,
    sandbox: CodexSandboxMode,
}

impl CodexRuntimeTranslator {
    #[cfg(test)]
    pub(super) fn new() -> Self {
        Self::with_configuration(
            CodexApprovalPolicy::OnRequest,
            CodexSandboxMode::WorkspaceWrite,
        )
    }

    pub(super) fn with_configuration(
        approval_policy: CodexApprovalPolicy,
        sandbox: CodexSandboxMode,
    ) -> Self {
        Self {
            in_flight: HashMap::new(),
            completed_ids: HashSet::new(),
            next_item_key: 1,
            next_request_id: 1,
            retained_bytes: 0,
            retained_byte_limit: MAX_TRANSLATOR_RETAINED_BYTES,
            token_usage: None,
            approval_policy,
            sandbox,
        }
    }

    #[cfg(test)]
    pub(super) fn with_retained_byte_limit(retained_byte_limit: usize) -> Self {
        Self {
            retained_byte_limit,
            ..Self::new()
        }
    }

    #[cfg(test)]
    pub(super) fn translate_line(
        &mut self,
        line: &str,
    ) -> Result<Vec<CodexRuntimeOutput>, ProtocolError> {
        let frame = serde_json::from_str::<Value>(line)
            .map_err(|_| fixed_error("codex-malformed-json", "Codex emitted malformed JSON"))?;
        self.translate_value(&frame)
    }

    pub(super) fn translate_value(
        &mut self,
        frame: &Value,
    ) -> Result<Vec<CodexRuntimeOutput>, ProtocolError> {
        if frame.get("error").is_some_and(|value| !value.is_null()) {
            return Err(fixed_error(
                "codex-protocol-error",
                "Codex returned a protocol error",
            ));
        }
        let method = frame.get("method").and_then(Value::as_str);
        let params = frame.get("params").cloned().unwrap_or_else(|| json!({}));
        if let (Some(method), Some(rpc_id)) = (method, frame.get("id")) {
            let request = self.approval_request(method, &params, rpc_id)?;
            let route = CodexApprovalRoute {
                rpc_id: validated_rpc_id(rpc_id)?,
                method: method.to_owned(),
                params,
            };
            return Ok(vec![CodexRuntimeOutput::Approval { request, route }]);
        }
        if frame.get("id").is_some() {
            return Err(fixed_error(
                "codex-unexpected-response",
                "Codex emitted an unexpected response frame",
            ));
        }
        let Some(method) = method else {
            return Err(fixed_error(
                "codex-unmodeled-frame",
                "Codex emitted an unmodeled protocol frame",
            ));
        };
        match method {
            "turn/completed" => {
                let turn = params
                    .get("turn")
                    .and_then(Value::as_object)
                    .ok_or_else(|| {
                        fixed_error(
                            "codex-turn-terminal-invalid",
                            "Codex completed a turn without an authoritative terminal object",
                        )
                    })?;
                if turn.get("status").and_then(Value::as_str) != Some("completed")
                    || turn.get("error").is_some_and(|error| !error.is_null())
                {
                    return Err(fixed_error(
                        "codex-turn-not-completed",
                        "Codex reported a non-success terminal turn",
                    ));
                }
                if !self.in_flight.is_empty() {
                    return Err(fixed_error(
                        "codex-turn-incomplete",
                        "Codex completed a turn with in-flight items",
                    ));
                }
                let turn_id = turn
                    .get("id")
                    .and_then(Value::as_str)
                    .filter(|value| !value.is_empty())
                    .ok_or_else(|| {
                        fixed_error(
                            "codex-turn-terminal-invalid",
                            "Codex completed a turn without an authoritative identity",
                        )
                    })?;
                if self
                    .token_usage
                    .as_ref()
                    .is_some_and(|usage| usage.turn_id != turn_id)
                {
                    return Err(fixed_error(
                        "codex-token-usage-turn-mismatch",
                        "Codex token usage does not belong to the completed turn",
                    ));
                }
                let token_usage = self.token_usage.take();
                if let Some(usage) = &token_usage {
                    self.retained_bytes -= usage.turn_id.len();
                }
                Ok(vec![CodexRuntimeOutput::TurnComplete(turn_summary(
                    &params,
                    token_usage.as_ref(),
                ))])
            }
            "turn/started"
            | "thread/started"
            | "thread/closed"
            | "thread/archived"
            | "thread/unarchived"
            | "thread/deleted"
            | "thread/settings/updated"
            | "thread/name/updated"
            | "thread/status/changed"
            | "thread/goal/cleared"
            | "thread/goal/updated"
            | "thread/compacted"
            | "turn/diff/updated"
            | "turn/plan/updated"
            | "serverRequest/resolved"
            | "hook/started"
            | "hook/completed" => Ok(Vec::new()),
            "warning" | "configWarning" | "deprecationNotice" | "guardianWarning" => {
                diagnostic_notification(method, &params)
            }
            "model/rerouted"
            | "model/safetyBuffering/updated"
            | "model/verification"
            | "turn/moderationMetadata" => Ok(vec![CodexRuntimeOutput::Diagnostic {
                code: format!("codex-{}", method.replace('/', "-")),
                detail: "Codex emitted a modeled non-terminal diagnostic notification".to_owned(),
            }]),
            "error" => error_notification(&params),
            "thread/tokenUsage/updated" => self.token_usage_updated(&params),
            "item/started" => self.item_started(&params),
            "item/completed" => self.item_completed(&params),
            "item/agentMessage/delta" => {
                self.accumulate_text(&params, RuntimeItemKind::AssistantMessage, "delta")?;
                Ok(Vec::new())
            }
            "item/reasoning/textDelta" | "item/reasoning/summaryTextDelta" => {
                self.accumulate_text(&params, RuntimeItemKind::Reasoning, "delta")?;
                Ok(Vec::new())
            }
            "item/reasoning/summaryPartAdded" => {
                self.accumulate_text(&params, RuntimeItemKind::Reasoning, "summary")?;
                Ok(Vec::new())
            }
            "item/commandExecution/outputDelta" => {
                self.validate_command_output_delta(&params)?;
                Ok(Vec::new())
            }
            "item/fileChange/patchUpdated" => self.file_change_patch_updated(&params),
            // 威胁场景：官方 partial 通知若被当成未知帧，正常的 plan、diff、MCP
            // 或 terminal 流会在 authoritative item/completed 之前被错误终止。
            "item/commandExecution/terminalInteraction"
            | "item/fileChange/outputDelta"
            | "item/plan/delta"
            | "item/mcpToolCall/progress"
            | "item/autoApprovalReview/started"
            | "item/autoApprovalReview/completed" => Ok(Vec::new()),
            other if other.starts_with("item/") => Err(fixed_error(
                "codex-unmodeled-item",
                "Codex emitted an unmodeled item frame",
            )),
            _ => Err(fixed_error(
                "codex-unmodeled-frame",
                "Codex emitted an unmodeled protocol frame",
            )),
        }
    }

    fn item_started(&mut self, params: &Value) -> Result<Vec<CodexRuntimeOutput>, ProtocolError> {
        let item = params
            .get("item")
            .ok_or_else(|| fixed_error("codex-item-invalid", "Codex item is missing"))?;
        let id = item
            .get("id")
            .and_then(Value::as_str)
            .filter(|value| !value.is_empty())
            .ok_or_else(|| fixed_error("codex-item-invalid", "Codex item identity is missing"))?;
        if self.in_flight.contains_key(id) || self.completed_ids.contains(id) {
            return Err(fixed_error(
                "codex-item-duplicate",
                "Codex repeated an item identity",
            ));
        }
        let kind = runtime_item_kind(item)?;
        let key = self.next_key()?;
        let initial_text = match kind {
            RuntimeItemKind::AssistantMessage => item
                .get("text")
                .and_then(Value::as_str)
                .unwrap_or_default()
                .to_owned(),
            RuntimeItemKind::Reasoning => reasoning_text(item),
            _ => String::new(),
        };
        let file_change_approval = if matches!(kind, RuntimeItemKind::Diff) {
            Some(file_change_approval_context(item)?)
        } else {
            None
        };
        let initial_text_bytes = initial_text.len();
        let approval_bytes = file_change_approval
            .as_ref()
            .map_or(0, FileChangeApprovalContext::retained_bytes);
        self.ensure_retained_capacity(
            id.len()
                .saturating_add(initial_text_bytes)
                .saturating_add(approval_bytes),
        )?;
        self.in_flight.insert(
            id.to_owned(),
            RuntimeInFlightItem {
                kind,
                accumulated_text: initial_text,
                file_change_approval,
                key: key.clone(),
            },
        );
        self.retained_bytes += id.len() + initial_text_bytes + approval_bytes;
        let started_item = match kind {
            RuntimeItemKind::Shell => Some(shell_item(item, ShellStatus::Running)),
            RuntimeItemKind::Diff => Some(AgentItem::Diff {
                files: runtime_diff_files(item)?,
                meta: status_meta("inProgress"),
            }),
            _ => None,
        };
        if let Some(item) = started_item {
            return Ok(vec![CodexRuntimeOutput::Event(AdapterEvent::Item {
                key,
                item,
            })]);
        }
        Ok(Vec::new())
    }

    fn item_completed(&mut self, params: &Value) -> Result<Vec<CodexRuntimeOutput>, ProtocolError> {
        let item = params
            .get("item")
            .ok_or_else(|| fixed_error("codex-item-invalid", "Codex item is missing"))?;
        let id = item
            .get("id")
            .and_then(Value::as_str)
            .filter(|value| !value.is_empty())
            .ok_or_else(|| fixed_error("codex-item-invalid", "Codex item identity is missing"))?;
        if self.completed_ids.contains(id) {
            return Err(fixed_error(
                "codex-item-duplicate",
                "Codex repeated an item identity",
            ));
        }
        let prior = self.in_flight.get(id).ok_or_else(|| {
            fixed_error(
                "codex-item-completion-orphan",
                "Codex completed an item that was not started",
            )
        })?;
        if runtime_item_kind(item)? != prior.kind {
            return Err(fixed_error(
                "codex-item-kind-mismatch",
                "Codex changed an in-flight item kind",
            ));
        }
        let item = build_item(item, prior.kind, &prior.accumulated_text)?;
        let (owned_id, prior) = self
            .in_flight
            .remove_entry(id)
            .expect("item existence was checked above");
        self.retained_bytes -= prior.accumulated_text.len()
            + prior
                .file_change_approval
                .as_ref()
                .map_or(0, FileChangeApprovalContext::retained_bytes);
        let key = prior.key;
        self.completed_ids.insert(owned_id);
        Ok(item.map_or_else(Vec::new, |item| {
            vec![CodexRuntimeOutput::Event(AdapterEvent::Item { key, item })]
        }))
    }

    fn accumulate_text(
        &mut self,
        params: &Value,
        kind: RuntimeItemKind,
        field: &str,
    ) -> Result<(), ProtocolError> {
        let id = params
            .get("itemId")
            .and_then(Value::as_str)
            .filter(|value| !value.is_empty())
            .ok_or_else(|| fixed_error("codex-item-invalid", "Codex delta identity is missing"))?;
        if self.completed_ids.contains(id) {
            return Err(fixed_error(
                "codex-item-duplicate",
                "Codex emitted a delta for a completed item",
            ));
        }
        let entry = self.in_flight.get_mut(id).ok_or_else(|| {
            fixed_error(
                "codex-item-delta-orphan",
                "Codex emitted a delta for an item that was not started",
            )
        })?;
        if entry.kind != kind {
            return Err(fixed_error(
                "codex-item-kind-mismatch",
                "Codex changed an in-flight item kind",
            ));
        }
        let delta = params
            .get(field)
            .and_then(Value::as_str)
            .unwrap_or_default();
        let new_retained_bytes = self
            .retained_bytes
            .checked_add(delta.len())
            .filter(|value| *value <= self.retained_byte_limit)
            .ok_or_else(|| {
                fixed_error(
                    "codex-retained-state-limit",
                    "Codex retained translator state exceeds the fixed turn bound",
                )
            })?;
        entry.accumulated_text.push_str(delta);
        self.retained_bytes = new_retained_bytes;
        Ok(())
    }

    fn ensure_retained_capacity(&self, additional: usize) -> Result<(), ProtocolError> {
        self.retained_bytes
            .checked_add(additional)
            .filter(|value| *value <= self.retained_byte_limit)
            .map(|_| ())
            .ok_or_else(|| {
                fixed_error(
                    "codex-retained-state-limit",
                    "Codex retained translator state exceeds the fixed turn bound",
                )
            })
    }

    fn token_usage_updated(
        &mut self,
        params: &Value,
    ) -> Result<Vec<CodexRuntimeOutput>, ProtocolError> {
        let turn_id = params
            .get("turnId")
            .and_then(Value::as_str)
            .filter(|value| !value.is_empty())
            .ok_or_else(|| {
                fixed_error(
                    "codex-token-usage-invalid",
                    "Codex token usage is missing its turn identity",
                )
            })?;
        let last = params
            .get("tokenUsage")
            .and_then(|value| value.get("last"))
            .ok_or_else(|| {
                fixed_error(
                    "codex-token-usage-invalid",
                    "Codex token usage is missing its per-turn counters",
                )
            })?;
        let input_tokens = last
            .get("inputTokens")
            .and_then(Value::as_u64)
            .ok_or_else(|| {
                fixed_error(
                    "codex-token-usage-invalid",
                    "Codex input token count is invalid",
                )
            })?;
        let output_tokens = last
            .get("outputTokens")
            .and_then(Value::as_u64)
            .ok_or_else(|| {
                fixed_error(
                    "codex-token-usage-invalid",
                    "Codex output token count is invalid",
                )
            })?;

        if let Some(current) = self.token_usage.as_mut() {
            if current.turn_id == turn_id {
                current.input_tokens = input_tokens;
                current.output_tokens = output_tokens;
                return Ok(Vec::new());
            }
            return Err(fixed_error(
                "codex-token-usage-turn-mismatch",
                "Codex emitted token usage for multiple turns",
            ));
        }
        self.ensure_retained_capacity(turn_id.len())?;
        self.token_usage = Some(PendingTokenUsage {
            turn_id: turn_id.to_owned(),
            input_tokens,
            output_tokens,
        });
        self.retained_bytes += turn_id.len();
        Ok(Vec::new())
    }

    fn validate_command_output_delta(&self, params: &Value) -> Result<(), ProtocolError> {
        // 威胁场景：命令可合法产生无限输出；canonical Shell 当前不持久化 stdout，
        // 若仍把 delta 累进 translator 内存，8 MiB 后会让正常 turn 失败且最终全部丢弃。
        if !params.get("delta").is_some_and(Value::is_string) {
            return Err(fixed_error(
                "codex-item-invalid",
                "Codex command output delta is invalid",
            ));
        }
        let id = params
            .get("itemId")
            .and_then(Value::as_str)
            .filter(|value| !value.is_empty())
            .ok_or_else(|| fixed_error("codex-item-invalid", "Codex delta identity is missing"))?;
        if self.completed_ids.contains(id) {
            return Err(fixed_error(
                "codex-item-duplicate",
                "Codex emitted a delta for a completed item",
            ));
        }
        let entry = self.in_flight.get(id).ok_or_else(|| {
            fixed_error(
                "codex-item-delta-orphan",
                "Codex emitted a delta for an item that was not started",
            )
        })?;
        if entry.kind != RuntimeItemKind::Shell {
            return Err(fixed_error(
                "codex-item-kind-mismatch",
                "Codex changed an in-flight item kind",
            ));
        }
        Ok(())
    }

    fn file_change_patch_updated(
        &mut self,
        params: &Value,
    ) -> Result<Vec<CodexRuntimeOutput>, ProtocolError> {
        let id = params
            .get("itemId")
            .and_then(Value::as_str)
            .filter(|value| !value.is_empty())
            .ok_or_else(|| fixed_error("codex-item-invalid", "Codex delta identity is missing"))?;
        if self.completed_ids.contains(id) {
            return Err(fixed_error(
                "codex-item-duplicate",
                "Codex emitted a patch update for a completed item",
            ));
        }
        let item = json!({
            "type": "fileChange",
            "id": id,
            "status": "inProgress",
            "changes": params.get("changes").cloned().unwrap_or(Value::Null)
        });
        let files = runtime_diff_files(&item)?;
        let next_approval = file_change_approval_context(&item)?;
        let next_bytes = next_approval.retained_bytes();
        let entry = self.in_flight.get(id).ok_or_else(|| {
            fixed_error(
                "codex-item-delta-orphan",
                "Codex emitted a patch update for an item that was not started",
            )
        })?;
        if entry.kind != RuntimeItemKind::Diff {
            return Err(fixed_error(
                "codex-item-kind-mismatch",
                "Codex changed an in-flight item kind",
            ));
        }
        let prior_bytes = entry
            .file_change_approval
            .as_ref()
            .map_or(0, FileChangeApprovalContext::retained_bytes);
        let without_prior = self.retained_bytes.saturating_sub(prior_bytes);
        if without_prior
            .checked_add(next_bytes)
            .is_none_or(|value| value > self.retained_byte_limit)
        {
            return Err(fixed_error(
                "codex-retained-state-limit",
                "Codex retained translator state exceeds the fixed turn bound",
            ));
        }
        let entry = self
            .in_flight
            .get_mut(id)
            .expect("item existence was checked above");
        entry.file_change_approval = Some(next_approval);
        self.retained_bytes = without_prior + next_bytes;
        Ok(vec![CodexRuntimeOutput::Event(AdapterEvent::Item {
            key: entry.key.clone(),
            item: AgentItem::Diff {
                files,
                meta: status_meta("inProgress"),
            },
        })])
    }

    fn next_key(&mut self) -> Result<AdapterItemKey, ProtocolError> {
        let value = self.next_item_key;
        if value > MAX_TRANSLATED_ITEMS_PER_TURN {
            return Err(fixed_error(
                "codex-item-limit",
                "Codex item count exceeds the fixed turn bound",
            ));
        }
        self.next_item_key = value
            .checked_add(1)
            .ok_or_else(|| fixed_error("codex-item-overflow", "Codex item counter overflowed"))?;
        AdapterItemKey::new(format!("codex-item-{value}"))
    }

    fn approval_request(
        &mut self,
        method: &str,
        params: &Value,
        rpc_id: &Value,
    ) -> Result<ActionRequest, ProtocolError> {
        let (kind, summary) = match method {
            "item/commandExecution/requestApproval" => (
                ActionKind::ExecuteCommand,
                command_approval_summary(params)?,
            ),
            "item/fileChange/requestApproval" => (
                ActionKind::EditFiles,
                self.file_change_approval_summary(params)?,
            ),
            "item/permissions/requestApproval" => (
                ActionKind::GrantExtraPermission,
                permissions_approval_summary(params)?,
            ),
            _ => {
                return Err(fixed_error(
                    "codex-unmodeled-request",
                    "Codex emitted an unmodeled server request",
                ));
            }
        };
        let request_id = params
            .get("approvalId")
            .and_then(Value::as_str)
            .filter(|value| !value.is_empty())
            .map(str::to_owned)
            .or_else(|| {
                rpc_id
                    .as_str()
                    .filter(|value| !value.is_empty())
                    .map(str::to_owned)
            })
            .or_else(|| rpc_id.as_i64().map(|value| value.to_string()))
            .unwrap_or_else(|| {
                let value = self.next_request_id;
                self.next_request_id = value.saturating_add(1);
                format!("codex-request-{value}")
            });
        Ok(ActionRequest {
            request_id,
            kind,
            summary,
            vendor: ActionRequestVendor::Codex {
                approval_policy_at_decision: self.approval_policy,
                sandbox_at_decision: self.sandbox,
                can_persist: true,
            },
        })
    }

    fn file_change_approval_summary(&self, params: &Value) -> Result<String, ProtocolError> {
        let item_id = params
            .get("itemId")
            .and_then(Value::as_str)
            .filter(|value| !value.is_empty())
            .ok_or_else(|| {
                fixed_error(
                    "codex-invalid-approval-params",
                    "Codex file approval is missing its item identity",
                )
            })?;
        let item = self.in_flight.get(item_id).ok_or_else(|| {
            fixed_error(
                "codex-approval-action-missing",
                "Codex file approval does not match an in-flight file change",
            )
        })?;
        if item.kind != RuntimeItemKind::Diff {
            return Err(fixed_error(
                "codex-approval-action-missing",
                "Codex file approval does not match an in-flight file change",
            ));
        }
        let changes = match item.file_change_approval.as_ref() {
            Some(FileChangeApprovalContext::Ready(value)) => value.clone(),
            Some(FileChangeApprovalContext::Empty) | None => {
                return Err(fixed_error(
                    "codex-approval-action-missing",
                    "Codex requested file approval without concrete changes",
                ));
            }
            Some(FileChangeApprovalContext::TooLarge) => {
                return Err(approval_summary_too_large());
            }
        };
        let details = [
            ("changes", Some(changes)),
            ("root", approval_text_field(params, "grantRoot")?),
            ("reason", approval_text_field(params, "reason")?),
        ];
        approval_summary("Apply file changes", &details)
    }
}

fn build_item(
    item: &Value,
    kind: RuntimeItemKind,
    accumulated: &str,
) -> Result<Option<AgentItem>, ProtocolError> {
    let item = match kind {
        RuntimeItemKind::AssistantMessage => AgentItem::AssistantMessage {
            text: item
                .get("text")
                .and_then(Value::as_str)
                .filter(|value| !value.is_empty())
                .map(str::to_owned)
                .unwrap_or_else(|| accumulated.to_owned()),
            meta: runtime_assistant_meta(item),
        },
        RuntimeItemKind::Reasoning => AgentItem::Reasoning {
            text: {
                let final_text = reasoning_text(item);
                if final_text.is_empty() {
                    accumulated.to_owned()
                } else {
                    final_text
                }
            },
            meta: AgentItemMeta::default(),
        },
        RuntimeItemKind::Shell => shell_item(item, terminal_shell_status_from(item)?),
        RuntimeItemKind::Diff => AgentItem::Diff {
            files: runtime_diff_files(item)?,
            meta: terminal_status_meta(item, &["completed", "failed", "declined"])?,
        },
        RuntimeItemKind::Plan => AgentItem::Plan {
            steps: plan_steps(item, accumulated),
            meta: AgentItemMeta::default(),
        },
        RuntimeItemKind::ImageView => AgentItem::ImageReference {
            saved_path: item.get("path").and_then(Value::as_str).map(Into::into),
            original_path: item.get("path").and_then(Value::as_str).map(Into::into),
            meta: AgentItemMeta::default(),
        },
        RuntimeItemKind::ImageGeneration => image_generation_item(item)?,
        RuntimeItemKind::McpToolCall => mcp_tool_call_item(item)?,
        RuntimeItemKind::DynamicToolCall => dynamic_tool_call_item(item)?,
        RuntimeItemKind::CollabAgentToolCall => collab_agent_tool_call_item(item)?,
        RuntimeItemKind::WebSearch => web_search_item(item)?,
        RuntimeItemKind::UserMessage => AgentItem::UserMessage {
            text: user_message_text(item),
            meta: AgentItemMeta::default(),
        },
        RuntimeItemKind::SubAgentActivity => sub_agent_activity_item(item)?,
        RuntimeItemKind::Sleep => sleep_item(item)?,
        RuntimeItemKind::EnteredReviewMode => review_mode_item(item, "enteredReviewMode")?,
        RuntimeItemKind::ExitedReviewMode => review_mode_item(item, "exitedReviewMode")?,
        RuntimeItemKind::ContextCompaction => AgentItem::ToolCall {
            name: "contextCompaction".to_owned(),
            args: json!({}),
            result: None,
            meta: AgentItemMeta::default(),
        },
        RuntimeItemKind::IgnoredHookPrompt => return Ok(None),
    };
    Ok(Some(item))
}

fn runtime_item_kind(item: &Value) -> Result<RuntimeItemKind, ProtocolError> {
    let kind = match item.get("type").and_then(Value::as_str) {
        Some("agentMessage") => RuntimeItemKind::AssistantMessage,
        Some("reasoning") => RuntimeItemKind::Reasoning,
        Some("commandExecution") => RuntimeItemKind::Shell,
        Some("fileChange") => RuntimeItemKind::Diff,
        Some("plan") => RuntimeItemKind::Plan,
        Some("imageView") => RuntimeItemKind::ImageView,
        Some("imageGeneration") => RuntimeItemKind::ImageGeneration,
        Some("mcpToolCall") => RuntimeItemKind::McpToolCall,
        Some("dynamicToolCall") => RuntimeItemKind::DynamicToolCall,
        Some("collabAgentToolCall") => RuntimeItemKind::CollabAgentToolCall,
        Some("webSearch") => RuntimeItemKind::WebSearch,
        Some("userMessage") => RuntimeItemKind::UserMessage,
        Some("subAgentActivity") => RuntimeItemKind::SubAgentActivity,
        Some("sleep") => RuntimeItemKind::Sleep,
        Some("enteredReviewMode") => RuntimeItemKind::EnteredReviewMode,
        Some("exitedReviewMode") => RuntimeItemKind::ExitedReviewMode,
        Some("contextCompaction") => RuntimeItemKind::ContextCompaction,
        Some("hookPrompt") if item.get("fragments").is_some_and(Value::is_array) => {
            RuntimeItemKind::IgnoredHookPrompt
        }
        _ => {
            return Err(fixed_error(
                "codex-unmodeled-item",
                "Codex emitted an unmodeled item",
            ));
        }
    };
    Ok(kind)
}

fn terminal_status_meta(item: &Value, allowed: &[&str]) -> Result<AgentItemMeta, ProtocolError> {
    let status = required_item_string(item, "status")?;
    if !allowed.contains(&status) {
        return Err(fixed_error(
            "codex-item-terminal-invalid",
            "Codex completed an item without a supported terminal status",
        ));
    }
    Ok(status_meta(status))
}

fn status_meta(status: &str) -> AgentItemMeta {
    let mut meta = AgentItemMeta::default();
    meta.vendor_extensions
        .insert("status".to_owned(), json!(status));
    meta
}

fn mcp_tool_call_item(item: &Value) -> Result<AgentItem, ProtocolError> {
    let server = required_item_string(item, "server")?;
    let tool = required_item_string(item, "tool")?;
    let arguments = item.get("arguments").cloned().ok_or_else(|| {
        fixed_error(
            "codex-item-shape-invalid",
            "Codex MCP tool arguments are missing",
        )
    })?;
    let status = required_item_string(item, "status")?;
    if !matches!(status, "completed" | "failed") {
        return Err(fixed_error(
            "codex-item-terminal-invalid",
            "Codex completed MCP tool call without a terminal status",
        ));
    }
    let result = match item.get("result") {
        None | Some(Value::Null) => None,
        Some(Value::Object(result)) => {
            let content = result
                .get("content")
                .and_then(Value::as_array)
                .cloned()
                .ok_or_else(|| {
                    fixed_error(
                        "codex-item-shape-invalid",
                        "Codex MCP result content must be an array",
                    )
                })?;
            // `_meta` 明确不投影：它可承载 connector/widget 私有身份或敏感元数据。
            Some(json!({
                "content": content,
                "structuredContent": result.get("structuredContent").cloned().unwrap_or(Value::Null)
            }))
        }
        Some(_) => {
            return Err(fixed_error(
                "codex-item-shape-invalid",
                "Codex MCP result must be an object or null",
            ));
        }
    };
    let error = match item.get("error") {
        None | Some(Value::Null) => None,
        Some(Value::Object(error)) => Some(json!({
            "message": error
                .get("message")
                .and_then(Value::as_str)
                .ok_or_else(|| fixed_error(
                    "codex-item-shape-invalid",
                    "Codex MCP error message is missing"
                ))?
        })),
        Some(_) => {
            return Err(fixed_error(
                "codex-item-shape-invalid",
                "Codex MCP error must be an object or null",
            ));
        }
    };
    let duration_ms = optional_u64(item, "durationMs")?;
    Ok(AgentItem::ToolCall {
        name: tool.to_owned(),
        args: json!({"server": server, "arguments": arguments}),
        result: Some(json!({"result": result, "error": error})),
        meta: tool_status_meta(status, duration_ms),
    })
}

fn dynamic_tool_call_item(item: &Value) -> Result<AgentItem, ProtocolError> {
    let tool = required_item_string(item, "tool")?;
    let arguments = item.get("arguments").cloned().ok_or_else(|| {
        fixed_error(
            "codex-item-shape-invalid",
            "Codex dynamic tool arguments are missing",
        )
    })?;
    let namespace = optional_item_string(item, "namespace")?;
    let status = required_item_string(item, "status")?;
    if !matches!(status, "completed" | "failed") {
        return Err(fixed_error(
            "codex-item-terminal-invalid",
            "Codex completed dynamic tool call without a terminal status",
        ));
    }
    let content_items = match item.get("contentItems") {
        None | Some(Value::Null) => None,
        Some(Value::Array(items)) => Some(
            items
                .iter()
                .map(validated_dynamic_content_item)
                .collect::<Result<Vec<_>, _>>()?,
        ),
        Some(_) => {
            return Err(fixed_error(
                "codex-item-shape-invalid",
                "Codex dynamic tool content must be an array or null",
            ));
        }
    };
    let success = match item.get("success") {
        None | Some(Value::Null) => None,
        Some(Value::Bool(value)) => Some(*value),
        Some(_) => {
            return Err(fixed_error(
                "codex-item-shape-invalid",
                "Codex dynamic tool success must be a boolean or null",
            ));
        }
    };
    let duration_ms = optional_u64(item, "durationMs")?;
    Ok(AgentItem::ToolCall {
        name: tool.to_owned(),
        args: json!({"namespace": namespace, "arguments": arguments}),
        result: Some(json!({"contentItems": content_items, "success": success})),
        meta: tool_status_meta(status, duration_ms),
    })
}

fn validated_dynamic_content_item(item: &Value) -> Result<Value, ProtocolError> {
    match item.get("type").and_then(Value::as_str) {
        Some("inputText") => Ok(json!({
            "type": "inputText",
            "text": required_item_string_allow_empty(item, "text")?
        })),
        Some("inputImage") => Ok(json!({
            "type": "inputImage",
            "imageUrl": required_item_string(item, "imageUrl")?
        })),
        _ => Err(fixed_error(
            "codex-item-shape-invalid",
            "Codex dynamic tool content type is unsupported",
        )),
    }
}

fn collab_agent_tool_call_item(item: &Value) -> Result<AgentItem, ProtocolError> {
    let tool = required_item_string(item, "tool")?;
    if !matches!(
        tool,
        "spawnAgent" | "sendInput" | "resumeAgent" | "wait" | "closeAgent"
    ) {
        return Err(fixed_error(
            "codex-item-shape-invalid",
            "Codex collaboration tool name is unsupported",
        ));
    }
    required_item_string(item, "senderThreadId")?;
    let receiver_ids = item
        .get("receiverThreadIds")
        .and_then(Value::as_array)
        .ok_or_else(|| {
            fixed_error(
                "codex-item-shape-invalid",
                "Codex collaboration receivers are invalid",
            )
        })?;
    if !receiver_ids
        .iter()
        .all(|value| value.as_str().is_some_and(|value| !value.is_empty()))
        || !item.get("agentsStates").is_some_and(Value::is_object)
    {
        return Err(fixed_error(
            "codex-item-shape-invalid",
            "Codex collaboration identity shape is invalid",
        ));
    }
    let status = required_item_string(item, "status")?;
    if !matches!(status, "completed" | "failed") {
        return Err(fixed_error(
            "codex-item-terminal-invalid",
            "Codex completed collaboration tool call without a terminal status",
        ));
    }
    let model = optional_item_string(item, "model")?;
    let prompt = optional_item_string(item, "prompt")?;
    let reasoning_effort = optional_item_string(item, "reasoningEffort")?;
    if reasoning_effort.as_deref().is_some_and(str::is_empty) {
        return Err(fixed_error(
            "codex-item-shape-invalid",
            "Codex collaboration reasoning effort is invalid",
        ));
    }
    Ok(AgentItem::ToolCall {
        name: tool.to_owned(),
        // sender/receiver/agentsStates 中的 vendor ThreadId 只验证、不持久化。
        args: json!({
            "model": model,
            "prompt": prompt,
            "reasoningEffort": reasoning_effort
        }),
        result: None,
        meta: status_meta(status),
    })
}

fn tool_status_meta(status: &str, duration_ms: Option<u64>) -> AgentItemMeta {
    let mut meta = status_meta(status);
    if let Some(duration_ms) = duration_ms {
        meta.vendor_extensions
            .insert("durationMs".to_owned(), json!(duration_ms));
    }
    meta
}

fn optional_u64(item: &Value, field: &str) -> Result<Option<u64>, ProtocolError> {
    match item.get(field) {
        None | Some(Value::Null) => Ok(None),
        Some(Value::Number(value)) => value.as_u64().map(Some).ok_or_else(|| {
            fixed_error(
                "codex-item-shape-invalid",
                &format!("Codex item field {field} must be a non-negative integer or null"),
            )
        }),
        Some(_) => Err(fixed_error(
            "codex-item-shape-invalid",
            &format!("Codex item field {field} must be an integer or null"),
        )),
    }
}

fn image_generation_item(item: &Value) -> Result<AgentItem, ProtocolError> {
    // 威胁场景：失败或未落盘的 generation 若被写成两个 path 都为空的
    // ImageReference，会在回放中伪装成一次成功图片产出。
    let status = required_item_string(item, "status")?;
    if !matches!(status, "completed" | "failed") {
        return Err(fixed_error(
            "codex-item-terminal-invalid",
            "Codex completed image generation without a supported terminal status",
        ));
    }
    let result = required_item_string_allow_empty(item, "result")?;
    let revised_prompt = optional_item_string(item, "revisedPrompt")?;
    let saved_path = optional_item_string(item, "savedPath")?;
    let mut meta = AgentItemMeta::default();
    meta.vendor_extensions
        .insert("status".to_owned(), json!(status));
    Ok(AgentItem::ToolCall {
        name: "imageGeneration".to_owned(),
        args: json!({"revisedPrompt": revised_prompt}),
        result: Some(json!({
            "result": result,
            "savedPath": saved_path,
            "status": status
        })),
        meta,
    })
}

fn web_search_item(item: &Value) -> Result<AgentItem, ProtocolError> {
    let query = required_item_string_allow_empty(item, "query")?;
    let action = match item.get("action") {
        None | Some(Value::Null) => Value::Null,
        Some(action) => validated_web_search_action(action)?,
    };
    Ok(AgentItem::ToolCall {
        name: "webSearch".to_owned(),
        args: json!({"query": query, "action": action}),
        result: None,
        meta: AgentItemMeta::default(),
    })
}

fn validated_web_search_action(action: &Value) -> Result<Value, ProtocolError> {
    let action = action.as_object().ok_or_else(|| {
        fixed_error(
            "codex-item-shape-invalid",
            "Codex web search action must be an object",
        )
    })?;
    let kind = action.get("type").and_then(Value::as_str).ok_or_else(|| {
        fixed_error(
            "codex-item-shape-invalid",
            "Codex web search action type is missing",
        )
    })?;
    let value = match kind {
        "search" => {
            let query = optional_object_string(action, "query")?;
            let queries = match action.get("queries") {
                None | Some(Value::Null) => None,
                Some(Value::Array(values)) => Some(
                    values
                        .iter()
                        .map(|value| {
                            value.as_str().map(str::to_owned).ok_or_else(|| {
                                fixed_error(
                                    "codex-item-shape-invalid",
                                    "Codex web search queries must be strings",
                                )
                            })
                        })
                        .collect::<Result<Vec<_>, _>>()?,
                ),
                Some(_) => {
                    return Err(fixed_error(
                        "codex-item-shape-invalid",
                        "Codex web search queries must be an array or null",
                    ));
                }
            };
            json!({"type": kind, "query": query, "queries": queries})
        }
        "openPage" => {
            json!({"type": kind, "url": optional_object_string(action, "url")?})
        }
        "findInPage" => json!({
            "type": kind,
            "url": optional_object_string(action, "url")?,
            "pattern": optional_object_string(action, "pattern")?
        }),
        "other" => json!({"type": kind}),
        _ => {
            return Err(fixed_error(
                "codex-item-shape-invalid",
                "Codex web search action type is unsupported",
            ));
        }
    };
    Ok(value)
}

fn sub_agent_activity_item(item: &Value) -> Result<AgentItem, ProtocolError> {
    let agent_path = required_item_string(item, "agentPath")?;
    required_item_string(item, "agentThreadId")?;
    let kind = required_item_string(item, "kind")?;
    if !matches!(kind, "started" | "interacted" | "interrupted") {
        return Err(fixed_error(
            "codex-item-shape-invalid",
            "Codex sub-agent activity kind is unsupported",
        ));
    }
    Ok(AgentItem::ToolCall {
        name: "subAgentActivity".to_owned(),
        // 私有 vendor thread identity 只参与 shape validation，不进入 Runtime/Relay。
        args: json!({"agentPath": agent_path, "kind": kind}),
        result: None,
        meta: AgentItemMeta::default(),
    })
}

fn sleep_item(item: &Value) -> Result<AgentItem, ProtocolError> {
    let duration_ms = item
        .get("durationMs")
        .and_then(Value::as_u64)
        .ok_or_else(|| {
            fixed_error(
                "codex-item-shape-invalid",
                "Codex sleep duration is invalid",
            )
        })?;
    Ok(AgentItem::ToolCall {
        name: "sleep".to_owned(),
        args: json!({"durationMs": duration_ms}),
        result: None,
        meta: AgentItemMeta::default(),
    })
}

fn review_mode_item(item: &Value, name: &str) -> Result<AgentItem, ProtocolError> {
    let review = required_item_string_allow_empty(item, "review")?;
    Ok(AgentItem::ToolCall {
        name: name.to_owned(),
        args: json!({"review": review}),
        result: None,
        meta: AgentItemMeta::default(),
    })
}

fn required_item_string<'a>(item: &'a Value, field: &str) -> Result<&'a str, ProtocolError> {
    item.get(field)
        .and_then(Value::as_str)
        .filter(|value| !value.is_empty())
        .ok_or_else(|| {
            fixed_error(
                "codex-item-shape-invalid",
                &format!("Codex item field {field} must be a non-empty string"),
            )
        })
}

fn required_item_string_allow_empty<'a>(
    item: &'a Value,
    field: &str,
) -> Result<&'a str, ProtocolError> {
    item.get(field).and_then(Value::as_str).ok_or_else(|| {
        fixed_error(
            "codex-item-shape-invalid",
            &format!("Codex item field {field} must be a string"),
        )
    })
}

fn optional_item_string(item: &Value, field: &str) -> Result<Option<String>, ProtocolError> {
    match item.get(field) {
        None | Some(Value::Null) => Ok(None),
        Some(Value::String(value)) => Ok(Some(value.clone())),
        Some(_) => Err(fixed_error(
            "codex-item-shape-invalid",
            &format!("Codex item field {field} must be a string or null"),
        )),
    }
}

fn optional_object_string(
    object: &serde_json::Map<String, Value>,
    field: &str,
) -> Result<Option<String>, ProtocolError> {
    match object.get(field) {
        None | Some(Value::Null) => Ok(None),
        Some(Value::String(value)) => Ok(Some(value.clone())),
        Some(_) => Err(fixed_error(
            "codex-item-shape-invalid",
            &format!("Codex object field {field} must be a string or null"),
        )),
    }
}

fn runtime_assistant_meta(item: &Value) -> AgentItemMeta {
    // 威胁场景：官方 memoryCitation 含 vendor ThreadId；若复用 compatibility
    // translator 的完整 metadata，它会原样进入 durable Runtime event 与未来 Relay。
    // canonical 路径只保留不承载 vendor identity 的 phase。
    let mut meta = AgentItemMeta::default();
    if let Some(phase) = item.get("phase").and_then(Value::as_str) {
        meta.vendor_extensions
            .insert("phase".to_owned(), json!(phase));
    }
    meta
}

fn runtime_diff_files(item: &Value) -> Result<Vec<agentdeck_protocol::DiffFile>, ProtocolError> {
    // 威胁场景：官方 PatchChangeKind 是对象；把它当字符串会把真实 add/delete
    // 都持久化成 Modified，并丢失 update.move_path 的 rename 语义。
    let changes = item
        .get("changes")
        .and_then(Value::as_array)
        .ok_or_else(|| fixed_error("codex-diff-shape-invalid", "Codex diff shape is invalid"))?;
    let mut files = Vec::with_capacity(changes.len());
    for change in changes {
        let path = change
            .get("path")
            .and_then(Value::as_str)
            .filter(|value| !value.is_empty())
            .ok_or_else(|| {
                fixed_error("codex-diff-shape-invalid", "Codex diff shape is invalid")
            })?;
        let patch = change.get("diff").and_then(Value::as_str).ok_or_else(|| {
            fixed_error("codex-diff-shape-invalid", "Codex diff shape is invalid")
        })?;
        let kind = change
            .get("kind")
            .and_then(Value::as_object)
            .ok_or_else(|| {
                fixed_error("codex-diff-shape-invalid", "Codex diff shape is invalid")
            })?;
        let status = match kind.get("type").and_then(Value::as_str) {
            Some("add") => agentdeck_protocol::DiffStatus::Added,
            Some("delete") => agentdeck_protocol::DiffStatus::Deleted,
            Some("update") => match kind.get("move_path") {
                Some(Value::String(move_path)) if !move_path.is_empty() => {
                    agentdeck_protocol::DiffStatus::Renamed
                }
                None | Some(Value::Null) => agentdeck_protocol::DiffStatus::Modified,
                _ => {
                    return Err(fixed_error(
                        "codex-diff-shape-invalid",
                        "Codex diff shape is invalid",
                    ));
                }
            },
            _ => {
                return Err(fixed_error(
                    "codex-diff-shape-invalid",
                    "Codex diff shape is invalid",
                ));
            }
        };
        files.push(agentdeck_protocol::DiffFile {
            path: path.into(),
            status,
            patch: Some(patch.to_owned()),
        });
    }
    Ok(files)
}

fn file_change_approval_context(item: &Value) -> Result<FileChangeApprovalContext, ProtocolError> {
    let changes = item
        .get("changes")
        .and_then(Value::as_array)
        .ok_or_else(|| fixed_error("codex-diff-shape-invalid", "Codex diff shape is invalid"))?;
    if changes.is_empty() {
        return Ok(FileChangeApprovalContext::Empty);
    }
    let mut summary = String::new();
    for change in changes {
        let path = change
            .get("path")
            .and_then(Value::as_str)
            .filter(|value| !value.is_empty())
            .ok_or_else(|| {
                fixed_error("codex-diff-shape-invalid", "Codex diff shape is invalid")
            })?;
        let path = match approval_text(path) {
            Ok(Some(path)) => path,
            Ok(None) => {
                return Err(fixed_error(
                    "codex-diff-shape-invalid",
                    "Codex diff path is invalid",
                ));
            }
            Err(error) if error.code == "codex-approval-summary-too-large" => {
                return Ok(FileChangeApprovalContext::TooLarge);
            }
            Err(error) => return Err(error),
        };
        let kind = change
            .get("kind")
            .and_then(Value::as_object)
            .ok_or_else(|| {
                fixed_error("codex-diff-shape-invalid", "Codex diff shape is invalid")
            })?;
        let action = match kind.get("type").and_then(Value::as_str) {
            Some("add") => format!("add {path}"),
            Some("delete") => format!("delete {path}"),
            Some("update") => match kind.get("move_path") {
                None | Some(Value::Null) => format!("update {path}"),
                Some(Value::String(destination)) if !destination.is_empty() => {
                    let destination = match approval_text(destination) {
                        Ok(Some(destination)) => destination,
                        Ok(None) => {
                            return Err(fixed_error(
                                "codex-diff-shape-invalid",
                                "Codex diff move path is invalid",
                            ));
                        }
                        Err(error) if error.code == "codex-approval-summary-too-large" => {
                            return Ok(FileChangeApprovalContext::TooLarge);
                        }
                        Err(error) => return Err(error),
                    };
                    format!("move {path} -> {destination}")
                }
                Some(_) => {
                    return Err(fixed_error(
                        "codex-diff-shape-invalid",
                        "Codex diff shape is invalid",
                    ));
                }
            },
            _ => {
                return Err(fixed_error(
                    "codex-diff-shape-invalid",
                    "Codex diff shape is invalid",
                ));
            }
        };
        if !summary.is_empty() {
            summary.push_str("; ");
        }
        summary.push_str(&action);
        if summary.len() > MAX_APPROVAL_SUMMARY_BYTES {
            return Ok(FileChangeApprovalContext::TooLarge);
        }
    }
    Ok(FileChangeApprovalContext::Ready(summary))
}

fn shell_item(item: &Value, status: ShellStatus) -> AgentItem {
    AgentItem::Shell {
        command: item
            .get("command")
            .and_then(Value::as_str)
            .unwrap_or_default()
            .to_owned(),
        status,
        exit_code: item
            .get("exitCode")
            .and_then(Value::as_i64)
            .and_then(|value| i32::try_from(value).ok()),
        duration_ms: item.get("durationMs").and_then(Value::as_u64),
        meta: AgentItemMeta::default(),
    }
}

fn command_approval_summary(params: &Value) -> Result<String, ProtocolError> {
    let command = command_approval_detail(params)?;
    let network = network_approval_detail(params)?;
    if command.is_none() && network.is_none() {
        return Err(fixed_error(
            "codex-approval-action-missing",
            "Codex requested command approval without a concrete command or network target",
        ));
    }
    let base = if command.is_some() {
        "Run command"
    } else {
        "Allow network access"
    };
    let details = [
        ("command", command),
        ("network", network),
        ("cwd", approval_text_field(params, "cwd")?),
        ("reason", approval_text_field(params, "reason")?),
    ];
    approval_summary(base, &details)
}

fn permissions_approval_summary(params: &Value) -> Result<String, ProtocolError> {
    let profile = validated_permission_profile(params)?;
    if !permission_profile_has_action(&profile) {
        return Err(fixed_error(
            "codex-approval-action-missing",
            "Codex requested an empty permission profile",
        ));
    }
    let profile = serde_json::to_string(&profile).map_err(|_| {
        fixed_error(
            "codex-invalid-approval-params",
            "Codex permission profile cannot be encoded",
        )
    })?;
    let profile = approval_structured_text(&profile)?.ok_or_else(|| {
        fixed_error(
            "codex-invalid-approval-params",
            "Codex permission profile cannot be displayed safely",
        )
    })?;
    let details = [
        ("profile", Some(profile)),
        ("cwd", approval_text_field(params, "cwd")?),
        ("reason", approval_text_field(params, "reason")?),
    ];
    approval_summary("Grant additional permissions", &details)
}

fn command_approval_detail(params: &Value) -> Result<Option<String>, ProtocolError> {
    if let Some(command) = approval_text_field(params, "command")? {
        return Ok(Some(command));
    }

    let actions = match params.get("commandActions") {
        Some(Value::Array(actions)) if !actions.is_empty() => actions,
        Some(Value::Null) | None | Some(Value::Array(_)) => return Ok(None),
        Some(_) => {
            return Err(fixed_error(
                "codex-invalid-approval-params",
                "Codex commandActions must be an array or null",
            ));
        }
    };
    if actions.len() > MAX_APPROVAL_COMMAND_ACTIONS {
        return Err(approval_summary_too_large());
    }
    let mut commands = String::new();
    for action in actions {
        let command = validated_command_action(action)?;
        let command = approval_text(command)?.ok_or_else(|| {
            fixed_error(
                "codex-invalid-approval-params",
                "Codex command action must contain a non-empty command",
            )
        })?;
        if !commands.is_empty() {
            commands.push_str(" | ");
        }
        commands.push_str(&command);
        if commands.len() > MAX_APPROVAL_SUMMARY_BYTES {
            return Err(approval_summary_too_large());
        }
    }
    Ok(Some(commands))
}

fn network_approval_detail(params: &Value) -> Result<Option<String>, ProtocolError> {
    let context = match params.get("networkApprovalContext") {
        None | Some(Value::Null) => return Ok(None),
        Some(Value::Object(context)) => context,
        Some(_) => {
            return Err(fixed_error(
                "codex-invalid-approval-params",
                "Codex network approval context must be an object or null",
            ));
        }
    };
    let host = context
        .get("host")
        .and_then(Value::as_str)
        .filter(|value| !value.is_empty())
        .ok_or_else(|| {
            fixed_error(
                "codex-invalid-approval-params",
                "Codex network approval host is missing",
            )
        })?;
    let host = approval_text(host)?.ok_or_else(|| {
        fixed_error(
            "codex-invalid-approval-params",
            "Codex network approval host is missing",
        )
    })?;
    let protocol = context
        .get("protocol")
        .and_then(Value::as_str)
        .filter(|value| matches!(*value, "http" | "https" | "socks5Tcp" | "socks5Udp"))
        .ok_or_else(|| {
            fixed_error(
                "codex-invalid-approval-params",
                "Codex network approval protocol is unsupported",
            )
        })?;
    Ok(Some(format!("{protocol} {host}")))
}

fn validated_command_action(action: &Value) -> Result<&str, ProtocolError> {
    let action = action.as_object().ok_or_else(|| {
        fixed_error(
            "codex-invalid-approval-params",
            "Codex commandActions entries must be objects",
        )
    })?;
    let command = required_action_string(action, "command")?;
    match action.get("type").and_then(Value::as_str) {
        Some("read") => {
            required_action_string(action, "name")?;
            let path = required_action_string(action, "path")?;
            validate_absolute_normal_path(path, "commandActions[].path")?;
        }
        Some("listFiles") => validate_optional_action_string(action, "path")?,
        Some("search") => {
            validate_optional_action_string(action, "path")?;
            validate_optional_action_string(action, "query")?;
        }
        Some("unknown") => {}
        _ => {
            return Err(fixed_error(
                "codex-invalid-approval-params",
                "Codex command action type is not an official supported value",
            ));
        }
    }
    Ok(command)
}

fn required_action_string<'a>(
    action: &'a serde_json::Map<String, Value>,
    field: &str,
) -> Result<&'a str, ProtocolError> {
    action
        .get(field)
        .and_then(Value::as_str)
        .filter(|value| !value.is_empty())
        .ok_or_else(|| {
            fixed_error(
                "codex-invalid-approval-params",
                &format!("Codex command action {field} must be a non-empty string"),
            )
        })
}

fn validate_optional_action_string(
    action: &serde_json::Map<String, Value>,
    field: &str,
) -> Result<(), ProtocolError> {
    if action
        .get(field)
        .is_some_and(|value| !value.is_null() && !value.is_string())
    {
        return Err(fixed_error(
            "codex-invalid-approval-params",
            &format!("Codex command action {field} must be a string or null"),
        ));
    }
    Ok(())
}

fn permission_profile_has_action(profile: &Value) -> bool {
    let Some(profile) = profile.as_object() else {
        return false;
    };
    let file_system_has_action = profile
        .get("fileSystem")
        .and_then(Value::as_object)
        .is_some_and(|file_system| {
            ["read", "write", "entries"].into_iter().any(|field| {
                file_system
                    .get(field)
                    .and_then(Value::as_array)
                    .is_some_and(|values| !values.is_empty())
            })
        });
    let network_has_action = profile
        .get("network")
        .and_then(Value::as_object)
        .and_then(|network| network.get("enabled"))
        .is_some_and(Value::is_boolean);
    file_system_has_action || network_has_action
}

fn approval_text_field(params: &Value, field: &str) -> Result<Option<String>, ProtocolError> {
    match params.get(field) {
        None | Some(Value::Null) => Ok(None),
        Some(Value::String(value)) => approval_text(value),
        Some(_) => Err(fixed_error(
            "codex-invalid-approval-params",
            &format!("Codex approval field {field} must be a string or null"),
        )),
    }
}

fn approval_text(value: &str) -> Result<Option<String>, ProtocolError> {
    if value.is_empty() || value.chars().all(char::is_whitespace) {
        return Ok(None);
    }
    if value.len() > MAX_APPROVAL_REDACTION_INPUT_BYTES {
        return Err(approval_summary_too_large());
    }
    // 威胁场景：把 newline/tab 折成空格会让 `echo ok\ncurl attacker` 在批准卡片
    // 看起来像一条无害 echo。JSON 字符串编码保留空白、反斜杠与控制符的可见差异。
    let redacted = redact(value);
    let canonical = serde_json::to_string(&redacted).map_err(|_| {
        fixed_error(
            "codex-invalid-approval-params",
            "Codex approval text cannot be displayed safely",
        )
    })?;
    if canonical.len() > MAX_APPROVAL_SUMMARY_BYTES {
        return Err(approval_summary_too_large());
    }
    Ok(Some(canonical))
}

fn approval_structured_text(value: &str) -> Result<Option<String>, ProtocolError> {
    let value = value.trim();
    if value.is_empty() {
        return Ok(None);
    }
    if value.len() > MAX_APPROVAL_REDACTION_INPUT_BYTES {
        return Err(approval_summary_too_large());
    }
    let redacted = redact(value);
    if redacted.len() > MAX_APPROVAL_SUMMARY_BYTES {
        return Err(approval_summary_too_large());
    }
    Ok(Some(redacted))
}

fn approval_summary(
    base: &str,
    details: &[(&str, Option<String>)],
) -> Result<String, ProtocolError> {
    let mut summary = base.to_owned();
    for (label, value) in details {
        let Some(value) = value else {
            continue;
        };
        summary.push_str(" · ");
        summary.push_str(label);
        summary.push_str(": ");
        summary.push_str(value);
        if summary.len() > MAX_APPROVAL_SUMMARY_BYTES {
            return Err(approval_summary_too_large());
        }
    }
    Ok(summary)
}

fn approval_summary_too_large() -> ProtocolError {
    fixed_error(
        "codex-approval-summary-too-large",
        "Codex approval action cannot be displayed completely within the fixed summary bound",
    )
}

fn diagnostic_notification(
    method: &str,
    params: &Value,
) -> Result<Vec<CodexRuntimeOutput>, ProtocolError> {
    // 威胁场景：recoverable warning 若走 unknown-frame 会杀死正常 turn；若直接
    // 丢弃又失去唯一诊断。这里只提取官方白名单文本，driver 经 redact 写诊断日志。
    let fields: &[&str] = match method {
        "warning" | "guardianWarning" => &["message"],
        "configWarning" | "deprecationNotice" => &["summary", "details", "path"],
        _ => {
            return Err(fixed_error(
                "codex-unmodeled-frame",
                "Codex emitted an unmodeled diagnostic notification",
            ));
        }
    };
    let mut detail = String::new();
    for field in fields {
        match params.get(*field) {
            None | Some(Value::Null) if *field != "message" && *field != "summary" => continue,
            Some(Value::String(value)) => {
                if !detail.is_empty() {
                    detail.push_str(" · ");
                }
                detail.push_str(field);
                detail.push_str(": ");
                push_utf8_prefix(&mut detail, value, MAX_DIAGNOSTIC_SOURCE_BYTES);
                if detail.len() >= MAX_DIAGNOSTIC_SOURCE_BYTES {
                    break;
                }
            }
            _ => {
                return Err(fixed_error(
                    "codex-diagnostic-shape-invalid",
                    "Codex diagnostic notification shape is invalid",
                ));
            }
        }
    }
    Ok(vec![CodexRuntimeOutput::Diagnostic {
        code: format!("codex-{}", method.replace('/', "-")),
        detail: redacted_diagnostic_detail(&detail),
    }])
}

fn error_notification(params: &Value) -> Result<Vec<CodexRuntimeOutput>, ProtocolError> {
    let will_retry = params
        .get("willRetry")
        .and_then(Value::as_bool)
        .ok_or_else(|| {
            fixed_error(
                "codex-error-shape-invalid",
                "Codex error notification shape is invalid",
            )
        })?;
    let message = params
        .get("error")
        .and_then(Value::as_object)
        .and_then(|error| error.get("message"))
        .and_then(Value::as_str)
        .ok_or_else(|| {
            fixed_error(
                "codex-error-shape-invalid",
                "Codex error notification shape is invalid",
            )
        })?;
    if will_retry {
        let mut source = String::new();
        push_utf8_prefix(&mut source, message, MAX_DIAGNOSTIC_SOURCE_BYTES);
        return Ok(vec![CodexRuntimeOutput::Diagnostic {
            code: "codex-turn-retrying".to_owned(),
            detail: redacted_diagnostic_detail(&source),
        }]);
    }
    Err(fixed_error(
        "codex-turn-error",
        "Codex reported a non-retryable turn error",
    ))
}

fn truncate_utf8_with_ellipsis(value: &mut String, max_bytes: usize) {
    if value.len() <= max_bytes {
        return;
    }
    let ellipsis = "…";
    let mut boundary = max_bytes.saturating_sub(ellipsis.len());
    while boundary > 0 && !value.is_char_boundary(boundary) {
        boundary -= 1;
    }
    value.truncate(boundary);
    value.push_str(ellipsis);
}

fn push_utf8_prefix(target: &mut String, value: &str, maximum: usize) {
    let remaining = maximum.saturating_sub(target.len());
    if remaining == 0 {
        return;
    }
    let mut end = value.len().min(remaining);
    while end > 0 && !value.is_char_boundary(end) {
        end -= 1;
    }
    target.push_str(&value[..end]);
}

fn redacted_diagnostic_detail(source: &str) -> String {
    let mut detail = redact(source);
    if detail.len() > MAX_DIAGNOSTIC_DETAIL_BYTES {
        truncate_utf8_with_ellipsis(&mut detail, MAX_DIAGNOSTIC_DETAIL_BYTES);
    }
    detail
}

fn turn_summary(params: &Value, token_usage: Option<&PendingTokenUsage>) -> TurnSummary {
    let turn = params.get("turn");
    TurnSummary {
        total_input_tokens: token_usage.map(|usage| usage.input_tokens),
        total_output_tokens: token_usage.map(|usage| usage.output_tokens),
        elapsed_ms: params
            .get("durationMs")
            .and_then(Value::as_u64)
            .or_else(|| {
                turn.and_then(|value| value.get("durationMs"))
                    .and_then(Value::as_u64)
            })
            .unwrap_or_default(),
    }
}

fn validated_rpc_id(value: &Value) -> Result<Value, ProtocolError> {
    match value {
        Value::String(value) if !value.is_empty() && value.len() <= 1024 => {
            Ok(Value::String(value.clone()))
        }
        Value::Number(value) if value.as_i64().is_some() => Ok(Value::Number(value.clone())),
        _ => Err(fixed_error(
            "codex-rpc-id-invalid",
            "Codex approval RPC identity is invalid",
        )),
    }
}

fn fixed_error(code: &str, message: &str) -> ProtocolError {
    ProtocolError {
        code: code.to_owned(),
        message: message.to_owned(),
        diagnostic_ref: None,
    }
}
