//! Claude Code stream-json → typed Runtime execution output。
//!
//! vendor session/tool identity 只用于 adapter 私有关联；输出只携带单调
//! `AdapterItemKey` 与中立 `AgentItem`，不构造 SessionId/ThreadId/RuntimeEvent。

use std::collections::{HashMap, HashSet};

use agentdeck_protocol::{
    ActionKind, ActionRequest, ActionRequestVendor, AgentItem, AgentItemMeta,
    ClaudeCodePermissionMode, DiffFile, DiffStatus, ProtocolError, ShellStatus, TurnSummary,
};
use serde_json::{Value, json};

use crate::agent::{AdapterEvent, AdapterItemKey};

const MAX_TRANSLATED_ITEMS_PER_TURN: u64 = 10_000;
// 这是 translator 持有的 id/name/JSON input 的逻辑 payload 预算；现有 item 上限
// 同时约束 HashMap/HashSet 每条记录的固定容器开销，避免 Store ACK gate 前无界累积。
const MAX_TRANSLATOR_RETAINED_BYTES: usize = 8 * 1024 * 1024;
const MAX_CONTROL_ID_BYTES: usize = 512;
const MAX_CONTROL_TOOL_NAME_BYTES: usize = 128;
const MAX_CONTROL_SUMMARY_BYTES: usize = 512;
const MAX_CONTROL_SUMMARY_SOURCE_BYTES: usize = 4 * 1024;

#[derive(Debug)]
pub(super) enum ClaudeCodeRuntimeOutput {
    Event(AdapterEvent),
    Approval {
        request: ActionRequest,
        route: ClaudeCodeApprovalRoute,
    },
    TurnComplete(TurnSummary),
}

#[derive(Debug)]
pub(super) struct ClaudeCodeApprovalRoute {
    pub(super) request_id: String,
    pub(super) tool_use_id: String,
    pub(super) tool_name: String,
}

#[derive(Debug)]
struct ToolUseRecord {
    key: AdapterItemKey,
    name: String,
    input: Value,
    retained_bytes: usize,
}

#[derive(Debug)]
pub(super) struct ClaudeCodeRuntimeTranslator {
    in_flight_tools: HashMap<String, ToolUseRecord>,
    completed_tool_ids: HashSet<String>,
    next_item_key: u64,
    retained_bytes: usize,
    retained_byte_limit: usize,
}

impl ClaudeCodeRuntimeTranslator {
    pub(super) fn new() -> Self {
        Self {
            in_flight_tools: HashMap::new(),
            completed_tool_ids: HashSet::new(),
            next_item_key: 1,
            retained_bytes: 0,
            retained_byte_limit: MAX_TRANSLATOR_RETAINED_BYTES,
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
    pub(super) fn retained_bytes_for_test(&self) -> usize {
        self.retained_bytes
    }

    #[cfg(test)]
    pub(super) fn translate_line(
        &mut self,
        line: &str,
    ) -> Result<Vec<ClaudeCodeRuntimeOutput>, ProtocolError> {
        let value =
            serde_json::from_str::<Value>(line).map_err(|_| fixed_error("cc-malformed-json"))?;
        self.translate_value(&value)
    }

    pub(super) fn translate_value(
        &mut self,
        frame: &Value,
    ) -> Result<Vec<ClaudeCodeRuntimeOutput>, ProtocolError> {
        let kind = frame
            .get("type")
            .and_then(Value::as_str)
            .filter(|value| !value.is_empty())
            .ok_or_else(|| fixed_error("cc-unmodeled-frame"))?;
        match kind {
            "system" => self.system(frame),
            "stream_event" => self.stream_event(frame),
            "assistant" => self.assistant(frame),
            "user" => self.user(frame),
            "result" => self.result(frame),
            "control_request" => self.control_request(frame),
            "tool_progress" => self.tool_progress(frame),
            // Legacy compatibility permission wire remains speculative. Canonical Runtime
            // exclusively accepts the recorded stdio control_request shape above.
            "permission_request" | "permission" | "prompt" => {
                Err(fixed_error("cc-permission-wire-unverified"))
            }
            _ => Err(fixed_error("cc-unmodeled-frame")),
        }
    }

    fn system(&mut self, frame: &Value) -> Result<Vec<ClaudeCodeRuntimeOutput>, ProtocolError> {
        let subtype = frame
            .get("subtype")
            .and_then(Value::as_str)
            .filter(|value| !value.is_empty())
            .ok_or_else(|| fixed_error("cc-system-subtype-missing"))?;
        match subtype {
            "init" => {
                validate_stream_identity(frame, "cc-system-frame-invalid")?;
                Ok(Vec::new())
            }
            "hook_started" | "hook_progress" | "hook_response" => {
                validate_stream_identity(frame, "cc-system-frame-invalid")?;
                required_frame_text(frame, "hook_id", "cc-system-frame-invalid")?;
                required_frame_text(frame, "hook_name", "cc-system-frame-invalid")?;
                Ok(Vec::new())
            }
            "status" => {
                validate_stream_identity(frame, "cc-system-frame-invalid")?;
                match frame.get("status") {
                    Some(Value::String(status))
                        if matches!(status.as_str(), "requesting" | "compacting") =>
                    {
                        Ok(Vec::new())
                    }
                    Some(Value::Null) => Ok(Vec::new()),
                    _ => Err(fixed_error("cc-system-frame-invalid")),
                }
            }
            "task_started" => {
                validate_task_identity(frame)?;
                required_frame_text(frame, "description", "cc-system-frame-invalid")?;
                validate_optional_frame_text(frame, "task_type", "cc-system-frame-invalid")?;
                Ok(Vec::new())
            }
            "task_progress" => {
                validate_task_identity(frame)?;
                required_frame_text(frame, "description", "cc-system-frame-invalid")?;
                Ok(Vec::new())
            }
            "task_notification" => {
                validate_task_identity(frame)?;
                match frame.get("status").and_then(Value::as_str) {
                    Some("completed" | "failed" | "stopped") => Ok(Vec::new()),
                    _ => Err(fixed_error("cc-system-frame-invalid")),
                }
            }
            "task_updated" => {
                validate_stream_identity(frame, "cc-system-frame-invalid")?;
                required_frame_text(frame, "task_id", "cc-system-frame-invalid")?;
                validate_task_update_patch(frame)?;
                Ok(Vec::new())
            }
            "background_tasks_changed" => {
                validate_stream_identity(frame, "cc-system-frame-invalid")?;
                let tasks = frame
                    .get("tasks")
                    .and_then(Value::as_array)
                    .ok_or_else(|| fixed_error("cc-system-frame-invalid"))?;
                if tasks.iter().all(|task| {
                    task.get("task_id")
                        .and_then(Value::as_str)
                        .is_some_and(|task_id| !task_id.is_empty())
                        && task.get("task_type").is_some_and(Value::is_string)
                        && task.get("description").is_some_and(Value::is_string)
                }) {
                    Ok(Vec::new())
                } else {
                    Err(fixed_error("cc-system-frame-invalid"))
                }
            }
            // P3.7 typed execution journal 尚未建模 vendor panel durability。若在这里
            // 产出 VendorPanelEvent，conversation append 只会稍后以通用 ACK failure
            // 拒绝；未知 system subtype 继续在 wire boundary fail-close。
            _ => Err(fixed_error("cc-system-frame-unmodeled")),
        }
    }

    fn stream_event(&self, frame: &Value) -> Result<Vec<ClaudeCodeRuntimeOutput>, ProtocolError> {
        let event = frame
            .get("event")
            .and_then(|value| value.get("type"))
            .and_then(Value::as_str)
            .ok_or_else(|| fixed_error("cc-stream-event-invalid"))?;
        if matches!(
            event,
            "message_start"
                | "content_block_start"
                | "content_block_delta"
                | "content_block_stop"
                | "message_delta"
                | "message_stop"
        ) {
            Err(fixed_error("cc-stream-event-unverified"))
        } else {
            Err(fixed_error("cc-stream-event-unmodeled"))
        }
    }

    fn assistant(&mut self, frame: &Value) -> Result<Vec<ClaudeCodeRuntimeOutput>, ProtocolError> {
        let content = frame
            .get("message")
            .and_then(|value| value.get("content"))
            .and_then(Value::as_array)
            .ok_or_else(|| fixed_error("cc-assistant-content-invalid"))?;
        let mut outputs = Vec::new();
        for block in content {
            let kind = block
                .get("type")
                .and_then(Value::as_str)
                .ok_or_else(|| fixed_error("cc-content-block-invalid"))?;
            match kind {
                "text" => {
                    let text = block
                        .get("text")
                        .and_then(Value::as_str)
                        .ok_or_else(|| fixed_error("cc-content-block-invalid"))?;
                    if !text.is_empty() {
                        outputs.push(self.item(AgentItem::AssistantMessage {
                            text: text.to_owned(),
                            meta: AgentItemMeta::default(),
                        })?);
                    }
                }
                "thinking" => {
                    let text = block
                        .get("thinking")
                        .or_else(|| block.get("text"))
                        .and_then(Value::as_str)
                        .ok_or_else(|| fixed_error("cc-content-block-invalid"))?;
                    if !text.is_empty() {
                        outputs.push(self.item(AgentItem::Reasoning {
                            text: text.to_owned(),
                            meta: AgentItemMeta::default(),
                        })?);
                    }
                }
                "tool_use" => outputs.push(self.tool_started(block)?),
                "image" => outputs.push(
                    self.item(AgentItem::ImageReference {
                        saved_path: None,
                        original_path: block
                            .get("source")
                            .and_then(|value| value.get("path").or_else(|| value.get("file_path")))
                            .and_then(Value::as_str)
                            .map(Into::into),
                        meta: AgentItemMeta::default(),
                    })?,
                ),
                _ => return Err(fixed_error("cc-content-block-unmodeled")),
            }
        }
        Ok(outputs)
    }

    fn user(&mut self, frame: &Value) -> Result<Vec<ClaudeCodeRuntimeOutput>, ProtocolError> {
        let Some(content) = frame.get("message").and_then(|value| value.get("content")) else {
            return Err(fixed_error("cc-user-content-invalid"));
        };
        if content.is_string() {
            return Ok(Vec::new());
        }
        let blocks = content
            .as_array()
            .ok_or_else(|| fixed_error("cc-user-content-invalid"))?;
        let mut outputs = Vec::new();
        for block in blocks {
            match block.get("type").and_then(Value::as_str) {
                Some("text") => {}
                Some("tool_result") => outputs.push(self.tool_completed(block)?),
                _ => return Err(fixed_error("cc-user-content-unmodeled")),
            }
        }
        Ok(outputs)
    }

    fn result(&self, frame: &Value) -> Result<Vec<ClaudeCodeRuntimeOutput>, ProtocolError> {
        match frame.get("subtype").and_then(Value::as_str) {
            Some("success") => {}
            Some(_) => return Err(fixed_error("cc-turn-failed")),
            None => return Err(fixed_error("cc-turn-terminal-invalid")),
        }
        match frame.get("is_error").and_then(Value::as_bool) {
            Some(false) => {}
            Some(true) => return Err(fixed_error("cc-turn-failed")),
            None => return Err(fixed_error("cc-turn-terminal-invalid")),
        }
        if frame
            .get("deferred_tool_use")
            .is_some_and(|value| !value.is_null())
        {
            return Err(fixed_error("cc-turn-not-completed"));
        }
        match frame.get("terminal_reason").and_then(Value::as_str) {
            Some("completed") => {}
            Some(_) => return Err(fixed_error("cc-turn-not-completed")),
            None => return Err(fixed_error("cc-turn-terminal-invalid")),
        }
        if !self.in_flight_tools.is_empty() {
            return Err(fixed_error("cc-turn-incomplete"));
        }
        let elapsed_ms = frame
            .get("duration_ms")
            .and_then(Value::as_u64)
            .ok_or_else(|| fixed_error("cc-turn-terminal-invalid"))?;
        let usage = frame.get("usage");
        Ok(vec![ClaudeCodeRuntimeOutput::TurnComplete(TurnSummary {
            total_input_tokens: usage
                .and_then(|value| value.get("input_tokens"))
                .and_then(Value::as_u64),
            total_output_tokens: usage
                .and_then(|value| value.get("output_tokens"))
                .and_then(Value::as_u64),
            elapsed_ms,
        })])
    }

    fn tool_progress(&self, frame: &Value) -> Result<Vec<ClaudeCodeRuntimeOutput>, ProtocolError> {
        // 威胁场景：已知的非权威工具进度若被当成未知 frame，会中止仍在运行的正常
        // tool turn；但若不校验 shape 就静默丢弃，又会把未来承载动作语义的同名漂移吞掉。
        validate_stream_identity(frame, "cc-tool-progress-invalid")?;
        required_frame_text(frame, "tool_use_id", "cc-tool-progress-invalid")?;
        required_frame_text(frame, "tool_name", "cc-tool-progress-invalid")?;
        frame
            .get("elapsed_time_seconds")
            .and_then(Value::as_f64)
            .filter(|value| value.is_finite() && *value >= 0.0)
            .ok_or_else(|| fixed_error("cc-tool-progress-invalid"))?;
        if frame
            .get("parent_tool_use_id")
            .is_some_and(|value| !value.is_null() && !value.is_string())
        {
            return Err(fixed_error("cc-tool-progress-invalid"));
        }
        Ok(Vec::new())
    }

    fn control_request(
        &self,
        frame: &Value,
    ) -> Result<Vec<ClaudeCodeRuntimeOutput>, ProtocolError> {
        let request_id = bounded_control_text(
            frame,
            "request_id",
            MAX_CONTROL_ID_BYTES,
            "cc-control-request-id-invalid",
        )?;
        let request = frame
            .get("request")
            .filter(|value| value.is_object())
            .ok_or_else(|| fixed_error("cc-control-request-invalid"))?;
        let subtype = request
            .get("subtype")
            .and_then(Value::as_str)
            .filter(|value| !value.is_empty())
            .ok_or_else(|| fixed_error("cc-control-subtype-invalid"))?;
        if subtype != "can_use_tool" {
            return Err(fixed_error("cc-control-subtype-unmodeled"));
        }
        let tool_use_id = bounded_control_text(
            request,
            "tool_use_id",
            MAX_CONTROL_ID_BYTES,
            "cc-control-tool-use-id-invalid",
        )?;
        let tool_name = bounded_control_text(
            request,
            "tool_name",
            MAX_CONTROL_TOOL_NAME_BYTES,
            "cc-control-tool-name-invalid",
        )?;
        let (kind, summary_prefix) = match tool_name {
            "Bash" => (ActionKind::ExecuteCommand, "Claude Code 请求执行命令"),
            "Edit" | "Write" | "MultiEdit" | "NotebookEdit" => {
                (ActionKind::EditFiles, "Claude Code 请求编辑文件")
            }
            "Read" => (ActionKind::GrantExtraPermission, "Claude Code 请求额外权限"),
            _ => return Err(fixed_error("cc-control-tool-unmodeled")),
        };
        // 只从已验证的、按 tool kind allowlist 的最小动作字段生成可判别摘要：Bash
        // 取 command，文件操作取目标 path。缺失具体动作或未知工具都 fail-close，禁止
        // 回退 description/display_name/tool_name 形成不可知情的审批。permission_suggestions、
        // 非所选 blocked_path、其余 input 与完整 raw frame 均不进入 durable ActionRequest。
        // 自由文本先做 source cap，再走统一 secret redactor 与 JSON 字符串可见转义；
        // 任何无法完整落入唯一 summary 的动作都 fail-close，禁止把截断命令交给用户盲签。
        let summary_detail = control_action_detail(tool_name, request)
            .ok_or_else(|| fixed_error("cc-control-action-invalid"))?;
        let summary = bounded_control_summary(summary_prefix, summary_detail)?
            .ok_or_else(|| fixed_error("cc-control-action-invalid"))?;
        let request = ActionRequest {
            request_id: request_id.to_owned(),
            kind,
            summary,
            vendor: ActionRequestVendor::ClaudeCode {
                permission_mode_at_decision: ClaudeCodePermissionMode::Default,
                tool_name: tool_name.to_owned(),
            },
        };
        Ok(vec![ClaudeCodeRuntimeOutput::Approval {
            request,
            route: ClaudeCodeApprovalRoute {
                request_id: request_id.to_owned(),
                tool_use_id: tool_use_id.to_owned(),
                tool_name: tool_name.to_owned(),
            },
        }])
    }

    fn tool_started(&mut self, block: &Value) -> Result<ClaudeCodeRuntimeOutput, ProtocolError> {
        let id = block
            .get("id")
            .and_then(Value::as_str)
            .filter(|value| !value.is_empty())
            .ok_or_else(|| fixed_error("cc-tool-identity-invalid"))?;
        if self.in_flight_tools.contains_key(id) || self.completed_tool_ids.contains(id) {
            return Err(fixed_error("cc-tool-identity-duplicate"));
        }
        let name = block
            .get("name")
            .and_then(Value::as_str)
            .filter(|value| !value.is_empty())
            .ok_or_else(|| fixed_error("cc-tool-name-invalid"))?;
        let input = block.get("input").cloned().unwrap_or(Value::Null);
        let record_retained_bytes = tool_record_retained_bytes(id, name, &input)?;
        let retained_bytes = self
            .retained_bytes
            .checked_add(record_retained_bytes)
            .filter(|retained| *retained <= self.retained_byte_limit)
            .ok_or_else(|| fixed_error("cc-retained-state-limit"))?;
        let key = self.next_key()?;
        let item = tool_item(name, &input, None, false);
        self.in_flight_tools.insert(
            id.to_owned(),
            ToolUseRecord {
                key: key.clone(),
                name: name.to_owned(),
                input,
                retained_bytes: record_retained_bytes,
            },
        );
        self.retained_bytes = retained_bytes;
        Ok(ClaudeCodeRuntimeOutput::Event(AdapterEvent::Item {
            key,
            item,
        }))
    }

    fn tool_completed(&mut self, block: &Value) -> Result<ClaudeCodeRuntimeOutput, ProtocolError> {
        let id = block
            .get("tool_use_id")
            .and_then(Value::as_str)
            .filter(|value| !value.is_empty())
            .ok_or_else(|| fixed_error("cc-tool-identity-invalid"))?;
        if self.completed_tool_ids.contains(id) {
            return Err(fixed_error("cc-tool-identity-duplicate"));
        }
        let record = self
            .in_flight_tools
            .get(id)
            .ok_or_else(|| fixed_error("cc-tool-result-orphan"))?;
        let retained_bytes = self
            .retained_bytes
            .checked_sub(record.retained_bytes)
            .and_then(|retained| retained.checked_add(id.len()))
            .filter(|retained| *retained <= self.retained_byte_limit)
            .ok_or_else(|| fixed_error("cc-retained-state-accounting"))?;
        let is_error = block
            .get("is_error")
            .and_then(Value::as_bool)
            .unwrap_or(false);
        let result = tool_result_text(block);
        let key = record.key.clone();
        let item = tool_item(&record.name, &record.input, Some(result), is_error);
        let (completed_id, _) = self
            .in_flight_tools
            .remove_entry(id)
            .ok_or_else(|| fixed_error("cc-retained-state-accounting"))?;
        let inserted = self.completed_tool_ids.insert(completed_id);
        debug_assert!(inserted, "completed tool id was checked before transition");
        self.retained_bytes = retained_bytes;
        Ok(ClaudeCodeRuntimeOutput::Event(AdapterEvent::Item {
            key,
            item,
        }))
    }

    fn item(&mut self, item: AgentItem) -> Result<ClaudeCodeRuntimeOutput, ProtocolError> {
        Ok(ClaudeCodeRuntimeOutput::Event(AdapterEvent::Item {
            key: self.next_key()?,
            item,
        }))
    }

    fn next_key(&mut self) -> Result<AdapterItemKey, ProtocolError> {
        let value = self.next_item_key;
        if value > MAX_TRANSLATED_ITEMS_PER_TURN {
            return Err(fixed_error("cc-item-limit"));
        }
        self.next_item_key = value
            .checked_add(1)
            .ok_or_else(|| fixed_error("cc-item-limit"))?;
        AdapterItemKey::new(format!("cc-item-{value}"))
    }
}

fn validate_task_identity(frame: &Value) -> Result<(), ProtocolError> {
    validate_stream_identity(frame, "cc-system-frame-invalid")?;
    required_frame_text(frame, "task_id", "cc-system-frame-invalid")?;
    validate_optional_frame_text(frame, "tool_use_id", "cc-system-frame-invalid")?;
    Ok(())
}

fn validate_task_update_patch(frame: &Value) -> Result<(), ProtocolError> {
    let patch = frame
        .get("patch")
        .and_then(Value::as_object)
        .filter(|patch| !patch.is_empty())
        .ok_or_else(|| fixed_error("cc-system-frame-invalid"))?;
    for (field, value) in patch {
        let valid = match field.as_str() {
            "status" => value.as_str().is_some_and(|status| {
                matches!(
                    status,
                    "pending" | "running" | "completed" | "failed" | "killed" | "paused"
                )
            }),
            "description" | "error" => value.is_string(),
            "end_time" | "total_paused_ms" => value
                .as_f64()
                .is_some_and(|number| number.is_finite() && number >= 0.0),
            "is_backgrounded" => value.is_boolean(),
            _ => false,
        };
        if !valid {
            return Err(fixed_error("cc-system-frame-invalid"));
        }
    }
    Ok(())
}

fn validate_stream_identity(frame: &Value, error_code: &str) -> Result<(), ProtocolError> {
    required_frame_text(frame, "session_id", error_code)?;
    required_frame_text(frame, "uuid", error_code)?;
    Ok(())
}

fn required_frame_text<'a>(
    frame: &'a Value,
    field: &str,
    error_code: &str,
) -> Result<&'a str, ProtocolError> {
    frame
        .get(field)
        .and_then(Value::as_str)
        .filter(|value| !value.is_empty())
        .ok_or_else(|| fixed_error(error_code))
}

fn validate_optional_frame_text(
    frame: &Value,
    field: &str,
    error_code: &str,
) -> Result<(), ProtocolError> {
    if frame
        .get(field)
        .is_some_and(|value| value.as_str().is_none_or(str::is_empty))
    {
        return Err(fixed_error(error_code));
    }
    Ok(())
}

fn bounded_control_text<'a>(
    value: &'a Value,
    field: &str,
    maximum: usize,
    error_code: &str,
) -> Result<&'a str, ProtocolError> {
    value
        .get(field)
        .and_then(Value::as_str)
        .filter(|text| !text.is_empty() && text.len() <= maximum && !text.as_bytes().contains(&0))
        .ok_or_else(|| fixed_error(error_code))
}

fn bounded_control_summary(prefix: &str, detail: &str) -> Result<Option<String>, ProtocolError> {
    let delimiter = "：";
    let detail_limit = MAX_CONTROL_SUMMARY_BYTES
        .saturating_sub(prefix.len())
        .saturating_sub(delimiter.len());
    if detail.is_empty() || detail.chars().all(char::is_whitespace) {
        return Ok(None);
    }
    if detail.len() > MAX_CONTROL_SUMMARY_SOURCE_BYTES {
        return Err(fixed_error("cc-control-action-too-large"));
    }
    let redacted = crate::record::redact(detail);
    let visible =
        serde_json::to_string(&redacted).map_err(|_| fixed_error("cc-control-action-invalid"))?;
    if visible.len() > detail_limit {
        return Err(fixed_error("cc-control-action-too-large"));
    }
    Ok(Some(format!("{prefix}{delimiter}{visible}")))
}

fn control_action_detail<'a>(tool_name: &'a str, request: &'a Value) -> Option<&'a str> {
    let input = request.get("input").filter(|value| value.is_object());
    match tool_name {
        "Bash" => input.and_then(|value| nonempty_text(value, "command")),
        "Edit" | "Write" | "MultiEdit" => input.and_then(|value| nonempty_text(value, "file_path")),
        "NotebookEdit" => input.and_then(|value| {
            nonempty_text(value, "notebook_path").or_else(|| nonempty_text(value, "file_path"))
        }),
        "Read" => input.and_then(|value| nonempty_text(value, "file_path")),
        _ => None,
    }
}

fn nonempty_text<'a>(value: &'a Value, field: &str) -> Option<&'a str> {
    value
        .get(field)
        .and_then(Value::as_str)
        .filter(|text| !text.is_empty())
}

fn tool_record_retained_bytes(id: &str, name: &str, input: &Value) -> Result<usize, ProtocolError> {
    let input_bytes = serde_json::to_vec(input)
        .map_err(|_| fixed_error("cc-retained-state-accounting"))?
        .len();
    id.len()
        .checked_add(name.len())
        .and_then(|retained| retained.checked_add(input_bytes))
        .ok_or_else(|| fixed_error("cc-retained-state-limit"))
}

fn tool_item(name: &str, input: &Value, result: Option<String>, is_error: bool) -> AgentItem {
    match name {
        "Bash" => AgentItem::Shell {
            command: input
                .get("command")
                .and_then(Value::as_str)
                .unwrap_or_default()
                .to_owned(),
            status: if result.is_none() {
                ShellStatus::Running
            } else if is_error {
                ShellStatus::Failed
            } else {
                ShellStatus::Completed
            },
            // stream-json tool_result 只报告 is_error，不携带进程权威 exit code；
            // 不能把成功/失败布尔值伪造成 0/1。
            exit_code: None,
            duration_ms: None,
            meta: AgentItemMeta::default(),
        },
        "Edit" | "Write" | "MultiEdit" => AgentItem::Diff {
            files: diff_files(name, input),
            meta: AgentItemMeta::default(),
        },
        _ => {
            let mut meta = AgentItemMeta::default();
            if is_error {
                meta.vendor_extensions.insert("isError".into(), json!(true));
            }
            AgentItem::ToolCall {
                name: name.to_owned(),
                args: input.clone(),
                result: result.map(|value| json!(value)),
                meta,
            }
        }
    }
}

fn diff_files(tool: &str, input: &Value) -> Vec<DiffFile> {
    let path = input
        .get("file_path")
        .and_then(Value::as_str)
        .unwrap_or_default()
        .into();
    match tool {
        "Write" => vec![DiffFile {
            path,
            status: DiffStatus::Added,
            patch: input
                .get("content")
                .and_then(Value::as_str)
                .map(str::to_owned),
        }],
        "Edit" => vec![DiffFile {
            path,
            status: DiffStatus::Modified,
            patch: Some(format!(
                "-{}\n+{}\n",
                input
                    .get("old_string")
                    .and_then(Value::as_str)
                    .unwrap_or_default(),
                input
                    .get("new_string")
                    .and_then(Value::as_str)
                    .unwrap_or_default()
            )),
        }],
        "MultiEdit" => vec![DiffFile {
            path,
            status: DiffStatus::Modified,
            patch: Some(
                input
                    .get("edits")
                    .and_then(Value::as_array)
                    .into_iter()
                    .flatten()
                    .map(|edit| {
                        format!(
                            "-{}\n+{}\n",
                            edit.get("old_string")
                                .and_then(Value::as_str)
                                .unwrap_or_default(),
                            edit.get("new_string")
                                .and_then(Value::as_str)
                                .unwrap_or_default()
                        )
                    })
                    .collect(),
            ),
        }],
        _ => Vec::new(),
    }
}

fn tool_result_text(block: &Value) -> String {
    let content = block.get("content");
    if let Some(text) = content.and_then(Value::as_str) {
        return text.to_owned();
    }
    content
        .and_then(Value::as_array)
        .into_iter()
        .flatten()
        .filter_map(|value| value.get("text").and_then(Value::as_str))
        .collect::<Vec<_>>()
        .join("\n")
}

fn fixed_error(code: &str) -> ProtocolError {
    ProtocolError {
        code: code.to_owned(),
        message: "Claude Code typed execution failed".to_owned(),
        diagnostic_ref: None,
    }
}
