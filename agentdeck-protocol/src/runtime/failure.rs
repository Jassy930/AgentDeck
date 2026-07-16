//! Runtime v2 类型化业务失败承载（design §14）。
//!
//! Relay 外层错误只描述通用路由/传输失败；daemon 业务错误必须在解密后的
//! Runtime payload 中以 `RuntimeFailure` 返回。这里登记 Runtime 契约需要承载的
//! `daemon.*` / `remote.*` failure code families（唯一产生/匹配来源）。

use schemars::JsonSchema;
use serde::{Deserialize, Serialize};

// —— daemon.command.* ——
pub const DAEMON_COMMAND_IDEMPOTENCY_CONFLICT: &str = "daemon.command.idempotency_conflict";
pub const DAEMON_COMMAND_QUEUE_FULL: &str = "daemon.command.queue_full";
pub const DAEMON_COMMAND_QUEUE_EXPIRED: &str = "daemon.command.queue_expired";
pub const DAEMON_COMMAND_INTERRUPTED: &str = "daemon.command.interrupted";

// —— daemon.runtime.* ——
pub const DAEMON_RUNTIME_RECOVERY_BLOCKED: &str = "daemon.runtime.recovery_blocked";
pub const DAEMON_RUNTIME_DISK_LOW: &str = "daemon.runtime.disk_low";
pub const DAEMON_RUNTIME_NOT_READY: &str = "daemon.runtime.not_ready";
pub const DAEMON_RUNTIME_PROTOCOL_MISMATCH: &str = "daemon.runtime.protocol_mismatch";
pub const DAEMON_RUNTIME_INVALID_REQUEST: &str = "daemon.runtime.invalid_request";
pub const DAEMON_RUNTIME_FEATURE_UNAVAILABLE: &str = "daemon.runtime.feature_unavailable";
pub const DAEMON_RUNTIME_IDENTITY_UNAVAILABLE: &str = "daemon.runtime.identity_unavailable";
pub const DAEMON_RUNTIME_ACTOR_UNAVAILABLE: &str = "daemon.runtime.actor_unavailable";
pub const DAEMON_RUNTIME_EXECUTION_FAILED: &str = "daemon.runtime.execution_failed";
pub const DAEMON_RUNTIME_CONNECTION_UNAVAILABLE: &str = "daemon.runtime.connection_unavailable";
pub const DAEMON_RUNTIME_READ_UNAVAILABLE: &str = "daemon.runtime.read_unavailable";

// —— daemon.authorization.* ——
pub const DAEMON_AUTHORIZATION_REVOKED: &str = "daemon.authorization.revoked";
pub const DAEMON_AUTHORIZATION_PERMISSION_DENIED: &str = "daemon.authorization.permission_denied";

// —— daemon.approval.* / daemon.turn.* ——
pub const DAEMON_APPROVAL_ALREADY_HANDLED: &str = "daemon.approval.already_handled";
pub const DAEMON_APPROVAL_DELIVERY_FAILED: &str = "daemon.approval.delivery_failed";
pub const DAEMON_APPROVAL_EXPIRED: &str = "daemon.approval.expired";
pub const DAEMON_TURN_STALE: &str = "daemon.turn.stale";

// —— daemon.payload.* / daemon.conversation.* ——
pub const DAEMON_PAYLOAD_ITEM_TOO_LARGE: &str = "daemon.payload.item_too_large";
pub const DAEMON_CONVERSATION_NOT_FOUND: &str = "daemon.conversation.not_found";

// —— remote.transfer.* （解密后分片重组失败）——
pub const REMOTE_TRANSFER_TOO_LARGE: &str = "remote.transfer.too_large";
pub const REMOTE_TRANSFER_HASH_MISMATCH: &str = "remote.transfer.hash_mismatch";
pub const REMOTE_TRANSFER_EXPIRED: &str = "remote.transfer.expired";
pub const REMOTE_TRANSFER_REASSEMBLY_FULL: &str = "remote.transfer.reassembly_full";

// —— remote.machine.* ——
pub const REMOTE_MACHINE_OFFLINE: &str = "remote.machine.offline";

/// 类型化业务失败：wire 上仍是稳定 `code` 字符串，`message` 供人读，
/// `diagnostic_ref` 用于关联日志但不得泄漏完整业务 ID（design §14）。
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct RuntimeFailure {
    pub code: String,
    pub message: String,
    #[serde(default)]
    pub diagnostic_ref: Option<String>,
}

impl RuntimeFailure {
    pub fn new(code: impl Into<String>, message: impl Into<String>) -> Self {
        Self {
            code: code.into(),
            message: message.into(),
            diagnostic_ref: None,
        }
    }

    pub fn with_diagnostic(mut self, diagnostic_ref: impl Into<String>) -> Self {
        self.diagnostic_ref = Some(diagnostic_ref.into());
        self
    }
}
