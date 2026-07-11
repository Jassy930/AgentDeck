//! Relay v2 外层失败码（design §14）。
//!
//! Relay 外层错误只描述通用路由/传输失败；daemon 业务错误必须在 encrypted payload 中
//! 返回（见 `runtime::failure` / `e2ee`）。这里登记 `relay.*` 与 relay 侧
//! `remote.transport.*` failure code families，并提供 wire 上的 [`RelayFailure`]。

use schemars::JsonSchema;
use serde::{Deserialize, Serialize};

// —— relay.version.* ——
pub const RELAY_VERSION_UNSUPPORTED: &str = "relay.version.unsupported";

// —— relay.transport.* ——
pub const RELAY_TRANSPORT_TLS_REQUIRED: &str = "relay.transport.tls_required";
pub const RELAY_TRANSPORT_CONFIG_INVALID: &str = "relay.transport.config_invalid";

// —— relay.auth.* ——
pub const RELAY_AUTH_INVALID_GRANT: &str = "relay.auth.invalid_grant";
pub const RELAY_AUTH_REVOKED: &str = "relay.auth.revoked";
pub const RELAY_AUTH_CHALLENGE_EXPIRED: &str = "relay.auth.challenge_expired";
pub const RELAY_AUTH_REPLAY: &str = "relay.auth.replay";

// —— relay.route.* ——
pub const RELAY_ROUTE_NOT_FOUND: &str = "relay.route.not_found";
pub const RELAY_ROUTE_FORBIDDEN: &str = "relay.route.forbidden";
pub const RELAY_ROUTE_CONFLICT: &str = "relay.route.conflict";

// —— relay.frame.* / relay.stream.* / relay.replay.* ——
pub const RELAY_FRAME_TOO_LARGE: &str = "relay.frame.too_large";
pub const RELAY_STREAM_OUT_OF_ORDER: &str = "relay.stream.out_of_order";
pub const RELAY_REPLAY_GAP: &str = "relay.replay.gap";
pub const RELAY_STREAM_GENERATION_STALE: &str = "relay.stream.generation_stale";

// —— relay.store.* / relay.quota.* / relay.disk.* ——
pub const RELAY_STORE_UNAVAILABLE: &str = "relay.store.unavailable";
pub const RELAY_QUOTA_EXCEEDED: &str = "relay.quota.exceeded";
pub const RELAY_DISK_LOW: &str = "relay.disk.low";

// —— relay 侧 transport 层的 remote.* ——
pub const REMOTE_TRANSPORT_TLS_PIN_MISMATCH: &str = "remote.transport.tls_pin_mismatch";

/// Relay 外层通用失败（wire 上是稳定 `code` 字符串）。绝不携带业务明文；
/// `in_reply_to` 只做请求关联，脱敏后关联日志（design §14）。
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct RelayFailure {
    pub code: String,
    pub message: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub in_reply_to: Option<String>,
}

impl RelayFailure {
    pub fn new(code: impl Into<String>, message: impl Into<String>) -> Self {
        Self {
            code: code.into(),
            message: message.into(),
            in_reply_to: None,
        }
    }

    pub fn in_reply_to(mut self, reference: impl Into<String>) -> Self {
        self.in_reply_to = Some(reference.into());
        self
    }
}
