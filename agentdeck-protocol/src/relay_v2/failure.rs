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
pub const RELAY_REPLAY_CURSOR_INVALID: &str = "relay.replay.cursor_invalid";
pub const RELAY_STREAM_GENERATION_STALE: &str = "relay.stream.generation_stale";

// —— relay.store.* / relay.quota.* / relay.disk.* ——
pub const RELAY_STORE_UNAVAILABLE: &str = "relay.store.unavailable";
pub const RELAY_QUOTA_EXCEEDED: &str = "relay.quota.exceeded";
pub const RELAY_DISK_LOW: &str = "relay.disk.low";

// —— relay 侧 transport 层的 remote.* ——
pub const REMOTE_TRANSPORT_TLS_PIN_MISMATCH: &str = "remote.transport.tls_pin_mismatch";

/// Relay 外层通用失败（wire 上是稳定 `code` 字符串）。绝不携带业务明文；
/// `in_reply_to` 只做请求关联，脱敏后关联日志（design §14）。
#[derive(Clone, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
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

    /// 只允许稳定failure namespace字符进入client诊断；message/reply reference永不进Debug。
    pub fn has_safe_code(&self) -> bool {
        !self.code.is_empty()
            && self.code.len() <= 128
            && (self.code.starts_with("relay.") || self.code.starts_with("remote.transport."))
            && self.code.bytes().all(|byte| {
                byte.is_ascii_lowercase() || byte.is_ascii_digit() || b"._-".contains(&byte)
            })
    }
}

impl std::fmt::Debug for RelayFailure {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("RelayFailure")
            .field(
                "code",
                &if self.has_safe_code() {
                    self.code.as_str()
                } else {
                    "<invalid>"
                },
            )
            .field("message", &"<redacted>")
            .field("in_reply_to", &"<redacted>")
            .finish()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn failure_debug_redacts_message_reference_and_invalid_code() {
        let safe = RelayFailure::new("relay.route.forbidden", "secret-message")
            .in_reply_to("secret-reference");
        let rendered = format!("{safe:?}");
        assert!(rendered.contains("relay.route.forbidden"));
        assert!(!rendered.contains("secret-message"));
        assert!(!rendered.contains("secret-reference"));

        let invalid = RelayFailure::new("relay.bad\nsecret", "message");
        let rendered = format!("{invalid:?}");
        assert!(rendered.contains("<invalid>"));
        assert!(!rendered.contains("secret"));
    }
}
