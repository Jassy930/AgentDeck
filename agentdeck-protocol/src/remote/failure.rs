//! Relay/remote 失败码注册表（类型化常量，取代散落裸字符串）。
//! wire 上仍是 `RelayControlMsg::Error.code: String`；这些常量是产生/匹配的唯一来源。

// relay.auth.*
pub const AUTH_INVALID_DEVICE: &str = "relay.auth.invalid_device";
pub const AUTH_REVOKED_DEVICE: &str = "relay.auth.revoked_device";
pub const AUTH_FORBIDDEN: &str = "relay.auth.forbidden";
// relay.pair.*
pub const PAIR_BAD_SECRET: &str = "relay.pair.bad_secret";
pub const PAIR_CHALLENGE_EXPIRED: &str = "relay.pair.challenge_expired";
pub const PAIR_BAD_SIGNATURE: &str = "relay.pair.bad_signature";
// relay.*
pub const VERSION_UNSUPPORTED: &str = "relay.version.unsupported";
pub const MACHINE_IDENTITY_CONFLICT: &str = "relay.machine.identity_conflict";
pub const REPLY_UNAUTHORIZED: &str = "relay.reply.unauthorized";
pub const CONFIG_PLAINTEXT_NON_LOOPBACK: &str = "relay.config.plaintext_non_loopback";
// remote.* (R0 复用)
pub const REMOTE_SESSION_NOT_FOUND: &str = "remote.session.not_found";
