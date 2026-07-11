//! Transport abstraction. v0.2 ships only stdio impl, but the trait
//! must support remote (async, reconnectable, auth context).

use serde::{Deserialize, Serialize};

/// Auth context carried with a transport connection. v0.2 stdio impl
/// uses `Anonymous`; v0.5 remote impls fill in token / device id.
#[derive(Clone, Serialize, Deserialize)]
pub enum AuthContext {
    Anonymous,
    Bearer { token: String, device_id: String },
}

impl std::fmt::Debug for AuthContext {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            AuthContext::Anonymous => write!(f, "AuthContext::Anonymous"),
            AuthContext::Bearer { device_id, .. } => {
                // token 脱敏，device_id 保留用于诊断
                write!(
                    f,
                    "AuthContext::Bearer {{ token: <redacted>, device_id: {device_id:?} }}"
                )
            }
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TransportConfig {
    pub reconnect_max_attempts: u32,
    pub reconnect_backoff_ms: u64,
    pub auth: AuthContext,
}

impl Default for TransportConfig {
    fn default() -> Self {
        Self {
            reconnect_max_attempts: 0,
            reconnect_backoff_ms: 0,
            auth: AuthContext::Anonymous,
        }
    }
}

/// Bidirectional JSONL-framed transport between client and daemon.
/// Must be Send + Sync + 'static so remote async impls can move across
/// task boundaries. v0.2 ships only stdio; v0.5 adds WS+TLS.
#[async_trait::async_trait]
pub trait Transport: Send + Sync + 'static {
    /// Send a single JSONL-encoded message to the daemon.
    async fn send(&self, line: String) -> Result<(), TransportError>;

    /// Receive the next JSONL line from the daemon. Returns None on EOF.
    async fn recv(&self) -> Result<Option<String>, TransportError>;

    /// Reconnect to the daemon if supported. Stdio impl returns
    /// `Err(TransportError::NotReconnectable)`.
    async fn reconnect(&self) -> Result<(), TransportError>;

    /// Return a snapshot of the current connection's auth context for
    /// logging / diagnostics. Must not leak token material in display.
    fn auth_context(&self) -> &AuthContext;
}

#[derive(Debug, thiserror::Error)]
pub enum TransportError {
    #[error("transport I/O failure: {0}")]
    Io(#[from] std::io::Error),
    #[error("transport closed by remote")]
    Closed,
    #[error("transport does not support reconnect")]
    NotReconnectable,
    #[error("transport auth failed: {0}")]
    AuthFailed(String),
}

#[cfg(test)]
mod redact_tests {
    use super::*;
    #[test]
    fn auth_context_debug_redacts_token() {
        let a = AuthContext::Bearer {
            token: "SECRET-TOKEN-123".into(),
            device_id: "dev-1".into(),
        };
        let s = format!("{a:?}");
        assert!(
            !s.contains("SECRET-TOKEN-123"),
            "token must be redacted in Debug: {s}"
        );
        assert!(s.contains("Bearer"), "should still show variant");
    }
}
