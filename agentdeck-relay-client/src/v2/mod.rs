//! Relay v2 binary client、TLS policy 与三类互斥连接状态机。

mod connection;
mod tls;
mod transport;

use std::fmt;
use std::sync::Arc;
use std::time::Duration;

use agentdeck_protocol::relay_v2::frame::{AuthProof, Authenticate, Challenge};
use agentdeck_protocol::relay_v2::{OpaqueRouteFrame, RelayServerId};
use async_trait::async_trait;
use url::Url;

pub use connection::{PairingEvent, RelayClient, RelayEnrollmentClient, RelayPairingClient};
pub use tls::RelayTlsPolicy;

pub(crate) const CONNECT_TIMEOUT: Duration = Duration::from_secs(5);
pub(crate) const HANDSHAKE_TIMEOUT: Duration = Duration::from_secs(10);
pub(crate) const IO_TIMEOUT: Duration = Duration::from_secs(10);
pub(crate) const MAX_ENROLLMENT_BYTES: usize = 64 * 1024;

/// Relay client 只公开稳定 failure code；唯一携带 wire 的错误是必须由调用方验证并
/// 持久化的 signed revocation/retirement terminal，Debug 仍完全脱敏。
#[derive(Clone, PartialEq, Eq)]
pub enum RelayClientError {
    Failure {
        code: String,
    },
    AuthenticationTerminal {
        frame: Box<OpaqueRouteFrame>,
        canonical_bytes: Arc<[u8]>,
    },
}

impl RelayClientError {
    pub(crate) fn new(code: impl Into<String>) -> Self {
        Self::Failure { code: code.into() }
    }

    pub(crate) fn authentication_terminal(
        frame: OpaqueRouteFrame,
        canonical_bytes: Vec<u8>,
    ) -> Self {
        Self::AuthenticationTerminal {
            frame: Box::new(frame),
            canonical_bytes: canonical_bytes.into(),
        }
    }

    pub fn code(&self) -> &str {
        match self {
            Self::Failure { code } => code,
            Self::AuthenticationTerminal { .. } => "relay.client.authentication_terminal",
        }
    }

    pub fn authentication_terminal_frame(&self) -> Option<&OpaqueRouteFrame> {
        match self {
            Self::AuthenticationTerminal { frame, .. } => Some(frame.as_ref()),
            Self::Failure { .. } => None,
        }
    }

    pub fn authentication_terminal_bytes(&self) -> Option<&[u8]> {
        match self {
            Self::AuthenticationTerminal {
                canonical_bytes, ..
            } => Some(canonical_bytes),
            Self::Failure { .. } => None,
        }
    }
}

impl fmt::Debug for RelayClientError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("RelayClientError")
            .field("code", &self.code())
            .field("wire", &"<redacted>")
            .finish()
    }
}

impl fmt::Display for RelayClientError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(self.code())
    }
}

impl std::error::Error for RelayClientError {}

/// 不可变的 Relay WSS origin、服务身份与 TLS policy。
#[derive(Clone)]
pub struct RelayClientConfig {
    pub(crate) origin: Url,
    pub(crate) expected_relay_server_id: RelayServerId,
    pub(crate) tls: RelayTlsPolicy,
}

impl RelayClientConfig {
    pub fn new(
        origin: &str,
        expected_relay_server_id: RelayServerId,
        tls: RelayTlsPolicy,
    ) -> Result<Self, RelayClientError> {
        let origin =
            Url::parse(origin).map_err(|_| RelayClientError::new("relay.client.origin_invalid"))?;
        if origin.scheme() != "wss"
            || origin.host_str().is_none()
            || !origin.username().is_empty()
            || origin.password().is_some()
            || origin.path() != "/"
            || origin.port() == Some(0)
            || origin.query().is_some()
            || origin.fragment().is_some()
        {
            return Err(RelayClientError::new("relay.client.origin_invalid"));
        }
        Ok(Self {
            origin,
            expected_relay_server_id,
            tls,
        })
    }

    pub fn origin(&self) -> &str {
        self.origin.as_str()
    }
}

impl fmt::Debug for RelayClientConfig {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("RelayClientConfig")
            .field("origin", &"<redacted>")
            .field("relay_server", &"<redacted>")
            .field("tls", &self.tls)
            .finish()
    }
}

/// Enrollment 与 WSS 复用完全相同的 frozen origin/TLS policy。
#[derive(Clone)]
pub struct EnrollmentClientConfig {
    pub(crate) relay: RelayClientConfig,
}

impl EnrollmentClientConfig {
    pub fn new(relay: RelayClientConfig) -> Self {
        Self { relay }
    }
}

impl fmt::Debug for EnrollmentClientConfig {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("EnrollmentClientConfig")
            .field("relay", &"<redacted>")
            .finish()
    }
}

/// 每个 fresh Challenge 只调用一次；实现方不得缓存/重放旧签名。
#[async_trait]
pub trait LinkAuthenticator: Send + Sync + 'static {
    fn proof(&self) -> AuthProof;

    async fn authenticate(&self, challenge: &Challenge) -> Result<Authenticate, RelayClientError>;
}
