//! RuntimeCore 到 daemon remote owner 的中立管理能力。
//!
//! Core 只看见本机管理请求、最小公开状态和稳定错误码；Relay transport、证书、
//! Keychain 与 durable workflow 都留在 `remote` 模块。

use agentdeck_protocol::runtime::{MachineEnrollRequest, MachineRemoteStatus, TrustResetRequest};
use async_trait::async_trait;

const REMOTE_ADMINISTRATION_UNAVAILABLE: &str = "daemon.remote.administration.unavailable";

/// 只携带 bounded stable code；面向 Runtime wire 的 message 由 Core 固定。
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct RemoteAdministrationError {
    code: String,
}

impl RemoteAdministrationError {
    #[must_use]
    pub fn new(code: impl AsRef<str>) -> Self {
        let code = code.as_ref();
        let valid = !code.is_empty()
            && code.len() <= 128
            && code.bytes().all(|byte| {
                byte.is_ascii_lowercase() || byte.is_ascii_digit() || b"._-".contains(&byte)
            });
        Self {
            code: if valid {
                code.to_owned()
            } else {
                REMOTE_ADMINISTRATION_UNAVAILABLE.to_owned()
            },
        }
    }

    #[must_use]
    pub fn code(&self) -> &str {
        &self.code
    }
}

#[async_trait]
pub trait RemoteAdministration: Send + Sync {
    async fn enroll(
        &self,
        request: MachineEnrollRequest,
    ) -> Result<MachineRemoteStatus, RemoteAdministrationError>;

    async fn status(&self) -> Result<MachineRemoteStatus, RemoteAdministrationError>;

    async fn trust_reset(
        &self,
        request: TrustResetRequest,
    ) -> Result<MachineRemoteStatus, RemoteAdministrationError>;
}

/// 默认构造保持 fail-closed，且没有任何 remote side effect。
#[derive(Debug, Default)]
pub struct DisabledRemoteAdministration;

#[async_trait]
impl RemoteAdministration for DisabledRemoteAdministration {
    async fn enroll(
        &self,
        _request: MachineEnrollRequest,
    ) -> Result<MachineRemoteStatus, RemoteAdministrationError> {
        Err(RemoteAdministrationError::new(
            REMOTE_ADMINISTRATION_UNAVAILABLE,
        ))
    }

    async fn status(&self) -> Result<MachineRemoteStatus, RemoteAdministrationError> {
        Err(RemoteAdministrationError::new(
            REMOTE_ADMINISTRATION_UNAVAILABLE,
        ))
    }

    async fn trust_reset(
        &self,
        _request: TrustResetRequest,
    ) -> Result<MachineRemoteStatus, RemoteAdministrationError> {
        Err(RemoteAdministrationError::new(
            REMOTE_ADMINISTRATION_UNAVAILABLE,
        ))
    }
}
