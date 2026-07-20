//! RuntimeCore 到 daemon device-revocation owner 的中立管理能力。
//!
//! Core 只传递 opaque [`DeviceHandle`]、单调 [`GrantSerial`] 与中立回执；Relay、
//! MachineRoot、auth ledger、route outbox 和连接 generation 均留在后续实现侧。

use agentdeck_protocol::runtime::RevocationReceipt;
use agentdeck_protocol::runtime::identity::{DeviceHandle, GrantSerial};
use async_trait::async_trait;

const REVOCATION_ADMINISTRATION_UNAVAILABLE: &str = "daemon.revocation.administration.unavailable";

/// 只携带最长 128-byte 的 stable code；wire failure message 由 Core 固定。
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct RevocationAdministrationError {
    code: String,
}

impl RevocationAdministrationError {
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
                REVOCATION_ADMINISTRATION_UNAVAILABLE.to_owned()
            },
        }
    }

    #[must_use]
    pub fn code(&self) -> &str {
        &self.code
    }
}

/// Local-only device revocation seam。它不接受 principal、Relay route 或 raw crypto key。
#[async_trait]
pub trait RevocationAdministration: Send + Sync {
    async fn revoke_device(
        &self,
        device: DeviceHandle,
        grant_serial: GrantSerial,
    ) -> Result<RevocationReceipt, RevocationAdministrationError>;
}

/// 默认 composition fail-close，且不产生 Store、crypto 或 network side effect。
#[derive(Debug, Default)]
pub struct DisabledRevocationAdministration;

#[async_trait]
impl RevocationAdministration for DisabledRevocationAdministration {
    async fn revoke_device(
        &self,
        _device: DeviceHandle,
        _grant_serial: GrantSerial,
    ) -> Result<RevocationReceipt, RevocationAdministrationError> {
        Err(RevocationAdministrationError::new(
            REVOCATION_ADMINISTRATION_UNAVAILABLE,
        ))
    }
}
