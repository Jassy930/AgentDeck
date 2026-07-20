//! RuntimeCore 到 daemon pairing owner 的中立管理能力。
//!
//! Core 只持有 caller identity、local-only 请求/回执与一个不保存 pairing state 的
//! bounded pending sink；Relay、MachineRoot、HPKE、PairRoute 与 SQLite workflow 均留在
//! `remote` / `store` 模块。

use agentdeck_protocol::runtime::{
    CreatePairInviteRequest, PairInvite, PairingReceipt, PendingPairing, RUNTIME_PROTOCOL_VERSION,
    RuntimeEnvelope, RuntimeMessage, RuntimeStreamItem,
};
use async_trait::async_trait;

use super::connection::{ConnectionError, ConnectionRegistry, EncodedRuntimeFrame};
use super::store::{IdempotencyOwner, RuntimeId};

const PAIRING_ADMINISTRATION_UNAVAILABLE: &str = "daemon.pairing.administration.unavailable";

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct PairingAdministrationError {
    code: String,
}

impl PairingAdministrationError {
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
                PAIRING_ADMINISTRATION_UNAVAILABLE.to_owned()
            },
        }
    }

    #[must_use]
    pub fn code(&self) -> &str {
        &self.code
    }
}

#[async_trait]
pub trait PairingAdministration: Send + Sync {
    async fn create(
        &self,
        owner: IdempotencyOwner,
        request: CreatePairInviteRequest,
    ) -> Result<PairInvite, PairingAdministrationError>;

    async fn list(&self) -> Result<Vec<PendingPairing>, PairingAdministrationError>;

    async fn confirm(
        &self,
        pairing_id: RuntimeId,
    ) -> Result<PairingReceipt, PairingAdministrationError>;

    async fn cancel(
        &self,
        pairing_id: RuntimeId,
    ) -> Result<PairingReceipt, PairingAdministrationError>;
}

#[derive(Debug, Default)]
pub struct DisabledPairingAdministration;

#[async_trait]
impl PairingAdministration for DisabledPairingAdministration {
    async fn create(
        &self,
        _owner: IdempotencyOwner,
        _request: CreatePairInviteRequest,
    ) -> Result<PairInvite, PairingAdministrationError> {
        Err(PairingAdministrationError::new(
            PAIRING_ADMINISTRATION_UNAVAILABLE,
        ))
    }

    async fn list(&self) -> Result<Vec<PendingPairing>, PairingAdministrationError> {
        Err(PairingAdministrationError::new(
            PAIRING_ADMINISTRATION_UNAVAILABLE,
        ))
    }

    async fn confirm(
        &self,
        _pairing_id: RuntimeId,
    ) -> Result<PairingReceipt, PairingAdministrationError> {
        Err(PairingAdministrationError::new(
            PAIRING_ADMINISTRATION_UNAVAILABLE,
        ))
    }

    async fn cancel(
        &self,
        _pairing_id: RuntimeId,
    ) -> Result<PairingReceipt, PairingAdministrationError> {
        Err(PairingAdministrationError::new(
            PAIRING_ADMINISTRATION_UNAVAILABLE,
        ))
    }
}

/// Remote pairing coordinator 在 durable pending commit 后调用的最小 capability。
/// 无订阅者是成功；慢连接只关闭自身，pending 仍可通过 list 读回。
pub trait PairingPendingSink: Send + Sync {
    fn publish(&self, pending: PendingPairing) -> Result<usize, PairingAdministrationError>;
}

pub(crate) struct RuntimePairingPendingSink {
    connections: ConnectionRegistry,
}

impl RuntimePairingPendingSink {
    pub(crate) fn new(connections: ConnectionRegistry) -> Self {
        Self { connections }
    }
}

impl PairingPendingSink for RuntimePairingPendingSink {
    fn publish(&self, pending: PendingPairing) -> Result<usize, PairingAdministrationError> {
        let message_id = random_pending_message_id()?;
        let envelope = RuntimeEnvelope {
            version: RUNTIME_PROTOCOL_VERSION,
            message_id,
            body: RuntimeMessage::Stream(RuntimeStreamItem::PairingPending(pending)),
        };
        let frame = EncodedRuntimeFrame::from_envelope(&envelope)
            .map_err(pairing_pending_connection_error)?;
        self.connections
            .try_enqueue_local_administration(frame)
            .map_err(pairing_pending_connection_error)
    }
}

fn random_pending_message_id()
-> Result<agentdeck_protocol::runtime::identity::MessageId, PairingAdministrationError> {
    let mut bytes = [0_u8; 16];
    getrandom::fill(&mut bytes).map_err(|_| {
        PairingAdministrationError::new("daemon.pairing.pending.identity_unavailable")
    })?;
    if bytes == [0; 16] {
        return Err(PairingAdministrationError::new(
            "daemon.pairing.pending.identity_unavailable",
        ));
    }
    Ok(agentdeck_protocol::runtime::identity::MessageId::new(
        format!("pairing-{}", uuid::Uuid::from_bytes(bytes).hyphenated()),
    ))
}

fn pairing_pending_connection_error(error: ConnectionError) -> PairingAdministrationError {
    let code = match error {
        ConnectionError::EntropyUnavailable => "daemon.pairing.pending.identity_unavailable",
        ConnectionError::Encode | ConnectionError::FrameTooLarge => {
            "daemon.pairing.pending.invalid"
        }
        _ => "daemon.pairing.pending.connection_unavailable",
    };
    PairingAdministrationError::new(code)
}
