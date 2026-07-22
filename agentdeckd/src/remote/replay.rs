//! Relay v2 ingress 的 durable replay 门禁。
//!
//! 本模块只负责在签名、key-directory revision 与 barrier/key readiness 已验证后，
//! 把完整 nonce scope 的 `(counter, ciphertext hash)` 交给 Runtime Store 线性化提交。
//! 完全相同的 tuple 会重新进入 RuntimeCore，由 durable command ledger 重放 receipt；
//! nonce reuse、revision rollback 与未验证签名则要求隔离当前连接。

use std::fmt;

use agentdeck_protocol::relay_v2::{
    DeviceRouteId, GrantSerial, KeyDirectoryRevision, MachineRouteId, StreamRouteId, TrustEpoch,
};

use crate::runtime::store::{RuntimeStoreError, RuntimeStoreHandle};

use super::super::runtime::store::remote_replay::{
    MAX_REMOTE_REPLAY_SCOPES, REMOTE_REPLAY_SCOPE_BYTES, RemoteReplayAdmission,
    RemoteReplayStoreDecision,
};

const REPLAY_SCOPE_VERSION: u8 = 1;
const DEVICE_COMMAND_PURPOSE: u8 = 1;
const DEVICE_REPLY_PURPOSE: u8 = 2;
const CONVERSATION_PURPOSE: u8 = 3;
const CATALOG_PURPOSE: u8 = 4;

#[derive(Clone, Eq, Hash, PartialEq)]
pub struct ReplayKeyScope {
    canonical: [u8; REMOTE_REPLAY_SCOPE_BYTES],
}

impl ReplayKeyScope {
    pub fn device_command(
        machine_route: MachineRouteId,
        trust_epoch: TrustEpoch,
        device_route: DeviceRouteId,
        grant_serial: GrantSerial,
        key_epoch: u64,
    ) -> Result<Self, ReplayError> {
        Self::directed(
            DEVICE_COMMAND_PURPOSE,
            machine_route,
            trust_epoch,
            device_route,
            grant_serial,
            key_epoch,
        )
    }

    pub fn device_reply(
        machine_route: MachineRouteId,
        trust_epoch: TrustEpoch,
        device_route: DeviceRouteId,
        grant_serial: GrantSerial,
        key_epoch: u64,
    ) -> Result<Self, ReplayError> {
        Self::directed(
            DEVICE_REPLY_PURPOSE,
            machine_route,
            trust_epoch,
            device_route,
            grant_serial,
            key_epoch,
        )
    }

    pub fn conversation(
        machine_route: MachineRouteId,
        trust_epoch: TrustEpoch,
        stream_route: StreamRouteId,
        key_epoch: u64,
    ) -> Result<Self, ReplayError> {
        Self::build(
            CONVERSATION_PURPOSE,
            machine_route,
            trust_epoch,
            *stream_route.as_bytes(),
            0,
            key_epoch,
        )
    }

    pub fn catalog(
        machine_route: MachineRouteId,
        trust_epoch: TrustEpoch,
        key_epoch: u64,
    ) -> Result<Self, ReplayError> {
        Self::build(
            CATALOG_PURPOSE,
            machine_route,
            trust_epoch,
            [0; 16],
            0,
            key_epoch,
        )
    }

    fn directed(
        purpose: u8,
        machine_route: MachineRouteId,
        trust_epoch: TrustEpoch,
        device_route: DeviceRouteId,
        grant_serial: GrantSerial,
        key_epoch: u64,
    ) -> Result<Self, ReplayError> {
        Self::build(
            purpose,
            machine_route,
            trust_epoch,
            *device_route.as_bytes(),
            grant_serial.value(),
            key_epoch,
        )
    }

    fn build(
        purpose: u8,
        machine_route: MachineRouteId,
        trust_epoch: TrustEpoch,
        subject_route: [u8; 16],
        grant_serial: u64,
        key_epoch: u64,
    ) -> Result<Self, ReplayError> {
        let directed = matches!(purpose, DEVICE_COMMAND_PURPOSE | DEVICE_REPLY_PURPOSE);
        let shape_valid = match purpose {
            DEVICE_COMMAND_PURPOSE | DEVICE_REPLY_PURPOSE => {
                subject_route != [0; 16] && grant_serial > 0
            }
            CONVERSATION_PURPOSE => subject_route != [0; 16] && grant_serial == 0,
            CATALOG_PURPOSE => subject_route == [0; 16] && grant_serial == 0,
            _ => false,
        };
        if machine_route.as_bytes() == &[0; 16]
            || trust_epoch.value() == 0
            || key_epoch == 0
            || !shape_valid
            || (directed && grant_serial == 0)
        {
            return Err(ReplayError::ScopeInvalid);
        }

        let mut canonical = [0_u8; REMOTE_REPLAY_SCOPE_BYTES];
        canonical[0] = REPLAY_SCOPE_VERSION;
        canonical[1] = purpose;
        canonical[2..18].copy_from_slice(machine_route.as_bytes());
        canonical[18..26].copy_from_slice(&trust_epoch.value().to_be_bytes());
        canonical[26..42].copy_from_slice(&subject_route);
        canonical[42..50].copy_from_slice(&grant_serial.to_be_bytes());
        canonical[50..58].copy_from_slice(&key_epoch.to_be_bytes());
        Ok(Self { canonical })
    }

    fn canonical(&self) -> [u8; REMOTE_REPLAY_SCOPE_BYTES] {
        self.canonical
    }
}

impl fmt::Debug for ReplayKeyScope {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("ReplayKeyScope([REDACTED])")
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ReplaySignatureStatus {
    Verified,
    Unverified,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ReplayReadiness {
    Ready,
    WaitingForBarrier,
    WaitingForKey,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ReplayObservation {
    pub scope: ReplayKeyScope,
    pub key_directory_revision: KeyDirectoryRevision,
    pub sender_counter: u64,
    pub ciphertext_sha256: [u8; 32],
    pub signature: ReplaySignatureStatus,
    pub readiness: ReplayReadiness,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ReplayDecision {
    Fresh,
    ExactDuplicate,
    Stale,
    KeySyncRequired {
        local_revision: KeyDirectoryRevision,
        observed_revision: KeyDirectoryRevision,
    },
    WaitingForBarrier,
    WaitingForKey,
}

impl ReplayDecision {
    #[must_use]
    pub const fn should_dispatch_to_runtime_core(self) -> bool {
        matches!(self, Self::Fresh | Self::ExactDuplicate)
    }
}

#[derive(Debug, thiserror::Error)]
pub enum ReplayError {
    #[error("remote replay scope is invalid")]
    ScopeInvalid,
    #[error("remote replay signature is not verified")]
    SignatureUnverified,
    #[error("remote replay key-directory revision rolled back")]
    RevisionRollback,
    #[error("remote replay counter reused a nonce with different ciphertext")]
    NonceReuse,
    #[error("remote replay sender epoch is retired")]
    RetiredKey,
    #[error("remote replay scope capacity is exhausted")]
    Capacity,
    #[error("remote replay durable store failed: {0}")]
    Store(#[source] RuntimeStoreError),
}

impl ReplayError {
    #[must_use]
    pub const fn code(&self) -> &'static str {
        match self {
            Self::ScopeInvalid => "daemon.remote.replay.scope_invalid",
            Self::SignatureUnverified => "daemon.remote.replay.signature_unverified",
            Self::RevisionRollback => "daemon.remote.replay.revision_rollback",
            Self::NonceReuse => "daemon.remote.replay.nonce_reuse",
            Self::RetiredKey => "daemon.remote.replay.retired_key",
            Self::Capacity => "daemon.remote.replay.capacity",
            Self::Store(error) => error.code(),
        }
    }

    #[must_use]
    pub const fn requires_connection_isolation(&self) -> bool {
        matches!(
            self,
            Self::SignatureUnverified
                | Self::RevisionRollback
                | Self::NonceReuse
                | Self::RetiredKey
        )
    }
}

impl From<RuntimeStoreError> for ReplayError {
    fn from(error: RuntimeStoreError) -> Self {
        Self::Store(error)
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct RemoteReplayConfig {
    scope_capacity: u64,
}

impl RemoteReplayConfig {
    #[must_use]
    pub const fn with_scope_capacity(mut self, scope_capacity: u64) -> Self {
        self.scope_capacity = scope_capacity;
        self
    }
}

impl Default for RemoteReplayConfig {
    fn default() -> Self {
        Self {
            scope_capacity: MAX_REMOTE_REPLAY_SCOPES,
        }
    }
}

#[derive(Clone, Debug)]
pub struct RemoteReplayGuard {
    store: RuntimeStoreHandle,
    config: RemoteReplayConfig,
}

impl RemoteReplayGuard {
    #[must_use]
    pub const fn new(store: RuntimeStoreHandle, config: RemoteReplayConfig) -> Self {
        Self { store, config }
    }

    pub async fn admit(
        &self,
        local_revision: KeyDirectoryRevision,
        observation: ReplayObservation,
    ) -> Result<ReplayDecision, ReplayError> {
        if observation.signature != ReplaySignatureStatus::Verified {
            return Err(ReplayError::SignatureUnverified);
        }
        if observation.key_directory_revision < local_revision {
            return Err(ReplayError::RevisionRollback);
        }
        let revision_ahead = observation.key_directory_revision > local_revision;
        if !revision_ahead {
            match observation.readiness {
                ReplayReadiness::WaitingForBarrier => {
                    return Ok(ReplayDecision::WaitingForBarrier);
                }
                ReplayReadiness::WaitingForKey => return Ok(ReplayDecision::WaitingForKey),
                ReplayReadiness::Ready => {}
            }
        }

        let outcome = self
            .store
            .admit_remote_replay(RemoteReplayAdmission {
                scope: observation.scope.canonical(),
                sender_counter: observation.sender_counter,
                ciphertext_sha256: observation.ciphertext_sha256,
                scope_capacity: self.config.scope_capacity,
            })
            .await?;
        match outcome {
            RemoteReplayStoreDecision::Fresh | RemoteReplayStoreDecision::ExactDuplicate
                if revision_ahead =>
            {
                Ok(ReplayDecision::KeySyncRequired {
                    local_revision,
                    observed_revision: observation.key_directory_revision,
                })
            }
            RemoteReplayStoreDecision::Fresh => Ok(ReplayDecision::Fresh),
            RemoteReplayStoreDecision::ExactDuplicate => Ok(ReplayDecision::ExactDuplicate),
            RemoteReplayStoreDecision::Stale => Ok(ReplayDecision::Stale),
            RemoteReplayStoreDecision::NonceReuse => Err(ReplayError::NonceReuse),
            RemoteReplayStoreDecision::Retired => Err(ReplayError::RetiredKey),
            RemoteReplayStoreDecision::Capacity => Err(ReplayError::Capacity),
        }
    }

    pub async fn contains_scope(&self, scope: &ReplayKeyScope) -> Result<bool, ReplayError> {
        Ok(self
            .store
            .contains_remote_replay_scope(scope.canonical())
            .await?)
    }

    pub async fn retire_scope(
        &self,
        scope: ReplayKeyScope,
        retired_at_ms: u64,
    ) -> Result<(), ReplayError> {
        Ok(self
            .store
            .retire_remote_replay_scope(scope.canonical(), retired_at_ms)
            .await?)
    }

    pub async fn pin_retired_scope(
        &self,
        scope: ReplayKeyScope,
        pin_id: [u8; 16],
    ) -> Result<(), ReplayError> {
        Ok(self
            .store
            .pin_retired_remote_replay_scope(scope.canonical(), pin_id)
            .await?)
    }

    pub async fn release_retired_pin(
        &self,
        scope: ReplayKeyScope,
        pin_id: [u8; 16],
    ) -> Result<(), ReplayError> {
        Ok(self
            .store
            .release_retired_remote_replay_pin(scope.canonical(), pin_id)
            .await?)
    }

    pub async fn gc_retired(&self, now_ms: u64) -> Result<u64, ReplayError> {
        Ok(self.store.gc_retired_remote_replay(now_ms).await?)
    }
}
