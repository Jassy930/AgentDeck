//! Machine trust-reset 的本地 Keychain 清理与 durable `LocalDeleted` 收口。
//!
//! 本模块消费 RemoteTransport ownership，先等待 session shutdown 并释放 active key
//! owner，再读取 authenticated `PurgeReadbackAbsent`。只有全部本地 item 删除且 exact
//! readback absent 后，才允许 Store CAS 到 `LocalDeleted`。

use std::fmt;

use agentdeck_protocol::e2ee::KeyId;
use agentdeck_protocol::relay_v2::{MachineRouteId, RelayServerId, RootKeyId, TrustEpoch};
use async_trait::async_trait;
use thiserror::Error;

use crate::local::listener::RemoteStartPermit;
use crate::runtime::store::{
    FinalizeMachineLocalDeletionOutcome, MachineCleanupWitnessV1, MachineEnrollmentState,
    MachineIdentityBinding, MachinePurgeReadbackProof, MachineRemoteLifecycle,
    MachineRemoteStateRecord, MachineTrustResetKind, RuntimeStoreError, RuntimeStoreHandle,
};
use crate::security::KeyStore;

use super::identity::{MachineIdentityError, cleanup_machine_identity};
use super::transport::{RemoteTransport, RemoteTransportError};

#[derive(Clone)]
struct AuthenticatedMachineCleanup {
    database_id: [u8; 16],
    record: MachineRemoteStateRecord,
    binding: MachineIdentityBinding,
    reset_kind: MachineTrustResetKind,
    purge_proof_hash: [u8; 32],
    /// P4.2 尚未创建 active symmetric-key reservation；空集合是当前 production
    /// authenticated 结果。P4.3 接入 key directory 后由 Store 填入真实 axes。
    counter_guard_axes: Vec<KeyId>,
}

impl AuthenticatedMachineCleanup {
    fn witness(&self) -> Result<MachineCleanupWitnessV1, RuntimeStoreError> {
        if self.record.lifecycle != MachineRemoteLifecycle::PurgeReadbackAbsent
            || self.record.root_key_id != self.binding.root_key_id
            || self.record.root_fingerprint != self.binding.root_fingerprint
            || self.record.trust_epoch != self.binding.trust_epoch
        {
            return Err(RuntimeStoreError::MachineRemoteConflict);
        }
        MachineCleanupWitnessV1::new(
            self.reset_kind,
            RelayServerId::from_bytes(self.record.relay_server_id),
            MachineRouteId::from_bytes(self.record.machine_route),
            RootKeyId::from_bytes(self.record.root_key_id),
            self.record.root_fingerprint,
            TrustEpoch::new(self.record.trust_epoch),
            self.purge_proof_hash,
        )
        .map_err(|_| RuntimeStoreError::MachineRemoteConflict)
    }
}

enum LoadedMachineCleanup {
    Pending(Box<AuthenticatedMachineCleanup>),
    AlreadyLocalDeleted,
}

#[async_trait]
trait MachineCleanupStore: Send + Sync {
    async fn load_authenticated_cleanup(&self) -> Result<LoadedMachineCleanup, RuntimeStoreError>;

    async fn finalize_local_deletion(
        &self,
        reset_kind: MachineTrustResetKind,
        purge_proof_hash: [u8; 32],
        cleanup_witness_hash: [u8; 32],
    ) -> Result<(), RuntimeStoreError>;
}

#[async_trait]
impl MachineCleanupStore for RuntimeStoreHandle {
    async fn load_authenticated_cleanup(&self) -> Result<LoadedMachineCleanup, RuntimeStoreError> {
        let state = self
            .load_machine_enrollment_state()
            .await?
            .ok_or(RuntimeStoreError::MachineRemoteConflict)?;
        match state {
            MachineEnrollmentState::PurgeReadbackAbsent(state) => {
                let purge_proof_hash = match (&state.reset_kind, &state.proof) {
                    (
                        MachineTrustResetKind::RootPresent,
                        MachinePurgeReadbackProof::RootPresent { terminal, .. },
                    ) => terminal.canonical_frame_hash,
                    (
                        MachineTrustResetKind::RootLost,
                        MachinePurgeReadbackProof::RootLost { purge },
                    ) => purge.canonical_hash,
                    _ => return Err(RuntimeStoreError::MachineRemoteConflict),
                };
                let cleanup = AuthenticatedMachineCleanup {
                    database_id: state.database_id,
                    record: state.record,
                    binding: state.binding,
                    reset_kind: state.reset_kind,
                    purge_proof_hash,
                    counter_guard_axes: Vec::new(),
                };
                cleanup.witness()?;
                Ok(LoadedMachineCleanup::Pending(Box::new(cleanup)))
            }
            MachineEnrollmentState::LocalDeleted(_) => {
                Ok(LoadedMachineCleanup::AlreadyLocalDeleted)
            }
            _ => Err(RuntimeStoreError::MachineRemoteConflict),
        }
    }

    async fn finalize_local_deletion(
        &self,
        reset_kind: MachineTrustResetKind,
        purge_proof_hash: [u8; 32],
        cleanup_witness_hash: [u8; 32],
    ) -> Result<(), RuntimeStoreError> {
        let outcome = self
            .finalize_machine_local_deletion(reset_kind, purge_proof_hash, cleanup_witness_hash)
            .await?;
        let state = match outcome {
            FinalizeMachineLocalDeletionOutcome::Finalized { state }
            | FinalizeMachineLocalDeletionOutcome::Replayed { state } => state,
        };
        let MachineEnrollmentState::LocalDeleted(state) = state else {
            return Err(RuntimeStoreError::MachineRemoteConflict);
        };
        if state.record.lifecycle != MachineRemoteLifecycle::LocalDeleted
            || state.reset_kind != reset_kind
            || state.purge_proof_hash != purge_proof_hash
            || state.cleanup_witness_hash != cleanup_witness_hash
        {
            return Err(RuntimeStoreError::MachineRemoteConflict);
        }
        Ok(())
    }
}

#[async_trait]
trait MachineCleanupRemoteOwner: Send {
    async fn shutdown_and_reclaim(self) -> Result<Option<RemoteStartPermit>, RemoteTransportError>;
}

struct OwnedRemoteTransport(Option<RemoteTransport>);

#[async_trait]
impl MachineCleanupRemoteOwner for OwnedRemoteTransport {
    async fn shutdown_and_reclaim(
        mut self,
    ) -> Result<Option<RemoteStartPermit>, RemoteTransportError> {
        if let Some(transport) = self.0.take() {
            return transport
                .shutdown_and_reclaim_start_permit()
                .await
                .map(Some);
        }
        Ok(None)
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum MachineCleanupDisposition {
    Finalized,
    AlreadyLocalDeleted,
}

pub struct MachineCleanupOutcome {
    disposition: MachineCleanupDisposition,
    reclaimed_start_permit: Option<RemoteStartPermit>,
}

impl MachineCleanupOutcome {
    #[must_use]
    pub const fn disposition(&self) -> MachineCleanupDisposition {
        self.disposition
    }

    /// 交还 manager 的同一个一次性 permit；旧 authenticator/key owner 已先销毁。
    #[must_use]
    pub fn into_reclaimed_start_permit(mut self) -> Option<RemoteStartPermit> {
        self.reclaimed_start_permit.take()
    }
}

impl fmt::Debug for MachineCleanupOutcome {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("MachineCleanupOutcome")
            .field("disposition", &self.disposition)
            .field(
                "reclaimed_start_permit",
                &self.reclaimed_start_permit.is_some(),
            )
            .finish()
    }
}

#[derive(Default)]
pub struct MachineCleanupWorkflow;

impl MachineCleanupWorkflow {
    #[must_use]
    pub const fn new() -> Self {
        Self
    }

    /// 消费调用方持有的唯一 transport slot。`Some` 会完整 shutdown；`None` 只用于
    /// root-lost/restart 时 manager 已无 transport owner 的显式状态。
    pub async fn run(
        &self,
        store: &RuntimeStoreHandle,
        key_store: &dyn KeyStore,
        transport: Option<RemoteTransport>,
    ) -> Result<MachineCleanupOutcome, MachineCleanupWorkflowError> {
        self.run_with(store, key_store, OwnedRemoteTransport(transport))
            .await
    }

    async fn run_with<O: MachineCleanupRemoteOwner>(
        &self,
        store: &dyn MachineCleanupStore,
        key_store: &dyn KeyStore,
        owner: O,
    ) -> Result<MachineCleanupOutcome, MachineCleanupWorkflowError> {
        // 顺序是类型/API 边界：owner 被按值消费并 drop 后，才允许取得 cleanup input。
        let reclaimed_start_permit = owner
            .shutdown_and_reclaim()
            .await
            .map_err(MachineCleanupWorkflowError::transport)?;
        let result: Result<MachineCleanupDisposition, MachineCleanupWorkflowError> = async {
            let cleanup = match store.load_authenticated_cleanup().await? {
                LoadedMachineCleanup::Pending(cleanup) => cleanup,
                LoadedMachineCleanup::AlreadyLocalDeleted => {
                    return Ok(MachineCleanupDisposition::AlreadyLocalDeleted);
                }
            };
            let witness = cleanup.witness()?;
            cleanup_machine_identity(
                key_store,
                cleanup.database_id,
                &cleanup.binding,
                cleanup.reset_kind,
                &cleanup.counter_guard_axes,
            )?;
            store
                .finalize_local_deletion(
                    cleanup.reset_kind,
                    cleanup.purge_proof_hash,
                    witness.canonical_sha256(),
                )
                .await?;
            Ok(MachineCleanupDisposition::Finalized)
        }
        .await;
        match result {
            Ok(disposition) => Ok(MachineCleanupOutcome {
                disposition,
                reclaimed_start_permit,
            }),
            Err(mut error) => {
                error.reclaimed_start_permit = reclaimed_start_permit;
                Err(error)
            }
        }
    }
}

#[derive(Debug, Error)]
enum MachineCleanupWorkflowErrorKind {
    #[error(transparent)]
    Store(#[from] RuntimeStoreError),
    #[error(transparent)]
    Identity(#[from] MachineIdentityError),
    #[error(transparent)]
    Transport(#[from] RemoteTransportError),
}

pub struct MachineCleanupWorkflowError {
    kind: MachineCleanupWorkflowErrorKind,
    reclaimed_start_permit: Option<RemoteStartPermit>,
}

impl MachineCleanupWorkflowError {
    #[must_use]
    pub fn code(&self) -> &str {
        match &self.kind {
            MachineCleanupWorkflowErrorKind::Store(error) => error.code(),
            MachineCleanupWorkflowErrorKind::Identity(error) => error.code(),
            MachineCleanupWorkflowErrorKind::Transport(error) => error.code(),
        }
    }

    /// cleanup 在 transport shutdown 后失败时仍把 permit 还给 manager，避免同一
    /// daemon 内失去显式重试/re-enroll capability。
    #[must_use]
    pub fn into_reclaimed_start_permit(mut self) -> Option<RemoteStartPermit> {
        self.reclaimed_start_permit.take()
    }

    fn transport(error: RemoteTransportError) -> Self {
        Self {
            kind: MachineCleanupWorkflowErrorKind::Transport(error),
            reclaimed_start_permit: None,
        }
    }
}

impl From<RuntimeStoreError> for MachineCleanupWorkflowError {
    fn from(error: RuntimeStoreError) -> Self {
        Self {
            kind: MachineCleanupWorkflowErrorKind::Store(error),
            reclaimed_start_permit: None,
        }
    }
}

impl From<MachineIdentityError> for MachineCleanupWorkflowError {
    fn from(error: MachineIdentityError) -> Self {
        Self {
            kind: MachineCleanupWorkflowErrorKind::Identity(error),
            reclaimed_start_permit: None,
        }
    }
}

impl fmt::Debug for MachineCleanupWorkflowError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("MachineCleanupWorkflowError")
            .field("code", &self.code())
            .finish()
    }
}

impl fmt::Display for MachineCleanupWorkflowError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(self.code())
    }
}

impl std::error::Error for MachineCleanupWorkflowError {}

#[cfg(test)]
#[path = "cleanup_tests.rs"]
mod tests;
