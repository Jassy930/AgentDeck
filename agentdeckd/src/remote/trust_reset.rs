//! Machine trust-reset 的确定性 root 签名与 durable orchestration。
//!
//! Root-present 先执行 `RetirePending → RelayCommitted`；manager 证明所有业务 owner
//! quiescence 并回收 transport 后，才调用无 transport 的 confirmation 进入
//! `PurgeReadbackAbsent`。Root-lost 只导入 Relay admin portable receipt，不建立
//! transport。本模块不删除本地 DB/Keychain，也不进入 LocalDeleted。

use std::fmt;
use std::time::Duration;

use agentdeck_crypto::{SignatureBytes, VerifyingKey, sha256, sign_tbs, verify_tbs};
use agentdeck_protocol::relay_v2::frame::{RetireMachine, RetirementCommitted};
use agentdeck_protocol::relay_v2::{
    Ed25519Signature, MAX_FRAME_BYTES, MachineRouteId, OpaqueRouteFrame, RELAY_PROTOCOL_VERSION,
    RelayAdminPurgeReceiptV1, RelayFrameBody, RelayServerId, RootKeyId, TrustEpoch, decode, encode,
};
use async_trait::async_trait;
use thiserror::Error;

use crate::runtime::store::{
    ConfirmMachinePurgeReadbackAbsentOutcome, MachineEnrollmentState, MachineIdentityBinding,
    MachinePurgeReadbackProof, MachineRemoteLifecycle, MachineRemoteStateRecord,
    MachineRetirementRequestMaterial, MachineRetirementTerminalMaterial, MachineTrustResetKind,
    PrepareMachineRetirementOutcome, PurgeReadbackAbsentMachineEnrollmentState,
    RecordMachineRetirementTerminalOutcome, RecordRootLostMachinePurgeOutcome,
    RelayCommittedMachineEnrollmentState, RuntimeCommitOperation, RuntimeStoreError,
    RuntimeStoreHandle,
};

use super::identity::MachineKeyMaterial;
use super::transport::{RemoteControl, RemoteTransport};

const TRUST_RESET_CONTROL_DEADLINE: Duration = Duration::from_secs(10);

/// Active/Armed identity 唯一允许产生的 MachineRoot 签名退役 owner。
///
/// 类型故意不实现 `Clone`；调用方只能读取 typed request 与冻结的 canonical bytes/hash，
/// 不能提供任意 TBS、hash 或 raw bytes 请求 MachineRoot 签名。
pub struct FrozenMachineRetirement {
    relay_server_id: RelayServerId,
    root_fingerprint: [u8; 32],
    retirement: RetireMachine,
    canonical_bytes: Vec<u8>,
    canonical_hash: [u8; 32],
}

impl FrozenMachineRetirement {
    #[must_use]
    pub const fn retirement(&self) -> &RetireMachine {
        &self.retirement
    }

    #[must_use]
    pub fn canonical_bytes(&self) -> &[u8] {
        &self.canonical_bytes
    }

    #[must_use]
    pub const fn canonical_hash(&self) -> [u8; 32] {
        self.canonical_hash
    }
}

impl fmt::Debug for FrozenMachineRetirement {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("FrozenMachineRetirement([REDACTED])")
    }
}

#[derive(Debug, Error, Clone, Copy, PartialEq, Eq)]
pub enum MachineRetirementError {
    #[error("active machine binding does not match its key material")]
    BindingMismatch,
    #[error("machine retirement Relay server ID must be nonzero")]
    InvalidRelayServerId,
    #[error("machine retirement route ID must be nonzero")]
    InvalidMachineRouteId,
    #[error("machine retirement Relay does not match the authenticated transport")]
    AuthenticatedRelayMismatch,
    #[error("machine retirement trust epoch does not match the active binding")]
    TrustEpochMismatch,
    #[error("active machine root public key is invalid")]
    InvalidRootPublicKey,
    #[error("machine retirement root signature verification failed")]
    SignatureInvalid,
}

impl MachineRetirementError {
    #[must_use]
    pub const fn code(self) -> &'static str {
        match self {
            Self::BindingMismatch => "daemon.remote.trust_reset.binding_mismatch",
            Self::InvalidRelayServerId => "daemon.remote.trust_reset.relay_id_invalid",
            Self::InvalidMachineRouteId => "daemon.remote.trust_reset.route_id_invalid",
            Self::AuthenticatedRelayMismatch => {
                "daemon.remote.trust_reset.authenticated_relay_mismatch"
            }
            Self::TrustEpochMismatch => "daemon.remote.trust_reset.epoch_mismatch",
            Self::InvalidRootPublicKey => "daemon.remote.trust_reset.root_key_invalid",
            Self::SignatureInvalid => "daemon.remote.trust_reset.signature_invalid",
        }
    }
}

#[cfg(test)]
pub(super) fn frozen_machine_retirement_for_test(
    relay_server_id: RelayServerId,
    root_fingerprint: [u8; 32],
    retirement: RetireMachine,
) -> FrozenMachineRetirement {
    let canonical_bytes = retirement.canonical_bytes();
    let canonical_hash = retirement.canonical_sha256();
    FrozenMachineRetirement {
        relay_server_id,
        root_fingerprint,
        retirement,
        canonical_bytes,
        canonical_hash,
    }
}

pub(super) fn freeze_machine_retirement(
    binding: &MachineIdentityBinding,
    material: &MachineKeyMaterial,
    relay_server_id: RelayServerId,
    machine_route: MachineRouteId,
    expected_trust_epoch: u64,
) -> Result<FrozenMachineRetirement, MachineRetirementError> {
    if relay_server_id.as_bytes() == &[0; 16] {
        return Err(MachineRetirementError::InvalidRelayServerId);
    }
    if machine_route.as_bytes() == &[0; 16] {
        return Err(MachineRetirementError::InvalidMachineRouteId);
    }
    if expected_trust_epoch == 0 || binding.trust_epoch != expected_trust_epoch {
        return Err(MachineRetirementError::TrustEpochMismatch);
    }
    if !binding_matches_material(binding, material) {
        return Err(MachineRetirementError::BindingMismatch);
    }
    let root = VerifyingKey::from_bytes(&binding.root_public_key)
        .map_err(|_| MachineRetirementError::InvalidRootPublicKey)?;
    let mut retirement = RetireMachine {
        machine_route,
        root_key_id: RootKeyId::from_bytes(binding.root_key_id),
        trust_epoch: TrustEpoch::new(binding.trust_epoch),
        signature: Ed25519Signature([0; 64]),
    };
    let tbs = retirement.to_be_signed_v1(relay_server_id, binding.root_fingerprint);
    retirement.signature = sign_tbs(material.root_signing_key(), &tbs).into();
    verify_tbs(&root, &tbs, &SignatureBytes::from(retirement.signature))
        .map_err(|_| MachineRetirementError::SignatureInvalid)?;
    let canonical_bytes = retirement.canonical_bytes();
    let canonical_hash = retirement.canonical_sha256();
    Ok(FrozenMachineRetirement {
        relay_server_id,
        root_fingerprint: binding.root_fingerprint,
        retirement,
        canonical_bytes,
        canonical_hash,
    })
}

fn binding_matches_material(
    binding: &MachineIdentityBinding,
    material: &MachineKeyMaterial,
) -> bool {
    let public = material.public_identity();
    binding.root_key_id != [0; 16]
        && binding.trust_epoch != 0
        && binding.root_public_key == *public.root().public_key()
        && binding.root_fingerprint == public.root().fingerprint()
        && binding.machine_hpke_public_key == *public.hpke().public_key()
        && binding.machine_hpke_fingerprint == public.hpke().fingerprint()
        && binding.link_sign_public_key == *public.link().public_key()
        && binding.link_sign_fingerprint == public.link().fingerprint()
        && binding.data_sign_public_key == *public.data().public_key()
        && binding.data_sign_fingerprint == public.data().fingerprint()
        && sha256(&binding.root_public_key) == binding.root_fingerprint
        && sha256(&binding.machine_hpke_public_key) == binding.machine_hpke_fingerprint
        && sha256(&binding.link_sign_public_key) == binding.link_sign_fingerprint
        && sha256(&binding.data_sign_public_key) == binding.data_sign_fingerprint
}

#[async_trait]
pub(super) trait TrustResetStore: Send + Sync {
    async fn load(&self) -> Result<Option<MachineEnrollmentState>, RuntimeStoreError>;

    async fn prepare_retirement(
        &self,
        retirement: RetireMachine,
    ) -> Result<PrepareMachineRetirementOutcome, RuntimeStoreError>;

    async fn record_terminal(
        &self,
        canonical_frame_bytes: Vec<u8>,
        canonical_frame_hash: [u8; 32],
    ) -> Result<RecordMachineRetirementTerminalOutcome, RuntimeStoreError>;

    async fn confirm_purge_absent(
        &self,
        canonical_frame_bytes: Vec<u8>,
        canonical_frame_hash: [u8; 32],
    ) -> Result<ConfirmMachinePurgeReadbackAbsentOutcome, RuntimeStoreError>;

    async fn record_root_lost(
        &self,
        receipt: RelayAdminPurgeReceiptV1,
    ) -> Result<RecordRootLostMachinePurgeOutcome, RuntimeStoreError>;
}

#[async_trait]
impl TrustResetStore for RuntimeStoreHandle {
    async fn load(&self) -> Result<Option<MachineEnrollmentState>, RuntimeStoreError> {
        self.load_machine_enrollment_state().await
    }

    async fn prepare_retirement(
        &self,
        retirement: RetireMachine,
    ) -> Result<PrepareMachineRetirementOutcome, RuntimeStoreError> {
        self.prepare_machine_retirement(retirement).await
    }

    async fn record_terminal(
        &self,
        canonical_frame_bytes: Vec<u8>,
        canonical_frame_hash: [u8; 32],
    ) -> Result<RecordMachineRetirementTerminalOutcome, RuntimeStoreError> {
        self.record_machine_retirement_terminal(canonical_frame_bytes, canonical_frame_hash)
            .await
    }

    async fn confirm_purge_absent(
        &self,
        canonical_frame_bytes: Vec<u8>,
        canonical_frame_hash: [u8; 32],
    ) -> Result<ConfirmMachinePurgeReadbackAbsentOutcome, RuntimeStoreError> {
        self.confirm_machine_purge_readback_absent(canonical_frame_bytes, canonical_frame_hash)
            .await
    }

    async fn record_root_lost(
        &self,
        receipt: RelayAdminPurgeReceiptV1,
    ) -> Result<RecordRootLostMachinePurgeOutcome, RuntimeStoreError> {
        self.record_root_lost_machine_purge(receipt).await
    }
}

pub(super) struct ObservedRetirementTerminal {
    committed: RetirementCommitted,
    canonical_frame_bytes: Vec<u8>,
    canonical_frame_hash: [u8; 32],
}

impl fmt::Debug for ObservedRetirementTerminal {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("ObservedRetirementTerminal([REDACTED])")
    }
}

#[derive(Clone)]
pub(super) struct TrustResetControlFailure {
    code: String,
}

impl TrustResetControlFailure {
    fn new(code: impl Into<String>) -> Self {
        Self { code: code.into() }
    }

    pub(super) fn code(&self) -> &str {
        &self.code
    }
}

impl fmt::Debug for TrustResetControlFailure {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("TrustResetControlFailure")
            .field("code", &self.code)
            .finish()
    }
}

#[async_trait]
pub(super) trait TrustResetControlTransport: Send {
    async fn retire(
        &mut self,
        retirement: RetireMachine,
    ) -> Result<ObservedRetirementTerminal, TrustResetControlFailure>;
}

#[async_trait]
impl TrustResetControlTransport for RemoteTransport {
    async fn retire(
        &mut self,
        retirement: RetireMachine,
    ) -> Result<ObservedRetirementTerminal, TrustResetControlFailure> {
        self.send_retirement(retirement)
            .await
            .map_err(|error| TrustResetControlFailure::new(error.code()))?;
        match self
            .next_control()
            .await
            .map_err(|error| TrustResetControlFailure::new(error.code()))?
        {
            Some(RemoteControl::RetirementTerminal(terminal)) => {
                let (committed, canonical_frame_bytes, canonical_frame_hash) =
                    terminal.into_parts();
                Ok(ObservedRetirementTerminal {
                    committed,
                    canonical_frame_bytes,
                    canonical_frame_hash,
                })
            }
            Some(RemoteControl::SafeFailure(failure)) => {
                Err(TrustResetControlFailure::new(failure.code()))
            }
            Some(RemoteControl::ServerRestarting(_)) => Err(TrustResetControlFailure::new(
                "daemon.remote.trust_reset.relay_restarting",
            )),
            None => Err(TrustResetControlFailure::new("remote.transport.closed")),
        }
    }
}

/// Root-present/root-lost 两条 durable trust-reset 路径的唯一 orchestrator。
pub struct MachineTrustResetWorkflow {
    control_deadline: Duration,
}

impl Default for MachineTrustResetWorkflow {
    fn default() -> Self {
        Self::new()
    }
}

impl MachineTrustResetWorkflow {
    #[must_use]
    pub const fn new() -> Self {
        Self {
            control_deadline: TRUST_RESET_CONTROL_DEADLINE,
        }
    }

    #[cfg(test)]
    #[must_use]
    pub(super) const fn with_control_deadline(control_deadline: Duration) -> Self {
        Self { control_deadline }
    }

    /// 仅推进 root-present retirement 到 durable `RelayCommitted`。
    ///
    /// 此窄接口故意不执行本地 purge confirmation：manager 必须先停止并 join
    /// RemoteLink、transition、publication、pairing owner，回收 transport，随后才能
    /// 调用 [`Self::confirm_root_present_after_quiescence`] 进入本地 scrub 边界。
    pub async fn run_root_present_to_relay_committed(
        &self,
        store: &RuntimeStoreHandle,
        frozen: FrozenMachineRetirement,
        transport: &mut RemoteTransport,
    ) -> Result<Box<RelayCommittedMachineEnrollmentState>, MachineTrustResetWorkflowError> {
        validate_frozen_retirement(&frozen)?;
        let prepared = store.prepare_retirement(frozen.retirement.clone()).await;
        let state = settle_prepare(store, prepared, &frozen).await?;
        self.drive_root_present_to_relay_committed(store, state, &frozen, Some(transport))
            .await
    }

    /// Root-lost 只导入 portable Relay admin receipt；本路径没有 transport 参数。
    pub async fn run_root_lost(
        &self,
        store: &RuntimeStoreHandle,
        receipt: RelayAdminPurgeReceiptV1,
    ) -> Result<Box<PurgeReadbackAbsentMachineEnrollmentState>, MachineTrustResetWorkflowError>
    {
        self.run_root_lost_with(store, receipt).await
    }

    /// 从 Store 中认证并恢复 exact retirement，但只推进到 `RelayCommitted`。
    /// `RetirePending` 仍要求同证书 transport；已经 terminal 的状态严格零网络。
    pub async fn resume_root_present_to_relay_committed(
        &self,
        store: &RuntimeStoreHandle,
        transport: Option<&mut RemoteTransport>,
    ) -> Result<Box<RelayCommittedMachineEnrollmentState>, MachineTrustResetWorkflowError> {
        let state = store
            .load_machine_enrollment_state()
            .await
            .map_err(MachineTrustResetWorkflowError::store)?
            .ok_or_else(MachineTrustResetWorkflowError::state_conflict)?;
        let frozen = frozen_from_durable_root_present(&state)?;
        self.drive_root_present_to_relay_committed(
            store,
            state,
            &frozen,
            transport.map(|value| value as &mut dyn TrustResetControlTransport),
        )
        .await
    }

    /// owner quiescence 已由 manager 证明后，消费 authenticated `RelayCommitted`
    /// terminal 并执行唯一一次本地 purge confirmation。此接口没有 transport 参数，
    /// 因而不能重新触达 Relay。
    pub async fn confirm_root_present_after_quiescence(
        &self,
        store: &RuntimeStoreHandle,
    ) -> Result<Box<PurgeReadbackAbsentMachineEnrollmentState>, MachineTrustResetWorkflowError>
    {
        let state = store
            .load_machine_enrollment_state()
            .await
            .map_err(MachineTrustResetWorkflowError::store)?
            .ok_or_else(MachineTrustResetWorkflowError::state_conflict)?;
        let frozen = frozen_from_durable_root_present(&state)?;
        self.confirm_root_present(store, state, &frozen).await
    }

    #[cfg(test)]
    async fn run_root_present_with(
        &self,
        store: &dyn TrustResetStore,
        frozen: FrozenMachineRetirement,
        transport: &mut dyn TrustResetControlTransport,
    ) -> Result<Box<PurgeReadbackAbsentMachineEnrollmentState>, MachineTrustResetWorkflowError>
    {
        validate_frozen_retirement(&frozen)?;
        let prepared = store.prepare_retirement(frozen.retirement.clone()).await;
        let state = settle_prepare(store, prepared, &frozen).await?;
        self.drive_root_present(store, state, &frozen, Some(transport))
            .await
    }

    #[cfg(test)]
    async fn drive_root_present(
        &self,
        store: &dyn TrustResetStore,
        state: MachineEnrollmentState,
        frozen: &FrozenMachineRetirement,
        transport: Option<&mut dyn TrustResetControlTransport>,
    ) -> Result<Box<PurgeReadbackAbsentMachineEnrollmentState>, MachineTrustResetWorkflowError>
    {
        let state = match state {
            MachineEnrollmentState::PurgeReadbackAbsent(purge) => {
                validate_root_present_purge(&purge, frozen, None)?;
                return Ok(purge);
            }
            state => state,
        };
        let committed = self
            .drive_root_present_to_relay_committed(store, state, frozen, transport)
            .await?;
        self.confirm_root_present(
            store,
            MachineEnrollmentState::RelayCommitted(committed),
            frozen,
        )
        .await
    }

    async fn drive_root_present_to_relay_committed(
        &self,
        store: &dyn TrustResetStore,
        mut state: MachineEnrollmentState,
        frozen: &FrozenMachineRetirement,
        mut transport: Option<&mut dyn TrustResetControlTransport>,
    ) -> Result<Box<RelayCommittedMachineEnrollmentState>, MachineTrustResetWorkflowError> {
        loop {
            state = match state {
                MachineEnrollmentState::RetirePending(pending) => {
                    validate_pending(&pending.record, &pending.retirement, frozen)?;
                    let control = transport
                        .as_deref_mut()
                        .ok_or_else(MachineTrustResetWorkflowError::transport_missing)?;
                    let observed = tokio::time::timeout(
                        self.control_deadline,
                        control.retire(pending.retirement.retirement.clone()),
                    )
                    .await
                    .map_err(|_| MachineTrustResetWorkflowError::terminal_timeout())?
                    .map_err(MachineTrustResetWorkflowError::control)?;
                    validate_observed_terminal(&observed, frozen)?;
                    let expected_bytes = observed.canonical_frame_bytes.clone();
                    let expected_hash = observed.canonical_frame_hash;
                    let recorded = store
                        .record_terminal(
                            observed.canonical_frame_bytes,
                            observed.canonical_frame_hash,
                        )
                        .await;
                    settle_terminal(store, recorded, frozen, &expected_bytes, expected_hash).await?
                }
                MachineEnrollmentState::RelayCommitted(committed) => {
                    validate_committed(
                        &committed.record,
                        &committed.retirement,
                        &committed.terminal,
                        frozen,
                    )?;
                    return Ok(committed);
                }
                MachineEnrollmentState::PurgeReadbackAbsent(_)
                | MachineEnrollmentState::EnrollmentPrepared(_)
                | MachineEnrollmentState::EnrollmentResponseValidated(_)
                | MachineEnrollmentState::Active(_)
                | MachineEnrollmentState::LocalDeleted(_) => {
                    return Err(MachineTrustResetWorkflowError::state_conflict());
                }
            };
        }
    }

    async fn confirm_root_present(
        &self,
        store: &dyn TrustResetStore,
        state: MachineEnrollmentState,
        frozen: &FrozenMachineRetirement,
    ) -> Result<Box<PurgeReadbackAbsentMachineEnrollmentState>, MachineTrustResetWorkflowError>
    {
        match state {
            MachineEnrollmentState::RelayCommitted(committed) => {
                validate_committed(
                    &committed.record,
                    &committed.retirement,
                    &committed.terminal,
                    frozen,
                )?;
                let terminal_bytes = committed.terminal.canonical_frame_bytes.clone();
                let terminal_hash = committed.terminal.canonical_frame_hash;
                let confirmed = store
                    .confirm_purge_absent(terminal_bytes.clone(), terminal_hash)
                    .await;
                let state =
                    settle_confirmation(store, confirmed, frozen, &terminal_bytes, terminal_hash)
                        .await?;
                let MachineEnrollmentState::PurgeReadbackAbsent(purge) = state else {
                    return Err(MachineTrustResetWorkflowError::state_conflict());
                };
                validate_root_present_purge(&purge, frozen, None)?;
                Ok(purge)
            }
            MachineEnrollmentState::PurgeReadbackAbsent(purge) => {
                validate_root_present_purge(&purge, frozen, None)?;
                Ok(purge)
            }
            _ => Err(MachineTrustResetWorkflowError::state_conflict()),
        }
    }

    async fn run_root_lost_with(
        &self,
        store: &dyn TrustResetStore,
        receipt: RelayAdminPurgeReceiptV1,
    ) -> Result<Box<PurgeReadbackAbsentMachineEnrollmentState>, MachineTrustResetWorkflowError>
    {
        let canonical_bytes = receipt
            .canonical_bytes()
            .map_err(|_| MachineTrustResetWorkflowError::proof_invalid())?;
        let canonical_hash = sha256(&canonical_bytes);
        let expected = receipt.clone();
        let recorded = store.record_root_lost(receipt).await;
        let state = match recorded {
            Ok(
                RecordRootLostMachinePurgeOutcome::Recorded { state }
                | RecordRootLostMachinePurgeOutcome::Replayed { state },
            ) => state,
            Err(RuntimeStoreError::CommitOutcomeUnknown {
                operation: RuntimeCommitOperation::RecordRootLostMachinePurge,
            }) => load_after_unknown(store).await?,
            Err(error) => return Err(MachineTrustResetWorkflowError::store(error)),
        };
        let MachineEnrollmentState::PurgeReadbackAbsent(purge) = state else {
            return Err(MachineTrustResetWorkflowError::state_conflict());
        };
        validate_root_lost_purge(&purge, &expected, &canonical_bytes, canonical_hash)?;
        Ok(purge)
    }
}

fn frozen_from_durable_root_present(
    state: &MachineEnrollmentState,
) -> Result<FrozenMachineRetirement, MachineTrustResetWorkflowError> {
    let (record, material) = match state {
        MachineEnrollmentState::RetirePending(value) => (&value.record, &value.retirement),
        MachineEnrollmentState::RelayCommitted(value) => (&value.record, &value.retirement),
        MachineEnrollmentState::PurgeReadbackAbsent(value) => {
            let MachinePurgeReadbackProof::RootPresent { retirement, .. } = &value.proof else {
                return Err(MachineTrustResetWorkflowError::state_conflict());
            };
            (&value.record, retirement)
        }
        _ => return Err(MachineTrustResetWorkflowError::state_conflict()),
    };
    let frozen = FrozenMachineRetirement {
        relay_server_id: RelayServerId::from_bytes(record.relay_server_id),
        root_fingerprint: record.root_fingerprint,
        retirement: material.retirement.clone(),
        canonical_bytes: material.canonical_bytes.clone(),
        canonical_hash: material.canonical_hash,
    };
    validate_frozen_retirement(&frozen)?;
    Ok(frozen)
}

impl fmt::Debug for MachineTrustResetWorkflow {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("MachineTrustResetWorkflow")
    }
}

async fn settle_prepare(
    store: &dyn TrustResetStore,
    result: Result<PrepareMachineRetirementOutcome, RuntimeStoreError>,
    frozen: &FrozenMachineRetirement,
) -> Result<MachineEnrollmentState, MachineTrustResetWorkflowError> {
    let state = match result {
        Ok(
            PrepareMachineRetirementOutcome::Prepared { state }
            | PrepareMachineRetirementOutcome::Replayed { state },
        ) => state,
        Err(RuntimeStoreError::CommitOutcomeUnknown {
            operation: RuntimeCommitOperation::PrepareMachineRetirement,
        }) => load_after_unknown(store).await?,
        Err(error) => return Err(MachineTrustResetWorkflowError::store(error)),
    };
    validate_root_present_stage(&state, frozen, RootPresentStage::RetirePending, None)?;
    Ok(state)
}

async fn settle_terminal(
    store: &dyn TrustResetStore,
    result: Result<RecordMachineRetirementTerminalOutcome, RuntimeStoreError>,
    frozen: &FrozenMachineRetirement,
    expected_terminal_bytes: &[u8],
    expected_terminal_hash: [u8; 32],
) -> Result<MachineEnrollmentState, MachineTrustResetWorkflowError> {
    let state = match result {
        Ok(
            RecordMachineRetirementTerminalOutcome::Recorded { state }
            | RecordMachineRetirementTerminalOutcome::Replayed { state },
        ) => state,
        Err(RuntimeStoreError::CommitOutcomeUnknown {
            operation: RuntimeCommitOperation::RecordMachineRetirementTerminal,
        }) => load_after_unknown(store).await?,
        Err(error) => return Err(MachineTrustResetWorkflowError::store(error)),
    };
    validate_root_present_stage(
        &state,
        frozen,
        RootPresentStage::RelayCommitted,
        Some((expected_terminal_bytes, expected_terminal_hash)),
    )?;
    Ok(state)
}

async fn settle_confirmation(
    store: &dyn TrustResetStore,
    result: Result<ConfirmMachinePurgeReadbackAbsentOutcome, RuntimeStoreError>,
    frozen: &FrozenMachineRetirement,
    expected_terminal_bytes: &[u8],
    expected_terminal_hash: [u8; 32],
) -> Result<MachineEnrollmentState, MachineTrustResetWorkflowError> {
    let state = match result {
        Ok(
            ConfirmMachinePurgeReadbackAbsentOutcome::Confirmed { state }
            | ConfirmMachinePurgeReadbackAbsentOutcome::Replayed { state },
        ) => state,
        Err(RuntimeStoreError::CommitOutcomeUnknown {
            operation: RuntimeCommitOperation::ConfirmMachinePurgeReadbackAbsent,
        }) => load_after_unknown(store).await?,
        Err(error) => return Err(MachineTrustResetWorkflowError::store(error)),
    };
    validate_root_present_stage(
        &state,
        frozen,
        RootPresentStage::PurgeReadbackAbsent,
        Some((expected_terminal_bytes, expected_terminal_hash)),
    )?;
    Ok(state)
}

async fn load_after_unknown(
    store: &dyn TrustResetStore,
) -> Result<MachineEnrollmentState, MachineTrustResetWorkflowError> {
    store
        .load()
        .await
        .map_err(MachineTrustResetWorkflowError::store)?
        .ok_or_else(MachineTrustResetWorkflowError::state_conflict)
}

#[derive(Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
enum RootPresentStage {
    RetirePending,
    RelayCommitted,
    PurgeReadbackAbsent,
}

fn validate_root_present_stage(
    state: &MachineEnrollmentState,
    frozen: &FrozenMachineRetirement,
    minimum: RootPresentStage,
    expected_terminal: Option<(&[u8], [u8; 32])>,
) -> Result<(), MachineTrustResetWorkflowError> {
    let actual = match state {
        MachineEnrollmentState::RetirePending(pending) => {
            validate_pending(&pending.record, &pending.retirement, frozen)?;
            RootPresentStage::RetirePending
        }
        MachineEnrollmentState::RelayCommitted(committed) => {
            validate_committed(
                &committed.record,
                &committed.retirement,
                &committed.terminal,
                frozen,
            )?;
            if let Some((bytes, hash)) = expected_terminal {
                require_exact_terminal(&committed.terminal, bytes, hash)?;
            }
            RootPresentStage::RelayCommitted
        }
        MachineEnrollmentState::PurgeReadbackAbsent(purge) => {
            validate_root_present_purge(purge, frozen, expected_terminal)?;
            RootPresentStage::PurgeReadbackAbsent
        }
        MachineEnrollmentState::EnrollmentPrepared(_)
        | MachineEnrollmentState::EnrollmentResponseValidated(_)
        | MachineEnrollmentState::Active(_)
        | MachineEnrollmentState::LocalDeleted(_) => {
            return Err(MachineTrustResetWorkflowError::state_conflict());
        }
    };
    if actual < minimum {
        return Err(MachineTrustResetWorkflowError::state_conflict());
    }
    Ok(())
}

fn validate_frozen_retirement(
    frozen: &FrozenMachineRetirement,
) -> Result<(), MachineTrustResetWorkflowError> {
    if frozen.relay_server_id.as_bytes() == &[0; 16]
        || frozen.root_fingerprint == [0; 32]
        || frozen.retirement.machine_route.as_bytes() == &[0; 16]
        || frozen.retirement.root_key_id.as_bytes() == &[0; 16]
        || frozen.retirement.trust_epoch.value() == 0
        || frozen.canonical_bytes.is_empty()
        || frozen.canonical_hash == [0; 32]
        || frozen.retirement.canonical_bytes() != frozen.canonical_bytes
        || frozen.retirement.canonical_sha256() != frozen.canonical_hash
        || sha256(&frozen.canonical_bytes) != frozen.canonical_hash
    {
        return Err(MachineTrustResetWorkflowError::state_conflict());
    }
    Ok(())
}

fn validate_pending(
    record: &MachineRemoteStateRecord,
    material: &MachineRetirementRequestMaterial,
    frozen: &FrozenMachineRetirement,
) -> Result<(), MachineTrustResetWorkflowError> {
    if record.lifecycle != MachineRemoteLifecycle::RetirePending
        || record.relay_server_id != *frozen.relay_server_id.as_bytes()
        || record.machine_route != *frozen.retirement.machine_route.as_bytes()
        || record.root_key_id != *frozen.retirement.root_key_id.as_bytes()
        || record.root_fingerprint != frozen.root_fingerprint
        || record.trust_epoch != frozen.retirement.trust_epoch.value()
        || material.retirement != frozen.retirement
        || material.canonical_bytes != frozen.canonical_bytes
        || material.canonical_hash != frozen.canonical_hash
        || material.retirement.canonical_bytes() != material.canonical_bytes
        || material.retirement.canonical_sha256() != material.canonical_hash
    {
        return Err(MachineTrustResetWorkflowError::state_conflict());
    }
    Ok(())
}

fn validate_committed(
    record: &MachineRemoteStateRecord,
    retirement: &MachineRetirementRequestMaterial,
    terminal: &MachineRetirementTerminalMaterial,
    frozen: &FrozenMachineRetirement,
) -> Result<(), MachineTrustResetWorkflowError> {
    let mut pending_record = record.clone();
    pending_record.lifecycle = MachineRemoteLifecycle::RetirePending;
    validate_pending(&pending_record, retirement, frozen)?;
    if record.lifecycle != MachineRemoteLifecycle::RelayCommitted {
        return Err(MachineTrustResetWorkflowError::state_conflict());
    }
    validate_terminal_material(terminal, frozen)
}

fn validate_root_present_purge(
    purge: &PurgeReadbackAbsentMachineEnrollmentState,
    frozen: &FrozenMachineRetirement,
    expected_terminal: Option<(&[u8], [u8; 32])>,
) -> Result<(), MachineTrustResetWorkflowError> {
    let MachinePurgeReadbackProof::RootPresent {
        retirement,
        terminal,
    } = &purge.proof
    else {
        return Err(MachineTrustResetWorkflowError::state_conflict());
    };
    let mut committed_record = purge.record.clone();
    committed_record.lifecycle = MachineRemoteLifecycle::RelayCommitted;
    validate_committed(&committed_record, retirement, terminal, frozen)?;
    if purge.record.lifecycle != MachineRemoteLifecycle::PurgeReadbackAbsent
        || purge.reset_kind != MachineTrustResetKind::RootPresent
    {
        return Err(MachineTrustResetWorkflowError::state_conflict());
    }
    if let Some((bytes, hash)) = expected_terminal {
        require_exact_terminal(terminal, bytes, hash)?;
    }
    Ok(())
}

fn validate_observed_terminal(
    observed: &ObservedRetirementTerminal,
    frozen: &FrozenMachineRetirement,
) -> Result<(), MachineTrustResetWorkflowError> {
    validate_terminal_parts(
        &observed.committed,
        &observed.canonical_frame_bytes,
        observed.canonical_frame_hash,
        frozen,
    )
}

fn validate_terminal_material(
    terminal: &MachineRetirementTerminalMaterial,
    frozen: &FrozenMachineRetirement,
) -> Result<(), MachineTrustResetWorkflowError> {
    validate_terminal_parts(
        &terminal.committed,
        &terminal.canonical_frame_bytes,
        terminal.canonical_frame_hash,
        frozen,
    )
}

fn validate_terminal_parts(
    committed: &RetirementCommitted,
    canonical_frame_bytes: &[u8],
    canonical_frame_hash: [u8; 32],
    frozen: &FrozenMachineRetirement,
) -> Result<(), MachineTrustResetWorkflowError> {
    if canonical_frame_bytes.is_empty()
        || canonical_frame_bytes.len() > MAX_FRAME_BYTES
        || canonical_frame_hash == [0; 32]
        || sha256(canonical_frame_bytes) != canonical_frame_hash
        || committed.machine_route != frozen.retirement.machine_route
        || committed.trust_epoch != frozen.retirement.trust_epoch
        || committed.retire_hash != frozen.canonical_hash
    {
        return Err(MachineTrustResetWorkflowError::terminal_invalid());
    }
    let frame = decode(canonical_frame_bytes)
        .map_err(|_| MachineTrustResetWorkflowError::terminal_invalid())?;
    if frame.version != RELAY_PROTOCOL_VERSION || encode(&frame) != canonical_frame_bytes {
        return Err(MachineTrustResetWorkflowError::terminal_invalid());
    }
    let OpaqueRouteFrame {
        body: RelayFrameBody::RetirementCommitted(decoded),
        ..
    } = frame
    else {
        return Err(MachineTrustResetWorkflowError::terminal_invalid());
    };
    if decoded != *committed {
        return Err(MachineTrustResetWorkflowError::terminal_invalid());
    }
    Ok(())
}

fn require_exact_terminal(
    terminal: &MachineRetirementTerminalMaterial,
    expected_bytes: &[u8],
    expected_hash: [u8; 32],
) -> Result<(), MachineTrustResetWorkflowError> {
    if terminal.canonical_frame_bytes != expected_bytes
        || terminal.canonical_frame_hash != expected_hash
    {
        return Err(MachineTrustResetWorkflowError::state_conflict());
    }
    Ok(())
}

fn validate_root_lost_purge(
    purge: &PurgeReadbackAbsentMachineEnrollmentState,
    expected_receipt: &RelayAdminPurgeReceiptV1,
    expected_bytes: &[u8],
    expected_hash: [u8; 32],
) -> Result<(), MachineTrustResetWorkflowError> {
    let MachinePurgeReadbackProof::RootLost { purge: proof } = &purge.proof else {
        return Err(MachineTrustResetWorkflowError::state_conflict());
    };
    if purge.record.lifecycle != MachineRemoteLifecycle::PurgeReadbackAbsent
        || purge.reset_kind != MachineTrustResetKind::RootLost
        || purge.record.relay_server_id != *expected_receipt.relay_server_id.as_bytes()
        || purge.record.machine_route != *expected_receipt.machine_route.as_bytes()
        || purge.record.root_key_id != *expected_receipt.root_key_id.as_bytes()
        || purge.record.root_fingerprint != expected_receipt.root_fingerprint
        || purge.record.trust_epoch != expected_receipt.trust_epoch.value()
        || purge.record.enrollment_receipt_hash != Some(expected_receipt.enrollment_receipt_hash)
        || proof.receipt != *expected_receipt
        || proof.canonical_bytes != expected_bytes
        || proof.canonical_hash != expected_hash
        || proof.receipt.canonical_bytes().ok().as_deref() != Some(expected_bytes)
        || proof.receipt.canonical_sha256().ok() != Some(expected_hash)
    {
        return Err(MachineTrustResetWorkflowError::state_conflict());
    }
    Ok(())
}

enum TrustResetWorkflowErrorKind {
    Store(RuntimeStoreError),
    Control(TrustResetControlFailure),
    StateConflict,
    TerminalInvalid,
    TerminalTimeout,
    ProofInvalid,
    TransportMissing,
}

pub struct MachineTrustResetWorkflowError {
    kind: TrustResetWorkflowErrorKind,
}

impl MachineTrustResetWorkflowError {
    fn store(error: RuntimeStoreError) -> Self {
        Self {
            kind: TrustResetWorkflowErrorKind::Store(error),
        }
    }

    fn control(error: TrustResetControlFailure) -> Self {
        Self {
            kind: TrustResetWorkflowErrorKind::Control(error),
        }
    }

    fn state_conflict() -> Self {
        Self {
            kind: TrustResetWorkflowErrorKind::StateConflict,
        }
    }

    fn terminal_invalid() -> Self {
        Self {
            kind: TrustResetWorkflowErrorKind::TerminalInvalid,
        }
    }

    fn terminal_timeout() -> Self {
        Self {
            kind: TrustResetWorkflowErrorKind::TerminalTimeout,
        }
    }

    fn proof_invalid() -> Self {
        Self {
            kind: TrustResetWorkflowErrorKind::ProofInvalid,
        }
    }

    fn transport_missing() -> Self {
        Self {
            kind: TrustResetWorkflowErrorKind::TransportMissing,
        }
    }

    #[must_use]
    pub fn code(&self) -> &str {
        match &self.kind {
            TrustResetWorkflowErrorKind::Store(error) => error.code(),
            TrustResetWorkflowErrorKind::Control(error) => error.code(),
            TrustResetWorkflowErrorKind::StateConflict => {
                "daemon.remote.trust_reset.state_conflict"
            }
            TrustResetWorkflowErrorKind::TerminalInvalid => {
                "daemon.remote.trust_reset.terminal_invalid"
            }
            TrustResetWorkflowErrorKind::TerminalTimeout => {
                "daemon.remote.trust_reset.terminal_timeout"
            }
            TrustResetWorkflowErrorKind::ProofInvalid => "daemon.remote.trust_reset.proof_invalid",
            TrustResetWorkflowErrorKind::TransportMissing => {
                "daemon.remote.trust_reset.transport_missing"
            }
        }
    }
}

impl fmt::Debug for MachineTrustResetWorkflowError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("MachineTrustResetWorkflowError")
            .field("code", &self.code())
            .finish()
    }
}

impl fmt::Display for MachineTrustResetWorkflowError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(self.code())
    }
}

impl std::error::Error for MachineTrustResetWorkflowError {}

#[cfg(test)]
#[path = "trust_reset_tests.rs"]
mod tests;
