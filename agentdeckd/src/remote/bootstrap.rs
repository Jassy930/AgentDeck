//! Machine identity 的本地 bootstrap/reconciliation。
//!
//! 冻结写入顺序为：四组长期 key exact load/create → authenticated DB Preparing →
//! key-directory guard exact install → authenticated DB Active。已有 Preparing/Active
//! 状态只允许 existing-only key load；任何缺失或分叉只阻断 remote，不修复或覆盖
//! 已认证 artifact。Runtime DB 的认证、worker、SQLite 或 cipher 错误仍向上返回，
//! 由 daemon 作为全局 Runtime fatal 处理。

use std::fmt;

use agentdeck_crypto::{
    CryptoError, DeviceKeyRecoverySealAuthority, HpkePublicKey, PairResponseSealAuthority,
    SignatureBytes, ValidatedRelayReceiptVerifyKey, VerifyingKey, seal_device_key_recovery_reply,
    seal_pair_pending, seal_pair_response, seal_pair_terminal, sha256,
    sign_authentication_transcript, sign_device_authorization,
    sign_key_directory as crypto_sign_key_directory, sign_key_update as crypto_sign_key_update,
    sign_sealed as crypto_sign_sealed, sign_tbs, verify_tbs,
};
use agentdeck_protocol::e2ee::{
    DeviceAuthorizationV1, DeviceKeyRecoveryInfoV1, DeviceKeyRecoveryReplyV1,
    KeyDirectorySignatureContextV1, KeyDirectoryV1, KeyUpdateInfoV1, KeyUpdateSetV1, KeyUpdateV1,
    MachineDataSignerBindingV1, OuterContextV1, PairRequestInfoV1, PairResponseInfoV1,
    PairResponsePlaintextV1, PairResponseV1, PairTerminalV1, PairingControlEnvelopeV1,
    SignedSealedBlobV1, UnsignedSealedBlobV1,
};
use agentdeck_protocol::relay_v2::{
    AuthenticationTranscriptV1, CertRole, DeviceRevocation, Ed25519Signature, LinkGeneration,
    MachineRouteId, PublicKeyBytes, RELAY_RECEIPT_FORMAT_VERSION, RELAY_RECEIPT_KEY_GENERATION_MVP,
    RelayGrant, RelayReceiptKeyId, RelayReceiptVerifyKeyV1, RelayServerId, RootKeyId,
    SignedCertificate, TrustEpoch,
};

use crate::config::DaemonConfig;
use crate::local::listener::RemoteStartPermit;
use crate::runtime::store::{
    ActivateMachineIdentityOutcome, MachineEnrollmentState, MachineIdentityBinding,
    MachineIdentityLifecycle, MachineIdentityStateRecord, PrepareMachineIdentityOutcome,
    RuntimeCommitOperation, RuntimeStoreError, RuntimeStoreHandle,
};
use crate::security::KeyStore;

use super::certificate::{
    MachineCertificate, MachineCertificateError, MachineCertificates, issue_machine_certificates,
    verify_active_machine_certificate,
};
use super::identity::{
    KeyDirectoryGuard, MachineIdentityError, MachineKeyMaterial, advance_key_directory_guard,
    install_key_directory_guard, load_key_directory_guard, load_machine_key_material,
    load_or_create_preparing_machine_key_material,
};
use super::trust_reset::{
    FrozenMachineRetirement, MachineRetirementError, freeze_machine_retirement,
};

const FRESH_TRUST_EPOCH: u64 = 1;
const FRESH_LINK_GENERATION: u64 = 1;
const FRESH_DATA_GENERATION: u64 = 1;
const FRESH_KEY_DIRECTORY_REVISION: u64 = 0;
const ROOT_KEY_ID_ATTEMPTS: usize = 8;
const REENROLL_ROOT_KEY_ID_DOMAIN: &[u8] = b"AgentDeck/ReenrollRootKeyIdV1\0";

#[derive(Clone, PartialEq, Eq)]
pub(super) struct MachinePairingAnchor {
    pub(super) relay_server_id: RelayServerId,
    pub(super) machine_route: MachineRouteId,
    pub(super) root_public_key: PublicKeyBytes,
    pub(super) root_fingerprint: [u8; 32],
    pub(super) root_key_id: RootKeyId,
    pub(super) trust_epoch: TrustEpoch,
    pub(super) machine_hpke_public_key: PublicKeyBytes,
    pub(super) data_generation: LinkGeneration,
    pub(super) data_certificate: SignedCertificate,
}

impl fmt::Debug for MachinePairingAnchor {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("MachinePairingAnchor([REDACTED])")
    }
}

#[cfg(test)]
pub(super) fn machine_pairing_anchor_for_test(
    relay_server_id: RelayServerId,
    machine_route: MachineRouteId,
    binding: &MachineIdentityBinding,
    data_certificate: SignedCertificate,
) -> MachinePairingAnchor {
    assert_eq!(
        data_certificate.subject_pubkey.0, binding.data_sign_public_key,
        "test MachineData certificate must match the authenticated Store binding"
    );
    MachinePairingAnchor {
        relay_server_id,
        machine_route,
        root_public_key: PublicKeyBytes(binding.root_public_key),
        root_fingerprint: binding.root_fingerprint,
        root_key_id: RootKeyId::from_bytes(binding.root_key_id),
        trust_epoch: TrustEpoch::new(binding.trust_epoch),
        machine_hpke_public_key: PublicKeyBytes(binding.machine_hpke_public_key),
        data_generation: LinkGeneration::new(binding.data_generation),
        data_certificate,
    }
}

impl MachinePairingAnchor {
    /// pairing lane 在发往 Relay 前以同一 frozen public anchor 复核完整 grant。
    /// 该入口不持有私钥，也不能签发或改写任何对象。
    pub(super) fn verify_relay_grant(&self, grant: &RelayGrant) -> Result<(), MachinePairingError> {
        validate_pairing_grant_axes(self, grant)?;
        if grant.signature.0 == [0; 64] {
            return Err(MachinePairingError::ContextMismatch);
        }
        verify_tbs(
            &self.root_verifying_key()?,
            &grant.to_be_signed_v1(self.relay_server_id, self.root_fingerprint),
            &SignatureBytes::from(grant.signature),
        )?;
        Ok(())
    }

    /// pairing lane 在发往 Relay 前以同一 frozen public anchor 复核完整 revocation。
    /// exact retry 可以复用同一签名，但 unsigned/wrong-root/wrong-trust 输入一律拒绝。
    pub(super) fn verify_device_revocation(
        &self,
        revocation: &DeviceRevocation,
    ) -> Result<(), MachinePairingError> {
        validate_pairing_revocation_axes(self, revocation)?;
        if revocation.signature.0 == [0; 64] {
            return Err(MachinePairingError::ContextMismatch);
        }
        verify_tbs(
            &self.root_verifying_key()?,
            &revocation.to_be_signed_v1(self.relay_server_id, self.root_fingerprint),
            &SignatureBytes::from(revocation.signature),
        )?;
        Ok(())
    }

    fn root_verifying_key(&self) -> Result<VerifyingKey, MachinePairingError> {
        if sha256(&self.root_public_key.0) != self.root_fingerprint {
            return Err(MachinePairingError::ContextMismatch);
        }
        Ok(VerifyingKey::from_bytes(&self.root_public_key.0)?)
    }
}

#[derive(Debug)]
pub(super) enum MachinePairingError {
    Certificate(MachineCertificateError),
    Crypto,
    ContextMismatch,
}

impl MachinePairingError {
    pub(super) fn code(&self) -> &'static str {
        match self {
            Self::Certificate(error) => error.code(),
            Self::Crypto => "remote.transport.pairing_crypto_failed",
            Self::ContextMismatch => "remote.transport.pairing_authority_mismatch",
        }
    }
}

impl From<MachineCertificateError> for MachinePairingError {
    fn from(error: MachineCertificateError) -> Self {
        Self::Certificate(error)
    }
}

impl From<CryptoError> for MachinePairingError {
    fn from(_error: CryptoError) -> Self {
        Self::Crypto
    }
}

/// P4.1 bootstrap 的三态结果。`Blocked` 只关闭 remote；本地 Runtime 继续启动。
pub enum RemoteBootstrapOutcome {
    Disabled,
    Active(Box<ActiveMachineIdentity>),
    Blocked(RemoteBootstrapBlock),
}

impl fmt::Debug for RemoteBootstrapOutcome {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Disabled => formatter.write_str("RemoteBootstrapOutcome::Disabled"),
            Self::Active(_) => formatter.write_str("RemoteBootstrapOutcome::Active([REDACTED])"),
            Self::Blocked(block) => formatter
                .debug_tuple("RemoteBootstrapOutcome::Blocked")
                .field(block)
                .finish(),
        }
    }
}

/// 不携带 Keychain 原始错误或 secret 的 remote-only block 证据。
#[derive(Clone, Copy, Eq, PartialEq)]
pub struct RemoteBootstrapBlock {
    code: &'static str,
}

impl RemoteBootstrapBlock {
    const DATABASE_ROLLBACK: Self = Self {
        code: "daemon.remote.identity.database_rollback",
    };
    const STATE_FORK: Self = Self {
        code: "daemon.remote.identity.state_fork",
    };
    const GUARD_MISSING: Self = Self {
        code: "daemon.remote.identity.guard_missing",
    };
    const ENTROPY_UNAVAILABLE: Self = Self {
        code: "daemon.remote.identity.entropy_unavailable",
    };
    const LOCAL_DELETED: Self = Self {
        code: "daemon.remote.enrollment.local_deleted",
    };

    fn identity(error: &MachineIdentityError) -> Self {
        Self { code: error.code() }
    }

    #[must_use]
    pub const fn code(self) -> &'static str {
        self.code
    }
}

impl fmt::Debug for RemoteBootstrapBlock {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("RemoteBootstrapBlock")
            .field("code", &self.code)
            .finish()
    }
}

/// Active identity 对长期私钥的唯一 owner。类型不实现 `Clone`。
pub struct ActiveMachineIdentity {
    state: MachineIdentityStateRecord,
    material: MachineKeyMaterial,
}

#[derive(Clone, Debug, Eq, PartialEq)]
struct KeyDirectoryRotationRecoveryEvidence {
    identity: MachineIdentityStateRecord,
    guard: KeyDirectoryGuard,
    remote_machine_route: MachineRouteId,
    remote_binding: MachineIdentityBinding,
    remote_root_key_id: [u8; 16],
    remote_root_fingerprint: [u8; 32],
    remote_trust_epoch: u64,
    global_revision: Option<u64>,
    transition: Option<crate::runtime::store::key_transition::KeyTransitionRecord>,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum KeyDirectoryRotationRecoveryAction {
    AdvanceGuardThenStore {
        operation_id: [u8; 16],
        from_revision: u64,
        to_revision: u64,
    },
    CompleteStore {
        operation_id: [u8; 16],
        from_revision: u64,
        to_revision: u64,
    },
}

fn plan_key_directory_rotation_recovery(
    evidence: &KeyDirectoryRotationRecoveryEvidence,
) -> Result<KeyDirectoryRotationRecoveryAction, RemoteBootstrapBlock> {
    use crate::runtime::store::key_transition::{
        KeyTransitionOperation, KeyTransitionPhase, KeyTransitionTarget,
    };

    let transition = evidence
        .transition
        .as_ref()
        .ok_or(RemoteBootstrapBlock::STATE_FORK)?;
    let global_revision = evidence
        .global_revision
        .ok_or(RemoteBootstrapBlock::STATE_FORK)?;
    let binding = &evidence.identity.binding;
    let operation_matches_target = match (transition.operation, transition.target) {
        (
            KeyTransitionOperation::Add | KeyTransitionOperation::Renew,
            KeyTransitionTarget::Device(target),
        ) => transition.recipients.contains(&target),
        (KeyTransitionOperation::Revoke, KeyTransitionTarget::Device(target)) => {
            !transition.recipients.contains(&target)
        }
        (
            KeyTransitionOperation::ActivateConversation,
            KeyTransitionTarget::Conversation {
                conversation_id,
                stream_route,
            },
        ) => conversation_id != [0; 16] && stream_route != [0; 16],
        (KeyTransitionOperation::CounterRecovery, KeyTransitionTarget::Device(target)) => {
            transition.recipients.contains(&target)
        }
        (
            KeyTransitionOperation::CounterRecovery,
            KeyTransitionTarget::Conversation {
                conversation_id,
                stream_route,
            },
        ) => conversation_id != [0; 16] && stream_route != [0; 16],
        _ => false,
    };
    let recipients_are_canonical = transition
        .recipients
        .iter()
        .enumerate()
        .all(|(index, item)| {
            item.device_route != [0; 16]
                && item.grant_serial != 0
                && transition.recipients[..index]
                    .last()
                    .is_none_or(|previous| previous < item)
        });
    if evidence.identity.lifecycle != MachineIdentityLifecycle::Active
        || evidence.remote_machine_route.as_bytes() == &[0; 16]
        || evidence.remote_binding != *binding
        || evidence.remote_root_key_id != binding.root_key_id
        || evidence.remote_root_fingerprint != binding.root_fingerprint
        || evidence.remote_trust_epoch != binding.trust_epoch
        || evidence.guard.database_id() != evidence.identity.database_id
        || evidence.guard.root_fingerprint() != binding.root_fingerprint
        || transition.operation_id == [0; 16]
        || transition.phase != KeyTransitionPhase::DrainingOld
        || transition.terminal.is_some()
        || transition.update_count != 0
        || !transition.cuts.is_empty()
        || !operation_matches_target
        || !recipients_are_canonical
        || transition.to_revision
            != transition
                .from_revision
                .checked_add(1)
                .ok_or(RemoteBootstrapBlock::STATE_FORK)?
        || transition.to_revision == 0
        || global_revision != transition.to_revision
        || binding.key_directory_revision != transition.from_revision
    {
        return Err(RemoteBootstrapBlock::STATE_FORK);
    }

    let action = match evidence.guard.key_directory_revision() {
        revision if revision == transition.from_revision => {
            KeyDirectoryRotationRecoveryAction::AdvanceGuardThenStore {
                operation_id: transition.operation_id,
                from_revision: transition.from_revision,
                to_revision: transition.to_revision,
            }
        }
        revision if revision == transition.to_revision => {
            KeyDirectoryRotationRecoveryAction::CompleteStore {
                operation_id: transition.operation_id,
                from_revision: transition.from_revision,
                to_revision: transition.to_revision,
            }
        }
        _ => return Err(RemoteBootstrapBlock::STATE_FORK),
    };
    Ok(action)
}

#[derive(Debug)]
enum KeyDirectoryRotationFinalizeError {
    OutcomeUnknown,
    Store(RuntimeStoreError),
}

#[async_trait::async_trait]
trait KeyDirectoryRotationRecoveryStore: Sync {
    async fn load_rotation_recovery_evidence(
        &self,
        guard: KeyDirectoryGuard,
    ) -> Result<KeyDirectoryRotationRecoveryEvidence, RuntimeStoreError>;

    async fn finalize_key_directory_rotation(
        &self,
        operation_id: [u8; 16],
    ) -> Result<
        crate::runtime::store::key_transition::KeyTransitionRecord,
        KeyDirectoryRotationFinalizeError,
    >;
}

#[async_trait::async_trait]
impl KeyDirectoryRotationRecoveryStore for RuntimeStoreHandle {
    async fn load_rotation_recovery_evidence(
        &self,
        guard: KeyDirectoryGuard,
    ) -> Result<KeyDirectoryRotationRecoveryEvidence, RuntimeStoreError> {
        let identity = self
            .load_machine_identity_state()
            .await?
            .ok_or(RuntimeStoreError::MachineIdentityMissing)?;
        let remote = self
            .load_machine_enrollment_state()
            .await?
            .ok_or(RuntimeStoreError::MachineRemoteConflict)?;
        let MachineEnrollmentState::Active(remote) = remote else {
            return Err(RuntimeStoreError::MachineRemoteConflict);
        };
        let global_revision = self
            .load_global_key_state()
            .await?
            .map(|global| global.revision().value());
        let transition = self
            .load_active_key_transition()
            .await?
            .map(|recovery| recovery.transition);
        Ok(KeyDirectoryRotationRecoveryEvidence {
            identity,
            guard,
            remote_machine_route: MachineRouteId::from_bytes(remote.record.machine_route),
            remote_binding: remote.binding,
            remote_root_key_id: remote.record.root_key_id,
            remote_root_fingerprint: remote.record.root_fingerprint,
            remote_trust_epoch: remote.record.trust_epoch,
            global_revision,
            transition,
        })
    }

    async fn finalize_key_directory_rotation(
        &self,
        operation_id: [u8; 16],
    ) -> Result<
        crate::runtime::store::key_transition::KeyTransitionRecord,
        KeyDirectoryRotationFinalizeError,
    > {
        match RuntimeStoreHandle::finalize_key_directory_rotation(self, operation_id).await {
            Ok(record) => Ok(record),
            Err(RuntimeStoreError::CommitOutcomeUnknown {
                operation: RuntimeCommitOperation::FinalizeKeyDirectoryRotation,
            }) => Err(KeyDirectoryRotationFinalizeError::OutcomeUnknown),
            Err(error) => Err(KeyDirectoryRotationFinalizeError::Store(error)),
        }
    }
}

#[derive(Debug, Eq, PartialEq)]
pub(crate) enum KeyDirectoryRotationRecoveryOutcome {
    Recovered(Box<MachineIdentityStateRecord>),
    Blocked(RemoteBootstrapBlock),
}

/// production startup 与运行期 transition owner 共用的唯一 guard/Store recovery 编排。
///
/// 调用方只提供既有 Store/KeyStore owner；本 seam 固定执行 authenticated evidence
/// 规划、必要的 guard exact CAS、单事务 Store finalize 与 exact reload，不允许下游复制
/// 或跳过其中任一步。
pub(crate) async fn recover_key_directory_rotation(
    store: &RuntimeStoreHandle,
    key_store: &dyn KeyStore,
) -> Result<KeyDirectoryRotationRecoveryOutcome, RuntimeStoreError> {
    drive_key_directory_rotation_recovery(store, key_store).await
}

async fn drive_key_directory_rotation_recovery<S: KeyDirectoryRotationRecoveryStore>(
    store: &S,
    key_store: &dyn KeyStore,
) -> Result<KeyDirectoryRotationRecoveryOutcome, RuntimeStoreError> {
    let guard = match load_key_directory_guard(key_store) {
        Ok(Some(guard)) => guard,
        Ok(None) => {
            return Ok(KeyDirectoryRotationRecoveryOutcome::Blocked(
                RemoteBootstrapBlock::GUARD_MISSING,
            ));
        }
        Err(error) => {
            return Ok(KeyDirectoryRotationRecoveryOutcome::Blocked(
                RemoteBootstrapBlock::identity(&error),
            ));
        }
    };
    let evidence = match store.load_rotation_recovery_evidence(guard).await {
        Ok(evidence) => evidence,
        Err(error) if rotation_store_error_is_state_fork(&error) => {
            return Ok(KeyDirectoryRotationRecoveryOutcome::Blocked(
                RemoteBootstrapBlock::STATE_FORK,
            ));
        }
        Err(error) => return Err(error),
    };
    let action = match plan_key_directory_rotation_recovery(&evidence) {
        Ok(action) => action,
        Err(block) => return Ok(KeyDirectoryRotationRecoveryOutcome::Blocked(block)),
    };
    let (operation_id, from_revision, to_revision, advance_guard) = match action {
        KeyDirectoryRotationRecoveryAction::AdvanceGuardThenStore {
            operation_id,
            from_revision,
            to_revision,
        } => (operation_id, from_revision, to_revision, true),
        KeyDirectoryRotationRecoveryAction::CompleteStore {
            operation_id,
            from_revision,
            to_revision,
        } => (operation_id, from_revision, to_revision, false),
    };
    let expected_guard = KeyDirectoryGuard::new(
        evidence.identity.database_id,
        evidence.identity.binding.root_fingerprint,
        from_revision,
    );
    let next_guard = KeyDirectoryGuard::new(
        evidence.identity.database_id,
        evidence.identity.binding.root_fingerprint,
        to_revision,
    );
    if advance_guard
        && let Err(error) = advance_key_directory_guard(key_store, expected_guard, next_guard)
    {
        return Ok(KeyDirectoryRotationRecoveryOutcome::Blocked(
            RemoteBootstrapBlock::identity(&error),
        ));
    }

    match store.finalize_key_directory_rotation(operation_id).await {
        Ok(_) | Err(KeyDirectoryRotationFinalizeError::OutcomeUnknown) => {}
        Err(KeyDirectoryRotationFinalizeError::Store(error))
            if rotation_store_error_is_state_fork(&error) =>
        {
            return Ok(KeyDirectoryRotationRecoveryOutcome::Blocked(
                RemoteBootstrapBlock::STATE_FORK,
            ));
        }
        Err(KeyDirectoryRotationFinalizeError::Store(error)) => return Err(error),
    }

    let persisted_guard = match load_key_directory_guard(key_store) {
        Ok(Some(guard)) => guard,
        Ok(None) => {
            return Ok(KeyDirectoryRotationRecoveryOutcome::Blocked(
                RemoteBootstrapBlock::GUARD_MISSING,
            ));
        }
        Err(error) => {
            return Ok(KeyDirectoryRotationRecoveryOutcome::Blocked(
                RemoteBootstrapBlock::identity(&error),
            ));
        }
    };
    let reloaded = match store.load_rotation_recovery_evidence(persisted_guard).await {
        Ok(evidence) => evidence,
        Err(error) if rotation_store_error_is_state_fork(&error) => {
            return Ok(KeyDirectoryRotationRecoveryOutcome::Blocked(
                RemoteBootstrapBlock::STATE_FORK,
            ));
        }
        Err(error) => return Err(error),
    };
    if !completed_rotation_matches(
        &reloaded,
        operation_id,
        from_revision,
        to_revision,
        next_guard,
    ) {
        return Ok(KeyDirectoryRotationRecoveryOutcome::Blocked(
            RemoteBootstrapBlock::STATE_FORK,
        ));
    }
    Ok(KeyDirectoryRotationRecoveryOutcome::Recovered(Box::new(
        reloaded.identity,
    )))
}

fn completed_rotation_matches(
    evidence: &KeyDirectoryRotationRecoveryEvidence,
    operation_id: [u8; 16],
    from_revision: u64,
    to_revision: u64,
    expected_guard: KeyDirectoryGuard,
) -> bool {
    use crate::runtime::store::key_transition::KeyTransitionPhase;

    let Some(transition) = evidence.transition.as_ref() else {
        return false;
    };
    evidence.identity.lifecycle == MachineIdentityLifecycle::Active
        && evidence.identity.binding.key_directory_revision == to_revision
        && evidence.guard == expected_guard
        && evidence.remote_machine_route.as_bytes() != &[0; 16]
        && evidence.remote_binding == evidence.identity.binding
        && evidence.remote_root_key_id == evidence.identity.binding.root_key_id
        && evidence.remote_root_fingerprint == evidence.identity.binding.root_fingerprint
        && evidence.remote_trust_epoch == evidence.identity.binding.trust_epoch
        && evidence.global_revision == Some(to_revision)
        && transition.operation_id == operation_id
        && transition.from_revision == from_revision
        && transition.to_revision == to_revision
        && transition.phase == KeyTransitionPhase::RotatedPreparingUpdates
        && transition.terminal.is_none()
        && transition.update_count == 0
        && transition.cuts.is_empty()
}

const fn rotation_store_error_is_state_fork(error: &RuntimeStoreError) -> bool {
    matches!(
        error,
        RuntimeStoreError::MachineIdentityMissing
            | RuntimeStoreError::MachineIdentityConflict
            | RuntimeStoreError::MachineRemoteConflict
            | RuntimeStoreError::PublicationMismatch
            | RuntimeStoreError::InvalidStateTransition
    )
}

/// `LocalDeleted` 显式 re-enroll 的临时 key owner。
///
/// Keychain material/guard 可以在 Store COMMIT 前 durable 存在，但本类型不会冒充
/// active identity；只有 Store 原子替换 tombstone 并读回 exact binding 后才能提升。
pub struct PendingReenrollmentIdentity {
    state: MachineIdentityStateRecord,
    material: MachineKeyMaterial,
}

impl PendingReenrollmentIdentity {
    #[must_use]
    pub const fn binding(&self) -> &MachineIdentityBinding {
        &self.state.binding
    }

    pub(super) fn certificates(
        &self,
        relay_server_id: RelayServerId,
        machine_route: MachineRouteId,
    ) -> Result<MachineCertificates, MachineCertificateError> {
        issue_machine_certificates(
            &self.state.binding,
            &self.material,
            relay_server_id,
            machine_route,
        )
    }

    /// Store `LocalDeleted → EnrollmentPrepared` 已原子插入相同 identity 后，
    /// 才把 pending owner 提升为 transport 可消费的 active owner。
    pub async fn activate_after_enrollment(
        self,
        store: &RuntimeStoreHandle,
    ) -> Result<Box<ActiveMachineIdentity>, PrepareReenrollmentIdentityError> {
        let persisted = store
            .load_machine_identity_state()
            .await
            .map_err(PrepareReenrollmentIdentityError::store)?
            .ok_or_else(PrepareReenrollmentIdentityError::state_conflict)?;
        if persisted.lifecycle != MachineIdentityLifecycle::Active
            || persisted.database_id != self.state.database_id
            || persisted.binding != self.state.binding
        {
            return Err(PrepareReenrollmentIdentityError::state_conflict());
        }
        Ok(Box::new(ActiveMachineIdentity {
            state: persisted,
            material: self.material,
        }))
    }
}

impl fmt::Debug for PendingReenrollmentIdentity {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("PendingReenrollmentIdentity([REDACTED])")
    }
}

enum PrepareReenrollmentIdentityErrorKind {
    Store(RuntimeStoreError),
    Identity(MachineIdentityError),
    StateConflict,
}

pub struct PrepareReenrollmentIdentityError {
    kind: PrepareReenrollmentIdentityErrorKind,
}

impl PrepareReenrollmentIdentityError {
    fn store(error: RuntimeStoreError) -> Self {
        Self {
            kind: PrepareReenrollmentIdentityErrorKind::Store(error),
        }
    }

    fn identity(error: MachineIdentityError) -> Self {
        Self {
            kind: PrepareReenrollmentIdentityErrorKind::Identity(error),
        }
    }

    fn state_conflict() -> Self {
        Self {
            kind: PrepareReenrollmentIdentityErrorKind::StateConflict,
        }
    }

    #[must_use]
    pub fn code(&self) -> &str {
        match &self.kind {
            PrepareReenrollmentIdentityErrorKind::Store(error) => error.code(),
            PrepareReenrollmentIdentityErrorKind::Identity(error) => error.code(),
            PrepareReenrollmentIdentityErrorKind::StateConflict => {
                "daemon.remote.enrollment.state_conflict"
            }
        }
    }
}

impl fmt::Debug for PrepareReenrollmentIdentityError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("PrepareReenrollmentIdentityError")
            .field("code", &self.code())
            .finish()
    }
}

impl fmt::Display for PrepareReenrollmentIdentityError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(self.code())
    }
}

impl std::error::Error for PrepareReenrollmentIdentityError {}

impl ActiveMachineIdentity {
    #[must_use]
    pub const fn binding(&self) -> &MachineIdentityBinding {
        &self.state.binding
    }

    /// 只签发与 active binding 完全一致的 MachineLink/MachineData 证书对。
    /// Ed25519 与 canonical TBS 都是确定性的，因此相同 Relay/route 重试字节一致。
    pub fn certificates(
        &self,
        relay_server_id: RelayServerId,
        machine_route: MachineRouteId,
    ) -> Result<MachineCertificates, MachineCertificateError> {
        issue_machine_certificates(
            &self.state.binding,
            &self.material,
            relay_server_id,
            machine_route,
        )
    }

    /// 只为调用方给出的 Relay/route 与当前 active trust epoch 冻结 typed RetireMachine。
    /// 不接受任意 TBS、hash、bytes 或签名输入。
    pub fn freeze_retirement(
        &self,
        relay_server_id: RelayServerId,
        machine_route: MachineRouteId,
        expected_trust_epoch: u64,
    ) -> Result<FrozenMachineRetirement, MachineRetirementError> {
        freeze_machine_retirement(
            &self.state.binding,
            &self.material,
            relay_server_id,
            machine_route,
            expected_trust_epoch,
        )
    }

    /// 以 active MachineRoot 公钥和冻结 binding 验证证书的全部语义/TBS 上下文。
    pub fn verify_certificate(
        &self,
        relay_server_id: RelayServerId,
        machine_route: MachineRouteId,
        expected_role: CertRole,
        certificate: &MachineCertificate,
    ) -> Result<(), MachineCertificateError> {
        verify_active_machine_certificate(
            &self.state.binding,
            &self.material,
            relay_server_id,
            machine_route,
            expected_role,
            certificate,
        )
    }

    /// 把 active key owner 与 listener 产生的一次性 remote-start capability 绑在一起。
    #[must_use]
    pub fn arm(self: Box<Self>, permit: RemoteStartPermit) -> ArmedRemoteIdentity {
        ArmedRemoteIdentity {
            identity: self,
            permit,
        }
    }
}

impl fmt::Debug for ActiveMachineIdentity {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("ActiveMachineIdentity([REDACTED])")
    }
}

/// P4.2 RemoteTransport composition 将消费的 owner；P4.1 只证明 permit 生命周期内
/// key material 持续存活，并在 local serve 返回后显式销毁两者。
pub struct ArmedRemoteIdentity {
    identity: Box<ActiveMachineIdentity>,
    permit: RemoteStartPermit,
}

impl ArmedRemoteIdentity {
    /// RemoteStartPermit owner 存活期间委托同一个窄 typed retirement signer。
    pub fn freeze_retirement(
        &self,
        relay_server_id: RelayServerId,
        machine_route: MachineRouteId,
        expected_trust_epoch: u64,
    ) -> Result<FrozenMachineRetirement, MachineRetirementError> {
        self.identity
            .freeze_retirement(relay_server_id, machine_route, expected_trust_epoch)
    }

    /// 只允许 RemoteTransport 按值拆出旧 key owner 与同一个 start permit。
    /// 两者仍由 transport 同时独占；reclaim 只能在 session join 且 owner drop 后返回 permit。
    pub(super) fn into_transport_parts(self) -> (MachineLinkIdentityOwner, RemoteStartPermit) {
        let Self { identity, permit } = self;
        (MachineLinkIdentityOwner { identity }, permit)
    }
}

/// Relay authenticator 独占的旧 MachineLink key owner；不携带 RemoteStartPermit，
/// 也不实现 Clone，确保 transport 可以先销毁 signer 再单独返还 permit。
pub(super) struct MachineLinkIdentityOwner {
    identity: Box<ActiveMachineIdentity>,
}

impl MachineLinkIdentityOwner {
    pub(super) fn freeze_retirement(
        &self,
        relay_server_id: RelayServerId,
        machine_route: MachineRouteId,
        expected_trust_epoch: u64,
    ) -> Result<FrozenMachineRetirement, MachineRetirementError> {
        self.identity
            .freeze_retirement(relay_server_id, machine_route, expected_trust_epoch)
    }

    pub(super) fn verify_link_certificate(
        &self,
        relay_server_id: RelayServerId,
        machine_route: MachineRouteId,
        certificate: &MachineCertificate,
    ) -> Result<(), MachineCertificateError> {
        self.identity.verify_certificate(
            relay_server_id,
            machine_route,
            CertRole::Link,
            certificate,
        )
    }

    pub(super) fn sign_link_authentication(
        &self,
        transcript: &AuthenticationTranscriptV1,
    ) -> Ed25519Signature {
        sign_authentication_transcript(self.identity.material.link_signing_key(), transcript).into()
    }

    pub(super) fn pairing_anchor(
        &self,
        relay_server_id: RelayServerId,
        machine_route: MachineRouteId,
        data_certificate: &SignedCertificate,
    ) -> Result<MachinePairingAnchor, MachinePairingError> {
        self.identity.verify_certificate(
            relay_server_id,
            machine_route,
            CertRole::Data,
            data_certificate,
        )?;
        let binding = self.identity.binding();
        Ok(MachinePairingAnchor {
            relay_server_id,
            machine_route,
            root_public_key: PublicKeyBytes(binding.root_public_key),
            root_fingerprint: binding.root_fingerprint,
            root_key_id: RootKeyId::from_bytes(binding.root_key_id),
            trust_epoch: TrustEpoch::new(binding.trust_epoch),
            machine_hpke_public_key: PublicKeyBytes(binding.machine_hpke_public_key),
            data_generation: LinkGeneration::new(binding.data_generation),
            data_certificate: data_certificate.clone(),
        })
    }

    pub(super) fn seal_pair_pending(
        &self,
        recipient: &HpkePublicKey,
        info: &PairRequestInfoV1,
        context: &OuterContextV1,
        request_hash: [u8; 32],
        signer: &MachineDataSignerBindingV1,
        mut rng: &mut dyn agentdeck_crypto::rand_core::CryptoRng,
    ) -> Result<PairingControlEnvelopeV1, MachinePairingError> {
        Ok(seal_pair_pending(
            recipient,
            info,
            context,
            request_hash,
            self.identity.material.data_signing_key(),
            signer,
            &mut rng,
        )?)
    }

    pub(super) fn seal_pair_terminal(
        &self,
        recipient: &HpkePublicKey,
        info: &PairRequestInfoV1,
        context: &OuterContextV1,
        terminal: PairTerminalV1,
        signer: &MachineDataSignerBindingV1,
        mut rng: &mut dyn agentdeck_crypto::rand_core::CryptoRng,
    ) -> Result<PairingControlEnvelopeV1, MachinePairingError> {
        Ok(seal_pair_terminal(
            recipient,
            info,
            context,
            terminal,
            self.identity.material.data_signing_key(),
            signer,
            &mut rng,
        )?)
    }

    pub(super) fn sign_relay_grant(
        &self,
        anchor: &MachinePairingAnchor,
        mut grant: RelayGrant,
    ) -> Result<RelayGrant, MachinePairingError> {
        if grant.signature.0 != [0; 64] {
            return Err(MachinePairingError::ContextMismatch);
        }
        validate_pairing_grant_axes(anchor, &grant)?;
        let tbs = grant.to_be_signed_v1(anchor.relay_server_id, anchor.root_fingerprint);
        grant.signature = sign_tbs(self.identity.material.root_signing_key(), &tbs).into();
        verify_tbs(
            &self.identity.material.root_signing_key().verifying_key(),
            &tbs,
            &SignatureBytes::from(grant.signature),
        )?;
        Ok(grant)
    }

    pub(super) fn sign_device_authorization(
        &self,
        anchor: &MachinePairingAnchor,
        grant: &RelayGrant,
        authorization: DeviceAuthorizationV1,
    ) -> Result<DeviceAuthorizationV1, MachinePairingError> {
        validate_pairing_grant_axes(anchor, grant)?;
        if grant.signature.0 == [0; 64] {
            return Err(MachinePairingError::ContextMismatch);
        }
        let tbs = grant.to_be_signed_v1(anchor.relay_server_id, anchor.root_fingerprint);
        verify_tbs(
            &self.identity.material.root_signing_key().verifying_key(),
            &tbs,
            &SignatureBytes::from(grant.signature),
        )?;
        Ok(sign_device_authorization(
            self.identity.material.root_signing_key(),
            anchor.relay_server_id,
            grant,
            authorization,
        )?)
    }

    /// 仅允许当前 MachineDataSign 对完整 typed key directory 签名。
    pub(super) fn sign_key_directory(
        &self,
        anchor: &MachinePairingAnchor,
        context: &KeyDirectorySignatureContextV1,
        directory: KeyDirectoryV1,
    ) -> Result<KeyDirectoryV1, MachinePairingError> {
        if context.relay_server_id != anchor.relay_server_id
            || context.machine_route != anchor.machine_route
            || context.root_trust_epoch != anchor.trust_epoch
            || context.device_route.as_bytes() == &[0; 16]
            || context.grant_serial.value() == 0
        {
            return Err(MachinePairingError::ContextMismatch);
        }
        let signer = MachineDataSignerBindingV1::from_certificate(&anchor.data_certificate)
            .map_err(|_| MachinePairingError::Crypto)?;
        Ok(crypto_sign_key_directory(
            self.identity.material.data_signing_key(),
            &signer,
            context,
            directory,
        )?)
    }

    /// 仅允许当前 MachineDataSign 对 protocol-owned KeyUpdate TBS 签名。
    pub(super) fn sign_key_update(
        &self,
        anchor: &MachinePairingAnchor,
        info: &KeyUpdateInfoV1,
        context: &OuterContextV1,
        update: KeyUpdateV1,
    ) -> Result<KeyUpdateV1, MachinePairingError> {
        if info.relay_server_id != anchor.relay_server_id
            || info.machine_route != anchor.machine_route
            || info.root_trust_epoch != anchor.trust_epoch
        {
            return Err(MachinePairingError::ContextMismatch);
        }
        let signer = MachineDataSignerBindingV1::from_certificate(&anchor.data_certificate)
            .map_err(|_| MachinePairingError::Crypto)?;
        Ok(crypto_sign_key_update(
            self.identity.material.data_signing_key(),
            &signer,
            info,
            context,
            update,
        )?)
    }

    /// 只允许当前 MachineDataSign 对 protocol 计算的 sealed-blob TBS 签名。
    /// 调用方拿不到 raw signing key，也不能传入任意 preimage。
    pub(super) fn sign_sealed(
        &self,
        anchor: &MachinePairingAnchor,
        unsigned: UnsignedSealedBlobV1,
        context: &OuterContextV1,
    ) -> Result<SignedSealedBlobV1, MachinePairingError> {
        if context.machine_route != Some(anchor.machine_route)
            || context.relay_protocol_version
                != agentdeck_protocol::relay_v2::RELAY_PROTOCOL_VERSION
            || context.e2ee_format_version != agentdeck_protocol::e2ee::E2EE_FORMAT_VERSION
            || context.validate().is_err()
        {
            return Err(MachinePairingError::ContextMismatch);
        }
        Ok(crypto_sign_sealed(
            unsigned,
            self.identity.material.data_signing_key(),
            context,
        ))
    }

    /// 只允许当前 root-certified MachineDataSign 与 exact DeviceHPKE recipient
    /// 生成 protocol-owned CounterRecovery reply；不存在 raw signing 或 reply-AEAD 入口。
    pub(super) fn seal_device_key_recovery_reply(
        &self,
        anchor: &MachinePairingAnchor,
        recipient: &HpkePublicKey,
        info: &DeviceKeyRecoveryInfoV1,
        context: &OuterContextV1,
        update_set: &KeyUpdateSetV1,
        mut rng: &mut dyn agentdeck_crypto::rand_core::CryptoRng,
    ) -> Result<DeviceKeyRecoveryReplyV1, MachinePairingError> {
        if info.relay_server_id != anchor.relay_server_id
            || info.machine_route != anchor.machine_route
            || info.root_trust_epoch != anchor.trust_epoch
        {
            return Err(MachinePairingError::ContextMismatch);
        }
        let signer = MachineDataSignerBindingV1::from_certificate(&anchor.data_certificate)
            .map_err(|_| MachinePairingError::Crypto)?;
        Ok(seal_device_key_recovery_reply(
            DeviceKeyRecoverySealAuthority {
                device_hpke_public_key: recipient,
                machine_data_signing_key: self.identity.material.data_signing_key(),
                signer: &signer,
            },
            info,
            context,
            update_set,
            &mut rng,
        )?)
    }

    pub(super) fn seal_pair_response(
        &self,
        anchor: &MachinePairingAnchor,
        recipient: &HpkePublicKey,
        info: &PairResponseInfoV1,
        context: &OuterContextV1,
        plaintext: &PairResponsePlaintextV1,
        mut rng: &mut dyn agentdeck_crypto::rand_core::CryptoRng,
    ) -> Result<PairResponseV1, MachinePairingError> {
        if info.relay_server_id != anchor.relay_server_id
            || info.machine_route != anchor.machine_route
            || info.root_trust_epoch != anchor.trust_epoch
        {
            return Err(MachinePairingError::ContextMismatch);
        }
        validate_pairing_grant_axes(anchor, &plaintext.relay_grant)?;
        if plaintext.relay_grant.signature.0 == [0; 64] {
            return Err(MachinePairingError::ContextMismatch);
        }
        let signer = MachineDataSignerBindingV1::from_certificate(&anchor.data_certificate)
            .map_err(|_| MachinePairingError::Crypto)?;
        Ok(seal_pair_response(
            recipient,
            info,
            context,
            plaintext,
            PairResponseSealAuthority {
                machine_data_signing_key: self.identity.material.data_signing_key(),
                signer: &signer,
                machine_root_verifying_key: &self
                    .identity
                    .material
                    .root_signing_key()
                    .verifying_key(),
            },
            &mut rng,
        )?)
    }

    pub(super) fn sign_device_revocation(
        &self,
        anchor: &MachinePairingAnchor,
        mut revocation: DeviceRevocation,
    ) -> Result<DeviceRevocation, MachinePairingError> {
        if revocation.signature.0 != [0; 64] {
            return Err(MachinePairingError::ContextMismatch);
        }
        validate_pairing_revocation_axes(anchor, &revocation)?;
        let tbs = revocation.to_be_signed_v1(anchor.relay_server_id, anchor.root_fingerprint);
        revocation.signature = sign_tbs(self.identity.material.root_signing_key(), &tbs).into();
        verify_tbs(
            &self.identity.material.root_signing_key().verifying_key(),
            &tbs,
            &SignatureBytes::from(revocation.signature),
        )?;
        Ok(revocation)
    }
}

fn validate_pairing_grant_axes(
    anchor: &MachinePairingAnchor,
    grant: &RelayGrant,
) -> Result<(), MachinePairingError> {
    if grant.machine_route != anchor.machine_route
        || grant.device_route.as_bytes() == &[0; 16]
        || grant.grant_serial.value() == 0
        || grant.root_key_id != anchor.root_key_id
        || grant.trust_epoch != anchor.trust_epoch
    {
        return Err(MachinePairingError::ContextMismatch);
    }
    validate_pairing_device_sign_key(anchor.relay_server_id, grant.device_sign_pubkey)?;
    Ok(())
}

fn validate_pairing_revocation_axes(
    anchor: &MachinePairingAnchor,
    revocation: &DeviceRevocation,
) -> Result<(), MachinePairingError> {
    if revocation.machine_route != anchor.machine_route
        || revocation.device_route.as_bytes() == &[0; 16]
        || revocation.grant_serial.value() == 0
        || revocation.root_key_id != anchor.root_key_id
        || revocation.trust_epoch != anchor.trust_epoch
    {
        return Err(MachinePairingError::ContextMismatch);
    }
    Ok(())
}

/// 复用 crypto crate 已有的 Ed25519 compressed-point/low-order preflight；这里只投影
/// 临时 public verifier anchor，不持有或暴露任何 receipt/private capability。
pub(super) fn validate_pairing_device_sign_key(
    relay_server_id: RelayServerId,
    public_key: PublicKeyBytes,
) -> Result<(), MachinePairingError> {
    ValidatedRelayReceiptVerifyKey::new(RelayReceiptVerifyKeyV1 {
        receipt_format_version: RELAY_RECEIPT_FORMAT_VERSION,
        relay_server_id,
        key_generation: RELAY_RECEIPT_KEY_GENERATION_MVP,
        key_id: RelayReceiptKeyId::from_public_key(&public_key),
        public_key,
    })?;
    Ok(())
}

impl fmt::Debug for MachineLinkIdentityOwner {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("MachineLinkIdentityOwner([REDACTED])")
    }
}

impl fmt::Debug for ArmedRemoteIdentity {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("ArmedRemoteIdentity([REDACTED])")
    }
}

/// 在 RuntimeStore 已成功 open 后、RuntimeCore recovery 前收敛 machine identity。
///
/// `remote_enabled=false` 是最先执行的分支，不读取 DB identity 或任何 stable
/// machine account。StorageKEK 与 store-open 失败由调用方在本函数外处理。
pub async fn reconcile_machine_identity(
    config: &DaemonConfig,
    store: &RuntimeStoreHandle,
    key_store: &dyn KeyStore,
) -> Result<RemoteBootstrapOutcome, RuntimeStoreError> {
    if !config.remote_enabled() {
        return Ok(RemoteBootstrapOutcome::Disabled);
    }

    let state = store.load_machine_identity_state().await?;
    if state.is_none()
        && matches!(
            store.load_machine_enrollment_state().await?,
            Some(MachineEnrollmentState::LocalDeleted(_))
        )
    {
        // LocalDeleted 必须等待显式 re-enroll；startup 不能先创建 standalone
        // replacement keys，更不能让普通 identity prepare 绕过 tombstone CAS。
        return Ok(RemoteBootstrapOutcome::Blocked(
            RemoteBootstrapBlock::LOCAL_DELETED,
        ));
    }
    let guard = match load_key_directory_guard(key_store) {
        Ok(guard) => guard,
        Err(error) => {
            return Ok(RemoteBootstrapOutcome::Blocked(
                RemoteBootstrapBlock::identity(&error),
            ));
        }
    };

    match state {
        None if guard.is_some() => Ok(RemoteBootstrapOutcome::Blocked(
            RemoteBootstrapBlock::DATABASE_ROLLBACK,
        )),
        None => reconcile_fresh(store, key_store).await,
        Some(state) => reconcile_existing(store, key_store, state, guard).await,
    }
}

/// 为显式 `LocalDeleted` re-enroll 准备 deterministic pending owner。
///
/// 本函数绝不调用 standalone identity prepare。四组 key existing-only/create 与
/// exact guard 先在 Keychain 收敛；随后 enrollment Store prepare 才会在一个事务中
/// 同时插入 active identity 并替换 tombstone。相同 DB/material 的 crash retry 会
/// 派生相同 root key ID，不会覆盖现有 material。
pub async fn prepare_reenrollment_identity(
    store: &RuntimeStoreHandle,
    key_store: &dyn KeyStore,
) -> Result<PendingReenrollmentIdentity, PrepareReenrollmentIdentityError> {
    let remote = store
        .load_machine_enrollment_state()
        .await
        .map_err(PrepareReenrollmentIdentityError::store)?;
    if !matches!(remote, Some(MachineEnrollmentState::LocalDeleted(_))) {
        return Err(PrepareReenrollmentIdentityError::state_conflict());
    }
    if store
        .load_machine_identity_state()
        .await
        .map_err(PrepareReenrollmentIdentityError::store)?
        .is_some()
    {
        return Err(PrepareReenrollmentIdentityError::state_conflict());
    }

    let material = load_or_create_preparing_machine_key_material(key_store)
        .map_err(PrepareReenrollmentIdentityError::identity)?;
    let database_id = store.authenticated_database_id();
    let root_key_id = deterministic_reenrollment_root_key_id(database_id, &material);
    let binding = fresh_binding(&material, root_key_id);
    let guard = KeyDirectoryGuard::new(
        database_id,
        binding.root_fingerprint,
        binding.key_directory_revision,
    );
    install_key_directory_guard(key_store, guard)
        .map_err(PrepareReenrollmentIdentityError::identity)?;
    Ok(PendingReenrollmentIdentity {
        state: MachineIdentityStateRecord {
            database_id,
            lifecycle: MachineIdentityLifecycle::Active,
            binding,
        },
        material,
    })
}

fn deterministic_reenrollment_root_key_id(
    database_id: [u8; 16],
    material: &MachineKeyMaterial,
) -> [u8; 16] {
    let mut input = Vec::with_capacity(REENROLL_ROOT_KEY_ID_DOMAIN.len() + 16 + 32 + 1);
    input.extend_from_slice(REENROLL_ROOT_KEY_ID_DOMAIN);
    input.extend_from_slice(&database_id);
    input.extend_from_slice(material.public_identity().root().public_key());
    for counter in 0_u8..=u8::MAX {
        input.push(counter);
        let digest = sha256(&input);
        input.pop();
        let mut id = [0; 16];
        id.copy_from_slice(&digest[..16]);
        if id != [0; 16] {
            return id;
        }
    }
    unreachable!("a 256-way SHA-256 derivation cannot yield only zero IDs")
}

async fn reconcile_fresh(
    store: &RuntimeStoreHandle,
    key_store: &dyn KeyStore,
) -> Result<RemoteBootstrapOutcome, RuntimeStoreError> {
    let material = match load_or_create_preparing_machine_key_material(key_store) {
        Ok(material) => material,
        Err(error) => {
            return Ok(RemoteBootstrapOutcome::Blocked(
                RemoteBootstrapBlock::identity(&error),
            ));
        }
    };
    let root_key_id = match fresh_root_key_id() {
        Ok(root_key_id) => *root_key_id.as_bytes(),
        Err(
            RootKeyIdGenerationError::EntropyUnavailable | RootKeyIdGenerationError::ZeroExhausted,
        ) => {
            return Ok(RemoteBootstrapOutcome::Blocked(
                RemoteBootstrapBlock::ENTROPY_UNAVAILABLE,
            ));
        }
    };
    let binding = fresh_binding(&material, root_key_id);
    let prepared = match prepare_exact(store, &binding).await {
        Ok(state) => state,
        Err(StoreStepError::StateFork) => {
            return Ok(RemoteBootstrapOutcome::Blocked(
                RemoteBootstrapBlock::STATE_FORK,
            ));
        }
        Err(StoreStepError::Fatal(error)) => return Err(error),
    };
    if prepared.lifecycle != MachineIdentityLifecycle::Preparing || prepared.binding != binding {
        return Ok(RemoteBootstrapOutcome::Blocked(
            RemoteBootstrapBlock::STATE_FORK,
        ));
    }

    let guard = KeyDirectoryGuard::new(
        prepared.database_id,
        binding.root_fingerprint,
        binding.key_directory_revision,
    );
    if let Err(error) = install_key_directory_guard(key_store, guard) {
        return Ok(RemoteBootstrapOutcome::Blocked(
            RemoteBootstrapBlock::identity(&error),
        ));
    }

    activate(store, binding, material).await
}

async fn reconcile_existing(
    store: &RuntimeStoreHandle,
    key_store: &dyn KeyStore,
    state: MachineIdentityStateRecord,
    guard: Option<KeyDirectoryGuard>,
) -> Result<RemoteBootstrapOutcome, RuntimeStoreError> {
    let material = match load_machine_key_material(key_store) {
        Ok(material) => material,
        Err(error) => {
            return Ok(RemoteBootstrapOutcome::Blocked(
                RemoteBootstrapBlock::identity(&error),
            ));
        }
    };
    if !binding_matches_material(&state.binding, &material) {
        return Ok(RemoteBootstrapOutcome::Blocked(
            RemoteBootstrapBlock::STATE_FORK,
        ));
    }

    if state.lifecycle == MachineIdentityLifecycle::Active {
        let global_revision = store
            .load_global_key_state()
            .await?
            .map(|global| global.revision().value());
        let active_transition = store.load_active_key_transition().await?;
        let identity_revision = state.binding.key_directory_revision;
        if global_revision.is_some_and(|revision| revision > identity_revision) {
            return match recover_key_directory_rotation(store, key_store).await? {
                KeyDirectoryRotationRecoveryOutcome::Recovered(recovered)
                    if binding_matches_material(&recovered.binding, &material) =>
                {
                    Ok(RemoteBootstrapOutcome::Active(Box::new(
                        ActiveMachineIdentity {
                            state: *recovered,
                            material,
                        },
                    )))
                }
                KeyDirectoryRotationRecoveryOutcome::Recovered(_) => Ok(
                    RemoteBootstrapOutcome::Blocked(RemoteBootstrapBlock::STATE_FORK),
                ),
                KeyDirectoryRotationRecoveryOutcome::Blocked(block) => {
                    Ok(RemoteBootstrapOutcome::Blocked(block))
                }
            };
        }

        let global_is_stable = match global_revision {
            None => identity_revision == 0 && active_transition.is_none(),
            Some(revision) if revision == identity_revision => {
                active_transition.as_ref().is_none_or(|recovery| {
                    recovery.transition.phase
                        != crate::runtime::store::key_transition::KeyTransitionPhase::DrainingOld
                        && recovery.transition.to_revision == identity_revision
                })
            }
            Some(_) => false,
        };
        if !global_is_stable {
            return Ok(RemoteBootstrapOutcome::Blocked(
                RemoteBootstrapBlock::STATE_FORK,
            ));
        }
    }

    let expected_guard = KeyDirectoryGuard::new(
        state.database_id,
        state.binding.root_fingerprint,
        state.binding.key_directory_revision,
    );
    match (state.lifecycle, guard) {
        (MachineIdentityLifecycle::Active, None) => Ok(RemoteBootstrapOutcome::Blocked(
            RemoteBootstrapBlock::GUARD_MISSING,
        )),
        (MachineIdentityLifecycle::Active, Some(actual)) if actual != expected_guard => Ok(
            RemoteBootstrapOutcome::Blocked(RemoteBootstrapBlock::STATE_FORK),
        ),
        (MachineIdentityLifecycle::Active, Some(_)) => Ok(RemoteBootstrapOutcome::Active(
            Box::new(ActiveMachineIdentity { state, material }),
        )),
        (MachineIdentityLifecycle::Preparing, Some(actual)) if actual != expected_guard => Ok(
            RemoteBootstrapOutcome::Blocked(RemoteBootstrapBlock::STATE_FORK),
        ),
        (MachineIdentityLifecycle::Preparing, None) => {
            if let Err(error) = install_key_directory_guard(key_store, expected_guard) {
                return Ok(RemoteBootstrapOutcome::Blocked(
                    RemoteBootstrapBlock::identity(&error),
                ));
            }
            activate(store, state.binding, material).await
        }
        (MachineIdentityLifecycle::Preparing, Some(_)) => {
            activate(store, state.binding, material).await
        }
    }
}

async fn activate(
    store: &RuntimeStoreHandle,
    binding: MachineIdentityBinding,
    material: MachineKeyMaterial,
) -> Result<RemoteBootstrapOutcome, RuntimeStoreError> {
    let active = match activate_exact(store, &binding).await {
        Ok(state) => state,
        Err(StoreStepError::StateFork) => {
            return Ok(RemoteBootstrapOutcome::Blocked(
                RemoteBootstrapBlock::STATE_FORK,
            ));
        }
        Err(StoreStepError::Fatal(error)) => return Err(error),
    };
    if active.lifecycle != MachineIdentityLifecycle::Active || active.binding != binding {
        return Ok(RemoteBootstrapOutcome::Blocked(
            RemoteBootstrapBlock::STATE_FORK,
        ));
    }
    Ok(RemoteBootstrapOutcome::Active(Box::new(
        ActiveMachineIdentity {
            state: active,
            material,
        },
    )))
}

fn fresh_binding(material: &MachineKeyMaterial, root_key_id: [u8; 16]) -> MachineIdentityBinding {
    let public = material.public_identity();
    MachineIdentityBinding {
        root_key_id,
        trust_epoch: FRESH_TRUST_EPOCH,
        link_generation: FRESH_LINK_GENERATION,
        data_generation: FRESH_DATA_GENERATION,
        key_directory_revision: FRESH_KEY_DIRECTORY_REVISION,
        root_public_key: *public.root().public_key(),
        root_fingerprint: public.root().fingerprint(),
        machine_hpke_public_key: *public.hpke().public_key(),
        machine_hpke_fingerprint: public.hpke().fingerprint(),
        link_sign_public_key: *public.link().public_key(),
        link_sign_fingerprint: public.link().fingerprint(),
        data_sign_public_key: *public.data().public_key(),
        data_sign_fingerprint: public.data().fingerprint(),
    }
}

fn binding_matches_material(
    binding: &MachineIdentityBinding,
    material: &MachineKeyMaterial,
) -> bool {
    let public = material.public_identity();
    binding.root_public_key == *public.root().public_key()
        && binding.root_fingerprint == public.root().fingerprint()
        && binding.machine_hpke_public_key == *public.hpke().public_key()
        && binding.machine_hpke_fingerprint == public.hpke().fingerprint()
        && binding.link_sign_public_key == *public.link().public_key()
        && binding.link_sign_fingerprint == public.link().fingerprint()
        && binding.data_sign_public_key == *public.data().public_key()
        && binding.data_sign_fingerprint == public.data().fingerprint()
}

#[derive(Debug, Eq, PartialEq)]
enum RootKeyIdGenerationError {
    EntropyUnavailable,
    ZeroExhausted,
}

fn fresh_root_key_id() -> Result<RootKeyId, RootKeyIdGenerationError> {
    fresh_root_key_id_with(|bytes| {
        getrandom::fill(bytes).map_err(|_| RootKeyIdGenerationError::EntropyUnavailable)
    })
}

fn fresh_root_key_id_with(
    mut fill: impl FnMut(&mut [u8; 16]) -> Result<(), RootKeyIdGenerationError>,
) -> Result<RootKeyId, RootKeyIdGenerationError> {
    for _ in 0..ROOT_KEY_ID_ATTEMPTS {
        let mut bytes = [0_u8; 16];
        fill(&mut bytes)?;
        if bytes != [0; 16] {
            return Ok(RootKeyId::from_bytes(bytes));
        }
    }
    Err(RootKeyIdGenerationError::ZeroExhausted)
}

enum StoreStepError {
    StateFork,
    Fatal(RuntimeStoreError),
}

async fn prepare_exact(
    store: &RuntimeStoreHandle,
    binding: &MachineIdentityBinding,
) -> Result<MachineIdentityStateRecord, StoreStepError> {
    let first = store.prepare_machine_identity(binding.clone()).await;
    let outcome = match first {
        Err(RuntimeStoreError::CommitOutcomeUnknown {
            operation: RuntimeCommitOperation::PrepareMachineIdentity,
        }) => store.prepare_machine_identity(binding.clone()).await,
        other => other,
    };
    match outcome {
        Ok(
            PrepareMachineIdentityOutcome::Prepared { state }
            | PrepareMachineIdentityOutcome::Replayed { state },
        ) => Ok(state),
        Err(
            RuntimeStoreError::MachineIdentityMissing | RuntimeStoreError::MachineIdentityConflict,
        ) => Err(StoreStepError::StateFork),
        Err(
            error @ RuntimeStoreError::CommitOutcomeUnknown {
                operation: RuntimeCommitOperation::PrepareMachineIdentity,
            },
        ) => settle_prepare_unknown(store, binding, error).await,
        Err(error) => Err(StoreStepError::Fatal(error)),
    }
}

async fn settle_prepare_unknown(
    store: &RuntimeStoreHandle,
    binding: &MachineIdentityBinding,
    unknown: RuntimeStoreError,
) -> Result<MachineIdentityStateRecord, StoreStepError> {
    match store.load_machine_identity_state().await {
        Ok(Some(state)) if state.binding == *binding => Ok(state),
        Ok(Some(_)) => Err(StoreStepError::StateFork),
        Ok(None) => Err(StoreStepError::Fatal(unknown)),
        Err(error) => Err(StoreStepError::Fatal(error)),
    }
}

async fn activate_exact(
    store: &RuntimeStoreHandle,
    binding: &MachineIdentityBinding,
) -> Result<MachineIdentityStateRecord, StoreStepError> {
    let first = store.activate_machine_identity(binding.clone()).await;
    let outcome = match first {
        Err(RuntimeStoreError::CommitOutcomeUnknown {
            operation: RuntimeCommitOperation::ActivateMachineIdentity,
        }) => store.activate_machine_identity(binding.clone()).await,
        other => other,
    };
    match outcome {
        Ok(
            ActivateMachineIdentityOutcome::Activated { state }
            | ActivateMachineIdentityOutcome::Replayed { state },
        ) => Ok(state),
        Err(
            RuntimeStoreError::MachineIdentityMissing | RuntimeStoreError::MachineIdentityConflict,
        ) => Err(StoreStepError::StateFork),
        Err(
            error @ RuntimeStoreError::CommitOutcomeUnknown {
                operation: RuntimeCommitOperation::ActivateMachineIdentity,
            },
        ) => settle_activate_unknown(store, binding, error).await,
        Err(error) => Err(StoreStepError::Fatal(error)),
    }
}

async fn settle_activate_unknown(
    store: &RuntimeStoreHandle,
    binding: &MachineIdentityBinding,
    unknown: RuntimeStoreError,
) -> Result<MachineIdentityStateRecord, StoreStepError> {
    match store.load_machine_identity_state().await {
        Ok(Some(state))
            if state.binding == *binding && state.lifecycle == MachineIdentityLifecycle::Active =>
        {
            Ok(state)
        }
        Ok(Some(state)) if state.binding != *binding => Err(StoreStepError::StateFork),
        Ok(Some(_)) | Ok(None) => Err(StoreStepError::Fatal(unknown)),
        Err(error) => Err(StoreStepError::Fatal(error)),
    }
}

#[cfg(test)]
mod tests {
    use std::sync::atomic::{AtomicUsize, Ordering};
    use std::sync::{Arc, Mutex};

    use agentdeck_protocol::relay_v2::{DeviceRouteId, GrantSerial};

    use super::*;
    use crate::runtime::store::key_transition::{
        CounterRetirementLifecycle, KeyTransitionOperation, KeyTransitionPhase,
        KeyTransitionRecipient, KeyTransitionRecord, KeyTransitionTarget,
    };
    use crate::security::{KeyStoreError, MemoryKeyStore, SecretBytes};

    const TEST_RELAY: RelayServerId = RelayServerId::from_bytes([0x41; 16]);
    const TEST_MACHINE: MachineRouteId = MachineRouteId::from_bytes([0x42; 16]);

    fn pairing_owner() -> (
        MachineLinkIdentityOwner,
        MachinePairingAnchor,
        agentdeck_crypto::VerifyingKey,
    ) {
        let keys = MemoryKeyStore::new();
        let material = load_or_create_preparing_machine_key_material(&keys)
            .expect("create machine key material");
        let root_verifying_key = material.root_signing_key().verifying_key();
        let binding = fresh_binding(&material, [0x43; 16]);
        let identity = Box::new(ActiveMachineIdentity {
            state: MachineIdentityStateRecord {
                database_id: [0x44; 16],
                lifecycle: MachineIdentityLifecycle::Active,
                binding,
            },
            material,
        });
        let data_certificate = identity
            .certificates(TEST_RELAY, TEST_MACHINE)
            .expect("issue active certificates")
            .data()
            .clone();
        let owner = MachineLinkIdentityOwner { identity };
        let anchor = owner
            .pairing_anchor(TEST_RELAY, TEST_MACHINE, &data_certificate)
            .unwrap_or_else(|error| panic!("bind pairing authority: {}", error.code()));
        (owner, anchor, root_verifying_key)
    }

    fn rotation_recovery_evidence(guard_revision: u64) -> KeyDirectoryRotationRecoveryEvidence {
        let keys = MemoryKeyStore::new();
        let material = load_or_create_preparing_machine_key_material(&keys)
            .expect("create recovery machine key material");
        let binding = fresh_binding(&material, [0x63; 16]);
        let recipient = KeyTransitionRecipient {
            device_route: [0x64; 16],
            grant_serial: 1,
        };
        KeyDirectoryRotationRecoveryEvidence {
            identity: MachineIdentityStateRecord {
                database_id: [0x65; 16],
                lifecycle: MachineIdentityLifecycle::Active,
                binding: binding.clone(),
            },
            guard: KeyDirectoryGuard::new([0x65; 16], binding.root_fingerprint, guard_revision),
            remote_machine_route: MachineRouteId::from_bytes([0x66; 16]),
            remote_binding: binding.clone(),
            remote_root_key_id: binding.root_key_id,
            remote_root_fingerprint: binding.root_fingerprint,
            remote_trust_epoch: binding.trust_epoch,
            global_revision: Some(1),
            transition: Some(KeyTransitionRecord {
                operation_id: [0x67; 16],
                operation: KeyTransitionOperation::Add,
                target: KeyTransitionTarget::Device(recipient),
                from_revision: 0,
                to_revision: 1,
                phase: KeyTransitionPhase::DrainingOld,
                terminal: None,
                recipients: vec![recipient],
                global_lineage: None,
                bootstrap_install_proof: None,
                replay_retirement: None,
                counter_retirement: CounterRetirementLifecycle::Pending,
                cuts: Vec::new(),
                update_count: 0,
                created_at_ms: 10,
                state_changed_at_ms: 10,
                terminal_at_ms: None,
                retain_until_ms: None,
            }),
        }
    }

    #[derive(Default)]
    struct RecordingKeyStore {
        inner: MemoryKeyStore,
        store_calls: AtomicUsize,
    }

    impl RecordingKeyStore {
        fn reset_store_calls(&self) {
            self.store_calls.store(0, Ordering::SeqCst);
        }

        fn store_calls(&self) -> usize {
            self.store_calls.load(Ordering::SeqCst)
        }
    }

    impl KeyStore for RecordingKeyStore {
        fn load(&self, account: &str) -> Result<Option<SecretBytes>, KeyStoreError> {
            self.inner.load(account)
        }

        fn store(&self, account: &str, value: &SecretBytes) -> Result<(), KeyStoreError> {
            self.store_calls.fetch_add(1, Ordering::SeqCst);
            self.inner.store(account, value)
        }

        fn delete(&self, account: &str) -> Result<(), KeyStoreError> {
            self.inner.delete(account)
        }
    }

    #[derive(Clone, Copy, Debug, Eq, PartialEq)]
    enum FakeFinalizeMode {
        Succeed,
        FailBeforeCommitOnce,
        OutcomeUnknownAfterCommitOnce,
        CorruptReload,
    }

    struct FakeRotationRecoveryState {
        evidence: KeyDirectoryRotationRecoveryEvidence,
        mode: FakeFinalizeMode,
        finalize_calls: usize,
        guard_revisions_at_finalize: Vec<u64>,
    }

    struct FakeRotationRecoveryStore {
        key_store: Arc<RecordingKeyStore>,
        state: Mutex<FakeRotationRecoveryState>,
    }

    impl FakeRotationRecoveryStore {
        fn new(
            initial_guard_revision: u64,
            mode: FakeFinalizeMode,
        ) -> (Arc<RecordingKeyStore>, Self) {
            let evidence = rotation_recovery_evidence(initial_guard_revision);
            let key_store = Arc::new(RecordingKeyStore::default());
            install_key_directory_guard(&*key_store, evidence.guard)
                .expect("install rotation recovery guard");
            key_store.reset_store_calls();
            let store = Self {
                key_store: Arc::clone(&key_store),
                state: Mutex::new(FakeRotationRecoveryState {
                    evidence,
                    mode,
                    finalize_calls: 0,
                    guard_revisions_at_finalize: Vec::new(),
                }),
            };
            (key_store, store)
        }

        fn finalize_calls(&self) -> usize {
            self.state.lock().expect("fake store lock").finalize_calls
        }

        fn guard_revisions_at_finalize(&self) -> Vec<u64> {
            self.state
                .lock()
                .expect("fake store lock")
                .guard_revisions_at_finalize
                .clone()
        }

        fn identity_revision(&self) -> u64 {
            self.state
                .lock()
                .expect("fake store lock")
                .evidence
                .identity
                .binding
                .key_directory_revision
        }
    }

    #[async_trait::async_trait]
    impl KeyDirectoryRotationRecoveryStore for FakeRotationRecoveryStore {
        async fn load_rotation_recovery_evidence(
            &self,
            guard: KeyDirectoryGuard,
        ) -> Result<KeyDirectoryRotationRecoveryEvidence, RuntimeStoreError> {
            let mut evidence = self.state.lock().expect("fake store lock").evidence.clone();
            evidence.guard = guard;
            Ok(evidence)
        }

        async fn finalize_key_directory_rotation(
            &self,
            operation_id: [u8; 16],
        ) -> Result<
            crate::runtime::store::key_transition::KeyTransitionRecord,
            KeyDirectoryRotationFinalizeError,
        > {
            let guard = load_key_directory_guard(&*self.key_store)
                .map_err(|_| {
                    KeyDirectoryRotationFinalizeError::Store(RuntimeStoreError::WorkerStopped)
                })?
                .ok_or_else(|| {
                    KeyDirectoryRotationFinalizeError::Store(RuntimeStoreError::WorkerStopped)
                })?;
            let mut state = self.state.lock().expect("fake store lock");
            state.finalize_calls += 1;
            state
                .guard_revisions_at_finalize
                .push(guard.key_directory_revision());
            if state.mode == FakeFinalizeMode::FailBeforeCommitOnce {
                state.mode = FakeFinalizeMode::Succeed;
                return Err(KeyDirectoryRotationFinalizeError::Store(
                    RuntimeStoreError::WorkerStopped,
                ));
            }

            let transition = state.evidence.transition.as_mut().ok_or_else(|| {
                KeyDirectoryRotationFinalizeError::Store(RuntimeStoreError::InvalidStateTransition)
            })?;
            if transition.operation_id != operation_id {
                return Err(KeyDirectoryRotationFinalizeError::Store(
                    RuntimeStoreError::InvalidStateTransition,
                ));
            }
            let to_revision = transition.to_revision;
            transition.phase = KeyTransitionPhase::RotatedPreparingUpdates;
            state.evidence.identity.binding.key_directory_revision = to_revision;
            state.evidence.remote_binding = state.evidence.identity.binding.clone();
            if state.mode == FakeFinalizeMode::CorruptReload {
                state.evidence.remote_trust_epoch = state
                    .evidence
                    .remote_trust_epoch
                    .checked_add(1)
                    .expect("test trust epoch");
            }
            let completed = state
                .evidence
                .transition
                .as_ref()
                .expect("completed fake transition")
                .clone();
            if state.mode == FakeFinalizeMode::OutcomeUnknownAfterCommitOnce {
                state.mode = FakeFinalizeMode::Succeed;
                return Err(KeyDirectoryRotationFinalizeError::OutcomeUnknown);
            }
            Ok(completed)
        }
    }

    #[test]
    fn guard_rotation_recovery_accepts_only_the_two_exact_one_step_crash_states() {
        let from = rotation_recovery_evidence(0);
        assert_eq!(
            plan_key_directory_rotation_recovery(&from),
            Ok(KeyDirectoryRotationRecoveryAction::AdvanceGuardThenStore {
                operation_id: [0x67; 16],
                from_revision: 0,
                to_revision: 1,
            })
        );

        let to = rotation_recovery_evidence(1);
        assert_eq!(
            plan_key_directory_rotation_recovery(&to),
            Ok(KeyDirectoryRotationRecoveryAction::CompleteStore {
                operation_id: [0x67; 16],
                from_revision: 0,
                to_revision: 1,
            })
        );
    }

    #[test]
    fn guard_rotation_recovery_rejects_missing_gap_phase_operation_and_binding_forks() {
        let mut invalid = Vec::new();

        let mut missing_transition = rotation_recovery_evidence(0);
        missing_transition.transition = None;
        invalid.push(missing_transition);

        let mut missing_global = rotation_recovery_evidence(0);
        missing_global.global_revision = None;
        invalid.push(missing_global);

        let mut global_gap = rotation_recovery_evidence(0);
        global_gap.global_revision = Some(2);
        invalid.push(global_gap);

        let mut transition_gap = rotation_recovery_evidence(0);
        transition_gap
            .transition
            .as_mut()
            .expect("transition")
            .to_revision = 2;
        invalid.push(transition_gap);

        let mut wrong_phase = rotation_recovery_evidence(0);
        wrong_phase.transition.as_mut().expect("transition").phase =
            KeyTransitionPhase::RotatedPreparingUpdates;
        invalid.push(wrong_phase);

        let mut wrong_operation = rotation_recovery_evidence(0);
        wrong_operation
            .transition
            .as_mut()
            .expect("transition")
            .operation = KeyTransitionOperation::ActivateConversation;
        invalid.push(wrong_operation);

        let mut wrong_database = rotation_recovery_evidence(0);
        wrong_database.guard = KeyDirectoryGuard::new(
            [0x68; 16],
            wrong_database.identity.binding.root_fingerprint,
            0,
        );
        invalid.push(wrong_database);

        let mut wrong_root = rotation_recovery_evidence(0);
        wrong_root.remote_root_fingerprint = [0x69; 32];
        invalid.push(wrong_root);

        let mut wrong_machine = rotation_recovery_evidence(0);
        wrong_machine.remote_machine_route = MachineRouteId::from_bytes([0; 16]);
        invalid.push(wrong_machine);

        let mut wrong_remote_binding = rotation_recovery_evidence(0);
        wrong_remote_binding.remote_binding.key_directory_revision = 1;
        invalid.push(wrong_remote_binding);

        let mut identity_ahead_of_draining_transition = rotation_recovery_evidence(1);
        identity_ahead_of_draining_transition
            .identity
            .binding
            .key_directory_revision = 1;
        identity_ahead_of_draining_transition
            .remote_binding
            .key_directory_revision = 1;
        invalid.push(identity_ahead_of_draining_transition);

        let wrong_guard_revision = rotation_recovery_evidence(2);
        invalid.push(wrong_guard_revision);

        for evidence in invalid {
            assert_eq!(
                plan_key_directory_rotation_recovery(&evidence),
                Err(RemoteBootstrapBlock::STATE_FORK),
                "invalid recovery evidence must fail closed: {evidence:?}"
            );
        }
    }

    #[tokio::test]
    async fn guard_rotation_recovery_orders_cas_before_finalize_and_skips_redundant_cas() {
        for (initial_guard_revision, expected_store_calls) in [(0, 1), (1, 0)] {
            let (key_store, store) =
                FakeRotationRecoveryStore::new(initial_guard_revision, FakeFinalizeMode::Succeed);
            let outcome = drive_key_directory_rotation_recovery(&store, &*key_store)
                .await
                .expect("drive exact recovery");
            let KeyDirectoryRotationRecoveryOutcome::Recovered(identity) = outcome else {
                panic!("exact one-step crash state must recover")
            };
            assert_eq!(identity.binding.key_directory_revision, 1);
            assert_eq!(key_store.store_calls(), expected_store_calls);
            assert_eq!(store.finalize_calls(), 1);
            assert_eq!(store.guard_revisions_at_finalize(), vec![1]);
        }
    }

    #[tokio::test]
    async fn guard_rotation_recovery_restarts_after_before_commit_store_failure() {
        let (key_store, store) =
            FakeRotationRecoveryStore::new(0, FakeFinalizeMode::FailBeforeCommitOnce);
        let error = drive_key_directory_rotation_recovery(&store, &*key_store)
            .await
            .expect_err("before-COMMIT store failure remains fatal for this startup");
        assert!(matches!(error, RuntimeStoreError::WorkerStopped));
        assert_eq!(store.identity_revision(), 0);
        assert_eq!(
            load_key_directory_guard(&*key_store)
                .expect("load advanced guard")
                .expect("guard remains installed")
                .key_directory_revision(),
            1
        );
        assert_eq!(key_store.store_calls(), 1);

        let outcome = drive_key_directory_rotation_recovery(&store, &*key_store)
            .await
            .expect("restart completes guard-ahead Store state");
        assert!(matches!(
            outcome,
            KeyDirectoryRotationRecoveryOutcome::Recovered(_)
        ));
        assert_eq!(store.identity_revision(), 1);
        assert_eq!(key_store.store_calls(), 1, "restart must not rewrite guard");
        assert_eq!(store.finalize_calls(), 2);
        assert_eq!(store.guard_revisions_at_finalize(), vec![1, 1]);
    }

    #[tokio::test]
    async fn guard_rotation_recovery_settles_after_commit_unknown_by_exact_reload() {
        let (key_store, store) =
            FakeRotationRecoveryStore::new(0, FakeFinalizeMode::OutcomeUnknownAfterCommitOnce);
        let outcome = drive_key_directory_rotation_recovery(&store, &*key_store)
            .await
            .expect("exact reload settles after-COMMIT unknown");
        let KeyDirectoryRotationRecoveryOutcome::Recovered(identity) = outcome else {
            panic!("committed exact state must settle as recovered")
        };
        assert_eq!(identity.binding.key_directory_revision, 1);
        assert_eq!(store.finalize_calls(), 1);
        assert_eq!(store.guard_revisions_at_finalize(), vec![1]);
    }

    #[tokio::test]
    async fn guard_rotation_recovery_blocks_inconsistent_exact_reload() {
        let (key_store, store) = FakeRotationRecoveryStore::new(0, FakeFinalizeMode::CorruptReload);
        let outcome = drive_key_directory_rotation_recovery(&store, &*key_store)
            .await
            .expect("state fork is a remote-only block");
        assert_eq!(
            outcome,
            KeyDirectoryRotationRecoveryOutcome::Blocked(RemoteBootstrapBlock::STATE_FORK)
        );
        assert_eq!(store.finalize_calls(), 1);
    }

    fn unsigned_grant(anchor: &MachinePairingAnchor, device_key: PublicKeyBytes) -> RelayGrant {
        RelayGrant {
            machine_route: anchor.machine_route,
            device_route: DeviceRouteId::from_bytes([0x45; 16]),
            device_sign_pubkey: device_key,
            grant_serial: GrantSerial::new(7),
            root_key_id: anchor.root_key_id,
            trust_epoch: anchor.trust_epoch,
            signature: Ed25519Signature([0; 64]),
        }
    }

    #[test]
    fn reenrollment_root_key_id_is_stable_for_same_database_and_key_material() {
        let keys = MemoryKeyStore::new();
        let first_material = load_or_create_preparing_machine_key_material(&keys)
            .expect("create re-enrollment material");
        let first = deterministic_reenrollment_root_key_id([0x31; 16], &first_material);
        drop(first_material);
        let existing = load_or_create_preparing_machine_key_material(&keys)
            .expect("load exact existing re-enrollment material");
        let replay = deterministic_reenrollment_root_key_id([0x31; 16], &existing);
        assert_eq!(first, replay);
        assert_ne!(first, [0; 16]);
        assert_ne!(
            first,
            deterministic_reenrollment_root_key_id([0x32; 16], &existing),
            "database binding participates in the domain-separated identity"
        );
    }

    #[test]
    fn root_key_id_entropy_failure_is_typed() {
        let error = fresh_root_key_id_with(|_| Err(RootKeyIdGenerationError::EntropyUnavailable))
            .expect_err("entropy failure must not panic or mint an ID");
        assert_eq!(error, RootKeyIdGenerationError::EntropyUnavailable);
    }

    #[test]
    fn root_key_id_rejects_continuous_all_zero_entropy() {
        let mut calls = 0;
        let error = fresh_root_key_id_with(|bytes| {
            calls += 1;
            *bytes = [0; 16];
            Ok(())
        })
        .expect_err("all-zero draws must be exhausted without minting an ID");
        assert_eq!(error, RootKeyIdGenerationError::ZeroExhausted);
        assert_eq!(calls, ROOT_KEY_ID_ATTEMPTS);
    }

    #[test]
    fn pairing_device_sign_preflight_rejects_zero_invalid_and_weak_points() {
        let valid = PublicKeyBytes(
            agentdeck_crypto::SigningKey::from_seed(&[0x51; 32])
                .verifying_key()
                .to_bytes(),
        );
        validate_pairing_device_sign_key(TEST_RELAY, valid).unwrap_or_else(|error| {
            panic!("valid DeviceSign key passes preflight: {}", error.code())
        });

        let mut weak = [0; 32];
        weak[0] = 1;
        for invalid in [
            PublicKeyBytes([0; 32]),
            PublicKeyBytes(weak),
            PublicKeyBytes([
                0x19, 0x46, 0x0c, 0x51, 0x3e, 0x55, 0x2e, 0xe0, 0x3a, 0x8f, 0xb9, 0x7b, 0xb5, 0xa8,
                0x83, 0x01, 0x1f, 0x6d, 0x33, 0xe6, 0x37, 0xd2, 0x89, 0xf9, 0xd0, 0x29, 0x25, 0xba,
                0xbf, 0xed, 0xfb, 0xfc,
            ]),
        ] {
            assert_eq!(
                validate_pairing_device_sign_key(TEST_RELAY, invalid)
                    .expect_err("invalid DeviceSign key must fail closed")
                    .code(),
                "remote.transport.pairing_crypto_failed"
            );
        }
    }

    #[test]
    fn pairing_root_authority_only_signs_unsigned_grants_and_revocations() {
        let (owner, anchor, root_verifying_key) = pairing_owner();
        let device_key = PublicKeyBytes(
            agentdeck_crypto::SigningKey::from_seed(&[0x52; 32])
                .verifying_key()
                .to_bytes(),
        );
        let grant = owner
            .sign_relay_grant(&anchor, unsigned_grant(&anchor, device_key))
            .unwrap_or_else(|error| panic!("sign zero-signature grant: {}", error.code()));
        verify_tbs(
            &root_verifying_key,
            &grant.to_be_signed_v1(anchor.relay_server_id, anchor.root_fingerprint),
            &SignatureBytes::from(grant.signature),
        )
        .expect("verify signed grant");

        let mut presigned_invalid_grant = unsigned_grant(&anchor, PublicKeyBytes([0; 32]));
        presigned_invalid_grant.signature = Ed25519Signature([0x53; 64]);
        assert_eq!(
            owner
                .sign_relay_grant(&anchor, presigned_invalid_grant)
                .expect_err("pre-signed grant must be rejected before key preflight")
                .code(),
            "remote.transport.pairing_authority_mismatch"
        );
        assert_eq!(
            owner
                .sign_relay_grant(&anchor, grant.clone())
                .expect_err("signed grant replay must not re-enter signing")
                .code(),
            "remote.transport.pairing_authority_mismatch"
        );

        let unsigned_revocation = DeviceRevocation {
            machine_route: grant.machine_route,
            device_route: grant.device_route,
            grant_serial: grant.grant_serial,
            root_key_id: grant.root_key_id,
            trust_epoch: grant.trust_epoch,
            signature: Ed25519Signature([0; 64]),
        };
        let revocation = owner
            .sign_device_revocation(&anchor, unsigned_revocation)
            .unwrap_or_else(|error| panic!("sign zero-signature revocation: {}", error.code()));
        verify_tbs(
            &root_verifying_key,
            &revocation.to_be_signed_v1(anchor.relay_server_id, anchor.root_fingerprint),
            &SignatureBytes::from(revocation.signature),
        )
        .expect("verify signed revocation");
        assert_eq!(
            owner
                .sign_device_revocation(&anchor, revocation)
                .expect_err("signed revocation replay must not re-enter signing")
                .code(),
            "remote.transport.pairing_authority_mismatch"
        );
    }
}
