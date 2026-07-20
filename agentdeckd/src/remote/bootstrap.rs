//! Machine identity 的本地 bootstrap/reconciliation。
//!
//! 冻结写入顺序为：四组长期 key exact load/create → authenticated DB Preparing →
//! key-directory guard exact install → authenticated DB Active。已有 Preparing/Active
//! 状态只允许 existing-only key load；任何缺失或分叉只阻断 remote，不修复或覆盖
//! 已认证 artifact。Runtime DB 的认证、worker、SQLite 或 cipher 错误仍向上返回，
//! 由 daemon 作为全局 Runtime fatal 处理。

use std::fmt;

use agentdeck_crypto::{sha256, sign_authentication_transcript};
use agentdeck_protocol::relay_v2::{
    AuthenticationTranscriptV1, CertRole, Ed25519Signature, MachineRouteId, RelayServerId,
    RootKeyId,
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
    KeyDirectoryGuard, MachineIdentityError, MachineKeyMaterial, install_key_directory_guard,
    load_key_directory_guard, load_machine_key_material,
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
    use super::*;
    use crate::security::MemoryKeyStore;

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
}
