//! Machine identity 的本地 bootstrap/reconciliation。
//!
//! 冻结写入顺序为：四组长期 key exact load/create → authenticated DB Preparing →
//! key-directory guard exact install → authenticated DB Active。已有 Preparing/Active
//! 状态只允许 existing-only key load；任何缺失或分叉只阻断 remote，不修复或覆盖
//! 已认证 artifact。Runtime DB 的认证、worker、SQLite 或 cipher 错误仍向上返回，
//! 由 daemon 作为全局 Runtime fatal 处理。

use std::fmt;

use agentdeck_protocol::relay_v2::RootKeyId;

use crate::local::listener::RemoteStartPermit;
use crate::runtime::store::{
    ActivateMachineIdentityOutcome, MachineIdentityBinding, MachineIdentityLifecycle,
    MachineIdentityStateRecord, PrepareMachineIdentityOutcome, RuntimeCommitOperation,
    RuntimeStoreError, RuntimeStoreHandle,
};
use crate::security::KeyStore;

use super::identity::{
    KeyDirectoryGuard, MachineIdentityError, MachineKeyMaterial, install_key_directory_guard,
    load_key_directory_guard, load_machine_key_material,
    load_or_create_preparing_machine_key_material,
};

const FRESH_TRUST_EPOCH: u64 = 1;
const FRESH_LINK_GENERATION: u64 = 1;
const FRESH_DATA_GENERATION: u64 = 1;
const FRESH_KEY_DIRECTORY_REVISION: u64 = 0;
const ROOT_KEY_ID_ATTEMPTS: usize = 8;

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
    _material: MachineKeyMaterial,
}

impl ActiveMachineIdentity {
    #[must_use]
    pub const fn binding(&self) -> &MachineIdentityBinding {
        &self.state.binding
    }

    /// 把 active key owner 与 listener 产生的一次性 remote-start capability 绑在一起。
    #[must_use]
    pub fn arm(self: Box<Self>, permit: RemoteStartPermit) -> ArmedRemoteIdentity {
        ArmedRemoteIdentity {
            _identity: self,
            _permit: permit,
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
    _identity: Box<ActiveMachineIdentity>,
    _permit: RemoteStartPermit,
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
    remote_enabled: bool,
    store: &RuntimeStoreHandle,
    key_store: &dyn KeyStore,
) -> Result<RemoteBootstrapOutcome, RuntimeStoreError> {
    if !remote_enabled {
        return Ok(RemoteBootstrapOutcome::Disabled);
    }

    let state = store.load_machine_identity_state().await?;
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
        Some(root_key_id) => root_key_id,
        None => {
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
            Box::new(ActiveMachineIdentity {
                state,
                _material: material,
            }),
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
            _material: material,
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

fn fresh_root_key_id() -> Option<[u8; 16]> {
    (0..ROOT_KEY_ID_ATTEMPTS).find_map(|_| {
        let id = RootKeyId::random();
        (*id.as_bytes() != [0; 16]).then_some(*id.as_bytes())
    })
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
