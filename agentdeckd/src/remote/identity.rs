//! Machine identity 的 Keychain material 与 rollback guard IO。
//!
//! 本模块只处理四组长期 key material、key-directory guard 与 counter high-water。
//! 它不拥有网络或配对流程。私钥只以 [`agentdeck_crypto`] 的 typed wrapper 暴露，
//! raw seed/IKM 不进入公开 API、`Debug` 或错误文本。

use std::fmt::{self, Write as _};
use std::sync::{Arc, Mutex, MutexGuard};

use agentdeck_crypto::{HpkePrivateKey, SigningKey, sha256};
use agentdeck_protocol::e2ee::{KeyId, KeyPurpose};
use thiserror::Error;
use zeroize::Zeroizing;

use crate::runtime::store::{MachineIdentityBinding, MachineTrustResetKind};
use crate::security::{KeyStore, KeyStoreError, SecretBytes};

use super::counter::{
    CounterError, CounterGuardBackend, CounterGuardCas, CounterGuardState, CounterScope,
    validate_guard_transition,
};

pub const MACHINE_ROOT_SIGN_ACCOUNT: &str = "machine-root-sign.v1";
pub const MACHINE_HPKE_ACCOUNT: &str = "machine-hpke.v1";
pub const MACHINE_LINK_SIGN_ACCOUNT: &str = "machine-link-sign.v1";
pub const MACHINE_DATA_SIGN_ACCOUNT: &str = "machine-data-sign.v1";
pub const KEY_DIRECTORY_GUARD_ACCOUNT: &str = "key-directory-guard.v1";

const KEY_MATERIAL_LEN: usize = 32;
const KEY_DIRECTORY_GUARD_DOMAIN: &[u8] = b"AgentDeck/KeyDirectoryGuardV1\0";
const COUNTER_GUARD_DOMAIN: &[u8] = b"AgentDeck/CounterGuardV1\0";
const KEY_DIRECTORY_GUARD_ENCODED_LEN: usize = KEY_DIRECTORY_GUARD_DOMAIN.len() + 16 + 32 + 8;
const COUNTER_GUARD_ENCODED_LEN: usize = COUNTER_GUARD_DOMAIN.len() + 1 + 8 + 8;

// Stable daemon 的 singleton lock 排除正常跨进程 writer；该锁再保证同一进程内
// load→validate→store→readback 不会由两个调用交错。恶意同 UID 进程不在安全边界内。
static KEYSTORE_IO: Mutex<()> = Mutex::new(());

#[derive(Debug, Error, PartialEq, Eq)]
pub enum MachineIdentityError {
    #[error("machine identity keystore failed: {0}")]
    KeyStore(#[from] KeyStoreError),
    #[error("machine identity key material is missing from account {account}")]
    MissingKeyMaterial { account: &'static str },
    #[error("machine identity key in account {account} has length {actual}; expected 32")]
    InvalidKeyLength {
        account: &'static str,
        actual: usize,
    },
    #[error("machine identity public key derivation failed for account {account}")]
    InvalidPublicKey { account: &'static str },
    #[error("operating-system entropy source is unavailable")]
    EntropyUnavailable,
    #[error("persisted machine identity item {account} is missing after store")]
    PersistedItemMissing { account: String },
    #[error("persisted machine identity item {account} changed during exact readback")]
    PersistedItemMismatch { account: String },
    #[error("machine identity guard in account {account} has invalid canonical encoding")]
    InvalidGuardEncoding { account: String },
    #[error("key-directory guard conflicts with the existing authenticated identity")]
    KeyDirectoryGuardConflict,
    #[error("key-directory guard database/root binding cannot change during revision advance")]
    KeyDirectoryGuardBindingMismatch,
    #[error(
        "key-directory guard revision cannot stay at or decrease from {current} to {requested}"
    )]
    KeyDirectoryGuardRegression { current: u64, requested: u64 },
    #[error("key-directory guard revision must advance exactly once from {current} to {requested}")]
    KeyDirectoryGuardJump { current: u64, requested: u64 },
    #[error("key-directory guard is missing")]
    KeyDirectoryGuardMissing,
    #[error("counter guard high-water cannot decrease from {current} to {requested}")]
    CounterRegression { current: u64, requested: u64 },
    #[error("scoped counter guard failed: {0}")]
    ScopedCounter(#[from] CounterError),
    #[error("expected root fingerprint does not match the persisted machine identity")]
    RootFingerprintMismatch,
    #[error("deleted machine identity item {account} is still present")]
    DeleteReadbackFailed { account: String },
    #[error("machine identity cleanup binding does not match account {account}")]
    CleanupBindingMismatch { account: &'static str },
    #[error("machine identity cleanup observed a partially missing local state")]
    CleanupPartialState,
    #[error("machine identity cleanup contains a duplicate counter guard axis")]
    CleanupCounterAxisDuplicate,
}

impl MachineIdentityError {
    #[must_use]
    pub const fn code(&self) -> &'static str {
        match self {
            Self::KeyStore(error) => error.code(),
            Self::MissingKeyMaterial { .. } => "daemon.remote.identity.key_missing",
            Self::InvalidKeyLength { .. } | Self::InvalidPublicKey { .. } => {
                "daemon.remote.identity.key_invalid"
            }
            Self::EntropyUnavailable => "daemon.remote.identity.entropy_unavailable",
            Self::PersistedItemMissing { .. } | Self::PersistedItemMismatch { .. } => {
                "daemon.remote.identity.key_persistence_failed"
            }
            Self::InvalidGuardEncoding { .. } => "daemon.remote.identity.guard_invalid",
            Self::KeyDirectoryGuardConflict => "daemon.remote.identity.guard_conflict",
            Self::KeyDirectoryGuardBindingMismatch => {
                "daemon.remote.identity.guard_binding_mismatch"
            }
            Self::KeyDirectoryGuardRegression { .. } => "daemon.remote.identity.guard_regression",
            Self::KeyDirectoryGuardJump { .. } => "daemon.remote.identity.guard_jump",
            Self::KeyDirectoryGuardMissing => "daemon.remote.identity.guard_missing",
            Self::CounterRegression { .. } => "daemon.remote.identity.counter_regression",
            Self::ScopedCounter(error) => error.code(),
            Self::RootFingerprintMismatch => "daemon.remote.identity.fingerprint_mismatch",
            Self::DeleteReadbackFailed { .. } => "daemon.remote.identity.delete_failed",
            Self::CleanupBindingMismatch { .. } => {
                "daemon.remote.identity.cleanup_binding_mismatch"
            }
            Self::CleanupPartialState => "daemon.remote.identity.cleanup_partial_state",
            Self::CleanupCounterAxisDuplicate => {
                "daemon.remote.identity.cleanup_counter_axis_duplicate"
            }
        }
    }
}

#[derive(Clone, Copy, PartialEq, Eq)]
pub struct PublicKeyMaterial {
    public_key: [u8; 32],
    fingerprint: [u8; 32],
}

impl PublicKeyMaterial {
    fn new(public_key: [u8; 32]) -> Self {
        Self {
            public_key,
            fingerprint: sha256(&public_key),
        }
    }

    #[must_use]
    pub const fn public_key(&self) -> &[u8; 32] {
        &self.public_key
    }

    #[must_use]
    pub const fn fingerprint(&self) -> [u8; 32] {
        self.fingerprint
    }
}

impl fmt::Debug for PublicKeyMaterial {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("PublicKeyMaterial([REDACTED])")
    }
}

#[derive(Clone, Copy, PartialEq, Eq)]
pub struct MachinePublicIdentity {
    root: PublicKeyMaterial,
    hpke: PublicKeyMaterial,
    link: PublicKeyMaterial,
    data: PublicKeyMaterial,
}

impl MachinePublicIdentity {
    #[must_use]
    pub const fn root(&self) -> &PublicKeyMaterial {
        &self.root
    }

    #[must_use]
    pub const fn hpke(&self) -> &PublicKeyMaterial {
        &self.hpke
    }

    #[must_use]
    pub const fn link(&self) -> &PublicKeyMaterial {
        &self.link
    }

    #[must_use]
    pub const fn data(&self) -> &PublicKeyMaterial {
        &self.data
    }
}

impl fmt::Debug for MachinePublicIdentity {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("MachinePublicIdentity([REDACTED])")
    }
}

pub struct MachineKeyMaterial {
    root: SigningKey,
    hpke: HpkePrivateKey,
    link: SigningKey,
    data: SigningKey,
    public_identity: MachinePublicIdentity,
}

impl MachineKeyMaterial {
    #[must_use]
    pub const fn public_identity(&self) -> &MachinePublicIdentity {
        &self.public_identity
    }

    #[must_use]
    pub const fn root_signing_key(&self) -> &SigningKey {
        &self.root
    }

    #[must_use]
    pub const fn hpke_private_key(&self) -> &HpkePrivateKey {
        &self.hpke
    }

    #[must_use]
    pub const fn link_signing_key(&self) -> &SigningKey {
        &self.link
    }

    #[must_use]
    pub const fn data_signing_key(&self) -> &SigningKey {
        &self.data
    }
}

impl fmt::Debug for MachineKeyMaterial {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("MachineKeyMaterial([REDACTED])")
    }
}

#[derive(Clone, Copy, PartialEq, Eq)]
pub struct KeyDirectoryGuard {
    database_id: [u8; 16],
    root_fingerprint: [u8; 32],
    key_directory_revision: u64,
}

impl KeyDirectoryGuard {
    #[must_use]
    pub const fn new(
        database_id: [u8; 16],
        root_fingerprint: [u8; 32],
        key_directory_revision: u64,
    ) -> Self {
        Self {
            database_id,
            root_fingerprint,
            key_directory_revision,
        }
    }

    #[must_use]
    pub const fn database_id(&self) -> [u8; 16] {
        self.database_id
    }

    #[must_use]
    pub const fn root_fingerprint(&self) -> [u8; 32] {
        self.root_fingerprint
    }

    #[must_use]
    pub const fn key_directory_revision(&self) -> u64 {
        self.key_directory_revision
    }
}

impl fmt::Debug for KeyDirectoryGuard {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("KeyDirectoryGuard")
            .field("database_id", &"[REDACTED]")
            .field("root_fingerprint", &"[REDACTED]")
            .field("key_directory_revision", &self.key_directory_revision)
            .finish()
    }
}

#[derive(Clone, Copy, PartialEq, Eq)]
pub struct CounterGuard {
    key_id: KeyId,
    high_water: u64,
}

impl CounterGuard {
    #[must_use]
    pub const fn key_id(&self) -> KeyId {
        self.key_id
    }

    #[must_use]
    pub const fn high_water(&self) -> u64 {
        self.high_water
    }
}

impl fmt::Debug for CounterGuard {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("CounterGuard")
            .field("key_id", &self.key_id)
            .field("high_water", &self.high_water)
            .finish()
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(super) enum MachineIdentityCleanupOutcome {
    Deleted,
    AlreadyAbsent,
}

/// Existing-only load。Active/Preparing reconciliation 使用本入口；缺任一 item 都失败且零写。
pub fn load_machine_key_material(
    key_store: &dyn KeyStore,
) -> Result<MachineKeyMaterial, MachineIdentityError> {
    let _guard = lock_keystore_io()?;
    load_machine_key_material_unlocked(key_store)
}

/// 仅供同一模块内 bootstrap 在确认 DB identity row 与 key-directory guard **均不存在**
/// 后调用。它先验证全部既有 item，再只补 missing account，绝不覆盖已有 material。
pub(super) fn load_or_create_preparing_machine_key_material(
    key_store: &dyn KeyStore,
) -> Result<MachineKeyMaterial, MachineIdentityError> {
    let _guard = lock_keystore_io()?;
    let mut raw = load_raw_material_unlocked(key_store)?;
    // 必须先完成所有 existing-item validation，之后才允许产生第一笔写入。
    validate_present_raw_material(&raw)?;
    fill_missing_material(key_store, &mut raw)?;
    material_from_complete_raw(raw)
}

pub fn delete_machine_key_material(
    key_store: &dyn KeyStore,
    expected_root_fingerprint: [u8; 32],
) -> Result<(), MachineIdentityError> {
    let _guard = lock_keystore_io()?;
    let raw = load_raw_material_unlocked(key_store)?;
    validate_present_raw_material(&raw)?;
    let root = raw
        .root
        .as_ref()
        .ok_or(MachineIdentityError::MissingKeyMaterial {
            account: MACHINE_ROOT_SIGN_ACCOUNT,
        })?;
    let root_public = signing_public(root);
    if sha256(&root_public) != expected_root_fingerprint {
        return Err(MachineIdentityError::RootFingerprintMismatch);
    }

    let present = [
        raw.data.is_some(),
        raw.link.is_some(),
        raw.hpke.is_some(),
        raw.root.is_some(),
    ];
    // Root 最后删除，保证任一中途失败后仍可用 expected fingerprint 安全重试。
    for (account, is_present) in [
        (MACHINE_DATA_SIGN_ACCOUNT, present[0]),
        (MACHINE_LINK_SIGN_ACCOUNT, present[1]),
        (MACHINE_HPKE_ACCOUNT, present[2]),
        (MACHINE_ROOT_SIGN_ACCOUNT, present[3]),
    ] {
        if is_present {
            delete_exact(key_store, account)?;
        }
    }
    Ok(())
}

pub fn load_key_directory_guard(
    key_store: &dyn KeyStore,
) -> Result<Option<KeyDirectoryGuard>, MachineIdentityError> {
    let _guard = lock_keystore_io()?;
    load_key_directory_guard_unlocked(key_store)
}

pub fn install_key_directory_guard(
    key_store: &dyn KeyStore,
    guard: KeyDirectoryGuard,
) -> Result<KeyDirectoryGuard, MachineIdentityError> {
    let _lock = lock_keystore_io()?;
    if let Some(existing) = load_key_directory_guard_unlocked(key_store)? {
        if existing == guard {
            return Ok(existing);
        }
        return Err(MachineIdentityError::KeyDirectoryGuardConflict);
    }

    let encoded = encode_key_directory_guard(guard);
    store_exact(key_store, KEY_DIRECTORY_GUARD_ACCOUNT, &encoded)?;
    let persisted = load_key_directory_guard_unlocked(key_store)?.ok_or_else(|| {
        MachineIdentityError::PersistedItemMissing {
            account: KEY_DIRECTORY_GUARD_ACCOUNT.to_owned(),
        }
    })?;
    if persisted != guard {
        return Err(MachineIdentityError::PersistedItemMismatch {
            account: KEY_DIRECTORY_GUARD_ACCOUNT.to_owned(),
        });
    }
    Ok(persisted)
}

/// 在新 key-directory revision 可用于 seal/dispatch 前，以完整旧 guard 推进其唯一后继。
///
/// CAS 的 expected/next 都绑定同一 database ID 与 MachineRoot fingerprint，revision
/// 只能递增 1。调用方必须把本 primitive 与可恢复的 durable Store transition 共同编排；
/// 若前一次 CAS 已成功但周边 transition 尚未完成，同一 old→new 调用只读重放。任何其他
/// 现值、绑定漂移、回退或跳号都 fail-close，且不会覆盖既有 guard。
pub fn advance_key_directory_guard(
    key_store: &dyn KeyStore,
    expected: KeyDirectoryGuard,
    next: KeyDirectoryGuard,
) -> Result<KeyDirectoryGuard, MachineIdentityError> {
    if !same_key_directory_binding(expected, next) {
        return Err(MachineIdentityError::KeyDirectoryGuardBindingMismatch);
    }
    if next.key_directory_revision <= expected.key_directory_revision {
        return Err(MachineIdentityError::KeyDirectoryGuardRegression {
            current: expected.key_directory_revision,
            requested: next.key_directory_revision,
        });
    }
    if expected.key_directory_revision.checked_add(1) != Some(next.key_directory_revision) {
        return Err(MachineIdentityError::KeyDirectoryGuardJump {
            current: expected.key_directory_revision,
            requested: next.key_directory_revision,
        });
    }

    let _lock = lock_keystore_io()?;
    let current = load_key_directory_guard_unlocked(key_store)?
        .ok_or(MachineIdentityError::KeyDirectoryGuardMissing)?;
    if current == next {
        return Ok(current);
    }
    if !same_key_directory_binding(current, expected) {
        return Err(MachineIdentityError::KeyDirectoryGuardBindingMismatch);
    }
    if current != expected {
        return Err(MachineIdentityError::KeyDirectoryGuardConflict);
    }

    let encoded = encode_key_directory_guard(next);
    store_exact(key_store, KEY_DIRECTORY_GUARD_ACCOUNT, &encoded)?;
    let persisted = load_key_directory_guard_unlocked(key_store)?.ok_or_else(|| {
        MachineIdentityError::PersistedItemMissing {
            account: KEY_DIRECTORY_GUARD_ACCOUNT.to_owned(),
        }
    })?;
    if persisted != next {
        return Err(MachineIdentityError::PersistedItemMismatch {
            account: KEY_DIRECTORY_GUARD_ACCOUNT.to_owned(),
        });
    }
    Ok(persisted)
}

pub fn delete_key_directory_guard(
    key_store: &dyn KeyStore,
    expected_root_fingerprint: [u8; 32],
) -> Result<bool, MachineIdentityError> {
    let _lock = lock_keystore_io()?;
    let Some(guard) = load_key_directory_guard_unlocked(key_store)? else {
        return Ok(false);
    };
    ensure_root_fingerprint(guard, expected_root_fingerprint)?;
    delete_exact(key_store, KEY_DIRECTORY_GUARD_ACCOUNT)?;
    Ok(true)
}

#[must_use]
pub fn counter_guard_account(key_id: KeyId) -> String {
    format!(
        "counter-guard/{}/{}",
        key_purpose_account_component(key_id.purpose),
        key_id.epoch
    )
}

pub fn load_counter_guard(
    key_store: &dyn KeyStore,
    key_id: KeyId,
) -> Result<Option<CounterGuard>, MachineIdentityError> {
    let _lock = lock_keystore_io()?;
    load_counter_guard_unlocked(key_store, key_id)
}

pub fn advance_counter_guard(
    key_store: &dyn KeyStore,
    key_id: KeyId,
    requested_high_water: u64,
) -> Result<CounterGuard, MachineIdentityError> {
    let _lock = lock_keystore_io()?;
    if let Some(current) = load_counter_guard_unlocked(key_store, key_id)? {
        if requested_high_water < current.high_water {
            return Err(MachineIdentityError::CounterRegression {
                current: current.high_water,
                requested: requested_high_water,
            });
        }
        if requested_high_water == current.high_water {
            return Ok(current);
        }
    }

    let next = CounterGuard {
        key_id,
        high_water: requested_high_water,
    };
    let account = counter_guard_account(key_id);
    store_exact(key_store, &account, &encode_counter_guard(next))?;
    let persisted = load_counter_guard_unlocked(key_store, key_id)?.ok_or_else(|| {
        MachineIdentityError::PersistedItemMissing {
            account: account.clone(),
        }
    })?;
    if persisted != next {
        return Err(MachineIdentityError::PersistedItemMismatch { account });
    }
    Ok(persisted)
}

pub fn delete_counter_guard(
    key_store: &dyn KeyStore,
    key_id: KeyId,
    expected_root_fingerprint: [u8; 32],
) -> Result<bool, MachineIdentityError> {
    let _lock = lock_keystore_io()?;
    let directory_guard = load_key_directory_guard_unlocked(key_store)?
        .ok_or(MachineIdentityError::KeyDirectoryGuardMissing)?;
    ensure_root_fingerprint(directory_guard, expected_root_fingerprint)?;
    if load_counter_guard_unlocked(key_store, key_id)?.is_none() {
        return Ok(false);
    }
    let account = counter_guard_account(key_id);
    delete_exact(key_store, &account)?;
    Ok(true)
}

/// V2 CounterGuard 的 Keychain account。只暴露完整 nonce scope 的 SHA-256 token，
/// 不把 route、grant、trust epoch 或 key material 写入 account 文本。
#[must_use]
pub fn scoped_counter_guard_account(scope: &CounterScope) -> String {
    encode_scoped_counter_guard_account(scope.token())
}

/// 从 Store 已认证 manifest 中的完整 scope token 恢复 V2 CounterGuard account。
///
/// 本入口不接受零 token；调用方仍须先完成 Store manifest 的 MAC/ledger 审计，不能把
/// 未认证磁盘字节直接当作 Keychain account capability。
pub(crate) fn scoped_counter_guard_account_from_token(
    scope_token: [u8; 32],
) -> Result<String, MachineIdentityError> {
    validate_scoped_counter_guard_token(scope_token)?;
    Ok(encode_scoped_counter_guard_account(scope_token))
}

fn encode_scoped_counter_guard_account(scope_token: [u8; 32]) -> String {
    let mut account = String::with_capacity("counter-guard-v2/".len() + 64);
    account.push_str("counter-guard-v2/");
    for byte in scope_token {
        // 写入 String 不会失败；避免引入另一套 hex 编码依赖。
        write!(&mut account, "{byte:02x}").expect("writing to String is infallible");
    }
    account
}

/// Existing-only 读取 Store 已认证 token 对应的 V2 CounterGuard。
///
/// 已存在 item 必须通过 canonical decode，且其内嵌 token 必须与 account token
/// 完全一致；缺失只返回 `None`，不创建、不覆盖。
pub(crate) fn load_scoped_counter_guard_for_token(
    key_store: &dyn KeyStore,
    scope_token: [u8; 32],
) -> Result<Option<CounterGuardState>, MachineIdentityError> {
    let _lock = lock_keystore_io()?;
    load_scoped_counter_guard_for_token_unlocked(key_store, scope_token)
}

/// Existing-only 删除 Store 已认证 token 对应的 V2 CounterGuard。
///
/// 第一笔 mutation 前先完成 canonical decode/token 校验；已缺失时零写返回
/// `false`，已存在时删除后必须精确读回 absent 才返回 `true`。
#[allow(dead_code)] // P4.5 trust-reset/counter GC 接线将在本 Task 后续消费该低层 seam。
pub(crate) fn delete_scoped_counter_guard_for_token(
    key_store: &dyn KeyStore,
    scope_token: [u8; 32],
) -> Result<bool, MachineIdentityError> {
    let _lock = lock_keystore_io()?;
    if load_scoped_counter_guard_for_token_unlocked(key_store, scope_token)?.is_none() {
        return Ok(false);
    }
    let account = scoped_counter_guard_account_from_token(scope_token)?;
    delete_exact(key_store, &account)?;
    Ok(true)
}

/// running daemon counter GC 的单临界区 batch delete。`scope_tokens` 必须来自 Store
/// authenticated exact plan 且严格排序；函数在第一笔 mutation 前 canonical decode
/// 全部现存 guard/embedded token，随后 existing-only 删除并逐项 exact absent readback。
/// Reserved+absent 合法且零写，不会补建 Keychain item。
pub(crate) fn delete_scoped_counter_guards_for_tokens(
    key_store: &dyn KeyStore,
    scope_tokens: &[[u8; 32]],
) -> Result<u64, MachineIdentityError> {
    let _lock = lock_keystore_io()?;
    let mut previous = None;
    let mut accounts = Vec::with_capacity(scope_tokens.len());
    for scope_token in scope_tokens.iter().copied() {
        if previous.is_some_and(|value| value >= scope_token) {
            return Err(MachineIdentityError::CleanupCounterAxisDuplicate);
        }
        let account = scoped_counter_guard_account_from_token(scope_token)?;
        accounts.push((scope_token, account));
        previous = Some(scope_token);
    }
    let mut guards = Vec::with_capacity(accounts.len());
    for (scope_token, account) in accounts {
        let guard = load_scoped_counter_guard_for_token_unlocked(key_store, scope_token)?;
        guards.push((account, guard));
    }
    let mut deleted = 0_u64;
    for (account, guard) in guards {
        if guard.is_some() {
            delete_exact(key_store, &account)?;
            deleted += 1;
        }
    }
    Ok(deleted)
}

/// stopped-daemon purge finalizer 的 V2-only batch cleanup。
///
/// `manifest` 必须来自 existing-only authenticated Runtime rescue read。全部现存 guard
/// 在第一笔删除前完成 canonical decode 与 embedded-token 校验；Root-present retry 只
/// 接受既定删除顺序产生的 absent-prefix，Reserved+absent 不参与该前缀。每笔删除均
/// exact absent readback，整个 batch 与同进程 CounterGuard IO 共用一个临界区。
pub(crate) fn cleanup_scoped_counter_guards(
    key_store: &dyn KeyStore,
    reset_kind: MachineTrustResetKind,
    manifest: &[([u8; 32], bool)],
) -> Result<(), MachineIdentityError> {
    let _lock = lock_keystore_io()?;
    let mut previous = None;
    let guards = manifest
        .iter()
        .copied()
        .map(|(scope_token, materialized)| {
            if previous.is_some_and(|value| value >= scope_token) {
                return Err(MachineIdentityError::CleanupCounterAxisDuplicate);
            }
            previous = Some(scope_token);
            let account = scoped_counter_guard_account_from_token(scope_token)?;
            let guard = load_scoped_counter_guard_for_token_unlocked(key_store, scope_token)?;
            Ok((account, guard, materialized || guard.is_some()))
        })
        .collect::<Result<Vec<_>, MachineIdentityError>>()?;

    if reset_kind == MachineTrustResetKind::RootPresent {
        let presence = guards
            .iter()
            .filter(|(_, _, participates)| *participates)
            .map(|(_, guard, _)| guard.is_some())
            .collect::<Vec<_>>();
        if !is_legal_cleanup_prefix(&presence) {
            return Err(MachineIdentityError::CleanupPartialState);
        }
    }
    for (account, guard, _) in guards {
        if guard.is_some() {
            delete_exact(key_store, &account)?;
        }
    }
    Ok(())
}

/// finalizer 全局 preflight 使用的 existing-only V2 batch audit。所有现存 item 都必须
/// canonical decode 且 embedded token 与 authenticated manifest 一致；零写入。
pub(crate) fn validate_scoped_counter_guards(
    key_store: &dyn KeyStore,
    manifest: &[([u8; 32], bool)],
) -> Result<(), MachineIdentityError> {
    let _lock = lock_keystore_io()?;
    let mut previous = None;
    for (scope_token, _) in manifest.iter().copied() {
        if previous.is_some_and(|value| value >= scope_token) {
            return Err(MachineIdentityError::CleanupCounterAxisDuplicate);
        }
        let _ = load_scoped_counter_guard_for_token_unlocked(key_store, scope_token)?;
        previous = Some(scope_token);
    }
    Ok(())
}

/// stable daemon 的真实 KeyStore-backed CounterGuard compare-and-swap adapter。
///
/// daemon singleton 排除正常跨进程 writer；`KEYSTORE_IO` 再把同进程内的
/// load→compare→store→exact readback 固定在一个临界区。同 UID 在线攻击者不在威胁边界内。
pub struct KeyStoreCounterGuardBackend<'a> {
    key_store: &'a dyn KeyStore,
}

impl<'a> KeyStoreCounterGuardBackend<'a> {
    #[must_use]
    pub const fn new(key_store: &'a dyn KeyStore) -> Self {
        Self { key_store }
    }
}

impl fmt::Debug for KeyStoreCounterGuardBackend<'_> {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("KeyStoreCounterGuardBackend([REDACTED])")
    }
}

impl CounterGuardBackend for KeyStoreCounterGuardBackend<'_> {
    type Error = MachineIdentityError;

    fn load_guard(&self, scope: &CounterScope) -> Result<Option<CounterGuardState>, Self::Error> {
        load_scoped_counter_guard(self.key_store, scope)
    }

    fn compare_and_swap_guard(
        &self,
        scope: &CounterScope,
        expected: Option<CounterGuardState>,
        next: CounterGuardState,
    ) -> Result<CounterGuardCas, Self::Error> {
        compare_and_swap_counter_guard(self.key_store, scope, expected, next)
    }
}

/// 长生命周期 remote/publication owner 使用的 `'static` CounterGuard adapter。它只延长
/// KeyStore capability 的进程内生命周期，不复制任何 key material。
#[derive(Clone)]
pub struct OwnedKeyStoreCounterGuardBackend {
    key_store: Arc<dyn KeyStore>,
}

impl OwnedKeyStoreCounterGuardBackend {
    #[must_use]
    pub fn new(key_store: Arc<dyn KeyStore>) -> Self {
        Self { key_store }
    }
}

impl fmt::Debug for OwnedKeyStoreCounterGuardBackend {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("OwnedKeyStoreCounterGuardBackend([REDACTED])")
    }
}

impl CounterGuardBackend for OwnedKeyStoreCounterGuardBackend {
    type Error = MachineIdentityError;

    fn load_guard(&self, scope: &CounterScope) -> Result<Option<CounterGuardState>, Self::Error> {
        load_scoped_counter_guard(self.key_store.as_ref(), scope)
    }

    fn compare_and_swap_guard(
        &self,
        scope: &CounterScope,
        expected: Option<CounterGuardState>,
        next: CounterGuardState,
    ) -> Result<CounterGuardCas, Self::Error> {
        compare_and_swap_counter_guard(self.key_store.as_ref(), scope, expected, next)
    }
}

fn load_scoped_counter_guard(
    key_store: &dyn KeyStore,
    scope: &CounterScope,
) -> Result<Option<CounterGuardState>, MachineIdentityError> {
    load_scoped_counter_guard_for_token(key_store, scope.token())
}

fn compare_and_swap_counter_guard(
    key_store: &dyn KeyStore,
    scope: &CounterScope,
    expected: Option<CounterGuardState>,
    next: CounterGuardState,
) -> Result<CounterGuardCas, MachineIdentityError> {
    if expected.is_some_and(|state| state.token() != scope.token()) || next.token() != scope.token()
    {
        return Err(CounterError::ScopeMismatch.into());
    }

    let _lock = lock_keystore_io()?;
    let current = load_scoped_counter_guard_unlocked(key_store, scope)?;
    if current != expected {
        return Ok(CounterGuardCas::Conflict(current));
    }
    validate_guard_transition(current, next)?;

    // 幂等 CAS 仍已在本临界区完成 canonical load/decode；无需产生第二笔覆盖写。
    if current == Some(next) {
        return Ok(CounterGuardCas::Swapped(next));
    }

    let account = scoped_counter_guard_account(scope);
    let encoded = next.encode();
    store_exact(key_store, &account, &encoded)?;
    let persisted = load_scoped_counter_guard_unlocked(key_store, scope)?.ok_or_else(|| {
        MachineIdentityError::PersistedItemMissing {
            account: account.clone(),
        }
    })?;
    if persisted != next {
        return Err(MachineIdentityError::PersistedItemMismatch { account });
    }
    Ok(CounterGuardCas::Swapped(persisted))
}

/// 只消费 Store 已认证的 machine binding、database ID、V2 scope manifest 与 legacy axes。
///
/// 所有现存 item 都会在第一笔删除前完成 existing-only 校验。Root-present 只接受固定
/// 删除顺序产生的 prefix-absent 形态；Root-lost 已由 portable admin purge receipt
/// 授权，允许任意 item 已缺失，但所有剩余 material 仍须逐项匹配。Root 永远最后删除。
pub(super) fn cleanup_machine_identity(
    key_store: &dyn KeyStore,
    database_id: [u8; 16],
    binding: &MachineIdentityBinding,
    reset_kind: MachineTrustResetKind,
    counter_guard_scopes: &[([u8; 32], bool)],
    counter_guard_axes: &[KeyId],
) -> Result<MachineIdentityCleanupOutcome, MachineIdentityError> {
    let _lock = lock_keystore_io()?;
    ensure_unique_counter_axes(counter_guard_axes)?;

    let raw = load_raw_material_unlocked(key_store)?;
    validate_present_raw_material(&raw)?;
    let directory_guard = load_key_directory_guard_unlocked(key_store)?;
    let scoped_counter_guards = counter_guard_scopes
        .iter()
        .copied()
        .map(|(scope_token, materialized)| {
            let account = scoped_counter_guard_account_from_token(scope_token)?;
            let guard = load_scoped_counter_guard_for_token_unlocked(key_store, scope_token)?;
            // Reserved+absent 是“已登记但从未生成 guard”的合法状态，不参与
            // root-present 删除前缀；Reserved+present 覆盖 guard CAS 后、manifest
            // phase COMMIT 前的 crash gap，仍须 existing-only 删除。
            Ok((account, guard, materialized || guard.is_some()))
        })
        .collect::<Result<Vec<_>, MachineIdentityError>>()?;
    let counter_guards = counter_guard_axes
        .iter()
        .copied()
        .map(|key_id| load_counter_guard_unlocked(key_store, key_id).map(|guard| (key_id, guard)))
        .collect::<Result<Vec<_>, _>>()?;

    validate_cleanup_binding(binding)?;
    if let Some(directory_guard) = directory_guard {
        let expected_guard = KeyDirectoryGuard::new(
            database_id,
            binding.root_fingerprint,
            binding.key_directory_revision,
        );
        if directory_guard != expected_guard {
            return Err(MachineIdentityError::CleanupBindingMismatch {
                account: KEY_DIRECTORY_GUARD_ACCOUNT,
            });
        }
    }
    validate_cleanup_material(&raw, binding)?;

    let all_keys_absent =
        raw.root.is_none() && raw.hpke.is_none() && raw.link.is_none() && raw.data.is_none();
    let all_counters_absent = scoped_counter_guards
        .iter()
        .all(|(_, guard, _)| guard.is_none())
        && counter_guards.iter().all(|(_, guard)| guard.is_none());
    if all_keys_absent && directory_guard.is_none() && all_counters_absent {
        return Ok(MachineIdentityCleanupOutcome::AlreadyAbsent);
    }

    // 删除序列是 V2 scopes → legacy counters → data → link → hpke → directory guard → root。
    // Root-present crash/retry 只接受该序列产生的 `absent* present*` 前缀；任何
    // 跳序缺失都在下一笔 mutation 前 fail-close。Root-lost 已先验证 portable
    // admin receipt，可以 existing-only 清除任意 surviving item，不补建缺失项。
    let mut presence = scoped_counter_guards
        .iter()
        .filter(|(_, _, participates_in_prefix)| *participates_in_prefix)
        .map(|(_, guard, _)| guard.is_some())
        .chain(counter_guards.iter().map(|(_, guard)| guard.is_some()))
        .collect::<Vec<_>>();
    presence.extend([
        raw.data.is_some(),
        raw.link.is_some(),
        raw.hpke.is_some(),
        directory_guard.is_some(),
    ]);
    if reset_kind == MachineTrustResetKind::RootPresent {
        presence.push(raw.root.is_some());
        if !is_legal_cleanup_prefix(&presence) {
            return Err(MachineIdentityError::CleanupPartialState);
        }
    }

    for (account, guard, _) in &scoped_counter_guards {
        if guard.is_some() {
            delete_exact(key_store, account)?;
        }
    }
    for (key_id, guard) in &counter_guards {
        if guard.is_some() {
            delete_exact(key_store, &counter_guard_account(*key_id))?;
        }
    }
    // 非 root key 先删；任何时候都把 root 留作最后一项。
    if raw.data.is_some() {
        delete_exact(key_store, MACHINE_DATA_SIGN_ACCOUNT)?;
    }
    if raw.link.is_some() {
        delete_exact(key_store, MACHINE_LINK_SIGN_ACCOUNT)?;
    }
    if raw.hpke.is_some() {
        delete_exact(key_store, MACHINE_HPKE_ACCOUNT)?;
    }
    if directory_guard.is_some() {
        delete_exact(key_store, KEY_DIRECTORY_GUARD_ACCOUNT)?;
    }
    if raw.root.is_some() {
        delete_exact(key_store, MACHINE_ROOT_SIGN_ACCOUNT)?;
    }

    Ok(MachineIdentityCleanupOutcome::Deleted)
}

fn is_legal_cleanup_prefix(presence: &[bool]) -> bool {
    let mut saw_present = false;
    for is_present in presence {
        if *is_present {
            saw_present = true;
        } else if saw_present {
            return false;
        }
    }
    true
}

fn ensure_unique_counter_axes(counter_guard_axes: &[KeyId]) -> Result<(), MachineIdentityError> {
    for (index, key_id) in counter_guard_axes.iter().enumerate() {
        if counter_guard_axes[..index].contains(key_id) {
            return Err(MachineIdentityError::CleanupCounterAxisDuplicate);
        }
    }
    Ok(())
}

fn validate_cleanup_binding(binding: &MachineIdentityBinding) -> Result<(), MachineIdentityError> {
    for (account, public_key, fingerprint) in [
        (
            MACHINE_ROOT_SIGN_ACCOUNT,
            &binding.root_public_key,
            binding.root_fingerprint,
        ),
        (
            MACHINE_HPKE_ACCOUNT,
            &binding.machine_hpke_public_key,
            binding.machine_hpke_fingerprint,
        ),
        (
            MACHINE_LINK_SIGN_ACCOUNT,
            &binding.link_sign_public_key,
            binding.link_sign_fingerprint,
        ),
        (
            MACHINE_DATA_SIGN_ACCOUNT,
            &binding.data_sign_public_key,
            binding.data_sign_fingerprint,
        ),
    ] {
        if sha256(public_key) != fingerprint {
            return Err(MachineIdentityError::CleanupBindingMismatch { account });
        }
    }
    Ok(())
}

fn validate_cleanup_material(
    raw: &RawMaterial,
    binding: &MachineIdentityBinding,
) -> Result<(), MachineIdentityError> {
    if let Some(root) = &raw.root {
        ensure_cleanup_public_matches(
            MACHINE_ROOT_SIGN_ACCOUNT,
            signing_public(root),
            binding.root_public_key,
            binding.root_fingerprint,
        )?;
    }
    if let Some(hpke) = &raw.hpke {
        let (_, hpke_public) = HpkePrivateKey::derive_keypair(hpke.as_ref());
        ensure_cleanup_public_matches(
            MACHINE_HPKE_ACCOUNT,
            array32(hpke_public.to_bytes(), MACHINE_HPKE_ACCOUNT)?,
            binding.machine_hpke_public_key,
            binding.machine_hpke_fingerprint,
        )?;
    }
    if let Some(link) = &raw.link {
        ensure_cleanup_public_matches(
            MACHINE_LINK_SIGN_ACCOUNT,
            signing_public(link),
            binding.link_sign_public_key,
            binding.link_sign_fingerprint,
        )?;
    }
    if let Some(data) = &raw.data {
        ensure_cleanup_public_matches(
            MACHINE_DATA_SIGN_ACCOUNT,
            signing_public(data),
            binding.data_sign_public_key,
            binding.data_sign_fingerprint,
        )?;
    }
    Ok(())
}

fn ensure_cleanup_public_matches(
    account: &'static str,
    actual_public_key: [u8; 32],
    expected_public_key: [u8; 32],
    expected_fingerprint: [u8; 32],
) -> Result<(), MachineIdentityError> {
    if actual_public_key != expected_public_key
        || sha256(&actual_public_key) != expected_fingerprint
    {
        return Err(MachineIdentityError::CleanupBindingMismatch { account });
    }
    Ok(())
}

#[derive(Clone, Copy)]
enum KeyKind {
    Signing,
    Hpke,
}

struct RawMaterial {
    root: Option<Zeroizing<[u8; 32]>>,
    hpke: Option<Zeroizing<[u8; 32]>>,
    link: Option<Zeroizing<[u8; 32]>>,
    data: Option<Zeroizing<[u8; 32]>>,
}

fn lock_keystore_io() -> Result<MutexGuard<'static, ()>, MachineIdentityError> {
    KEYSTORE_IO
        .lock()
        .map_err(|_| MachineIdentityError::KeyStore(KeyStoreError::Poisoned))
}

fn load_machine_key_material_unlocked(
    key_store: &dyn KeyStore,
) -> Result<MachineKeyMaterial, MachineIdentityError> {
    let raw = load_raw_material_unlocked(key_store)?;
    validate_present_raw_material(&raw)?;
    material_from_complete_raw(raw)
}

fn load_raw_material_unlocked(
    key_store: &dyn KeyStore,
) -> Result<RawMaterial, MachineIdentityError> {
    Ok(RawMaterial {
        root: load_optional_raw(key_store, MACHINE_ROOT_SIGN_ACCOUNT)?,
        hpke: load_optional_raw(key_store, MACHINE_HPKE_ACCOUNT)?,
        link: load_optional_raw(key_store, MACHINE_LINK_SIGN_ACCOUNT)?,
        data: load_optional_raw(key_store, MACHINE_DATA_SIGN_ACCOUNT)?,
    })
}

fn validate_present_raw_material(raw: &RawMaterial) -> Result<(), MachineIdentityError> {
    for (account, kind, value) in [
        (MACHINE_ROOT_SIGN_ACCOUNT, KeyKind::Signing, &raw.root),
        (MACHINE_HPKE_ACCOUNT, KeyKind::Hpke, &raw.hpke),
        (MACHINE_LINK_SIGN_ACCOUNT, KeyKind::Signing, &raw.link),
        (MACHINE_DATA_SIGN_ACCOUNT, KeyKind::Signing, &raw.data),
    ] {
        if let Some(value) = value {
            validate_raw_key(account, kind, value)?;
        }
    }
    Ok(())
}

fn fill_missing_material(
    key_store: &dyn KeyStore,
    raw: &mut RawMaterial,
) -> Result<(), MachineIdentityError> {
    for (account, slot) in [
        (MACHINE_ROOT_SIGN_ACCOUNT, &mut raw.root),
        (MACHINE_HPKE_ACCOUNT, &mut raw.hpke),
        (MACHINE_LINK_SIGN_ACCOUNT, &mut raw.link),
        (MACHINE_DATA_SIGN_ACCOUNT, &mut raw.data),
    ] {
        if slot.is_none() {
            *slot = Some(generate_and_persist_raw(key_store, account)?);
        }
    }
    Ok(())
}

fn material_from_complete_raw(
    raw: RawMaterial,
) -> Result<MachineKeyMaterial, MachineIdentityError> {
    let root_seed = raw.root.ok_or(MachineIdentityError::MissingKeyMaterial {
        account: MACHINE_ROOT_SIGN_ACCOUNT,
    })?;
    let hpke_ikm = raw.hpke.ok_or(MachineIdentityError::MissingKeyMaterial {
        account: MACHINE_HPKE_ACCOUNT,
    })?;
    let link_seed = raw.link.ok_or(MachineIdentityError::MissingKeyMaterial {
        account: MACHINE_LINK_SIGN_ACCOUNT,
    })?;
    let data_seed = raw.data.ok_or(MachineIdentityError::MissingKeyMaterial {
        account: MACHINE_DATA_SIGN_ACCOUNT,
    })?;

    let root = SigningKey::from_seed(&root_seed);
    let (hpke, hpke_public) = HpkePrivateKey::derive_keypair(hpke_ikm.as_ref());
    let link = SigningKey::from_seed(&link_seed);
    let data = SigningKey::from_seed(&data_seed);
    let hpke_public = array32(hpke_public.to_bytes(), MACHINE_HPKE_ACCOUNT)?;
    let public_identity = MachinePublicIdentity {
        root: PublicKeyMaterial::new(root.verifying_key().to_bytes()),
        hpke: PublicKeyMaterial::new(hpke_public),
        link: PublicKeyMaterial::new(link.verifying_key().to_bytes()),
        data: PublicKeyMaterial::new(data.verifying_key().to_bytes()),
    };
    Ok(MachineKeyMaterial {
        root,
        hpke,
        link,
        data,
        public_identity,
    })
}

fn signing_public(seed: &[u8; 32]) -> [u8; 32] {
    SigningKey::from_seed(seed).verifying_key().to_bytes()
}

fn validate_raw_key(
    account: &'static str,
    kind: KeyKind,
    raw: &[u8; 32],
) -> Result<(), MachineIdentityError> {
    match kind {
        KeyKind::Signing => {
            let _ = signing_public(raw);
        }
        KeyKind::Hpke => {
            let (_, public) = HpkePrivateKey::derive_keypair(raw);
            let _ = array32(public.to_bytes(), account)?;
        }
    }
    Ok(())
}

fn load_optional_raw(
    key_store: &dyn KeyStore,
    account: &'static str,
) -> Result<Option<Zeroizing<[u8; 32]>>, MachineIdentityError> {
    key_store
        .load(account)?
        .map(|secret| raw_array(account, secret))
        .transpose()
}

fn load_required_raw(
    key_store: &dyn KeyStore,
    account: &'static str,
) -> Result<Zeroizing<[u8; 32]>, MachineIdentityError> {
    load_optional_raw(key_store, account)?
        .ok_or(MachineIdentityError::MissingKeyMaterial { account })
}

fn raw_array(
    account: &'static str,
    secret: SecretBytes,
) -> Result<Zeroizing<[u8; 32]>, MachineIdentityError> {
    let actual = secret.expose_secret().len();
    if actual != KEY_MATERIAL_LEN {
        return Err(MachineIdentityError::InvalidKeyLength { account, actual });
    }
    let mut raw = Zeroizing::new([0_u8; 32]);
    raw.copy_from_slice(secret.expose_secret());
    Ok(raw)
}

fn generate_and_persist_raw(
    key_store: &dyn KeyStore,
    account: &'static str,
) -> Result<Zeroizing<[u8; 32]>, MachineIdentityError> {
    let mut raw = Zeroizing::new([0_u8; 32]);
    getrandom::fill(raw.as_mut()).map_err(|_| MachineIdentityError::EntropyUnavailable)?;
    store_exact(key_store, account, raw.as_ref())?;
    load_required_raw(key_store, account)
}

fn store_exact(
    key_store: &dyn KeyStore,
    account: &str,
    expected: &[u8],
) -> Result<(), MachineIdentityError> {
    let secret = SecretBytes::new(expected.to_vec());
    key_store.store(account, &secret)?;
    let persisted =
        key_store
            .load(account)?
            .ok_or_else(|| MachineIdentityError::PersistedItemMissing {
                account: account.to_owned(),
            })?;
    if persisted.expose_secret() != expected {
        return Err(MachineIdentityError::PersistedItemMismatch {
            account: account.to_owned(),
        });
    }
    Ok(())
}

fn delete_exact(key_store: &dyn KeyStore, account: &str) -> Result<(), MachineIdentityError> {
    key_store.delete(account)?;
    if key_store.load(account)?.is_some() {
        return Err(MachineIdentityError::DeleteReadbackFailed {
            account: account.to_owned(),
        });
    }
    Ok(())
}

fn encode_key_directory_guard(guard: KeyDirectoryGuard) -> Vec<u8> {
    let mut encoded = Vec::with_capacity(KEY_DIRECTORY_GUARD_ENCODED_LEN);
    encoded.extend_from_slice(KEY_DIRECTORY_GUARD_DOMAIN);
    encoded.extend_from_slice(&guard.database_id);
    encoded.extend_from_slice(&guard.root_fingerprint);
    encoded.extend_from_slice(&guard.key_directory_revision.to_be_bytes());
    encoded
}

fn decode_key_directory_guard(bytes: &[u8]) -> Result<KeyDirectoryGuard, MachineIdentityError> {
    if bytes.len() != KEY_DIRECTORY_GUARD_ENCODED_LEN
        || !bytes.starts_with(KEY_DIRECTORY_GUARD_DOMAIN)
    {
        return Err(invalid_guard(KEY_DIRECTORY_GUARD_ACCOUNT));
    }
    let mut cursor = KEY_DIRECTORY_GUARD_DOMAIN.len();
    let database_id = take_array::<16>(bytes, &mut cursor)
        .ok_or_else(|| invalid_guard(KEY_DIRECTORY_GUARD_ACCOUNT))?;
    let root_fingerprint = take_array::<32>(bytes, &mut cursor)
        .ok_or_else(|| invalid_guard(KEY_DIRECTORY_GUARD_ACCOUNT))?;
    let revision = take_array::<8>(bytes, &mut cursor)
        .ok_or_else(|| invalid_guard(KEY_DIRECTORY_GUARD_ACCOUNT))?;
    if cursor != bytes.len() {
        return Err(invalid_guard(KEY_DIRECTORY_GUARD_ACCOUNT));
    }
    Ok(KeyDirectoryGuard::new(
        database_id,
        root_fingerprint,
        u64::from_be_bytes(revision),
    ))
}

fn load_key_directory_guard_unlocked(
    key_store: &dyn KeyStore,
) -> Result<Option<KeyDirectoryGuard>, MachineIdentityError> {
    key_store
        .load(KEY_DIRECTORY_GUARD_ACCOUNT)?
        .map(|secret| decode_key_directory_guard(secret.expose_secret()))
        .transpose()
}

fn encode_counter_guard(guard: CounterGuard) -> Vec<u8> {
    let mut encoded = Vec::with_capacity(COUNTER_GUARD_ENCODED_LEN);
    encoded.extend_from_slice(COUNTER_GUARD_DOMAIN);
    encoded.push(key_purpose_tag(guard.key_id.purpose));
    encoded.extend_from_slice(&guard.key_id.epoch.to_be_bytes());
    encoded.extend_from_slice(&guard.high_water.to_be_bytes());
    encoded
}

fn decode_counter_guard(
    account: &str,
    expected_key_id: KeyId,
    bytes: &[u8],
) -> Result<CounterGuard, MachineIdentityError> {
    if bytes.len() != COUNTER_GUARD_ENCODED_LEN || !bytes.starts_with(COUNTER_GUARD_DOMAIN) {
        return Err(invalid_guard(account));
    }
    let mut cursor = COUNTER_GUARD_DOMAIN.len();
    let purpose = bytes[cursor];
    cursor += 1;
    let epoch = take_array::<8>(bytes, &mut cursor).ok_or_else(|| invalid_guard(account))?;
    let high_water = take_array::<8>(bytes, &mut cursor).ok_or_else(|| invalid_guard(account))?;
    if cursor != bytes.len()
        || purpose != key_purpose_tag(expected_key_id.purpose)
        || u64::from_be_bytes(epoch) != expected_key_id.epoch
    {
        return Err(invalid_guard(account));
    }
    Ok(CounterGuard {
        key_id: expected_key_id,
        high_water: u64::from_be_bytes(high_water),
    })
}

fn load_counter_guard_unlocked(
    key_store: &dyn KeyStore,
    key_id: KeyId,
) -> Result<Option<CounterGuard>, MachineIdentityError> {
    let account = counter_guard_account(key_id);
    key_store
        .load(&account)?
        .map(|secret| decode_counter_guard(&account, key_id, secret.expose_secret()))
        .transpose()
}

fn load_scoped_counter_guard_unlocked(
    key_store: &dyn KeyStore,
    scope: &CounterScope,
) -> Result<Option<CounterGuardState>, MachineIdentityError> {
    load_scoped_counter_guard_for_token_unlocked(key_store, scope.token())
}

fn load_scoped_counter_guard_for_token_unlocked(
    key_store: &dyn KeyStore,
    scope_token: [u8; 32],
) -> Result<Option<CounterGuardState>, MachineIdentityError> {
    let account = scoped_counter_guard_account_from_token(scope_token)?;
    let state = key_store
        .load(&account)?
        .map(|secret| CounterGuardState::decode(secret.expose_secret()))
        .transpose()?;
    if state.is_some_and(|state| state.token() != scope_token) {
        return Err(CounterError::ScopeMismatch.into());
    }
    Ok(state)
}

fn validate_scoped_counter_guard_token(scope_token: [u8; 32]) -> Result<(), MachineIdentityError> {
    if scope_token == [0; 32] {
        return Err(CounterError::InvalidScope {
            axis: "scope token",
        }
        .into());
    }
    Ok(())
}

fn ensure_root_fingerprint(
    guard: KeyDirectoryGuard,
    expected: [u8; 32],
) -> Result<(), MachineIdentityError> {
    if guard.root_fingerprint != expected {
        return Err(MachineIdentityError::RootFingerprintMismatch);
    }
    Ok(())
}

fn same_key_directory_binding(left: KeyDirectoryGuard, right: KeyDirectoryGuard) -> bool {
    left.database_id == right.database_id && left.root_fingerprint == right.root_fingerprint
}

fn key_purpose_tag(purpose: KeyPurpose) -> u8 {
    match purpose {
        KeyPurpose::Catalog => 0,
        KeyPurpose::ConversationDek => 1,
        KeyPurpose::DeviceCommandTx => 2,
        KeyPurpose::DeviceReplyTx => 3,
    }
}

fn key_purpose_account_component(purpose: KeyPurpose) -> &'static str {
    match purpose {
        KeyPurpose::Catalog => "catalog",
        KeyPurpose::ConversationDek => "conversation-dek",
        KeyPurpose::DeviceCommandTx => "device-command-tx",
        KeyPurpose::DeviceReplyTx => "device-reply-tx",
    }
}

fn invalid_guard(account: &str) -> MachineIdentityError {
    MachineIdentityError::InvalidGuardEncoding {
        account: account.to_owned(),
    }
}

fn take_array<const N: usize>(bytes: &[u8], cursor: &mut usize) -> Option<[u8; N]> {
    let end = cursor.checked_add(N)?;
    let value = bytes.get(*cursor..end)?.try_into().ok()?;
    *cursor = end;
    Some(value)
}

fn array32(bytes: Vec<u8>, account: &'static str) -> Result<[u8; 32], MachineIdentityError> {
    bytes
        .try_into()
        .map_err(|_| MachineIdentityError::InvalidPublicKey { account })
}

#[cfg(test)]
mod tests {
    use std::collections::HashMap;

    use super::*;

    #[derive(Default)]
    struct TestKeyStore {
        values: Mutex<HashMap<String, Vec<u8>>>,
        stores: Mutex<Vec<String>>,
        deletes: Mutex<Vec<String>>,
        corrupt_readback: Mutex<Option<String>>,
        missing_readback: Mutex<Option<String>>,
        corrupt_readback_after_store: Mutex<Option<String>>,
        missing_readback_after_store: Mutex<Option<String>>,
        retain_after_delete: Mutex<Option<String>>,
    }

    impl TestKeyStore {
        fn insert(&self, account: &str, bytes: &[u8]) {
            self.values
                .lock()
                .unwrap()
                .insert(account.to_owned(), bytes.to_vec());
        }
    }

    impl KeyStore for TestKeyStore {
        fn load(&self, account: &str) -> Result<Option<SecretBytes>, KeyStoreError> {
            let value = self.values.lock().unwrap().get(account).cloned();
            let Some(mut value) = value else {
                return Ok(None);
            };
            let mut missing = self.missing_readback.lock().unwrap();
            if missing.as_deref() == Some(account) {
                *missing = None;
                return Ok(None);
            }
            drop(missing);
            let mut corrupt = self.corrupt_readback.lock().unwrap();
            if corrupt.as_deref() == Some(account) {
                *corrupt = None;
                value[0] ^= 0xff;
            }
            Ok(Some(SecretBytes::new(value)))
        }

        fn store(&self, account: &str, value: &SecretBytes) -> Result<(), KeyStoreError> {
            self.stores.lock().unwrap().push(account.to_owned());
            self.values
                .lock()
                .unwrap()
                .insert(account.to_owned(), value.expose_secret().to_vec());
            let mut corrupt_after_store = self.corrupt_readback_after_store.lock().unwrap();
            if corrupt_after_store.as_deref() == Some(account) {
                *corrupt_after_store = None;
                *self.corrupt_readback.lock().unwrap() = Some(account.to_owned());
            }
            drop(corrupt_after_store);
            let mut missing_after_store = self.missing_readback_after_store.lock().unwrap();
            if missing_after_store.as_deref() == Some(account) {
                *missing_after_store = None;
                *self.missing_readback.lock().unwrap() = Some(account.to_owned());
            }
            Ok(())
        }

        fn delete(&self, account: &str) -> Result<(), KeyStoreError> {
            self.deletes.lock().unwrap().push(account.to_owned());
            if self.retain_after_delete.lock().unwrap().as_deref() == Some(account) {
                return Ok(());
            }
            self.values.lock().unwrap().remove(account);
            Ok(())
        }
    }

    #[test]
    fn pre_preparing_generation_is_restart_stable() {
        let store = TestKeyStore::default();
        let first = load_or_create_preparing_machine_key_material(&store).unwrap();
        let first_public = *first.public_identity();
        assert_eq!(store.stores.lock().unwrap().len(), 4);

        let second = load_or_create_preparing_machine_key_material(&store).unwrap();
        assert_eq!(*second.public_identity(), first_public);
        assert_eq!(store.stores.lock().unwrap().len(), 4);
    }

    #[test]
    fn pre_preparing_partial_only_fills_missing_after_validating_existing() {
        let store = TestKeyStore::default();
        store.insert(MACHINE_ROOT_SIGN_ACCOUNT, &[0x51; 32]);
        store.insert(MACHINE_HPKE_ACCOUNT, &[0x52; 32]);
        let material = load_or_create_preparing_machine_key_material(&store).unwrap();
        assert_eq!(
            *store.stores.lock().unwrap(),
            vec![MACHINE_LINK_SIGN_ACCOUNT, MACHINE_DATA_SIGN_ACCOUNT]
        );
        assert_eq!(
            material.public_identity.root.public_key,
            signing_public(&[0x51; 32])
        );
    }

    #[test]
    fn invalid_existing_material_fails_before_first_write() {
        let store = TestKeyStore::default();
        store.insert(MACHINE_ROOT_SIGN_ACCOUNT, &[0x61; 31]);
        let error = load_or_create_preparing_machine_key_material(&store).unwrap_err();
        assert_eq!(error.code(), "daemon.remote.identity.key_invalid");
        assert!(store.stores.lock().unwrap().is_empty());

        // 缺失的前序 account 不能在后序既有 item 完成校验前被补写。
        let later_invalid = TestKeyStore::default();
        later_invalid.insert(MACHINE_DATA_SIGN_ACCOUNT, &[0x62; 31]);
        let error = load_or_create_preparing_machine_key_material(&later_invalid).unwrap_err();
        assert_eq!(error.code(), "daemon.remote.identity.key_invalid");
        assert!(later_invalid.stores.lock().unwrap().is_empty());
    }

    #[test]
    fn generated_material_requires_exact_readback() {
        let store = TestKeyStore::default();
        *store.corrupt_readback.lock().unwrap() = Some(MACHINE_ROOT_SIGN_ACCOUNT.to_owned());
        let error = load_or_create_preparing_machine_key_material(&store).unwrap_err();
        assert_eq!(
            error.code(),
            "daemon.remote.identity.key_persistence_failed"
        );
        assert_eq!(
            *store.stores.lock().unwrap(),
            vec![MACHINE_ROOT_SIGN_ACCOUNT]
        );

        let missing = TestKeyStore::default();
        *missing.missing_readback.lock().unwrap() = Some(MACHINE_ROOT_SIGN_ACCOUNT.to_owned());
        let error = load_or_create_preparing_machine_key_material(&missing).unwrap_err();
        assert_eq!(
            error.code(),
            "daemon.remote.identity.key_persistence_failed"
        );
        assert_eq!(
            *missing.stores.lock().unwrap(),
            vec![MACHINE_ROOT_SIGN_ACCOUNT]
        );
    }

    fn directory_guard(revision: u64) -> KeyDirectoryGuard {
        KeyDirectoryGuard::new([0x71; 16], [0x72; 32], revision)
    }

    #[test]
    fn key_directory_guard_advance_is_monotonic_exact_retry_and_persisted() {
        let store = TestKeyStore::default();
        let current = directory_guard(9);
        let next = directory_guard(10);
        install_key_directory_guard(&store, current).unwrap();

        assert_eq!(
            advance_key_directory_guard(&store, current, next).unwrap(),
            next
        );
        assert_eq!(load_key_directory_guard(&store).unwrap(), Some(next));
        assert_eq!(
            *store.stores.lock().unwrap(),
            vec![KEY_DIRECTORY_GUARD_ACCOUNT, KEY_DIRECTORY_GUARD_ACCOUNT]
        );

        // guard CAS 成功但周边 durable transition 尚未完成时，重启会以同一
        // old→new reservation 重试；exact next 只读重放，不能产生覆盖写。
        assert_eq!(
            advance_key_directory_guard(&store, current, next).unwrap(),
            next
        );
        assert_eq!(load_key_directory_guard(&store).unwrap(), Some(next));
        assert_eq!(
            *store.stores.lock().unwrap(),
            vec![KEY_DIRECTORY_GUARD_ACCOUNT, KEY_DIRECTORY_GUARD_ACCOUNT]
        );
    }

    #[test]
    fn key_directory_guard_advance_rejects_regression_and_jump_without_write() {
        for (next_revision, expected_code) in [
            (8, "daemon.remote.identity.guard_regression"),
            (9, "daemon.remote.identity.guard_regression"),
            (11, "daemon.remote.identity.guard_jump"),
        ] {
            let store = TestKeyStore::default();
            let current = directory_guard(9);
            install_key_directory_guard(&store, current).unwrap();
            let stores_before = store.stores.lock().unwrap().clone();

            let error =
                advance_key_directory_guard(&store, current, directory_guard(next_revision))
                    .expect_err("non-successor revision must fail closed");
            assert_eq!(error.code(), expected_code);
            assert_eq!(load_key_directory_guard(&store).unwrap(), Some(current));
            assert_eq!(*store.stores.lock().unwrap(), stores_before);
        }
    }

    #[test]
    fn key_directory_guard_advance_rejects_wrong_binding_without_write() {
        for next in [
            KeyDirectoryGuard::new([0x73; 16], [0x72; 32], 10),
            KeyDirectoryGuard::new([0x71; 16], [0x74; 32], 10),
        ] {
            let store = TestKeyStore::default();
            let current = directory_guard(9);
            install_key_directory_guard(&store, current).unwrap();
            let stores_before = store.stores.lock().unwrap().clone();

            let error = advance_key_directory_guard(&store, current, next)
                .expect_err("database/root binding changes must fail closed");
            assert_eq!(
                error.code(),
                "daemon.remote.identity.guard_binding_mismatch"
            );
            assert_eq!(load_key_directory_guard(&store).unwrap(), Some(current));
            assert_eq!(*store.stores.lock().unwrap(), stores_before);
        }

        let store = TestKeyStore::default();
        let persisted = KeyDirectoryGuard::new([0x73; 16], [0x72; 32], 9);
        install_key_directory_guard(&store, persisted).unwrap();
        let stores_before = store.stores.lock().unwrap().clone();
        let error = advance_key_directory_guard(&store, directory_guard(9), directory_guard(10))
            .expect_err("persisted database/root binding mismatch must fail closed");
        assert_eq!(
            error.code(),
            "daemon.remote.identity.guard_binding_mismatch"
        );
        assert_eq!(load_key_directory_guard(&store).unwrap(), Some(persisted));
        assert_eq!(*store.stores.lock().unwrap(), stores_before);
    }

    #[test]
    fn key_directory_guard_advance_rejects_cas_conflict_without_overwrite() {
        let store = TestKeyStore::default();
        let persisted = directory_guard(9);
        install_key_directory_guard(&store, persisted).unwrap();
        let stores_before = store.stores.lock().unwrap().clone();

        let error = advance_key_directory_guard(&store, directory_guard(10), directory_guard(11))
            .expect_err("non-current expected guard must conflict");
        assert_eq!(error.code(), "daemon.remote.identity.guard_conflict");
        assert_eq!(load_key_directory_guard(&store).unwrap(), Some(persisted));
        assert_eq!(*store.stores.lock().unwrap(), stores_before);
    }

    #[test]
    fn key_directory_guard_advance_rejects_missing_guard_without_installing() {
        let store = TestKeyStore::default();
        let error = advance_key_directory_guard(&store, directory_guard(9), directory_guard(10))
            .expect_err("advance cannot synthesize a missing guard");
        assert_eq!(error.code(), "daemon.remote.identity.guard_missing");
        assert_eq!(load_key_directory_guard(&store).unwrap(), None);
        assert!(store.stores.lock().unwrap().is_empty());
    }

    #[test]
    fn key_directory_guard_advance_requires_exact_store_readback() {
        for missing in [false, true] {
            let store = TestKeyStore::default();
            let current = directory_guard(9);
            install_key_directory_guard(&store, current).unwrap();
            if missing {
                *store.missing_readback_after_store.lock().unwrap() =
                    Some(KEY_DIRECTORY_GUARD_ACCOUNT.to_owned());
            } else {
                *store.corrupt_readback_after_store.lock().unwrap() =
                    Some(KEY_DIRECTORY_GUARD_ACCOUNT.to_owned());
            }

            let error = advance_key_directory_guard(&store, current, directory_guard(10))
                .expect_err("advance must verify the persisted guard bytes");
            assert_eq!(
                error.code(),
                "daemon.remote.identity.key_persistence_failed"
            );
        }
    }

    fn scoped_publication_counter() -> CounterScope {
        CounterScope::publication(
            [0xa1; 32],
            KeyId {
                purpose: KeyPurpose::ConversationDek,
                epoch: 9,
            },
            [0xa2; 16],
        )
        .unwrap()
    }

    #[test]
    fn scoped_counter_guard_cas_preserves_conflict_and_promotes_exact_state() {
        let store = TestKeyStore::default();
        let backend = KeyStoreCounterGuardBackend::new(&store);
        let scope = scoped_publication_counter();
        let pending =
            CounterGuardState::pending(scope.token(), 0, 1_024, [0xb1; 16], [0xb2; 16], [0xb3; 32])
                .unwrap();
        assert_eq!(
            backend
                .compare_and_swap_guard(&scope, None, pending)
                .unwrap(),
            CounterGuardCas::Swapped(pending)
        );
        assert_eq!(backend.load_guard(&scope).unwrap(), Some(pending));

        let stable = CounterGuardState::stable(scope.token(), 1_024, [0xb4; 32]).unwrap();
        assert_eq!(
            backend
                .compare_and_swap_guard(&scope, None, stable)
                .unwrap(),
            CounterGuardCas::Conflict(Some(pending))
        );
        assert_eq!(backend.load_guard(&scope).unwrap(), Some(pending));

        assert_eq!(
            backend
                .compare_and_swap_guard(&scope, Some(pending), stable)
                .unwrap(),
            CounterGuardCas::Swapped(stable)
        );
        assert_eq!(backend.load_guard(&scope).unwrap(), Some(stable));
    }

    #[test]
    fn owned_counter_guard_backend_is_static_and_preserves_exact_cas_semantics() {
        fn assert_owner<T: Send + Sync + 'static>() {}
        assert_owner::<OwnedKeyStoreCounterGuardBackend>();

        let store = std::sync::Arc::new(TestKeyStore::default());
        let key_store: std::sync::Arc<dyn KeyStore> = store;
        let backend = OwnedKeyStoreCounterGuardBackend::new(key_store);
        let scope = scoped_publication_counter();
        let pending =
            CounterGuardState::pending(scope.token(), 0, 1_024, [0xd1; 16], [0xd2; 16], [0xd3; 32])
                .unwrap();
        assert_eq!(
            backend
                .compare_and_swap_guard(&scope, None, pending)
                .unwrap(),
            CounterGuardCas::Swapped(pending)
        );
        assert_eq!(backend.load_guard(&scope).unwrap(), Some(pending));
    }

    #[test]
    fn authenticated_scope_token_restores_canonical_v2_account() {
        let token = [0xab; 32];
        assert_eq!(
            scoped_counter_guard_account_from_token(token).unwrap(),
            format!("counter-guard-v2/{}", "ab".repeat(32))
        );
        let error = scoped_counter_guard_account_from_token([0; 32])
            .expect_err("zero manifest token must fail closed");
        assert_eq!(error.code(), "daemon.remote.counter.scope_invalid");
    }

    #[test]
    fn token_based_scoped_guard_load_decodes_and_rejects_embedded_token_mismatch() {
        let store = TestKeyStore::default();
        let token = [0xe1; 32];
        let account = scoped_counter_guard_account_from_token(token).unwrap();
        let stable = CounterGuardState::stable(token, 1_024, [0xe2; 32]).unwrap();
        store.insert(&account, &stable.encode());
        assert_eq!(
            load_scoped_counter_guard_for_token(&store, token).unwrap(),
            Some(stable)
        );

        let wrong = CounterGuardState::stable([0xe3; 32], 1_024, [0xe4; 32]).unwrap();
        store.insert(&account, &wrong.encode());
        let error = load_scoped_counter_guard_for_token(&store, token)
            .expect_err("account and embedded token mismatch must fail closed");
        assert_eq!(error.code(), "daemon.remote.counter.scope_mismatch");
        let error = delete_scoped_counter_guard_for_token(&store, token)
            .expect_err("mismatched guard must be rejected before delete");
        assert_eq!(error.code(), "daemon.remote.counter.scope_mismatch");
        assert!(store.deletes.lock().unwrap().is_empty());
    }

    #[test]
    fn token_based_scoped_guard_delete_is_existing_only_with_absent_readback() {
        let store = TestKeyStore::default();
        let token = [0xf1; 32];
        let account = scoped_counter_guard_account_from_token(token).unwrap();

        assert!(!delete_scoped_counter_guard_for_token(&store, token).unwrap());
        assert!(store.deletes.lock().unwrap().is_empty());

        let stable = CounterGuardState::stable(token, 2_048, [0xf2; 32]).unwrap();
        store.insert(&account, &stable.encode());
        assert!(delete_scoped_counter_guard_for_token(&store, token).unwrap());
        assert_eq!(*store.deletes.lock().unwrap(), vec![account.clone()]);
        assert_eq!(
            load_scoped_counter_guard_for_token(&store, token).unwrap(),
            None
        );

        store.insert(&account, &stable.encode());
        *store.retain_after_delete.lock().unwrap() = Some(account.clone());
        let error = delete_scoped_counter_guard_for_token(&store, token)
            .expect_err("delete must require an exact absent readback");
        assert_eq!(error.code(), "daemon.remote.identity.delete_failed");
        assert_eq!(
            load_scoped_counter_guard_for_token(&store, token).unwrap(),
            Some(stable)
        );
    }

    #[test]
    fn scoped_guard_batch_delete_audits_all_before_first_mutation() {
        let store = TestKeyStore::default();
        let first = [0xa1; 32];
        let second = [0xa2; 32];
        let first_account = scoped_counter_guard_account_from_token(first).unwrap();
        let second_account = scoped_counter_guard_account_from_token(second).unwrap();
        let second_guard = CounterGuardState::stable(second, 1_024, [0xa3; 32]).unwrap();
        store.insert(&second_account, &second_guard.encode());

        assert_eq!(
            delete_scoped_counter_guards_for_tokens(&store, &[first, second]).unwrap(),
            1
        );
        assert_eq!(*store.deletes.lock().unwrap(), vec![second_account.clone()]);
        assert!(store.values.lock().unwrap().get(&second_account).is_none());

        store.deletes.lock().unwrap().clear();
        let first_guard = CounterGuardState::stable(first, 2_048, [0xa4; 32]).unwrap();
        let mismatched = CounterGuardState::stable([0xa5; 32], 2_048, [0xa6; 32]).unwrap();
        store.insert(&first_account, &first_guard.encode());
        store.insert(&second_account, &mismatched.encode());
        let error = delete_scoped_counter_guards_for_tokens(&store, &[first, second])
            .expect_err("later malformed guard must fail before deleting the first");
        assert_eq!(error.code(), "daemon.remote.counter.scope_mismatch");
        assert!(store.deletes.lock().unwrap().is_empty());
        assert!(store.values.lock().unwrap().contains_key(&first_account));
        assert!(store.values.lock().unwrap().contains_key(&second_account));

        assert_eq!(
            delete_scoped_counter_guards_for_tokens(&store, &[second, first])
                .expect_err("plan tokens must be strictly ordered"),
            MachineIdentityError::CleanupCounterAxisDuplicate
        );
        assert!(store.deletes.lock().unwrap().is_empty());
    }

    #[test]
    fn scoped_counter_guard_cas_requires_exact_key_store_readback() {
        for missing in [false, true] {
            let store = TestKeyStore::default();
            let backend = KeyStoreCounterGuardBackend::new(&store);
            let scope = scoped_publication_counter();
            let account = scoped_counter_guard_account(&scope);
            if missing {
                *store.missing_readback.lock().unwrap() = Some(account);
            } else {
                *store.corrupt_readback.lock().unwrap() = Some(account);
            }
            let pending = CounterGuardState::pending(
                scope.token(),
                0,
                1_024,
                [0xc1; 16],
                [0xc2; 16],
                [0xc3; 32],
            )
            .unwrap();
            let error = backend
                .compare_and_swap_guard(&scope, None, pending)
                .unwrap_err();
            assert_eq!(
                error.code(),
                "daemon.remote.identity.key_persistence_failed"
            );
        }
    }
}
