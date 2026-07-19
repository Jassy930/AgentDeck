//! Machine identity 的 Keychain material 与 rollback guard IO。
//!
//! 本模块只处理四组长期 key material、key-directory guard 与 counter high-water。
//! 它不拥有网络或配对流程。私钥只以 [`agentdeck_crypto`] 的 typed wrapper 暴露，
//! raw seed/IKM 不进入公开 API、`Debug` 或错误文本。

use std::fmt;
use std::sync::{Mutex, MutexGuard};

use agentdeck_crypto::{HpkePrivateKey, SigningKey, sha256};
use agentdeck_protocol::e2ee::{KeyId, KeyPurpose};
use thiserror::Error;
use zeroize::Zeroizing;

use crate::security::{KeyStore, KeyStoreError, SecretBytes};

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
    #[error("key-directory guard is missing")]
    KeyDirectoryGuardMissing,
    #[error("counter guard high-water cannot decrease from {current} to {requested}")]
    CounterRegression { current: u64, requested: u64 },
    #[error("expected root fingerprint does not match the persisted machine identity")]
    RootFingerprintMismatch,
    #[error("deleted machine identity item {account} is still present")]
    DeleteReadbackFailed { account: String },
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
            Self::KeyDirectoryGuardMissing => "daemon.remote.identity.guard_missing",
            Self::CounterRegression { .. } => "daemon.remote.identity.counter_regression",
            Self::RootFingerprintMismatch => "daemon.remote.identity.fingerprint_mismatch",
            Self::DeleteReadbackFailed { .. } => "daemon.remote.identity.delete_failed",
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

fn ensure_root_fingerprint(
    guard: KeyDirectoryGuard,
    expected: [u8; 32],
) -> Result<(), MachineIdentityError> {
    if guard.root_fingerprint != expected {
        return Err(MachineIdentityError::RootFingerprintMismatch);
    }
    Ok(())
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
        corrupt_readback: Mutex<Option<String>>,
        missing_readback: Mutex<Option<String>>,
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
            Ok(())
        }

        fn delete(&self, account: &str) -> Result<(), KeyStoreError> {
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
}
