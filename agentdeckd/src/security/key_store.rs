use std::collections::HashMap;
use std::fmt;
use std::io;
use std::path::{Path, PathBuf};
use std::sync::Mutex;

use thiserror::Error;
use zeroize::Zeroize;

/// Runtime 数据库包装密钥在 Keychain 中的固定 account。
pub const STORAGE_KEK_ACCOUNT: &str = "storage-kek.v1";
const STORAGE_KEK_LEN: usize = 32;

/// 不允许通过 `Debug` 泄漏、销毁时清零的秘密字节。
pub struct SecretBytes(Vec<u8>);

impl SecretBytes {
    #[must_use]
    pub fn new(bytes: Vec<u8>) -> Self {
        Self(bytes)
    }

    /// 只允许在明确的加解密或 Keychain IO 边界借用秘密。
    #[must_use]
    pub fn expose_secret(&self) -> &[u8] {
        &self.0
    }

    #[allow(dead_code)] // P4 pairing coordinator consumes the staged Store capability.
    pub(crate) fn retained_capacity(&self) -> usize {
        self.0.capacity()
    }

    fn expose_secret_mut(&mut self) -> &mut [u8] {
        &mut self.0
    }
}

impl fmt::Debug for SecretBytes {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("SecretBytes([REDACTED])")
    }
}

impl Drop for SecretBytes {
    fn drop(&mut self) {
        self.0.zeroize();
    }
}

/// Keychain 或测试 keystore 的 typed failure。
#[derive(Debug, Error, PartialEq, Eq)]
pub enum KeyStoreError {
    #[error("daemon storage Keychain access group is not provisioned")]
    AccessGroupMissing,
    #[error("daemon storage Keychain access group is invalid")]
    AccessGroupInvalid,
    #[error("daemon storage Keychain is unsupported on this platform")]
    UnsupportedPlatform,
    #[error("daemon storage keystore lock is poisoned")]
    Poisoned,
    #[error("daemon storage keystore {operation} failed with status {status}")]
    Backend {
        operation: &'static str,
        status: i32,
    },
}

impl KeyStoreError {
    #[must_use]
    pub const fn code(&self) -> &'static str {
        match self {
            Self::AccessGroupMissing => "daemon.keystore.access_group_unconfigured",
            Self::AccessGroupInvalid => "daemon.keystore.access_group_invalid",
            Self::UnsupportedPlatform => "daemon.keystore.unsupported_platform",
            Self::Poisoned | Self::Backend { .. } => "daemon.keystore.unavailable",
        }
    }
}

/// Secret storage seam。生产 stable 实例只注入 macOS Keychain 实现。
pub trait KeyStore: Send + Sync {
    fn load(&self, account: &str) -> Result<Option<SecretBytes>, KeyStoreError>;
    fn store(&self, account: &str, value: &SecretBytes) -> Result<(), KeyStoreError>;
    fn delete(&self, account: &str) -> Result<(), KeyStoreError>;
}

/// 仅供 ephemeral/test 注入的进程内 keystore。
#[derive(Default)]
pub struct MemoryKeyStore {
    values: Mutex<HashMap<String, SecretBytes>>,
}

impl MemoryKeyStore {
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }
}

impl KeyStore for MemoryKeyStore {
    fn load(&self, account: &str) -> Result<Option<SecretBytes>, KeyStoreError> {
        let values = self.values.lock().map_err(|_| KeyStoreError::Poisoned)?;
        Ok(values
            .get(account)
            .map(|value| SecretBytes::new(value.expose_secret().to_vec())))
    }

    fn store(&self, account: &str, value: &SecretBytes) -> Result<(), KeyStoreError> {
        let mut values = self.values.lock().map_err(|_| KeyStoreError::Poisoned)?;
        values.insert(
            account.to_owned(),
            SecretBytes::new(value.expose_secret().to_vec()),
        );
        Ok(())
    }

    fn delete(&self, account: &str) -> Result<(), KeyStoreError> {
        let mut values = self.values.lock().map_err(|_| KeyStoreError::Poisoned)?;
        values.remove(account);
        Ok(())
    }
}

/// 固定 32 bytes、销毁时清零的 Runtime DB 包装密钥。
pub struct StorageKek([u8; STORAGE_KEK_LEN]);

impl StorageKek {
    fn from_secret(secret: SecretBytes) -> Result<Self, StorageKekError> {
        let actual = secret.expose_secret().len();
        if actual != STORAGE_KEK_LEN {
            return Err(StorageKekError::InvalidKeyLength { actual });
        }
        let mut bytes = [0_u8; STORAGE_KEK_LEN];
        bytes.copy_from_slice(secret.expose_secret());
        Ok(Self(bytes))
    }

    #[must_use]
    pub fn expose_secret(&self) -> &[u8; STORAGE_KEK_LEN] {
        &self.0
    }
}

impl fmt::Debug for StorageKek {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("StorageKek([REDACTED])")
    }
}

impl Drop for StorageKek {
    fn drop(&mut self) {
        self.0.zeroize();
    }
}

#[derive(Debug, Error)]
pub enum StorageKekError {
    #[error("runtime data exists but storage-kek.v1 is missing")]
    StorageKeyMissing,
    #[error("storage-kek.v1 has invalid length {actual}; expected 32")]
    InvalidKeyLength { actual: usize },
    #[error("storage keystore failed: {0}")]
    KeyStore(#[from] KeyStoreError),
    #[error("failed to inspect runtime storage artifact {path}: {source}")]
    RuntimeArtifact {
        path: PathBuf,
        #[source]
        source: io::Error,
    },
    #[error("operating-system entropy source is unavailable")]
    EntropyUnavailable,
    #[error("storage-kek.v1 was not readable after a successful store")]
    PersistedKeyMissing,
    #[error("storage-kek.v1 changed while it was persisted")]
    PersistedKeyMismatch,
}

impl StorageKekError {
    #[must_use]
    pub const fn code(&self) -> &'static str {
        match self {
            Self::StorageKeyMissing => "daemon.storage.key_missing",
            Self::InvalidKeyLength { .. } => "daemon.storage.key_invalid",
            Self::KeyStore(error) => error.code(),
            Self::RuntimeArtifact { .. } => "daemon.storage.state_check_failed",
            Self::EntropyUnavailable => "daemon.storage.entropy_unavailable",
            Self::PersistedKeyMissing | Self::PersistedKeyMismatch => {
                "daemon.storage.key_persistence_failed"
            }
        }
    }
}

/// 读取既有 StorageKEK，或只在完全 fresh 的 Runtime namespace 中创建一次。
///
/// `runtime.db`、对应 WAL 或 SHM 任一非空而 Keychain item 缺失时必须 fail-close，
/// 防止用替代 key 覆盖/误判既有加密状态。
pub fn load_or_create_storage_kek(
    key_store: &dyn KeyStore,
    runtime_db: &Path,
) -> Result<StorageKek, StorageKekError> {
    if let Some(secret) = key_store.load(STORAGE_KEK_ACCOUNT)? {
        return StorageKek::from_secret(secret);
    }

    for artifact in runtime_artifacts(runtime_db) {
        if artifact_is_nonempty(&artifact)? {
            return Err(StorageKekError::StorageKeyMissing);
        }
    }

    let mut secret = SecretBytes::new(vec![0_u8; STORAGE_KEK_LEN]);
    getrandom::fill(secret.expose_secret_mut()).map_err(|_| StorageKekError::EntropyUnavailable)?;
    let storage_kek = StorageKek::from_secret(SecretBytes::new(secret.expose_secret().to_vec()))?;
    key_store.store(STORAGE_KEK_ACCOUNT, &secret)?;
    let persisted = key_store
        .load(STORAGE_KEK_ACCOUNT)?
        .ok_or(StorageKekError::PersistedKeyMissing)?;
    let persisted = StorageKek::from_secret(persisted)?;
    if persisted.expose_secret() != storage_kek.expose_secret() {
        return Err(StorageKekError::PersistedKeyMismatch);
    }
    Ok(persisted)
}

fn runtime_artifacts(runtime_db: &Path) -> [PathBuf; 3] {
    [
        runtime_db.to_path_buf(),
        sidecar(runtime_db, "-wal"),
        sidecar(runtime_db, "-shm"),
    ]
}

fn sidecar(path: &Path, suffix: &str) -> PathBuf {
    let mut value = path.as_os_str().to_os_string();
    value.push(suffix);
    PathBuf::from(value)
}

fn artifact_is_nonempty(path: &Path) -> Result<bool, StorageKekError> {
    match std::fs::symlink_metadata(path) {
        Ok(metadata) => Ok(metadata.len() > 0 || !metadata.file_type().is_file()),
        Err(error) if error.kind() == io::ErrorKind::NotFound => Ok(false),
        Err(source) => Err(StorageKekError::RuntimeArtifact {
            path: path.to_path_buf(),
            source,
        }),
    }
}
