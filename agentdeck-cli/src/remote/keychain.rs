//! Persistent remote client 的 Keychain account 与可注入 secret-store primitive。
//!
//! 本模块冻结 account 命名和 immutable/exact-readback 语义；production macOS
//! Data Protection Keychain adapter 由 sibling `macos_keychain` 在签名 type-state 后接入。
//! [`MemoryRemoteKeyStore`] 只能由 library/test harness 显式注入，不提供 CLI、环境变量
//! 或配置文件选择面。

use std::collections::HashMap;
use std::fmt;
use std::sync::Mutex;

use agentdeck_protocol::relay_v2::MachineRouteId;
use agentdeck_protocol::runtime::MachineRootFingerprint;
use base64::{Engine as _, engine::general_purpose::URL_SAFE_NO_PAD};
use sha2::{Digest, Sha256};
use thiserror::Error;
use uuid::Uuid;
use zeroize::Zeroize;

/// CLI persistent remote item 的固定 Data Protection Keychain service。
pub const REMOTE_KEYCHAIN_SERVICE: &str = "com.agentdeck.remote.v1";
const ACCOUNT_LOG_DOMAIN: &[u8] = b"agentdeck.remote.key-account.log.v1\0";

/// Keychain account 的封闭、带版本 purpose。
#[derive(Clone, Copy, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub enum RemoteKeyPurpose {
    PendingPairingRecord,
    DeviceSignPrivateKey,
    DeviceHpkePrivateKey,
    DeviceGrant,
    DeviceStorageKek,
    CounterGuard,
    PairedCommitMarker,
}

impl RemoteKeyPurpose {
    #[must_use]
    pub const fn account_component(self) -> &'static str {
        match self {
            Self::PendingPairingRecord => "pending-pairing-record.v1",
            Self::DeviceSignPrivateKey => "device-sign-private-key.v1",
            Self::DeviceHpkePrivateKey => "device-hpke-private-key.v1",
            Self::DeviceGrant => "device-grant.v1",
            Self::DeviceStorageKek => "device-storage-kek.v1",
            Self::CounterGuard => "counter-guard.v1",
            Self::PairedCommitMarker => "paired-commit-marker.v1",
        }
    }
}

/// Pending namespace 只允许首次发送前必需的三类 item。
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum PendingRemoteKeyPurpose {
    PairingRecord,
    DeviceSignPrivateKey,
    DeviceHpkePrivateKey,
}

impl From<PendingRemoteKeyPurpose> for RemoteKeyPurpose {
    fn from(value: PendingRemoteKeyPurpose) -> Self {
        match value {
            PendingRemoteKeyPurpose::PairingRecord => Self::PendingPairingRecord,
            PendingRemoteKeyPurpose::DeviceSignPrivateKey => Self::DeviceSignPrivateKey,
            PendingRemoteKeyPurpose::DeviceHpkePrivateKey => Self::DeviceHpkePrivateKey,
        }
    }
}

/// Paired namespace 只允许 marker 与 machine-scoped final item。
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum PairedRemoteKeyPurpose {
    DeviceSignPrivateKey,
    DeviceHpkePrivateKey,
    DeviceGrant,
    DeviceStorageKek,
    CounterGuard,
    CommitMarker,
}

impl From<PairedRemoteKeyPurpose> for RemoteKeyPurpose {
    fn from(value: PairedRemoteKeyPurpose) -> Self {
        match value {
            PairedRemoteKeyPurpose::DeviceSignPrivateKey => Self::DeviceSignPrivateKey,
            PairedRemoteKeyPurpose::DeviceHpkePrivateKey => Self::DeviceHpkePrivateKey,
            PairedRemoteKeyPurpose::DeviceGrant => Self::DeviceGrant,
            PairedRemoteKeyPurpose::DeviceStorageKek => Self::DeviceStorageKek,
            PairedRemoteKeyPurpose::CounterGuard => Self::CounterGuard,
            PairedRemoteKeyPurpose::CommitMarker => Self::PairedCommitMarker,
        }
    }
}

/// 已 canonicalize 的 remote Keychain account。
#[derive(Clone, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub struct RemoteKeyAccount(String);

impl RemoteKeyAccount {
    /// 首次发出 PairRequest 前使用的 pending account。
    #[must_use]
    pub fn pending(
        installation_id: Uuid,
        invite_hash: [u8; 32],
        purpose: PendingRemoteKeyPurpose,
    ) -> Self {
        let purpose = RemoteKeyPurpose::from(purpose);
        Self(format!(
            "pending/cli/{}/{}/{}",
            installation_id.hyphenated(),
            URL_SAFE_NO_PAD.encode(invite_hash),
            purpose.account_component(),
        ))
    }

    /// PairResponse 验证后使用的 machine-scoped account。
    #[must_use]
    pub fn paired(
        installation_id: Uuid,
        machine_root_fingerprint: MachineRootFingerprint,
        machine_route: MachineRouteId,
        purpose: PairedRemoteKeyPurpose,
    ) -> Self {
        let purpose = RemoteKeyPurpose::from(purpose);
        Self(format!(
            "cli/{}/{}/{}/{}",
            installation_id.hyphenated(),
            URL_SAFE_NO_PAD.encode(machine_root_fingerprint.as_bytes()),
            URL_SAFE_NO_PAD.encode(machine_route.as_bytes()),
            purpose.account_component(),
        ))
    }

    #[must_use]
    pub fn as_str(&self) -> &str {
        &self.0
    }

    fn audit_token(&self) -> String {
        let mut hasher = Sha256::new();
        hasher.update(ACCOUNT_LOG_DOMAIN);
        hasher.update(self.0.as_bytes());
        let digest = hasher.finalize();
        let mut token = String::with_capacity(16);
        for byte in &digest[..8] {
            use fmt::Write as _;
            write!(&mut token, "{byte:02x}").expect("writing to String cannot fail");
        }
        token
    }
}

impl fmt::Display for RemoteKeyAccount {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(formatter, "remote-key-account:{}", self.audit_token())
    }
}

impl fmt::Debug for RemoteKeyAccount {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_tuple("RemoteKeyAccount")
            .field(&self.to_string())
            .finish()
    }
}

/// 不允许通过 `Debug` 泄漏且销毁时清零的 remote secret。
pub struct RemoteSecret(Vec<u8>);

impl RemoteSecret {
    #[must_use]
    pub fn new(bytes: Vec<u8>) -> Self {
        Self(bytes)
    }

    /// 只允许在明确的加解密或 Keychain IO 边界借用秘密。
    #[must_use]
    pub fn expose_secret(&self) -> &[u8] {
        &self.0
    }
}

impl fmt::Debug for RemoteSecret {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("RemoteSecret([REDACTED])")
    }
}

impl Drop for RemoteSecret {
    fn drop(&mut self) {
        self.0.zeroize();
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum RemoteKeyPersistence {
    Inserted,
    AlreadyPresent,
}

#[derive(Debug, Error, Eq, PartialEq)]
pub enum RemoteKeyStoreError {
    #[error("remote Keychain item {account} already exists with different bytes")]
    ImmutableConflict { account: RemoteKeyAccount },
    #[error("remote Keychain item {account} was absent or changed during exact readback")]
    PersistenceReadbackFailed { account: RemoteKeyAccount },
    #[error("remote Keychain item {account} remained present after delete")]
    DeleteReadbackFailed { account: RemoteKeyAccount },
    #[error("remote keystore backend is unavailable")]
    BackendUnavailable,
    #[error("remote keystore lock is poisoned")]
    Poisoned,
}

impl RemoteKeyStoreError {
    #[must_use]
    pub const fn code(&self) -> &'static str {
        match self {
            Self::ImmutableConflict { .. } => "remote.keystore.immutable_conflict",
            Self::PersistenceReadbackFailed { .. } | Self::DeleteReadbackFailed { .. } => {
                "remote.keystore.persistence_failed"
            }
            Self::BackendUnavailable | Self::Poisoned => "remote.keystore.unavailable",
        }
    }
}

/// Secret storage seam。所有成功 mutation 都必须完成 exact readback。
pub trait RemoteKeyStore: Send + Sync {
    fn load(&self, account: &RemoteKeyAccount)
    -> Result<Option<RemoteSecret>, RemoteKeyStoreError>;

    /// 原子 insert-if-absent；same-bytes retry 幂等，different-bytes 永不覆盖。
    fn persist_immutable(
        &self,
        account: &RemoteKeyAccount,
        value: &RemoteSecret,
    ) -> Result<RemoteKeyPersistence, RemoteKeyStoreError>;

    /// 删除后必须读回 absent；重复删除幂等。
    fn delete_exact(&self, account: &RemoteKeyAccount) -> Result<(), RemoteKeyStoreError>;
}

/// 仅供 injected automatic/library harness 使用的进程内 remote keystore。
#[derive(Default)]
pub struct MemoryRemoteKeyStore {
    values: Mutex<HashMap<RemoteKeyAccount, RemoteSecret>>,
}

impl MemoryRemoteKeyStore {
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }
}

impl RemoteKeyStore for MemoryRemoteKeyStore {
    fn load(
        &self,
        account: &RemoteKeyAccount,
    ) -> Result<Option<RemoteSecret>, RemoteKeyStoreError> {
        let values = self
            .values
            .lock()
            .map_err(|_| RemoteKeyStoreError::Poisoned)?;
        Ok(values
            .get(account)
            .map(|value| RemoteSecret::new(value.expose_secret().to_vec())))
    }

    fn persist_immutable(
        &self,
        account: &RemoteKeyAccount,
        value: &RemoteSecret,
    ) -> Result<RemoteKeyPersistence, RemoteKeyStoreError> {
        let mut values = self
            .values
            .lock()
            .map_err(|_| RemoteKeyStoreError::Poisoned)?;
        let outcome = match values.get(account) {
            Some(persisted) if persisted.expose_secret() == value.expose_secret() => {
                RemoteKeyPersistence::AlreadyPresent
            }
            Some(_) => {
                return Err(RemoteKeyStoreError::ImmutableConflict {
                    account: account.clone(),
                });
            }
            None => {
                values.insert(
                    account.clone(),
                    RemoteSecret::new(value.expose_secret().to_vec()),
                );
                RemoteKeyPersistence::Inserted
            }
        };

        if values
            .get(account)
            .is_none_or(|persisted| persisted.expose_secret() != value.expose_secret())
        {
            return Err(RemoteKeyStoreError::PersistenceReadbackFailed {
                account: account.clone(),
            });
        }
        Ok(outcome)
    }

    fn delete_exact(&self, account: &RemoteKeyAccount) -> Result<(), RemoteKeyStoreError> {
        let mut values = self
            .values
            .lock()
            .map_err(|_| RemoteKeyStoreError::Poisoned)?;
        values.remove(account);
        if values.contains_key(account) {
            return Err(RemoteKeyStoreError::DeleteReadbackFailed {
                account: account.clone(),
            });
        }
        Ok(())
    }
}
