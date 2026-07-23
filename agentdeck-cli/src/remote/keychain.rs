//! Persistent remote client 的 Keychain account 与可注入 secret-store primitive。
//!
//! 本模块冻结 account 命名和 immutable/exact-readback 语义；production macOS
//! Data Protection Keychain adapter 由 sibling `macos_keychain` 在签名 type-state 后接入。
//! [`MemoryRemoteKeyStore`] 只能由 library/test harness 显式注入，不提供 CLI、环境变量
//! 或配置文件选择面。

use std::collections::{HashMap, HashSet};
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
/// 单一 CLI installation 允许恢复的 paired machine marker 硬上界。
pub const MAX_PAIRED_COMMIT_MARKERS_PER_INSTALLATION: usize = 256;
/// 单次 Data Protection Keychain attributes 查询允许返回的总 item 硬上界。
///
/// 同一 CLI-only access group/service 可包含多个 installation、pending item 与每台机器的
/// final item，因此本上界高于 paired machine marker 上界；production 查询只取 `limit + 1`
/// 条用于 fail-close 判定，不会无界枚举。
pub const MAX_ENUMERATED_REMOTE_KEYCHAIN_ACCOUNT_ATTRIBUTES: usize = 4_096;
pub(crate) const MAX_REMOTE_KEY_ACCOUNT_BYTES: usize = 160;
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
#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
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

impl PairedRemoteKeyPurpose {
    fn from_account_component(component: &str) -> Option<Self> {
        match component {
            "device-sign-private-key.v1" => Some(Self::DeviceSignPrivateKey),
            "device-hpke-private-key.v1" => Some(Self::DeviceHpkePrivateKey),
            "device-grant.v1" => Some(Self::DeviceGrant),
            "device-storage-kek.v1" => Some(Self::DeviceStorageKek),
            "counter-guard.v1" => Some(Self::CounterGuard),
            "paired-commit-marker.v1" => Some(Self::CommitMarker),
            _ => None,
        }
    }
}

/// 严格解码后的 paired Keychain account；原始文本只有逐字 canonical 才能构造。
#[derive(Clone, Eq, PartialEq)]
pub struct ParsedPairedRemoteKeyAccount {
    account: RemoteKeyAccount,
    installation_id: Uuid,
    machine_root_fingerprint: MachineRootFingerprint,
    machine_route: MachineRouteId,
    purpose: PairedRemoteKeyPurpose,
}

impl ParsedPairedRemoteKeyAccount {
    #[must_use]
    pub const fn account(&self) -> &RemoteKeyAccount {
        &self.account
    }

    #[must_use]
    pub const fn installation_id(&self) -> Uuid {
        self.installation_id
    }

    #[must_use]
    pub const fn machine_root_fingerprint(&self) -> MachineRootFingerprint {
        self.machine_root_fingerprint
    }

    #[must_use]
    pub const fn machine_route(&self) -> MachineRouteId {
        self.machine_route
    }

    #[must_use]
    pub const fn purpose(&self) -> PairedRemoteKeyPurpose {
        self.purpose
    }
}

impl fmt::Debug for ParsedPairedRemoteKeyAccount {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("ParsedPairedRemoteKeyAccount")
            .field("account", &self.account)
            .field("purpose", &self.purpose)
            .finish_non_exhaustive()
    }
}

#[derive(Clone, Copy, Debug, Error, Eq, PartialEq)]
#[error("remote Keychain account is malformed or noncanonical")]
pub struct RemoteKeyAccountParseError;

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

    /// 严格解析 paired account，并用 typed 字段重编码后逐字比对 canonical 文本。
    ///
    /// 不接受 pending namespace、非小写 hyphenated UUID、带 padding/非 URL-safe Base64、
    /// 未知 purpose、额外 component 或超长输入。
    pub fn parse_paired(
        canonical: &str,
    ) -> Result<ParsedPairedRemoteKeyAccount, RemoteKeyAccountParseError> {
        if canonical.len() > MAX_REMOTE_KEY_ACCOUNT_BYTES || !canonical.is_ascii() {
            return Err(RemoteKeyAccountParseError);
        }
        let components = canonical.split('/').collect::<Vec<_>>();
        let [client_kind, installation, root, route, purpose] = components.as_slice() else {
            return Err(RemoteKeyAccountParseError);
        };
        if *client_kind != "cli" {
            return Err(RemoteKeyAccountParseError);
        }

        let installation_id =
            Uuid::parse_str(installation).map_err(|_| RemoteKeyAccountParseError)?;
        let machine_root_fingerprint =
            MachineRootFingerprint::from_bytes(decode_account_component(root)?);
        let machine_route = MachineRouteId::from_bytes(decode_account_component(route)?);
        let purpose = PairedRemoteKeyPurpose::from_account_component(purpose)
            .ok_or(RemoteKeyAccountParseError)?;
        let account = Self::paired(
            installation_id,
            machine_root_fingerprint,
            machine_route,
            purpose,
        );
        if account.as_str() != canonical {
            return Err(RemoteKeyAccountParseError);
        }
        Ok(ParsedPairedRemoteKeyAccount {
            account,
            installation_id,
            machine_root_fingerprint,
            machine_route,
            purpose,
        })
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
    #[error("remote Keychain item {account} is missing for compare-and-replace")]
    CompareAndReplaceMissing { account: RemoteKeyAccount },
    #[error("remote Keychain item {account} does not match compare-and-replace expected bytes")]
    CompareAndReplaceMismatch { account: RemoteKeyAccount },
    #[error("remote Keychain item {account} compare-and-replace commit is unknown")]
    CompareAndReplaceCommitUnknown { account: RemoteKeyAccount },
    #[error("remote Keychain account enumeration contained a malformed or noncanonical item")]
    MalformedEnumeratedAccount,
    #[error("remote Keychain account enumeration contained a duplicate item")]
    DuplicateEnumeratedAccount,
    #[error("remote Keychain account enumeration exceeded its fixed limit")]
    EnumerationLimitExceeded,
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
            Self::CompareAndReplaceMissing { .. } => "remote.keystore.compare_and_replace_missing",
            Self::CompareAndReplaceMismatch { .. } => {
                "remote.keystore.compare_and_replace_mismatch"
            }
            Self::CompareAndReplaceCommitUnknown { .. } => {
                "remote.keystore.compare_and_replace_commit_unknown"
            }
            Self::MalformedEnumeratedAccount | Self::DuplicateEnumeratedAccount => {
                "remote.keystore.enumeration_integrity_failed"
            }
            Self::EnumerationLimitExceeded => "remote.keystore.enumeration_limit_exceeded",
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

    /// 只更新已存在且逐字匹配 `expected` 的 item；成功前必须逐字读回 `replacement`。
    ///
    /// 默认实现让尚未使用可变 Keychain state 的 injected fault stores 保持显式 unavailable；
    /// production 与标准 memory backend 必须覆盖此方法。
    fn compare_and_replace_exact(
        &self,
        _account: &RemoteKeyAccount,
        _expected: &RemoteSecret,
        _replacement: &RemoteSecret,
    ) -> Result<(), RemoteKeyStoreError> {
        Err(RemoteKeyStoreError::BackendUnavailable)
    }

    /// 删除后必须读回 absent；重复删除幂等。
    fn delete_exact(&self, account: &RemoteKeyAccount) -> Result<(), RemoteKeyStoreError>;

    /// 只返回当前 installation 的 canonical paired commit-marker attributes。
    ///
    /// 默认实现让既有 injected fault stores 保持显式 unavailable；production 与标准 memory
    /// backend 必须覆盖此方法，且不得通过枚举接口读取 private value。
    fn list_paired_commit_markers(
        &self,
        _installation_id: Uuid,
    ) -> Result<Vec<ParsedPairedRemoteKeyAccount>, RemoteKeyStoreError> {
        Err(RemoteKeyStoreError::BackendUnavailable)
    }
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

    fn compare_and_replace_exact(
        &self,
        account: &RemoteKeyAccount,
        expected: &RemoteSecret,
        replacement: &RemoteSecret,
    ) -> Result<(), RemoteKeyStoreError> {
        let mut values = self
            .values
            .lock()
            .map_err(|_| RemoteKeyStoreError::Poisoned)?;
        let Some(current) = values.get(account) else {
            return Err(RemoteKeyStoreError::CompareAndReplaceMissing {
                account: account.clone(),
            });
        };
        if current.expose_secret() != expected.expose_secret() {
            return Err(RemoteKeyStoreError::CompareAndReplaceMismatch {
                account: account.clone(),
            });
        }

        values.insert(
            account.clone(),
            RemoteSecret::new(replacement.expose_secret().to_vec()),
        );
        if values
            .get(account)
            .is_none_or(|durable| durable.expose_secret() != replacement.expose_secret())
        {
            return Err(RemoteKeyStoreError::CompareAndReplaceCommitUnknown {
                account: account.clone(),
            });
        }
        Ok(())
    }

    fn list_paired_commit_markers(
        &self,
        installation_id: Uuid,
    ) -> Result<Vec<ParsedPairedRemoteKeyAccount>, RemoteKeyStoreError> {
        let accounts = self
            .values
            .lock()
            .map_err(|_| RemoteKeyStoreError::Poisoned)?
            .keys()
            .map(|account| account.as_str().to_owned())
            .collect();
        validate_enumerated_accounts(accounts, installation_id)
    }
}

fn decode_account_component<const N: usize>(
    canonical: &str,
) -> Result<[u8; N], RemoteKeyAccountParseError> {
    let expected_length = (N * 4).div_ceil(3);
    if canonical.len() != expected_length {
        return Err(RemoteKeyAccountParseError);
    }
    let decoded = URL_SAFE_NO_PAD
        .decode(canonical)
        .map_err(|_| RemoteKeyAccountParseError)?;
    let bytes: [u8; N] = decoded.try_into().map_err(|_| RemoteKeyAccountParseError)?;
    if URL_SAFE_NO_PAD.encode(bytes) != canonical {
        return Err(RemoteKeyAccountParseError);
    }
    Ok(bytes)
}

fn validate_pending_account(canonical: &str) -> Result<(), RemoteKeyAccountParseError> {
    if canonical.len() > MAX_REMOTE_KEY_ACCOUNT_BYTES || !canonical.is_ascii() {
        return Err(RemoteKeyAccountParseError);
    }
    let components = canonical.split('/').collect::<Vec<_>>();
    let [namespace, client_kind, installation, invite_hash, purpose] = components.as_slice() else {
        return Err(RemoteKeyAccountParseError);
    };
    if *namespace != "pending" || *client_kind != "cli" {
        return Err(RemoteKeyAccountParseError);
    }
    let installation_id = Uuid::parse_str(installation).map_err(|_| RemoteKeyAccountParseError)?;
    let invite_hash = decode_account_component(invite_hash)?;
    let purpose = match *purpose {
        "pending-pairing-record.v1" => PendingRemoteKeyPurpose::PairingRecord,
        "device-sign-private-key.v1" => PendingRemoteKeyPurpose::DeviceSignPrivateKey,
        "device-hpke-private-key.v1" => PendingRemoteKeyPurpose::DeviceHpkePrivateKey,
        _ => return Err(RemoteKeyAccountParseError),
    };
    if RemoteKeyAccount::pending(installation_id, invite_hash, purpose).as_str() != canonical {
        return Err(RemoteKeyAccountParseError);
    }
    Ok(())
}

pub(crate) fn validate_enumerated_accounts(
    accounts: Vec<String>,
    installation_id: Uuid,
) -> Result<Vec<ParsedPairedRemoteKeyAccount>, RemoteKeyStoreError> {
    if accounts.len() > MAX_ENUMERATED_REMOTE_KEYCHAIN_ACCOUNT_ATTRIBUTES {
        return Err(RemoteKeyStoreError::EnumerationLimitExceeded);
    }

    let mut seen = HashSet::with_capacity(accounts.len());
    let mut markers = Vec::new();
    for canonical in accounts {
        if !seen.insert(canonical.clone()) {
            return Err(RemoteKeyStoreError::DuplicateEnumeratedAccount);
        }
        if canonical.starts_with("pending/") {
            validate_pending_account(&canonical)
                .map_err(|_| RemoteKeyStoreError::MalformedEnumeratedAccount)?;
            continue;
        }
        let parsed = RemoteKeyAccount::parse_paired(&canonical)
            .map_err(|_| RemoteKeyStoreError::MalformedEnumeratedAccount)?;
        if parsed.installation_id() == installation_id
            && parsed.purpose() == PairedRemoteKeyPurpose::CommitMarker
        {
            markers.push(parsed);
            if markers.len() > MAX_PAIRED_COMMIT_MARKERS_PER_INSTALLATION {
                return Err(RemoteKeyStoreError::EnumerationLimitExceeded);
            }
        }
    }
    markers.sort_unstable_by(|left, right| left.account().as_str().cmp(right.account().as_str()));
    Ok(markers)
}
