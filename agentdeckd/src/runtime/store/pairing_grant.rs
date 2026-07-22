//! `awaitingLocalConfirmation -> grantPreparing` 的 durable confirm CAS。
//!
//! Relay 可见 grant、设备私有 authorization/directory/response、daemon 内部全局 key
//! state 与 InstallGrant outbox 在同一 SQLite 事务冻结。`remote_key_directory` 只保存
//! daemon-private 全局 key state；按设备渲染的签名目录只存在 pairing frozen payload。

use std::collections::{HashMap, HashSet};

use agentdeck_crypto::{
    SecretAeadKey, SignatureBytes, VerifyingKey, sha256, verify_device_authorization,
    verify_key_directory, verify_pair_response_envelope, verify_tbs,
};
use agentdeck_protocol::e2ee::{
    DeviceAuthorizationV1, E2EE_FORMAT_VERSION, KeyDirectorySignatureContextV1, KeyDirectoryV1,
    KeyPurpose, MachineDataSignerBindingV1, OuterContextV1, OuterFrameKind, PairInviteV1,
    PairRequestPlaintextV1, PairResponseInfoV1, PairResponseV1,
};
use agentdeck_protocol::relay_v2::frame::{InstallGrant, OpaqueRouteFrame, RelayFrameBody};
use agentdeck_protocol::relay_v2::{
    DeviceRouteId, GrantSerial, KeyDirectoryRevision, PairRouteId, RELAY_PROTOCOL_VERSION,
    RelayGrant, StreamRouteId, decode, encode,
};
use agentdeck_protocol::runtime::{PairingReceipt, RUNTIME_PROTOCOL_VERSION};
use rusqlite::{Connection, OptionalExtension};
use zeroize::Zeroizing;

use crate::runtime::model::RuntimeStoreError;
use crate::security::SecretBytes;

use super::cipher::{RowAad, RuntimeKeyBundle};
use super::identity::{RuntimeId, RuntimeIdKind};
use super::pairing::{AuthenticatedPairingRow, PairingInviteLifecycle};
use super::pairing_authorization::{
    AuthenticatedAuthorization, AuthorizationLifecycle, MAX_AUTHORIZATION_SEALED_BYTES,
    MAX_AUTHORIZATIONS, load_authorizations,
};
use super::pairing_revocation::{
    AuthenticatedRevocationOutbox, load_revocation_outboxes, validate_revocation_signature,
};
use super::schema::{RUNTIME_CRYPTO_CONTEXT_VERSION, RUNTIME_SCHEMA_FAMILY};
use super::sqlite::RuntimeLedger;

const GLOBAL_KEY_MAGIC_V1: &[u8; 5] = b"ADGK1";
const GLOBAL_KEY_MAGIC_V2: &[u8; 5] = b"ADGK2";
pub(super) const GLOBAL_KEY_TABLE: &[u8] = b"remote_key_directory";
pub(super) const GLOBAL_KEY_COLUMN: &[u8] = b"sealed_directory";
const OUTBOX_TABLE: &[u8] = b"remote_control_outbox";
const OUTBOX_COLUMN: &[u8] = b"sealed_frame";
const GLOBAL_KEY_METADATA_DOMAIN: &[u8] = b"remote.key-directory.metadata.v1";
const INSTALL_OPERATION_DOMAIN: &[u8] = b"remote.control.install-grant.operation.v1";
const OUTBOX_METADATA_DOMAIN: &[u8] = b"remote.control.outbox.metadata.v1";
pub(super) const MAX_GLOBAL_KEY_STATE_BYTES: usize = 64 * 1024 * 1024;
pub(super) const MAX_DEVICES: usize = 256;
const MAX_DEVICE_RECORDS: usize = MAX_DEVICES;
pub(crate) const MAX_RETENTION_OWNERS_PER_KEY: usize = 256;
const MAX_RETIRED_KEY_TOMBSTONES: usize = 65_536;
const MAX_ACTIVE_CONVERSATIONS: usize = 1_024;
const LEGACY_RETIREMENT_TIME_UNKNOWN: u64 = u64::MAX;
const RETIRED_SHARED_KEY_OWNER_BYTES: usize = 42;
const RETIRED_SHARED_KEY_TARGET_BYTES: usize = 25;
const INTERNAL_KEY_BASE_BYTES: usize = 8 + 8 + 2 + 32;
const REMOVED_DEVICE_TRANSPORT_SECRET: [u8; 32] = [0; 32];
#[allow(dead_code)] // P4.5 key-retirement coordinator consumes this after transaction wiring.
pub(crate) const RETIRED_KEY_RETENTION_MS: u64 = 25 * 60 * 60 * 1_000;

/// durable retention owner 类型。完整 owner identity 代替递增计数，使 acquire/release
/// 在崩溃恢复后仍可幂等重试。
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
#[allow(dead_code)] // P4.5 publisher/replay/snapshot coordinators consume this seam.
pub(crate) enum RetiredKeyOwnerKind {
    Publication,
    Replay,
    Snapshot,
}

impl RetiredKeyOwnerKind {
    const fn tag(self) -> u8 {
        match self {
            Self::Publication => 0,
            Self::Replay => 1,
            Self::Snapshot => 2,
        }
    }

    fn from_tag(tag: u8) -> Result<Self, RuntimeStoreError> {
        match tag {
            0 => Ok(Self::Publication),
            1 => Ok(Self::Replay),
            2 => Ok(Self::Snapshot),
            _ => Err(RuntimeStoreError::UnknownOrCorruptSchema),
        }
    }
}

/// 一个 durable owner 只绑定一条 retired shared-key identity。
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
#[allow(dead_code)] // P4.5 publisher/replay/snapshot coordinators consume this seam.
pub(crate) struct RetiredSharedKeyOwner {
    kind: RetiredKeyOwnerKind,
    owner_id: [u8; 16],
    purpose: KeyPurpose,
    stream_route: Option<StreamRouteId>,
    epoch: u64,
}

#[allow(dead_code)] // P4.5 publisher/replay/snapshot coordinators consume this seam.
impl RetiredSharedKeyOwner {
    pub(crate) fn new(
        kind: RetiredKeyOwnerKind,
        owner_id: [u8; 16],
        purpose: KeyPurpose,
        stream_route: Option<StreamRouteId>,
        epoch: u64,
    ) -> Result<Self, RuntimeStoreError> {
        if owner_id == [0; 16] || epoch == 0 {
            return Err(RuntimeStoreError::PairingConflict);
        }
        match (purpose, stream_route) {
            (KeyPurpose::Catalog, None) => {}
            (KeyPurpose::ConversationDek, Some(route)) if route.as_bytes() != &[0; 16] => {}
            _ => return Err(RuntimeStoreError::PairingConflict),
        }
        Ok(Self {
            kind,
            owner_id,
            purpose,
            stream_route,
            epoch,
        })
    }

    fn canonical_bytes(self) -> [u8; RETIRED_SHARED_KEY_OWNER_BYTES] {
        let mut encoded = [0_u8; RETIRED_SHARED_KEY_OWNER_BYTES];
        encoded[0] = self.kind.tag();
        encoded[1..17].copy_from_slice(&self.owner_id);
        encoded[17] = match self.purpose {
            KeyPurpose::Catalog => 0,
            KeyPurpose::ConversationDek => 1,
            KeyPurpose::DeviceCommandTx => 2,
            KeyPurpose::DeviceReplyTx => 3,
        };
        if let Some(route) = self.stream_route {
            encoded[18..34].copy_from_slice(route.as_bytes());
        }
        encoded[34..42].copy_from_slice(&self.epoch.to_be_bytes());
        encoded
    }

    fn from_canonical_bytes(encoded: &[u8]) -> Result<Self, RuntimeStoreError> {
        let encoded: &[u8; RETIRED_SHARED_KEY_OWNER_BYTES] = encoded
            .try_into()
            .map_err(|_| RuntimeStoreError::UnknownOrCorruptSchema)?;
        let kind = RetiredKeyOwnerKind::from_tag(encoded[0])?;
        let owner_id = encoded[1..17]
            .try_into()
            .map_err(|_| RuntimeStoreError::UnknownOrCorruptSchema)?;
        let purpose = match encoded[17] {
            0 => KeyPurpose::Catalog,
            1 => KeyPurpose::ConversationDek,
            2 => KeyPurpose::DeviceCommandTx,
            3 => KeyPurpose::DeviceReplyTx,
            _ => return Err(RuntimeStoreError::UnknownOrCorruptSchema),
        };
        let route_bytes: [u8; 16] = encoded[18..34]
            .try_into()
            .map_err(|_| RuntimeStoreError::UnknownOrCorruptSchema)?;
        let stream_route = (route_bytes != [0; 16]).then(|| StreamRouteId::from_bytes(route_bytes));
        let epoch = u64::from_be_bytes(
            encoded[34..42]
                .try_into()
                .map_err(|_| RuntimeStoreError::UnknownOrCorruptSchema)?,
        );
        Self::new(kind, owner_id, purpose, stream_route, epoch)
            .map_err(|_| RuntimeStoreError::UnknownOrCorruptSchema)
    }

    fn binds_to(
        self,
        purpose: KeyPurpose,
        stream_route: Option<StreamRouteId>,
        epoch: u64,
    ) -> bool {
        self.purpose == purpose && self.stream_route == stream_route && self.epoch == epoch
    }

    fn target(self) -> RetiredSharedKeyTarget {
        RetiredSharedKeyTarget {
            purpose: self.purpose,
            stream_route: self.stream_route,
            epoch: self.epoch,
        }
    }
}

/// 已完成 25 小时保留并删除 secret 后留下的最小 target 证据。它只用于判定
/// release exact retry，不能恢复 key、创建 owner 或授权任意 missing target。
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
struct RetiredSharedKeyTarget {
    purpose: KeyPurpose,
    stream_route: Option<StreamRouteId>,
    epoch: u64,
}

impl RetiredSharedKeyTarget {
    fn new(
        purpose: KeyPurpose,
        stream_route: Option<StreamRouteId>,
        epoch: u64,
    ) -> Result<Self, RuntimeStoreError> {
        if epoch == 0 {
            return Err(RuntimeStoreError::PairingConflict);
        }
        match (purpose, stream_route) {
            (KeyPurpose::Catalog, None) => {}
            (KeyPurpose::ConversationDek, Some(route)) if route.as_bytes() != &[0; 16] => {}
            _ => return Err(RuntimeStoreError::PairingConflict),
        }
        Ok(Self {
            purpose,
            stream_route,
            epoch,
        })
    }

    fn canonical_bytes(self) -> [u8; RETIRED_SHARED_KEY_TARGET_BYTES] {
        let mut encoded = [0_u8; RETIRED_SHARED_KEY_TARGET_BYTES];
        encoded[0] = match self.purpose {
            KeyPurpose::Catalog => 0,
            KeyPurpose::ConversationDek => 1,
            KeyPurpose::DeviceCommandTx | KeyPurpose::DeviceReplyTx => {
                unreachable!("validated retired shared-key target purpose")
            }
        };
        if let Some(route) = self.stream_route {
            encoded[1..17].copy_from_slice(route.as_bytes());
        }
        encoded[17..25].copy_from_slice(&self.epoch.to_be_bytes());
        encoded
    }

    fn from_canonical_bytes(encoded: &[u8]) -> Result<Self, RuntimeStoreError> {
        let encoded: &[u8; RETIRED_SHARED_KEY_TARGET_BYTES] = encoded
            .try_into()
            .map_err(|_| RuntimeStoreError::UnknownOrCorruptSchema)?;
        let purpose = match encoded[0] {
            0 => KeyPurpose::Catalog,
            1 => KeyPurpose::ConversationDek,
            _ => return Err(RuntimeStoreError::UnknownOrCorruptSchema),
        };
        let route_bytes: [u8; 16] = encoded[1..17]
            .try_into()
            .map_err(|_| RuntimeStoreError::UnknownOrCorruptSchema)?;
        let stream_route = (route_bytes != [0; 16]).then(|| StreamRouteId::from_bytes(route_bytes));
        let epoch = u64::from_be_bytes(
            encoded[17..25]
                .try_into()
                .map_err(|_| RuntimeStoreError::UnknownOrCorruptSchema)?,
        );
        Self::new(purpose, stream_route, epoch)
            .map_err(|_| RuntimeStoreError::UnknownOrCorruptSchema)
    }
}

pub(super) struct InternalKey {
    pub(super) epoch: u64,
    pub(super) key: SecretBytes,
    retired_at_ms: Option<u64>,
    retention_owners: Vec<RetiredSharedKeyOwner>,
}

impl InternalKey {
    pub(super) fn new(epoch: u64, key: SecretBytes) -> Result<Self, RuntimeStoreError> {
        if epoch == 0
            || key.expose_secret().len() != 32
            || key.expose_secret().iter().all(|byte| *byte == 0)
        {
            return Err(RuntimeStoreError::PairingConflict);
        }
        Ok(Self {
            epoch,
            key,
            retired_at_ms: None,
            retention_owners: Vec::new(),
        })
    }

    fn as_secret_aead_key(&self) -> Result<SecretAeadKey, RuntimeStoreError> {
        let bytes: [u8; 32] = self
            .key
            .expose_secret()
            .try_into()
            .map_err(|_| RuntimeStoreError::UnknownOrCorruptSchema)?;
        Ok(SecretAeadKey::from_bytes(bytes))
    }

    #[allow(dead_code)] // P4.5 membership rotation seam.
    fn retire_at(&mut self, retired_at_ms: u64) -> Result<(), RuntimeStoreError> {
        if self.retired_at_ms.is_some()
            || retired_at_ms == 0
            || retired_at_ms == LEGACY_RETIREMENT_TIME_UNKNOWN
        {
            return Err(RuntimeStoreError::PairingConflict);
        }
        self.retired_at_ms = Some(retired_at_ms);
        Ok(())
    }

    pub(super) fn retire_with_unknown_legacy_time(&mut self) -> Result<(), RuntimeStoreError> {
        if self.retired_at_ms.is_some() {
            return Err(RuntimeStoreError::PairingConflict);
        }
        self.retired_at_ms = Some(LEGACY_RETIREMENT_TIME_UNKNOWN);
        Ok(())
    }

    #[allow(dead_code)] // P4.5 key-retirement coordinator seam.
    fn retention_expired(&self, now_ms: u64) -> bool {
        self.retention_owners.is_empty()
            && self.retired_at_ms.is_some_and(|retired_at_ms| {
                retired_at_ms != LEGACY_RETIREMENT_TIME_UNKNOWN
                    && retired_at_ms
                        .checked_add(RETIRED_KEY_RETENTION_MS)
                        .is_some_and(|deadline| now_ms >= deadline)
            })
    }
}

/// Device route tombstone 继续保留双方向 epoch 供历史 authorization/directory 审计，
/// 但 retention 到期后 `key=None`，canonical ADGK2 固定宽度位置只写全零 absent marker。
/// active device 与 retention 窗口内的 revoked device 必须始终同时持有两把 secret。
pub(super) struct DeviceTransportKey {
    pub(super) epoch: u64,
    pub(super) key: Option<SecretBytes>,
}

impl DeviceTransportKey {
    pub(super) fn new(epoch: u64, key: SecretBytes) -> Result<Self, RuntimeStoreError> {
        if epoch == 0
            || key.expose_secret().len() != 32
            || key.expose_secret().iter().all(|byte| *byte == 0)
        {
            return Err(RuntimeStoreError::PairingConflict);
        }
        Ok(Self {
            epoch,
            key: Some(key),
        })
    }

    const fn removed(epoch: u64) -> Result<Self, RuntimeStoreError> {
        if epoch == 0 {
            return Err(RuntimeStoreError::PairingConflict);
        }
        Ok(Self { epoch, key: None })
    }

    fn as_secret_aead_key(&self) -> Result<SecretAeadKey, RuntimeStoreError> {
        let bytes: [u8; 32] = self
            .key
            .as_ref()
            .ok_or(RuntimeStoreError::PairingConflict)?
            .expose_secret()
            .try_into()
            .map_err(|_| RuntimeStoreError::UnknownOrCorruptSchema)?;
        Ok(SecretAeadKey::from_bytes(bytes))
    }

    fn encoded_secret(&self) -> &[u8; 32] {
        self.key
            .as_ref()
            .and_then(|key| key.expose_secret().try_into().ok())
            .unwrap_or(&REMOVED_DEVICE_TRANSPORT_SECRET)
    }

    const fn has_secret(&self) -> bool {
        self.key.is_some()
    }
}

pub(super) struct DeviceKeys {
    pub(super) device_route: DeviceRouteId,
    pub(super) command: DeviceTransportKey,
    pub(super) reply: DeviceTransportKey,
    revoked_at_ms: Option<u64>,
}

impl DeviceKeys {
    fn new(
        device_route: DeviceRouteId,
        command_epoch: u64,
        command_key: SecretBytes,
        reply_epoch: u64,
        reply_key: SecretBytes,
    ) -> Result<Self, RuntimeStoreError> {
        if device_route.as_bytes() == &[0; 16] {
            return Err(RuntimeStoreError::PairingConflict);
        }
        Ok(Self {
            device_route,
            command: DeviceTransportKey::new(command_epoch, command_key)?,
            reply: DeviceTransportKey::new(reply_epoch, reply_key)?,
            revoked_at_ms: None,
        })
    }

    fn removed(
        device_route: DeviceRouteId,
        command_epoch: u64,
        reply_epoch: u64,
        revoked_at_ms: u64,
    ) -> Result<Self, RuntimeStoreError> {
        if device_route.as_bytes() == &[0; 16]
            || revoked_at_ms == 0
            || revoked_at_ms == LEGACY_RETIREMENT_TIME_UNKNOWN
        {
            return Err(RuntimeStoreError::PairingConflict);
        }
        Ok(Self {
            device_route,
            command: DeviceTransportKey::removed(command_epoch)?,
            reply: DeviceTransportKey::removed(reply_epoch)?,
            revoked_at_ms: Some(revoked_at_ms),
        })
    }

    pub(super) fn is_active(&self) -> bool {
        self.revoked_at_ms.is_none()
    }

    fn has_transport_secrets(&self) -> bool {
        self.command.has_secret() && self.reply.has_secret()
    }

    fn transport_secrets_expired(&self, now_ms: u64) -> bool {
        self.has_transport_secrets()
            && self.revoked_at_ms.is_some_and(|revoked_at_ms| {
                revoked_at_ms
                    .checked_add(RETIRED_KEY_RETENTION_MS)
                    .is_some_and(|deadline| now_ms >= deadline)
            })
    }

    fn remove_transport_secrets(&mut self) -> Result<(), RuntimeStoreError> {
        if self.is_active() || !self.has_transport_secrets() {
            return Err(RuntimeStoreError::PairingConflict);
        }
        self.command.key = None;
        self.reply.key = None;
        Ok(())
    }
}

pub(super) struct ConversationKeys {
    stream_route: StreamRouteId,
    history: Vec<InternalKey>,
}

/// StorageKEK 下持久化的 daemon-private 全局 key state。它不是任何单设备公开目录。
pub(crate) struct GlobalKeyStateV1 {
    pub(super) revision: u64,
    pub(super) catalogs: Vec<InternalKey>,
    pub(super) devices: Vec<DeviceKeys>,
    conversations: Vec<ConversationKeys>,
    retired_key_tombstones: Vec<RetiredSharedKeyTarget>,
}

impl std::fmt::Debug for GlobalKeyStateV1 {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("GlobalKeyStateV1")
            .field("revision", &self.revision)
            .field("device_count", &self.devices.len())
            .field("conversation_count", &self.conversations.len())
            .field(
                "retired_key_tombstone_count",
                &self.retired_key_tombstones.len(),
            )
            .field("key_material", &"[REDACTED]")
            .finish()
    }
}

/// builder 用于按新设备渲染严格三项 bootstrap directory 的借用副本。
pub(crate) struct BootstrapKeyView {
    pub(crate) purpose: KeyPurpose,
    pub(crate) stream_route: Option<StreamRouteId>,
    pub(crate) epoch: u64,
    pub(crate) key: SecretAeadKey,
}

/// 成员变化时每条 active conversation 必须且只能提交一个新 key。
#[allow(dead_code)] // P4.5 manager composition consumes this after the Store slice.
pub(crate) struct ConversationKeyRotation {
    stream_route: StreamRouteId,
    key: SecretBytes,
}

#[allow(dead_code)] // P4.5 manager composition consumes this after the Store slice.
impl ConversationKeyRotation {
    #[must_use]
    pub(crate) const fn new(stream_route: StreamRouteId, key: SecretBytes) -> Self {
        Self { stream_route, key }
    }
}

/// 当前 shared key 的借用副本；由 publisher/key-update coordinator 消费。
#[allow(dead_code)] // P4.5 signed publisher composition seam.
pub(crate) struct SharedKeyView {
    pub(crate) purpose: KeyPurpose,
    pub(crate) stream_route: Option<StreamRouteId>,
    pub(crate) epoch: u64,
    #[allow(dead_code)] // P4.5 signed publisher composition consumes the secret after this slice.
    pub(crate) key: SecretAeadKey,
}

/// retired shared key 的 durable retention/readback 投影。publisher/replay 先登记 owner，
/// 完成 frozen publication 或 replay retention 后再精确 release；owner 非空时 GC 必须保留。
#[allow(dead_code)] // P4.5 replay/key-retirement composition seam.
pub(crate) struct RetiredSharedKeyView {
    pub(crate) purpose: KeyPurpose,
    pub(crate) stream_route: Option<StreamRouteId>,
    pub(crate) epoch: u64,
    pub(crate) retired_at_ms: u64,
    pub(crate) retention_owners: Vec<RetiredSharedKeyOwner>,
    #[allow(dead_code)]
    // P4.5 replay/key-retirement composition consumes the secret after this slice.
    pub(crate) key: SecretAeadKey,
}

/// 一次成员变化中的 old/new epoch 轴。Relay-committed cut 由 publication Store 追加，
/// 不能由调用方把两份自报 cursor 填进本状态机。
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
#[allow(dead_code)] // P4.5 committed barrier composition seam.
pub(crate) struct SharedKeyTransition {
    pub(crate) purpose: KeyPurpose,
    pub(crate) stream_route: Option<StreamRouteId>,
    pub(crate) old_epoch: u64,
    pub(crate) new_epoch: u64,
    pub(crate) retired_at_ms: u64,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
#[allow(dead_code)] // P4.5 manager composition seam.
enum MembershipChange {
    Add(DeviceRouteId),
    Revoke(DeviceRouteId),
}

/// 纯状态机的原子输出。只有完整 Catalog + 所有 active conversation 轮换成功，
/// 才能取得 next state 与 barrier/key-update transition plan。
#[allow(dead_code)] // P4.5 manager/publisher composition seam.
pub(crate) struct MembershipKeyRotationPlan {
    state: GlobalKeyStateV1,
    change: MembershipChange,
    transitions: Vec<SharedKeyTransition>,
}

#[allow(dead_code)] // P4.5 manager/publisher composition seam.
impl MembershipKeyRotationPlan {
    #[must_use]
    pub(crate) const fn revision(&self) -> KeyDirectoryRevision {
        self.state.revision()
    }

    pub(crate) fn new_device_bootstrap(
        &self,
    ) -> Result<Option<[BootstrapKeyView; 3]>, RuntimeStoreError> {
        match self.change {
            MembershipChange::Add(route) => self.state.bootstrap_view(route).map(Some),
            MembershipChange::Revoke(_) => Ok(None),
        }
    }

    pub(crate) fn shared_updates_for_device(
        &self,
        route: DeviceRouteId,
    ) -> Result<Vec<SharedKeyView>, RuntimeStoreError> {
        if !self.state.device(route).is_some_and(DeviceKeys::is_active) {
            return Err(RuntimeStoreError::PairingConflict);
        }
        self.state.current_shared_keys()
    }

    #[must_use]
    pub(crate) fn transitions(&self) -> &[SharedKeyTransition] {
        &self.transitions
    }

    #[must_use]
    pub(crate) fn into_state(self) -> GlobalKeyStateV1 {
        self.state
    }

    #[cfg(test)]
    pub(crate) fn retired_key_count_for_test(&self) -> usize {
        self.state.retired_key_count_for_test()
    }

    #[cfg(test)]
    pub(crate) fn retired_at_values_for_test(&self) -> Vec<u64> {
        self.state.retired_at_values_for_test()
    }

    #[cfg(test)]
    pub(crate) fn device_revoked_at_for_test(&self, route: DeviceRouteId) -> Option<u64> {
        self.state.device_revoked_at_for_test(route)
    }
}

impl GlobalKeyStateV1 {
    #[allow(clippy::too_many_arguments)]
    #[cfg(test)]
    pub(crate) fn bootstrap(
        revision: u64,
        catalog_epoch: u64,
        catalog_key: SecretBytes,
        device_route: DeviceRouteId,
        command_epoch: u64,
        command_key: SecretBytes,
        reply_epoch: u64,
        reply_key: SecretBytes,
    ) -> Result<Self, RuntimeStoreError> {
        Self::bootstrap_with_conversations(
            revision,
            catalog_epoch,
            catalog_key,
            device_route,
            command_epoch,
            command_key,
            reply_epoch,
            reply_key,
            Vec::new(),
        )
    }

    /// 首次 grant 的单 revision bootstrap。所有已认证 conversation route 都在 revision=1
    /// 内取得 epoch-1 key；禁止逐 route 调用 `activate_conversation` 制造无 transition 的
    /// 中间 revision。
    #[allow(clippy::too_many_arguments)]
    pub(crate) fn bootstrap_with_conversations(
        revision: u64,
        catalog_epoch: u64,
        catalog_key: SecretBytes,
        device_route: DeviceRouteId,
        command_epoch: u64,
        command_key: SecretBytes,
        reply_epoch: u64,
        reply_key: SecretBytes,
        mut conversation_keys: Vec<ConversationKeyRotation>,
    ) -> Result<Self, RuntimeStoreError> {
        if revision != 1 {
            return Err(RuntimeStoreError::PairingConflict);
        }
        conversation_keys.sort_by_key(|entry| *entry.stream_route.as_bytes());
        if conversation_keys
            .windows(2)
            .any(|pair| pair[0].stream_route == pair[1].stream_route)
        {
            return Err(RuntimeStoreError::PairingConflict);
        }
        let conversations = conversation_keys
            .into_iter()
            .map(|entry| {
                Ok(ConversationKeys {
                    stream_route: entry.stream_route,
                    history: vec![InternalKey::new(1, entry.key)?],
                })
            })
            .collect::<Result<Vec<_>, RuntimeStoreError>>()?;
        let value = Self {
            revision,
            catalogs: vec![InternalKey::new(catalog_epoch, catalog_key)?],
            devices: vec![DeviceKeys::new(
                device_route,
                command_epoch,
                command_key,
                reply_epoch,
                reply_key,
            )?],
            conversations,
            retired_key_tombstones: Vec::new(),
        };
        value.validate()?;
        Ok(value)
    }

    /// 仅保留给旧 fixture 的兼容状态机；production add-member 固定走
    /// `plan_add_device`，不能按“当前恰好没有 conversation”降级。
    #[cfg(test)]
    pub(crate) fn next_for_device(
        self,
        device_route: DeviceRouteId,
        catalog_key: SecretBytes,
        command_key: SecretBytes,
        reply_key: SecretBytes,
    ) -> Result<Self, RuntimeStoreError> {
        self.plan_add_device(
            device_route,
            catalog_key,
            command_key,
            reply_key,
            Vec::new(),
            1,
        )
        .map(MembershipKeyRotationPlan::into_state)
    }

    /// 新 conversation stream 的初始 epoch。directory revision 与 daemon-private state
    /// 一起单调推进；发布前仍需由上层冻结 signed key update。
    #[allow(dead_code)] // P4.5 RuntimeCore conversation activation wiring follows this slice.
    pub(crate) fn activate_conversation(
        mut self,
        stream_route: StreamRouteId,
        key: SecretBytes,
    ) -> Result<Self, RuntimeStoreError> {
        self.validate()?;
        if stream_route.as_bytes() == &[0; 16]
            || self.conversations.len() >= MAX_ACTIVE_CONVERSATIONS
            || self
                .conversations
                .iter()
                .any(|conversation| conversation.stream_route == stream_route)
        {
            return Err(RuntimeStoreError::PairingConflict);
        }
        self.revision = self.checked_next_revision()?;
        self.conversations.push(ConversationKeys {
            stream_route,
            history: vec![InternalKey::new(1, key)?],
        });
        self.conversations
            .sort_by_key(|conversation| *conversation.stream_route.as_bytes());
        self.validate()?;
        Ok(self)
    }

    #[allow(clippy::too_many_arguments)]
    #[allow(dead_code)] // P4.5 pairing manager consumes the atomic plan after this slice.
    pub(crate) fn plan_add_device(
        mut self,
        device_route: DeviceRouteId,
        catalog_key: SecretBytes,
        command_key: SecretBytes,
        reply_key: SecretBytes,
        conversation_rotations: Vec<ConversationKeyRotation>,
        retired_at_ms: u64,
    ) -> Result<MembershipKeyRotationPlan, RuntimeStoreError> {
        self.validate()?;
        if self
            .devices
            .iter()
            .any(|device| device.device_route == device_route)
        {
            return Err(RuntimeStoreError::PairingConflict);
        }
        if self.devices.len() >= MAX_DEVICE_RECORDS
            || self
                .devices
                .iter()
                .filter(|device| device.has_transport_secrets())
                .count()
                >= MAX_DEVICES
        {
            return Err(RuntimeStoreError::PairingLimit);
        }
        let transitions =
            self.rotate_shared_keys(catalog_key, conversation_rotations, retired_at_ms)?;
        self.devices
            .push(DeviceKeys::new(device_route, 1, command_key, 1, reply_key)?);
        self.devices
            .sort_by_key(|device| *device.device_route.as_bytes());
        self.validate()?;
        Ok(MembershipKeyRotationPlan {
            state: self,
            change: MembershipChange::Add(device_route),
            transitions,
        })
    }

    /// durable revoke 事务必须一次消费完整 shared-key rotation plan；任何单 key
    /// 提前落盘都会破坏成员变更的原子边界。
    pub(crate) fn plan_revoke_device(
        mut self,
        device_route: DeviceRouteId,
        catalog_key: SecretBytes,
        conversation_rotations: Vec<ConversationKeyRotation>,
        retired_at_ms: u64,
    ) -> Result<MembershipKeyRotationPlan, RuntimeStoreError> {
        self.validate()?;
        let device_index = self
            .devices
            .iter()
            .position(|device| device.device_route == device_route && device.is_active())
            .ok_or(RuntimeStoreError::PairingConflict)?;
        let transitions =
            self.rotate_shared_keys(catalog_key, conversation_rotations, retired_at_ms)?;
        self.devices[device_index].revoked_at_ms = Some(retired_at_ms);
        self.validate()?;
        Ok(MembershipKeyRotationPlan {
            state: self,
            change: MembershipChange::Revoke(device_route),
            transitions,
        })
    }

    #[allow(dead_code)] // Used by the pending P4.5 manager composition seams above.
    fn rotate_shared_keys(
        &mut self,
        catalog_key: SecretBytes,
        mut conversation_rotations: Vec<ConversationKeyRotation>,
        retired_at_ms: u64,
    ) -> Result<Vec<SharedKeyTransition>, RuntimeStoreError> {
        if retired_at_ms == 0 || retired_at_ms == LEGACY_RETIREMENT_TIME_UNKNOWN {
            return Err(RuntimeStoreError::PairingConflict);
        }
        conversation_rotations.sort_by_key(|rotation| *rotation.stream_route.as_bytes());
        if conversation_rotations.len() != self.conversations.len()
            || conversation_rotations
                .iter()
                .zip(&self.conversations)
                .any(|(rotation, conversation)| rotation.stream_route != conversation.stream_route)
        {
            return Err(RuntimeStoreError::PairingConflict);
        }
        let next_revision = self.checked_next_revision()?;
        let catalog = self
            .catalogs
            .last_mut()
            .ok_or(RuntimeStoreError::UnknownOrCorruptSchema)?;
        let old_catalog_epoch = catalog.epoch;
        let new_catalog_epoch = old_catalog_epoch.checked_add(1).ok_or(
            RuntimeStoreError::CapacityArithmeticOverflow {
                field: "catalog_key_epoch",
            },
        )?;
        catalog.retire_at(retired_at_ms)?;
        self.catalogs
            .push(InternalKey::new(new_catalog_epoch, catalog_key)?);
        let mut transitions = Vec::with_capacity(1 + self.conversations.len());
        transitions.push(SharedKeyTransition {
            purpose: KeyPurpose::Catalog,
            stream_route: None,
            old_epoch: old_catalog_epoch,
            new_epoch: new_catalog_epoch,
            retired_at_ms,
        });
        for (conversation, rotation) in self.conversations.iter_mut().zip(conversation_rotations) {
            let current = conversation
                .history
                .last_mut()
                .ok_or(RuntimeStoreError::UnknownOrCorruptSchema)?;
            let old_epoch = current.epoch;
            let new_epoch =
                old_epoch
                    .checked_add(1)
                    .ok_or(RuntimeStoreError::CapacityArithmeticOverflow {
                        field: "conversation_key_epoch",
                    })?;
            current.retire_at(retired_at_ms)?;
            conversation
                .history
                .push(InternalKey::new(new_epoch, rotation.key)?);
            transitions.push(SharedKeyTransition {
                purpose: KeyPurpose::ConversationDek,
                stream_route: Some(conversation.stream_route),
                old_epoch,
                new_epoch,
                retired_at_ms,
            });
        }
        self.revision = next_revision;
        Ok(transitions)
    }

    #[allow(dead_code)] // Used by the pending P4.5 manager composition seams above.
    fn checked_next_revision(&self) -> Result<u64, RuntimeStoreError> {
        self.revision
            .checked_add(1)
            .ok_or(RuntimeStoreError::CapacityArithmeticOverflow {
                field: "remote_key_directory_revision",
            })
    }

    #[allow(dead_code)] // P4.5 replay/key-retirement composition seam.
    pub(crate) fn prune_expired_retired_keys(
        mut self,
        now_ms: u64,
    ) -> Result<Self, RuntimeStoreError> {
        self.validate()?;
        let mut collected_targets = Vec::new();
        for key in self
            .catalogs
            .iter()
            .filter(|key| key.retention_expired(now_ms))
        {
            collected_targets.push(RetiredSharedKeyTarget::new(
                KeyPurpose::Catalog,
                None,
                key.epoch,
            )?);
        }
        for conversation in &self.conversations {
            for key in conversation
                .history
                .iter()
                .filter(|key| key.retention_expired(now_ms))
            {
                collected_targets.push(RetiredSharedKeyTarget::new(
                    KeyPurpose::ConversationDek,
                    Some(conversation.stream_route),
                    key.epoch,
                )?);
            }
        }
        let collect_device_transport_secrets = self
            .devices
            .iter()
            .any(|device| device.transport_secrets_expired(now_ms));
        if collected_targets.is_empty() && !collect_device_transport_secrets {
            return Ok(self);
        }
        let mut next_tombstones = self.retired_key_tombstones.clone();
        next_tombstones.extend(collected_targets);
        next_tombstones.sort_by_key(|target| target.canonical_bytes());
        next_tombstones.dedup();
        if next_tombstones.len() > MAX_RETIRED_KEY_TOMBSTONES {
            return Err(RuntimeStoreError::PairingLimit);
        }
        // 先让 exact target tombstone 进入 candidate state 并按“尚未删除 secret”的
        // 更大尺寸做完整容量预检；任何失败都返回原 durable state 的 fail-retain。
        self.retired_key_tombstones = next_tombstones;
        self.ensure_canonical_capacity()?;
        self.catalogs.retain(|key| !key.retention_expired(now_ms));
        for conversation in &mut self.conversations {
            conversation
                .history
                .retain(|key| !key.retention_expired(now_ms));
        }
        for device in &mut self.devices {
            if device.transport_secrets_expired(now_ms) {
                device.remove_transport_secrets()?;
            }
        }
        self.validate()?;
        self.ensure_canonical_capacity()?;
        Ok(self)
    }

    /// CounterGuard/DB rollback 的 targeted shared-sender rekey。
    ///
    /// 与 membership rotation 不同，这里只轮换已确认发生 rollback 的 exact sender
    /// scope；directory revision 仍单调推进一次，旧 shared key 进入正常 retention，
    /// 由后续 `CounterRecovery` transition 对所有当前 recipient 分发新目录并发布
    /// 对应 stream 的 epoch barrier。
    pub(crate) fn rotate_counter_recovery_shared(
        mut self,
        purpose: KeyPurpose,
        stream_route: Option<StreamRouteId>,
        replacement_key: SecretBytes,
        retired_at_ms: u64,
    ) -> Result<(Self, SharedKeyTransition), RuntimeStoreError> {
        self.validate()?;
        if retired_at_ms == 0 || retired_at_ms == LEGACY_RETIREMENT_TIME_UNKNOWN {
            return Err(RuntimeStoreError::PairingConflict);
        }
        let history = self.shared_key_history_mut(purpose, stream_route)?;
        let current = history
            .last_mut()
            .ok_or(RuntimeStoreError::UnknownOrCorruptSchema)?;
        if replacement_key.expose_secret() == current.key.expose_secret() {
            return Err(RuntimeStoreError::PairingConflict);
        }
        let old_epoch = current.epoch;
        let new_epoch =
            old_epoch
                .checked_add(1)
                .ok_or(RuntimeStoreError::CapacityArithmeticOverflow {
                    field: "counter_recovery_shared_key_epoch",
                })?;
        current.retire_at(retired_at_ms)?;
        history.push(InternalKey::new(new_epoch, replacement_key)?);
        self.revision = self.checked_next_revision()?;
        self.validate()?;
        Ok((
            self,
            SharedKeyTransition {
                purpose,
                stream_route,
                old_epoch,
                new_epoch,
                retired_at_ms,
            },
        ))
    }

    /// CounterGuard/DB rollback 的 daemon→device directed sender rekey。
    /// 只替换目标 active device 的 reply key；command key 与其他 device keys 原样保留。
    pub(crate) fn rotate_counter_recovery_reply(
        mut self,
        device_route: DeviceRouteId,
        replacement_key: SecretBytes,
    ) -> Result<(Self, u64, u64), RuntimeStoreError> {
        self.validate()?;
        let device = self
            .devices
            .iter_mut()
            .find(|device| device.device_route == device_route && device.is_active())
            .ok_or(RuntimeStoreError::PairingConflict)?;
        let reply_key = device
            .reply
            .key
            .as_ref()
            .ok_or(RuntimeStoreError::PairingConflict)?;
        if replacement_key.expose_secret() == reply_key.expose_secret() {
            return Err(RuntimeStoreError::PairingConflict);
        }
        let old_epoch = device.reply.epoch;
        let new_epoch =
            old_epoch
                .checked_add(1)
                .ok_or(RuntimeStoreError::CapacityArithmeticOverflow {
                    field: "counter_recovery_reply_key_epoch",
                })?;
        device.reply = DeviceTransportKey::new(new_epoch, replacement_key)?;
        self.revision = self.checked_next_revision()?;
        self.validate()?;
        Ok((self, old_epoch, new_epoch))
    }

    #[allow(dead_code)] // P4.5 signed publisher composition seam.
    pub(crate) fn current_shared_keys(&self) -> Result<Vec<SharedKeyView>, RuntimeStoreError> {
        self.validate()?;
        let mut views = Vec::with_capacity(1 + self.conversations.len());
        let catalog = self
            .catalogs
            .last()
            .ok_or(RuntimeStoreError::UnknownOrCorruptSchema)?;
        views.push(SharedKeyView {
            purpose: KeyPurpose::Catalog,
            stream_route: None,
            epoch: catalog.epoch,
            key: catalog.as_secret_aead_key()?,
        });
        for conversation in &self.conversations {
            let current = conversation
                .history
                .last()
                .ok_or(RuntimeStoreError::UnknownOrCorruptSchema)?;
            views.push(SharedKeyView {
                purpose: KeyPurpose::ConversationDek,
                stream_route: Some(conversation.stream_route),
                epoch: current.epoch,
                key: current.as_secret_aead_key()?,
            });
        }
        Ok(views)
    }

    /// Grant freezer 只取得 daemon-private state 中已登记的 conversation route；confirm
    /// 事务仍会用 authenticated production publication directory 做第二次精确对账。
    pub(crate) fn active_conversation_routes(&self) -> Vec<StreamRouteId> {
        self.conversations
            .iter()
            .map(|conversation| conversation.stream_route)
            .collect()
    }

    #[allow(dead_code)] // P4.5 replay/key-retirement composition seam.
    pub(crate) fn retired_shared_keys(
        &self,
    ) -> Result<Vec<RetiredSharedKeyView>, RuntimeStoreError> {
        self.validate()?;
        let mut views = Vec::new();
        for key in self
            .catalogs
            .iter()
            .filter(|key| key.retired_at_ms.is_some())
        {
            views.push(RetiredSharedKeyView {
                purpose: KeyPurpose::Catalog,
                stream_route: None,
                epoch: key.epoch,
                retired_at_ms: key
                    .retired_at_ms
                    .ok_or(RuntimeStoreError::UnknownOrCorruptSchema)?,
                retention_owners: key.retention_owners.clone(),
                key: key.as_secret_aead_key()?,
            });
        }
        for conversation in &self.conversations {
            for key in conversation
                .history
                .iter()
                .filter(|key| key.retired_at_ms.is_some())
            {
                views.push(RetiredSharedKeyView {
                    purpose: KeyPurpose::ConversationDek,
                    stream_route: Some(conversation.stream_route),
                    epoch: key.epoch,
                    retired_at_ms: key
                        .retired_at_ms
                        .ok_or(RuntimeStoreError::UnknownOrCorruptSchema)?,
                    retention_owners: key.retention_owners.clone(),
                    key: key.as_secret_aead_key()?,
                });
            }
        }
        Ok(views)
    }

    pub(crate) fn retained_retired_secret_count(&self) -> Result<usize, RuntimeStoreError> {
        let shared = self.retired_shared_keys()?.len();
        let directed = self
            .devices
            .iter()
            .filter(|device| !device.is_active() && device.has_transport_secrets())
            .count()
            .checked_mul(2)
            .ok_or(RuntimeStoreError::CapacityArithmeticOverflow {
                field: "retained_retired_device_transport_keys",
            })?;
        shared
            .checked_add(directed)
            .ok_or(RuntimeStoreError::CapacityArithmeticOverflow {
                field: "retained_retired_keys",
            })
    }

    /// owner 可以在 key 仍为 current 时预绑定；后续 rotation 会把同一 `InternalKey`
    /// 连同 owner 原样移入 retired history，从而消除 freeze/pin 与 retirement 之间的窗口。
    pub(crate) fn acquire_retired_shared_key_owner(
        mut self,
        owner: RetiredSharedKeyOwner,
    ) -> Result<Self, RuntimeStoreError> {
        self.validate()?;
        {
            let key = self
                .shared_key_history_mut(owner.purpose, owner.stream_route)?
                .iter_mut()
                .find(|key| key.epoch == owner.epoch)
                .ok_or(RuntimeStoreError::PairingConflict)?;
            if !key.retention_owners.contains(&owner) {
                if key.retention_owners.len() >= MAX_RETENTION_OWNERS_PER_KEY {
                    return Err(RuntimeStoreError::PairingLimit);
                }
                key.retention_owners.push(owner);
                key.retention_owners
                    .sort_by_key(|retention_owner| retention_owner.canonical_bytes());
            }
        }
        self.validate()?;
        self.ensure_canonical_capacity()?;
        Ok(self)
    }

    pub(crate) fn release_retired_shared_key_owner(
        mut self,
        owner: RetiredSharedKeyOwner,
    ) -> Result<Self, RuntimeStoreError> {
        self.validate()?;
        let target = owner.target();
        let mut live_target = false;
        if let Ok(history) = self.shared_key_history_mut(owner.purpose, owner.stream_route)
            && let Some(key) = history.iter_mut().find(|key| key.epoch == owner.epoch)
        {
            key.retention_owners
                .retain(|retention_owner| *retention_owner != owner);
            live_target = true;
        }
        if !live_target
            && self
                .retired_key_tombstones
                .binary_search_by_key(&target.canonical_bytes(), |entry| entry.canonical_bytes())
                .is_err()
        {
            return Err(RuntimeStoreError::PairingConflict);
        }
        self.validate()?;
        Ok(self)
    }

    #[allow(dead_code)] // Used by the pending P4.5 retention composition seams above.
    fn shared_key_history_mut(
        &mut self,
        purpose: KeyPurpose,
        stream_route: Option<StreamRouteId>,
    ) -> Result<&mut Vec<InternalKey>, RuntimeStoreError> {
        match (purpose, stream_route) {
            (KeyPurpose::Catalog, None) => Ok(&mut self.catalogs),
            (KeyPurpose::ConversationDek, Some(route)) => self
                .conversations
                .iter_mut()
                .find(|conversation| conversation.stream_route == route)
                .map(|conversation| &mut conversation.history)
                .ok_or(RuntimeStoreError::PairingConflict),
            _ => Err(RuntimeStoreError::PairingConflict),
        }
    }

    /// directed request/reply sealer 只取得目标 active device 的单方向 key。
    #[allow(dead_code)] // P4.5 directed command/reply sealer composition seam.
    pub(crate) fn device_transport_key(
        &self,
        device_route: DeviceRouteId,
        purpose: KeyPurpose,
    ) -> Result<BootstrapKeyView, RuntimeStoreError> {
        self.validate()?;
        let device = self
            .device(device_route)
            .filter(|device| device.is_active())
            .ok_or(RuntimeStoreError::PairingConflict)?;
        let key = match purpose {
            KeyPurpose::DeviceCommandTx => &device.command,
            KeyPurpose::DeviceReplyTx => &device.reply,
            _ => return Err(RuntimeStoreError::PairingConflict),
        };
        Ok(BootstrapKeyView {
            purpose,
            stream_route: None,
            epoch: key.epoch,
            key: key.as_secret_aead_key()?,
        })
    }

    #[must_use]
    pub(crate) const fn revision(&self) -> KeyDirectoryRevision {
        KeyDirectoryRevision::new(self.revision)
    }

    #[must_use]
    #[cfg(test)]
    pub(crate) fn device_count(&self) -> usize {
        self.devices.len()
    }

    #[must_use]
    #[cfg(test)]
    pub(crate) fn has_retention_owner_for_test(&self, owner: RetiredSharedKeyOwner) -> bool {
        self.catalogs
            .iter()
            .chain(
                self.conversations
                    .iter()
                    .flat_map(|conversation| conversation.history.iter()),
            )
            .any(|key| key.retention_owners.contains(&owner))
    }

    pub(crate) fn bootstrap_view(
        &self,
        device_route: DeviceRouteId,
    ) -> Result<[BootstrapKeyView; 3], RuntimeStoreError> {
        let device = self
            .devices
            .iter()
            .find(|device| device.device_route == device_route && device.is_active())
            .ok_or(RuntimeStoreError::PairingConflict)?;
        let catalog = self
            .catalogs
            .last()
            .ok_or(RuntimeStoreError::UnknownOrCorruptSchema)?;
        Ok([
            BootstrapKeyView {
                purpose: KeyPurpose::Catalog,
                stream_route: None,
                epoch: catalog.epoch,
                key: catalog.as_secret_aead_key()?,
            },
            BootstrapKeyView {
                purpose: KeyPurpose::DeviceCommandTx,
                stream_route: None,
                epoch: device.command.epoch,
                key: device.command.as_secret_aead_key()?,
            },
            BootstrapKeyView {
                purpose: KeyPurpose::DeviceReplyTx,
                stream_route: None,
                epoch: device.reply.epoch,
                key: device.reply.as_secret_aead_key()?,
            },
        ])
    }

    /// PairResponse install directory 的完整当前 key view。首 grant 会返回 epoch-1
    /// conversations；后续 Add 则返回轮换后的 current epochs。
    pub(crate) fn install_directory_view(
        &self,
        device_route: DeviceRouteId,
    ) -> Result<Vec<BootstrapKeyView>, RuntimeStoreError> {
        let mut views = self
            .bootstrap_view(device_route)?
            .into_iter()
            .collect::<Vec<_>>();
        for conversation in &self.conversations {
            let key = conversation
                .history
                .last()
                .ok_or(RuntimeStoreError::UnknownOrCorruptSchema)?;
            views.push(BootstrapKeyView {
                purpose: KeyPurpose::ConversationDek,
                stream_route: Some(conversation.stream_route),
                epoch: key.epoch,
                key: key.as_secret_aead_key()?,
            });
        }
        views.sort_by_key(|view| {
            let purpose = match view.purpose {
                KeyPurpose::Catalog => 0_u8,
                KeyPurpose::ConversationDek => 1,
                KeyPurpose::DeviceCommandTx => 2,
                KeyPurpose::DeviceReplyTx => 3,
            };
            (
                purpose,
                view.stream_route.map_or([0; 16], |route| *route.as_bytes()),
                view.epoch,
            )
        });
        Ok(views)
    }

    pub(super) fn validate(&self) -> Result<(), RuntimeStoreError> {
        if self.revision == 0
            || self.catalogs.is_empty()
            || self.catalogs.len() > usize::from(u16::MAX)
            || self.devices.is_empty()
            || self.devices.len() > MAX_DEVICE_RECORDS
            || self.conversations.len() > MAX_ACTIVE_CONVERSATIONS
        {
            return Err(RuntimeStoreError::PairingConflict);
        }
        let mut key_material = HashSet::new();
        Self::validate_key_history(&self.catalogs, KeyPurpose::Catalog, None, &mut key_material)?;
        let mut previous = None;
        let mut retained_secret_devices = 0_usize;
        for device in &self.devices {
            let has_command_secret = device.command.has_secret();
            let has_reply_secret = device.reply.has_secret();
            if previous.is_some_and(|route| route >= *device.device_route.as_bytes())
                || device.command.epoch == 0
                || device.reply.epoch == 0
                || device.revoked_at_ms == Some(0)
                || device.revoked_at_ms == Some(LEGACY_RETIREMENT_TIME_UNKNOWN)
                || has_command_secret != has_reply_secret
                || (device.is_active() && !has_command_secret)
            {
                return Err(RuntimeStoreError::PairingConflict);
            }
            if has_command_secret {
                retained_secret_devices = retained_secret_devices.checked_add(1).ok_or(
                    RuntimeStoreError::CapacityArithmeticOverflow {
                        field: "retained_device_transport_secrets",
                    },
                )?;
                for key in [&device.command, &device.reply] {
                    let secret = key
                        .key
                        .as_ref()
                        .ok_or(RuntimeStoreError::PairingConflict)?
                        .expose_secret();
                    if secret.len() != 32
                        || secret.iter().all(|byte| *byte == 0)
                        || !key_material.insert(secret)
                    {
                        return Err(RuntimeStoreError::PairingConflict);
                    }
                }
            }
            previous = Some(*device.device_route.as_bytes());
        }
        if retained_secret_devices > MAX_DEVICES {
            return Err(RuntimeStoreError::PairingConflict);
        }
        let mut previous_stream = None;
        for conversation in &self.conversations {
            if conversation.stream_route.as_bytes() == &[0; 16]
                || previous_stream
                    .is_some_and(|route| route >= *conversation.stream_route.as_bytes())
                || conversation.history.len() > usize::from(u16::MAX)
            {
                return Err(RuntimeStoreError::PairingConflict);
            }
            Self::validate_key_history(
                &conversation.history,
                KeyPurpose::ConversationDek,
                Some(conversation.stream_route),
                &mut key_material,
            )?;
            previous_stream = Some(*conversation.stream_route.as_bytes());
        }
        if self.retired_key_tombstones.len() > MAX_RETIRED_KEY_TOMBSTONES {
            return Err(RuntimeStoreError::PairingConflict);
        }
        for (index, target) in self.retired_key_tombstones.iter().enumerate() {
            if index > 0
                && self.retired_key_tombstones[index - 1].canonical_bytes()
                    >= target.canonical_bytes()
            {
                return Err(RuntimeStoreError::PairingConflict);
            }
            let current_epoch = match (target.purpose, target.stream_route) {
                (KeyPurpose::Catalog, None) => self
                    .catalogs
                    .last()
                    .map(|key| key.epoch)
                    .ok_or(RuntimeStoreError::PairingConflict)?,
                (KeyPurpose::ConversationDek, Some(route)) if route.as_bytes() != &[0; 16] => self
                    .conversations
                    .iter()
                    .find(|conversation| conversation.stream_route == route)
                    .and_then(|conversation| conversation.history.last())
                    .map(|key| key.epoch)
                    .ok_or(RuntimeStoreError::PairingConflict)?,
                _ => return Err(RuntimeStoreError::PairingConflict),
            };
            let still_live = match (target.purpose, target.stream_route) {
                (KeyPurpose::Catalog, None) => {
                    self.catalogs.iter().any(|key| key.epoch == target.epoch)
                }
                (KeyPurpose::ConversationDek, Some(route)) => self
                    .conversations
                    .iter()
                    .find(|conversation| conversation.stream_route == route)
                    .is_some_and(|conversation| {
                        conversation
                            .history
                            .iter()
                            .any(|key| key.epoch == target.epoch)
                    }),
                _ => true,
            };
            if target.epoch == 0 || target.epoch >= current_epoch || still_live {
                return Err(RuntimeStoreError::PairingConflict);
            }
        }
        Ok(())
    }

    fn validate_key_history<'a>(
        history: &'a [InternalKey],
        purpose: KeyPurpose,
        stream_route: Option<StreamRouteId>,
        key_material: &mut HashSet<&'a [u8]>,
    ) -> Result<(), RuntimeStoreError> {
        if history.is_empty() {
            return Err(RuntimeStoreError::PairingConflict);
        }
        let mut previous_epoch = 0_u64;
        for (index, key) in history.iter().enumerate() {
            let is_current = index + 1 == history.len();
            if key.epoch <= previous_epoch
                || key.key.expose_secret().len() != 32
                || key.key.expose_secret().iter().all(|byte| *byte == 0)
                || (is_current && key.retired_at_ms.is_some())
                || (!is_current && key.retired_at_ms.is_none())
                || key.retired_at_ms == Some(0)
                || key.retention_owners.len() > MAX_RETENTION_OWNERS_PER_KEY
                || key
                    .retention_owners
                    .iter()
                    .any(|owner| !owner.binds_to(purpose, stream_route, key.epoch))
                || key
                    .retention_owners
                    .windows(2)
                    .any(|owners| owners[0].canonical_bytes() >= owners[1].canonical_bytes())
                || !key_material.insert(key.key.expose_secret())
            {
                return Err(RuntimeStoreError::PairingConflict);
            }
            previous_epoch = key.epoch;
        }
        Ok(())
    }
}

// ADGK1/ADGK2 的 canonical codec 保持在同一 Rust 模块作用域内，避免扩大私有接口。
include!("pairing_grant_state_codec.rs");

impl GlobalKeyStateV1 {
    #[cfg(test)]
    pub(crate) fn retired_key_count_for_test(&self) -> usize {
        self.catalogs
            .iter()
            .chain(
                self.conversations
                    .iter()
                    .flat_map(|conversation| &conversation.history),
            )
            .filter(|key| key.retired_at_ms.is_some())
            .count()
    }

    #[cfg(test)]
    pub(crate) fn retired_at_values_for_test(&self) -> Vec<u64> {
        self.catalogs
            .iter()
            .chain(
                self.conversations
                    .iter()
                    .flat_map(|conversation| &conversation.history),
            )
            .filter_map(|key| key.retired_at_ms)
            .collect()
    }

    #[cfg(test)]
    pub(crate) fn shared_key_epochs_for_test(&self) -> Vec<(Option<StreamRouteId>, u64)> {
        let mut epochs = vec![(None, self.catalogs.last().expect("validated catalog").epoch)];
        epochs.extend(self.conversations.iter().map(|conversation| {
            (
                Some(conversation.stream_route),
                conversation
                    .history
                    .last()
                    .expect("validated conversation")
                    .epoch,
            )
        }));
        epochs
    }

    #[cfg(test)]
    pub(crate) fn device_revoked_at_for_test(&self, route: DeviceRouteId) -> Option<u64> {
        self.device(route).and_then(|device| device.revoked_at_ms)
    }

    #[cfg(test)]
    pub(crate) fn device_key_epochs_for_test(&self, route: DeviceRouteId) -> Option<(u64, u64)> {
        self.device(route)
            .map(|device| (device.command.epoch, device.reply.epoch))
    }

    pub(super) fn device(&self, route: DeviceRouteId) -> Option<&DeviceKeys> {
        self.devices
            .iter()
            .find(|device| device.device_route == route)
    }

    #[must_use]
    pub(super) fn contains_device_route(&self, route: DeviceRouteId) -> bool {
        self.device(route).is_some()
    }
}

/// 仅能从 authenticated awaiting row 消费得到的 grant builder 输入。
pub(crate) struct PairingGrantPreparation {
    pairing_id: RuntimeId,
    invite: PairInviteV1,
    request_hash: [u8; 32],
    request: PairRequestPlaintextV1,
}

impl std::fmt::Debug for PairingGrantPreparation {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter.write_str("PairingGrantPreparation([REDACTED])")
    }
}

impl PairingGrantPreparation {
    #[must_use]
    pub(crate) const fn pairing_id(&self) -> RuntimeId {
        self.pairing_id
    }

    #[must_use]
    pub(crate) const fn invite(&self) -> &PairInviteV1 {
        &self.invite
    }

    #[must_use]
    pub(crate) const fn request_hash(&self) -> [u8; 32] {
        self.request_hash
    }

    #[must_use]
    pub(crate) const fn request(&self) -> &PairRequestPlaintextV1 {
        &self.request
    }
}

impl super::pairing::PairingInviteRecord {
    pub(crate) fn into_grant_preparation(
        self,
    ) -> Result<PairingGrantPreparation, RuntimeStoreError> {
        if self.lifecycle != PairingInviteLifecycle::AwaitingLocalConfirmation
            || self.canonical_pending_frame.is_none()
        {
            return Err(RuntimeStoreError::PairingConflict);
        }
        let request_hash = self
            .request_hash
            .ok_or(RuntimeStoreError::UnknownOrCorruptSchema)?;
        let invite = PairInviteV1::from_canonical_bytes(self.canonical_invite.expose_secret())
            .map_err(|_| RuntimeStoreError::UnknownOrCorruptSchema)?;
        let request = PairRequestPlaintextV1::from_canonical_bytes(
            self.canonical_pair_request_plaintext
                .as_ref()
                .ok_or(RuntimeStoreError::UnknownOrCorruptSchema)?
                .expose_secret(),
        )
        .map_err(|_| RuntimeStoreError::UnknownOrCorruptSchema)?;
        Ok(PairingGrantPreparation {
            pairing_id: self.pairing_id,
            invite,
            request_hash,
            request,
        })
    }
}

pub(crate) struct ConfirmPairingGrant {
    pairing_id: RuntimeId,
    request_hash: [u8; 32],
    relay_grant: RelayGrant,
    device_authorization: DeviceAuthorizationV1,
    key_directory: KeyDirectoryV1,
    response: PairResponseV1,
    global_key_state: GlobalKeyStateV1,
}

impl ConfirmPairingGrant {
    #[allow(clippy::too_many_arguments)]
    #[must_use]
    pub(crate) fn new(
        pairing_id: RuntimeId,
        request_hash: [u8; 32],
        relay_grant: RelayGrant,
        device_authorization: DeviceAuthorizationV1,
        key_directory: KeyDirectoryV1,
        response: PairResponseV1,
        global_key_state: GlobalKeyStateV1,
    ) -> Self {
        Self {
            pairing_id,
            request_hash,
            relay_grant,
            device_authorization,
            key_directory,
            response,
            global_key_state,
        }
    }
}

impl std::fmt::Debug for ConfirmPairingGrant {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter.write_str("ConfirmPairingGrant([REDACTED])")
    }
}

pub(crate) struct PreparedConfirmPairingGrant {
    pub(super) pairing_id: RuntimeId,
    pub(super) request_hash: [u8; 32],
    pub(super) canonical_relay_grant: Vec<u8>,
    pub(super) canonical_authorization: SecretBytes,
    pub(super) canonical_key_directory: SecretBytes,
    pub(super) canonical_response: SecretBytes,
    pub(super) canonical_global_key_state: SecretBytes,
    pub(super) canonical_install_frame: Vec<u8>,
    pub(super) grant_hash: [u8; 32],
    pub(super) authorization_hash: [u8; 32],
    pub(super) response_hash: [u8; 32],
    pub(super) global_key_state_hash: [u8; 32],
    retained_bytes: usize,
}

impl PreparedConfirmPairingGrant {
    #[must_use]
    pub(crate) const fn retained_bytes(&self) -> usize {
        self.retained_bytes
    }
}

pub(crate) fn prepare_confirm(
    input: ConfirmPairingGrant,
) -> Result<PreparedConfirmPairingGrant, RuntimeStoreError> {
    if input.pairing_id.kind() != RuntimeIdKind::Pairing {
        return Err(RuntimeStoreError::IdKindMismatch {
            expected: RuntimeIdKind::Pairing,
            actual: input.pairing_id.kind(),
        });
    }
    if input.request_hash == [0; 32] {
        return Err(RuntimeStoreError::PairingConflict);
    }
    let ConfirmPairingGrant {
        pairing_id,
        request_hash,
        relay_grant,
        device_authorization,
        key_directory,
        response,
        global_key_state,
    } = input;
    let canonical_relay_grant = relay_grant.canonical_bytes();
    let canonical_authorization = SecretBytes::new(
        device_authorization
            .canonical_bytes()
            .map_err(|_| RuntimeStoreError::PairingConflict)?,
    );
    let canonical_key_directory = SecretBytes::new(
        key_directory
            .canonical_bytes()
            .map_err(|_| RuntimeStoreError::PairingConflict)?,
    );
    let canonical_response = SecretBytes::new(
        response
            .canonical_bytes()
            .map_err(|_| RuntimeStoreError::PairingConflict)?,
    );
    let global = global_key_state.canonical_bytes()?;
    let canonical_global_key_state = SecretBytes::new(global.to_vec());
    let canonical_install_frame = encode(&OpaqueRouteFrame {
        version: RELAY_PROTOCOL_VERSION,
        body: RelayFrameBody::InstallGrant(InstallGrant {
            grant: relay_grant.clone(),
        }),
    });
    let grant_hash = relay_grant.canonical_sha256();
    let authorization_hash = device_authorization
        .canonical_sha256()
        .map_err(|_| RuntimeStoreError::PairingConflict)?;
    let response_hash = response
        .canonical_sha256()
        .map_err(|_| RuntimeStoreError::PairingConflict)?;
    let global_key_state_hash = sha256(canonical_global_key_state.expose_secret());
    if [
        grant_hash,
        authorization_hash,
        response_hash,
        global_key_state_hash,
    ]
    .contains(&[0; 32])
    {
        return Err(RuntimeStoreError::PairingConflict);
    }
    let retained_bytes = [
        canonical_relay_grant.capacity(),
        canonical_authorization.retained_capacity(),
        canonical_key_directory.retained_capacity(),
        canonical_response.retained_capacity(),
        canonical_global_key_state.retained_capacity(),
        canonical_install_frame.capacity(),
    ]
    .into_iter()
    .try_fold(0_usize, |total, value| total.checked_add(value))
    .ok_or(RuntimeStoreError::PayloadTooLarge)?;
    if retained_bytes > super::pairing::MAX_PAIRING_STATE_PLAINTEXT_BYTES {
        return Err(RuntimeStoreError::PayloadTooLarge);
    }
    Ok(PreparedConfirmPairingGrant {
        pairing_id,
        request_hash,
        canonical_relay_grant,
        canonical_authorization,
        canonical_key_directory,
        canonical_response,
        canonical_global_key_state,
        canonical_install_frame,
        grant_hash,
        authorization_hash,
        response_hash,
        global_key_state_hash,
        retained_bytes,
    })
}

pub(super) struct AuthenticatedGlobalKeyState {
    pub(super) revision: u64,
    pub(super) directory_hash: [u8; 32],
    pub(super) state: GlobalKeyStateV1,
    pub(super) sealed_bytes: u64,
    pub(super) metadata_token: [u8; 32],
}

pub(super) struct AuthenticatedInstallOutbox {
    pub(super) outbox_id: RuntimeId,
    pub(super) operation_key: [u8; 32],
    pub(super) device_route: DeviceRouteId,
    pub(super) grant_serial: GrantSerial,
    pub(super) frame_hash: [u8; 32],
    pub(super) grant: RelayGrant,
    pub(super) canonical_frame: Vec<u8>,
    pub(super) sealed_bytes: u64,
    pub(super) created_at_ms: u64,
    pub(super) metadata_token: [u8; 32],
}

pub(super) struct AuthenticatedGrantDirectory {
    pub(super) authorizations: Vec<AuthenticatedAuthorization>,
    pub(super) global: Option<AuthenticatedGlobalKeyState>,
    pub(super) installs: Vec<AuthenticatedInstallOutbox>,
    pub(super) revocations: Vec<AuthenticatedRevocationOutbox>,
}

impl AuthenticatedGrantDirectory {
    pub(super) fn authorization_count(&self) -> u64 {
        u64::try_from(self.authorizations.len()).unwrap_or(u64::MAX)
    }

    pub(super) fn authorization_bytes(&self) -> u64 {
        self.authorizations
            .iter()
            .try_fold(0_u64, |total, row| {
                total.checked_add(row.sealed_bytes).and_then(|bytes| {
                    bytes.checked_add(row.sealed_revocation_bytes.unwrap_or_default())
                })
            })
            .unwrap_or(u64::MAX)
    }

    pub(super) fn authorization_preparing_count(&self) -> u64 {
        u64::try_from(
            self.authorizations
                .iter()
                .filter(|row| row.lifecycle == AuthorizationLifecycle::GrantPreparing)
                .count(),
        )
        .unwrap_or(u64::MAX)
    }

    pub(super) fn authorization_active_count(&self) -> u64 {
        u64::try_from(
            self.authorizations
                .iter()
                .filter(|row| row.lifecycle == AuthorizationLifecycle::Active)
                .count(),
        )
        .unwrap_or(u64::MAX)
    }

    pub(super) fn authorization_revoking_count(&self) -> u64 {
        u64::try_from(
            self.authorizations
                .iter()
                .filter(|row| row.lifecycle == AuthorizationLifecycle::Revoking)
                .count(),
        )
        .unwrap_or(u64::MAX)
    }

    pub(super) fn authorization_revoked_count(&self) -> u64 {
        u64::try_from(
            self.authorizations
                .iter()
                .filter(|row| row.lifecycle == AuthorizationLifecycle::Revoked)
                .count(),
        )
        .unwrap_or(u64::MAX)
    }

    pub(super) fn key_state_count(&self) -> u64 {
        u64::from(self.global.is_some())
    }

    pub(super) fn key_state_bytes(&self) -> u64 {
        self.global.as_ref().map_or(0, |row| row.sealed_bytes)
    }

    pub(super) fn install_count(&self) -> u64 {
        u64::try_from(self.installs.len()).unwrap_or(u64::MAX)
    }

    pub(super) fn install_bytes(&self) -> u64 {
        self.installs
            .iter()
            .try_fold(0_u64, |total, row| total.checked_add(row.sealed_bytes))
            .unwrap_or(u64::MAX)
    }

    pub(super) fn revocation_count(&self) -> u64 {
        u64::try_from(self.revocations.len()).unwrap_or(u64::MAX)
    }

    pub(super) fn revocation_bytes(&self) -> u64 {
        self.revocations
            .iter()
            .try_fold(0_u64, |total, row| total.checked_add(row.sealed_bytes))
            .unwrap_or(u64::MAX)
    }
}

fn fixed<const N: usize>(value: Vec<u8>) -> Result<[u8; N], RuntimeStoreError> {
    value
        .try_into()
        .map_err(|_| RuntimeStoreError::UnknownOrCorruptSchema)
}

fn nonnegative(value: i64) -> Result<u64, RuntimeStoreError> {
    u64::try_from(value).map_err(|_| RuntimeStoreError::UnknownOrCorruptSchema)
}

fn sequence(value: &str) -> Result<u64, RuntimeStoreError> {
    if value.len() != 20 || !value.as_bytes().iter().all(u8::is_ascii_digit) {
        return Err(RuntimeStoreError::UnknownOrCorruptSchema);
    }
    let parsed = value
        .parse::<u64>()
        .map_err(|_| RuntimeStoreError::UnknownOrCorruptSchema)?;
    if parsed == 0 || super::sequence::encode_sequence(parsed) != value {
        return Err(RuntimeStoreError::UnknownOrCorruptSchema);
    }
    Ok(parsed)
}

pub(super) fn seal_row(
    key_bundle: &RuntimeKeyBundle,
    database_id: [u8; 16],
    table: &[u8],
    primary_key: &[u8],
    column: &[u8],
    plaintext: &[u8],
    maximum: usize,
) -> Result<Vec<u8>, RuntimeStoreError> {
    Ok(key_bundle.row_cipher().seal_bounded(
        &RowAad {
            schema_family: RUNTIME_SCHEMA_FAMILY.as_bytes(),
            schema_version: RUNTIME_CRYPTO_CONTEXT_VERSION,
            database_id: &database_id,
            table,
            primary_key,
            column,
        },
        plaintext,
        maximum,
    )?)
}

pub(super) fn open_row(
    key_bundle: &RuntimeKeyBundle,
    database_id: [u8; 16],
    table: &[u8],
    primary_key: &[u8],
    column: &[u8],
    ciphertext: &[u8],
    maximum: usize,
) -> Result<SecretBytes, RuntimeStoreError> {
    Ok(key_bundle.row_cipher().open_bounded(
        &RowAad {
            schema_family: RUNTIME_SCHEMA_FAMILY.as_bytes(),
            schema_version: RUNTIME_CRYPTO_CONTEXT_VERSION,
            database_id: &database_id,
            table,
            primary_key,
            column,
        },
        ciphertext,
        maximum,
    )?)
}

pub(super) fn global_key_token(
    key_bundle: &RuntimeKeyBundle,
    database_id: [u8; 16],
    revision: u64,
    directory_hash: [u8; 32],
    sealed: &[u8],
) -> Result<[u8; 32], RuntimeStoreError> {
    let sealed_len =
        u64::try_from(sealed.len()).map_err(|_| RuntimeStoreError::UnknownOrCorruptSchema)?;
    let sealed_hash = sha256(sealed);
    super::stream::metadata_mac(
        key_bundle,
        GLOBAL_KEY_METADATA_DOMAIN,
        &[
            &database_id,
            &revision.to_be_bytes(),
            &directory_hash,
            &sealed_len.to_be_bytes(),
            &sealed_hash,
        ],
    )
}

pub(super) fn install_operation_key(
    key_bundle: &RuntimeKeyBundle,
    device_route: DeviceRouteId,
    serial: GrantSerial,
) -> Result<[u8; 32], RuntimeStoreError> {
    let mut input = Vec::with_capacity(24);
    input.extend_from_slice(device_route.as_bytes());
    input.extend_from_slice(&serial.value().to_be_bytes());
    let value = *key_bundle
        .blind_index(INSTALL_OPERATION_DOMAIN, &input)?
        .as_bytes();
    if value == [0; 32] {
        return Err(RuntimeStoreError::UnknownOrCorruptSchema);
    }
    Ok(value)
}

#[allow(clippy::too_many_arguments)]
pub(super) fn install_outbox_token(
    key_bundle: &RuntimeKeyBundle,
    database_id: [u8; 16],
    outbox_id: RuntimeId,
    operation_key: [u8; 32],
    device_route: DeviceRouteId,
    serial: GrantSerial,
    frame_hash: [u8; 32],
    sealed: &[u8],
    created_at_ms: u64,
    state_changed_at_ms: u64,
) -> Result<[u8; 32], RuntimeStoreError> {
    let sealed_len =
        u64::try_from(sealed.len()).map_err(|_| RuntimeStoreError::UnknownOrCorruptSchema)?;
    let sealed_hash = sha256(sealed);
    super::stream::metadata_mac(
        key_bundle,
        OUTBOX_METADATA_DOMAIN,
        &[
            &database_id,
            outbox_id.as_bytes(),
            b"installGrant",
            &operation_key,
            b"prepared",
            device_route.as_bytes(),
            &serial.value().to_be_bytes(),
            &frame_hash,
            &sealed_len.to_be_bytes(),
            &sealed_hash,
            &created_at_ms.to_be_bytes(),
            &state_changed_at_ms.to_be_bytes(),
        ],
    )
}

pub(super) fn load_global_key_state(
    connection: &Connection,
    key_bundle: &RuntimeKeyBundle,
    database_id: [u8; 16],
) -> Result<Option<AuthenticatedGlobalKeyState>, RuntimeStoreError> {
    #[allow(clippy::type_complexity)]
    let raw = connection
        .query_row(
            "SELECT database_id, revision, directory_hash, sealed_directory,
                    sealed_directory_bytes, metadata_token
             FROM remote_key_directory WHERE singleton = 1",
            [],
            |row| {
                Ok((
                    row.get::<_, Vec<u8>>(0)?,
                    row.get::<_, String>(1)?,
                    row.get::<_, Vec<u8>>(2)?,
                    row.get::<_, Vec<u8>>(3)?,
                    row.get::<_, i64>(4)?,
                    row.get::<_, Vec<u8>>(5)?,
                ))
            },
        )
        .optional()?;
    let Some(raw) = raw else {
        return Ok(None);
    };
    let row_database_id = fixed(raw.0)?;
    let revision = sequence(&raw.1)?;
    let directory_hash = fixed(raw.2)?;
    let sealed_bytes = nonnegative(raw.4)?;
    let metadata_token = fixed(raw.5)?;
    if row_database_id != database_id
        || directory_hash == [0; 32]
        || sealed_bytes != u64::try_from(raw.3.len()).unwrap_or(u64::MAX)
        || global_key_token(key_bundle, database_id, revision, directory_hash, &raw.3)?
            != metadata_token
    {
        return Err(RuntimeStoreError::UnknownOrCorruptSchema);
    }
    let canonical_state = open_row(
        key_bundle,
        database_id,
        GLOBAL_KEY_TABLE,
        b"1",
        GLOBAL_KEY_COLUMN,
        &raw.3,
        MAX_GLOBAL_KEY_STATE_BYTES,
    )?;
    let state = GlobalKeyStateV1::from_canonical_bytes(canonical_state.expose_secret())?;
    if state.revision != revision || sha256(canonical_state.expose_secret()) != directory_hash {
        return Err(RuntimeStoreError::UnknownOrCorruptSchema);
    }
    Ok(Some(AuthenticatedGlobalKeyState {
        revision,
        directory_hash,
        state,
        sealed_bytes,
        metadata_token,
    }))
}

pub(super) fn exact_install_frame(
    canonical: &[u8],
) -> Result<(RelayGrant, [u8; 32]), RuntimeStoreError> {
    if canonical.len() > super::pairing::MAX_CONTROL_FRAME_PLAINTEXT_BYTES {
        return Err(RuntimeStoreError::UnknownOrCorruptSchema);
    }
    let frame: OpaqueRouteFrame =
        decode(canonical).map_err(|_| RuntimeStoreError::UnknownOrCorruptSchema)?;
    if encode(&frame) != canonical || frame.version != RELAY_PROTOCOL_VERSION {
        return Err(RuntimeStoreError::UnknownOrCorruptSchema);
    }
    let RelayFrameBody::InstallGrant(InstallGrant { grant }) = frame.body else {
        return Err(RuntimeStoreError::UnknownOrCorruptSchema);
    };
    let grant_hash = grant.canonical_sha256();
    if grant_hash == [0; 32] {
        return Err(RuntimeStoreError::UnknownOrCorruptSchema);
    }
    Ok((grant, grant_hash))
}

fn load_install_outboxes(
    connection: &Connection,
    key_bundle: &RuntimeKeyBundle,
    database_id: [u8; 16],
) -> Result<Vec<AuthenticatedInstallOutbox>, RuntimeStoreError> {
    let mut statement = connection.prepare(
        "SELECT outbox_id, operation_key, lifecycle, database_id, pairing_id,
                device_route, grant_serial, frame_hash, sealed_frame, sealed_frame_bytes,
                terminal_hash, sealed_terminal, sealed_terminal_bytes,
                created_at_ms, state_changed_at_ms, metadata_token
         FROM remote_control_outbox
         WHERE operation_kind = 'installGrant' ORDER BY outbox_id",
    )?;
    let raws = statement
        .query_map([], |row| {
            Ok((
                row.get::<_, Vec<u8>>(0)?,
                row.get::<_, Vec<u8>>(1)?,
                row.get::<_, String>(2)?,
                row.get::<_, Vec<u8>>(3)?,
                row.get::<_, Option<Vec<u8>>>(4)?,
                row.get::<_, Option<Vec<u8>>>(5)?,
                row.get::<_, Option<String>>(6)?,
                row.get::<_, Vec<u8>>(7)?,
                row.get::<_, Vec<u8>>(8)?,
                row.get::<_, i64>(9)?,
                row.get::<_, Option<Vec<u8>>>(10)?,
                row.get::<_, Option<Vec<u8>>>(11)?,
                row.get::<_, Option<i64>>(12)?,
                row.get::<_, i64>(13)?,
                row.get::<_, i64>(14)?,
                row.get::<_, Vec<u8>>(15)?,
            ))
        })?
        .collect::<Result<Vec<_>, _>>()?;
    raws.into_iter()
        .map(|raw| {
            let outbox_id = RuntimeId::from_bytes(RuntimeIdKind::RemoteOutbox, fixed(raw.0)?)
                .map_err(|_| RuntimeStoreError::UnknownOrCorruptSchema)?;
            let operation_key = fixed(raw.1)?;
            let row_database_id = fixed(raw.3)?;
            let device_route = DeviceRouteId::from_bytes(fixed(
                raw.5.ok_or(RuntimeStoreError::UnknownOrCorruptSchema)?,
            )?);
            let serial = GrantSerial::new(sequence(
                raw.6
                    .as_deref()
                    .ok_or(RuntimeStoreError::UnknownOrCorruptSchema)?,
            )?);
            let frame_hash = fixed(raw.7)?;
            let sealed_bytes = nonnegative(raw.9)?;
            let created_at_ms = nonnegative(raw.13)?;
            let state_changed_at_ms = nonnegative(raw.14)?;
            let metadata_token = fixed(raw.15)?;
            if raw.2 != "prepared"
                || row_database_id != database_id
                || raw.4.is_some()
                || raw.10.is_some()
                || raw.11.is_some()
                || raw.12.is_some()
                || created_at_ms != state_changed_at_ms
                || sealed_bytes != u64::try_from(raw.8.len()).unwrap_or(u64::MAX)
                || install_operation_key(key_bundle, device_route, serial)? != operation_key
                || install_outbox_token(
                    key_bundle,
                    database_id,
                    outbox_id,
                    operation_key,
                    device_route,
                    serial,
                    frame_hash,
                    &raw.8,
                    created_at_ms,
                    state_changed_at_ms,
                )? != metadata_token
            {
                return Err(RuntimeStoreError::UnknownOrCorruptSchema);
            }
            let canonical = open_row(
                key_bundle,
                database_id,
                OUTBOX_TABLE,
                outbox_id.as_bytes(),
                OUTBOX_COLUMN,
                &raw.8,
                super::pairing::MAX_CONTROL_FRAME_PLAINTEXT_BYTES,
            )?;
            let canonical_frame = canonical.expose_secret().to_vec();
            let (grant, grant_hash) = exact_install_frame(&canonical_frame)?;
            if sha256(&canonical_frame) != frame_hash
                || grant.device_route != device_route
                || grant.grant_serial != serial
                || grant.canonical_sha256() != grant_hash
            {
                return Err(RuntimeStoreError::UnknownOrCorruptSchema);
            }
            Ok(AuthenticatedInstallOutbox {
                outbox_id,
                operation_key,
                device_route,
                grant_serial: serial,
                frame_hash,
                grant,
                canonical_frame,
                sealed_bytes,
                created_at_ms,
                metadata_token,
            })
        })
        .collect()
}

fn response_context(pair_route: PairRouteId) -> OuterContextV1 {
    OuterContextV1 {
        frame_kind: OuterFrameKind::PairResponse,
        relay_protocol_version: RELAY_PROTOCOL_VERSION,
        e2ee_format_version: E2EE_FORMAT_VERSION,
        machine_route: None,
        device_route: None,
        stream_route: None,
        request_route: None,
        pair_route: Some(pair_route),
        stream_generation: None,
        stream_cursor: None,
        stream_seq: None,
        message_key_epoch: 0,
    }
}

fn response_info(
    pairing: &AuthenticatedPairingRow,
    invite: &PairInviteV1,
    request_hash: [u8; 32],
    grant: &RelayGrant,
) -> Result<PairResponseInfoV1, RuntimeStoreError> {
    Ok(PairResponseInfoV1 {
        e2ee_format_version: E2EE_FORMAT_VERSION,
        runtime_protocol_version: RUNTIME_PROTOCOL_VERSION,
        relay_server_id: invite.relay_server_id,
        pair_route: PairRouteId::from_bytes(*pairing.record.pair_route.as_bytes()),
        invite_hash: invite
            .canonical_sha256()
            .map_err(|_| RuntimeStoreError::UnknownOrCorruptSchema)?,
        expiry_ms: invite.expires_at_ms,
        request_hash,
        machine_route: grant.machine_route,
        device_route: grant.device_route,
        grant_serial: grant.grant_serial,
        root_trust_epoch: grant.trust_epoch,
    })
}

fn same_key(left: &InternalKey, right: &InternalKey) -> bool {
    left.epoch == right.epoch
        && left.key.expose_secret() == right.key.expose_secret()
        && left.retired_at_ms == right.retired_at_ms
        && left.retention_owners == right.retention_owners
}

fn same_device_key(left: &DeviceTransportKey, right: &DeviceTransportKey) -> bool {
    left.epoch == right.epoch
        && left.key.as_ref().map(SecretBytes::expose_secret)
            == right.key.as_ref().map(SecretBytes::expose_secret)
}

fn same_device(left: &DeviceKeys, right: &DeviceKeys) -> bool {
    left.device_route == right.device_route
        && same_device_key(&left.command, &right.command)
        && same_device_key(&left.reply, &right.reply)
        && left.revoked_at_ms == right.revoked_at_ms
}

fn rotated_device_key(previous: &DeviceTransportKey, next: &DeviceTransportKey) -> bool {
    previous
        .epoch
        .checked_add(1)
        .is_some_and(|epoch| epoch == next.epoch)
        && previous.key.as_ref().is_some_and(|previous| {
            next.key
                .as_ref()
                .is_some_and(|next| previous.expose_secret() != next.expose_secret())
        })
}

fn rotated_key(previous: &InternalKey, next: &InternalKey) -> bool {
    previous
        .epoch
        .checked_add(1)
        .is_some_and(|epoch| epoch == next.epoch)
        && previous.key.expose_secret() != next.key.expose_secret()
        && previous.retired_at_ms.is_none()
        && previous.retention_owners.is_empty()
        && next.retired_at_ms.is_none()
        && next.retention_owners.is_empty()
}

fn rotated_history(previous: &[InternalKey], next: &[InternalKey]) -> bool {
    if previous.is_empty() || next.len() != previous.len() + 1 {
        return false;
    }
    if previous.len() > 1
        && !previous[..previous.len() - 1]
            .iter()
            .zip(&next[..previous.len() - 1])
            .all(|(old, retained)| same_key(old, retained))
    {
        return false;
    }
    let old_current = &previous[previous.len() - 1];
    let retired_current = &next[previous.len() - 1];
    let new_current = &next[previous.len()];
    old_current.epoch == retired_current.epoch
        && old_current.key.expose_secret() == retired_current.key.expose_secret()
        && old_current.retired_at_ms.is_none()
        && old_current.retention_owners.is_empty()
        && retired_current.retired_at_ms.is_some()
        && retired_current.retention_owners.is_empty()
        && rotated_key(old_current, new_current)
}

fn same_conversation(left: &ConversationKeys, right: &ConversationKeys) -> bool {
    left.stream_route == right.stream_route
        && left.history.len() == right.history.len()
        && left
            .history
            .iter()
            .zip(&right.history)
            .all(|(old, retained)| same_key(old, retained))
}

fn same_global_state(
    left: &GlobalKeyStateV1,
    right: &GlobalKeyStateV1,
) -> Result<bool, RuntimeStoreError> {
    Ok(left.canonical_bytes()?.as_slice() == right.canonical_bytes()?.as_slice())
}

fn copied_key(key: &InternalKey) -> SecretBytes {
    SecretBytes::new(key.key.expose_secret().to_vec())
}

fn copied_device_key(key: &DeviceTransportKey) -> Result<SecretBytes, RuntimeStoreError> {
    key.key
        .as_ref()
        .map(|key| SecretBytes::new(key.expose_secret().to_vec()))
        .ok_or(RuntimeStoreError::PairingConflict)
}

fn validate_initial_global_transition(
    next: &GlobalKeyStateV1,
    new_device: DeviceRouteId,
    active_stream_routes: &[StreamRouteId],
) -> Result<(), RuntimeStoreError> {
    let catalog = next
        .catalogs
        .last()
        .ok_or(RuntimeStoreError::PairingConflict)?;
    let device = next
        .device(new_device)
        .filter(|device| device.is_active())
        .ok_or(RuntimeStoreError::PairingConflict)?;
    if next.catalogs.len() != 1
        || next.devices.len() != 1
        || next.revision != 1
        || catalog.epoch != 1
        || device.command.epoch != 1
        || device.reply.epoch != 1
        || next.active_conversation_routes() != active_stream_routes
    {
        return Err(RuntimeStoreError::PairingConflict);
    }
    let conversation_keys = active_stream_routes
        .iter()
        .map(|stream_route| {
            let conversation = next
                .conversations
                .iter()
                .find(|conversation| conversation.stream_route == *stream_route)
                .ok_or(RuntimeStoreError::PairingConflict)?;
            if conversation.history.len() != 1 || conversation.history[0].epoch != 1 {
                return Err(RuntimeStoreError::PairingConflict);
            }
            Ok(ConversationKeyRotation::new(
                *stream_route,
                copied_key(&conversation.history[0]),
            ))
        })
        .collect::<Result<Vec<_>, RuntimeStoreError>>()?;
    let expected = GlobalKeyStateV1::bootstrap_with_conversations(
        1,
        catalog.epoch,
        copied_key(catalog),
        new_device,
        device.command.epoch,
        copied_device_key(&device.command)?,
        device.reply.epoch,
        copied_device_key(&device.reply)?,
        conversation_keys,
    )?;
    if !same_global_state(&expected, next)? {
        return Err(RuntimeStoreError::PairingConflict);
    }
    Ok(())
}

fn validate_add_global_transition(
    previous: &AuthenticatedGlobalKeyState,
    next: &GlobalKeyStateV1,
    new_device: DeviceRouteId,
    active_stream_routes: &[StreamRouteId],
    now_ms: u64,
) -> Result<(), RuntimeStoreError> {
    if previous.state.active_conversation_routes() != active_stream_routes
        || next.active_conversation_routes() != active_stream_routes
    {
        return Err(RuntimeStoreError::PairingConflict);
    }
    let catalog = next
        .catalogs
        .last()
        .ok_or(RuntimeStoreError::PairingConflict)?;
    let retired_at_ms = next
        .catalogs
        .get(previous.state.catalogs.len().saturating_sub(1))
        .and_then(|catalog| catalog.retired_at_ms)
        .filter(|retired_at_ms| *retired_at_ms <= now_ms)
        .ok_or(RuntimeStoreError::PairingConflict)?;
    let device = next
        .device(new_device)
        .filter(|device| device.is_active())
        .ok_or(RuntimeStoreError::PairingConflict)?;
    let rotations = active_stream_routes
        .iter()
        .map(|stream_route| {
            let key = next
                .conversations
                .iter()
                .find(|conversation| conversation.stream_route == *stream_route)
                .and_then(|conversation| conversation.history.last())
                .ok_or(RuntimeStoreError::PairingConflict)?;
            Ok(ConversationKeyRotation::new(*stream_route, copied_key(key)))
        })
        .collect::<Result<Vec<_>, RuntimeStoreError>>()?;
    let previous_copy =
        GlobalKeyStateV1::from_canonical_bytes(previous.state.canonical_bytes()?.as_slice())?;
    let expected = previous_copy
        .plan_add_device(
            new_device,
            copied_key(catalog),
            copied_device_key(&device.command)?,
            copied_device_key(&device.reply)?,
            rotations,
            retired_at_ms,
        )?
        .into_state();
    if !same_global_state(&expected, next)? {
        return Err(RuntimeStoreError::PairingConflict);
    }
    Ok(())
}

fn validate_global_transition(
    previous: Option<&AuthenticatedGlobalKeyState>,
    next: &GlobalKeyStateV1,
    new_device: DeviceRouteId,
    allocation: super::pairing_grant_allocation::ValidatedGrantAllocation,
    active_stream_routes: &[StreamRouteId],
    now_ms: u64,
) -> Result<(), RuntimeStoreError> {
    next.validate()?;
    match previous {
        None if allocation == super::pairing_grant_allocation::ValidatedGrantAllocation::New => {
            validate_initial_global_transition(next, new_device, active_stream_routes)?;
        }
        Some(previous) => {
            if next.revision
                != previous.revision.checked_add(1).ok_or(
                    RuntimeStoreError::CapacityArithmeticOverflow {
                        field: "remote_key_directory_revision",
                    },
                )?
                || !rotated_history(&previous.state.catalogs, &next.catalogs)
            {
                return Err(RuntimeStoreError::PairingConflict);
            }
            match allocation {
                super::pairing_grant_allocation::ValidatedGrantAllocation::New => {
                    validate_add_global_transition(
                        previous,
                        next,
                        new_device,
                        active_stream_routes,
                        now_ms,
                    )?;
                }
                super::pairing_grant_allocation::ValidatedGrantAllocation::Renew {
                    device_route,
                    ..
                } => {
                    if new_device != device_route
                        || previous.state.active_conversation_routes() != active_stream_routes
                        || next.active_conversation_routes() != active_stream_routes
                        || next.devices.len() != previous.state.devices.len()
                        || next.conversations.len() != previous.state.conversations.len()
                        || previous
                            .state
                            .conversations
                            .iter()
                            .zip(&next.conversations)
                            .any(|(old, retained)| !same_conversation(old, retained))
                    {
                        return Err(RuntimeStoreError::PairingConflict);
                    }
                    for old in &previous.state.devices {
                        let retained = next
                            .devices
                            .iter()
                            .find(|device| device.device_route == old.device_route)
                            .ok_or(RuntimeStoreError::PairingConflict)?;
                        if old.device_route == device_route {
                            if !rotated_device_key(&old.command, &retained.command)
                                || !rotated_device_key(&old.reply, &retained.reply)
                            {
                                return Err(RuntimeStoreError::PairingConflict);
                            }
                        } else if !same_device(old, retained) {
                            return Err(RuntimeStoreError::PairingConflict);
                        }
                    }
                }
            }
        }
        None => return Err(RuntimeStoreError::PairingConflict),
    }
    Ok(())
}

fn validate_bootstrap_view(
    directory: &KeyDirectoryV1,
    state: &GlobalKeyStateV1,
    device_route: DeviceRouteId,
) -> Result<(), RuntimeStoreError> {
    let active_routes = state.active_conversation_routes();
    if state.revision == 1 {
        directory
            .validate_initial_directory_for_device(device_route, &active_routes)
            .map_err(|_| RuntimeStoreError::PairingConflict)?;
    } else {
        directory
            .validate_for_device(device_route)
            .map_err(|_| RuntimeStoreError::PairingConflict)?;
    }
    if directory.revision.value() > state.revision {
        return Err(RuntimeStoreError::PairingConflict);
    }
    let device = state
        .device(device_route)
        .ok_or(RuntimeStoreError::PairingConflict)?;
    let catalog_epoch = directory
        .entries
        .iter()
        .find(|entry| entry.key_id.purpose == KeyPurpose::Catalog)
        .map(|entry| entry.key_id.epoch)
        .ok_or(RuntimeStoreError::PairingConflict)?;
    let command_epoch = directory
        .entries
        .iter()
        .find(|entry| entry.key_id.purpose == KeyPurpose::DeviceCommandTx)
        .map(|entry| entry.key_id.epoch)
        .ok_or(RuntimeStoreError::PairingConflict)?;
    let reply_epoch = directory
        .entries
        .iter()
        .find(|entry| entry.key_id.purpose == KeyPurpose::DeviceReplyTx)
        .map(|entry| entry.key_id.epoch)
        .ok_or(RuntimeStoreError::PairingConflict)?;
    let observed_conversations = directory
        .entries
        .iter()
        .filter(|entry| entry.key_id.purpose == KeyPurpose::ConversationDek)
        .map(|entry| {
            Ok((
                entry
                    .stream_route
                    .ok_or(RuntimeStoreError::PairingConflict)?,
                entry.key_id.epoch,
            ))
        })
        .collect::<Result<Vec<_>, RuntimeStoreError>>()?;
    let historical_conversations_match = observed_conversations.len() == state.conversations.len()
        && observed_conversations.iter().zip(&state.conversations).all(
            |((stream_route, epoch), conversation)| {
                *stream_route == conversation.stream_route
                    && conversation.history.iter().any(|key| key.epoch == *epoch)
            },
        );
    if !state
        .catalogs
        .iter()
        .any(|catalog| catalog.epoch == catalog_epoch)
        || command_epoch != device.command.epoch
        || reply_epoch != device.reply.epoch
        || !historical_conversations_match
    {
        return Err(RuntimeStoreError::PairingConflict);
    }
    Ok(())
}

fn validate_current_bootstrap_view(
    directory: &KeyDirectoryV1,
    state: &GlobalKeyStateV1,
    device_route: DeviceRouteId,
) -> Result<(), RuntimeStoreError> {
    validate_bootstrap_view(directory, state, device_route)?;
    let current_catalog_epoch = state
        .catalogs
        .last()
        .map(|catalog| catalog.epoch)
        .ok_or(RuntimeStoreError::UnknownOrCorruptSchema)?;
    let presented_catalog_epoch = directory
        .entries
        .iter()
        .find(|entry| entry.key_id.purpose == KeyPurpose::Catalog)
        .map(|entry| entry.key_id.epoch)
        .ok_or(RuntimeStoreError::PairingConflict)?;
    let presented_conversations = directory
        .entries
        .iter()
        .filter(|entry| entry.key_id.purpose == KeyPurpose::ConversationDek)
        .map(|entry| {
            Ok((
                entry
                    .stream_route
                    .ok_or(RuntimeStoreError::PairingConflict)?,
                entry.key_id.epoch,
            ))
        })
        .collect::<Result<Vec<_>, RuntimeStoreError>>()?;
    let current_conversations = state
        .conversations
        .iter()
        .map(|conversation| {
            Ok((
                conversation.stream_route,
                conversation
                    .history
                    .last()
                    .ok_or(RuntimeStoreError::PairingConflict)?
                    .epoch,
            ))
        })
        .collect::<Result<Vec<_>, RuntimeStoreError>>()?;
    if presented_catalog_epoch != current_catalog_epoch
        || presented_conversations != current_conversations
        || !state
            .device(device_route)
            .is_some_and(DeviceKeys::is_active)
    {
        return Err(RuntimeStoreError::PairingConflict);
    }
    Ok(())
}

fn validate_durable_authorization(
    authorization: &AuthenticatedAuthorization,
    global: &AuthenticatedGlobalKeyState,
    active: &crate::runtime::model::ActiveMachineEnrollmentState,
) -> Result<(), RuntimeStoreError> {
    let grant = &authorization.grant;
    let root = VerifyingKey::from_bytes(&active.binding.root_public_key)
        .map_err(|_| RuntimeStoreError::UnknownOrCorruptSchema)?;
    if grant.machine_route.as_bytes() != &active.record.machine_route
        || grant.root_key_id.as_bytes() != &active.record.root_key_id
        || grant.trust_epoch.value() != active.record.trust_epoch
        || grant.device_route != authorization.device_route
        || grant.grant_serial != authorization.grant_serial
        || grant.canonical_sha256() != authorization.grant_hash
        || grant.canonical_bytes() != authorization.canonical_relay_grant
        || sha256(&grant.device_sign_pubkey.0) != authorization.device_sign_fingerprint
        || authorization.authorization.grant_hash != authorization.grant_hash
        || authorization.authorization.device_route != authorization.device_route
        || authorization.authorization.grant_serial != authorization.grant_serial
        || authorization.authorization.device_sign_fingerprint
            != authorization.device_sign_fingerprint
        || authorization
            .authorization
            .canonical_sha256()
            .map_err(|_| RuntimeStoreError::UnknownOrCorruptSchema)?
            != authorization.authorization_hash
        || authorization.key_directory_revision > global.revision
        || global.state.device(authorization.device_route).is_none()
    {
        return Err(RuntimeStoreError::UnknownOrCorruptSchema);
    }
    verify_tbs(
        &root,
        &grant.to_be_signed_v1(
            active.connection.relay_server_id,
            active.binding.root_fingerprint,
        ),
        &SignatureBytes::from(grant.signature),
    )
    .map_err(|_| RuntimeStoreError::UnknownOrCorruptSchema)?;
    verify_device_authorization(
        &root,
        active.connection.relay_server_id,
        grant,
        &authorization.authorization,
    )
    .map_err(|_| RuntimeStoreError::UnknownOrCorruptSchema)
}

#[allow(clippy::too_many_arguments)]
fn verify_materials(
    pairing: &AuthenticatedPairingRow,
    grant: &RelayGrant,
    authorization: &DeviceAuthorizationV1,
    directory: &KeyDirectoryV1,
    response: &PairResponseV1,
    global: &GlobalKeyStateV1,
    active: &crate::runtime::model::ActiveMachineEnrollmentState,
    require_current_key_view: bool,
) -> Result<(), RuntimeStoreError> {
    let request_hash = pairing
        .record
        .request_hash
        .ok_or(RuntimeStoreError::UnknownOrCorruptSchema)?;
    let fingerprint = pairing
        .record
        .device_sign_fingerprint
        .ok_or(RuntimeStoreError::UnknownOrCorruptSchema)?;
    let invite = PairInviteV1::from_canonical_bytes(pairing.record.canonical_invite())
        .map_err(|_| RuntimeStoreError::UnknownOrCorruptSchema)?;
    let request = PairRequestPlaintextV1::from_canonical_bytes(
        pairing
            .record
            .canonical_pair_request_plaintext
            .as_ref()
            .ok_or(RuntimeStoreError::UnknownOrCorruptSchema)?
            .expose_secret(),
    )
    .map_err(|_| RuntimeStoreError::UnknownOrCorruptSchema)?;
    let root = VerifyingKey::from_bytes(&active.binding.root_public_key)
        .map_err(|_| RuntimeStoreError::UnknownOrCorruptSchema)?;
    let data = VerifyingKey::from_bytes(&active.binding.data_sign_public_key)
        .map_err(|_| RuntimeStoreError::UnknownOrCorruptSchema)?;
    let signer = MachineDataSignerBindingV1::from_certificate(&active.data_cert)
        .map_err(|_| RuntimeStoreError::UnknownOrCorruptSchema)?;
    if pairing.record.relay_server_id != active.record.relay_server_id
        || pairing.record.machine_route != active.record.machine_route
        || grant.machine_route.as_bytes() != &active.record.machine_route
        || grant.root_key_id.as_bytes() != &active.record.root_key_id
        || grant.trust_epoch.value() != active.record.trust_epoch
        || grant.device_sign_pubkey != request.device_sign_pubkey
        || sha256(&grant.device_sign_pubkey.0) != fingerprint
        || authorization.device_hpke_pubkey != request.device_hpke_pubkey
        || authorization.capabilities != request.authorization_request.capabilities
        || authorization.permissions != request.authorization_request.permissions
        || authorization.device_sign_fingerprint != fingerprint
        || authorization.grant_hash != grant.canonical_sha256()
    {
        return Err(RuntimeStoreError::PairingConflict);
    }
    verify_tbs(
        &root,
        &grant.to_be_signed_v1(
            active.connection.relay_server_id,
            active.binding.root_fingerprint,
        ),
        &SignatureBytes::from(grant.signature),
    )
    .map_err(|_| RuntimeStoreError::PairingConflict)?;
    verify_device_authorization(
        &root,
        active.connection.relay_server_id,
        grant,
        authorization,
    )
    .map_err(|_| RuntimeStoreError::PairingConflict)?;
    let key_context = KeyDirectorySignatureContextV1 {
        relay_server_id: active.connection.relay_server_id,
        machine_route: grant.machine_route,
        device_route: grant.device_route,
        grant_serial: grant.grant_serial,
        root_trust_epoch: grant.trust_epoch,
    };
    verify_key_directory(&data, &signer, &key_context, directory)
        .map_err(|_| RuntimeStoreError::PairingConflict)?;
    if require_current_key_view {
        validate_bootstrap_view(directory, global, grant.device_route)?;
    }
    let info = response_info(pairing, &invite, request_hash, grant)?;
    verify_pair_response_envelope(
        &data,
        &info,
        &response_context(PairRouteId::from_bytes(
            *pairing.record.pair_route.as_bytes(),
        )),
        response,
        &signer,
    )
    .map_err(|_| RuntimeStoreError::PairingConflict)
}

pub(super) struct ValidatedPrepared {
    pub(super) grant: RelayGrant,
    pub(super) authorization: DeviceAuthorizationV1,
    pub(super) directory: KeyDirectoryV1,
    pub(super) global: GlobalKeyStateV1,
    pub(super) allocation: super::pairing_grant_allocation::ValidatedGrantAllocation,
}

pub(super) fn validate_prepared(
    pairing: &AuthenticatedPairingRow,
    pairings: &[AuthenticatedPairingRow],
    prepared: &PreparedConfirmPairingGrant,
    grants: &AuthenticatedGrantDirectory,
    active: &crate::runtime::model::ActiveMachineEnrollmentState,
    active_stream_routes: &[StreamRouteId],
    now_ms: u64,
) -> Result<ValidatedPrepared, RuntimeStoreError> {
    if prepared.pairing_id != pairing.record.pairing_id
        || pairing.record.request_hash != Some(prepared.request_hash)
    {
        return Err(RuntimeStoreError::PairingConflict);
    }
    let (grant, observed_grant_hash) = exact_install_frame(&prepared.canonical_install_frame)
        .map_err(|_| RuntimeStoreError::PairingConflict)?;
    let authorization = DeviceAuthorizationV1::from_canonical_bytes(
        prepared.canonical_authorization.expose_secret(),
    )
    .map_err(|_| RuntimeStoreError::PairingConflict)?;
    let directory =
        KeyDirectoryV1::from_canonical_bytes(prepared.canonical_key_directory.expose_secret())
            .map_err(|_| RuntimeStoreError::PairingConflict)?;
    let response =
        PairResponseV1::from_canonical_bytes(prepared.canonical_response.expose_secret())
            .map_err(|_| RuntimeStoreError::PairingConflict)?;
    let global =
        GlobalKeyStateV1::from_canonical_bytes(prepared.canonical_global_key_state.expose_secret())
            .map_err(|_| RuntimeStoreError::PairingConflict)?;
    if grant.canonical_bytes() != prepared.canonical_relay_grant
        || observed_grant_hash != prepared.grant_hash
        || authorization.canonical_sha256().ok() != Some(prepared.authorization_hash)
        || response.canonical_sha256().ok() != Some(prepared.response_hash)
        || sha256(prepared.canonical_global_key_state.expose_secret())
            != prepared.global_key_state_hash
        || directory.revision.value() != global.revision
    {
        return Err(RuntimeStoreError::PairingConflict);
    }
    let allocation = super::pairing_grant_allocation::validate_confirm_allocation(
        pairing, pairings, grants, &grant,
    )?;
    validate_global_transition(
        grants.global.as_ref(),
        &global,
        grant.device_route,
        allocation,
        active_stream_routes,
        now_ms,
    )?;
    validate_current_bootstrap_view(&directory, &global, grant.device_route)?;
    verify_materials(
        pairing,
        &grant,
        &authorization,
        &directory,
        &response,
        &global,
        active,
        true,
    )?;
    Ok(ValidatedPrepared {
        grant,
        authorization,
        directory,
        global,
        allocation,
    })
}

#[path = "pairing_grant_audit.rs"]
mod audit;
pub(super) use audit::authenticate_grant_directory;
#[cfg(test)]
pub(super) use audit::validate_authorization_histories;
