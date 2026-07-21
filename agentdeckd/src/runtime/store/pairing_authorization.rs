//! 设备授权账本的 durable payload、认证元数据与逐行加载边界。

use std::sync::Arc;

use agentdeck_crypto::{AeadReceivingKey, SecretAeadKey, VerifyingKey, sha256};
use agentdeck_protocol::e2ee::{
    AuthorizationPermissionV1, DeviceAuthorizationV1, KeyId, KeyPurpose,
};
use agentdeck_protocol::relay_v2::{
    DeviceRevocation, DeviceRouteId, GrantSerial, KeyDirectoryRevision, MachineRouteId, RelayGrant,
};
use agentdeck_protocol::runtime::identity::{DeviceHandle, GrantSerial as RuntimeGrantSerial};
use rusqlite::Connection;
use zeroize::Zeroizing;

use crate::runtime::model::{RemoteCommandAuthorizationBinding, RuntimeStoreError};
use crate::security::SecretBytes;

use super::cipher::RuntimeKeyBundle;
use super::pairing_grant::{exact_install_frame, open_row};
use super::pairing_revocation::{MAX_REVOCATION_PLAINTEXT_BYTES, exact_revoke_frame};

const AUTHORIZATION_PAYLOAD_MAGIC: &[u8; 5] = b"ADAL1";
const AUTH_TABLE: &[u8] = b"remote_authorization_ledger";
const AUTH_COLUMN: &[u8] = b"sealed_authorization";
const AUTH_REVOCATION_COLUMN: &[u8] = b"sealed_revocation";
const AUTH_METADATA_DOMAIN: &[u8] = b"remote.authorization.metadata.v1";
const AUTH_REVOCATION_METADATA_DOMAIN: &[u8] = b"remote.authorization.revocation.metadata.v1";
pub(super) const MAX_AUTHORIZATION_PLAINTEXT_BYTES: usize = 256 * 1024;
pub(super) const MAX_AUTHORIZATIONS: u64 = 256;
pub(super) const MAX_AUTHORIZATION_SEALED_BYTES: u64 = 64 * 1024 * 1024;

/// Store 全库认证后签发的 Active uplink capability。字段私有，raw Relay frame 无法
/// 构造；RemoteLink 只借用其中的验签/接收能力，不取得 canonical durable state。
#[derive(Clone)]
pub(crate) struct ActiveRemoteIngressProof {
    material: Arc<RemoteIngressMaterial>,
}

struct RemoteIngressMaterial {
    database_id: [u8; 16],
    machine_trust_domain: [u8; 32],
    machine_route: MachineRouteId,
    device_route: DeviceRouteId,
    grant_serial: GrantSerial,
    device_sign_fingerprint: [u8; 32],
    device_verifying_key: VerifyingKey,
    authorization_hash: [u8; 32],
    key_directory_revision: KeyDirectoryRevision,
    command_key_epoch: u64,
    reply_key_epoch: u64,
    #[allow(dead_code, reason = "同一 P4.4 Task 的 RemoteLink crypto slice 消费")]
    command_receiving_key: AeadReceivingKey,
    permissions: Vec<AuthorizationPermissionV1>,
    authorization_metadata_token: [u8; 32],
    directory_metadata_token: [u8; 32],
}

impl std::fmt::Debug for ActiveRemoteIngressProof {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter.write_str("ActiveRemoteIngressProof([REDACTED])")
    }
}

impl ActiveRemoteIngressProof {
    pub(crate) fn machine_trust_domain(&self) -> [u8; 32] {
        self.material.machine_trust_domain
    }

    pub(crate) fn machine_route(&self) -> MachineRouteId {
        self.material.machine_route
    }

    pub(crate) fn device_route(&self) -> DeviceRouteId {
        self.material.device_route
    }

    pub(crate) fn grant_serial(&self) -> GrantSerial {
        self.material.grant_serial
    }

    pub(crate) fn device_sign_fingerprint(&self) -> [u8; 32] {
        self.material.device_sign_fingerprint
    }

    pub(crate) fn authorization_hash(&self) -> [u8; 32] {
        self.material.authorization_hash
    }

    pub(crate) fn key_directory_revision(&self) -> KeyDirectoryRevision {
        self.material.key_directory_revision
    }

    pub(crate) fn command_key_epoch(&self) -> u64 {
        self.material.command_key_epoch
    }

    pub(crate) fn permissions(&self) -> &[AuthorizationPermissionV1] {
        &self.material.permissions
    }

    #[allow(dead_code, reason = "同一 P4.4 Task 的 RemoteLink crypto slice 消费")]
    pub(crate) fn device_verifying_key(&self) -> &VerifyingKey {
        &self.material.device_verifying_key
    }

    #[allow(dead_code, reason = "同一 P4.4 Task 的 RemoteLink crypto slice 消费")]
    pub(crate) fn command_receiving_key(&self) -> &AeadReceivingKey {
        &self.material.command_receiving_key
    }

    pub(crate) fn command_authorization_binding(
        &self,
    ) -> Result<RemoteCommandAuthorizationBinding, RuntimeStoreError> {
        RemoteCommandAuthorizationBinding::new(
            self.machine_trust_domain(),
            self.machine_route(),
            self.device_route(),
            self.grant_serial(),
            self.device_sign_fingerprint(),
            self.authorization_hash(),
            self.key_directory_revision(),
            self.command_key_epoch(),
            self.permissions().to_vec(),
        )
    }

    /// 把“写 issuer registry”和“发布已注册标记”封装为一个不可拆开的最小入口。
    /// 返回 token 字段私有且不可克隆，Core 之外无法伪造可 activation 的 registration。
    pub(crate) fn register_principal_lease<T, E>(
        &self,
        register: impl FnOnce() -> Result<T, E>,
    ) -> Result<(T, RemotePrincipalRegistration), E> {
        let value = register()?;
        Ok((
            value,
            RemotePrincipalRegistration {
                material: self.material.clone(),
            },
        ))
    }
}

/// Active proof 已在 Core issuer 中建立 exact shared lease 的 opaque 一次性凭据。
#[allow(
    dead_code,
    reason = "同一 P4.4 Task 的 RemoteLink activation slice 消费"
)]
pub(crate) struct RemotePrincipalRegistration {
    material: Arc<RemoteIngressMaterial>,
}

impl std::fmt::Debug for RemotePrincipalRegistration {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter.write_str("RemotePrincipalRegistration([REDACTED])")
    }
}

/// DeviceSign/AAD/replay/AEAD 完成后的 exact Active 复核回执。只有 Store 能构造；
/// 其 lifetime 独立于 read transaction，但绑定同一 opaque Active proof。
#[derive(Clone)]
#[allow(
    dead_code,
    reason = "同一 P4.4 Task 的 RemoteLink final recheck slice 消费"
)]
pub(crate) struct CurrentRemoteAuthorizationProof {
    active: ActiveRemoteIngressProof,
}

/// P4.5 directed reply/publisher 可挂载的 Store-derived opaque authorization。
/// 本类型只冻结身份与 key epoch，不暴露 reply key，也不实现 seal/outbox。
#[derive(Clone, Debug, Eq, PartialEq)]
#[allow(dead_code, reason = "P4.5 publisher 接缝，当前 Task 不实现 publish")]
pub(crate) struct RemoteReplyAuthorization {
    machine_trust_domain: [u8; 32],
    machine_route: MachineRouteId,
    device_route: DeviceRouteId,
    grant_serial: GrantSerial,
    authorization_hash: [u8; 32],
    key_directory_revision: KeyDirectoryRevision,
    reply_key_epoch: u64,
}

#[allow(dead_code, reason = "P4.5 publisher 接缝，当前 Task 不实现 publish")]
impl RemoteReplyAuthorization {
    pub(crate) const fn machine_trust_domain(&self) -> [u8; 32] {
        self.machine_trust_domain
    }

    pub(crate) const fn machine_route(&self) -> MachineRouteId {
        self.machine_route
    }

    pub(crate) const fn device_route(&self) -> DeviceRouteId {
        self.device_route
    }

    pub(crate) const fn grant_serial(&self) -> GrantSerial {
        self.grant_serial
    }

    pub(crate) const fn authorization_hash(&self) -> [u8; 32] {
        self.authorization_hash
    }

    pub(crate) const fn key_directory_revision(&self) -> KeyDirectoryRevision {
        self.key_directory_revision
    }

    pub(crate) const fn reply_key_epoch(&self) -> u64 {
        self.reply_key_epoch
    }

    #[cfg(test)]
    pub(crate) fn for_test(
        machine_route: MachineRouteId,
        device_route: DeviceRouteId,
        marker: u8,
    ) -> Self {
        Self {
            machine_trust_domain: [marker; 32],
            machine_route,
            device_route,
            grant_serial: GrantSerial::new(u64::from(marker).max(1)),
            authorization_hash: [marker; 32],
            key_directory_revision: KeyDirectoryRevision::new(u64::from(marker).max(1)),
            reply_key_epoch: u64::from(marker).max(1),
        }
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum RemoteCommandAuthorizationStatus {
    Active,
    Inactive,
    Unprovable,
}

impl std::fmt::Debug for CurrentRemoteAuthorizationProof {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter.write_str("CurrentRemoteAuthorizationProof([REDACTED])")
    }
}

#[allow(
    dead_code,
    reason = "同一 P4.4 Task 的 RemoteLink final recheck slice 消费"
)]
impl CurrentRemoteAuthorizationProof {
    pub(crate) fn grant_serial(&self) -> GrantSerial {
        self.active.grant_serial()
    }

    pub(crate) fn authorization_hash(&self) -> [u8; 32] {
        self.active.authorization_hash()
    }

    pub(crate) fn active(&self) -> &ActiveRemoteIngressProof {
        &self.active
    }

    /// final proof 只确认 registration 与 Store exact recheck 来自同一 opaque material。
    /// 完整 crypto 与本次 current recheck 均先于 Core registration。
    pub(crate) fn confirms_registered(&self, registration: &RemotePrincipalRegistration) -> bool {
        Arc::ptr_eq(&self.active.material, &registration.material)
    }

    pub(crate) fn command_authorization_binding(
        &self,
    ) -> Result<RemoteCommandAuthorizationBinding, RuntimeStoreError> {
        self.active.command_authorization_binding()
    }

    pub(crate) fn remote_reply_authorization(&self) -> RemoteReplyAuthorization {
        RemoteReplyAuthorization {
            machine_trust_domain: self.active.machine_trust_domain(),
            machine_route: self.active.machine_route(),
            device_route: self.active.device_route(),
            grant_serial: self.active.grant_serial(),
            authorization_hash: self.active.authorization_hash(),
            key_directory_revision: self.active.key_directory_revision(),
            reply_key_epoch: self.active.material.reply_key_epoch,
        }
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(super) enum AuthorizationLifecycle {
    GrantPreparing,
    Active,
    Superseded,
    Revoking,
    Revoked,
}

impl AuthorizationLifecycle {
    pub(super) const fn as_str(self) -> &'static str {
        match self {
            Self::GrantPreparing => "grantPreparing",
            Self::Active => "active",
            Self::Superseded => "superseded",
            Self::Revoking => "revoking",
            Self::Revoked => "revoked",
        }
    }

    fn parse(value: &str) -> Result<Self, RuntimeStoreError> {
        match value {
            "grantPreparing" => Ok(Self::GrantPreparing),
            "active" => Ok(Self::Active),
            "superseded" => Ok(Self::Superseded),
            "revoking" => Ok(Self::Revoking),
            "revoked" => Ok(Self::Revoked),
            _ => Err(RuntimeStoreError::UnknownOrCorruptSchema),
        }
    }
}

pub(super) struct AuthenticatedAuthorization {
    pub(super) device_route: DeviceRouteId,
    pub(super) grant_serial: GrantSerial,
    pub(super) lifecycle: AuthorizationLifecycle,
    pub(super) device_sign_fingerprint: [u8; 32],
    pub(super) grant_hash: [u8; 32],
    pub(super) authorization_hash: [u8; 32],
    pub(super) key_directory_revision: u64,
    pub(super) grant: RelayGrant,
    pub(super) canonical_relay_grant: Vec<u8>,
    pub(super) canonical_install_frame: Vec<u8>,
    pub(super) authorization: DeviceAuthorizationV1,
    pub(super) canonical_authorization: SecretBytes,
    pub(super) revocation_hash: Option<[u8; 32]>,
    pub(super) revocation: Option<DeviceRevocation>,
    pub(super) canonical_revocation_frame: Option<Vec<u8>>,
    pub(super) sealed_bytes: u64,
    pub(super) sealed_revocation_bytes: Option<u64>,
    pub(super) created_at_ms: u64,
    pub(super) state_changed_at_ms: u64,
    pub(super) metadata_token: [u8; 32],
}

pub(super) fn encode_authorization_payload(
    canonical_relay_grant: &[u8],
    canonical_install_frame: &[u8],
    canonical_authorization: &[u8],
) -> Result<Zeroizing<Vec<u8>>, RuntimeStoreError> {
    let fields = [
        canonical_relay_grant,
        canonical_install_frame,
        canonical_authorization,
    ];
    let mut encoded = Zeroizing::new(Vec::new());
    encoded.extend_from_slice(AUTHORIZATION_PAYLOAD_MAGIC);
    for field in fields {
        let length = u32::try_from(field.len()).map_err(|_| RuntimeStoreError::PayloadTooLarge)?;
        encoded.extend_from_slice(&length.to_be_bytes());
        encoded.extend_from_slice(field);
    }
    if encoded.len() > MAX_AUTHORIZATION_PLAINTEXT_BYTES {
        return Err(RuntimeStoreError::PayloadTooLarge);
    }
    Ok(encoded)
}

fn decode_authorization_payload(encoded: &[u8]) -> Result<[&[u8]; 3], RuntimeStoreError> {
    if encoded.len() > MAX_AUTHORIZATION_PLAINTEXT_BYTES
        || encoded.get(..AUTHORIZATION_PAYLOAD_MAGIC.len()) != Some(AUTHORIZATION_PAYLOAD_MAGIC)
    {
        return Err(RuntimeStoreError::UnknownOrCorruptSchema);
    }
    let mut cursor = AUTHORIZATION_PAYLOAD_MAGIC.len();
    let mut fields = [&[][..]; 3];
    for field in &mut fields {
        let length_end = cursor
            .checked_add(4)
            .ok_or(RuntimeStoreError::UnknownOrCorruptSchema)?;
        let length = u32::from_be_bytes(
            encoded
                .get(cursor..length_end)
                .ok_or(RuntimeStoreError::UnknownOrCorruptSchema)?
                .try_into()
                .map_err(|_| RuntimeStoreError::UnknownOrCorruptSchema)?,
        );
        cursor = length_end;
        let end = cursor
            .checked_add(
                usize::try_from(length).map_err(|_| RuntimeStoreError::UnknownOrCorruptSchema)?,
            )
            .ok_or(RuntimeStoreError::UnknownOrCorruptSchema)?;
        *field = encoded
            .get(cursor..end)
            .ok_or(RuntimeStoreError::UnknownOrCorruptSchema)?;
        cursor = end;
    }
    if cursor != encoded.len() {
        return Err(RuntimeStoreError::UnknownOrCorruptSchema);
    }
    Ok(fields)
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

fn authorization_primary_key(device_route: DeviceRouteId, serial: GrantSerial) -> [u8; 24] {
    let mut value = [0_u8; 24];
    value[..16].copy_from_slice(device_route.as_bytes());
    value[16..].copy_from_slice(&serial.value().to_be_bytes());
    value
}

#[allow(clippy::too_many_arguments)]
pub(super) fn authorization_token(
    key_bundle: &RuntimeKeyBundle,
    database_id: [u8; 16],
    device_route: DeviceRouteId,
    grant_serial: GrantSerial,
    lifecycle: AuthorizationLifecycle,
    fingerprint: [u8; 32],
    grant_hash: [u8; 32],
    authorization_hash: [u8; 32],
    revision: u64,
    sealed: &[u8],
    created_at_ms: u64,
    state_changed_at_ms: u64,
) -> Result<[u8; 32], RuntimeStoreError> {
    let sealed_len =
        u64::try_from(sealed.len()).map_err(|_| RuntimeStoreError::UnknownOrCorruptSchema)?;
    let sealed_hash = sha256(sealed);
    super::stream::metadata_mac(
        key_bundle,
        AUTH_METADATA_DOMAIN,
        &[
            &database_id,
            device_route.as_bytes(),
            &grant_serial.value().to_be_bytes(),
            lifecycle.as_str().as_bytes(),
            &fingerprint,
            &grant_hash,
            &authorization_hash,
            &revision.to_be_bytes(),
            &sealed_len.to_be_bytes(),
            &sealed_hash,
            &created_at_ms.to_be_bytes(),
            &state_changed_at_ms.to_be_bytes(),
        ],
    )
}

/// 仅供组合测试模拟“KeyUpdate 已被端点确认”后的最小 Store 状态。
///
/// P4.4 需要证明同一 MachineLink 上多个当前设备不会串路由，但第二台设备加入后，
/// 第一台设备在 P4.5 真正实现 KeyUpdate 之前应继续被 lower-revision 门禁隔离。
/// 这个 helper 只在测试构建中存在，只更新已认证 Active authorization 的 revision 与
/// 对应 metadata token；production loader 和 mutation API 均不放宽。
#[cfg(test)]
pub(super) fn align_active_authorization_revision_for_test(
    connection: &mut Connection,
    key_bundle: &RuntimeKeyBundle,
    database_id: [u8; 16],
    device_route: DeviceRouteId,
) -> Result<KeyDirectoryRevision, RuntimeStoreError> {
    let transaction =
        connection.transaction_with_behavior(rusqlite::TransactionBehavior::Immediate)?;
    let directory = super::pairing::load_directory(&transaction, key_bundle, database_id)?;
    let global_revision = directory
        .grants
        .global
        .as_ref()
        .ok_or(RuntimeStoreError::PairingConflict)?
        .revision;
    let authorization = directory
        .grants
        .authorizations
        .iter()
        .find(|authorization| {
            authorization.device_route == device_route
                && authorization.lifecycle == AuthorizationLifecycle::Active
        })
        .ok_or(RuntimeStoreError::PairingConflict)?;
    if authorization.key_directory_revision == global_revision {
        transaction.commit()?;
        return Ok(KeyDirectoryRevision::new(global_revision));
    }
    if authorization.key_directory_revision == 0
        || authorization.key_directory_revision > global_revision
        || authorization.revocation_hash.is_some()
        || authorization.sealed_revocation_bytes.is_some()
    {
        return Err(RuntimeStoreError::UnknownOrCorruptSchema);
    }

    let grant_serial = authorization.grant_serial;
    let old_revision = authorization.key_directory_revision;
    let fingerprint = authorization.device_sign_fingerprint;
    let grant_hash = authorization.grant_hash;
    let authorization_hash = authorization.authorization_hash;
    let created_at_ms = authorization.created_at_ms;
    let state_changed_at_ms = authorization.state_changed_at_ms;
    let sealed_bytes = authorization.sealed_bytes;
    let old_metadata_token = authorization.metadata_token;
    drop(directory);

    let encoded_grant_serial = super::sequence::encode_sequence(grant_serial.value());
    let sealed_authorization: Vec<u8> = transaction.query_row(
        "SELECT sealed_authorization FROM remote_authorization_ledger
         WHERE device_route = ?1 AND grant_serial = ?2 AND lifecycle = 'active'",
        rusqlite::params![device_route.as_bytes().as_slice(), encoded_grant_serial],
        |row| row.get(0),
    )?;
    if u64::try_from(sealed_authorization.len()).unwrap_or(u64::MAX) != sealed_bytes {
        return Err(RuntimeStoreError::UnknownOrCorruptSchema);
    }
    let metadata_token = authorization_token(
        key_bundle,
        database_id,
        device_route,
        grant_serial,
        AuthorizationLifecycle::Active,
        fingerprint,
        grant_hash,
        authorization_hash,
        global_revision,
        &sealed_authorization,
        created_at_ms,
        state_changed_at_ms,
    )?;
    let changed = transaction.execute(
        "UPDATE remote_authorization_ledger
         SET key_directory_revision = ?1, metadata_token = ?2
         WHERE device_route = ?3 AND grant_serial = ?4 AND lifecycle = 'active'
           AND key_directory_revision = ?5 AND metadata_token = ?6",
        rusqlite::params![
            super::sequence::encode_sequence(global_revision),
            metadata_token.as_slice(),
            device_route.as_bytes().as_slice(),
            super::sequence::encode_sequence(grant_serial.value()),
            super::sequence::encode_sequence(old_revision),
            old_metadata_token.as_slice(),
        ],
    )?;
    if changed != 1 {
        return Err(RuntimeStoreError::PairingConflict);
    }
    let aligned = super::pairing::load_directory(&transaction, key_bundle, database_id)?;
    if aligned.grants.global.as_ref().map(|global| global.revision) != Some(global_revision)
        || !aligned.grants.authorizations.iter().any(|authorization| {
            authorization.device_route == device_route
                && authorization.lifecycle == AuthorizationLifecycle::Active
                && authorization.key_directory_revision == global_revision
                && authorization.metadata_token == metadata_token
        })
    {
        return Err(RuntimeStoreError::UnknownOrCorruptSchema);
    }
    transaction.commit()?;
    Ok(KeyDirectoryRevision::new(global_revision))
}

#[allow(clippy::too_many_arguments)]
pub(super) fn authorization_revocation_token(
    key_bundle: &RuntimeKeyBundle,
    database_id: [u8; 16],
    device_route: DeviceRouteId,
    grant_serial: GrantSerial,
    lifecycle: AuthorizationLifecycle,
    fingerprint: [u8; 32],
    grant_hash: [u8; 32],
    authorization_hash: [u8; 32],
    revision: u64,
    sealed_authorization: &[u8],
    revocation_hash: [u8; 32],
    sealed_revocation: &[u8],
    created_at_ms: u64,
    state_changed_at_ms: u64,
) -> Result<[u8; 32], RuntimeStoreError> {
    if !matches!(
        lifecycle,
        AuthorizationLifecycle::Revoking | AuthorizationLifecycle::Revoked
    ) || revocation_hash == [0; 32]
    {
        return Err(RuntimeStoreError::UnknownOrCorruptSchema);
    }
    let authorization_len = u64::try_from(sealed_authorization.len())
        .map_err(|_| RuntimeStoreError::UnknownOrCorruptSchema)?;
    let revocation_len = u64::try_from(sealed_revocation.len())
        .map_err(|_| RuntimeStoreError::UnknownOrCorruptSchema)?;
    let authorization_sealed_hash = sha256(sealed_authorization);
    let revocation_sealed_hash = sha256(sealed_revocation);
    super::stream::metadata_mac(
        key_bundle,
        AUTH_REVOCATION_METADATA_DOMAIN,
        &[
            &database_id,
            device_route.as_bytes(),
            &grant_serial.value().to_be_bytes(),
            lifecycle.as_str().as_bytes(),
            &fingerprint,
            &grant_hash,
            &authorization_hash,
            &revision.to_be_bytes(),
            &authorization_len.to_be_bytes(),
            &authorization_sealed_hash,
            &revocation_hash,
            &revocation_len.to_be_bytes(),
            &revocation_sealed_hash,
            &created_at_ms.to_be_bytes(),
            &state_changed_at_ms.to_be_bytes(),
        ],
    )
}

pub(super) fn load_authorizations(
    connection: &Connection,
    key_bundle: &RuntimeKeyBundle,
    database_id: [u8; 16],
) -> Result<Vec<AuthenticatedAuthorization>, RuntimeStoreError> {
    let mut statement = connection.prepare(
        "SELECT device_route, grant_serial, lifecycle, database_id,
                device_sign_fingerprint, grant_hash, authorization_hash,
                key_directory_revision, sealed_authorization, sealed_authorization_bytes,
                revocation_hash, sealed_revocation, sealed_revocation_bytes,
                created_at_ms, state_changed_at_ms, metadata_token
         FROM remote_authorization_ledger ORDER BY device_route, grant_serial",
    )?;
    let raws = statement
        .query_map([], |row| {
            Ok((
                row.get::<_, Vec<u8>>(0)?,
                row.get::<_, String>(1)?,
                row.get::<_, String>(2)?,
                row.get::<_, Vec<u8>>(3)?,
                row.get::<_, Vec<u8>>(4)?,
                row.get::<_, Vec<u8>>(5)?,
                row.get::<_, Vec<u8>>(6)?,
                row.get::<_, String>(7)?,
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
            let device_route = DeviceRouteId::from_bytes(fixed(raw.0)?);
            let grant_serial = GrantSerial::new(sequence(&raw.1)?);
            let lifecycle = AuthorizationLifecycle::parse(&raw.2)?;
            let row_database_id = fixed(raw.3)?;
            let fingerprint = fixed(raw.4)?;
            let grant_hash = fixed(raw.5)?;
            let authorization_hash = fixed(raw.6)?;
            let revision = sequence(&raw.7)?;
            let sealed_bytes = nonnegative(raw.9)?;
            let revocation_hash = raw
                .10
                .as_ref()
                .map(|value| fixed(value.clone()))
                .transpose()?;
            let sealed_revocation_bytes = raw.12.map(nonnegative).transpose()?;
            let created_at_ms = nonnegative(raw.13)?;
            let state_changed_at_ms = nonnegative(raw.14)?;
            let metadata_token = fixed(raw.15)?;
            let primary_key = authorization_primary_key(device_route, grant_serial);
            let metadata_matches = match lifecycle {
                AuthorizationLifecycle::GrantPreparing
                | AuthorizationLifecycle::Active
                | AuthorizationLifecycle::Superseded
                    if revocation_hash.is_none()
                        && raw.11.is_none()
                        && sealed_revocation_bytes.is_none() =>
                {
                    authorization_token(
                        key_bundle,
                        database_id,
                        device_route,
                        grant_serial,
                        lifecycle,
                        fingerprint,
                        grant_hash,
                        authorization_hash,
                        revision,
                        &raw.8,
                        created_at_ms,
                        state_changed_at_ms,
                    )? == metadata_token
                }
                AuthorizationLifecycle::Revoking | AuthorizationLifecycle::Revoked => {
                    match (revocation_hash, raw.11.as_deref(), sealed_revocation_bytes) {
                        (Some(revocation_hash), Some(sealed_revocation), Some(_)) => {
                            authorization_revocation_token(
                                key_bundle,
                                database_id,
                                device_route,
                                grant_serial,
                                lifecycle,
                                fingerprint,
                                grant_hash,
                                authorization_hash,
                                revision,
                                &raw.8,
                                revocation_hash,
                                sealed_revocation,
                                created_at_ms,
                                state_changed_at_ms,
                            )? == metadata_token
                        }
                        _ => false,
                    }
                }
                _ => false,
            };
            if row_database_id != database_id
                || state_changed_at_ms < created_at_ms
                || (lifecycle == AuthorizationLifecycle::GrantPreparing
                    && created_at_ms != state_changed_at_ms)
                || sealed_bytes != u64::try_from(raw.8.len()).unwrap_or(u64::MAX)
                || !metadata_matches
            {
                return Err(RuntimeStoreError::UnknownOrCorruptSchema);
            }
            let payload = open_row(
                key_bundle,
                database_id,
                AUTH_TABLE,
                &primary_key,
                AUTH_COLUMN,
                &raw.8,
                MAX_AUTHORIZATION_PLAINTEXT_BYTES,
            )?;
            let fields = decode_authorization_payload(payload.expose_secret())?;
            let (grant, observed_grant_hash) = exact_install_frame(fields[1])?;
            let authorization = DeviceAuthorizationV1::from_canonical_bytes(fields[2])
                .map_err(|_| RuntimeStoreError::UnknownOrCorruptSchema)?;
            if authorization.canonical_sha256().ok() != Some(authorization_hash)
                || authorization.device_route != device_route
                || authorization.grant_serial != grant_serial
                || authorization.device_sign_fingerprint != fingerprint
                || grant.device_route != device_route
                || grant.grant_serial != grant_serial
                || observed_grant_hash != grant_hash
                || grant.canonical_bytes().as_slice() != fields[0]
            {
                return Err(RuntimeStoreError::UnknownOrCorruptSchema);
            }
            let (revocation, canonical_revocation_frame) = match (
                lifecycle,
                revocation_hash,
                raw.11.as_deref(),
                sealed_revocation_bytes,
            ) {
                (
                    AuthorizationLifecycle::Revoking | AuthorizationLifecycle::Revoked,
                    Some(expected_hash),
                    Some(sealed_revocation),
                    Some(expected_bytes),
                ) if expected_bytes
                    == u64::try_from(sealed_revocation.len()).unwrap_or(u64::MAX) =>
                {
                    let canonical = open_row(
                        key_bundle,
                        database_id,
                        AUTH_TABLE,
                        &primary_key,
                        AUTH_REVOCATION_COLUMN,
                        sealed_revocation,
                        MAX_REVOCATION_PLAINTEXT_BYTES,
                    )?;
                    let (revocation, observed_hash) =
                        exact_revoke_frame(canonical.expose_secret())?;
                    if observed_hash != expected_hash
                        || revocation.device_route != device_route
                        || revocation.grant_serial != grant_serial
                    {
                        return Err(RuntimeStoreError::UnknownOrCorruptSchema);
                    }
                    (Some(revocation), Some(canonical.expose_secret().to_vec()))
                }
                (
                    AuthorizationLifecycle::GrantPreparing
                    | AuthorizationLifecycle::Active
                    | AuthorizationLifecycle::Superseded,
                    None,
                    None,
                    None,
                ) => (None, None),
                _ => return Err(RuntimeStoreError::UnknownOrCorruptSchema),
            };
            Ok(AuthenticatedAuthorization {
                device_route,
                grant_serial,
                lifecycle,
                device_sign_fingerprint: fingerprint,
                grant_hash,
                authorization_hash,
                key_directory_revision: revision,
                grant,
                canonical_relay_grant: fields[0].to_vec(),
                canonical_install_frame: fields[1].to_vec(),
                authorization,
                canonical_authorization: SecretBytes::new(fields[2].to_vec()),
                revocation_hash,
                revocation,
                canonical_revocation_frame,
                sealed_bytes,
                sealed_revocation_bytes,
                created_at_ms,
                state_changed_at_ms,
                metadata_token,
            })
        })
        .collect()
}

pub(crate) fn load_active_remote_ingress(
    connection: &Connection,
    key_bundle: &RuntimeKeyBundle,
    database_id: [u8; 16],
    machine_trust_domain: [u8; 32],
    machine_route: MachineRouteId,
    device_route: DeviceRouteId,
) -> Result<ActiveRemoteIngressProof, RuntimeStoreError> {
    if machine_trust_domain == [0; 32]
        || machine_route.as_bytes() == &[0; 16]
        || device_route.as_bytes() == &[0; 16]
    {
        return Err(RuntimeStoreError::PairingConflict);
    }
    let active_machine = super::pairing::active_machine(connection, key_bundle, database_id)?;
    if active_machine.record.machine_route != *machine_route.as_bytes() {
        return Err(RuntimeStoreError::PairingConflict);
    }
    let directory = super::pairing::load_directory(connection, key_bundle, database_id)?;
    let authorization = directory
        .grants
        .authorizations
        .iter()
        .find(|authorization| {
            authorization.lifecycle == AuthorizationLifecycle::Active
                && authorization.device_route == device_route
                && authorization.grant.machine_route == machine_route
        })
        .ok_or(RuntimeStoreError::PairingConflict)?;
    let global = directory
        .grants
        .global
        .as_ref()
        .ok_or(RuntimeStoreError::PairingConflict)?;
    build_active_remote_ingress(
        database_id,
        machine_trust_domain,
        machine_route,
        device_route,
        authorization,
        global,
    )
}

/// daemon 重启且没有 live RemoteLink lease 时的 local revoke bootstrap。本次单读只为
/// exact Active authorization 签发 proof；preparing/inactive 仍由 durable owner 处理。
pub(crate) fn load_active_remote_ingress_for_revoke(
    connection: &Connection,
    key_bundle: &RuntimeKeyBundle,
    database_id: [u8; 16],
    machine_trust_domain: [u8; 32],
    device: &DeviceHandle,
    grant_serial: RuntimeGrantSerial,
) -> Result<Option<ActiveRemoteIngressProof>, RuntimeStoreError> {
    if machine_trust_domain == [0; 32] || grant_serial.0 == 0 {
        return Err(RuntimeStoreError::PairingConflict);
    }
    let device_route = super::pairing_revocation::device_route_from_handle(device)?;
    let relay_grant_serial = GrantSerial::new(grant_serial.0);
    let directory = super::pairing::load_directory(connection, key_bundle, database_id)?;
    let Some(authorization) = directory
        .grants
        .authorizations
        .iter()
        .find(|authorization| {
            authorization.device_route == device_route
                && authorization.grant_serial == relay_grant_serial
        })
    else {
        return Ok(None);
    };
    if authorization.lifecycle != AuthorizationLifecycle::Active {
        return Ok(None);
    }
    let active_machine = super::pairing::active_machine(connection, key_bundle, database_id)?;
    let machine_route = authorization.grant.machine_route;
    if active_machine.record.machine_route != *machine_route.as_bytes() {
        return Err(RuntimeStoreError::PairingConflict);
    }
    let global = directory
        .grants
        .global
        .as_ref()
        .ok_or(RuntimeStoreError::PairingConflict)?;
    build_active_remote_ingress(
        database_id,
        machine_trust_domain,
        machine_route,
        device_route,
        authorization,
        global,
    )
    .map(Some)
}

fn build_active_remote_ingress(
    database_id: [u8; 16],
    machine_trust_domain: [u8; 32],
    machine_route: MachineRouteId,
    device_route: DeviceRouteId,
    authorization: &AuthenticatedAuthorization,
    global: &super::pairing_grant::AuthenticatedGlobalKeyState,
) -> Result<ActiveRemoteIngressProof, RuntimeStoreError> {
    let device_keys = global
        .state
        .devices
        .iter()
        .find(|keys| keys.device_route == device_route)
        .ok_or(RuntimeStoreError::PairingConflict)?;
    if authorization.key_directory_revision != global.revision
        || global.revision == 0
        || device_keys.command.epoch == 0
        || device_keys.reply.epoch == 0
    {
        return Err(RuntimeStoreError::UnknownOrCorruptSchema);
    }
    let command_key_bytes: [u8; 32] = device_keys
        .command
        .key
        .expose_secret()
        .try_into()
        .map_err(|_| RuntimeStoreError::UnknownOrCorruptSchema)?;
    let device_verifying_key = VerifyingKey::from_bytes(&authorization.grant.device_sign_pubkey.0)
        .map_err(|_| RuntimeStoreError::UnknownOrCorruptSchema)?;
    let command_key_epoch = device_keys.command.epoch;
    let material = RemoteIngressMaterial {
        database_id,
        machine_trust_domain,
        machine_route,
        device_route,
        grant_serial: authorization.grant_serial,
        device_sign_fingerprint: authorization.device_sign_fingerprint,
        device_verifying_key,
        authorization_hash: authorization.authorization_hash,
        key_directory_revision: KeyDirectoryRevision::new(global.revision),
        command_key_epoch,
        reply_key_epoch: device_keys.reply.epoch,
        command_receiving_key: AeadReceivingKey::new(
            KeyId {
                purpose: KeyPurpose::DeviceCommandTx,
                epoch: command_key_epoch,
            },
            command_key_epoch,
            SecretAeadKey::from_bytes(command_key_bytes),
        ),
        permissions: authorization.authorization.permissions.clone(),
        authorization_metadata_token: authorization.metadata_token,
        directory_metadata_token: global.metadata_token,
    };
    Ok(ActiveRemoteIngressProof {
        material: Arc::new(material),
    })
}

pub(crate) fn recheck_active_remote_ingress(
    connection: &Connection,
    key_bundle: &RuntimeKeyBundle,
    database_id: [u8; 16],
    machine_trust_domain: [u8; 32],
    proof: &ActiveRemoteIngressProof,
) -> Result<CurrentRemoteAuthorizationProof, RuntimeStoreError> {
    if proof.material.database_id != database_id
        || proof.material.machine_trust_domain != machine_trust_domain
    {
        return Err(RuntimeStoreError::PairingConflict);
    }
    let current = load_active_remote_ingress(
        connection,
        key_bundle,
        database_id,
        machine_trust_domain,
        proof.machine_route(),
        proof.device_route(),
    )?;
    let expected = proof.material.as_ref();
    let observed = current.material.as_ref();
    if expected.database_id != observed.database_id
        || expected.machine_trust_domain != observed.machine_trust_domain
        || expected.machine_route != observed.machine_route
        || expected.device_route != observed.device_route
        || expected.grant_serial != observed.grant_serial
        || expected.device_sign_fingerprint != observed.device_sign_fingerprint
        || expected.device_verifying_key != observed.device_verifying_key
        || expected.authorization_hash != observed.authorization_hash
        || expected.key_directory_revision != observed.key_directory_revision
        || expected.command_key_epoch != observed.command_key_epoch
        || expected.reply_key_epoch != observed.reply_key_epoch
        || expected.permissions != observed.permissions
        || expected.authorization_metadata_token != observed.authorization_metadata_token
        || expected.directory_metadata_token != observed.directory_metadata_token
    {
        return Err(RuntimeStoreError::PairingConflict);
    }
    Ok(CurrentRemoteAuthorizationProof {
        active: proof.clone(),
    })
}

pub(crate) fn classify_remote_command_authorization(
    connection: &Connection,
    key_bundle: &RuntimeKeyBundle,
    database_id: [u8; 16],
    machine_trust_domain: [u8; 32],
    binding: &RemoteCommandAuthorizationBinding,
) -> Result<RemoteCommandAuthorizationStatus, RuntimeStoreError> {
    if binding.machine_trust_domain() != machine_trust_domain {
        return Ok(RemoteCommandAuthorizationStatus::Unprovable);
    }
    let directory = super::pairing::load_directory(connection, key_bundle, database_id)?;
    let Some(authorization) = directory
        .grants
        .authorizations
        .iter()
        .find(|authorization| {
            authorization.device_route == binding.device_route()
                && authorization.grant_serial == binding.grant_serial()
        })
    else {
        return Ok(RemoteCommandAuthorizationStatus::Unprovable);
    };
    let exact_authorization = authorization.grant.machine_route == binding.machine_route()
        && authorization.device_sign_fingerprint == binding.device_sign_fingerprint()
        && authorization.authorization_hash == binding.authorization_hash()
        && authorization.key_directory_revision == binding.key_directory_revision().value()
        && authorization.authorization.permissions.as_slice() == binding.permissions();
    if !exact_authorization {
        return Ok(RemoteCommandAuthorizationStatus::Unprovable);
    }
    match authorization.lifecycle {
        AuthorizationLifecycle::Active => {
            let Some(global) = directory.grants.global.as_ref() else {
                return Ok(RemoteCommandAuthorizationStatus::Unprovable);
            };
            let exact_key = global.revision == binding.key_directory_revision().value()
                && global.state.devices.iter().any(|device| {
                    device.device_route == binding.device_route()
                        && device.command.epoch == binding.command_key_epoch()
                });
            Ok(if exact_key {
                RemoteCommandAuthorizationStatus::Active
            } else {
                RemoteCommandAuthorizationStatus::Unprovable
            })
        }
        AuthorizationLifecycle::Superseded
        | AuthorizationLifecycle::Revoking
        | AuthorizationLifecycle::Revoked => Ok(RemoteCommandAuthorizationStatus::Inactive),
        AuthorizationLifecycle::GrantPreparing => Ok(RemoteCommandAuthorizationStatus::Unprovable),
    }
}
