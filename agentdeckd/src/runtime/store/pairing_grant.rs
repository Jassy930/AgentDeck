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
    RelayGrant, decode, encode,
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

const GLOBAL_KEY_MAGIC: &[u8; 5] = b"ADGK1";
const GLOBAL_KEY_TABLE: &[u8] = b"remote_key_directory";
const GLOBAL_KEY_COLUMN: &[u8] = b"sealed_directory";
const OUTBOX_TABLE: &[u8] = b"remote_control_outbox";
const OUTBOX_COLUMN: &[u8] = b"sealed_frame";
const GLOBAL_KEY_METADATA_DOMAIN: &[u8] = b"remote.key-directory.metadata.v1";
const INSTALL_OPERATION_DOMAIN: &[u8] = b"remote.control.install-grant.operation.v1";
const OUTBOX_METADATA_DOMAIN: &[u8] = b"remote.control.outbox.metadata.v1";
const MAX_GLOBAL_KEY_STATE_BYTES: usize = 64 * 1024 * 1024;
pub(super) const MAX_DEVICES: usize = 256;

pub(super) struct InternalKey {
    pub(super) epoch: u64,
    pub(super) key: SecretBytes,
}

impl InternalKey {
    pub(super) fn new(epoch: u64, key: SecretBytes) -> Result<Self, RuntimeStoreError> {
        if epoch == 0
            || key.expose_secret().len() != 32
            || key.expose_secret().iter().all(|byte| *byte == 0)
        {
            return Err(RuntimeStoreError::PairingConflict);
        }
        Ok(Self { epoch, key })
    }

    fn as_secret_aead_key(&self) -> Result<SecretAeadKey, RuntimeStoreError> {
        let bytes: [u8; 32] = self
            .key
            .expose_secret()
            .try_into()
            .map_err(|_| RuntimeStoreError::UnknownOrCorruptSchema)?;
        Ok(SecretAeadKey::from_bytes(bytes))
    }
}

pub(super) struct DeviceKeys {
    pub(super) device_route: DeviceRouteId,
    pub(super) command: InternalKey,
    pub(super) reply: InternalKey,
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
            command: InternalKey::new(command_epoch, command_key)?,
            reply: InternalKey::new(reply_epoch, reply_key)?,
        })
    }
}

/// StorageKEK 下持久化的 daemon-private 全局 key state。它不是任何单设备公开目录。
pub(crate) struct GlobalKeyStateV1 {
    pub(super) revision: u64,
    pub(super) catalogs: Vec<InternalKey>,
    pub(super) devices: Vec<DeviceKeys>,
}

impl std::fmt::Debug for GlobalKeyStateV1 {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("GlobalKeyStateV1")
            .field("revision", &self.revision)
            .field("device_count", &self.devices.len())
            .field("key_material", &"[REDACTED]")
            .finish()
    }
}

/// builder 用于按新设备渲染严格三项 bootstrap directory 的借用副本。
pub(crate) struct BootstrapKeyView {
    pub(crate) purpose: KeyPurpose,
    pub(crate) epoch: u64,
    pub(crate) key: SecretAeadKey,
}

impl GlobalKeyStateV1 {
    #[allow(clippy::too_many_arguments)]
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
        if revision != 1 {
            return Err(RuntimeStoreError::PairingConflict);
        }
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
        };
        value.validate()?;
        Ok(value)
    }

    /// 消费旧 singleton，轮换 Catalog 并追加新设备；既有 device keys 原样保留。
    pub(crate) fn next_for_device(
        mut self,
        device_route: DeviceRouteId,
        catalog_key: SecretBytes,
        command_key: SecretBytes,
        reply_key: SecretBytes,
    ) -> Result<Self, RuntimeStoreError> {
        self.validate()?;
        if self.devices.len() >= MAX_DEVICES
            || self
                .devices
                .iter()
                .any(|device| device.device_route == device_route)
        {
            return Err(RuntimeStoreError::PairingLimit);
        }
        self.revision =
            self.revision
                .checked_add(1)
                .ok_or(RuntimeStoreError::CapacityArithmeticOverflow {
                    field: "remote_key_directory_revision",
                })?;
        let current_catalog = self
            .catalogs
            .last()
            .ok_or(RuntimeStoreError::UnknownOrCorruptSchema)?;
        let next_catalog_epoch = current_catalog.epoch.checked_add(1).ok_or(
            RuntimeStoreError::CapacityArithmeticOverflow {
                field: "catalog_key_epoch",
            },
        )?;
        self.catalogs
            .push(InternalKey::new(next_catalog_epoch, catalog_key)?);
        self.devices
            .push(DeviceKeys::new(device_route, 1, command_key, 1, reply_key)?);
        self.devices
            .sort_by_key(|device| *device.device_route.as_bytes());
        self.validate()?;
        Ok(self)
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

    pub(crate) fn bootstrap_view(
        &self,
        device_route: DeviceRouteId,
    ) -> Result<[BootstrapKeyView; 3], RuntimeStoreError> {
        let device = self
            .devices
            .iter()
            .find(|device| device.device_route == device_route)
            .ok_or(RuntimeStoreError::PairingConflict)?;
        let catalog = self
            .catalogs
            .last()
            .ok_or(RuntimeStoreError::UnknownOrCorruptSchema)?;
        Ok([
            BootstrapKeyView {
                purpose: KeyPurpose::Catalog,
                epoch: catalog.epoch,
                key: catalog.as_secret_aead_key()?,
            },
            BootstrapKeyView {
                purpose: KeyPurpose::DeviceCommandTx,
                epoch: device.command.epoch,
                key: device.command.as_secret_aead_key()?,
            },
            BootstrapKeyView {
                purpose: KeyPurpose::DeviceReplyTx,
                epoch: device.reply.epoch,
                key: device.reply.as_secret_aead_key()?,
            },
        ])
    }

    pub(super) fn validate(&self) -> Result<(), RuntimeStoreError> {
        if self.revision == 0
            || self.catalogs.is_empty()
            || self.catalogs.len() > MAX_DEVICES
            || self.devices.is_empty()
            || self.devices.len() > MAX_DEVICES
        {
            return Err(RuntimeStoreError::PairingConflict);
        }
        let mut key_material = HashSet::new();
        let mut previous_epoch = 0_u64;
        for catalog in &self.catalogs {
            if catalog.epoch <= previous_epoch
                || catalog.key.expose_secret().len() != 32
                || catalog.key.expose_secret().iter().all(|byte| *byte == 0)
                || !key_material.insert(catalog.key.expose_secret())
            {
                return Err(RuntimeStoreError::PairingConflict);
            }
            previous_epoch = catalog.epoch;
        }
        let mut previous = None;
        for device in &self.devices {
            if previous.is_some_and(|route| route >= *device.device_route.as_bytes())
                || device.command.epoch == 0
                || device.reply.epoch == 0
                || device.command.key.expose_secret().len() != 32
                || device.reply.key.expose_secret().len() != 32
                || device
                    .command
                    .key
                    .expose_secret()
                    .iter()
                    .all(|byte| *byte == 0)
                || device
                    .reply
                    .key
                    .expose_secret()
                    .iter()
                    .all(|byte| *byte == 0)
                || !key_material.insert(device.command.key.expose_secret())
                || !key_material.insert(device.reply.key.expose_secret())
            {
                return Err(RuntimeStoreError::PairingConflict);
            }
            previous = Some(*device.device_route.as_bytes());
        }
        Ok(())
    }

    fn canonical_bytes(&self) -> Result<Zeroizing<Vec<u8>>, RuntimeStoreError> {
        self.validate()?;
        let mut encoded = Zeroizing::new(Vec::with_capacity(
            17 + self.catalogs.len() * 40 + self.devices.len() * 96,
        ));
        encoded.extend_from_slice(GLOBAL_KEY_MAGIC);
        encoded.extend_from_slice(&self.revision.to_be_bytes());
        encoded.extend_from_slice(
            &u16::try_from(self.catalogs.len())
                .map_err(|_| RuntimeStoreError::PairingLimit)?
                .to_be_bytes(),
        );
        for catalog in &self.catalogs {
            encoded.extend_from_slice(&catalog.epoch.to_be_bytes());
            encoded.extend_from_slice(catalog.key.expose_secret());
        }
        encoded.extend_from_slice(
            &u16::try_from(self.devices.len())
                .map_err(|_| RuntimeStoreError::PairingLimit)?
                .to_be_bytes(),
        );
        for device in &self.devices {
            encoded.extend_from_slice(device.device_route.as_bytes());
            encoded.extend_from_slice(&device.command.epoch.to_be_bytes());
            encoded.extend_from_slice(device.command.key.expose_secret());
            encoded.extend_from_slice(&device.reply.epoch.to_be_bytes());
            encoded.extend_from_slice(device.reply.key.expose_secret());
        }
        if encoded.len() > MAX_GLOBAL_KEY_STATE_BYTES {
            return Err(RuntimeStoreError::PairingLimit);
        }
        Ok(encoded)
    }

    fn from_canonical_bytes(encoded: &[u8]) -> Result<Self, RuntimeStoreError> {
        if encoded.len() < 57 || encoded.len() > MAX_GLOBAL_KEY_STATE_BYTES {
            return Err(RuntimeStoreError::UnknownOrCorruptSchema);
        }
        let mut cursor = 0_usize;
        let take = |cursor: &mut usize, count: usize| -> Result<&[u8], RuntimeStoreError> {
            let end = cursor
                .checked_add(count)
                .ok_or(RuntimeStoreError::UnknownOrCorruptSchema)?;
            let value = encoded
                .get(*cursor..end)
                .ok_or(RuntimeStoreError::UnknownOrCorruptSchema)?;
            *cursor = end;
            Ok(value)
        };
        if take(&mut cursor, GLOBAL_KEY_MAGIC.len())? != GLOBAL_KEY_MAGIC {
            return Err(RuntimeStoreError::UnknownOrCorruptSchema);
        }
        let revision = u64::from_be_bytes(
            take(&mut cursor, 8)?
                .try_into()
                .map_err(|_| RuntimeStoreError::UnknownOrCorruptSchema)?,
        );
        let catalog_count = usize::from(u16::from_be_bytes(
            take(&mut cursor, 2)?
                .try_into()
                .map_err(|_| RuntimeStoreError::UnknownOrCorruptSchema)?,
        ));
        if catalog_count == 0 || catalog_count > MAX_DEVICES {
            return Err(RuntimeStoreError::UnknownOrCorruptSchema);
        }
        let mut catalogs = Vec::with_capacity(catalog_count);
        for _ in 0..catalog_count {
            let epoch = u64::from_be_bytes(
                take(&mut cursor, 8)?
                    .try_into()
                    .map_err(|_| RuntimeStoreError::UnknownOrCorruptSchema)?,
            );
            catalogs.push(InternalKey::new(
                epoch,
                SecretBytes::new(take(&mut cursor, 32)?.to_vec()),
            )?);
        }
        let count = usize::from(u16::from_be_bytes(
            take(&mut cursor, 2)?
                .try_into()
                .map_err(|_| RuntimeStoreError::UnknownOrCorruptSchema)?,
        ));
        if count == 0 || count > MAX_DEVICES {
            return Err(RuntimeStoreError::UnknownOrCorruptSchema);
        }
        let mut devices = Vec::with_capacity(count);
        for _ in 0..count {
            let device_route = DeviceRouteId::from_bytes(
                take(&mut cursor, 16)?
                    .try_into()
                    .map_err(|_| RuntimeStoreError::UnknownOrCorruptSchema)?,
            );
            let command_epoch = u64::from_be_bytes(
                take(&mut cursor, 8)?
                    .try_into()
                    .map_err(|_| RuntimeStoreError::UnknownOrCorruptSchema)?,
            );
            let command_key = SecretBytes::new(take(&mut cursor, 32)?.to_vec());
            let reply_epoch = u64::from_be_bytes(
                take(&mut cursor, 8)?
                    .try_into()
                    .map_err(|_| RuntimeStoreError::UnknownOrCorruptSchema)?,
            );
            let reply_key = SecretBytes::new(take(&mut cursor, 32)?.to_vec());
            devices.push(DeviceKeys::new(
                device_route,
                command_epoch,
                command_key,
                reply_epoch,
                reply_key,
            )?);
        }
        if cursor != encoded.len() {
            return Err(RuntimeStoreError::UnknownOrCorruptSchema);
        }
        let value = Self {
            revision,
            catalogs,
            devices,
        };
        value.validate()?;
        if value.canonical_bytes()?.as_slice() != encoded {
            return Err(RuntimeStoreError::UnknownOrCorruptSchema);
        }
        Ok(value)
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
    left.epoch == right.epoch && left.key.expose_secret() == right.key.expose_secret()
}

fn same_device(left: &DeviceKeys, right: &DeviceKeys) -> bool {
    left.device_route == right.device_route
        && same_key(&left.command, &right.command)
        && same_key(&left.reply, &right.reply)
}

fn rotated_key(previous: &InternalKey, next: &InternalKey) -> bool {
    previous
        .epoch
        .checked_add(1)
        .is_some_and(|epoch| epoch == next.epoch)
        && previous.key.expose_secret() != next.key.expose_secret()
}

fn validate_global_transition(
    previous: Option<&AuthenticatedGlobalKeyState>,
    next: &GlobalKeyStateV1,
    new_device: DeviceRouteId,
    allocation: super::pairing_grant_allocation::ValidatedGrantAllocation,
) -> Result<(), RuntimeStoreError> {
    next.validate()?;
    match previous {
        None if allocation == super::pairing_grant_allocation::ValidatedGrantAllocation::New => {
            if next.revision != 1
                || next.catalogs.len() != 1
                || next.devices.len() != 1
                || next.devices[0].device_route != new_device
            {
                return Err(RuntimeStoreError::PairingConflict);
            }
        }
        Some(previous) => {
            if next.revision
                != previous.revision.checked_add(1).ok_or(
                    RuntimeStoreError::CapacityArithmeticOverflow {
                        field: "remote_key_directory_revision",
                    },
                )?
                || next.catalogs.len() != previous.state.catalogs.len() + 1
            {
                return Err(RuntimeStoreError::PairingConflict);
            }
            for (old, retained) in previous.state.catalogs.iter().zip(&next.catalogs) {
                if !same_key(old, retained) {
                    return Err(RuntimeStoreError::PairingConflict);
                }
            }
            match allocation {
                super::pairing_grant_allocation::ValidatedGrantAllocation::New => {
                    if next.devices.len() != previous.state.devices.len() + 1
                        || next
                            .devices
                            .iter()
                            .filter(|device| device.device_route == new_device)
                            .count()
                            != 1
                    {
                        return Err(RuntimeStoreError::PairingConflict);
                    }
                    for old in &previous.state.devices {
                        let retained = next
                            .devices
                            .iter()
                            .find(|device| device.device_route == old.device_route)
                            .ok_or(RuntimeStoreError::PairingConflict)?;
                        if !same_device(old, retained) {
                            return Err(RuntimeStoreError::PairingConflict);
                        }
                    }
                }
                super::pairing_grant_allocation::ValidatedGrantAllocation::Renew {
                    device_route,
                    ..
                } => {
                    if new_device != device_route
                        || next.devices.len() != previous.state.devices.len()
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
                            if !rotated_key(&old.command, &retained.command)
                                || !rotated_key(&old.reply, &retained.reply)
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
    directory
        .validate_bootstrap_for_device(device_route)
        .map_err(|_| RuntimeStoreError::PairingConflict)?;
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
    if !state
        .catalogs
        .iter()
        .any(|catalog| catalog.epoch == catalog_epoch)
        || command_epoch != device.command.epoch
        || reply_epoch != device.reply.epoch
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
    )?;
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
