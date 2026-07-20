//! 本机授权撤销、orphan grant 清理与 Relay ACK 的 durable Store 状态机。

use agentdeck_crypto::{SignatureBytes, VerifyingKey, sha256, verify_tbs};
use agentdeck_protocol::relay_v2::frame::{OpaqueRouteFrame, RelayFrameBody, RevokeDevice};
use agentdeck_protocol::relay_v2::{
    DeviceRevocation, DeviceRouteId, GrantSerial, RELAY_PROTOCOL_VERSION, RelayGrant, decode,
    encode,
};
use agentdeck_protocol::runtime::identity::{DeviceHandle, GrantSerial as RuntimeGrantSerial};
use rusqlite::{Connection, TransactionBehavior, params};

use crate::runtime::model::{
    RuntimeCommitOperation, RuntimeStoreConfig, RuntimeStoreError, RuntimeStoreOperation,
};

use super::cipher::{RowAad, RuntimeKeyBundle};
use super::identity::{RuntimeId, RuntimeIdKind};
use super::pairing_authorization::{
    AuthenticatedAuthorization, AuthorizationLifecycle, authorization_revocation_token,
};
use super::schema::{RUNTIME_CRYPTO_CONTEXT_VERSION, RUNTIME_SCHEMA_FAMILY};
use super::sqlite::{RuntimeLedger, RuntimeSqlite};

const AUTH_TABLE: &[u8] = b"remote_authorization_ledger";
const AUTH_REVOCATION_COLUMN: &[u8] = b"sealed_revocation";
const OUTBOX_TABLE: &[u8] = b"remote_control_outbox";
const OUTBOX_COLUMN: &[u8] = b"sealed_frame";
const REVOCATION_OPERATION_DOMAIN: &[u8] = b"remote.control.revoke-device.operation.v1";
const REVOCATION_OUTBOX_METADATA_DOMAIN: &[u8] = b"remote.control.revoke-device.outbox.metadata.v1";
pub(super) const MAX_REVOCATION_PLAINTEXT_BYTES: usize = 64 * 1024;
const MAX_REVOCATION_RECOVERY_RETAINED_BYTES: usize = 128 * 1024 * 1024;
const DEVICE_HANDLE_PREFIX: &str = "device-";

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum RevocationCause {
    Local,
    OrphanExpired { pairing_id: RuntimeId },
}

pub(crate) struct BeginDeviceRevocation {
    cause: RevocationCause,
    revocation: DeviceRevocation,
}

impl BeginDeviceRevocation {
    #[must_use]
    pub(crate) const fn local(revocation: DeviceRevocation) -> Self {
        Self {
            cause: RevocationCause::Local,
            revocation,
        }
    }

    #[must_use]
    pub(crate) const fn orphan(pairing_id: RuntimeId, revocation: DeviceRevocation) -> Self {
        Self {
            cause: RevocationCause::OrphanExpired { pairing_id },
            revocation,
        }
    }
}

impl std::fmt::Debug for BeginDeviceRevocation {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter.write_str("BeginDeviceRevocation([REDACTED])")
    }
}

pub(crate) struct PreparedDeviceRevocation {
    cause: RevocationCause,
    revocation: DeviceRevocation,
    revocation_hash: [u8; 32],
    canonical_revoke_frame: Vec<u8>,
    frame_hash: [u8; 32],
}

impl PreparedDeviceRevocation {
    pub(crate) fn retained_bytes(&self) -> usize {
        self.canonical_revoke_frame.capacity()
    }
}

impl std::fmt::Debug for PreparedDeviceRevocation {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter.write_str("PreparedDeviceRevocation([REDACTED])")
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum RevocationRecoveryPhase {
    AwaitingGrantCommit,
    ReadyToRevoke,
}

#[derive(Debug)]
pub(crate) struct RevocationTarget {
    pairing_id: Option<RuntimeId>,
    device: DeviceHandle,
    grant: RelayGrant,
}

impl RevocationTarget {
    #[must_use]
    pub(crate) const fn pairing_id(&self) -> Option<RuntimeId> {
        self.pairing_id
    }

    #[must_use]
    pub(crate) const fn device(&self) -> &DeviceHandle {
        &self.device
    }

    #[must_use]
    pub(crate) const fn grant(&self) -> &RelayGrant {
        &self.grant
    }
}

#[derive(Debug)]
pub(crate) enum RevocationTargetStatus {
    Ready {
        target: RevocationTarget,
    },
    Revoking {
        recovery: Box<DeviceRevocationRecovery>,
    },
    Revoked {
        revocation: DeviceRevocation,
    },
}

pub(crate) struct DeviceRevocationRecovery {
    pairing_id: Option<RuntimeId>,
    device_route: DeviceRouteId,
    grant_serial: GrantSerial,
    grant: RelayGrant,
    revocation: DeviceRevocation,
    canonical_install_frame: Option<Vec<u8>>,
    canonical_revoke_frame: Vec<u8>,
}

impl std::fmt::Debug for DeviceRevocationRecovery {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter.write_str("DeviceRevocationRecovery([REDACTED])")
    }
}

impl DeviceRevocationRecovery {
    #[must_use]
    pub(crate) const fn pairing_id(&self) -> Option<RuntimeId> {
        self.pairing_id
    }

    #[must_use]
    pub(crate) const fn device_route(&self) -> DeviceRouteId {
        self.device_route
    }

    #[must_use]
    pub(crate) const fn grant_serial(&self) -> GrantSerial {
        self.grant_serial
    }

    #[must_use]
    pub(crate) const fn grant(&self) -> &RelayGrant {
        &self.grant
    }

    #[must_use]
    pub(crate) const fn revocation(&self) -> &DeviceRevocation {
        &self.revocation
    }

    #[must_use]
    pub(crate) const fn phase(&self) -> RevocationRecoveryPhase {
        if self.canonical_install_frame.is_some() {
            RevocationRecoveryPhase::AwaitingGrantCommit
        } else {
            RevocationRecoveryPhase::ReadyToRevoke
        }
    }

    /// 当前阶段唯一允许发送的 canonical frame；不会把 revoke 与 install 同批暴露。
    #[must_use]
    pub(crate) fn canonical_next_frame(&self) -> &[u8] {
        self.canonical_install_frame
            .as_deref()
            .unwrap_or(&self.canonical_revoke_frame)
    }

    fn retained_bytes(&self) -> Result<usize, RuntimeStoreError> {
        self.canonical_install_frame
            .as_ref()
            .map_or(0, Vec::capacity)
            .checked_add(self.canonical_revoke_frame.capacity())
            .ok_or(RuntimeStoreError::PayloadTooLarge)
    }
}

#[derive(Debug)]
pub(crate) enum BeginDeviceRevocationOutcome {
    Prepared { recovery: DeviceRevocationRecovery },
    Replayed { recovery: DeviceRevocationRecovery },
    AlreadyRevoked { revocation: DeviceRevocation },
}

pub(super) struct AuthenticatedRevocationOutbox {
    pub(super) outbox_id: RuntimeId,
    pub(super) operation_key: [u8; 32],
    pub(super) device_route: DeviceRouteId,
    pub(super) grant_serial: GrantSerial,
    pub(super) frame_hash: [u8; 32],
    pub(super) revocation: DeviceRevocation,
    pub(super) revocation_hash: [u8; 32],
    pub(super) canonical_frame: Vec<u8>,
    pub(super) sealed_bytes: u64,
    pub(super) metadata_token: [u8; 32],
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

pub(super) fn exact_revoke_frame(
    canonical: &[u8],
) -> Result<(DeviceRevocation, [u8; 32]), RuntimeStoreError> {
    if canonical.is_empty() || canonical.len() > MAX_REVOCATION_PLAINTEXT_BYTES {
        return Err(RuntimeStoreError::UnknownOrCorruptSchema);
    }
    let frame: OpaqueRouteFrame =
        decode(canonical).map_err(|_| RuntimeStoreError::UnknownOrCorruptSchema)?;
    if frame.version != RELAY_PROTOCOL_VERSION || encode(&frame) != canonical {
        return Err(RuntimeStoreError::UnknownOrCorruptSchema);
    }
    let RelayFrameBody::RevokeDevice(RevokeDevice { revocation }) = frame.body else {
        return Err(RuntimeStoreError::UnknownOrCorruptSchema);
    };
    let revocation_hash = revocation.canonical_sha256();
    if revocation.device_route.as_bytes() == &[0; 16]
        || revocation.grant_serial.value() == 0
        || revocation.signature.0 == [0; 64]
        || revocation_hash == [0; 32]
    {
        return Err(RuntimeStoreError::UnknownOrCorruptSchema);
    }
    Ok((revocation, revocation_hash))
}

fn prepare_begin(
    input: BeginDeviceRevocation,
) -> Result<PreparedDeviceRevocation, RuntimeStoreError> {
    if matches!(
        input.cause,
        RevocationCause::OrphanExpired { pairing_id }
            if pairing_id.kind() != RuntimeIdKind::Pairing
    ) {
        return Err(RuntimeStoreError::IdKindMismatch {
            expected: RuntimeIdKind::Pairing,
            actual: match input.cause {
                RevocationCause::OrphanExpired { pairing_id } => pairing_id.kind(),
                RevocationCause::Local => RuntimeIdKind::Pairing,
            },
        });
    }
    let canonical_revoke_frame = encode(&OpaqueRouteFrame {
        version: RELAY_PROTOCOL_VERSION,
        body: RelayFrameBody::RevokeDevice(RevokeDevice {
            revocation: input.revocation.clone(),
        }),
    });
    let (observed, revocation_hash) = exact_revoke_frame(&canonical_revoke_frame)
        .map_err(|_| RuntimeStoreError::PairingConflict)?;
    if observed != input.revocation {
        return Err(RuntimeStoreError::PairingConflict);
    }
    let frame_hash = sha256(&canonical_revoke_frame);
    if frame_hash == [0; 32] {
        return Err(RuntimeStoreError::PairingConflict);
    }
    Ok(PreparedDeviceRevocation {
        cause: input.cause,
        revocation: input.revocation,
        revocation_hash,
        canonical_revoke_frame,
        frame_hash,
    })
}

pub(super) fn revocation_operation_key(
    key_bundle: &RuntimeKeyBundle,
    device_route: DeviceRouteId,
    serial: GrantSerial,
) -> Result<[u8; 32], RuntimeStoreError> {
    let mut input = Vec::with_capacity(24);
    input.extend_from_slice(device_route.as_bytes());
    input.extend_from_slice(&serial.value().to_be_bytes());
    let value = *key_bundle
        .blind_index(REVOCATION_OPERATION_DOMAIN, &input)?
        .as_bytes();
    if value == [0; 32] {
        return Err(RuntimeStoreError::UnknownOrCorruptSchema);
    }
    Ok(value)
}

#[allow(clippy::too_many_arguments)]
pub(super) fn revocation_outbox_token(
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
        REVOCATION_OUTBOX_METADATA_DOMAIN,
        &[
            &database_id,
            outbox_id.as_bytes(),
            b"revokeDevice",
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

fn open_outbox_frame(
    key_bundle: &RuntimeKeyBundle,
    database_id: [u8; 16],
    outbox_id: RuntimeId,
    sealed: &[u8],
) -> Result<Vec<u8>, RuntimeStoreError> {
    let opened = key_bundle.row_cipher().open_bounded(
        &RowAad {
            schema_family: RUNTIME_SCHEMA_FAMILY.as_bytes(),
            schema_version: RUNTIME_CRYPTO_CONTEXT_VERSION,
            database_id: &database_id,
            table: OUTBOX_TABLE,
            primary_key: outbox_id.as_bytes(),
            column: OUTBOX_COLUMN,
        },
        sealed,
        MAX_REVOCATION_PLAINTEXT_BYTES,
    )?;
    Ok(opened.expose_secret().to_vec())
}

pub(super) fn load_revocation_outboxes(
    connection: &Connection,
    key_bundle: &RuntimeKeyBundle,
    database_id: [u8; 16],
) -> Result<Vec<AuthenticatedRevocationOutbox>, RuntimeStoreError> {
    let mut statement = connection.prepare(
        "SELECT outbox_id, operation_key, lifecycle, database_id, pairing_id,
                device_route, grant_serial, frame_hash, sealed_frame, sealed_frame_bytes,
                terminal_hash, sealed_terminal, sealed_terminal_bytes,
                created_at_ms, state_changed_at_ms, metadata_token
         FROM remote_control_outbox
         WHERE operation_kind = 'revokeDevice' ORDER BY outbox_id",
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
            let grant_serial = GrantSerial::new(sequence(
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
                || revocation_operation_key(key_bundle, device_route, grant_serial)?
                    != operation_key
                || revocation_outbox_token(
                    key_bundle,
                    database_id,
                    outbox_id,
                    operation_key,
                    device_route,
                    grant_serial,
                    frame_hash,
                    &raw.8,
                    created_at_ms,
                    state_changed_at_ms,
                )? != metadata_token
            {
                return Err(RuntimeStoreError::UnknownOrCorruptSchema);
            }
            let canonical_frame = open_outbox_frame(key_bundle, database_id, outbox_id, &raw.8)?;
            let (revocation, revocation_hash) = exact_revoke_frame(&canonical_frame)?;
            if sha256(&canonical_frame) != frame_hash
                || revocation.device_route != device_route
                || revocation.grant_serial != grant_serial
            {
                return Err(RuntimeStoreError::UnknownOrCorruptSchema);
            }
            Ok(AuthenticatedRevocationOutbox {
                outbox_id,
                operation_key,
                device_route,
                grant_serial,
                frame_hash,
                revocation,
                revocation_hash,
                canonical_frame,
                sealed_bytes,
                metadata_token,
            })
        })
        .collect()
}

pub(super) fn validate_revocation_signature(
    authorization: &AuthenticatedAuthorization,
    revocation: &DeviceRevocation,
    active: &crate::runtime::model::ActiveMachineEnrollmentState,
) -> Result<(), RuntimeStoreError> {
    let grant = &authorization.grant;
    if revocation.machine_route != grant.machine_route
        || revocation.device_route != grant.device_route
        || revocation.grant_serial != grant.grant_serial
        || revocation.root_key_id != grant.root_key_id
        || revocation.trust_epoch != grant.trust_epoch
        || revocation.machine_route.as_bytes() != &active.record.machine_route
        || revocation.root_key_id.as_bytes() != &active.record.root_key_id
        || revocation.trust_epoch.value() != active.record.trust_epoch
    {
        return Err(RuntimeStoreError::PairingConflict);
    }
    let root = VerifyingKey::from_bytes(&active.binding.root_public_key)
        .map_err(|_| RuntimeStoreError::PairingConflict)?;
    verify_tbs(
        &root,
        &revocation.to_be_signed_v1(
            active.connection.relay_server_id,
            active.binding.root_fingerprint,
        ),
        &SignatureBytes::from(revocation.signature),
    )
    .map_err(|_| RuntimeStoreError::PairingConflict)
}

struct BeginBindings<'a> {
    authorization: &'a AuthenticatedAuthorization,
    pairing: Option<&'a super::pairing::AuthenticatedPairingRow>,
}

fn validate_begin_target<'a>(
    directory: &'a super::pairing::PairingDirectory,
    prepared: &PreparedDeviceRevocation,
    active: &crate::runtime::model::ActiveMachineEnrollmentState,
    now_ms: u64,
) -> Result<BeginBindings<'a>, RuntimeStoreError> {
    let authorization = directory
        .grants
        .authorizations
        .iter()
        .find(|authorization| {
            authorization.device_route == prepared.revocation.device_route
                && authorization.grant_serial == prepared.revocation.grant_serial
        })
        .ok_or(RuntimeStoreError::PairingConflict)?;
    validate_revocation_signature(authorization, &prepared.revocation, active)?;
    let grant_pairing = directory.pairings.iter().find(|pairing| {
        pairing.record.grant_hash == Some(authorization.grant_hash)
            && pairing.record.canonical_relay_grant.as_deref()
                == Some(authorization.canonical_relay_grant.as_slice())
    });
    let pairing = match prepared.cause {
        RevocationCause::Local => match authorization.lifecycle {
            AuthorizationLifecycle::GrantPreparing => {
                let pairing = grant_pairing.ok_or(RuntimeStoreError::PairingConflict)?;
                if pairing.record.lifecycle
                    != super::pairing::PairingInviteLifecycle::GrantPreparing
                    || now_ms < pairing.record.state_changed_at_ms
                    || now_ms >= pairing.record.expires_at_ms
                {
                    return Err(RuntimeStoreError::PairingConflict);
                }
                Some(pairing)
            }
            AuthorizationLifecycle::Active => match grant_pairing {
                Some(pairing)
                    if pairing.record.lifecycle
                        == super::pairing::PairingInviteLifecycle::GrantCommitted =>
                {
                    if now_ms < pairing.record.state_changed_at_ms {
                        return Err(RuntimeStoreError::ClockRegressed {
                            persisted_ms: pairing.record.state_changed_at_ms,
                            observed_ms: now_ms,
                        });
                    }
                    if now_ms >= pairing.record.expires_at_ms {
                        return Err(RuntimeStoreError::PairingConflict);
                    }
                    Some(pairing)
                }
                Some(pairing)
                    if pairing.record.lifecycle
                        == super::pairing::PairingInviteLifecycle::Delivered =>
                {
                    None
                }
                None => None,
                _ => return Err(RuntimeStoreError::PairingConflict),
            },
            AuthorizationLifecycle::Superseded
            | AuthorizationLifecycle::Revoking
            | AuthorizationLifecycle::Revoked => {
                return Err(RuntimeStoreError::PairingConflict);
            }
        },
        RevocationCause::OrphanExpired { pairing_id } => {
            let pairing = grant_pairing.ok_or(RuntimeStoreError::PairingConflict)?;
            let expected_authorization_lifecycle = match pairing.record.lifecycle {
                super::pairing::PairingInviteLifecycle::GrantPreparing => {
                    AuthorizationLifecycle::GrantPreparing
                }
                super::pairing::PairingInviteLifecycle::GrantCommitted => {
                    AuthorizationLifecycle::Active
                }
                _ => return Err(RuntimeStoreError::PairingConflict),
            };
            if pairing.record.pairing_id != pairing_id
                || pairing.record.expires_at_ms > now_ms
                || now_ms < pairing.record.state_changed_at_ms
                || authorization.lifecycle != expected_authorization_lifecycle
            {
                return Err(RuntimeStoreError::PairingConflict);
            }
            Some(pairing)
        }
    };
    if directory.grants.revocations.iter().any(|outbox| {
        outbox.device_route == authorization.device_route
            && outbox.grant_serial == authorization.grant_serial
    }) {
        return Err(RuntimeStoreError::PairingConflict);
    }
    Ok(BeginBindings {
        authorization,
        pairing,
    })
}

fn next_begin_ledger(
    current: &RuntimeLedger,
    previous: AuthorizationLifecycle,
    sealed_revocation_bytes: usize,
    sealed_outbox_bytes: usize,
) -> Result<RuntimeLedger, RuntimeStoreError> {
    let sealed_revocation_bytes =
        u64::try_from(sealed_revocation_bytes).map_err(|_| RuntimeStoreError::PayloadTooLarge)?;
    let sealed_outbox_bytes =
        u64::try_from(sealed_outbox_bytes).map_err(|_| RuntimeStoreError::PayloadTooLarge)?;
    let mut next = current.clone();
    match previous {
        AuthorizationLifecycle::GrantPreparing => {
            next.remote_authorization_preparing_count = next
                .remote_authorization_preparing_count
                .checked_sub(1)
                .ok_or(RuntimeStoreError::UnknownOrCorruptSchema)?;
        }
        AuthorizationLifecycle::Active => {
            next.remote_authorization_active_count = next
                .remote_authorization_active_count
                .checked_sub(1)
                .ok_or(RuntimeStoreError::UnknownOrCorruptSchema)?;
        }
        AuthorizationLifecycle::Superseded
        | AuthorizationLifecycle::Revoking
        | AuthorizationLifecycle::Revoked => {
            return Err(RuntimeStoreError::PairingConflict);
        }
    }
    next.remote_authorization_revoking_count = next
        .remote_authorization_revoking_count
        .checked_add(1)
        .ok_or(RuntimeStoreError::CapacityArithmeticOverflow {
            field: "remote_authorization_revoking_count",
        })?;
    next.remote_authorization_sealed_bytes = next
        .remote_authorization_sealed_bytes
        .checked_add(sealed_revocation_bytes)
        .ok_or(RuntimeStoreError::CapacityArithmeticOverflow {
            field: "remote_authorization_sealed_bytes",
        })?;
    next.remote_control_outbox_count = next.remote_control_outbox_count.checked_add(1).ok_or(
        RuntimeStoreError::CapacityArithmeticOverflow {
            field: "remote_control_outbox_count",
        },
    )?;
    next.remote_control_outbox_pending_count = next
        .remote_control_outbox_pending_count
        .checked_add(1)
        .ok_or(RuntimeStoreError::CapacityArithmeticOverflow {
            field: "remote_control_outbox_pending_count",
        })?;
    next.remote_control_outbox_sealed_bytes = next
        .remote_control_outbox_sealed_bytes
        .checked_add(sealed_outbox_bytes)
        .ok_or(RuntimeStoreError::CapacityArithmeticOverflow {
            field: "remote_control_outbox_sealed_bytes",
        })?;
    if next.remote_authorization_sealed_bytes
        > super::pairing_authorization::MAX_AUTHORIZATION_SEALED_BYTES
        || next.remote_control_outbox_count > super::pairing::MAX_CONTROL_OUTBOX
        || next.remote_control_outbox_sealed_bytes > super::pairing::MAX_CONTROL_OUTBOX_SEALED_BYTES
    {
        return Err(RuntimeStoreError::PairingLimit);
    }
    Ok(next)
}

pub(super) fn recovery(
    directory: &super::pairing::PairingDirectory,
    authorization: &AuthenticatedAuthorization,
) -> Result<DeviceRevocationRecovery, RuntimeStoreError> {
    if authorization.lifecycle != AuthorizationLifecycle::Revoking {
        return Err(RuntimeStoreError::UnknownOrCorruptSchema);
    }
    let outbox = directory
        .grants
        .revocations
        .iter()
        .find(|outbox| {
            outbox.device_route == authorization.device_route
                && outbox.grant_serial == authorization.grant_serial
        })
        .ok_or(RuntimeStoreError::UnknownOrCorruptSchema)?;
    let pairing = directory.pairings.iter().find(|pairing| {
        pairing.record.lifecycle == super::pairing::PairingInviteLifecycle::OrphanRevoking
            && pairing.record.grant_hash == Some(authorization.grant_hash)
    });
    let install = directory.grants.installs.iter().find(|install| {
        install.device_route == authorization.device_route
            && install.grant_serial == authorization.grant_serial
    });
    if pairing.is_none() && install.is_some() {
        return Err(RuntimeStoreError::UnknownOrCorruptSchema);
    }
    Ok(DeviceRevocationRecovery {
        pairing_id: pairing.map(|pairing| pairing.record.pairing_id),
        device_route: authorization.device_route,
        grant_serial: authorization.grant_serial,
        grant: authorization.grant.clone(),
        revocation: outbox.revocation.clone(),
        canonical_install_frame: install.map(|install| install.canonical_frame.clone()),
        canonical_revoke_frame: outbox.canonical_frame.clone(),
    })
}

fn classify_existing(
    directory: &super::pairing::PairingDirectory,
    prepared: &PreparedDeviceRevocation,
) -> Result<Option<BeginDeviceRevocationOutcome>, RuntimeStoreError> {
    let authorization = directory
        .grants
        .authorizations
        .iter()
        .find(|authorization| {
            authorization.device_route == prepared.revocation.device_route
                && authorization.grant_serial == prepared.revocation.grant_serial
        })
        .ok_or(RuntimeStoreError::PairingConflict)?;
    if !matches!(
        authorization.lifecycle,
        AuthorizationLifecycle::Revoking | AuthorizationLifecycle::Revoked
    ) {
        return Ok(None);
    }
    if authorization.revocation.as_ref() != Some(&prepared.revocation)
        || authorization.revocation_hash != Some(prepared.revocation_hash)
        || authorization.canonical_revocation_frame.as_deref()
            != Some(prepared.canonical_revoke_frame.as_slice())
    {
        return Err(RuntimeStoreError::PairingConflict);
    }
    match prepared.cause {
        RevocationCause::Local => {
            let pairing = directory
                .pairings
                .iter()
                .find(|pairing| pairing.record.grant_hash == Some(authorization.grant_hash));
            match (
                authorization.lifecycle,
                pairing.map(|pairing| &pairing.record),
            ) {
                (AuthorizationLifecycle::Revoking, Some(pairing))
                    if pairing.lifecycle
                        == super::pairing::PairingInviteLifecycle::OrphanRevoking
                        && pairing.state_changed_at_ms < pairing.expires_at_ms => {}
                (AuthorizationLifecycle::Revoking, Some(pairing))
                    if pairing.lifecycle == super::pairing::PairingInviteLifecycle::Delivered => {}
                (AuthorizationLifecycle::Revoking, None) => {}
                (AuthorizationLifecycle::Revoked, Some(pairing))
                    if matches!(
                        pairing.lifecycle,
                        super::pairing::PairingInviteLifecycle::Canceled
                            | super::pairing::PairingInviteLifecycle::Delivered
                    ) => {}
                (AuthorizationLifecycle::Revoked, None) => {}
                _ => return Err(RuntimeStoreError::PairingConflict),
            }
        }
        RevocationCause::OrphanExpired { pairing_id } => {
            let pairing = directory
                .pairings
                .iter()
                .find(|pairing| pairing.record.pairing_id == pairing_id)
                .ok_or(RuntimeStoreError::PairingConflict)?;
            let lifecycle_matches = match authorization.lifecycle {
                AuthorizationLifecycle::Revoking => {
                    pairing.record.lifecycle
                        == super::pairing::PairingInviteLifecycle::OrphanRevoking
                        && pairing.record.state_changed_at_ms >= pairing.record.expires_at_ms
                }
                AuthorizationLifecycle::Revoked => {
                    pairing.record.lifecycle == super::pairing::PairingInviteLifecycle::Expired
                }
                AuthorizationLifecycle::GrantPreparing
                | AuthorizationLifecycle::Active
                | AuthorizationLifecycle::Superseded => false,
            };
            if !lifecycle_matches || pairing.record.grant_hash != Some(authorization.grant_hash) {
                return Err(RuntimeStoreError::PairingConflict);
            }
        }
    }
    Ok(Some(match authorization.lifecycle {
        AuthorizationLifecycle::Revoking => BeginDeviceRevocationOutcome::Replayed {
            recovery: recovery(directory, authorization)?,
        },
        AuthorizationLifecycle::Revoked => BeginDeviceRevocationOutcome::AlreadyRevoked {
            revocation: authorization
                .revocation
                .clone()
                .ok_or(RuntimeStoreError::UnknownOrCorruptSchema)?,
        },
        AuthorizationLifecycle::GrantPreparing
        | AuthorizationLifecycle::Active
        | AuthorizationLifecycle::Superseded => {
            return Ok(None);
        }
    }))
}

pub(crate) fn list_revocation_recovery(
    connection: &Connection,
    key_bundle: &RuntimeKeyBundle,
    database_id: [u8; 16],
) -> Result<Vec<DeviceRevocationRecovery>, RuntimeStoreError> {
    let directory = super::pairing::load_directory(connection, key_bundle, database_id)?;
    let recoveries = directory
        .grants
        .authorizations
        .iter()
        .filter(|authorization| authorization.lifecycle == AuthorizationLifecycle::Revoking)
        .map(|authorization| recovery(&directory, authorization))
        .collect::<Result<Vec<_>, _>>()?;
    let retained = recoveries.iter().try_fold(
        recoveries
            .capacity()
            .checked_mul(std::mem::size_of::<DeviceRevocationRecovery>())
            .ok_or(RuntimeStoreError::PayloadTooLarge)?,
        |total, recovery| {
            total
                .checked_add(recovery.retained_bytes()?)
                .ok_or(RuntimeStoreError::PayloadTooLarge)
        },
    )?;
    ensure_recovery_budget(retained)?;
    Ok(recoveries)
}

fn device_handle(device_route: DeviceRouteId) -> DeviceHandle {
    const HEX: &[u8; 16] = b"0123456789abcdef";
    let mut value = String::with_capacity(DEVICE_HANDLE_PREFIX.len() + 32);
    value.push_str(DEVICE_HANDLE_PREFIX);
    for byte in device_route.as_bytes() {
        value.push(char::from(HEX[usize::from(byte >> 4)]));
        value.push(char::from(HEX[usize::from(byte & 0x0f)]));
    }
    DeviceHandle::new(value)
}

fn device_route_from_handle(handle: &DeviceHandle) -> Result<DeviceRouteId, RuntimeStoreError> {
    let encoded = handle
        .as_str()
        .strip_prefix(DEVICE_HANDLE_PREFIX)
        .ok_or(RuntimeStoreError::PairingConflict)?;
    if encoded.len() != 32 || !encoded.bytes().all(|byte| byte.is_ascii_hexdigit()) {
        return Err(RuntimeStoreError::PairingConflict);
    }
    let nibble = |byte: u8| -> Result<u8, RuntimeStoreError> {
        match byte {
            b'0'..=b'9' => Ok(byte - b'0'),
            b'a'..=b'f' => Ok(byte - b'a' + 10),
            _ => Err(RuntimeStoreError::PairingConflict),
        }
    };
    let bytes = encoded.as_bytes();
    let mut route = [0_u8; 16];
    for (index, value) in route.iter_mut().enumerate() {
        let offset = index * 2;
        *value = (nibble(bytes[offset])? << 4) | nibble(bytes[offset + 1])?;
    }
    if route == [0; 16] || device_handle(DeviceRouteId::from_bytes(route)) != *handle {
        return Err(RuntimeStoreError::PairingConflict);
    }
    Ok(DeviceRouteId::from_bytes(route))
}

pub(crate) fn load_revocation_target(
    connection: &Connection,
    key_bundle: &RuntimeKeyBundle,
    database_id: [u8; 16],
    device: &DeviceHandle,
    grant_serial: RuntimeGrantSerial,
) -> Result<Option<RevocationTargetStatus>, RuntimeStoreError> {
    let device_route = device_route_from_handle(device)?;
    let grant_serial = GrantSerial::new(grant_serial.0);
    if grant_serial.value() == 0 {
        return Err(RuntimeStoreError::PairingConflict);
    }
    let directory = super::pairing::load_directory(connection, key_bundle, database_id)?;
    let Some(authorization) = directory
        .grants
        .authorizations
        .iter()
        .find(|authorization| {
            authorization.device_route == device_route && authorization.grant_serial == grant_serial
        })
    else {
        return Ok(None);
    };
    Ok(Some(match authorization.lifecycle {
        AuthorizationLifecycle::GrantPreparing | AuthorizationLifecycle::Active => {
            RevocationTargetStatus::Ready {
                target: RevocationTarget {
                    pairing_id: None,
                    device: device.clone(),
                    grant: authorization.grant.clone(),
                },
            }
        }
        AuthorizationLifecycle::Revoking => RevocationTargetStatus::Revoking {
            recovery: Box::new(recovery(&directory, authorization)?),
        },
        AuthorizationLifecycle::Revoked => RevocationTargetStatus::Revoked {
            revocation: authorization
                .revocation
                .clone()
                .ok_or(RuntimeStoreError::UnknownOrCorruptSchema)?,
        },
        AuthorizationLifecycle::Superseded => return Err(RuntimeStoreError::PairingConflict),
    }))
}

pub(crate) fn list_due_orphan_revocation_targets(
    connection: &Connection,
    key_bundle: &RuntimeKeyBundle,
    database_id: [u8; 16],
    now_ms: u64,
) -> Result<Vec<RevocationTarget>, RuntimeStoreError> {
    let directory = super::pairing::load_directory(connection, key_bundle, database_id)?;
    directory
        .pairings
        .iter()
        .filter(|pairing| {
            pairing.record.expires_at_ms <= now_ms
                && matches!(
                    pairing.record.lifecycle,
                    super::pairing::PairingInviteLifecycle::GrantPreparing
                        | super::pairing::PairingInviteLifecycle::GrantCommitted
                )
        })
        .map(|pairing| {
            let grant_hash = pairing
                .record
                .grant_hash
                .ok_or(RuntimeStoreError::UnknownOrCorruptSchema)?;
            let authorization = directory
                .grants
                .authorizations
                .iter()
                .find(|authorization| authorization.grant_hash == grant_hash)
                .ok_or(RuntimeStoreError::UnknownOrCorruptSchema)?;
            Ok(RevocationTarget {
                pairing_id: Some(pairing.record.pairing_id),
                device: device_handle(authorization.device_route),
                grant: authorization.grant.clone(),
            })
        })
        .collect()
}

/// Root-present trust reset 的 authenticated drain 输入；历史与已在撤销中的授权不重复暴露。
pub(crate) fn list_revocation_drain_targets(
    connection: &Connection,
    key_bundle: &RuntimeKeyBundle,
    database_id: [u8; 16],
) -> Result<Vec<RevocationTarget>, RuntimeStoreError> {
    let directory = super::pairing::load_directory(connection, key_bundle, database_id)?;
    Ok(directory
        .grants
        .authorizations
        .iter()
        .filter(|authorization| {
            matches!(
                authorization.lifecycle,
                AuthorizationLifecycle::GrantPreparing | AuthorizationLifecycle::Active
            )
        })
        .map(|authorization| RevocationTarget {
            pairing_id: None,
            device: device_handle(authorization.device_route),
            grant: authorization.grant.clone(),
        })
        .collect())
}

pub(crate) fn begin_device_revocation(
    state: &mut RuntimeSqlite,
    config: &RuntimeStoreConfig,
    prepared: PreparedDeviceRevocation,
    now_ms: u64,
) -> Result<BeginDeviceRevocationOutcome, RuntimeStoreError> {
    let directory =
        super::pairing::load_directory(&state.connection, &state.key_bundle, state.database_id)?;
    if let Some(existing) = classify_existing(&directory, &prepared)? {
        return Ok(existing);
    }
    let active =
        super::pairing::active_machine(&state.connection, &state.key_bundle, state.database_id)?;
    let _ = validate_begin_target(&directory, &prepared, &active, now_ms)?;
    super::sqlite::admit_safety_write(
        &state.connection,
        &state.key_bundle,
        state.database_id,
        &state.storage_path,
        config.capacity_probe.as_ref(),
    )?;

    let transaction = state
        .connection
        .transaction_with_behavior(TransactionBehavior::Immediate)?;
    let directory =
        super::pairing::load_directory(&transaction, &state.key_bundle, state.database_id)?;
    if let Some(existing) = classify_existing(&directory, &prepared)? {
        return Ok(existing);
    }
    let active =
        super::pairing::active_machine(&transaction, &state.key_bundle, state.database_id)?;
    let bindings = validate_begin_target(&directory, &prepared, &active, now_ms)?;
    let authorization = bindings.authorization;
    let primary_key =
        authorization_primary_key(authorization.device_route, authorization.grant_serial);
    let sealed_authorization: Vec<u8> = transaction.query_row(
        "SELECT sealed_authorization FROM remote_authorization_ledger
         WHERE device_route = ?1 AND grant_serial = ?2",
        params![
            authorization.device_route.as_bytes().as_slice(),
            super::sequence::encode_sequence(authorization.grant_serial.value()),
        ],
        |row| row.get(0),
    )?;
    if u64::try_from(sealed_authorization.len()).unwrap_or(u64::MAX) != authorization.sealed_bytes {
        return Err(RuntimeStoreError::UnknownOrCorruptSchema);
    }
    let sealed_revocation = super::pairing_grant::seal_row(
        &state.key_bundle,
        state.database_id,
        AUTH_TABLE,
        &primary_key,
        AUTH_REVOCATION_COLUMN,
        &prepared.canonical_revoke_frame,
        MAX_REVOCATION_PLAINTEXT_BYTES,
    )?;
    let authorization_token = authorization_revocation_token(
        &state.key_bundle,
        state.database_id,
        authorization.device_route,
        authorization.grant_serial,
        AuthorizationLifecycle::Revoking,
        authorization.device_sign_fingerprint,
        authorization.grant_hash,
        authorization.authorization_hash,
        authorization.key_directory_revision,
        &sealed_authorization,
        prepared.revocation_hash,
        &sealed_revocation,
        authorization.created_at_ms,
        now_ms,
    )?;

    let outbox_id = super::pairing::allocate_id(&transaction, config, RuntimeIdKind::RemoteOutbox)?;
    let sealed_outbox = super::pairing_grant::seal_row(
        &state.key_bundle,
        state.database_id,
        OUTBOX_TABLE,
        outbox_id.as_bytes(),
        OUTBOX_COLUMN,
        &prepared.canonical_revoke_frame,
        MAX_REVOCATION_PLAINTEXT_BYTES,
    )?;
    let operation_key = revocation_operation_key(
        &state.key_bundle,
        authorization.device_route,
        authorization.grant_serial,
    )?;
    let outbox_token = revocation_outbox_token(
        &state.key_bundle,
        state.database_id,
        outbox_id,
        operation_key,
        authorization.device_route,
        authorization.grant_serial,
        prepared.frame_hash,
        &sealed_outbox,
        now_ms,
        now_ms,
    )?;
    let next = next_begin_ledger(
        &directory.ledger,
        authorization.lifecycle,
        sealed_revocation.len(),
        sealed_outbox.len(),
    )?;

    if transaction.execute(
        "UPDATE remote_authorization_ledger
         SET lifecycle = 'revoking', revocation_hash = ?1,
             sealed_revocation = ?2, sealed_revocation_bytes = ?3,
             state_changed_at_ms = ?4, metadata_token = ?5
         WHERE device_route = ?6 AND grant_serial = ?7
           AND lifecycle = ?8 AND metadata_token = ?9",
        params![
            &prepared.revocation_hash[..],
            &sealed_revocation,
            i64::try_from(sealed_revocation.len())
                .map_err(|_| RuntimeStoreError::PayloadTooLarge)?,
            i64::try_from(now_ms).map_err(|_| RuntimeStoreError::TimeOutOfRange)?,
            &authorization_token[..],
            authorization.device_route.as_bytes().as_slice(),
            super::sequence::encode_sequence(authorization.grant_serial.value()),
            authorization.lifecycle.as_str(),
            &authorization.metadata_token[..],
        ],
    )? != 1
    {
        return Err(RuntimeStoreError::PairingConflict);
    }
    if transaction.execute(
        "INSERT INTO remote_control_outbox (
             outbox_id, operation_kind, operation_key, lifecycle, database_id,
             pairing_id, device_route, grant_serial, frame_hash,
             sealed_frame, sealed_frame_bytes, terminal_hash, sealed_terminal,
             sealed_terminal_bytes, created_at_ms, state_changed_at_ms, metadata_token
         ) VALUES (?1, 'revokeDevice', ?2, 'prepared', ?3,
                   NULL, ?4, ?5, ?6, ?7, ?8, NULL, NULL, NULL, ?9, ?9, ?10)",
        params![
            outbox_id.as_bytes().as_slice(),
            &operation_key[..],
            &state.database_id[..],
            authorization.device_route.as_bytes().as_slice(),
            super::sequence::encode_sequence(authorization.grant_serial.value()),
            &prepared.frame_hash[..],
            &sealed_outbox,
            i64::try_from(sealed_outbox.len()).map_err(|_| RuntimeStoreError::PayloadTooLarge)?,
            i64::try_from(now_ms).map_err(|_| RuntimeStoreError::TimeOutOfRange)?,
            &outbox_token[..],
        ],
    )? != 1
    {
        return Err(RuntimeStoreError::PairingConflict);
    }
    if let Some(pairing) = bindings.pairing {
        let sealed_state: Vec<u8> = transaction.query_row(
            "SELECT sealed_state FROM remote_pairings WHERE pairing_id = ?1",
            [pairing.record.pairing_id.as_bytes().as_slice()],
            |row| row.get(0),
        )?;
        let pairing_token = super::pairing::pairing_row_token(
            &state.key_bundle,
            state.database_id,
            pairing.record.pairing_id,
            super::pairing::PairingInviteLifecycle::OrphanRevoking,
            pairing.record.relay_server_id,
            pairing.record.machine_route,
            pairing.record.pair_route,
            pairing.record.expires_at_ms,
            pairing.record.created_at_ms,
            now_ms,
            pairing.record.request_hash,
            pairing.record.device_sign_fingerprint,
            pairing.record.grant_hash,
            pairing.record.response_hash,
            &sealed_state,
        )?;
        if transaction.execute(
            "UPDATE remote_pairings
             SET lifecycle = 'orphanRevoking', state_changed_at_ms = ?1,
                 metadata_token = ?2
             WHERE pairing_id = ?3 AND lifecycle = ?4 AND metadata_token = ?5",
            params![
                i64::try_from(now_ms).map_err(|_| RuntimeStoreError::TimeOutOfRange)?,
                &pairing_token[..],
                pairing.record.pairing_id.as_bytes().as_slice(),
                match pairing.record.lifecycle {
                    super::pairing::PairingInviteLifecycle::GrantPreparing => "grantPreparing",
                    super::pairing::PairingInviteLifecycle::GrantCommitted => "grantCommitted",
                    _ => return Err(RuntimeStoreError::PairingConflict),
                },
                &pairing.metadata_token[..],
            ],
        )? != 1
        {
            return Err(RuntimeStoreError::PairingConflict);
        }
    }
    let _ = super::sqlite::update_runtime_ledger(
        &transaction,
        &state.key_bundle,
        state.database_id,
        &directory.ledger,
        &next,
    )?;
    config
        .fault_injector
        .before_operation(RuntimeStoreOperation::BeginDeviceRevocationBeforeCommit)?;
    super::sqlite::commit_transaction(transaction, RuntimeCommitOperation::BeginDeviceRevocation)?;
    super::sqlite::latch_post_commit_capacity(state, config);
    config
        .fault_injector
        .before_operation(RuntimeStoreOperation::BeginDeviceRevocationAfterCommit)
        .map_err(|_| RuntimeStoreError::CommitOutcomeUnknown {
            operation: RuntimeCommitOperation::BeginDeviceRevocation,
        })?;
    let directory =
        super::pairing::load_directory(&state.connection, &state.key_bundle, state.database_id)?;
    let authorization = directory
        .grants
        .authorizations
        .iter()
        .find(|authorization| {
            authorization.device_route == prepared.revocation.device_route
                && authorization.grant_serial == prepared.revocation.grant_serial
        })
        .ok_or(RuntimeStoreError::UnknownOrCorruptSchema)?;
    Ok(BeginDeviceRevocationOutcome::Prepared {
        recovery: recovery(&directory, authorization)?,
    })
}

fn ensure_recovery_budget(retained: usize) -> Result<(), RuntimeStoreError> {
    if retained > MAX_REVOCATION_RECOVERY_RETAINED_BYTES {
        return Err(RuntimeStoreError::RecoveryPageTooLarge {
            projected_bytes: u64::try_from(retained).unwrap_or(u64::MAX),
            limit_bytes: MAX_REVOCATION_RECOVERY_RETAINED_BYTES as u64,
        });
    }
    Ok(())
}

pub(crate) fn prepare_begin_for_dispatch(
    input: BeginDeviceRevocation,
) -> Result<PreparedDeviceRevocation, RuntimeStoreError> {
    prepare_begin(input)
}

#[cfg(test)]
mod budget_tests {
    use super::*;

    #[test]
    fn revocation_recovery_budget_accepts_exact_limit_and_rejects_plus_one() {
        ensure_recovery_budget(MAX_REVOCATION_RECOVERY_RETAINED_BYTES)
            .expect("exact revocation recovery limit is legal");
        let projected = MAX_REVOCATION_RECOVERY_RETAINED_BYTES + 1;
        assert!(matches!(
            ensure_recovery_budget(projected),
            Err(RuntimeStoreError::RecoveryPageTooLarge {
                projected_bytes,
                limit_bytes,
            }) if projected_bytes == projected as u64
                && limit_bytes == MAX_REVOCATION_RECOVERY_RETAINED_BYTES as u64
        ));
    }
}
