//! Orphan InstallGrant 与 DeviceRevocation 的 Relay commit ACK 状态机。

use agentdeck_crypto::sha256;
use agentdeck_protocol::relay_v2::frame::{OpaqueRouteFrame, RelayFrameBody, RevocationCommitted};
use agentdeck_protocol::relay_v2::{
    DeviceRevocation, DeviceRouteId, GrantSerial, RELAY_PROTOCOL_VERSION, decode, encode,
};
use rusqlite::{TransactionBehavior, params};

use crate::runtime::model::{
    RuntimeCommitOperation, RuntimeStoreConfig, RuntimeStoreError, RuntimeStoreOperation,
};

use super::identity::{RuntimeId, RuntimeIdKind};
use super::pairing_authorization::{
    AuthenticatedAuthorization, AuthorizationLifecycle, authorization_revocation_token,
};
use super::pairing_revocation::{DeviceRevocationRecovery, recovery};
use super::sqlite::RuntimeSqlite;

pub(crate) struct PreparedOrphanGrantCommitted {
    pairing_id: RuntimeId,
    device_route: DeviceRouteId,
    grant_serial: GrantSerial,
    grant_hash: [u8; 32],
}

impl PreparedOrphanGrantCommitted {
    pub(crate) const fn retained_bytes(&self) -> usize {
        0
    }
}

#[derive(Debug)]
pub(crate) enum AcknowledgeOrphanGrantCommittedOutcome {
    Advanced { recovery: DeviceRevocationRecovery },
    Replayed { recovery: DeviceRevocationRecovery },
}

pub(crate) struct AcknowledgeRevocationCommitted {
    canonical_terminal: Vec<u8>,
}

impl AcknowledgeRevocationCommitted {
    #[must_use]
    pub(crate) const fn new(canonical_terminal: Vec<u8>) -> Self {
        Self { canonical_terminal }
    }
}

impl std::fmt::Debug for AcknowledgeRevocationCommitted {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter.write_str("AcknowledgeRevocationCommitted([REDACTED])")
    }
}

pub(crate) struct PreparedRevocationCommitted {
    pub(super) device_route: DeviceRouteId,
    pub(super) grant_serial: GrantSerial,
    pub(super) revocation: DeviceRevocation,
    pub(super) revocation_hash: [u8; 32],
}

impl PreparedRevocationCommitted {
    pub(crate) const fn retained_bytes(&self) -> usize {
        0
    }
}

#[derive(Debug)]
pub(crate) enum AcknowledgeRevocationCommittedOutcome {
    Committed { revocation: DeviceRevocation },
    Replayed { revocation: DeviceRevocation },
}

pub(crate) fn prepare_revocation_committed(
    input: AcknowledgeRevocationCommitted,
) -> Result<PreparedRevocationCommitted, RuntimeStoreError> {
    if input.canonical_terminal.is_empty()
        || input.canonical_terminal.len()
            > super::pairing_revocation::MAX_REVOCATION_PLAINTEXT_BYTES
    {
        return Err(RuntimeStoreError::PayloadTooLarge);
    }
    let frame: OpaqueRouteFrame =
        decode(&input.canonical_terminal).map_err(|_| RuntimeStoreError::PairingConflict)?;
    if frame.version != RELAY_PROTOCOL_VERSION || encode(&frame) != input.canonical_terminal {
        return Err(RuntimeStoreError::PairingConflict);
    }
    let RelayFrameBody::RevocationCommitted(RevocationCommitted {
        device_route,
        grant_serial,
        signed_revocation,
    }) = frame.body
    else {
        return Err(RuntimeStoreError::PairingConflict);
    };
    let revocation_hash = signed_revocation.canonical_sha256();
    if device_route != signed_revocation.device_route
        || grant_serial != signed_revocation.grant_serial
        || device_route.as_bytes() == &[0; 16]
        || grant_serial.value() == 0
        || signed_revocation.signature.0 == [0; 64]
        || revocation_hash == [0; 32]
    {
        return Err(RuntimeStoreError::PairingConflict);
    }
    Ok(PreparedRevocationCommitted {
        device_route,
        grant_serial,
        revocation: signed_revocation,
        revocation_hash,
    })
}

pub(crate) fn prepare_orphan_grant_committed(
    pairing_id: RuntimeId,
    canonical_terminal: Vec<u8>,
) -> Result<PreparedOrphanGrantCommitted, RuntimeStoreError> {
    if pairing_id.kind() != RuntimeIdKind::Pairing {
        return Err(RuntimeStoreError::IdKindMismatch {
            expected: RuntimeIdKind::Pairing,
            actual: pairing_id.kind(),
        });
    }
    if canonical_terminal.is_empty()
        || canonical_terminal.len() > super::pairing::MAX_CONTROL_FRAME_PLAINTEXT_BYTES
    {
        return Err(RuntimeStoreError::PayloadTooLarge);
    }
    let frame: OpaqueRouteFrame =
        decode(&canonical_terminal).map_err(|_| RuntimeStoreError::PairingConflict)?;
    if frame.version != RELAY_PROTOCOL_VERSION || encode(&frame) != canonical_terminal {
        return Err(RuntimeStoreError::PairingConflict);
    }
    let RelayFrameBody::GrantCommitted(committed) = frame.body else {
        return Err(RuntimeStoreError::PairingConflict);
    };
    if committed.device_route.as_bytes() == &[0; 16]
        || committed.grant_serial.value() == 0
        || committed.grant_hash == [0; 32]
    {
        return Err(RuntimeStoreError::PairingConflict);
    }
    Ok(PreparedOrphanGrantCommitted {
        pairing_id,
        device_route: committed.device_route,
        grant_serial: committed.grant_serial,
        grant_hash: committed.grant_hash,
    })
}

fn orphan_ack_bindings<'a>(
    directory: &'a super::pairing::PairingDirectory,
    prepared: &PreparedOrphanGrantCommitted,
) -> Result<
    (
        &'a AuthenticatedAuthorization,
        Option<&'a super::pairing_grant::AuthenticatedInstallOutbox>,
    ),
    RuntimeStoreError,
> {
    let pairing = directory
        .pairings
        .iter()
        .find(|pairing| pairing.record.pairing_id == prepared.pairing_id)
        .ok_or(RuntimeStoreError::PairingConflict)?;
    if pairing.record.lifecycle != super::pairing::PairingInviteLifecycle::OrphanRevoking
        || pairing.record.grant_hash != Some(prepared.grant_hash)
    {
        return Err(RuntimeStoreError::PairingConflict);
    }
    let authorization = directory
        .grants
        .authorizations
        .iter()
        .find(|authorization| {
            authorization.device_route == prepared.device_route
                && authorization.grant_serial == prepared.grant_serial
        })
        .ok_or(RuntimeStoreError::PairingConflict)?;
    if authorization.lifecycle != AuthorizationLifecycle::Revoking
        || authorization.grant_hash != prepared.grant_hash
    {
        return Err(RuntimeStoreError::PairingConflict);
    }
    let install = directory.grants.installs.iter().find(|install| {
        install.device_route == prepared.device_route
            && install.grant_serial == prepared.grant_serial
    });
    Ok((authorization, install))
}

pub(crate) fn acknowledge_orphan_grant_committed(
    state: &mut RuntimeSqlite,
    config: &RuntimeStoreConfig,
    prepared: PreparedOrphanGrantCommitted,
) -> Result<AcknowledgeOrphanGrantCommittedOutcome, RuntimeStoreError> {
    let directory =
        super::pairing::load_directory(&state.connection, &state.key_bundle, state.database_id)?;
    let (authorization, install) = orphan_ack_bindings(&directory, &prepared)?;
    if install.is_none() {
        return Ok(AcknowledgeOrphanGrantCommittedOutcome::Replayed {
            recovery: recovery(&directory, authorization)?,
        });
    }
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
    let (authorization, install) = orphan_ack_bindings(&directory, &prepared)?;
    let Some(install) = install else {
        return Ok(AcknowledgeOrphanGrantCommittedOutcome::Replayed {
            recovery: recovery(&directory, authorization)?,
        });
    };
    if transaction.execute(
        "DELETE FROM remote_control_outbox
         WHERE outbox_id = ?1 AND operation_kind = 'installGrant'
           AND operation_key = ?2 AND lifecycle = 'prepared'
           AND device_route = ?3 AND grant_serial = ?4
           AND frame_hash = ?5 AND metadata_token = ?6",
        params![
            install.outbox_id.as_bytes().as_slice(),
            &install.operation_key[..],
            install.device_route.as_bytes().as_slice(),
            super::sequence::encode_sequence(install.grant_serial.value()),
            &install.frame_hash[..],
            &install.metadata_token[..],
        ],
    )? != 1
    {
        return Err(RuntimeStoreError::PairingConflict);
    }
    let mut next = directory.ledger.clone();
    next.remote_control_outbox_count = next
        .remote_control_outbox_count
        .checked_sub(1)
        .ok_or(RuntimeStoreError::UnknownOrCorruptSchema)?;
    next.remote_control_outbox_pending_count = next
        .remote_control_outbox_pending_count
        .checked_sub(1)
        .ok_or(RuntimeStoreError::UnknownOrCorruptSchema)?;
    next.remote_control_outbox_sealed_bytes = next
        .remote_control_outbox_sealed_bytes
        .checked_sub(install.sealed_bytes)
        .ok_or(RuntimeStoreError::UnknownOrCorruptSchema)?;
    let _ = super::sqlite::update_runtime_ledger(
        &transaction,
        &state.key_bundle,
        state.database_id,
        &directory.ledger,
        &next,
    )?;
    config
        .fault_injector
        .before_operation(RuntimeStoreOperation::AcknowledgeOrphanGrantCommittedBeforeCommit)?;
    super::sqlite::commit_transaction(
        transaction,
        RuntimeCommitOperation::AcknowledgeOrphanGrantCommitted,
    )?;
    super::sqlite::latch_post_commit_capacity(state, config);
    config
        .fault_injector
        .before_operation(RuntimeStoreOperation::AcknowledgeOrphanGrantCommittedAfterCommit)
        .map_err(|_| RuntimeStoreError::CommitOutcomeUnknown {
            operation: RuntimeCommitOperation::AcknowledgeOrphanGrantCommitted,
        })?;
    let directory =
        super::pairing::load_directory(&state.connection, &state.key_bundle, state.database_id)?;
    let (authorization, install) = orphan_ack_bindings(&directory, &prepared)?;
    if install.is_some() {
        return Err(RuntimeStoreError::UnknownOrCorruptSchema);
    }
    Ok(AcknowledgeOrphanGrantCommittedOutcome::Advanced {
        recovery: recovery(&directory, authorization)?,
    })
}

fn revocation_ack_authorization<'a>(
    directory: &'a super::pairing::PairingDirectory,
    prepared: &PreparedRevocationCommitted,
) -> Result<&'a AuthenticatedAuthorization, RuntimeStoreError> {
    let authorization = directory
        .grants
        .authorizations
        .iter()
        .find(|authorization| {
            authorization.device_route == prepared.device_route
                && authorization.grant_serial == prepared.grant_serial
        })
        .ok_or(RuntimeStoreError::PairingConflict)?;
    if !matches!(
        authorization.lifecycle,
        AuthorizationLifecycle::Revoking | AuthorizationLifecycle::Revoked
    ) || authorization.revocation.as_ref() != Some(&prepared.revocation)
        || authorization.revocation_hash != Some(prepared.revocation_hash)
    {
        return Err(RuntimeStoreError::PairingConflict);
    }
    Ok(authorization)
}

fn replayed_revocation_ack(
    directory: &super::pairing::PairingDirectory,
    prepared: &PreparedRevocationCommitted,
) -> Result<Option<AcknowledgeRevocationCommittedOutcome>, RuntimeStoreError> {
    let authorization = revocation_ack_authorization(directory, prepared)?;
    if authorization.lifecycle != AuthorizationLifecycle::Revoked {
        return Ok(None);
    }
    if directory.grants.revocations.iter().any(|outbox| {
        outbox.device_route == prepared.device_route && outbox.grant_serial == prepared.grant_serial
    }) || directory.grants.installs.iter().any(|install| {
        install.device_route == prepared.device_route
            && install.grant_serial == prepared.grant_serial
    }) {
        return Err(RuntimeStoreError::UnknownOrCorruptSchema);
    }
    Ok(Some(AcknowledgeRevocationCommittedOutcome::Replayed {
        revocation: prepared.revocation.clone(),
    }))
}

pub(crate) fn acknowledge_revocation_committed(
    state: &mut RuntimeSqlite,
    config: &RuntimeStoreConfig,
    prepared: PreparedRevocationCommitted,
    now_ms: u64,
) -> Result<AcknowledgeRevocationCommittedOutcome, RuntimeStoreError> {
    let directory =
        super::pairing::load_directory(&state.connection, &state.key_bundle, state.database_id)?;
    if let Some(replayed) = replayed_revocation_ack(&directory, &prepared)? {
        return Ok(replayed);
    }
    let authorization = revocation_ack_authorization(&directory, &prepared)?;
    if authorization.lifecycle != AuthorizationLifecycle::Revoking
        || directory.grants.installs.iter().any(|install| {
            install.device_route == prepared.device_route
                && install.grant_serial == prepared.grant_serial
        })
    {
        return Err(RuntimeStoreError::PairingConflict);
    }
    let _revoke = directory
        .grants
        .revocations
        .iter()
        .find(|outbox| {
            outbox.device_route == prepared.device_route
                && outbox.grant_serial == prepared.grant_serial
        })
        .ok_or(RuntimeStoreError::UnknownOrCorruptSchema)?;
    if now_ms < authorization.state_changed_at_ms {
        return Err(RuntimeStoreError::ClockRegressed {
            persisted_ms: authorization.state_changed_at_ms,
            observed_ms: now_ms,
        });
    }
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
    if let Some(replayed) = replayed_revocation_ack(&directory, &prepared)? {
        return Ok(replayed);
    }
    let authorization = revocation_ack_authorization(&directory, &prepared)?;
    if authorization.lifecycle != AuthorizationLifecycle::Revoking
        || directory.grants.installs.iter().any(|install| {
            install.device_route == prepared.device_route
                && install.grant_serial == prepared.grant_serial
        })
    {
        return Err(RuntimeStoreError::PairingConflict);
    }
    let revoke = directory
        .grants
        .revocations
        .iter()
        .find(|outbox| {
            outbox.device_route == prepared.device_route
                && outbox.grant_serial == prepared.grant_serial
        })
        .ok_or(RuntimeStoreError::UnknownOrCorruptSchema)?;
    if now_ms < authorization.state_changed_at_ms {
        return Err(RuntimeStoreError::ClockRegressed {
            persisted_ms: authorization.state_changed_at_ms,
            observed_ms: now_ms,
        });
    }
    let sealed_authorization: Vec<u8> = transaction.query_row(
        "SELECT sealed_authorization FROM remote_authorization_ledger
         WHERE device_route = ?1 AND grant_serial = ?2",
        params![
            authorization.device_route.as_bytes().as_slice(),
            super::sequence::encode_sequence(authorization.grant_serial.value()),
        ],
        |row| row.get(0),
    )?;
    let sealed_revocation: Vec<u8> = transaction.query_row(
        "SELECT sealed_revocation FROM remote_authorization_ledger
         WHERE device_route = ?1 AND grant_serial = ?2",
        params![
            authorization.device_route.as_bytes().as_slice(),
            super::sequence::encode_sequence(authorization.grant_serial.value()),
        ],
        |row| row.get(0),
    )?;
    let authorization_token = authorization_revocation_token(
        &state.key_bundle,
        state.database_id,
        authorization.device_route,
        authorization.grant_serial,
        AuthorizationLifecycle::Revoked,
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
    if transaction.execute(
        "UPDATE remote_authorization_ledger
         SET lifecycle = 'revoked', state_changed_at_ms = ?1, metadata_token = ?2
         WHERE device_route = ?3 AND grant_serial = ?4
           AND lifecycle = 'revoking' AND revocation_hash = ?5
           AND metadata_token = ?6",
        params![
            i64::try_from(now_ms).map_err(|_| RuntimeStoreError::TimeOutOfRange)?,
            &authorization_token[..],
            authorization.device_route.as_bytes().as_slice(),
            super::sequence::encode_sequence(authorization.grant_serial.value()),
            &prepared.revocation_hash[..],
            &authorization.metadata_token[..],
        ],
    )? != 1
    {
        return Err(RuntimeStoreError::PairingConflict);
    }
    if transaction.execute(
        "DELETE FROM remote_control_outbox
         WHERE outbox_id = ?1 AND operation_kind = 'revokeDevice'
           AND operation_key = ?2 AND lifecycle = 'prepared'
           AND device_route = ?3 AND grant_serial = ?4
           AND frame_hash = ?5 AND metadata_token = ?6",
        params![
            revoke.outbox_id.as_bytes().as_slice(),
            &revoke.operation_key[..],
            revoke.device_route.as_bytes().as_slice(),
            super::sequence::encode_sequence(revoke.grant_serial.value()),
            &revoke.frame_hash[..],
            &revoke.metadata_token[..],
        ],
    )? != 1
    {
        return Err(RuntimeStoreError::PairingConflict);
    }

    let orphan = directory.pairings.iter().find(|pairing| {
        pairing.record.lifecycle == super::pairing::PairingInviteLifecycle::OrphanRevoking
            && pairing.record.grant_hash == Some(authorization.grant_hash)
    });
    let close_write = if let Some(pairing) = orphan {
        let canonical_close = super::pairing_terminal::frozen_close_frame(pairing);
        let frame_hash = sha256(&canonical_close);
        let outbox_id =
            super::pairing::allocate_id(&transaction, config, RuntimeIdKind::RemoteOutbox)?;
        let sealed_close = super::pairing_terminal::seal_close_frame(
            &state.key_bundle,
            state.database_id,
            outbox_id,
            &canonical_close,
        )?;
        let operation_key = super::pairing_terminal::close_operation_key(
            &state.key_bundle,
            pairing.record.pairing_id,
        )?;
        let metadata_token = super::pairing_terminal::close_outbox_token(
            &state.key_bundle,
            state.database_id,
            outbox_id,
            operation_key,
            pairing.record.pairing_id,
            frame_hash,
            &sealed_close,
            now_ms,
            now_ms,
        )?;
        if transaction.execute(
            "INSERT INTO remote_control_outbox (
                 outbox_id, operation_kind, operation_key, lifecycle, database_id,
                 pairing_id, device_route, grant_serial, frame_hash,
                 sealed_frame, sealed_frame_bytes, terminal_hash, sealed_terminal,
                 sealed_terminal_bytes, created_at_ms, state_changed_at_ms, metadata_token
             ) VALUES (?1, 'closePairRoute', ?2, 'prepared', ?3,
                       ?4, NULL, NULL, ?5, ?6, ?7, NULL, NULL, NULL, ?8, ?8, ?9)",
            params![
                outbox_id.as_bytes().as_slice(),
                &operation_key[..],
                &state.database_id[..],
                pairing.record.pairing_id.as_bytes().as_slice(),
                &frame_hash[..],
                &sealed_close,
                i64::try_from(sealed_close.len())
                    .map_err(|_| RuntimeStoreError::PayloadTooLarge)?,
                i64::try_from(now_ms).map_err(|_| RuntimeStoreError::TimeOutOfRange)?,
                &metadata_token[..],
            ],
        )? != 1
        {
            return Err(RuntimeStoreError::PairingConflict);
        }
        let terminal_lifecycle =
            if pairing.record.state_changed_at_ms >= pairing.record.expires_at_ms {
                super::pairing::PairingInviteLifecycle::Expired
            } else {
                super::pairing::PairingInviteLifecycle::Canceled
            };
        let sealed_state: Vec<u8> = transaction.query_row(
            "SELECT sealed_state FROM remote_pairings WHERE pairing_id = ?1",
            [pairing.record.pairing_id.as_bytes().as_slice()],
            |row| row.get(0),
        )?;
        let pairing_token = super::pairing::pairing_row_token(
            &state.key_bundle,
            state.database_id,
            pairing.record.pairing_id,
            terminal_lifecycle,
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
             SET lifecycle = ?1, state_changed_at_ms = ?2, metadata_token = ?3
             WHERE pairing_id = ?4 AND lifecycle = 'orphanRevoking'
               AND metadata_token = ?5",
            params![
                match terminal_lifecycle {
                    super::pairing::PairingInviteLifecycle::Expired => "expired",
                    super::pairing::PairingInviteLifecycle::Canceled => "canceled",
                    _ => return Err(RuntimeStoreError::UnknownOrCorruptSchema),
                },
                i64::try_from(now_ms).map_err(|_| RuntimeStoreError::TimeOutOfRange)?,
                &pairing_token[..],
                pairing.record.pairing_id.as_bytes().as_slice(),
                &pairing.metadata_token[..],
            ],
        )? != 1
        {
            return Err(RuntimeStoreError::PairingConflict);
        }
        Some(sealed_close.len())
    } else {
        None
    };

    let mut next = directory.ledger.clone();
    next.remote_authorization_revoking_count = next
        .remote_authorization_revoking_count
        .checked_sub(1)
        .ok_or(RuntimeStoreError::UnknownOrCorruptSchema)?;
    next.remote_authorization_revoked_count = next
        .remote_authorization_revoked_count
        .checked_add(1)
        .ok_or(RuntimeStoreError::CapacityArithmeticOverflow {
            field: "remote_authorization_revoked_count",
        })?;
    next.remote_control_outbox_count = next
        .remote_control_outbox_count
        .checked_sub(1)
        .ok_or(RuntimeStoreError::UnknownOrCorruptSchema)?;
    next.remote_control_outbox_pending_count = next
        .remote_control_outbox_pending_count
        .checked_sub(1)
        .ok_or(RuntimeStoreError::UnknownOrCorruptSchema)?;
    next.remote_control_outbox_sealed_bytes = next
        .remote_control_outbox_sealed_bytes
        .checked_sub(revoke.sealed_bytes)
        .ok_or(RuntimeStoreError::UnknownOrCorruptSchema)?;
    if let Some(close_bytes) = close_write {
        let close_bytes =
            u64::try_from(close_bytes).map_err(|_| RuntimeStoreError::PayloadTooLarge)?;
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
            .checked_add(close_bytes)
            .ok_or(RuntimeStoreError::CapacityArithmeticOverflow {
                field: "remote_control_outbox_sealed_bytes",
            })?;
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
        .before_operation(RuntimeStoreOperation::AcknowledgeRevocationCommittedBeforeCommit)?;
    super::sqlite::commit_transaction(
        transaction,
        RuntimeCommitOperation::AcknowledgeRevocationCommitted,
    )?;
    super::sqlite::latch_post_commit_capacity(state, config);
    config
        .fault_injector
        .before_operation(RuntimeStoreOperation::AcknowledgeRevocationCommittedAfterCommit)
        .map_err(|_| RuntimeStoreError::CommitOutcomeUnknown {
            operation: RuntimeCommitOperation::AcknowledgeRevocationCommitted,
        })?;
    let directory =
        super::pairing::load_directory(&state.connection, &state.key_bundle, state.database_id)?;
    let authorization = revocation_ack_authorization(&directory, &prepared)?;
    if authorization.lifecycle != AuthorizationLifecycle::Revoked
        || directory.grants.revocations.iter().any(|outbox| {
            outbox.device_route == prepared.device_route
                && outbox.grant_serial == prepared.grant_serial
        })
    {
        return Err(RuntimeStoreError::UnknownOrCorruptSchema);
    }
    Ok(AcknowledgeRevocationCommittedOutcome::Committed {
        revocation: prepared.revocation,
    })
}
