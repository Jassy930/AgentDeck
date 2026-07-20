//! G1 confirm CAS transaction、exact replay 与 grantPreparing recovery projection。

use agentdeck_crypto::sha256;
use agentdeck_protocol::relay_v2::{DeviceRouteId, GrantSerial};
use agentdeck_protocol::runtime::{PairingReceipt, PairingState};
use rusqlite::{Connection, TransactionBehavior, params};

use crate::runtime::model::{
    RuntimeCommitOperation, RuntimeStoreConfig, RuntimeStoreError, RuntimeStoreOperation,
};
use crate::security::SecretBytes;

use super::cipher::RuntimeKeyBundle;
use super::identity::{RuntimeId, RuntimeIdKind};
use super::pairing::{AuthenticatedPairingRow, PairingInviteLifecycle};
use super::pairing_authorization::{
    AuthorizationLifecycle, MAX_AUTHORIZATION_PLAINTEXT_BYTES, authorization_token,
    encode_authorization_payload,
};
use super::pairing_grant::{
    AuthenticatedGlobalKeyState, ConfirmPairingGrant, GlobalKeyStateV1,
    PreparedConfirmPairingGrant, global_key_token, install_operation_key, install_outbox_token,
    load_global_key_state, prepare_confirm, seal_row, validate_prepared,
};
use super::sqlite::{RuntimeLedger, RuntimeSqlite};

const PAIRING_TABLE: &[u8] = b"remote_pairings";
const PAIRING_COLUMN: &[u8] = b"sealed_state";
const AUTH_TABLE: &[u8] = b"remote_authorization_ledger";
const AUTH_COLUMN: &[u8] = b"sealed_authorization";
const GLOBAL_KEY_TABLE: &[u8] = b"remote_key_directory";
const GLOBAL_KEY_COLUMN: &[u8] = b"sealed_directory";
const OUTBOX_TABLE: &[u8] = b"remote_control_outbox";
const OUTBOX_COLUMN: &[u8] = b"sealed_frame";
const MAX_GLOBAL_KEY_STATE_BYTES: usize = 64 * 1024 * 1024;
const MAX_AUTHORIZATIONS: u64 = 256;
const MAX_AUTHORIZATION_SEALED_BYTES: u64 = 64 * 1024 * 1024;

#[derive(Debug)]
pub(crate) struct GrantPreparingRecovery {
    pairing_id: RuntimeId,
    request_hash: [u8; 32],
    device_route: DeviceRouteId,
    grant_serial: GrantSerial,
    grant_hash: [u8; 32],
    response_hash: [u8; 32],
    canonical_install_frame: Vec<u8>,
    canonical_response: SecretBytes,
    receipt: PairingReceipt,
}

impl GrantPreparingRecovery {
    #[must_use]
    pub(crate) const fn pairing_id(&self) -> RuntimeId {
        self.pairing_id
    }

    #[must_use]
    pub(crate) const fn request_hash(&self) -> [u8; 32] {
        self.request_hash
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
    pub(crate) const fn grant_hash(&self) -> [u8; 32] {
        self.grant_hash
    }

    #[must_use]
    pub(crate) const fn response_hash(&self) -> [u8; 32] {
        self.response_hash
    }

    #[must_use]
    pub(crate) fn canonical_install_frame(&self) -> &[u8] {
        &self.canonical_install_frame
    }

    #[must_use]
    pub(crate) fn canonical_response(&self) -> &[u8] {
        self.canonical_response.expose_secret()
    }

    #[must_use]
    pub(crate) const fn receipt(&self) -> &PairingReceipt {
        &self.receipt
    }
}

#[derive(Debug)]
pub(crate) enum ConfirmPairingGrantOutcome {
    Confirmed {
        receipt: PairingReceipt,
        recovery: GrantPreparingRecovery,
    },
    Replayed {
        receipt: PairingReceipt,
        recovery: GrantPreparingRecovery,
    },
    AlreadyHandled {
        receipt: PairingReceipt,
        state: PairingState,
    },
}

fn state(lifecycle: PairingInviteLifecycle) -> PairingState {
    match lifecycle {
        PairingInviteLifecycle::RouteOpening => PairingState::RouteOpening,
        PairingInviteLifecycle::Unused => PairingState::Unused,
        PairingInviteLifecycle::Preparing => PairingState::Preparing,
        PairingInviteLifecycle::AwaitingLocalConfirmation => {
            PairingState::AwaitingLocalConfirmation
        }
        PairingInviteLifecycle::GrantPreparing => PairingState::GrantPreparing,
        PairingInviteLifecycle::GrantCommitted => PairingState::GrantCommitted,
        PairingInviteLifecycle::Delivered => PairingState::Delivered,
        PairingInviteLifecycle::OrphanRevoking => PairingState::OrphanRevoking,
        PairingInviteLifecycle::Canceled => PairingState::Canceled,
        PairingInviteLifecycle::Expired => PairingState::Expired,
    }
}

fn recovery(
    directory: &super::pairing::PairingDirectory,
    pairing: &AuthenticatedPairingRow,
) -> Result<GrantPreparingRecovery, RuntimeStoreError> {
    let grant_hash = pairing
        .record
        .grant_hash
        .ok_or(RuntimeStoreError::UnknownOrCorruptSchema)?;
    let install = directory
        .grants
        .installs
        .iter()
        .find(|install| install.grant.canonical_sha256() == grant_hash)
        .ok_or(RuntimeStoreError::UnknownOrCorruptSchema)?;
    let receipt = directory
        .terminal
        .receipt_value(pairing.record.pairing_id)
        .ok_or(RuntimeStoreError::UnknownOrCorruptSchema)?
        .clone();
    Ok(GrantPreparingRecovery {
        pairing_id: pairing.record.pairing_id,
        request_hash: pairing
            .record
            .request_hash
            .ok_or(RuntimeStoreError::UnknownOrCorruptSchema)?,
        device_route: install.grant.device_route,
        grant_serial: install.grant.grant_serial,
        grant_hash,
        response_hash: pairing
            .record
            .response_hash
            .ok_or(RuntimeStoreError::UnknownOrCorruptSchema)?,
        canonical_install_frame: install.canonical_frame.clone(),
        canonical_response: SecretBytes::new(
            pairing
                .record
                .canonical_pair_response
                .as_ref()
                .ok_or(RuntimeStoreError::UnknownOrCorruptSchema)?
                .expose_secret()
                .to_vec(),
        ),
        receipt,
    })
}

fn classify_existing(
    directory: &super::pairing::PairingDirectory,
    prepared: &PreparedConfirmPairingGrant,
) -> Result<Option<ConfirmPairingGrantOutcome>, RuntimeStoreError> {
    let Some(receipt) = directory
        .terminal
        .receipt_value(prepared.pairing_id)
        .cloned()
    else {
        return Ok(None);
    };
    let lifecycle = directory
        .pairings
        .iter()
        .find(|pairing| pairing.record.pairing_id == prepared.pairing_id)
        .map_or(PairingState::ClosedTombstone, |pairing| {
            state(pairing.record.lifecycle)
        });
    match receipt {
        PairingReceipt::Confirmed { .. } => {
            let pairing = directory
                .pairings
                .iter()
                .find(|pairing| pairing.record.pairing_id == prepared.pairing_id)
                .ok_or(RuntimeStoreError::UnknownOrCorruptSchema)?;
            if pairing.record.request_hash != Some(prepared.request_hash)
                || pairing.record.grant_hash != Some(prepared.grant_hash)
                || pairing.record.response_hash != Some(prepared.response_hash)
                || pairing.record.canonical_relay_grant.as_deref()
                    != Some(prepared.canonical_relay_grant.as_slice())
                || pairing
                    .record
                    .canonical_device_authorization
                    .as_ref()
                    .map(SecretBytes::expose_secret)
                    != Some(prepared.canonical_authorization.expose_secret())
                || pairing
                    .record
                    .canonical_key_directory_view
                    .as_ref()
                    .map(SecretBytes::expose_secret)
                    != Some(prepared.canonical_key_directory.expose_secret())
                || pairing
                    .record
                    .canonical_pair_response
                    .as_ref()
                    .map(SecretBytes::expose_secret)
                    != Some(prepared.canonical_response.expose_secret())
                || pairing.record.canonical_install_frame.as_deref()
                    != Some(prepared.canonical_install_frame.as_slice())
                || pairing.record.global_key_state_hash != Some(prepared.global_key_state_hash)
            {
                return Err(RuntimeStoreError::PairingConflict);
            }
            match pairing.record.lifecycle {
                PairingInviteLifecycle::GrantPreparing => {
                    Ok(Some(ConfirmPairingGrantOutcome::Replayed {
                        receipt: receipt.clone(),
                        recovery: recovery(directory, pairing)?,
                    }))
                }
                PairingInviteLifecycle::GrantCommitted => {
                    Ok(Some(ConfirmPairingGrantOutcome::AlreadyHandled {
                        receipt,
                        state: PairingState::GrantCommitted,
                    }))
                }
                _ => Err(RuntimeStoreError::UnknownOrCorruptSchema),
            }
        }
        PairingReceipt::Canceled { .. } | PairingReceipt::Expired { .. } => {
            Ok(Some(ConfirmPairingGrantOutcome::AlreadyHandled {
                receipt,
                state: lifecycle,
            }))
        }
        PairingReceipt::Replayed { .. }
        | PairingReceipt::AlreadyHandled { .. }
        | PairingReceipt::Failed { .. } => Err(RuntimeStoreError::UnknownOrCorruptSchema),
    }
}

fn authorization_primary_key(device_route: DeviceRouteId, serial: GrantSerial) -> [u8; 24] {
    let mut value = [0_u8; 24];
    value[..16].copy_from_slice(device_route.as_bytes());
    value[16..].copy_from_slice(&serial.value().to_be_bytes());
    value
}

fn supersede_previous_authorization(
    transaction: &rusqlite::Transaction<'_>,
    key_bundle: &RuntimeKeyBundle,
    database_id: [u8; 16],
    grants: &super::pairing_grant::AuthenticatedGrantDirectory,
    allocation: super::pairing_grant_allocation::ValidatedGrantAllocation,
    now_ms: u64,
) -> Result<(), RuntimeStoreError> {
    let super::pairing_grant_allocation::ValidatedGrantAllocation::Renew {
        device_route,
        previous_serial,
        ..
    } = allocation
    else {
        return Ok(());
    };
    let previous = grants
        .authorizations
        .iter()
        .find(|authorization| {
            authorization.device_route == device_route
                && authorization.grant_serial == previous_serial
                && authorization.lifecycle == AuthorizationLifecycle::Active
        })
        .ok_or(RuntimeStoreError::PairingConflict)?;
    let sealed_authorization: Vec<u8> = transaction.query_row(
        "SELECT sealed_authorization FROM remote_authorization_ledger
         WHERE device_route = ?1 AND grant_serial = ?2",
        params![
            device_route.as_bytes().as_slice(),
            super::sequence::encode_sequence(previous_serial.value()),
        ],
        |row| row.get(0),
    )?;
    if u64::try_from(sealed_authorization.len()).unwrap_or(u64::MAX) != previous.sealed_bytes {
        return Err(RuntimeStoreError::UnknownOrCorruptSchema);
    }
    let metadata_token = authorization_token(
        key_bundle,
        database_id,
        device_route,
        previous_serial,
        AuthorizationLifecycle::Superseded,
        previous.device_sign_fingerprint,
        previous.grant_hash,
        previous.authorization_hash,
        previous.key_directory_revision,
        &sealed_authorization,
        previous.created_at_ms,
        now_ms,
    )?;
    if transaction.execute(
        "UPDATE remote_authorization_ledger
         SET lifecycle = 'superseded', state_changed_at_ms = ?1, metadata_token = ?2
         WHERE device_route = ?3 AND grant_serial = ?4
           AND lifecycle = 'active' AND metadata_token = ?5",
        params![
            i64::try_from(now_ms).map_err(|_| RuntimeStoreError::TimeOutOfRange)?,
            &metadata_token[..],
            device_route.as_bytes().as_slice(),
            super::sequence::encode_sequence(previous_serial.value()),
            &previous.metadata_token[..],
        ],
    )? != 1
    {
        return Err(RuntimeStoreError::PairingConflict);
    }
    Ok(())
}

#[allow(clippy::too_many_arguments)]
fn next_ledger(
    current: &RuntimeLedger,
    previous_pairing_bytes: u64,
    pairing_bytes: usize,
    receipt_bytes: usize,
    authorization_bytes: usize,
    previous_global_bytes: Option<u64>,
    global_bytes: usize,
    install_bytes: usize,
    renewal: bool,
) -> Result<RuntimeLedger, RuntimeStoreError> {
    let pairing_bytes =
        u64::try_from(pairing_bytes).map_err(|_| RuntimeStoreError::PayloadTooLarge)?;
    let receipt_bytes =
        u64::try_from(receipt_bytes).map_err(|_| RuntimeStoreError::PayloadTooLarge)?;
    let authorization_bytes =
        u64::try_from(authorization_bytes).map_err(|_| RuntimeStoreError::PayloadTooLarge)?;
    let global_bytes =
        u64::try_from(global_bytes).map_err(|_| RuntimeStoreError::PayloadTooLarge)?;
    let install_bytes =
        u64::try_from(install_bytes).map_err(|_| RuntimeStoreError::PayloadTooLarge)?;
    let mut next = current.clone();
    next.remote_pairing_sealed_bytes = next
        .remote_pairing_sealed_bytes
        .checked_sub(previous_pairing_bytes)
        .and_then(|bytes| bytes.checked_add(pairing_bytes))
        .ok_or(RuntimeStoreError::CapacityArithmeticOverflow {
            field: "remote_pairing_sealed_bytes",
        })?;
    next.remote_pairing_receipt_count = next.remote_pairing_receipt_count.checked_add(1).ok_or(
        RuntimeStoreError::CapacityArithmeticOverflow {
            field: "remote_pairing_receipt_count",
        },
    )?;
    next.remote_pairing_receipt_bytes = next
        .remote_pairing_receipt_bytes
        .checked_add(receipt_bytes)
        .ok_or(RuntimeStoreError::CapacityArithmeticOverflow {
            field: "remote_pairing_receipt_bytes",
        })?;
    next.remote_authorization_count = next.remote_authorization_count.checked_add(1).ok_or(
        RuntimeStoreError::CapacityArithmeticOverflow {
            field: "remote_authorization_count",
        },
    )?;
    next.remote_authorization_preparing_count = next
        .remote_authorization_preparing_count
        .checked_add(1)
        .ok_or(RuntimeStoreError::CapacityArithmeticOverflow {
            field: "remote_authorization_preparing_count",
        })?;
    if renewal {
        next.remote_authorization_active_count = next
            .remote_authorization_active_count
            .checked_sub(1)
            .ok_or(RuntimeStoreError::UnknownOrCorruptSchema)?;
    }
    next.remote_authorization_sealed_bytes = next
        .remote_authorization_sealed_bytes
        .checked_add(authorization_bytes)
        .ok_or(RuntimeStoreError::CapacityArithmeticOverflow {
            field: "remote_authorization_sealed_bytes",
        })?;
    match previous_global_bytes {
        None => next.remote_key_directory_count = 1,
        Some(previous) => {
            next.remote_key_directory_sealed_bytes = next
                .remote_key_directory_sealed_bytes
                .checked_sub(previous)
                .ok_or(RuntimeStoreError::UnknownOrCorruptSchema)?;
        }
    }
    next.remote_key_directory_sealed_bytes = next
        .remote_key_directory_sealed_bytes
        .checked_add(global_bytes)
        .ok_or(RuntimeStoreError::CapacityArithmeticOverflow {
            field: "remote_key_directory_sealed_bytes",
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
        .checked_add(install_bytes)
        .ok_or(RuntimeStoreError::CapacityArithmeticOverflow {
            field: "remote_control_outbox_sealed_bytes",
        })?;
    if next.remote_pairing_sealed_bytes > super::pairing::MAX_PAIRING_SEALED_BYTES
        || next.remote_pairing_receipt_count > 65_536
        || next.remote_pairing_receipt_bytes > 64 * 1024 * 1024
        || next.remote_authorization_count > MAX_AUTHORIZATIONS
        || next.remote_authorization_sealed_bytes > MAX_AUTHORIZATION_SEALED_BYTES
        || next.remote_key_directory_count > 1
        || next.remote_key_directory_sealed_bytes > 64 * 1024 * 1024
        || next.remote_control_outbox_count > super::pairing::MAX_CONTROL_OUTBOX
        || next.remote_control_outbox_sealed_bytes > super::pairing::MAX_CONTROL_OUTBOX_SEALED_BYTES
    {
        return Err(RuntimeStoreError::PairingLimit);
    }
    Ok(next)
}

#[cfg(test)]
#[allow(clippy::too_many_arguments)]
pub(super) fn next_ledger_for_test(
    current: &RuntimeLedger,
    previous_pairing_bytes: u64,
    pairing_bytes: usize,
    receipt_bytes: usize,
    authorization_bytes: usize,
    previous_global_bytes: Option<u64>,
    global_bytes: usize,
    install_bytes: usize,
) -> Result<RuntimeLedger, RuntimeStoreError> {
    next_ledger(
        current,
        previous_pairing_bytes,
        pairing_bytes,
        receipt_bytes,
        authorization_bytes,
        previous_global_bytes,
        global_bytes,
        install_bytes,
        false,
    )
}

fn already_expired(
    state: &mut RuntimeSqlite,
    config: &RuntimeStoreConfig,
    pairing_id: RuntimeId,
    now_ms: u64,
) -> Result<ConfirmPairingGrantOutcome, RuntimeStoreError> {
    let outcome = super::pairing_terminal::terminalize_pairing(
        state,
        config,
        pairing_id,
        super::pairing_terminal::PairingTerminalAction::Expire,
        now_ms,
    )?;
    let receipt = match outcome {
        super::pairing_terminal::PairingTerminalizeOutcome::Transitioned { receipt, .. }
        | super::pairing_terminal::PairingTerminalizeOutcome::Replayed { receipt, .. }
        | super::pairing_terminal::PairingTerminalizeOutcome::AlreadyHandled { receipt, .. } => {
            receipt
        }
    };
    Ok(ConfirmPairingGrantOutcome::AlreadyHandled {
        receipt,
        state: PairingState::Expired,
    })
}

pub(crate) fn confirm_pairing_grant(
    state: &mut RuntimeSqlite,
    config: &RuntimeStoreConfig,
    prepared: PreparedConfirmPairingGrant,
    now_ms: u64,
) -> Result<ConfirmPairingGrantOutcome, RuntimeStoreError> {
    let directory =
        super::pairing::load_directory(&state.connection, &state.key_bundle, state.database_id)?;
    if let Some(existing) = classify_existing(&directory, &prepared)? {
        return Ok(existing);
    }
    let current = directory
        .pairings
        .iter()
        .find(|pairing| pairing.record.pairing_id == prepared.pairing_id)
        .ok_or(RuntimeStoreError::PairingConflict)?;
    if now_ms < current.record.state_changed_at_ms {
        return Err(RuntimeStoreError::ClockRegressed {
            persisted_ms: current.record.state_changed_at_ms,
            observed_ms: now_ms,
        });
    }
    if now_ms >= current.record.expires_at_ms {
        return already_expired(state, config, prepared.pairing_id, now_ms);
    }
    if current.record.lifecycle != PairingInviteLifecycle::AwaitingLocalConfirmation {
        return Err(RuntimeStoreError::PairingConflict);
    }
    let active =
        super::pairing::active_machine(&state.connection, &state.key_bundle, state.database_id)?;
    let _ = validate_prepared(
        current,
        &directory.pairings,
        &prepared,
        &directory.grants,
        &active,
    )?;
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
    let mut directory =
        super::pairing::load_directory(&transaction, &state.key_bundle, state.database_id)?;
    if let Some(existing) = classify_existing(&directory, &prepared)? {
        return Ok(existing);
    }
    let pairing_index = directory
        .pairings
        .iter()
        .position(|pairing| pairing.record.pairing_id == prepared.pairing_id)
        .ok_or(RuntimeStoreError::PairingConflict)?;
    let current = directory.pairings.swap_remove(pairing_index);
    if current.record.lifecycle != PairingInviteLifecycle::AwaitingLocalConfirmation
        || current.record.request_hash != Some(prepared.request_hash)
        || now_ms < current.record.state_changed_at_ms
        || now_ms >= current.record.expires_at_ms
    {
        return Err(RuntimeStoreError::PairingConflict);
    }
    let active =
        super::pairing::active_machine(&transaction, &state.key_bundle, state.database_id)?;
    let validated = validate_prepared(
        &current,
        &directory.pairings,
        &prepared,
        &directory.grants,
        &active,
    )?;
    let receipt_write = super::pairing_terminal::prepare_confirmed_receipt(
        &state.key_bundle,
        state.database_id,
        &current,
        now_ms,
    )?;
    let pairing_payload = super::pairing::encode_grant_payload(
        &current,
        prepared.grant_hash,
        prepared.response_hash,
        &prepared.canonical_relay_grant,
        prepared.canonical_authorization.expose_secret(),
        prepared.canonical_key_directory.expose_secret(),
        prepared.canonical_response.expose_secret(),
        &prepared.canonical_install_frame,
        prepared.global_key_state_hash,
    )?;
    let sealed_pairing = seal_row(
        &state.key_bundle,
        state.database_id,
        PAIRING_TABLE,
        prepared.pairing_id.as_bytes(),
        PAIRING_COLUMN,
        pairing_payload.as_slice(),
        super::pairing::MAX_PAIRING_STATE_PLAINTEXT_BYTES,
    )?;
    let pairing_token = super::pairing::pairing_row_token(
        &state.key_bundle,
        state.database_id,
        prepared.pairing_id,
        PairingInviteLifecycle::GrantPreparing,
        current.record.relay_server_id,
        current.record.machine_route,
        current.record.pair_route,
        current.record.expires_at_ms,
        current.record.created_at_ms,
        now_ms,
        Some(prepared.request_hash),
        current.record.device_sign_fingerprint,
        Some(prepared.grant_hash),
        Some(prepared.response_hash),
        &sealed_pairing,
    )?;
    let auth_primary =
        authorization_primary_key(validated.grant.device_route, validated.grant.grant_serial);
    let authorization_payload = encode_authorization_payload(
        &prepared.canonical_relay_grant,
        &prepared.canonical_install_frame,
        prepared.canonical_authorization.expose_secret(),
    )?;
    let sealed_authorization = seal_row(
        &state.key_bundle,
        state.database_id,
        AUTH_TABLE,
        &auth_primary,
        AUTH_COLUMN,
        authorization_payload.as_slice(),
        MAX_AUTHORIZATION_PLAINTEXT_BYTES,
    )?;
    let auth_token = authorization_token(
        &state.key_bundle,
        state.database_id,
        validated.grant.device_route,
        validated.grant.grant_serial,
        AuthorizationLifecycle::GrantPreparing,
        validated.authorization.device_sign_fingerprint,
        prepared.grant_hash,
        prepared.authorization_hash,
        validated.directory.revision.value(),
        &sealed_authorization,
        now_ms,
        now_ms,
    )?;
    let sealed_global = seal_row(
        &state.key_bundle,
        state.database_id,
        GLOBAL_KEY_TABLE,
        b"1",
        GLOBAL_KEY_COLUMN,
        prepared.canonical_global_key_state.expose_secret(),
        MAX_GLOBAL_KEY_STATE_BYTES,
    )?;
    let global_token = global_key_token(
        &state.key_bundle,
        state.database_id,
        validated.global.revision().value(),
        prepared.global_key_state_hash,
        &sealed_global,
    )?;
    let outbox_id = super::pairing::allocate_id(&transaction, config, RuntimeIdKind::RemoteOutbox)?;
    let sealed_install = seal_row(
        &state.key_bundle,
        state.database_id,
        OUTBOX_TABLE,
        outbox_id.as_bytes(),
        OUTBOX_COLUMN,
        &prepared.canonical_install_frame,
        super::pairing::MAX_CONTROL_FRAME_PLAINTEXT_BYTES,
    )?;
    let operation_key = install_operation_key(
        &state.key_bundle,
        validated.grant.device_route,
        validated.grant.grant_serial,
    )?;
    let frame_hash = sha256(&prepared.canonical_install_frame);
    let outbox_token = install_outbox_token(
        &state.key_bundle,
        state.database_id,
        outbox_id,
        operation_key,
        validated.grant.device_route,
        validated.grant.grant_serial,
        frame_hash,
        &sealed_install,
        now_ms,
        now_ms,
    )?;
    let next = next_ledger(
        &directory.ledger,
        current.sealed_state_bytes,
        sealed_pairing.len(),
        usize::try_from(receipt_write.receipt_bytes())
            .map_err(|_| RuntimeStoreError::PayloadTooLarge)?,
        sealed_authorization.len(),
        directory
            .grants
            .global
            .as_ref()
            .map(|global| global.sealed_bytes),
        sealed_global.len(),
        sealed_install.len(),
        validated.allocation.is_renewal(),
    )?;

    supersede_previous_authorization(
        &transaction,
        &state.key_bundle,
        state.database_id,
        &directory.grants,
        validated.allocation,
        now_ms,
    )?;
    super::pairing_terminal::insert_confirmed_receipt(&transaction, &current, &receipt_write)?;
    if transaction.execute(
        "INSERT INTO remote_authorization_ledger (
             device_route, grant_serial, lifecycle, database_id,
             device_sign_fingerprint, grant_hash, authorization_hash,
             key_directory_revision, sealed_authorization, sealed_authorization_bytes,
             revocation_hash, sealed_revocation, sealed_revocation_bytes,
             created_at_ms, state_changed_at_ms, metadata_token
         ) VALUES (?1, ?2, 'grantPreparing', ?3, ?4, ?5, ?6, ?7, ?8, ?9,
                   NULL, NULL, NULL, ?10, ?10, ?11)",
        params![
            validated.grant.device_route.as_bytes().as_slice(),
            super::sequence::encode_sequence(validated.grant.grant_serial.value()),
            &state.database_id[..],
            &validated.authorization.device_sign_fingerprint[..],
            &prepared.grant_hash[..],
            &prepared.authorization_hash[..],
            super::sequence::encode_sequence(validated.directory.revision.value()),
            &sealed_authorization,
            i64::try_from(sealed_authorization.len())
                .map_err(|_| RuntimeStoreError::PayloadTooLarge)?,
            i64::try_from(now_ms).map_err(|_| RuntimeStoreError::TimeOutOfRange)?,
            &auth_token[..],
        ],
    )? != 1
    {
        return Err(RuntimeStoreError::PairingConflict);
    }
    match directory.grants.global.as_ref() {
        None => {
            if transaction.execute(
                "INSERT INTO remote_key_directory (
                     singleton, database_id, revision, directory_hash,
                     sealed_directory, sealed_directory_bytes, metadata_token
                 ) VALUES (1, ?1, ?2, ?3, ?4, ?5, ?6)",
                params![
                    &state.database_id[..],
                    super::sequence::encode_sequence(validated.global.revision().value()),
                    &prepared.global_key_state_hash[..],
                    &sealed_global,
                    i64::try_from(sealed_global.len())
                        .map_err(|_| RuntimeStoreError::PayloadTooLarge)?,
                    &global_token[..],
                ],
            )? != 1
            {
                return Err(RuntimeStoreError::PairingConflict);
            }
        }
        Some(previous) => {
            if transaction.execute(
                "UPDATE remote_key_directory
                 SET revision = ?1, directory_hash = ?2, sealed_directory = ?3,
                     sealed_directory_bytes = ?4, metadata_token = ?5
                 WHERE singleton = 1 AND revision = ?6 AND directory_hash = ?7
                   AND metadata_token = ?8",
                params![
                    super::sequence::encode_sequence(validated.global.revision().value()),
                    &prepared.global_key_state_hash[..],
                    &sealed_global,
                    i64::try_from(sealed_global.len())
                        .map_err(|_| RuntimeStoreError::PayloadTooLarge)?,
                    &global_token[..],
                    super::sequence::encode_sequence(previous.revision),
                    &previous.directory_hash[..],
                    &previous.metadata_token[..],
                ],
            )? != 1
            {
                return Err(RuntimeStoreError::PairingConflict);
            }
        }
    }
    if transaction.execute(
        "INSERT INTO remote_control_outbox (
             outbox_id, operation_kind, operation_key, lifecycle, database_id,
             pairing_id, device_route, grant_serial, frame_hash, sealed_frame,
             sealed_frame_bytes, terminal_hash, sealed_terminal, sealed_terminal_bytes,
             created_at_ms, state_changed_at_ms, metadata_token
         ) VALUES (?1, 'installGrant', ?2, 'prepared', ?3, NULL, ?4, ?5, ?6, ?7,
                   ?8, NULL, NULL, NULL, ?9, ?9, ?10)",
        params![
            outbox_id.as_bytes().as_slice(),
            &operation_key[..],
            &state.database_id[..],
            validated.grant.device_route.as_bytes().as_slice(),
            super::sequence::encode_sequence(validated.grant.grant_serial.value()),
            &frame_hash[..],
            &sealed_install,
            i64::try_from(sealed_install.len()).map_err(|_| RuntimeStoreError::PayloadTooLarge)?,
            i64::try_from(now_ms).map_err(|_| RuntimeStoreError::TimeOutOfRange)?,
            &outbox_token[..],
        ],
    )? != 1
    {
        return Err(RuntimeStoreError::PairingConflict);
    }
    if transaction.execute(
        "UPDATE remote_pairings
         SET lifecycle = 'grantPreparing', state_changed_at_ms = ?1,
             grant_hash = ?2, response_hash = ?3, sealed_state = ?4,
             sealed_state_bytes = ?5, metadata_token = ?6
         WHERE pairing_id = ?7 AND lifecycle = 'awaitingLocalConfirmation'
           AND request_hash = ?8 AND metadata_token = ?9",
        params![
            i64::try_from(now_ms).map_err(|_| RuntimeStoreError::TimeOutOfRange)?,
            &prepared.grant_hash[..],
            &prepared.response_hash[..],
            &sealed_pairing,
            i64::try_from(sealed_pairing.len()).map_err(|_| RuntimeStoreError::PayloadTooLarge)?,
            &pairing_token[..],
            prepared.pairing_id.as_bytes().as_slice(),
            &prepared.request_hash[..],
            &current.metadata_token[..],
        ],
    )? != 1
    {
        return Err(RuntimeStoreError::PairingConflict);
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
        .before_operation(RuntimeStoreOperation::ConfirmPairingGrantBeforeCommit)?;
    super::sqlite::commit_transaction(transaction, RuntimeCommitOperation::ConfirmPairingGrant)?;
    super::sqlite::latch_post_commit_capacity(state, config);
    config
        .fault_injector
        .before_operation(RuntimeStoreOperation::ConfirmPairingGrantAfterCommit)
        .map_err(|_| RuntimeStoreError::CommitOutcomeUnknown {
            operation: RuntimeCommitOperation::ConfirmPairingGrant,
        })?;
    let directory =
        super::pairing::load_directory(&state.connection, &state.key_bundle, state.database_id)?;
    let pairing = directory
        .pairings
        .iter()
        .find(|pairing| pairing.record.pairing_id == prepared.pairing_id)
        .ok_or(RuntimeStoreError::UnknownOrCorruptSchema)?;
    let recovery = recovery(&directory, pairing)?;
    Ok(ConfirmPairingGrantOutcome::Confirmed {
        receipt: receipt_write.receipt().clone(),
        recovery,
    })
}

pub(crate) fn list_grant_preparing_recovery(
    connection: &Connection,
    key_bundle: &RuntimeKeyBundle,
    database_id: [u8; 16],
) -> Result<Vec<GrantPreparingRecovery>, RuntimeStoreError> {
    let directory = super::pairing::load_directory(connection, key_bundle, database_id)?;
    directory
        .pairings
        .iter()
        .filter(|pairing| pairing.record.lifecycle == PairingInviteLifecycle::GrantPreparing)
        .map(|pairing| recovery(&directory, pairing))
        .collect()
}

pub(crate) fn load_global_key_state_for_use(
    connection: &Connection,
    key_bundle: &RuntimeKeyBundle,
    database_id: [u8; 16],
) -> Result<Option<GlobalKeyStateV1>, RuntimeStoreError> {
    Ok(load_global_key_state(connection, key_bundle, database_id)?
        .map(|AuthenticatedGlobalKeyState { state, .. }| state))
}

pub(crate) fn prepare(
    input: ConfirmPairingGrant,
) -> Result<PreparedConfirmPairingGrant, RuntimeStoreError> {
    prepare_confirm(input)
}
