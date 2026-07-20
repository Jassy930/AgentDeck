//! `grantPreparing -> grantCommitted` 的 Relay ACK CAS 与 PairResponse 恢复投影。

use agentdeck_crypto::{HpkePrivateKey, sha256};
use agentdeck_protocol::e2ee::{PairInviteV1, PairResponseV1};
use agentdeck_protocol::relay_v2::frame::{GrantCommitted, OpaqueRouteFrame, RelayFrameBody};
use agentdeck_protocol::relay_v2::{
    DeviceRouteId, GrantSerial, RELAY_PROTOCOL_VERSION, RelayGrant, decode, encode,
};
use rusqlite::{TransactionBehavior, params};

use crate::runtime::model::{
    RuntimeCommitOperation, RuntimeStoreConfig, RuntimeStoreError, RuntimeStoreOperation,
};
use crate::security::SecretBytes;

use super::identity::{RuntimeId, RuntimeIdKind};
use super::pairing::{AuthenticatedPairingRow, PairingDirectory, PairingInviteLifecycle};
use super::pairing_authorization::{
    AuthenticatedAuthorization, AuthorizationLifecycle, MAX_AUTHORIZATION_PLAINTEXT_BYTES,
    authorization_token, encode_authorization_payload,
};
use super::pairing_grant::{AuthenticatedInstallOutbox, exact_install_frame, seal_row};
use super::sqlite::{RuntimeLedger, RuntimeSqlite};

const PAIRING_TABLE: &[u8] = b"remote_pairings";
const PAIRING_COLUMN: &[u8] = b"sealed_state";
const AUTH_TABLE: &[u8] = b"remote_authorization_ledger";
const AUTH_COLUMN: &[u8] = b"sealed_authorization";
const MAX_COMMITTED_RECOVERY_RETAINED_BYTES: usize = 128 * 1024 * 1024;

pub(crate) struct AcknowledgeGrantCommitted {
    pairing_id: RuntimeId,
    canonical_terminal: Vec<u8>,
}

impl AcknowledgeGrantCommitted {
    #[must_use]
    pub(crate) const fn new(pairing_id: RuntimeId, canonical_terminal: Vec<u8>) -> Self {
        Self {
            pairing_id,
            canonical_terminal,
        }
    }
}

impl std::fmt::Debug for AcknowledgeGrantCommitted {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter.write_str("AcknowledgeGrantCommitted([REDACTED])")
    }
}

pub(crate) struct PreparedGrantCommitted {
    pairing_id: RuntimeId,
    device_route: DeviceRouteId,
    grant_serial: GrantSerial,
    grant_hash: [u8; 32],
}

impl PreparedGrantCommitted {
    pub(crate) const fn retained_bytes(&self) -> usize {
        0
    }
}

pub(crate) struct GrantCommittedRecovery {
    pairing_id: RuntimeId,
    request_hash: [u8; 32],
    device_route: DeviceRouteId,
    grant_serial: GrantSerial,
    grant_hash: [u8; 32],
    response_hash: [u8; 32],
    invite: PairInviteV1,
    relay_grant: RelayGrant,
    pair_response: PairResponseV1,
    canonical_pair_response: SecretBytes,
    invite_hpke_private_key: HpkePrivateKey,
}

impl std::fmt::Debug for GrantCommittedRecovery {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter.write_str("GrantCommittedRecovery([REDACTED])")
    }
}

impl GrantCommittedRecovery {
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
    pub(crate) const fn invite(&self) -> &PairInviteV1 {
        &self.invite
    }

    #[must_use]
    pub(crate) const fn relay_grant(&self) -> &RelayGrant {
        &self.relay_grant
    }

    #[must_use]
    pub(crate) const fn pair_response(&self) -> &PairResponseV1 {
        &self.pair_response
    }

    #[must_use]
    pub(crate) fn canonical_pair_response(&self) -> &[u8] {
        self.canonical_pair_response.expose_secret()
    }

    #[must_use]
    pub(crate) const fn invite_hpke_private_key(&self) -> &HpkePrivateKey {
        &self.invite_hpke_private_key
    }

    pub(crate) fn retained_bytes(&self) -> Result<usize, RuntimeStoreError> {
        self.invite
            .wss_url
            .capacity()
            .checked_add(self.invite.machine_display_name.capacity())
            .and_then(|bytes| bytes.checked_add(self.pair_response.enc.capacity()))
            .and_then(|bytes| bytes.checked_add(self.pair_response.ciphertext.capacity()))
            .and_then(|bytes| bytes.checked_add(self.canonical_pair_response.retained_capacity()))
            .ok_or(RuntimeStoreError::PayloadTooLarge)
    }
}

#[derive(Debug)]
pub(crate) enum AcknowledgeGrantCommittedOutcome {
    Committed { recovery: GrantCommittedRecovery },
    Replayed { recovery: GrantCommittedRecovery },
}

fn prepare(input: AcknowledgeGrantCommitted) -> Result<PreparedGrantCommitted, RuntimeStoreError> {
    if input.pairing_id.kind() != RuntimeIdKind::Pairing {
        return Err(RuntimeStoreError::IdKindMismatch {
            expected: RuntimeIdKind::Pairing,
            actual: input.pairing_id.kind(),
        });
    }
    if input.canonical_terminal.is_empty()
        || input.canonical_terminal.len() > super::pairing::MAX_CONTROL_FRAME_PLAINTEXT_BYTES
    {
        return Err(RuntimeStoreError::PayloadTooLarge);
    }
    let frame: OpaqueRouteFrame =
        decode(&input.canonical_terminal).map_err(|_| RuntimeStoreError::PairingConflict)?;
    if frame.version != RELAY_PROTOCOL_VERSION || encode(&frame) != input.canonical_terminal {
        return Err(RuntimeStoreError::PairingConflict);
    }
    let RelayFrameBody::GrantCommitted(GrantCommitted {
        device_route,
        grant_serial,
        grant_hash,
    }) = frame.body
    else {
        return Err(RuntimeStoreError::PairingConflict);
    };
    if device_route.as_bytes() == &[0; 16] || grant_serial.value() == 0 || grant_hash == [0; 32] {
        return Err(RuntimeStoreError::PairingConflict);
    }
    Ok(PreparedGrantCommitted {
        pairing_id: input.pairing_id,
        device_route,
        grant_serial,
        grant_hash,
    })
}

fn recovery(
    directory: &PairingDirectory,
    pairing: &AuthenticatedPairingRow,
) -> Result<GrantCommittedRecovery, RuntimeStoreError> {
    if pairing.record.lifecycle != PairingInviteLifecycle::GrantCommitted {
        return Err(RuntimeStoreError::UnknownOrCorruptSchema);
    }
    let request_hash = pairing
        .record
        .request_hash
        .ok_or(RuntimeStoreError::UnknownOrCorruptSchema)?;
    let grant_hash = pairing
        .record
        .grant_hash
        .ok_or(RuntimeStoreError::UnknownOrCorruptSchema)?;
    let response_hash = pairing
        .record
        .response_hash
        .ok_or(RuntimeStoreError::UnknownOrCorruptSchema)?;
    let (relay_grant, observed_grant_hash) = exact_install_frame(
        pairing
            .record
            .canonical_install_frame
            .as_deref()
            .ok_or(RuntimeStoreError::UnknownOrCorruptSchema)?,
    )?;
    let canonical_pair_response = pairing
        .record
        .canonical_pair_response
        .as_ref()
        .ok_or(RuntimeStoreError::UnknownOrCorruptSchema)?;
    let pair_response =
        PairResponseV1::from_canonical_bytes(canonical_pair_response.expose_secret())
            .map_err(|_| RuntimeStoreError::UnknownOrCorruptSchema)?;
    let invite = PairInviteV1::from_canonical_bytes(pairing.record.canonical_invite())
        .map_err(|_| RuntimeStoreError::UnknownOrCorruptSchema)?;
    let invite_hpke_private_key =
        HpkePrivateKey::from_bytes(pairing.record.invite_hpke_private_key.expose_secret())
            .map_err(|_| RuntimeStoreError::UnknownOrCorruptSchema)?;
    let authorization = directory
        .grants
        .authorizations
        .iter()
        .find(|authorization| {
            authorization.device_route == relay_grant.device_route
                && authorization.grant_serial == relay_grant.grant_serial
        })
        .ok_or(RuntimeStoreError::UnknownOrCorruptSchema)?;
    if observed_grant_hash != grant_hash
        || relay_grant.canonical_bytes()
            != pairing
                .record
                .canonical_relay_grant
                .as_deref()
                .ok_or(RuntimeStoreError::UnknownOrCorruptSchema)?
        || pair_response.canonical_bytes().ok().as_deref()
            != Some(canonical_pair_response.expose_secret())
        || pair_response.canonical_sha256().ok() != Some(response_hash)
        || sha256(canonical_pair_response.expose_secret()) != response_hash
        || invite.canonical_bytes().ok().as_deref() != Some(pairing.record.canonical_invite())
        || invite_hpke_private_key.public_key().to_bytes() != invite.invite_hpke_pubkey.0
        || authorization.lifecycle != AuthorizationLifecycle::Active
        || authorization.grant_hash != grant_hash
        || directory.grants.installs.iter().any(|install| {
            install.device_route == relay_grant.device_route
                && install.grant_serial == relay_grant.grant_serial
        })
    {
        return Err(RuntimeStoreError::UnknownOrCorruptSchema);
    }
    Ok(GrantCommittedRecovery {
        pairing_id: pairing.record.pairing_id,
        request_hash,
        device_route: relay_grant.device_route,
        grant_serial: relay_grant.grant_serial,
        grant_hash,
        response_hash,
        invite,
        relay_grant,
        pair_response,
        canonical_pair_response: SecretBytes::new(canonical_pair_response.expose_secret().to_vec()),
        invite_hpke_private_key,
    })
}

fn classify_existing(
    directory: &PairingDirectory,
    prepared: &PreparedGrantCommitted,
) -> Result<Option<AcknowledgeGrantCommittedOutcome>, RuntimeStoreError> {
    let pairing = directory
        .pairings
        .iter()
        .find(|pairing| pairing.record.pairing_id == prepared.pairing_id)
        .ok_or(RuntimeStoreError::PairingConflict)?;
    if pairing.record.lifecycle != PairingInviteLifecycle::GrantCommitted {
        return Ok(None);
    }
    let recovery = recovery(directory, pairing)?;
    if recovery.device_route != prepared.device_route
        || recovery.grant_serial != prepared.grant_serial
        || recovery.grant_hash != prepared.grant_hash
    {
        return Err(RuntimeStoreError::PairingConflict);
    }
    Ok(Some(AcknowledgeGrantCommittedOutcome::Replayed {
        recovery,
    }))
}

struct PreparingBindings<'a> {
    pairing: &'a AuthenticatedPairingRow,
    authorization: &'a AuthenticatedAuthorization,
    install: &'a AuthenticatedInstallOutbox,
}

fn validate_preparing<'a>(
    directory: &'a PairingDirectory,
    prepared: &PreparedGrantCommitted,
) -> Result<PreparingBindings<'a>, RuntimeStoreError> {
    let pairing = directory
        .pairings
        .iter()
        .find(|pairing| pairing.record.pairing_id == prepared.pairing_id)
        .ok_or(RuntimeStoreError::PairingConflict)?;
    if pairing.record.lifecycle != PairingInviteLifecycle::GrantPreparing
        || pairing.record.grant_hash != Some(prepared.grant_hash)
    {
        return Err(RuntimeStoreError::PairingConflict);
    }
    let (relay_grant, observed_grant_hash) = exact_install_frame(
        pairing
            .record
            .canonical_install_frame
            .as_deref()
            .ok_or(RuntimeStoreError::UnknownOrCorruptSchema)?,
    )?;
    if observed_grant_hash != prepared.grant_hash
        || relay_grant.device_route != prepared.device_route
        || relay_grant.grant_serial != prepared.grant_serial
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
    let install = directory
        .grants
        .installs
        .iter()
        .find(|install| {
            install.device_route == prepared.device_route
                && install.grant_serial == prepared.grant_serial
        })
        .ok_or(RuntimeStoreError::PairingConflict)?;
    if authorization.lifecycle != AuthorizationLifecycle::GrantPreparing
        || authorization.grant_hash != prepared.grant_hash
        || install.grant.canonical_sha256() != prepared.grant_hash
        || install.canonical_frame
            != pairing
                .record
                .canonical_install_frame
                .as_deref()
                .ok_or(RuntimeStoreError::UnknownOrCorruptSchema)?
    {
        return Err(RuntimeStoreError::PairingConflict);
    }
    Ok(PreparingBindings {
        pairing,
        authorization,
        install,
    })
}

fn authorization_primary_key(device_route: DeviceRouteId, serial: GrantSerial) -> [u8; 24] {
    let mut value = [0_u8; 24];
    value[..16].copy_from_slice(device_route.as_bytes());
    value[16..].copy_from_slice(&serial.value().to_be_bytes());
    value
}

#[allow(clippy::too_many_arguments)]
fn next_ledger(
    current: &RuntimeLedger,
    previous_pairing_bytes: u64,
    next_pairing_bytes: usize,
    previous_authorization_bytes: u64,
    next_authorization_bytes: usize,
    install_bytes: u64,
) -> Result<RuntimeLedger, RuntimeStoreError> {
    let next_pairing_bytes =
        u64::try_from(next_pairing_bytes).map_err(|_| RuntimeStoreError::PayloadTooLarge)?;
    let next_authorization_bytes =
        u64::try_from(next_authorization_bytes).map_err(|_| RuntimeStoreError::PayloadTooLarge)?;
    let mut next = current.clone();
    next.remote_pairing_sealed_bytes = next
        .remote_pairing_sealed_bytes
        .checked_sub(previous_pairing_bytes)
        .and_then(|bytes| bytes.checked_add(next_pairing_bytes))
        .ok_or(RuntimeStoreError::CapacityArithmeticOverflow {
            field: "remote_pairing_sealed_bytes",
        })?;
    next.remote_authorization_preparing_count = next
        .remote_authorization_preparing_count
        .checked_sub(1)
        .ok_or(RuntimeStoreError::UnknownOrCorruptSchema)?;
    next.remote_authorization_active_count = next
        .remote_authorization_active_count
        .checked_add(1)
        .ok_or(RuntimeStoreError::CapacityArithmeticOverflow {
            field: "remote_authorization_active_count",
        })?;
    next.remote_authorization_sealed_bytes = next
        .remote_authorization_sealed_bytes
        .checked_sub(previous_authorization_bytes)
        .and_then(|bytes| bytes.checked_add(next_authorization_bytes))
        .ok_or(RuntimeStoreError::CapacityArithmeticOverflow {
            field: "remote_authorization_sealed_bytes",
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
        .checked_sub(install_bytes)
        .ok_or(RuntimeStoreError::UnknownOrCorruptSchema)?;
    if next.remote_pairing_sealed_bytes > super::pairing::MAX_PAIRING_SEALED_BYTES
        || next.remote_authorization_sealed_bytes > 64 * 1024 * 1024
    {
        return Err(RuntimeStoreError::PairingLimit);
    }
    Ok(next)
}

pub(crate) fn acknowledge_grant_committed(
    state: &mut RuntimeSqlite,
    config: &RuntimeStoreConfig,
    prepared: PreparedGrantCommitted,
    now_ms: u64,
) -> Result<AcknowledgeGrantCommittedOutcome, RuntimeStoreError> {
    let directory =
        super::pairing::load_directory(&state.connection, &state.key_bundle, state.database_id)?;
    if let Some(existing) = classify_existing(&directory, &prepared)? {
        return Ok(existing);
    }
    let bindings = validate_preparing(&directory, &prepared)?;
    if now_ms < bindings.pairing.record.state_changed_at_ms {
        return Err(RuntimeStoreError::ClockRegressed {
            persisted_ms: bindings.pairing.record.state_changed_at_ms,
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
    if let Some(existing) = classify_existing(&directory, &prepared)? {
        return Ok(existing);
    }
    let bindings = validate_preparing(&directory, &prepared)?;
    if now_ms < bindings.pairing.record.state_changed_at_ms {
        return Err(RuntimeStoreError::ClockRegressed {
            persisted_ms: bindings.pairing.record.state_changed_at_ms,
            observed_ms: now_ms,
        });
    }

    let pairing = bindings.pairing;
    let grant_hash = pairing
        .record
        .grant_hash
        .ok_or(RuntimeStoreError::UnknownOrCorruptSchema)?;
    let response_hash = pairing
        .record
        .response_hash
        .ok_or(RuntimeStoreError::UnknownOrCorruptSchema)?;
    let pairing_payload = super::pairing::encode_grant_payload(
        pairing,
        grant_hash,
        response_hash,
        pairing
            .record
            .canonical_relay_grant
            .as_deref()
            .ok_or(RuntimeStoreError::UnknownOrCorruptSchema)?,
        pairing
            .record
            .canonical_device_authorization
            .as_ref()
            .ok_or(RuntimeStoreError::UnknownOrCorruptSchema)?
            .expose_secret(),
        pairing
            .record
            .canonical_key_directory_view
            .as_ref()
            .ok_or(RuntimeStoreError::UnknownOrCorruptSchema)?
            .expose_secret(),
        pairing
            .record
            .canonical_pair_response
            .as_ref()
            .ok_or(RuntimeStoreError::UnknownOrCorruptSchema)?
            .expose_secret(),
        pairing
            .record
            .canonical_install_frame
            .as_deref()
            .ok_or(RuntimeStoreError::UnknownOrCorruptSchema)?,
        pairing
            .record
            .global_key_state_hash
            .ok_or(RuntimeStoreError::UnknownOrCorruptSchema)?,
    )?;
    let sealed_pairing = seal_row(
        &state.key_bundle,
        state.database_id,
        PAIRING_TABLE,
        pairing.record.pairing_id.as_bytes(),
        PAIRING_COLUMN,
        pairing_payload.as_slice(),
        super::pairing::MAX_PAIRING_STATE_PLAINTEXT_BYTES,
    )?;
    let pairing_token = super::pairing::pairing_row_token(
        &state.key_bundle,
        state.database_id,
        pairing.record.pairing_id,
        PairingInviteLifecycle::GrantCommitted,
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
        &sealed_pairing,
    )?;

    let authorization = bindings.authorization;
    let auth_primary =
        authorization_primary_key(authorization.device_route, authorization.grant_serial);
    let authorization_payload = encode_authorization_payload(
        &authorization.canonical_relay_grant,
        &authorization.canonical_install_frame,
        authorization.canonical_authorization.expose_secret(),
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
        authorization.device_route,
        authorization.grant_serial,
        AuthorizationLifecycle::Active,
        authorization.device_sign_fingerprint,
        authorization.grant_hash,
        authorization.authorization_hash,
        authorization.key_directory_revision,
        &sealed_authorization,
        authorization.created_at_ms,
        now_ms,
    )?;
    let next = next_ledger(
        &directory.ledger,
        pairing.sealed_state_bytes,
        sealed_pairing.len(),
        authorization.sealed_bytes,
        sealed_authorization.len(),
        bindings.install.sealed_bytes,
    )?;

    if transaction.execute(
        "UPDATE remote_pairings
         SET lifecycle = 'grantCommitted', state_changed_at_ms = ?1,
             sealed_state = ?2, sealed_state_bytes = ?3, metadata_token = ?4
         WHERE pairing_id = ?5 AND lifecycle = 'grantPreparing'
           AND grant_hash = ?6 AND response_hash = ?7 AND metadata_token = ?8",
        params![
            i64::try_from(now_ms).map_err(|_| RuntimeStoreError::TimeOutOfRange)?,
            &sealed_pairing,
            i64::try_from(sealed_pairing.len()).map_err(|_| RuntimeStoreError::PayloadTooLarge)?,
            &pairing_token[..],
            pairing.record.pairing_id.as_bytes().as_slice(),
            &grant_hash[..],
            &response_hash[..],
            &pairing.metadata_token[..],
        ],
    )? != 1
    {
        return Err(RuntimeStoreError::PairingConflict);
    }
    if transaction.execute(
        "UPDATE remote_authorization_ledger
         SET lifecycle = 'active', sealed_authorization = ?1,
             sealed_authorization_bytes = ?2, state_changed_at_ms = ?3, metadata_token = ?4
         WHERE device_route = ?5 AND grant_serial = ?6 AND lifecycle = 'grantPreparing'
           AND grant_hash = ?7 AND metadata_token = ?8",
        params![
            &sealed_authorization,
            i64::try_from(sealed_authorization.len())
                .map_err(|_| RuntimeStoreError::PayloadTooLarge)?,
            i64::try_from(now_ms).map_err(|_| RuntimeStoreError::TimeOutOfRange)?,
            &auth_token[..],
            authorization.device_route.as_bytes().as_slice(),
            super::sequence::encode_sequence(authorization.grant_serial.value()),
            &authorization.grant_hash[..],
            &authorization.metadata_token[..],
        ],
    )? != 1
    {
        return Err(RuntimeStoreError::PairingConflict);
    }
    let install = bindings.install;
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
    let _ = super::sqlite::update_runtime_ledger(
        &transaction,
        &state.key_bundle,
        state.database_id,
        &directory.ledger,
        &next,
    )?;
    config
        .fault_injector
        .before_operation(RuntimeStoreOperation::AcknowledgeGrantCommittedBeforeCommit)?;
    super::sqlite::commit_transaction(
        transaction,
        RuntimeCommitOperation::AcknowledgeGrantCommitted,
    )?;
    super::sqlite::latch_post_commit_capacity(state, config);
    config
        .fault_injector
        .before_operation(RuntimeStoreOperation::AcknowledgeGrantCommittedAfterCommit)
        .map_err(|_| RuntimeStoreError::CommitOutcomeUnknown {
            operation: RuntimeCommitOperation::AcknowledgeGrantCommitted,
        })?;
    let directory =
        super::pairing::load_directory(&state.connection, &state.key_bundle, state.database_id)?;
    let pairing = directory
        .pairings
        .iter()
        .find(|pairing| pairing.record.pairing_id == prepared.pairing_id)
        .ok_or(RuntimeStoreError::UnknownOrCorruptSchema)?;
    Ok(AcknowledgeGrantCommittedOutcome::Committed {
        recovery: recovery(&directory, pairing)?,
    })
}

pub(crate) fn list_grant_committed_recovery(
    connection: &rusqlite::Connection,
    key_bundle: &super::cipher::RuntimeKeyBundle,
    database_id: [u8; 16],
) -> Result<Vec<GrantCommittedRecovery>, RuntimeStoreError> {
    let directory = super::pairing::load_directory(connection, key_bundle, database_id)?;
    let recoveries = directory
        .pairings
        .iter()
        .filter(|pairing| pairing.record.lifecycle == PairingInviteLifecycle::GrantCommitted)
        .map(|pairing| recovery(&directory, pairing))
        .collect::<Result<Vec<_>, _>>()?;
    let retained = recoveries.iter().try_fold(
        recoveries
            .capacity()
            .checked_mul(std::mem::size_of::<GrantCommittedRecovery>())
            .ok_or(RuntimeStoreError::PayloadTooLarge)?,
        |total, recovery| {
            total
                .checked_add(recovery.retained_bytes()?)
                .ok_or(RuntimeStoreError::PayloadTooLarge)
        },
    )?;
    ensure_committed_recovery_budget(retained)?;
    Ok(recoveries)
}

fn ensure_committed_recovery_budget(retained: usize) -> Result<(), RuntimeStoreError> {
    if retained > MAX_COMMITTED_RECOVERY_RETAINED_BYTES {
        return Err(RuntimeStoreError::RecoveryPageTooLarge {
            projected_bytes: u64::try_from(retained).unwrap_or(u64::MAX),
            limit_bytes: MAX_COMMITTED_RECOVERY_RETAINED_BYTES as u64,
        });
    }
    Ok(())
}

pub(crate) fn prepare_for_dispatch(
    input: AcknowledgeGrantCommitted,
) -> Result<PreparedGrantCommitted, RuntimeStoreError> {
    prepare(input)
}

#[cfg(test)]
mod budget_tests {
    use super::*;

    #[test]
    fn committed_recovery_budget_accepts_exact_limit_and_rejects_plus_one() {
        ensure_committed_recovery_budget(MAX_COMMITTED_RECOVERY_RETAINED_BYTES)
            .expect("exact committed recovery limit is legal");
        let projected = MAX_COMMITTED_RECOVERY_RETAINED_BYTES + 1;
        assert!(matches!(
            ensure_committed_recovery_budget(projected),
            Err(RuntimeStoreError::RecoveryPageTooLarge {
                projected_bytes,
                limit_bytes,
            }) if projected_bytes == projected as u64
                && limit_bytes == MAX_COMMITTED_RECOVERY_RETAINED_BYTES as u64
        ));
    }
}
