//! `grantCommitted -> delivered` 的 endpoint receipt CAS 与 durable Close outbox。

use agentdeck_crypto::sha256;
use agentdeck_protocol::e2ee::{KeyDirectoryV1, PairInviteV1, PairResponseV1};
use agentdeck_protocol::relay_v2::{
    DeviceRouteId, GrantSerial, MachineRouteId, PairRouteId, RelayServerId, TrustEpoch,
};
use rusqlite::{TransactionBehavior, params};

use crate::remote::access::{PairResponseAccessBinding, VerifiedPairResponseReceipt};
use crate::runtime::model::{
    RuntimeCommitOperation, RuntimeStoreConfig, RuntimeStoreError, RuntimeStoreOperation,
};

use super::identity::{RuntimeId, RuntimeIdKind};
use super::key_transition::{KeyTransitionRecipient, PairingBootstrapInstallBinding};
use super::pairing::{AuthenticatedPairingRow, PairingDirectory, PairingInviteLifecycle};
use super::pairing_terminal::PairingCloseProjection;
use super::sqlite::{RuntimeLedger, RuntimeSqlite};

const PAIRING_TABLE: &[u8] = b"remote_pairings";
const PAIRING_COLUMN: &[u8] = b"sealed_state";
const MAX_DELIVERY_RECEIPT_BYTES: usize = 64 * 1024;

/// 只可从密码学层产出的 verified receipt 冻结；字段不公开且不实现 `Clone`。
pub(crate) struct AcknowledgePairResponseReceived {
    pairing_id: RuntimeId,
    canonical_receipt: Vec<u8>,
    receipt_hash: [u8; 32],
    request_hash: [u8; 32],
    grant_hash: [u8; 32],
    response_hash: [u8; 32],
    relay_server_id: RelayServerId,
    pair_route: PairRouteId,
    invite_hash: [u8; 32],
    expiry_ms: u64,
    machine_route: MachineRouteId,
    device_route: DeviceRouteId,
    grant_serial: GrantSerial,
    root_trust_epoch: TrustEpoch,
    device_sign_fingerprint: [u8; 32],
    info_sha256: [u8; 32],
    aad_sha256: [u8; 32],
    tbs_sha256: [u8; 32],
}

impl std::fmt::Debug for AcknowledgePairResponseReceived {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter.write_str("AcknowledgePairResponseReceived([REDACTED])")
    }
}

impl AcknowledgePairResponseReceived {
    #[must_use]
    pub(crate) fn new(pairing_id: RuntimeId, proof: &VerifiedPairResponseReceipt) -> Self {
        let canonical_receipt = proof.canonical_receipt().to_vec();
        Self {
            pairing_id,
            receipt_hash: sha256(&canonical_receipt),
            canonical_receipt,
            request_hash: proof.request_hash(),
            grant_hash: proof.grant_hash(),
            response_hash: proof.response_hash(),
            relay_server_id: proof.relay_server_id(),
            pair_route: proof.pair_route(),
            invite_hash: proof.invite_hash(),
            expiry_ms: proof.expiry_ms(),
            machine_route: proof.machine_route(),
            device_route: proof.device_route(),
            grant_serial: proof.grant_serial(),
            root_trust_epoch: proof.root_trust_epoch(),
            device_sign_fingerprint: proof.device_sign_fingerprint(),
            info_sha256: proof.info_sha256(),
            aad_sha256: proof.aad_sha256(),
            tbs_sha256: proof.tbs_sha256(),
        }
    }

    pub(crate) fn retained_bytes(&self) -> usize {
        self.canonical_receipt.capacity()
    }
}

#[derive(Debug)]
pub(crate) enum AcknowledgePairResponseReceivedOutcome {
    Delivered { close: PairingCloseProjection },
    Replayed { close: PairingCloseProjection },
}

fn validate_proof(
    pairing: &AuthenticatedPairingRow,
    input: &AcknowledgePairResponseReceived,
) -> Result<(), RuntimeStoreError> {
    if input.pairing_id != pairing.record.pairing_id
        || input.canonical_receipt.is_empty()
        || input.canonical_receipt.len() > MAX_DELIVERY_RECEIPT_BYTES
        || input.receipt_hash == [0; 32]
        || sha256(&input.canonical_receipt) != input.receipt_hash
    {
        return Err(RuntimeStoreError::PairingConflict);
    }
    let invite =
        PairInviteV1::from_canonical_bytes(pairing.record.canonical_invite.expose_secret())
            .map_err(|_| RuntimeStoreError::UnknownOrCorruptSchema)?;
    let install = pairing
        .record
        .canonical_install_frame
        .as_deref()
        .ok_or(RuntimeStoreError::UnknownOrCorruptSchema)?;
    let (grant, observed_grant_hash) = super::pairing_grant::exact_install_frame(install)?;
    let response = PairResponseV1::from_canonical_bytes(
        pairing
            .record
            .canonical_pair_response
            .as_ref()
            .ok_or(RuntimeStoreError::UnknownOrCorruptSchema)?
            .expose_secret(),
    )
    .map_err(|_| RuntimeStoreError::UnknownOrCorruptSchema)?;
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
    if grant.canonical_bytes()
        != pairing
            .record
            .canonical_relay_grant
            .as_deref()
            .ok_or(RuntimeStoreError::UnknownOrCorruptSchema)?
        || observed_grant_hash != grant_hash
        || response.canonical_sha256().ok() != Some(response_hash)
    {
        return Err(RuntimeStoreError::UnknownOrCorruptSchema);
    }
    let binding = PairResponseAccessBinding::from_frozen(&invite, request_hash, &grant, &response)
        .map_err(|_| RuntimeStoreError::PairingConflict)?;
    let verified = binding
        .verify_signed_receipt(&input.canonical_receipt)
        .map_err(|_| RuntimeStoreError::PairingConflict)?;
    let invite_hash = invite
        .canonical_sha256()
        .map_err(|_| RuntimeStoreError::UnknownOrCorruptSchema)?;
    let axes_match = input.request_hash == request_hash
        && input.request_hash == verified.request_hash()
        && input.grant_hash == grant_hash
        && input.grant_hash == verified.grant_hash()
        && input.response_hash == response_hash
        && input.response_hash == verified.response_hash()
        && input.relay_server_id.as_bytes() == &pairing.record.relay_server_id
        && input.relay_server_id == verified.relay_server_id()
        && input.pair_route.as_bytes() == pairing.record.pair_route.as_bytes()
        && input.pair_route == verified.pair_route()
        && input.invite_hash == invite_hash
        && input.invite_hash == verified.invite_hash()
        && input.expiry_ms == pairing.record.expires_at_ms
        && input.expiry_ms == verified.expiry_ms()
        && input.machine_route.as_bytes() == &pairing.record.machine_route
        && input.machine_route == grant.machine_route
        && input.machine_route == verified.machine_route()
        && input.device_route == grant.device_route
        && input.device_route == verified.device_route()
        && input.grant_serial == grant.grant_serial
        && input.grant_serial == verified.grant_serial()
        && input.root_trust_epoch == grant.trust_epoch
        && input.root_trust_epoch == verified.root_trust_epoch()
        && input.device_sign_fingerprint
            == pairing
                .record
                .device_sign_fingerprint
                .ok_or(RuntimeStoreError::UnknownOrCorruptSchema)?
        && input.device_sign_fingerprint == verified.device_sign_fingerprint()
        && input.info_sha256 == verified.info_sha256()
        && input.aad_sha256 == verified.aad_sha256()
        && input.tbs_sha256 == verified.tbs_sha256()
        && input.canonical_receipt == verified.canonical_receipt();
    if !axes_match {
        return Err(RuntimeStoreError::PairingConflict);
    }
    Ok(())
}

pub(super) fn bootstrap_directory(
    pairing: &AuthenticatedPairingRow,
) -> Result<(KeyDirectoryV1, &[u8]), RuntimeStoreError> {
    let canonical = pairing
        .record
        .canonical_key_directory_view
        .as_ref()
        .ok_or(RuntimeStoreError::UnknownOrCorruptSchema)?
        .expose_secret();
    let directory = KeyDirectoryV1::from_canonical_bytes(canonical)
        .map_err(|_| RuntimeStoreError::UnknownOrCorruptSchema)?;
    if directory
        .canonical_bytes()
        .map_err(|_| RuntimeStoreError::UnknownOrCorruptSchema)?
        .as_slice()
        != canonical
    {
        return Err(RuntimeStoreError::UnknownOrCorruptSchema);
    }
    Ok((directory, canonical))
}

fn bootstrap_binding(
    pairing: &AuthenticatedPairingRow,
    input: &AcknowledgePairResponseReceived,
    received_at_ms: u64,
) -> Result<PairingBootstrapInstallBinding, RuntimeStoreError> {
    let (directory, canonical_directory) = bootstrap_directory(pairing)?;
    if directory.revision.value() == 0
        || directory
            .entries
            .first()
            .is_none_or(|entry| entry.device_route != input.device_route)
    {
        return Err(RuntimeStoreError::PairingConflict);
    }
    Ok(PairingBootstrapInstallBinding {
        pairing_id: *pairing.record.pairing_id.as_bytes(),
        relay_server_id: *input.relay_server_id.as_bytes(),
        pair_route: *input.pair_route.as_bytes(),
        machine_route: *input.machine_route.as_bytes(),
        device_route: *input.device_route.as_bytes(),
        grant_serial: input.grant_serial.value(),
        root_trust_epoch: input.root_trust_epoch.value(),
        key_revision: directory.revision.value(),
        expiry_ms: input.expiry_ms,
        invite_hash: input.invite_hash,
        request_hash: input.request_hash,
        grant_hash: input.grant_hash,
        response_hash: input.response_hash,
        receipt_hash: input.receipt_hash,
        device_sign_fingerprint: input.device_sign_fingerprint,
        info_sha256: input.info_sha256,
        aad_sha256: input.aad_sha256,
        tbs_sha256: input.tbs_sha256,
        key_directory_hash: sha256(canonical_directory),
        global_key_state_hash: pairing
            .record
            .global_key_state_hash
            .ok_or(RuntimeStoreError::UnknownOrCorruptSchema)?,
        key_slot_digest: super::key_transition::key_directory_slot_digest(&directory)?,
        canonical_receipt: input.canonical_receipt.clone(),
        received_at_ms,
    })
}

#[cfg(test)]
pub(super) fn bootstrap_binding_for_test(
    pairing: &AuthenticatedPairingRow,
    input: &AcknowledgePairResponseReceived,
    received_at_ms: u64,
) -> Result<PairingBootstrapInstallBinding, RuntimeStoreError> {
    bootstrap_binding(pairing, input, received_at_ms)
}

pub(super) fn ensure_durable_bootstrap_install_proof(
    connection: &rusqlite::Connection,
    key_bundle: &super::cipher::RuntimeKeyBundle,
    database_id: [u8; 16],
    pairing: &AuthenticatedPairingRow,
) -> Result<super::key_transition::PairingBootstrapInstallProofRead, RuntimeStoreError> {
    if pairing.record.lifecycle != PairingInviteLifecycle::Delivered
        || pairing
            .record
            .delivery_receipt_hash
            .is_none_or(|hash| hash == [0; 32])
    {
        return Err(RuntimeStoreError::InvalidStateTransition);
    }
    let (directory, _) = bootstrap_directory(pairing)?;
    let response = PairResponseV1::from_canonical_bytes(
        pairing
            .record
            .canonical_pair_response
            .as_ref()
            .ok_or(RuntimeStoreError::UnknownOrCorruptSchema)?
            .expose_secret(),
    )
    .map_err(|_| RuntimeStoreError::UnknownOrCorruptSchema)?;
    let plaintext_device = directory
        .entries
        .first()
        .ok_or(RuntimeStoreError::UnknownOrCorruptSchema)?
        .device_route;
    let install = pairing
        .record
        .canonical_install_frame
        .as_deref()
        .ok_or(RuntimeStoreError::UnknownOrCorruptSchema)?;
    let (grant, _) = super::pairing_grant::exact_install_frame(install)?;
    if grant.device_route != plaintext_device {
        return Err(RuntimeStoreError::UnknownOrCorruptSchema);
    }
    let proof = super::key_transition::load_pairing_bootstrap_install_proof(
        connection,
        key_bundle,
        database_id,
        KeyTransitionRecipient {
            device_route: *grant.device_route.as_bytes(),
            grant_serial: grant.grant_serial.value(),
        },
        directory.revision.value(),
    )?;
    let super::key_transition::PairingBootstrapInstallProofRead::Verified(proof) = proof else {
        return Ok(
            super::key_transition::PairingBootstrapInstallProofRead::LegacyTransitionCollected,
        );
    };
    let binding = &proof.binding;
    if pairing.record.delivery_receipt_hash != Some(binding.receipt_hash)
        || pairing.record.state_changed_at_ms != binding.received_at_ms
    {
        return Err(RuntimeStoreError::PairingConflict);
    }
    let input = AcknowledgePairResponseReceived {
        pairing_id: pairing.record.pairing_id,
        canonical_receipt: binding.canonical_receipt.clone(),
        receipt_hash: binding.receipt_hash,
        request_hash: binding.request_hash,
        grant_hash: binding.grant_hash,
        response_hash: binding.response_hash,
        relay_server_id: RelayServerId::from_bytes(binding.relay_server_id),
        pair_route: PairRouteId::from_bytes(binding.pair_route),
        invite_hash: binding.invite_hash,
        expiry_ms: binding.expiry_ms,
        machine_route: MachineRouteId::from_bytes(binding.machine_route),
        device_route: DeviceRouteId::from_bytes(binding.device_route),
        grant_serial: GrantSerial::new(binding.grant_serial),
        root_trust_epoch: TrustEpoch::new(binding.root_trust_epoch),
        device_sign_fingerprint: binding.device_sign_fingerprint,
        info_sha256: binding.info_sha256,
        aad_sha256: binding.aad_sha256,
        tbs_sha256: binding.tbs_sha256,
    };
    validate_proof(pairing, &input)?;
    if response.canonical_sha256().ok() != Some(binding.response_hash)
        || bootstrap_binding(pairing, &input, pairing.record.state_changed_at_ms)? != *binding
    {
        return Err(RuntimeStoreError::PairingConflict);
    }
    Ok(super::key_transition::PairingBootstrapInstallProofRead::Verified(proof))
}

fn classify_existing(
    directory: &PairingDirectory,
    input: &AcknowledgePairResponseReceived,
) -> Result<Option<AcknowledgePairResponseReceivedOutcome>, RuntimeStoreError> {
    let pairing = directory
        .pairings
        .iter()
        .find(|pairing| pairing.record.pairing_id == input.pairing_id)
        .ok_or(RuntimeStoreError::PairingConflict)?;
    validate_proof(pairing, input)?;
    match pairing.record.lifecycle {
        PairingInviteLifecycle::GrantCommitted => {
            if pairing.record.delivery_receipt_hash.is_some()
                || directory
                    .terminal
                    .close_projection(input.pairing_id)
                    .is_some()
            {
                return Err(RuntimeStoreError::UnknownOrCorruptSchema);
            }
            Ok(None)
        }
        PairingInviteLifecycle::Delivered => {
            if pairing.record.delivery_receipt_hash != Some(input.receipt_hash) {
                return Err(RuntimeStoreError::PairingConflict);
            }
            let close = directory
                .terminal
                .close_projection(input.pairing_id)
                .ok_or(RuntimeStoreError::UnknownOrCorruptSchema)?;
            Ok(Some(AcknowledgePairResponseReceivedOutcome::Replayed {
                close,
            }))
        }
        _ => Err(RuntimeStoreError::PairingConflict),
    }
}

fn next_ledger(
    ledger: &RuntimeLedger,
    previous_pairing_bytes: u64,
    next_pairing_bytes: usize,
    close_bytes: usize,
) -> Result<RuntimeLedger, RuntimeStoreError> {
    let next_pairing_bytes =
        u64::try_from(next_pairing_bytes).map_err(|_| RuntimeStoreError::PayloadTooLarge)?;
    let close_bytes = u64::try_from(close_bytes).map_err(|_| RuntimeStoreError::PayloadTooLarge)?;
    let mut next = ledger.clone();
    next.remote_pairing_sealed_bytes = next
        .remote_pairing_sealed_bytes
        .checked_sub(previous_pairing_bytes)
        .and_then(|bytes| bytes.checked_add(next_pairing_bytes))
        .ok_or(RuntimeStoreError::CapacityArithmeticOverflow {
            field: "remote_pairing_sealed_bytes",
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
        .checked_add(close_bytes)
        .ok_or(RuntimeStoreError::CapacityArithmeticOverflow {
            field: "remote_control_outbox_sealed_bytes",
        })?;
    if next.remote_pairing_sealed_bytes > super::pairing::MAX_PAIRING_SEALED_BYTES
        || next.remote_control_outbox_count > super::pairing::MAX_CONTROL_OUTBOX
        || next.remote_control_outbox_sealed_bytes > super::pairing::MAX_CONTROL_OUTBOX_SEALED_BYTES
    {
        return Err(RuntimeStoreError::PairingLimit);
    }
    Ok(next)
}

pub(crate) fn acknowledge_pair_response_received(
    state: &mut RuntimeSqlite,
    config: &RuntimeStoreConfig,
    input: AcknowledgePairResponseReceived,
    now_ms: u64,
) -> Result<AcknowledgePairResponseReceivedOutcome, RuntimeStoreError> {
    if input.pairing_id.kind() != RuntimeIdKind::Pairing {
        return Err(RuntimeStoreError::IdKindMismatch {
            expected: RuntimeIdKind::Pairing,
            actual: input.pairing_id.kind(),
        });
    }
    let directory =
        super::pairing::load_directory(&state.connection, &state.key_bundle, state.database_id)?;
    let replay_needs_backfill = if let Some(replayed) = classify_existing(&directory, &input)? {
        let pairing = directory
            .pairings
            .iter()
            .find(|pairing| pairing.record.pairing_id == input.pairing_id)
            .ok_or(RuntimeStoreError::PairingConflict)?;
        match ensure_durable_bootstrap_install_proof(
            &state.connection,
            &state.key_bundle,
            state.database_id,
            pairing,
        ) {
            Ok(_) => return Ok(replayed),
            Err(RuntimeStoreError::InvalidStateTransition) => true,
            Err(error) => return Err(error),
        }
    } else {
        false
    };
    let pairing = directory
        .pairings
        .iter()
        .find(|pairing| pairing.record.pairing_id == input.pairing_id)
        .ok_or(RuntimeStoreError::PairingConflict)?;
    if !replay_needs_backfill {
        validate_delivery_time(pairing, now_ms)?;
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
    if let Some(replayed) = classify_existing(&directory, &input)? {
        let pairing = directory
            .pairings
            .iter()
            .find(|pairing| pairing.record.pairing_id == input.pairing_id)
            .ok_or(RuntimeStoreError::PairingConflict)?;
        match ensure_durable_bootstrap_install_proof(
            &transaction,
            &state.key_bundle,
            state.database_id,
            pairing,
        ) {
            Ok(_) => return Ok(replayed),
            Err(RuntimeStoreError::InvalidStateTransition) => {}
            Err(error) => return Err(error),
        }
        let mut next = directory.ledger.clone();
        let binding = bootstrap_binding(pairing, &input, pairing.record.state_changed_at_ms)?;
        let _ = super::key_transition::reconcile_pairing_bootstrap_install_proof_in_transaction(
            &transaction,
            &state.key_bundle,
            state.database_id,
            &mut next,
            binding,
            super::key_transition::PairingBootstrapProofReconcileMode::LegacyReplayBackfill,
        )?;
        let _ = super::sqlite::update_runtime_ledger(
            &transaction,
            &state.key_bundle,
            state.database_id,
            &directory.ledger,
            &next,
        )?;
        config
            .fault_injector
            .before_operation(RuntimeStoreOperation::AcknowledgePairResponseReceivedBeforeCommit)?;
        super::sqlite::commit_transaction(
            transaction,
            RuntimeCommitOperation::AcknowledgePairResponseReceived,
        )?;
        super::sqlite::latch_post_commit_capacity(state, config);
        config
            .fault_injector
            .before_operation(RuntimeStoreOperation::AcknowledgePairResponseReceivedAfterCommit)
            .map_err(|_| RuntimeStoreError::CommitOutcomeUnknown {
                operation: RuntimeCommitOperation::AcknowledgePairResponseReceived,
            })?;
        let directory = super::pairing::load_directory(
            &state.connection,
            &state.key_bundle,
            state.database_id,
        )?;
        let Some(replayed) = classify_existing(&directory, &input)? else {
            return Err(RuntimeStoreError::UnknownOrCorruptSchema);
        };
        let pairing = directory
            .pairings
            .iter()
            .find(|pairing| pairing.record.pairing_id == input.pairing_id)
            .ok_or(RuntimeStoreError::UnknownOrCorruptSchema)?;
        let proof = ensure_durable_bootstrap_install_proof(
            &state.connection,
            &state.key_bundle,
            state.database_id,
            pairing,
        )?;
        if !matches!(
            proof,
            super::key_transition::PairingBootstrapInstallProofRead::Verified(_)
        ) {
            return Err(RuntimeStoreError::UnknownOrCorruptSchema);
        }
        return Ok(replayed);
    }
    let pairing = directory
        .pairings
        .iter()
        .find(|pairing| pairing.record.pairing_id == input.pairing_id)
        .ok_or(RuntimeStoreError::PairingConflict)?;
    validate_delivery_time(pairing, now_ms)?;

    let payload = super::pairing::encode_delivered_payload(pairing, input.receipt_hash)?;
    let sealed_pairing = super::pairing_grant::seal_row(
        &state.key_bundle,
        state.database_id,
        PAIRING_TABLE,
        pairing.record.pairing_id.as_bytes(),
        PAIRING_COLUMN,
        payload.as_slice(),
        super::pairing::MAX_PAIRING_STATE_PLAINTEXT_BYTES,
    )?;
    let pairing_token = super::pairing::pairing_row_token(
        &state.key_bundle,
        state.database_id,
        pairing.record.pairing_id,
        PairingInviteLifecycle::Delivered,
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

    let close_frame = super::pairing_terminal::frozen_close_frame(pairing);
    let frame_hash = sha256(&close_frame);
    if frame_hash == [0; 32] {
        return Err(RuntimeStoreError::UnknownOrCorruptSchema);
    }
    let outbox_id = super::pairing::allocate_id(&transaction, config, RuntimeIdKind::RemoteOutbox)?;
    let sealed_close = super::pairing_terminal::seal_close_frame(
        &state.key_bundle,
        state.database_id,
        outbox_id,
        &close_frame,
    )?;
    let operation_key =
        super::pairing_terminal::close_operation_key(&state.key_bundle, input.pairing_id)?;
    let close_token = super::pairing_terminal::close_outbox_token(
        &state.key_bundle,
        state.database_id,
        outbox_id,
        operation_key,
        input.pairing_id,
        frame_hash,
        &sealed_close,
        now_ms,
        now_ms,
    )?;
    let mut next = next_ledger(
        &directory.ledger,
        pairing.sealed_state_bytes,
        sealed_pairing.len(),
        sealed_close.len(),
    )?;
    let binding = bootstrap_binding(pairing, &input, now_ms)?;
    let _ = super::key_transition::reconcile_pairing_bootstrap_install_proof_in_transaction(
        &transaction,
        &state.key_bundle,
        state.database_id,
        &mut next,
        binding,
        super::key_transition::PairingBootstrapProofReconcileMode::FreshDelivery,
    )?;

    if transaction.execute(
        "UPDATE remote_pairings
         SET lifecycle = 'delivered', state_changed_at_ms = ?1,
             sealed_state = ?2, sealed_state_bytes = ?3, metadata_token = ?4
         WHERE pairing_id = ?5 AND lifecycle = 'grantCommitted'
           AND request_hash = ?6 AND grant_hash = ?7 AND response_hash = ?8
           AND metadata_token = ?9",
        params![
            i64::try_from(now_ms).map_err(|_| RuntimeStoreError::TimeOutOfRange)?,
            &sealed_pairing,
            i64::try_from(sealed_pairing.len()).map_err(|_| RuntimeStoreError::PayloadTooLarge)?,
            &pairing_token[..],
            input.pairing_id.as_bytes().as_slice(),
            &input.request_hash[..],
            &input.grant_hash[..],
            &input.response_hash[..],
            &pairing.metadata_token[..],
        ],
    )? != 1
    {
        return Err(RuntimeStoreError::PairingConflict);
    }
    if transaction.execute(
        "INSERT INTO remote_control_outbox (
             outbox_id, operation_kind, operation_key, lifecycle, database_id, pairing_id,
             device_route, grant_serial, frame_hash, sealed_frame, sealed_frame_bytes,
             terminal_hash, sealed_terminal, sealed_terminal_bytes, created_at_ms,
             state_changed_at_ms, metadata_token
         ) VALUES (?1, 'closePairRoute', ?2, 'prepared', ?3, ?4,
                   NULL, NULL, ?5, ?6, ?7, NULL, NULL, NULL, ?8, ?8, ?9)",
        params![
            outbox_id.as_bytes().as_slice(),
            &operation_key[..],
            &state.database_id[..],
            input.pairing_id.as_bytes().as_slice(),
            &frame_hash[..],
            &sealed_close,
            i64::try_from(sealed_close.len()).map_err(|_| RuntimeStoreError::PayloadTooLarge)?,
            i64::try_from(now_ms).map_err(|_| RuntimeStoreError::TimeOutOfRange)?,
            &close_token[..],
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
        .before_operation(RuntimeStoreOperation::AcknowledgePairResponseReceivedBeforeCommit)?;
    super::sqlite::commit_transaction(
        transaction,
        RuntimeCommitOperation::AcknowledgePairResponseReceived,
    )?;
    super::sqlite::latch_post_commit_capacity(state, config);
    config
        .fault_injector
        .before_operation(RuntimeStoreOperation::AcknowledgePairResponseReceivedAfterCommit)
        .map_err(|_| RuntimeStoreError::CommitOutcomeUnknown {
            operation: RuntimeCommitOperation::AcknowledgePairResponseReceived,
        })?;
    let directory =
        super::pairing::load_directory(&state.connection, &state.key_bundle, state.database_id)?;
    let Some(AcknowledgePairResponseReceivedOutcome::Replayed { close }) =
        classify_existing(&directory, &input)?
    else {
        return Err(RuntimeStoreError::UnknownOrCorruptSchema);
    };
    let pairing = directory
        .pairings
        .iter()
        .find(|pairing| pairing.record.pairing_id == input.pairing_id)
        .ok_or(RuntimeStoreError::UnknownOrCorruptSchema)?;
    let proof = ensure_durable_bootstrap_install_proof(
        &state.connection,
        &state.key_bundle,
        state.database_id,
        pairing,
    )?;
    if !matches!(
        proof,
        super::key_transition::PairingBootstrapInstallProofRead::Verified(_)
    ) {
        return Err(RuntimeStoreError::UnknownOrCorruptSchema);
    }
    Ok(AcknowledgePairResponseReceivedOutcome::Delivered { close })
}

fn validate_delivery_time(
    pairing: &AuthenticatedPairingRow,
    now_ms: u64,
) -> Result<(), RuntimeStoreError> {
    if now_ms < pairing.record.state_changed_at_ms {
        return Err(RuntimeStoreError::ClockRegressed {
            persisted_ms: pairing.record.state_changed_at_ms,
            observed_ms: now_ms,
        });
    }
    if now_ms >= pairing.record.expires_at_ms {
        return Err(RuntimeStoreError::PairingExpired);
    }
    Ok(())
}
