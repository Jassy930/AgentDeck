//! Runtime v9 authenticated machine enrollment lifecycle。
//!
//! 本模块只拥有 durable enrollment state；不依赖 daemon remote transport，也不发起网络请求。

use agentdeck_crypto::{
    SignatureBytes, ValidatedRelayReceiptVerifyKey, VerifyingKey, sha256,
    verify_relay_admin_purge_receipt, verify_tbs,
};
use agentdeck_protocol::relay_v2::frame::{RetireMachine, RetirementCommitted};
use agentdeck_protocol::relay_v2::{
    CertRole, Digest32, ENROLLMENT_BUNDLE_VERSION, EnrollmentBundleV2, EnrollmentCode,
    MachineEnrollmentRequestV1, MachineEnrollmentResponseV1, MachineRouteId, PublicKeyBytes,
    RELAY_PROTOCOL_VERSION, RelayAdminPurgeReceiptExpectationV1, RelayAdminPurgeReceiptV1,
    RelayFrameBody, RelayReceiptVerifyKeyV1, RelayServerId, RootKeyId, SignedCertificate,
    TrustEpoch, decode, encode, enrollment_receipt_hash, purge_request_hash,
};
use rusqlite::{Connection, OptionalExtension, Transaction, TransactionBehavior, params};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use url::Url;
use zeroize::Zeroizing;

use crate::runtime::model::{
    ActivateMachineEnrollmentOutcome, ActiveMachineEnrollmentState,
    ConfirmMachinePurgeReadbackAbsentOutcome, FinalizeMachineLocalDeletionOutcome,
    LocalDeletedMachineEnrollmentState, MachineCleanupWitnessV1,
    MachineEnrollmentConnectionMaterial, MachineEnrollmentState, MachineIdentityBinding,
    MachineIdentityLifecycle, MachinePurgeReadbackProof, MachineRemoteLifecycle,
    MachineRemoteStateRecord, MachineRetirementRequestMaterial, MachineRetirementTerminalMaterial,
    MachineRootLostPurgeMaterial, MachineTrustResetKind, PrepareMachineEnrollmentOutcome,
    PrepareMachineRetirementOutcome, PreparedMachineEnrollmentState,
    PurgeReadbackAbsentMachineEnrollmentState, RecordMachineRetirementTerminalOutcome,
    RecordRootLostMachinePurgeOutcome, RecordValidatedEnrollmentResponseOutcome,
    RelayCommittedMachineEnrollmentState, RetirePendingMachineEnrollmentState,
    RuntimeCommitOperation, RuntimeStoreConfig, RuntimeStoreError, RuntimeStoreOperation,
    ValidatedMachineEnrollmentState,
};

use super::cipher::{RowAad, RuntimeKeyBundle};
use super::sqlite::{RuntimeLedger, RuntimeSqlite};

const PAYLOAD_VERSION: u8 = 1;
const MAX_STATE_PLAINTEXT_BYTES: usize = 64 * 1024;
const ROW_METADATA_DOMAIN: &[u8] = b"machine.remote.metadata.v1";
const ROW_PRIMARY_KEY: &[u8] = b"singleton=1";
const ROW_COLUMN: &[u8] = b"sealed_state";

/// Trust reset 的临时 Store 栅栏。
///
/// P4.3 coordinator 完成 terminal close/revoke/scrub 前，任何仍有授权力或秘密材料的
/// v10 remote row 都必须阻止 machine trust lifecycle 前进。无秘密的 pairing receipt
/// tombstone 刻意不在这里：它只用于防止 pairing ID/route 复用，不具有授权力。
fn require_remote_security_state_empty(
    connection: &Connection,
    key_bundle: &RuntimeKeyBundle,
    database_id: [u8; 16],
) -> Result<(), RuntimeStoreError> {
    let ledger = super::sqlite::load_runtime_ledger(connection, key_bundle, database_id)?;
    let physical: (i64, i64, i64, i64) = connection.query_row(
        "SELECT (SELECT COUNT(*) FROM remote_pairings),
                (SELECT COUNT(*) FROM remote_control_outbox),
                (SELECT COUNT(*) FROM remote_authorization_ledger),
                (SELECT COUNT(*) FROM remote_key_directory)",
        [],
        |row| Ok((row.get(0)?, row.get(1)?, row.get(2)?, row.get(3)?)),
    )?;
    let ledger_occupied = ledger.remote_pairing_count != 0
        || ledger.remote_pairing_sealed_bytes != 0
        || ledger.remote_authorization_count != 0
        || ledger.remote_authorization_preparing_count != 0
        || ledger.remote_authorization_active_count != 0
        || ledger.remote_authorization_revoking_count != 0
        || ledger.remote_authorization_revoked_count != 0
        || ledger.remote_authorization_sealed_bytes != 0
        || ledger.remote_key_directory_count != 0
        || ledger.remote_key_directory_sealed_bytes != 0
        || ledger.remote_control_outbox_count != 0
        || ledger.remote_control_outbox_pending_count != 0
        || ledger.remote_control_outbox_acknowledged_count != 0
        || ledger.remote_control_outbox_sealed_bytes != 0;
    if physical != (0, 0, 0, 0) || ledger_occupied {
        return Err(RuntimeStoreError::MachineRemoteConflict);
    }
    Ok(())
}

#[derive(Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct StoredConnectionV1 {
    public_wss_url: String,
    relay_server_id: RelayServerId,
    receipt_verify_key: RelayReceiptVerifyKeyV1,
    spki_pins: Vec<Digest32>,
    expires_at_ms: u64,
}

#[derive(Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct StoredBindingV1 {
    root_key_id: [u8; 16],
    trust_epoch: u64,
    link_generation: u64,
    data_generation: u64,
    key_directory_revision: u64,
    root_public_key: [u8; 32],
    root_fingerprint: [u8; 32],
    machine_hpke_public_key: [u8; 32],
    machine_hpke_fingerprint: [u8; 32],
    link_sign_public_key: [u8; 32],
    link_sign_fingerprint: [u8; 32],
    data_sign_public_key: [u8; 32],
    data_sign_fingerprint: [u8; 32],
}

impl From<MachineIdentityBinding> for StoredBindingV1 {
    fn from(value: MachineIdentityBinding) -> Self {
        Self {
            root_key_id: value.root_key_id,
            trust_epoch: value.trust_epoch,
            link_generation: value.link_generation,
            data_generation: value.data_generation,
            key_directory_revision: value.key_directory_revision,
            root_public_key: value.root_public_key,
            root_fingerprint: value.root_fingerprint,
            machine_hpke_public_key: value.machine_hpke_public_key,
            machine_hpke_fingerprint: value.machine_hpke_fingerprint,
            link_sign_public_key: value.link_sign_public_key,
            link_sign_fingerprint: value.link_sign_fingerprint,
            data_sign_public_key: value.data_sign_public_key,
            data_sign_fingerprint: value.data_sign_fingerprint,
        }
    }
}

impl From<StoredBindingV1> for MachineIdentityBinding {
    fn from(value: StoredBindingV1) -> Self {
        Self {
            root_key_id: value.root_key_id,
            trust_epoch: value.trust_epoch,
            link_generation: value.link_generation,
            data_generation: value.data_generation,
            key_directory_revision: value.key_directory_revision,
            root_public_key: value.root_public_key,
            root_fingerprint: value.root_fingerprint,
            machine_hpke_public_key: value.machine_hpke_public_key,
            machine_hpke_fingerprint: value.machine_hpke_fingerprint,
            link_sign_public_key: value.link_sign_public_key,
            link_sign_fingerprint: value.link_sign_fingerprint,
            data_sign_public_key: value.data_sign_public_key,
            data_sign_fingerprint: value.data_sign_fingerprint,
        }
    }
}

#[derive(PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct PreparedPayloadV1 {
    version: u8,
    connection: StoredConnectionV1,
    code: EnrollmentCode,
    machine_route: MachineRouteId,
    binding: StoredBindingV1,
    link_cert: SignedCertificate,
    data_cert: SignedCertificate,
}

#[derive(PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct ValidatedPayloadV1 {
    version: u8,
    prepared: PreparedPayloadV1,
    response: MachineEnrollmentResponseV1,
}

#[derive(PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct ActivePayloadV1 {
    version: u8,
    connection: StoredConnectionV1,
    machine_route: MachineRouteId,
    binding: StoredBindingV1,
    link_cert: SignedCertificate,
    data_cert: SignedCertificate,
    prepare_input_hash: [u8; 32],
    response: MachineEnrollmentResponseV1,
}

#[derive(PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct RetirePendingPayloadV1 {
    version: u8,
    active: ActivePayloadV1,
    retirement: RetireMachine,
    retirement_bytes: Vec<u8>,
    retirement_hash: [u8; 32],
}

#[derive(PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct RelayCommittedPayloadV1 {
    version: u8,
    pending: RetirePendingPayloadV1,
    terminal: RetirementCommitted,
    terminal_frame_bytes: Vec<u8>,
    terminal_frame_hash: [u8; 32],
}

#[derive(PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct RootPresentPurgePayloadV1 {
    version: u8,
    committed: RelayCommittedPayloadV1,
}

#[derive(PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct RootLostPurgePayloadV1 {
    version: u8,
    active: ActivePayloadV1,
    receipt: RelayAdminPurgeReceiptV1,
    receipt_bytes: Vec<u8>,
    receipt_hash: [u8; 32],
}

#[derive(Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
enum StoredResetKindV1 {
    RootPresent,
    RootLost,
}

impl From<MachineTrustResetKind> for StoredResetKindV1 {
    fn from(value: MachineTrustResetKind) -> Self {
        match value {
            MachineTrustResetKind::RootPresent => Self::RootPresent,
            MachineTrustResetKind::RootLost => Self::RootLost,
        }
    }
}

impl From<StoredResetKindV1> for MachineTrustResetKind {
    fn from(value: StoredResetKindV1) -> Self {
        match value {
            StoredResetKindV1::RootPresent => Self::RootPresent,
            StoredResetKindV1::RootLost => Self::RootLost,
        }
    }
}

#[derive(PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct LocalDeletedPayloadV1 {
    version: u8,
    reset_kind: StoredResetKindV1,
    relay_server_id: RelayServerId,
    machine_route: MachineRouteId,
    root_key_id: RootKeyId,
    root_fingerprint: [u8; 32],
    trust_epoch: TrustEpoch,
    previous_prepare_input_hash: [u8; 32],
    purge_proof_hash: [u8; 32],
    cleanup_witness_hash: [u8; 32],
}

enum PurgeReadbackPayload {
    RootPresent(RootPresentPurgePayloadV1),
    RootLost(RootLostPurgePayloadV1),
}

enum LoadedPayload {
    Prepared(PreparedPayloadV1),
    Validated(ValidatedPayloadV1),
    Active(ActivePayloadV1),
    RetirePending(RetirePendingPayloadV1),
    RelayCommitted(RelayCommittedPayloadV1),
    PurgeReadbackAbsent(PurgeReadbackPayload),
    LocalDeleted(LocalDeletedPayloadV1),
}

pub(super) struct PreparedMachineEnrollmentWrite {
    payload: PreparedPayloadV1,
    canonical: Zeroizing<Vec<u8>>,
    prepare_input_hash: [u8; 32],
    request_hash: [u8; 32],
    receipt_verify_key_hash: [u8; 32],
}

impl std::fmt::Debug for PreparedMachineEnrollmentWrite {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter.write_str("PreparedMachineEnrollmentWrite([REDACTED])")
    }
}

impl PreparedMachineEnrollmentWrite {
    pub(super) fn retained_capacity(&self) -> usize {
        self.canonical.capacity()
            + self.payload.connection.public_wss_url.capacity()
            + self.payload.connection.spki_pins.capacity() * std::mem::size_of::<Digest32>()
    }
}

pub(super) struct ValidatedEnrollmentResponseWrite {
    expected_request_hash: [u8; 32],
    response: MachineEnrollmentResponseV1,
    response_hash: [u8; 32],
}

pub(super) struct PreparedMachineRetirementWrite {
    retirement: RetireMachine,
    canonical: Zeroizing<Vec<u8>>,
    canonical_hash: [u8; 32],
}

impl std::fmt::Debug for PreparedMachineRetirementWrite {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter.write_str("PreparedMachineRetirementWrite([REDACTED])")
    }
}

impl PreparedMachineRetirementWrite {
    pub(super) fn retained_capacity(&self) -> usize {
        self.canonical.capacity()
    }
}

pub(super) struct PreparedRetirementTerminalWrite {
    committed: RetirementCommitted,
    canonical_frame_bytes: Zeroizing<Vec<u8>>,
    canonical_frame_hash: [u8; 32],
}

impl std::fmt::Debug for PreparedRetirementTerminalWrite {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter.write_str("PreparedRetirementTerminalWrite([REDACTED])")
    }
}

impl PreparedRetirementTerminalWrite {
    pub(super) fn retained_capacity(&self) -> usize {
        self.canonical_frame_bytes.capacity()
    }
}

pub(super) struct PreparedRootLostPurgeWrite {
    receipt: RelayAdminPurgeReceiptV1,
    canonical: Zeroizing<Vec<u8>>,
    canonical_hash: [u8; 32],
}

impl std::fmt::Debug for PreparedRootLostPurgeWrite {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter.write_str("PreparedRootLostPurgeWrite([REDACTED])")
    }
}

impl PreparedRootLostPurgeWrite {
    pub(super) fn retained_capacity(&self) -> usize {
        self.canonical.capacity()
    }
}

impl std::fmt::Debug for ValidatedEnrollmentResponseWrite {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter.write_str("ValidatedEnrollmentResponseWrite([REDACTED])")
    }
}

struct AuthenticatedRow {
    database_id: [u8; 16],
    record: MachineRemoteStateRecord,
    metadata_token: [u8; 32],
    payload: LoadedPayload,
}

struct RawRow {
    lifecycle: String,
    reset_kind: Option<String>,
    database_id: Vec<u8>,
    relay_server_id: Vec<u8>,
    machine_route: Vec<u8>,
    root_key_id: Vec<u8>,
    root_fingerprint: Vec<u8>,
    trust_epoch: String,
    request_hash: Vec<u8>,
    response_hash: Option<Vec<u8>>,
    enrollment_receipt_hash: Option<Vec<u8>>,
    receipt_verify_key_hash: Vec<u8>,
    sealed_state: Vec<u8>,
    sealed_state_bytes: i64,
    metadata_token: Vec<u8>,
}

pub(super) fn prepare_write(
    bundle: EnrollmentBundleV2,
    machine_route: MachineRouteId,
    binding: MachineIdentityBinding,
    link_cert: SignedCertificate,
    data_cert: SignedCertificate,
) -> Result<PreparedMachineEnrollmentWrite, RuntimeStoreError> {
    let connection = validate_bundle(&bundle)?;
    validate_route_and_binding(machine_route, &binding, &link_cert, &data_cert, &connection)?;
    let payload = PreparedPayloadV1 {
        version: PAYLOAD_VERSION,
        connection,
        code: bundle.code,
        machine_route,
        binding: binding.into(),
        link_cert,
        data_cert,
    };
    let request = request_from_prepared(&payload);
    let request_hash = request.canonical_sha256();
    let canonical =
        encode_payload(&payload).map_err(|_| RuntimeStoreError::MachineRemoteConflict)?;
    let prepare_input_hash = Sha256::digest(canonical.as_slice()).into();
    let receipt_verify_key_hash = payload
        .connection
        .receipt_verify_key
        .canonical_sha256()
        .map_err(|_| RuntimeStoreError::MachineRemoteConflict)?;
    Ok(PreparedMachineEnrollmentWrite {
        payload,
        canonical,
        prepare_input_hash,
        request_hash,
        receipt_verify_key_hash,
    })
}

pub(crate) fn prepare_input_hash_for_bundle(
    bundle: EnrollmentBundleV2,
    machine_route: MachineRouteId,
    binding: MachineIdentityBinding,
    link_cert: SignedCertificate,
    data_cert: SignedCertificate,
) -> Result<[u8; 32], RuntimeStoreError> {
    Ok(prepare_write(bundle, machine_route, binding, link_cert, data_cert)?.prepare_input_hash)
}

pub(super) fn prepare_response_write(
    expected_request_hash: [u8; 32],
    response: MachineEnrollmentResponseV1,
) -> Result<ValidatedEnrollmentResponseWrite, RuntimeStoreError> {
    if expected_request_hash == [0; 32] {
        return Err(RuntimeStoreError::MachineRemoteConflict);
    }
    let response_hash = response
        .canonical_sha256()
        .map_err(|_| RuntimeStoreError::MachineRemoteConflict)?;
    Ok(ValidatedEnrollmentResponseWrite {
        expected_request_hash,
        response,
        response_hash,
    })
}

pub(super) fn prepare_retirement_write(
    retirement: RetireMachine,
) -> Result<PreparedMachineRetirementWrite, RuntimeStoreError> {
    let canonical = Zeroizing::new(retirement.canonical_bytes());
    if canonical.is_empty() || canonical.len() > MAX_STATE_PLAINTEXT_BYTES {
        return Err(RuntimeStoreError::MachineRemoteConflict);
    }
    let canonical_hash = sha256(canonical.as_slice());
    Ok(PreparedMachineRetirementWrite {
        retirement,
        canonical,
        canonical_hash,
    })
}

pub(super) fn prepare_terminal_write(
    canonical_frame_bytes: Vec<u8>,
    canonical_frame_hash: [u8; 32],
) -> Result<PreparedRetirementTerminalWrite, RuntimeStoreError> {
    if canonical_frame_bytes.is_empty()
        || canonical_frame_bytes.len() > agentdeck_protocol::relay_v2::MAX_FRAME_BYTES
        || canonical_frame_hash == [0; 32]
        || sha256(&canonical_frame_bytes) != canonical_frame_hash
    {
        return Err(RuntimeStoreError::MachineRemoteConflict);
    }
    let frame =
        decode(&canonical_frame_bytes).map_err(|_| RuntimeStoreError::MachineRemoteConflict)?;
    if frame.version != RELAY_PROTOCOL_VERSION || encode(&frame) != canonical_frame_bytes {
        return Err(RuntimeStoreError::MachineRemoteConflict);
    }
    let RelayFrameBody::RetirementCommitted(committed) = frame.body else {
        return Err(RuntimeStoreError::MachineRemoteConflict);
    };
    Ok(PreparedRetirementTerminalWrite {
        committed,
        canonical_frame_bytes: Zeroizing::new(canonical_frame_bytes),
        canonical_frame_hash,
    })
}

pub(super) fn prepare_root_lost_purge_write(
    receipt: RelayAdminPurgeReceiptV1,
) -> Result<PreparedRootLostPurgeWrite, RuntimeStoreError> {
    receipt
        .validate()
        .map_err(|_| RuntimeStoreError::MachineRemoteConflict)?;
    let canonical = Zeroizing::new(
        receipt
            .canonical_bytes()
            .map_err(|_| RuntimeStoreError::MachineRemoteConflict)?,
    );
    if canonical.is_empty() || canonical.len() > MAX_STATE_PLAINTEXT_BYTES {
        return Err(RuntimeStoreError::MachineRemoteConflict);
    }
    let canonical_hash = sha256(canonical.as_slice());
    Ok(PreparedRootLostPurgeWrite {
        receipt,
        canonical,
        canonical_hash,
    })
}

pub(super) fn prepare_machine_enrollment(
    state: &mut RuntimeSqlite,
    config: &RuntimeStoreConfig,
    prepared: PreparedMachineEnrollmentWrite,
) -> Result<PrepareMachineEnrollmentOutcome, RuntimeStoreError> {
    if let Some(current) =
        load_authenticated_row(&state.connection, &state.key_bundle, state.database_id)?
    {
        if matches!(&current.payload, LoadedPayload::LocalDeleted(_)) {
            return replace_local_deleted_enrollment(state, config, current, prepared);
        }
        if prepare_input_hash(&current.payload)? == prepared.prepare_input_hash {
            return Ok(PrepareMachineEnrollmentOutcome::Replayed {
                state: into_public_state(current),
            });
        }
        return Err(RuntimeStoreError::MachineRemoteConflict);
    }
    require_active_identity(
        &state.connection,
        &state.key_bundle,
        state.database_id,
        &prepared.payload.binding.clone().into(),
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
    if load_authenticated_row(&transaction, &state.key_bundle, state.database_id)?.is_some() {
        return Err(RuntimeStoreError::MachineRemoteConflict);
    }
    require_active_identity(
        &transaction,
        &state.key_bundle,
        state.database_id,
        &prepared.payload.binding.clone().into(),
    )?;
    let sealed_state = seal_payload(
        &state.key_bundle,
        state.database_id,
        prepared.canonical.as_slice(),
    )?;
    let record = record_for_prepared(&prepared, sealed_state.len());
    let metadata_token = row_token(
        &state.key_bundle,
        state.database_id,
        &record,
        None,
        &sealed_state,
    )?;
    insert_row(
        &transaction,
        state.database_id,
        &record,
        &sealed_state,
        metadata_token,
    )?;
    let ledger =
        super::sqlite::load_runtime_ledger(&transaction, &state.key_bundle, state.database_id)?;
    if ledger.machine_remote_state_count != 0 {
        return Err(RuntimeStoreError::UnknownOrCorruptSchema);
    }
    let mut next = ledger.clone();
    next.machine_remote_state_count = 1;
    let _ = super::sqlite::update_runtime_ledger(
        &transaction,
        &state.key_bundle,
        state.database_id,
        &ledger,
        &next,
    )?;
    config
        .fault_injector
        .before_operation(RuntimeStoreOperation::PrepareMachineEnrollmentBeforeCommit)?;
    super::sqlite::commit_transaction(
        transaction,
        RuntimeCommitOperation::PrepareMachineEnrollment,
    )?;
    super::sqlite::latch_post_commit_capacity(state, config);
    config
        .fault_injector
        .before_operation(RuntimeStoreOperation::PrepareMachineEnrollmentAfterCommit)
        .map_err(|_| RuntimeStoreError::CommitOutcomeUnknown {
            operation: RuntimeCommitOperation::PrepareMachineEnrollment,
        })?;
    let current = load_authenticated_row(&state.connection, &state.key_bundle, state.database_id)?
        .ok_or(RuntimeStoreError::UnknownOrCorruptSchema)?;
    Ok(PrepareMachineEnrollmentOutcome::Prepared {
        state: into_public_state(current),
    })
}

fn replace_local_deleted_enrollment(
    state: &mut RuntimeSqlite,
    config: &RuntimeStoreConfig,
    current: AuthenticatedRow,
    prepared: PreparedMachineEnrollmentWrite,
) -> Result<PrepareMachineEnrollmentOutcome, RuntimeStoreError> {
    require_remote_security_state_empty(&state.connection, &state.key_bundle, state.database_id)?;
    let LoadedPayload::LocalDeleted(tombstone) = &current.payload else {
        return Err(RuntimeStoreError::MachineRemoteConflict);
    };
    let binding: MachineIdentityBinding = prepared.payload.binding.clone().into();
    if prepared.payload.machine_route.as_bytes() == &current.record.machine_route
        || binding.root_key_id == current.record.root_key_id
        || binding.root_fingerprint == current.record.root_fingerprint
        || prepared.prepare_input_hash == tombstone.previous_prepare_input_hash
        || prepared.request_hash == current.record.request_hash
    {
        return Err(RuntimeStoreError::MachineRemoteConflict);
    }
    validate_local_deleted_absence(
        &state.connection,
        &state.key_bundle,
        state.database_id,
        &current.record,
    )?;
    super::sqlite::admit_safety_write(
        &state.connection,
        &state.key_bundle,
        state.database_id,
        &state.storage_path,
        config.capacity_probe.as_ref(),
    )?;
    let sealed_state = seal_payload(
        &state.key_bundle,
        state.database_id,
        prepared.canonical.as_slice(),
    )?;
    let next = record_for_prepared(&prepared, sealed_state.len());
    let next_token = row_token(
        &state.key_bundle,
        state.database_id,
        &next,
        None,
        &sealed_state,
    )?;
    let transaction = state
        .connection
        .transaction_with_behavior(TransactionBehavior::Immediate)?;
    require_remote_security_state_empty(&transaction, &state.key_bundle, state.database_id)?;
    validate_locator_absent(&transaction, &current.record)?;
    super::machine_identity::insert_active_replacement(
        &transaction,
        &state.key_bundle,
        state.database_id,
        binding,
    )?;
    if update_row(
        &transaction,
        "localDeleted",
        &current.metadata_token,
        &next,
        None,
        &sealed_state,
        next_token,
    )? != 1
    {
        return Err(RuntimeStoreError::MachineRemoteConflict);
    }
    let ledger =
        super::sqlite::load_runtime_ledger(&transaction, &state.key_bundle, state.database_id)?;
    if ledger.machine_remote_state_count != 1 || ledger.machine_identity_count != 1 {
        return Err(RuntimeStoreError::UnknownOrCorruptSchema);
    }
    config
        .fault_injector
        .before_operation(RuntimeStoreOperation::ReplaceLocalDeletedEnrollmentBeforeCommit)?;
    super::sqlite::commit_transaction(
        transaction,
        RuntimeCommitOperation::ReplaceLocalDeletedEnrollment,
    )?;
    super::sqlite::latch_post_commit_capacity(state, config);
    config
        .fault_injector
        .before_operation(RuntimeStoreOperation::ReplaceLocalDeletedEnrollmentAfterCommit)
        .map_err(|_| RuntimeStoreError::CommitOutcomeUnknown {
            operation: RuntimeCommitOperation::ReplaceLocalDeletedEnrollment,
        })?;
    let current = load_authenticated_row(&state.connection, &state.key_bundle, state.database_id)?
        .ok_or(RuntimeStoreError::UnknownOrCorruptSchema)?;
    Ok(PrepareMachineEnrollmentOutcome::Prepared {
        state: into_public_state(current),
    })
}

pub(super) fn record_validated_enrollment_response(
    state: &mut RuntimeSqlite,
    config: &RuntimeStoreConfig,
    prepared: ValidatedEnrollmentResponseWrite,
) -> Result<RecordValidatedEnrollmentResponseOutcome, RuntimeStoreError> {
    let current = load_authenticated_row(&state.connection, &state.key_bundle, state.database_id)?
        .ok_or(RuntimeStoreError::MachineRemoteConflict)?;
    if current.record.request_hash != prepared.expected_request_hash {
        return Err(RuntimeStoreError::MachineRemoteConflict);
    }
    if current.record.response_hash.is_some() {
        if current.record.response_hash == Some(prepared.response_hash) {
            return Ok(RecordValidatedEnrollmentResponseOutcome::Replayed {
                state: into_public_state(current),
            });
        }
        return Err(RuntimeStoreError::MachineRemoteConflict);
    }
    let LoadedPayload::Prepared(prepared_payload) = current.payload else {
        return Err(RuntimeStoreError::MachineRemoteConflict);
    };
    validate_response(&current.record, &prepared.response)?;
    super::sqlite::admit_safety_write(
        &state.connection,
        &state.key_bundle,
        state.database_id,
        &state.storage_path,
        config.capacity_probe.as_ref(),
    )?;
    let payload = ValidatedPayloadV1 {
        version: PAYLOAD_VERSION,
        prepared: prepared_payload,
        response: prepared.response,
    };
    let canonical = encode_payload(&payload)?;
    let sealed_state = seal_payload(&state.key_bundle, state.database_id, canonical.as_slice())?;
    let mut next = current.record;
    next.lifecycle = MachineRemoteLifecycle::EnrollmentResponseValidated;
    next.response_hash = Some(prepared.response_hash);
    next.sealed_state_bytes = sealed_state.len();
    let next_token = row_token(
        &state.key_bundle,
        state.database_id,
        &next,
        None,
        &sealed_state,
    )?;
    let transaction = state
        .connection
        .transaction_with_behavior(TransactionBehavior::Immediate)?;
    if update_row(
        &transaction,
        "enrollmentPrepared",
        &current.metadata_token,
        &next,
        None,
        &sealed_state,
        next_token,
    )? != 1
    {
        return Err(RuntimeStoreError::MachineRemoteConflict);
    }
    config
        .fault_injector
        .before_operation(RuntimeStoreOperation::RecordValidatedEnrollmentResponseBeforeCommit)?;
    super::sqlite::commit_transaction(
        transaction,
        RuntimeCommitOperation::RecordValidatedEnrollmentResponse,
    )?;
    super::sqlite::latch_post_commit_capacity(state, config);
    config
        .fault_injector
        .before_operation(RuntimeStoreOperation::RecordValidatedEnrollmentResponseAfterCommit)
        .map_err(|_| RuntimeStoreError::CommitOutcomeUnknown {
            operation: RuntimeCommitOperation::RecordValidatedEnrollmentResponse,
        })?;
    let current = load_authenticated_row(&state.connection, &state.key_bundle, state.database_id)?
        .ok_or(RuntimeStoreError::UnknownOrCorruptSchema)?;
    Ok(RecordValidatedEnrollmentResponseOutcome::Recorded {
        state: into_public_state(current),
    })
}

pub(super) fn activate_machine_enrollment(
    state: &mut RuntimeSqlite,
    config: &RuntimeStoreConfig,
    expected_request_hash: [u8; 32],
    expected_response_hash: [u8; 32],
) -> Result<ActivateMachineEnrollmentOutcome, RuntimeStoreError> {
    if expected_request_hash == [0; 32] || expected_response_hash == [0; 32] {
        return Err(RuntimeStoreError::MachineRemoteConflict);
    }
    let current = load_authenticated_row(&state.connection, &state.key_bundle, state.database_id)?
        .ok_or(RuntimeStoreError::MachineRemoteConflict)?;
    if current.record.request_hash != expected_request_hash
        || current.record.response_hash != Some(expected_response_hash)
    {
        return Err(RuntimeStoreError::MachineRemoteConflict);
    }
    if current.record.lifecycle == MachineRemoteLifecycle::Active {
        validate_locator_mirror(&state.connection, &current.record)?;
        return Ok(ActivateMachineEnrollmentOutcome::Replayed {
            state: into_public_state(current),
        });
    }
    let LoadedPayload::Validated(validated) = current.payload else {
        return Err(RuntimeStoreError::MachineRemoteConflict);
    };
    let prepare_input_hash = prepared_payload_hash(&validated.prepared)?;
    let receipt_hash = validated.response.receipt_hash;
    let payload = ActivePayloadV1 {
        version: PAYLOAD_VERSION,
        connection: validated.prepared.connection,
        machine_route: validated.prepared.machine_route,
        binding: validated.prepared.binding,
        link_cert: validated.prepared.link_cert,
        data_cert: validated.prepared.data_cert,
        prepare_input_hash,
        response: validated.response,
    };
    let canonical = encode_payload(&payload)?;
    super::sqlite::admit_safety_write(
        &state.connection,
        &state.key_bundle,
        state.database_id,
        &state.storage_path,
        config.capacity_probe.as_ref(),
    )?;
    let sealed_state = seal_payload(&state.key_bundle, state.database_id, canonical.as_slice())?;
    let mut next = current.record;
    next.lifecycle = MachineRemoteLifecycle::Active;
    next.enrollment_receipt_hash = Some(receipt_hash);
    next.sealed_state_bytes = sealed_state.len();
    let next_token = row_token(
        &state.key_bundle,
        state.database_id,
        &next,
        None,
        &sealed_state,
    )?;
    let transaction = state
        .connection
        .transaction_with_behavior(TransactionBehavior::Immediate)?;
    if update_row(
        &transaction,
        "enrollmentResponseValidated",
        &current.metadata_token,
        &next,
        None,
        &sealed_state,
        next_token,
    )? != 1
    {
        return Err(RuntimeStoreError::MachineRemoteConflict);
    }
    insert_locator_mirror(&transaction, &next)?;
    validate_locator_mirror(&transaction, &next)?;
    config
        .fault_injector
        .before_operation(RuntimeStoreOperation::ActivateMachineEnrollmentBeforeCommit)?;
    super::sqlite::commit_transaction(
        transaction,
        RuntimeCommitOperation::ActivateMachineEnrollment,
    )?;
    super::sqlite::latch_post_commit_capacity(state, config);
    config
        .fault_injector
        .before_operation(RuntimeStoreOperation::ActivateMachineEnrollmentAfterCommit)
        .map_err(|_| RuntimeStoreError::CommitOutcomeUnknown {
            operation: RuntimeCommitOperation::ActivateMachineEnrollment,
        })?;
    let current = load_authenticated_row(&state.connection, &state.key_bundle, state.database_id)?
        .ok_or(RuntimeStoreError::UnknownOrCorruptSchema)?;
    Ok(ActivateMachineEnrollmentOutcome::Activated {
        state: into_public_state(current),
    })
}

pub(super) fn prepare_machine_retirement(
    state: &mut RuntimeSqlite,
    config: &RuntimeStoreConfig,
    prepared: PreparedMachineRetirementWrite,
) -> Result<PrepareMachineRetirementOutcome, RuntimeStoreError> {
    let current = load_authenticated_row(&state.connection, &state.key_bundle, state.database_id)?
        .ok_or(RuntimeStoreError::MachineRemoteConflict)?;
    if let Some(retirement) = root_present_retirement(&current.payload) {
        if retirement.retirement == prepared.retirement
            && retirement.retirement_bytes == *prepared.canonical
            && retirement.retirement_hash == prepared.canonical_hash
        {
            return Ok(PrepareMachineRetirementOutcome::Replayed {
                state: into_public_state(current),
            });
        }
        return Err(RuntimeStoreError::MachineRemoteConflict);
    }
    let LoadedPayload::Active(active) = current.payload else {
        return Err(RuntimeStoreError::MachineRemoteConflict);
    };
    validate_retirement(&current.record, &active, &prepared.retirement)?;
    let payload = RetirePendingPayloadV1 {
        version: PAYLOAD_VERSION,
        active,
        retirement: prepared.retirement,
        retirement_bytes: prepared.canonical.to_vec(),
        retirement_hash: prepared.canonical_hash,
    };
    let canonical = encode_payload(&payload)?;
    let mut next = current.record;
    next.lifecycle = MachineRemoteLifecycle::RetirePending;
    let next = commit_remote_transition(
        state,
        config,
        &current.metadata_token,
        next,
        canonical.as_slice(),
        RemoteTransition {
            previous_lifecycle: MachineRemoteLifecycle::Active,
            reset_kind: MachineTrustResetKind::RootPresent,
            remote_cleanup: Some(
                reset_cleanup::RemoteSecurityCleanupMode::RootPresentAfterRevocation,
            ),
            before_operation: RuntimeStoreOperation::PrepareMachineRetirementBeforeCommit,
            after_operation: RuntimeStoreOperation::PrepareMachineRetirementAfterCommit,
            commit_operation: RuntimeCommitOperation::PrepareMachineRetirement,
        },
    )?;
    Ok(PrepareMachineRetirementOutcome::Prepared {
        state: into_public_state(next),
    })
}

pub(super) fn record_machine_retirement_terminal(
    state: &mut RuntimeSqlite,
    config: &RuntimeStoreConfig,
    prepared: PreparedRetirementTerminalWrite,
) -> Result<RecordMachineRetirementTerminalOutcome, RuntimeStoreError> {
    let current = load_authenticated_row(&state.connection, &state.key_bundle, state.database_id)?
        .ok_or(RuntimeStoreError::MachineRemoteConflict)?;
    if let Some(committed) = root_present_committed(&current.payload) {
        if terminal_matches(committed, &prepared) {
            return Ok(RecordMachineRetirementTerminalOutcome::Replayed {
                state: into_public_state(current),
            });
        }
        return Err(RuntimeStoreError::MachineRemoteConflict);
    }
    let LoadedPayload::RetirePending(pending) = current.payload else {
        return Err(RuntimeStoreError::MachineRemoteConflict);
    };
    validate_terminal(&pending, &prepared)?;
    let payload = RelayCommittedPayloadV1 {
        version: PAYLOAD_VERSION,
        pending,
        terminal: prepared.committed,
        terminal_frame_bytes: prepared.canonical_frame_bytes.to_vec(),
        terminal_frame_hash: prepared.canonical_frame_hash,
    };
    let canonical = encode_payload(&payload)?;
    let mut next = current.record;
    next.lifecycle = MachineRemoteLifecycle::RelayCommitted;
    let next = commit_remote_transition(
        state,
        config,
        &current.metadata_token,
        next,
        canonical.as_slice(),
        RemoteTransition {
            previous_lifecycle: MachineRemoteLifecycle::RetirePending,
            reset_kind: MachineTrustResetKind::RootPresent,
            remote_cleanup: None,
            before_operation: RuntimeStoreOperation::RecordMachineRetirementTerminalBeforeCommit,
            after_operation: RuntimeStoreOperation::RecordMachineRetirementTerminalAfterCommit,
            commit_operation: RuntimeCommitOperation::RecordMachineRetirementTerminal,
        },
    )?;
    Ok(RecordMachineRetirementTerminalOutcome::Recorded {
        state: into_public_state(next),
    })
}

pub(super) fn confirm_machine_purge_readback_absent(
    state: &mut RuntimeSqlite,
    config: &RuntimeStoreConfig,
    prepared: PreparedRetirementTerminalWrite,
) -> Result<ConfirmMachinePurgeReadbackAbsentOutcome, RuntimeStoreError> {
    let current = load_authenticated_row(&state.connection, &state.key_bundle, state.database_id)?
        .ok_or(RuntimeStoreError::MachineRemoteConflict)?;
    if let LoadedPayload::PurgeReadbackAbsent(PurgeReadbackPayload::RootPresent(purge)) =
        &current.payload
    {
        if terminal_matches(&purge.committed, &prepared) {
            return Ok(ConfirmMachinePurgeReadbackAbsentOutcome::Replayed {
                state: into_public_state(current),
            });
        }
        return Err(RuntimeStoreError::MachineRemoteConflict);
    }
    let LoadedPayload::RelayCommitted(committed) = current.payload else {
        return Err(RuntimeStoreError::MachineRemoteConflict);
    };
    if !terminal_matches(&committed, &prepared) {
        return Err(RuntimeStoreError::MachineRemoteConflict);
    }
    let payload = RootPresentPurgePayloadV1 {
        version: PAYLOAD_VERSION,
        committed,
    };
    let canonical = encode_payload(&payload)?;
    let mut next = current.record;
    next.lifecycle = MachineRemoteLifecycle::PurgeReadbackAbsent;
    let next = commit_remote_transition(
        state,
        config,
        &current.metadata_token,
        next,
        canonical.as_slice(),
        RemoteTransition {
            previous_lifecycle: MachineRemoteLifecycle::RelayCommitted,
            reset_kind: MachineTrustResetKind::RootPresent,
            remote_cleanup: None,
            before_operation: RuntimeStoreOperation::ConfirmMachinePurgeReadbackAbsentBeforeCommit,
            after_operation: RuntimeStoreOperation::ConfirmMachinePurgeReadbackAbsentAfterCommit,
            commit_operation: RuntimeCommitOperation::ConfirmMachinePurgeReadbackAbsent,
        },
    )?;
    Ok(ConfirmMachinePurgeReadbackAbsentOutcome::Confirmed {
        state: into_public_state(next),
    })
}

pub(super) fn record_root_lost_machine_purge(
    state: &mut RuntimeSqlite,
    config: &RuntimeStoreConfig,
    prepared: PreparedRootLostPurgeWrite,
) -> Result<RecordRootLostMachinePurgeOutcome, RuntimeStoreError> {
    let current = load_authenticated_row(&state.connection, &state.key_bundle, state.database_id)?
        .ok_or(RuntimeStoreError::MachineRemoteConflict)?;
    if let LoadedPayload::PurgeReadbackAbsent(PurgeReadbackPayload::RootLost(purge)) =
        &current.payload
    {
        if purge.receipt == prepared.receipt
            && purge.receipt_bytes == *prepared.canonical
            && purge.receipt_hash == prepared.canonical_hash
        {
            return Ok(RecordRootLostMachinePurgeOutcome::Replayed {
                state: into_public_state(current),
            });
        }
        return Err(RuntimeStoreError::MachineRemoteConflict);
    }
    let LoadedPayload::Active(active) = current.payload else {
        return Err(RuntimeStoreError::MachineRemoteConflict);
    };
    validate_root_lost_receipt(&current.record, &active, &prepared.receipt)?;
    let payload = RootLostPurgePayloadV1 {
        version: PAYLOAD_VERSION,
        active,
        receipt: prepared.receipt,
        receipt_bytes: prepared.canonical.to_vec(),
        receipt_hash: prepared.canonical_hash,
    };
    let canonical = encode_payload(&payload)?;
    let mut next = current.record;
    next.lifecycle = MachineRemoteLifecycle::PurgeReadbackAbsent;
    let next = commit_remote_transition(
        state,
        config,
        &current.metadata_token,
        next,
        canonical.as_slice(),
        RemoteTransition {
            previous_lifecycle: MachineRemoteLifecycle::Active,
            reset_kind: MachineTrustResetKind::RootLost,
            remote_cleanup: Some(
                reset_cleanup::RemoteSecurityCleanupMode::RootLostAfterPurgeReadback,
            ),
            before_operation: RuntimeStoreOperation::RecordRootLostMachinePurgeBeforeCommit,
            after_operation: RuntimeStoreOperation::RecordRootLostMachinePurgeAfterCommit,
            commit_operation: RuntimeCommitOperation::RecordRootLostMachinePurge,
        },
    )?;
    Ok(RecordRootLostMachinePurgeOutcome::Recorded {
        state: into_public_state(next),
    })
}

pub(super) fn finalize_machine_local_deletion(
    state: &mut RuntimeSqlite,
    config: &RuntimeStoreConfig,
    expected_reset_kind: MachineTrustResetKind,
    expected_purge_proof_hash: [u8; 32],
    cleanup_witness_hash: [u8; 32],
) -> Result<FinalizeMachineLocalDeletionOutcome, RuntimeStoreError> {
    if expected_purge_proof_hash == [0; 32] || cleanup_witness_hash == [0; 32] {
        return Err(RuntimeStoreError::MachineRemoteConflict);
    }
    let current = load_authenticated_row(&state.connection, &state.key_bundle, state.database_id)?
        .ok_or(RuntimeStoreError::MachineRemoteConflict)?;
    require_remote_security_state_empty(&state.connection, &state.key_bundle, state.database_id)?;
    if let LoadedPayload::LocalDeleted(payload) = &current.payload {
        if MachineTrustResetKind::from(payload.reset_kind) == expected_reset_kind
            && payload.purge_proof_hash == expected_purge_proof_hash
            && payload.cleanup_witness_hash == cleanup_witness_hash
        {
            return Ok(FinalizeMachineLocalDeletionOutcome::Replayed {
                state: into_public_state(current),
            });
        }
        return Err(RuntimeStoreError::MachineRemoteConflict);
    }
    let LoadedPayload::PurgeReadbackAbsent(purge) = current.payload else {
        return Err(RuntimeStoreError::MachineRemoteConflict);
    };
    let material = deletion_material(&purge);
    if material.reset_kind != expected_reset_kind
        || material.purge_proof_hash != expected_purge_proof_hash
    {
        return Err(RuntimeStoreError::MachineRemoteConflict);
    }
    let witness = MachineCleanupWitnessV1::new(
        material.reset_kind,
        RelayServerId::from_bytes(current.record.relay_server_id),
        MachineRouteId::from_bytes(current.record.machine_route),
        RootKeyId::from_bytes(current.record.root_key_id),
        current.record.root_fingerprint,
        TrustEpoch::new(current.record.trust_epoch),
        material.purge_proof_hash,
    )
    .map_err(|_| RuntimeStoreError::MachineRemoteConflict)?;
    if witness.canonical_sha256() != cleanup_witness_hash {
        return Err(RuntimeStoreError::MachineRemoteConflict);
    }
    let payload = LocalDeletedPayloadV1 {
        version: PAYLOAD_VERSION,
        reset_kind: material.reset_kind.into(),
        relay_server_id: RelayServerId::from_bytes(current.record.relay_server_id),
        machine_route: MachineRouteId::from_bytes(current.record.machine_route),
        root_key_id: RootKeyId::from_bytes(current.record.root_key_id),
        root_fingerprint: current.record.root_fingerprint,
        trust_epoch: TrustEpoch::new(current.record.trust_epoch),
        previous_prepare_input_hash: material.previous_prepare_input_hash,
        purge_proof_hash: material.purge_proof_hash,
        cleanup_witness_hash,
    };
    let canonical = encode_payload(&payload)?;
    super::sqlite::admit_safety_write(
        &state.connection,
        &state.key_bundle,
        state.database_id,
        &state.storage_path,
        config.capacity_probe.as_ref(),
    )?;
    let sealed_state = seal_payload(&state.key_bundle, state.database_id, canonical.as_slice())?;
    let mut next = current.record;
    next.lifecycle = MachineRemoteLifecycle::LocalDeleted;
    next.sealed_state_bytes = sealed_state.len();
    let reset_name = reset_kind_name(material.reset_kind);
    let next_token = row_token(
        &state.key_bundle,
        state.database_id,
        &next,
        Some(reset_name),
        &sealed_state,
    )?;
    let transaction = state
        .connection
        .transaction_with_behavior(TransactionBehavior::Immediate)?;
    if update_row(
        &transaction,
        "purgeReadbackAbsent",
        &current.metadata_token,
        &next,
        Some(reset_name),
        &sealed_state,
        next_token,
    )? != 1
    {
        return Err(RuntimeStoreError::MachineRemoteConflict);
    }
    delete_locator_mirror(&transaction, &next)?;
    super::machine_identity::delete_active_for_local_deleted(
        &transaction,
        &state.key_bundle,
        state.database_id,
        &material.binding,
    )?;
    validate_locator_absent(&transaction, &next)?;
    if super::machine_identity::load_machine_identity_state(
        &transaction,
        &state.key_bundle,
        state.database_id,
    )?
    .is_some()
    {
        return Err(RuntimeStoreError::UnknownOrCorruptSchema);
    }
    config
        .fault_injector
        .before_operation(RuntimeStoreOperation::FinalizeMachineLocalDeletionBeforeCommit)?;
    super::sqlite::commit_transaction(
        transaction,
        RuntimeCommitOperation::FinalizeMachineLocalDeletion,
    )?;
    super::sqlite::latch_post_commit_capacity(state, config);
    config
        .fault_injector
        .before_operation(RuntimeStoreOperation::FinalizeMachineLocalDeletionAfterCommit)
        .map_err(|_| RuntimeStoreError::CommitOutcomeUnknown {
            operation: RuntimeCommitOperation::FinalizeMachineLocalDeletion,
        })?;
    let current = load_authenticated_row(&state.connection, &state.key_bundle, state.database_id)?
        .ok_or(RuntimeStoreError::UnknownOrCorruptSchema)?;
    Ok(FinalizeMachineLocalDeletionOutcome::Finalized {
        state: into_public_state(current),
    })
}

mod reset_cleanup;
mod storage;

#[cfg(test)]
mod reset_guard_tests;

use storage::*;
pub(super) use storage::{
    blocks_standalone_identity_prepare, load_machine_enrollment_state, validate_v9_integrity,
};
