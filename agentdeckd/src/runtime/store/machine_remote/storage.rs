use super::*;

pub(super) struct DeletionMaterial {
    pub(super) reset_kind: MachineTrustResetKind,
    pub(super) binding: MachineIdentityBinding,
    pub(super) previous_prepare_input_hash: [u8; 32],
    pub(super) purge_proof_hash: [u8; 32],
}

pub(super) fn deletion_material(payload: &PurgeReadbackPayload) -> DeletionMaterial {
    match payload {
        PurgeReadbackPayload::RootPresent(payload) => DeletionMaterial {
            reset_kind: MachineTrustResetKind::RootPresent,
            binding: payload.committed.pending.active.binding.clone().into(),
            previous_prepare_input_hash: payload.committed.pending.active.prepare_input_hash,
            purge_proof_hash: payload.committed.terminal_frame_hash,
        },
        PurgeReadbackPayload::RootLost(payload) => DeletionMaterial {
            reset_kind: MachineTrustResetKind::RootLost,
            binding: payload.active.binding.clone().into(),
            previous_prepare_input_hash: payload.active.prepare_input_hash,
            purge_proof_hash: payload.receipt_hash,
        },
    }
}

pub(super) fn root_present_retirement(payload: &LoadedPayload) -> Option<&RetirePendingPayloadV1> {
    match payload {
        LoadedPayload::RetirePending(pending) => Some(pending),
        LoadedPayload::RelayCommitted(committed) => Some(&committed.pending),
        LoadedPayload::PurgeReadbackAbsent(PurgeReadbackPayload::RootPresent(purge)) => {
            Some(&purge.committed.pending)
        }
        _ => None,
    }
}

pub(super) fn root_present_committed(payload: &LoadedPayload) -> Option<&RelayCommittedPayloadV1> {
    match payload {
        LoadedPayload::RelayCommitted(committed) => Some(committed),
        LoadedPayload::PurgeReadbackAbsent(PurgeReadbackPayload::RootPresent(purge)) => {
            Some(&purge.committed)
        }
        _ => None,
    }
}

pub(super) fn terminal_matches(
    committed: &RelayCommittedPayloadV1,
    prepared: &PreparedRetirementTerminalWrite,
) -> bool {
    committed.terminal == prepared.committed
        && committed.terminal_frame_bytes == *prepared.canonical_frame_bytes
        && committed.terminal_frame_hash == prepared.canonical_frame_hash
}

pub(super) fn validate_retirement(
    record: &MachineRemoteStateRecord,
    active: &ActivePayloadV1,
    retirement: &RetireMachine,
) -> Result<(), RuntimeStoreError> {
    if retirement.machine_route.as_bytes() != &record.machine_route
        || retirement.root_key_id.as_bytes() != &record.root_key_id
        || retirement.trust_epoch.value() != record.trust_epoch
        || active.binding.root_key_id != record.root_key_id
        || active.binding.root_fingerprint != record.root_fingerprint
    {
        return Err(RuntimeStoreError::MachineRemoteConflict);
    }
    let root = VerifyingKey::from_bytes(&active.binding.root_public_key)
        .map_err(|_| RuntimeStoreError::MachineRemoteConflict)?;
    verify_tbs(
        &root,
        &retirement.to_be_signed_v1(
            RelayServerId::from_bytes(record.relay_server_id),
            record.root_fingerprint,
        ),
        &SignatureBytes::from(retirement.signature),
    )
    .map_err(|_| RuntimeStoreError::MachineRemoteConflict)
}

pub(super) fn validate_terminal(
    pending: &RetirePendingPayloadV1,
    terminal: &PreparedRetirementTerminalWrite,
) -> Result<(), RuntimeStoreError> {
    if terminal.committed.machine_route != pending.retirement.machine_route
        || terminal.committed.trust_epoch != pending.retirement.trust_epoch
        || terminal.committed.retire_hash != pending.retirement_hash
    {
        return Err(RuntimeStoreError::MachineRemoteConflict);
    }
    Ok(())
}

pub(super) fn validate_root_lost_receipt(
    record: &MachineRemoteStateRecord,
    active: &ActivePayloadV1,
    receipt: &RelayAdminPurgeReceiptV1,
) -> Result<(), RuntimeStoreError> {
    let enrollment_receipt_hash = record
        .enrollment_receipt_hash
        .ok_or(RuntimeStoreError::MachineRemoteConflict)?;
    let expectation = RelayAdminPurgeReceiptExpectationV1 {
        relay_server_id: RelayServerId::from_bytes(record.relay_server_id),
        machine_route: MachineRouteId::from_bytes(record.machine_route),
        root_key_id: RootKeyId::from_bytes(record.root_key_id),
        root_fingerprint: record.root_fingerprint,
        trust_epoch: TrustEpoch::new(record.trust_epoch),
        enrollment_receipt_hash,
        purge_request_hash: purge_request_hash(
            MachineRouteId::from_bytes(record.machine_route),
            record.root_fingerprint,
        )
        .map_err(|_| RuntimeStoreError::MachineRemoteConflict)?,
    };
    let verify_key =
        ValidatedRelayReceiptVerifyKey::new(active.connection.receipt_verify_key.clone())
            .map_err(|_| RuntimeStoreError::MachineRemoteConflict)?;
    verify_relay_admin_purge_receipt(&verify_key, &expectation, receipt)
        .map_err(|_| RuntimeStoreError::MachineRemoteConflict)
}

pub(super) struct RemoteTransition {
    pub(super) previous_lifecycle: MachineRemoteLifecycle,
    pub(super) reset_kind: MachineTrustResetKind,
    pub(super) remote_cleanup: Option<super::reset_cleanup::RemoteSecurityCleanupMode>,
    pub(super) before_operation: RuntimeStoreOperation,
    pub(super) after_operation: RuntimeStoreOperation,
    pub(super) commit_operation: RuntimeCommitOperation,
}

pub(super) fn commit_remote_transition(
    state: &mut RuntimeSqlite,
    config: &RuntimeStoreConfig,
    previous_token: &[u8; 32],
    mut next: MachineRemoteStateRecord,
    canonical: &[u8],
    transition: RemoteTransition,
) -> Result<AuthenticatedRow, RuntimeStoreError> {
    super::super::sqlite::admit_safety_write(
        &state.connection,
        &state.key_bundle,
        state.database_id,
        &state.storage_path,
        config.capacity_probe.as_ref(),
    )?;
    let sealed_state = seal_payload(&state.key_bundle, state.database_id, canonical)?;
    next.sealed_state_bytes = sealed_state.len();
    let reset_name = reset_kind_name(transition.reset_kind);
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
    if let Some(mode) = transition.remote_cleanup {
        super::reset_cleanup::scrub_remote_security_state(
            &transaction,
            &state.key_bundle,
            state.database_id,
            mode,
        )?;
    }
    if update_row(
        &transaction,
        lifecycle_name(transition.previous_lifecycle),
        previous_token,
        &next,
        Some(reset_name),
        &sealed_state,
        next_token,
    )? != 1
    {
        return Err(RuntimeStoreError::MachineRemoteConflict);
    }
    validate_locator_mirror(&transaction, &next)?;
    config
        .fault_injector
        .before_operation(transition.before_operation)?;
    super::super::sqlite::commit_transaction(transaction, transition.commit_operation)?;
    super::super::sqlite::latch_post_commit_capacity(state, config);
    config
        .fault_injector
        .before_operation(transition.after_operation)
        .map_err(|_| RuntimeStoreError::CommitOutcomeUnknown {
            operation: transition.commit_operation,
        })?;
    load_authenticated_row(&state.connection, &state.key_bundle, state.database_id)?
        .ok_or(RuntimeStoreError::UnknownOrCorruptSchema)
}

pub(in crate::runtime::store) fn load_machine_enrollment_state(
    connection: &Connection,
    key_bundle: &RuntimeKeyBundle,
    database_id: [u8; 16],
) -> Result<Option<MachineEnrollmentState>, RuntimeStoreError> {
    let ledger = super::super::sqlite::load_runtime_ledger(connection, key_bundle, database_id)?;
    let state = load_authenticated_row(connection, key_bundle, database_id)?;
    if ledger.machine_remote_state_count != u64::from(state.is_some()) {
        return Err(RuntimeStoreError::UnknownOrCorruptSchema);
    }
    match state {
        Some(state) => {
            if state.record.lifecycle == MachineRemoteLifecycle::LocalDeleted {
                validate_local_deleted_absence(connection, key_bundle, database_id, &state.record)?;
            } else if requires_locator_mirror(state.record.lifecycle) {
                validate_locator_mirror(connection, &state.record)?;
            }
            Ok(Some(into_public_state(state)))
        }
        None => Ok(None),
    }
}

pub(in crate::runtime::store) fn blocks_standalone_identity_prepare(
    connection: &Connection,
    key_bundle: &RuntimeKeyBundle,
    database_id: [u8; 16],
) -> Result<bool, RuntimeStoreError> {
    Ok(load_authenticated_row(connection, key_bundle, database_id)?
        .is_some_and(|state| state.record.lifecycle == MachineRemoteLifecycle::LocalDeleted))
}

pub(in crate::runtime::store) fn validate_v9_integrity(
    connection: &Connection,
    key_bundle: &RuntimeKeyBundle,
    database_id: [u8; 16],
    ledger: &RuntimeLedger,
) -> Result<(), RuntimeStoreError> {
    let physical_count: i64 =
        connection.query_row("SELECT COUNT(*) FROM machine_remote_state", [], |row| {
            row.get(0)
        })?;
    let physical_count =
        u64::try_from(physical_count).map_err(|_| RuntimeStoreError::UnknownOrCorruptSchema)?;
    if physical_count > 1 || physical_count != ledger.machine_remote_state_count {
        return Err(RuntimeStoreError::UnknownOrCorruptSchema);
    }
    let state = load_authenticated_row(connection, key_bundle, database_id)?;
    if u64::from(state.is_some()) != physical_count {
        return Err(RuntimeStoreError::UnknownOrCorruptSchema);
    }
    if let Some(state) = state.as_ref()
        && requires_locator_mirror(state.record.lifecycle)
    {
        validate_locator_mirror(connection, &state.record)?;
    } else if let Some(state) = state.as_ref()
        && state.record.lifecycle == MachineRemoteLifecycle::LocalDeleted
    {
        validate_local_deleted_absence(connection, key_bundle, database_id, &state.record)?;
    }
    Ok(())
}

pub(super) fn validate_local_deleted_absence(
    connection: &Connection,
    key_bundle: &RuntimeKeyBundle,
    database_id: [u8; 16],
    record: &MachineRemoteStateRecord,
) -> Result<(), RuntimeStoreError> {
    validate_locator_absent(connection, record)?;
    if super::super::machine_identity::load_machine_identity_state(
        connection,
        key_bundle,
        database_id,
    )?
    .is_some()
    {
        return Err(RuntimeStoreError::UnknownOrCorruptSchema);
    }
    Ok(())
}

pub(super) const fn requires_locator_mirror(lifecycle: MachineRemoteLifecycle) -> bool {
    matches!(
        lifecycle,
        MachineRemoteLifecycle::Active
            | MachineRemoteLifecycle::RetirePending
            | MachineRemoteLifecycle::RelayCommitted
            | MachineRemoteLifecycle::PurgeReadbackAbsent
    )
}

pub(super) fn validate_bundle(
    bundle: &EnrollmentBundleV2,
) -> Result<StoredConnectionV1, RuntimeStoreError> {
    if bundle.version != ENROLLMENT_BUNDLE_VERSION
        || bundle.public_wss_url.len() > 2048
        || bundle.relay_server_id.as_bytes() == &[0; 16]
        || bundle.code.0 == [0; 32]
        || bundle.expires_at_ms == 0
        || !(1..=2).contains(&bundle.spki_pins.len())
        || bundle.spki_pins.iter().any(|pin| pin.0 == [0; 32])
        || (bundle.spki_pins.len() == 2 && bundle.spki_pins[0] == bundle.spki_pins[1])
    {
        return Err(RuntimeStoreError::MachineRemoteConflict);
    }
    let origin =
        Url::parse(&bundle.public_wss_url).map_err(|_| RuntimeStoreError::MachineRemoteConflict)?;
    if origin.scheme() != "wss"
        || origin.host_str().is_none()
        || !origin.username().is_empty()
        || origin.password().is_some()
        || origin.path() != "/"
        || origin.port() == Some(0)
        || origin.query().is_some()
        || origin.fragment().is_some()
        || origin.as_str() != bundle.public_wss_url
    {
        return Err(RuntimeStoreError::MachineRemoteConflict);
    }
    let verify_key = ValidatedRelayReceiptVerifyKey::new(bundle.receipt_verify_key.clone())
        .map_err(|_| RuntimeStoreError::MachineRemoteConflict)?;
    if verify_key.wire_anchor().relay_server_id != bundle.relay_server_id {
        return Err(RuntimeStoreError::MachineRemoteConflict);
    }
    Ok(StoredConnectionV1 {
        public_wss_url: bundle.public_wss_url.clone(),
        relay_server_id: bundle.relay_server_id,
        receipt_verify_key: bundle.receipt_verify_key.clone(),
        spki_pins: bundle.spki_pins.clone(),
        expires_at_ms: bundle.expires_at_ms,
    })
}

pub(super) fn validate_route_and_binding(
    machine_route: MachineRouteId,
    binding: &MachineIdentityBinding,
    link_cert: &SignedCertificate,
    data_cert: &SignedCertificate,
    connection: &StoredConnectionV1,
) -> Result<(), RuntimeStoreError> {
    if machine_route.as_bytes() == &[0; 16]
        || binding.root_key_id == [0; 16]
        || binding.trust_epoch == 0
        || binding.link_generation == 0
        || binding.data_generation == 0
    {
        return Err(RuntimeStoreError::MachineRemoteConflict);
    }
    for (public_key, fingerprint) in [
        (&binding.root_public_key, &binding.root_fingerprint),
        (
            &binding.machine_hpke_public_key,
            &binding.machine_hpke_fingerprint,
        ),
        (
            &binding.link_sign_public_key,
            &binding.link_sign_fingerprint,
        ),
        (
            &binding.data_sign_public_key,
            &binding.data_sign_fingerprint,
        ),
    ] {
        if public_key == &[0; 32] || sha256(public_key) != *fingerprint {
            return Err(RuntimeStoreError::MachineRemoteConflict);
        }
    }
    verify_certificate(
        connection.relay_server_id,
        machine_route,
        binding,
        CertRole::Link,
        link_cert,
    )?;
    verify_certificate(
        connection.relay_server_id,
        machine_route,
        binding,
        CertRole::Data,
        data_cert,
    )
}

pub(super) fn verify_certificate(
    relay_server_id: RelayServerId,
    machine_route: MachineRouteId,
    binding: &MachineIdentityBinding,
    role: CertRole,
    certificate: &SignedCertificate,
) -> Result<(), RuntimeStoreError> {
    let (subject, generation) = match role {
        CertRole::Link => (binding.link_sign_public_key, binding.link_generation),
        CertRole::Data => (binding.data_sign_public_key, binding.data_generation),
    };
    if certificate.cert_role != role
        || certificate.subject_pubkey.0 != subject
        || certificate.generation.value() != generation
        || certificate.root_key_id != RootKeyId::from_bytes(binding.root_key_id)
        || certificate.trust_epoch != TrustEpoch::new(binding.trust_epoch)
        || certificate.not_after_ms.is_some()
    {
        return Err(RuntimeStoreError::MachineRemoteConflict);
    }
    let root = VerifyingKey::from_bytes(&binding.root_public_key)
        .map_err(|_| RuntimeStoreError::MachineRemoteConflict)?;
    let tbs = certificate.to_be_signed_v1(relay_server_id, machine_route, binding.root_fingerprint);
    verify_tbs(&root, &tbs, &SignatureBytes::from(certificate.signature))
        .map_err(|_| RuntimeStoreError::MachineRemoteConflict)
}

pub(super) fn request_from_prepared(payload: &PreparedPayloadV1) -> MachineEnrollmentRequestV1 {
    MachineEnrollmentRequestV1 {
        code: payload.code.clone(),
        machine_route: payload.machine_route,
        root_pubkey: PublicKeyBytes(payload.binding.root_public_key),
        link_cert: payload.link_cert.clone(),
        data_cert: payload.data_cert.clone(),
    }
}

pub(super) fn validate_response(
    record: &MachineRemoteStateRecord,
    response: &MachineEnrollmentResponseV1,
) -> Result<(), RuntimeStoreError> {
    response
        .validate()
        .map_err(|_| RuntimeStoreError::MachineRemoteConflict)?;
    let expected_receipt = enrollment_receipt_hash(
        RelayServerId::from_bytes(record.relay_server_id),
        MachineRouteId::from_bytes(record.machine_route),
        record.trust_epoch,
        record.request_hash,
    );
    if response.relay_server_id.as_bytes() != &record.relay_server_id
        || response.machine_route.as_bytes() != &record.machine_route
        || response.trust_epoch != record.trust_epoch
        || response.receipt_hash != expected_receipt
    {
        return Err(RuntimeStoreError::MachineRemoteConflict);
    }
    Ok(())
}

pub(super) fn record_for_prepared(
    prepared: &PreparedMachineEnrollmentWrite,
    sealed_state_bytes: usize,
) -> MachineRemoteStateRecord {
    MachineRemoteStateRecord {
        lifecycle: MachineRemoteLifecycle::EnrollmentPrepared,
        relay_server_id: *prepared.payload.connection.relay_server_id.as_bytes(),
        machine_route: *prepared.payload.machine_route.as_bytes(),
        root_key_id: prepared.payload.binding.root_key_id,
        root_fingerprint: prepared.payload.binding.root_fingerprint,
        trust_epoch: prepared.payload.binding.trust_epoch,
        request_hash: prepared.request_hash,
        response_hash: None,
        enrollment_receipt_hash: None,
        receipt_verify_key_hash: prepared.receipt_verify_key_hash,
        sealed_state_bytes,
    }
}

pub(super) fn require_active_identity(
    connection: &Connection,
    key_bundle: &RuntimeKeyBundle,
    database_id: [u8; 16],
    expected: &MachineIdentityBinding,
) -> Result<(), RuntimeStoreError> {
    let identity = super::super::machine_identity::load_machine_identity_state(
        connection,
        key_bundle,
        database_id,
    )?
    .ok_or(RuntimeStoreError::MachineIdentityMissing)?;
    if identity.lifecycle != MachineIdentityLifecycle::Active || &identity.binding != expected {
        return Err(RuntimeStoreError::MachineRemoteConflict);
    }
    Ok(())
}

pub(super) fn encode_payload<T: Serialize>(
    value: &T,
) -> Result<Zeroizing<Vec<u8>>, RuntimeStoreError> {
    let encoded = Zeroizing::new(
        serde_json::to_vec(value).map_err(|_| RuntimeStoreError::UnknownOrCorruptSchema)?,
    );
    if encoded.len() > MAX_STATE_PLAINTEXT_BYTES {
        return Err(RuntimeStoreError::PayloadTooLarge);
    }
    Ok(encoded)
}

pub(super) fn decode_payload<T>(bytes: &[u8]) -> Result<T, RuntimeStoreError>
where
    T: Serialize + for<'de> Deserialize<'de>,
{
    let decoded: T =
        serde_json::from_slice(bytes).map_err(|_| RuntimeStoreError::UnknownOrCorruptSchema)?;
    let canonical = encode_payload(&decoded)?;
    if canonical.as_slice() != bytes {
        return Err(RuntimeStoreError::UnknownOrCorruptSchema);
    }
    Ok(decoded)
}

pub(super) fn prepared_payload_hash(
    payload: &PreparedPayloadV1,
) -> Result<[u8; 32], RuntimeStoreError> {
    Ok(Sha256::digest(encode_payload(payload)?.as_slice()).into())
}

pub(super) fn prepare_input_hash(payload: &LoadedPayload) -> Result<[u8; 32], RuntimeStoreError> {
    match payload {
        LoadedPayload::Prepared(payload) => prepared_payload_hash(payload),
        LoadedPayload::Validated(payload) => prepared_payload_hash(&payload.prepared),
        LoadedPayload::Active(payload) if payload.prepare_input_hash != [0; 32] => {
            Ok(payload.prepare_input_hash)
        }
        LoadedPayload::Active(_) => Err(RuntimeStoreError::UnknownOrCorruptSchema),
        LoadedPayload::RetirePending(payload) => Ok(payload.active.prepare_input_hash),
        LoadedPayload::RelayCommitted(payload) => Ok(payload.pending.active.prepare_input_hash),
        LoadedPayload::PurgeReadbackAbsent(PurgeReadbackPayload::RootPresent(payload)) => {
            Ok(payload.committed.pending.active.prepare_input_hash)
        }
        LoadedPayload::PurgeReadbackAbsent(PurgeReadbackPayload::RootLost(payload)) => {
            Ok(payload.active.prepare_input_hash)
        }
        LoadedPayload::LocalDeleted(payload) => Ok(payload.previous_prepare_input_hash),
    }
}

pub(super) fn seal_payload(
    key_bundle: &RuntimeKeyBundle,
    database_id: [u8; 16],
    canonical: &[u8],
) -> Result<Vec<u8>, RuntimeStoreError> {
    Ok(key_bundle.row_cipher().seal_bounded(
        &RowAad {
            schema_family: super::super::schema::RUNTIME_SCHEMA_FAMILY.as_bytes(),
            schema_version: super::super::schema::RUNTIME_CRYPTO_CONTEXT_VERSION,
            database_id: &database_id,
            table: b"machine_remote_state",
            primary_key: ROW_PRIMARY_KEY,
            column: ROW_COLUMN,
        },
        canonical,
        MAX_STATE_PLAINTEXT_BYTES,
    )?)
}

pub(super) fn open_payload(
    key_bundle: &RuntimeKeyBundle,
    database_id: [u8; 16],
    sealed: &[u8],
) -> Result<crate::security::SecretBytes, RuntimeStoreError> {
    Ok(key_bundle.row_cipher().open_bounded(
        &RowAad {
            schema_family: super::super::schema::RUNTIME_SCHEMA_FAMILY.as_bytes(),
            schema_version: super::super::schema::RUNTIME_CRYPTO_CONTEXT_VERSION,
            database_id: &database_id,
            table: b"machine_remote_state",
            primary_key: ROW_PRIMARY_KEY,
            column: ROW_COLUMN,
        },
        sealed,
        MAX_STATE_PLAINTEXT_BYTES,
    )?)
}

pub(super) fn row_token(
    key_bundle: &RuntimeKeyBundle,
    database_id: [u8; 16],
    record: &MachineRemoteStateRecord,
    reset_kind: Option<&str>,
    sealed_state: &[u8],
) -> Result<[u8; 32], RuntimeStoreError> {
    let mut message = Vec::with_capacity(320);
    message.extend_from_slice(&database_id);
    message.push(lifecycle_tag(record.lifecycle));
    match reset_kind {
        None => message.push(0),
        Some(value) => {
            message.push(1);
            message.extend_from_slice(&(value.len() as u64).to_be_bytes());
            message.extend_from_slice(value.as_bytes());
        }
    }
    message.extend_from_slice(&record.relay_server_id);
    message.extend_from_slice(&record.machine_route);
    message.extend_from_slice(&record.root_key_id);
    message.extend_from_slice(&record.root_fingerprint);
    message.extend_from_slice(&record.trust_epoch.to_be_bytes());
    message.extend_from_slice(&record.request_hash);
    encode_optional_hash(&mut message, record.response_hash);
    encode_optional_hash(&mut message, record.enrollment_receipt_hash);
    message.extend_from_slice(&record.receipt_verify_key_hash);
    message.extend_from_slice(
        &u64::try_from(record.sealed_state_bytes)
            .map_err(|_| RuntimeStoreError::UnknownOrCorruptSchema)?
            .to_be_bytes(),
    );
    message.extend_from_slice(&Sha256::digest(sealed_state));
    Ok(*key_bundle
        .blind_index(ROW_METADATA_DOMAIN, &message)?
        .as_bytes())
}

pub(super) fn encode_optional_hash(message: &mut Vec<u8>, value: Option<[u8; 32]>) {
    match value {
        None => message.push(0),
        Some(value) => {
            message.push(1);
            message.extend_from_slice(&value);
        }
    }
}

pub(super) const fn lifecycle_tag(lifecycle: MachineRemoteLifecycle) -> u8 {
    match lifecycle {
        MachineRemoteLifecycle::EnrollmentPrepared => 0,
        MachineRemoteLifecycle::EnrollmentResponseValidated => 1,
        MachineRemoteLifecycle::Active => 2,
        MachineRemoteLifecycle::RetirePending => 3,
        MachineRemoteLifecycle::RelayCommitted => 4,
        MachineRemoteLifecycle::PurgeReadbackAbsent => 5,
        MachineRemoteLifecycle::LocalDeleted => 6,
    }
}

pub(super) const fn lifecycle_name(lifecycle: MachineRemoteLifecycle) -> &'static str {
    match lifecycle {
        MachineRemoteLifecycle::EnrollmentPrepared => "enrollmentPrepared",
        MachineRemoteLifecycle::EnrollmentResponseValidated => "enrollmentResponseValidated",
        MachineRemoteLifecycle::Active => "active",
        MachineRemoteLifecycle::RetirePending => "retirePending",
        MachineRemoteLifecycle::RelayCommitted => "relayCommitted",
        MachineRemoteLifecycle::PurgeReadbackAbsent => "purgeReadbackAbsent",
        MachineRemoteLifecycle::LocalDeleted => "localDeleted",
    }
}

pub(super) const fn reset_kind_name(reset_kind: MachineTrustResetKind) -> &'static str {
    match reset_kind {
        MachineTrustResetKind::RootPresent => "rootPresent",
        MachineTrustResetKind::RootLost => "rootLost",
    }
}

pub(super) fn parse_reset_kind(
    value: Option<&str>,
) -> Result<Option<MachineTrustResetKind>, RuntimeStoreError> {
    match value {
        None => Ok(None),
        Some("rootPresent") => Ok(Some(MachineTrustResetKind::RootPresent)),
        Some("rootLost") => Ok(Some(MachineTrustResetKind::RootLost)),
        Some(_) => Err(RuntimeStoreError::UnknownOrCorruptSchema),
    }
}

pub(super) fn parse_lifecycle(value: &str) -> Result<MachineRemoteLifecycle, RuntimeStoreError> {
    match value {
        "enrollmentPrepared" => Ok(MachineRemoteLifecycle::EnrollmentPrepared),
        "enrollmentResponseValidated" => Ok(MachineRemoteLifecycle::EnrollmentResponseValidated),
        "active" => Ok(MachineRemoteLifecycle::Active),
        "retirePending" => Ok(MachineRemoteLifecycle::RetirePending),
        "relayCommitted" => Ok(MachineRemoteLifecycle::RelayCommitted),
        "purgeReadbackAbsent" => Ok(MachineRemoteLifecycle::PurgeReadbackAbsent),
        "localDeleted" => Ok(MachineRemoteLifecycle::LocalDeleted),
        _ => Err(RuntimeStoreError::UnknownOrCorruptSchema),
    }
}

pub(super) fn fixed<const N: usize>(value: Vec<u8>) -> Result<[u8; N], RuntimeStoreError> {
    value
        .try_into()
        .map_err(|_| RuntimeStoreError::UnknownOrCorruptSchema)
}

pub(super) fn optional_fixed<const N: usize>(
    value: Option<Vec<u8>>,
) -> Result<Option<[u8; N]>, RuntimeStoreError> {
    value.map(fixed).transpose()
}

pub(super) fn decode_u64(value: &str) -> Result<u64, RuntimeStoreError> {
    if value.len() != super::super::sequence::SEQUENCE_TEXT_WIDTH
        || !value.as_bytes().iter().all(u8::is_ascii_digit)
    {
        return Err(RuntimeStoreError::UnknownOrCorruptSchema);
    }
    let decoded = value
        .parse::<u64>()
        .map_err(|_| RuntimeStoreError::UnknownOrCorruptSchema)?;
    if super::super::sequence::encode_sequence(decoded) != value {
        return Err(RuntimeStoreError::UnknownOrCorruptSchema);
    }
    Ok(decoded)
}

pub(super) fn raw_row(row: &rusqlite::Row<'_>) -> Result<RawRow, rusqlite::Error> {
    Ok(RawRow {
        lifecycle: row.get(0)?,
        reset_kind: row.get(1)?,
        database_id: row.get(2)?,
        relay_server_id: row.get(3)?,
        machine_route: row.get(4)?,
        root_key_id: row.get(5)?,
        root_fingerprint: row.get(6)?,
        trust_epoch: row.get(7)?,
        request_hash: row.get(8)?,
        response_hash: row.get(9)?,
        enrollment_receipt_hash: row.get(10)?,
        receipt_verify_key_hash: row.get(11)?,
        sealed_state: row.get(12)?,
        sealed_state_bytes: row.get(13)?,
        metadata_token: row.get(14)?,
    })
}

pub(super) fn load_authenticated_row(
    connection: &Connection,
    key_bundle: &RuntimeKeyBundle,
    expected_database_id: [u8; 16],
) -> Result<Option<AuthenticatedRow>, RuntimeStoreError> {
    let raw = connection
        .query_row(
            "SELECT lifecycle, reset_kind, database_id, relay_server_id, machine_route,
                    root_key_id, root_fingerprint, trust_epoch, request_hash, response_hash,
                    enrollment_receipt_hash, receipt_verify_key_hash, sealed_state,
                    sealed_state_bytes, metadata_token
             FROM machine_remote_state WHERE singleton = 1",
            [],
            raw_row,
        )
        .optional()?;
    raw.map(|raw| authenticate_row(key_bundle, expected_database_id, raw))
        .transpose()
}

pub(super) fn authenticate_row(
    key_bundle: &RuntimeKeyBundle,
    expected_database_id: [u8; 16],
    raw: RawRow,
) -> Result<AuthenticatedRow, RuntimeStoreError> {
    let database_id = fixed(raw.database_id)?;
    let reset_kind = parse_reset_kind(raw.reset_kind.as_deref())?;
    let sealed_state_bytes = usize::try_from(raw.sealed_state_bytes)
        .map_err(|_| RuntimeStoreError::UnknownOrCorruptSchema)?;
    let record = MachineRemoteStateRecord {
        lifecycle: parse_lifecycle(&raw.lifecycle)?,
        relay_server_id: fixed(raw.relay_server_id)?,
        machine_route: fixed(raw.machine_route)?,
        root_key_id: fixed(raw.root_key_id)?,
        root_fingerprint: fixed(raw.root_fingerprint)?,
        trust_epoch: decode_u64(&raw.trust_epoch)?,
        request_hash: fixed(raw.request_hash)?,
        response_hash: optional_fixed(raw.response_hash)?,
        enrollment_receipt_hash: optional_fixed(raw.enrollment_receipt_hash)?,
        receipt_verify_key_hash: fixed(raw.receipt_verify_key_hash)?,
        sealed_state_bytes,
    };
    let metadata_token = fixed(raw.metadata_token)?;
    if database_id != expected_database_id
        || !valid_lifecycle_reset(record.lifecycle, reset_kind)
        || sealed_state_bytes != raw.sealed_state.len()
        || row_token(
            key_bundle,
            database_id,
            &record,
            raw.reset_kind.as_deref(),
            &raw.sealed_state,
        )? != metadata_token
    {
        return Err(RuntimeStoreError::UnknownOrCorruptSchema);
    }
    let plaintext = open_payload(key_bundle, database_id, &raw.sealed_state)?;
    let payload = match record.lifecycle {
        MachineRemoteLifecycle::EnrollmentPrepared => {
            LoadedPayload::Prepared(decode_payload(plaintext.expose_secret())?)
        }
        MachineRemoteLifecycle::EnrollmentResponseValidated => {
            LoadedPayload::Validated(decode_payload(plaintext.expose_secret())?)
        }
        MachineRemoteLifecycle::Active => {
            LoadedPayload::Active(decode_payload(plaintext.expose_secret())?)
        }
        MachineRemoteLifecycle::RetirePending => {
            LoadedPayload::RetirePending(decode_payload(plaintext.expose_secret())?)
        }
        MachineRemoteLifecycle::RelayCommitted => {
            LoadedPayload::RelayCommitted(decode_payload(plaintext.expose_secret())?)
        }
        MachineRemoteLifecycle::PurgeReadbackAbsent => match reset_kind {
            Some(MachineTrustResetKind::RootPresent) => LoadedPayload::PurgeReadbackAbsent(
                PurgeReadbackPayload::RootPresent(decode_payload(plaintext.expose_secret())?),
            ),
            Some(MachineTrustResetKind::RootLost) => LoadedPayload::PurgeReadbackAbsent(
                PurgeReadbackPayload::RootLost(decode_payload(plaintext.expose_secret())?),
            ),
            None => return Err(RuntimeStoreError::UnknownOrCorruptSchema),
        },
        MachineRemoteLifecycle::LocalDeleted => {
            LoadedPayload::LocalDeleted(decode_payload(plaintext.expose_secret())?)
        }
    };
    validate_loaded_payload(&record, reset_kind, &payload)?;
    Ok(AuthenticatedRow {
        database_id,
        record,
        metadata_token,
        payload,
    })
}

pub(super) const fn valid_lifecycle_reset(
    lifecycle: MachineRemoteLifecycle,
    reset_kind: Option<MachineTrustResetKind>,
) -> bool {
    match lifecycle {
        MachineRemoteLifecycle::EnrollmentPrepared
        | MachineRemoteLifecycle::EnrollmentResponseValidated
        | MachineRemoteLifecycle::Active => reset_kind.is_none(),
        MachineRemoteLifecycle::RetirePending | MachineRemoteLifecycle::RelayCommitted => {
            matches!(reset_kind, Some(MachineTrustResetKind::RootPresent))
        }
        MachineRemoteLifecycle::PurgeReadbackAbsent | MachineRemoteLifecycle::LocalDeleted => {
            reset_kind.is_some()
        }
    }
}

pub(super) fn validate_loaded_payload(
    record: &MachineRemoteStateRecord,
    reset_kind: Option<MachineTrustResetKind>,
    payload: &LoadedPayload,
) -> Result<(), RuntimeStoreError> {
    match payload {
        LoadedPayload::Prepared(payload) => {
            if payload.version != PAYLOAD_VERSION
                || record.response_hash.is_some()
                || record.enrollment_receipt_hash.is_some()
            {
                return Err(RuntimeStoreError::UnknownOrCorruptSchema);
            }
            validate_prepared_against_record(record, payload)
        }
        LoadedPayload::Validated(payload) => {
            if payload.version != PAYLOAD_VERSION
                || record.response_hash.is_none()
                || record.enrollment_receipt_hash.is_some()
            {
                return Err(RuntimeStoreError::UnknownOrCorruptSchema);
            }
            validate_prepared_against_record(record, &payload.prepared)?;
            validate_response(record, &payload.response)
                .map_err(|_| RuntimeStoreError::UnknownOrCorruptSchema)?;
            if payload
                .response
                .canonical_sha256()
                .map_err(|_| RuntimeStoreError::UnknownOrCorruptSchema)?
                != record.response_hash.unwrap_or([0; 32])
            {
                return Err(RuntimeStoreError::UnknownOrCorruptSchema);
            }
            Ok(())
        }
        LoadedPayload::Active(payload) => validate_active_payload(record, payload),
        LoadedPayload::RetirePending(payload) => {
            if !matches!(reset_kind, Some(MachineTrustResetKind::RootPresent)) {
                return Err(RuntimeStoreError::UnknownOrCorruptSchema);
            }
            validate_retire_pending_payload(record, payload)
        }
        LoadedPayload::RelayCommitted(payload) => {
            if !matches!(reset_kind, Some(MachineTrustResetKind::RootPresent)) {
                return Err(RuntimeStoreError::UnknownOrCorruptSchema);
            }
            validate_relay_committed_payload(record, payload)
        }
        LoadedPayload::PurgeReadbackAbsent(PurgeReadbackPayload::RootPresent(payload)) => {
            if payload.version != PAYLOAD_VERSION
                || !matches!(reset_kind, Some(MachineTrustResetKind::RootPresent))
            {
                return Err(RuntimeStoreError::UnknownOrCorruptSchema);
            }
            validate_relay_committed_payload(record, &payload.committed)
        }
        LoadedPayload::PurgeReadbackAbsent(PurgeReadbackPayload::RootLost(payload)) => {
            if payload.version != PAYLOAD_VERSION
                || !matches!(reset_kind, Some(MachineTrustResetKind::RootLost))
            {
                return Err(RuntimeStoreError::UnknownOrCorruptSchema);
            }
            validate_active_payload(record, &payload.active)?;
            let prepared = prepare_root_lost_purge_write(payload.receipt.clone())
                .map_err(|_| RuntimeStoreError::UnknownOrCorruptSchema)?;
            if payload.receipt_bytes != *prepared.canonical
                || payload.receipt_hash != prepared.canonical_hash
            {
                return Err(RuntimeStoreError::UnknownOrCorruptSchema);
            }
            validate_root_lost_receipt(record, &payload.active, &payload.receipt)
                .map_err(|_| RuntimeStoreError::UnknownOrCorruptSchema)
        }
        LoadedPayload::LocalDeleted(payload) => {
            validate_local_deleted_payload(record, reset_kind, payload)
        }
    }
}

pub(super) fn validate_local_deleted_payload(
    record: &MachineRemoteStateRecord,
    reset_kind: Option<MachineTrustResetKind>,
    payload: &LocalDeletedPayloadV1,
) -> Result<(), RuntimeStoreError> {
    let payload_reset = MachineTrustResetKind::from(payload.reset_kind);
    if payload.version != PAYLOAD_VERSION
        || reset_kind != Some(payload_reset)
        || payload.relay_server_id.as_bytes() != &record.relay_server_id
        || payload.machine_route.as_bytes() != &record.machine_route
        || payload.root_key_id.as_bytes() != &record.root_key_id
        || payload.root_fingerprint != record.root_fingerprint
        || payload.trust_epoch.value() != record.trust_epoch
        || payload.previous_prepare_input_hash == [0; 32]
        || payload.purge_proof_hash == [0; 32]
        || payload.cleanup_witness_hash == [0; 32]
        || record.response_hash.is_none()
        || record.enrollment_receipt_hash.is_none()
    {
        return Err(RuntimeStoreError::UnknownOrCorruptSchema);
    }
    let witness = MachineCleanupWitnessV1::new(
        payload_reset,
        payload.relay_server_id,
        payload.machine_route,
        payload.root_key_id,
        payload.root_fingerprint,
        payload.trust_epoch,
        payload.purge_proof_hash,
    )
    .map_err(|_| RuntimeStoreError::UnknownOrCorruptSchema)?;
    if witness.canonical_sha256() != payload.cleanup_witness_hash {
        return Err(RuntimeStoreError::UnknownOrCorruptSchema);
    }
    Ok(())
}

pub(super) fn validate_active_payload(
    record: &MachineRemoteStateRecord,
    payload: &ActivePayloadV1,
) -> Result<(), RuntimeStoreError> {
    if payload.version != PAYLOAD_VERSION
        || payload.prepare_input_hash == [0; 32]
        || record.response_hash.is_none()
        || record.enrollment_receipt_hash != Some(payload.response.receipt_hash)
    {
        return Err(RuntimeStoreError::UnknownOrCorruptSchema);
    }
    let binding: MachineIdentityBinding = payload.binding.clone().into();
    validate_connection(&payload.connection)?;
    validate_route_and_binding(
        payload.machine_route,
        &binding,
        &payload.link_cert,
        &payload.data_cert,
        &payload.connection,
    )
    .map_err(|_| RuntimeStoreError::UnknownOrCorruptSchema)?;
    validate_common(record, &payload.connection, payload.machine_route, &binding)?;
    validate_response(record, &payload.response)
        .map_err(|_| RuntimeStoreError::UnknownOrCorruptSchema)?;
    if payload
        .response
        .canonical_sha256()
        .map_err(|_| RuntimeStoreError::UnknownOrCorruptSchema)?
        != record.response_hash.unwrap_or([0; 32])
    {
        return Err(RuntimeStoreError::UnknownOrCorruptSchema);
    }
    Ok(())
}

pub(super) fn validate_retire_pending_payload(
    record: &MachineRemoteStateRecord,
    payload: &RetirePendingPayloadV1,
) -> Result<(), RuntimeStoreError> {
    if payload.version != PAYLOAD_VERSION
        || payload.retirement_bytes != payload.retirement.canonical_bytes()
        || payload.retirement_hash != sha256(&payload.retirement_bytes)
    {
        return Err(RuntimeStoreError::UnknownOrCorruptSchema);
    }
    validate_active_payload(record, &payload.active)?;
    validate_retirement(record, &payload.active, &payload.retirement)
        .map_err(|_| RuntimeStoreError::UnknownOrCorruptSchema)
}

pub(super) fn validate_relay_committed_payload(
    record: &MachineRemoteStateRecord,
    payload: &RelayCommittedPayloadV1,
) -> Result<(), RuntimeStoreError> {
    if payload.version != PAYLOAD_VERSION {
        return Err(RuntimeStoreError::UnknownOrCorruptSchema);
    }
    validate_retire_pending_payload(record, &payload.pending)?;
    let prepared = prepare_terminal_write(
        payload.terminal_frame_bytes.clone(),
        payload.terminal_frame_hash,
    )
    .map_err(|_| RuntimeStoreError::UnknownOrCorruptSchema)?;
    if payload.terminal != prepared.committed {
        return Err(RuntimeStoreError::UnknownOrCorruptSchema);
    }
    validate_terminal(&payload.pending, &prepared)
        .map_err(|_| RuntimeStoreError::UnknownOrCorruptSchema)
}

pub(super) fn validate_prepared_against_record(
    record: &MachineRemoteStateRecord,
    payload: &PreparedPayloadV1,
) -> Result<(), RuntimeStoreError> {
    if payload.version != PAYLOAD_VERSION {
        return Err(RuntimeStoreError::UnknownOrCorruptSchema);
    }
    validate_connection(&payload.connection)?;
    let binding: MachineIdentityBinding = payload.binding.clone().into();
    validate_route_and_binding(
        payload.machine_route,
        &binding,
        &payload.link_cert,
        &payload.data_cert,
        &payload.connection,
    )
    .map_err(|_| RuntimeStoreError::UnknownOrCorruptSchema)?;
    validate_common(record, &payload.connection, payload.machine_route, &binding)?;
    if request_from_prepared(payload).canonical_sha256() != record.request_hash {
        return Err(RuntimeStoreError::UnknownOrCorruptSchema);
    }
    Ok(())
}

pub(super) fn validate_connection(
    connection: &StoredConnectionV1,
) -> Result<(), RuntimeStoreError> {
    let bundle = EnrollmentBundleV2 {
        version: ENROLLMENT_BUNDLE_VERSION,
        public_wss_url: connection.public_wss_url.clone(),
        relay_server_id: connection.relay_server_id,
        receipt_verify_key: connection.receipt_verify_key.clone(),
        code: EnrollmentCode([1; 32]),
        spki_pins: connection.spki_pins.clone(),
        expires_at_ms: connection.expires_at_ms,
    };
    validate_bundle(&bundle)
        .map(|_| ())
        .map_err(|_| RuntimeStoreError::UnknownOrCorruptSchema)
}

pub(super) fn validate_common(
    record: &MachineRemoteStateRecord,
    connection: &StoredConnectionV1,
    machine_route: MachineRouteId,
    binding: &MachineIdentityBinding,
) -> Result<(), RuntimeStoreError> {
    let anchor_hash = connection
        .receipt_verify_key
        .canonical_sha256()
        .map_err(|_| RuntimeStoreError::UnknownOrCorruptSchema)?;
    if record.relay_server_id != *connection.relay_server_id.as_bytes()
        || record.machine_route != *machine_route.as_bytes()
        || record.root_key_id != binding.root_key_id
        || record.root_fingerprint != binding.root_fingerprint
        || record.trust_epoch != binding.trust_epoch
        || record.request_hash == [0; 32]
        || record.receipt_verify_key_hash != anchor_hash
    {
        return Err(RuntimeStoreError::UnknownOrCorruptSchema);
    }
    Ok(())
}

pub(super) fn insert_row(
    transaction: &Transaction<'_>,
    database_id: [u8; 16],
    record: &MachineRemoteStateRecord,
    sealed_state: &[u8],
    metadata_token: [u8; 32],
) -> Result<(), RuntimeStoreError> {
    if transaction.execute(
        "INSERT INTO machine_remote_state (
             singleton, lifecycle, reset_kind, database_id, relay_server_id, machine_route,
             root_key_id, root_fingerprint, trust_epoch, request_hash, response_hash,
             enrollment_receipt_hash, receipt_verify_key_hash, sealed_state,
             sealed_state_bytes, metadata_token
         ) VALUES (1, ?1, NULL, ?2, ?3, ?4, ?5, ?6, ?7, ?8, NULL, NULL, ?9, ?10, ?11, ?12)",
        params![
            lifecycle_name(record.lifecycle),
            &database_id[..],
            &record.relay_server_id[..],
            &record.machine_route[..],
            &record.root_key_id[..],
            &record.root_fingerprint[..],
            super::super::sequence::encode_sequence(record.trust_epoch),
            &record.request_hash[..],
            &record.receipt_verify_key_hash[..],
            sealed_state,
            i64::try_from(record.sealed_state_bytes)
                .map_err(|_| RuntimeStoreError::UnknownOrCorruptSchema)?,
            &metadata_token[..],
        ],
    )? != 1
    {
        return Err(RuntimeStoreError::MachineRemoteConflict);
    }
    Ok(())
}

pub(super) fn update_row(
    transaction: &Transaction<'_>,
    previous_lifecycle: &str,
    previous_token: &[u8; 32],
    record: &MachineRemoteStateRecord,
    reset_kind: Option<&str>,
    sealed_state: &[u8],
    metadata_token: [u8; 32],
) -> Result<usize, RuntimeStoreError> {
    Ok(transaction.execute(
        "UPDATE machine_remote_state
         SET lifecycle = ?1, reset_kind = ?2, relay_server_id = ?3,
             machine_route = ?4, root_key_id = ?5, root_fingerprint = ?6,
             trust_epoch = ?7, request_hash = ?8, response_hash = ?9,
             enrollment_receipt_hash = ?10, receipt_verify_key_hash = ?11,
             sealed_state = ?12, sealed_state_bytes = ?13, metadata_token = ?14
         WHERE singleton = 1 AND lifecycle = ?15 AND metadata_token = ?16",
        params![
            lifecycle_name(record.lifecycle),
            reset_kind,
            &record.relay_server_id[..],
            &record.machine_route[..],
            &record.root_key_id[..],
            &record.root_fingerprint[..],
            super::super::sequence::encode_sequence(record.trust_epoch),
            &record.request_hash[..],
            record.response_hash.as_ref().map(|value| &value[..]),
            record
                .enrollment_receipt_hash
                .as_ref()
                .map(|value| &value[..]),
            &record.receipt_verify_key_hash[..],
            sealed_state,
            i64::try_from(record.sealed_state_bytes)
                .map_err(|_| RuntimeStoreError::UnknownOrCorruptSchema)?,
            &metadata_token[..],
            previous_lifecycle,
            &previous_token[..],
        ],
    )?)
}

pub(super) fn insert_locator_mirror(
    transaction: &Transaction<'_>,
    record: &MachineRemoteStateRecord,
) -> Result<(), RuntimeStoreError> {
    transaction.execute(
        "INSERT INTO machine_enrollment_receipts (
             relay_server_id, machine_route, root_fingerprint
         ) VALUES (?1, ?2, ?3)
         ON CONFLICT(relay_server_id, machine_route) DO NOTHING",
        params![
            &record.relay_server_id[..],
            &record.machine_route[..],
            &record.root_fingerprint[..],
        ],
    )?;
    let fingerprint: Vec<u8> = transaction.query_row(
        "SELECT root_fingerprint FROM machine_enrollment_receipts
         WHERE relay_server_id = ?1 AND machine_route = ?2",
        params![&record.relay_server_id[..], &record.machine_route[..]],
        |row| row.get(0),
    )?;
    if fingerprint.as_slice() != record.root_fingerprint {
        return Err(RuntimeStoreError::MachineRemoteConflict);
    }
    Ok(())
}

pub(super) fn validate_locator_mirror(
    connection: &Connection,
    record: &MachineRemoteStateRecord,
) -> Result<(), RuntimeStoreError> {
    let fingerprint: Option<Vec<u8>> = connection
        .query_row(
            "SELECT root_fingerprint FROM machine_enrollment_receipts
             WHERE relay_server_id = ?1 AND machine_route = ?2",
            params![&record.relay_server_id[..], &record.machine_route[..]],
            |row| row.get(0),
        )
        .optional()?;
    if fingerprint.as_deref() != Some(&record.root_fingerprint[..]) {
        return Err(RuntimeStoreError::UnknownOrCorruptSchema);
    }
    Ok(())
}

pub(super) fn delete_locator_mirror(
    transaction: &Transaction<'_>,
    record: &MachineRemoteStateRecord,
) -> Result<(), RuntimeStoreError> {
    if transaction.execute(
        "DELETE FROM machine_enrollment_receipts
         WHERE relay_server_id = ?1 AND machine_route = ?2 AND root_fingerprint = ?3",
        params![
            &record.relay_server_id[..],
            &record.machine_route[..],
            &record.root_fingerprint[..],
        ],
    )? != 1
    {
        return Err(RuntimeStoreError::UnknownOrCorruptSchema);
    }
    Ok(())
}

pub(super) fn validate_locator_absent(
    connection: &Connection,
    record: &MachineRemoteStateRecord,
) -> Result<(), RuntimeStoreError> {
    let count: i64 = connection.query_row(
        "SELECT COUNT(*) FROM machine_enrollment_receipts
         WHERE relay_server_id = ?1 AND machine_route = ?2",
        params![&record.relay_server_id[..], &record.machine_route[..]],
        |row| row.get(0),
    )?;
    if count != 0 {
        return Err(RuntimeStoreError::UnknownOrCorruptSchema);
    }
    Ok(())
}

pub(super) fn into_public_state(row: AuthenticatedRow) -> MachineEnrollmentState {
    let database_id = row.database_id;
    let record = row.record;
    match row.payload {
        LoadedPayload::Prepared(payload) => {
            let request = request_from_prepared(&payload);
            MachineEnrollmentState::EnrollmentPrepared(Box::new(PreparedMachineEnrollmentState {
                record,
                connection: connection_material(payload.connection),
                request,
            }))
        }
        LoadedPayload::Validated(payload) => {
            let request = request_from_prepared(&payload.prepared);
            MachineEnrollmentState::EnrollmentResponseValidated(Box::new(
                ValidatedMachineEnrollmentState {
                    record,
                    connection: connection_material(payload.prepared.connection),
                    request,
                    response: payload.response,
                },
            ))
        }
        LoadedPayload::Active(payload) => {
            MachineEnrollmentState::Active(Box::new(ActiveMachineEnrollmentState {
                record,
                connection: connection_material(payload.connection),
                binding: payload.binding.into(),
                link_cert: payload.link_cert,
                data_cert: payload.data_cert,
                prepare_input_hash: payload.prepare_input_hash,
                response: payload.response,
            }))
        }
        LoadedPayload::RetirePending(payload) => {
            let RetirePendingPayloadV1 {
                active,
                retirement,
                retirement_bytes,
                retirement_hash,
                ..
            } = payload;
            MachineEnrollmentState::RetirePending(Box::new(RetirePendingMachineEnrollmentState {
                record,
                connection: connection_material(active.connection),
                binding: active.binding.into(),
                link_cert: active.link_cert,
                retirement: MachineRetirementRequestMaterial {
                    retirement,
                    canonical_bytes: retirement_bytes,
                    canonical_hash: retirement_hash,
                },
            }))
        }
        LoadedPayload::RelayCommitted(payload) => {
            let (retirement, terminal) = root_present_material(payload);
            MachineEnrollmentState::RelayCommitted(Box::new(RelayCommittedMachineEnrollmentState {
                record,
                retirement,
                terminal,
            }))
        }
        LoadedPayload::PurgeReadbackAbsent(PurgeReadbackPayload::RootPresent(payload)) => {
            let binding = payload.committed.pending.active.binding.clone().into();
            let (retirement, terminal) = root_present_material(payload.committed);
            MachineEnrollmentState::PurgeReadbackAbsent(Box::new(
                PurgeReadbackAbsentMachineEnrollmentState {
                    record,
                    database_id,
                    binding,
                    reset_kind: MachineTrustResetKind::RootPresent,
                    proof: MachinePurgeReadbackProof::RootPresent {
                        retirement,
                        terminal,
                    },
                },
            ))
        }
        LoadedPayload::PurgeReadbackAbsent(PurgeReadbackPayload::RootLost(payload)) => {
            let binding = payload.active.binding.clone().into();
            MachineEnrollmentState::PurgeReadbackAbsent(Box::new(
                PurgeReadbackAbsentMachineEnrollmentState {
                    record,
                    database_id,
                    binding,
                    reset_kind: MachineTrustResetKind::RootLost,
                    proof: MachinePurgeReadbackProof::RootLost {
                        purge: MachineRootLostPurgeMaterial {
                            receipt: payload.receipt,
                            canonical_bytes: payload.receipt_bytes,
                            canonical_hash: payload.receipt_hash,
                        },
                    },
                },
            ))
        }
        LoadedPayload::LocalDeleted(payload) => {
            MachineEnrollmentState::LocalDeleted(Box::new(LocalDeletedMachineEnrollmentState {
                record,
                reset_kind: payload.reset_kind.into(),
                previous_prepare_input_hash: payload.previous_prepare_input_hash,
                purge_proof_hash: payload.purge_proof_hash,
                cleanup_witness_hash: payload.cleanup_witness_hash,
            }))
        }
    }
}

pub(super) fn root_present_material(
    payload: RelayCommittedPayloadV1,
) -> (
    MachineRetirementRequestMaterial,
    MachineRetirementTerminalMaterial,
) {
    (
        MachineRetirementRequestMaterial {
            retirement: payload.pending.retirement,
            canonical_bytes: payload.pending.retirement_bytes,
            canonical_hash: payload.pending.retirement_hash,
        },
        MachineRetirementTerminalMaterial {
            committed: payload.terminal,
            canonical_frame_bytes: payload.terminal_frame_bytes,
            canonical_frame_hash: payload.terminal_frame_hash,
        },
    )
}

pub(super) fn connection_material(
    value: StoredConnectionV1,
) -> MachineEnrollmentConnectionMaterial {
    MachineEnrollmentConnectionMaterial {
        public_wss_url: value.public_wss_url,
        relay_server_id: value.relay_server_id,
        receipt_verify_key: value.receipt_verify_key,
        spki_pins: value.spki_pins,
        expires_at_ms: value.expires_at_ms,
    }
}
