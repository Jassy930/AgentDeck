//! Runtime v8 authenticated machine identity public binding。
//!
//! 本模块只持久化 public key/fingerprint 与单调元数据；私钥 seed、HPKE IKM、
//! StorageKEK、CounterGuard material 和 certificate 永不进入 Runtime DB。

use rusqlite::{Connection, OptionalExtension, TransactionBehavior, params};
use sha2::{Digest, Sha256};

use crate::runtime::model::{
    ActivateMachineIdentityOutcome, MachineIdentityBinding, MachineIdentityLifecycle,
    MachineIdentityStateRecord, PrepareMachineIdentityOutcome, RuntimeCommitOperation,
    RuntimeStoreConfig, RuntimeStoreError, RuntimeStoreOperation,
};

use super::cipher::RuntimeKeyBundle;
use super::sqlite::{RuntimeLedger, RuntimeSqlite};

const METADATA_DOMAIN: &[u8] = b"machine.identity.metadata.v1";

impl MachineIdentityLifecycle {
    fn parse(value: &str) -> Result<Self, RuntimeStoreError> {
        match value {
            "preparing" => Ok(Self::Preparing),
            "active" => Ok(Self::Active),
            _ => Err(RuntimeStoreError::UnknownOrCorruptSchema),
        }
    }

    const fn tag(self) -> u8 {
        match self {
            Self::Preparing => 0,
            Self::Active => 1,
        }
    }
}

struct RawMachineIdentityRow {
    identity_state: String,
    database_id: Vec<u8>,
    root_key_id: Vec<u8>,
    trust_epoch: String,
    link_generation: String,
    data_generation: String,
    key_directory_revision: String,
    root_public_key: Vec<u8>,
    root_fingerprint: Vec<u8>,
    machine_hpke_public_key: Vec<u8>,
    machine_hpke_fingerprint: Vec<u8>,
    link_sign_public_key: Vec<u8>,
    link_sign_fingerprint: Vec<u8>,
    data_sign_public_key: Vec<u8>,
    data_sign_fingerprint: Vec<u8>,
    metadata_token: Vec<u8>,
}

fn fixed<const N: usize>(value: Vec<u8>) -> Result<[u8; N], RuntimeStoreError> {
    value
        .try_into()
        .map_err(|_| RuntimeStoreError::UnknownOrCorruptSchema)
}

fn decode_u64(value: &str) -> Result<u64, RuntimeStoreError> {
    if value.len() != super::sequence::SEQUENCE_TEXT_WIDTH
        || !value.as_bytes().iter().all(u8::is_ascii_digit)
    {
        return Err(RuntimeStoreError::UnknownOrCorruptSchema);
    }
    let decoded = value
        .parse::<u64>()
        .map_err(|_| RuntimeStoreError::UnknownOrCorruptSchema)?;
    if super::sequence::encode_sequence(decoded) != value {
        return Err(RuntimeStoreError::UnknownOrCorruptSchema);
    }
    Ok(decoded)
}

fn validate_binding(binding: &MachineIdentityBinding) -> Result<(), RuntimeStoreError> {
    if binding.root_key_id == [0; 16]
        || binding.trust_epoch == 0
        || binding.link_generation == 0
        || binding.data_generation == 0
    {
        return Err(RuntimeStoreError::MachineIdentityConflict);
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
        if public_key == &[0; 32] {
            return Err(RuntimeStoreError::MachineIdentityConflict);
        }
        let expected: [u8; 32] = Sha256::digest(public_key).into();
        if &expected != fingerprint {
            return Err(RuntimeStoreError::MachineIdentityConflict);
        }
    }
    Ok(())
}

fn row_token(
    key_bundle: &RuntimeKeyBundle,
    state: &MachineIdentityStateRecord,
) -> Result<[u8; 32], RuntimeStoreError> {
    let binding = &state.binding;
    let mut message = Vec::with_capacity(16 + 1 + 16 + 4 * 8 + 8 * 32);
    message.extend_from_slice(&state.database_id);
    message.push(state.lifecycle.tag());
    message.extend_from_slice(&binding.root_key_id);
    message.extend_from_slice(&binding.trust_epoch.to_be_bytes());
    message.extend_from_slice(&binding.link_generation.to_be_bytes());
    message.extend_from_slice(&binding.data_generation.to_be_bytes());
    message.extend_from_slice(&binding.key_directory_revision.to_be_bytes());
    message.extend_from_slice(&binding.root_public_key);
    message.extend_from_slice(&binding.root_fingerprint);
    message.extend_from_slice(&binding.machine_hpke_public_key);
    message.extend_from_slice(&binding.machine_hpke_fingerprint);
    message.extend_from_slice(&binding.link_sign_public_key);
    message.extend_from_slice(&binding.link_sign_fingerprint);
    message.extend_from_slice(&binding.data_sign_public_key);
    message.extend_from_slice(&binding.data_sign_fingerprint);
    Ok(*key_bundle
        .blind_index(METADATA_DOMAIN, &message)?
        .as_bytes())
}

fn raw_row(row: &rusqlite::Row<'_>) -> Result<RawMachineIdentityRow, rusqlite::Error> {
    Ok(RawMachineIdentityRow {
        identity_state: row.get(0)?,
        database_id: row.get(1)?,
        root_key_id: row.get(2)?,
        trust_epoch: row.get(3)?,
        link_generation: row.get(4)?,
        data_generation: row.get(5)?,
        key_directory_revision: row.get(6)?,
        root_public_key: row.get(7)?,
        root_fingerprint: row.get(8)?,
        machine_hpke_public_key: row.get(9)?,
        machine_hpke_fingerprint: row.get(10)?,
        link_sign_public_key: row.get(11)?,
        link_sign_fingerprint: row.get(12)?,
        data_sign_public_key: row.get(13)?,
        data_sign_fingerprint: row.get(14)?,
        metadata_token: row.get(15)?,
    })
}

fn authenticate_row(
    key_bundle: &RuntimeKeyBundle,
    expected_database_id: [u8; 16],
    raw: RawMachineIdentityRow,
) -> Result<MachineIdentityStateRecord, RuntimeStoreError> {
    let state = MachineIdentityStateRecord {
        database_id: fixed(raw.database_id)?,
        lifecycle: MachineIdentityLifecycle::parse(&raw.identity_state)?,
        binding: MachineIdentityBinding {
            root_key_id: fixed(raw.root_key_id)?,
            trust_epoch: decode_u64(&raw.trust_epoch)?,
            link_generation: decode_u64(&raw.link_generation)?,
            data_generation: decode_u64(&raw.data_generation)?,
            key_directory_revision: decode_u64(&raw.key_directory_revision)?,
            root_public_key: fixed(raw.root_public_key)?,
            root_fingerprint: fixed(raw.root_fingerprint)?,
            machine_hpke_public_key: fixed(raw.machine_hpke_public_key)?,
            machine_hpke_fingerprint: fixed(raw.machine_hpke_fingerprint)?,
            link_sign_public_key: fixed(raw.link_sign_public_key)?,
            link_sign_fingerprint: fixed(raw.link_sign_fingerprint)?,
            data_sign_public_key: fixed(raw.data_sign_public_key)?,
            data_sign_fingerprint: fixed(raw.data_sign_fingerprint)?,
        },
    };
    let metadata_token: [u8; 32] = fixed(raw.metadata_token)?;
    validate_binding(&state.binding).map_err(|_| RuntimeStoreError::UnknownOrCorruptSchema)?;
    if state.database_id != expected_database_id || row_token(key_bundle, &state)? != metadata_token
    {
        return Err(RuntimeStoreError::UnknownOrCorruptSchema);
    }
    Ok(state)
}

fn load_row(
    connection: &Connection,
    key_bundle: &RuntimeKeyBundle,
    database_id: [u8; 16],
) -> Result<Option<MachineIdentityStateRecord>, RuntimeStoreError> {
    let raw = connection
        .query_row(
            "SELECT identity_state, database_id, root_key_id, trust_epoch,
                    link_generation, data_generation, key_directory_revision,
                    root_public_key, root_fingerprint,
                    machine_hpke_public_key, machine_hpke_fingerprint,
                    link_sign_public_key, link_sign_fingerprint,
                    data_sign_public_key, data_sign_fingerprint, metadata_token
             FROM machine_identity_state WHERE singleton = 1",
            [],
            raw_row,
        )
        .optional()?;
    raw.map(|raw| authenticate_row(key_bundle, database_id, raw))
        .transpose()
}

pub(super) fn load_machine_identity_state(
    connection: &Connection,
    key_bundle: &RuntimeKeyBundle,
    database_id: [u8; 16],
) -> Result<Option<MachineIdentityStateRecord>, RuntimeStoreError> {
    let ledger = super::sqlite::load_runtime_ledger(connection, key_bundle, database_id)?;
    let state = load_row(connection, key_bundle, database_id)?;
    if ledger.machine_identity_count != u64::from(state.is_some()) {
        return Err(RuntimeStoreError::UnknownOrCorruptSchema);
    }
    Ok(state)
}

pub(super) fn validate_v8_integrity(
    connection: &Connection,
    key_bundle: &RuntimeKeyBundle,
    database_id: [u8; 16],
    ledger: &RuntimeLedger,
) -> Result<(), RuntimeStoreError> {
    let physical_count: i64 =
        connection.query_row("SELECT COUNT(*) FROM machine_identity_state", [], |row| {
            row.get(0)
        })?;
    let physical_count =
        u64::try_from(physical_count).map_err(|_| RuntimeStoreError::UnknownOrCorruptSchema)?;
    if physical_count > 1 || physical_count != ledger.machine_identity_count {
        return Err(RuntimeStoreError::UnknownOrCorruptSchema);
    }
    let state = load_row(connection, key_bundle, database_id)?;
    if u64::from(state.is_some()) != physical_count {
        return Err(RuntimeStoreError::UnknownOrCorruptSchema);
    }
    Ok(())
}

fn replay_prepare(
    state: Option<MachineIdentityStateRecord>,
    binding: &MachineIdentityBinding,
) -> Result<Option<PrepareMachineIdentityOutcome>, RuntimeStoreError> {
    match state {
        None => Ok(None),
        Some(state) if &state.binding == binding => {
            Ok(Some(PrepareMachineIdentityOutcome::Replayed { state }))
        }
        Some(_) => Err(RuntimeStoreError::MachineIdentityConflict),
    }
}

pub(super) fn prepare_machine_identity(
    state: &mut RuntimeSqlite,
    config: &RuntimeStoreConfig,
    binding: MachineIdentityBinding,
) -> Result<PrepareMachineIdentityOutcome, RuntimeStoreError> {
    validate_binding(&binding)?;
    if let Some(outcome) = replay_prepare(
        load_machine_identity_state(&state.connection, &state.key_bundle, state.database_id)?,
        &binding,
    )? {
        return Ok(outcome);
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
    if let Some(outcome) = replay_prepare(
        load_machine_identity_state(&transaction, &state.key_bundle, state.database_id)?,
        &binding,
    )? {
        return Ok(outcome);
    }
    let record = MachineIdentityStateRecord {
        database_id: state.database_id,
        lifecycle: MachineIdentityLifecycle::Preparing,
        binding,
    };
    let token = row_token(&state.key_bundle, &record)?;
    let binding = &record.binding;
    transaction.execute(
        "INSERT INTO machine_identity_state (
             singleton, identity_state, database_id, root_key_id, trust_epoch,
             link_generation, data_generation, key_directory_revision,
             root_public_key, root_fingerprint,
             machine_hpke_public_key, machine_hpke_fingerprint,
             link_sign_public_key, link_sign_fingerprint,
             data_sign_public_key, data_sign_fingerprint, metadata_token
         ) VALUES (1, 'preparing', ?1, ?2, ?3, ?4, ?5, ?6,
                   ?7, ?8, ?9, ?10, ?11, ?12, ?13, ?14, ?15)",
        params![
            &record.database_id[..],
            &binding.root_key_id[..],
            super::sequence::encode_sequence(binding.trust_epoch),
            super::sequence::encode_sequence(binding.link_generation),
            super::sequence::encode_sequence(binding.data_generation),
            super::sequence::encode_sequence(binding.key_directory_revision),
            &binding.root_public_key[..],
            &binding.root_fingerprint[..],
            &binding.machine_hpke_public_key[..],
            &binding.machine_hpke_fingerprint[..],
            &binding.link_sign_public_key[..],
            &binding.link_sign_fingerprint[..],
            &binding.data_sign_public_key[..],
            &binding.data_sign_fingerprint[..],
            &token[..],
        ],
    )?;
    let ledger =
        super::sqlite::load_runtime_ledger(&transaction, &state.key_bundle, state.database_id)?;
    if ledger.machine_identity_count != 0 {
        return Err(RuntimeStoreError::UnknownOrCorruptSchema);
    }
    let mut next = ledger.clone();
    next.machine_identity_count = 1;
    let _ = super::sqlite::update_runtime_ledger(
        &transaction,
        &state.key_bundle,
        state.database_id,
        &ledger,
        &next,
    )?;
    config
        .fault_injector
        .before_operation(RuntimeStoreOperation::PrepareMachineIdentityBeforeCommit)?;
    super::sqlite::commit_transaction(transaction, RuntimeCommitOperation::PrepareMachineIdentity)?;
    super::sqlite::latch_post_commit_capacity(state, config);
    if config
        .fault_injector
        .before_operation(RuntimeStoreOperation::PrepareMachineIdentityAfterCommit)
        .is_err()
    {
        return Err(RuntimeStoreError::CommitOutcomeUnknown {
            operation: RuntimeCommitOperation::PrepareMachineIdentity,
        });
    }
    Ok(PrepareMachineIdentityOutcome::Prepared { state: record })
}

pub(super) fn activate_machine_identity(
    state: &mut RuntimeSqlite,
    config: &RuntimeStoreConfig,
    binding: MachineIdentityBinding,
) -> Result<ActivateMachineIdentityOutcome, RuntimeStoreError> {
    validate_binding(&binding)?;
    let current =
        load_machine_identity_state(&state.connection, &state.key_bundle, state.database_id)?
            .ok_or(RuntimeStoreError::MachineIdentityMissing)?;
    if current.binding != binding {
        return Err(RuntimeStoreError::MachineIdentityConflict);
    }
    if current.lifecycle == MachineIdentityLifecycle::Active {
        return Ok(ActivateMachineIdentityOutcome::Replayed { state: current });
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
    let current = load_machine_identity_state(&transaction, &state.key_bundle, state.database_id)?
        .ok_or(RuntimeStoreError::MachineIdentityMissing)?;
    if current.binding != binding {
        return Err(RuntimeStoreError::MachineIdentityConflict);
    }
    if current.lifecycle == MachineIdentityLifecycle::Active {
        return Ok(ActivateMachineIdentityOutcome::Replayed { state: current });
    }
    let active = MachineIdentityStateRecord {
        lifecycle: MachineIdentityLifecycle::Active,
        ..current.clone()
    };
    let next_token = row_token(&state.key_bundle, &active)?;
    let previous_token = row_token(&state.key_bundle, &current)?;
    if transaction.execute(
        "UPDATE machine_identity_state
         SET identity_state = 'active', metadata_token = ?1
         WHERE singleton = 1 AND identity_state = 'preparing' AND metadata_token = ?2",
        params![&next_token[..], &previous_token[..]],
    )? != 1
    {
        return Err(RuntimeStoreError::MachineIdentityConflict);
    }
    let ledger =
        super::sqlite::load_runtime_ledger(&transaction, &state.key_bundle, state.database_id)?;
    if ledger.machine_identity_count != 1 {
        return Err(RuntimeStoreError::UnknownOrCorruptSchema);
    }
    config
        .fault_injector
        .before_operation(RuntimeStoreOperation::ActivateMachineIdentityBeforeCommit)?;
    super::sqlite::commit_transaction(
        transaction,
        RuntimeCommitOperation::ActivateMachineIdentity,
    )?;
    super::sqlite::latch_post_commit_capacity(state, config);
    if config
        .fault_injector
        .before_operation(RuntimeStoreOperation::ActivateMachineIdentityAfterCommit)
        .is_err()
    {
        return Err(RuntimeStoreError::CommitOutcomeUnknown {
            operation: RuntimeCommitOperation::ActivateMachineIdentity,
        });
    }
    Ok(ActivateMachineIdentityOutcome::Activated { state: active })
}
