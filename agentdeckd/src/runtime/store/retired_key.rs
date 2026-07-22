//! ADGK2 retired-key owner 与 GC 的 authenticated singleton transaction。
//!
//! shared key 可绑定 durable owner；revoked device 的 directed transport secrets 则按
//! `revoked_at + 25h` 一并清除。纯状态变换由 `GlobalKeyStateV1` 负责；本模块只负责
//! 在同一 SQLite transaction 内认证旧 singleton、按 revision/hash/token 做 CAS、重封
//! canonical bytes，并同步 RuntimeLedger。exact retry 若 canonical state 已相同则零写。

use agentdeck_crypto::sha256;
use rusqlite::{TransactionBehavior, params};
use zeroize::Zeroizing;

use crate::runtime::model::{RuntimeStoreConfig, RuntimeStoreError};

use super::cipher::ROW_BLOB_V1_OVERHEAD_LEN;
use super::cipher::RuntimeKeyBundle;
use super::pairing_grant::{
    AuthenticatedGlobalKeyState, GLOBAL_KEY_COLUMN, GLOBAL_KEY_TABLE, GlobalKeyStateV1,
    MAX_GLOBAL_KEY_STATE_BYTES, RetiredSharedKeyOwner, global_key_token, load_global_key_state,
    seal_row,
};
use super::sqlite::{RuntimeLedger, RuntimeSqlite, SafetyReserveProjection};

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum RetiredKeyMutationOutcome {
    Applied,
    AlreadyApplied,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) struct RetiredKeyGcOutcome {
    pub(crate) mutation: RetiredKeyMutationOutcome,
    pub(crate) collected: u64,
}

#[derive(Clone, Copy)]
enum Mutation {
    Acquire(RetiredSharedKeyOwner),
    Release(RetiredSharedKeyOwner),
    GarbageCollect { now_ms: u64 },
}

impl Mutation {
    fn apply(self, state: GlobalKeyStateV1) -> Result<GlobalKeyStateV1, RuntimeStoreError> {
        match self {
            Self::Acquire(owner) => state.acquire_retired_shared_key_owner(owner),
            Self::Release(owner) => state.release_retired_shared_key_owner(owner),
            Self::GarbageCollect { now_ms } => state.prune_expired_retired_keys(now_ms),
        }
    }
}

struct ExpectedSingleton {
    revision: u64,
    directory_hash: [u8; 32],
    metadata_token: [u8; 32],
    sealed_bytes: u64,
}

struct PreparedMutation {
    expected: ExpectedSingleton,
    canonical: Zeroizing<Vec<u8>>,
    collected: u64,
}

enum Preparation {
    AlreadyApplied { collected: u64 },
    Write(PreparedMutation),
}

pub(crate) fn acquire_owner(
    state: &mut RuntimeSqlite,
    config: &RuntimeStoreConfig,
    owner: RetiredSharedKeyOwner,
) -> Result<RetiredKeyMutationOutcome, RuntimeStoreError> {
    Ok(apply_mutation(state, config, Mutation::Acquire(owner))?.mutation)
}

pub(crate) fn release_owner(
    state: &mut RuntimeSqlite,
    config: &RuntimeStoreConfig,
    owner: RetiredSharedKeyOwner,
) -> Result<RetiredKeyMutationOutcome, RuntimeStoreError> {
    Ok(apply_mutation(state, config, Mutation::Release(owner))?.mutation)
}

pub(crate) fn gc_expired(
    state: &mut RuntimeSqlite,
    config: &RuntimeStoreConfig,
    now_ms: u64,
) -> Result<RetiredKeyGcOutcome, RuntimeStoreError> {
    apply_mutation(state, config, Mutation::GarbageCollect { now_ms })
}

pub(super) fn acquire_owner_in_transaction(
    transaction: &rusqlite::Transaction<'_>,
    key_bundle: &RuntimeKeyBundle,
    database_id: [u8; 16],
    ledger: &RuntimeLedger,
    next_ledger: &mut RuntimeLedger,
    owner: RetiredSharedKeyOwner,
) -> Result<RetiredKeyMutationOutcome, RuntimeStoreError> {
    Ok(apply_mutation_in_transaction(
        transaction,
        key_bundle,
        database_id,
        ledger,
        next_ledger,
        Mutation::Acquire(owner),
    )?
    .mutation)
}

pub(super) fn release_owner_in_transaction(
    transaction: &rusqlite::Transaction<'_>,
    key_bundle: &RuntimeKeyBundle,
    database_id: [u8; 16],
    ledger: &RuntimeLedger,
    next_ledger: &mut RuntimeLedger,
    owner: RetiredSharedKeyOwner,
) -> Result<RetiredKeyMutationOutcome, RuntimeStoreError> {
    Ok(apply_mutation_in_transaction(
        transaction,
        key_bundle,
        database_id,
        ledger,
        next_ledger,
        Mutation::Release(owner),
    )?
    .mutation)
}

fn apply_mutation(
    state: &mut RuntimeSqlite,
    config: &RuntimeStoreConfig,
    mutation: Mutation,
) -> Result<RetiredKeyGcOutcome, RuntimeStoreError> {
    let current = required_singleton(&state.connection, &state.key_bundle, state.database_id)?;
    let preflight = prepare(current, mutation)?;
    if let Preparation::AlreadyApplied { collected } = preflight {
        return Ok(RetiredKeyGcOutcome {
            mutation: RetiredKeyMutationOutcome::AlreadyApplied,
            collected,
        });
    }
    let Preparation::Write(preflight) = preflight else {
        unreachable!("already-applied retired-key mutation returned above")
    };
    let projected_write_bytes = u64::try_from(preflight.canonical.len())
        .map_err(|_| RuntimeStoreError::PayloadTooLarge)?
        .checked_add(ROW_BLOB_V1_OVERHEAD_LEN as u64)
        .ok_or(RuntimeStoreError::CapacityArithmeticOverflow {
            field: "remote_key_directory_write_bytes",
        })?;
    super::sqlite::admit_ordinary_write(
        &state.connection,
        &state.key_bundle,
        state.database_id,
        &state.storage_path,
        &mut state.admission_state,
        config.capacity_probe.as_ref(),
        projected_write_bytes,
        SafetyReserveProjection::Current,
    )?;

    let key_bundle = state.key_bundle.clone();
    let database_id = state.database_id;
    let transaction = state
        .connection
        .transaction_with_behavior(TransactionBehavior::Immediate)?;
    // Admission 与 BEGIN IMMEDIATE 之间即使未来不再由单 worker 串行，仍重新认证并
    // 重算 mutation；exact retry 可在这里收敛为零写。
    let ledger = super::sqlite::load_runtime_ledger(&transaction, &key_bundle, database_id)?;
    let mut next_ledger = ledger.clone();
    let outcome = apply_mutation_in_transaction(
        &transaction,
        &key_bundle,
        database_id,
        &ledger,
        &mut next_ledger,
        mutation,
    )?;
    if outcome.mutation == RetiredKeyMutationOutcome::AlreadyApplied {
        return Ok(outcome);
    }
    let _ = super::sqlite::update_runtime_ledger(
        &transaction,
        &key_bundle,
        database_id,
        &ledger,
        &next_ledger,
    )?;
    transaction.commit()?;
    super::sqlite::latch_post_commit_capacity(state, config);
    Ok(outcome)
}

fn apply_mutation_in_transaction(
    transaction: &rusqlite::Transaction<'_>,
    key_bundle: &RuntimeKeyBundle,
    database_id: [u8; 16],
    ledger: &RuntimeLedger,
    next_ledger: &mut RuntimeLedger,
    mutation: Mutation,
) -> Result<RetiredKeyGcOutcome, RuntimeStoreError> {
    let prepared = prepare(
        required_singleton(transaction, key_bundle, database_id)?,
        mutation,
    )?;
    let Preparation::Write(prepared) = prepared else {
        return Ok(RetiredKeyGcOutcome {
            mutation: RetiredKeyMutationOutcome::AlreadyApplied,
            collected: match prepared {
                Preparation::AlreadyApplied { collected } => collected,
                Preparation::Write(_) => unreachable!(),
            },
        });
    };
    let sealed = seal_row(
        key_bundle,
        database_id,
        GLOBAL_KEY_TABLE,
        b"1",
        GLOBAL_KEY_COLUMN,
        prepared.canonical.as_slice(),
        MAX_GLOBAL_KEY_STATE_BYTES,
    )?;
    let sealed_bytes =
        u64::try_from(sealed.len()).map_err(|_| RuntimeStoreError::PayloadTooLarge)?;
    let directory_hash = sha256(prepared.canonical.as_slice());
    if directory_hash == [0; 32] {
        return Err(RuntimeStoreError::UnknownOrCorruptSchema);
    }
    let metadata_token = global_key_token(
        key_bundle,
        database_id,
        prepared.expected.revision,
        directory_hash,
        &sealed,
    )?;
    validate_singleton_ledger(ledger, prepared.expected.sealed_bytes)?;
    if next_ledger.remote_key_directory_count != ledger.remote_key_directory_count
        || next_ledger.remote_key_directory_sealed_bytes != ledger.remote_key_directory_sealed_bytes
    {
        return Err(RuntimeStoreError::UnknownOrCorruptSchema);
    }
    let projected_ledger = project_ledger(ledger, prepared.expected.sealed_bytes, sealed_bytes)?;
    next_ledger.remote_key_directory_count = projected_ledger.remote_key_directory_count;
    next_ledger.remote_key_directory_sealed_bytes =
        projected_ledger.remote_key_directory_sealed_bytes;
    if transaction.execute(
        "UPDATE remote_key_directory
         SET directory_hash = ?1, sealed_directory = ?2,
             sealed_directory_bytes = ?3, metadata_token = ?4
         WHERE singleton = 1 AND revision = ?5 AND directory_hash = ?6
           AND metadata_token = ?7 AND sealed_directory_bytes = ?8",
        params![
            &directory_hash[..],
            &sealed,
            i64::try_from(sealed_bytes).map_err(|_| RuntimeStoreError::PayloadTooLarge)?,
            &metadata_token[..],
            super::sequence::encode_sequence(prepared.expected.revision),
            &prepared.expected.directory_hash[..],
            &prepared.expected.metadata_token[..],
            i64::try_from(prepared.expected.sealed_bytes)
                .map_err(|_| RuntimeStoreError::UnknownOrCorruptSchema)?,
        ],
    )? != 1
    {
        return Err(RuntimeStoreError::SchemaInspectionRaced);
    }
    Ok(RetiredKeyGcOutcome {
        mutation: RetiredKeyMutationOutcome::Applied,
        collected: prepared.collected,
    })
}

fn required_singleton(
    connection: &rusqlite::Connection,
    key_bundle: &super::cipher::RuntimeKeyBundle,
    database_id: [u8; 16],
) -> Result<AuthenticatedGlobalKeyState, RuntimeStoreError> {
    load_global_key_state(connection, key_bundle, database_id)?
        .ok_or(RuntimeStoreError::PairingConflict)
}

fn prepare(
    current: AuthenticatedGlobalKeyState,
    mutation: Mutation,
) -> Result<Preparation, RuntimeStoreError> {
    let before_count = retired_count(&current.state)?;
    let before = current.state.canonical_bytes()?;
    let next = mutation.apply(current.state)?;
    let after_count = retired_count(&next)?;
    let collected = before_count
        .checked_sub(after_count)
        .ok_or(RuntimeStoreError::UnknownOrCorruptSchema)?;
    let collected =
        u64::try_from(collected).map_err(|_| RuntimeStoreError::UnknownOrCorruptSchema)?;
    let canonical = next.canonical_bytes()?;
    if before.as_slice() == canonical.as_slice() {
        return Ok(Preparation::AlreadyApplied { collected });
    }
    Ok(Preparation::Write(PreparedMutation {
        expected: ExpectedSingleton {
            revision: current.revision,
            directory_hash: current.directory_hash,
            metadata_token: current.metadata_token,
            sealed_bytes: current.sealed_bytes,
        },
        canonical,
        collected,
    }))
}

fn retired_count(state: &GlobalKeyStateV1) -> Result<usize, RuntimeStoreError> {
    state.retained_retired_secret_count()
}

fn validate_singleton_ledger(
    ledger: &RuntimeLedger,
    expected_sealed_bytes: u64,
) -> Result<(), RuntimeStoreError> {
    if ledger.remote_key_directory_count != 1
        || ledger.remote_key_directory_sealed_bytes != expected_sealed_bytes
    {
        return Err(RuntimeStoreError::UnknownOrCorruptSchema);
    }
    Ok(())
}

fn project_ledger(
    current: &RuntimeLedger,
    previous_bytes: u64,
    next_bytes: u64,
) -> Result<RuntimeLedger, RuntimeStoreError> {
    let mut next = current.clone();
    next.remote_key_directory_sealed_bytes = next
        .remote_key_directory_sealed_bytes
        .checked_sub(previous_bytes)
        .ok_or(RuntimeStoreError::UnknownOrCorruptSchema)?
        .checked_add(next_bytes)
        .ok_or(RuntimeStoreError::CapacityArithmeticOverflow {
            field: "remote_key_directory_sealed_bytes",
        })?;
    if next.remote_key_directory_sealed_bytes > MAX_GLOBAL_KEY_STATE_BYTES as u64 {
        return Err(RuntimeStoreError::PairingLimit);
    }
    Ok(next)
}
