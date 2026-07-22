//! P4.5 authenticated CounterGuard scope manifest。
//!
//! manifest 记录已由本机 secure-store CounterGuard 预留或实体化的 scope token；
//! 它不持有 guard high-water 或业务状态。每行 MAC 覆盖单调 phase，并与 Runtime
//! ledger 共同阻止离线增删改和跨库移植。

use rusqlite::{Connection, TransactionBehavior, params};

use crate::runtime::model::{RuntimeStoreConfig, RuntimeStoreError};

use super::cipher::RuntimeKeyBundle;
use super::sqlite::{RuntimeLedger, RuntimeSqlite};

pub(super) const MAX_REMOTE_COUNTER_GUARD_SCOPES: u64 = 4_096;
const METADATA_DOMAIN: &[u8] = b"runtime.remote.counter-guard-manifest.metadata.v2";
pub(crate) type CounterGuardCleanupManifest = Vec<([u8; 32], bool)>;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum CounterGuardManifestPhase {
    Reserved,
    Materialized,
}

impl CounterGuardManifestPhase {
    const fn text(self) -> &'static str {
        match self {
            Self::Reserved => "reserved",
            Self::Materialized => "materialized",
        }
    }

    const fn tag(self) -> u8 {
        match self {
            Self::Reserved => 0,
            Self::Materialized => 1,
        }
    }

    const fn is_materialized(self) -> bool {
        matches!(self, Self::Materialized)
    }

    fn parse(value: &str) -> Result<Self, RuntimeStoreError> {
        match value {
            "reserved" => Ok(Self::Reserved),
            "materialized" => Ok(Self::Materialized),
            _ => Err(RuntimeStoreError::UnknownOrCorruptSchema),
        }
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
struct ManifestEntry {
    scope_token: [u8; 32],
    phase: CounterGuardManifestPhase,
}

pub(super) fn register(
    state: &mut RuntimeSqlite,
    config: &RuntimeStoreConfig,
    scope_token: [u8; 32],
) -> Result<(), RuntimeStoreError> {
    validate_scope(scope_token)?;
    let current = load_entries(state)?;
    if find_entry(&current, scope_token).is_ok() {
        return Ok(());
    }
    if u64::try_from(current.len()).unwrap_or(u64::MAX) >= MAX_REMOTE_COUNTER_GUARD_SCOPES {
        return Err(limit_error());
    }

    super::sqlite::admit_safety_write(
        &state.connection,
        &state.key_bundle,
        state.database_id,
        &state.storage_path,
        config.capacity_probe.as_ref(),
    )?;
    let key_bundle = state.key_bundle.clone();
    let database_id = state.database_id;
    let transaction = state
        .connection
        .transaction_with_behavior(TransactionBehavior::Immediate)?;
    let ledger = super::sqlite::load_runtime_ledger(&transaction, &key_bundle, database_id)?;
    let current = load_against_ledger(&transaction, &key_bundle, database_id, &ledger)?;
    if find_entry(&current, scope_token).is_ok() {
        return Ok(());
    }
    if u64::try_from(current.len()).unwrap_or(u64::MAX) >= MAX_REMOTE_COUNTER_GUARD_SCOPES {
        return Err(limit_error());
    }

    let phase = CounterGuardManifestPhase::Reserved;
    let token = metadata_token_for_phase(&key_bundle, database_id, scope_token, phase)?;
    transaction.execute(
        "INSERT INTO remote_counter_guard_manifest
             (scope_token, database_id, phase, metadata_token)
         VALUES (?1, ?2, ?3, ?4)",
        params![&scope_token[..], &database_id[..], phase.text(), &token[..]],
    )?;
    let mut next = ledger.clone();
    next.remote_counter_guard_manifest_count = next
        .remote_counter_guard_manifest_count
        .checked_add(1)
        .ok_or(RuntimeStoreError::UnknownOrCorruptSchema)?;
    let _ = super::sqlite::update_runtime_ledger(
        &transaction,
        &key_bundle,
        database_id,
        &ledger,
        &next,
    )?;
    transaction.commit()?;
    super::sqlite::latch_post_commit_capacity(state, config);

    let persisted = load_entries(state)?;
    let index = find_entry(&persisted, scope_token)
        .map_err(|_| RuntimeStoreError::UnknownOrCorruptSchema)?;
    if persisted[index].phase != CounterGuardManifestPhase::Reserved {
        return Err(RuntimeStoreError::UnknownOrCorruptSchema);
    }
    Ok(())
}

pub(super) fn mark_materialized(
    state: &mut RuntimeSqlite,
    config: &RuntimeStoreConfig,
    scope_token: [u8; 32],
) -> Result<(), RuntimeStoreError> {
    validate_scope(scope_token)?;
    let current = load_entries(state)?;
    let index =
        find_entry(&current, scope_token).map_err(|_| RuntimeStoreError::UnknownOrCorruptSchema)?;
    if current[index].phase == CounterGuardManifestPhase::Materialized {
        return Ok(());
    }

    super::sqlite::admit_safety_write(
        &state.connection,
        &state.key_bundle,
        state.database_id,
        &state.storage_path,
        config.capacity_probe.as_ref(),
    )?;
    let key_bundle = state.key_bundle.clone();
    let database_id = state.database_id;
    let transaction = state
        .connection
        .transaction_with_behavior(TransactionBehavior::Immediate)?;
    let ledger = super::sqlite::load_runtime_ledger(&transaction, &key_bundle, database_id)?;
    let current = load_against_ledger(&transaction, &key_bundle, database_id, &ledger)?;
    let index =
        find_entry(&current, scope_token).map_err(|_| RuntimeStoreError::UnknownOrCorruptSchema)?;
    if current[index].phase == CounterGuardManifestPhase::Materialized {
        return Ok(());
    }

    let reserved_token = metadata_token_for_phase(
        &key_bundle,
        database_id,
        scope_token,
        CounterGuardManifestPhase::Reserved,
    )?;
    let materialized_token = metadata_token_for_phase(
        &key_bundle,
        database_id,
        scope_token,
        CounterGuardManifestPhase::Materialized,
    )?;
    let updated = transaction.execute(
        "UPDATE remote_counter_guard_manifest
         SET phase = 'materialized', metadata_token = ?1
         WHERE scope_token = ?2 AND database_id = ?3
           AND phase = 'reserved' AND metadata_token = ?4",
        params![
            &materialized_token[..],
            &scope_token[..],
            &database_id[..],
            &reserved_token[..]
        ],
    )?;
    if updated != 1 {
        return Err(RuntimeStoreError::UnknownOrCorruptSchema);
    }
    transaction.commit()?;
    super::sqlite::latch_post_commit_capacity(state, config);

    let persisted = load_entries(state)?;
    let index = find_entry(&persisted, scope_token)
        .map_err(|_| RuntimeStoreError::UnknownOrCorruptSchema)?;
    if persisted[index].phase != CounterGuardManifestPhase::Materialized {
        return Err(RuntimeStoreError::UnknownOrCorruptSchema);
    }
    Ok(())
}

#[allow(
    dead_code,
    reason = "token-only manifest view remains available for focused diagnostics/tests"
)]
pub(super) fn load(state: &RuntimeSqlite) -> Result<Vec<[u8; 32]>, RuntimeStoreError> {
    load_entries(state).map(|entries| entries.into_iter().map(|entry| entry.scope_token).collect())
}

pub(super) fn load_for_cleanup(
    state: &RuntimeSqlite,
) -> Result<CounterGuardCleanupManifest, RuntimeStoreError> {
    load_entries(state).map(|entries| {
        entries
            .into_iter()
            .map(|entry| (entry.scope_token, entry.phase.is_materialized()))
            .collect()
    })
}

fn load_entries(state: &RuntimeSqlite) -> Result<Vec<ManifestEntry>, RuntimeStoreError> {
    let ledger = super::sqlite::load_runtime_ledger(
        &state.connection,
        &state.key_bundle,
        state.database_id,
    )?;
    load_against_ledger(
        &state.connection,
        &state.key_bundle,
        state.database_id,
        &ledger,
    )
}

pub(crate) fn validate_v12_integrity(
    connection: &Connection,
    key_bundle: &RuntimeKeyBundle,
    database_id: [u8; 16],
    ledger: &RuntimeLedger,
) -> Result<(), RuntimeStoreError> {
    load_against_ledger(connection, key_bundle, database_id, ledger).map(|_| ())
}

/// 仅供 Machine LocalDeleted finalizer 使用。caller 必须已经以 authenticated
/// manifest 驱动 secure-store existing-only 删除并逐项读回 absent；本函数把同一份
/// manifest 与 lifecycle/ledger 更新放进一个 SQLite 事务，不自行 COMMIT。
pub(in crate::runtime::store) fn clear_after_guard_readback(
    transaction: &rusqlite::Transaction<'_>,
    key_bundle: &RuntimeKeyBundle,
    database_id: [u8; 16],
    ledger: &mut RuntimeLedger,
) -> Result<(), RuntimeStoreError> {
    let manifest = load_against_ledger(transaction, key_bundle, database_id, ledger)?;
    let deleted = transaction.execute("DELETE FROM remote_counter_guard_manifest", [])?;
    if deleted != manifest.len() {
        return Err(RuntimeStoreError::UnknownOrCorruptSchema);
    }
    ledger.remote_counter_guard_manifest_count = 0;
    Ok(())
}

/// guard-first counter GC 的 scoped manifest 收口。caller 已逐项完成 Keychain
/// existing-only delete + absent readback；本函数先认证完整 manifest，再只删除 exact
/// candidate rows，并在 caller 的同一 transaction 中精确扣减 ledger。
pub(in crate::runtime::store) fn remove_scopes_after_guard_readback(
    transaction: &rusqlite::Transaction<'_>,
    key_bundle: &RuntimeKeyBundle,
    database_id: [u8; 16],
    ledger: &RuntimeLedger,
    next_ledger: &mut RuntimeLedger,
    scope_tokens: &[[u8; 32]],
) -> Result<u64, RuntimeStoreError> {
    if next_ledger.remote_counter_guard_manifest_count != ledger.remote_counter_guard_manifest_count
        || scope_tokens.windows(2).any(|pair| pair[0] >= pair[1])
    {
        return Err(RuntimeStoreError::UnknownOrCorruptSchema);
    }
    let manifest = load_against_ledger(transaction, key_bundle, database_id, ledger)?;
    let mut selected = Vec::new();
    selected
        .try_reserve_exact(scope_tokens.len())
        .map_err(|_| RuntimeStoreError::PayloadTooLarge)?;
    for scope_token in scope_tokens.iter().copied() {
        validate_scope(scope_token)?;
        if let Ok(index) = find_entry(&manifest, scope_token) {
            selected.push(manifest[index]);
        }
    }

    for entry in &selected {
        let metadata_token =
            metadata_token_for_phase(key_bundle, database_id, entry.scope_token, entry.phase)?;
        let deleted = transaction.execute(
            "DELETE FROM remote_counter_guard_manifest
             WHERE scope_token = ?1 AND database_id = ?2
               AND phase = ?3 AND metadata_token = ?4",
            rusqlite::params![
                &entry.scope_token[..],
                &database_id[..],
                entry.phase.text(),
                &metadata_token[..],
            ],
        )?;
        if deleted != 1 {
            return Err(RuntimeStoreError::SchemaInspectionRaced);
        }
    }
    let deleted =
        u64::try_from(selected.len()).map_err(|_| RuntimeStoreError::UnknownOrCorruptSchema)?;
    next_ledger.remote_counter_guard_manifest_count = next_ledger
        .remote_counter_guard_manifest_count
        .checked_sub(deleted)
        .ok_or(RuntimeStoreError::UnknownOrCorruptSchema)?;
    Ok(deleted)
}

pub(crate) fn load_cleanup_against_ledger(
    connection: &Connection,
    key_bundle: &RuntimeKeyBundle,
    database_id: [u8; 16],
    ledger: &RuntimeLedger,
) -> Result<CounterGuardCleanupManifest, RuntimeStoreError> {
    load_against_ledger(connection, key_bundle, database_id, ledger).map(|entries| {
        entries
            .into_iter()
            .map(|entry| (entry.scope_token, entry.phase.is_materialized()))
            .collect()
    })
}

fn load_against_ledger(
    connection: &Connection,
    key_bundle: &RuntimeKeyBundle,
    database_id: [u8; 16],
    ledger: &RuntimeLedger,
) -> Result<Vec<ManifestEntry>, RuntimeStoreError> {
    if ledger.remote_counter_guard_manifest_count > MAX_REMOTE_COUNTER_GUARD_SCOPES {
        return Err(RuntimeStoreError::UnknownOrCorruptSchema);
    }
    let capacity = usize::try_from(ledger.remote_counter_guard_manifest_count)
        .map_err(|_| RuntimeStoreError::PayloadTooLarge)?;
    let mut manifest = Vec::new();
    manifest
        .try_reserve_exact(capacity)
        .map_err(|_| RuntimeStoreError::PayloadTooLarge)?;
    let mut statement = connection.prepare(
        "SELECT scope_token, database_id, phase, metadata_token
         FROM remote_counter_guard_manifest ORDER BY scope_token",
    )?;
    let mut rows = statement.query([])?;
    let mut previous = None;
    while let Some(row) = rows.next()? {
        if manifest.len() >= usize::try_from(MAX_REMOTE_COUNTER_GUARD_SCOPES).unwrap_or(usize::MAX)
        {
            return Err(RuntimeStoreError::UnknownOrCorruptSchema);
        }
        let scope_token = fixed::<32>(row.get(0)?)?;
        let row_database_id = fixed::<16>(row.get(1)?)?;
        let phase = CounterGuardManifestPhase::parse(&row.get::<_, String>(2)?)?;
        let observed_token = fixed::<32>(row.get(3)?)?;
        validate_scope(scope_token)?;
        if row_database_id != database_id
            || observed_token
                != metadata_token_for_phase(key_bundle, database_id, scope_token, phase)?
            || previous.is_some_and(|value| value >= scope_token)
        {
            return Err(RuntimeStoreError::UnknownOrCorruptSchema);
        }
        manifest.push(ManifestEntry { scope_token, phase });
        previous = Some(scope_token);
    }
    if u64::try_from(manifest.len()).unwrap_or(u64::MAX)
        != ledger.remote_counter_guard_manifest_count
    {
        return Err(RuntimeStoreError::UnknownOrCorruptSchema);
    }
    Ok(manifest)
}

#[cfg(test)]
pub(super) fn metadata_token(
    key_bundle: &RuntimeKeyBundle,
    database_id: [u8; 16],
    scope_token: [u8; 32],
    materialized: bool,
) -> Result<[u8; 32], RuntimeStoreError> {
    let phase = if materialized {
        CounterGuardManifestPhase::Materialized
    } else {
        CounterGuardManifestPhase::Reserved
    };
    metadata_token_for_phase(key_bundle, database_id, scope_token, phase)
}

fn metadata_token_for_phase(
    key_bundle: &RuntimeKeyBundle,
    database_id: [u8; 16],
    scope_token: [u8; 32],
    phase: CounterGuardManifestPhase,
) -> Result<[u8; 32], RuntimeStoreError> {
    validate_scope(scope_token)?;
    let mut message = [0_u8; 49];
    message[..16].copy_from_slice(&database_id);
    message[16..48].copy_from_slice(&scope_token);
    message[48] = phase.tag();
    Ok(*key_bundle
        .blind_index(METADATA_DOMAIN, &message)?
        .as_bytes())
}

fn find_entry(entries: &[ManifestEntry], scope_token: [u8; 32]) -> Result<usize, usize> {
    entries.binary_search_by_key(&scope_token, |entry| entry.scope_token)
}

fn validate_scope(scope_token: [u8; 32]) -> Result<(), RuntimeStoreError> {
    if scope_token == [0; 32] {
        return Err(RuntimeStoreError::UnknownOrCorruptSchema);
    }
    Ok(())
}

fn fixed<const N: usize>(value: Vec<u8>) -> Result<[u8; N], RuntimeStoreError> {
    value
        .try_into()
        .map_err(|_| RuntimeStoreError::UnknownOrCorruptSchema)
}

fn limit_error() -> RuntimeStoreError {
    RuntimeStoreError::StoreFull {
        projected_footprint_bytes: MAX_REMOTE_COUNTER_GUARD_SCOPES + 1,
        hard_limit_bytes: MAX_REMOTE_COUNTER_GUARD_SCOPES,
    }
}
