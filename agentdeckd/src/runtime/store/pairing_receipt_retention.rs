//! Pairing terminal receipt 的有界保留期清理边界。
//!
//! 清理先冻结一个最多 64 行的 authenticated page，再以同一 page 做安全事务。这样
//! COMMIT outcome unknown 的调用方可以原样重放，不能重新 scan 后误删下一页。任何仍有
//! pairing row 或 control outbox 的 receipt 都保留给幂等恢复。

use std::mem::size_of;

use rusqlite::{Connection, TransactionBehavior, params};

use crate::runtime::model::{
    RuntimeCommitOperation, RuntimeStoreConfig, RuntimeStoreError, RuntimeStoreOperation,
};

use super::cipher::RuntimeKeyBundle;
use super::sqlite::{RuntimeLedger, RuntimeSqlite};

pub(super) const MAX_PAIRING_RECEIPT_PURGE_BATCH: u64 = 64;

#[derive(Clone)]
struct PurgeCandidate {
    pairing_id: [u8; 16],
    receipt_bytes: u64,
    retain_until_ms: u64,
    metadata_token: [u8; 32],
}

/// 单次维护冻结页。字段保持私有，调用方只能原样 clone/replay，不能扩大删除集合。
#[derive(Clone)]
pub(crate) struct PairingReceiptPurgePlan {
    now_ms: u64,
    candidates: Vec<PurgeCandidate>,
}

impl std::fmt::Debug for PairingReceiptPurgePlan {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("PairingReceiptPurgePlan")
            .field("candidate_count", &self.candidates.len())
            .finish_non_exhaustive()
    }
}

impl PairingReceiptPurgePlan {
    pub(crate) fn retained_bytes(&self) -> usize {
        self.candidates
            .capacity()
            .saturating_mul(size_of::<PurgeCandidate>())
    }

    #[must_use]
    pub(crate) fn candidate_count(&self) -> u64 {
        u64::try_from(self.candidates.len()).unwrap_or(u64::MAX)
    }

    fn validate(&self) -> Result<i64, RuntimeStoreError> {
        let count = self.candidate_count();
        if count == 0 || count > MAX_PAIRING_RECEIPT_PURGE_BATCH {
            return Err(RuntimeStoreError::UnknownOrCorruptSchema);
        }
        let mut ids = self
            .candidates
            .iter()
            .map(|candidate| candidate.pairing_id)
            .collect::<Vec<_>>();
        ids.sort_unstable();
        if ids.windows(2).any(|pair| pair[0] == pair[1]) {
            return Err(RuntimeStoreError::UnknownOrCorruptSchema);
        }
        i64::try_from(self.now_ms).map_err(|_| RuntimeStoreError::TimeOutOfRange)
    }

    #[cfg(test)]
    pub(super) fn truncate_for_test(&mut self, length: usize) {
        self.candidates.truncate(length);
    }
}

#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub(crate) struct PairingReceiptPurgeOutcome {
    purged_count: u64,
    purged_bytes: u64,
    has_more: bool,
    replayed: bool,
}

impl PairingReceiptPurgeOutcome {
    #[must_use]
    #[cfg(test)]
    pub(crate) const fn purged_count(self) -> u64 {
        self.purged_count
    }

    #[must_use]
    #[cfg(test)]
    pub(crate) const fn purged_bytes(self) -> u64 {
        self.purged_bytes
    }

    #[must_use]
    pub(crate) const fn has_more(self) -> bool {
        self.has_more
    }

    #[must_use]
    #[cfg(test)]
    pub(crate) const fn replayed(self) -> bool {
        self.replayed
    }
}

fn fixed<const N: usize>(value: Vec<u8>) -> Result<[u8; N], RuntimeStoreError> {
    value
        .try_into()
        .map_err(|_| RuntimeStoreError::UnknownOrCorruptSchema)
}

fn nonnegative(value: i64) -> Result<u64, RuntimeStoreError> {
    u64::try_from(value).map_err(|_| RuntimeStoreError::UnknownOrCorruptSchema)
}

fn eligible_exists(connection: &Connection, now_ms: i64) -> Result<bool, RuntimeStoreError> {
    let exists: i64 = connection.query_row(
        "SELECT EXISTS(
             SELECT 1
             FROM remote_pairing_receipts AS receipt
             WHERE receipt.retain_until_ms < ?1
               AND NOT EXISTS (
                   SELECT 1 FROM remote_pairings AS pairing
                   WHERE pairing.pairing_id = receipt.pairing_id
               )
               AND NOT EXISTS (
                   SELECT 1 FROM remote_control_outbox AS outbox
                   WHERE outbox.pairing_id = receipt.pairing_id
               )
         )",
        [now_ms],
        |row| row.get(0),
    )?;
    Ok(exists != 0)
}

fn load_candidates(
    connection: &Connection,
    now_ms: i64,
) -> Result<Vec<PurgeCandidate>, RuntimeStoreError> {
    let mut statement = connection.prepare(
        "SELECT receipt.pairing_id, receipt.receipt_bytes,
                receipt.retain_until_ms, receipt.metadata_token
         FROM remote_pairing_receipts AS receipt
         WHERE receipt.retain_until_ms < ?1
           AND NOT EXISTS (
               SELECT 1 FROM remote_pairings AS pairing
               WHERE pairing.pairing_id = receipt.pairing_id
           )
           AND NOT EXISTS (
               SELECT 1 FROM remote_control_outbox AS outbox
               WHERE outbox.pairing_id = receipt.pairing_id
           )
         ORDER BY receipt.retain_until_ms, receipt.pairing_id
         LIMIT ?2",
    )?;
    let raw = statement
        .query_map(
            params![
                now_ms,
                i64::try_from(MAX_PAIRING_RECEIPT_PURGE_BATCH)
                    .map_err(|_| RuntimeStoreError::UnknownOrCorruptSchema)?,
            ],
            |row| {
                Ok((
                    row.get::<_, Vec<u8>>(0)?,
                    row.get::<_, i64>(1)?,
                    row.get::<_, i64>(2)?,
                    row.get::<_, Vec<u8>>(3)?,
                ))
            },
        )?
        .collect::<Result<Vec<_>, _>>()?;
    raw.into_iter()
        .map(
            |(pairing_id, receipt_bytes, retain_until_ms, metadata_token)| {
                let pairing_id = fixed(pairing_id)?;
                let receipt_bytes = nonnegative(receipt_bytes)?;
                let retain_until_ms = nonnegative(retain_until_ms)?;
                let metadata_token = fixed(metadata_token)?;
                if pairing_id == [0; 16] || receipt_bytes == 0 || metadata_token == [0; 32] {
                    return Err(RuntimeStoreError::UnknownOrCorruptSchema);
                }
                Ok(PurgeCandidate {
                    pairing_id,
                    receipt_bytes,
                    retain_until_ms,
                    metadata_token,
                })
            },
        )
        .collect()
}

pub(crate) fn plan_expired_pairing_receipts(
    connection: &Connection,
    key_bundle: &RuntimeKeyBundle,
    database_id: [u8; 16],
    now_ms: u64,
) -> Result<Option<PairingReceiptPurgePlan>, RuntimeStoreError> {
    let now_sql = i64::try_from(now_ms).map_err(|_| RuntimeStoreError::TimeOutOfRange)?;
    let _ = super::pairing::load_directory(connection, key_bundle, database_id)?;
    let candidates = load_candidates(connection, now_sql)?;
    Ok((!candidates.is_empty()).then_some(PairingReceiptPurgePlan { now_ms, candidates }))
}

fn next_ledger(
    current: &RuntimeLedger,
    purged_count: u64,
    purged_bytes: u64,
) -> Result<RuntimeLedger, RuntimeStoreError> {
    let mut next = current.clone();
    next.remote_pairing_receipt_count = next
        .remote_pairing_receipt_count
        .checked_sub(purged_count)
        .ok_or(RuntimeStoreError::UnknownOrCorruptSchema)?;
    next.remote_pairing_receipt_bytes = next
        .remote_pairing_receipt_bytes
        .checked_sub(purged_bytes)
        .ok_or(RuntimeStoreError::UnknownOrCorruptSchema)?;
    Ok(next)
}

fn exact_candidate_present(
    connection: &Connection,
    candidate: &PurgeCandidate,
    now_ms: i64,
) -> Result<Option<bool>, RuntimeStoreError> {
    let (id_present, exact_present): (i64, i64) = connection.query_row(
        "SELECT
             EXISTS(
                 SELECT 1 FROM remote_pairing_receipts
                 WHERE pairing_id = ?1
             ),
             EXISTS(
                 SELECT 1 FROM remote_pairing_receipts AS receipt
                 WHERE receipt.pairing_id = ?1 AND receipt.receipt_bytes = ?2
                   AND receipt.retain_until_ms = ?3 AND receipt.metadata_token = ?4
                   AND receipt.retain_until_ms < ?5
                   AND NOT EXISTS (
                       SELECT 1 FROM remote_pairings AS pairing
                       WHERE pairing.pairing_id = receipt.pairing_id
                   )
                   AND NOT EXISTS (
                       SELECT 1 FROM remote_control_outbox AS outbox
                       WHERE outbox.pairing_id = receipt.pairing_id
                   )
             )",
        params![
            &candidate.pairing_id[..],
            i64::try_from(candidate.receipt_bytes)
                .map_err(|_| RuntimeStoreError::UnknownOrCorruptSchema)?,
            i64::try_from(candidate.retain_until_ms)
                .map_err(|_| RuntimeStoreError::UnknownOrCorruptSchema)?,
            &candidate.metadata_token[..],
            now_ms,
        ],
        |row| Ok((row.get(0)?, row.get(1)?)),
    )?;
    match (id_present != 0, exact_present != 0) {
        (true, true) => Ok(Some(true)),
        (false, false) => Ok(Some(false)),
        (true, false) => Ok(None),
        (false, true) => Err(RuntimeStoreError::UnknownOrCorruptSchema),
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum FrozenPageState {
    Present,
    Absent,
}

fn classify_frozen_page(
    connection: &Connection,
    plan: &PairingReceiptPurgePlan,
    now_ms: i64,
) -> Result<FrozenPageState, RuntimeStoreError> {
    let mut present = 0_u64;
    let mut absent = 0_u64;
    for candidate in &plan.candidates {
        match exact_candidate_present(connection, candidate, now_ms)? {
            Some(true) => present += 1,
            Some(false) => absent += 1,
            None => return Err(RuntimeStoreError::PairingConflict),
        }
    }
    if present == plan.candidate_count() && absent == 0 {
        Ok(FrozenPageState::Present)
    } else if absent == plan.candidate_count() && present == 0 {
        Ok(FrozenPageState::Absent)
    } else {
        Err(RuntimeStoreError::PairingConflict)
    }
}

pub(crate) fn apply_pairing_receipt_purge(
    state: &mut RuntimeSqlite,
    config: &RuntimeStoreConfig,
    plan: PairingReceiptPurgePlan,
) -> Result<PairingReceiptPurgeOutcome, RuntimeStoreError> {
    let now_ms = plan.validate()?;
    let _ =
        super::pairing::load_directory(&state.connection, &state.key_bundle, state.database_id)?;
    if classify_frozen_page(&state.connection, &plan, now_ms)? == FrozenPageState::Absent {
        return Ok(PairingReceiptPurgeOutcome {
            has_more: eligible_exists(&state.connection, now_ms)?,
            replayed: true,
            ..PairingReceiptPurgeOutcome::default()
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
    if classify_frozen_page(&transaction, &plan, now_ms)? == FrozenPageState::Absent {
        return Ok(PairingReceiptPurgeOutcome {
            has_more: eligible_exists(&transaction, now_ms)?,
            replayed: true,
            ..PairingReceiptPurgeOutcome::default()
        });
    }
    let purged_count = plan.candidate_count();
    let purged_bytes = plan.candidates.iter().try_fold(0_u64, |total, candidate| {
        total
            .checked_add(candidate.receipt_bytes)
            .ok_or(RuntimeStoreError::UnknownOrCorruptSchema)
    })?;
    let next = next_ledger(&directory.ledger, purged_count, purged_bytes)?;
    for candidate in &plan.candidates {
        if transaction.execute(
            "DELETE FROM remote_pairing_receipts
             WHERE pairing_id = ?1 AND receipt_bytes = ?2
               AND retain_until_ms = ?3 AND metadata_token = ?4
               AND retain_until_ms < ?5
               AND NOT EXISTS (
                   SELECT 1 FROM remote_pairings
                   WHERE pairing_id = ?1
               )
               AND NOT EXISTS (
                   SELECT 1 FROM remote_control_outbox
                   WHERE pairing_id = ?1
               )",
            params![
                &candidate.pairing_id[..],
                i64::try_from(candidate.receipt_bytes)
                    .map_err(|_| RuntimeStoreError::UnknownOrCorruptSchema)?,
                i64::try_from(candidate.retain_until_ms)
                    .map_err(|_| RuntimeStoreError::UnknownOrCorruptSchema)?,
                &candidate.metadata_token[..],
                now_ms,
            ],
        )? != 1
        {
            return Err(RuntimeStoreError::UnknownOrCorruptSchema);
        }
    }
    let has_more = eligible_exists(&transaction, now_ms)?;
    let _ = super::sqlite::update_runtime_ledger(
        &transaction,
        &state.key_bundle,
        state.database_id,
        &directory.ledger,
        &next,
    )?;
    config
        .fault_injector
        .before_operation(RuntimeStoreOperation::PurgePairingReceiptsBeforeCommit)?;
    super::sqlite::commit_transaction(transaction, RuntimeCommitOperation::PurgePairingReceipts)?;
    super::sqlite::latch_post_commit_capacity(state, config);
    config
        .fault_injector
        .before_operation(RuntimeStoreOperation::PurgePairingReceiptsAfterCommit)
        .map_err(|_| RuntimeStoreError::CommitOutcomeUnknown {
            operation: RuntimeCommitOperation::PurgePairingReceipts,
        })?;
    let audited =
        super::pairing::load_directory(&state.connection, &state.key_bundle, state.database_id)?;
    if audited.ledger.remote_pairing_receipt_count != next.remote_pairing_receipt_count
        || audited.ledger.remote_pairing_receipt_bytes != next.remote_pairing_receipt_bytes
    {
        return Err(RuntimeStoreError::UnknownOrCorruptSchema);
    }
    Ok(PairingReceiptPurgeOutcome {
        purged_count,
        purged_bytes,
        has_more,
        replayed: false,
    })
}

#[cfg(test)]
pub(super) fn next_ledger_for_test(
    current: &RuntimeLedger,
    purged_count: u64,
    purged_bytes: u64,
) -> Result<RuntimeLedger, RuntimeStoreError> {
    next_ledger(current, purged_count, purged_bytes)
}
