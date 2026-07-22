//! Machine trust-reset 对全部 remote security state 的原子清理边界。
//!
//! pairing receipt 是 30 天保留的无授权 tombstone，故意不在本模块删除。其余仍能
//! 授权、恢复网络操作或持有秘密材料的 row 必须在 Relay terminal/readback 与业务
//! owner quiescence 之后，与 machine lifecycle 转换同事务清除。publication stream
//! 保留本机稳定 identity，但旧 trust domain 的 route/generation/counter/cursor 全部重置。

use rusqlite::{Transaction, params};

use crate::runtime::model::RuntimeStoreError;

use super::super::cipher::RuntimeKeyBundle;
use super::super::pairing_authorization::AuthorizationLifecycle;
use super::super::sqlite;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(super) enum RemoteSecurityCleanupMode {
    /// MachineRoot 尚在：Relay 已逐 grant 确认撤销，PairRoute 也都已确认关闭。
    RootPresentAfterRevocation,
    /// MachineRoot 已丢失：经签名 admin purge receipt 证明 Relay 已不存在该 machine。
    RootLostAfterPurgeReadback,
}

pub(super) fn require_root_present_ready(
    transaction: &Transaction<'_>,
    key_bundle: &RuntimeKeyBundle,
    database_id: [u8; 16],
) -> Result<(), RuntimeStoreError> {
    let directory = super::super::pairing::load_directory(transaction, key_bundle, database_id)?;
    require_root_present_directory_ready(&directory)
}

pub(super) fn scrub_remote_security_state(
    transaction: &Transaction<'_>,
    key_bundle: &RuntimeKeyBundle,
    database_id: [u8; 16],
    mode: RemoteSecurityCleanupMode,
) -> Result<(), RuntimeStoreError> {
    // 先做完整 authenticated audit；任何离线改删/移植都必须在开始 DELETE 前 fail-close。
    let directory = super::super::pairing::load_directory(transaction, key_bundle, database_id)?;
    let ledger = super::super::sqlite::load_runtime_ledger(transaction, key_bundle, database_id)?;
    if directory.ledger != ledger {
        return Err(RuntimeStoreError::UnknownOrCorruptSchema);
    }
    super::super::publication::validate_integrity(transaction, key_bundle, database_id, &ledger)?;
    super::super::remote_replay::validate_v11_integrity(
        transaction,
        key_bundle,
        database_id,
        &ledger,
    )?;
    super::super::key_transition::validate_v12_integrity(
        transaction,
        key_bundle,
        database_id,
        &ledger,
    )?;
    super::super::remote_counter_guard_manifest::validate_v12_integrity(
        transaction,
        key_bundle,
        database_id,
        &ledger,
    )?;
    if mode == RemoteSecurityCleanupMode::RootPresentAfterRevocation {
        require_root_present_directory_ready(&directory)?;
    }

    let expected_outboxes = directory.ledger.remote_control_outbox_count;
    let expected_pairings = directory.ledger.remote_pairing_count;
    let expected_authorizations = directory.ledger.remote_authorization_count;
    let expected_key_directories = directory.ledger.remote_key_directory_count;

    // child-first 顺序是安全不变量；第一笔 DELETE 之前上面的全库认证必须已经完成。
    delete_exact(
        transaction,
        "DELETE FROM remote_key_update_outbox",
        ledger.remote_key_update_outbox_count,
    )?;
    delete_exact(
        transaction,
        "DELETE FROM remote_key_transitions",
        ledger.remote_key_transition_count,
    )?;
    let mut next = ledger.clone();
    super::super::publication::reset_for_machine_purge(
        transaction,
        key_bundle,
        database_id,
        &mut next,
    )?;
    delete_exact(
        transaction,
        "DELETE FROM remote_replay_states",
        ledger.remote_replay_scope_count,
    )?;
    delete_exact(
        transaction,
        "DELETE FROM remote_counter_states",
        ledger.remote_counter_state_count,
    )?;
    delete_exact(
        transaction,
        "DELETE FROM remote_control_outbox",
        expected_outboxes,
    )?;
    delete_exact(
        transaction,
        "DELETE FROM remote_pairings",
        expected_pairings,
    )?;
    delete_exact(
        transaction,
        "DELETE FROM remote_authorization_ledger",
        expected_authorizations,
    )?;
    delete_exact(
        transaction,
        "DELETE FROM remote_key_directory",
        expected_key_directories,
    )?;

    next.remote_pairing_count = 0;
    next.remote_pairing_sealed_bytes = 0;
    next.remote_authorization_count = 0;
    next.remote_authorization_preparing_count = 0;
    next.remote_authorization_active_count = 0;
    next.remote_authorization_revoking_count = 0;
    next.remote_authorization_revoked_count = 0;
    next.remote_authorization_sealed_bytes = 0;
    next.remote_key_directory_count = 0;
    next.remote_key_directory_sealed_bytes = 0;
    next.remote_control_outbox_count = 0;
    next.remote_control_outbox_pending_count = 0;
    next.remote_control_outbox_acknowledged_count = 0;
    next.remote_control_outbox_sealed_bytes = 0;
    next.remote_replay_scope_count = 0;
    next.remote_replay_retired_scope_count = 0;
    next.remote_replay_pin_count = 0;
    next.remote_replay_sealed_bytes = 0;
    next.remote_counter_state_count = 0;
    next.remote_counter_state_sealed_bytes = 0;
    // manifest 必须保留到 secure-store V2 guards 全部 exact absent；LocalDeleted
    // finalizer 再与 lifecycle/ledger 同事务删除它。
    next.remote_key_transition_count = 0;
    next.remote_key_transition_active_count = 0;
    next.remote_key_transition_sealed_bytes = 0;
    next.remote_key_update_outbox_count = 0;
    next.remote_key_update_outbox_sealed_bytes = 0;
    let _pending =
        sqlite::update_runtime_ledger(transaction, key_bundle, database_id, &ledger, &next)?;

    for table in [
        "remote_key_update_outbox",
        "remote_key_transitions",
        "publication_outbox",
        "remote_replay_states",
        "remote_counter_states",
        "remote_control_outbox",
        "remote_pairings",
        "remote_authorization_ledger",
        "remote_key_directory",
    ] {
        if row_count(transaction, table)? != 0 {
            return Err(RuntimeStoreError::UnknownOrCorruptSchema);
        }
    }
    super::super::publication::validate_integrity(transaction, key_bundle, database_id, &next)?;
    super::super::remote_replay::validate_v11_integrity(
        transaction,
        key_bundle,
        database_id,
        &next,
    )?;
    super::super::key_transition::validate_v12_integrity(
        transaction,
        key_bundle,
        database_id,
        &next,
    )?;
    super::super::remote_counter_guard_manifest::validate_v12_integrity(
        transaction,
        key_bundle,
        database_id,
        &next,
    )?;
    Ok(())
}

fn require_root_present_directory_ready(
    directory: &super::super::pairing::PairingDirectory,
) -> Result<(), RuntimeStoreError> {
    if !directory.pairings.is_empty()
        || !directory.outboxes.is_empty()
        || !directory.grants.installs.is_empty()
        || !directory.grants.revocations.is_empty()
        || directory.grants.authorizations.iter().any(|authorization| {
            !matches!(
                authorization.lifecycle,
                AuthorizationLifecycle::Superseded | AuthorizationLifecycle::Revoked
            )
        })
    {
        return Err(RuntimeStoreError::MachineRemoteConflict);
    }
    Ok(())
}

fn row_count(transaction: &Transaction<'_>, table: &str) -> Result<u64, RuntimeStoreError> {
    let statement = match table {
        "remote_key_update_outbox" => "SELECT COUNT(*) FROM remote_key_update_outbox",
        "remote_key_transitions" => "SELECT COUNT(*) FROM remote_key_transitions",
        "publication_outbox" => "SELECT COUNT(*) FROM publication_outbox",
        "remote_replay_states" => "SELECT COUNT(*) FROM remote_replay_states",
        "remote_counter_states" => "SELECT COUNT(*) FROM remote_counter_states",
        "remote_control_outbox" => "SELECT COUNT(*) FROM remote_control_outbox",
        "remote_pairings" => "SELECT COUNT(*) FROM remote_pairings",
        "remote_authorization_ledger" => "SELECT COUNT(*) FROM remote_authorization_ledger",
        "remote_key_directory" => "SELECT COUNT(*) FROM remote_key_directory",
        _ => return Err(RuntimeStoreError::UnknownOrCorruptSchema),
    };
    let count: i64 = transaction.query_row(statement, params![], |row| row.get(0))?;
    u64::try_from(count).map_err(|_| RuntimeStoreError::UnknownOrCorruptSchema)
}

fn delete_exact(
    transaction: &Transaction<'_>,
    statement: &str,
    expected: u64,
) -> Result<(), RuntimeStoreError> {
    let deleted = transaction.execute(statement, [])?;
    if u64::try_from(deleted).map_err(|_| RuntimeStoreError::UnknownOrCorruptSchema)? != expected {
        return Err(RuntimeStoreError::UnknownOrCorruptSchema);
    }
    Ok(())
}
