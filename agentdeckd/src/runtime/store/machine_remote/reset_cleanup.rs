//! Machine trust-reset 对 P4.3 remote security state 的原子清理边界。
//!
//! pairing receipt 是 30 天保留的无授权 tombstone，故意不在本模块删除。其余仍能
//! 授权、恢复网络操作或持有秘密材料的 row 必须与 machine lifecycle 转换同事务清除。

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

pub(super) fn scrub_remote_security_state(
    transaction: &Transaction<'_>,
    key_bundle: &RuntimeKeyBundle,
    database_id: [u8; 16],
    mode: RemoteSecurityCleanupMode,
) -> Result<(), RuntimeStoreError> {
    // 先做完整 authenticated audit；任何离线改删/移植都必须在开始 DELETE 前 fail-close。
    let directory = super::super::pairing::load_directory(transaction, key_bundle, database_id)?;
    if mode == RemoteSecurityCleanupMode::RootPresentAfterRevocation
        && (!directory.pairings.is_empty()
            || !directory.outboxes.is_empty()
            || !directory.grants.installs.is_empty()
            || !directory.grants.revocations.is_empty()
            || directory.grants.authorizations.iter().any(|authorization| {
                !matches!(
                    authorization.lifecycle,
                    AuthorizationLifecycle::Superseded | AuthorizationLifecycle::Revoked
                )
            }))
    {
        return Err(RuntimeStoreError::MachineRemoteConflict);
    }

    let expected_outboxes = directory.ledger.remote_control_outbox_count;
    let expected_pairings = directory.ledger.remote_pairing_count;
    let expected_authorizations = directory.ledger.remote_authorization_count;
    let expected_key_directories = directory.ledger.remote_key_directory_count;

    // 外键顺序是安全不变量：先移除 durable 网络操作，再移除其 pairing/auth parent。
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

    let mut next = directory.ledger.clone();
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
    let _pending = sqlite::update_runtime_ledger(
        transaction,
        key_bundle,
        database_id,
        &directory.ledger,
        &next,
    )?;

    let remaining: (i64, i64, i64, i64) = transaction.query_row(
        "SELECT (SELECT COUNT(*) FROM remote_pairings),
                (SELECT COUNT(*) FROM remote_control_outbox),
                (SELECT COUNT(*) FROM remote_authorization_ledger),
                (SELECT COUNT(*) FROM remote_key_directory)",
        params![],
        |row| Ok((row.get(0)?, row.get(1)?, row.get(2)?, row.get(3)?)),
    )?;
    if remaining != (0, 0, 0, 0) {
        return Err(RuntimeStoreError::UnknownOrCorruptSchema);
    }
    Ok(())
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
