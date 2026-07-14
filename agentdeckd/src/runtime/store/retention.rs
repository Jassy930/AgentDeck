//! Logical replay retention 的单一裁剪授权边界。
//!
//! 具体威胁场景：outbox 本地不可消费，或 snapshot ciphertext 被等长篡改后，若它们
//! 仍能授权 trim，writer 会删除唯一 replay membership，造成永久 snapshot/backfill 缺口。

use rusqlite::{Connection, params};

use crate::runtime::model::{RuntimeStoreError, RuntimeStoreLane};

use super::cipher::RuntimeKeyBundle;
use super::identity::{RuntimeId, RuntimeIdKind};
use super::sequence::{SequenceScope, decode_sequence};

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) struct RetentionEvidence {
    pub active_pin_covers_victim: bool,
    pub durable_snapshot_covers_victim: bool,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum RetentionBlock {
    ActivePin,
    ReplacementMissing,
}

/// 纯策略层：pin 优先阻断；没有 durable replacement 也阻断。
pub(crate) const fn evaluate_trim(evidence: RetentionEvidence) -> Result<(), RetentionBlock> {
    if evidence.active_pin_covers_victim {
        return Err(RetentionBlock::ActivePin);
    }
    if !evidence.durable_snapshot_covers_victim {
        return Err(RetentionBlock::ReplacementMissing);
    }
    Ok(())
}

#[derive(Clone, Copy)]
pub(super) enum RetentionTarget<'a> {
    Catalog,
    Conversation(&'a [u8]),
}

pub(super) fn authorize_trim(
    connection: &Connection,
    key_bundle: &RuntimeKeyBundle,
    target: RetentionTarget<'_>,
    victim: &str,
    now_ms: u64,
) -> Result<(), RuntimeStoreError> {
    connection.execute(
        "DELETE FROM temp.active_stream_pins WHERE expires_at_ms <= ?1",
        [super::stream::sqlite_u64(now_ms)?],
    )?;
    let (sequence_scope, active_pin_covers_victim) = match target {
        RetentionTarget::Catalog => (
            SequenceScope::CatalogRevision,
            active_catalog_pin_covers(connection, victim, now_ms)?,
        ),
        RetentionTarget::Conversation(conversation_id) => (
            SequenceScope::EventSeq,
            active_conversation_pin_covers(connection, conversation_id, victim, now_ms)?,
        ),
    };
    let victim_value = decode_sequence(sequence_scope, victim)?;
    let durable_snapshot_covers_victim = match target {
        RetentionTarget::Catalog => super::snapshot::authenticated_catalog_snapshot_covers(
            connection,
            key_bundle,
            victim_value,
        )?,
        RetentionTarget::Conversation(conversation_id) => {
            let conversation_id = RuntimeId::from_bytes(
                RuntimeIdKind::Conversation,
                conversation_id
                    .try_into()
                    .map_err(|_| RuntimeStoreError::UnknownOrCorruptSchema)?,
            )?;
            super::snapshot::authenticated_conversation_snapshot_covers(
                connection,
                key_bundle,
                conversation_id,
                victim_value,
            )?
        }
    };
    evaluate_trim(RetentionEvidence {
        active_pin_covers_victim,
        durable_snapshot_covers_victim,
    })
    .map_err(|block| match block {
        RetentionBlock::ActivePin => RuntimeStoreError::WorkerBusy {
            lane: RuntimeStoreLane::Normal,
        },
        RetentionBlock::ReplacementMissing => RuntimeStoreError::PublicationNeedsSnapshot,
    })
}

fn active_catalog_pin_covers(
    connection: &Connection,
    victim: &str,
    now_ms: u64,
) -> Result<bool, RuntimeStoreError> {
    let active: i64 = connection.query_row(
        "SELECT EXISTS(
             SELECT 1 FROM temp.active_stream_pins
             WHERE scope = 'catalog' AND target_id IS NULL AND state = 'active'
               AND expires_at_ms > ?2
               AND first_seq <= ?1 AND through_seq >= ?1
         )",
        params![victim, super::stream::sqlite_u64(now_ms)?],
        |row| row.get(0),
    )?;
    Ok(active != 0)
}

fn active_conversation_pin_covers(
    connection: &Connection,
    conversation_id: &[u8],
    victim: &str,
    now_ms: u64,
) -> Result<bool, RuntimeStoreError> {
    let active: i64 = connection.query_row(
        "SELECT EXISTS(
             SELECT 1 FROM temp.active_stream_pins
             WHERE target_id = ?1 AND state = 'active' AND expires_at_ms > ?3 AND (
                 (scope = 'event' AND first_seq <= ?2 AND through_seq >= ?2)
                 OR (scope = 'snapshot' AND through_seq IS NOT NULL AND through_seq >= ?2)
             )
         )",
        params![conversation_id, victim, super::stream::sqlite_u64(now_ms)?],
        |row| row.get(0),
    )?;
    Ok(active != 0)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn policy_requires_no_pin_and_at_least_one_durable_replacement() {
        assert_eq!(
            evaluate_trim(RetentionEvidence {
                active_pin_covers_victim: true,
                durable_snapshot_covers_victim: true,
            }),
            Err(RetentionBlock::ActivePin)
        );
        assert_eq!(
            evaluate_trim(RetentionEvidence {
                active_pin_covers_victim: false,
                durable_snapshot_covers_victim: false,
            }),
            Err(RetentionBlock::ReplacementMissing)
        );
        assert_eq!(
            evaluate_trim(RetentionEvidence {
                active_pin_covers_victim: false,
                durable_snapshot_covers_victim: true,
            }),
            Ok(())
        );
    }
}
