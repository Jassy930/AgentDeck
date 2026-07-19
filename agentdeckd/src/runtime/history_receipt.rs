//! Native history command receipt 的进程内有界索引。
//!
//! 本索引只记录最近一次完整读取并完成 canonical 组装的 history command identity，
//! 不实现序列化，也不持有 Runtime Store、路径、正文或 adapter 私有引用。

use std::collections::{HashMap, HashSet};
use std::fmt;
use std::sync::{Arc, Mutex};

use super::store::{RuntimeId, RuntimeIdKind};

pub(crate) const MAX_HISTORY_COMMAND_IDS_PER_CONVERSATION: usize = 10_000;

#[derive(Clone, Default)]
pub(crate) struct HistoryOnlyReceiptRegistry {
    entries: Arc<Mutex<HashMap<RuntimeId, HashSet<RuntimeId>>>>,
}

impl fmt::Debug for HistoryOnlyReceiptRegistry {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("HistoryOnlyReceiptRegistry([REDACTED])")
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq, thiserror::Error)]
pub(crate) enum HistoryOnlyReceiptError {
    #[error("history-only receipt identity has kind {actual}, expected {expected}")]
    InvalidIdentityKind {
        expected: RuntimeIdKind,
        actual: RuntimeIdKind,
    },
    #[error(
        "history-only receipt set exceeds its per-conversation limit of {limit} command identities"
    )]
    ConversationLimit { limit: usize },
    #[error("history-only receipt registry state is poisoned")]
    StatePoisoned,
}

impl HistoryOnlyReceiptRegistry {
    /// 原子替换一个 conversation 的完整已验证 command set。
    ///
    /// kind、去重和硬上限都在获取共享锁之前完成；任一验证失败不会清空或部分
    /// 覆盖既有集合。空集合等价于清除该 conversation，避免保留空 map entry。
    pub(crate) fn replace(
        &self,
        conversation_id: RuntimeId,
        command_ids: impl IntoIterator<Item = RuntimeId>,
    ) -> Result<(), HistoryOnlyReceiptError> {
        require_kind(conversation_id, RuntimeIdKind::Conversation)?;
        let mut replacement = HashSet::new();
        for command_id in command_ids {
            require_kind(command_id, RuntimeIdKind::Command)?;
            if !replacement.contains(&command_id)
                && replacement.len() == MAX_HISTORY_COMMAND_IDS_PER_CONVERSATION
            {
                return Err(HistoryOnlyReceiptError::ConversationLimit {
                    limit: MAX_HISTORY_COMMAND_IDS_PER_CONVERSATION,
                });
            }
            replacement.insert(command_id);
        }

        let mut entries = self
            .entries
            .lock()
            .map_err(|_| HistoryOnlyReceiptError::StatePoisoned)?;
        if replacement.is_empty() {
            entries.remove(&conversation_id);
        } else {
            entries.insert(conversation_id, replacement);
        }
        Ok(())
    }

    pub(crate) fn contains(
        &self,
        conversation_id: RuntimeId,
        command_id: RuntimeId,
    ) -> Result<bool, HistoryOnlyReceiptError> {
        require_kind(conversation_id, RuntimeIdKind::Conversation)?;
        require_kind(command_id, RuntimeIdKind::Command)?;
        let entries = self
            .entries
            .lock()
            .map_err(|_| HistoryOnlyReceiptError::StatePoisoned)?;
        Ok(entries
            .get(&conversation_id)
            .is_some_and(|commands| commands.contains(&command_id)))
    }

    /// 清除一个 conversation 的 volatile receipt set。返回值表示清除前是否存在。
    pub(crate) fn clear(
        &self,
        conversation_id: RuntimeId,
    ) -> Result<bool, HistoryOnlyReceiptError> {
        require_kind(conversation_id, RuntimeIdKind::Conversation)?;
        self.entries
            .lock()
            .map_err(|_| HistoryOnlyReceiptError::StatePoisoned)
            .map(|mut entries| entries.remove(&conversation_id).is_some())
    }
}

fn require_kind(
    identity: RuntimeId,
    expected: RuntimeIdKind,
) -> Result<(), HistoryOnlyReceiptError> {
    let actual = identity.kind();
    if actual == expected {
        Ok(())
    } else {
        Err(HistoryOnlyReceiptError::InvalidIdentityKind { expected, actual })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn id(kind: RuntimeIdKind, value: u128) -> RuntimeId {
        RuntimeId::from_bytes(kind, value.to_be_bytes()).expect("nonzero history receipt identity")
    }

    fn conversation(value: u128) -> RuntimeId {
        id(RuntimeIdKind::Conversation, value)
    }

    fn command(value: u128) -> RuntimeId {
        id(RuntimeIdKind::Command, value)
    }

    #[test]
    fn replace_installs_the_exact_deduplicated_set_and_clones_share_it() {
        let registry = HistoryOnlyReceiptRegistry::default();
        let shared = registry.clone();
        let conversation = conversation(1);
        let first = command(11);
        let second = command(12);

        registry
            .replace(conversation, [first, first, second])
            .expect("replace history-only receipt set");

        assert!(shared.contains(conversation, first).unwrap());
        assert!(shared.contains(conversation, second).unwrap());
        assert!(!shared.contains(conversation, command(13)).unwrap());
    }

    #[test]
    fn replacement_removes_commands_missing_from_the_latest_verified_read() {
        let registry = HistoryOnlyReceiptRegistry::default();
        let conversation = conversation(2);
        let removed = command(21);
        let retained = command(22);
        let appended = command(23);
        registry.replace(conversation, [removed, retained]).unwrap();

        registry
            .replace(conversation, [retained, appended])
            .expect("replace with truncated latest set");

        assert!(!registry.contains(conversation, removed).unwrap());
        assert!(registry.contains(conversation, retained).unwrap());
        assert!(registry.contains(conversation, appended).unwrap());
    }

    #[test]
    fn exact_limit_is_accepted_and_overflow_preserves_the_previous_set() {
        let registry = HistoryOnlyReceiptRegistry::default();
        let conversation = conversation(3);
        let exact = (1..=MAX_HISTORY_COMMAND_IDS_PER_CONVERSATION)
            .map(|value| command(value as u128))
            .collect::<Vec<_>>();
        registry
            .replace(conversation, exact.iter().copied())
            .expect("accept exact history receipt limit");
        assert!(registry.contains(conversation, exact[0]).unwrap());
        assert!(
            registry
                .contains(conversation, exact[exact.len() - 1])
                .unwrap()
        );

        let overflow = exact
            .iter()
            .copied()
            .chain(std::iter::once(command(20_000)));
        assert_eq!(
            registry.replace(conversation, overflow),
            Err(HistoryOnlyReceiptError::ConversationLimit {
                limit: MAX_HISTORY_COMMAND_IDS_PER_CONVERSATION,
            })
        );
        assert!(registry.contains(conversation, exact[0]).unwrap());
        assert!(!registry.contains(conversation, command(20_000)).unwrap());
    }

    #[test]
    fn conversations_are_isolated_during_replace() {
        let registry = HistoryOnlyReceiptRegistry::default();
        let first_conversation = conversation(4);
        let second_conversation = conversation(5);
        let shared_command = command(41);
        let first_only = command(42);
        let second_only = command(43);
        registry
            .replace(first_conversation, [shared_command, first_only])
            .unwrap();
        registry
            .replace(second_conversation, [shared_command, second_only])
            .unwrap();

        registry
            .replace(first_conversation, [first_only])
            .expect("replace only the first conversation");

        assert!(
            !registry
                .contains(first_conversation, shared_command)
                .unwrap()
        );
        assert!(registry.contains(first_conversation, first_only).unwrap());
        assert!(
            registry
                .contains(second_conversation, shared_command)
                .unwrap()
        );
        assert!(registry.contains(second_conversation, second_only).unwrap());
    }

    #[test]
    fn clear_is_conversation_scoped_and_idempotent() {
        let registry = HistoryOnlyReceiptRegistry::default();
        let first_conversation = conversation(6);
        let second_conversation = conversation(7);
        let first = command(61);
        let second = command(71);
        registry.replace(first_conversation, [first]).unwrap();
        registry.replace(second_conversation, [second]).unwrap();

        assert!(registry.clear(first_conversation).unwrap());
        assert!(!registry.clear(first_conversation).unwrap());
        assert!(!registry.contains(first_conversation, first).unwrap());
        assert!(registry.contains(second_conversation, second).unwrap());
    }

    #[test]
    fn invalid_identity_kinds_fail_before_mutating_the_previous_set() {
        let registry = HistoryOnlyReceiptRegistry::default();
        let conversation = conversation(8);
        let retained = command(81);
        registry.replace(conversation, [retained]).unwrap();

        assert_eq!(
            registry.replace(command(82), [command(83)]),
            Err(HistoryOnlyReceiptError::InvalidIdentityKind {
                expected: RuntimeIdKind::Conversation,
                actual: RuntimeIdKind::Command,
            })
        );
        assert_eq!(
            registry.replace(conversation, [id(RuntimeIdKind::Event, 84)]),
            Err(HistoryOnlyReceiptError::InvalidIdentityKind {
                expected: RuntimeIdKind::Command,
                actual: RuntimeIdKind::Event,
            })
        );
        assert_eq!(
            registry.contains(command(85), retained),
            Err(HistoryOnlyReceiptError::InvalidIdentityKind {
                expected: RuntimeIdKind::Conversation,
                actual: RuntimeIdKind::Command,
            })
        );
        assert_eq!(
            registry.contains(conversation, id(RuntimeIdKind::Event, 86)),
            Err(HistoryOnlyReceiptError::InvalidIdentityKind {
                expected: RuntimeIdKind::Command,
                actual: RuntimeIdKind::Event,
            })
        );
        assert_eq!(
            registry.clear(command(87)),
            Err(HistoryOnlyReceiptError::InvalidIdentityKind {
                expected: RuntimeIdKind::Conversation,
                actual: RuntimeIdKind::Command,
            })
        );
        assert!(registry.contains(conversation, retained).unwrap());
    }

    #[test]
    fn debug_is_redacted_and_a_fresh_registry_recovers_nothing() {
        let registry = HistoryOnlyReceiptRegistry::default();
        let conversation = conversation(9);
        let command = command(91);
        registry.replace(conversation, [command]).unwrap();
        let debug = format!("{registry:?}");
        assert_eq!(debug, "HistoryOnlyReceiptRegistry([REDACTED])");
        assert!(!debug.contains(&conversation.to_canonical_string()));
        assert!(!debug.contains(&command.to_canonical_string()));

        let restarted = HistoryOnlyReceiptRegistry::default();
        assert!(!restarted.contains(conversation, command).unwrap());
    }
}
