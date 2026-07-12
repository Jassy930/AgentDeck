//! Runtime 持久化对象的 128-bit 稳定身份、严格文本 codec 与碰撞重试。
//!
//! 数据库中保存固定 16 bytes；跨 IPC/诊断边界只接受 lowercase hyphenated UUID。
//! UUID 文本只是无损表示，不改写随机位，因此保留完整 128-bit CSPRNG 输出。

use std::fmt;

use thiserror::Error;

/// 单次分配最多尝试的独立随机候选数。
pub const MAX_RUNTIME_ID_COLLISION_ATTEMPTS: usize = 16;

#[derive(Clone, Copy, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub enum RuntimeIdKind {
    Database,
    Conversation,
    Command,
    Turn,
    Event,
    Approval,
    AdapterState,
    DaemonBoot,
}

impl fmt::Display for RuntimeIdKind {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(match self {
            Self::Database => "database",
            Self::Conversation => "conversation",
            Self::Command => "command",
            Self::Turn => "turn",
            Self::Event => "event",
            Self::Approval => "approval",
            Self::AdapterState => "adapter-state",
            Self::DaemonBoot => "daemon-boot",
        })
    }
}

/// kind-tagged、固定 16 bytes 且禁止全零的 Runtime 身份。
#[derive(Clone, Copy, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub struct RuntimeId {
    kind: RuntimeIdKind,
    bytes: [u8; 16],
}

impl RuntimeId {
    pub fn from_bytes(kind: RuntimeIdKind, bytes: [u8; 16]) -> Result<Self, RuntimeIdError> {
        if bytes == [0; 16] {
            return Err(RuntimeIdError::Zero { kind });
        }
        Ok(Self { kind, bytes })
    }

    /// 只接受 36-byte、lowercase、标准 8-4-4-4-12 hyphenated UUID。
    pub fn parse_canonical(kind: RuntimeIdKind, value: &str) -> Result<Self, RuntimeIdError> {
        let parsed =
            uuid::Uuid::parse_str(value).map_err(|_| RuntimeIdError::InvalidText { kind })?;
        let canonical = parsed.hyphenated().to_string();
        if value != canonical {
            return Err(RuntimeIdError::NonCanonicalText { kind });
        }
        Self::from_bytes(kind, parsed.into_bytes())
    }

    #[must_use]
    pub const fn kind(&self) -> RuntimeIdKind {
        self.kind
    }

    #[must_use]
    pub const fn as_bytes(&self) -> &[u8; 16] {
        &self.bytes
    }

    #[must_use]
    pub fn to_canonical_string(self) -> String {
        uuid::Uuid::from_bytes(self.bytes).hyphenated().to_string()
    }
}

impl fmt::Display for RuntimeId {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        uuid::Uuid::from_bytes(self.bytes)
            .hyphenated()
            .fmt(formatter)
    }
}

impl fmt::Debug for RuntimeId {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("RuntimeId")
            .field("kind", &self.kind)
            .field("value", &self.to_canonical_string())
            .finish()
    }
}

#[derive(Clone, Copy, Debug, Error, Eq, PartialEq)]
pub enum RuntimeIdError {
    #[error("{kind} id text is not a UUID")]
    InvalidText { kind: RuntimeIdKind },
    #[error("{kind} id text is not canonical lowercase hyphenated UUID")]
    NonCanonicalText { kind: RuntimeIdKind },
    #[error("{kind} id must not be all zero")]
    Zero { kind: RuntimeIdKind },
    #[error("operating-system entropy source is unavailable for {kind} id")]
    EntropyUnavailable { kind: RuntimeIdKind },
    #[error("{kind} id source returned another kind: {actual}")]
    SourceKindMismatch {
        kind: RuntimeIdKind,
        actual: RuntimeIdKind,
    },
    #[error("{kind} id allocation exhausted after {attempts} collisions")]
    CollisionExhausted {
        kind: RuntimeIdKind,
        attempts: usize,
    },
}

/// 可替换为确定性测试序列的 Runtime ID 熵入口。
pub trait RuntimeIdSource: Send {
    fn next_id(&mut self, kind: RuntimeIdKind) -> Result<RuntimeId, RuntimeIdError>;
}

/// 生产实现：每个候选直接读取 128-bit OS CSPRNG，不使用时间/PID/counter。
#[derive(Clone, Copy, Debug, Default)]
pub struct OsRuntimeIdSource;

impl RuntimeIdSource for OsRuntimeIdSource {
    fn next_id(&mut self, kind: RuntimeIdKind) -> Result<RuntimeId, RuntimeIdError> {
        let mut bytes = [0_u8; 16];
        getrandom::fill(&mut bytes).map_err(|_| RuntimeIdError::EntropyUnavailable { kind })?;
        RuntimeId::from_bytes(kind, bytes)
    }
}

/// 对注入 source 与纯 collision predicate 做固定上界重试；不接触 DB 或全局状态。
pub fn allocate_unique_runtime_id(
    kind: RuntimeIdKind,
    source: &mut (impl RuntimeIdSource + ?Sized),
    mut collides: impl FnMut(&RuntimeId) -> bool,
) -> Result<RuntimeId, RuntimeIdError> {
    for _ in 0..MAX_RUNTIME_ID_COLLISION_ATTEMPTS {
        let candidate = source.next_id(kind)?;
        if candidate.kind != kind {
            return Err(RuntimeIdError::SourceKindMismatch {
                kind,
                actual: candidate.kind,
            });
        }
        if !collides(&candidate) {
            return Ok(candidate);
        }
    }
    Err(RuntimeIdError::CollisionExhausted {
        kind,
        attempts: MAX_RUNTIME_ID_COLLISION_ATTEMPTS,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn approval_id_kind_has_a_neutral_stable_label() {
        assert_eq!(RuntimeIdKind::Approval.to_string(), "approval");
        let id = RuntimeId::from_bytes(RuntimeIdKind::Approval, [0xa5; 16])
            .expect("non-zero approval id");
        assert_eq!(id.kind(), RuntimeIdKind::Approval);
    }
}
