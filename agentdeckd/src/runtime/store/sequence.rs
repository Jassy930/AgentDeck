//! Runtime SQLite 中 u64 high-water 的定宽文本编码。
//!
//! SQLite signed INTEGER 无法覆盖完整 u64；固定 20 位十进制文本既保留完整范围，
//! 又让字典序与无符号数值顺序一致。空 high-water 使用 `None`，首次分配为 0。

use thiserror::Error;

pub const SEQUENCE_TEXT_WIDTH: usize = 20;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum SequenceScope {
    CatalogRevision,
    CommandSeq,
    EventSeq,
    LeaderStartTime,
}

#[derive(Clone, Copy, Debug, Eq, Error, PartialEq)]
pub enum SequenceError {
    #[error("invalid fixed-width u64 encoding for {scope:?}")]
    InvalidEncoding { scope: SequenceScope },
    #[error("u64 sequence is exhausted for {scope:?}")]
    Exhausted { scope: SequenceScope },
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct AllocatedSequence {
    pub value: u64,
    pub encoded: String,
}

#[must_use]
pub fn encode_sequence(value: u64) -> String {
    format!("{value:0SEQUENCE_TEXT_WIDTH$}")
}

pub fn decode_sequence(scope: SequenceScope, encoded: &str) -> Result<u64, SequenceError> {
    if encoded.len() != SEQUENCE_TEXT_WIDTH || !encoded.as_bytes().iter().all(u8::is_ascii_digit) {
        return Err(SequenceError::InvalidEncoding { scope });
    }

    let value = encoded
        .parse::<u64>()
        .map_err(|_| SequenceError::InvalidEncoding { scope })?;
    if encode_sequence(value) != encoded {
        return Err(SequenceError::InvalidEncoding { scope });
    }
    Ok(value)
}

pub fn next_sequence(
    scope: SequenceScope,
    high_water: Option<&str>,
) -> Result<AllocatedSequence, SequenceError> {
    let value = match high_water {
        None => 0,
        Some(encoded) => decode_sequence(scope, encoded)?
            .checked_add(1)
            .ok_or(SequenceError::Exhausted { scope })?,
    };
    Ok(AllocatedSequence {
        value,
        encoded: encode_sequence(value),
    })
}
