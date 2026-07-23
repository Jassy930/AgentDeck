//! Durable Runtime Stream source 与 compact Transfer identity 的共享契约。
//!
//! `adrt-shared-v1` identity 必须能由 daemon 和远程客户端独立反解；同一份
//! immutable Catalog/Event source 在重连、重启和不同 connection 上派生完全相同的
//! transferId、messageId 与 compact partCount。这里不承载 Relay 路由或业务状态。

use std::fmt::{self, Write as _};

use sha2::{Digest, Sha256};

use super::RUNTIME_PROTOCOL_VERSION;
use super::identity::{ConversationId, EventId, MessageId, TransferId};
use super::transfer::{
    MAX_PART_BYTES, MAX_TRANSFER_BYTES, MAX_TRANSFER_PARTS, RuntimeTransferCarrierV1,
    RuntimeTransferChannel,
};

const TRANSFER_ID_PREFIX: &str = "adrt-shared-v1";
const MESSAGE_ID_PREFIX: &str = "shared-transfer-";
const MESSAGE_ID_DOMAIN: &[u8] = b"AgentDeck/DurableStreamTransferMessageIdV1\0";

/// 一次 durable Catalog publication 最多合并的连续 revision 数。
pub const MAX_DURABLE_CATALOG_REVISIONS: u64 = 500;

/// `adrt-shared-v1` 中 canonical lowercase hyphenated、非零的 128-bit Runtime ID。
#[derive(Clone, Copy, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub struct DurableStreamObjectId([u8; 16]);

impl DurableStreamObjectId {
    /// 从 daemon 持久身份 bytes 构造；全零不是合法 Runtime identity。
    pub fn from_bytes(bytes: [u8; 16]) -> Result<Self, DurableStreamTransferIdentityError> {
        if bytes == [0; 16] {
            return Err(DurableStreamTransferIdentityError::InvalidSource);
        }
        Ok(Self(bytes))
    }

    /// 严格解析 lowercase 8-4-4-4-12 UUID 文本；不接受 nil 或宽松变体。
    pub fn parse_canonical(value: &str) -> Result<Self, DurableStreamTransferIdentityError> {
        parse_object_id(value, DurableStreamTransferIdentityError::InvalidSource)
    }

    #[must_use]
    pub const fn as_bytes(self) -> [u8; 16] {
        self.0
    }
}

impl fmt::Display for DurableStreamObjectId {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        for (index, byte) in self.0.iter().enumerate() {
            if matches!(index, 4 | 6 | 8 | 10) {
                formatter.write_str("-")?;
            }
            write!(formatter, "{byte:02x}")?;
        }
        Ok(())
    }
}

/// Durable Stream transfer 的 authenticated journal source。
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum DurableStreamTransferSource {
    Catalog {
        first_revision: u64,
        through_revision: u64,
    },
    Event {
        conversation_id: DurableStreamObjectId,
        event_id: DurableStreamObjectId,
        event_seq: u64,
    },
}

/// `adrt-shared-v1` 的 canonical、可反解 identity。
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct DurableStreamTransferIdentity {
    source: DurableStreamTransferSource,
    total_bytes: u64,
    total_sha256: [u8; 32],
}

impl DurableStreamTransferIdentity {
    pub fn for_catalog(
        first_revision: u64,
        through_revision: u64,
        payload: &[u8],
    ) -> Result<Self, DurableStreamTransferIdentityError> {
        Self::from_catalog_metadata(
            first_revision,
            through_revision,
            payload_len(payload)?,
            Sha256::digest(payload).into(),
        )
    }

    pub fn from_catalog_metadata(
        first_revision: u64,
        through_revision: u64,
        total_bytes: u64,
        total_sha256: [u8; 32],
    ) -> Result<Self, DurableStreamTransferIdentityError> {
        Self::from_metadata(
            DurableStreamTransferSource::Catalog {
                first_revision,
                through_revision,
            },
            total_bytes,
            total_sha256,
        )
    }

    pub fn for_event(
        conversation_id: &ConversationId,
        event_id: &EventId,
        event_seq: u64,
        payload: &[u8],
    ) -> Result<Self, DurableStreamTransferIdentityError> {
        Self::from_event_metadata(
            conversation_id,
            event_id,
            event_seq,
            payload_len(payload)?,
            Sha256::digest(payload).into(),
        )
    }

    pub fn from_event_metadata(
        conversation_id: &ConversationId,
        event_id: &EventId,
        event_seq: u64,
        total_bytes: u64,
        total_sha256: [u8; 32],
    ) -> Result<Self, DurableStreamTransferIdentityError> {
        let conversation_id = DurableStreamObjectId::parse_canonical(conversation_id.as_str())?;
        let event_id = DurableStreamObjectId::parse_canonical(event_id.as_str())?;
        Self::from_metadata(
            DurableStreamTransferSource::Event {
                conversation_id,
                event_id,
                event_seq,
            },
            total_bytes,
            total_sha256,
        )
    }

    pub fn from_metadata(
        source: DurableStreamTransferSource,
        total_bytes: u64,
        total_sha256: [u8; 32],
    ) -> Result<Self, DurableStreamTransferIdentityError> {
        validate_source(source)?;
        if total_bytes > MAX_TRANSFER_BYTES {
            return Err(DurableStreamTransferIdentityError::TooLarge);
        }
        Ok(Self {
            source,
            total_bytes,
            total_sha256,
        })
    }

    pub fn parse_transfer_id(
        transfer_id: &TransferId,
    ) -> Result<Self, DurableStreamTransferIdentityError> {
        if !transfer_id.is_valid_wire_value() {
            return Err(DurableStreamTransferIdentityError::InvalidIdentity);
        }
        let parts = transfer_id.as_str().split(':').collect::<Vec<_>>();
        let identity = match parts.as_slice() {
            [prefix, "c", first, through, total_bytes, digest] if *prefix == TRANSFER_ID_PREFIX => {
                let first_revision = parse_u64(first)?;
                let through_revision = parse_u64(through)?;
                let identity = Self::from_catalog_metadata(
                    first_revision,
                    through_revision,
                    parse_total_bytes(total_bytes)?,
                    parse_hex_digest(digest)?,
                );
                identity.map_err(parse_context_error)?
            }
            [
                prefix,
                "e",
                conversation,
                event,
                sequence,
                total_bytes,
                digest,
            ] if *prefix == TRANSFER_ID_PREFIX => Self::from_metadata(
                DurableStreamTransferSource::Event {
                    conversation_id: parse_object_id(
                        conversation,
                        DurableStreamTransferIdentityError::InvalidIdentity,
                    )?,
                    event_id: parse_object_id(
                        event,
                        DurableStreamTransferIdentityError::InvalidIdentity,
                    )?,
                    event_seq: parse_u64(sequence)?,
                },
                parse_total_bytes(total_bytes)?,
                parse_hex_digest(digest)?,
            )
            .map_err(parse_context_error)?,
            _ => return Err(DurableStreamTransferIdentityError::InvalidIdentity),
        };
        if identity.transfer_id() != *transfer_id {
            return Err(DurableStreamTransferIdentityError::InvalidIdentity);
        }
        Ok(identity)
    }

    #[must_use]
    pub const fn source(self) -> DurableStreamTransferSource {
        self.source
    }

    #[must_use]
    pub const fn total_bytes(self) -> u64 {
        self.total_bytes
    }

    #[must_use]
    pub const fn total_sha256(self) -> [u8; 32] {
        self.total_sha256
    }

    #[must_use]
    pub fn transfer_id(self) -> TransferId {
        let mut value = String::new();
        match self.source {
            DurableStreamTransferSource::Catalog {
                first_revision,
                through_revision,
            } => write!(
                &mut value,
                "{TRANSFER_ID_PREFIX}:c:{first_revision}:{through_revision}:{}:",
                self.total_bytes
            )
            .expect("writing to String cannot fail"),
            DurableStreamTransferSource::Event {
                conversation_id,
                event_id,
                event_seq,
            } => write!(
                &mut value,
                "{TRANSFER_ID_PREFIX}:e:{conversation_id}:{event_id}:{event_seq}:{}:",
                self.total_bytes
            )
            .expect("writing to String cannot fail"),
        }
        append_hex(&mut value, &self.total_sha256);
        TransferId::new(value)
    }

    #[must_use]
    pub fn message_id(self) -> MessageId {
        let transfer_id = self.transfer_id();
        let mut hasher = Sha256::new();
        hasher.update(MESSAGE_ID_DOMAIN);
        hasher.update(transfer_id.as_str().as_bytes());
        let digest: [u8; 32] = hasher.finalize().into();
        let mut value = String::with_capacity(MESSAGE_ID_PREFIX.len() + 64);
        value.push_str(MESSAGE_ID_PREFIX);
        append_hex(&mut value, &digest);
        MessageId::new(value)
    }

    /// durable Relay compact carrier 使用固定 3.5 MiB part size；零字节仍有一个 part。
    #[must_use]
    pub fn part_count(self) -> u32 {
        let count = self.total_bytes.max(1).div_ceil(MAX_PART_BYTES as u64);
        u32::try_from(count).expect("validated transfer bound has a representable part count")
    }

    /// 校验 compact carrier 的全部 identity metadata；part 内容在完成重组后由总 hash 校验。
    pub fn validate_carrier(
        self,
        carrier: &RuntimeTransferCarrierV1,
    ) -> Result<(), DurableStreamTransferIdentityError> {
        if carrier.runtime_version != RUNTIME_PROTOCOL_VERSION
            || carrier.channel != RuntimeTransferChannel::Stream
            || carrier.message_id != self.message_id()
            || carrier.transfer.transfer_id != self.transfer_id()
            || carrier.transfer.total_bytes != self.total_bytes
            || carrier.transfer.total_sha256 != self.total_sha256
            || carrier.transfer.part_count != self.part_count()
            || carrier.transfer.validate().is_err()
        {
            return Err(DurableStreamTransferIdentityError::MetadataMismatch);
        }
        Ok(())
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq, thiserror::Error)]
pub enum DurableStreamTransferIdentityError {
    #[error("durable Stream transfer source is invalid")]
    InvalidSource,
    #[error("durable Stream transfer identity is invalid")]
    InvalidIdentity,
    #[error("durable Stream transfer exceeds its hard limit")]
    TooLarge,
    #[error("durable Stream transfer carrier metadata does not match its identity")]
    MetadataMismatch,
}

fn payload_len(payload: &[u8]) -> Result<u64, DurableStreamTransferIdentityError> {
    u64::try_from(payload.len()).map_err(|_| DurableStreamTransferIdentityError::TooLarge)
}

fn validate_source(
    source: DurableStreamTransferSource,
) -> Result<(), DurableStreamTransferIdentityError> {
    if let DurableStreamTransferSource::Catalog {
        first_revision,
        through_revision,
    } = source
    {
        if through_revision < first_revision {
            return Err(DurableStreamTransferIdentityError::InvalidSource);
        }
        let count = through_revision
            .checked_sub(first_revision)
            .and_then(|distance| distance.checked_add(1))
            .ok_or(DurableStreamTransferIdentityError::TooLarge)?;
        if count > MAX_DURABLE_CATALOG_REVISIONS {
            return Err(DurableStreamTransferIdentityError::TooLarge);
        }
    }
    Ok(())
}

fn parse_context_error(
    error: DurableStreamTransferIdentityError,
) -> DurableStreamTransferIdentityError {
    match error {
        DurableStreamTransferIdentityError::InvalidSource => {
            DurableStreamTransferIdentityError::InvalidIdentity
        }
        other => other,
    }
}

fn parse_u64(value: &str) -> Result<u64, DurableStreamTransferIdentityError> {
    let parsed = value
        .parse::<u64>()
        .map_err(|_| DurableStreamTransferIdentityError::InvalidIdentity)?;
    if parsed.to_string() != value {
        return Err(DurableStreamTransferIdentityError::InvalidIdentity);
    }
    Ok(parsed)
}

fn parse_total_bytes(value: &str) -> Result<u64, DurableStreamTransferIdentityError> {
    let parsed = parse_u64(value)?;
    if parsed > MAX_TRANSFER_BYTES {
        return Err(DurableStreamTransferIdentityError::TooLarge);
    }
    Ok(parsed)
}

fn parse_hex_digest(value: &str) -> Result<[u8; 32], DurableStreamTransferIdentityError> {
    if value.len() != 64
        || !value
            .as_bytes()
            .iter()
            .all(|byte| byte.is_ascii_digit() || matches!(byte, b'a'..=b'f'))
    {
        return Err(DurableStreamTransferIdentityError::InvalidIdentity);
    }
    let mut digest = [0_u8; 32];
    for (index, slot) in digest.iter_mut().enumerate() {
        let offset = index * 2;
        *slot = u8::from_str_radix(&value[offset..offset + 2], 16)
            .map_err(|_| DurableStreamTransferIdentityError::InvalidIdentity)?;
    }
    Ok(digest)
}

fn parse_object_id(
    value: &str,
    error: DurableStreamTransferIdentityError,
) -> Result<DurableStreamObjectId, DurableStreamTransferIdentityError> {
    let bytes = value.as_bytes();
    if bytes.len() != 36
        || bytes.get(8) != Some(&b'-')
        || bytes.get(13) != Some(&b'-')
        || bytes.get(18) != Some(&b'-')
        || bytes.get(23) != Some(&b'-')
    {
        return Err(error);
    }
    let mut decoded = [0_u8; 16];
    let mut output = 0_usize;
    let mut high = None;
    for (index, byte) in bytes.iter().copied().enumerate() {
        if matches!(index, 8 | 13 | 18 | 23) {
            continue;
        }
        let nibble = match byte {
            b'0'..=b'9' => byte - b'0',
            b'a'..=b'f' => byte - b'a' + 10,
            _ => return Err(error),
        };
        match high.take() {
            None => high = Some(nibble),
            Some(high) => {
                decoded[output] = (high << 4) | nibble;
                output += 1;
            }
        }
    }
    if output != decoded.len() || high.is_some() || decoded == [0; 16] {
        return Err(error);
    }
    Ok(DurableStreamObjectId(decoded))
}

fn append_hex(output: &mut String, bytes: &[u8]) {
    for byte in bytes {
        write!(output, "{byte:02x}").expect("writing to String cannot fail");
    }
}

const _: () = assert!(
    MAX_TRANSFER_BYTES.div_ceil(MAX_PART_BYTES as u64) <= u32::MAX as u64
        && MAX_TRANSFER_BYTES.div_ceil(MAX_PART_BYTES as u64) <= MAX_TRANSFER_PARTS as u64
);
