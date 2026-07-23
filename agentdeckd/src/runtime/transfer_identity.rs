//! Durable Runtime Stream source 到 compact Transfer identity 的中立绑定。
//!
//! 本模块只依赖 Runtime protocol/store identity，不认识 Relay 或 remote adapter。
//! transferId 可被 Store 严格反解；messageId 则由同一 canonical identity 派生，
//! 因而同一 immutable journal source 在重连、重启和不同 connection 上保持一致。

use std::fmt::Write as _;

use agentdeck_protocol::runtime::identity::{ConversationId, EventId, MessageId, TransferId};
use agentdeck_protocol::runtime::{
    DurableStreamTransferIdentity as ProtocolDurableStreamTransferIdentity,
    DurableStreamTransferIdentityError as ProtocolDurableStreamTransferIdentityError,
    DurableStreamTransferSource as ProtocolDurableStreamTransferSource, MAX_PART_BYTES,
    MAX_TRANSFER_BYTES, RuntimeReply, RuntimeStreamItem, RuntimeTransferCarrierV1,
    RuntimeTransferChannel, StreamCursor, TransferEnvelope,
};
use sha2::{Digest, Sha256};

use super::store::identity::{RuntimeId, RuntimeIdKind};

const PUBLICATION_ID_DOMAIN: &[u8] = b"AgentDeck/DurableStreamTransferPublicationIdV1\0";
const REPLY_TRANSFER_ID_DOMAIN: &[u8] = b"AgentDeck/DurableReplyTransferIdV1\0";
const REPLY_TRANSFER_ID_PREFIX: &str = "reply-transfer-";

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum DurableStreamSource {
    Catalog {
        first_revision: u64,
        through_revision: u64,
    },
    Event {
        conversation_id: RuntimeId,
        event_id: RuntimeId,
        event_seq: u64,
    },
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) struct DurableStreamTransferIdentity {
    shared: ProtocolDurableStreamTransferIdentity,
}

impl DurableStreamTransferIdentity {
    pub(crate) fn for_stream_source(
        source: DurableStreamSource,
        item: &RuntimeStreamItem,
        payload: &[u8],
    ) -> Result<Self, DurableStreamTransferIdentityError> {
        let source_matches = match (source, item) {
            (
                DurableStreamSource::Catalog {
                    first_revision,
                    through_revision,
                },
                RuntimeStreamItem::CatalogDelta(delta),
            ) => first_revision <= through_revision && delta.catalog_revision == through_revision,
            (
                DurableStreamSource::Event {
                    conversation_id,
                    event_id,
                    event_seq,
                },
                RuntimeStreamItem::Event(event),
            ) => {
                let parsed_conversation_id = RuntimeId::parse_canonical(
                    RuntimeIdKind::Conversation,
                    event.conversation_id.as_str(),
                )
                .map_err(|_| DurableStreamTransferIdentityError::InvalidSource)?;
                let parsed_event_id =
                    RuntimeId::parse_canonical(RuntimeIdKind::Event, event.event_id.as_str())
                        .map_err(|_| DurableStreamTransferIdentityError::InvalidSource)?;
                parsed_conversation_id == conversation_id
                    && parsed_event_id == event_id
                    && event.event_seq == event_seq
            }
            _ => false,
        };
        if !source_matches {
            return Err(DurableStreamTransferIdentityError::InvalidSource);
        }
        let shared = match source {
            DurableStreamSource::Catalog {
                first_revision,
                through_revision,
            } => ProtocolDurableStreamTransferIdentity::for_catalog(
                first_revision,
                through_revision,
                payload,
            ),
            DurableStreamSource::Event {
                conversation_id,
                event_id,
                event_seq,
            } => ProtocolDurableStreamTransferIdentity::for_event(
                &ConversationId::new(conversation_id.to_canonical_string()),
                &EventId::new(event_id.to_canonical_string()),
                event_seq,
                payload,
            ),
        }
        .map_err(map_protocol_identity_error)?;
        Ok(Self { shared })
    }

    #[cfg(test)]
    pub(crate) fn from_stream_metadata(
        source: DurableStreamSource,
        total_bytes: u64,
        total_sha256: [u8; 32],
    ) -> Result<Self, DurableStreamTransferIdentityError> {
        let shared = match source {
            DurableStreamSource::Catalog {
                first_revision,
                through_revision,
            } => ProtocolDurableStreamTransferIdentity::from_catalog_metadata(
                first_revision,
                through_revision,
                total_bytes,
                total_sha256,
            ),
            DurableStreamSource::Event {
                conversation_id,
                event_id,
                event_seq,
            } => ProtocolDurableStreamTransferIdentity::from_event_metadata(
                &ConversationId::new(conversation_id.to_canonical_string()),
                &EventId::new(event_id.to_canonical_string()),
                event_seq,
                total_bytes,
                total_sha256,
            ),
        }
        .map_err(map_protocol_identity_error)?;
        Ok(Self { shared })
    }

    pub(crate) fn parse_transfer_id(
        transfer_id: &TransferId,
    ) -> Result<Self, DurableStreamTransferIdentityError> {
        Ok(Self {
            shared: ProtocolDurableStreamTransferIdentity::parse_transfer_id(transfer_id)
                .map_err(map_protocol_identity_error)?,
        })
    }

    pub(crate) fn source(self) -> DurableStreamSource {
        match self.shared.source() {
            ProtocolDurableStreamTransferSource::Catalog {
                first_revision,
                through_revision,
            } => DurableStreamSource::Catalog {
                first_revision,
                through_revision,
            },
            ProtocolDurableStreamTransferSource::Event {
                conversation_id,
                event_id,
                event_seq,
            } => DurableStreamSource::Event {
                conversation_id: RuntimeId::from_bytes(
                    RuntimeIdKind::Conversation,
                    conversation_id.as_bytes(),
                )
                .expect("shared durable identity rejects the all-zero conversation id"),
                event_id: RuntimeId::from_bytes(RuntimeIdKind::Event, event_id.as_bytes())
                    .expect("shared durable identity rejects the all-zero event id"),
                event_seq,
            },
        }
    }

    pub(crate) fn transfer_id(self) -> TransferId {
        self.shared.transfer_id()
    }

    pub(crate) fn message_id(self) -> MessageId {
        self.shared.message_id()
    }

    pub(crate) fn part_count(self) -> Result<u32, DurableStreamTransferIdentityError> {
        Ok(self.shared.part_count())
    }

    pub(crate) fn carrier_for_part(
        self,
        payload: &[u8],
        part_index: u32,
    ) -> Result<RuntimeTransferCarrierV1, DurableStreamTransferIdentityError> {
        if u64::try_from(payload.len()).ok() != Some(self.shared.total_bytes())
            || Sha256::digest(payload).as_slice() != self.shared.total_sha256()
        {
            return Err(DurableStreamTransferIdentityError::SourceMismatch);
        }
        let part_count = self.part_count()?;
        if part_index >= part_count {
            return Err(DurableStreamTransferIdentityError::InvalidPart);
        }
        let start = usize::try_from(part_index)
            .ok()
            .and_then(|index| index.checked_mul(MAX_PART_BYTES))
            .ok_or(DurableStreamTransferIdentityError::InvalidPart)?;
        let end = start.saturating_add(MAX_PART_BYTES).min(payload.len());
        let part = if start < payload.len() {
            payload[start..end].to_vec()
        } else {
            Vec::new()
        };
        let transfer = TransferEnvelope::new(
            self.transfer_id(),
            part_index,
            part_count,
            self.shared.total_sha256(),
            self.shared.total_bytes(),
            part,
        )
        .map_err(|_| DurableStreamTransferIdentityError::InvalidPart)?;
        Ok(RuntimeTransferCarrierV1::new(
            self.message_id(),
            RuntimeTransferChannel::Stream,
            transfer,
        ))
    }

    pub(crate) fn validates_carrier(self, carrier: &RuntimeTransferCarrierV1) -> bool {
        self.shared.validate_carrier(carrier).is_ok()
    }

    pub(crate) fn publication_id(
        self,
        carrier: &RuntimeTransferCarrierV1,
    ) -> Result<[u8; 16], DurableStreamTransferIdentityError> {
        if !self.validates_carrier(carrier) {
            return Err(DurableStreamTransferIdentityError::InvalidPart);
        }
        let encoded = carrier
            .encode()
            .map_err(|_| DurableStreamTransferIdentityError::InvalidPart)?;
        let transfer_id = self.transfer_id();
        let transfer_id_len = u64::try_from(transfer_id.as_str().len())
            .map_err(|_| DurableStreamTransferIdentityError::TooLarge)?;
        let encoded_len = u64::try_from(encoded.len())
            .map_err(|_| DurableStreamTransferIdentityError::TooLarge)?;
        let mut hasher = Sha256::new();
        hasher.update(PUBLICATION_ID_DOMAIN);
        hasher.update(transfer_id_len.to_be_bytes());
        hasher.update(transfer_id.as_str().as_bytes());
        hasher.update(encoded_len.to_be_bytes());
        hasher.update(&encoded);
        let digest: [u8; 32] = hasher.finalize().into();
        let mut publication_id = [0_u8; 16];
        publication_id.copy_from_slice(&digest[..16]);
        publication_id[0] |= 0x80;
        Ok(publication_id)
    }
}

fn map_protocol_identity_error(
    error: ProtocolDurableStreamTransferIdentityError,
) -> DurableStreamTransferIdentityError {
    match error {
        ProtocolDurableStreamTransferIdentityError::InvalidSource => {
            DurableStreamTransferIdentityError::InvalidSource
        }
        ProtocolDurableStreamTransferIdentityError::InvalidIdentity => {
            DurableStreamTransferIdentityError::InvalidIdentity
        }
        ProtocolDurableStreamTransferIdentityError::TooLarge => {
            DurableStreamTransferIdentityError::TooLarge
        }
        ProtocolDurableStreamTransferIdentityError::MetadataMismatch => {
            DurableStreamTransferIdentityError::InvalidPart
        }
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) struct DurableReplyTransferIdentity {
    transfer_id: [u8; 32],
}

impl DurableReplyTransferIdentity {
    pub(crate) fn for_reply(
        request_message_id: &MessageId,
        reply: &RuntimeReply,
        payload: &[u8],
    ) -> Result<Self, DurableStreamTransferIdentityError> {
        if !request_message_id.is_valid_wire_value()
            || u64::try_from(payload.len())
                .ok()
                .is_none_or(|len| len > MAX_TRANSFER_BYTES)
        {
            return Err(DurableStreamTransferIdentityError::TooLarge);
        }
        let mut material = Vec::new();
        material.extend_from_slice(REPLY_TRANSFER_ID_DOMAIN);
        append_bounded(&mut material, request_message_id.as_str().as_bytes())?;
        match reply {
            RuntimeReply::Catalog(snapshot) => {
                material.push(1);
                append_cursor(&mut material, snapshot.base_catalog_cursor);
            }
            RuntimeReply::Snapshot(snapshot) => {
                material.push(2);
                let conversation = RuntimeId::parse_canonical(
                    RuntimeIdKind::Conversation,
                    snapshot.conversation_id.as_str(),
                )
                .map_err(|_| DurableStreamTransferIdentityError::InvalidSource)?;
                material.extend_from_slice(conversation.as_bytes());
                append_cursor(&mut material, snapshot.base_event_cursor);
            }
            RuntimeReply::Backfill(chunk) => {
                material.push(3);
                match chunk {
                    agentdeck_protocol::runtime::BackfillChunk::Catalog { range, .. } => {
                        material.push(1);
                        append_cursor(&mut material, range.after());
                        append_cursor(&mut material, range.through());
                    }
                    agentdeck_protocol::runtime::BackfillChunk::Conversation {
                        conversation_id,
                        range,
                        ..
                    } => {
                        material.push(2);
                        let conversation = RuntimeId::parse_canonical(
                            RuntimeIdKind::Conversation,
                            conversation_id.as_str(),
                        )
                        .map_err(|_| DurableStreamTransferIdentityError::InvalidSource)?;
                        material.extend_from_slice(conversation.as_bytes());
                        append_cursor(&mut material, range.after());
                        append_cursor(&mut material, range.through());
                    }
                }
            }
            _ => return Err(DurableStreamTransferIdentityError::InvalidSource),
        }
        let total_bytes = u64::try_from(payload.len())
            .map_err(|_| DurableStreamTransferIdentityError::TooLarge)?;
        material.extend_from_slice(&total_bytes.to_be_bytes());
        material.extend_from_slice(&Sha256::digest(payload));
        Ok(Self {
            transfer_id: Sha256::digest(material).into(),
        })
    }

    pub(crate) fn transfer_id(self) -> TransferId {
        let mut value = String::with_capacity(REPLY_TRANSFER_ID_PREFIX.len() + 64);
        value.push_str(REPLY_TRANSFER_ID_PREFIX);
        append_hex(&mut value, &self.transfer_id);
        TransferId::new(value)
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq, thiserror::Error)]
pub(crate) enum DurableStreamTransferIdentityError {
    #[error("durable Stream transfer source is invalid")]
    InvalidSource,
    #[error("durable Stream transfer identity is invalid")]
    InvalidIdentity,
    #[error("durable Stream transfer exceeds its hard limit")]
    TooLarge,
    #[error("durable Stream transfer source bytes do not match its identity")]
    SourceMismatch,
    #[error("durable Stream transfer part is invalid")]
    InvalidPart,
}

fn append_hex(output: &mut String, bytes: &[u8]) {
    for byte in bytes {
        write!(output, "{byte:02x}").expect("writing to String cannot fail");
    }
}

fn append_bounded(
    output: &mut Vec<u8>,
    value: &[u8],
) -> Result<(), DurableStreamTransferIdentityError> {
    let len =
        u64::try_from(value.len()).map_err(|_| DurableStreamTransferIdentityError::TooLarge)?;
    output.extend_from_slice(&len.to_be_bytes());
    output.extend_from_slice(value);
    Ok(())
}

fn append_cursor(output: &mut Vec<u8>, cursor: StreamCursor) {
    match cursor.high_water() {
        None => output.push(0),
        Some(value) => {
            output.push(1);
            output.extend_from_slice(&value.to_be_bytes());
        }
    }
}

#[cfg(test)]
mod tests {
    use agentdeck_protocol::runtime::{BackfillChunk, BackfillRange, CatalogDelta};

    use super::*;

    #[test]
    fn explicit_catalog_revision_is_not_inferred_from_change_count() {
        let item = RuntimeStreamItem::CatalogDelta(CatalogDelta {
            catalog_revision: 9,
            changes: Vec::new(),
        });
        let RuntimeStreamItem::CatalogDelta(delta) = &item else {
            unreachable!("catalog fixture")
        };
        let payload = serde_json::to_vec(delta).expect("encode catalog delta");
        let one_revision = DurableStreamTransferIdentity::for_stream_source(
            DurableStreamSource::Catalog {
                first_revision: 9,
                through_revision: 9,
            },
            &item,
            &payload,
        )
        .expect("explicit one-revision source");
        let explicit_range = DurableStreamTransferIdentity::for_stream_source(
            DurableStreamSource::Catalog {
                first_revision: 7,
                through_revision: 9,
            },
            &item,
            &payload,
        )
        .expect("explicit authenticated range remains distinct");
        assert_ne!(one_revision.transfer_id(), explicit_range.transfer_id());
    }

    #[test]
    fn reply_transfer_id_is_stable_and_binds_request_cursor_hash_and_bytes() {
        let range = BackfillRange::new(StreamCursor::BeforeFirst, StreamCursor::At(0))
            .expect("one-entry range");
        let chunk = BackfillChunk::catalog(
            range,
            vec![CatalogDelta {
                catalog_revision: 0,
                changes: Vec::new(),
            }],
        )
        .expect("canonical catalog backfill");
        let reply = RuntimeReply::Backfill(chunk);
        let payload = serde_json::to_vec(&reply).expect("encode reply fixture");
        let message = MessageId::new("authenticated-request-message");
        let first = DurableReplyTransferIdentity::for_reply(&message, &reply, &payload)
            .expect("derive durable reply transfer");
        let repeated = DurableReplyTransferIdentity::for_reply(&message, &reply, &payload)
            .expect("repeat durable reply transfer");
        assert_eq!(first.transfer_id(), repeated.transfer_id());

        let changed_message = DurableReplyTransferIdentity::for_reply(
            &MessageId::new("another-authenticated-request"),
            &reply,
            &payload,
        )
        .expect("changed request binding");
        let mut changed_payload = payload.clone();
        changed_payload.push(b' ');
        let changed_bytes =
            DurableReplyTransferIdentity::for_reply(&message, &reply, &changed_payload)
                .expect("changed payload binding");
        assert_ne!(first.transfer_id(), changed_message.transfer_id());
        assert_ne!(first.transfer_id(), changed_bytes.transfer_id());
    }
}
