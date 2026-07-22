//! Shared Runtime stream/transfer 到 durable publication identity 的纯规范化。

use std::fmt::Write as _;
use std::sync::Arc;

use agentdeck_crypto::sha256;
use agentdeck_protocol::e2ee::{OuterFrameKind, SealedPayloadKind};
use agentdeck_protocol::runtime::identity::MessageId;
use agentdeck_protocol::runtime::{
    MAX_RUNTIME_JSON_FRAME_BYTES, RUNTIME_PROTOCOL_VERSION, RuntimeEnvelope, RuntimeMessage,
    RuntimeStreamItem, RuntimeTransferCarrierV1,
};

use crate::runtime::store::identity::{RuntimeId, RuntimeIdKind};
use crate::runtime::store::publication::SharedJournalIdentity;
use crate::runtime::store::{PublicationPayloadKind, PublicationScope};
use crate::runtime::transfer_identity::{DurableStreamSource, DurableStreamTransferIdentity};

use super::SharedPublisherError;

const SHARED_PUBLICATION_ID_DOMAIN: &[u8] = b"AgentDeck/SharedPublicationIdV1\0";
pub(super) const STABLE_MESSAGE_ID_PREFIX: &str = "remote-publication-";

/// 进入 Store backend 的 canonical 请求。payload bytes 已排除 caller 的随机
/// `RuntimeEnvelope.messageId`，相同 durable item 在所有 connection 上逐字节一致。
#[derive(Clone, Debug, Eq, PartialEq)]
pub(crate) struct CanonicalSharedPublication {
    pub(super) publication_id: [u8; 16],
    pub(super) scope: PublicationScope,
    pub(super) inner_after: Option<u64>,
    pub(super) inner_through: Option<u64>,
    pub(super) payload_kind: PublicationPayloadKind,
    pub(super) sealed_payload_kind: SealedPayloadKind,
    pub(super) frame_kind: OuterFrameKind,
    pub(super) journal_identity: SharedJournalIdentity,
    pub(super) canonical_item_bytes: Arc<[u8]>,
    pub(super) canonical_runtime_sha256: [u8; 32],
    pub(super) canonical_runtime_bytes: Arc<[u8]>,
}

impl CanonicalSharedPublication {
    pub(super) fn parse(runtime_bytes: Arc<[u8]>) -> Result<Self, SharedPublisherError> {
        if runtime_bytes.len() >= MAX_RUNTIME_JSON_FRAME_BYTES {
            return Err(SharedPublisherError::InvalidRuntimeEnvelope);
        }
        let envelope: RuntimeEnvelope = serde_json::from_slice(runtime_bytes.as_ref())
            .map_err(|_| SharedPublisherError::InvalidRuntimeEnvelope)?;
        let RuntimeMessage::Stream(item) = envelope.body else {
            return Err(SharedPublisherError::NotSharedStreamItem);
        };

        let (
            scope,
            inner_after,
            inner_through,
            payload_kind,
            sealed_payload_kind,
            frame_kind,
            durable_id,
            journal_identity,
        ) = match &item {
            RuntimeStreamItem::CatalogDelta(delta) => {
                // 一条 CatalogDelta 对应 authenticated journal 的一个 revision；一个
                // revision 可以合法包含多个 changes，绝不能由展示行数反推 range。
                (
                    PublicationScope::Catalog,
                    delta.catalog_revision.checked_sub(1),
                    Some(delta.catalog_revision),
                    PublicationPayloadKind::Catalog,
                    SealedPayloadKind::CatalogDelta,
                    OuterFrameKind::CatalogPublish,
                    DurableIdentity::Catalog(delta.catalog_revision),
                    SharedJournalIdentity::CatalogRange,
                )
            }
            RuntimeStreamItem::Event(event) => {
                if event.event_id.as_str().is_empty() {
                    return Err(SharedPublisherError::InvalidDurableIdentity);
                }
                let conversation = RuntimeId::parse_canonical(
                    RuntimeIdKind::Conversation,
                    event.conversation_id.as_str(),
                )
                .map_err(|_| SharedPublisherError::InvalidDurableIdentity)?;
                let event_id =
                    RuntimeId::parse_canonical(RuntimeIdKind::Event, event.event_id.as_str())
                        .map_err(|_| SharedPublisherError::InvalidDurableIdentity)?;
                (
                    PublicationScope::Conversation(conversation),
                    event.event_seq.checked_sub(1),
                    Some(event.event_seq),
                    PublicationPayloadKind::Event,
                    SealedPayloadKind::ConversationEvent,
                    OuterFrameKind::ConversationPublish,
                    DurableIdentity::Conversation {
                        conversation,
                        event_seq: event.event_seq,
                        event_id: event.event_id.as_str(),
                    },
                    SharedJournalIdentity::Event { event_id },
                )
            }
            RuntimeStreamItem::PairingPending(_) => {
                return Err(SharedPublisherError::PairingPendingIsLocalOnly);
            }
            RuntimeStreamItem::TransferPart(_) => {
                return Err(SharedPublisherError::TransferRequiresDurableAssembler);
            }
        };

        let canonical_item =
            serde_json::to_vec(&item).map_err(|_| SharedPublisherError::CanonicalEncodingFailed)?;
        let digest = publication_digest(scope, durable_id, &canonical_item)?;
        let mut publication_id = [0_u8; 16];
        publication_id.copy_from_slice(&digest[..16]);
        // Store IDs prohibit all-zero. Setting one fixed domain bit retains deterministic
        // 127-bit collision resistance without a random fallback.
        publication_id[0] |= 0x80;

        let stable_envelope = RuntimeEnvelope {
            version: RUNTIME_PROTOCOL_VERSION,
            message_id: stable_message_id(digest),
            body: RuntimeMessage::Stream(item),
        };
        let canonical_runtime_bytes = stable_envelope
            .to_json_bytes_checked()
            .map_err(|_| SharedPublisherError::CanonicalEncodingFailed)?;
        let canonical_runtime_sha256 = sha256(&canonical_runtime_bytes);
        Ok(Self {
            publication_id,
            scope,
            inner_after,
            inner_through,
            payload_kind,
            sealed_payload_kind,
            frame_kind,
            journal_identity,
            canonical_item_bytes: Arc::from(canonical_item),
            canonical_runtime_sha256,
            canonical_runtime_bytes: Arc::from(canonical_runtime_bytes),
        })
    }

    pub(super) fn parse_transfer(
        carrier: RuntimeTransferCarrierV1,
    ) -> Result<Self, SharedPublisherError> {
        let identity =
            DurableStreamTransferIdentity::parse_transfer_id(&carrier.transfer.transfer_id)
                .map_err(|_| SharedPublisherError::InvalidDurableIdentity)?;
        if !identity.validates_carrier(&carrier) {
            return Err(SharedPublisherError::InvalidDurableIdentity);
        }
        let final_part = carrier
            .transfer
            .part_index
            .checked_add(1)
            .is_some_and(|next| next == carrier.transfer.part_count);
        let (scope, source_after, source_through, final_payload_kind, frame_kind) =
            match identity.source {
                DurableStreamSource::Catalog {
                    first_revision,
                    through_revision,
                } => (
                    PublicationScope::Catalog,
                    first_revision.checked_sub(1),
                    through_revision,
                    PublicationPayloadKind::Catalog,
                    OuterFrameKind::CatalogPublish,
                ),
                DurableStreamSource::Event {
                    conversation_id,
                    event_seq,
                    ..
                } => (
                    PublicationScope::Conversation(conversation_id),
                    event_seq.checked_sub(1),
                    event_seq,
                    PublicationPayloadKind::Event,
                    OuterFrameKind::ConversationPublish,
                ),
            };
        let (inner_after, inner_through, payload_kind) = if final_part {
            (source_after, Some(source_through), final_payload_kind)
        } else {
            (None, None, PublicationPayloadKind::Control)
        };
        let canonical = carrier
            .encode()
            .map_err(|_| SharedPublisherError::CanonicalEncodingFailed)?;
        let publication_id = identity
            .publication_id(&carrier)
            .map_err(|_| SharedPublisherError::InvalidDurableIdentity)?;
        let canonical_runtime_sha256 = sha256(&canonical);
        Ok(Self {
            publication_id,
            scope,
            inner_after,
            inner_through,
            payload_kind,
            sealed_payload_kind: SealedPayloadKind::TransferPart,
            frame_kind,
            journal_identity: SharedJournalIdentity::Transfer { identity },
            canonical_item_bytes: Arc::from(canonical.clone()),
            canonical_runtime_sha256,
            canonical_runtime_bytes: Arc::from(canonical),
        })
    }
}

enum DurableIdentity<'a> {
    Catalog(u64),
    Conversation {
        conversation: RuntimeId,
        event_seq: u64,
        event_id: &'a str,
    },
}

fn publication_digest(
    scope: PublicationScope,
    durable: DurableIdentity<'_>,
    canonical_item: &[u8],
) -> Result<[u8; 32], SharedPublisherError> {
    let mut material = Vec::with_capacity(
        SHARED_PUBLICATION_ID_DOMAIN
            .len()
            .saturating_add(canonical_item.len())
            .saturating_add(128),
    );
    material.extend_from_slice(SHARED_PUBLICATION_ID_DOMAIN);
    match scope {
        PublicationScope::Catalog => material.push(1),
        PublicationScope::Conversation(conversation) => {
            material.push(2);
            material.extend_from_slice(conversation.as_bytes());
        }
    }
    match durable {
        DurableIdentity::Catalog(revision) => {
            material.push(1);
            material.extend_from_slice(&revision.to_be_bytes());
        }
        DurableIdentity::Conversation {
            conversation,
            event_seq,
            event_id,
        } => {
            material.push(2);
            material.extend_from_slice(conversation.as_bytes());
            material.extend_from_slice(&event_seq.to_be_bytes());
            append_len_prefixed(&mut material, event_id.as_bytes())?;
        }
    }
    append_len_prefixed(&mut material, canonical_item)?;
    Ok(sha256(&material))
}

fn append_len_prefixed(output: &mut Vec<u8>, value: &[u8]) -> Result<(), SharedPublisherError> {
    let len =
        u64::try_from(value.len()).map_err(|_| SharedPublisherError::CanonicalEncodingFailed)?;
    output.extend_from_slice(&len.to_be_bytes());
    output.extend_from_slice(value);
    Ok(())
}

fn stable_message_id(digest: [u8; 32]) -> MessageId {
    let mut value = String::with_capacity(STABLE_MESSAGE_ID_PREFIX.len() + 64);
    value.push_str(STABLE_MESSAGE_ID_PREFIX);
    for byte in digest {
        write!(&mut value, "{byte:02x}").expect("writing to String cannot fail");
    }
    MessageId::new(value)
}
