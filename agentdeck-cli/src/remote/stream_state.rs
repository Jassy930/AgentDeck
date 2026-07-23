//! Persistent remote live-stream 的严格本地状态编码。
//!
//! `StreamBindingV1` 原始 canonical bytes 始终保留；Relay outer applied/ACK、Runtime
//! inner applied 与 receive replay tuple 是彼此独立的轴，不能互相推导。

use std::cmp::Ordering;
use std::collections::HashSet;

use agentdeck_protocol::e2ee::{STREAM_BINDING_MAX_CANONICAL_BYTES, StreamBindingV1};
use agentdeck_protocol::runtime::{ConversationId, RuntimeInnerCursor, StreamCursor};
use thiserror::Error;

const STREAM_STATE_MAGIC: &[u8; 4] = b"ADSB";
const STREAM_STATE_VERSION: u16 = 1;
const STREAM_STATE_HEADER_LEN: usize = 12;
const MAX_CONVERSATION_ID_BYTES: usize = 1_024;
const MAX_DURABLE_STREAM_STATE_BYTES: usize = 16 * 1_024;
pub(crate) const MAX_DURABLE_STREAM_BINDINGS: usize = 4_096;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct DurableStreamReplayTupleV1 {
    stream_seq: u64,
    sender_counter: u64,
    signed_blob_sha256: [u8; 32],
}

impl DurableStreamReplayTupleV1 {
    #[must_use]
    pub const fn stream_seq(self) -> u64 {
        self.stream_seq
    }

    #[must_use]
    pub const fn sender_counter(self) -> u64 {
        self.sender_counter
    }

    #[must_use]
    pub const fn signed_blob_sha256(self) -> [u8; 32] {
        self.signed_blob_sha256
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct DurableStreamBindingV1 {
    binding: StreamBindingV1,
    outer_applied: StreamCursor,
    outer_acked: StreamCursor,
    inner_applied: RuntimeInnerCursor,
    replay_tuple: Option<DurableStreamReplayTupleV1>,
}

impl DurableStreamBindingV1 {
    pub(crate) fn from_stream_binding(
        binding: StreamBindingV1,
    ) -> Result<Self, RemoteStreamStateError> {
        let value = Self {
            outer_applied: binding.stream_cursor,
            outer_acked: binding.stream_cursor,
            inner_applied: binding.inner_cursor.clone(),
            binding,
            replay_tuple: None,
        };
        value.validate()?;
        Ok(value)
    }

    #[must_use]
    pub const fn binding(&self) -> &StreamBindingV1 {
        &self.binding
    }

    #[must_use]
    pub const fn outer_applied(&self) -> StreamCursor {
        self.outer_applied
    }

    #[must_use]
    pub const fn outer_acked(&self) -> StreamCursor {
        self.outer_acked
    }

    #[must_use]
    pub const fn inner_applied(&self) -> &RuntimeInnerCursor {
        &self.inner_applied
    }

    #[must_use]
    pub const fn replay_tuple(&self) -> Option<DurableStreamReplayTupleV1> {
        self.replay_tuple
    }

    pub fn canonical_bytes(&self) -> Result<Vec<u8>, RemoteStreamStateError> {
        self.validate()?;
        let binding = self
            .binding
            .canonical_bytes()
            .map_err(|_| RemoteStreamStateError::InvalidCanonical)?;
        let mut body = Vec::with_capacity(binding.len() + 128);
        put_bytes(&mut body, &binding)?;
        put_cursor(&mut body, self.outer_applied);
        put_cursor(&mut body, self.outer_acked);
        put_inner_cursor(&mut body, &self.inner_applied)?;
        match self.replay_tuple {
            None => body.push(0),
            Some(replay) => {
                body.push(1);
                body.extend_from_slice(&replay.stream_seq.to_be_bytes());
                body.extend_from_slice(&replay.sender_counter.to_be_bytes());
                body.extend_from_slice(&replay.signed_blob_sha256);
            }
        }
        if body.len() > MAX_DURABLE_STREAM_STATE_BYTES - STREAM_STATE_HEADER_LEN {
            return Err(RemoteStreamStateError::TooLarge);
        }
        let body_len = u32::try_from(body.len()).map_err(|_| RemoteStreamStateError::TooLarge)?;
        let mut encoded = Vec::with_capacity(STREAM_STATE_HEADER_LEN + body.len());
        encoded.extend_from_slice(STREAM_STATE_MAGIC);
        encoded.extend_from_slice(&STREAM_STATE_VERSION.to_be_bytes());
        encoded.extend_from_slice(&[0, 0]);
        encoded.extend_from_slice(&body_len.to_be_bytes());
        encoded.extend_from_slice(&body);
        Ok(encoded)
    }

    pub fn from_canonical_bytes(bytes: &[u8]) -> Result<Self, RemoteStreamStateError> {
        if bytes.len() < STREAM_STATE_HEADER_LEN
            || bytes.len() > MAX_DURABLE_STREAM_STATE_BYTES
            || &bytes[..4] != STREAM_STATE_MAGIC
            || u16::from_be_bytes([bytes[4], bytes[5]]) != STREAM_STATE_VERSION
            || bytes[6..8] != [0, 0]
        {
            return Err(RemoteStreamStateError::InvalidCanonical);
        }
        let declared = u32::from_be_bytes(
            bytes[8..12]
                .try_into()
                .map_err(|_| RemoteStreamStateError::InvalidCanonical)?,
        ) as usize;
        if declared != bytes.len() - STREAM_STATE_HEADER_LEN {
            return Err(RemoteStreamStateError::InvalidCanonical);
        }
        let mut decoder = Decoder::new(&bytes[STREAM_STATE_HEADER_LEN..]);
        let binding_bytes = decoder.bytes(STREAM_BINDING_MAX_CANONICAL_BYTES)?;
        let binding = StreamBindingV1::from_canonical_bytes(binding_bytes)
            .map_err(|_| RemoteStreamStateError::InvalidCanonical)?;
        if binding
            .canonical_bytes()
            .map_err(|_| RemoteStreamStateError::InvalidCanonical)?
            != binding_bytes
        {
            return Err(RemoteStreamStateError::InvalidCanonical);
        }
        let outer_applied = decoder.cursor()?;
        let outer_acked = decoder.cursor()?;
        let inner_applied = decoder.inner_cursor()?;
        let replay_tuple = match decoder.u8()? {
            0 => None,
            1 => Some(DurableStreamReplayTupleV1 {
                stream_seq: decoder.u64()?,
                sender_counter: decoder.u64()?,
                signed_blob_sha256: decoder.fixed()?,
            }),
            _ => return Err(RemoteStreamStateError::InvalidCanonical),
        };
        decoder.finish()?;
        let value = Self {
            binding,
            outer_applied,
            outer_acked,
            inner_applied,
            replay_tuple,
        };
        value.validate()?;
        if value.canonical_bytes()? != bytes {
            return Err(RemoteStreamStateError::InvalidCanonical);
        }
        Ok(value)
    }

    fn validate(&self) -> Result<(), RemoteStreamStateError> {
        self.binding
            .validate()
            .map_err(|_| RemoteStreamStateError::InvalidCanonical)?;
        self.outer_applied
            .checked_next()
            .map_err(|_| RemoteStreamStateError::InvalidCanonical)?;
        self.outer_acked
            .checked_next()
            .map_err(|_| RemoteStreamStateError::InvalidCanonical)?;
        inner_cursor_value(&self.inner_applied)
            .checked_next()
            .map_err(|_| RemoteStreamStateError::InvalidCanonical)?;
        if !same_target(&self.binding.inner_cursor, &self.inner_applied)
            || cursor_cmp(self.binding.stream_cursor, self.outer_acked) == Ordering::Greater
            || cursor_cmp(self.outer_acked, self.outer_applied) == Ordering::Greater
            || cursor_cmp(
                inner_cursor_value(&self.binding.inner_cursor),
                inner_cursor_value(&self.inner_applied),
            ) == Ordering::Greater
        {
            return Err(RemoteStreamStateError::InvalidCanonical);
        }
        match self.replay_tuple {
            None if self.outer_applied == self.binding.stream_cursor
                && self.inner_applied == self.binding.inner_cursor =>
            {
                Ok(())
            }
            Some(replay)
                if replay.signed_blob_sha256 != [0; 32]
                    && replay_matches_applied_or_next(self.outer_applied, replay.stream_seq)
                    && cursor_cmp(
                        self.binding.stream_cursor,
                        StreamCursor::At(replay.stream_seq),
                    ) == Ordering::Less =>
            {
                Ok(())
            }
            _ => Err(RemoteStreamStateError::InvalidCanonical),
        }
    }

    pub(crate) fn target_key(&self) -> DurableStreamTargetKey {
        target_key(&self.binding.inner_cursor)
    }
}

#[derive(Clone, Debug, Eq, Ord, PartialEq, PartialOrd)]
pub(crate) enum DurableStreamTargetKey {
    Catalog,
    Conversation(String),
}

pub(crate) fn decode_stream_bindings(
    entries: &[Vec<u8>],
) -> Result<Vec<DurableStreamBindingV1>, RemoteStreamStateError> {
    if entries.len() > MAX_DURABLE_STREAM_BINDINGS {
        return Err(RemoteStreamStateError::TooLarge);
    }
    let mut states = Vec::with_capacity(entries.len());
    let mut previous = None;
    let mut routes = HashSet::with_capacity(entries.len());
    for entry in entries {
        let state = DurableStreamBindingV1::from_canonical_bytes(entry)?;
        let key = state.target_key();
        if previous.as_ref().is_some_and(|previous| previous >= &key)
            || !routes.insert(*state.binding.stream_route.as_bytes())
        {
            return Err(RemoteStreamStateError::InvalidCanonical);
        }
        previous = Some(key);
        states.push(state);
    }
    Ok(states)
}

pub(crate) fn encode_stream_bindings(
    mut states: Vec<DurableStreamBindingV1>,
) -> Result<Vec<Vec<u8>>, RemoteStreamStateError> {
    if states.len() > MAX_DURABLE_STREAM_BINDINGS {
        return Err(RemoteStreamStateError::TooLarge);
    }
    states.sort_by_key(DurableStreamBindingV1::target_key);
    let mut encoded = Vec::with_capacity(states.len());
    let mut previous = None;
    let mut routes = HashSet::with_capacity(states.len());
    for state in states {
        let key = state.target_key();
        if previous.as_ref().is_some_and(|previous| previous >= &key)
            || !routes.insert(*state.binding.stream_route.as_bytes())
        {
            return Err(RemoteStreamStateError::InvalidCanonical);
        }
        previous = Some(key);
        encoded.push(state.canonical_bytes()?);
    }
    Ok(encoded)
}

#[derive(Debug, Error, Eq, PartialEq)]
pub enum RemoteStreamStateError {
    #[error("durable stream state has an invalid canonical encoding")]
    InvalidCanonical,
    #[error("durable stream state exceeds its hard bound")]
    TooLarge,
}

impl RemoteStreamStateError {
    #[must_use]
    pub const fn code(&self) -> &'static str {
        match self {
            Self::InvalidCanonical => "remote.stream_state.invalid",
            Self::TooLarge => "remote.stream_state.too_large",
        }
    }
}

fn target_key(cursor: &RuntimeInnerCursor) -> DurableStreamTargetKey {
    match cursor {
        RuntimeInnerCursor::Catalog { .. } => DurableStreamTargetKey::Catalog,
        RuntimeInnerCursor::Conversation {
            conversation_id, ..
        } => DurableStreamTargetKey::Conversation(conversation_id.as_str().to_owned()),
    }
}

fn same_target(left: &RuntimeInnerCursor, right: &RuntimeInnerCursor) -> bool {
    match (left, right) {
        (RuntimeInnerCursor::Catalog { .. }, RuntimeInnerCursor::Catalog { .. }) => true,
        (
            RuntimeInnerCursor::Conversation {
                conversation_id: left,
                ..
            },
            RuntimeInnerCursor::Conversation {
                conversation_id: right,
                ..
            },
        ) => left == right,
        _ => false,
    }
}

fn inner_cursor_value(cursor: &RuntimeInnerCursor) -> StreamCursor {
    match cursor {
        RuntimeInnerCursor::Catalog { cursor }
        | RuntimeInnerCursor::Conversation { cursor, .. } => *cursor,
    }
}

fn cursor_cmp(left: StreamCursor, right: StreamCursor) -> Ordering {
    match (left, right) {
        (StreamCursor::BeforeFirst, StreamCursor::BeforeFirst) => Ordering::Equal,
        (StreamCursor::BeforeFirst, StreamCursor::At(_)) => Ordering::Less,
        (StreamCursor::At(_), StreamCursor::BeforeFirst) => Ordering::Greater,
        (StreamCursor::At(left), StreamCursor::At(right)) => left.cmp(&right),
    }
}

fn replay_matches_applied_or_next(outer_applied: StreamCursor, replay_seq: u64) -> bool {
    outer_applied == StreamCursor::At(replay_seq)
        || outer_applied
            .checked_next()
            .is_ok_and(|next| next == replay_seq)
}

fn put_bytes(output: &mut Vec<u8>, bytes: &[u8]) -> Result<(), RemoteStreamStateError> {
    let length = u32::try_from(bytes.len()).map_err(|_| RemoteStreamStateError::TooLarge)?;
    output.extend_from_slice(&length.to_be_bytes());
    output.extend_from_slice(bytes);
    Ok(())
}

fn put_cursor(output: &mut Vec<u8>, cursor: StreamCursor) {
    match cursor {
        StreamCursor::BeforeFirst => {
            output.push(0);
            output.extend_from_slice(&0_u64.to_be_bytes());
        }
        StreamCursor::At(value) => {
            output.push(1);
            output.extend_from_slice(&value.to_be_bytes());
        }
    }
}

fn put_inner_cursor(
    output: &mut Vec<u8>,
    cursor: &RuntimeInnerCursor,
) -> Result<(), RemoteStreamStateError> {
    match cursor {
        RuntimeInnerCursor::Catalog { cursor } => {
            output.push(0);
            put_cursor(output, *cursor);
        }
        RuntimeInnerCursor::Conversation {
            conversation_id,
            cursor,
        } => {
            output.push(1);
            let identity = conversation_id.as_str().as_bytes();
            if identity.is_empty() || identity.len() > MAX_CONVERSATION_ID_BYTES {
                return Err(RemoteStreamStateError::InvalidCanonical);
            }
            put_bytes(output, identity)?;
            put_cursor(output, *cursor);
        }
    }
    Ok(())
}

struct Decoder<'a> {
    bytes: &'a [u8],
    cursor: usize,
}

impl<'a> Decoder<'a> {
    const fn new(bytes: &'a [u8]) -> Self {
        Self { bytes, cursor: 0 }
    }

    fn take(&mut self, length: usize) -> Result<&'a [u8], RemoteStreamStateError> {
        let end = self
            .cursor
            .checked_add(length)
            .ok_or(RemoteStreamStateError::InvalidCanonical)?;
        let value = self
            .bytes
            .get(self.cursor..end)
            .ok_or(RemoteStreamStateError::InvalidCanonical)?;
        self.cursor = end;
        Ok(value)
    }

    fn u8(&mut self) -> Result<u8, RemoteStreamStateError> {
        self.take(1)?
            .first()
            .copied()
            .ok_or(RemoteStreamStateError::InvalidCanonical)
    }

    fn u32(&mut self) -> Result<u32, RemoteStreamStateError> {
        Ok(u32::from_be_bytes(
            self.take(4)?
                .try_into()
                .map_err(|_| RemoteStreamStateError::InvalidCanonical)?,
        ))
    }

    fn u64(&mut self) -> Result<u64, RemoteStreamStateError> {
        Ok(u64::from_be_bytes(
            self.take(8)?
                .try_into()
                .map_err(|_| RemoteStreamStateError::InvalidCanonical)?,
        ))
    }

    fn fixed<const N: usize>(&mut self) -> Result<[u8; N], RemoteStreamStateError> {
        self.take(N)?
            .try_into()
            .map_err(|_| RemoteStreamStateError::InvalidCanonical)
    }

    fn bytes(&mut self, maximum: usize) -> Result<&'a [u8], RemoteStreamStateError> {
        let length =
            usize::try_from(self.u32()?).map_err(|_| RemoteStreamStateError::InvalidCanonical)?;
        if length == 0 || length > maximum {
            return Err(RemoteStreamStateError::InvalidCanonical);
        }
        self.take(length)
    }

    fn cursor(&mut self) -> Result<StreamCursor, RemoteStreamStateError> {
        let tag = self.u8()?;
        let value = self.u64()?;
        match (tag, value) {
            (0, 0) => Ok(StreamCursor::BeforeFirst),
            (1, value) => Ok(StreamCursor::At(value)),
            _ => Err(RemoteStreamStateError::InvalidCanonical),
        }
    }

    fn inner_cursor(&mut self) -> Result<RuntimeInnerCursor, RemoteStreamStateError> {
        match self.u8()? {
            0 => Ok(RuntimeInnerCursor::Catalog {
                cursor: self.cursor()?,
            }),
            1 => {
                let bytes = self.bytes(MAX_CONVERSATION_ID_BYTES)?;
                let identity = std::str::from_utf8(bytes)
                    .map_err(|_| RemoteStreamStateError::InvalidCanonical)?;
                Ok(RuntimeInnerCursor::Conversation {
                    conversation_id: ConversationId::new(identity),
                    cursor: self.cursor()?,
                })
            }
            _ => Err(RemoteStreamStateError::InvalidCanonical),
        }
    }

    fn finish(self) -> Result<(), RemoteStreamStateError> {
        if self.cursor == self.bytes.len() {
            Ok(())
        } else {
            Err(RemoteStreamStateError::InvalidCanonical)
        }
    }
}

#[cfg(test)]
mod tests {
    use agentdeck_protocol::e2ee::{E2EE_FORMAT_VERSION, KeyId, KeyPurpose};
    use agentdeck_protocol::relay_v2::{
        DeviceRouteId, GrantSerial, KeyDirectoryRevision, MachineRouteId, RELAY_PROTOCOL_VERSION,
        StreamGenerationId, StreamRouteId, TrustEpoch,
    };
    use agentdeck_protocol::runtime::RUNTIME_PROTOCOL_VERSION;

    use super::*;

    fn binding(
        route: StreamRouteId,
        generation: u8,
        target: RuntimeInnerCursor,
    ) -> StreamBindingV1 {
        let purpose = match &target {
            RuntimeInnerCursor::Catalog { .. } => KeyPurpose::Catalog,
            RuntimeInnerCursor::Conversation { .. } => KeyPurpose::ConversationDek,
        };
        StreamBindingV1 {
            format_version: E2EE_FORMAT_VERSION,
            runtime_protocol_version: RUNTIME_PROTOCOL_VERSION,
            relay_protocol_version: RELAY_PROTOCOL_VERSION,
            machine_route: MachineRouteId::from_bytes([0x11; 16]),
            device_route: DeviceRouteId::from_bytes([0x12; 16]),
            grant_serial: GrantSerial::new(7),
            root_trust_epoch: TrustEpoch::new(2),
            stream_route: route,
            stream_generation: StreamGenerationId::from_bytes([generation; 16]),
            stream_cursor: StreamCursor::BeforeFirst,
            inner_cursor: target,
            key_directory_revision: KeyDirectoryRevision::new(4),
            key_id: KeyId { purpose, epoch: 3 },
        }
    }

    fn catalog(route: u8) -> DurableStreamBindingV1 {
        DurableStreamBindingV1::from_stream_binding(binding(
            StreamRouteId::from_bytes([route; 16]),
            route.wrapping_add(0x10),
            RuntimeInnerCursor::Catalog {
                cursor: StreamCursor::BeforeFirst,
            },
        ))
        .unwrap()
    }

    fn conversation(route: u8, id: &str) -> DurableStreamBindingV1 {
        DurableStreamBindingV1::from_stream_binding(binding(
            StreamRouteId::from_bytes([route; 16]),
            route.wrapping_add(0x20),
            RuntimeInnerCursor::Conversation {
                conversation_id: ConversationId::new(id),
                cursor: StreamCursor::BeforeFirst,
            },
        ))
        .unwrap()
    }

    #[test]
    fn replay_admission_is_independent_from_outer_apply_and_ack() {
        let initial = catalog(0x31);
        let pending = DurableStreamBindingV1 {
            replay_tuple: Some(DurableStreamReplayTupleV1 {
                stream_seq: 0,
                sender_counter: 0,
                signed_blob_sha256: [0x41; 32],
            }),
            ..initial.clone()
        };
        let canonical = pending.canonical_bytes().expect("durable pre-apply replay");
        assert_eq!(
            DurableStreamBindingV1::from_canonical_bytes(&canonical).unwrap(),
            pending
        );

        let applied = DurableStreamBindingV1 {
            outer_applied: StreamCursor::At(0),
            ..pending.clone()
        };
        applied
            .canonical_bytes()
            .expect("same replay tuple remains valid after apply");

        let skipped = DurableStreamBindingV1 {
            replay_tuple: Some(DurableStreamReplayTupleV1 {
                stream_seq: 1,
                sender_counter: 0,
                signed_blob_sha256: [0x42; 32],
            }),
            ..initial
        };
        assert_eq!(
            skipped.canonical_bytes().unwrap_err(),
            RemoteStreamStateError::InvalidCanonical
        );
    }

    #[test]
    fn collection_rejects_duplicate_targets_routes_and_noncanonical_order() {
        let catalog_state = catalog(0x51);
        let first = conversation(0x52, "conversation-a");
        let second = conversation(0x53, "conversation-b");
        let canonical =
            encode_stream_bindings(vec![second.clone(), catalog_state.clone(), first.clone()])
                .expect("encoder sorts unique targets");
        decode_stream_bindings(&canonical).expect("canonical sorted collection");

        assert_eq!(
            encode_stream_bindings(vec![first.clone(), conversation(0x54, "conversation-a")])
                .unwrap_err(),
            RemoteStreamStateError::InvalidCanonical
        );
        assert_eq!(
            encode_stream_bindings(vec![first.clone(), conversation(0x52, "conversation-b")])
                .unwrap_err(),
            RemoteStreamStateError::InvalidCanonical
        );
        assert_eq!(
            encode_stream_bindings(vec![catalog(0x52), first]).unwrap_err(),
            RemoteStreamStateError::InvalidCanonical
        );

        let mut reversed = canonical;
        reversed.swap(0, 1);
        assert_eq!(
            decode_stream_bindings(&reversed).unwrap_err(),
            RemoteStreamStateError::InvalidCanonical
        );
    }

    #[test]
    fn canonical_decoder_rejects_reserved_trailing_and_noncanonical_cursor_bytes() {
        let canonical = catalog(0x61).canonical_bytes().unwrap();
        for mutated in [
            {
                let mut value = canonical.clone();
                value[6] = 1;
                value
            },
            {
                let mut value = canonical.clone();
                value.push(0);
                let body_len = u32::from_be_bytes(value[8..12].try_into().unwrap()) + 1;
                value[8..12].copy_from_slice(&body_len.to_be_bytes());
                value
            },
            {
                let mut value = canonical.clone();
                let binding_len = u32::from_be_bytes(value[12..16].try_into().unwrap()) as usize;
                let outer_cursor_value = 16 + binding_len + 1;
                value[outer_cursor_value + 7] = 1;
                value
            },
        ] {
            assert_eq!(
                DurableStreamBindingV1::from_canonical_bytes(&mutated).unwrap_err(),
                RemoteStreamStateError::InvalidCanonical
            );
        }
    }
}
