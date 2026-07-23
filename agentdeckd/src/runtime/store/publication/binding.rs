//! SubscriptionBarrier 冻结的 Relay publication binding capability。
//!
//! capability 只在 daemon 内流转：Store 从同一个 authenticated publication row、
//! committed cut 与 shared-key directory 捕获全部轴；RemoteLink 最终定向 seal 前，
//! Safety transaction 必须再次精确认证这些轴。Runtime DTO 中的本地 subscription
//! generation 不参与此 capability。

use agentdeck_protocol::e2ee::{E2EE_FORMAT_VERSION, KeyId, StreamBindingV1};
use agentdeck_protocol::relay_v2::{
    DeviceRouteId, GrantSerial, KeyDirectoryRevision, MachineRouteId, RELAY_PROTOCOL_VERSION,
    StreamGenerationId, StreamRouteId, TrustEpoch,
};
use agentdeck_protocol::runtime::identity::ConversationId;
use agentdeck_protocol::runtime::{
    RUNTIME_PROTOCOL_VERSION, RuntimeInnerCursor, RuntimeSyncComplete, StreamCursor,
};
use rusqlite::Transaction;

#[cfg(test)]
use crate::runtime::events::RuntimeStreamTarget;

use super::*;

/// Store-issued、daemon-private 的 exact publication cut capability。
///
/// 字段不公开，production constructor 只接受已完成全目录认证的 row。Copy 仅用于
/// `EncodedRuntimeFrame -> ConnectionWrite` 的同进程 transport metadata handoff；最终
/// seal transaction 仍会重新认证，不把该副本当作持久化真源。
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) struct StreamBindingPermit {
    scope: PublicationScope,
    publication_stream_id: [u8; 16],
    stream_route: [u8; 16],
    generation: [u8; 16],
    outer: StreamCursor,
    inner: StreamCursor,
    key_directory_revision: u64,
    key_id: KeyId,
}

impl StreamBindingPermit {
    #[must_use]
    pub(crate) const fn publication_stream_id(&self) -> [u8; 16] {
        self.publication_stream_id
    }

    #[must_use]
    pub(crate) const fn generation(&self) -> [u8; 16] {
        self.generation
    }

    #[must_use]
    pub(crate) const fn outer(&self) -> StreamCursor {
        self.outer
    }

    #[must_use]
    pub(crate) const fn inner(&self) -> StreamCursor {
        self.inner
    }

    #[must_use]
    pub(crate) const fn key_directory_revision(&self) -> u64 {
        self.key_directory_revision
    }

    #[must_use]
    pub(crate) fn inner_cursor(&self) -> RuntimeInnerCursor {
        match self.scope {
            PublicationScope::Catalog => RuntimeInnerCursor::Catalog { cursor: self.inner },
            PublicationScope::Conversation(conversation_id) => RuntimeInnerCursor::Conversation {
                conversation_id: ConversationId::new(conversation_id.to_canonical_string()),
                cursor: self.inner,
            },
        }
    }

    /// SyncComplete 是先发送的 Runtime 状态；只校验它与 permit 的 target/outer/revision
    /// 一致。普通 subscription 的 inner 可以高于 publication cut，且本地 generation
    /// 故意不参与比较。
    pub(crate) fn matches_runtime_sync(&self, sync: &RuntimeSyncComplete) -> bool {
        if sync.stream_cursor != self.outer
            || (sync.key_directory_revision != 0
                && sync.key_directory_revision != self.key_directory_revision)
        {
            return false;
        }
        match (&self.scope, &sync.inner_cursor) {
            (PublicationScope::Catalog, RuntimeInnerCursor::Catalog { cursor }) => {
                cursor_is_at_or_after(*cursor, self.inner)
            }
            (
                PublicationScope::Conversation(expected),
                RuntimeInnerCursor::Conversation {
                    conversation_id,
                    cursor,
                },
            ) => {
                conversation_id.as_str() == expected.to_canonical_string()
                    && cursor_is_at_or_after(*cursor, self.inner)
            }
            _ => false,
        }
    }

    pub(crate) fn to_protocol(
        self,
        machine_route: MachineRouteId,
        device_route: DeviceRouteId,
        grant_serial: GrantSerial,
        root_trust_epoch: TrustEpoch,
    ) -> StreamBindingV1 {
        StreamBindingV1 {
            format_version: E2EE_FORMAT_VERSION,
            runtime_protocol_version: RUNTIME_PROTOCOL_VERSION,
            relay_protocol_version: RELAY_PROTOCOL_VERSION,
            machine_route,
            device_route,
            grant_serial,
            root_trust_epoch,
            stream_route: StreamRouteId::from_bytes(self.stream_route),
            stream_generation: StreamGenerationId::from_bytes(self.generation),
            stream_cursor: self.outer,
            inner_cursor: self.inner_cursor(),
            key_directory_revision: KeyDirectoryRevision::new(self.key_directory_revision),
            key_id: self.key_id,
        }
    }

    #[cfg(test)]
    #[allow(clippy::too_many_arguments)]
    pub(crate) fn for_test(
        target: RuntimeStreamTarget,
        publication_stream_id: [u8; 16],
        stream_route: [u8; 16],
        generation: [u8; 16],
        outer: StreamCursor,
        inner: StreamCursor,
        key_directory_revision: u64,
        key_id: KeyId,
    ) -> Self {
        let scope = match target {
            RuntimeStreamTarget::Catalog => PublicationScope::Catalog,
            RuntimeStreamTarget::Conversation(conversation_id) => {
                PublicationScope::Conversation(conversation_id)
            }
        };
        Self {
            scope,
            publication_stream_id,
            stream_route,
            generation,
            outer,
            inner,
            key_directory_revision,
            key_id,
        }
    }
}

fn cursor_is_at_or_after(candidate: StreamCursor, floor: StreamCursor) -> bool {
    match (candidate.high_water(), floor.high_water()) {
        (_, None) => true,
        (Some(candidate), Some(floor)) => candidate >= floor,
        (None, Some(_)) => false,
    }
}

/// 调用方必须先通过 `authenticate_directory` 取得 `stream`。
pub(in crate::runtime::store) fn capture_stream_binding_permit(
    transaction: &Transaction<'_>,
    key_bundle: &RuntimeKeyBundle,
    database_id: [u8; 16],
    stream: &PublicationStreamRecord,
) -> Result<Option<StreamBindingPermit>, RuntimeStoreError> {
    let Some((key_directory_revision, key_id)) =
        super::shared::current_shared_key_identity(key_bundle, database_id, transaction, stream)?
    else {
        // Local-only Store 没有 remote key directory，仍可正常建立本地 subscription。
        return Ok(None);
    };
    Ok(Some(StreamBindingPermit {
        scope: stream.scope,
        publication_stream_id: stream.publication_stream_id,
        stream_route: stream.stream_route,
        generation: stream.generation,
        outer: StreamCursor::from_high_water(stream.committed_high_water),
        inner: StreamCursor::from_high_water(stream.committed_inner_cursor),
        key_directory_revision,
        key_id,
    }))
}

pub(in crate::runtime::store) fn validate_stream_binding_permit_in_transaction(
    transaction: &Transaction<'_>,
    key_bundle: &RuntimeKeyBundle,
    database_id: [u8; 16],
    permit: &StreamBindingPermit,
) -> Result<(), RuntimeStoreError> {
    let ledger = super::super::sqlite::load_runtime_ledger(transaction, key_bundle, database_id)?;
    let stream = super::authenticate_directory(transaction, key_bundle, &ledger, permit.scope)?
        .ok_or(RuntimeStoreError::PublicationMismatch)?;
    if stream.publication_stream_id != permit.publication_stream_id
        || stream.scope != permit.scope
        || stream.stream_route != permit.stream_route
        || stream.generation != permit.generation
        || StreamCursor::from_high_water(stream.committed_high_water) != permit.outer
        || StreamCursor::from_high_water(stream.committed_inner_cursor) != permit.inner
    {
        return Err(RuntimeStoreError::PublicationMismatch);
    }
    let identity =
        super::shared::current_shared_key_identity(key_bundle, database_id, transaction, &stream)?
            .ok_or(RuntimeStoreError::PublicationMismatch)?;
    if identity != (permit.key_directory_revision, permit.key_id) {
        return Err(RuntimeStoreError::PublicationMismatch);
    }
    Ok(())
}
