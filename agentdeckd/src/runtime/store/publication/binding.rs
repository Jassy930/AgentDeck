//! SubscriptionBarrier 冻结的 Relay publication binding capability。
//!
//! capability 只在 daemon 内流转：Store 从同一个 authenticated publication row、
//! committed cut 与 shared-key directory 捕获全部轴；RemoteLink 最终定向 seal 前，
//! Safety transaction 必须再次精确认证这些轴。Runtime DTO 中的本地 subscription
//! generation 不参与此 capability。

use agentdeck_protocol::e2ee::{E2EE_FORMAT_VERSION, KeyId, KeyPurpose, StreamBindingV1};
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

#[derive(Clone, Debug, Eq, PartialEq)]
enum StreamBindingProvenance {
    /// 普通 SubscriptionBarrier 必须始终绑定 transaction 当下的 exact current row。
    Current,
    /// 新设备 transition snapshot 的 wire cut 是 barrier 前的 `C/H`；当前 row 必须
    /// 已精确提交为 `next(C)/H`，且 active Add transition 仍绑定同一目标与新 epoch。
    Transition(Box<super::super::key_transition::TransitionStreamBindingProvenance>),
}

/// Store-issued、daemon-private 的 exact publication cut capability。
///
/// 字段不公开，production constructor 只接受已完成全目录认证的 row。Clone 仅用于
/// `EncodedRuntimeFrame -> ConnectionWrite` 的同进程 transport metadata handoff；最终
/// seal transaction 仍会重新认证，不把该副本当作持久化真源。较大的 transition
/// provenance 单独装箱，避免让所有普通 ConnectionWrite 膨胀。
#[derive(Clone, Debug, Eq, PartialEq)]
pub(crate) struct StreamBindingPermit {
    scope: PublicationScope,
    publication_stream_id: [u8; 16],
    stream_route: [u8; 16],
    generation: [u8; 16],
    outer: StreamCursor,
    inner: StreamCursor,
    key_directory_revision: u64,
    key_id: KeyId,
    provenance: StreamBindingProvenance,
}

impl StreamBindingPermit {
    #[cfg(test)]
    #[must_use]
    pub(crate) const fn generation(&self) -> [u8; 16] {
        self.generation
    }

    #[cfg(test)]
    #[must_use]
    pub(crate) const fn outer(&self) -> StreamCursor {
        self.outer
    }

    #[cfg(test)]
    #[must_use]
    pub(crate) const fn inner(&self) -> StreamCursor {
        self.inner
    }

    #[must_use]
    pub(crate) const fn key_directory_revision(&self) -> u64 {
        self.key_directory_revision
    }

    pub(crate) fn matches_reply_authorization(
        &self,
        authorization: &super::super::pairing_authorization::RemoteReplyAuthorization,
    ) -> bool {
        match &self.provenance {
            StreamBindingProvenance::Current => true,
            StreamBindingProvenance::Transition(provenance) => {
                provenance.recipient.device_route == *authorization.device_route().as_bytes()
                    && provenance.recipient.grant_serial == authorization.grant_serial().value()
                    && provenance.authorization_hash == authorization.authorization_hash()
                    && self.key_directory_revision == authorization.key_directory_revision().value()
            }
        }
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
        &self,
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
            provenance: StreamBindingProvenance::Current,
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
        provenance: StreamBindingProvenance::Current,
    }))
}

/// active Add transition 的 directed snapshot 专用 binding capture。
///
/// EpochBarrier 已把 current publication row 推进到 `barrier_sequence/H`；wire binding
/// 仍必须携带 frozen `C/H/new epoch`。这里不放宽 generic capture，而是把 exact
/// transition provenance 连同稳定 wire 轴封进独立 capability。
pub(in crate::runtime::store) fn capture_transition_stream_binding_permit(
    transaction: &Transaction<'_>,
    key_bundle: &RuntimeKeyBundle,
    database_id: [u8; 16],
    stream: &PublicationStreamRecord,
    transition: &super::super::key_transition::TransitionSnapshotPermit,
) -> Result<StreamBindingPermit, RuntimeStoreError> {
    let provenance = transition.stream_binding_provenance();
    let cut = transition.stream_binding_cut();
    super::super::key_transition::validate_transition_stream_binding_provenance_in_transaction(
        transaction,
        key_bundle,
        database_id,
        provenance,
        cut,
    )?;
    if !transition_scope_matches_publication_scope(cut.scope, stream.scope)
        || stream.publication_stream_id != cut.publication_stream_id
        || stream.stream_route != cut.stream_route
        || stream.generation != cut.generation
        || checked_next_outer(cut.relay_committed_outer)? != provenance.barrier_sequence
        || stream.committed_high_water != Some(provenance.barrier_sequence)
        || stream.committed_inner_cursor != cut.relay_committed_inner
    {
        return Err(RuntimeStoreError::PublicationMismatch);
    }
    let expected_key_id = transition_key_id(cut.scope, cut.key_epoch);
    let identity =
        super::shared::current_shared_key_identity(key_bundle, database_id, transaction, stream)?
            .ok_or(RuntimeStoreError::PublicationMismatch)?;
    if identity != (cut.key_directory_revision, expected_key_id) {
        return Err(RuntimeStoreError::PublicationMismatch);
    }
    Ok(StreamBindingPermit {
        scope: stream.scope,
        publication_stream_id: cut.publication_stream_id,
        stream_route: cut.stream_route,
        generation: cut.generation,
        outer: StreamCursor::from_high_water(cut.relay_committed_outer),
        inner: StreamCursor::from_high_water(cut.relay_committed_inner),
        key_directory_revision: cut.key_directory_revision,
        key_id: expected_key_id,
        provenance: StreamBindingProvenance::Transition(Box::new(provenance)),
    })
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
    {
        return Err(RuntimeStoreError::PublicationMismatch);
    }
    match &permit.provenance {
        StreamBindingProvenance::Current => {
            if StreamCursor::from_high_water(stream.committed_high_water) != permit.outer
                || StreamCursor::from_high_water(stream.committed_inner_cursor) != permit.inner
            {
                return Err(RuntimeStoreError::PublicationMismatch);
            }
        }
        StreamBindingProvenance::Transition(provenance) => {
            let cut = transition_cut_from_permit(permit);
            super::super::key_transition::validate_transition_stream_binding_provenance_in_transaction(
                transaction,
                key_bundle,
                database_id,
                **provenance,
                cut,
            )?;
            if transition_key_id(cut.scope, cut.key_epoch) != permit.key_id
                || checked_next_outer(cut.relay_committed_outer)? != provenance.barrier_sequence
                || stream.committed_high_water != Some(provenance.barrier_sequence)
                || stream.committed_inner_cursor != cut.relay_committed_inner
            {
                return Err(RuntimeStoreError::PublicationMismatch);
            }
        }
    }
    let identity =
        super::shared::current_shared_key_identity(key_bundle, database_id, transaction, &stream)?
            .ok_or(RuntimeStoreError::PublicationMismatch)?;
    if identity != (permit.key_directory_revision, permit.key_id) {
        return Err(RuntimeStoreError::PublicationMismatch);
    }
    Ok(())
}

fn transition_cut_from_permit(
    permit: &StreamBindingPermit,
) -> super::super::key_transition::TransitionStreamBindingCut {
    let scope = match permit.scope {
        PublicationScope::Catalog => {
            super::super::key_transition::KeyTransitionStreamScope::Catalog
        }
        PublicationScope::Conversation(conversation_id) => {
            super::super::key_transition::KeyTransitionStreamScope::Conversation(
                *conversation_id.as_bytes(),
            )
        }
    };
    super::super::key_transition::TransitionStreamBindingCut {
        scope,
        publication_stream_id: permit.publication_stream_id,
        stream_route: permit.stream_route,
        generation: permit.generation,
        relay_committed_outer: permit.outer.high_water(),
        relay_committed_inner: permit.inner.high_water(),
        key_directory_revision: permit.key_directory_revision,
        key_epoch: permit.key_id.epoch,
    }
}

fn transition_scope_matches_publication_scope(
    transition: super::super::key_transition::KeyTransitionStreamScope,
    publication: PublicationScope,
) -> bool {
    match (transition, publication) {
        (
            super::super::key_transition::KeyTransitionStreamScope::Catalog,
            PublicationScope::Catalog,
        ) => true,
        (
            super::super::key_transition::KeyTransitionStreamScope::Conversation(expected),
            PublicationScope::Conversation(conversation_id),
        ) => conversation_id.as_bytes() == &expected,
        _ => false,
    }
}

fn transition_key_id(
    scope: super::super::key_transition::KeyTransitionStreamScope,
    epoch: u64,
) -> KeyId {
    let purpose = match scope {
        super::super::key_transition::KeyTransitionStreamScope::Catalog => KeyPurpose::Catalog,
        super::super::key_transition::KeyTransitionStreamScope::Conversation(_) => {
            KeyPurpose::ConversationDek
        }
    };
    KeyId { purpose, epoch }
}

fn checked_next_outer(outer: Option<u64>) -> Result<u64, RuntimeStoreError> {
    outer.map_or(Ok(0), |outer| {
        outer
            .checked_add(1)
            .ok_or(RuntimeStoreError::PublicationMismatch)
    })
}
