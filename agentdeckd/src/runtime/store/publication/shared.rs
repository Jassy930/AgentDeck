//! Shared publication 的 authenticated Store preflight 与 transaction key binding。
//!
//! preflight 只返回 key identity；raw ADGK2 key 仅在最终 `BEGIN IMMEDIATE` freeze
//! transaction 内重新读取，并随一次性 sealer axes 移动。

use agentdeck_crypto::SecretAeadKey;
use agentdeck_protocol::e2ee::{KeyControlV1, KeyId, KeyPurpose, SignedSealedBlobV1};
use agentdeck_protocol::relay_v2::StreamRouteId;
use agentdeck_protocol::runtime::catalog::CatalogDelta;
use agentdeck_protocol::runtime::event::RuntimeEvent;
use agentdeck_protocol::runtime::{RuntimeStreamItem, RuntimeTransferCarrierV1};

use super::super::key_transition::KeyTransitionStreamScope;
use super::*;
use crate::runtime::transfer_identity::{DurableStreamSource, DurableStreamTransferIdentity};

const MAX_SHARED_CATALOG_RANGE: u64 = 500;
const EPOCH_BARRIER_PUBLICATION_ID_DOMAIN: &[u8] = b"AgentDeck/EpochBarrierPublicationIdV1\0";

/// EpochBarrier 的 Store-authenticated durable identity。所有字段都来自已冻结的
/// `BarriersFrozen` cut；generic `Control` payload 无法构造或旁路这条 identity。
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) struct EpochBarrierJournalIdentity {
    pub operation_id: [u8; 16],
    pub scope: KeyTransitionStreamScope,
    pub publication_stream_id: [u8; 16],
    pub stream_route: [u8; 16],
    pub generation: [u8; 16],
    pub barrier_sequence: u64,
    pub key_directory_revision: u64,
    pub key_id: KeyId,
    pub barrier_sha256: [u8; 32],
}

impl EpochBarrierJournalIdentity {
    /// 一个 transition 会同时向多个 publication stream 写 barrier；publication id
    /// 因此必须同时绑定 operation 与 stream，不能直接复用 operation id。
    pub(crate) fn publication_id(self) -> [u8; 16] {
        let mut digest = Sha256::new();
        digest.update(EPOCH_BARRIER_PUBLICATION_ID_DOMAIN);
        digest.update(self.operation_id);
        digest.update(self.publication_stream_id);
        let digest: [u8; 32] = digest.finalize().into();
        digest[..16]
            .try_into()
            .expect("SHA-256 prefix has a fixed sixteen-byte length")
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum SharedJournalIdentity {
    CatalogRange,
    Event {
        event_id: RuntimeId,
    },
    Transfer {
        identity: DurableStreamTransferIdentity,
    },
    EpochBarrier(EpochBarrierJournalIdentity),
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub(crate) struct SharedPublicationPreflightRequest {
    pub publication_id: [u8; 16],
    pub scope: PublicationScope,
    pub inner_after: Option<u64>,
    pub inner_through: Option<u64>,
    pub payload_kind: PublicationPayloadKind,
    pub journal_identity: SharedJournalIdentity,
    pub canonical_item_bytes: Vec<u8>,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) struct SharedPublicationStreamProposal {
    pub publication_stream_id: [u8; 16],
    pub stream_route: [u8; 16],
    pub generation: [u8; 16],
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub(crate) struct SharedPublicationTransactionBinding {
    pub request: SharedPublicationPreflightRequest,
    pub expected_key_directory_revision: u64,
    pub expected_key_id: KeyId,
}

#[derive(Debug)]
pub(crate) struct TransactionSharedKeyAxes {
    pub key_directory_revision: u64,
    pub key_id: KeyId,
    pub key: SecretAeadKey,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum SharedPublicationPreflight {
    AlreadyHandled,
    /// 现有 scope 已进入 `NeedsSnapshot`。caller 必须使用这个 authenticated
    /// stream/generation identity 调用原地 rotation；不得消费一次性 sealer，也不得
    /// 用新的随机 proposal 旁路为第二条 directory row。
    RotationRequired(RotatePublicationStreamRequest),
    Frozen {
        publication_stream_id: [u8; 16],
        generation: [u8; 16],
        stream_seq: u64,
        blob_sha256: [u8; 32],
        key_directory_revision: u64,
        key_id: KeyId,
    },
    Fresh {
        publication_stream_id: [u8; 16],
        generation: [u8; 16],
        key_directory_revision: u64,
        key_id: KeyId,
    },
}

pub(crate) fn preflight_shared_publication(
    state: &mut RuntimeSqlite,
    config: &RuntimeStoreConfig,
    request: &SharedPublicationPreflightRequest,
    proposal: SharedPublicationStreamProposal,
    now_ms: u64,
) -> Result<SharedPublicationPreflight, RuntimeStoreError> {
    validate_request(request)?;
    validate_nonzero_id(proposal.publication_stream_id)?;
    validate_nonzero_id(proposal.stream_route)?;
    validate_nonzero_id(proposal.generation)?;

    // 先认证目录，只有 Catalog 确实缺 stream 才做写 admission。ACK tombstone 与
    // exact frozen retry 是纯 readback，不能被当前磁盘写水位误挡在 guard 之前。
    let pre_ledger = super::super::sqlite::load_runtime_ledger(
        &state.connection,
        &state.key_bundle,
        state.database_id,
    )?;
    let needs_catalog_create =
        !authenticate_directory_records(&state.connection, &state.key_bundle, &pre_ledger)?
            .into_iter()
            .any(|stream| {
                matches!(
                    stream.state,
                    PublicationStreamState::Active | PublicationStreamState::NeedsSnapshot
                ) && stream.scope == request.scope
            })
            && request.scope == PublicationScope::Catalog
            && !matches!(
                request.journal_identity,
                SharedJournalIdentity::EpochBarrier(_)
            );
    if needs_catalog_create {
        super::super::sqlite::admit_ordinary_write(
            &state.connection,
            &state.key_bundle,
            state.database_id,
            &state.storage_path,
            &mut state.admission_state,
            config.capacity_probe.as_ref(),
            1024 * 1024,
            super::super::sqlite::SafetyReserveProjection::Current,
        )?;
    }

    let database_id = state.database_id;
    let key_bundle = &state.key_bundle;
    let transaction = state
        .connection
        .transaction_with_behavior(TransactionBehavior::Immediate)?;
    validate_journal(&transaction, key_bundle, database_id, request)?;
    let ledger = super::super::sqlite::load_runtime_ledger(&transaction, key_bundle, database_id)?;
    let directory = authenticate_directory_records(&transaction, key_bundle, &ledger)?;
    let existing = select_shared_preflight_stream(directory, request.scope)?;
    let (stream, created) = match existing {
        Some(stream) => (stream, false),
        None if request.scope == PublicationScope::Catalog
            && !matches!(
                request.journal_identity,
                SharedJournalIdentity::EpochBarrier(_)
            ) =>
        {
            let next_count = ledger
                .publication_stream_count
                .checked_add(1)
                .ok_or(RuntimeStoreError::UnknownOrCorruptSchema)?;
            if next_count > 1_025 {
                return Err(RuntimeStoreError::ConversationLimit);
            }
            let stream = PublicationStreamRecord {
                publication_stream_id: proposal.publication_stream_id,
                scope: PublicationScope::Catalog,
                stream_route: proposal.stream_route,
                generation: proposal.generation,
                counter_scope_token: None,
                sender_counter_high_water: None,
                reserved_high_water: None,
                committed_high_water: None,
                committed_inner_cursor: None,
                last_committed_blob_hash: None,
                acknowledged_high_water: None,
                acknowledged_inner_cursor: None,
                last_acknowledged_blob_hash: None,
                last_acknowledged_publication_id: None,
                last_acknowledged_request_digest: None,
                last_rotation_request_digest: None,
                rotation_serial: 0,
                state: PublicationStreamState::Active,
                created_at_ms: now_ms,
                updated_at_ms: now_ms,
            };
            insert_stream(&transaction, key_bundle, &stream)?;
            let mut next = ledger.clone();
            next.publication_stream_count = next_count;
            let _ = super::super::sqlite::update_runtime_ledger(
                &transaction,
                key_bundle,
                database_id,
                &ledger,
                &next,
            )?;
            (stream, true)
        }
        // Runtime conversation -> ADGK2 stream_route 的 authenticated activation mapping
        // 不存在时禁止猜测随机 route；activation wiring 由后续 task 安装。
        None => return Err(RuntimeStoreError::PublicationMismatch),
    };

    let outcome =
        classify_existing_or_fresh(&transaction, key_bundle, database_id, request, &stream)?;
    if created {
        commit_with_faults(
            transaction,
            config,
            RuntimeStoreOperation::CreatePublicationStreamBeforeCommit,
            RuntimeCommitOperation::CreatePublicationStream,
        )?;
        super::super::sqlite::latch_post_commit_capacity(state, config);
        after_commit(
            config,
            RuntimeStoreOperation::CreatePublicationStreamAfterCommit,
            RuntimeCommitOperation::CreatePublicationStream,
        )?;
    }
    Ok(outcome)
}

fn select_shared_preflight_stream(
    directory: Vec<PublicationStreamRecord>,
    scope: PublicationScope,
) -> Result<Option<PublicationStreamRecord>, RuntimeStoreError> {
    let mut active = None;
    let mut needs_rotation = None;
    for stream in directory.into_iter().filter(|stream| stream.scope == scope) {
        match stream.state {
            PublicationStreamState::Active => {
                if active.replace(stream).is_some() {
                    return Err(RuntimeStoreError::UnknownOrCorruptSchema);
                }
            }
            PublicationStreamState::NeedsSnapshot => {
                if needs_rotation.replace(stream).is_some() {
                    // P4 production 从第一版起只允许原地 rotation；没有 authenticated
                    // lineage 能从多个 stranded generation 中猜测当前 owner。
                    return Err(RuntimeStoreError::PublicationMismatch);
                }
            }
            PublicationStreamState::Retired => {}
        }
    }
    Ok(active.or(needs_rotation))
}

fn classify_existing_or_fresh(
    connection: &Connection,
    key_bundle: &RuntimeKeyBundle,
    database_id: [u8; 16],
    request: &SharedPublicationPreflightRequest,
    stream: &PublicationStreamRecord,
) -> Result<SharedPublicationPreflight, RuntimeStoreError> {
    if stream.scope != request.scope || stream.state == PublicationStreamState::Retired {
        return Err(RuntimeStoreError::PublicationMismatch);
    }
    if let SharedJournalIdentity::EpochBarrier(identity) = request.journal_identity {
        validate_epoch_barrier_stream(stream, identity)?;
    }
    if stream.last_acknowledged_publication_id == Some(request.publication_id)
        && stream.acknowledged_inner_cursor == request.inner_through
    {
        return Ok(SharedPublicationPreflight::AlreadyHandled);
    }
    if let Some(frozen) =
        load_optional_outbox(connection, key_bundle, database_id, request.publication_id)?
    {
        if frozen.publication_stream_id != stream.publication_stream_id
            || frozen.generation != stream.generation
            || frozen.inner_after != request.inner_after
            || frozen.inner_through != request.inner_through
            || frozen.payload_kind != request.payload_kind
        {
            return Err(RuntimeStoreError::PublicationMismatch);
        }
        if let SharedJournalIdentity::EpochBarrier(identity) = request.journal_identity
            && (frozen.publication_stream_id != identity.publication_stream_id
                || frozen.generation != identity.generation
                || frozen.stream_seq != identity.barrier_sequence)
        {
            return Err(RuntimeStoreError::PublicationMismatch);
        }
        let counter_key_id = super::super::remote_counter::load_frozen_key_id_for_publication(
            connection,
            key_bundle,
            database_id,
            &frozen,
        )?;
        let signed = SignedSealedBlobV1::from_wire_bytes(&frozen.blob)
            .map_err(|_| RuntimeStoreError::UnknownOrCorruptSchema)?;
        if signed.inner.key_id != counter_key_id
            || signed.inner.key_epoch != counter_key_id.epoch
            || signed.inner.key_directory_revision == 0
            || matches!(
                request.journal_identity,
                SharedJournalIdentity::EpochBarrier(identity)
                    if signed.inner.key_id != identity.key_id
                        || signed.inner.key_directory_revision
                            != identity.key_directory_revision
            )
        {
            return Err(RuntimeStoreError::UnknownOrCorruptSchema);
        }
        return Ok(SharedPublicationPreflight::Frozen {
            publication_stream_id: frozen.publication_stream_id,
            generation: frozen.generation,
            stream_seq: frozen.stream_seq,
            blob_sha256: frozen.blob_sha256,
            key_directory_revision: signed.inner.key_directory_revision,
            key_id: counter_key_id,
        });
    }
    ensure_shared_freeze_allowed(
        connection,
        key_bundle,
        database_id,
        request.journal_identity,
    )?;
    validate_transfer_order(connection, key_bundle, database_id, request, stream)?;
    if stream.state == PublicationStreamState::NeedsSnapshot {
        return Ok(SharedPublicationPreflight::RotationRequired(
            RotatePublicationStreamRequest {
                publication_stream_id: stream.publication_stream_id,
                expected_generation: stream.generation,
            },
        ));
    }
    let (revision, key_id, _key) = current_shared_key(key_bundle, database_id, connection, stream)?;
    Ok(SharedPublicationPreflight::Fresh {
        publication_stream_id: stream.publication_stream_id,
        generation: stream.generation,
        key_directory_revision: revision,
        key_id,
    })
}

pub(crate) fn shared_transaction_key_axes(
    transaction: &Transaction<'_>,
    key_bundle: &RuntimeKeyBundle,
    database_id: [u8; 16],
    stream: &PublicationStreamRecord,
    assigned_stream_seq: u64,
    binding: &SharedPublicationTransactionBinding,
) -> Result<TransactionSharedKeyAxes, RuntimeStoreError> {
    if binding.request.scope != stream.scope
        || binding.expected_key_directory_revision == 0
        || binding.expected_key_id.epoch == 0
    {
        return Err(RuntimeStoreError::PublicationMismatch);
    }
    // Preflight 与 freeze 之间可并发开始 membership/key transition；因此最终
    // transaction 必须再次认证 fence，禁止使用刚变旧的 ADGK2 冻结迟到 row。
    ensure_shared_freeze_allowed(
        transaction,
        key_bundle,
        database_id,
        binding.request.journal_identity,
    )?;
    if let SharedJournalIdentity::EpochBarrier(identity) = binding.request.journal_identity {
        validate_epoch_barrier_stream(stream, identity)?;
        if assigned_stream_seq != identity.barrier_sequence {
            return Err(RuntimeStoreError::PublicationMismatch);
        }
    }
    validate_journal(transaction, key_bundle, database_id, &binding.request)?;
    validate_transfer_order(
        transaction,
        key_bundle,
        database_id,
        &binding.request,
        stream,
    )?;
    let (revision, key_id, key) = current_shared_key(key_bundle, database_id, transaction, stream)?;
    if revision != binding.expected_key_directory_revision || key_id != binding.expected_key_id {
        return Err(RuntimeStoreError::PublicationMismatch);
    }
    Ok(TransactionSharedKeyAxes {
        key_directory_revision: revision,
        key_id,
        key,
    })
}

fn validate_epoch_barrier_stream(
    stream: &PublicationStreamRecord,
    identity: EpochBarrierJournalIdentity,
) -> Result<(), RuntimeStoreError> {
    if stream.publication_stream_id != identity.publication_stream_id
        || stream.stream_route != identity.stream_route
        || stream.generation != identity.generation
    {
        return Err(RuntimeStoreError::PublicationMismatch);
    }
    Ok(())
}

/// 普通 shared journal 在 active transition 到 `BarriersCommitted` 前一律拒绝新
/// freeze。唯一旁路是带完整 frozen-cut 轴的 EpochBarrier identity；不能按
/// `payload_kind == Control` 泛化放行。
fn ensure_shared_freeze_allowed(
    connection: &Connection,
    key_bundle: &RuntimeKeyBundle,
    database_id: [u8; 16],
    journal_identity: SharedJournalIdentity,
) -> Result<(), RuntimeStoreError> {
    match journal_identity {
        SharedJournalIdentity::CatalogRange
        | SharedJournalIdentity::Event { .. }
        | SharedJournalIdentity::Transfer { .. } => {
            super::super::key_transition::ensure_no_active_transition_for_business(
                connection,
                key_bundle,
                database_id,
            )
        }
        SharedJournalIdentity::EpochBarrier(identity) => {
            super::super::key_transition::authorize_epoch_barrier_identity(
                connection,
                key_bundle,
                database_id,
                identity,
                None,
            )
        }
    }
}

fn current_shared_key(
    key_bundle: &RuntimeKeyBundle,
    database_id: [u8; 16],
    connection: &Connection,
    stream: &PublicationStreamRecord,
) -> Result<(u64, KeyId, SecretAeadKey), RuntimeStoreError> {
    let state = super::super::pairing_grant_tx::load_global_key_state_for_use(
        connection,
        key_bundle,
        database_id,
    )?
    .ok_or(RuntimeStoreError::PairingConflict)?;
    let revision = state.revision().value();
    let expected = match stream.scope {
        PublicationScope::Catalog => (KeyPurpose::Catalog, None),
        PublicationScope::Conversation(_) => (
            KeyPurpose::ConversationDek,
            Some(StreamRouteId::from_bytes(stream.stream_route)),
        ),
    };
    let view = state
        .current_shared_keys()?
        .into_iter()
        .find(|view| (view.purpose, view.stream_route) == expected)
        .ok_or(RuntimeStoreError::PairingConflict)?;
    let key_id = KeyId {
        purpose: view.purpose,
        epoch: view.epoch,
    };
    Ok((revision, key_id, view.key))
}

fn validate_request(request: &SharedPublicationPreflightRequest) -> Result<(), RuntimeStoreError> {
    validate_nonzero_id(request.publication_id)?;
    if request.canonical_item_bytes.is_empty()
        || request.canonical_item_bytes.len() > MAX_PUBLICATION_BLOB_BYTES
    {
        return Err(RuntimeStoreError::PayloadTooLarge);
    }
    validate_inner_range(
        request.inner_after,
        request.inner_through,
        request.payload_kind,
    )?;
    match (
        request.scope,
        request.payload_kind,
        request.journal_identity,
    ) {
        (
            PublicationScope::Catalog,
            PublicationPayloadKind::Catalog,
            SharedJournalIdentity::CatalogRange,
        ) => Ok(()),
        (
            PublicationScope::Conversation(conversation),
            PublicationPayloadKind::Event,
            SharedJournalIdentity::Event { event_id },
        ) if conversation.kind() == RuntimeIdKind::Conversation
            && event_id.kind() == RuntimeIdKind::Event =>
        {
            Ok(())
        }
        (
            scope,
            PublicationPayloadKind::Control
            | PublicationPayloadKind::Catalog
            | PublicationPayloadKind::Event,
            SharedJournalIdentity::Transfer { identity },
        ) if transfer_scope(identity) == scope => Ok(()),
        (scope, PublicationPayloadKind::Control, SharedJournalIdentity::EpochBarrier(identity)) => {
            validate_epoch_barrier_identity_shape(request.publication_id, scope, identity)
        }
        _ => Err(RuntimeStoreError::PublicationMismatch),
    }
}

fn validate_epoch_barrier_identity_shape(
    publication_id: [u8; 16],
    scope: PublicationScope,
    identity: EpochBarrierJournalIdentity,
) -> Result<(), RuntimeStoreError> {
    let expected_purpose = match scope {
        PublicationScope::Catalog if identity.scope == KeyTransitionStreamScope::Catalog => {
            KeyPurpose::Catalog
        }
        PublicationScope::Conversation(conversation_id)
            if conversation_id.kind() == RuntimeIdKind::Conversation
                && identity.scope
                    == KeyTransitionStreamScope::Conversation(*conversation_id.as_bytes()) =>
        {
            KeyPurpose::ConversationDek
        }
        PublicationScope::Catalog | PublicationScope::Conversation(_) => {
            return Err(RuntimeStoreError::PublicationMismatch);
        }
    };
    if identity.operation_id == [0; 16]
        || identity.publication_stream_id == [0; 16]
        || identity.stream_route == [0; 16]
        || identity.generation == [0; 16]
        || identity.key_directory_revision == 0
        || identity.key_id.purpose != expected_purpose
        || identity.key_id.epoch == 0
        || identity.barrier_sha256 == [0; 32]
        || publication_id != identity.publication_id()
    {
        return Err(RuntimeStoreError::PublicationMismatch);
    }
    Ok(())
}

fn validate_journal(
    connection: &Connection,
    key_bundle: &RuntimeKeyBundle,
    database_id: [u8; 16],
    request: &SharedPublicationPreflightRequest,
) -> Result<(), RuntimeStoreError> {
    validate_request(request)?;
    if let SharedJournalIdentity::Transfer { identity } = request.journal_identity {
        return validate_transfer_journal(connection, key_bundle, database_id, request, identity);
    }
    if let SharedJournalIdentity::EpochBarrier(identity) = request.journal_identity {
        let control = KeyControlV1::from_canonical_bytes(&request.canonical_item_bytes)
            .map_err(|_| RuntimeStoreError::PublicationMismatch)?;
        let KeyControlV1::EpochBarrier {
            stream_route,
            barrier,
            ..
        } = control
        else {
            return Err(RuntimeStoreError::PublicationMismatch);
        };
        if stream_route.as_bytes() != &identity.stream_route
            || barrier.stream_generation.as_bytes() != &identity.generation
            || barrier.key_directory_revision.value() != identity.key_directory_revision
            || barrier.new_epoch != identity.key_id.epoch
            || barrier
                .stream_cursor
                .checked_next()
                .map_err(|_| RuntimeStoreError::PublicationMismatch)?
                != identity.barrier_sequence
            || barrier
                .canonical_sha256()
                .map_err(|_| RuntimeStoreError::PublicationMismatch)?
                != identity.barrier_sha256
        {
            return Err(RuntimeStoreError::PublicationMismatch);
        }
        return super::super::key_transition::authorize_epoch_barrier_identity(
            connection,
            key_bundle,
            database_id,
            identity,
            Some(&barrier),
        );
    }
    let _requested: RuntimeStreamItem = serde_json::from_slice(&request.canonical_item_bytes)
        .map_err(|_| RuntimeStoreError::PublicationMismatch)?;
    let canonical = match (
        request.scope,
        request.journal_identity,
        request.inner_through,
    ) {
        (PublicationScope::Catalog, SharedJournalIdentity::CatalogRange, Some(through)) => {
            let first = request.inner_after.map_or(Ok(0), |after| {
                after
                    .checked_add(1)
                    .ok_or(RuntimeStoreError::PublicationMismatch)
            })?;
            load_catalog_item(connection, key_bundle, database_id, first, through)?
        }
        (
            PublicationScope::Conversation(conversation_id),
            SharedJournalIdentity::Event { event_id },
            Some(through),
        ) => load_event_item(
            connection,
            key_bundle,
            database_id,
            conversation_id,
            event_id,
            through,
        )?,
        _ => return Err(RuntimeStoreError::PublicationMismatch),
    };
    if serde_json::to_vec(&canonical).map_err(|_| RuntimeStoreError::UnknownOrCorruptSchema)?
        != request.canonical_item_bytes
    {
        return Err(RuntimeStoreError::PublicationMismatch);
    }
    Ok(())
}

fn validate_transfer_journal(
    connection: &Connection,
    key_bundle: &RuntimeKeyBundle,
    database_id: [u8; 16],
    request: &SharedPublicationPreflightRequest,
    identity: DurableStreamTransferIdentity,
) -> Result<(), RuntimeStoreError> {
    let carrier = RuntimeTransferCarrierV1::decode(&request.canonical_item_bytes)
        .map_err(|_| RuntimeStoreError::PublicationMismatch)?;
    if !identity.validates_carrier(&carrier)
        || DurableStreamTransferIdentity::parse_transfer_id(&carrier.transfer.transfer_id).ok()
            != Some(identity)
        || identity
            .publication_id(&carrier)
            .map_err(|_| RuntimeStoreError::PublicationMismatch)?
            != request.publication_id
    {
        return Err(RuntimeStoreError::PublicationMismatch);
    }
    let source_payload =
        load_transfer_source_payload(connection, key_bundle, database_id, identity)?;
    let expected = identity
        .carrier_for_part(&source_payload, carrier.transfer.part_index)
        .map_err(|_| RuntimeStoreError::PublicationMismatch)?;
    if expected != carrier
        || expected
            .encode()
            .map_err(|_| RuntimeStoreError::PublicationMismatch)?
            != request.canonical_item_bytes
    {
        return Err(RuntimeStoreError::PublicationMismatch);
    }
    let final_part = carrier.transfer.part_index + 1 == carrier.transfer.part_count;
    let (source_after, source_through, final_kind) = match identity.source {
        DurableStreamSource::Catalog {
            first_revision,
            through_revision,
        } => (
            first_revision.checked_sub(1),
            through_revision,
            PublicationPayloadKind::Catalog,
        ),
        DurableStreamSource::Event { event_seq, .. } => (
            event_seq.checked_sub(1),
            event_seq,
            PublicationPayloadKind::Event,
        ),
    };
    let valid_cursor = if final_part {
        request.inner_after == source_after
            && request.inner_through == Some(source_through)
            && request.payload_kind == final_kind
    } else {
        request.inner_after.is_none()
            && request.inner_through.is_none()
            && request.payload_kind == PublicationPayloadKind::Control
    };
    if !valid_cursor {
        return Err(RuntimeStoreError::PublicationMismatch);
    }
    Ok(())
}

fn load_transfer_source_payload(
    connection: &Connection,
    key_bundle: &RuntimeKeyBundle,
    database_id: [u8; 16],
    identity: DurableStreamTransferIdentity,
) -> Result<Vec<u8>, RuntimeStoreError> {
    let source = match identity.source {
        DurableStreamSource::Catalog {
            first_revision,
            through_revision,
        } => load_catalog_item(
            connection,
            key_bundle,
            database_id,
            first_revision,
            through_revision,
        )?,
        DurableStreamSource::Event {
            conversation_id,
            event_id,
            event_seq,
        } => load_event_item(
            connection,
            key_bundle,
            database_id,
            conversation_id,
            event_id,
            event_seq,
        )?,
    };
    match &source {
        RuntimeStreamItem::CatalogDelta(delta) => serde_json::to_vec(delta),
        RuntimeStreamItem::Event(event) => serde_json::to_vec(event),
        RuntimeStreamItem::PairingPending(_) | RuntimeStreamItem::TransferPart(_) => {
            return Err(RuntimeStoreError::PublicationMismatch);
        }
    }
    .map_err(|_| RuntimeStoreError::UnknownOrCorruptSchema)
}

fn validate_transfer_order(
    connection: &Connection,
    key_bundle: &RuntimeKeyBundle,
    database_id: [u8; 16],
    request: &SharedPublicationPreflightRequest,
    stream: &PublicationStreamRecord,
) -> Result<(), RuntimeStoreError> {
    let SharedJournalIdentity::Transfer { identity } = request.journal_identity else {
        return Ok(());
    };
    let carrier = RuntimeTransferCarrierV1::decode(&request.canonical_item_bytes)
        .map_err(|_| RuntimeStoreError::PublicationMismatch)?;
    let part_index = carrier.transfer.part_index;
    if part_index == 0 {
        if let Some(latest_seq) = stream.reserved_high_water
            && let Ok(latest) = super::load_outbox_by_stream_seq(
                connection,
                key_bundle,
                database_id,
                stream.publication_stream_id,
                stream.generation,
                latest_seq,
            )
            && latest.inner_through.is_none()
            && latest.payload_kind == PublicationPayloadKind::Control
        {
            return Err(RuntimeStoreError::PublicationMismatch);
        }
        return Ok(());
    }
    let payload = load_transfer_source_payload(connection, key_bundle, database_id, identity)?;
    let previous = identity
        .carrier_for_part(&payload, part_index - 1)
        .map_err(|_| RuntimeStoreError::PublicationMismatch)?;
    let previous_id = identity
        .publication_id(&previous)
        .map_err(|_| RuntimeStoreError::PublicationMismatch)?;
    if let Some(previous) = load_optional_outbox(connection, key_bundle, database_id, previous_id)?
    {
        if previous.publication_stream_id == stream.publication_stream_id
            && previous.generation == stream.generation
            && previous.inner_after.is_none()
            && previous.inner_through.is_none()
            && previous.payload_kind == PublicationPayloadKind::Control
        {
            return Ok(());
        }
        return Err(RuntimeStoreError::PublicationMismatch);
    }
    if stream.last_acknowledged_publication_id == Some(previous_id)
        && stream.acknowledged_inner_cursor.is_none()
    {
        return Ok(());
    }
    Err(RuntimeStoreError::PublicationMismatch)
}

fn load_catalog_item(
    connection: &Connection,
    key_bundle: &RuntimeKeyBundle,
    database_id: [u8; 16],
    first: u64,
    through: u64,
) -> Result<RuntimeStreamItem, RuntimeStoreError> {
    let count = through
        .checked_sub(first)
        .and_then(|value| value.checked_add(1))
        .ok_or(RuntimeStoreError::PublicationMismatch)?;
    if count > MAX_SHARED_CATALOG_RANGE {
        return Err(RuntimeStoreError::PayloadTooLarge);
    }
    let read_crypto = key_bundle.read_only_capability();
    let mut changes = Vec::new();
    for revision in first..=through {
        let delta = super::super::catalog::load_delta(
            connection,
            &read_crypto,
            database_id,
            &encode_sequence(revision),
        )?;
        changes.extend(delta.changes);
    }
    Ok(RuntimeStreamItem::CatalogDelta(CatalogDelta {
        catalog_revision: through,
        changes,
    }))
}

fn load_event_item(
    connection: &Connection,
    key_bundle: &RuntimeKeyBundle,
    database_id: [u8; 16],
    conversation_id: RuntimeId,
    event_id: RuntimeId,
    event_seq: u64,
) -> Result<RuntimeStreamItem, RuntimeStoreError> {
    let event = super::super::journal::load_event(connection, key_bundle, database_id, event_id)?;
    if event.conversation_id != conversation_id
        || event.event_seq != event_seq
        || event.event_id != event_id
    {
        return Err(RuntimeStoreError::PublicationMismatch);
    }
    let event: RuntimeEvent = serde_json::from_slice(&event.payload)
        .map_err(|_| RuntimeStoreError::UnknownOrCorruptSchema)?;
    Ok(RuntimeStreamItem::Event(event))
}

const fn transfer_scope(identity: DurableStreamTransferIdentity) -> PublicationScope {
    match identity.source {
        DurableStreamSource::Catalog { .. } => PublicationScope::Catalog,
        DurableStreamSource::Event {
            conversation_id, ..
        } => PublicationScope::Conversation(conversation_id),
    }
}

#[cfg(test)]
mod epoch_barrier_identity_tests {
    use agentdeck_protocol::e2ee::{EpochBarrierV1, KeyControlV1, KeyId, KeyPurpose};
    use agentdeck_protocol::relay_v2::{KeyDirectoryRevision, StreamGenerationId, StreamRouteId};
    use agentdeck_protocol::runtime::{RuntimeInnerCursor, StreamCursor};

    use super::*;

    fn identity() -> EpochBarrierJournalIdentity {
        EpochBarrierJournalIdentity {
            operation_id: [0x11; 16],
            scope: KeyTransitionStreamScope::Catalog,
            publication_stream_id: [0x22; 16],
            stream_route: [0x33; 16],
            generation: [0x44; 16],
            barrier_sequence: 8,
            key_directory_revision: 2,
            key_id: KeyId {
                purpose: KeyPurpose::Catalog,
                epoch: 2,
            },
            barrier_sha256: [0x55; 32],
        }
    }

    fn canonical_control() -> Vec<u8> {
        KeyControlV1::epoch_barrier(
            StreamRouteId::from_bytes([0x33; 16]),
            EpochBarrierV1 {
                stream_generation: StreamGenerationId::from_bytes([0x44; 16]),
                stream_cursor: StreamCursor::At(7),
                inner_cursor: RuntimeInnerCursor::Catalog {
                    cursor: StreamCursor::At(9),
                },
                old_epoch: 1,
                new_epoch: 2,
                key_directory_revision: KeyDirectoryRevision::new(2),
            },
        )
        .canonical_bytes()
        .expect("canonical EpochBarrier control")
    }

    #[test]
    fn epoch_barrier_publication_id_binds_operation_and_publication_stream() {
        let baseline = identity();
        let mut changed_operation = baseline;
        changed_operation.operation_id[0] ^= 1;
        let mut changed_stream = baseline;
        changed_stream.publication_stream_id[0] ^= 1;

        assert_ne!(baseline.publication_id(), baseline.operation_id);
        assert_ne!(
            baseline.publication_id(),
            changed_operation.publication_id()
        );
        assert_ne!(baseline.publication_id(), changed_stream.publication_id());
    }

    #[test]
    fn generic_control_identity_cannot_claim_epoch_barrier_bypass() {
        let control = canonical_control();
        let generic = SharedPublicationPreflightRequest {
            publication_id: [0x66; 16],
            scope: PublicationScope::Catalog,
            inner_after: None,
            inner_through: None,
            payload_kind: PublicationPayloadKind::Control,
            journal_identity: SharedJournalIdentity::CatalogRange,
            canonical_item_bytes: control.clone(),
        };
        assert!(matches!(
            validate_request(&generic),
            Err(RuntimeStoreError::PublicationMismatch)
        ));

        let identity = identity();
        let dedicated = SharedPublicationPreflightRequest {
            publication_id: identity.publication_id(),
            scope: PublicationScope::Catalog,
            inner_after: None,
            inner_through: None,
            payload_kind: PublicationPayloadKind::Control,
            journal_identity: SharedJournalIdentity::EpochBarrier(identity),
            canonical_item_bytes: control,
        };
        validate_request(&dedicated).expect("dedicated identity has a valid outer shape");

        let mut direct_operation_id = dedicated;
        direct_operation_id.publication_id = identity.operation_id;
        assert!(matches!(
            validate_request(&direct_operation_id),
            Err(RuntimeStoreError::PublicationMismatch)
        ));
    }
}
