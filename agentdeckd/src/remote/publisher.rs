//! P4.5 signed publication 的线性生命周期。
//!
//! 顺序固定为 CounterGuard reserve → seal once → Runtime DB exact freeze → Relay
//! COMMIT → device delivery ACK。该状态机不持 canonical Runtime 业务状态；真正的 durable
//! payload、cursor 与 outbox 仍由 Runtime Store 持有。

use agentdeck_protocol::e2ee::KeyId;
use agentdeck_protocol::relay_v2::{MachineRouteId, StreamGenerationId, StreamRouteId};

use crate::runtime::store::publication::{
    FreezeSignedPublicationRequest, SharedPublicationTransactionBinding,
    TransactionPublicationAxes, TransactionSharedKeyAxes,
};
use crate::runtime::store::remote_counter::{
    RemoteCounterGapRequest, RemoteCounterRecord, RemoteCounterRecordKind,
    RemoteCounterReservation, RemoteCounterRetirementRequest,
};
use crate::runtime::store::{
    FrozenPublication, PublicationPayloadKind, RuntimeStoreError, RuntimeStoreHandle,
};

use super::counter::{
    COUNTER_BLOCK_SIZE, CounterDbState, CounterError, CounterGuardBackend, CounterGuardCas,
    CounterGuardPhase, CounterGuardState, CounterRecovery, CounterScope,
    reconcile_counter_recovery,
};

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum PublicationClass {
    Catalog,
    ConversationEvent,
    EpochBarrier,
    DirectedSnapshot,
    DirectoryRevisionAdvance,
}

impl PublicationClass {
    #[must_use]
    pub const fn tag(self) -> u8 {
        match self {
            Self::Catalog => 1,
            Self::ConversationEvent => 2,
            Self::EpochBarrier => 3,
            Self::DirectedSnapshot => 4,
            Self::DirectoryRevisionAdvance => 5,
        }
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct PublicationSealAxes {
    machine_route: MachineRouteId,
    stream_route: StreamRouteId,
    generation: StreamGenerationId,
    key_directory_revision: u64,
    stream_seq: u64,
    key_id: KeyId,
    key_epoch: u64,
    sender_counter: u64,
    inner_after: Option<u64>,
    inner_through: Option<u64>,
}

impl PublicationSealAxes {
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        machine_route: MachineRouteId,
        stream_route: StreamRouteId,
        generation: StreamGenerationId,
        key_directory_revision: u64,
        stream_seq: u64,
        key_id: KeyId,
        key_epoch: u64,
        sender_counter: u64,
        inner_after: Option<u64>,
        inner_through: Option<u64>,
    ) -> Result<Self, PublicationError> {
        if machine_route.as_bytes() == &[0; 16]
            || stream_route.as_bytes() == &[0; 16]
            || generation.as_bytes() == &[0; 16]
            || key_directory_revision == 0
            || key_id.epoch == 0
            || key_epoch == 0
            || key_id.epoch != key_epoch
            || matches!((inner_after, inner_through), (Some(after), Some(through)) if through <= after)
            || (inner_after.is_some() && inner_through.is_none())
        {
            return Err(PublicationError::InvalidAxes);
        }
        Ok(Self {
            machine_route,
            stream_route,
            generation,
            key_directory_revision,
            stream_seq,
            key_id,
            key_epoch,
            sender_counter,
            inner_after,
            inner_through,
        })
    }

    #[must_use]
    pub const fn stream_seq(self) -> u64 {
        self.stream_seq
    }

    #[must_use]
    pub const fn sender_counter(self) -> u64 {
        self.sender_counter
    }

    #[must_use]
    pub(crate) const fn stream_route(self) -> StreamRouteId {
        self.stream_route
    }

    #[must_use]
    pub(crate) const fn generation(self) -> StreamGenerationId {
        self.generation
    }
}

/// signed publication 在进入 Store 前已经固定的轴。`stream_route/stream_seq/counter`
/// 只能由 Store 的 `BEGIN IMMEDIATE` transaction 补齐，production API 因而不接受
/// 调用方预先 seal 的 blob。
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct SignedPublicationRequest {
    pub publication_id: [u8; 16],
    pub publication_stream_id: [u8; 16],
    pub machine_route: MachineRouteId,
    pub generation: StreamGenerationId,
    pub key_directory_revision: u64,
    pub key_id: KeyId,
    pub counter_scope: CounterScope,
    pub inner_after: Option<u64>,
    pub inner_through: Option<u64>,
    pub payload_kind: PublicationPayloadKind,
    /// 传入 transaction-bound sealer 的闭包在 worker queue 中保留的堆内存。
    /// Store lane budget 必须覆盖它，不能把捕获的 key/plaintext 记成零成本。
    pub sealer_retained_bytes: usize,
}

impl SignedPublicationRequest {
    fn validate(&self) -> Result<(), PublicationError> {
        if self.publication_id == [0; 16]
            || self.publication_stream_id == [0; 16]
            || self.machine_route.as_bytes() == &[0; 16]
            || self.generation.as_bytes() == &[0; 16]
            || self.key_directory_revision == 0
            || self.key_id.epoch == 0
            || self.counter_scope.token() == [0; 32]
            || !valid_signed_inner_range(self.inner_after, self.inner_through, self.payload_kind)
        {
            return Err(PublicationError::InvalidAxes);
        }
        Ok(())
    }

    fn matches_frozen(&self, frozen: &FrozenPublication) -> bool {
        frozen.publication_id == self.publication_id
            && frozen.publication_stream_id == self.publication_stream_id
            && frozen.generation == *self.generation.as_bytes()
            && frozen.counter_scope_token == self.counter_scope.token()
            && frozen.inner_after == self.inner_after
            && frozen.inner_through == self.inner_through
            && frozen.payload_kind == self.payload_kind
    }
}

/// KeyStore guard 与 Runtime Store 的窄协调器。它不持 canonical Runtime payload；
/// caller 提供的一次性 sealer 在 blocking Store worker 的 transaction 内消费真实分配轴。
pub struct SignedPublicationCoordinator<'a, B: CounterGuardBackend> {
    store: &'a RuntimeStoreHandle,
    guard: &'a B,
}

impl<'a, B: CounterGuardBackend> SignedPublicationCoordinator<'a, B> {
    #[must_use]
    pub const fn new(store: &'a RuntimeStoreHandle, guard: &'a B) -> Self {
        Self { store, guard }
    }

    /// RemoteLink admission 前对一个 Store-derived active sender scope 做完整
    /// CounterGuard/DB 对账。可证明的 crash gap 会先 durable 跳号，可证明的 frozen
    /// reservation 会收敛为 Stable；任何 rollback/分叉都必须先写入 Retired tombstone
    /// 再 fail-close，不能延迟到下一次业务发送才发现。
    pub async fn audit_sender_scope(
        &self,
        scope: CounterScope,
        key_id: KeyId,
    ) -> Result<(), SignedPublicationError> {
        if !self
            .store
            .remote_counter_scope_allowed(scope.token())
            .await?
        {
            return Err(SignedPublicationError::RetireKey);
        }
        self.store
            .register_remote_counter_guard_scope(scope.token())
            .await?;
        let mut guard = self
            .guard
            .load_guard(&scope)
            .map_err(|_| SignedPublicationError::GuardUnavailable)?;
        if guard.is_some() {
            self.store
                .mark_remote_counter_guard_scope_materialized(scope.token())
                .await?;
        }
        let mut database = self
            .store
            .load_remote_counter_record(scope.token(), key_id)
            .await?;
        if database.kind.is_retirement_lineage() {
            return Err(SignedPublicationError::RetireKey);
        }

        if let Some(pending) = guard.filter(|state| state.phase() == CounterGuardPhase::Pending) {
            if database.kind == RemoteCounterRecordKind::Gap
                && database.reservation_id == pending.reservation_id()
                && database.publication_id == pending.publication_id()
                && database.reserved_end == pending.reserved_through()
            {
                let stable = CounterGuardState::stable(
                    scope.token(),
                    database.reserved_end,
                    database.db_anchor,
                )?;
                self.swap_exact(scope, pending, stable)?;
                guard = Some(stable);
            } else {
                let recovery = reconcile_counter_recovery(&pending, &counter_db_state(&database)?)?;
                match recovery {
                    CounterRecovery::GuardAheadGap { abandoned_through } => {
                        let gap = self
                            .store
                            .record_remote_counter_gap(RemoteCounterGapRequest {
                                scope_token: scope.token(),
                                key_id,
                                expected_reserved_end: database.reserved_end,
                                expected_db_anchor: database.db_anchor,
                                abandoned_through,
                                reservation_id: pending
                                    .reservation_id()
                                    .ok_or(SignedPublicationError::RetireKey)?,
                                publication_id: pending
                                    .publication_id()
                                    .ok_or(SignedPublicationError::RetireKey)?,
                            })
                            .await?;
                        let stable = CounterGuardState::stable(
                            scope.token(),
                            gap.reserved_end,
                            gap.db_anchor,
                        )?;
                        self.swap_exact(scope, pending, stable)?;
                        guard = Some(stable);
                        database = gap;
                    }
                    CounterRecovery::RetryFrozen {
                        exact_db_anchor, ..
                    } => {
                        let stable = CounterGuardState::stable(
                            scope.token(),
                            pending.reserved_through(),
                            exact_db_anchor,
                        )?;
                        self.swap_exact(scope, pending, stable)?;
                        guard = Some(stable);
                    }
                    CounterRecovery::ReserveNextBlock { .. } | CounterRecovery::RetireKey => {
                        self.retire_sender_scope(scope, key_id, Some(pending), &database)
                            .await?;
                        return Err(SignedPublicationError::RetireKey);
                    }
                }
            }
        }

        if validate_stable_head(guard, &database).is_err() {
            self.retire_sender_scope(scope, key_id, guard, &database)
                .await?;
            return Err(SignedPublicationError::RetireKey);
        }
        Ok(())
    }

    pub async fn freeze_signed<F>(
        &self,
        request: SignedPublicationRequest,
        sealer: F,
    ) -> Result<FrozenPublication, SignedPublicationError>
    where
        F: FnOnce(PublicationSealAxes) -> Result<Vec<u8>, PublicationError> + Send + 'static,
    {
        self.freeze_signed_inner(request, None, move |axes, shared_key| {
            if shared_key.is_some() {
                return Err(PublicationError::InvalidAxes);
            }
            sealer(axes)
        })
        .await
    }

    pub(crate) async fn freeze_shared_signed<F>(
        &self,
        request: SignedPublicationRequest,
        binding: SharedPublicationTransactionBinding,
        sealer: F,
    ) -> Result<FrozenPublication, SignedPublicationError>
    where
        F: FnOnce(
                PublicationSealAxes,
                TransactionSharedKeyAxes,
            ) -> Result<Vec<u8>, PublicationError>
            + Send
            + 'static,
    {
        self.freeze_signed_inner(request, Some(binding), move |axes, shared_key| {
            sealer(axes, shared_key.ok_or(PublicationError::InvalidAxes)?)
        })
        .await
    }

    async fn freeze_signed_inner<F>(
        &self,
        request: SignedPublicationRequest,
        shared_binding: Option<SharedPublicationTransactionBinding>,
        sealer: F,
    ) -> Result<FrozenPublication, SignedPublicationError>
    where
        F: FnOnce(
                PublicationSealAxes,
                Option<TransactionSharedKeyAxes>,
            ) -> Result<Vec<u8>, PublicationError>
            + Send
            + 'static,
    {
        request.validate()?;
        if !self
            .store
            .remote_counter_scope_allowed(request.counter_scope.token())
            .await?
        {
            return Err(SignedPublicationError::RetireKey);
        }
        self.store
            .register_remote_counter_guard_scope(request.counter_scope.token())
            .await?;
        if let Some(existing) = self.existing_frozen(&request).await? {
            return self.finish_existing(&request, existing).await;
        }

        let mut guard = self
            .guard
            .load_guard(&request.counter_scope)
            .map_err(|_| SignedPublicationError::GuardUnavailable)?;
        if guard.is_some() {
            self.store
                .mark_remote_counter_guard_scope_materialized(request.counter_scope.token())
                .await?;
        }
        let mut database = self
            .store
            .load_remote_counter_record(request.counter_scope.token(), request.key_id)
            .await?;
        if database.kind.is_retirement_lineage() {
            return Err(SignedPublicationError::RetireKey);
        }
        self.reconcile_gap_if_needed(&request, &mut guard, &mut database)
            .await?;
        if let Err(error) = validate_stable_head(guard, &database) {
            self.retire_counter(&request, guard, &database).await?;
            return Err(error);
        }

        let previous_end = database.reserved_end;
        let Some(reserved_end) = previous_end.checked_add(COUNTER_BLOCK_SIZE) else {
            self.retire_counter(&request, guard, &database).await?;
            return Err(SignedPublicationError::RetireKey);
        };
        let reservation_id = random_reservation_id()?;
        let pending = CounterGuardState::pending(
            request.counter_scope.token(),
            previous_end,
            reserved_end,
            reservation_id,
            request.publication_id,
            database.db_anchor,
        )?;
        match self
            .guard
            .compare_and_swap_guard(&request.counter_scope, guard, pending)
            .map_err(|_| SignedPublicationError::GuardUnavailable)?
        {
            CounterGuardCas::Swapped(persisted) if persisted == pending => {}
            CounterGuardCas::Swapped(_) | CounterGuardCas::Conflict(_) => {
                return Err(SignedPublicationError::GuardConflict);
            }
        }
        self.store
            .mark_remote_counter_guard_scope_materialized(request.counter_scope.token())
            .await?;

        let static_request = request;
        let frozen_result = self
            .store
            .freeze_signed_publication(FreezeSignedPublicationRequest {
                publication_id: static_request.publication_id,
                publication_stream_id: static_request.publication_stream_id,
                generation: *static_request.generation.as_bytes(),
                counter: RemoteCounterReservation {
                    scope_token: static_request.counter_scope.token(),
                    key_id: static_request.key_id,
                    previous_reserved_end: previous_end,
                    reserved_end,
                    previous_db_anchor: database.db_anchor,
                    reservation_id,
                    publication_id: static_request.publication_id,
                },
                inner_after: static_request.inner_after,
                inner_through: static_request.inner_through,
                payload_kind: static_request.payload_kind,
                shared_binding,
                sealer_retained_bytes: static_request.sealer_retained_bytes,
                sealer: Box::new(move |assigned: TransactionPublicationAxes| {
                    let axes = PublicationSealAxes::new(
                        static_request.machine_route,
                        StreamRouteId::from_bytes(assigned.stream_route),
                        static_request.generation,
                        static_request.key_directory_revision,
                        assigned.stream_seq,
                        static_request.key_id,
                        static_request.key_id.epoch,
                        assigned.sender_counter,
                        static_request.inner_after,
                        static_request.inner_through,
                    )
                    .map_err(|_| RuntimeStoreError::PublicationMismatch)?;
                    sealer(axes, assigned.shared_key)
                        .map_err(|_| RuntimeStoreError::PublicationMismatch)
                }),
            })
            .await;
        let frozen = match frozen_result {
            Ok(frozen) => frozen,
            Err(RuntimeStoreError::InvalidStateTransition)
                if !self
                    .store
                    .remote_counter_scope_allowed(static_request.counter_scope.token())
                    .await? =>
            {
                return Err(SignedPublicationError::RetireKey);
            }
            Err(error) => return Err(error.into()),
        };
        let exact_anchor = frozen
            .counter_db_anchor
            .ok_or(RuntimeStoreError::UnknownOrCorruptSchema)?;
        let stable = CounterGuardState::stable(
            static_request.counter_scope.token(),
            reserved_end,
            exact_anchor,
        )?;
        match self
            .guard
            .compare_and_swap_guard(&static_request.counter_scope, Some(pending), stable)
            .map_err(|_| SignedPublicationError::GuardUnavailable)?
        {
            CounterGuardCas::Swapped(persisted) if persisted == stable => Ok(frozen),
            CounterGuardCas::Swapped(_) | CounterGuardCas::Conflict(_) => {
                Err(SignedPublicationError::GuardConflict)
            }
        }
    }

    async fn existing_frozen(
        &self,
        request: &SignedPublicationRequest,
    ) -> Result<Option<FrozenPublication>, SignedPublicationError> {
        let existing = self
            .store
            .load_frozen_publication(request.publication_id)
            .await?;
        if existing
            .as_ref()
            .is_some_and(|row| !request.matches_frozen(row))
        {
            return Err(SignedPublicationError::Conflict);
        }
        Ok(existing)
    }

    async fn finish_existing(
        &self,
        request: &SignedPublicationRequest,
        mut frozen: FrozenPublication,
    ) -> Result<FrozenPublication, SignedPublicationError> {
        let guard = self
            .guard
            .load_guard(&request.counter_scope)
            .map_err(|_| SignedPublicationError::GuardUnavailable)?;
        if guard.is_some() {
            self.store
                .mark_remote_counter_guard_scope_materialized(request.counter_scope.token())
                .await?;
        }
        let record = self
            .store
            .load_remote_counter_record(request.counter_scope.token(), request.key_id)
            .await?;
        if record.kind.is_retirement_lineage() {
            return Err(SignedPublicationError::RetireKey);
        }
        if record.publication_id != Some(frozen.publication_id)
            || record.kind != RemoteCounterRecordKind::Frozen
        {
            self.retire_counter(request, guard, &record).await?;
            return Err(SignedPublicationError::RetireKey);
        }
        let Some(guard) = guard else {
            self.retire_counter(request, None, &record).await?;
            return Err(SignedPublicationError::RetireKey);
        };
        let database = counter_db_state(&record)?;
        match reconcile_counter_recovery(&guard, &database)? {
            CounterRecovery::RetryFrozen {
                publication_id,
                exact_db_anchor,
            } if publication_id == frozen.publication_id => {
                if guard.phase() == CounterGuardPhase::Pending {
                    let stable = CounterGuardState::stable(
                        request.counter_scope.token(),
                        guard.reserved_through(),
                        exact_db_anchor,
                    )?;
                    match self
                        .guard
                        .compare_and_swap_guard(&request.counter_scope, Some(guard), stable)
                        .map_err(|_| SignedPublicationError::GuardUnavailable)?
                    {
                        CounterGuardCas::Swapped(persisted) if persisted == stable => {}
                        CounterGuardCas::Swapped(_) | CounterGuardCas::Conflict(_) => {
                            return Err(SignedPublicationError::GuardConflict);
                        }
                    }
                }
                frozen.counter_db_anchor = Some(exact_db_anchor);
                Ok(frozen)
            }
            _ => {
                self.retire_counter(request, Some(guard), &record).await?;
                Err(SignedPublicationError::RetireKey)
            }
        }
    }

    async fn reconcile_gap_if_needed(
        &self,
        request: &SignedPublicationRequest,
        guard: &mut Option<CounterGuardState>,
        database: &mut RemoteCounterRecord,
    ) -> Result<(), SignedPublicationError> {
        let Some(pending) = *guard else {
            return Ok(());
        };
        if pending.phase() != CounterGuardPhase::Pending {
            return Ok(());
        }
        if database.kind == RemoteCounterRecordKind::Gap
            && database.reservation_id == pending.reservation_id()
            && database.publication_id == pending.publication_id()
            && database.reserved_end == pending.reserved_through()
        {
            let stable = CounterGuardState::stable(
                request.counter_scope.token(),
                database.reserved_end,
                database.db_anchor,
            )?;
            self.swap_exact(request.counter_scope, pending, stable)?;
            *guard = Some(stable);
            return Ok(());
        }
        if database.kind.is_retirement_lineage() {
            return Err(SignedPublicationError::RetireKey);
        }
        let db = counter_db_state(database)?;
        match reconcile_counter_recovery(&pending, &db)? {
            CounterRecovery::GuardAheadGap { abandoned_through } => {
                let gap_result = self
                    .store
                    .record_remote_counter_gap(RemoteCounterGapRequest {
                        scope_token: request.counter_scope.token(),
                        key_id: request.key_id,
                        expected_reserved_end: database.reserved_end,
                        expected_db_anchor: database.db_anchor,
                        abandoned_through,
                        reservation_id: pending
                            .reservation_id()
                            .ok_or(SignedPublicationError::RetireKey)?,
                        publication_id: pending
                            .publication_id()
                            .ok_or(SignedPublicationError::RetireKey)?,
                    })
                    .await;
                let gap = match gap_result {
                    Ok(gap) => gap,
                    Err(RuntimeStoreError::InvalidStateTransition)
                        if !self
                            .store
                            .remote_counter_scope_allowed(request.counter_scope.token())
                            .await? =>
                    {
                        return Err(SignedPublicationError::RetireKey);
                    }
                    Err(error) => return Err(error.into()),
                };
                let stable = CounterGuardState::stable(
                    request.counter_scope.token(),
                    gap.reserved_end,
                    gap.db_anchor,
                )?;
                self.swap_exact(request.counter_scope, pending, stable)?;
                *guard = Some(stable);
                *database = gap;
                Ok(())
            }
            CounterRecovery::RetryFrozen { .. } | CounterRecovery::ReserveNextBlock { .. } => {
                self.retire_counter(request, Some(pending), database)
                    .await?;
                Err(SignedPublicationError::RetireKey)
            }
            CounterRecovery::RetireKey => {
                self.retire_counter(request, Some(pending), database)
                    .await?;
                Err(SignedPublicationError::RetireKey)
            }
        }
    }

    async fn retire_counter(
        &self,
        request: &SignedPublicationRequest,
        guard: Option<CounterGuardState>,
        database: &RemoteCounterRecord,
    ) -> Result<(), SignedPublicationError> {
        self.retire_sender_scope(request.counter_scope, request.key_id, guard, database)
            .await
    }

    async fn retire_sender_scope(
        &self,
        scope: CounterScope,
        key_id: KeyId,
        guard: Option<CounterGuardState>,
        database: &RemoteCounterRecord,
    ) -> Result<(), SignedPublicationError> {
        if database.kind.is_retirement_lineage() {
            return Ok(());
        }
        let retired_through = guard
            .filter(|guard| guard.token() == scope.token())
            .map_or(database.reserved_end, |guard| {
                database.reserved_end.max(guard.reserved_through())
            });
        let retired = self
            .store
            .retire_remote_counter(RemoteCounterRetirementRequest {
                scope_token: scope.token(),
                key_id,
                expected_reserved_end: database.reserved_end,
                expected_db_anchor: database.db_anchor,
                retired_through,
            })
            .await?;
        if retired.kind != RemoteCounterRecordKind::Retired {
            return Err(SignedPublicationError::RetireKey);
        }
        Ok(())
    }

    fn swap_exact(
        &self,
        scope: CounterScope,
        expected: CounterGuardState,
        next: CounterGuardState,
    ) -> Result<(), SignedPublicationError> {
        match self
            .guard
            .compare_and_swap_guard(&scope, Some(expected), next)
            .map_err(|_| SignedPublicationError::GuardUnavailable)?
        {
            CounterGuardCas::Swapped(persisted) if persisted == next => Ok(()),
            CounterGuardCas::Swapped(_) | CounterGuardCas::Conflict(_) => {
                Err(SignedPublicationError::GuardConflict)
            }
        }
    }
}

fn validate_stable_head(
    guard: Option<CounterGuardState>,
    database: &RemoteCounterRecord,
) -> Result<(), SignedPublicationError> {
    match guard {
        None if database.kind == RemoteCounterRecordKind::Genesis && database.reserved_end == 0 => {
            Ok(())
        }
        Some(guard)
            if guard.phase() == CounterGuardPhase::Stable
                && guard.token() == database.scope_token
                && guard.reserved_through() == database.reserved_end
                && guard.database_anchor() == database.db_anchor =>
        {
            Ok(())
        }
        _ => Err(SignedPublicationError::RetireKey),
    }
}

fn counter_db_state(record: &RemoteCounterRecord) -> Result<CounterDbState, CounterError> {
    match record.kind {
        RemoteCounterRecordKind::Frozen => CounterDbState::frozen(
            record.scope_token,
            record.reserved_end,
            record.reservation_id.ok_or(CounterError::InvalidState {
                field: "reservation id",
            })?,
            record.publication_id.ok_or(CounterError::InvalidState {
                field: "publication id",
            })?,
            record.db_anchor,
        ),
        RemoteCounterRecordKind::Genesis | RemoteCounterRecordKind::Gap => {
            CounterDbState::unchanged(record.scope_token, record.reserved_end, record.db_anchor)
        }
        RemoteCounterRecordKind::Retired
        | RemoteCounterRecordKind::RecoveryStaged
        | RemoteCounterRecordKind::Recovered => Err(CounterError::InvalidTransition),
    }
}

fn random_reservation_id() -> Result<[u8; 16], SignedPublicationError> {
    let mut reservation = [0_u8; 16];
    getrandom::fill(&mut reservation).map_err(|_| SignedPublicationError::EntropyUnavailable)?;
    reservation[0] |= 0x80;
    Ok(reservation)
}

const fn valid_signed_inner_range(
    after: Option<u64>,
    through: Option<u64>,
    payload: PublicationPayloadKind,
) -> bool {
    match (after, through, payload) {
        (None, None, PublicationPayloadKind::Control)
        | (None, Some(_), PublicationPayloadKind::Event | PublicationPayloadKind::Catalog) => true,
        (
            Some(after),
            Some(through),
            PublicationPayloadKind::Event | PublicationPayloadKind::Catalog,
        ) => after < through,
        _ => false,
    }
}

#[derive(Debug, thiserror::Error)]
pub enum SignedPublicationError {
    #[error("signed publication input is invalid: {0}")]
    Publication(#[from] PublicationError),
    #[error("signed publication counter state is invalid: {0}")]
    Counter(#[from] CounterError),
    #[error("signed publication Store operation failed: {0}")]
    Store(#[from] RuntimeStoreError),
    #[error("signed publication CounterGuard backend is unavailable")]
    GuardUnavailable,
    #[error("signed publication CounterGuard compare-and-swap conflicted")]
    GuardConflict,
    #[error("signed publication id conflicts with an existing frozen row")]
    Conflict,
    #[error("signed publication counter scope must be retired")]
    RetireKey,
    #[error("signed publication reservation entropy is unavailable")]
    EntropyUnavailable,
}

impl SignedPublicationError {
    #[must_use]
    pub const fn code(&self) -> &'static str {
        match self {
            Self::Publication(error) => error.code(),
            Self::Counter(error) => error.code(),
            Self::Store(_) => "daemon.remote.publisher.store_unavailable",
            Self::GuardUnavailable => "daemon.remote.publisher.guard_unavailable",
            Self::GuardConflict => "daemon.remote.publisher.guard_conflict",
            Self::Conflict => "daemon.remote.publisher.conflict",
            Self::RetireKey => "daemon.remote.publisher.retire_key",
            Self::EntropyUnavailable => "daemon.remote.publisher.entropy_unavailable",
        }
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq, thiserror::Error)]
pub enum PublicationError {
    #[error("publication seal axes are invalid")]
    InvalidAxes,
}

impl PublicationError {
    #[must_use]
    pub const fn code(self) -> &'static str {
        match self {
            Self::InvalidAxes => "daemon.remote.publisher.invalid_axes",
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn signed_catalog_publication_accepts_the_same_contiguous_inner_ranges_as_store() {
        assert!(valid_signed_inner_range(
            None,
            Some(0),
            PublicationPayloadKind::Catalog,
        ));
        assert!(valid_signed_inner_range(
            Some(7),
            Some(8),
            PublicationPayloadKind::Catalog,
        ));
        assert!(!valid_signed_inner_range(
            Some(8),
            Some(8),
            PublicationPayloadKind::Catalog,
        ));
        assert!(!valid_signed_inner_range(
            Some(8),
            None,
            PublicationPayloadKind::Catalog,
        ));
    }
}
