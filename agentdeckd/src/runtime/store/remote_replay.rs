//! Runtime v11 authenticated remote replay/counter state。
//!
//! replay scope、counter→ciphertext hash window 与 retention pins 只存在于 row AEAD
//! plaintext；SQLite 主键是 scope 的 blind-index token。所有外露 GC 投影同时受行
//! metadata token 和 RuntimeLedger totals 认证，离线删行、换行或改字段会在 full open
//! audit 中 fail-close。

use std::collections::{BTreeMap, BTreeSet};

use agentdeck_protocol::e2ee::KeyPurpose;
use agentdeck_protocol::relay_v2::{DeviceRouteId, StreamRouteId};
use rusqlite::{OptionalExtension, Transaction, TransactionBehavior, params};
use sha2::{Digest, Sha256};
use zeroize::{Zeroize, Zeroizing};

use crate::runtime::model::{RuntimeStoreConfig, RuntimeStoreError};

use super::cipher::{ROW_BLOB_V1_OVERHEAD_LEN, RowAad, RuntimeKeyBundle};
use super::schema::{RUNTIME_CRYPTO_CONTEXT_VERSION, RUNTIME_SCHEMA_FAMILY};
use super::sqlite::{RuntimeLedger, RuntimeSqlite, SafetyReserveProjection};
use super::{RetiredKeyOwnerKind, RetiredSharedKeyOwner};

pub(crate) const REMOTE_REPLAY_SCOPE_BYTES: usize = 58;
pub(crate) const REMOTE_REPLAY_WINDOW: u64 = 4_096;
pub(crate) const REMOTE_REPLAY_RETENTION_MS: u64 = 25 * 60 * 60 * 1_000;
pub(crate) const MAX_REMOTE_REPLAY_SCOPES: u64 = 4_096;
const MAX_REPLAY_PINS_PER_SCOPE: usize = 4_096;
const MAX_REPLAY_PLAINTEXT_BYTES: usize = 256 * 1024;
const MAX_REPLAY_SEALED_BYTES: u64 = 1024 * 1024 * 1024;
const MAX_REPLAY_PIN_COUNT: u64 = 1_048_576;
const REPLAY_TABLE: &[u8] = b"remote_replay_states";
const REPLAY_COLUMN: &[u8] = b"sealed_state";
const REPLAY_SCOPE_DOMAIN: &[u8] = b"runtime.remote.replay.scope.v1";
const REPLAY_METADATA_DOMAIN: &[u8] = b"runtime.remote.replay.metadata.v1";
const COUNTER_METADATA_DOMAIN: &[u8] = b"runtime.remote.counter.metadata.v1";
const REPLAY_STATE_MAGIC: &[u8; 4] = b"ADRW";
const REPLAY_STATE_VERSION: u8 = 2;
const DEVICE_COMMAND_PURPOSE: u8 = 1;
const DEVICE_REPLY_PURPOSE: u8 = 2;
const CONVERSATION_PURPOSE: u8 = 3;
const CATALOG_PURPOSE: u8 = 4;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum RemoteReplayStoreDecision {
    Fresh,
    ExactDuplicate,
    Stale,
    NonceReuse,
    Retired,
    Capacity,
}

#[derive(Clone, Copy)]
pub(crate) struct RemoteReplayAdmission {
    pub scope: [u8; REMOTE_REPLAY_SCOPE_BYTES],
    pub sender_counter: u64,
    pub ciphertext_sha256: [u8; 32],
    pub scope_capacity: u64,
}

struct ReplayState {
    scope: [u8; REMOTE_REPLAY_SCOPE_BYTES],
    high_water: u64,
    entries: BTreeMap<u64, [u8; 32]>,
    retired_at_ms: Option<u64>,
    nonce_reuse_quarantine: bool,
    pins: BTreeSet<[u8; 16]>,
}

impl Drop for ReplayState {
    fn drop(&mut self) {
        self.scope.zeroize();
        for hash in self.entries.values_mut() {
            hash.zeroize();
        }
        for pin in std::mem::take(&mut self.pins) {
            let mut pin = pin;
            pin.zeroize();
        }
    }
}

impl ReplayState {
    fn fresh(
        scope: [u8; REMOTE_REPLAY_SCOPE_BYTES],
        counter: u64,
        hash: [u8; 32],
    ) -> Result<Self, RuntimeStoreError> {
        validate_scope(&scope)?;
        let mut entries = BTreeMap::new();
        entries.insert(counter, hash);
        Ok(Self {
            scope,
            high_water: counter,
            entries,
            retired_at_ms: None,
            nonce_reuse_quarantine: false,
            pins: BTreeSet::new(),
        })
    }

    fn floor(&self) -> u64 {
        self.high_water.saturating_sub(REMOTE_REPLAY_WINDOW - 1)
    }

    fn observe(&mut self, counter: u64, hash: [u8; 32]) -> RemoteReplayStoreDecision {
        if counter < self.floor() {
            return RemoteReplayStoreDecision::Stale;
        }
        if let Some(existing) = self.entries.get(&counter) {
            return if existing == &hash {
                RemoteReplayStoreDecision::ExactDuplicate
            } else {
                RemoteReplayStoreDecision::NonceReuse
            };
        }
        if counter > self.high_water {
            self.high_water = counter;
            let floor = self.floor();
            self.entries.retain(|observed, _| *observed >= floor);
        }
        self.entries.insert(counter, hash);
        RemoteReplayStoreDecision::Fresh
    }

    fn validate(&self) -> Result<(), RuntimeStoreError> {
        validate_scope(&self.scope)?;
        if self.entries.is_empty()
            || self.entries.len() > REMOTE_REPLAY_WINDOW as usize
            || self.pins.len() > MAX_REPLAY_PINS_PER_SCOPE
            || !self.entries.contains_key(&self.high_water)
            || self
                .entries
                .keys()
                .any(|counter| *counter < self.floor() || *counter > self.high_water)
            || self.pins.iter().any(|pin| pin == &[0; 16])
            || (!self.pins.is_empty() && self.retired_at_ms.is_none())
            || (self.nonce_reuse_quarantine && self.retired_at_ms.is_none())
        {
            return Err(RuntimeStoreError::UnknownOrCorruptSchema);
        }
        Ok(())
    }

    fn encode(&self) -> Result<Zeroizing<Vec<u8>>, RuntimeStoreError> {
        self.validate()?;
        let entry_count =
            u32::try_from(self.entries.len()).map_err(|_| RuntimeStoreError::PayloadTooLarge)?;
        let pin_count =
            u32::try_from(self.pins.len()).map_err(|_| RuntimeStoreError::PayloadTooLarge)?;
        let mut encoded = Zeroizing::new(Vec::with_capacity(
            4 + 1
                + REMOTE_REPLAY_SCOPE_BYTES
                + 8
                + 1
                + 8
                + 1
                + 4
                + self.entries.len() * 40
                + 4
                + self.pins.len() * 16,
        ));
        encoded.extend_from_slice(REPLAY_STATE_MAGIC);
        encoded.push(REPLAY_STATE_VERSION);
        encoded.extend_from_slice(&self.scope);
        encoded.extend_from_slice(&self.high_water.to_be_bytes());
        match self.retired_at_ms {
            None => encoded.push(0),
            Some(retired_at_ms) => {
                encoded.push(1);
                encoded.extend_from_slice(&retired_at_ms.to_be_bytes());
            }
        }
        encoded.push(u8::from(self.nonce_reuse_quarantine));
        encoded.extend_from_slice(&entry_count.to_be_bytes());
        for (counter, hash) in &self.entries {
            encoded.extend_from_slice(&counter.to_be_bytes());
            encoded.extend_from_slice(hash);
        }
        encoded.extend_from_slice(&pin_count.to_be_bytes());
        for pin in &self.pins {
            encoded.extend_from_slice(pin);
        }
        if encoded.len() > MAX_REPLAY_PLAINTEXT_BYTES {
            return Err(RuntimeStoreError::PayloadTooLarge);
        }
        Ok(encoded)
    }

    fn decode(encoded: &[u8]) -> Result<Self, RuntimeStoreError> {
        let mut decoder = ReplayDecoder::new(encoded);
        if decoder.take(4)? != REPLAY_STATE_MAGIC || decoder.u8()? != REPLAY_STATE_VERSION {
            return Err(RuntimeStoreError::UnknownOrCorruptSchema);
        }
        let scope = decoder.fixed()?;
        let high_water = decoder.u64()?;
        let retired_at_ms = match decoder.u8()? {
            0 => None,
            1 => Some(decoder.u64()?),
            _ => return Err(RuntimeStoreError::UnknownOrCorruptSchema),
        };
        let nonce_reuse_quarantine = match decoder.u8()? {
            0 => false,
            1 => true,
            _ => return Err(RuntimeStoreError::UnknownOrCorruptSchema),
        };
        let entry_count = decoder.u32()? as usize;
        if entry_count == 0 || entry_count > REMOTE_REPLAY_WINDOW as usize {
            return Err(RuntimeStoreError::UnknownOrCorruptSchema);
        }
        let mut entries = BTreeMap::new();
        for _ in 0..entry_count {
            let counter = decoder.u64()?;
            let hash = decoder.fixed()?;
            if entries.insert(counter, hash).is_some() {
                return Err(RuntimeStoreError::UnknownOrCorruptSchema);
            }
        }
        let pin_count = decoder.u32()? as usize;
        if pin_count > MAX_REPLAY_PINS_PER_SCOPE {
            return Err(RuntimeStoreError::UnknownOrCorruptSchema);
        }
        let mut pins = BTreeSet::new();
        for _ in 0..pin_count {
            if !pins.insert(decoder.fixed()?) {
                return Err(RuntimeStoreError::UnknownOrCorruptSchema);
            }
        }
        if !decoder.is_finished() {
            return Err(RuntimeStoreError::UnknownOrCorruptSchema);
        }
        let state = Self {
            scope,
            high_water,
            entries,
            retired_at_ms,
            nonce_reuse_quarantine,
            pins,
        };
        state.validate()?;
        if state.encode()?.as_slice() != encoded {
            return Err(RuntimeStoreError::UnknownOrCorruptSchema);
        }
        Ok(state)
    }
}

struct ReplayDecoder<'a> {
    bytes: &'a [u8],
    offset: usize,
}

impl<'a> ReplayDecoder<'a> {
    const fn new(bytes: &'a [u8]) -> Self {
        Self { bytes, offset: 0 }
    }

    fn take(&mut self, count: usize) -> Result<&'a [u8], RuntimeStoreError> {
        let end = self
            .offset
            .checked_add(count)
            .ok_or(RuntimeStoreError::UnknownOrCorruptSchema)?;
        let value = self
            .bytes
            .get(self.offset..end)
            .ok_or(RuntimeStoreError::UnknownOrCorruptSchema)?;
        self.offset = end;
        Ok(value)
    }

    fn fixed<const N: usize>(&mut self) -> Result<[u8; N], RuntimeStoreError> {
        self.take(N)?
            .try_into()
            .map_err(|_| RuntimeStoreError::UnknownOrCorruptSchema)
    }

    fn u8(&mut self) -> Result<u8, RuntimeStoreError> {
        Ok(self.take(1)?[0])
    }

    fn u32(&mut self) -> Result<u32, RuntimeStoreError> {
        Ok(u32::from_be_bytes(self.fixed()?))
    }

    fn u64(&mut self) -> Result<u64, RuntimeStoreError> {
        Ok(u64::from_be_bytes(self.fixed()?))
    }

    fn is_finished(&self) -> bool {
        self.offset == self.bytes.len()
    }
}

struct AuthenticatedReplayRow {
    scope_token: [u8; 32],
    retired_at_ms: Option<u64>,
    sealed_bytes: u64,
    metadata_token: [u8; 32],
    pin_count: u64,
    state: ReplayState,
}

struct ReplayRowProjection {
    scope_token: [u8; 32],
    retired_at_ms: Option<u64>,
    sealed_bytes: u64,
    metadata_token: [u8; 32],
    pin_count: u64,
}

impl AuthenticatedReplayRow {
    fn into_projection_and_state(
        self,
    ) -> Result<(ReplayRowProjection, ReplayState), RuntimeStoreError> {
        Ok((
            ReplayRowProjection {
                scope_token: self.scope_token,
                retired_at_ms: self.retired_at_ms,
                sealed_bytes: self.sealed_bytes,
                metadata_token: self.metadata_token,
                pin_count: self.pin_count,
            },
            self.state,
        ))
    }
}

struct RawReplayRow {
    scope_token: Vec<u8>,
    database_id: Vec<u8>,
    retired_at_ms: Option<i64>,
    sealed_state: Vec<u8>,
    sealed_state_bytes: i64,
    metadata_token: Vec<u8>,
}

pub(crate) fn admit(
    state: &mut RuntimeSqlite,
    config: &RuntimeStoreConfig,
    input: RemoteReplayAdmission,
) -> Result<RemoteReplayStoreDecision, RuntimeStoreError> {
    validate_scope(&input.scope)?;
    let capacity = input.scope_capacity.min(MAX_REMOTE_REPLAY_SCOPES);
    let scope_token = replay_scope_token(&state.key_bundle, &input.scope)?;
    let current = load_replay_by_token(
        &state.connection,
        &state.key_bundle,
        state.database_id,
        scope_token,
    )?;
    if current.is_none() {
        let ledger = super::sqlite::load_runtime_ledger(
            &state.connection,
            &state.key_bundle,
            state.database_id,
        )?;
        if capacity == 0 || ledger.remote_replay_scope_count >= capacity {
            return Ok(RemoteReplayStoreDecision::Capacity);
        }
        let next = ReplayState::fresh(input.scope, input.sender_counter, input.ciphertext_sha256)?;
        persist_replay_state(state, config, None, next)?;
        return Ok(RemoteReplayStoreDecision::Fresh);
    }

    let mut current = current.expect("checked above");
    if current.state.scope != input.scope {
        return Err(RuntimeStoreError::UnknownOrCorruptSchema);
    }
    if current.state.retired_at_ms.is_some() {
        return Ok(RemoteReplayStoreDecision::Retired);
    }
    let decision = current
        .state
        .observe(input.sender_counter, input.ciphertext_sha256);
    match decision {
        RemoteReplayStoreDecision::Fresh => {
            let (previous, next) = current.into_projection_and_state()?;
            persist_replay_state(state, config, Some(previous), next)?;
        }
        RemoteReplayStoreDecision::NonceReuse => {
            current.state.retired_at_ms = Some(config.clock.now_ms()?);
            current.state.nonce_reuse_quarantine = true;
            let (previous, next) = current.into_projection_and_state()?;
            persist_replay_state(state, config, Some(previous), next)?;
        }
        RemoteReplayStoreDecision::ExactDuplicate
        | RemoteReplayStoreDecision::Stale
        | RemoteReplayStoreDecision::Retired
        | RemoteReplayStoreDecision::Capacity => {}
    }
    Ok(decision)
}

pub(crate) fn contains_scope(
    state: &RuntimeSqlite,
    scope: [u8; REMOTE_REPLAY_SCOPE_BYTES],
) -> Result<bool, RuntimeStoreError> {
    validate_scope(&scope)?;
    let token = replay_scope_token(&state.key_bundle, &scope)?;
    Ok(load_replay_by_token(
        &state.connection,
        &state.key_bundle,
        state.database_id,
        token,
    )?
    .is_some_and(|row| row.state.scope == scope))
}

pub(crate) fn retire_scope(
    state: &mut RuntimeSqlite,
    config: &RuntimeStoreConfig,
    scope: [u8; REMOTE_REPLAY_SCOPE_BYTES],
    retired_at_ms: u64,
) -> Result<(), RuntimeStoreError> {
    let mut current = required_replay_row(state, scope)?;
    match current.state.retired_at_ms {
        Some(existing) if existing == retired_at_ms => return Ok(()),
        Some(_) => return Err(RuntimeStoreError::InvalidStateTransition),
        None => current.state.retired_at_ms = Some(retired_at_ms),
    }
    persist_mutated_replay_state(state, config, current)
}

/// 在调用方已持有的 membership/transition transaction 内退役 scope。
///
/// 从未观测到的 scope 视为成功；已被 nonce quarantine 或先前重试退役的
/// scope 也只读成功，不覆盖首次 durable retirement time。
pub(super) fn retire_scope_if_present_in_transaction(
    transaction: &Transaction<'_>,
    key_bundle: &RuntimeKeyBundle,
    database_id: [u8; 16],
    next_ledger: &mut RuntimeLedger,
    scope: [u8; REMOTE_REPLAY_SCOPE_BYTES],
    retired_at_ms: u64,
) -> Result<bool, RuntimeStoreError> {
    validate_scope(&scope)?;
    if retired_at_ms == 0 {
        return Err(RuntimeStoreError::TimeOutOfRange);
    }
    let scope_token = replay_scope_token(key_bundle, &scope)?;
    let Some(mut current) =
        load_replay_by_token(transaction, key_bundle, database_id, scope_token)?
    else {
        return Ok(false);
    };
    if current.state.scope != scope {
        return Err(RuntimeStoreError::UnknownOrCorruptSchema);
    }
    if current.state.retired_at_ms.is_none() {
        current.state.retired_at_ms = Some(retired_at_ms);
        let (previous, next) = current.into_projection_and_state()?;
        persist_replay_state_in_transaction(
            transaction,
            key_bundle,
            database_id,
            Some(previous),
            next,
            next_ledger,
        )?;
    }
    Ok(true)
}

pub(crate) fn pin_retired_scope(
    state: &mut RuntimeSqlite,
    config: &RuntimeStoreConfig,
    scope: [u8; REMOTE_REPLAY_SCOPE_BYTES],
    pin_id: [u8; 16],
) -> Result<(), RuntimeStoreError> {
    if pin_id == [0; 16] {
        return Err(RuntimeStoreError::InvalidConfig(
            "remote replay retention pin must be non-zero",
        ));
    }
    persist_retired_pin_and_shared_owner(state, config, scope, pin_id, true)
}

pub(crate) fn release_retired_pin(
    state: &mut RuntimeSqlite,
    config: &RuntimeStoreConfig,
    scope: [u8; REMOTE_REPLAY_SCOPE_BYTES],
    pin_id: [u8; 16],
) -> Result<(), RuntimeStoreError> {
    if pin_id == [0; 16] {
        return Err(RuntimeStoreError::InvalidConfig(
            "remote replay retention pin must be non-zero",
        ));
    }
    persist_retired_pin_and_shared_owner(state, config, scope, pin_id, false)
}

fn persist_retired_pin_and_shared_owner(
    state: &mut RuntimeSqlite,
    config: &RuntimeStoreConfig,
    scope: [u8; REMOTE_REPLAY_SCOPE_BYTES],
    pin_id: [u8; 16],
    acquire: bool,
) -> Result<(), RuntimeStoreError> {
    validate_scope(&scope)?;
    super::sqlite::admit_ordinary_write(
        &state.connection,
        &state.key_bundle,
        state.database_id,
        &state.storage_path,
        &mut state.admission_state,
        config.capacity_probe.as_ref(),
        MAX_REPLAY_PLAINTEXT_BYTES as u64 + ROW_BLOB_V1_OVERHEAD_LEN as u64,
        SafetyReserveProjection::Current,
    )?;
    let key_bundle = state.key_bundle.clone();
    let database_id = state.database_id;
    let transaction = state
        .connection
        .transaction_with_behavior(TransactionBehavior::Immediate)?;
    let scope_token = replay_scope_token(&key_bundle, &scope)?;
    let mut current = load_replay_by_token(&transaction, &key_bundle, database_id, scope_token)?
        .ok_or(RuntimeStoreError::InvalidStateTransition)?;
    if current.state.scope != scope {
        return Err(RuntimeStoreError::UnknownOrCorruptSchema);
    }
    if current.state.retired_at_ms.is_none() {
        return Err(RuntimeStoreError::InvalidStateTransition);
    }
    let ledger = super::sqlite::load_runtime_ledger(&transaction, &key_bundle, database_id)?;
    let mut next_ledger = ledger.clone();
    let replay_changed = if acquire {
        if current.state.pins.contains(&pin_id) {
            false
        } else {
            if current.state.pins.len() >= MAX_REPLAY_PINS_PER_SCOPE {
                return Err(RuntimeStoreError::StoreFull {
                    projected_footprint_bytes: MAX_REPLAY_PINS_PER_SCOPE as u64 + 1,
                    hard_limit_bytes: MAX_REPLAY_PINS_PER_SCOPE as u64,
                });
            }
            current.state.pins.insert(pin_id);
            true
        }
    } else {
        current.state.pins.remove(&pin_id)
    };
    if replay_changed {
        let (previous, next) = current.into_projection_and_state()?;
        persist_replay_state_in_transaction(
            &transaction,
            &key_bundle,
            database_id,
            Some(previous),
            next,
            &mut next_ledger,
        )?;
    }

    let owner_changed = if let Some(owner) = replay_retention_owner(scope, pin_id)? {
        let outcome = if acquire {
            super::retired_key::acquire_owner_in_transaction(
                &transaction,
                &key_bundle,
                database_id,
                &ledger,
                &mut next_ledger,
                owner,
            )?
        } else {
            // The replay pin is removed first in this same transaction; a crash can therefore
            // expose neither a released owner with a live pin nor an orphan owner.
            super::retired_key::release_owner_in_transaction(
                &transaction,
                &key_bundle,
                database_id,
                &ledger,
                &mut next_ledger,
                owner,
            )?
        };
        outcome == super::retired_key::RetiredKeyMutationOutcome::Applied
    } else {
        false
    };
    if !replay_changed && !owner_changed {
        return Ok(());
    }
    let _ = super::sqlite::update_runtime_ledger(
        &transaction,
        &key_bundle,
        database_id,
        &ledger,
        &next_ledger,
    )?;
    transaction.commit()?;
    super::sqlite::latch_post_commit_capacity(state, config);
    Ok(())
}

pub(crate) fn gc_retired(
    state: &mut RuntimeSqlite,
    config: &RuntimeStoreConfig,
    now_ms: u64,
) -> Result<u64, RuntimeStoreError> {
    super::sqlite::admit_ordinary_write(
        &state.connection,
        &state.key_bundle,
        state.database_id,
        &state.storage_path,
        &mut state.admission_state,
        config.capacity_probe.as_ref(),
        MAX_REPLAY_PLAINTEXT_BYTES as u64 + ROW_BLOB_V1_OVERHEAD_LEN as u64,
        SafetyReserveProjection::Current,
    )?;
    let key_bundle = state.key_bundle.clone();
    let database_id = state.database_id;
    let transaction = state
        .connection
        .transaction_with_behavior(TransactionBehavior::Immediate)?;
    let cutoff = now_ms.saturating_sub(REMOTE_REPLAY_RETENTION_MS);
    let tokens = replay_tokens_retired_through(&transaction, cutoff)?;
    let ledger = super::sqlite::load_runtime_ledger(&transaction, &key_bundle, database_id)?;
    let global_keys =
        super::pairing_grant::load_global_key_state(&transaction, &key_bundle, database_id)?;
    let authorizations =
        super::pairing_authorization::load_authorizations(&transaction, &key_bundle, database_id)?;
    let mut next_ledger = ledger.clone();
    let mut deleted = 0_u64;
    for token in tokens {
        let Some(row) = load_replay_by_token(&transaction, &key_bundle, database_id, token)? else {
            return Err(RuntimeStoreError::SchemaInspectionRaced);
        };
        let Some(retired_at_ms) = row.state.retired_at_ms else {
            return Err(RuntimeStoreError::UnknownOrCorruptSchema);
        };
        // nonce reuse 表明该 sender epoch 已发生密钥/计数器安全故障。普通 25h retention
        // 不能让同一 scope 在 key rotation、grant revoke 或 trust reset 尚未完成时重新变成
        // fresh。只有 authenticated key directory/authorization 已证明旧 scope 不再是
        // active sender，且 transition 已越过 pre-barrier fence，才允许同一 GC 事务删除
        // quarantine；否则容量耗尽也继续 fail-close。
        let quarantine_repaired = if row.state.nonce_reuse_quarantine {
            nonce_reuse_quarantine_has_canonical_repair(
                &transaction,
                &key_bundle,
                database_id,
                &row.state,
                global_keys.as_ref(),
                &authorizations,
            )?
        } else {
            true
        };
        if retired_at_ms > cutoff || !quarantine_repaired || !row.state.pins.is_empty() {
            continue;
        }
        if transaction.execute(
            "DELETE FROM remote_replay_states WHERE scope_token = ?1 AND metadata_token = ?2",
            params![&row.scope_token[..], &row.metadata_token[..]],
        )? != 1
        {
            return Err(RuntimeStoreError::SchemaInspectionRaced);
        }
        let (projection, _state) = row.into_projection_and_state()?;
        subtract_row_totals(&mut next_ledger, &projection)?;
        deleted = deleted
            .checked_add(1)
            .ok_or(RuntimeStoreError::UnknownOrCorruptSchema)?;
    }
    if deleted == 0 {
        return Ok(0);
    }
    let _ = super::sqlite::update_runtime_ledger(
        &transaction,
        &key_bundle,
        database_id,
        &ledger,
        &next_ledger,
    )?;
    transaction.commit()?;
    super::sqlite::latch_post_commit_capacity(state, config);
    Ok(deleted)
}

fn persist_mutated_replay_state(
    state: &mut RuntimeSqlite,
    config: &RuntimeStoreConfig,
    current: AuthenticatedReplayRow,
) -> Result<(), RuntimeStoreError> {
    let (previous, next) = current.into_projection_and_state()?;
    persist_replay_state(state, config, Some(previous), next)
}

fn persist_replay_state(
    state: &mut RuntimeSqlite,
    config: &RuntimeStoreConfig,
    previous: Option<ReplayRowProjection>,
    next: ReplayState,
) -> Result<(), RuntimeStoreError> {
    super::sqlite::admit_ordinary_write(
        &state.connection,
        &state.key_bundle,
        state.database_id,
        &state.storage_path,
        &mut state.admission_state,
        config.capacity_probe.as_ref(),
        MAX_REPLAY_PLAINTEXT_BYTES as u64 + ROW_BLOB_V1_OVERHEAD_LEN as u64,
        SafetyReserveProjection::Current,
    )?;
    let key_bundle = state.key_bundle.clone();
    let database_id = state.database_id;
    let transaction = state
        .connection
        .transaction_with_behavior(TransactionBehavior::Immediate)?;
    let ledger = super::sqlite::load_runtime_ledger(&transaction, &key_bundle, database_id)?;
    let mut next_ledger = ledger.clone();
    persist_replay_state_in_transaction(
        &transaction,
        &key_bundle,
        database_id,
        previous,
        next,
        &mut next_ledger,
    )?;
    let _ = super::sqlite::update_runtime_ledger(
        &transaction,
        &key_bundle,
        database_id,
        &ledger,
        &next_ledger,
    )?;
    transaction.commit()?;
    super::sqlite::latch_post_commit_capacity(state, config);
    Ok(())
}

fn persist_replay_state_in_transaction(
    transaction: &Transaction<'_>,
    key_bundle: &RuntimeKeyBundle,
    database_id: [u8; 16],
    previous: Option<ReplayRowProjection>,
    next: ReplayState,
    next_ledger: &mut RuntimeLedger,
) -> Result<(), RuntimeStoreError> {
    let scope_token = replay_scope_token(key_bundle, &next.scope)?;
    if previous
        .as_ref()
        .is_some_and(|row| row.scope_token != scope_token)
    {
        return Err(RuntimeStoreError::UnknownOrCorruptSchema);
    }
    let encoded = next.encode()?;
    let sealed = seal_state(
        key_bundle,
        database_id,
        REPLAY_TABLE,
        &scope_token,
        REPLAY_COLUMN,
        encoded.as_ref(),
    )?;
    let sealed_bytes =
        u64::try_from(sealed.len()).map_err(|_| RuntimeStoreError::PayloadTooLarge)?;
    let metadata_token = replay_metadata_token(
        key_bundle,
        database_id,
        scope_token,
        next.retired_at_ms,
        &sealed,
    )?;
    let changed = match &previous {
        None => transaction.execute(
            "INSERT INTO remote_replay_states (
                 scope_token, database_id, retired_at_ms, sealed_state,
                 sealed_state_bytes, metadata_token
             ) VALUES (?1, ?2, ?3, ?4, ?5, ?6)",
            params![
                &scope_token[..],
                &database_id[..],
                optional_i64(next.retired_at_ms)?,
                &sealed,
                i64::try_from(sealed_bytes).map_err(|_| RuntimeStoreError::PayloadTooLarge)?,
                &metadata_token[..],
            ],
        )?,
        Some(previous) => transaction.execute(
            "UPDATE remote_replay_states
             SET retired_at_ms = ?1, sealed_state = ?2, sealed_state_bytes = ?3,
                 metadata_token = ?4
             WHERE scope_token = ?5 AND metadata_token = ?6",
            params![
                optional_i64(next.retired_at_ms)?,
                &sealed,
                i64::try_from(sealed_bytes).map_err(|_| RuntimeStoreError::PayloadTooLarge)?,
                &metadata_token[..],
                &scope_token[..],
                &previous.metadata_token[..],
            ],
        )?,
    };
    if changed != 1 {
        return Err(RuntimeStoreError::SchemaInspectionRaced);
    }
    if let Some(previous) = &previous {
        subtract_row_totals(next_ledger, previous)?;
    }
    add_state_totals(next_ledger, &next, sealed_bytes)?;
    Ok(())
}

fn required_replay_row(
    state: &RuntimeSqlite,
    scope: [u8; REMOTE_REPLAY_SCOPE_BYTES],
) -> Result<AuthenticatedReplayRow, RuntimeStoreError> {
    validate_scope(&scope)?;
    let token = replay_scope_token(&state.key_bundle, &scope)?;
    let row = load_replay_by_token(
        &state.connection,
        &state.key_bundle,
        state.database_id,
        token,
    )?
    .ok_or(RuntimeStoreError::InvalidStateTransition)?;
    if row.state.scope != scope {
        return Err(RuntimeStoreError::UnknownOrCorruptSchema);
    }
    Ok(row)
}

fn replay_tokens_retired_through(
    transaction: &Transaction<'_>,
    cutoff: u64,
) -> Result<Vec<[u8; 32]>, RuntimeStoreError> {
    let cutoff = i64::try_from(cutoff).unwrap_or(i64::MAX);
    let mut statement = transaction.prepare(
        "SELECT scope_token FROM remote_replay_states
         WHERE retired_at_ms IS NOT NULL AND retired_at_ms <= ?1
         ORDER BY retired_at_ms, scope_token",
    )?;
    let mut rows = statement.query([cutoff])?;
    let mut tokens = Vec::new();
    while let Some(row) = rows.next()? {
        tokens.push(fixed(row.get(0)?)?);
        if tokens.len() > MAX_REMOTE_REPLAY_SCOPES as usize {
            return Err(RuntimeStoreError::UnknownOrCorruptSchema);
        }
    }
    Ok(tokens)
}

fn load_replay_by_token(
    connection: &rusqlite::Connection,
    key_bundle: &RuntimeKeyBundle,
    database_id: [u8; 16],
    scope_token: [u8; 32],
) -> Result<Option<AuthenticatedReplayRow>, RuntimeStoreError> {
    let raw = connection
        .query_row(
            "SELECT scope_token, database_id, retired_at_ms, sealed_state,
                    sealed_state_bytes, metadata_token
             FROM remote_replay_states WHERE scope_token = ?1",
            [&scope_token[..]],
            |row| {
                Ok(RawReplayRow {
                    scope_token: row.get(0)?,
                    database_id: row.get(1)?,
                    retired_at_ms: row.get(2)?,
                    sealed_state: row.get(3)?,
                    sealed_state_bytes: row.get(4)?,
                    metadata_token: row.get(5)?,
                })
            },
        )
        .optional()?;
    raw.map(|raw| authenticate_replay_row(key_bundle, database_id, raw))
        .transpose()
}

fn authenticate_replay_row(
    key_bundle: &RuntimeKeyBundle,
    expected_database_id: [u8; 16],
    raw: RawReplayRow,
) -> Result<AuthenticatedReplayRow, RuntimeStoreError> {
    let scope_token = fixed(raw.scope_token)?;
    let database_id = fixed(raw.database_id)?;
    let retired_at_ms = raw.retired_at_ms.map(nonnegative).transpose()?;
    let sealed_bytes = nonnegative(raw.sealed_state_bytes)?;
    let metadata_token = fixed(raw.metadata_token)?;
    if database_id != expected_database_id
        || sealed_bytes != u64::try_from(raw.sealed_state.len()).unwrap_or(u64::MAX)
        || metadata_token
            != replay_metadata_token(
                key_bundle,
                database_id,
                scope_token,
                retired_at_ms,
                &raw.sealed_state,
            )?
    {
        return Err(RuntimeStoreError::UnknownOrCorruptSchema);
    }
    let plaintext = open_state(
        key_bundle,
        database_id,
        REPLAY_TABLE,
        &scope_token,
        REPLAY_COLUMN,
        &raw.sealed_state,
    )?;
    let state = ReplayState::decode(plaintext.expose_secret())?;
    if state.retired_at_ms != retired_at_ms
        || replay_scope_token(key_bundle, &state.scope)? != scope_token
    {
        return Err(RuntimeStoreError::UnknownOrCorruptSchema);
    }
    let pin_count =
        u64::try_from(state.pins.len()).map_err(|_| RuntimeStoreError::UnknownOrCorruptSchema)?;
    Ok(AuthenticatedReplayRow {
        scope_token,
        retired_at_ms,
        sealed_bytes,
        metadata_token,
        pin_count,
        state,
    })
}

fn add_state_totals(
    ledger: &mut RuntimeLedger,
    state: &ReplayState,
    sealed_bytes: u64,
) -> Result<(), RuntimeStoreError> {
    ledger.remote_replay_scope_count = ledger
        .remote_replay_scope_count
        .checked_add(1)
        .ok_or(RuntimeStoreError::UnknownOrCorruptSchema)?;
    if state.retired_at_ms.is_some() {
        ledger.remote_replay_retired_scope_count = ledger
            .remote_replay_retired_scope_count
            .checked_add(1)
            .ok_or(RuntimeStoreError::UnknownOrCorruptSchema)?;
    }
    ledger.remote_replay_pin_count = ledger
        .remote_replay_pin_count
        .checked_add(
            u64::try_from(state.pins.len())
                .map_err(|_| RuntimeStoreError::UnknownOrCorruptSchema)?,
        )
        .ok_or(RuntimeStoreError::UnknownOrCorruptSchema)?;
    ledger.remote_replay_sealed_bytes = ledger
        .remote_replay_sealed_bytes
        .checked_add(sealed_bytes)
        .ok_or(RuntimeStoreError::UnknownOrCorruptSchema)?;
    if ledger.remote_replay_scope_count > MAX_REMOTE_REPLAY_SCOPES
        || ledger.remote_replay_pin_count > MAX_REPLAY_PIN_COUNT
        || ledger.remote_replay_sealed_bytes > MAX_REPLAY_SEALED_BYTES
    {
        return Err(RuntimeStoreError::UnknownOrCorruptSchema);
    }
    Ok(())
}

fn subtract_row_totals(
    ledger: &mut RuntimeLedger,
    row: &ReplayRowProjection,
) -> Result<(), RuntimeStoreError> {
    ledger.remote_replay_scope_count = ledger
        .remote_replay_scope_count
        .checked_sub(1)
        .ok_or(RuntimeStoreError::UnknownOrCorruptSchema)?;
    if row.retired_at_ms.is_some() {
        ledger.remote_replay_retired_scope_count = ledger
            .remote_replay_retired_scope_count
            .checked_sub(1)
            .ok_or(RuntimeStoreError::UnknownOrCorruptSchema)?;
    }
    ledger.remote_replay_pin_count = ledger
        .remote_replay_pin_count
        .checked_sub(row.pin_count)
        .ok_or(RuntimeStoreError::UnknownOrCorruptSchema)?;
    ledger.remote_replay_sealed_bytes = ledger
        .remote_replay_sealed_bytes
        .checked_sub(row.sealed_bytes)
        .ok_or(RuntimeStoreError::UnknownOrCorruptSchema)?;
    Ok(())
}

pub(crate) fn validate_v11_integrity(
    connection: &rusqlite::Connection,
    key_bundle: &RuntimeKeyBundle,
    database_id: [u8; 16],
    ledger: &RuntimeLedger,
) -> Result<(), RuntimeStoreError> {
    let mut statement = connection.prepare(
        "SELECT scope_token, database_id, retired_at_ms, sealed_state,
                sealed_state_bytes, metadata_token
         FROM remote_replay_states ORDER BY scope_token",
    )?;
    let mut rows = statement.query([])?;
    let mut scope_count = 0_u64;
    let mut retired_count = 0_u64;
    let mut pin_count = 0_u64;
    let mut sealed_bytes = 0_u64;
    while let Some(row) = rows.next()? {
        let authenticated = authenticate_replay_row(
            key_bundle,
            database_id,
            RawReplayRow {
                scope_token: row.get(0)?,
                database_id: row.get(1)?,
                retired_at_ms: row.get(2)?,
                sealed_state: row.get(3)?,
                sealed_state_bytes: row.get(4)?,
                metadata_token: row.get(5)?,
            },
        )?;
        scope_count = checked_add(scope_count, 1)?;
        retired_count = checked_add(
            retired_count,
            u64::from(authenticated.retired_at_ms.is_some()),
        )?;
        pin_count = checked_add(
            pin_count,
            u64::try_from(authenticated.state.pins.len())
                .map_err(|_| RuntimeStoreError::UnknownOrCorruptSchema)?,
        )?;
        sealed_bytes = checked_add(sealed_bytes, authenticated.sealed_bytes)?;
    }
    if scope_count != ledger.remote_replay_scope_count
        || retired_count != ledger.remote_replay_retired_scope_count
        || pin_count != ledger.remote_replay_pin_count
        || sealed_bytes != ledger.remote_replay_sealed_bytes
    {
        return Err(RuntimeStoreError::UnknownOrCorruptSchema);
    }
    validate_counter_integrity(connection, key_bundle, database_id, ledger)
}

fn validate_counter_integrity(
    connection: &rusqlite::Connection,
    key_bundle: &RuntimeKeyBundle,
    database_id: [u8; 16],
    ledger: &RuntimeLedger,
) -> Result<(), RuntimeStoreError> {
    super::remote_counter::validate_full_integrity(connection, key_bundle, database_id, ledger)
}

fn replay_scope_token(
    key_bundle: &RuntimeKeyBundle,
    scope: &[u8; REMOTE_REPLAY_SCOPE_BYTES],
) -> Result<[u8; 32], RuntimeStoreError> {
    Ok(*key_bundle
        .blind_index(REPLAY_SCOPE_DOMAIN, scope)?
        .as_bytes())
}

fn replay_metadata_token(
    key_bundle: &RuntimeKeyBundle,
    database_id: [u8; 16],
    scope_token: [u8; 32],
    retired_at_ms: Option<u64>,
    sealed: &[u8],
) -> Result<[u8; 32], RuntimeStoreError> {
    let mut message = Vec::with_capacity(16 + 32 + 1 + 8 + 8 + 32);
    message.extend_from_slice(&database_id);
    message.extend_from_slice(&scope_token);
    match retired_at_ms {
        None => message.push(0),
        Some(value) => {
            message.push(1);
            message.extend_from_slice(&value.to_be_bytes());
        }
    }
    message.extend_from_slice(
        &u64::try_from(sealed.len())
            .map_err(|_| RuntimeStoreError::PayloadTooLarge)?
            .to_be_bytes(),
    );
    message.extend_from_slice(&Sha256::digest(sealed));
    Ok(*key_bundle
        .blind_index(REPLAY_METADATA_DOMAIN, &message)?
        .as_bytes())
}

#[allow(
    dead_code,
    reason = "P4.5 CounterGuard writer consumes the v11 projection helper"
)]
#[allow(clippy::too_many_arguments)]
pub(super) fn counter_metadata_token(
    key_bundle: &RuntimeKeyBundle,
    database_id: [u8; 16],
    scope_token: [u8; 32],
    purpose: &str,
    key_epoch: u64,
    reserved_end: u64,
    reservation_id: Option<[u8; 16]>,
    db_anchor: [u8; 32],
    lifecycle: &str,
    sealed: &[u8],
) -> Result<[u8; 32], RuntimeStoreError> {
    let mut message = Vec::with_capacity(16 + 32 + 32 + purpose.len() + lifecycle.len());
    append_field(&mut message, &database_id)?;
    append_field(&mut message, &scope_token)?;
    append_field(&mut message, purpose.as_bytes())?;
    append_field(&mut message, &key_epoch.to_be_bytes())?;
    append_field(&mut message, &reserved_end.to_be_bytes())?;
    match reservation_id {
        None => append_field(&mut message, &[])?,
        Some(value) => append_field(&mut message, &value)?,
    }
    append_field(&mut message, &db_anchor)?;
    append_field(&mut message, lifecycle.as_bytes())?;
    append_field(
        &mut message,
        &u64::try_from(sealed.len())
            .map_err(|_| RuntimeStoreError::PayloadTooLarge)?
            .to_be_bytes(),
    )?;
    append_field(&mut message, &Sha256::digest(sealed))?;
    Ok(*key_bundle
        .blind_index(COUNTER_METADATA_DOMAIN, &message)?
        .as_bytes())
}

fn seal_state(
    key_bundle: &RuntimeKeyBundle,
    database_id: [u8; 16],
    table: &[u8],
    primary_key: &[u8],
    column: &[u8],
    plaintext: &[u8],
) -> Result<Vec<u8>, RuntimeStoreError> {
    Ok(key_bundle.row_cipher().seal_bounded(
        &RowAad {
            schema_family: RUNTIME_SCHEMA_FAMILY.as_bytes(),
            schema_version: RUNTIME_CRYPTO_CONTEXT_VERSION,
            database_id: &database_id,
            table,
            primary_key,
            column,
        },
        plaintext,
        MAX_REPLAY_PLAINTEXT_BYTES,
    )?)
}

fn open_state(
    key_bundle: &RuntimeKeyBundle,
    database_id: [u8; 16],
    table: &[u8],
    primary_key: &[u8],
    column: &[u8],
    ciphertext: &[u8],
) -> Result<crate::security::SecretBytes, RuntimeStoreError> {
    Ok(key_bundle.row_cipher().open_bounded(
        &RowAad {
            schema_family: RUNTIME_SCHEMA_FAMILY.as_bytes(),
            schema_version: RUNTIME_CRYPTO_CONTEXT_VERSION,
            database_id: &database_id,
            table,
            primary_key,
            column,
        },
        ciphertext,
        MAX_REPLAY_PLAINTEXT_BYTES,
    )?)
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
struct ReplayScopeAxes {
    purpose: KeyPurpose,
    subject_route: [u8; 16],
    grant_serial: u64,
    key_epoch: u64,
}

fn nonce_reuse_quarantine_has_canonical_repair(
    connection: &rusqlite::Connection,
    key_bundle: &RuntimeKeyBundle,
    database_id: [u8; 16],
    replay: &ReplayState,
    global: Option<&super::pairing_grant::AuthenticatedGlobalKeyState>,
    authorizations: &[super::pairing_authorization::AuthenticatedAuthorization],
) -> Result<bool, RuntimeStoreError> {
    match super::key_transition::ensure_no_active_transition_for_business(
        connection,
        key_bundle,
        database_id,
    ) {
        Ok(()) => {}
        Err(RuntimeStoreError::InvalidStateTransition) => return Ok(false),
        Err(error) => return Err(error),
    }
    let axes = replay_scope_axes(&replay.scope)?;
    match axes.purpose {
        KeyPurpose::DeviceCommandTx | KeyPurpose::DeviceReplyTx => {
            let device_route = DeviceRouteId::from_bytes(axes.subject_route);
            let exact_grants = authorizations
                .iter()
                .filter(|authorization| {
                    authorization.device_route == device_route
                        && authorization.grant_serial.value() == axes.grant_serial
                })
                .collect::<Vec<_>>();
            if exact_grants.iter().any(|authorization| {
                authorization.lifecycle
                    == super::pairing_authorization::AuthorizationLifecycle::Active
            }) {
                let Some(global) = global else {
                    return Ok(false);
                };
                return global_has_newer_sender_epoch(&global.state, axes);
            }
            // 仅“查不到 active”不是 revoke 证据；synthetic/未知 scope 必须继续
            // quarantine。只有 authenticated terminal/superseded 行能证明 authorization
            // gate 已在 replay admission 前永久拒绝旧 grant。
            Ok(!exact_grants.is_empty()
                && exact_grants.iter().all(|authorization| {
                    matches!(
                        authorization.lifecycle,
                        super::pairing_authorization::AuthorizationLifecycle::Superseded
                            | super::pairing_authorization::AuthorizationLifecycle::Revoked
                    )
                }))
        }
        KeyPurpose::Catalog | KeyPurpose::ConversationDek => {
            let Some(global) = global else {
                return Ok(false);
            };
            global_has_newer_sender_epoch(&global.state, axes)
        }
    }
}

fn global_has_newer_sender_epoch(
    global: &super::pairing_grant::GlobalKeyStateV1,
    axes: ReplayScopeAxes,
) -> Result<bool, RuntimeStoreError> {
    match axes.purpose {
        KeyPurpose::DeviceCommandTx | KeyPurpose::DeviceReplyTx => {
            let current = match global
                .device_transport_key(DeviceRouteId::from_bytes(axes.subject_route), axes.purpose)
            {
                Ok(current) => current,
                Err(RuntimeStoreError::PairingConflict) => return Ok(false),
                Err(error) => return Err(error),
            };
            Ok(current.epoch > axes.key_epoch)
        }
        KeyPurpose::Catalog | KeyPurpose::ConversationDek => {
            let expected_route = if axes.purpose == KeyPurpose::ConversationDek {
                Some(StreamRouteId::from_bytes(axes.subject_route))
            } else {
                None
            };
            Ok(global.current_shared_keys()?.into_iter().any(|current| {
                current.purpose == axes.purpose
                    && current.stream_route == expected_route
                    && current.epoch > axes.key_epoch
            }))
        }
    }
}

fn replay_scope_axes(
    scope: &[u8; REMOTE_REPLAY_SCOPE_BYTES],
) -> Result<ReplayScopeAxes, RuntimeStoreError> {
    validate_scope(scope)?;
    let purpose = match scope[1] {
        DEVICE_COMMAND_PURPOSE => KeyPurpose::DeviceCommandTx,
        DEVICE_REPLY_PURPOSE => KeyPurpose::DeviceReplyTx,
        CONVERSATION_PURPOSE => KeyPurpose::ConversationDek,
        CATALOG_PURPOSE => KeyPurpose::Catalog,
        _ => return Err(RuntimeStoreError::UnknownOrCorruptSchema),
    };
    Ok(ReplayScopeAxes {
        purpose,
        subject_route: scope[26..42]
            .try_into()
            .map_err(|_| RuntimeStoreError::UnknownOrCorruptSchema)?,
        grant_serial: u64::from_be_bytes(
            scope[42..50]
                .try_into()
                .map_err(|_| RuntimeStoreError::UnknownOrCorruptSchema)?,
        ),
        key_epoch: u64::from_be_bytes(
            scope[50..58]
                .try_into()
                .map_err(|_| RuntimeStoreError::UnknownOrCorruptSchema)?,
        ),
    })
}

pub(super) fn canonical_device_command_scope(
    machine_route: [u8; 16],
    trust_epoch: u64,
    device_route: [u8; 16],
    grant_serial: u64,
    key_epoch: u64,
) -> Result<[u8; REMOTE_REPLAY_SCOPE_BYTES], RuntimeStoreError> {
    let mut scope = [0_u8; REMOTE_REPLAY_SCOPE_BYTES];
    scope[0] = 1;
    scope[1] = DEVICE_COMMAND_PURPOSE;
    scope[2..18].copy_from_slice(&machine_route);
    scope[18..26].copy_from_slice(&trust_epoch.to_be_bytes());
    scope[26..42].copy_from_slice(&device_route);
    scope[42..50].copy_from_slice(&grant_serial.to_be_bytes());
    scope[50..58].copy_from_slice(&key_epoch.to_be_bytes());
    validate_device_command_scope(&scope)?;
    Ok(scope)
}

pub(super) fn validate_device_command_scope(
    scope: &[u8; REMOTE_REPLAY_SCOPE_BYTES],
) -> Result<(), RuntimeStoreError> {
    validate_scope(scope)?;
    if scope[1] != DEVICE_COMMAND_PURPOSE {
        return Err(RuntimeStoreError::PublicationMismatch);
    }
    Ok(())
}

pub(super) fn device_command_scope_subject(
    scope: &[u8; REMOTE_REPLAY_SCOPE_BYTES],
) -> Result<([u8; 16], u64), RuntimeStoreError> {
    let axes = device_command_scope_axes(scope)?;
    Ok((axes.device_route, axes.grant_serial))
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(super) struct DeviceCommandScopeAxes {
    pub machine_route: [u8; 16],
    pub trust_epoch: u64,
    pub device_route: [u8; 16],
    pub grant_serial: u64,
    pub command_key_epoch: u64,
}

pub(super) fn device_command_scope_axes(
    scope: &[u8; REMOTE_REPLAY_SCOPE_BYTES],
) -> Result<DeviceCommandScopeAxes, RuntimeStoreError> {
    validate_device_command_scope(scope)?;
    Ok(DeviceCommandScopeAxes {
        machine_route: scope[2..18]
            .try_into()
            .map_err(|_| RuntimeStoreError::PublicationMismatch)?,
        trust_epoch: u64::from_be_bytes(
            scope[18..26]
                .try_into()
                .map_err(|_| RuntimeStoreError::PublicationMismatch)?,
        ),
        device_route: scope[26..42]
            .try_into()
            .map_err(|_| RuntimeStoreError::PublicationMismatch)?,
        grant_serial: u64::from_be_bytes(
            scope[42..50]
                .try_into()
                .map_err(|_| RuntimeStoreError::PublicationMismatch)?,
        ),
        command_key_epoch: u64::from_be_bytes(
            scope[50..58]
                .try_into()
                .map_err(|_| RuntimeStoreError::PublicationMismatch)?,
        ),
    })
}

fn validate_scope(scope: &[u8; REMOTE_REPLAY_SCOPE_BYTES]) -> Result<(), RuntimeStoreError> {
    let purpose = scope[1];
    let machine_nonzero = scope[2..18].iter().any(|byte| *byte != 0);
    let trust_epoch = u64::from_be_bytes(
        scope[18..26]
            .try_into()
            .map_err(|_| RuntimeStoreError::InvalidConfig("invalid remote replay scope"))?,
    );
    let subject_nonzero = scope[26..42].iter().any(|byte| *byte != 0);
    let grant = u64::from_be_bytes(
        scope[42..50]
            .try_into()
            .map_err(|_| RuntimeStoreError::InvalidConfig("invalid remote replay scope"))?,
    );
    let key_epoch = u64::from_be_bytes(
        scope[50..58]
            .try_into()
            .map_err(|_| RuntimeStoreError::InvalidConfig("invalid remote replay scope"))?,
    );
    let shape_valid = match purpose {
        DEVICE_COMMAND_PURPOSE | DEVICE_REPLY_PURPOSE => subject_nonzero && grant > 0,
        CONVERSATION_PURPOSE => subject_nonzero && grant == 0,
        CATALOG_PURPOSE => !subject_nonzero && grant == 0,
        _ => false,
    };
    if scope[0] != 1 || !machine_nonzero || trust_epoch == 0 || key_epoch == 0 || !shape_valid {
        return Err(RuntimeStoreError::InvalidConfig(
            "invalid remote replay scope",
        ));
    }
    Ok(())
}

fn replay_retention_owner(
    scope: [u8; REMOTE_REPLAY_SCOPE_BYTES],
    pin_id: [u8; 16],
) -> Result<Option<RetiredSharedKeyOwner>, RuntimeStoreError> {
    validate_scope(&scope)?;
    let key_epoch = u64::from_be_bytes(
        scope[50..58]
            .try_into()
            .map_err(|_| RuntimeStoreError::UnknownOrCorruptSchema)?,
    );
    let (purpose, stream_route) = match scope[1] {
        DEVICE_COMMAND_PURPOSE | DEVICE_REPLY_PURPOSE => return Ok(None),
        CONVERSATION_PURPOSE => {
            let route = scope[26..42]
                .try_into()
                .map(StreamRouteId::from_bytes)
                .map_err(|_| RuntimeStoreError::UnknownOrCorruptSchema)?;
            (KeyPurpose::ConversationDek, Some(route))
        }
        CATALOG_PURPOSE => (KeyPurpose::Catalog, None),
        _ => return Err(RuntimeStoreError::UnknownOrCorruptSchema),
    };
    RetiredSharedKeyOwner::new(
        RetiredKeyOwnerKind::Replay,
        pin_id,
        purpose,
        stream_route,
        key_epoch,
    )
    .map(Some)
}

fn optional_i64(value: Option<u64>) -> Result<Option<i64>, RuntimeStoreError> {
    value
        .map(|value| i64::try_from(value).map_err(|_| RuntimeStoreError::TimeOutOfRange))
        .transpose()
}

fn nonnegative(value: i64) -> Result<u64, RuntimeStoreError> {
    u64::try_from(value).map_err(|_| RuntimeStoreError::UnknownOrCorruptSchema)
}

fn fixed<const N: usize>(value: Vec<u8>) -> Result<[u8; N], RuntimeStoreError> {
    value
        .try_into()
        .map_err(|_| RuntimeStoreError::UnknownOrCorruptSchema)
}

fn append_field(message: &mut Vec<u8>, field: &[u8]) -> Result<(), RuntimeStoreError> {
    message.extend_from_slice(
        &u32::try_from(field.len())
            .map_err(|_| RuntimeStoreError::PayloadTooLarge)?
            .to_be_bytes(),
    );
    message.extend_from_slice(field);
    Ok(())
}

fn checked_add(left: u64, right: u64) -> Result<u64, RuntimeStoreError> {
    left.checked_add(right)
        .ok_or(RuntimeStoreError::UnknownOrCorruptSchema)
}

#[cfg(test)]
mod quarantine_recovery_tests {
    use super::*;
    use crate::security::SecretBytes;

    fn secret(seed: u8) -> SecretBytes {
        SecretBytes::new(vec![seed; 32])
    }

    fn device_axes(
        device_route: DeviceRouteId,
        purpose: KeyPurpose,
        epoch: u64,
    ) -> ReplayScopeAxes {
        ReplayScopeAxes {
            purpose,
            subject_route: *device_route.as_bytes(),
            grant_serial: 1,
            key_epoch: epoch,
        }
    }

    #[test]
    fn nonce_quarantine_requires_authenticated_strictly_newer_sender_epoch() {
        let device_route = DeviceRouteId::from_bytes([0x41; 16]);
        let original = super::super::pairing_grant::GlobalKeyStateV1::bootstrap(
            1,
            1,
            secret(0x11),
            device_route,
            1,
            secret(0x12),
            1,
            secret(0x13),
        )
        .expect("bootstrap authenticated sender keys");
        for purpose in [KeyPurpose::DeviceCommandTx, KeyPurpose::DeviceReplyTx] {
            assert!(
                !global_has_newer_sender_epoch(&original, device_axes(device_route, purpose, 1))
                    .expect("compare current sender epoch"),
                "the same active epoch must keep nonce quarantine"
            );
        }
        assert!(
            !global_has_newer_sender_epoch(
                &original,
                ReplayScopeAxes {
                    purpose: KeyPurpose::Catalog,
                    subject_route: [0; 16],
                    grant_serial: 0,
                    key_epoch: 1,
                },
            )
            .expect("compare current catalog epoch")
        );

        let renewed = original
            .renew_for_device(device_route, secret(0x21), secret(0x22), secret(0x23))
            .expect("rotate sender epochs canonically");
        for purpose in [KeyPurpose::DeviceCommandTx, KeyPurpose::DeviceReplyTx] {
            assert!(
                global_has_newer_sender_epoch(&renewed, device_axes(device_route, purpose, 1))
                    .expect("read authenticated replacement epoch"),
                "a strictly newer current sender epoch authorizes eventual quarantine GC"
            );
            assert!(
                !global_has_newer_sender_epoch(&renewed, device_axes(device_route, purpose, 2))
                    .expect("reject deleting current replacement epoch")
            );
        }
        assert!(
            global_has_newer_sender_epoch(
                &renewed,
                ReplayScopeAxes {
                    purpose: KeyPurpose::Catalog,
                    subject_route: [0; 16],
                    grant_serial: 0,
                    key_epoch: 1,
                },
            )
            .expect("read authenticated catalog replacement")
        );
    }
}
