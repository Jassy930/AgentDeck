//! P4.5 sender counter 的 scope、Keychain guard 状态与 crash recovery 纯状态机。
//!
//! 同一对称发送 key 下，nonce counter 必须永不复用。V2 guard account 因此不再只绑定
//! `KeyPurpose + epoch`，而是绑定完整发送域：publication 使用 daemon-local 稳定
//! `publication_stream_id`，不绑定 rollover 会同时替换的 Relay route/generation；directed lane
//! 还包含 machine trust epoch、device route 与 grant serial。这里不持有 key，也不执行 DB 或
//! Keychain IO；真实 KeyStore compare-and-swap adapter 位于 `identity`。

use std::fmt;

pub use agentdeck_crypto::counter::COUNTER_BLOCK_SIZE;
use agentdeck_crypto::sha256;
use agentdeck_protocol::e2ee::{KeyId, KeyPurpose};
use agentdeck_protocol::relay_v2::{DeviceRouteId, GrantSerial, MachineRouteId, TrustEpoch};
use thiserror::Error;

const COUNTER_SCOPE_DOMAIN: &[u8] = b"AgentDeck/CounterScopeV2\0";
const PUBLICATION_SCOPE_TAG: u8 = 1;
const PREBOUND_DIRECTED_REPLY_SCOPE_TAG: u8 = 2;
const TRUST_EPOCH_DIRECTED_SCOPE_TAG: u8 = 3;

const COUNTER_GUARD_STATE_DOMAIN: &[u8] = b"AgentDeck/CounterGuardStateV2\0";
const STABLE_STATE_TAG: u8 = 1;
const PENDING_STATE_TAG: u8 = 2;
const STABLE_STATE_ENCODED_LEN: usize = COUNTER_GUARD_STATE_DOMAIN.len() + 1 + 32 + 8 + 32;
const PENDING_STATE_ENCODED_LEN: usize =
    COUNTER_GUARD_STATE_DOMAIN.len() + 1 + 32 + 8 + 8 + 16 + 16 + 32;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Error)]
pub enum CounterError {
    #[error("counter scope has an invalid {axis}")]
    InvalidScope { axis: &'static str },
    #[error("counter guard state has an invalid {field}")]
    InvalidState { field: &'static str },
    #[error("counter guard and database state belong to different scopes")]
    ScopeMismatch,
    #[error("counter guard transition is not monotonic")]
    InvalidTransition,
    #[error("counter guard has an invalid canonical encoding")]
    InvalidEncoding,
}

impl CounterError {
    #[must_use]
    pub const fn code(self) -> &'static str {
        match self {
            Self::InvalidScope { .. } => "daemon.remote.counter.scope_invalid",
            Self::InvalidState { .. } | Self::InvalidEncoding => {
                "daemon.remote.counter.state_invalid"
            }
            Self::ScopeMismatch => "daemon.remote.counter.scope_mismatch",
            Self::InvalidTransition => "daemon.remote.counter.transition_invalid",
        }
    }
}

/// 完整 sender nonce domain 的不可逆、非秘密 account token。
#[derive(Clone, Copy, PartialEq, Eq, Hash)]
pub struct CounterScope {
    token: [u8; 32],
}

impl CounterScope {
    /// daemon shared publication counter。只接受 Catalog 或 ConversationDEK。
    pub fn publication(
        trust_domain: [u8; 32],
        key_id: KeyId,
        publication_stream_id: [u8; 16],
    ) -> Result<Self, CounterError> {
        ensure_scope_nonzero(&trust_domain, "trust domain")?;
        ensure_scope_nonzero(&publication_stream_id, "publication stream id")?;
        if !matches!(
            key_id.purpose,
            KeyPurpose::Catalog | KeyPurpose::ConversationDek
        ) {
            return Err(CounterError::InvalidScope {
                axis: "publication key purpose",
            });
        }

        let mut canonical = scope_prefix(PUBLICATION_SCOPE_TAG, trust_domain, key_id);
        canonical.extend_from_slice(&publication_stream_id);
        Ok(Self {
            token: sha256(&canonical),
        })
    }

    /// 已把 machine/trust epoch 纳入 `trust_domain` 的 directed-reply scope。
    ///
    /// 本入口用于 protocol-level prebound trust domain 与测试向量。daemon production 必须优先使用
    /// [`Self::directed_reply_for_trust_epoch`]，避免调用方遗漏显式 trust epoch 轴。
    pub fn directed_reply(
        trust_domain: [u8; 32],
        key_id: KeyId,
        device_route: DeviceRouteId,
        grant_serial: GrantSerial,
    ) -> Result<Self, CounterError> {
        ensure_scope_nonzero(&trust_domain, "trust domain")?;
        ensure_scope_nonzero(device_route.as_bytes(), "device route")?;
        ensure_positive(grant_serial.value(), "grant serial")?;
        if key_id.purpose != KeyPurpose::DeviceReplyTx {
            return Err(CounterError::InvalidScope {
                axis: "directed-reply key purpose",
            });
        }

        let mut canonical = scope_prefix(PREBOUND_DIRECTED_REPLY_SCOPE_TAG, trust_domain, key_id);
        canonical.extend_from_slice(device_route.as_bytes());
        canonical.extend_from_slice(&grant_serial.value().to_be_bytes());
        Ok(Self {
            token: sha256(&canonical),
        })
    }

    /// daemon→device directed reply 的完整 production scope。
    pub fn directed_reply_for_trust_epoch(
        trust_domain: [u8; 32],
        machine_route: MachineRouteId,
        trust_epoch: TrustEpoch,
        device_route: DeviceRouteId,
        grant_serial: GrantSerial,
        key_epoch: u64,
    ) -> Result<Self, CounterError> {
        Self::directed_for_trust_epoch(
            trust_domain,
            machine_route,
            trust_epoch,
            KeyId {
                purpose: KeyPurpose::DeviceReplyTx,
                epoch: key_epoch,
            },
            device_route,
            grant_serial,
        )
    }

    /// 绑定完整 machine/device trust 轴的 directed sender scope。
    ///
    /// `DeviceCommandTx` 由设备端 allocator 使用，`DeviceReplyTx` 由 daemon allocator 使用；
    /// purpose tag 保证两条方向不能共享 guard account。
    pub fn directed_for_trust_epoch(
        trust_domain: [u8; 32],
        machine_route: MachineRouteId,
        trust_epoch: TrustEpoch,
        key_id: KeyId,
        device_route: DeviceRouteId,
        grant_serial: GrantSerial,
    ) -> Result<Self, CounterError> {
        ensure_scope_nonzero(&trust_domain, "trust domain")?;
        ensure_scope_nonzero(machine_route.as_bytes(), "machine route")?;
        ensure_positive(trust_epoch.value(), "trust epoch")?;
        ensure_scope_nonzero(device_route.as_bytes(), "device route")?;
        ensure_positive(grant_serial.value(), "grant serial")?;
        if !matches!(
            key_id.purpose,
            KeyPurpose::DeviceCommandTx | KeyPurpose::DeviceReplyTx
        ) {
            return Err(CounterError::InvalidScope {
                axis: "directed key purpose",
            });
        }

        let mut canonical = scope_prefix(TRUST_EPOCH_DIRECTED_SCOPE_TAG, trust_domain, key_id);
        canonical.extend_from_slice(machine_route.as_bytes());
        canonical.extend_from_slice(&trust_epoch.value().to_be_bytes());
        canonical.extend_from_slice(device_route.as_bytes());
        canonical.extend_from_slice(&grant_serial.value().to_be_bytes());
        Ok(Self {
            token: sha256(&canonical),
        })
    }

    #[must_use]
    pub const fn token(&self) -> [u8; 32] {
        self.token
    }
}

impl fmt::Debug for CounterScope {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("CounterScope([REDACTED])")
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CounterGuardPhase {
    Pending,
    Stable,
}

#[derive(Clone, Copy, PartialEq, Eq)]
enum CounterGuardBody {
    Pending {
        previous_high_water: u64,
        reserved_through: u64,
        reservation_id: [u8; 16],
        publication_id: [u8; 16],
        previous_db_anchor: [u8; 32],
    },
    Stable {
        reserved_through: u64,
        exact_db_anchor: [u8; 32],
    },
}

/// Keychain 中的 V2 guard。Pending 证明 Keychain 已先预留，Stable 再绑定 DB exact anchor。
#[derive(Clone, Copy, PartialEq, Eq)]
pub struct CounterGuardState {
    scope_token: [u8; 32],
    body: CounterGuardBody,
}

impl CounterGuardState {
    pub fn pending(
        scope_token: [u8; 32],
        previous_high_water: u64,
        reserved_through: u64,
        reservation_id: [u8; 16],
        publication_id: [u8; 16],
        previous_db_anchor: [u8; 32],
    ) -> Result<Self, CounterError> {
        validate_token(scope_token)?;
        validate_full_block(previous_high_water, reserved_through)?;
        ensure_state_nonzero(&reservation_id, "reservation id")?;
        ensure_state_nonzero(&publication_id, "publication id")?;
        ensure_state_nonzero(&previous_db_anchor, "previous database anchor")?;
        Ok(Self {
            scope_token,
            body: CounterGuardBody::Pending {
                previous_high_water,
                reserved_through,
                reservation_id,
                publication_id,
                previous_db_anchor,
            },
        })
    }

    pub fn stable(
        scope_token: [u8; 32],
        reserved_through: u64,
        exact_db_anchor: [u8; 32],
    ) -> Result<Self, CounterError> {
        validate_token(scope_token)?;
        ensure_state_nonzero(&exact_db_anchor, "exact database anchor")?;
        Ok(Self {
            scope_token,
            body: CounterGuardBody::Stable {
                reserved_through,
                exact_db_anchor,
            },
        })
    }

    #[must_use]
    pub const fn token(&self) -> [u8; 32] {
        self.scope_token
    }

    #[must_use]
    pub const fn phase(&self) -> CounterGuardPhase {
        match self.body {
            CounterGuardBody::Pending { .. } => CounterGuardPhase::Pending,
            CounterGuardBody::Stable { .. } => CounterGuardPhase::Stable,
        }
    }

    /// guard 已经不可再使用的 exclusive reserved end。
    #[must_use]
    pub const fn reserved_through(&self) -> u64 {
        match self.body {
            CounterGuardBody::Pending {
                reserved_through, ..
            }
            | CounterGuardBody::Stable {
                reserved_through, ..
            } => reserved_through,
        }
    }

    #[must_use]
    pub const fn previous_high_water(&self) -> Option<u64> {
        match self.body {
            CounterGuardBody::Pending {
                previous_high_water,
                ..
            } => Some(previous_high_water),
            CounterGuardBody::Stable { .. } => None,
        }
    }

    #[must_use]
    pub const fn reservation_id(&self) -> Option<[u8; 16]> {
        match self.body {
            CounterGuardBody::Pending { reservation_id, .. } => Some(reservation_id),
            CounterGuardBody::Stable { .. } => None,
        }
    }

    #[must_use]
    pub const fn publication_id(&self) -> Option<[u8; 16]> {
        match self.body {
            CounterGuardBody::Pending { publication_id, .. } => Some(publication_id),
            CounterGuardBody::Stable { .. } => None,
        }
    }

    #[must_use]
    pub const fn database_anchor(&self) -> [u8; 32] {
        match self.body {
            CounterGuardBody::Pending {
                previous_db_anchor, ..
            } => previous_db_anchor,
            CounterGuardBody::Stable {
                exact_db_anchor, ..
            } => exact_db_anchor,
        }
    }

    pub(crate) fn encode(self) -> Vec<u8> {
        let mut encoded = Vec::with_capacity(match self.body {
            CounterGuardBody::Pending { .. } => PENDING_STATE_ENCODED_LEN,
            CounterGuardBody::Stable { .. } => STABLE_STATE_ENCODED_LEN,
        });
        encoded.extend_from_slice(COUNTER_GUARD_STATE_DOMAIN);
        match self.body {
            CounterGuardBody::Stable {
                reserved_through,
                exact_db_anchor,
            } => {
                encoded.push(STABLE_STATE_TAG);
                encoded.extend_from_slice(&self.scope_token);
                encoded.extend_from_slice(&reserved_through.to_be_bytes());
                encoded.extend_from_slice(&exact_db_anchor);
            }
            CounterGuardBody::Pending {
                previous_high_water,
                reserved_through,
                reservation_id,
                publication_id,
                previous_db_anchor,
            } => {
                encoded.push(PENDING_STATE_TAG);
                encoded.extend_from_slice(&self.scope_token);
                encoded.extend_from_slice(&previous_high_water.to_be_bytes());
                encoded.extend_from_slice(&reserved_through.to_be_bytes());
                encoded.extend_from_slice(&reservation_id);
                encoded.extend_from_slice(&publication_id);
                encoded.extend_from_slice(&previous_db_anchor);
            }
        }
        encoded
    }

    pub(crate) fn decode(bytes: &[u8]) -> Result<Self, CounterError> {
        if !bytes.starts_with(COUNTER_GUARD_STATE_DOMAIN) {
            return Err(CounterError::InvalidEncoding);
        }
        let mut cursor = COUNTER_GUARD_STATE_DOMAIN.len();
        let tag = *bytes.get(cursor).ok_or(CounterError::InvalidEncoding)?;
        cursor += 1;
        let token = take_array::<32>(bytes, &mut cursor)?;
        let state = match tag {
            STABLE_STATE_TAG if bytes.len() == STABLE_STATE_ENCODED_LEN => {
                let reserved_through = u64::from_be_bytes(take_array::<8>(bytes, &mut cursor)?);
                let exact_db_anchor = take_array::<32>(bytes, &mut cursor)?;
                Self::stable(token, reserved_through, exact_db_anchor)?
            }
            PENDING_STATE_TAG if bytes.len() == PENDING_STATE_ENCODED_LEN => {
                let previous_high_water = u64::from_be_bytes(take_array::<8>(bytes, &mut cursor)?);
                let reserved_through = u64::from_be_bytes(take_array::<8>(bytes, &mut cursor)?);
                let reservation_id = take_array::<16>(bytes, &mut cursor)?;
                let publication_id = take_array::<16>(bytes, &mut cursor)?;
                let previous_db_anchor = take_array::<32>(bytes, &mut cursor)?;
                Self::pending(
                    token,
                    previous_high_water,
                    reserved_through,
                    reservation_id,
                    publication_id,
                    previous_db_anchor,
                )?
            }
            _ => return Err(CounterError::InvalidEncoding),
        };
        if cursor != bytes.len() {
            return Err(CounterError::InvalidEncoding);
        }
        Ok(state)
    }
}

impl fmt::Debug for CounterGuardState {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("CounterGuardState")
            .field("scope_token", &"[REDACTED]")
            .field("phase", &self.phase())
            .field("reserved_through", &self.reserved_through())
            .finish()
    }
}

#[derive(Clone, Copy, PartialEq, Eq)]
enum CounterDbBody {
    Unchanged {
        reserved_through: u64,
        exact_anchor: [u8; 32],
    },
    Frozen {
        reserved_through: u64,
        reservation_id: [u8; 16],
        publication_id: [u8; 16],
        exact_anchor: [u8; 32],
    },
}

/// Store 整行认证后的 counter 状态。`reserved_through` 是整块 end，不是已消费 counter。
#[derive(Clone, Copy, PartialEq, Eq)]
pub struct CounterDbState {
    scope_token: [u8; 32],
    body: CounterDbBody,
}

impl CounterDbState {
    pub fn unchanged(
        scope_token: [u8; 32],
        reserved_through: u64,
        exact_anchor: [u8; 32],
    ) -> Result<Self, CounterError> {
        validate_token(scope_token)?;
        ensure_state_nonzero(&exact_anchor, "exact database anchor")?;
        Ok(Self {
            scope_token,
            body: CounterDbBody::Unchanged {
                reserved_through,
                exact_anchor,
            },
        })
    }

    pub fn frozen(
        scope_token: [u8; 32],
        reserved_through: u64,
        reservation_id: [u8; 16],
        publication_id: [u8; 16],
        exact_anchor: [u8; 32],
    ) -> Result<Self, CounterError> {
        validate_token(scope_token)?;
        ensure_state_nonzero(&reservation_id, "reservation id")?;
        ensure_state_nonzero(&publication_id, "publication id")?;
        ensure_state_nonzero(&exact_anchor, "exact database anchor")?;
        Ok(Self {
            scope_token,
            body: CounterDbBody::Frozen {
                reserved_through,
                reservation_id,
                publication_id,
                exact_anchor,
            },
        })
    }

    #[must_use]
    pub const fn token(&self) -> [u8; 32] {
        self.scope_token
    }

    #[must_use]
    pub const fn reserved_through(&self) -> u64 {
        match self.body {
            CounterDbBody::Unchanged {
                reserved_through, ..
            }
            | CounterDbBody::Frozen {
                reserved_through, ..
            } => reserved_through,
        }
    }

    #[must_use]
    pub const fn exact_anchor(&self) -> [u8; 32] {
        match self.body {
            CounterDbBody::Unchanged { exact_anchor, .. }
            | CounterDbBody::Frozen { exact_anchor, .. } => exact_anchor,
        }
    }
}

impl fmt::Debug for CounterDbState {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("CounterDbState")
            .field("scope_token", &"[REDACTED]")
            .field("reserved_through", &self.reserved_through())
            .finish()
    }
}

/// open/recovery 对 guard 与已认证 Store row 的 fail-close 判定。
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CounterRecovery {
    /// guard 与 DB exact 一致；重启仍放弃旧 block remainder，从 `after` 申请下一整块。
    ReserveNextBlock { after: u64 },
    /// guard 已领先、DB 仍是之前 exact anchor；整块只能跳过，不能消费。
    GuardAheadGap { abandoned_through: u64 },
    /// DB 已冻结同一 reservation/publication；只允许逐字节重试既有 frozen blob。
    RetryFrozen {
        publication_id: [u8; 16],
        exact_db_anchor: [u8; 32],
    },
    /// DB 落后/分叉、状态不一致或下一个 1,024 block 会溢出；必须退休 key。
    RetireKey,
}

/// 对账不执行 IO，也不把 DB 中“已消费 counter”当作可信 high-water。
pub fn reconcile_counter_recovery(
    guard: &CounterGuardState,
    db: &CounterDbState,
) -> Result<CounterRecovery, CounterError> {
    if guard.scope_token != db.scope_token {
        return Err(CounterError::ScopeMismatch);
    }

    match (guard.body, db.body) {
        (
            CounterGuardBody::Pending {
                previous_high_water,
                reserved_through,
                previous_db_anchor,
                ..
            },
            CounterDbBody::Unchanged {
                reserved_through: db_reserved_through,
                exact_anchor,
            },
        ) if previous_high_water == db_reserved_through && previous_db_anchor == exact_anchor => {
            Ok(CounterRecovery::GuardAheadGap {
                abandoned_through: reserved_through,
            })
        }
        // 上一条 publication 已冻结过时，DB 的 stable head 合法保持 `Frozen`；下一次
        // reservation 若在 guard Pending 后、DB freeze 前崩溃，pending 携带的 previous
        // high-water/anchor 仍能逐字证明该 Frozen row 就是唯一 predecessor。只允许整块
        // 跳号，绝不能把旧 blob 当成当前 pending 的 RetryFrozen。
        (
            CounterGuardBody::Pending {
                previous_high_water,
                reserved_through,
                previous_db_anchor,
                ..
            },
            CounterDbBody::Frozen {
                reserved_through: db_reserved_through,
                exact_anchor,
                ..
            },
        ) if previous_high_water == db_reserved_through && previous_db_anchor == exact_anchor => {
            Ok(CounterRecovery::GuardAheadGap {
                abandoned_through: reserved_through,
            })
        }
        (
            CounterGuardBody::Pending {
                reserved_through,
                reservation_id,
                publication_id,
                ..
            },
            CounterDbBody::Frozen {
                reserved_through: db_reserved_through,
                reservation_id: db_reservation_id,
                publication_id: db_publication_id,
                exact_anchor,
            },
        ) if reserved_through == db_reserved_through
            && reservation_id == db_reservation_id
            && publication_id == db_publication_id =>
        {
            Ok(CounterRecovery::RetryFrozen {
                publication_id,
                exact_db_anchor: exact_anchor,
            })
        }
        (
            CounterGuardBody::Stable {
                reserved_through,
                exact_db_anchor,
            },
            CounterDbBody::Frozen {
                reserved_through: db_reserved_through,
                publication_id,
                exact_anchor,
                ..
            },
        ) if reserved_through == db_reserved_through && exact_db_anchor == exact_anchor => {
            Ok(CounterRecovery::RetryFrozen {
                publication_id,
                exact_db_anchor,
            })
        }
        (
            CounterGuardBody::Stable {
                reserved_through,
                exact_db_anchor,
            },
            CounterDbBody::Unchanged {
                reserved_through: db_reserved_through,
                exact_anchor,
            },
        ) if reserved_through == db_reserved_through && exact_db_anchor == exact_anchor => {
            if reserved_through.checked_add(COUNTER_BLOCK_SIZE).is_some() {
                Ok(CounterRecovery::ReserveNextBlock {
                    after: reserved_through,
                })
            } else {
                Ok(CounterRecovery::RetireKey)
            }
        }
        // authenticated DB rollback/divergence 不是普通 crash gap；key 必须退休。
        _ => Ok(CounterRecovery::RetireKey),
    }
}

/// Keychain/secure-store 的 V2 compare-and-swap seam。
///
/// adapter 必须在一个排他临界区内完成 load→compare→store→exact readback；单独的
/// `load` 结果不能作为后续无条件覆盖依据。
pub trait CounterGuardBackend: Send + Sync {
    type Error;

    fn load_guard(&self, scope: &CounterScope) -> Result<Option<CounterGuardState>, Self::Error>;

    fn compare_and_swap_guard(
        &self,
        scope: &CounterScope,
        expected: Option<CounterGuardState>,
        next: CounterGuardState,
    ) -> Result<CounterGuardCas, Self::Error>;
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CounterGuardCas {
    Swapped(CounterGuardState),
    Conflict(Option<CounterGuardState>),
}

/// backend 在写入前调用的 monotonic transition validator。
pub(crate) fn validate_guard_transition(
    current: Option<CounterGuardState>,
    next: CounterGuardState,
) -> Result<(), CounterError> {
    let valid = match (current.map(|state| state.body), next.body) {
        (
            None,
            CounterGuardBody::Pending {
                previous_high_water,
                ..
            },
        ) => previous_high_water == 0,
        (Some(current), next) if current == next => true,
        (
            Some(CounterGuardBody::Stable {
                reserved_through,
                exact_db_anchor,
            }),
            CounterGuardBody::Pending {
                previous_high_water,
                reserved_through: next_reserved_through,
                previous_db_anchor,
                ..
            },
        ) => {
            previous_high_water == reserved_through
                && previous_db_anchor == exact_db_anchor
                && is_next_full_block(previous_high_water, next_reserved_through)
        }
        (
            Some(CounterGuardBody::Pending {
                reserved_through,
                previous_db_anchor,
                ..
            }),
            CounterGuardBody::Pending {
                previous_high_water,
                reserved_through: next_reserved_through,
                previous_db_anchor: next_previous_db_anchor,
                ..
            },
        ) => {
            previous_high_water == reserved_through
                && previous_db_anchor == next_previous_db_anchor
                && is_next_full_block(previous_high_water, next_reserved_through)
        }
        (
            Some(CounterGuardBody::Pending {
                reserved_through, ..
            }),
            CounterGuardBody::Stable {
                reserved_through: next_reserved_through,
                ..
            },
        ) => reserved_through == next_reserved_through,
        _ => false,
    };
    if !valid {
        return Err(CounterError::InvalidTransition);
    }
    Ok(())
}

fn scope_prefix(tag: u8, trust_domain: [u8; 32], key_id: KeyId) -> Vec<u8> {
    let mut canonical = Vec::with_capacity(COUNTER_SCOPE_DOMAIN.len() + 1 + 32 + 1 + 8 + 64);
    canonical.extend_from_slice(COUNTER_SCOPE_DOMAIN);
    canonical.push(tag);
    canonical.extend_from_slice(&trust_domain);
    canonical.push(key_purpose_tag(key_id.purpose));
    canonical.extend_from_slice(&key_id.epoch.to_be_bytes());
    canonical
}

const fn key_purpose_tag(purpose: KeyPurpose) -> u8 {
    match purpose {
        KeyPurpose::Catalog => 0,
        KeyPurpose::ConversationDek => 1,
        KeyPurpose::DeviceCommandTx => 2,
        KeyPurpose::DeviceReplyTx => 3,
    }
}

fn validate_token(token: [u8; 32]) -> Result<(), CounterError> {
    ensure_state_nonzero(&token, "scope token")
}

fn validate_full_block(previous: u64, reserved_through: u64) -> Result<(), CounterError> {
    if !is_next_full_block(previous, reserved_through) {
        return Err(CounterError::InvalidState {
            field: "counter block",
        });
    }
    Ok(())
}

fn is_next_full_block(previous: u64, reserved_through: u64) -> bool {
    previous.checked_add(COUNTER_BLOCK_SIZE) == Some(reserved_through)
}

fn ensure_scope_nonzero(bytes: &[u8], axis: &'static str) -> Result<(), CounterError> {
    if bytes.iter().all(|byte| *byte == 0) {
        return Err(CounterError::InvalidScope { axis });
    }
    Ok(())
}

fn ensure_state_nonzero(bytes: &[u8], field: &'static str) -> Result<(), CounterError> {
    if bytes.iter().all(|byte| *byte == 0) {
        return Err(CounterError::InvalidState { field });
    }
    Ok(())
}

fn ensure_positive(value: u64, axis: &'static str) -> Result<(), CounterError> {
    if value == 0 {
        return Err(CounterError::InvalidScope { axis });
    }
    Ok(())
}

fn take_array<const N: usize>(bytes: &[u8], cursor: &mut usize) -> Result<[u8; N], CounterError> {
    let end = cursor.checked_add(N).ok_or(CounterError::InvalidEncoding)?;
    let value = bytes
        .get(*cursor..end)
        .ok_or(CounterError::InvalidEncoding)?
        .try_into()
        .map_err(|_| CounterError::InvalidEncoding)?;
    *cursor = end;
    Ok(value)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn publication_scope() -> CounterScope {
        CounterScope::publication(
            [0x11; 32],
            KeyId {
                purpose: KeyPurpose::ConversationDek,
                epoch: 7,
            },
            [0x12; 16],
        )
        .unwrap()
    }

    #[test]
    fn guard_codec_roundtrips_both_phases_and_rejects_trailing_bytes() {
        let token = publication_scope().token();
        for state in [
            CounterGuardState::pending(token, 1_024, 2_048, [0x21; 16], [0x22; 16], [0x23; 32])
                .unwrap(),
            CounterGuardState::stable(token, 2_048, [0x24; 32]).unwrap(),
        ] {
            let encoded = state.encode();
            assert_eq!(CounterGuardState::decode(&encoded).unwrap(), state);
            let mut trailing = encoded;
            trailing.push(0);
            assert_eq!(
                CounterGuardState::decode(&trailing),
                Err(CounterError::InvalidEncoding)
            );
        }
    }

    #[test]
    fn transition_requires_exact_1024_block_and_db_anchor_continuity() {
        let token = publication_scope().token();
        let stable = CounterGuardState::stable(token, 1_024, [0x31; 32]).unwrap();
        let pending =
            CounterGuardState::pending(token, 1_024, 2_048, [0x32; 16], [0x33; 16], [0x31; 32])
                .unwrap();
        assert_eq!(validate_guard_transition(Some(stable), pending), Ok(()));
        assert_eq!(
            validate_guard_transition(
                Some(stable),
                CounterGuardState::pending(
                    token,
                    1_024,
                    2_048,
                    [0x32; 16],
                    [0x33; 16],
                    [0x34; 32],
                )
                .unwrap(),
            ),
            Err(CounterError::InvalidTransition)
        );
    }

    #[test]
    fn directed_scope_token_changes_for_every_trust_and_nonce_axis() {
        let trust_domain = [0x35; 32];
        let machine = MachineRouteId::from_bytes([0x36; 16]);
        let trust_epoch = TrustEpoch::new(2);
        let device = DeviceRouteId::from_bytes([0x37; 16]);
        let grant = GrantSerial::new(3);
        let tokens = [
            CounterScope::directed_reply_for_trust_epoch(
                trust_domain,
                machine,
                trust_epoch,
                device,
                grant,
                4,
            )
            .unwrap()
            .token(),
            CounterScope::directed_reply_for_trust_epoch(
                [0x38; 32],
                machine,
                trust_epoch,
                device,
                grant,
                4,
            )
            .unwrap()
            .token(),
            CounterScope::directed_reply_for_trust_epoch(
                trust_domain,
                MachineRouteId::from_bytes([0x39; 16]),
                trust_epoch,
                device,
                grant,
                4,
            )
            .unwrap()
            .token(),
            CounterScope::directed_reply_for_trust_epoch(
                trust_domain,
                machine,
                TrustEpoch::new(5),
                device,
                grant,
                4,
            )
            .unwrap()
            .token(),
            CounterScope::directed_reply_for_trust_epoch(
                trust_domain,
                machine,
                trust_epoch,
                DeviceRouteId::from_bytes([0x3a; 16]),
                grant,
                4,
            )
            .unwrap()
            .token(),
            CounterScope::directed_reply_for_trust_epoch(
                trust_domain,
                machine,
                trust_epoch,
                device,
                GrantSerial::new(6),
                4,
            )
            .unwrap()
            .token(),
            CounterScope::directed_reply_for_trust_epoch(
                trust_domain,
                machine,
                trust_epoch,
                device,
                grant,
                7,
            )
            .unwrap()
            .token(),
            CounterScope::directed_for_trust_epoch(
                trust_domain,
                machine,
                trust_epoch,
                KeyId {
                    purpose: KeyPurpose::DeviceCommandTx,
                    epoch: 4,
                },
                device,
                grant,
            )
            .unwrap()
            .token(),
        ];
        for (index, token) in tokens.iter().enumerate() {
            assert!(tokens[..index].iter().all(|previous| previous != token));
        }
    }

    #[test]
    fn recovery_retries_stabilized_frozen_row_but_retires_stale_db() {
        let token = publication_scope().token();
        let stable = CounterGuardState::stable(token, 2_048, [0x41; 32]).unwrap();
        let frozen =
            CounterDbState::frozen(token, 2_048, [0x42; 16], [0x43; 16], [0x41; 32]).unwrap();
        assert_eq!(
            reconcile_counter_recovery(&stable, &frozen).unwrap(),
            CounterRecovery::RetryFrozen {
                publication_id: [0x43; 16],
                exact_db_anchor: [0x41; 32],
            }
        );

        let stale = CounterDbState::unchanged(token, 1_024, [0x44; 32]).unwrap();
        assert_eq!(
            reconcile_counter_recovery(&stable, &stale).unwrap(),
            CounterRecovery::RetireKey
        );
    }

    #[test]
    fn recovery_records_gap_when_next_pending_follows_exact_prior_frozen_row() {
        let token = publication_scope().token();
        let pending =
            CounterGuardState::pending(token, 2_048, 3_072, [0x51; 16], [0x52; 16], [0x53; 32])
                .unwrap();
        let prior_frozen =
            CounterDbState::frozen(token, 2_048, [0x54; 16], [0x55; 16], [0x53; 32]).unwrap();
        assert_eq!(
            reconcile_counter_recovery(&pending, &prior_frozen).unwrap(),
            CounterRecovery::GuardAheadGap {
                abandoned_through: 3_072,
            }
        );

        let forked =
            CounterDbState::frozen(token, 2_048, [0x54; 16], [0x55; 16], [0x56; 32]).unwrap();
        assert_eq!(
            reconcile_counter_recovery(&pending, &forked).unwrap(),
            CounterRecovery::RetireKey
        );
    }
}
