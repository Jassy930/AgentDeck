//! PairResponse 验证后的 two-phase paired machine promotion。
//!
//! `PairedCommitMarkerV1` 是唯一可见性边界。随机 StorageKEK 必须先以 provisional
//! Keychain item 持久化，随后才能一次性提交 sealed CryptoState；其余 final items 完成
//! exact readback 后才最后写 marker。marker 前的 partial state 永远不代表 paired。

#![cfg(unix)]

use std::collections::HashSet;
use std::fmt;
use std::path::{Path, PathBuf};
use std::sync::Arc;

use agentdeck_crypto::counter::COUNTER_BLOCK_SIZE;
use agentdeck_crypto::rand_core::CryptoRng;
use agentdeck_crypto::{
    CryptoError, HpkePrivateKey, HpkePublicKey, SecretAeadKey, SignatureBytes, SigningKey,
    VerifyingKey, open_key_directory_entry, open_pair_response, seal_pair_response_received,
    sha256, verify_tbs,
};
use agentdeck_protocol::e2ee::{
    DeviceAuthorizationV1, E2EE_FORMAT_VERSION, KeyDirectoryV1, KeyId, KeyPurpose, KeyUpdateInfoV1,
    MachineDataSignerBindingV1, OuterContextV1, OuterFrameKind, PairResponseReceivedV1,
    PairResponseV1, PairingControlEnvelopeV1, PairingError,
};
use agentdeck_protocol::relay_v2::RELAY_PROTOCOL_VERSION;
use agentdeck_protocol::relay_v2::auth::{
    AuthCanonicalError, CertRole, Ed25519Signature, RelayGrant, SignedCertificate,
};
use agentdeck_protocol::relay_v2::id::{
    DeviceRouteId, GrantSerial, KeyDirectoryRevision, MachineRouteId, RelayServerId, StreamRouteId,
    TrustEpoch,
};
use agentdeck_protocol::runtime::{MachineRootFingerprint, RUNTIME_PROTOCOL_VERSION};
use thiserror::Error;
use uuid::Uuid;
use zeroize::{Zeroize, Zeroizing};

use super::crypto_state::{
    CryptoStateError, CryptoStateIdentity, CryptoStateSnapshot, DeviceStorageKek,
    FileCryptoStateStore, MAX_CRYPTO_STATE_PLAINTEXT_LEN,
};
use super::device_lock::{RemoteDeviceLease, RemoteDeviceLockError, RemoteDeviceLockKey};
use super::keychain::{
    PairedRemoteKeyPurpose, ParsedPairedRemoteKeyAccount, PendingRemoteKeyPurpose,
    RemoteKeyAccount, RemoteKeyStore, RemoteKeyStoreError, RemoteSecret,
};
use super::pending::{PendingInvitePublicProjection, VerifiedPendingPairResponse};

const STATE_MAGIC: &[u8; 4] = b"ADPS";
const STATE_VERSION: u16 = 1;
const MUTABLE_STATE_VERSION: u16 = 2;
const STATE_HEADER_LEN: usize = 12;
const MAX_STATE_FIELD_LEN: usize = 8 * 1024 * 1024;
const MAX_STATE_STRING_LEN: usize = 8 * 1024;
const MAX_STATE_COLLECTION_ITEMS: usize = 4_096;
const MAX_MUTABLE_AUDIT_ATTEMPTS: usize = 3;

const MARKER_MAGIC: &[u8; 4] = b"ADPM";
const MARKER_VERSION: u16 = 1;
const KEK_MAGIC: &[u8; 4] = b"ADKK";
const KEK_VERSION: u16 = 1;
const COUNTER_GUARD_MAGIC: &[u8; 4] = b"ADCG";
const COUNTER_GUARD_VERSION: u16 = 1;
const MUTABLE_COUNTER_GUARD_VERSION: u16 = 2;
const PROMOTION_ID_DOMAIN: &[u8] = b"AgentDeck/PairedPromotionIdV1\0";

/// 仅供 automatic library harness 在 reservation/recovery 的 durable 边界注入进程终止。
/// production CLI 不构造该 observer，也不存在环境变量或配置入口。
#[doc(hidden)]
pub trait PairedMutationObserver: Send + Sync {
    fn after_stage(&self, stage: PairedMutationStage);
}

#[doc(hidden)]
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum PairedMutationStage {
    GuardPendingDurable,
    StateDurable,
    RecoveryStateDurable,
    GuardStableDurable,
}

/// 已在 CounterGuard 中 durable 预留的 DeviceCommandTx counter 整块。
#[derive(Eq, PartialEq)]
pub struct CommandCounterReservation {
    reservation_id: [u8; 16],
    start: u64,
    end_exclusive: u64,
}

impl fmt::Debug for CommandCounterReservation {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("CommandCounterReservation")
            .field("reservation_id", &"[REDACTED]")
            .field("start", &self.start)
            .field("end_exclusive", &self.end_exclusive)
            .finish()
    }
}

impl CommandCounterReservation {
    #[must_use]
    pub const fn reservation_id(&self) -> [u8; 16] {
        self.reservation_id
    }

    #[must_use]
    pub const fn start(&self) -> u64 {
        self.start
    }

    #[must_use]
    pub const fn end_exclusive(&self) -> u64 {
        self.end_exclusive
    }

    fn validate(&self) -> Result<(), PairedPromotionError> {
        if all_zero(&self.reservation_id)
            || self
                .start
                .checked_add(COUNTER_BLOCK_SIZE)
                .is_none_or(|end| end != self.end_exclusive)
        {
            return Err(PairedPromotionError::InvalidState);
        }
        Ok(())
    }
}

/// 纯内存地准备下一整块；overflow 必须早于 entropy、state 构造与任一 durable mutation。
fn prepare_command_counter_reservation<R: CryptoRng>(
    previous_high_water: u64,
    rng: &mut R,
) -> Result<CommandCounterReservation, PairedPromotionError> {
    let end_exclusive = previous_high_water
        .checked_add(COUNTER_BLOCK_SIZE)
        .ok_or(PairedPromotionError::CounterEpochExhausted)?;
    let mut reservation_id = [0_u8; 16];
    rng.try_fill_bytes(&mut reservation_id)
        .map_err(|_| PairedPromotionError::EntropyUnavailable)?;
    if all_zero(&reservation_id) {
        return Err(PairedPromotionError::EntropyUnavailable);
    }
    let reservation = CommandCounterReservation {
        reservation_id,
        start: previous_high_water,
        end_exclusive,
    };
    reservation.validate()?;
    Ok(reservation)
}

#[derive(Debug, Error)]
pub enum PairedPromotionError {
    #[error("paired promotion could not acquire the remote device lease")]
    DeviceLock(#[source] RemoteDeviceLockError),
    #[error("paired promotion persistence failed")]
    Persistence(#[source] RemoteKeyStoreError),
    #[error("paired promotion sealed state failed")]
    CryptoState(#[source] CryptoStateError),
    #[error("paired promotion cryptographic validation failed")]
    Crypto(#[source] CryptoError),
    #[error("paired promotion canonical state is invalid")]
    Protocol(#[source] PairingError),
    #[error("paired promotion auth credential is invalid")]
    AuthCanonical(#[source] AuthCanonicalError),
    #[error("paired promotion entropy source is unavailable")]
    EntropyUnavailable,
    #[error("paired command counter reached the current key epoch limit")]
    CounterEpochExhausted,
    #[error("paired promotion is incomplete or corrupt")]
    Incomplete,
    #[error("paired promotion conflicts with durable state")]
    Conflict,
    #[error("paired promotion state has an invalid canonical encoding")]
    InvalidState,
}

impl PairedPromotionError {
    #[must_use]
    pub const fn code(&self) -> &'static str {
        match self {
            Self::DeviceLock(error) => error.code(),
            Self::Persistence(_) => "remote.pairing.paired_persistence_failed",
            Self::CryptoState(error) => error.code(),
            Self::Crypto(_) | Self::Protocol(_) | Self::AuthCanonical(_) | Self::InvalidState => {
                "remote.pairing.paired_invalid"
            }
            Self::EntropyUnavailable => "remote.pairing.entropy_unavailable",
            Self::CounterEpochExhausted => "remote.counter.epoch_retirement_required",
            Self::Incomplete => "remote.pairing.paired_incomplete",
            Self::Conflict => "remote.pairing.paired_conflict",
        }
    }
}

/// marker exact readback 后才可返回给 transport 的 frozen receipt outbox。
pub struct PromotedPairedMachine {
    state_path: PathBuf,
    canonical_receipt_carrier: Vec<u8>,
    machine_route: MachineRouteId,
    device_route: DeviceRouteId,
    request_hash: [u8; 32],
    grant_hash: [u8; 32],
    response_hash: [u8; 32],
    already_committed: bool,
}

impl fmt::Debug for PromotedPairedMachine {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("PromotedPairedMachine([REDACTED])")
    }
}

impl PromotedPairedMachine {
    #[must_use]
    pub fn state_path(&self) -> &Path {
        &self.state_path
    }

    #[must_use]
    pub fn canonical_receipt_carrier(&self) -> &[u8] {
        &self.canonical_receipt_carrier
    }

    #[must_use]
    pub const fn machine_route(&self) -> MachineRouteId {
        self.machine_route
    }

    #[must_use]
    pub const fn device_route(&self) -> DeviceRouteId {
        self.device_route
    }

    #[must_use]
    pub const fn request_hash(&self) -> [u8; 32] {
        self.request_hash
    }

    #[must_use]
    pub const fn grant_hash(&self) -> [u8; 32] {
        self.grant_hash
    }

    #[must_use]
    pub const fn response_hash(&self) -> [u8; 32] {
        self.response_hash
    }

    #[must_use]
    pub const fn was_already_committed(&self) -> bool {
        self.already_committed
    }
}

/// marker account、sealed state 与所有 final Keychain item 共用的 machine identity。
#[derive(Clone, Copy, Eq, PartialEq)]
pub struct PairedMachineIdentity {
    machine_root_fingerprint: MachineRootFingerprint,
    machine_route: MachineRouteId,
}

impl fmt::Debug for PairedMachineIdentity {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("PairedMachineIdentity([REDACTED])")
    }
}

impl PairedMachineIdentity {
    #[must_use]
    pub const fn new(
        machine_root_fingerprint: MachineRootFingerprint,
        machine_route: MachineRouteId,
    ) -> Self {
        Self {
            machine_root_fingerprint,
            machine_route,
        }
    }

    #[must_use]
    pub const fn machine_root_fingerprint(self) -> MachineRootFingerprint {
        self.machine_root_fingerprint
    }

    #[must_use]
    pub const fn machine_route(self) -> MachineRouteId {
        self.machine_route
    }
}

/// 完整审计后可用于选择 machine 的无 secret 投影。
#[derive(Clone, Eq, PartialEq)]
pub struct PairedMachineSummary {
    identity: PairedMachineIdentity,
    machine_display_name: String,
    device_route: DeviceRouteId,
}

impl fmt::Debug for PairedMachineSummary {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("PairedMachineSummary([REDACTED])")
    }
}

impl PairedMachineSummary {
    #[must_use]
    pub const fn identity(&self) -> PairedMachineIdentity {
        self.identity
    }

    #[must_use]
    pub fn machine_display_name(&self) -> &str {
        &self.machine_display_name
    }

    #[must_use]
    pub const fn device_route(&self) -> DeviceRouteId {
        self.device_route
    }
}

struct OpenedPairedDirectoryKey {
    _key_id: KeyId,
    _stream_route: Option<StreamRouteId>,
    _key: SecretAeadKey,
}

struct AuditedPairedMachine {
    identity: PairedMachineIdentity,
    machine_display_name: String,
    wss_url: String,
    device_route: DeviceRouteId,
    grant_serial: GrantSerial,
    trust_epoch: TrustEpoch,
    directory_revision: KeyDirectoryRevision,
    _relay_server_id: RelayServerId,
    _current_spki_pin: [u8; 32],
    _next_spki_pin: [u8; 32],
    state_store: FileCryptoStateStore,
    state_snapshot: CryptoStateSnapshot,
    state: PairedCryptoState,
    counter_account: RemoteKeyAccount,
    counter_guard_bytes: RemoteSecret,
    counter_guard: CounterGuardState,
    device_command_binding: CounterBindingV1,
    marker: PairedCommitMarkerV1,
    _canonical_receipt_carrier: Vec<u8>,
    _grant: RelayGrant,
    _authorization: DeviceAuthorizationV1,
    _device_signing_key: SigningKey,
    _device_hpke_private_key: HpkePrivateKey,
    _opened_directory_keys: Vec<OpenedPairedDirectoryKey>,
}

impl AuditedPairedMachine {
    fn summary(&self) -> PairedMachineSummary {
        PairedMachineSummary {
            identity: self.identity,
            machine_display_name: self.machine_display_name.clone(),
            device_route: self.device_route,
        }
    }

    fn into_opened<'a>(
        self,
        store: &'a dyn RemoteKeyStore,
        mutation_observer: Option<Arc<dyn PairedMutationObserver>>,
        lease: RemoteDeviceLease,
    ) -> OpenedPairedMachine<'a> {
        OpenedPairedMachine {
            audited: self,
            store,
            mutation_observer,
            _lease: lease,
        }
    }
}

/// marker-first 只读审计成功后持有 device lease 与 typed crypto capabilities 的 machine。
///
/// 本类型不实现 `Clone` / serde，`Debug` 永远 redacted，且没有 raw secret getter。
pub struct OpenedPairedMachine<'a> {
    audited: AuditedPairedMachine,
    store: &'a dyn RemoteKeyStore,
    mutation_observer: Option<Arc<dyn PairedMutationObserver>>,
    // 必须最后销毁，确保 crypto/counter capabilities 不会晚于跨进程独占 lease。
    _lease: RemoteDeviceLease,
}

impl fmt::Debug for OpenedPairedMachine<'_> {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("OpenedPairedMachine([REDACTED])")
    }
}

impl OpenedPairedMachine<'_> {
    #[must_use]
    pub const fn identity(&self) -> PairedMachineIdentity {
        self.audited.identity
    }

    #[must_use]
    pub fn machine_display_name(&self) -> &str {
        &self.audited.machine_display_name
    }

    #[must_use]
    pub fn wss_url(&self) -> &str {
        &self.audited.wss_url
    }

    #[must_use]
    pub const fn device_route(&self) -> DeviceRouteId {
        self.audited.device_route
    }

    #[must_use]
    pub const fn grant_serial(&self) -> GrantSerial {
        self.audited.grant_serial
    }

    #[must_use]
    pub const fn trust_epoch(&self) -> TrustEpoch {
        self.audited.trust_epoch
    }

    #[must_use]
    pub const fn directory_revision(&self) -> KeyDirectoryRevision {
        self.audited.directory_revision
    }

    /// 只暴露已逐项 DeviceHPKE 解封成功的 key 数量，不返回 raw key。
    #[must_use]
    pub fn opened_key_count(&self) -> usize {
        self.audited._opened_directory_keys.len()
    }

    /// 查询完整审计后是否存在指定 purpose；不暴露 epoch、route 或 raw key。
    #[must_use]
    pub fn has_opened_key_purpose(&self, purpose: KeyPurpose) -> bool {
        self.audited
            ._opened_directory_keys
            .iter()
            .any(|key| key._key_id.purpose == purpose)
    }

    /// 先提升 Keychain guard，再替换 sealed state，最后 finalize guard。
    /// 重启永不复用先前进程可能消费过的 reservation remainder。
    pub fn reserve_command_counter_block<R: CryptoRng>(
        &mut self,
        rng: &mut R,
    ) -> Result<CommandCounterReservation, PairedPromotionError> {
        self.refresh_mutable_state()?;
        self.recover_pending_guard()?;

        let (previous_high_water, current_state_hash, binding, initial_guard_commitment) =
            match self.audited.counter_guard {
                CounterGuardState::V1(guard) => (
                    guard.reserved_high_water,
                    sha256(self.audited.state_snapshot.expose_secret()),
                    guard.binding,
                    self.audited.marker.counter_guard_hash,
                ),
                CounterGuardState::V2(CounterGuardV2 {
                    initial_guard_commitment,
                    directory_revision: _,
                    binding,
                    phase:
                        CounterGuardPhaseV2::Stable {
                            reserved_high_water,
                            current_state_hash,
                        },
                }) => (
                    reserved_high_water,
                    current_state_hash,
                    binding,
                    initial_guard_commitment,
                ),
                CounterGuardState::V2(CounterGuardV2 {
                    phase: CounterGuardPhaseV2::Pending { .. },
                    ..
                }) => return Err(PairedPromotionError::InvalidState),
            };
        if current_state_hash != sha256(self.audited.state_snapshot.expose_secret()) {
            return Err(PairedPromotionError::Conflict);
        }
        let reservation = prepare_command_counter_reservation(previous_high_water, rng)?;
        let end_exclusive = reservation.end_exclusive;
        let reservation_id = reservation.reservation_id;

        let next_state = self.audited.state.with_counter_reservation(
            self.audited.marker.state_plaintext_hash,
            self.audited.marker.counter_guard_hash,
            &reservation,
        )?;
        let next_state_bytes = next_state.encode()?;
        let next_state_hash = sha256(&next_state_bytes);
        let pending = CounterGuardV2::pending(
            initial_guard_commitment,
            self.audited.directory_revision,
            binding,
            previous_high_water,
            end_exclusive,
            reservation_id,
            current_state_hash,
            next_state_hash,
        )?;
        self.replace_counter_guard(CounterGuardState::V2(pending))?;
        self.observe_mutation(PairedMutationStage::GuardPendingDurable);

        let next_snapshot = CryptoStateSnapshot::new(next_state_bytes);
        self.audited
            .state_store
            .compare_and_replace(&self.audited.state_snapshot, &next_snapshot)
            .map_err(PairedPromotionError::CryptoState)?;
        // observer 位于 durable store 返回与内存 cache 更新之间，覆盖 committed-but-stale handle。
        self.observe_mutation(PairedMutationStage::StateDurable);
        self.audited.state_snapshot = next_snapshot;
        self.audited.state = next_state;

        let stable = CounterGuardV2::stable(
            initial_guard_commitment,
            self.audited.directory_revision,
            binding,
            end_exclusive,
            next_state_hash,
        )?;
        self.replace_counter_guard(CounterGuardState::V2(stable))?;
        self.observe_mutation(PairedMutationStage::GuardStableDurable);
        Ok(reservation)
    }

    fn recover_pending_guard(&mut self) -> Result<(), PairedPromotionError> {
        let CounterGuardState::V2(guard) = self.audited.counter_guard else {
            return Ok(());
        };
        let CounterGuardPhaseV2::Pending {
            previous_high_water,
            next_high_water,
            reservation_id,
            previous_state_hash,
            next_state_hash,
        } = guard.phase
        else {
            return Ok(());
        };
        let mut current_hash = sha256(self.audited.state_snapshot.expose_secret());
        let expected = CommandCounterReservation {
            reservation_id,
            start: previous_high_water,
            end_exclusive: next_high_water,
        };
        expected.validate()?;
        if current_hash == next_state_hash {
            if self.audited.state.counter_reservation() != Some(&expected) {
                return Err(PairedPromotionError::Conflict);
            }
        } else if current_hash == previous_state_hash {
            // guard-first 已经让整块不可复用。用 pending 中冻结的同一 reservation 重建
            // canonical next state，写成 sealed counter fence，但绝不把该块返回给调用方。
            let (skipped_state, skipped_snapshot) = rebuild_frozen_counter_state(
                &self.audited.marker,
                &self.audited.state,
                expected,
                next_state_hash,
            )?;
            self.audited
                .state_store
                .compare_and_replace(&self.audited.state_snapshot, &skipped_snapshot)
                .map_err(PairedPromotionError::CryptoState)?;
            // recovery 自己也是 state CAS → guard finalize 的事务；在 cache 更新前保留
            // 独立 crash seam，证明 committed-but-stale reopen 只走 pending+next。
            self.observe_mutation(PairedMutationStage::RecoveryStateDurable);
            self.audited.state_snapshot = skipped_snapshot;
            self.audited.state = skipped_state;
            current_hash = next_state_hash;
        } else {
            return Err(PairedPromotionError::Conflict);
        }

        // 无论 recovery 从 previous 还是 next 进入，重启都不暴露该 reservation；它只作为
        // exact sealed fence 与 Stable HWM 绑定，下一次调用从下一整块继续。
        let stable = CounterGuardV2::stable(
            guard.initial_guard_commitment,
            guard.directory_revision,
            guard.binding,
            next_high_water,
            current_hash,
        )?;
        self.replace_counter_guard(CounterGuardState::V2(stable))?;
        Ok(())
    }

    /// mutation error 之后不得信任内存 expected；每次 reserve 都从两个 durable backend
    /// 重新读回，并只接受 marker initial commitments 下的 coherent previous/next/stable。
    fn refresh_mutable_state(&mut self) -> Result<(), PairedPromotionError> {
        let counter_guard_bytes = self
            .store
            .load(&self.audited.counter_account)
            .map_err(PairedPromotionError::Persistence)?
            .ok_or(PairedPromotionError::Incomplete)?;
        let counter_guard = CounterGuardState::decode(counter_guard_bytes.expose_secret())?;
        let state_snapshot = self
            .audited
            .state_store
            .load()
            .map_err(PairedPromotionError::CryptoState)?
            .ok_or(PairedPromotionError::Incomplete)?;
        let state = PairedCryptoState::decode(state_snapshot.expose_secret())?;
        self.audited.marker.validate_state(
            self.audited.identity,
            &state,
            state_snapshot.expose_secret(),
        )?;
        validate_counter_guard_state(
            &self.audited.marker,
            &counter_guard,
            counter_guard_bytes.expose_secret(),
            &state,
            state_snapshot.expose_secret(),
            self.audited.device_command_binding,
        )?;
        self.audited.counter_guard_bytes = counter_guard_bytes;
        self.audited.counter_guard = counter_guard;
        self.audited.state_snapshot = state_snapshot;
        self.audited.state = state;
        Ok(())
    }

    fn replace_counter_guard(
        &mut self,
        replacement: CounterGuardState,
    ) -> Result<(), PairedPromotionError> {
        let replacement_bytes = replacement.encode();
        self.store
            .compare_and_replace_exact(
                &self.audited.counter_account,
                &self.audited.counter_guard_bytes,
                &RemoteSecret::new(replacement_bytes.clone()),
            )
            .map_err(PairedPromotionError::Persistence)?;
        self.audited.counter_guard_bytes = RemoteSecret::new(replacement_bytes);
        self.audited.counter_guard = replacement;
        Ok(())
    }

    fn observe_mutation(&self, stage: PairedMutationStage) {
        if let Some(observer) = &self.mutation_observer {
            observer.after_stage(stage);
        }
    }
}

/// 当前 installation 的 marker-backed paired machine 只读恢复入口。
pub struct PairedMachineStore<'a> {
    store: &'a dyn RemoteKeyStore,
    installation_id: Uuid,
    state_root: PathBuf,
    mutation_observer: Option<Arc<dyn PairedMutationObserver>>,
}

impl fmt::Debug for PairedMachineStore<'_> {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("PairedMachineStore")
            .field("identity", &"[REDACTED]")
            .finish_non_exhaustive()
    }
}

impl<'a> PairedMachineStore<'a> {
    #[must_use]
    pub fn new(store: &'a dyn RemoteKeyStore, installation_id: Uuid, state_root: &Path) -> Self {
        Self::new_inner(store, installation_id, state_root, None)
    }

    #[doc(hidden)]
    #[must_use]
    pub fn new_with_mutation_observer(
        store: &'a dyn RemoteKeyStore,
        installation_id: Uuid,
        state_root: &Path,
        observer: Arc<dyn PairedMutationObserver>,
    ) -> Self {
        Self::new_inner(store, installation_id, state_root, Some(observer))
    }

    fn new_inner(
        store: &'a dyn RemoteKeyStore,
        installation_id: Uuid,
        state_root: &Path,
        mutation_observer: Option<Arc<dyn PairedMutationObserver>>,
    ) -> Self {
        Self {
            store,
            installation_id,
            state_root: state_root.to_path_buf(),
            mutation_observer,
        }
    }

    /// 只枚举当前 installation 的 commit marker，并逐项完成与 `open_exact` 相同的全审计。
    /// 任一 marker 损坏都会让整个 list fail-close，不会静默省略。
    pub fn list(&self) -> Result<Vec<PairedMachineSummary>, PairedPromotionError> {
        let markers = self
            .store
            .list_paired_commit_markers(self.installation_id)
            .map_err(PairedPromotionError::Persistence)?;
        let mut machines = Vec::with_capacity(markers.len());
        for marker in markers {
            let audited = self.audit_marker(&marker)?;
            machines.push(audited.summary());
        }
        Ok(machines)
    }

    /// 在取得 exact machine lease 后，从 marker 开始只读恢复；缺失 marker 不可见且不可修复。
    pub fn open_exact(
        &self,
        identity: PairedMachineIdentity,
    ) -> Result<OpenedPairedMachine<'a>, PairedPromotionError> {
        let account = RemoteKeyAccount::paired(
            self.installation_id,
            identity.machine_root_fingerprint,
            identity.machine_route,
            PairedRemoteKeyPurpose::CommitMarker,
        );
        let parsed = RemoteKeyAccount::parse_paired(account.as_str())
            .map_err(|_| PairedPromotionError::InvalidState)?;
        let lease = RemoteDeviceLease::acquire_in(
            &self.state_root,
            RemoteDeviceLockKey::new(
                self.installation_id,
                identity.machine_root_fingerprint,
                identity.machine_route,
            ),
        )
        .map_err(PairedPromotionError::DeviceLock)?;
        let audited = self.audit_marker(&parsed)?;
        let mut opened = audited.into_opened(self.store, self.mutation_observer.clone(), lease);
        opened.recover_pending_guard()?;
        Ok(opened)
    }

    fn audit_marker(
        &self,
        parsed: &ParsedPairedRemoteKeyAccount,
    ) -> Result<AuditedPairedMachine, PairedPromotionError> {
        if parsed.installation_id() != self.installation_id
            || parsed.purpose() != PairedRemoteKeyPurpose::CommitMarker
        {
            return Err(PairedPromotionError::Conflict);
        }
        let identity =
            PairedMachineIdentity::new(parsed.machine_root_fingerprint(), parsed.machine_route());

        // marker 是唯一 visibility gate；在它 exact load/decode 前不读取任何 final item/state。
        let marker_secret = self.load_required(parsed.account())?;
        let marker = PairedCommitMarkerV1::decode(marker_secret.expose_secret())?;
        marker.validate_account(self.installation_id, identity)?;
        let accounts = PairedAccounts::new(
            self.installation_id,
            identity.machine_root_fingerprint,
            identity.machine_route,
        );
        if &accounts.marker != parsed.account() {
            return Err(PairedPromotionError::Conflict);
        }

        // 固定只读顺序：marker → KEK → DeviceSign/HPKE → grant → guard → sealed state。
        let kek_secret = self.load_required(&accounts.kek)?;
        let kek_record = StorageKekRecordV1::decode(kek_secret.expose_secret())?;
        if kek_record.promotion_id != marker.promotion_id
            || marker.kek_record_hash != kek_record.commitment()
        {
            return Err(PairedPromotionError::Conflict);
        }
        let device_sign_secret = self.load_required(&accounts.device_sign)?;
        let device_hpke_secret = self.load_required(&accounts.device_hpke)?;
        let grant_secret = self.load_required(&accounts.grant)?;

        let state_store = FileCryptoStateStore::new_in(
            &self.state_root,
            CryptoStateIdentity::new(
                self.installation_id,
                identity.machine_root_fingerprint,
                identity.machine_route,
            ),
            kek_record.device_storage_kek(),
        )
        .map_err(PairedPromotionError::CryptoState)?;
        let (counter_secret, state_snapshot) =
            self.load_coherent_mutable_pair(&accounts.counter_guard, &state_store)?;
        let counter_guard = CounterGuardState::decode(counter_secret.expose_secret())?;
        let state = PairedCryptoState::decode(state_snapshot.expose_secret())?;
        marker.validate_state(identity, &state, state_snapshot.expose_secret())?;
        let bootstrap = state.bootstrap();

        let audit = audit_durable_state(
            bootstrap,
            grant_secret.expose_secret(),
            &device_sign_secret,
            &device_hpke_secret,
        )?;
        if marker.device_sign_pubkey != audit.device_signing_key.verifying_key().to_bytes()
            || marker.device_hpke_pubkey != hpke_public_bytes(&audit.device_hpke_private_key)?
        {
            return Err(PairedPromotionError::Conflict);
        }
        validate_counter_guard_state(
            &marker,
            &counter_guard,
            counter_secret.expose_secret(),
            &state,
            state_snapshot.expose_secret(),
            audit.device_command_binding,
        )?;

        Ok(AuditedPairedMachine {
            identity,
            machine_display_name: bootstrap.machine_display_name.clone(),
            wss_url: bootstrap.wss_url.clone(),
            device_route: bootstrap.device_route,
            grant_serial: bootstrap.grant_serial,
            trust_epoch: bootstrap.trust_epoch,
            directory_revision: bootstrap.directory_revision,
            _relay_server_id: bootstrap.relay_server_id,
            _current_spki_pin: bootstrap.current_spki_pin,
            _next_spki_pin: bootstrap.next_spki_pin,
            _canonical_receipt_carrier: bootstrap.receipt_carrier.clone(),
            state_store,
            state_snapshot,
            state,
            counter_account: accounts.counter_guard,
            counter_guard_bytes: counter_secret,
            counter_guard,
            device_command_binding: audit.device_command_binding,
            marker,
            _grant: audit.grant,
            _authorization: audit.authorization,
            _device_signing_key: audit.device_signing_key,
            _device_hpke_private_key: audit.device_hpke_private_key,
            _opened_directory_keys: audit.opened_keys,
        })
    }

    fn load_required(
        &self,
        account: &RemoteKeyAccount,
    ) -> Result<RemoteSecret, PairedPromotionError> {
        self.store
            .load(account)
            .map_err(PairedPromotionError::Persistence)?
            .ok_or(PairedPromotionError::Incomplete)
    }

    /// `list()` 不取 device lease；用 bounded guard1→state→guard2 避免把合法 writer
    /// 的三阶段切换误判为 durable divergence。读取始终只读，耗尽重试后 fail-close。
    fn load_coherent_mutable_pair(
        &self,
        counter_account: &RemoteKeyAccount,
        state_store: &FileCryptoStateStore,
    ) -> Result<(RemoteSecret, CryptoStateSnapshot), PairedPromotionError> {
        for _ in 0..MAX_MUTABLE_AUDIT_ATTEMPTS {
            let before = self.load_required(counter_account)?;
            let state = state_store
                .load()
                .map_err(PairedPromotionError::CryptoState)?
                .ok_or(PairedPromotionError::Incomplete)?;
            let after = self.load_required(counter_account)?;
            if before.expose_secret() == after.expose_secret() {
                return Ok((after, state));
            }
        }
        Err(PairedPromotionError::Conflict)
    }
}

pub struct PairedPromotionCoordinator<'a> {
    store: &'a dyn RemoteKeyStore,
    installation_id: Uuid,
    state_root: PathBuf,
}

impl fmt::Debug for PairedPromotionCoordinator<'_> {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("PairedPromotionCoordinator")
            .field("identity", &"[REDACTED]")
            .finish_non_exhaustive()
    }
}

impl<'a> PairedPromotionCoordinator<'a> {
    #[must_use]
    pub fn new(store: &'a dyn RemoteKeyStore, installation_id: Uuid, state_root: &Path) -> Self {
        Self {
            store,
            installation_id,
            state_root: state_root.to_path_buf(),
        }
    }

    /// 只接受 durable pending transaction 产出的不可伪造 verified capability。
    pub fn promote<R: CryptoRng>(
        &self,
        response: VerifiedPendingPairResponse,
        rng: &mut R,
    ) -> Result<PromotedPairedMachine, PairedPromotionError> {
        let material = response.into_promotion_material();
        let verified = material.verified;
        let info = verified.info();
        let root_fingerprint =
            MachineRootFingerprint::from_bytes(verified.machine_root_fingerprint());
        let accounts =
            PairedAccounts::new(self.installation_id, root_fingerprint, info.machine_route);
        let _lease = RemoteDeviceLease::acquire_in(
            &self.state_root,
            RemoteDeviceLockKey::new(self.installation_id, root_fingerprint, info.machine_route),
        )
        .map_err(PairedPromotionError::DeviceLock)?;

        let promotion_id = promotion_id(self.installation_id, &verified);
        if let Some(marker) = self
            .store
            .load(&accounts.marker)
            .map_err(PairedPromotionError::Persistence)?
        {
            return self.audit_committed(
                &accounts,
                &verified,
                &material.invite_public,
                promotion_id,
                marker.expose_secret(),
                true,
            );
        }

        let pending = self.load_pending_secrets(verified.info().invite_hash)?;
        let signing_key = signing_key(&pending.device_sign)?;
        let hpke_private = hpke_private_key(&pending.device_hpke)?;
        validate_pending_keys(&verified, &signing_key, &hpke_private)?;

        // StorageKEK 是 sealed file 的 prerequisite；marker 前只属于 provisional state。
        if self
            .store
            .load(&accounts.kek)
            .map_err(PairedPromotionError::Persistence)?
            .is_none()
        {
            self.reject_state_without_kek(root_fingerprint, info.machine_route)?;
        }
        let kek_record = self.load_or_create_kek(&accounts.kek, promotion_id, rng)?;
        let state_store = self.open_state_store(
            root_fingerprint,
            info.machine_route,
            kek_record.device_storage_kek(),
        )?;
        let state = match state_store
            .load()
            .map_err(PairedPromotionError::CryptoState)?
        {
            Some(snapshot) => PairedCryptoStateV1::decode(snapshot.expose_secret())?,
            None => {
                let state = build_initial_state(
                    self.installation_id,
                    &verified,
                    &material.invite_public,
                    promotion_id,
                    &signing_key,
                    rng,
                )?;
                let encoded = state.encode()?;
                state_store
                    .commit_initial(&CryptoStateSnapshot::new(encoded))
                    .map_err(PairedPromotionError::CryptoState)?;
                let durable = state_store
                    .load()
                    .map_err(PairedPromotionError::CryptoState)?
                    .ok_or(PairedPromotionError::Incomplete)?;
                PairedCryptoStateV1::decode(durable.expose_secret())?
            }
        };

        let grant_bytes = verified.relay_grant().canonical_bytes();
        let audit = audit_state(
            self.installation_id,
            &state,
            &verified,
            &material.invite_public,
            &grant_bytes,
            &pending.device_sign,
            &pending.device_hpke,
        )?;
        let counter_guard =
            CounterGuardV1::from_binding(state.directory_revision, audit.device_command_binding);
        let counter_bytes = counter_guard.encode();

        self.persist_exact(&accounts.device_sign, &pending.device_sign)?;
        self.persist_exact(&accounts.device_hpke, &pending.device_hpke)?;
        self.persist_exact(&accounts.grant, &RemoteSecret::new(grant_bytes.clone()))?;
        self.persist_exact(
            &accounts.counter_guard,
            &RemoteSecret::new(counter_bytes.clone()),
        )?;

        let state_bytes = state.encode()?;
        let marker = PairedCommitMarkerV1::new(
            self.installation_id,
            &state,
            promotion_id,
            sha256(&state_bytes),
            kek_record.commitment(),
            sha256(&counter_bytes),
            signing_key.verifying_key().to_bytes(),
            hpke_public_bytes(&hpke_private)?,
        );
        let marker_bytes = marker.encode();
        self.persist_exact(&accounts.marker, &RemoteSecret::new(marker_bytes.clone()))?;

        self.audit_committed(
            &accounts,
            &verified,
            &material.invite_public,
            promotion_id,
            &marker_bytes,
            false,
        )
    }

    fn load_pending_secrets(
        &self,
        invite_hash: [u8; 32],
    ) -> Result<PendingSecrets, PairedPromotionError> {
        let device_sign = self
            .store
            .load(&RemoteKeyAccount::pending(
                self.installation_id,
                invite_hash,
                PendingRemoteKeyPurpose::DeviceSignPrivateKey,
            ))
            .map_err(PairedPromotionError::Persistence)?
            .ok_or(PairedPromotionError::Incomplete)?;
        let device_hpke = self
            .store
            .load(&RemoteKeyAccount::pending(
                self.installation_id,
                invite_hash,
                PendingRemoteKeyPurpose::DeviceHpkePrivateKey,
            ))
            .map_err(PairedPromotionError::Persistence)?
            .ok_or(PairedPromotionError::Incomplete)?;
        Ok(PendingSecrets {
            device_sign,
            device_hpke,
        })
    }

    fn load_or_create_kek<R: CryptoRng>(
        &self,
        account: &RemoteKeyAccount,
        promotion_id: [u8; 32],
        rng: &mut R,
    ) -> Result<StorageKekRecordV1, PairedPromotionError> {
        if let Some(existing) = self
            .store
            .load(account)
            .map_err(PairedPromotionError::Persistence)?
        {
            let record = StorageKekRecordV1::decode(existing.expose_secret())?;
            return if record.promotion_id == promotion_id {
                Ok(record)
            } else {
                Err(PairedPromotionError::Conflict)
            };
        }

        let mut key = [0_u8; 32];
        rng.try_fill_bytes(&mut key)
            .map_err(|_| PairedPromotionError::EntropyUnavailable)?;
        if key.iter().all(|byte| *byte == 0) {
            key.zeroize();
            return Err(PairedPromotionError::EntropyUnavailable);
        }
        let candidate = StorageKekRecordV1 { promotion_id, key };
        let encoded = candidate.encode();
        match self
            .store
            .persist_immutable(account, &RemoteSecret::new(encoded))
        {
            Ok(_) => {}
            Err(RemoteKeyStoreError::ImmutableConflict { .. }) => {
                return Err(PairedPromotionError::Conflict);
            }
            Err(error) => return Err(PairedPromotionError::Persistence(error)),
        }
        let durable = self
            .store
            .load(account)
            .map_err(PairedPromotionError::Persistence)?
            .ok_or(PairedPromotionError::Incomplete)?;
        let durable = StorageKekRecordV1::decode(durable.expose_secret())?;
        if durable.promotion_id != promotion_id {
            return Err(PairedPromotionError::Conflict);
        }
        Ok(durable)
    }

    fn open_state_store(
        &self,
        root_fingerprint: MachineRootFingerprint,
        machine_route: MachineRouteId,
        kek: DeviceStorageKek,
    ) -> Result<FileCryptoStateStore, PairedPromotionError> {
        FileCryptoStateStore::new_in(
            &self.state_root,
            CryptoStateIdentity::new(self.installation_id, root_fingerprint, machine_route),
            kek,
        )
        .map_err(PairedPromotionError::CryptoState)
    }

    /// immutable state 已存在但 KEK 缺失时不可生成替代 KEK；否则会把离线损坏扩大成
    /// 一个看似可恢复、实际永远无法解密的 provisional account。
    fn reject_state_without_kek(
        &self,
        root_fingerprint: MachineRootFingerprint,
        machine_route: MachineRouteId,
    ) -> Result<(), PairedPromotionError> {
        let probe = self.open_state_store(
            root_fingerprint,
            machine_route,
            DeviceStorageKek::new([0; 32]),
        )?;
        match probe.load() {
            Ok(None) => Ok(()),
            Ok(Some(_)) | Err(CryptoStateError::AuthenticationFailed) => {
                Err(PairedPromotionError::Incomplete)
            }
            Err(error) => Err(PairedPromotionError::CryptoState(error)),
        }
    }

    fn persist_exact(
        &self,
        account: &RemoteKeyAccount,
        value: &RemoteSecret,
    ) -> Result<(), PairedPromotionError> {
        match self.store.persist_immutable(account, value) {
            Ok(_) => {}
            Err(RemoteKeyStoreError::ImmutableConflict { .. }) => {
                return Err(PairedPromotionError::Conflict);
            }
            Err(error) => return Err(PairedPromotionError::Persistence(error)),
        }
        let durable = self
            .store
            .load(account)
            .map_err(PairedPromotionError::Persistence)?
            .ok_or(PairedPromotionError::Incomplete)?;
        if durable.expose_secret() != value.expose_secret() {
            return Err(PairedPromotionError::Conflict);
        }
        Ok(())
    }

    #[allow(clippy::too_many_arguments)]
    fn audit_committed(
        &self,
        accounts: &PairedAccounts,
        verified: &agentdeck_crypto::VerifiedPairResponseV1,
        invite: &PendingInvitePublicProjection,
        promotion_id: [u8; 32],
        marker_bytes: &[u8],
        already_committed: bool,
    ) -> Result<PromotedPairedMachine, PairedPromotionError> {
        let marker = PairedCommitMarkerV1::decode(marker_bytes)?;
        marker.validate_expected(self.installation_id, verified, promotion_id)?;

        let kek_secret = self.load_required(&accounts.kek)?;
        let kek_record = StorageKekRecordV1::decode(kek_secret.expose_secret())?;
        if kek_record.promotion_id != promotion_id
            || marker.kek_record_hash != kek_record.commitment()
        {
            return Err(PairedPromotionError::Conflict);
        }
        let state_store = self.open_state_store(
            MachineRootFingerprint::from_bytes(verified.machine_root_fingerprint()),
            verified.info().machine_route,
            kek_record.device_storage_kek(),
        )?;
        let state_snapshot = state_store
            .load()
            .map_err(PairedPromotionError::CryptoState)?
            .ok_or(PairedPromotionError::Incomplete)?;
        let state = PairedCryptoState::decode(state_snapshot.expose_secret())?;
        let identity = PairedMachineIdentity::new(
            MachineRootFingerprint::from_bytes(verified.machine_root_fingerprint()),
            verified.info().machine_route,
        );
        marker.validate_state(identity, &state, state_snapshot.expose_secret())?;
        let bootstrap = state.bootstrap();

        let device_sign = self.load_required(&accounts.device_sign)?;
        let device_hpke = self.load_required(&accounts.device_hpke)?;
        let grant = self.load_required(&accounts.grant)?;
        let counter = self.load_required(&accounts.counter_guard)?;
        let signing_key = signing_key(&device_sign)?;
        let hpke_private = hpke_private_key(&device_hpke)?;
        let audit = audit_state(
            self.installation_id,
            bootstrap,
            verified,
            invite,
            grant.expose_secret(),
            &device_sign,
            &device_hpke,
        )?;
        let counter_guard = CounterGuardState::decode(counter.expose_secret())?;
        validate_counter_guard_state(
            &marker,
            &counter_guard,
            counter.expose_secret(),
            &state,
            state_snapshot.expose_secret(),
            audit.device_command_binding,
        )?;
        if marker.device_sign_pubkey != signing_key.verifying_key().to_bytes()
            || marker.device_hpke_pubkey != hpke_public_bytes(&hpke_private)?
            || marker.receipt_carrier_hash != sha256(&bootstrap.receipt_carrier)
        {
            return Err(PairedPromotionError::Conflict);
        }

        Ok(PromotedPairedMachine {
            state_path: state_store.state_path().to_path_buf(),
            canonical_receipt_carrier: bootstrap.receipt_carrier.clone(),
            machine_route: bootstrap.machine_route,
            device_route: bootstrap.device_route,
            request_hash: bootstrap.request_hash,
            grant_hash: bootstrap.grant_hash,
            response_hash: bootstrap.response_hash,
            already_committed,
        })
    }

    fn load_required(
        &self,
        account: &RemoteKeyAccount,
    ) -> Result<RemoteSecret, PairedPromotionError> {
        self.store
            .load(account)
            .map_err(PairedPromotionError::Persistence)?
            .ok_or(PairedPromotionError::Incomplete)
    }
}

struct PendingSecrets {
    device_sign: RemoteSecret,
    device_hpke: RemoteSecret,
}

struct PairedAccounts {
    device_sign: RemoteKeyAccount,
    device_hpke: RemoteKeyAccount,
    grant: RemoteKeyAccount,
    kek: RemoteKeyAccount,
    counter_guard: RemoteKeyAccount,
    marker: RemoteKeyAccount,
}

impl PairedAccounts {
    fn new(
        installation_id: Uuid,
        root_fingerprint: MachineRootFingerprint,
        machine_route: MachineRouteId,
    ) -> Self {
        let account = |purpose| {
            RemoteKeyAccount::paired(installation_id, root_fingerprint, machine_route, purpose)
        };
        Self {
            device_sign: account(PairedRemoteKeyPurpose::DeviceSignPrivateKey),
            device_hpke: account(PairedRemoteKeyPurpose::DeviceHpkePrivateKey),
            grant: account(PairedRemoteKeyPurpose::DeviceGrant),
            kek: account(PairedRemoteKeyPurpose::DeviceStorageKek),
            counter_guard: account(PairedRemoteKeyPurpose::CounterGuard),
            marker: account(PairedRemoteKeyPurpose::CommitMarker),
        }
    }
}

fn signing_key(secret: &RemoteSecret) -> Result<SigningKey, PairedPromotionError> {
    let mut seed: [u8; 32] = secret
        .expose_secret()
        .try_into()
        .map_err(|_| PairedPromotionError::InvalidState)?;
    let key = SigningKey::from_seed(&seed);
    seed.zeroize();
    Ok(key)
}

fn hpke_private_key(secret: &RemoteSecret) -> Result<HpkePrivateKey, PairedPromotionError> {
    HpkePrivateKey::from_bytes(secret.expose_secret()).map_err(PairedPromotionError::Crypto)
}

fn hpke_public_bytes(private: &HpkePrivateKey) -> Result<[u8; 32], PairedPromotionError> {
    private
        .public_key()
        .to_bytes()
        .try_into()
        .map_err(|_| PairedPromotionError::InvalidState)
}

fn validate_pending_keys(
    verified: &agentdeck_crypto::VerifiedPairResponseV1,
    signing_key: &SigningKey,
    hpke_private: &HpkePrivateKey,
) -> Result<(), PairedPromotionError> {
    if verified.relay_grant().device_sign_pubkey.0 != signing_key.verifying_key().to_bytes()
        || verified.device_authorization().device_hpke_pubkey.0 != hpke_public_bytes(hpke_private)?
    {
        return Err(PairedPromotionError::Conflict);
    }
    Ok(())
}

fn promotion_id(
    installation_id: Uuid,
    verified: &agentdeck_crypto::VerifiedPairResponseV1,
) -> [u8; 32] {
    let info = verified.info();
    promotion_id_from_parts(
        installation_id,
        info.invite_hash,
        info.request_hash,
        verified.response_hash(),
        verified.machine_root_fingerprint(),
        info.machine_route,
    )
}

fn promotion_id_from_parts(
    installation_id: Uuid,
    invite_hash: [u8; 32],
    request_hash: [u8; 32],
    response_hash: [u8; 32],
    machine_root_fingerprint: [u8; 32],
    machine_route: MachineRouteId,
) -> [u8; 32] {
    let mut input = Vec::with_capacity(PROMOTION_ID_DOMAIN.len() + 176);
    input.extend_from_slice(PROMOTION_ID_DOMAIN);
    input.extend_from_slice(installation_id.as_bytes());
    input.extend_from_slice(&invite_hash);
    input.extend_from_slice(&request_hash);
    input.extend_from_slice(&response_hash);
    input.extend_from_slice(&machine_root_fingerprint);
    input.extend_from_slice(machine_route.as_bytes());
    sha256(&input)
}

fn response_received_context(
    pair_route: agentdeck_protocol::relay_v2::PairRouteId,
) -> OuterContextV1 {
    OuterContextV1 {
        frame_kind: OuterFrameKind::PairResponseReceived,
        relay_protocol_version: RELAY_PROTOCOL_VERSION,
        e2ee_format_version: E2EE_FORMAT_VERSION,
        machine_route: None,
        device_route: None,
        stream_route: None,
        request_route: None,
        pair_route: Some(pair_route),
        stream_generation: None,
        stream_cursor: None,
        stream_seq: None,
        message_key_epoch: 0,
    }
}

fn pair_response_context(pair_route: agentdeck_protocol::relay_v2::PairRouteId) -> OuterContextV1 {
    OuterContextV1 {
        frame_kind: OuterFrameKind::PairResponse,
        relay_protocol_version: RELAY_PROTOCOL_VERSION,
        e2ee_format_version: E2EE_FORMAT_VERSION,
        machine_route: None,
        device_route: None,
        stream_route: None,
        request_route: None,
        pair_route: Some(pair_route),
        stream_generation: None,
        stream_cursor: None,
        stream_seq: None,
        message_key_epoch: 0,
    }
}

fn key_update_context(info: &KeyUpdateInfoV1) -> OuterContextV1 {
    OuterContextV1 {
        frame_kind: OuterFrameKind::KeyUpdate,
        relay_protocol_version: RELAY_PROTOCOL_VERSION,
        e2ee_format_version: E2EE_FORMAT_VERSION,
        machine_route: Some(info.machine_route),
        device_route: Some(info.device_route),
        stream_route: info.stream_route,
        request_route: None,
        pair_route: None,
        stream_generation: None,
        stream_cursor: None,
        stream_seq: None,
        message_key_epoch: info.key_epoch,
    }
}

fn build_initial_state<R: CryptoRng>(
    installation_id: Uuid,
    verified: &agentdeck_crypto::VerifiedPairResponseV1,
    invite: &PendingInvitePublicProjection,
    promotion_id: [u8; 32],
    device_signing_key: &SigningKey,
    rng: &mut R,
) -> Result<PairedCryptoStateV1, PairedPromotionError> {
    let info = verified.info();
    let grant_hash = verified.relay_grant().canonical_sha256();
    let invite_recipient = HpkePublicKey::from_bytes(&invite.invite_hpke_pubkey)
        .map_err(PairedPromotionError::Crypto)?;
    let receipt = seal_pair_response_received(
        &invite_recipient,
        info,
        &response_received_context(info.pair_route),
        PairResponseReceivedV1 {
            request_hash: info.request_hash,
            grant_hash,
            response_hash: verified.response_hash(),
            signature: Ed25519Signature([0; 64]),
        },
        device_signing_key,
        rng,
    )
    .map_err(PairedPromotionError::Crypto)?
    .canonical_bytes()
    .map_err(PairedPromotionError::Protocol)?;

    Ok(PairedCryptoStateV1 {
        installation_id,
        invite_hpke_pubkey: invite.invite_hpke_pubkey,
        wss_url: invite.wss_url.clone(),
        current_spki_pin: invite.current_spki_pin,
        next_spki_pin: invite.next_spki_pin,
        machine_display_name: invite.machine_display_name.clone(),
        relay_server_id: info.relay_server_id,
        machine_root_pubkey: verified.machine_root_pubkey().0,
        machine_root_fingerprint: verified.machine_root_fingerprint(),
        machine_route: info.machine_route,
        device_route: info.device_route,
        grant_serial: info.grant_serial,
        trust_epoch: info.root_trust_epoch,
        invite_hash: info.invite_hash,
        request_hash: info.request_hash,
        grant_hash,
        response_hash: verified.response_hash(),
        promotion_id,
        directory_revision: verified.key_directory().revision,
        canonical_response: verified.canonical_response().to_vec(),
        data_sign_certificate: verified.data_sign_certificate().canonical_bytes(),
        device_authorization: verified
            .device_authorization()
            .canonical_bytes()
            .map_err(PairedPromotionError::Protocol)?,
        key_directory: verified
            .key_directory()
            .canonical_bytes()
            .map_err(PairedPromotionError::Protocol)?,
        receipt_carrier: receipt,
    })
}

struct StateAudit {
    device_command_binding: CounterBindingV1,
}

struct DurableStateAudit {
    device_signing_key: SigningKey,
    device_hpke_private_key: HpkePrivateKey,
    grant: RelayGrant,
    authorization: DeviceAuthorizationV1,
    opened_keys: Vec<OpenedPairedDirectoryKey>,
    device_command_binding: CounterBindingV1,
}

#[allow(clippy::too_many_arguments)]
fn audit_state(
    installation_id: Uuid,
    state: &PairedCryptoStateV1,
    verified: &agentdeck_crypto::VerifiedPairResponseV1,
    invite: &PendingInvitePublicProjection,
    grant_bytes: &[u8],
    device_sign_secret: &RemoteSecret,
    device_hpke_secret: &RemoteSecret,
) -> Result<StateAudit, PairedPromotionError> {
    let expected_info = verified.info();
    if state.installation_id != installation_id
        || state.invite_hpke_pubkey != invite.invite_hpke_pubkey
        || state.wss_url != invite.wss_url
        || state.current_spki_pin != invite.current_spki_pin
        || state.next_spki_pin != invite.next_spki_pin
        || state.machine_display_name != invite.machine_display_name
        || state.relay_server_id != expected_info.relay_server_id
        || state.machine_root_pubkey != verified.machine_root_pubkey().0
        || state.machine_root_fingerprint != verified.machine_root_fingerprint()
        || state.machine_route != expected_info.machine_route
        || state.device_route != expected_info.device_route
        || state.grant_serial != expected_info.grant_serial
        || state.trust_epoch != expected_info.root_trust_epoch
        || state.invite_hash != expected_info.invite_hash
        || state.request_hash != expected_info.request_hash
        || state.grant_hash != verified.relay_grant().canonical_sha256()
        || state.response_hash != verified.response_hash()
        || state.promotion_id != promotion_id(installation_id, verified)
        || state.directory_revision != verified.key_directory().revision
        || state.canonical_response != verified.canonical_response()
        || state.data_sign_certificate != verified.data_sign_certificate().canonical_bytes()
        || state.device_authorization
            != verified
                .device_authorization()
                .canonical_bytes()
                .map_err(PairedPromotionError::Protocol)?
        || state.key_directory
            != verified
                .key_directory()
                .canonical_bytes()
                .map_err(PairedPromotionError::Protocol)?
        || grant_bytes != verified.relay_grant().canonical_bytes()
    {
        return Err(PairedPromotionError::Conflict);
    }

    let durable = audit_durable_state(state, grant_bytes, device_sign_secret, device_hpke_secret)?;
    Ok(StateAudit {
        device_command_binding: durable.device_command_binding,
    })
}

/// 不依赖 pending transaction 的 durable paired state 全审计。
///
/// canonical PairResponse 会再次以 paired DeviceHPKE 解密，随后 exact 比对并复核
/// Root→Data cert、grant/authorization、directory 签名，再逐项重新解封 wrapped keys。
fn audit_durable_state(
    state: &PairedCryptoStateV1,
    grant_bytes: &[u8],
    device_sign_secret: &RemoteSecret,
    device_hpke_secret: &RemoteSecret,
) -> Result<DurableStateAudit, PairedPromotionError> {
    let response = PairResponseV1::from_canonical_bytes(&state.canonical_response)
        .map_err(PairedPromotionError::Protocol)?;
    let info = &response.info;
    if state.relay_server_id != info.relay_server_id
        || state.machine_route != info.machine_route
        || state.device_route != info.device_route
        || state.grant_serial != info.grant_serial
        || state.trust_epoch != info.root_trust_epoch
        || state.invite_hash != info.invite_hash
        || state.request_hash != info.request_hash
        || state.response_hash != sha256(&state.canonical_response)
        || state.promotion_id
            != promotion_id_from_parts(
                state.installation_id,
                state.invite_hash,
                state.request_hash,
                state.response_hash,
                state.machine_root_fingerprint,
                state.machine_route,
            )
    {
        return Err(PairedPromotionError::Conflict);
    }
    let certificate = SignedCertificate::from_canonical_bytes(&state.data_sign_certificate)
        .map_err(PairedPromotionError::AuthCanonical)?;
    let grant = RelayGrant::from_canonical_bytes(grant_bytes)
        .map_err(PairedPromotionError::AuthCanonical)?;
    let authorization = DeviceAuthorizationV1::from_canonical_bytes(&state.device_authorization)
        .map_err(PairedPromotionError::Protocol)?;
    let directory = KeyDirectoryV1::from_canonical_bytes(&state.key_directory)
        .map_err(PairedPromotionError::Protocol)?;
    PairingControlEnvelopeV1::from_canonical_bytes(&state.receipt_carrier)
        .map_err(PairedPromotionError::Protocol)?;

    if state.grant_hash != grant.canonical_sha256()
        || state.directory_revision != directory.revision
        || grant.machine_route != state.machine_route
        || grant.device_route != state.device_route
        || grant.grant_serial != state.grant_serial
        || grant.trust_epoch != state.trust_epoch
    {
        return Err(PairedPromotionError::Conflict);
    }

    let root = VerifyingKey::from_bytes(&state.machine_root_pubkey)
        .map_err(PairedPromotionError::Crypto)?;
    if sha256(&root.to_bytes()) != state.machine_root_fingerprint
        || certificate.cert_role != CertRole::Data
        || certificate.root_key_id != grant.root_key_id
        || certificate.trust_epoch != state.trust_epoch
    {
        return Err(PairedPromotionError::Conflict);
    }
    verify_tbs(
        &root,
        &certificate.to_be_signed_v1(
            state.relay_server_id,
            state.machine_route,
            state.machine_root_fingerprint,
        ),
        &SignatureBytes::from(certificate.signature),
    )
    .map_err(PairedPromotionError::Crypto)?;
    verify_tbs(
        &root,
        &grant.to_be_signed_v1(state.relay_server_id, state.machine_root_fingerprint),
        &SignatureBytes::from(grant.signature),
    )
    .map_err(PairedPromotionError::Crypto)?;

    let data_verifier = VerifyingKey::from_bytes(&certificate.subject_pubkey.0)
        .map_err(PairedPromotionError::Crypto)?;
    let signer = MachineDataSignerBindingV1::from_certificate(&certificate)
        .map_err(PairedPromotionError::Protocol)?;
    let signing_key = signing_key(device_sign_secret)?;
    let hpke_private = hpke_private_key(device_hpke_secret)?;
    let plaintext = open_pair_response(
        &hpke_private,
        info,
        &pair_response_context(info.pair_route),
        &response,
        &data_verifier,
        &signer,
        &root,
    )
    .map_err(PairedPromotionError::Crypto)?;
    if plaintext.request_hash != state.request_hash
        || plaintext.relay_grant.canonical_bytes() != grant_bytes
        || plaintext
            .device_authorization
            .canonical_bytes()
            .map_err(PairedPromotionError::Protocol)?
            != state.device_authorization
        || plaintext
            .key_directory
            .canonical_bytes()
            .map_err(PairedPromotionError::Protocol)?
            != state.key_directory
        || authorization
            .canonical_bytes()
            .map_err(PairedPromotionError::Protocol)?
            != state.device_authorization
        || directory
            .canonical_bytes()
            .map_err(PairedPromotionError::Protocol)?
            != state.key_directory
        || grant.device_sign_pubkey.0 != signing_key.verifying_key().to_bytes()
        || authorization.device_hpke_pubkey.0 != hpke_public_bytes(&hpke_private)?
    {
        return Err(PairedPromotionError::Conflict);
    }

    let mut slots = HashSet::with_capacity(directory.entries.len());
    let mut command_binding = None;
    let mut opened_keys = Vec::with_capacity(directory.entries.len());
    for entry in &directory.entries {
        if !slots.insert((entry.key_id.purpose, entry.stream_route)) {
            return Err(PairedPromotionError::InvalidState);
        }
        let entry_info = KeyUpdateInfoV1 {
            e2ee_format_version: E2EE_FORMAT_VERSION,
            runtime_protocol_version: RUNTIME_PROTOCOL_VERSION,
            relay_server_id: state.relay_server_id,
            machine_route: state.machine_route,
            device_route: state.device_route,
            stream_route: entry.stream_route,
            grant_serial: state.grant_serial,
            root_trust_epoch: state.trust_epoch,
            key_directory_revision: directory.revision,
            key_purpose: entry.key_id.purpose,
            key_epoch: entry.key_id.epoch,
        };
        let key = open_key_directory_entry(
            &hpke_private,
            &entry_info,
            &key_update_context(&entry_info),
            entry,
        )
        .map_err(PairedPromotionError::Crypto)?;
        if entry.key_id.purpose == KeyPurpose::DeviceCommandTx {
            if entry.stream_route.is_some() || command_binding.is_some() {
                return Err(PairedPromotionError::InvalidState);
            }
            command_binding = Some(CounterBindingV1 {
                key_epoch: entry.key_id.epoch,
                nonce_prefix: agentdeck_crypto::derive_nonce_prefix(&key),
            });
        }
        opened_keys.push(OpenedPairedDirectoryKey {
            _key_id: entry.key_id,
            _stream_route: entry.stream_route,
            _key: key,
        });
    }

    Ok(DurableStateAudit {
        device_signing_key: signing_key,
        device_hpke_private_key: hpke_private,
        grant,
        authorization,
        opened_keys,
        device_command_binding: command_binding.ok_or(PairedPromotionError::InvalidState)?,
    })
}

fn validate_counter_guard_state(
    marker: &PairedCommitMarkerV1,
    guard: &CounterGuardState,
    guard_bytes: &[u8],
    state: &PairedCryptoState,
    state_bytes: &[u8],
    expected_binding: CounterBindingV1,
) -> Result<(), PairedPromotionError> {
    let state_hash = sha256(state_bytes);
    match (*guard, state) {
        (CounterGuardState::V1(value), PairedCryptoState::V1(_))
            if value
                == CounterGuardV1::from_binding(marker.directory_revision, expected_binding)
                && sha256(guard_bytes) == marker.counter_guard_hash =>
        {
            Ok(())
        }
        (CounterGuardState::V1(_), PairedCryptoState::V1(_)) => Err(PairedPromotionError::Conflict),
        (CounterGuardState::V1(_), PairedCryptoState::V2(_)) => Err(PairedPromotionError::Conflict),
        (CounterGuardState::V2(value), _) => {
            if value.initial_guard_commitment != marker.counter_guard_hash
                || value.directory_revision != marker.directory_revision
                || value.binding != expected_binding
            {
                return Err(PairedPromotionError::Conflict);
            }
            match value.phase {
                CounterGuardPhaseV2::Stable {
                    reserved_high_water,
                    current_state_hash,
                } if current_state_hash == state_hash
                    && state_matches_stable_high_water(state, reserved_high_water) =>
                {
                    Ok(())
                }
                CounterGuardPhaseV2::Pending {
                    previous_high_water,
                    next_high_water,
                    reservation_id,
                    previous_state_hash,
                    next_state_hash,
                } if state_hash == previous_state_hash
                    && state_matches_previous_high_water(state, previous_high_water) =>
                {
                    let expected = CommandCounterReservation {
                        reservation_id,
                        start: previous_high_water,
                        end_exclusive: next_high_water,
                    };
                    expected.validate()?;
                    rebuild_frozen_counter_state(marker, state, expected, next_state_hash)?;
                    Ok(())
                }
                CounterGuardPhaseV2::Pending {
                    previous_high_water,
                    next_high_water,
                    reservation_id,
                    previous_state_hash: _,
                    next_state_hash,
                } if state_hash == next_state_hash => {
                    let expected = CommandCounterReservation {
                        reservation_id,
                        start: previous_high_water,
                        end_exclusive: next_high_water,
                    };
                    expected.validate()?;
                    if state.counter_reservation() == Some(&expected) {
                        Ok(())
                    } else {
                        Err(PairedPromotionError::Conflict)
                    }
                }
                _ => Err(PairedPromotionError::Conflict),
            }
        }
    }
}

/// 纯只读地重建 Pending 冻结的 canonical next state；inventory audit 与 recovery
/// 共用这一条路径，避免 `list()` 接受一个直到 `open()` 才发现不可恢复的 transition。
fn rebuild_frozen_counter_state(
    marker: &PairedCommitMarkerV1,
    previous: &PairedCryptoState,
    reservation: CommandCounterReservation,
    expected_state_hash: [u8; 32],
) -> Result<(PairedCryptoState, CryptoStateSnapshot), PairedPromotionError> {
    let next = previous.with_counter_reservation(
        marker.state_plaintext_hash,
        marker.counter_guard_hash,
        &reservation,
    )?;
    let encoded = next.encode()?;
    if sha256(&encoded) != expected_state_hash {
        return Err(PairedPromotionError::Conflict);
    }
    Ok((next, CryptoStateSnapshot::new(encoded)))
}

fn state_matches_previous_high_water(state: &PairedCryptoState, high_water: u64) -> bool {
    match state {
        // V1 guard 本身只编码初始 HWM=0；任何非零值都必须已有 V2 sealed fence。
        PairedCryptoState::V1(_) => high_water == 0,
        PairedCryptoState::V2(_) => state
            .counter_reservation()
            .is_some_and(|reservation| reservation.end_exclusive == high_water),
    }
}

fn state_matches_stable_high_water(state: &PairedCryptoState, high_water: u64) -> bool {
    match state {
        // stable V2 总在 sealed-state CAS 之后；V1 state 是不可能的 durable 顺序。
        PairedCryptoState::V1(_) => false,
        PairedCryptoState::V2(_) => state
            .counter_reservation()
            .is_some_and(|reservation| reservation.end_exclusive == high_water),
    }
}

struct StorageKekRecordV1 {
    promotion_id: [u8; 32],
    key: [u8; 32],
}

impl fmt::Debug for StorageKekRecordV1 {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("StorageKekRecordV1([REDACTED])")
    }
}

impl Drop for StorageKekRecordV1 {
    fn drop(&mut self) {
        self.key.zeroize();
    }
}

impl StorageKekRecordV1 {
    fn encode(&self) -> Vec<u8> {
        let mut encoded = Vec::with_capacity(72);
        encoded.extend_from_slice(KEK_MAGIC);
        encoded.extend_from_slice(&KEK_VERSION.to_be_bytes());
        encoded.extend_from_slice(&[0, 0]);
        encoded.extend_from_slice(&self.promotion_id);
        encoded.extend_from_slice(&self.key);
        encoded
    }

    fn commitment(&self) -> [u8; 32] {
        sha256(&Zeroizing::new(self.encode()))
    }

    fn decode(bytes: &[u8]) -> Result<Self, PairedPromotionError> {
        if bytes.len() != 72
            || &bytes[..4] != KEK_MAGIC
            || u16::from_be_bytes([bytes[4], bytes[5]]) != KEK_VERSION
            || bytes[6..8] != [0, 0]
        {
            return Err(PairedPromotionError::InvalidState);
        }
        let promotion_id: [u8; 32] = bytes[8..40]
            .try_into()
            .map_err(|_| PairedPromotionError::InvalidState)?;
        let key: [u8; 32] = bytes[40..72]
            .try_into()
            .map_err(|_| PairedPromotionError::InvalidState)?;
        if all_zero(&promotion_id) || all_zero(&key) {
            return Err(PairedPromotionError::InvalidState);
        }
        let value = Self { promotion_id, key };
        if value.encode() != bytes {
            return Err(PairedPromotionError::InvalidState);
        }
        Ok(value)
    }

    fn device_storage_kek(&self) -> DeviceStorageKek {
        DeviceStorageKek::new(self.key)
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
struct CounterBindingV1 {
    key_epoch: u64,
    nonce_prefix: [u8; 4],
}

#[derive(Clone, Copy, Eq, PartialEq)]
enum CounterGuardState {
    V1(CounterGuardV1),
    V2(CounterGuardV2),
}

impl fmt::Debug for CounterGuardState {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("CounterGuardState([REDACTED])")
    }
}

impl CounterGuardState {
    fn decode(bytes: &[u8]) -> Result<Self, PairedPromotionError> {
        if bytes.len() < 8 || &bytes[..4] != COUNTER_GUARD_MAGIC {
            return Err(PairedPromotionError::InvalidState);
        }
        match u16::from_be_bytes([bytes[4], bytes[5]]) {
            COUNTER_GUARD_VERSION => CounterGuardV1::decode(bytes).map(Self::V1),
            MUTABLE_COUNTER_GUARD_VERSION => CounterGuardV2::decode(bytes).map(Self::V2),
            _ => Err(PairedPromotionError::InvalidState),
        }
    }

    fn encode(self) -> Vec<u8> {
        match self {
            Self::V1(value) => value.encode(),
            Self::V2(value) => value.encode(),
        }
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
struct CounterGuardV1 {
    directory_revision: KeyDirectoryRevision,
    binding: CounterBindingV1,
    reserved_high_water: u64,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum CounterGuardPhaseV2 {
    Stable {
        reserved_high_water: u64,
        current_state_hash: [u8; 32],
    },
    Pending {
        previous_high_water: u64,
        next_high_water: u64,
        reservation_id: [u8; 16],
        previous_state_hash: [u8; 32],
        next_state_hash: [u8; 32],
    },
}

#[derive(Clone, Copy, Eq, PartialEq)]
struct CounterGuardV2 {
    initial_guard_commitment: [u8; 32],
    directory_revision: KeyDirectoryRevision,
    binding: CounterBindingV1,
    phase: CounterGuardPhaseV2,
}

impl fmt::Debug for CounterGuardV2 {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("CounterGuardV2([REDACTED])")
    }
}

impl CounterGuardV2 {
    fn stable(
        initial_guard_commitment: [u8; 32],
        directory_revision: KeyDirectoryRevision,
        binding: CounterBindingV1,
        reserved_high_water: u64,
        current_state_hash: [u8; 32],
    ) -> Result<Self, PairedPromotionError> {
        let value = Self {
            initial_guard_commitment,
            directory_revision,
            binding,
            phase: CounterGuardPhaseV2::Stable {
                reserved_high_water,
                current_state_hash,
            },
        };
        value.validate()?;
        Ok(value)
    }

    #[allow(clippy::too_many_arguments)]
    fn pending(
        initial_guard_commitment: [u8; 32],
        directory_revision: KeyDirectoryRevision,
        binding: CounterBindingV1,
        previous_high_water: u64,
        next_high_water: u64,
        reservation_id: [u8; 16],
        previous_state_hash: [u8; 32],
        next_state_hash: [u8; 32],
    ) -> Result<Self, PairedPromotionError> {
        let value = Self {
            initial_guard_commitment,
            directory_revision,
            binding,
            phase: CounterGuardPhaseV2::Pending {
                previous_high_water,
                next_high_water,
                reservation_id,
                previous_state_hash,
                next_state_hash,
            },
        };
        value.validate()?;
        Ok(value)
    }

    fn encode(self) -> Vec<u8> {
        let mut encoded = Vec::with_capacity(match self.phase {
            CounterGuardPhaseV2::Stable { .. } => 100,
            CounterGuardPhaseV2::Pending { .. } => 156,
        });
        encoded.extend_from_slice(COUNTER_GUARD_MAGIC);
        encoded.extend_from_slice(&MUTABLE_COUNTER_GUARD_VERSION.to_be_bytes());
        encoded.push(match self.phase {
            CounterGuardPhaseV2::Stable { .. } => 0,
            CounterGuardPhaseV2::Pending { .. } => 1,
        });
        encoded.push(0);
        encoded.extend_from_slice(&self.initial_guard_commitment);
        encoded.extend_from_slice(&self.directory_revision.value().to_be_bytes());
        encoded.extend_from_slice(&self.binding.key_epoch.to_be_bytes());
        encoded.extend_from_slice(&self.binding.nonce_prefix);
        match self.phase {
            CounterGuardPhaseV2::Stable {
                reserved_high_water,
                current_state_hash,
            } => {
                encoded.extend_from_slice(&reserved_high_water.to_be_bytes());
                encoded.extend_from_slice(&current_state_hash);
            }
            CounterGuardPhaseV2::Pending {
                previous_high_water,
                next_high_water,
                reservation_id,
                previous_state_hash,
                next_state_hash,
            } => {
                encoded.extend_from_slice(&previous_high_water.to_be_bytes());
                encoded.extend_from_slice(&next_high_water.to_be_bytes());
                encoded.extend_from_slice(&reservation_id);
                encoded.extend_from_slice(&previous_state_hash);
                encoded.extend_from_slice(&next_state_hash);
            }
        }
        encoded
    }

    fn decode(bytes: &[u8]) -> Result<Self, PairedPromotionError> {
        if !matches!(bytes.len(), 100 | 156)
            || &bytes[..4] != COUNTER_GUARD_MAGIC
            || u16::from_be_bytes([bytes[4], bytes[5]]) != MUTABLE_COUNTER_GUARD_VERSION
            || bytes[7] != 0
        {
            return Err(PairedPromotionError::InvalidState);
        }
        let mut decoder = StateDecoder::new(&bytes[8..]);
        let initial_guard_commitment = decoder.fixed()?;
        let directory_revision = KeyDirectoryRevision::new(decoder.u64()?);
        let binding = CounterBindingV1 {
            key_epoch: decoder.u64()?,
            nonce_prefix: decoder.fixed()?,
        };
        let value = match bytes[6] {
            0 if bytes.len() == 100 => Self::stable(
                initial_guard_commitment,
                directory_revision,
                binding,
                decoder.u64()?,
                decoder.fixed()?,
            )?,
            1 if bytes.len() == 156 => Self::pending(
                initial_guard_commitment,
                directory_revision,
                binding,
                decoder.u64()?,
                decoder.u64()?,
                decoder.fixed()?,
                decoder.fixed()?,
                decoder.fixed()?,
            )?,
            _ => return Err(PairedPromotionError::InvalidState),
        };
        decoder.finish()?;
        if value.encode() != bytes {
            return Err(PairedPromotionError::InvalidState);
        }
        Ok(value)
    }

    fn validate(self) -> Result<(), PairedPromotionError> {
        if all_zero(&self.initial_guard_commitment)
            || self.directory_revision.value() == 0
            || self.binding.key_epoch == 0
        {
            return Err(PairedPromotionError::InvalidState);
        }
        match self.phase {
            CounterGuardPhaseV2::Stable {
                reserved_high_water,
                current_state_hash,
            } if reserved_high_water == 0
                || !reserved_high_water.is_multiple_of(COUNTER_BLOCK_SIZE)
                || all_zero(&current_state_hash) =>
            {
                Err(PairedPromotionError::InvalidState)
            }
            CounterGuardPhaseV2::Pending {
                previous_high_water,
                next_high_water,
                reservation_id,
                previous_state_hash,
                next_state_hash,
            } if !previous_high_water.is_multiple_of(COUNTER_BLOCK_SIZE)
                || previous_high_water
                    .checked_add(COUNTER_BLOCK_SIZE)
                    .is_none_or(|end| end != next_high_water)
                || all_zero(&reservation_id)
                || all_zero(&previous_state_hash)
                || all_zero(&next_state_hash)
                || previous_state_hash == next_state_hash =>
            {
                Err(PairedPromotionError::InvalidState)
            }
            _ => Ok(()),
        }
    }
}

impl CounterGuardV1 {
    fn from_binding(directory_revision: KeyDirectoryRevision, binding: CounterBindingV1) -> Self {
        Self {
            directory_revision,
            binding,
            reserved_high_water: 0,
        }
    }

    fn encode(&self) -> Vec<u8> {
        let mut encoded = Vec::with_capacity(36);
        encoded.extend_from_slice(COUNTER_GUARD_MAGIC);
        encoded.extend_from_slice(&COUNTER_GUARD_VERSION.to_be_bytes());
        encoded.extend_from_slice(&[0, 0]);
        encoded.extend_from_slice(&self.directory_revision.value().to_be_bytes());
        encoded.extend_from_slice(&self.binding.key_epoch.to_be_bytes());
        encoded.extend_from_slice(&self.binding.nonce_prefix);
        encoded.extend_from_slice(&self.reserved_high_water.to_be_bytes());
        encoded
    }

    fn decode(bytes: &[u8]) -> Result<Self, PairedPromotionError> {
        if bytes.len() != 36
            || &bytes[..4] != COUNTER_GUARD_MAGIC
            || u16::from_be_bytes([bytes[4], bytes[5]]) != COUNTER_GUARD_VERSION
            || bytes[6..8] != [0, 0]
        {
            return Err(PairedPromotionError::InvalidState);
        }
        let value = Self {
            directory_revision: KeyDirectoryRevision::new(read_u64(&bytes[8..16])?),
            binding: CounterBindingV1 {
                key_epoch: read_u64(&bytes[16..24])?,
                nonce_prefix: bytes[24..28]
                    .try_into()
                    .map_err(|_| PairedPromotionError::InvalidState)?,
            },
            reserved_high_water: read_u64(&bytes[28..36])?,
        };
        if value.directory_revision.value() == 0
            || value.binding.key_epoch == 0
            || value.reserved_high_water != 0
            || value.encode() != bytes
        {
            return Err(PairedPromotionError::InvalidState);
        }
        Ok(value)
    }
}

#[derive(Clone)]
struct PairedCryptoStateV1 {
    installation_id: Uuid,
    invite_hpke_pubkey: [u8; 32],
    wss_url: String,
    current_spki_pin: [u8; 32],
    next_spki_pin: [u8; 32],
    machine_display_name: String,
    relay_server_id: RelayServerId,
    machine_root_pubkey: [u8; 32],
    machine_root_fingerprint: [u8; 32],
    machine_route: MachineRouteId,
    device_route: DeviceRouteId,
    grant_serial: GrantSerial,
    trust_epoch: TrustEpoch,
    invite_hash: [u8; 32],
    request_hash: [u8; 32],
    grant_hash: [u8; 32],
    response_hash: [u8; 32],
    promotion_id: [u8; 32],
    directory_revision: KeyDirectoryRevision,
    canonical_response: Vec<u8>,
    data_sign_certificate: Vec<u8>,
    device_authorization: Vec<u8>,
    key_directory: Vec<u8>,
    receipt_carrier: Vec<u8>,
}

impl fmt::Debug for PairedCryptoStateV1 {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("PairedCryptoStateV1([REDACTED])")
    }
}

impl PairedCryptoStateV1 {
    fn encode(&self) -> Result<Vec<u8>, PairedPromotionError> {
        self.validate_shape()?;
        let mut body = Vec::new();
        body.extend_from_slice(self.installation_id.as_bytes());
        body.extend_from_slice(&self.invite_hpke_pubkey);
        body.extend_from_slice(self.relay_server_id.as_bytes());
        body.extend_from_slice(&self.machine_root_pubkey);
        body.extend_from_slice(&self.machine_root_fingerprint);
        body.extend_from_slice(&self.current_spki_pin);
        body.extend_from_slice(&self.next_spki_pin);
        body.extend_from_slice(self.machine_route.as_bytes());
        body.extend_from_slice(self.device_route.as_bytes());
        body.extend_from_slice(&self.grant_serial.value().to_be_bytes());
        body.extend_from_slice(&self.trust_epoch.value().to_be_bytes());
        body.extend_from_slice(&self.invite_hash);
        body.extend_from_slice(&self.request_hash);
        body.extend_from_slice(&self.grant_hash);
        body.extend_from_slice(&self.response_hash);
        body.extend_from_slice(&self.promotion_id);
        body.extend_from_slice(&self.directory_revision.value().to_be_bytes());
        // receipt outbox=pending、counter reservation=None、空 replay/cursor collections。
        body.extend_from_slice(&[0, 0]);
        body.extend_from_slice(&0_u16.to_be_bytes());
        body.extend_from_slice(&0_u16.to_be_bytes());
        put_state_field(&mut body, self.wss_url.as_bytes(), MAX_STATE_STRING_LEN)?;
        put_state_field(
            &mut body,
            self.machine_display_name.as_bytes(),
            MAX_STATE_STRING_LEN,
        )?;
        put_state_field(&mut body, &self.canonical_response, MAX_STATE_FIELD_LEN)?;
        put_state_field(&mut body, &self.data_sign_certificate, MAX_STATE_FIELD_LEN)?;
        put_state_field(&mut body, &self.device_authorization, MAX_STATE_FIELD_LEN)?;
        put_state_field(&mut body, &self.key_directory, MAX_STATE_FIELD_LEN)?;
        put_state_field(&mut body, &self.receipt_carrier, MAX_STATE_FIELD_LEN)?;
        if body.len() > MAX_CRYPTO_STATE_PLAINTEXT_LEN - STATE_HEADER_LEN {
            return Err(PairedPromotionError::InvalidState);
        }
        let body_len = u32::try_from(body.len()).map_err(|_| PairedPromotionError::InvalidState)?;
        let mut encoded = Vec::with_capacity(STATE_HEADER_LEN + body.len());
        encoded.extend_from_slice(STATE_MAGIC);
        encoded.extend_from_slice(&STATE_VERSION.to_be_bytes());
        encoded.extend_from_slice(&[0, 0]);
        encoded.extend_from_slice(&body_len.to_be_bytes());
        encoded.extend_from_slice(&body);
        Ok(encoded)
    }

    fn decode(bytes: &[u8]) -> Result<Self, PairedPromotionError> {
        if bytes.len() < STATE_HEADER_LEN
            || bytes.len() > MAX_CRYPTO_STATE_PLAINTEXT_LEN
            || &bytes[..4] != STATE_MAGIC
            || u16::from_be_bytes([bytes[4], bytes[5]]) != STATE_VERSION
            || bytes[6..8] != [0, 0]
        {
            return Err(PairedPromotionError::InvalidState);
        }
        let declared = u32::from_be_bytes(
            bytes[8..12]
                .try_into()
                .map_err(|_| PairedPromotionError::InvalidState)?,
        ) as usize;
        if declared != bytes.len() - STATE_HEADER_LEN {
            return Err(PairedPromotionError::InvalidState);
        }
        let mut decoder = StateDecoder::new(&bytes[STATE_HEADER_LEN..]);
        let installation_id = Uuid::from_bytes(decoder.fixed()?);
        let invite_hpke_pubkey = decoder.fixed()?;
        let relay_server_id = RelayServerId::from_bytes(decoder.fixed()?);
        let machine_root_pubkey = decoder.fixed()?;
        let machine_root_fingerprint = decoder.fixed()?;
        let current_spki_pin = decoder.fixed()?;
        let next_spki_pin = decoder.fixed()?;
        let machine_route = MachineRouteId::from_bytes(decoder.fixed()?);
        let device_route = DeviceRouteId::from_bytes(decoder.fixed()?);
        let grant_serial = GrantSerial::new(decoder.u64()?);
        let trust_epoch = TrustEpoch::new(decoder.u64()?);
        let invite_hash = decoder.fixed()?;
        let request_hash = decoder.fixed()?;
        let grant_hash = decoder.fixed()?;
        let response_hash = decoder.fixed()?;
        let promotion_id = decoder.fixed()?;
        let directory_revision = KeyDirectoryRevision::new(decoder.u64()?);
        if decoder.u8()? != 0 || decoder.u8()? != 0 || decoder.u16()? != 0 || decoder.u16()? != 0 {
            return Err(PairedPromotionError::InvalidState);
        }
        let wss_url = decoder.string(MAX_STATE_STRING_LEN)?;
        let machine_display_name = decoder.string(MAX_STATE_STRING_LEN)?;
        let canonical_response = decoder.field(MAX_STATE_FIELD_LEN)?.to_vec();
        let data_sign_certificate = decoder.field(MAX_STATE_FIELD_LEN)?.to_vec();
        let device_authorization = decoder.field(MAX_STATE_FIELD_LEN)?.to_vec();
        let key_directory = decoder.field(MAX_STATE_FIELD_LEN)?.to_vec();
        let receipt_carrier = decoder.field(MAX_STATE_FIELD_LEN)?.to_vec();
        decoder.finish()?;
        let value = Self {
            installation_id,
            invite_hpke_pubkey,
            wss_url,
            current_spki_pin,
            next_spki_pin,
            machine_display_name,
            relay_server_id,
            machine_root_pubkey,
            machine_root_fingerprint,
            machine_route,
            device_route,
            grant_serial,
            trust_epoch,
            invite_hash,
            request_hash,
            grant_hash,
            response_hash,
            promotion_id,
            directory_revision,
            canonical_response,
            data_sign_certificate,
            device_authorization,
            key_directory,
            receipt_carrier,
        };
        value.validate_shape()?;
        if value.encode()? != bytes {
            return Err(PairedPromotionError::InvalidState);
        }
        Ok(value)
    }

    fn validate_shape(&self) -> Result<(), PairedPromotionError> {
        if self.installation_id.is_nil()
            || all_zero(&self.invite_hpke_pubkey)
            || self.wss_url.is_empty()
            || self.wss_url.len() > MAX_STATE_STRING_LEN
            || all_zero(&self.current_spki_pin)
            || all_zero(&self.next_spki_pin)
            || self.machine_display_name.is_empty()
            || self.machine_display_name.len() > MAX_STATE_STRING_LEN
            || all_zero(self.relay_server_id.as_bytes())
            || all_zero(&self.machine_root_pubkey)
            || all_zero(&self.machine_root_fingerprint)
            || all_zero(self.machine_route.as_bytes())
            || all_zero(self.device_route.as_bytes())
            || self.grant_serial.value() == 0
            || self.trust_epoch.value() == 0
            || all_zero(&self.invite_hash)
            || all_zero(&self.request_hash)
            || all_zero(&self.grant_hash)
            || all_zero(&self.response_hash)
            || all_zero(&self.promotion_id)
            || self.directory_revision.value() == 0
            || self.canonical_response.is_empty()
            || self.data_sign_certificate.is_empty()
            || self.device_authorization.is_empty()
            || self.key_directory.is_empty()
            || self.receipt_carrier.is_empty()
        {
            return Err(PairedPromotionError::InvalidState);
        }
        Ok(())
    }
}

enum PairedCryptoState {
    V1(PairedCryptoStateV1),
    V2(PairedCryptoStateV2),
}

impl fmt::Debug for PairedCryptoState {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("PairedCryptoState([REDACTED])")
    }
}

impl PairedCryptoState {
    fn decode(bytes: &[u8]) -> Result<Self, PairedPromotionError> {
        if bytes.len() < STATE_HEADER_LEN || &bytes[..4] != STATE_MAGIC {
            return Err(PairedPromotionError::InvalidState);
        }
        match u16::from_be_bytes([bytes[4], bytes[5]]) {
            STATE_VERSION => PairedCryptoStateV1::decode(bytes).map(Self::V1),
            MUTABLE_STATE_VERSION => PairedCryptoStateV2::decode(bytes).map(Self::V2),
            _ => Err(PairedPromotionError::InvalidState),
        }
    }

    fn encode(&self) -> Result<Vec<u8>, PairedPromotionError> {
        match self {
            Self::V1(value) => value.encode(),
            Self::V2(value) => value.encode(),
        }
    }

    const fn bootstrap(&self) -> &PairedCryptoStateV1 {
        match self {
            Self::V1(value) => value,
            Self::V2(value) => &value.bootstrap,
        }
    }

    const fn counter_reservation(&self) -> Option<&CommandCounterReservation> {
        match self {
            Self::V1(_) => None,
            Self::V2(value) => value.counter_reservation.as_ref(),
        }
    }

    fn with_counter_reservation(
        &self,
        initial_state_commitment: [u8; 32],
        initial_guard_commitment: [u8; 32],
        reservation: &CommandCounterReservation,
    ) -> Result<Self, PairedPromotionError> {
        reservation.validate()?;
        let stored_reservation = || CommandCounterReservation {
            reservation_id: reservation.reservation_id,
            start: reservation.start,
            end_exclusive: reservation.end_exclusive,
        };
        let value = match self {
            Self::V1(bootstrap) => PairedCryptoStateV2 {
                initial_state_commitment,
                initial_guard_commitment,
                bootstrap: bootstrap.clone(),
                receipt_terminal: None,
                counter_reservation: Some(stored_reservation()),
                replay_windows: Vec::new(),
                stream_cursors: Vec::new(),
            },
            Self::V2(current) => PairedCryptoStateV2 {
                initial_state_commitment: current.initial_state_commitment,
                initial_guard_commitment: current.initial_guard_commitment,
                bootstrap: current.bootstrap.clone(),
                receipt_terminal: current.receipt_terminal.clone(),
                counter_reservation: Some(stored_reservation()),
                replay_windows: current.replay_windows.clone(),
                stream_cursors: current.stream_cursors.clone(),
            },
        };
        value.validate()?;
        Ok(Self::V2(value))
    }
}

/// V2 把 marker 的两个旧 hash 固化为 initial commitments；当前 state hash 只由 guard 绑定。
/// receipt/replay/cursor 以 bounded canonical blob 保存，具体语义由后续 runtime 层严格解码。
struct PairedCryptoStateV2 {
    initial_state_commitment: [u8; 32],
    initial_guard_commitment: [u8; 32],
    bootstrap: PairedCryptoStateV1,
    receipt_terminal: Option<Vec<u8>>,
    counter_reservation: Option<CommandCounterReservation>,
    replay_windows: Vec<Vec<u8>>,
    stream_cursors: Vec<Vec<u8>>,
}

impl fmt::Debug for PairedCryptoStateV2 {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("PairedCryptoStateV2([REDACTED])")
    }
}

impl PairedCryptoStateV2 {
    fn encode(&self) -> Result<Vec<u8>, PairedPromotionError> {
        self.validate()?;
        let mut body = Vec::new();
        body.extend_from_slice(&self.initial_state_commitment);
        body.extend_from_slice(&self.initial_guard_commitment);
        let bootstrap = Zeroizing::new(self.bootstrap.encode()?);
        put_state_field(
            &mut body,
            bootstrap.as_slice(),
            MAX_CRYPTO_STATE_PLAINTEXT_LEN,
        )?;
        put_state_field(
            &mut body,
            self.receipt_terminal.as_deref().unwrap_or_default(),
            MAX_STATE_FIELD_LEN,
        )?;
        match &self.counter_reservation {
            Some(reservation) => {
                body.push(1);
                body.extend_from_slice(&[0, 0, 0]);
                body.extend_from_slice(&reservation.reservation_id);
                body.extend_from_slice(&reservation.start.to_be_bytes());
                body.extend_from_slice(&reservation.end_exclusive.to_be_bytes());
            }
            None => body.extend_from_slice(&[0; 36]),
        }
        put_state_collection(&mut body, &self.replay_windows)?;
        put_state_collection(&mut body, &self.stream_cursors)?;
        if body.len() > MAX_CRYPTO_STATE_PLAINTEXT_LEN - STATE_HEADER_LEN {
            return Err(PairedPromotionError::InvalidState);
        }
        let body_len = u32::try_from(body.len()).map_err(|_| PairedPromotionError::InvalidState)?;
        let mut encoded = Vec::with_capacity(STATE_HEADER_LEN + body.len());
        encoded.extend_from_slice(STATE_MAGIC);
        encoded.extend_from_slice(&MUTABLE_STATE_VERSION.to_be_bytes());
        encoded.extend_from_slice(&[0, 0]);
        encoded.extend_from_slice(&body_len.to_be_bytes());
        encoded.extend_from_slice(&body);
        Ok(encoded)
    }

    fn decode(bytes: &[u8]) -> Result<Self, PairedPromotionError> {
        if bytes.len() < STATE_HEADER_LEN
            || bytes.len() > MAX_CRYPTO_STATE_PLAINTEXT_LEN
            || &bytes[..4] != STATE_MAGIC
            || u16::from_be_bytes([bytes[4], bytes[5]]) != MUTABLE_STATE_VERSION
            || bytes[6..8] != [0, 0]
        {
            return Err(PairedPromotionError::InvalidState);
        }
        let declared = u32::from_be_bytes(
            bytes[8..12]
                .try_into()
                .map_err(|_| PairedPromotionError::InvalidState)?,
        ) as usize;
        if declared != bytes.len() - STATE_HEADER_LEN {
            return Err(PairedPromotionError::InvalidState);
        }
        let mut decoder = StateDecoder::new(&bytes[STATE_HEADER_LEN..]);
        let initial_state_commitment = decoder.fixed()?;
        let initial_guard_commitment = decoder.fixed()?;
        let bootstrap =
            PairedCryptoStateV1::decode(decoder.field(MAX_CRYPTO_STATE_PLAINTEXT_LEN)?)?;
        let receipt = decoder.field(MAX_STATE_FIELD_LEN)?.to_vec();
        let receipt_terminal = (!receipt.is_empty()).then_some(receipt);
        let reservation_tag = decoder.u8()?;
        if decoder.take(3)? != [0, 0, 0] {
            return Err(PairedPromotionError::InvalidState);
        }
        let reservation_id = decoder.fixed()?;
        let reservation_start = decoder.u64()?;
        let reservation_end = decoder.u64()?;
        let counter_reservation = match reservation_tag {
            0 if all_zero(&reservation_id) && reservation_start == 0 && reservation_end == 0 => {
                None
            }
            1 => Some(CommandCounterReservation {
                reservation_id,
                start: reservation_start,
                end_exclusive: reservation_end,
            }),
            _ => return Err(PairedPromotionError::InvalidState),
        };
        let replay_windows = decode_state_collection(&mut decoder)?;
        let stream_cursors = decode_state_collection(&mut decoder)?;
        decoder.finish()?;
        let value = Self {
            initial_state_commitment,
            initial_guard_commitment,
            bootstrap,
            receipt_terminal,
            counter_reservation,
            replay_windows,
            stream_cursors,
        };
        value.validate()?;
        let canonical = Zeroizing::new(value.encode()?);
        if canonical.as_slice() != bytes {
            return Err(PairedPromotionError::InvalidState);
        }
        Ok(value)
    }

    fn validate(&self) -> Result<(), PairedPromotionError> {
        let bootstrap = Zeroizing::new(self.bootstrap.encode()?);
        if all_zero(&self.initial_state_commitment)
            || all_zero(&self.initial_guard_commitment)
            || sha256(bootstrap.as_slice()) != self.initial_state_commitment
            || self.receipt_terminal.as_ref().is_some_and(Vec::is_empty)
            || self.replay_windows.len() > MAX_STATE_COLLECTION_ITEMS
            || self.stream_cursors.len() > MAX_STATE_COLLECTION_ITEMS
            || self
                .replay_windows
                .iter()
                .chain(&self.stream_cursors)
                .any(|entry| entry.is_empty() || entry.len() > MAX_STATE_FIELD_LEN)
        {
            return Err(PairedPromotionError::InvalidState);
        }
        if let Some(reservation) = &self.counter_reservation {
            reservation.validate()?;
        }
        Ok(())
    }
}

#[derive(Clone, Copy)]
struct PairedCommitMarkerV1 {
    installation_id: Uuid,
    root_fingerprint: [u8; 32],
    relay_server_id: RelayServerId,
    machine_route: MachineRouteId,
    device_route: DeviceRouteId,
    grant_serial: GrantSerial,
    trust_epoch: TrustEpoch,
    directory_revision: KeyDirectoryRevision,
    device_sign_pubkey: [u8; 32],
    device_hpke_pubkey: [u8; 32],
    invite_hash: [u8; 32],
    request_hash: [u8; 32],
    grant_hash: [u8; 32],
    response_hash: [u8; 32],
    promotion_id: [u8; 32],
    state_plaintext_hash: [u8; 32],
    kek_record_hash: [u8; 32],
    counter_guard_hash: [u8; 32],
    receipt_carrier_hash: [u8; 32],
}

impl fmt::Debug for PairedCommitMarkerV1 {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("PairedCommitMarkerV1([REDACTED])")
    }
}

impl PairedCommitMarkerV1 {
    #[allow(clippy::too_many_arguments)]
    fn new(
        installation_id: Uuid,
        state: &PairedCryptoStateV1,
        promotion_id: [u8; 32],
        state_plaintext_hash: [u8; 32],
        kek_record_hash: [u8; 32],
        counter_guard_hash: [u8; 32],
        device_sign_pubkey: [u8; 32],
        device_hpke_pubkey: [u8; 32],
    ) -> Self {
        Self {
            installation_id,
            root_fingerprint: state.machine_root_fingerprint,
            relay_server_id: state.relay_server_id,
            machine_route: state.machine_route,
            device_route: state.device_route,
            grant_serial: state.grant_serial,
            trust_epoch: state.trust_epoch,
            directory_revision: state.directory_revision,
            device_sign_pubkey,
            device_hpke_pubkey,
            invite_hash: state.invite_hash,
            request_hash: state.request_hash,
            grant_hash: state.grant_hash,
            response_hash: state.response_hash,
            promotion_id,
            state_plaintext_hash,
            kek_record_hash,
            counter_guard_hash,
            receipt_carrier_hash: sha256(&state.receipt_carrier),
        }
    }

    fn encode(&self) -> Vec<u8> {
        let mut encoded = Vec::with_capacity(480);
        encoded.extend_from_slice(MARKER_MAGIC);
        encoded.extend_from_slice(&MARKER_VERSION.to_be_bytes());
        encoded.extend_from_slice(&[0, 0]);
        encoded.extend_from_slice(self.installation_id.as_bytes());
        encoded.extend_from_slice(&self.root_fingerprint);
        encoded.extend_from_slice(self.relay_server_id.as_bytes());
        encoded.extend_from_slice(self.machine_route.as_bytes());
        encoded.extend_from_slice(self.device_route.as_bytes());
        encoded.extend_from_slice(&self.grant_serial.value().to_be_bytes());
        encoded.extend_from_slice(&self.trust_epoch.value().to_be_bytes());
        encoded.extend_from_slice(&self.directory_revision.value().to_be_bytes());
        encoded.extend_from_slice(&self.device_sign_pubkey);
        encoded.extend_from_slice(&self.device_hpke_pubkey);
        for hash in [
            self.invite_hash,
            self.request_hash,
            self.grant_hash,
            self.response_hash,
            self.promotion_id,
            self.state_plaintext_hash,
            self.kek_record_hash,
            self.counter_guard_hash,
            self.receipt_carrier_hash,
        ] {
            encoded.extend_from_slice(&hash);
        }
        encoded
    }

    fn decode(bytes: &[u8]) -> Result<Self, PairedPromotionError> {
        if bytes.len() != 480
            || &bytes[..4] != MARKER_MAGIC
            || u16::from_be_bytes([bytes[4], bytes[5]]) != MARKER_VERSION
            || bytes[6..8] != [0, 0]
        {
            return Err(PairedPromotionError::InvalidState);
        }
        let mut decoder = StateDecoder::new(&bytes[8..]);
        let value = Self {
            installation_id: Uuid::from_bytes(decoder.fixed()?),
            root_fingerprint: decoder.fixed()?,
            relay_server_id: RelayServerId::from_bytes(decoder.fixed()?),
            machine_route: MachineRouteId::from_bytes(decoder.fixed()?),
            device_route: DeviceRouteId::from_bytes(decoder.fixed()?),
            grant_serial: GrantSerial::new(decoder.u64()?),
            trust_epoch: TrustEpoch::new(decoder.u64()?),
            directory_revision: KeyDirectoryRevision::new(decoder.u64()?),
            device_sign_pubkey: decoder.fixed()?,
            device_hpke_pubkey: decoder.fixed()?,
            invite_hash: decoder.fixed()?,
            request_hash: decoder.fixed()?,
            grant_hash: decoder.fixed()?,
            response_hash: decoder.fixed()?,
            promotion_id: decoder.fixed()?,
            state_plaintext_hash: decoder.fixed()?,
            kek_record_hash: decoder.fixed()?,
            counter_guard_hash: decoder.fixed()?,
            receipt_carrier_hash: decoder.fixed()?,
        };
        decoder.finish()?;
        if value.encode() != bytes || value.any_required_zero() {
            return Err(PairedPromotionError::InvalidState);
        }
        Ok(value)
    }

    fn any_required_zero(&self) -> bool {
        self.installation_id.is_nil()
            || all_zero(&self.root_fingerprint)
            || all_zero(self.relay_server_id.as_bytes())
            || all_zero(self.machine_route.as_bytes())
            || all_zero(self.device_route.as_bytes())
            || self.grant_serial.value() == 0
            || self.trust_epoch.value() == 0
            || self.directory_revision.value() == 0
            || [
                self.device_sign_pubkey,
                self.device_hpke_pubkey,
                self.invite_hash,
                self.request_hash,
                self.grant_hash,
                self.response_hash,
                self.promotion_id,
                self.state_plaintext_hash,
                self.kek_record_hash,
                self.counter_guard_hash,
                self.receipt_carrier_hash,
            ]
            .iter()
            .any(|value| all_zero(value))
    }

    fn validate_account(
        &self,
        installation_id: Uuid,
        identity: PairedMachineIdentity,
    ) -> Result<(), PairedPromotionError> {
        if self.installation_id != installation_id
            || self.root_fingerprint != *identity.machine_root_fingerprint.as_bytes()
            || self.machine_route != identity.machine_route
        {
            return Err(PairedPromotionError::Conflict);
        }
        Ok(())
    }

    fn validate_state(
        &self,
        identity: PairedMachineIdentity,
        state: &PairedCryptoState,
        state_bytes: &[u8],
    ) -> Result<(), PairedPromotionError> {
        let bootstrap = state.bootstrap();
        if bootstrap.installation_id != self.installation_id
            || bootstrap.machine_root_fingerprint != self.root_fingerprint
            || bootstrap.machine_root_fingerprint != *identity.machine_root_fingerprint.as_bytes()
            || bootstrap.relay_server_id != self.relay_server_id
            || bootstrap.machine_route != self.machine_route
            || bootstrap.machine_route != identity.machine_route
            || bootstrap.device_route != self.device_route
            || bootstrap.grant_serial != self.grant_serial
            || bootstrap.trust_epoch != self.trust_epoch
            || bootstrap.directory_revision != self.directory_revision
            || bootstrap.invite_hash != self.invite_hash
            || bootstrap.request_hash != self.request_hash
            || bootstrap.grant_hash != self.grant_hash
            || bootstrap.response_hash != self.response_hash
            || bootstrap.promotion_id != self.promotion_id
            || sha256(&bootstrap.receipt_carrier) != self.receipt_carrier_hash
        {
            return Err(PairedPromotionError::Conflict);
        }
        match state {
            PairedCryptoState::V1(_) if sha256(state_bytes) == self.state_plaintext_hash => {}
            PairedCryptoState::V2(value)
                if value.initial_state_commitment == self.state_plaintext_hash
                    && value.initial_guard_commitment == self.counter_guard_hash => {}
            _ => return Err(PairedPromotionError::Conflict),
        }
        Ok(())
    }

    fn validate_expected(
        &self,
        installation_id: Uuid,
        verified: &agentdeck_crypto::VerifiedPairResponseV1,
        promotion_id: [u8; 32],
    ) -> Result<(), PairedPromotionError> {
        let info = verified.info();
        if self.installation_id != installation_id
            || self.root_fingerprint != verified.machine_root_fingerprint()
            || self.relay_server_id != info.relay_server_id
            || self.machine_route != info.machine_route
            || self.device_route != info.device_route
            || self.grant_serial != info.grant_serial
            || self.trust_epoch != info.root_trust_epoch
            || self.directory_revision != verified.key_directory().revision
            || self.device_sign_pubkey != verified.relay_grant().device_sign_pubkey.0
            || self.device_hpke_pubkey != verified.device_authorization().device_hpke_pubkey.0
            || self.invite_hash != info.invite_hash
            || self.request_hash != info.request_hash
            || self.grant_hash != verified.relay_grant().canonical_sha256()
            || self.response_hash != verified.response_hash()
            || self.promotion_id != promotion_id
        {
            return Err(PairedPromotionError::Conflict);
        }
        Ok(())
    }
}

struct StateDecoder<'a> {
    bytes: &'a [u8],
    cursor: usize,
}

impl<'a> StateDecoder<'a> {
    const fn new(bytes: &'a [u8]) -> Self {
        Self { bytes, cursor: 0 }
    }

    fn take(&mut self, length: usize) -> Result<&'a [u8], PairedPromotionError> {
        let end = self
            .cursor
            .checked_add(length)
            .ok_or(PairedPromotionError::InvalidState)?;
        let value = self
            .bytes
            .get(self.cursor..end)
            .ok_or(PairedPromotionError::InvalidState)?;
        self.cursor = end;
        Ok(value)
    }

    fn fixed<const N: usize>(&mut self) -> Result<[u8; N], PairedPromotionError> {
        self.take(N)?
            .try_into()
            .map_err(|_| PairedPromotionError::InvalidState)
    }

    fn u8(&mut self) -> Result<u8, PairedPromotionError> {
        Ok(self.take(1)?[0])
    }

    fn u16(&mut self) -> Result<u16, PairedPromotionError> {
        Ok(u16::from_be_bytes(self.fixed()?))
    }

    fn u32(&mut self) -> Result<u32, PairedPromotionError> {
        Ok(u32::from_be_bytes(self.fixed()?))
    }

    fn u64(&mut self) -> Result<u64, PairedPromotionError> {
        Ok(u64::from_be_bytes(self.fixed()?))
    }

    fn field(&mut self, max: usize) -> Result<&'a [u8], PairedPromotionError> {
        let length =
            usize::try_from(self.u32()?).map_err(|_| PairedPromotionError::InvalidState)?;
        if length > max {
            return Err(PairedPromotionError::InvalidState);
        }
        self.take(length)
    }

    fn string(&mut self, max: usize) -> Result<String, PairedPromotionError> {
        String::from_utf8(self.field(max)?.to_vec()).map_err(|_| PairedPromotionError::InvalidState)
    }

    fn finish(self) -> Result<(), PairedPromotionError> {
        if self.cursor != self.bytes.len() {
            return Err(PairedPromotionError::InvalidState);
        }
        Ok(())
    }
}

fn put_state_field(
    encoded: &mut Vec<u8>,
    value: &[u8],
    max: usize,
) -> Result<(), PairedPromotionError> {
    if value.len() > max {
        return Err(PairedPromotionError::InvalidState);
    }
    let length = u32::try_from(value.len()).map_err(|_| PairedPromotionError::InvalidState)?;
    encoded.extend_from_slice(&length.to_be_bytes());
    encoded.extend_from_slice(value);
    Ok(())
}

fn put_state_collection(
    encoded: &mut Vec<u8>,
    values: &[Vec<u8>],
) -> Result<(), PairedPromotionError> {
    if values.len() > MAX_STATE_COLLECTION_ITEMS {
        return Err(PairedPromotionError::InvalidState);
    }
    let count = u16::try_from(values.len()).map_err(|_| PairedPromotionError::InvalidState)?;
    encoded.extend_from_slice(&count.to_be_bytes());
    for value in values {
        if value.is_empty() {
            return Err(PairedPromotionError::InvalidState);
        }
        put_state_field(encoded, value, MAX_STATE_FIELD_LEN)?;
    }
    Ok(())
}

fn decode_state_collection(
    decoder: &mut StateDecoder<'_>,
) -> Result<Vec<Vec<u8>>, PairedPromotionError> {
    let count = usize::from(decoder.u16()?);
    if count > MAX_STATE_COLLECTION_ITEMS {
        return Err(PairedPromotionError::InvalidState);
    }
    let mut values = Vec::with_capacity(count);
    for _ in 0..count {
        let value = decoder.field(MAX_STATE_FIELD_LEN)?.to_vec();
        if value.is_empty() {
            return Err(PairedPromotionError::InvalidState);
        }
        values.push(value);
    }
    Ok(values)
}

fn read_u64(bytes: &[u8]) -> Result<u64, PairedPromotionError> {
    Ok(u64::from_be_bytes(
        bytes
            .try_into()
            .map_err(|_| PairedPromotionError::InvalidState)?,
    ))
}

fn all_zero(bytes: &[u8]) -> bool {
    bytes.iter().all(|byte| *byte == 0)
}

#[cfg(test)]
mod counter_reservation_tests {
    use std::convert::Infallible;

    use agentdeck_crypto::rand_core::{TryCryptoRng, TryRng};

    use super::*;

    struct CountingRng {
        fill_calls: usize,
    }

    impl TryRng for CountingRng {
        type Error = Infallible;

        fn try_next_u32(&mut self) -> Result<u32, Self::Error> {
            unreachable!("counter reservation only requests exact bytes")
        }

        fn try_next_u64(&mut self) -> Result<u64, Self::Error> {
            unreachable!("counter reservation only requests exact bytes")
        }

        fn try_fill_bytes(&mut self, output: &mut [u8]) -> Result<(), Self::Error> {
            self.fill_calls += 1;
            output.fill(0x5a);
            Ok(())
        }
    }

    impl TryCryptoRng for CountingRng {}

    #[test]
    fn last_counter_block_succeeds_then_epoch_exhaustion_precedes_entropy() {
        let maximum_aligned_high_water = u64::MAX - (u64::MAX % COUNTER_BLOCK_SIZE);
        let last_start = maximum_aligned_high_water - COUNTER_BLOCK_SIZE;
        let mut rng = CountingRng { fill_calls: 0 };

        let last = prepare_command_counter_reservation(last_start, &mut rng).unwrap();
        assert_eq!(last.start(), last_start);
        assert_eq!(last.end_exclusive(), maximum_aligned_high_water);
        assert_eq!(rng.fill_calls, 1);

        let error = prepare_command_counter_reservation(maximum_aligned_high_water, &mut rng)
            .expect_err("the next block cannot be represented in the current key epoch");
        assert_eq!(error.code(), "remote.counter.epoch_retirement_required");
        assert_eq!(
            rng.fill_calls, 1,
            "overflow must fail before RNG and therefore before every durable mutation"
        );
    }
}
