//! RuntimeCore connection registry 与每连接有界 outbox。
//!
//! 本层只持有已经认证的 principal 与 opaque encoded frame。它不读取 socket、
//! 不 import 任何 Relay/UDS transport 类型，RuntimeCore 也只做 `try_enqueue`，
//! 永不 await 慢 writer。

use std::collections::HashMap;
use std::fmt;
use std::hash::{Hash, Hasher};
use std::sync::{Arc, Mutex, Weak};

use agentdeck_protocol::runtime::RuntimeEnvelope;
use tokio::sync::{OwnedSemaphorePermit, Semaphore, mpsc, oneshot};
use zeroize::Zeroizing;

use crate::runtime::store::IdempotencyOwner;

pub const DEFAULT_CONNECTION_WRITER_FRAMES: usize = 512;
pub const DEFAULT_CONNECTION_WRITER_BYTES: usize = 16 * 1024 * 1024;
pub const DEFAULT_RUNTIME_CONNECTION_CAPACITY: usize = 128;
pub const DEFAULT_PRINCIPAL_LEASE_CAPACITY: usize = 1_024;

const PRINCIPAL_ACTIVE: u8 = 0;
#[allow(dead_code)] // P4 durable revocation ledger 接线后成为 production path。
const PRINCIPAL_REVOKING: u8 = 1;
#[allow(dead_code)] // P4 durable revocation ledger 接线后成为 production path。
const PRINCIPAL_REVOKED: u8 = 2;

/// 认证后、不可由 transport raw field 直接构造的 principal capability。
///
/// 字段和构造器都不公开；P3.8/P4 transport 必须先完成 peer/signature/replay
/// 验证，再通过 daemon 内部 issuer 获取此 capability。P4 durable auth ledger
/// 接入前 production remote issuer 保持关闭。
#[derive(Clone)]
pub struct AuthenticatedPrincipal {
    identity: Arc<PrincipalIdentity>,
    authorization: Arc<AuthorizationLease>,
}

#[derive(Clone, Eq, PartialEq, Hash)]
enum PrincipalIdentity {
    Local {
        machine_trust_domain: [u8; 32],
        uid: u32,
        client_installation_id: [u8; 16],
    },
    #[allow(dead_code)] // production remote issuer 在 P4 auth ledger 前保持不存在。
    Remote {
        machine_trust_domain: [u8; 32],
        machine_route: [u8; 16],
        device_route: [u8; 16],
        grant_serial: u64,
        device_sign_fingerprint: [u8; 32],
    },
}

struct AuthorizationLease {
    state: std::sync::atomic::AtomicU8,
    inflight: std::sync::atomic::AtomicUsize,
    quiesced: tokio::sync::Notify,
    approval_permissions: ApprovalPermissionGrant,
}

#[allow(dead_code)] // P3.5 Core resolve/retry 接线后构造非 None grants。
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub(crate) enum ApprovalPermissionGrant {
    #[default]
    None,
    ResolveOnly,
    RetryOnly,
    ResolveAndRetry,
}

#[allow(dead_code)] // P3.5 Core resolve/retry 接线后消费。
impl ApprovalPermissionGrant {
    const fn allows_any(self) -> bool {
        !matches!(self, Self::None)
    }

    const fn allows_resolve(self) -> bool {
        matches!(self, Self::ResolveOnly | Self::ResolveAndRetry)
    }

    const fn allows_retry(self) -> bool {
        matches!(self, Self::RetryOnly | Self::ResolveAndRetry)
    }
}

impl AuthenticatedPrincipal {
    pub(crate) fn idempotency_owner(&self) -> IdempotencyOwner {
        match self.identity.as_ref() {
            PrincipalIdentity::Local {
                machine_trust_domain,
                uid,
                client_installation_id,
            } => IdempotencyOwner::Local {
                machine_trust_domain: *machine_trust_domain,
                uid: *uid,
                client_installation_id: *client_installation_id,
            },
            PrincipalIdentity::Remote {
                machine_trust_domain,
                device_route,
                device_sign_fingerprint,
                ..
            } => IdempotencyOwner::Remote {
                machine_trust_domain: *machine_trust_domain,
                device_route: *device_route,
                device_sign_fingerprint: *device_sign_fingerprint,
            },
        }
    }

    pub(crate) fn is_local(&self) -> bool {
        matches!(self.identity.as_ref(), PrincipalIdentity::Local { .. })
    }

    pub(crate) fn authorization_key(&self) -> PrincipalAuthorizationKey {
        PrincipalAuthorizationKey(self.identity.clone())
    }

    pub(crate) fn try_enter(&self) -> Result<AuthorizationGuard, PrincipalAccessError> {
        self.authorization.try_enter()
    }

    #[allow(dead_code)] // P4 durable revoke transaction 调用。
    pub(crate) async fn begin_revoke(&self) -> Result<(), PrincipalAccessError> {
        self.authorization.begin_revoke().await
    }

    #[allow(dead_code)] // P4 durable revoke transaction 调用。
    pub(crate) fn finish_revoke(&self) {
        self.authorization
            .state
            .store(PRINCIPAL_REVOKED, std::sync::atomic::Ordering::Release);
    }

    #[cfg(test)]
    pub(crate) fn is_active(&self) -> bool {
        self.authorization
            .state
            .load(std::sync::atomic::Ordering::Acquire)
            == PRINCIPAL_ACTIVE
    }
}

impl fmt::Debug for AuthenticatedPrincipal {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        let kind = if self.is_local() { "local" } else { "remote" };
        formatter
            .debug_struct("AuthenticatedPrincipal")
            .field("kind", &kind)
            .field("identity", &"[REDACTED]")
            .finish()
    }
}

/// 完整授权主体 key；remote grant serial 属于此 key，但不属于 idempotency owner。
#[derive(Clone)]
pub(crate) struct PrincipalAuthorizationKey(Arc<PrincipalIdentity>);

impl PartialEq for PrincipalAuthorizationKey {
    fn eq(&self, other: &Self) -> bool {
        self.0 == other.0
    }
}

impl Eq for PrincipalAuthorizationKey {}

impl Hash for PrincipalAuthorizationKey {
    fn hash<H: Hasher>(&self, state: &mut H) {
        self.0.hash(state);
    }
}

impl fmt::Debug for PrincipalAuthorizationKey {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("PrincipalAuthorizationKey([REDACTED])")
    }
}

impl AuthorizationLease {
    fn new(approval_permissions: ApprovalPermissionGrant) -> Self {
        Self {
            state: std::sync::atomic::AtomicU8::new(PRINCIPAL_ACTIVE),
            inflight: std::sync::atomic::AtomicUsize::new(0),
            quiesced: tokio::sync::Notify::new(),
            approval_permissions,
        }
    }

    fn try_enter(self: &Arc<Self>) -> Result<AuthorizationGuard, PrincipalAccessError> {
        use std::sync::atomic::Ordering;

        if self.state.load(Ordering::Acquire) != PRINCIPAL_ACTIVE {
            return Err(PrincipalAccessError::Revoked);
        }
        self.inflight.fetch_add(1, Ordering::AcqRel);
        if self.state.load(Ordering::Acquire) != PRINCIPAL_ACTIVE {
            if self.inflight.fetch_sub(1, Ordering::AcqRel) == 1 {
                self.quiesced.notify_waiters();
            }
            return Err(PrincipalAccessError::Revoked);
        }
        Ok(AuthorizationGuard {
            lease: self.clone(),
        })
    }

    #[allow(dead_code)] // 由 P4 durable revoke path 间接调用。
    async fn begin_revoke(&self) -> Result<(), PrincipalAccessError> {
        use std::sync::atomic::Ordering;

        self.state
            .compare_exchange(
                PRINCIPAL_ACTIVE,
                PRINCIPAL_REVOKING,
                Ordering::AcqRel,
                Ordering::Acquire,
            )
            .map_err(|_| PrincipalAccessError::Revoked)?;
        loop {
            // `notify_waiters` 不保留 permit：先注册并 enable waiter，再复查 inflight，
            // 消除“最后一个 guard 在 load 与 notified 之间 drop”的 lost wakeup。
            let notified = self.quiesced.notified();
            tokio::pin!(notified);
            notified.as_mut().enable();
            if self.inflight.load(Ordering::Acquire) == 0 {
                break;
            }
            notified.await;
        }
        Ok(())
    }
}

pub(crate) struct AuthorizationGuard {
    lease: Arc<AuthorizationLease>,
}

/// Approval first-wins/retry CAS 的 daemon-private authorization capability。
/// 字段私有，且持有共享 principal lease guard 直到调用方完成 SQLite COMMIT。
#[allow(dead_code)] // P3.5 Core/store CAS 接线后消费。
pub(crate) struct ApprovalAuthorizationGuard {
    _authorization: AuthorizationGuard,
    identity: Arc<PrincipalIdentity>,
    permissions: ApprovalPermissionGrant,
}

#[allow(dead_code)] // P3.5 Core/store CAS 接线后消费。
impl ApprovalAuthorizationGuard {
    pub(crate) fn require_resolve(&self) -> Result<(), PrincipalAccessError> {
        if self.permissions.allows_resolve() {
            Ok(())
        } else {
            Err(PrincipalAccessError::PermissionDenied)
        }
    }

    pub(crate) fn require_retry(&self) -> Result<(), PrincipalAccessError> {
        if self.permissions.allows_retry() {
            Ok(())
        } else {
            Err(PrincipalAccessError::PermissionDenied)
        }
    }

    pub(crate) fn claimant_binding(&self) -> ApprovalClaimantBinding {
        ApprovalClaimantBinding::from_identity(self.identity.as_ref())
    }
}

impl fmt::Debug for ApprovalAuthorizationGuard {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("ApprovalAuthorizationGuard")
            .field("identity", &"[REDACTED]")
            .field("permissions", &self.permissions)
            .finish()
    }
}

/// StorageKEK blind-index 输入；不是 claimant token，也不做无 key hash。
/// Drop 时由 `Zeroizing` 清除完整 authorization identity canonical bytes。
#[allow(dead_code)] // P3.5 store blind-index 接线后消费。
pub(crate) struct ApprovalClaimantBinding {
    canonical: Zeroizing<Vec<u8>>,
}

#[allow(dead_code)] // P3.5 store blind-index 接线后消费。
impl ApprovalClaimantBinding {
    fn from_identity(identity: &PrincipalIdentity) -> Self {
        let mut canonical = Vec::with_capacity(160);
        append_canonical_field(&mut canonical, b"approval.claimant.v1");
        match identity {
            PrincipalIdentity::Local {
                machine_trust_domain,
                uid: principal_uid,
                client_installation_id,
            } => {
                append_canonical_field(&mut canonical, &[1]);
                append_canonical_field(&mut canonical, machine_trust_domain);
                append_canonical_field(&mut canonical, &principal_uid.to_be_bytes());
                append_canonical_field(&mut canonical, client_installation_id);
            }
            PrincipalIdentity::Remote {
                machine_trust_domain,
                machine_route,
                device_route,
                grant_serial: serial,
                device_sign_fingerprint,
            } => {
                append_canonical_field(&mut canonical, &[2]);
                append_canonical_field(&mut canonical, machine_trust_domain);
                append_canonical_field(&mut canonical, machine_route);
                append_canonical_field(&mut canonical, device_route);
                append_canonical_field(&mut canonical, &serial.to_be_bytes());
                append_canonical_field(&mut canonical, device_sign_fingerprint);
            }
        }
        Self {
            canonical: Zeroizing::new(canonical),
        }
    }

    pub(crate) fn as_bytes(&self) -> &[u8] {
        self.canonical.as_slice()
    }
}

impl fmt::Debug for ApprovalClaimantBinding {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("ApprovalClaimantBinding([REDACTED])")
    }
}

#[allow(dead_code)] // 仅由 P3.5 claimant binding 构造路径调用。
fn append_canonical_field(target: &mut Vec<u8>, field: &[u8]) {
    let length = u32::try_from(field.len()).expect("approval claimant field length is fixed");
    target.extend_from_slice(&length.to_be_bytes());
    target.extend_from_slice(field);
}

#[allow(dead_code)] // P3.5 Core resolve/retry 接线后消费。
pub(crate) trait ApprovalPrincipalCapability {
    fn try_enter_approval(&self) -> Result<ApprovalAuthorizationGuard, PrincipalAccessError>;
}

#[allow(dead_code)] // P3.5 Core resolve/retry 接线后调用。
impl ApprovalPrincipalCapability for AuthenticatedPrincipal {
    fn try_enter_approval(&self) -> Result<ApprovalAuthorizationGuard, PrincipalAccessError> {
        let permissions = self.authorization.approval_permissions;
        if !permissions.allows_any() {
            return Err(PrincipalAccessError::PermissionDenied);
        }
        let authorization = self.authorization.try_enter()?;
        Ok(ApprovalAuthorizationGuard {
            _authorization: authorization,
            identity: self.identity.clone(),
            permissions,
        })
    }
}

impl Drop for AuthorizationGuard {
    fn drop(&mut self) {
        use std::sync::atomic::Ordering;

        if self.lease.inflight.fetch_sub(1, Ordering::AcqRel) == 1 {
            self.lease.quiesced.notify_waiters();
        }
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq, thiserror::Error)]
pub enum PrincipalAccessError {
    #[error("principal authorization is revoked or revoking")]
    Revoked,
    #[error("principal authorization registry is unavailable")]
    RegistryUnavailable,
    #[error("principal authorization registry reached its hard limit")]
    RegistryFull,
    #[error("principal lacks the required approval permission")]
    #[allow(dead_code)] // P3.5 Core resolve/retry 接线后由 capability 构造。
    PermissionDenied,
    #[error("approval permissions conflict with the existing full authorization identity")]
    PermissionConflict,
}

/// runtime 内部 issuer。raw transport 无法直接构造 `AuthenticatedPrincipal`。
pub(crate) struct PrincipalIssuer {
    machine_trust_domain: [u8; 32],
    lease_capacity: usize,
    leases: Mutex<HashMap<PrincipalIdentity, Arc<AuthorizationLease>>>,
}

impl PrincipalIssuer {
    pub(crate) fn local_only(machine_trust_domain: [u8; 32]) -> Self {
        Self {
            machine_trust_domain,
            lease_capacity: DEFAULT_PRINCIPAL_LEASE_CAPACITY,
            leases: Mutex::new(HashMap::new()),
        }
    }

    pub(crate) fn issue_verified_local(
        &self,
        uid: u32,
        client_installation_id: [u8; 16],
    ) -> Result<AuthenticatedPrincipal, PrincipalAccessError> {
        self.issue(
            PrincipalIdentity::Local {
                machine_trust_domain: self.machine_trust_domain,
                uid,
                client_installation_id,
            },
            ApprovalPermissionGrant::None,
        )
    }

    #[allow(dead_code)] // P3.5 Core principal issuance 接线后调用。
    pub(crate) fn issue_verified_local_with_approval_permissions(
        &self,
        uid: u32,
        client_installation_id: [u8; 16],
        permissions: ApprovalPermissionGrant,
    ) -> Result<AuthenticatedPrincipal, PrincipalAccessError> {
        self.issue(
            PrincipalIdentity::Local {
                machine_trust_domain: self.machine_trust_domain,
                uid,
                client_installation_id,
            },
            permissions,
        )
    }

    #[cfg(test)]
    pub(crate) fn issue_test_remote(
        &self,
        machine_route: [u8; 16],
        device_route: [u8; 16],
        grant_serial: u64,
        device_sign_fingerprint: [u8; 32],
    ) -> Result<AuthenticatedPrincipal, PrincipalAccessError> {
        self.issue(
            PrincipalIdentity::Remote {
                machine_trust_domain: self.machine_trust_domain,
                machine_route,
                device_route,
                grant_serial,
                device_sign_fingerprint,
            },
            ApprovalPermissionGrant::None,
        )
    }

    #[cfg(test)]
    pub(crate) fn issue_test_remote_with_approval_permissions(
        &self,
        machine_route: [u8; 16],
        device_route: [u8; 16],
        grant_serial: u64,
        device_sign_fingerprint: [u8; 32],
        permissions: ApprovalPermissionGrant,
    ) -> Result<AuthenticatedPrincipal, PrincipalAccessError> {
        self.issue(
            PrincipalIdentity::Remote {
                machine_trust_domain: self.machine_trust_domain,
                machine_route,
                device_route,
                grant_serial,
                device_sign_fingerprint,
            },
            permissions,
        )
    }

    fn issue(
        &self,
        identity: PrincipalIdentity,
        approval_permissions: ApprovalPermissionGrant,
    ) -> Result<AuthenticatedPrincipal, PrincipalAccessError> {
        let mut leases = self
            .leases
            .lock()
            .map_err(|_| PrincipalAccessError::RegistryUnavailable)?;
        let authorization = match leases.get(&identity).cloned() {
            Some(lease) => {
                if lease.approval_permissions != approval_permissions {
                    return Err(PrincipalAccessError::PermissionConflict);
                }
                lease
            }
            None => {
                if leases.len() >= self.lease_capacity {
                    return Err(PrincipalAccessError::RegistryFull);
                }
                let lease = Arc::new(AuthorizationLease::new(approval_permissions));
                leases.insert(identity.clone(), lease.clone());
                lease
            }
        };
        Ok(AuthenticatedPrincipal {
            identity: Arc::new(identity),
            authorization,
        })
    }
}

/// 单次连接随机 identity；连接重建必然获得新 generation/id。
#[derive(Clone, Copy, Eq, Hash, PartialEq)]
pub struct ConnectionId([u8; 16]);

impl ConnectionId {
    fn random() -> Result<Self, ConnectionError> {
        let mut bytes = [0_u8; 16];
        getrandom::fill(&mut bytes).map_err(|_| ConnectionError::EntropyUnavailable)?;
        if bytes == [0; 16] {
            return Err(ConnectionError::EntropyUnavailable);
        }
        Ok(Self(bytes))
    }
}

impl fmt::Debug for ConnectionId {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("ConnectionId([OPAQUE])")
    }
}

/// transport-owned bounded receiving channel。RuntimeCore 只把 frame 放入自己的
/// 512/16MiB outbox；真正的 socket writer 在此 channel 的另一端，并且必须在
/// socket write/flush 成功后显式 ACK。ACK 前 frame/byte permit 始终由 Core 持有。
#[derive(Clone)]
pub struct ConnectionSink {
    sender: mpsc::Sender<ConnectionWrite>,
}

impl ConnectionSink {
    #[must_use]
    pub fn new(sender: mpsc::Sender<ConnectionWrite>) -> Self {
        Self { sender }
    }
}

/// transport 的单次写入工作项。丢弃而不 ACK 会关闭当前 Runtime connection；
/// 只有 `acknowledge` 才释放 Core 的 frame/byte budget。
pub struct ConnectionWrite {
    bytes: Arc<[u8]>,
    acknowledged: Option<oneshot::Sender<()>>,
}

impl ConnectionWrite {
    #[must_use]
    pub fn bytes(&self) -> &[u8] {
        &self.bytes
    }

    pub fn acknowledge(mut self) -> Result<(), ConnectionError> {
        self.acknowledged
            .take()
            .ok_or(ConnectionError::Lagged)?
            .send(())
            .map_err(|_| ConnectionError::Lagged)
    }
}

impl fmt::Debug for ConnectionWrite {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("ConnectionWrite")
            .field("encoded_bytes", &self.bytes.len())
            .finish()
    }
}

#[derive(Clone)]
pub struct EncodedRuntimeFrame {
    bytes: Arc<[u8]>,
}

impl EncodedRuntimeFrame {
    pub fn from_envelope(envelope: &RuntimeEnvelope) -> Result<Self, ConnectionError> {
        let bytes = envelope
            .to_json_bytes_checked()
            .map_err(|error| match error {
                agentdeck_protocol::runtime::RuntimeSizeError::TooLarge
                | agentdeck_protocol::runtime::RuntimeSizeError::FrameTooLarge => {
                    ConnectionError::FrameTooLarge
                }
                agentdeck_protocol::runtime::RuntimeSizeError::Encode(_) => ConnectionError::Encode,
            })?;
        Ok(Self {
            bytes: Arc::from(bytes),
        })
    }

    #[cfg(test)]
    #[must_use]
    pub fn from_bytes(bytes: impl Into<Arc<[u8]>>) -> Self {
        Self {
            bytes: bytes.into(),
        }
    }
}

struct QueuedFrame {
    frame: EncodedRuntimeFrame,
    _bytes: OwnedSemaphorePermit,
    _frame: OwnedSemaphorePermit,
}

struct ConnectionEntry {
    principal: AuthenticatedPrincipal,
    writer: mpsc::Sender<QueuedFrame>,
    byte_budget: Arc<Semaphore>,
    frame_budget: Arc<Semaphore>,
}

type ConnectionEntries = Mutex<HashMap<ConnectionId, ConnectionEntry>>;
type WriterTasks = Mutex<HashMap<ConnectionId, tokio::task::JoinHandle<()>>>;

/// task 正常退出或被 abort 时都会执行，先移除 registry/task handle，再释放
/// connection slot；因此新 writer 不会与尚未完成清理的旧 writer 越过硬上界。
struct WriterTaskLifetime {
    id: ConnectionId,
    entries: Weak<ConnectionEntries>,
    tasks: Weak<WriterTasks>,
    connection_slot: Option<OwnedSemaphorePermit>,
}

impl Drop for WriterTaskLifetime {
    fn drop(&mut self) {
        if let Some(entries) = self.entries.upgrade()
            && let Ok(mut entries) = entries.lock()
        {
            entries.remove(&self.id);
        }
        if let Some(tasks) = self.tasks.upgrade()
            && let Ok(mut tasks) = tasks.lock()
        {
            // 在 task-map 锁内先释放 slot 再移除 handle：新 connect 即使取得
            // permit，也必须等待同一把锁，不能在旧 task 完成登记清理前 spawn。
            self.connection_slot.take();
            tasks.remove(&self.id);
            return;
        }
        // registry 已经 Drop、无法再接入新连接时只需释放剩余 slot。
        self.connection_slot.take();
    }
}

pub(crate) struct ConnectionRegistry {
    entries: Arc<ConnectionEntries>,
    tasks: Arc<WriterTasks>,
    connection_slots: Arc<Semaphore>,
    frame_capacity: usize,
    byte_capacity: usize,
}

impl ConnectionRegistry {
    pub(crate) fn new(frame_capacity: usize, byte_capacity: usize) -> Self {
        Self {
            entries: Arc::new(Mutex::new(HashMap::new())),
            tasks: Arc::new(Mutex::new(HashMap::new())),
            connection_slots: Arc::new(Semaphore::new(DEFAULT_RUNTIME_CONNECTION_CAPACITY)),
            frame_capacity,
            byte_capacity,
        }
    }

    pub(crate) fn connect(
        &self,
        principal: AuthenticatedPrincipal,
        sink: ConnectionSink,
    ) -> Result<ConnectionId, ConnectionError> {
        if self.frame_capacity == 0
            || self.byte_capacity == 0
            || self.byte_capacity > u32::MAX as usize
        {
            return Err(ConnectionError::InvalidCapacity);
        }
        // 必须在创建 channel/task 前取得全局 writer slot；失败路径不产生任何后台任务。
        let connection_slot = self
            .connection_slots
            .clone()
            .try_acquire_owned()
            .map_err(|_| {
                if self.connection_slots.is_closed() {
                    ConnectionError::ShuttingDown
                } else {
                    ConnectionError::ConnectionLimit
                }
            })?;
        let mut entries = self
            .entries
            .lock()
            .map_err(|_| ConnectionError::RegistryPoisoned)?;
        let mut tasks = self
            .tasks
            .lock()
            .map_err(|_| ConnectionError::RegistryPoisoned)?;
        // shutdown 先 close semaphore，再等待这两张表的锁。若 close 已发生，
        // 此处必须在 channel/spawn 前失败；若尚未发生，则本次插入仍持锁，随后
        // shutdown 必然能 take 并 join 它。
        if self.connection_slots.is_closed() {
            return Err(ConnectionError::ShuttingDown);
        }
        let id = ConnectionId::random()?;
        if entries.contains_key(&id) {
            return Err(ConnectionError::EntropyUnavailable);
        }
        let (writer, mut receiver) = mpsc::channel::<QueuedFrame>(self.frame_capacity);
        let byte_budget = Arc::new(Semaphore::new(self.byte_capacity));
        let frame_budget = Arc::new(Semaphore::new(self.frame_capacity));
        let weak_entries = Arc::downgrade(&self.entries);
        let weak_tasks = Arc::downgrade(&self.tasks);
        let lifetime = WriterTaskLifetime {
            id,
            entries: weak_entries,
            tasks: weak_tasks,
            connection_slot: Some(connection_slot),
        };
        let (published, published_rx) = oneshot::channel();
        let task = tokio::spawn(async move {
            // lifetime 在 spawn 前已构造；即使 task 从未 poll 就被 abort，future Drop
            // 仍会执行 registry cleanup 并释放 slot。
            let _lifetime = lifetime;
            if published_rx.await.is_err() {
                return;
            }
            while let Some(queued) = receiver.recv().await {
                let (acknowledged, acknowledgement) = oneshot::channel();
                if sink
                    .sender
                    .send(ConnectionWrite {
                        bytes: queued.frame.bytes.clone(),
                        acknowledged: Some(acknowledged),
                    })
                    .await
                    .is_err()
                    || acknowledgement.await.is_err()
                {
                    break;
                }
                drop(queued);
            }
        });
        let entry = ConnectionEntry {
            principal,
            writer,
            byte_budget,
            frame_budget,
        };
        let replaced = entries.insert(id, entry);
        debug_assert!(replaced.is_none());
        let replaced = tasks.insert(id, task);
        debug_assert!(replaced.is_none());
        drop(tasks);
        drop(entries);
        let _ = published.send(());
        Ok(id)
    }

    pub(crate) fn principal(
        &self,
        id: ConnectionId,
    ) -> Result<AuthenticatedPrincipal, ConnectionError> {
        self.entries
            .lock()
            .map_err(|_| ConnectionError::RegistryPoisoned)?
            .get(&id)
            .map(|entry| entry.principal.clone())
            .ok_or(ConnectionError::NotFound)
    }

    /// 只做同步 `try_send`。任一 frame/byte 上限命中即移除并 abort 当前连接，
    /// 不等待 transport，也不影响其他 connection。
    pub(crate) fn try_enqueue(
        &self,
        id: ConnectionId,
        frame: EncodedRuntimeFrame,
    ) -> Result<(), ConnectionError> {
        let encoded_len = frame.bytes.len();
        let mut entries = self
            .entries
            .lock()
            .map_err(|_| ConnectionError::RegistryPoisoned)?;
        let entry = entries.get(&id).ok_or(ConnectionError::NotFound)?;
        if encoded_len == 0 || encoded_len > self.byte_capacity {
            let removed = entries.remove(&id).is_some();
            drop(entries);
            if removed {
                self.abort_tracked_writer(id)?;
            }
            return Err(ConnectionError::Lagged);
        }
        let permits = u32::try_from(encoded_len).map_err(|_| ConnectionError::Lagged)?;
        let byte_permit = entry
            .byte_budget
            .clone()
            .try_acquire_many_owned(permits)
            .map_err(|_| ConnectionError::Lagged);
        let frame_permit = entry
            .frame_budget
            .clone()
            .try_acquire_owned()
            .map_err(|_| ConnectionError::Lagged);
        let queued = byte_permit.and_then(|bytes| {
            let frame_permit = frame_permit?;
            entry
                .writer
                .try_send(QueuedFrame {
                    frame,
                    _bytes: bytes,
                    _frame: frame_permit,
                })
                .map_err(|_| ConnectionError::Lagged)
        });
        if queued.is_err() {
            let removed = entries.remove(&id).is_some();
            drop(entries);
            if removed {
                self.abort_tracked_writer(id)?;
            }
        }
        queued
    }

    pub(crate) async fn disconnect(&self, id: ConnectionId) -> Result<(), ConnectionError> {
        self.entries
            .lock()
            .map_err(|_| ConnectionError::RegistryPoisoned)?
            .remove(&id);
        let task = self
            .tasks
            .lock()
            .map_err(|_| ConnectionError::RegistryPoisoned)?
            .remove(&id);
        if let Some(task) = task {
            task.abort();
            join_writer(task).await?;
        }
        Ok(())
    }

    pub(crate) async fn shutdown(&self) -> Result<(), ConnectionError> {
        self.connection_slots.close();
        let entries = std::mem::take(
            &mut *self
                .entries
                .lock()
                .map_err(|_| ConnectionError::RegistryPoisoned)?,
        );
        let tasks = std::mem::take(
            &mut *self
                .tasks
                .lock()
                .map_err(|_| ConnectionError::RegistryPoisoned)?,
        );
        drop(entries);
        for task in tasks.values() {
            task.abort();
        }
        let mut failed = false;
        for (_, task) in tasks {
            if join_writer(task).await.is_err() {
                failed = true;
            }
        }
        if failed {
            return Err(ConnectionError::WriterTaskFailed);
        }
        Ok(())
    }

    fn abort_tracked_writer(&self, id: ConnectionId) -> Result<(), ConnectionError> {
        if let Some(task) = self
            .tasks
            .lock()
            .map_err(|_| ConnectionError::RegistryPoisoned)?
            .get(&id)
        {
            task.abort();
        }
        Ok(())
    }

    #[cfg(test)]
    pub(crate) fn len(&self) -> usize {
        self.entries.lock().map_or(0, |entries| entries.len())
    }

    #[cfg(test)]
    pub(crate) fn active_writer_count(&self) -> usize {
        DEFAULT_RUNTIME_CONNECTION_CAPACITY - self.connection_slots.available_permits()
    }

    #[cfg(test)]
    pub(crate) fn tracked_task_count(&self) -> usize {
        self.tasks.lock().map_or(0, |tasks| tasks.len())
    }
}

impl Drop for ConnectionRegistry {
    fn drop(&mut self) {
        self.connection_slots.close();
        let entries = match self.entries.lock() {
            Ok(mut entries) => std::mem::take(&mut *entries),
            Err(poisoned) => std::mem::take(&mut *poisoned.into_inner()),
        };
        drop(entries);
        let tasks = match self.tasks.lock() {
            Ok(mut tasks) => std::mem::take(&mut *tasks),
            Err(poisoned) => std::mem::take(&mut *poisoned.into_inner()),
        };
        for (_, task) in tasks {
            task.abort();
        }
    }
}

async fn join_writer(task: tokio::task::JoinHandle<()>) -> Result<(), ConnectionError> {
    match task.await {
        Ok(()) => Ok(()),
        Err(error) if error.is_cancelled() => Ok(()),
        Err(_) => Err(ConnectionError::WriterTaskFailed),
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq, thiserror::Error)]
pub enum ConnectionError {
    #[error("connection id entropy is unavailable")]
    EntropyUnavailable,
    #[error("connection writer capacity is invalid")]
    InvalidCapacity,
    #[error("runtime connection registry reached its hard limit")]
    ConnectionLimit,
    #[error("runtime connection registry is shutting down")]
    ShuttingDown,
    #[error("connection registry is unavailable")]
    RegistryPoisoned,
    #[error("connection was not found")]
    NotFound,
    #[error("connection writer lagged or closed")]
    Lagged,
    #[error("connection writer task failed while shutting down")]
    WriterTaskFailed,
    #[error("runtime envelope encoding failed")]
    Encode,
    #[error("runtime JSON/UDS frame exceeds its hard limit")]
    FrameTooLarge,
}

#[cfg(test)]
mod tests {
    use super::*;

    use agentdeck_protocol::runtime::command::HelloParams;
    use agentdeck_protocol::runtime::identity::{ConversationId, EventId, MessageId};
    use agentdeck_protocol::runtime::{
        MAX_RUNTIME_JSON_FRAME_BYTES, RUNTIME_PROTOCOL_VERSION, RuntimeEnvelope, RuntimeEvent,
        RuntimeEventBody, RuntimeFailure, RuntimeMessage, RuntimeReply, RuntimeStreamItem,
    };

    fn principal(seed: u8) -> AuthenticatedPrincipal {
        PrincipalIssuer::local_only([0xA1; 32])
            .issue_verified_local(501, [seed; 16])
            .expect("issue test local principal")
    }

    #[test]
    fn encoded_frame_contains_the_complete_runtime_envelope() {
        let envelope = RuntimeEnvelope {
            version: RUNTIME_PROTOCOL_VERSION,
            message_id: MessageId::new("message-connection-test"),
            body: RuntimeMessage::Reply(RuntimeReply::Hello(HelloParams {
                runtime_protocol_version: RUNTIME_PROTOCOL_VERSION,
            })),
        };
        let frame = EncodedRuntimeFrame::from_envelope(&envelope).expect("encode envelope");
        let decoded: RuntimeEnvelope =
            serde_json::from_slice(&frame.bytes).expect("decode complete envelope");
        assert_eq!(decoded.version, RUNTIME_PROTOCOL_VERSION);
        assert_eq!(decoded.message_id.as_str(), "message-connection-test");
        assert!(matches!(
            decoded.body,
            RuntimeMessage::Reply(RuntimeReply::Hello(HelloParams {
                runtime_protocol_version: RUNTIME_PROTOCOL_VERSION
            }))
        ));
    }

    #[test]
    fn encoded_frame_rejects_oversized_reply_and_stream_before_writer_admission() {
        let failure = || {
            RuntimeFailure::new(
                "daemon.test.oversized",
                "x".repeat(MAX_RUNTIME_JSON_FRAME_BYTES),
            )
        };
        let reply = RuntimeEnvelope {
            version: RUNTIME_PROTOCOL_VERSION,
            message_id: MessageId::new("message-oversized-reply"),
            body: RuntimeMessage::Reply(RuntimeReply::Failure(failure())),
        };
        assert!(matches!(
            EncodedRuntimeFrame::from_envelope(&reply),
            Err(ConnectionError::FrameTooLarge)
        ));

        let event = RuntimeEvent::new(
            ConversationId::new("conversation-oversized-stream"),
            EventId::new("event-oversized-stream"),
            0,
            None,
            None,
            None,
            RuntimeEventBody::Error { failure: failure() },
        )
        .unwrap();
        let stream = RuntimeEnvelope {
            version: RUNTIME_PROTOCOL_VERSION,
            message_id: MessageId::new("message-oversized-stream"),
            body: RuntimeMessage::Stream(RuntimeStreamItem::Event(event)),
        };
        assert!(matches!(
            EncodedRuntimeFrame::from_envelope(&stream),
            Err(ConnectionError::FrameTooLarge)
        ));
    }

    #[tokio::test]
    async fn slow_writer_is_disconnected_without_affecting_fast_writer() {
        let registry = ConnectionRegistry::new(2, 8);
        let (slow_tx, mut slow_rx) = mpsc::channel(1);
        let (fast_tx, mut fast_rx) = mpsc::channel(8);
        let slow = registry
            .connect(principal(1), ConnectionSink::new(slow_tx))
            .expect("connect slow");
        let fast = registry
            .connect(principal(2), ConnectionSink::new(fast_tx))
            .expect("connect fast");

        let mut accepted = 0_usize;
        let mut lagged = false;
        for _ in 0..16 {
            match registry.try_enqueue(slow, EncodedRuntimeFrame::from_bytes(&b"aa"[..])) {
                Ok(()) => accepted += 1,
                Err(ConnectionError::Lagged) => {
                    lagged = true;
                    break;
                }
                Err(other) => panic!("unexpected slow writer error: {other:?}"),
            }
            tokio::task::yield_now().await;
        }
        assert!(accepted > 0);
        assert!(lagged, "bounded slow writer must eventually lag");
        assert!(matches!(
            registry.principal(slow),
            Err(ConnectionError::NotFound)
        ));

        registry
            .try_enqueue(fast, EncodedRuntimeFrame::from_bytes(&b"ok"[..]))
            .expect("fast writer remains connected");
        let write = fast_rx.recv().await.expect("fast transport write");
        assert_eq!(write.bytes(), b"ok");
        write.acknowledge().expect("ack fast socket flush");
        drop(slow_rx.recv().await);
        registry.shutdown().await.expect("shutdown registry");
    }

    #[tokio::test]
    async fn byte_budget_is_reserved_atomically_and_disconnect_is_idempotent() {
        let registry = Arc::new(ConnectionRegistry::new(32, 4));
        let (tx, _rx) = mpsc::channel(1);
        let id = registry
            .connect(principal(3), ConnectionSink::new(tx))
            .expect("connect");
        let first = registry.clone();
        let second = registry.clone();
        let (left, right) = tokio::join!(
            async move { first.try_enqueue(id, EncodedRuntimeFrame::from_bytes(&b"aaa"[..])) },
            async move { second.try_enqueue(id, EncodedRuntimeFrame::from_bytes(&b"bbb"[..])) }
        );
        assert!(
            (left.is_ok() && right == Err(ConnectionError::Lagged))
                || (right.is_ok() && left == Err(ConnectionError::Lagged))
        );
        registry.disconnect(id).await.expect("first disconnect");
        registry
            .disconnect(id)
            .await
            .expect("idempotent disconnect");
        assert_eq!(registry.len(), 0);
    }

    #[tokio::test]
    async fn revocation_waits_for_inflight_guard_and_new_work_fails_closed() {
        let principal = principal(4);
        let guard = principal.try_enter().expect("active guard");
        let revoking = principal.clone();
        let task = tokio::spawn(async move { revoking.begin_revoke().await });
        tokio::task::yield_now().await;
        assert_eq!(
            principal.try_enter().err(),
            Some(PrincipalAccessError::Revoked)
        );
        assert!(!task.is_finished());
        drop(guard);
        task.await.expect("join revoke").expect("begin revoke");
        principal.finish_revoke();
        assert!(!principal.is_active());
    }

    #[tokio::test]
    async fn same_authorization_identity_shares_one_revocation_lease() {
        let issuer = PrincipalIssuer::local_only([0xC3; 32]);
        let first = issuer
            .issue_verified_local(501, [9; 16])
            .expect("first capability");
        let second = issuer
            .issue_verified_local(501, [9; 16])
            .expect("second capability");
        let guard = second.try_enter().expect("shared lease guard");
        let revoking = first.clone();
        let revoke = tokio::spawn(async move { revoking.begin_revoke().await });
        tokio::task::yield_now().await;
        assert_eq!(
            second.try_enter().err(),
            Some(PrincipalAccessError::Revoked)
        );
        drop(guard);
        revoke.await.expect("join revoke").expect("begin revoke");
        first.finish_revoke();
        assert_eq!(
            second.try_enter().err(),
            Some(PrincipalAccessError::Revoked)
        );
        drop(second);
        drop(first);
        let reissued = issuer
            .issue_verified_local(501, [9; 16])
            .expect("reissue identical capability");
        assert_eq!(
            reissued.try_enter().err(),
            Some(PrincipalAccessError::Revoked),
            "issuer lifetime must retain the revoked lease"
        );
    }

    #[test]
    fn approval_permissions_are_explicit_and_fail_closed_per_operation() {
        let issuer = PrincipalIssuer::local_only([0xC4; 32]);
        let none = issuer
            .issue_verified_local(501, [1; 16])
            .expect("principal without approval permission");
        assert!(matches!(
            none.try_enter_approval(),
            Err(PrincipalAccessError::PermissionDenied)
        ));

        let resolve_only = issuer
            .issue_verified_local_with_approval_permissions(
                501,
                [2; 16],
                ApprovalPermissionGrant::ResolveOnly,
            )
            .expect("resolve-only principal");
        let resolve = resolve_only
            .try_enter_approval()
            .expect("enter resolve capability");
        resolve.require_resolve().expect("resolve permission");
        assert_eq!(
            resolve.require_retry(),
            Err(PrincipalAccessError::PermissionDenied)
        );

        let retry_only = issuer
            .issue_verified_local_with_approval_permissions(
                501,
                [3; 16],
                ApprovalPermissionGrant::RetryOnly,
            )
            .expect("retry-only principal");
        let retry = retry_only
            .try_enter_approval()
            .expect("enter retry capability");
        retry.require_retry().expect("retry permission");
        assert_eq!(
            retry.require_resolve(),
            Err(PrincipalAccessError::PermissionDenied)
        );
    }

    #[test]
    fn verified_remote_can_resolve_without_an_is_local_shortcut() {
        let issuer = PrincipalIssuer::local_only([0xC5; 32]);
        let remote = issuer
            .issue_test_remote_with_approval_permissions(
                [4; 16],
                [5; 16],
                7,
                [6; 32],
                ApprovalPermissionGrant::ResolveOnly,
            )
            .expect("verified remote approval principal");
        assert!(!remote.is_local());
        remote
            .try_enter_approval()
            .expect("remote approval guard")
            .require_resolve()
            .expect("issuer-granted remote resolve");
    }

    #[tokio::test]
    async fn approval_guard_holds_the_shared_lease_through_revoking() {
        let issuer = PrincipalIssuer::local_only([0xC6; 32]);
        let first = issuer
            .issue_verified_local_with_approval_permissions(
                501,
                [7; 16],
                ApprovalPermissionGrant::ResolveAndRetry,
            )
            .expect("first approval principal");
        let second = issuer
            .issue_verified_local_with_approval_permissions(
                501,
                [7; 16],
                ApprovalPermissionGrant::ResolveAndRetry,
            )
            .expect("same identity reuses approval grant");
        let guard = second.try_enter_approval().expect("shared approval guard");
        guard.require_resolve().expect("resolve permission");
        let revoking = first.clone();
        let revoke = tokio::spawn(async move { revoking.begin_revoke().await });
        tokio::task::yield_now().await;
        assert!(matches!(
            second.try_enter_approval(),
            Err(PrincipalAccessError::Revoked)
        ));
        assert!(!revoke.is_finished(), "approval guard must cover the CAS");
        drop(guard);
        revoke.await.expect("join revoke").expect("begin revoke");
        first.finish_revoke();
    }

    #[test]
    fn same_full_identity_cannot_be_reissued_with_different_approval_bits() {
        let issuer = PrincipalIssuer::local_only([0xC7; 32]);
        issuer
            .issue_verified_local_with_approval_permissions(
                501,
                [8; 16],
                ApprovalPermissionGrant::ResolveOnly,
            )
            .expect("first signed permission set");
        assert!(matches!(
            issuer.issue_verified_local_with_approval_permissions(
                501,
                [8; 16],
                ApprovalPermissionGrant::RetryOnly,
            ),
            Err(PrincipalAccessError::PermissionConflict)
        ));
        assert!(matches!(
            issuer.issue_verified_local(501, [8; 16]),
            Err(PrincipalAccessError::PermissionConflict)
        ));
    }

    #[test]
    fn claimant_binding_is_canonical_full_identity_and_debug_redacted() {
        let issuer = PrincipalIssuer::local_only([0xC8; 32]);
        let first = issuer
            .issue_test_remote_with_approval_permissions(
                [9; 16],
                [10; 16],
                11,
                [12; 32],
                ApprovalPermissionGrant::ResolveAndRetry,
            )
            .expect("first remote claimant");
        let replay = issuer
            .issue_test_remote_with_approval_permissions(
                [9; 16],
                [10; 16],
                11,
                [12; 32],
                ApprovalPermissionGrant::ResolveAndRetry,
            )
            .expect("same full identity");
        let renewed = issuer
            .issue_test_remote_with_approval_permissions(
                [9; 16],
                [10; 16],
                12,
                [12; 32],
                ApprovalPermissionGrant::ResolveAndRetry,
            )
            .expect("new grant serial is a new full identity");
        let first_binding = first
            .try_enter_approval()
            .expect("first approval guard")
            .claimant_binding();
        let replay_binding = replay
            .try_enter_approval()
            .expect("replay approval guard")
            .claimant_binding();
        let renewed_binding = renewed
            .try_enter_approval()
            .expect("renewed approval guard")
            .claimant_binding();
        assert_eq!(first_binding.as_bytes(), replay_binding.as_bytes());
        assert_ne!(first_binding.as_bytes(), renewed_binding.as_bytes());
        assert_eq!(
            format!("{first_binding:?}"),
            "ApprovalClaimantBinding([REDACTED])"
        );
        assert!(!format!("{first_binding:?}").contains("090909"));
    }

    #[tokio::test]
    async fn dropped_unacknowledged_transport_write_removes_registry_entry() {
        let registry = ConnectionRegistry::new(2, 8);
        let (tx, mut rx) = mpsc::channel(1);
        let id = registry
            .connect(principal(7), ConnectionSink::new(tx))
            .expect("connect");
        registry
            .try_enqueue(id, EncodedRuntimeFrame::from_bytes(&b"lost"[..]))
            .expect("enqueue");
        drop(rx.recv().await.expect("transport work without ACK"));
        tokio::time::timeout(std::time::Duration::from_secs(1), async {
            while registry.len() != 0 {
                tokio::task::yield_now().await;
            }
        })
        .await
        .expect("writer cleanup");
        assert!(matches!(
            registry.principal(id),
            Err(ConnectionError::NotFound)
        ));
        assert_eq!(registry.active_writer_count(), 0);
    }

    #[tokio::test]
    async fn total_connection_count_saturates_at_the_hard_limit() {
        let registry = ConnectionRegistry::new(1, 8);
        for seed in 0_u16..128 {
            let (tx, _rx) = mpsc::channel(1);
            registry
                .connect(
                    principal(u8::try_from(seed).expect("test seed")),
                    ConnectionSink::new(tx),
                )
                .expect("connection below hard limit");
        }
        let (overflow_tx, _overflow_rx) = mpsc::channel(1);
        assert!(
            registry
                .connect(principal(255), ConnectionSink::new(overflow_tx))
                .is_err(),
            "the 129th writer must fail before allocating an untracked task"
        );
        registry.shutdown().await.expect("join saturated writers");
        assert_eq!(registry.active_writer_count(), 0);
        assert_eq!(registry.tracked_task_count(), 0);
    }

    #[tokio::test]
    async fn principal_lease_count_saturates_without_evicting_reuse_or_revoked_tombstone() {
        let issuer = PrincipalIssuer::local_only([0xD4; 32]);
        let first_id = 0_u128.to_be_bytes();
        let first = issuer
            .issue_verified_local(501, first_id)
            .expect("first principal");
        for index in 1_u128..1_024 {
            issuer
                .issue_verified_local(501, index.to_be_bytes())
                .expect("principal below hard limit");
        }

        issuer
            .issue_verified_local(501, first_id)
            .expect("same identity reuses a lease at capacity");
        first.begin_revoke().await.expect("begin revoke");
        first.finish_revoke();
        assert!(
            issuer
                .issue_verified_local(501, 1_024_u128.to_be_bytes())
                .is_err(),
            "a new identity must fail closed at capacity"
        );
        let tombstone = issuer
            .issue_verified_local(501, first_id)
            .expect("revoked tombstone remains addressable");
        assert_eq!(
            tombstone.try_enter().err(),
            Some(PrincipalAccessError::Revoked),
            "capacity pressure must not evict a revoked tombstone"
        );
    }

    #[tokio::test]
    async fn dropping_registry_breaks_writer_registry_ownership() {
        let registry = ConnectionRegistry::new(1, 8);
        let entries = Arc::downgrade(&registry.entries);
        let tasks = Arc::downgrade(&registry.tasks);
        let slots = registry.connection_slots.clone();
        let (tx, mut rx) = mpsc::channel(1);
        registry
            .connect(principal(8), ConnectionSink::new(tx))
            .expect("connect");
        drop(registry);
        tokio::time::timeout(std::time::Duration::from_secs(1), async {
            while entries.upgrade().is_some() {
                tokio::task::yield_now().await;
            }
        })
        .await
        .expect("writer task must not retain the registry after Drop");
        assert!(tasks.upgrade().is_none());
        tokio::time::timeout(std::time::Duration::from_secs(1), async {
            while slots.available_permits() != DEFAULT_RUNTIME_CONNECTION_CAPACITY {
                tokio::task::yield_now().await;
            }
        })
        .await
        .expect("Drop must abort every writer task");
        assert!(rx.recv().await.is_none());
    }

    #[tokio::test]
    async fn disconnect_and_shutdown_join_writers_before_returning() {
        let registry = ConnectionRegistry::new(2, 16);
        let (first_tx, mut first_rx) = mpsc::channel(1);
        let first = registry
            .connect(principal(9), ConnectionSink::new(first_tx))
            .expect("first connection");
        assert_eq!(registry.active_writer_count(), 1);
        registry.disconnect(first).await.expect("disconnect first");
        assert_eq!(registry.active_writer_count(), 0);
        assert_eq!(registry.tracked_task_count(), 0);
        assert!(first_rx.recv().await.is_none());

        let (second_tx, mut second_rx) = mpsc::channel(1);
        let (third_tx, mut third_rx) = mpsc::channel(1);
        registry
            .connect(principal(10), ConnectionSink::new(second_tx))
            .expect("second connection");
        registry
            .connect(principal(11), ConnectionSink::new(third_tx))
            .expect("third connection");
        assert_eq!(registry.active_writer_count(), 2);
        registry.shutdown().await.expect("shutdown writers");
        assert_eq!(registry.active_writer_count(), 0);
        assert_eq!(registry.len(), 0);
        assert_eq!(registry.tracked_task_count(), 0);
        assert!(second_rx.recv().await.is_none());
        assert!(third_rx.recv().await.is_none());
        registry.shutdown().await.expect("idempotent shutdown");
    }

    #[tokio::test]
    async fn repeated_lag_abort_reclaims_task_map_and_slots_without_churn_growth() {
        let registry = ConnectionRegistry::new(1, 1);
        for index in 0_u16..512 {
            let (tx, _rx) = mpsc::channel(1);
            let id = registry
                .connect(
                    principal(u8::try_from(index % 251).expect("principal seed")),
                    ConnectionSink::new(tx),
                )
                .expect("connect churn writer");
            assert_eq!(
                registry.try_enqueue(id, EncodedRuntimeFrame::from_bytes(&b"xx"[..])),
                Err(ConnectionError::Lagged)
            );
            tokio::time::timeout(std::time::Duration::from_secs(1), async {
                while registry.active_writer_count() != 0 || registry.tracked_task_count() != 0 {
                    tokio::task::yield_now().await;
                }
            })
            .await
            .expect("lagged writer cleanup");
            assert_eq!(registry.len(), 0);
        }
        registry.shutdown().await.expect("shutdown after churn");
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 4)]
    async fn concurrent_connect_and_shutdown_leave_no_writer_outside_the_join_fence() {
        let registry = Arc::new(ConnectionRegistry::new(1, 8));
        let barrier = Arc::new(tokio::sync::Barrier::new(33));
        let mut connects = Vec::new();
        for seed in 0_u8..32 {
            let registry = registry.clone();
            let barrier = barrier.clone();
            connects.push(tokio::spawn(async move {
                let (tx, _rx) = mpsc::channel(1);
                barrier.wait().await;
                registry.connect(principal(seed), ConnectionSink::new(tx))
            }));
        }
        let shutting_down = {
            let registry = registry.clone();
            let barrier = barrier.clone();
            tokio::spawn(async move {
                barrier.wait().await;
                registry.shutdown().await
            })
        };

        for connect in connects {
            match connect.await.expect("join connect racer") {
                Ok(_) | Err(ConnectionError::ShuttingDown) => {}
                Err(other) => panic!("unexpected connect race result: {other:?}"),
            }
        }
        shutting_down
            .await
            .expect("join shutdown racer")
            .expect("shutdown race");
        assert_eq!(registry.len(), 0);
        assert_eq!(registry.tracked_task_count(), 0);
        assert_eq!(registry.active_writer_count(), 0);

        let (tx, _rx) = mpsc::channel(1);
        assert_eq!(
            registry.connect(principal(250), ConnectionSink::new(tx)),
            Err(ConnectionError::ShuttingDown)
        );
    }

    #[test]
    fn grant_renewal_changes_authorization_key_but_not_idempotency_owner() {
        let issuer = PrincipalIssuer::local_only([0xB2; 32]);
        let first = issuer
            .issue_test_remote([1; 16], [2; 16], 7, [3; 32])
            .expect("issue old grant");
        let renewed = issuer
            .issue_test_remote([1; 16], [2; 16], 8, [3; 32])
            .expect("issue renewed grant");
        assert_eq!(first.idempotency_owner(), renewed.idempotency_owner());
        assert_ne!(first.authorization_key(), renewed.authorization_key());
    }
}
