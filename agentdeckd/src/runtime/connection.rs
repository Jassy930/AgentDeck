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
use tokio::sync::{Notify, OwnedSemaphorePermit, Semaphore, mpsc, oneshot};
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

    /// 向调用方自己的 domain-separated buffer 写入完整 authorization identity。
    /// remote 必含 machine route 与 grant serial；不能退化成故意跨 renewal 稳定的
    /// idempotency owner。
    pub(crate) fn append_authorization_identity_binding(&self, target: &mut Vec<u8>) {
        append_canonical_field(target, b"principal.authorization.v1");
        match self.identity.as_ref() {
            PrincipalIdentity::Local {
                machine_trust_domain,
                uid,
                client_installation_id,
            } => {
                append_canonical_field(target, &[1]);
                append_canonical_field(target, machine_trust_domain);
                append_canonical_field(target, &uid.to_be_bytes());
                append_canonical_field(target, client_installation_id);
            }
            PrincipalIdentity::Remote {
                machine_trust_domain,
                machine_route,
                device_route,
                grant_serial,
                device_sign_fingerprint,
            } => {
                append_canonical_field(target, &[2]);
                append_canonical_field(target, machine_trust_domain);
                append_canonical_field(target, machine_route);
                append_canonical_field(target, device_route);
                append_canonical_field(target, &grant_serial.to_be_bytes());
                append_canonical_field(target, device_sign_fingerprint);
            }
        }
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

/// daemon-private authorization identity 的 length-delimited canonical field。
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

    #[cfg(test)]
    pub(super) const fn from_test_bytes(bytes: [u8; 16]) -> Self {
        Self(bytes)
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

/// connection-owned reply pump 在 transport write/flush ACK 后完成的回执。
///
/// barrier/backfill job 可以等待此回执后再推进 store pin；RuntimeCore 的普通请求
/// 处理只负责入队，不等待此回执或 socket。
#[must_use = "flush receipt must be awaited before advancing paced state"]
pub struct FlushReceipt {
    completion: oneshot::Receiver<Result<(), ConnectionError>>,
}

impl FlushReceipt {
    pub async fn wait(self) -> Result<(), ConnectionError> {
        self.completion
            .await
            .unwrap_or(Err(ConnectionError::Lagged))
    }
}

impl fmt::Debug for FlushReceipt {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("FlushReceipt([PENDING])")
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
    flush_completion: Option<oneshot::Sender<Result<(), ConnectionError>>>,
}

struct ConnectionIncarnation;

#[must_use = "paced reservation must be committed or dropped to release its budgets"]
pub(super) struct PacedFrameReservation {
    id: ConnectionId,
    incarnation: Arc<ConnectionIncarnation>,
    writer: mpsc::Sender<QueuedFrame>,
    frame: EncodedRuntimeFrame,
    byte_permit: OwnedSemaphorePermit,
    frame_permit: OwnedSemaphorePermit,
    reservation_slot: OwnedSemaphorePermit,
}

struct ConnectionEntry {
    incarnation: Arc<ConnectionIncarnation>,
    principal: AuthenticatedPrincipal,
    writer: mpsc::Sender<QueuedFrame>,
    byte_budget: Arc<Semaphore>,
    frame_budget: Arc<Semaphore>,
    paced_reservation_slot: Arc<Semaphore>,
}

type ConnectionEntries = Mutex<HashMap<ConnectionId, ConnectionEntry>>;

struct TrackedWriterTask {
    incarnation: Arc<ConnectionIncarnation>,
    handle: Option<tokio::task::JoinHandle<()>>,
    exit: Arc<WriterTaskExit>,
}

const WRITER_TASK_RUNNING: u8 = 0;
const WRITER_TASK_EXITED_OK: u8 = 1;
const WRITER_TASK_EXITED_FAILED: u8 = 2;

struct WriterTaskExit {
    terminal: std::sync::atomic::AtomicU8,
    notified: Notify,
}

impl WriterTaskExit {
    fn new() -> Self {
        Self {
            terminal: std::sync::atomic::AtomicU8::new(WRITER_TASK_RUNNING),
            notified: Notify::new(),
        }
    }

    fn publish_terminal(&self, terminal: u8) {
        self.terminal
            .store(terminal, std::sync::atomic::Ordering::Release);
        self.notified.notify_waiters();
    }

    async fn wait(&self) -> Result<(), ConnectionError> {
        loop {
            let notified = self.notified.notified();
            tokio::pin!(notified);
            notified.as_mut().enable();
            match self.terminal.load(std::sync::atomic::Ordering::Acquire) {
                WRITER_TASK_RUNNING => notified.await,
                WRITER_TASK_EXITED_OK => return Ok(()),
                WRITER_TASK_EXITED_FAILED => return Err(ConnectionError::WriterTaskFailed),
                _ => return Err(ConnectionError::WriterTaskFailed),
            }
        }
    }
}

type WriterTasks = Mutex<HashMap<ConnectionId, TrackedWriterTask>>;

enum DisconnectWriter {
    Owner(tokio::task::JoinHandle<()>),
    Wait(Arc<WriterTaskExit>),
    Absent,
}

struct ShutdownWriter {
    handle: Option<tokio::task::JoinHandle<()>>,
    exit: Arc<WriterTaskExit>,
}

fn connection_id_is_available(
    entries: &HashMap<ConnectionId, ConnectionEntry>,
    tasks: &HashMap<ConnectionId, TrackedWriterTask>,
    id: ConnectionId,
) -> bool {
    !entries.contains_key(&id) && !tasks.contains_key(&id)
}

/// task 正常退出、panic 或被 abort 时都会执行。在同一个 task-map 临界区内先释放
/// connection slot、再 exact 删除 tombstone、随后发布 terminal outcome；调用方观察
/// 到 terminal 时，writer 的 entry/task/slot 资源已经完成清理。
struct WriterTaskLifetime {
    id: ConnectionId,
    incarnation: Arc<ConnectionIncarnation>,
    entries: Weak<ConnectionEntries>,
    tasks: Weak<WriterTasks>,
    connection_slot: Option<OwnedSemaphorePermit>,
    exit: Arc<WriterTaskExit>,
}

impl WriterTaskLifetime {
    fn fail_close_entry(&self) {
        if let Some(entries) = self.entries.upgrade()
            && let Ok(mut entries) = entries.lock()
            && entries
                .get(&self.id)
                .is_some_and(|entry| Arc::ptr_eq(&entry.incarnation, &self.incarnation))
        {
            entries.remove(&self.id);
        }
    }

    fn fail_close_entry_and_complete(
        &self,
        completion: Option<oneshot::Sender<Result<(), ConnectionError>>>,
        result: Result<(), ConnectionError>,
    ) {
        let mut completion = completion;
        if let Some(entries) = self.entries.upgrade()
            && let Ok(mut entries) = entries.lock()
        {
            if entries
                .get(&self.id)
                .is_some_and(|entry| Arc::ptr_eq(&entry.incarnation, &self.incarnation))
            {
                entries.remove(&self.id);
            }
            if let Some(completion) = completion.take() {
                let _ = completion.send(result);
            }
            return;
        }
        if let Some(completion) = completion {
            let _ = completion.send(result);
        }
    }
}

impl Drop for WriterTaskLifetime {
    fn drop(&mut self) {
        let terminal = if std::thread::panicking() {
            WRITER_TASK_EXITED_FAILED
        } else {
            WRITER_TASK_EXITED_OK
        };
        self.fail_close_entry();
        if let Some(tasks) = self.tasks.upgrade()
            && let Ok(mut tasks) = tasks.lock()
        {
            // 在 task-map 锁内先释放 slot 再移除 handle：新 connect 即使取得
            // permit，也必须等待同一把锁，不能在旧 task 完成登记清理前 spawn。
            self.connection_slot.take();
            if tasks
                .get(&self.id)
                .is_some_and(|task| Arc::ptr_eq(&task.incarnation, &self.incarnation))
            {
                tasks.remove(&self.id);
            }
            self.exit.publish_terminal(terminal);
        } else {
            // registry 已经 Drop、无法再接入新连接时只需释放剩余 slot。
            self.connection_slot.take();
            self.exit.publish_terminal(terminal);
        }
    }
}

#[derive(Clone)]
pub(crate) struct ConnectionRegistry {
    clone_lifetime: Arc<()>,
    entries: Arc<ConnectionEntries>,
    tasks: Arc<WriterTasks>,
    connection_slots: Arc<Semaphore>,
    frame_capacity: usize,
    byte_capacity: usize,
}

impl ConnectionRegistry {
    pub(crate) fn new(frame_capacity: usize, byte_capacity: usize) -> Self {
        Self {
            clone_lifetime: Arc::new(()),
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
        if !connection_id_is_available(&entries, &tasks, id) {
            return Err(ConnectionError::EntropyUnavailable);
        }
        let (writer, mut receiver) = mpsc::channel::<QueuedFrame>(self.frame_capacity);
        let incarnation = Arc::new(ConnectionIncarnation);
        let byte_budget = Arc::new(Semaphore::new(self.byte_capacity));
        let frame_budget = Arc::new(Semaphore::new(self.frame_capacity));
        let paced_reservation_slot = Arc::new(Semaphore::new(1));
        let exit = Arc::new(WriterTaskExit::new());
        let weak_entries = Arc::downgrade(&self.entries);
        let weak_tasks = Arc::downgrade(&self.tasks);
        let lifetime = WriterTaskLifetime {
            id,
            incarnation: incarnation.clone(),
            entries: weak_entries,
            tasks: weak_tasks,
            connection_slot: Some(connection_slot),
            exit: exit.clone(),
        };
        let (published, published_rx) = oneshot::channel();
        let task = tokio::spawn(async move {
            // lifetime 在 spawn 前已构造；即使 task 从未 poll 就被 abort，future Drop
            // 仍会执行 registry cleanup 并释放 slot。
            let lifetime = lifetime;
            if published_rx.await.is_err() {
                return;
            }
            while let Some(mut queued) = receiver.recv().await {
                let (acknowledged, acknowledgement) = oneshot::channel();
                let transport_result = if sink
                    .sender
                    .send(ConnectionWrite {
                        bytes: queued.frame.bytes.clone(),
                        acknowledged: Some(acknowledged),
                    })
                    .await
                    .is_err()
                {
                    Err(ConnectionError::Lagged)
                } else {
                    acknowledgement.await.map_err(|_| ConnectionError::Lagged)
                };
                let completion = queued.flush_completion.take();
                drop(queued);
                if transport_result.is_err() {
                    // 先让新业务入口 fail-close；JoinHandle 与 connection slot 仍由
                    // live writer 持有，直到 async future 真正返回并执行 Drop。entry
                    // removal 与 error completion 在同一临界区排序，调用方不会观察到
                    // “connection 已消失但 flush error 尚不可见”的中间态。
                    lifetime.fail_close_entry_and_complete(completion, transport_result);
                } else if let Some(completion) = completion {
                    let _ = completion.send(Ok(()));
                }
                if transport_result.is_err() {
                    break;
                }
            }
        });
        let entry = ConnectionEntry {
            incarnation: incarnation.clone(),
            principal,
            writer,
            byte_budget,
            frame_budget,
            paced_reservation_slot,
        };
        let replaced = entries.insert(id, entry);
        debug_assert!(replaced.is_none());
        let replaced = tasks.insert(
            id,
            TrackedWriterTask {
                incarnation,
                handle: Some(task),
                exit,
            },
        );
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
        let incarnation = entry.incarnation.clone();
        if encoded_len == 0 || encoded_len > self.byte_capacity {
            let removed = entries.remove(&id).is_some();
            drop(entries);
            if removed {
                self.abort_tracked_writer(id, &incarnation)?;
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
                    flush_completion: None,
                })
                .map_err(|_| ConnectionError::Lagged)
        });
        if queued.is_err() {
            let removed = entries.remove(&id).is_some();
            drop(entries);
            if removed {
                self.abort_tracked_writer(id, &incarnation)?;
            }
        }
        queued
    }

    /// paced producer 使用的异步 reservation。它只等待本 connection 的 frame/byte
    /// permit，不发送 frame；调用方可在等待后重新检查自己的 lifecycle admission。
    pub(super) async fn reserve_paced(
        &self,
        id: ConnectionId,
        frame: EncodedRuntimeFrame,
    ) -> Result<PacedFrameReservation, ConnectionError> {
        let encoded_len = frame.bytes.len();
        if encoded_len == 0 || encoded_len > self.byte_capacity {
            self.fail_connection(id)?;
            return Err(ConnectionError::Lagged);
        }
        let permits = u32::try_from(encoded_len).map_err(|_| ConnectionError::Lagged)?;
        let (incarnation, writer, byte_budget, frame_budget, paced_reservation_slot) = {
            let entries = self
                .entries
                .lock()
                .map_err(|_| ConnectionError::RegistryPoisoned)?;
            let entry = entries.get(&id).ok_or(ConnectionError::NotFound)?;
            (
                entry.incarnation.clone(),
                entry.writer.clone(),
                entry.byte_budget.clone(),
                entry.frame_budget.clone(),
                entry.paced_reservation_slot.clone(),
            )
        };
        let reservation_slot = paced_reservation_slot
            .try_acquire_owned()
            .map_err(|_| ConnectionError::Lagged)?;
        let frame_permit = frame_budget
            .acquire_owned()
            .await
            .map_err(|_| ConnectionError::Lagged)?;
        let byte_permit = byte_budget
            .acquire_many_owned(permits)
            .await
            .map_err(|_| ConnectionError::Lagged)?;
        Ok(PacedFrameReservation {
            id,
            incarnation,
            writer,
            frame,
            byte_permit,
            frame_permit,
            reservation_slot,
        })
    }

    /// 已取得 Core admission 后同步提交 reservation。permit 与 flush completion
    /// 一起进入 reply pump，并持续持有到 transport flush ACK。
    pub(super) fn commit_paced(
        &self,
        reservation: PacedFrameReservation,
    ) -> Result<FlushReceipt, ConnectionError> {
        let PacedFrameReservation {
            id,
            incarnation,
            writer,
            frame,
            byte_permit,
            frame_permit,
            reservation_slot: _reservation_slot,
        } = reservation;
        let mut entries = self
            .entries
            .lock()
            .map_err(|_| ConnectionError::RegistryPoisoned)?;
        if !entries
            .get(&id)
            .is_some_and(|entry| Arc::ptr_eq(&entry.incarnation, &incarnation))
        {
            return Err(ConnectionError::NotFound);
        }
        let (completion, receipt) = oneshot::channel();
        if writer
            .try_send(QueuedFrame {
                frame,
                _bytes: byte_permit,
                _frame: frame_permit,
                flush_completion: Some(completion),
            })
            .is_err()
        {
            entries.remove(&id);
            drop(entries);
            self.abort_tracked_writer(id, &incarnation)?;
            return Err(ConnectionError::Lagged);
        }
        drop(entries);
        Ok(FlushReceipt {
            completion: receipt,
        })
    }

    pub(crate) async fn disconnect(&self, id: ConnectionId) -> Result<(), ConnectionError> {
        match self.begin_disconnect(id)? {
            DisconnectWriter::Owner(task) => {
                task.abort();
                join_writer(task).await?;
            }
            DisconnectWriter::Wait(exit) => exit.wait().await?,
            DisconnectWriter::Absent => {}
        }
        Ok(())
    }

    fn begin_disconnect(&self, id: ConnectionId) -> Result<DisconnectWriter, ConnectionError> {
        let incarnation = self
            .entries
            .lock()
            .map_err(|_| ConnectionError::RegistryPoisoned)?
            .remove(&id)
            .map(|entry| entry.incarnation);
        let writer = {
            let mut tasks = self
                .tasks
                .lock()
                .map_err(|_| ConnectionError::RegistryPoisoned)?;
            let Some(task) = tasks.get_mut(&id) else {
                return Ok(DisconnectWriter::Absent);
            };
            let matches = incarnation
                .as_ref()
                .is_none_or(|incarnation| Arc::ptr_eq(&task.incarnation, incarnation));
            if !matches {
                DisconnectWriter::Absent
            } else if let Some(handle) = task.handle.take() {
                DisconnectWriter::Owner(handle)
            } else {
                DisconnectWriter::Wait(task.exit.clone())
            }
        };
        Ok(writer)
    }

    pub(crate) async fn shutdown(&self) -> Result<(), ConnectionError> {
        self.connection_slots.close();
        let entries = std::mem::take(
            &mut *self
                .entries
                .lock()
                .map_err(|_| ConnectionError::RegistryPoisoned)?,
        );
        let tasks = self.claim_writers_for_shutdown()?;
        drop(entries);
        for task in &tasks {
            if let Some(handle) = task.handle.as_ref() {
                handle.abort();
            }
        }
        let mut failed = false;
        for task in tasks {
            if let Some(handle) = task.handle {
                if join_writer(handle).await.is_err() {
                    failed = true;
                }
            } else {
                if task.exit.wait().await.is_err() {
                    failed = true;
                }
            }
        }
        if failed {
            return Err(ConnectionError::WriterTaskFailed);
        }
        Ok(())
    }

    fn claim_writers_for_shutdown(&self) -> Result<Vec<ShutdownWriter>, ConnectionError> {
        let mut tasks = self
            .tasks
            .lock()
            .map_err(|_| ConnectionError::RegistryPoisoned)?;
        Ok(tasks
            .values_mut()
            .map(|task| ShutdownWriter {
                handle: task.handle.take(),
                exit: task.exit.clone(),
            })
            .collect())
    }

    fn abort_tracked_writer(
        &self,
        id: ConnectionId,
        incarnation: &Arc<ConnectionIncarnation>,
    ) -> Result<(), ConnectionError> {
        if let Some(task) = self
            .tasks
            .lock()
            .map_err(|_| ConnectionError::RegistryPoisoned)?
            .get(&id)
            .filter(|task| Arc::ptr_eq(&task.incarnation, incarnation))
            && let Some(handle) = task.handle.as_ref()
        {
            handle.abort();
        }
        Ok(())
    }

    fn fail_connection(&self, id: ConnectionId) -> Result<(), ConnectionError> {
        let incarnation = self
            .entries
            .lock()
            .map_err(|_| ConnectionError::RegistryPoisoned)?
            .remove(&id)
            .map(|entry| entry.incarnation);
        if let Some(incarnation) = incarnation {
            self.abort_tracked_writer(id, &incarnation)?;
        }
        Ok(())
    }

    /// 威胁场景：客户端已收到 subscription 的部分 snapshot/backfill 后，daemon
    /// 无法再生成连续终态；继续复用连接会让客户端把残缺 reducer 当成可恢复状态。
    /// production reply pump 只能在这种已部分交付的错误上 fail-close 当前连接。
    pub(crate) fn fail_close(&self, id: ConnectionId) -> Result<(), ConnectionError> {
        self.fail_connection(id)
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
        // detached reply pump 只持一个 registry clone；该 capability 结束时不能把
        // RuntimeCore 仍在使用的共享 writer 全部关闭。最后一个 owner 才执行兜底清理。
        if Arc::strong_count(&self.clone_lifetime) != 1 {
            return;
        }
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
            if let Some(handle) = task.handle {
                handle.abort();
            }
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
#[path = "connection/tests.rs"]
mod tests;
