//! RuntimeCore connection registry 与每连接有界 outbox。
//!
//! 本层只持有已经认证的 principal 与 opaque encoded frame。它不读取 socket、
//! 不 import 任何 Relay/UDS transport 类型，RuntimeCore 也只做 `try_enqueue`，
//! 永不 await 慢 writer。

use std::collections::HashMap;
use std::fmt;
use std::hash::{Hash, Hasher};
use std::sync::{Arc, Mutex, Weak};

use agentdeck_protocol::e2ee::AuthorizationPermissionV1;
use agentdeck_protocol::runtime::identity::{DeviceHandle, GrantSerial};
use agentdeck_protocol::runtime::{
    MAX_JSON_PART_BYTES, MAX_PART_BYTES, RuntimeEnvelope, RuntimeTransferCarrierError,
    RuntimeTransferCarrierV1,
};
use tokio::sync::{Notify, OwnedSemaphorePermit, Semaphore, mpsc, oneshot};
use zeroize::Zeroizing;

use crate::runtime::model::RemoteCommandAuthorizationBinding;
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
const DEVICE_HANDLE_PREFIX: &str = "device-";

/// 认证后、不可由 transport raw field 直接构造的 principal capability。
///
/// 字段和构造器都不公开；P3.8/P4 transport 必须先完成 peer/signature/replay
/// 验证，再通过 daemon 内部 issuer 获取此 capability。P4 durable auth ledger
/// 接入前 production remote issuer 保持关闭。
#[derive(Clone)]
pub struct AuthenticatedPrincipal {
    identity: Arc<PrincipalIdentity>,
    authorization: Arc<AuthorizationLease>,
    /// 本次 Store-current proof 冻结的 exact command binding。共享 lease 只承载稳定
    /// identity/permissions/revoke state；rotation 后的新请求必须保留新 revision 快照，
    /// 不能复用首次连接的旧 ADC2 binding。
    remote_command_authorization: Option<RemoteCommandAuthorizationBinding>,
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

/// 由 exact authenticated remote principal 派生的一次 self-revoke admission。
///
/// request/transport 不能提供或覆盖 target；`into_parts` 会先释放 Active permission
/// guard，避免后续共享 revoke fence 等待自身 inflight。Revoking lease 的 exact retry
/// 不再新增 guard，但仍只能得到同一 principal/route/serial。
pub(crate) struct RemoteSelfRevocationAdmission {
    principal: AuthenticatedPrincipal,
    device: DeviceHandle,
    grant_serial: GrantSerial,
    authorization: Option<AuthorizationGuard>,
}

impl RemoteSelfRevocationAdmission {
    /// Active admission 仍走普通 connection；Revoking 只能复用 exact connection，
    /// 或交给 Core 建立 purpose-scoped self-revoke retry connection。
    pub(crate) const fn is_revoking_retry(&self) -> bool {
        self.authorization.is_none()
    }

    pub(crate) fn into_parts(self) -> (AuthenticatedPrincipal, DeviceHandle, GrantSerial) {
        let Self {
            principal,
            device,
            grant_serial,
            authorization,
        } = self;
        drop(authorization);
        (principal, device, grant_serial)
    }

    /// 只把 Revoking admission 转成 purpose-scoped connection capability。Active
    /// admission 仍必须走普通 `RuntimeCore::connect`；已经 Revoked 的 lease 即使 token
    /// 先前已生成，也会在 Core attach 的前后双读中拒绝。
    pub(crate) fn into_revoking_retry_principal(
        self,
    ) -> Result<AuthenticatedPrincipal, PrincipalAccessError> {
        if self.authorization.is_some() {
            return Err(PrincipalAccessError::PermissionDenied);
        }
        let Self {
            principal,
            device: _,
            grant_serial: _,
            authorization: _,
        } = self;
        if !principal.is_revoking() {
            return Err(PrincipalAccessError::Revoked);
        }
        Ok(principal)
    }
}

impl fmt::Debug for RemoteSelfRevocationAdmission {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("RemoteSelfRevocationAdmission([REDACTED])")
    }
}

struct AuthorizationLease {
    state: std::sync::atomic::AtomicU8,
    inflight: std::sync::atomic::AtomicUsize,
    quiesced: tokio::sync::Notify,
    approval_permissions: ApprovalPermissionGrant,
    remote_permissions: Option<RemotePermissionGrant>,
    local_administration: bool,
}

/// issuer 对稳定 principal identity 的共享 lease 与最近一次 Store-current command
/// binding。历史 `AuthenticatedPrincipal` 保留各自快照；latest 只供后续签发和离线 revoke
/// 找回当前 exact binding，且绝不允许 revision 回退。
struct PrincipalLeaseRecord {
    authorization: Arc<AuthorizationLease>,
    latest_remote_command_authorization: Option<RemoteCommandAuthorizationBinding>,
}

/// Store-authenticated remote permission allowlist。固定 bitset 避免把 grant 的
/// 可变长 wire `Vec` 留在 Core lease 内，也让相同完整身份的重复签发可以做 exact
/// permission conflict 检查。`None` 只表示已通过 same-EUID issuer 的 local
/// principal；remote principal 必须始终携带 `Some`（允许为空集合）。
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
struct RemotePermissionGrant(u16);

impl RemotePermissionGrant {
    #[cfg(test)]
    const ALL: Self = Self((1 << 9) - 1);

    fn from_permissions(permissions: &[AuthorizationPermissionV1]) -> Self {
        let mut bits = 0_u16;
        for permission in permissions {
            bits |= permission_bit(*permission);
        }
        Self(bits)
    }

    const fn allows(self, permission: AuthorizationPermissionV1) -> bool {
        self.0 & permission_bit(permission) != 0
    }

    const fn approval_permissions(self) -> ApprovalPermissionGrant {
        match (
            self.allows(AuthorizationPermissionV1::ApprovalResolve),
            self.allows(AuthorizationPermissionV1::ApprovalRetry),
        ) {
            (false, false) => ApprovalPermissionGrant::None,
            (true, false) => ApprovalPermissionGrant::ResolveOnly,
            (false, true) => ApprovalPermissionGrant::RetryOnly,
            (true, true) => ApprovalPermissionGrant::ResolveAndRetry,
        }
    }
}

const fn permission_bit(permission: AuthorizationPermissionV1) -> u16 {
    1 << match permission {
        AuthorizationPermissionV1::CatalogRead => 0,
        AuthorizationPermissionV1::ConversationRead => 1,
        AuthorizationPermissionV1::ConversationStart => 2,
        AuthorizationPermissionV1::PromptSend => 3,
        AuthorizationPermissionV1::CommandCancel => 4,
        AuthorizationPermissionV1::ApprovalResolve => 5,
        AuthorizationPermissionV1::ApprovalRetry => 6,
        AuthorizationPermissionV1::MetadataWrite => 7,
        AuthorizationPermissionV1::RevokeSelf => 8,
    }
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

    /// Durable prompt admission 只能冻结 Store proof 产生的 exact ADC2 binding。
    /// local principal 与历史 test-only raw remote issuer 都不伪造该能力。
    pub(crate) fn remote_command_authorization_binding(
        &self,
    ) -> Option<RemoteCommandAuthorizationBinding> {
        self.remote_command_authorization.clone()
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

    /// Runtime business authorization 的唯一 permission gate。local principal 已由
    /// same-EUID transport issuer 认证，继续保持既有完整业务能力；remote principal
    /// 必须同时命中 Store proof 固化进 lease 的九项 allowlist。
    pub(crate) fn try_enter_runtime_permission(
        &self,
        permission: AuthorizationPermissionV1,
    ) -> Result<AuthorizationGuard, PrincipalAccessError> {
        if self
            .authorization
            .remote_permissions
            .is_some_and(|permissions| !permissions.allows(permission))
        {
            return Err(PrincipalAccessError::PermissionDenied);
        }
        self.authorization.try_enter()
    }

    /// 只允许 exact remote identity 发起自身撤销。target 完全来自 issuer 固化的
    /// device route/grant serial；local principal、缺 permission、零 route/serial 均在
    /// backend 前拒绝。Revoking 只为同一 exact self-revoke 的 durable retry 放行。
    pub(crate) fn try_enter_remote_self_revocation(
        &self,
    ) -> Result<RemoteSelfRevocationAdmission, PrincipalAccessError> {
        let (device, grant_serial) = self.remote_self_revocation_target()?;
        let authorization = self.authorization.try_enter_self_revocation()?;
        Ok(RemoteSelfRevocationAdmission {
            principal: self.clone(),
            device,
            grant_serial,
            authorization,
        })
    }

    /// Safety-task 登记前的只读校验。它不提升 lease；Fresh 若在真正 mutation
    /// admission 前被另一请求抢先推进到 Revoking，后续原子 CAS 仍会拒绝。
    pub(crate) fn ensure_remote_self_revocation(
        &self,
        allow_revoking_retry: bool,
    ) -> Result<(), PrincipalAccessError> {
        self.remote_self_revocation_target()?;
        self.authorization
            .ensure_self_revocation(allow_revoking_retry)
    }

    /// Safety task 已被 Core 同步登记后才调用的 mutation 线性化点。Fresh 只有
    /// 唯一 `Active -> Revoking` CAS 胜者；只有 durable ExactDuplicate 可复用
    /// 已 Revoking lease。target 始终从 authenticated principal 派生。
    pub(crate) async fn admit_remote_self_revocation(
        &self,
        allow_revoking_retry: bool,
    ) -> Result<(DeviceHandle, GrantSerial), PrincipalAccessError> {
        let target = self.remote_self_revocation_target()?;
        self.authorization
            .admit_self_revocation(allow_revoking_retry)
            .await?;
        Ok(target)
    }

    fn remote_self_revocation_target(
        &self,
    ) -> Result<(DeviceHandle, GrantSerial), PrincipalAccessError> {
        let (device_route, grant_serial) = match self.identity.as_ref() {
            PrincipalIdentity::Remote {
                device_route,
                grant_serial,
                ..
            } if *device_route != [0; 16] && *grant_serial != 0 => (*device_route, *grant_serial),
            PrincipalIdentity::Local { .. } | PrincipalIdentity::Remote { .. } => {
                return Err(PrincipalAccessError::PermissionDenied);
            }
        };
        let permissions = self
            .authorization
            .remote_permissions
            .ok_or(PrincipalAccessError::PermissionDenied)?;
        if !permissions.allows(AuthorizationPermissionV1::RevokeSelf) {
            return Err(PrincipalAccessError::PermissionDenied);
        }
        let device =
            canonical_device_handle(device_route).ok_or(PrincipalAccessError::PermissionDenied)?;
        Ok((device, GrantSerial::new(grant_serial)))
    }

    /// 只有 same-EUID control issuer 能签发本能力；普通本地 read principal 与
    /// remote principal 即使持有 approval permission 也不能执行 machine-wide admin。
    pub(crate) fn try_enter_local_administration(
        &self,
    ) -> Result<AuthorizationGuard, PrincipalAccessError> {
        if !self.is_local() || !self.authorization.local_administration {
            return Err(PrincipalAccessError::PermissionDenied);
        }
        self.authorization.try_enter()
    }

    pub(crate) fn may_receive_local_administration_stream(&self) -> bool {
        self.is_local()
            && self.authorization.local_administration
            && self
                .authorization
                .state
                .load(std::sync::atomic::Ordering::Acquire)
                == PRINCIPAL_ACTIVE
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

    pub(crate) fn is_revoking(&self) -> bool {
        self.authorization
            .state
            .load(std::sync::atomic::Ordering::Acquire)
            == PRINCIPAL_REVOKING
    }

    #[cfg(test)]
    pub(crate) fn is_active(&self) -> bool {
        self.authorization
            .state
            .load(std::sync::atomic::Ordering::Acquire)
            == PRINCIPAL_ACTIVE
    }

    #[cfg(test)]
    pub(crate) fn is_revoked(&self) -> bool {
        self.authorization
            .state
            .load(std::sync::atomic::Ordering::Acquire)
            == PRINCIPAL_REVOKED
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
    fn new(
        approval_permissions: ApprovalPermissionGrant,
        remote_permissions: Option<RemotePermissionGrant>,
        local_administration: bool,
    ) -> Self {
        Self {
            state: std::sync::atomic::AtomicU8::new(PRINCIPAL_ACTIVE),
            inflight: std::sync::atomic::AtomicUsize::new(0),
            quiesced: tokio::sync::Notify::new(),
            approval_permissions,
            remote_permissions,
            local_administration,
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

    fn try_enter_self_revocation(
        self: &Arc<Self>,
    ) -> Result<Option<AuthorizationGuard>, PrincipalAccessError> {
        use std::sync::atomic::Ordering;

        match self.state.load(Ordering::Acquire) {
            PRINCIPAL_ACTIVE => self.try_enter().map(Some),
            PRINCIPAL_REVOKING => Ok(None),
            PRINCIPAL_REVOKED => Err(PrincipalAccessError::Revoked),
            _ => Err(PrincipalAccessError::RegistryUnavailable),
        }
    }

    fn ensure_self_revocation(
        &self,
        allow_revoking_retry: bool,
    ) -> Result<(), PrincipalAccessError> {
        use std::sync::atomic::Ordering;

        match self.state.load(Ordering::Acquire) {
            PRINCIPAL_ACTIVE => Ok(()),
            PRINCIPAL_REVOKING if allow_revoking_retry => Ok(()),
            PRINCIPAL_REVOKING | PRINCIPAL_REVOKED => Err(PrincipalAccessError::Revoked),
            _ => Err(PrincipalAccessError::RegistryUnavailable),
        }
    }

    async fn admit_self_revocation(
        &self,
        allow_revoking_retry: bool,
    ) -> Result<(), PrincipalAccessError> {
        self.transition_to_revoking(allow_revoking_retry).await
    }

    #[allow(dead_code)] // 由 P4 durable revoke path 间接调用。
    async fn begin_revoke(&self) -> Result<(), PrincipalAccessError> {
        self.transition_to_revoking(true).await
    }

    async fn transition_to_revoking(
        &self,
        allow_revoking_retry: bool,
    ) -> Result<(), PrincipalAccessError> {
        use std::sync::atomic::Ordering;

        match self.state.compare_exchange(
            PRINCIPAL_ACTIVE,
            PRINCIPAL_REVOKING,
            Ordering::AcqRel,
            Ordering::Acquire,
        ) {
            Ok(PRINCIPAL_ACTIVE) => {}
            Err(PRINCIPAL_REVOKING) if allow_revoking_retry => {}
            Ok(_) => unreachable!("compare_exchange success must return Active"),
            Err(PRINCIPAL_REVOKING) | Err(PRINCIPAL_REVOKED) => {
                return Err(PrincipalAccessError::Revoked);
            }
            Err(_) => return Err(PrincipalAccessError::RegistryUnavailable),
        }
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
    leases: Mutex<HashMap<PrincipalIdentity, PrincipalLeaseRecord>>,
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
            None,
            false,
            None,
        )
    }

    /// 只供完成 same-EUID peer credential 验证的本地控制面签发。
    /// installation identity 只参与审计与幂等命名空间，不是认证凭据。
    pub(crate) fn issue_verified_local_control(
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
            ApprovalPermissionGrant::ResolveAndRetry,
            None,
            true,
            None,
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
            None,
            false,
            None,
        )
    }

    /// 只接受 Store-issued `ActiveRemoteIngressProof` 解出的完整字段。调用方不能
    /// 省略 trust domain、grant serial 或 permissions；相同完整 identity 的 lease
    /// 复用还会 exact 比较 permission bitset，防止 stale proof 静默升级/降级。
    pub(crate) fn issue_verified_remote(
        &self,
        binding: RemoteCommandAuthorizationBinding,
    ) -> Result<AuthenticatedPrincipal, PrincipalAccessError> {
        let machine_trust_domain = binding.machine_trust_domain();
        if machine_trust_domain != self.machine_trust_domain {
            return Err(PrincipalAccessError::PermissionDenied);
        }
        let remote_permissions = RemotePermissionGrant::from_permissions(binding.permissions());
        self.issue(
            PrincipalIdentity::Remote {
                machine_trust_domain,
                machine_route: *binding.machine_route().as_bytes(),
                device_route: *binding.device_route().as_bytes(),
                grant_serial: binding.grant_serial().value(),
                device_sign_fingerprint: binding.device_sign_fingerprint(),
            },
            remote_permissions.approval_permissions(),
            Some(remote_permissions),
            false,
            Some(binding),
        )
    }

    /// local durable revoke 用 canonical DeviceHandle + serial 找回 issuer registry 中
    /// 的 exact remote lease。lookup 不依赖 active connection，因此离线设备同样能先
    /// 进入 Revoking；不存在或非 canonical handle 返回 `None`，绝不近似匹配。
    pub(crate) fn remote_principal_for_revoke(
        &self,
        device: &DeviceHandle,
        grant_serial: GrantSerial,
    ) -> Result<Option<AuthenticatedPrincipal>, PrincipalAccessError> {
        let Some(device_route) = parse_canonical_device_handle(device) else {
            return Ok(None);
        };
        let leases = self
            .leases
            .lock()
            .map_err(|_| PrincipalAccessError::RegistryUnavailable)?;
        Ok(leases
            .iter()
            .find(|(identity, _)| {
                matches!(
                    identity,
                    PrincipalIdentity::Remote {
                        device_route: candidate_route,
                        grant_serial: candidate_serial,
                        ..
                    } if *candidate_route == device_route && *candidate_serial == grant_serial.0
                )
            })
            .map(|(identity, record)| AuthenticatedPrincipal {
                identity: Arc::new(identity.clone()),
                authorization: Arc::clone(&record.authorization),
                remote_command_authorization: record.latest_remote_command_authorization.clone(),
            }))
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
            Some(RemotePermissionGrant::ALL),
            false,
            None,
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
            Some(RemotePermissionGrant::ALL),
            false,
            None,
        )
    }

    fn issue(
        &self,
        identity: PrincipalIdentity,
        approval_permissions: ApprovalPermissionGrant,
        remote_permissions: Option<RemotePermissionGrant>,
        local_administration: bool,
        remote_command_authorization: Option<RemoteCommandAuthorizationBinding>,
    ) -> Result<AuthenticatedPrincipal, PrincipalAccessError> {
        let mut leases = self
            .leases
            .lock()
            .map_err(|_| PrincipalAccessError::RegistryUnavailable)?;
        let authorization = match leases.get_mut(&identity) {
            Some(record) => {
                if record.authorization.approval_permissions != approval_permissions
                    || record.authorization.remote_permissions != remote_permissions
                    || record.authorization.local_administration != local_administration
                {
                    return Err(PrincipalAccessError::PermissionConflict);
                }
                advance_remote_command_authorization(
                    &mut record.latest_remote_command_authorization,
                    remote_command_authorization.as_ref(),
                )?;
                Arc::clone(&record.authorization)
            }
            None => {
                if leases.len() >= self.lease_capacity {
                    return Err(PrincipalAccessError::RegistryFull);
                }
                let lease = Arc::new(AuthorizationLease::new(
                    approval_permissions,
                    remote_permissions,
                    local_administration,
                ));
                leases.insert(
                    identity.clone(),
                    PrincipalLeaseRecord {
                        authorization: Arc::clone(&lease),
                        latest_remote_command_authorization: remote_command_authorization.clone(),
                    },
                );
                lease
            }
        };
        Ok(AuthenticatedPrincipal {
            identity: Arc::new(identity),
            authorization,
            remote_command_authorization,
        })
    }
}

fn advance_remote_command_authorization(
    current: &mut Option<RemoteCommandAuthorizationBinding>,
    candidate: Option<&RemoteCommandAuthorizationBinding>,
) -> Result<(), PrincipalAccessError> {
    match (current.as_ref(), candidate) {
        (None, None) => Ok(()),
        (Some(installed), Some(candidate)) if installed == candidate => Ok(()),
        (Some(installed), Some(candidate))
            if candidate.key_directory_revision().value()
                > installed.key_directory_revision().value()
                && candidate.authorization_hash() == installed.authorization_hash()
                && candidate.command_key_epoch() >= installed.command_key_epoch() =>
        {
            *current = Some(candidate.clone());
            Ok(())
        }
        (None, Some(_)) | (Some(_), None) | (Some(_), Some(_)) => {
            Err(PrincipalAccessError::PermissionConflict)
        }
    }
}

fn parse_canonical_device_handle(handle: &DeviceHandle) -> Option<[u8; 16]> {
    let encoded = handle.as_str().strip_prefix(DEVICE_HANDLE_PREFIX)?;
    if encoded.len() != 32 {
        return None;
    }
    let nibble = |byte: u8| match byte {
        b'0'..=b'9' => Some(byte - b'0'),
        b'a'..=b'f' => Some(byte - b'a' + 10),
        _ => None,
    };
    let encoded = encoded.as_bytes();
    let mut route = [0_u8; 16];
    for (index, value) in route.iter_mut().enumerate() {
        let offset = index * 2;
        *value = (nibble(encoded[offset])? << 4) | nibble(encoded[offset + 1])?;
    }
    (route != [0; 16]).then_some(route)
}

fn canonical_device_handle(device_route: [u8; 16]) -> Option<DeviceHandle> {
    if device_route == [0; 16] {
        return None;
    }
    const HEX: &[u8; 16] = b"0123456789abcdef";
    let mut value = String::with_capacity(DEVICE_HANDLE_PREFIX.len() + 32);
    value.push_str(DEVICE_HANDLE_PREFIX);
    for byte in device_route {
        value.push(char::from(HEX[usize::from(byte >> 4)]));
        value.push(char::from(HEX[usize::from(byte & 0x0f)]));
    }
    Some(DeviceHandle::new(value))
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
    pub(crate) const fn from_test_bytes(bytes: [u8; 16]) -> Self {
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
    framing_profile: ConnectionFramingProfile,
}

impl ConnectionSink {
    #[must_use]
    pub fn new(sender: mpsc::Sender<ConnectionWrite>) -> Self {
        Self {
            sender,
            framing_profile: ConnectionFramingProfile::JsonRuntime,
        }
    }

    /// 为只理解 Runtime JSON 的 local UDS 保留默认值；MachineLink 必须显式安装
    /// compact transfer capability，不能从 principal 或 payload magic 推断 transport。
    #[must_use]
    pub(crate) fn with_framing_profile(mut self, profile: ConnectionFramingProfile) -> Self {
        self.framing_profile = profile;
        self
    }
}

/// connection transport 能力，而不是业务或 authorization state。compact profile
/// 仍接受普通 Runtime JSON，只把 oversized Reply/Stream transfer 改走 ADRT1 carrier。
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum ConnectionFramingProfile {
    JsonRuntime,
    CompactTransfer,
}

impl ConnectionFramingProfile {
    pub(crate) const fn transfer_part_bytes(self) -> usize {
        match self {
            Self::JsonRuntime => MAX_JSON_PART_BYTES,
            Self::CompactTransfer => MAX_PART_BYTES,
        }
    }

    const fn accepts(self, kind: EncodedRuntimeFrameKind) -> bool {
        match (self, kind) {
            (_, EncodedRuntimeFrameKind::JsonRuntime)
            | (Self::CompactTransfer, EncodedRuntimeFrameKind::CompactTransfer) => true,
            (Self::JsonRuntime, EncodedRuntimeFrameKind::CompactTransfer) => false,
        }
    }
}

/// typed encoded frame kind。transport dispatch 不检查 magic；只有专用 carrier
/// constructor 能构造 `CompactTransfer`。
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum EncodedRuntimeFrameKind {
    JsonRuntime,
    CompactTransfer,
}

/// transport 的单次写入工作项。丢弃而不 ACK 会关闭当前 Runtime connection；
/// 只有 `acknowledge` 才释放 Core 的 frame/byte budget。
pub struct ConnectionWrite {
    bytes: Arc<[u8]>,
    kind: EncodedRuntimeFrameKind,
    stream_binding: Option<super::store::StreamBindingPermit>,
    acknowledged: Option<oneshot::Sender<()>>,
}

impl ConnectionWrite {
    #[must_use]
    pub fn bytes(&self) -> &[u8] {
        &self.bytes
    }

    #[must_use]
    pub(crate) fn kind(&self) -> EncodedRuntimeFrameKind {
        self.kind
    }

    /// daemon-private publication binding metadata；transport 不得从 Runtime JSON
    /// 重建这些轴，也不得把它序列化进本地 IPC。
    #[must_use]
    pub(crate) fn stream_binding(&self) -> Option<super::store::StreamBindingPermit> {
        self.stream_binding.clone()
    }

    /// 返回可与 `cancelled` 的可变借用并行使用的共享 encoded frame。
    #[must_use]
    pub fn shared_bytes(&self) -> Arc<[u8]> {
        self.bytes.clone()
    }

    /// 等待 Core 侧 ACK receiver 被 drop。transport 应把这个 future 与实际
    /// write+flush 竞争；取消获胜时关闭当前连接且不得 ACK。
    pub async fn cancelled(&mut self) {
        if let Some(acknowledged) = self.acknowledged.as_mut() {
            acknowledged.closed().await;
        }
    }

    #[cfg(test)]
    pub(crate) fn for_transport_test(bytes: impl Into<Arc<[u8]>>) -> (Self, oneshot::Receiver<()>) {
        let (acknowledged, acknowledgement) = oneshot::channel();
        (
            Self {
                bytes: bytes.into(),
                kind: EncodedRuntimeFrameKind::JsonRuntime,
                stream_binding: None,
                acknowledged: Some(acknowledged),
            },
            acknowledgement,
        )
    }

    #[cfg(test)]
    pub(crate) fn for_transport_test_with_stream_binding(
        bytes: impl Into<Arc<[u8]>>,
        permit: super::store::StreamBindingPermit,
    ) -> (Self, oneshot::Receiver<()>) {
        let (acknowledged, acknowledgement) = oneshot::channel();
        (
            Self {
                bytes: bytes.into(),
                kind: EncodedRuntimeFrameKind::JsonRuntime,
                stream_binding: Some(permit),
                acknowledged: Some(acknowledged),
            },
            acknowledgement,
        )
    }

    #[cfg(test)]
    pub(crate) fn for_compact_transfer_test(
        carrier: &RuntimeTransferCarrierV1,
    ) -> Result<(Self, oneshot::Receiver<()>), ConnectionError> {
        let frame = EncodedRuntimeFrame::from_transfer_carrier(carrier)?;
        let (acknowledged, acknowledgement) = oneshot::channel();
        Ok((
            Self {
                bytes: frame.bytes,
                kind: frame.kind,
                stream_binding: frame.stream_binding,
                acknowledged: Some(acknowledged),
            },
            acknowledgement,
        ))
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
            .field("kind", &self.kind)
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
    kind: EncodedRuntimeFrameKind,
    stream_binding: Option<super::store::StreamBindingPermit>,
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
            kind: EncodedRuntimeFrameKind::JsonRuntime,
            stream_binding: None,
        })
    }

    pub(crate) fn from_transfer_carrier(
        carrier: &RuntimeTransferCarrierV1,
    ) -> Result<Self, ConnectionError> {
        let bytes = carrier.encode().map_err(|error| match error {
            RuntimeTransferCarrierError::TooLarge => ConnectionError::FrameTooLarge,
            RuntimeTransferCarrierError::Invalid
            | RuntimeTransferCarrierError::Version
            | RuntimeTransferCarrierError::Transfer(_) => ConnectionError::Encode,
        })?;
        Ok(Self {
            bytes: Arc::from(bytes),
            kind: EncodedRuntimeFrameKind::CompactTransfer,
            stream_binding: None,
        })
    }

    #[must_use]
    pub(crate) fn with_stream_binding(mut self, permit: super::store::StreamBindingPermit) -> Self {
        self.stream_binding = Some(permit);
        self
    }

    #[cfg(test)]
    const fn kind(&self) -> EncodedRuntimeFrameKind {
        self.kind
    }

    #[cfg(test)]
    #[must_use]
    pub fn from_bytes(bytes: impl Into<Arc<[u8]>>) -> Self {
        Self {
            bytes: bytes.into(),
            kind: EncodedRuntimeFrameKind::JsonRuntime,
            stream_binding: None,
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
    framing_profile: ConnectionFramingProfile,
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
        let ConnectionSink {
            sender: sink_sender,
            framing_profile,
        } = sink;
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
                let transport_result = if sink_sender
                    .send(ConnectionWrite {
                        bytes: queued.frame.bytes.clone(),
                        kind: queued.frame.kind,
                        stream_binding: queued.frame.stream_binding.clone(),
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
            framing_profile,
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

    pub(crate) fn framing_profile(
        &self,
        id: ConnectionId,
    ) -> Result<ConnectionFramingProfile, ConnectionError> {
        self.entries
            .lock()
            .map_err(|_| ConnectionError::RegistryPoisoned)?
            .get(&id)
            .map(|entry| entry.framing_profile)
            .ok_or(ConnectionError::NotFound)
    }

    /// Durable local revoke 在 lease 进入 Revoked 后用 exact authorization identity
    /// 取得应切断的 connection 快照。只返回 opaque IDs；真正 subscription/job/writer
    /// 清理由 RuntimeCore 复用标准 disconnect 顺序完成。
    pub(crate) fn connections_for_authorization(
        &self,
        key: &PrincipalAuthorizationKey,
    ) -> Result<Vec<ConnectionId>, ConnectionError> {
        Ok(self
            .entries
            .lock()
            .map_err(|_| ConnectionError::RegistryPoisoned)?
            .iter()
            .filter_map(|(id, entry)| entry.principal.authorization_key().eq(key).then_some(*id))
            .collect())
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
        if !entry.framing_profile.accepts(frame.kind) {
            return Err(ConnectionError::FramingProfileMismatch);
        }
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

    /// 向当前 local-control principals 广播一个已编码的管理 stream item。
    ///
    /// 快照只保留 opaque connection ID；真正入队仍逐连接复核 incarnation/budget。
    /// 单个慢 writer 会由 `try_enqueue` fail-close，但不会阻断其他本机管理员或
    /// durable pairing 的后续 `listPendingPairings` 读回。
    pub(crate) fn try_enqueue_local_administration(
        &self,
        frame: EncodedRuntimeFrame,
    ) -> Result<usize, ConnectionError> {
        let recipients = self
            .entries
            .lock()
            .map_err(|_| ConnectionError::RegistryPoisoned)?
            .iter()
            .filter_map(|(id, entry)| {
                entry
                    .principal
                    .may_receive_local_administration_stream()
                    .then_some(*id)
            })
            .collect::<Vec<_>>();
        let mut delivered = 0_usize;
        for recipient in recipients {
            match self.try_enqueue(recipient, frame.clone()) {
                Ok(()) => delivered += 1,
                Err(
                    ConnectionError::NotFound
                    | ConnectionError::Lagged
                    | ConnectionError::WriterTaskFailed,
                ) => {}
                Err(error) => return Err(error),
            }
        }
        Ok(delivered)
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
        let (
            incarnation,
            writer,
            byte_budget,
            frame_budget,
            paced_reservation_slot,
            framing_profile,
        ) = {
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
                entry.framing_profile,
            )
        };
        if !framing_profile.accepts(frame.kind) {
            return Err(ConnectionError::FramingProfileMismatch);
        }
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
    #[error("encoded Runtime frame is unsupported by the connection framing profile")]
    FramingProfileMismatch,
}

#[cfg(test)]
#[path = "connection/tests.rs"]
mod tests;
