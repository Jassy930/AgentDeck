//! 单一 blocking worker 独占 SQLite connection 的 async handle。

use std::collections::HashMap;
use std::fmt;
use std::path::{Path, PathBuf};
use std::sync::{Arc, Mutex, OnceLock, Weak};

use tokio::sync::{mpsc, oneshot};

use super::model::{
    CommitMachineLinkAuth, ConfirmDeviceAuth, DeviceTrustView, EnrollmentCodeSeed, FaultPoint,
    GrantCommit, InstallGrantRecord, MAX_CONTROL_BLOB_BYTES, MachineInventoryPage,
    MachineInventoryQuery, MachineLinkAuthCommit, MachineReadback, MachineReadbackQuery,
    MachineRecord, MachineTrustView, MaintenanceReport, PersistAck, PersistPublish,
    PersistRetirement, PersistRevocation, PersistSubscription, PersistUnsubscribe, PublishCommit,
    PurgeMachine, PurgeReadback, RegisterMachine, RelayV2StoreConfig, ReplayPage,
    ReplayPageRequest, RetirementCommit, RevocationCommit, StoreError, StoreSnapshot, StreamRecord,
    StreamRegistration, SubscriptionLease, UnsubscribeCommit, normalize_platform_root_alias,
};
use super::sqlite;
use agentdeck_protocol::relay_v2::{DeviceRouteId, MachineRouteId, RelayServerId};

// Publish command may carry a full 4 MiB frame. Keep the actor queue deliberately
// small and use non-waiting admission: the store owns at most four queued commands
// plus the command currently executing; callers retain rejected requests themselves.
const STORE_COMMAND_CAPACITY: usize = 4;

#[derive(Clone)]
pub struct RelayStoreHandle {
    tx: mpsc::Sender<StoreCommand>,
    authorization_ownership: Arc<AuthorizationOwnership>,
    relay_server_id: RelayServerId,
}

struct AuthorizationOwnership {
    claimed: Mutex<bool>,
}

struct StoreOpenLease;

fn claim_store_path(storage_path: &Path) -> Result<Arc<StoreOpenLease>, StoreError> {
    static OPEN_STORES: OnceLock<Mutex<HashMap<PathBuf, Weak<StoreOpenLease>>>> = OnceLock::new();
    let registry = OPEN_STORES.get_or_init(|| Mutex::new(HashMap::new()));
    let mut open_stores = registry.lock().map_err(|_| StoreError::WorkerUnavailable)?;
    open_stores.retain(|_, lease| lease.strong_count() > 0);
    if open_stores
        .get(storage_path)
        .and_then(Weak::upgrade)
        .is_some()
    {
        return Err(StoreError::StoreAlreadyOpen);
    }
    let lease = Arc::new(StoreOpenLease);
    open_stores.insert(storage_path.to_path_buf(), Arc::downgrade(&lease));
    Ok(lease)
}

pub(crate) struct AuthorizationOwner {
    ownership: Arc<AuthorizationOwnership>,
}

impl Drop for AuthorizationOwner {
    fn drop(&mut self) {
        if let Ok(mut claimed) = self.ownership.claimed.lock() {
            *claimed = false;
        }
    }
}

impl fmt::Debug for RelayStoreHandle {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("RelayStoreHandle")
            .finish_non_exhaustive()
    }
}

impl RelayStoreHandle {
    /// 启动专用 std blocking worker；只有 worker 完成 schema、migration、PRAGMA
    /// 与快照读回后，startup oneshot 才返回成功。
    pub async fn open(config: RelayV2StoreConfig) -> Result<Self, StoreError> {
        let ownership_path = normalize_platform_root_alias(&config.storage_path);
        let open_lease = claim_store_path(&ownership_path)?;
        let authorization_ownership = Arc::new(AuthorizationOwnership {
            claimed: Mutex::new(false),
        });
        let (tx, rx) = mpsc::channel(STORE_COMMAND_CAPACITY);
        let (ready_tx, ready_rx) = oneshot::channel();

        std::thread::Builder::new()
            .name("agentdeck-relay-v2-store".to_owned())
            .spawn(move || run(config, rx, ready_tx, open_lease))?;

        match ready_rx.await {
            Ok(Ok(relay_server_id)) => Ok(Self {
                tx,
                authorization_ownership,
                relay_server_id,
            }),
            Ok(Err(error)) => Err(error),
            Err(_) => Err(StoreError::WorkerStopped),
        }
    }

    /// Store ready gate 已从 worker 持有连接读回的权威 server identity；Core/handshake
    /// 可同步读取，不能信任客户端 Hello 自报或为每次 Pairing 额外排队 Inspect。
    pub fn relay_server_id(&self) -> RelayServerId {
        self.relay_server_id
    }

    pub async fn inspect(&self) -> Result<StoreSnapshot, StoreError> {
        self.dispatch(|reply| StoreCommand::Inspect { reply }).await
    }

    /// 从唯一 worker 持有的生产连接执行 readiness 探针。
    ///
    /// 探针与所有 Store 命令共享同一有界队列：队列满、worker 停止、schema/PRAGMA
    /// 漂移、磁盘低水位或无法取得短写事务时一律 fail-closed。
    pub async fn probe_readiness(&self) -> Result<(), StoreError> {
        self.dispatch(|reply| StoreCommand::ProbeReadiness { reply })
            .await
    }

    pub async fn machine_trust(
        &self,
        machine_route: MachineRouteId,
    ) -> Result<MachineTrustView, StoreError> {
        self.dispatch(|reply| StoreCommand::MachineTrust {
            machine_route,
            reply,
        })
        .await
    }

    pub async fn machine_inventory(
        &self,
        query: MachineInventoryQuery,
    ) -> Result<MachineInventoryPage, StoreError> {
        self.dispatch(|reply| StoreCommand::MachineInventory { query, reply })
            .await
    }

    pub async fn machine_readback(
        &self,
        query: MachineReadbackQuery,
    ) -> Result<MachineReadback, StoreError> {
        self.dispatch(|reply| StoreCommand::MachineReadback { query, reply })
            .await
    }

    pub async fn device_trust(
        &self,
        machine_route: MachineRouteId,
        device_route: DeviceRouteId,
    ) -> Result<DeviceTrustView, StoreError> {
        self.dispatch(|reply| StoreCommand::DeviceTrust {
            machine_route,
            device_route,
            reply,
        })
        .await
    }

    pub async fn commit_machine_link_auth(
        &self,
        request: CommitMachineLinkAuth,
    ) -> Result<MachineLinkAuthCommit, StoreError> {
        self.dispatch_trust(None, |reply| StoreCommand::CommitMachineLinkAuth {
            request,
            reply,
        })
        .await
    }

    pub async fn confirm_device_auth(&self, request: ConfirmDeviceAuth) -> Result<(), StoreError> {
        self.dispatch_trust(None, |reply| StoreCommand::ConfirmDeviceAuth {
            request,
            reply,
        })
        .await
    }

    pub(crate) async fn commit_machine_link_auth_authorized(
        &self,
        owner: &AuthorizationOwner,
        request: CommitMachineLinkAuth,
    ) -> Result<MachineLinkAuthCommit, StoreError> {
        self.dispatch_trust(Some(owner), |reply| StoreCommand::CommitMachineLinkAuth {
            request,
            reply,
        })
        .await
    }

    pub(crate) async fn confirm_device_auth_authorized(
        &self,
        owner: &AuthorizationOwner,
        request: ConfirmDeviceAuth,
    ) -> Result<(), StoreError> {
        self.dispatch_trust(Some(owner), |reply| StoreCommand::ConfirmDeviceAuth {
            request,
            reply,
        })
        .await
    }

    pub async fn seed_enrollment_code(
        &self,
        request: EnrollmentCodeSeed,
    ) -> Result<(), StoreError> {
        self.dispatch(|reply| StoreCommand::SeedEnrollmentCode { request, reply })
            .await
    }

    pub async fn register_machine(
        &self,
        request: RegisterMachine,
    ) -> Result<MachineRecord, StoreError> {
        self.register_machine_inner(None, request).await
    }

    pub(crate) async fn register_machine_authorized(
        &self,
        owner: &AuthorizationOwner,
        request: RegisterMachine,
    ) -> Result<MachineRecord, StoreError> {
        self.register_machine_inner(Some(owner), request).await
    }

    async fn register_machine_inner(
        &self,
        owner: Option<&AuthorizationOwner>,
        request: RegisterMachine,
    ) -> Result<MachineRecord, StoreError> {
        if request.response_blob.len() > MAX_CONTROL_BLOB_BYTES {
            return Err(StoreError::InvalidValue {
                field: "register_machine.response_blob",
                reason: "control blob exceeds 64 KiB",
            });
        }
        self.dispatch_trust(owner, |reply| StoreCommand::RegisterMachine {
            request: Box::new(request),
            reply,
        })
        .await
    }

    pub async fn install_grant(
        &self,
        request: InstallGrantRecord,
    ) -> Result<GrantCommit, StoreError> {
        self.install_grant_inner(None, request).await
    }

    pub(crate) async fn install_grant_authorized(
        &self,
        owner: &AuthorizationOwner,
        request: InstallGrantRecord,
    ) -> Result<GrantCommit, StoreError> {
        self.install_grant_inner(Some(owner), request).await
    }

    async fn install_grant_inner(
        &self,
        owner: Option<&AuthorizationOwner>,
        request: InstallGrantRecord,
    ) -> Result<GrantCommit, StoreError> {
        self.dispatch_trust(owner, |reply| StoreCommand::InstallGrant { request, reply })
            .await
    }

    pub async fn register_stream(
        &self,
        request: StreamRegistration,
    ) -> Result<StreamRecord, StoreError> {
        self.dispatch(|reply| StoreCommand::RegisterStream { request, reply })
            .await
    }

    pub async fn publish(&self, request: PersistPublish) -> Result<PublishCommit, StoreError> {
        request.validate_queue_payload()?;
        self.dispatch(|reply| StoreCommand::Publish { request, reply })
            .await
    }

    pub async fn subscribe(
        &self,
        request: PersistSubscription,
    ) -> Result<SubscriptionLease, StoreError> {
        self.dispatch(|reply| StoreCommand::Subscribe { request, reply })
            .await
    }

    pub async fn replay_page(&self, request: ReplayPageRequest) -> Result<ReplayPage, StoreError> {
        self.dispatch(|reply| StoreCommand::ReplayPage { request, reply })
            .await
    }

    pub async fn unsubscribe(
        &self,
        request: PersistUnsubscribe,
    ) -> Result<UnsubscribeCommit, StoreError> {
        self.dispatch(|reply| StoreCommand::Unsubscribe { request, reply })
            .await
    }

    pub async fn ack(&self, request: PersistAck) -> Result<(), StoreError> {
        self.dispatch(|reply| StoreCommand::Ack { request, reply })
            .await
    }

    pub async fn revoke(&self, request: PersistRevocation) -> Result<RevocationCommit, StoreError> {
        self.revoke_inner(None, request).await
    }

    pub(crate) async fn revoke_authorized(
        &self,
        owner: &AuthorizationOwner,
        request: PersistRevocation,
    ) -> Result<RevocationCommit, StoreError> {
        self.revoke_inner(Some(owner), request).await
    }

    async fn revoke_inner(
        &self,
        owner: Option<&AuthorizationOwner>,
        request: PersistRevocation,
    ) -> Result<RevocationCommit, StoreError> {
        if request.signed_revocation_blob.len() > MAX_CONTROL_BLOB_BYTES {
            return Err(StoreError::InvalidValue {
                field: "revocation.signed_blob",
                reason: "control blob exceeds 64 KiB",
            });
        }
        self.dispatch_trust(owner, |reply| StoreCommand::Revoke { request, reply })
            .await
    }

    pub(crate) async fn retire_machine_authorized(
        &self,
        owner: &AuthorizationOwner,
        request: PersistRetirement,
    ) -> Result<RetirementCommit, StoreError> {
        if request.retirement_terminal_blob.len() > super::model::MAX_TERMINAL_BLOB_BYTES {
            return Err(StoreError::InvalidValue {
                field: "retirement.terminal_blob",
                reason: "terminal blob exceeds 4 KiB",
            });
        }
        self.dispatch_trust(Some(owner), |reply| StoreCommand::RetireMachine {
            request,
            reply,
        })
        .await
    }

    pub async fn purge_machine(&self, request: PurgeMachine) -> Result<PurgeReadback, StoreError> {
        self.purge_machine_inner(None, request).await
    }

    pub(crate) async fn purge_machine_authorized(
        &self,
        owner: &AuthorizationOwner,
        request: PurgeMachine,
    ) -> Result<PurgeReadback, StoreError> {
        self.purge_machine_inner(Some(owner), request).await
    }

    async fn purge_machine_inner(
        &self,
        owner: Option<&AuthorizationOwner>,
        request: PurgeMachine,
    ) -> Result<PurgeReadback, StoreError> {
        self.dispatch_trust(owner, |reply| StoreCommand::PurgeMachine { request, reply })
            .await
    }

    /// 执行一次确定性的物理清理事务。P2.6 的 server sweeper 负责周期调度；
    /// replay 也会先执行同一事务，保证逻辑过期后不再返回 ciphertext。
    pub async fn run_maintenance(&self) -> Result<MaintenanceReport, StoreError> {
        self.dispatch(|reply| StoreCommand::Maintenance { reply })
            .await
    }

    pub async fn shutdown(&self) -> Result<(), StoreError> {
        self.dispatch_trust(None, |reply| StoreCommand::Shutdown { reply })
            .await
    }

    pub(crate) fn claim_authorization_owner(&self) -> Result<AuthorizationOwner, StoreError> {
        let mut claimed = self
            .authorization_ownership
            .claimed
            .lock()
            .map_err(|_| StoreError::WorkerUnavailable)?;
        if *claimed {
            return Err(StoreError::AuthorizationOwned);
        }
        *claimed = true;
        drop(claimed);
        Ok(AuthorizationOwner {
            ownership: self.authorization_ownership.clone(),
        })
    }

    async fn dispatch_trust<T>(
        &self,
        owner: Option<&AuthorizationOwner>,
        command: impl FnOnce(oneshot::Sender<Result<T, StoreError>>) -> StoreCommand,
    ) -> Result<T, StoreError> {
        let response = {
            let claimed = self
                .authorization_ownership
                .claimed
                .lock()
                .map_err(|_| StoreError::WorkerUnavailable)?;
            let authorized = match owner {
                Some(owner) => {
                    Arc::ptr_eq(&self.authorization_ownership, &owner.ownership) && *claimed
                }
                None => !*claimed,
            };
            if !authorized {
                return Err(StoreError::AuthorizationOwned);
            }
            let (reply, response) = oneshot::channel();
            match self.tx.try_send(command(reply)) {
                Ok(()) => {}
                Err(mpsc::error::TrySendError::Full(_)) => return Err(StoreError::WorkerBusy),
                Err(mpsc::error::TrySendError::Closed(_)) => {
                    return Err(StoreError::WorkerUnavailable);
                }
            }
            response
        };
        response.await.map_err(|_| StoreError::WorkerStopped)?
    }

    async fn dispatch<T>(
        &self,
        command: impl FnOnce(oneshot::Sender<Result<T, StoreError>>) -> StoreCommand,
    ) -> Result<T, StoreError> {
        let (reply, response) = oneshot::channel();
        match self.tx.try_send(command(reply)) {
            Ok(()) => {}
            Err(mpsc::error::TrySendError::Full(_)) => return Err(StoreError::WorkerBusy),
            Err(mpsc::error::TrySendError::Closed(_)) => {
                return Err(StoreError::WorkerUnavailable);
            }
        }
        response.await.map_err(|_| StoreError::WorkerStopped)?
    }
}

enum StoreCommand {
    Inspect {
        reply: oneshot::Sender<Result<StoreSnapshot, StoreError>>,
    },
    ProbeReadiness {
        reply: oneshot::Sender<Result<(), StoreError>>,
    },
    MachineTrust {
        machine_route: MachineRouteId,
        reply: oneshot::Sender<Result<MachineTrustView, StoreError>>,
    },
    MachineInventory {
        query: MachineInventoryQuery,
        reply: oneshot::Sender<Result<MachineInventoryPage, StoreError>>,
    },
    MachineReadback {
        query: MachineReadbackQuery,
        reply: oneshot::Sender<Result<MachineReadback, StoreError>>,
    },
    DeviceTrust {
        machine_route: MachineRouteId,
        device_route: DeviceRouteId,
        reply: oneshot::Sender<Result<DeviceTrustView, StoreError>>,
    },
    CommitMachineLinkAuth {
        request: CommitMachineLinkAuth,
        reply: oneshot::Sender<Result<MachineLinkAuthCommit, StoreError>>,
    },
    ConfirmDeviceAuth {
        request: ConfirmDeviceAuth,
        reply: oneshot::Sender<Result<(), StoreError>>,
    },
    SeedEnrollmentCode {
        request: EnrollmentCodeSeed,
        reply: oneshot::Sender<Result<(), StoreError>>,
    },
    RegisterMachine {
        request: Box<RegisterMachine>,
        reply: oneshot::Sender<Result<MachineRecord, StoreError>>,
    },
    InstallGrant {
        request: InstallGrantRecord,
        reply: oneshot::Sender<Result<GrantCommit, StoreError>>,
    },
    RegisterStream {
        request: StreamRegistration,
        reply: oneshot::Sender<Result<StreamRecord, StoreError>>,
    },
    Publish {
        request: PersistPublish,
        reply: oneshot::Sender<Result<PublishCommit, StoreError>>,
    },
    Subscribe {
        request: PersistSubscription,
        reply: oneshot::Sender<Result<SubscriptionLease, StoreError>>,
    },
    ReplayPage {
        request: ReplayPageRequest,
        reply: oneshot::Sender<Result<ReplayPage, StoreError>>,
    },
    Unsubscribe {
        request: PersistUnsubscribe,
        reply: oneshot::Sender<Result<UnsubscribeCommit, StoreError>>,
    },
    Ack {
        request: PersistAck,
        reply: oneshot::Sender<Result<(), StoreError>>,
    },
    Revoke {
        request: PersistRevocation,
        reply: oneshot::Sender<Result<RevocationCommit, StoreError>>,
    },
    RetireMachine {
        request: PersistRetirement,
        reply: oneshot::Sender<Result<RetirementCommit, StoreError>>,
    },
    PurgeMachine {
        request: PurgeMachine,
        reply: oneshot::Sender<Result<PurgeReadback, StoreError>>,
    },
    Maintenance {
        reply: oneshot::Sender<Result<MaintenanceReport, StoreError>>,
    },
    Shutdown {
        reply: oneshot::Sender<Result<(), StoreError>>,
    },
}

fn run(
    config: RelayV2StoreConfig,
    mut rx: mpsc::Receiver<StoreCommand>,
    ready: oneshot::Sender<Result<RelayServerId, StoreError>>,
    open_lease: Arc<StoreOpenLease>,
) {
    let (mut conn, process_lock) = match sqlite::open(&config) {
        Ok(opened) => opened,
        Err(error) => {
            let _ = ready.send(Err(error));
            return;
        }
    };

    let relay_server_id = match sqlite::snapshot(&conn) {
        Ok(snapshot) => snapshot.relay_server_id,
        Err(error) => {
            let _ = ready.send(Err(error));
            return;
        }
    };
    if ready.send(Ok(relay_server_id)).is_err() {
        return;
    }

    while let Some(command) = rx.blocking_recv() {
        match command {
            StoreCommand::Inspect { reply } => {
                let _ = reply.send(sqlite::snapshot(&conn));
            }
            StoreCommand::ProbeReadiness { reply } => {
                let _ = reply.send(sqlite::probe_readiness(&mut conn, &config));
            }
            StoreCommand::MachineTrust {
                machine_route,
                reply,
            } => {
                let _ = reply.send(sqlite::machine_trust(&conn, machine_route));
            }
            StoreCommand::MachineInventory { query, reply } => {
                let _ = reply.send(sqlite::machine_inventory(&conn, query));
            }
            StoreCommand::MachineReadback { query, reply } => {
                let _ = reply.send(sqlite::machine_readback(&conn, query));
            }
            StoreCommand::DeviceTrust {
                machine_route,
                device_route,
                reply,
            } => {
                let _ = reply.send(sqlite::device_trust(&conn, machine_route, device_route));
            }
            StoreCommand::CommitMachineLinkAuth { request, reply } => {
                let _ = reply.send(sqlite::commit_machine_link_auth(
                    &mut conn, &config, request,
                ));
            }
            StoreCommand::ConfirmDeviceAuth { request, reply } => {
                let _ = reply.send(sqlite::confirm_device_auth(&conn, &config, request));
            }
            StoreCommand::SeedEnrollmentCode { request, reply } => {
                let _ = reply.send(sqlite::seed_enrollment_code(&mut conn, &config, request));
            }
            StoreCommand::RegisterMachine { request, reply } => {
                let _ = reply.send(sqlite::register_machine(&mut conn, &config, *request));
            }
            StoreCommand::InstallGrant { request, reply } => {
                let _ = reply.send(sqlite::install_grant(&mut conn, &config, request));
            }
            StoreCommand::RegisterStream { request, reply } => {
                let _ = reply.send(sqlite::register_stream(&mut conn, &config, request));
            }
            StoreCommand::Publish { request, reply } => {
                let _ = reply.send(sqlite::publish(&mut conn, &config, request));
            }
            StoreCommand::Subscribe { request, reply } => {
                let _ = reply.send(sqlite::subscribe(&mut conn, &config, request));
            }
            StoreCommand::ReplayPage { request, reply } => {
                let _ = reply.send(sqlite::replay_page(&mut conn, &config, request));
            }
            StoreCommand::Unsubscribe { request, reply } => {
                let _ = reply.send(sqlite::unsubscribe(&mut conn, &config, request));
            }
            StoreCommand::Ack { request, reply } => {
                let _ = reply.send(sqlite::ack(&mut conn, &config, request));
            }
            StoreCommand::Revoke { request, reply } => {
                let _ = reply.send(sqlite::revoke(&mut conn, &config, request));
            }
            StoreCommand::RetireMachine { request, reply } => {
                let _ = reply.send(sqlite::retire_machine(&mut conn, &config, request));
            }
            StoreCommand::PurgeMachine { request, reply } => {
                let _ = reply.send(sqlite::purge_machine(&mut conn, &config, request));
            }
            StoreCommand::Maintenance { reply } => {
                let _ = reply.send(sqlite::run_maintenance(&mut conn, &config));
            }
            StoreCommand::Shutdown { reply } => {
                drop(conn);
                // shutdown ACK 是“同一 DB 可立即由另一个进程打开”的 happens-before。
                // 不能依赖函数 return 后的局部析构，因为 oneshot 会先唤醒多线程 runtime。
                drop(process_lock);
                drop(open_lease);
                let _ = reply.send(Ok(()));
                let _ = config.fault_injector.check(FaultPoint::ShutdownAfterReply);
                return;
            }
        }
    }
}
