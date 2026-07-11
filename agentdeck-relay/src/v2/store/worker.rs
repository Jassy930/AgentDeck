//! 单一 blocking worker 独占 SQLite connection 的 async handle。

use std::fmt;

use tokio::sync::{mpsc, oneshot};

use super::model::{
    EnrollmentCodeSeed, GrantCommit, InstallGrantRecord, MAX_CONTROL_BLOB_BYTES, MachineRecord,
    MaintenanceReport, PersistAck, PersistPublish, PersistRevocation, PersistSubscription,
    PersistUnsubscribe, PublishCommit, PurgeMachine, PurgeReadback, RegisterMachine,
    RelayV2StoreConfig, ReplayPage, ReplayPageRequest, RevocationCommit, StoreError, StoreSnapshot,
    StreamRecord, StreamRegistration, SubscriptionLease, UnsubscribeCommit,
};
use super::sqlite;

// Publish command may carry a full 4 MiB frame. Keep the actor queue deliberately
// small and use non-waiting admission: the store owns at most four queued commands
// plus the command currently executing; callers retain rejected requests themselves.
const STORE_COMMAND_CAPACITY: usize = 4;

#[derive(Clone)]
pub struct RelayStoreHandle {
    tx: mpsc::Sender<StoreCommand>,
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
        let (tx, rx) = mpsc::channel(STORE_COMMAND_CAPACITY);
        let (ready_tx, ready_rx) = oneshot::channel();

        std::thread::Builder::new()
            .name("agentdeck-relay-v2-store".to_owned())
            .spawn(move || run(config, rx, ready_tx))?;

        match ready_rx.await {
            Ok(Ok(())) => Ok(Self { tx }),
            Ok(Err(error)) => Err(error),
            Err(_) => Err(StoreError::WorkerStopped),
        }
    }

    pub async fn inspect(&self) -> Result<StoreSnapshot, StoreError> {
        self.dispatch(|reply| StoreCommand::Inspect { reply }).await
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
        if request.response_blob.len() > MAX_CONTROL_BLOB_BYTES {
            return Err(StoreError::InvalidValue {
                field: "register_machine.response_blob",
                reason: "control blob exceeds 64 KiB",
            });
        }
        self.dispatch(|reply| StoreCommand::RegisterMachine {
            request: Box::new(request),
            reply,
        })
        .await
    }

    pub async fn install_grant(
        &self,
        request: InstallGrantRecord,
    ) -> Result<GrantCommit, StoreError> {
        self.dispatch(|reply| StoreCommand::InstallGrant { request, reply })
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
        if request.signed_revocation_blob.len() > MAX_CONTROL_BLOB_BYTES {
            return Err(StoreError::InvalidValue {
                field: "revocation.signed_blob",
                reason: "control blob exceeds 64 KiB",
            });
        }
        self.dispatch(|reply| StoreCommand::Revoke { request, reply })
            .await
    }

    pub async fn purge_machine(&self, request: PurgeMachine) -> Result<PurgeReadback, StoreError> {
        self.dispatch(|reply| StoreCommand::PurgeMachine { request, reply })
            .await
    }

    /// 执行一次确定性的物理清理事务。P2.6 的 server sweeper 负责周期调度；
    /// replay 也会先执行同一事务，保证逻辑过期后不再返回 ciphertext。
    pub async fn run_maintenance(&self) -> Result<MaintenanceReport, StoreError> {
        self.dispatch(|reply| StoreCommand::Maintenance { reply })
            .await
    }

    pub async fn shutdown(&self) -> Result<(), StoreError> {
        self.dispatch(|reply| StoreCommand::Shutdown { reply })
            .await
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
    ready: oneshot::Sender<Result<(), StoreError>>,
) {
    let mut conn = match sqlite::open(&config) {
        Ok(conn) => conn,
        Err(error) => {
            let _ = ready.send(Err(error));
            return;
        }
    };

    if ready.send(Ok(())).is_err() {
        return;
    }

    while let Some(command) = rx.blocking_recv() {
        match command {
            StoreCommand::Inspect { reply } => {
                let _ = reply.send(sqlite::snapshot(&conn));
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
            StoreCommand::PurgeMachine { request, reply } => {
                let _ = reply.send(sqlite::purge_machine(&mut conn, &config, request));
            }
            StoreCommand::Maintenance { reply } => {
                let _ = reply.send(sqlite::run_maintenance(&mut conn, &config));
            }
            StoreCommand::Shutdown { reply } => {
                drop(conn);
                let _ = reply.send(Ok(()));
                return;
            }
        }
    }
}
