use super::*;

impl RuntimeStoreHandle {
    /// 只接受 typed Item/Error；在进入 worker queue 前立即 canonicalize 并释放原始
    /// AgentItem，lane budget 因而按真实 retained bytes 计费。
    pub async fn append_execution_event(
        &self,
        input: super::super::AppendExecutionEvent,
    ) -> Result<super::super::AppendExecutionEventOutcome, RuntimeStoreError> {
        ensure_running(&self.lifecycle)?;
        // 威胁场景：多个连接同时提交最大 Item 时，lane admission 前的 canonicalization
        // 可能并发分配多份 64 MiB scratch。独立单许可只约束这段 Store 内构造窗口；
        // canonical bytes 落地后再按真实 retained capacity 进入 normal lane。
        let build_permit = self
            .execution_event_build_permit
            .clone()
            .try_acquire_owned()
            .map_err(|error| match error {
                tokio::sync::TryAcquireError::NoPermits => RuntimeStoreError::WorkerBusy {
                    lane: RuntimeStoreLane::Normal,
                },
                tokio::sync::TryAcquireError::Closed => RuntimeStoreError::WorkerStopped,
            })?;
        let input = PreparedExecutionEvent::from_input(input)?;
        let charge = memory_charge(size_of::<NormalCommand>(), &[input.retained_capacity()])?;
        let memory_permit = self
            .normal_budget
            .clone()
            .try_acquire_many_owned(charge)
            .map_err(|error| match error {
                tokio::sync::TryAcquireError::NoPermits => RuntimeStoreError::WorkerBusy {
                    lane: RuntimeStoreLane::Normal,
                },
                tokio::sync::TryAcquireError::Closed => RuntimeStoreError::WorkerStopped,
            })?;
        drop(build_permit);
        let (reply, result) = oneshot::channel();
        self.normal_tx
            .try_send(Queued {
                command: NormalCommand::AppendExecutionEvent { input, reply },
                memory_permit,
            })
            .map_err(|error| map_try_send(error, RuntimeStoreLane::Normal))?;
        result.await.map_err(|_| RuntimeStoreError::WorkerStopped)?
    }
}

#[cfg(test)]
mod tests {
    use std::fs;
    use std::sync::atomic::{AtomicU64, Ordering};

    use agentdeck_protocol::runtime::identity::{EntityId, ItemId};
    use agentdeck_protocol::{AgentItem, AgentItemMeta, AgentKind};
    use rusqlite::{Connection, OpenFlags, params};

    use crate::runtime::model::{ConversationDescriptor, IdempotencyOwner};
    use crate::runtime::store::{
        AppendExecutionEvent, AppendExecutionEventOutcome, RuntimeId, RuntimeIdKind,
    };
    use crate::security::{MemoryKeyStore, load_or_create_storage_kek};

    use super::*;

    static NEXT_TEMP_ID: AtomicU64 = AtomicU64::new(1);

    struct TestRoot(PathBuf);

    impl TestRoot {
        fn new() -> Self {
            let sequence = NEXT_TEMP_ID.fetch_add(1, Ordering::Relaxed);
            let path = std::env::temp_dir().join(format!(
                "agentdeckd-execution-event-build-gate-{}-{sequence}",
                std::process::id()
            ));
            let _ = fs::remove_dir_all(&path);
            fs::create_dir(&path).expect("create isolated execution-event root");
            #[cfg(unix)]
            {
                use std::os::unix::fs::PermissionsExt;
                fs::set_permissions(&path, fs::Permissions::from_mode(0o700))
                    .expect("secure execution-event root");
            }
            Self(path)
        }

        fn database(&self) -> PathBuf {
            self.0.join("runtime.db")
        }
    }

    impl Drop for TestRoot {
        fn drop(&mut self) {
            let _ = fs::remove_dir_all(&self.0);
        }
    }

    fn runtime_id(kind: RuntimeIdKind, seed: u8) -> RuntimeId {
        RuntimeId::from_bytes(kind, [seed; 16]).expect("non-zero runtime id")
    }

    fn event_state(database: &Path, event_id: RuntimeId) -> (i64, i64) {
        let connection = Connection::open_with_flags(database, OpenFlags::SQLITE_OPEN_READ_ONLY)
            .expect("open read-only runtime database");
        let event_count = connection
            .query_row(
                "SELECT COUNT(*) FROM event_journal WHERE event_id = ?1",
                params![&event_id.as_bytes()[..]],
                |row| row.get(0),
            )
            .expect("read execution event count");
        let event_high_water = connection
            .query_row(
                "SELECT CAST(event_high_water AS INTEGER) FROM conversations",
                [],
                |row| row.get(0),
            )
            .expect("read conversation event high-water");
        (event_count, event_high_water)
    }

    #[tokio::test]
    async fn execution_event_build_gate_returns_worker_busy_without_consuming_identity() {
        // 威胁场景：一个最大 Item 正在 canonicalize 时，第二个调用若排队或先落库，
        // 可绕过单份 scratch 上界并提前消耗 eventId/eventSeq。
        let root = TestRoot::new();
        let keys = MemoryKeyStore::new();
        let storage_kek = load_or_create_storage_kek(&keys, &root.0.join("key-state.db"))
            .expect("load test StorageKEK");
        let store = RuntimeStoreHandle::open(RuntimeStoreConfig::new(root.database()), storage_kek)
            .await
            .expect("open runtime store");
        let conversation_id = runtime_id(RuntimeIdKind::Conversation, 0x81);
        store
            .create_conversation(NewConversation {
                conversation_id,
                adapter_state_key: runtime_id(RuntimeIdKind::AdapterState, 0x82),
                descriptor: ConversationDescriptor {
                    agent_kind: AgentKind::Codex,
                    title: Some("execution event build gate".to_owned()),
                    cwd: root.0.clone(),
                },
            })
            .await
            .expect("create conversation");
        let command = match store
            .accept_command(AcceptCommand {
                conversation_id,
                owner: IdempotencyOwner::Local {
                    machine_trust_domain: [0x11; 32],
                    uid: 501,
                    client_installation_id: [0x22; 16],
                },
                idempotency_key: "execution-event-build-gate".to_owned(),
                payload: b"real prompt sample".to_vec(),
            })
            .await
            .expect("accept command")
        {
            AcceptOutcome::Accepted { command, .. } => command,
            AcceptOutcome::Replayed { .. } => panic!("fresh command cannot replay"),
        };
        let daemon_boot_id = runtime_id(RuntimeIdKind::DaemonBoot, 0x83);
        let execution_nonce = b"execution-event-build-gate-nonce".to_vec();
        let intent = match store
            .mark_started_with_event(StartCommand {
                conversation_id,
                command_id: command.command_id,
                daemon_boot_id,
                execution_nonce: execution_nonce.clone(),
            })
            .await
            .expect("start command")
        {
            StartOutcome::Started { intent, .. } => intent,
            StartOutcome::Replayed { .. } => panic!("fresh start cannot replay"),
        };
        store
            .persist_execution_fence(ExecutionFence {
                command_id: command.command_id,
                daemon_boot_id,
                execution_nonce: execution_nonce.clone(),
                process_group_id: 7_081,
                leader_pid: 7_081,
                leader_start_time: 8_081,
                payload: b"execution-event-build-gate-fence".to_vec(),
            })
            .await
            .expect("persist execution fence");
        store
            .authorize_execution_release(AuthorizeExecutionRelease {
                command_id: command.command_id,
                daemon_boot_id,
                execution_nonce,
            })
            .await
            .expect("authorize execution release");

        let event_id = runtime_id(RuntimeIdKind::Event, 0x85);
        let input = AppendExecutionEvent::item(
            conversation_id,
            command.command_id,
            intent.turn_id,
            event_id,
            ItemId::new("build-gate-item"),
            EntityId::new("build-gate-entity"),
            AgentItem::AssistantMessage {
                text: "real canonicalization sample".to_owned(),
                meta: AgentItemMeta::default(),
            },
        );
        let held = store
            .execution_event_build_permit
            .clone()
            .acquire_owned()
            .await
            .expect("hold the only build permit");

        let busy = tokio::time::timeout(
            Duration::from_millis(100),
            store.append_execution_event(input.clone()),
        )
        .await
        .expect("build gate must reject without waiting");
        assert!(matches!(
            busy,
            Err(RuntimeStoreError::WorkerBusy {
                lane: RuntimeStoreLane::Normal
            })
        ));
        assert_eq!(event_state(&root.database(), event_id), (0, 0));

        drop(held);
        assert!(matches!(
            store
                .append_execution_event(input)
                .await
                .expect("same input appends after permit release"),
            AppendExecutionEventOutcome::Appended { event }
                if event.event_id == event_id && event.event_seq == 1
        ));
        assert_eq!(event_state(&root.database(), event_id), (1, 1));

        store.shutdown().await.expect("shutdown runtime store");
    }
}
