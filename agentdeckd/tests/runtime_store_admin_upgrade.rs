use std::collections::HashSet;
use std::fs;
use std::os::unix::fs::{MetadataExt, PermissionsExt};
use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};

use agentdeck_protocol::runtime::{
    ArtifactSha256, IdempotencyKey, LocalOnlyAdministration, RuntimeFailure, StageUpgradeRequest,
};
use agentdeckd::runtime::model::{
    RuntimeCapacityObservation, RuntimeCapacityProbe, RuntimeCapacityProbeError,
};
use agentdeckd::runtime::store::{
    AcceptAdminUpgradeOutcome, AcceptCommand, AcceptOutcome, AdminUpgradeStatus,
    AdminUpgradeTerminalOutcome, AuthorizeExecutionRelease, ExecutionFence,
    FinalizeAdminUpgradeOutcome, IdempotencyOwner, NewConversation, RuntimeClock,
    RuntimeClockError, RuntimeCommitOperation, RuntimeId, RuntimeIdKind, RuntimeStoreConfig,
    RuntimeStoreError, RuntimeStoreFaultInjector, RuntimeStoreHandle, RuntimeStoreLane,
    RuntimeStoreOperation, StartCommand,
};
use agentdeckd::security::{MemoryKeyStore, load_or_create_storage_kek};
use rusqlite::Connection;

#[path = "support/runtime_configuration.rs"]
mod runtime_configuration;
#[path = "support/runtime_descriptor.rs"]
mod runtime_descriptor;
#[path = "support/store_admission.rs"]
mod store_admission;

struct TestRoot {
    path: PathBuf,
    _permit: store_admission::Permit,
}

impl TestRoot {
    fn new(label: &str) -> Self {
        let permit = store_admission::acquire();
        let path = std::env::temp_dir().join(format!(
            "agentdeck-admin-upgrade-{label}-{}",
            std::process::id()
        ));
        let _ = fs::remove_dir_all(&path);
        fs::create_dir(&path).expect("create admin upgrade test root");
        fs::set_permissions(&path, fs::Permissions::from_mode(0o700))
            .expect("secure admin upgrade test root");
        Self {
            path,
            _permit: permit,
        }
    }

    fn database(&self) -> PathBuf {
        self.path.join("runtime.db")
    }
}

impl Drop for TestRoot {
    fn drop(&mut self) {
        let _ = fs::remove_dir_all(&self.path);
    }
}

fn request(key: &str, target: &str, hash_byte: char) -> StageUpgradeRequest {
    StageUpgradeRequest::new(
        target.to_owned(),
        ArtifactSha256::new(hash_byte.to_string().repeat(64)).expect("canonical artifact hash"),
        IdempotencyKey::new(key),
        LocalOnlyAdministration::LocalOnly,
    )
    .expect("valid stage upgrade request")
}

fn runtime_id(kind: RuntimeIdKind, seed: u8) -> RuntimeId {
    RuntimeId::from_bytes(kind, [seed; 16]).expect("valid runtime id")
}

fn conversation(seed: u8) -> NewConversation {
    NewConversation {
        conversation_id: runtime_id(RuntimeIdKind::Conversation, seed),
        adapter_state_key: runtime_id(RuntimeIdKind::AdapterState, seed.wrapping_add(0x40)),
        descriptor: runtime_descriptor::descriptor(format!("admin-started-{seed}").as_bytes()),
    }
}

fn owner(seed: u8) -> IdempotencyOwner {
    IdempotencyOwner::Local {
        machine_trust_domain: [0x31; 32],
        uid: 501,
        client_installation_id: [seed; 16],
    }
}

#[derive(Debug, Eq, PartialEq)]
struct ArtifactEvidence {
    bytes: Vec<u8>,
    device: u64,
    inode: u64,
    length: u64,
    modified_seconds: i64,
    modified_nanoseconds: i64,
    changed_seconds: i64,
    changed_nanoseconds: i64,
}

fn artifact_evidence(database: &Path) -> Vec<Option<ArtifactEvidence>> {
    [
        database.to_path_buf(),
        PathBuf::from(format!("{}-wal", database.display())),
        PathBuf::from(format!("{}-shm", database.display())),
        PathBuf::from(format!("{}-journal", database.display())),
    ]
    .into_iter()
    .map(|path| match fs::read(&path) {
        Ok(bytes) => {
            let metadata = fs::metadata(&path).expect("inspect runtime artifact");
            Some(ArtifactEvidence {
                bytes,
                device: metadata.dev(),
                inode: metadata.ino(),
                length: metadata.len(),
                modified_seconds: metadata.mtime(),
                modified_nanoseconds: metadata.mtime_nsec(),
                changed_seconds: metadata.ctime(),
                changed_nanoseconds: metadata.ctime_nsec(),
            })
        }
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => None,
        Err(error) => panic!("read runtime artifact: {error}"),
    })
    .collect()
}

fn assert_no_artifact_sentinels(database: &Path, sentinels: &[&[u8]]) {
    for artifact in artifact_evidence(database).into_iter().flatten() {
        for sentinel in sentinels {
            assert!(
                !artifact
                    .bytes
                    .windows(sentinel.len())
                    .any(|window| window == *sentinel),
                "admin plaintext sentinel leaked into main/WAL/SHM/journal"
            );
        }
    }
}

struct FailOnce {
    target: RuntimeStoreOperation,
    fired: AtomicBool,
}

impl FailOnce {
    fn new(target: RuntimeStoreOperation) -> Self {
        Self {
            target,
            fired: AtomicBool::new(false),
        }
    }
}

impl RuntimeStoreFaultInjector for FailOnce {
    fn before_operation(&self, operation: RuntimeStoreOperation) -> Result<(), RuntimeStoreError> {
        if operation == self.target && !self.fired.swap(true, Ordering::AcqRel) {
            Err(RuntimeStoreError::WorkerStopped)
        } else {
            Ok(())
        }
    }
}

#[derive(Clone)]
struct RejectCapacityAfterFinalizeCommit {
    rejected: Arc<AtomicBool>,
}

impl RejectCapacityAfterFinalizeCommit {
    fn new() -> Self {
        Self {
            rejected: Arc::new(AtomicBool::new(false)),
        }
    }

    fn is_rejected(&self) -> bool {
        self.rejected.load(Ordering::Acquire)
    }
}

impl RuntimeStoreFaultInjector for RejectCapacityAfterFinalizeCommit {
    fn before_operation(&self, operation: RuntimeStoreOperation) -> Result<(), RuntimeStoreError> {
        if operation == RuntimeStoreOperation::FinalizeAdminUpgradeAfterCommit
            && !self.rejected.swap(true, Ordering::AcqRel)
        {
            Err(RuntimeStoreError::WorkerStopped)
        } else {
            Ok(())
        }
    }
}

impl RuntimeCapacityProbe for RejectCapacityAfterFinalizeCommit {
    fn observe(
        &self,
        _database: &Path,
    ) -> Result<RuntimeCapacityObservation, RuntimeCapacityProbeError> {
        if self.is_rejected() {
            return Ok(RuntimeCapacityObservation {
                main_bytes: 2 * 1024 * 1024 * 1024 + 1,
                wal_bytes: 0,
                shm_bytes: 0,
                filesystem_total_bytes: 20 * 1024 * 1024 * 1024,
                filesystem_available_bytes: 8 * 1024 * 1024 * 1024,
            });
        }
        Ok(RuntimeCapacityObservation {
            main_bytes: 8 * 1024 * 1024,
            wal_bytes: 2 * 1024 * 1024,
            shm_bytes: 32 * 1024,
            filesystem_total_bytes: 20 * 1024 * 1024 * 1024,
            filesystem_available_bytes: 4 * 1024 * 1024 * 1024,
        })
    }
}

#[derive(Clone)]
struct ManualClock(Arc<AtomicU64>);

impl ManualClock {
    fn new(now_ms: u64) -> Self {
        Self(Arc::new(AtomicU64::new(now_ms)))
    }

    fn set(&self, now_ms: u64) {
        self.0.store(now_ms, Ordering::Release);
    }
}

impl RuntimeClock for ManualClock {
    fn now_ms(&self) -> Result<u64, RuntimeClockError> {
        Ok(self.0.load(Ordering::Acquire))
    }
}

async fn create_started_fixture(
    store: &RuntimeStoreHandle,
    seed: u8,
    with_fence: bool,
    released: bool,
) {
    assert!(!released || with_fence);
    let created = store
        .create_conversation(conversation(seed))
        .await
        .expect("create active Started conversation");
    runtime_configuration::configure_codex_revision_one(store, created.conversation_id).await;
    let command = match store
        .accept_command(AcceptCommand {
            conversation_id: created.conversation_id,
            owner: owner(seed),
            idempotency_key: format!("active-started-{seed}"),
            expected_configuration_revision: 1,
            payload: vec![seed; 8],
        })
        .await
        .expect("accept active Started command")
    {
        AcceptOutcome::Accepted { command, .. } => command,
        AcceptOutcome::Replayed { .. } => panic!("fresh active Started command replayed"),
    };
    let daemon_boot_id = runtime_id(RuntimeIdKind::DaemonBoot, seed.wrapping_add(0x60));
    let execution_nonce = vec![seed; 16];
    store
        .mark_started_with_event(StartCommand {
            conversation_id: created.conversation_id,
            command_id: command.command_id,
            daemon_boot_id,
            execution_nonce: execution_nonce.clone(),
        })
        .await
        .expect("mark active Started command");
    if with_fence {
        store
            .persist_execution_fence(ExecutionFence {
                command_id: command.command_id,
                daemon_boot_id,
                execution_nonce: execution_nonce.clone(),
                process_group_id: i64::from(seed) + 10_000,
                leader_pid: i64::from(seed) + 10_000,
                leader_start_time: u64::from(seed) + 1,
                payload: vec![seed.wrapping_add(1); 32],
            })
            .await
            .expect("persist active Started fence");
    }
    if released {
        store
            .authorize_execution_release(AuthorizeExecutionRelease {
                command_id: command.command_id,
                daemon_boot_id,
                execution_nonce,
            })
            .await
            .expect("authorize active Started release");
    }
}

#[tokio::test]
async fn admin_upgrade_accept_replay_conflict_finalize_and_recovery_are_durable() {
    let root = TestRoot::new("lifecycle");
    let keys = MemoryKeyStore::new();
    let store = RuntimeStoreHandle::open(
        RuntimeStoreConfig::new(root.database()),
        load_or_create_storage_kek(&keys, &root.database()).expect("create admin upgrade KEK"),
    )
    .await
    .expect("open admin upgrade store");

    let accepted = store
        .accept_admin_upgrade(request("upgrade-key", "1.2.3", 'a'))
        .await
        .expect("accept fresh admin upgrade");
    let command = match accepted {
        AcceptAdminUpgradeOutcome::Accepted {
            command,
            active_started_commands,
        } => {
            assert_eq!(active_started_commands, 0);
            command
        }
        AcceptAdminUpgradeOutcome::Replayed { .. } => panic!("fresh request cannot replay"),
    };
    assert_eq!(command.status(), AdminUpgradeStatus::Pending);
    assert_eq!(command.target_version(), "1.2.3");
    assert!(command.terminal_failure().is_none());

    let replayed = store
        .accept_admin_upgrade(request("upgrade-key", "1.2.3", 'a'))
        .await
        .expect("replay exact pending upgrade");
    assert!(matches!(
        replayed,
        AcceptAdminUpgradeOutcome::Replayed {
            active_started_commands: 0,
            ..
        }
    ));
    assert!(matches!(
        store
            .accept_admin_upgrade(request("upgrade-key", "1.2.4", 'b'))
            .await,
        Err(RuntimeStoreError::IdempotencyConflict)
    ));

    let page = store
        .load_pending_admin_upgrades(None)
        .await
        .expect("load pending admin recovery page");
    assert_eq!(page.commands().len(), 1);
    assert!(page.next_cursor().is_none());

    let finalized = store
        .finalize_admin_upgrade(command, AdminUpgradeTerminalOutcome::Completed)
        .await
        .expect("finalize admin upgrade");
    assert!(matches!(
        finalized,
        FinalizeAdminUpgradeOutcome::Finalized { .. }
    ));
    assert!(
        store
            .load_pending_admin_upgrades(None)
            .await
            .expect("reload empty pending admin page")
            .commands()
            .is_empty()
    );
    store
        .shutdown()
        .await
        .expect("shutdown admin upgrade store");

    let reopened = RuntimeStoreHandle::open(
        RuntimeStoreConfig::new(root.database()),
        load_or_create_storage_kek(&keys, &root.database()).expect("reload admin upgrade KEK"),
    )
    .await
    .expect("reopen admin upgrade store");
    let replayed = reopened
        .accept_admin_upgrade(request("upgrade-key", "1.2.3", 'a'))
        .await
        .expect("replay completed upgrade after restart");
    let command = match replayed {
        AcceptAdminUpgradeOutcome::Replayed { command, .. } => command,
        AcceptAdminUpgradeOutcome::Accepted { .. } => panic!("durable upgrade must replay"),
    };
    assert_eq!(command.status(), AdminUpgradeStatus::Completed);
    assert!(command.terminal_failure().is_none());
    reopened.shutdown().await.expect("shutdown reopened store");
}

#[tokio::test]
async fn failed_admin_upgrade_replays_exact_failure_and_rejects_terminal_conflict() {
    let root = TestRoot::new("failed-replay");
    let keys = MemoryKeyStore::new();
    let store = RuntimeStoreHandle::open(
        RuntimeStoreConfig::new(root.database()),
        load_or_create_storage_kek(&keys, &root.database()).expect("create failure replay KEK"),
    )
    .await
    .expect("open failure replay store");
    let command = match store
        .accept_admin_upgrade(request("failed-key", "2.0.0", 'c'))
        .await
        .expect("accept failure fixture")
    {
        AcceptAdminUpgradeOutcome::Accepted { command, .. } => command,
        AcceptAdminUpgradeOutcome::Replayed { .. } => panic!("fresh failure fixture replayed"),
    };
    let retry = command.clone();
    let failure = RuntimeFailure::new("daemon.runtime.execution_failed", "upgrade switch failed")
        .with_diagnostic("upgrade-test");
    let finalized = store
        .finalize_admin_upgrade(
            command,
            AdminUpgradeTerminalOutcome::Failed {
                failure: failure.clone(),
            },
        )
        .await
        .expect("finalize failed admin upgrade");
    let finalized = match finalized {
        FinalizeAdminUpgradeOutcome::Finalized { command } => command,
        FinalizeAdminUpgradeOutcome::Replayed { .. } => panic!("fresh failure cannot replay"),
    };
    assert_eq!(finalized.status(), AdminUpgradeStatus::Failed);
    assert_eq!(finalized.terminal_failure(), Some(&failure));

    assert!(matches!(
        store
            .finalize_admin_upgrade(
                retry.clone(),
                AdminUpgradeTerminalOutcome::Failed {
                    failure: failure.clone(),
                },
            )
            .await
            .expect("exact failed finalization replay"),
        FinalizeAdminUpgradeOutcome::Replayed { .. }
    ));
    assert!(matches!(
        store
            .finalize_admin_upgrade(
                retry.clone(),
                AdminUpgradeTerminalOutcome::Failed {
                    failure: RuntimeFailure::new(
                        "daemon.runtime.different_failure",
                        "different terminal failure",
                    )
                    .with_diagnostic("different-diagnostic"),
                },
            )
            .await,
        Err(RuntimeStoreError::TerminalConflict)
    ));
    assert!(matches!(
        store
            .finalize_admin_upgrade(retry, AdminUpgradeTerminalOutcome::Completed)
            .await,
        Err(RuntimeStoreError::TerminalConflict)
    ));
    let replayed = store
        .accept_admin_upgrade(request("failed-key", "2.0.0", 'c'))
        .await
        .expect("replay failed command");
    let replayed = match replayed {
        AcceptAdminUpgradeOutcome::Replayed { command, .. } => command,
        AcceptAdminUpgradeOutcome::Accepted { .. } => panic!("failed row must replay"),
    };
    assert_eq!(replayed.terminal_failure(), Some(&failure));
    assert_eq!(
        store
            .query_admin_upgrade(request("failed-key", "2.0.0", 'c'))
            .await
            .expect("query failed command")
            .expect("failed command exists")
            .terminal_failure(),
        Some(&failure)
    );
    assert_eq!(store.active_started_command_count().await.unwrap(), 0);
    store
        .shutdown()
        .await
        .expect("shutdown failure replay store");
}

#[tokio::test]
async fn admin_upgrade_accept_before_and_after_commit_have_exact_retry_semantics() {
    for (label, operation, committed) in [
        (
            "accept-before-commit",
            RuntimeStoreOperation::AcceptAdminUpgradeBeforeCommit,
            false,
        ),
        (
            "accept-after-commit",
            RuntimeStoreOperation::AcceptAdminUpgradeAfterCommit,
            true,
        ),
    ] {
        let root = TestRoot::new(label);
        let keys = MemoryKeyStore::new();
        let store = RuntimeStoreHandle::open(
            RuntimeStoreConfig::new(root.database())
                .with_fault_injector(Arc::new(FailOnce::new(operation))),
            load_or_create_storage_kek(&keys, &root.database()).expect("create accept fault KEK"),
        )
        .await
        .expect("open accept fault store");
        let first = store
            .accept_admin_upgrade(request(label, "3.0.0", 'd'))
            .await
            .expect_err("injected accept fault must surface");
        if committed {
            assert!(matches!(
                first,
                RuntimeStoreError::CommitOutcomeUnknown {
                    operation: RuntimeCommitOperation::AcceptAdminUpgrade
                }
            ));
        } else {
            assert!(matches!(first, RuntimeStoreError::WorkerStopped));
        }
        let retry = store
            .accept_admin_upgrade(request(label, "3.0.0", 'd'))
            .await
            .expect("retry exact accept after injected fault");
        assert_eq!(
            matches!(retry, AcceptAdminUpgradeOutcome::Replayed { .. }),
            committed,
            "after-COMMIT must replay; before-COMMIT must accept fresh"
        );
        store.shutdown().await.expect("shutdown accept fault store");
    }
}

#[tokio::test]
async fn admin_upgrade_finalize_before_and_after_commit_have_exact_retry_semantics() {
    for (label, operation, committed) in [
        (
            "finalize-before-commit",
            RuntimeStoreOperation::FinalizeAdminUpgradeBeforeCommit,
            false,
        ),
        (
            "finalize-after-commit",
            RuntimeStoreOperation::FinalizeAdminUpgradeAfterCommit,
            true,
        ),
    ] {
        let root = TestRoot::new(label);
        let keys = MemoryKeyStore::new();
        let store = RuntimeStoreHandle::open(
            RuntimeStoreConfig::new(root.database())
                .with_fault_injector(Arc::new(FailOnce::new(operation))),
            load_or_create_storage_kek(&keys, &root.database()).expect("create finalize fault KEK"),
        )
        .await
        .expect("open finalize fault store");
        let command = match store
            .accept_admin_upgrade(request(label, "4.0.0", 'e'))
            .await
            .expect("accept finalize fault fixture")
        {
            AcceptAdminUpgradeOutcome::Accepted { command, .. } => command,
            AcceptAdminUpgradeOutcome::Replayed { .. } => panic!("fresh fixture replayed"),
        };
        let first = store
            .finalize_admin_upgrade(command.clone(), AdminUpgradeTerminalOutcome::Completed)
            .await
            .expect_err("injected finalize fault must surface");
        if committed {
            assert!(matches!(
                first,
                RuntimeStoreError::CommitOutcomeUnknown {
                    operation: RuntimeCommitOperation::FinalizeAdminUpgrade
                }
            ));
        } else {
            assert!(matches!(first, RuntimeStoreError::WorkerStopped));
        }
        let retry = store
            .finalize_admin_upgrade(command, AdminUpgradeTerminalOutcome::Completed)
            .await
            .expect("retry exact finalize after injected fault");
        assert_eq!(
            matches!(retry, FinalizeAdminUpgradeOutcome::Replayed { .. }),
            committed,
            "after-COMMIT must replay; before-COMMIT must finalize fresh"
        );
        store
            .shutdown()
            .await
            .expect("shutdown finalize fault store");
    }
}

#[tokio::test]
async fn admin_upgrade_finalize_after_commit_replay_bypasses_new_capacity_failure() {
    let root = TestRoot::new("finalize-after-commit-capacity");
    let keys = MemoryKeyStore::new();
    let fault = RejectCapacityAfterFinalizeCommit::new();
    let store = RuntimeStoreHandle::open(
        RuntimeStoreConfig::new(root.database())
            .with_capacity_probe(fault.clone())
            .with_fault_injector(Arc::new(fault.clone())),
        load_or_create_storage_kek(&keys, &root.database())
            .expect("create finalize capacity fault KEK"),
    )
    .await
    .expect("open finalize capacity fault store");
    let upgrade = request("finalize-capacity-replay", "4.1.0", 'f');
    let command = match store
        .accept_admin_upgrade(upgrade.clone())
        .await
        .expect("accept finalize capacity fixture")
    {
        AcceptAdminUpgradeOutcome::Accepted { command, .. } => command,
        AcceptAdminUpgradeOutcome::Replayed { .. } => panic!("fresh fixture replayed"),
    };

    assert!(matches!(
        store
            .finalize_admin_upgrade(command.clone(), AdminUpgradeTerminalOutcome::Completed,)
            .await,
        Err(RuntimeStoreError::CommitOutcomeUnknown {
            operation: RuntimeCommitOperation::FinalizeAdminUpgrade
        })
    ));
    assert!(
        fault.is_rejected(),
        "fault must reject later capacity probes"
    );

    assert!(matches!(
        store
            .finalize_admin_upgrade(command, AdminUpgradeTerminalOutcome::Completed)
            .await
            .expect("authenticated terminal replay must bypass capacity admission"),
        FinalizeAdminUpgradeOutcome::Replayed { .. }
    ));
    assert_eq!(
        store
            .query_admin_upgrade(upgrade)
            .await
            .expect("query committed upgrade")
            .expect("committed upgrade exists")
            .status(),
        AdminUpgradeStatus::Completed
    );
    store
        .shutdown()
        .await
        .expect("shutdown finalize capacity fault store");
}

#[tokio::test]
async fn offline_admin_row_tamper_fails_closed_without_rewriting_runtime_artifacts() {
    for (label, mutation) in [
        (
            "sealed-request",
            "UPDATE admin_commands SET sealed_request = zeroblob(length(sealed_request))",
        ),
        (
            "sealed-outcome",
            "UPDATE admin_commands SET sealed_outcome = zeroblob(length(sealed_outcome))",
        ),
        (
            "metadata-token",
            "UPDATE admin_commands SET metadata_token = zeroblob(32)",
        ),
        (
            "idempotency-token",
            "UPDATE admin_commands SET idempotency_token = zeroblob(32)",
        ),
        (
            "request-token",
            "UPDATE admin_commands SET request_token = zeroblob(32)",
        ),
        (
            "command-kind",
            "UPDATE admin_commands SET command_kind = 'stageUpgrade-tampered'",
        ),
        ("state", "UPDATE admin_commands SET state = 'completed'"),
        (
            "created-at",
            "UPDATE admin_commands SET created_at_ms = created_at_ms - 1",
        ),
        (
            "state-changed-at",
            "UPDATE admin_commands SET state_changed_at_ms = state_changed_at_ms + 1",
        ),
        (
            "retention",
            "UPDATE admin_commands SET retain_until_ms = retain_until_ms + 1",
        ),
        (
            "charged-bytes",
            "UPDATE admin_commands SET charged_bytes = charged_bytes + 1",
        ),
        ("deleted-row", "DELETE FROM admin_commands"),
    ] {
        let root = TestRoot::new(&format!("offline-tamper-{label}"));
        let keys = MemoryKeyStore::new();
        let store = RuntimeStoreHandle::open(
            RuntimeStoreConfig::new(root.database()),
            load_or_create_storage_kek(&keys, &root.database()).expect("create tamper KEK"),
        )
        .await
        .expect("open tamper fixture");
        let accepted = store
            .accept_admin_upgrade(request(&format!("tamper-key-{label}"), "5.0.0", 'f'))
            .await
            .expect("persist authenticated admin row");
        if label == "sealed-outcome" {
            let command = match accepted {
                AcceptAdminUpgradeOutcome::Accepted { command, .. } => command,
                AcceptAdminUpgradeOutcome::Replayed { .. } => {
                    panic!("fresh outcome tamper fixture replayed")
                }
            };
            store
                .finalize_admin_upgrade(
                    command,
                    AdminUpgradeTerminalOutcome::Failed {
                        failure: RuntimeFailure::new(
                            "daemon.upgrade.offline_tamper_fixture",
                            "terminal outcome tamper fixture",
                        ),
                    },
                )
                .await
                .expect("persist authenticated terminal outcome");
        }
        store.shutdown().await.expect("shutdown tamper fixture");

        let connection = Connection::open(root.database()).expect("open offline tamper writer");
        connection
            .execute_batch("PRAGMA ignore_check_constraints = ON;")
            .expect("allow structurally invalid offline tamper fixture");
        assert_eq!(
            connection
                .execute(mutation, [])
                .unwrap_or_else(|error| panic!("tamper {label} side: {error}")),
            1
        );
        drop(connection);
        let before = artifact_evidence(&root.database());
        let error = RuntimeStoreHandle::open(
            RuntimeStoreConfig::new(root.database()),
            load_or_create_storage_kek(&keys, &root.database()).expect("reload tampered KEK"),
        )
        .await
        .expect_err("offline admin row tamper must fail closed");
        assert!(matches!(
            error,
            RuntimeStoreError::UnknownOrCorruptSchema | RuntimeStoreError::Cipher(_)
        ));
        assert_eq!(
            artifact_evidence(&root.database()),
            before,
            "rejected {label} tamper rewrote main/WAL/SHM/journal"
        );
    }
}

#[tokio::test]
async fn admin_request_and_terminal_outcome_plaintext_stay_out_of_main_wal_and_shm() {
    const KEY: &str = "admin-idempotency-sentinel-71c8";
    const TARGET: &str = "9.8.7-admin-target-sentinel-82d9";
    const SHA256: &str = "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef";
    const FAILURE_CODE: &str = "daemon.upgrade.sentinel-93ea";
    const FAILURE_MESSAGE: &str = "admin-outcome-message-sentinel-a4fb";
    const DIAGNOSTIC: &str = "admin-outcome-diagnostic-sentinel-b50c";

    let root = TestRoot::new("plaintext-sentinels");
    let keys = MemoryKeyStore::new();
    let store = RuntimeStoreHandle::open(
        RuntimeStoreConfig::new(root.database()),
        load_or_create_storage_kek(&keys, &root.database()).expect("create sentinel KEK"),
    )
    .await
    .expect("open sentinel store");
    let sentinel_request = StageUpgradeRequest::new(
        TARGET.to_owned(),
        ArtifactSha256::new(SHA256.to_owned()).expect("sentinel artifact hash"),
        IdempotencyKey::new(KEY),
        LocalOnlyAdministration::LocalOnly,
    )
    .expect("sentinel admin request");
    let command = match store
        .accept_admin_upgrade(sentinel_request)
        .await
        .expect("accept sentinel admin command")
    {
        AcceptAdminUpgradeOutcome::Accepted { command, .. } => command,
        AcceptAdminUpgradeOutcome::Replayed { .. } => panic!("fresh sentinel command replayed"),
    };
    store
        .finalize_admin_upgrade(
            command,
            AdminUpgradeTerminalOutcome::Failed {
                failure: RuntimeFailure::new(FAILURE_CODE, FAILURE_MESSAGE)
                    .with_diagnostic(DIAGNOSTIC),
            },
        )
        .await
        .expect("finalize sentinel admin command");
    let sentinels: &[&[u8]] = &[
        KEY.as_bytes(),
        TARGET.as_bytes(),
        SHA256.as_bytes(),
        FAILURE_CODE.as_bytes(),
        FAILURE_MESSAGE.as_bytes(),
        DIAGNOSTIC.as_bytes(),
    ];
    assert_no_artifact_sentinels(&root.database(), sentinels);
    store.shutdown().await.expect("shutdown sentinel store");
    assert_no_artifact_sentinels(&root.database(), sentinels);
}

#[tokio::test]
async fn active_started_count_sums_all_three_ledger_buckets_and_uses_the_normal_lane() {
    let root = TestRoot::new("active-started-buckets");
    let keys = MemoryKeyStore::new();
    let store = RuntimeStoreHandle::open(
        RuntimeStoreConfig::new(root.database()),
        load_or_create_storage_kek(&keys, &root.database()).expect("create Started-count KEK"),
    )
    .await
    .expect("open Started-count store");

    create_started_fixture(&store, 0x11, false, false).await;
    create_started_fixture(&store, 0x12, true, false).await;
    create_started_fixture(&store, 0x13, true, true).await;
    assert_eq!(store.active_started_command_count().await.unwrap(), 3);
    assert!(matches!(
        store
            .accept_admin_upgrade(request("three-started", "10.0.0", 'b'))
            .await
            .expect("accept upgrade with three Started commands"),
        AcceptAdminUpgradeOutcome::Accepted {
            active_started_commands: 3,
            ..
        }
    ));
    store
        .shutdown()
        .await
        .expect("shutdown Started-count store");

    let constrained = RuntimeStoreHandle::open(
        RuntimeStoreConfig::new(root.database()).with_lane_byte_capacity(1),
        load_or_create_storage_kek(&keys, &root.database()).expect("reload Started-count KEK"),
    )
    .await
    .expect("reopen Started-count store with constrained lanes");
    assert!(matches!(
        constrained.active_started_command_count().await,
        Err(RuntimeStoreError::WorkerBusy {
            lane: RuntimeStoreLane::Normal
        })
    ));
    constrained
        .shutdown()
        .await
        .expect("shutdown constrained Started-count store");
}

#[tokio::test]
async fn recovery_in_progress_blocks_admin_normal_and_safety_lanes_but_allows_readback() {
    let root = TestRoot::new("recovery-lanes");
    let keys = MemoryKeyStore::new();
    let store = RuntimeStoreHandle::open(
        RuntimeStoreConfig::new(root.database()),
        load_or_create_storage_kek(&keys, &root.database()).expect("create recovery-lane KEK"),
    )
    .await
    .expect("open recovery-lane store");
    let original = request("recovery-pending", "11.0.0", 'c');
    let command = match store
        .accept_admin_upgrade(original.clone())
        .await
        .expect("accept recovery-lane fixture")
    {
        AcceptAdminUpgradeOutcome::Accepted { command, .. } => command,
        AcceptAdminUpgradeOutcome::Replayed { .. } => panic!("fresh recovery fixture replayed"),
    };

    let recovery_cursor = store
        .begin_recovery_scan()
        .await
        .expect("begin recovery-lane scan");
    assert!(matches!(
        store
            .accept_admin_upgrade(request("recovery-blocked", "11.0.1", 'd'))
            .await,
        Err(RuntimeStoreError::RecoveryInProgress)
    ));
    assert!(matches!(
        store.query_admin_upgrade(original).await,
        Err(RuntimeStoreError::RecoveryInProgress)
    ));
    assert!(matches!(
        store.active_started_command_count().await,
        Err(RuntimeStoreError::RecoveryInProgress)
    ));
    assert!(matches!(
        store
            .finalize_admin_upgrade(command.clone(), AdminUpgradeTerminalOutcome::Completed)
            .await,
        Err(RuntimeStoreError::RecoveryInProgress)
    ));
    let pending = store
        .load_pending_admin_upgrades(None)
        .await
        .expect("read lane remains available during command recovery");
    assert_eq!(pending.commands().len(), 1);

    let page = store
        .load_recovery_page(recovery_cursor)
        .await
        .expect("load terminal empty recovery page");
    store
        .finish_recovery_scan(page.completion.expect("empty recovery completion"))
        .await
        .expect("finish recovery-lane scan");
    store
        .finalize_admin_upgrade(command, AdminUpgradeTerminalOutcome::Completed)
        .await
        .expect("safety lane resumes after recovery");
    store
        .shutdown()
        .await
        .expect("shutdown recovery-lane store");
}

#[tokio::test]
async fn pending_admin_recovery_uses_bounded_keyset_pages() {
    let root = TestRoot::new("pending-pages");
    let keys = MemoryKeyStore::new();
    let store = RuntimeStoreHandle::open(
        RuntimeStoreConfig::new(root.database()),
        load_or_create_storage_kek(&keys, &root.database()).expect("create pending page KEK"),
    )
    .await
    .expect("open pending page store");
    for index in 0..65_u8 {
        store
            .accept_admin_upgrade(request(
                &format!("page-key-{index:03}"),
                &format!("6.0.{index}"),
                char::from(b'a' + index % 6),
            ))
            .await
            .expect("accept paged pending command");
    }
    store
        .shutdown()
        .await
        .expect("shutdown pending page writer");

    let reopened = RuntimeStoreHandle::open(
        RuntimeStoreConfig::new(root.database()),
        load_or_create_storage_kek(&keys, &root.database()).expect("reload pending page KEK"),
    )
    .await
    .expect("reopen pending page store");
    let first = reopened
        .load_pending_admin_upgrades(None)
        .await
        .expect("load first pending page");
    assert_eq!(first.commands().len(), 64);
    let cursor = first.next_cursor().expect("first page cursor").clone();
    let second = reopened
        .load_pending_admin_upgrades(Some(cursor))
        .await
        .expect("load second pending page");
    assert_eq!(second.commands().len(), 1);
    assert!(second.next_cursor().is_none());
    let keys = first
        .commands()
        .iter()
        .chain(second.commands())
        .map(|command| command.request().idempotency_key().as_str().to_owned())
        .collect::<HashSet<_>>();
    assert_eq!(keys.len(), 65);
    for index in 0..65_u8 {
        assert!(keys.contains(&format!("page-key-{index:03}")));
    }
    reopened
        .shutdown()
        .await
        .expect("shutdown reopened pending page store");
}

#[tokio::test]
async fn terminal_admin_rows_are_retained_without_an_implicit_accept_time_sweeper() {
    const THIRTY_DAYS_MS: u64 = 2_592_000_000;
    let root = TestRoot::new("retention");
    let keys = MemoryKeyStore::new();
    let clock = ManualClock::new(10);
    let store = RuntimeStoreHandle::open(
        RuntimeStoreConfig::new(root.database()).with_clock(clock.clone()),
        load_or_create_storage_kek(&keys, &root.database()).expect("create retention KEK"),
    )
    .await
    .expect("open retention store");
    let old = request("retained-key", "7.0.0", 'a');
    let command = match store
        .accept_admin_upgrade(old.clone())
        .await
        .expect("accept retained command")
    {
        AcceptAdminUpgradeOutcome::Accepted { command, .. } => command,
        AcceptAdminUpgradeOutcome::Replayed { .. } => panic!("fresh retained command replayed"),
    };
    let terminal_at_ms = 1_000;
    clock.set(terminal_at_ms);
    store
        .finalize_admin_upgrade(command, AdminUpgradeTerminalOutcome::Completed)
        .await
        .expect("finalize retained command");
    let retain_until_ms: u64 = Connection::open(root.database())
        .expect("open retention readback")
        .query_row(
            "SELECT retain_until_ms FROM admin_commands WHERE state = 'completed'",
            [],
            |row| row.get(0),
        )
        .expect("read terminal retention extension");
    assert_eq!(retain_until_ms, terminal_at_ms + THIRTY_DAYS_MS);

    clock.set(terminal_at_ms + THIRTY_DAYS_MS - 1);
    store
        .accept_admin_upgrade(request("before-cutoff", "7.0.1", 'b'))
        .await
        .expect("accept before retention cutoff");
    assert!(
        store
            .query_admin_upgrade(old.clone())
            .await
            .expect("query before retention cutoff")
            .is_some()
    );
    clock.set(terminal_at_ms + THIRTY_DAYS_MS + 1);
    store
        .accept_admin_upgrade(request("after-cutoff", "7.0.2", 'c'))
        .await
        .expect("accept after retention cutoff");
    assert!(
        store
            .query_admin_upgrade(old)
            .await
            .expect("query after retention floor")
            .is_some()
    );
    store.shutdown().await.expect("shutdown retention store");

    let reopened = RuntimeStoreHandle::open(
        RuntimeStoreConfig::new(root.database()).with_clock(clock),
        load_or_create_storage_kek(&keys, &root.database()).expect("reload retention KEK"),
    )
    .await
    .expect("reopen retained terminal row");
    assert!(
        reopened
            .query_admin_upgrade(request("retained-key", "7.0.0", 'a'))
            .await
            .expect("query retained terminal after reopen")
            .is_some()
    );
    reopened
        .shutdown()
        .await
        .expect("shutdown reopened retention store");
}
