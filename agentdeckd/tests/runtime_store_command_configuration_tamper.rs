#[path = "support/runtime_command_configuration_tamper.rs"]
mod command_configuration_tamper;
#[path = "support/runtime_configuration.rs"]
mod runtime_configuration;
#[path = "support/runtime_descriptor.rs"]
mod runtime_descriptor;
#[path = "support/store_admission.rs"]
mod store_admission;

use std::fs;
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicU64, Ordering};

use agentdeck_protocol::runtime::{
    CodexConversationConfiguration, ConversationConfiguration, VendorConfigurationSnapshot,
};
use agentdeck_protocol::{CodexApprovalPolicy, CodexReasoningEffort, CodexSandboxMode};
use agentdeckd::runtime::store::{
    AcceptCommand, AcceptOutcome, CommandReceiptSelector, ConfigureConversation,
    ConfigureConversationOutcome, IdempotencyOwner, NewConversation, QueryCommandReceipt,
    RuntimeId, RuntimeIdKind, RuntimeStoreConfig, RuntimeStoreError, RuntimeStoreHandle,
};
use agentdeckd::security::{MemoryKeyStore, StorageKek, load_or_create_storage_kek};

use command_configuration_tamper::{StoreArtifacts, TargetPinCorruption};

static NEXT_TEMP_ID: AtomicU64 = AtomicU64::new(1);

struct TestRoot {
    path: PathBuf,
    _permit: store_admission::Permit,
}

impl TestRoot {
    fn new(label: &str) -> Self {
        let permit = store_admission::acquire();
        let sequence = NEXT_TEMP_ID.fetch_add(1, Ordering::Relaxed);
        let path = Path::new("/tmp").join(format!(
            "agentdeckd-command-pin-tamper-{label}-{}-{sequence}",
            std::process::id()
        ));
        let _ = fs::remove_dir_all(&path);
        fs::create_dir(&path).expect("create command pin tamper root");
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            fs::set_permissions(&path, fs::Permissions::from_mode(0o700))
                .expect("secure command pin tamper root");
        }
        Self {
            path,
            _permit: permit,
        }
    }

    fn database(&self) -> PathBuf {
        self.path.join("runtime.db")
    }

    fn storage_kek(&self, keys: &MemoryKeyStore) -> StorageKek {
        load_or_create_storage_kek(keys, &self.path.join("key-state.db"))
            .expect("load command pin tamper StorageKEK")
    }
}

impl Drop for TestRoot {
    fn drop(&mut self) {
        let _ = fs::remove_dir_all(&self.path);
    }
}

#[derive(Clone)]
struct AcceptedFixture {
    conversation_id: RuntimeId,
    command_id: RuntimeId,
    owner: IdempotencyOwner,
    idempotency_key: String,
}

struct Fixture {
    root: TestRoot,
    keys: MemoryKeyStore,
    store: Option<RuntimeStoreHandle>,
    a0: AcceptedFixture,
    a1: AcceptedFixture,
    b0: AcceptedFixture,
}

impl Fixture {
    async fn create(label: &str) -> Self {
        let root = TestRoot::new(label);
        let keys = MemoryKeyStore::new();
        let store = RuntimeStoreHandle::open(
            RuntimeStoreConfig::new(root.database()),
            root.storage_kek(&keys),
        )
        .await
        .expect("open command pin tamper fixture");
        let conversation_a = runtime_id(RuntimeIdKind::Conversation, 0x11);
        let conversation_b = runtime_id(RuntimeIdKind::Conversation, 0x21);
        for (conversation_id, adapter_seed, descriptor) in [
            (
                conversation_a,
                0x12,
                b"pin tamper conversation A".as_slice(),
            ),
            (
                conversation_b,
                0x22,
                b"pin tamper conversation B".as_slice(),
            ),
        ] {
            store
                .create_conversation(NewConversation {
                    conversation_id,
                    adapter_state_key: runtime_id(RuntimeIdKind::AdapterState, adapter_seed),
                    descriptor: runtime_descriptor::descriptor(descriptor),
                })
                .await
                .expect("create command pin tamper conversation");
            runtime_configuration::configure_codex_revision_one(&store, conversation_id).await;
        }

        let a0 = accept(&store, conversation_a, 0x31, "a-seq-zero").await;
        let a1 = accept(&store, conversation_a, 0x32, "a-seq-one").await;
        let b0 = accept(&store, conversation_b, 0x33, "b-seq-zero").await;
        assert_eq!((a0.1, a1.1, b0.1), (0, 1, 0));
        assert_eq!(
            configure_revision_two(&store, conversation_a).await,
            2,
            "conversation A must advance after both commands are pinned to revision one"
        );

        let fixture = Self {
            root,
            keys,
            store: Some(store),
            a0: a0.0,
            a1: a1.0,
            b0: b0.0,
        };
        fixture.assert_baseline().await;
        fixture
    }

    fn store(&self) -> &RuntimeStoreHandle {
        self.store.as_ref().expect("fixture store is live")
    }

    fn database(&self) -> PathBuf {
        self.root.database()
    }

    fn storage_kek(&self) -> StorageKek {
        self.root.storage_kek(&self.keys)
    }

    async fn assert_baseline(&self) {
        for command in [&self.a0, &self.a1, &self.b0] {
            let by_command = self
                .store()
                .query_command_receipt(receipt_by_command(command))
                .await
                .expect("baseline receipt by command id");
            let by_idempotency = self
                .store()
                .query_command_receipt(receipt_by_idempotency(command))
                .await
                .expect("baseline receipt by idempotency key");
            assert_eq!(by_command, by_idempotency);
            assert_eq!(by_command.configuration_revision, 1);
        }
        let recovered = complete_recovery(self.store())
            .await
            .expect("baseline recovery must authenticate all command pins");
        assert_eq!(recovered.len(), 3);
        for command in [&self.a0, &self.a1, &self.b0] {
            assert!(
                recovered
                    .iter()
                    .any(|(command_id, revision)| *command_id == command.command_id
                        && *revision == 1),
                "baseline recovery must preserve revision-one pin for {}",
                command.idempotency_key
            );
        }
    }

    async fn assert_target_rejected_without_artifact_drift(&self, label: &str) {
        let baseline = StoreArtifacts::read(&self.database());
        for (selector, query) in [
            ("command-id", receipt_by_command(&self.a0)),
            ("idempotency", receipt_by_idempotency(&self.a0)),
        ] {
            let error = self
                .store()
                .query_command_receipt(query)
                .await
                .expect_err("corrupted target pin query must fail closed");
            assert_integrity_error(error, &format!("{label}/{selector}"));
        }
        let error = self
            .store()
            .begin_recovery_scan()
            .await
            .expect_err("live recovery must reject corrupted target pin");
        assert_integrity_error(error, &format!("{label}/live-recovery"));
        StoreArtifacts::read(&self.database()).assert_main_and_wal_unchanged(
            &baseline,
            &format!("{label}: receipt and live recovery rejection"),
        );
    }

    async fn assert_target_queries_remain_local_but_global_audit_rejects(&self, label: &str) {
        let baseline = StoreArtifacts::read(&self.database());
        let by_command = self
            .store()
            .query_command_receipt(receipt_by_command(&self.a0))
            .await
            .expect("unrelated global divergence must not poison local command-id query");
        let by_idempotency = self
            .store()
            .query_command_receipt(receipt_by_idempotency(&self.a0))
            .await
            .expect("unrelated global divergence must not poison local idempotency query");
        assert_eq!(by_command, by_idempotency);
        assert_eq!(by_command.configuration_revision, 1);
        let error = self
            .store()
            .begin_recovery_scan()
            .await
            .expect_err("global pin divergence must fail live recovery audit");
        assert_integrity_error(error, &format!("{label}/live-recovery"));
        StoreArtifacts::read(&self.database()).assert_main_and_wal_unchanged(
            &baseline,
            &format!("{label}: local reads and recovery rejection"),
        );
    }

    async fn shutdown_and_assert_reopen_rejected(mut self, label: &str) {
        self.store
            .take()
            .expect("take live tampered store")
            .shutdown()
            .await
            .expect("shutdown tampered store without repair");
        let baseline = StoreArtifacts::read(&self.database());
        let error =
            RuntimeStoreHandle::open(RuntimeStoreConfig::new(self.database()), self.storage_kek())
                .await
                .expect_err("tampered current-v5 store must fail closed on reopen");
        assert_integrity_error(error, &format!("{label}/reopen"));
        assert_eq!(
            StoreArtifacts::read(&self.database()),
            baseline,
            "{label}: rejected reopen must not rewrite main/WAL/SHM"
        );
    }
}

#[derive(Clone, Copy, Debug)]
enum TargetCase {
    TokenBitFlip,
    RevisionSwap,
    FreshSeqZeroDelete,
    CrossCommandToken,
    CrossConversationToken,
}

impl TargetCase {
    fn label(self) -> &'static str {
        match self {
            Self::TokenBitFlip => "token-bitflip",
            Self::RevisionSwap => "revision-swap",
            Self::FreshSeqZeroDelete => "fresh-seq0-delete",
            Self::CrossCommandToken => "cross-command-token",
            Self::CrossConversationToken => "cross-conversation-token",
        }
    }
}

#[tokio::test]
async fn target_pin_corruption_fails_both_queries_live_recovery_and_reopen() {
    // Target revision swap 故意保留 revision-one token：这是无 KEK 的 offline row
    // corruption 模型，必须由原 MAC 拒绝，不能把它误写成“持有 KEK 的攻击者仍可伪造”。
    for case in [
        TargetCase::TokenBitFlip,
        TargetCase::RevisionSwap,
        TargetCase::FreshSeqZeroDelete,
        TargetCase::CrossCommandToken,
        TargetCase::CrossConversationToken,
    ] {
        let fixture = Fixture::create(case.label()).await;
        let corruption = match case {
            TargetCase::TokenBitFlip => TargetPinCorruption::TokenBitFlip,
            TargetCase::RevisionSwap => TargetPinCorruption::RevisionSwapToTwo,
            TargetCase::FreshSeqZeroDelete => TargetPinCorruption::Delete,
            TargetCase::CrossCommandToken => TargetPinCorruption::CopyToken {
                source_conversation_id: fixture.a1.conversation_id,
                source_command_seq: 1,
            },
            TargetCase::CrossConversationToken => TargetPinCorruption::CopyToken {
                source_conversation_id: fixture.b0.conversation_id,
                source_command_seq: 0,
            },
        };
        command_configuration_tamper::corrupt_target_pin(
            &fixture.database(),
            &fixture.storage_kek(),
            fixture.a0.conversation_id,
            0,
            corruption,
        );
        fixture
            .assert_target_rejected_without_artifact_drift(case.label())
            .await;
        fixture
            .shutdown_and_assert_reopen_rejected(case.label())
            .await;
    }
}

#[tokio::test]
async fn global_pin_divergence_preserves_local_queries_but_fails_recovery_and_reopen() {
    // orphan/ledger 两例用已自证的 production crypto 构造 MAC-valid 分叉。单行 receipt
    // 读取保持局部，不为无关 orphan 做 O(n) 全库扫描；恢复与重开才承担全库审计。
    for case in ["authenticated-orphan", "authenticated-ledger-divergence"] {
        let fixture = Fixture::create(case).await;
        match case {
            "authenticated-orphan" => {
                command_configuration_tamper::insert_authenticated_orphan_pin(
                    &fixture.database(),
                    &fixture.storage_kek(),
                    fixture.a0.conversation_id,
                    2,
                    1,
                );
            }
            "authenticated-ledger-divergence" => {
                command_configuration_tamper::diverge_authenticated_pin_ledger(
                    &fixture.database(),
                    &fixture.storage_kek(),
                );
            }
            _ => unreachable!(),
        }
        fixture
            .assert_target_queries_remain_local_but_global_audit_rejects(case)
            .await;
        fixture.shutdown_and_assert_reopen_rejected(case).await;
    }
}

async fn accept(
    store: &RuntimeStoreHandle,
    conversation_id: RuntimeId,
    owner_seed: u8,
    idempotency_key: &str,
) -> (AcceptedFixture, u64) {
    let owner = owner(owner_seed);
    let command = match store
        .accept_command(AcceptCommand {
            conversation_id,
            owner: owner.clone(),
            idempotency_key: idempotency_key.to_owned(),
            expected_configuration_revision: 1,
            payload: format!("pin-tamper-prompt-{idempotency_key}").into_bytes(),
        })
        .await
        .expect("accept command pin tamper fixture")
    {
        AcceptOutcome::Accepted { command, .. } => command,
        other => panic!("fresh command pin fixture cannot replay: {other:?}"),
    };
    assert_eq!(command.configuration_revision, 1);
    (
        AcceptedFixture {
            conversation_id,
            command_id: command.command_id,
            owner,
            idempotency_key: idempotency_key.to_owned(),
        },
        command.command_seq,
    )
}

async fn configure_revision_two(store: &RuntimeStoreHandle, conversation_id: RuntimeId) -> u64 {
    let outcome = store
        .configure_conversation(ConfigureConversation {
            conversation_id,
            owner: owner(0x41),
            idempotency_key: "fixture-codex-configuration-revision-two".to_owned(),
            expected_configuration_revision: 1,
            configuration: ConversationConfiguration::new(VendorConfigurationSnapshot::Codex(
                CodexConversationConfiguration::new(
                    CodexApprovalPolicy::OnRequest,
                    CodexSandboxMode::WorkspaceWrite,
                    CodexReasoningEffort::High,
                ),
            )),
        })
        .await
        .expect("advance pin tamper conversation configuration");
    match outcome {
        ConfigureConversationOutcome::Applied { configuration } => {
            configuration.configuration_revision
        }
        other => panic!("fresh revision-two configuration must apply: {other:?}"),
    }
}

fn owner(seed: u8) -> IdempotencyOwner {
    IdempotencyOwner::Local {
        machine_trust_domain: [0xA1; 32],
        uid: 501,
        client_installation_id: [seed; 16],
    }
}

fn receipt_by_command(command: &AcceptedFixture) -> QueryCommandReceipt {
    QueryCommandReceipt {
        expected_owner: command.owner.clone(),
        selector: CommandReceiptSelector::Command {
            conversation_id: command.conversation_id,
            command_id: command.command_id,
        },
    }
}

fn receipt_by_idempotency(command: &AcceptedFixture) -> QueryCommandReceipt {
    QueryCommandReceipt {
        expected_owner: command.owner.clone(),
        selector: CommandReceiptSelector::Idempotency {
            conversation_id: command.conversation_id,
            idempotency_key: command.idempotency_key.clone(),
        },
    }
}

async fn complete_recovery(
    store: &RuntimeStoreHandle,
) -> Result<Vec<(RuntimeId, u64)>, RuntimeStoreError> {
    let mut cursor = store.begin_recovery_scan().await?;
    let mut accepted = Vec::new();
    let completion = loop {
        let page = store.load_recovery_page(cursor).await?;
        if let Some(conversation) = page.conversation {
            accepted.extend(
                conversation
                    .accepted
                    .into_iter()
                    .map(|command| (command.command_id, command.configuration_revision)),
            );
        }
        if let Some(next) = page.next_cursor {
            cursor = next;
        } else {
            break page
                .completion
                .ok_or(RuntimeStoreError::UnknownOrCorruptSchema)?;
        }
    };
    store.finish_recovery_scan(completion).await?;
    Ok(accepted)
}

fn assert_integrity_error(error: RuntimeStoreError, label: &str) {
    assert!(
        matches!(error, RuntimeStoreError::UnknownOrCorruptSchema),
        "{label} must return typed authenticated corruption, got {error:?}"
    );
}

fn runtime_id(kind: RuntimeIdKind, seed: u8) -> RuntimeId {
    RuntimeId::from_bytes(kind, [seed; 16]).expect("valid typed runtime id")
}
