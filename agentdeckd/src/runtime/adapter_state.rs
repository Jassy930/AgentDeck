//! Adapter 私有 resume state 在 RuntimeStore 中使用的中立 namespace。
//!
//! 本模块只表达物理隔离域，不承载任何 vendor identity 类型或序列化格式。

use agentdeck_protocol::AgentKind;

/// 两个 adapter 各自独占的 RuntimeStore namespace。
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(super) enum AdapterStateNamespace {
    Codex,
    ClaudeCode,
}

impl AdapterStateNamespace {
    pub(super) const fn origin_namespace(self) -> &'static str {
        match self {
            Self::Codex => "codex",
            Self::ClaudeCode => "claude-code",
        }
    }

    pub(super) fn from_origin_namespace(value: &str) -> Option<Self> {
        match value {
            "codex" => Some(Self::Codex),
            "claude-code" => Some(Self::ClaudeCode),
            _ => None,
        }
    }

    pub(super) const fn table(self) -> &'static str {
        match self {
            Self::Codex => "codex_adapter_state",
            Self::ClaudeCode => "claude_code_adapter_state",
        }
    }

    pub(super) const fn table_bytes(self) -> &'static [u8] {
        self.table().as_bytes()
    }

    pub(super) const fn key_token_domain(self) -> &'static [u8] {
        match self {
            Self::Codex => b"codex.adapter-state.key.v1",
            Self::ClaudeCode => b"claude-code.adapter-state.key.v1",
        }
    }

    pub(super) const fn reference_token_domain(self) -> &'static [u8] {
        match self {
            Self::Codex => b"codex.adapter-state.reference.v1",
            Self::ClaudeCode => b"claude-code.adapter-state.reference.v1",
        }
    }

    pub(super) const fn other(self) -> Self {
        match self {
            Self::Codex => Self::ClaudeCode,
            Self::ClaudeCode => Self::Codex,
        }
    }

    pub(super) const fn agent_kind(self) -> AgentKind {
        match self {
            Self::Codex => AgentKind::Codex,
            Self::ClaudeCode => AgentKind::ClaudeCode,
        }
    }
}

#[cfg(test)]
mod tests {
    use std::fs;
    use std::path::PathBuf;
    use std::sync::Arc;
    use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};

    use crate::runtime::store::{
        ConversationDescriptor, NewConversation, RuntimeCommitOperation, RuntimeId, RuntimeIdKind,
        RuntimeStoreConfig, RuntimeStoreError, RuntimeStoreFaultInjector, RuntimeStoreHandle,
        RuntimeStoreOperation,
    };
    use crate::security::SecretBytes;
    use crate::security::{MemoryKeyStore, load_or_create_storage_kek};

    use super::AdapterStateNamespace;

    static NEXT_TEMP_ID: AtomicU64 = AtomicU64::new(1);

    struct TestRoot(PathBuf);

    impl TestRoot {
        fn new(name: &str) -> Self {
            let sequence = NEXT_TEMP_ID.fetch_add(1, Ordering::Relaxed);
            let path = std::env::temp_dir().join(format!(
                "agentdeckd-adapter-state-store-{name}-{}-{sequence}",
                std::process::id()
            ));
            let _ = fs::remove_dir_all(&path);
            fs::create_dir(&path).expect("create adapter state test root");
            #[cfg(unix)]
            {
                use std::os::unix::fs::PermissionsExt;
                fs::set_permissions(&path, fs::Permissions::from_mode(0o700))
                    .expect("secure adapter state test root");
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

    fn runtime_id(kind: RuntimeIdKind, byte: u8) -> RuntimeId {
        RuntimeId::from_bytes(kind, [byte; 16]).expect("valid runtime id")
    }

    async fn open_store(root: &TestRoot, keys: &MemoryKeyStore) -> RuntimeStoreHandle {
        let storage_kek = load_or_create_storage_kek(keys, &root.database())
            .expect("load adapter state test KEK");
        RuntimeStoreHandle::open(RuntimeStoreConfig::new(root.database()), storage_kek)
            .await
            .expect("open adapter state test store")
    }

    async fn bind_state(
        store: &RuntimeStoreHandle,
        namespace: AdapterStateNamespace,
        adapter_state_key: RuntimeId,
        state_reference: SecretBytes,
    ) -> Result<(), RuntimeStoreError> {
        match namespace {
            AdapterStateNamespace::Codex => {
                store
                    .codex_adapter_state_vault()
                    .bind(adapter_state_key, state_reference)
                    .await
            }
            AdapterStateNamespace::ClaudeCode => {
                store
                    .claude_code_adapter_state_vault()
                    .bind(adapter_state_key, state_reference)
                    .await
            }
        }
    }

    async fn resolve_state(
        store: &RuntimeStoreHandle,
        namespace: AdapterStateNamespace,
        adapter_state_key: RuntimeId,
    ) -> Result<Option<SecretBytes>, RuntimeStoreError> {
        match namespace {
            AdapterStateNamespace::Codex => {
                store
                    .codex_adapter_state_vault()
                    .resolve(adapter_state_key)
                    .await
            }
            AdapterStateNamespace::ClaudeCode => {
                store
                    .claude_code_adapter_state_vault()
                    .resolve(adapter_state_key)
                    .await
            }
        }
    }

    async fn create_conversation(
        store: &RuntimeStoreHandle,
        seed: u8,
        agent_kind: agentdeck_protocol::AgentKind,
    ) -> RuntimeId {
        let adapter_state_key = runtime_id(RuntimeIdKind::AdapterState, seed.wrapping_add(1));
        store
            .create_conversation(NewConversation {
                conversation_id: runtime_id(RuntimeIdKind::Conversation, seed),
                adapter_state_key,
                descriptor: ConversationDescriptor {
                    agent_kind,
                    title: Some("neutral".to_owned()),
                    cwd: PathBuf::from("/tmp/agentdeck-runtime-test"),
                },
            })
            .await
            .expect("create conversation")
            .adapter_state_key
    }

    #[tokio::test]
    async fn bind_is_exact_retry_and_namespaces_fail_closed() {
        let root = TestRoot::new("bind");
        let keys = MemoryKeyStore::new();
        let store = open_store(&root, &keys).await;
        let codex_key =
            create_conversation(&store, 0x11, agentdeck_protocol::AgentKind::Codex).await;
        let cc_key =
            create_conversation(&store, 0x21, agentdeck_protocol::AgentKind::ClaudeCode).await;

        bind_state(
            &store,
            AdapterStateNamespace::Codex,
            codex_key,
            SecretBytes::new(b"private-codex-ref".to_vec()),
        )
        .await
        .expect("bind Codex ref");
        bind_state(
            &store,
            AdapterStateNamespace::Codex,
            codex_key,
            SecretBytes::new(b"private-codex-ref".to_vec()),
        )
        .await
        .expect("exact retry");
        assert!(matches!(
            resolve_state(&store, AdapterStateNamespace::Codex, codex_key)
                .await
                .expect("resolve Codex ref"),
            Some(secret) if secret.expose_secret() == b"private-codex-ref"
        ));
        assert!(matches!(
            bind_state(
                &store,
                AdapterStateNamespace::Codex,
                codex_key,
                SecretBytes::new(b"different-ref".to_vec()),
            )
            .await,
            Err(RuntimeStoreError::AdapterStateConflict)
        ));

        bind_state(
            &store,
            AdapterStateNamespace::ClaudeCode,
            cc_key,
            SecretBytes::new(b"private-cc-ref".to_vec()),
        )
        .await
        .expect("bind CC ref");
        assert!(matches!(
            resolve_state(&store, AdapterStateNamespace::ClaudeCode, codex_key).await,
            Err(RuntimeStoreError::AdapterStateNamespaceMismatch)
        ));
        assert!(matches!(
            resolve_state(&store, AdapterStateNamespace::Codex, cc_key).await,
            Err(RuntimeStoreError::AdapterStateNamespaceMismatch)
        ));

        store.shutdown().await.expect("shutdown store");
        let raw = fs::read(root.database()).expect("read DB");
        assert!(
            !raw.windows(b"private-codex-ref".len())
                .any(|window| { window == b"private-codex-ref" })
        );
        assert!(
            !raw.windows(b"private-cc-ref".len())
                .any(|window| { window == b"private-cc-ref" })
        );
    }

    #[tokio::test]
    async fn bind_validates_kind_and_conversation_membership() {
        let root = TestRoot::new("identity");
        let keys = MemoryKeyStore::new();
        let store = open_store(&root, &keys).await;

        assert!(matches!(
            bind_state(
                &store,
                AdapterStateNamespace::Codex,
                runtime_id(RuntimeIdKind::Conversation, 0x31),
                SecretBytes::new(b"wrong-kind".to_vec()),
            )
            .await,
            Err(RuntimeStoreError::IdKindMismatch { .. })
        ));
        assert!(matches!(
            bind_state(
                &store,
                AdapterStateNamespace::Codex,
                runtime_id(RuntimeIdKind::AdapterState, 0x32),
                SecretBytes::new(b"orphan".to_vec()),
            )
            .await,
            Err(RuntimeStoreError::ConversationNotFound)
        ));
        let codex_key =
            create_conversation(&store, 0x32, agentdeck_protocol::AgentKind::Codex).await;
        assert!(matches!(
            bind_state(
                &store,
                AdapterStateNamespace::ClaudeCode,
                codex_key,
                SecretBytes::new(b"wrong-agent-namespace".to_vec()),
            )
            .await,
            Err(RuntimeStoreError::AdapterStateNamespaceMismatch)
        ));
        let first = create_conversation(&store, 0x33, agentdeck_protocol::AgentKind::Codex).await;
        let second = create_conversation(&store, 0x34, agentdeck_protocol::AgentKind::Codex).await;
        bind_state(
            &store,
            AdapterStateNamespace::Codex,
            first,
            SecretBytes::new(b"one-native-ref".to_vec()),
        )
        .await
        .expect("bind unique native ref");
        assert!(matches!(
            bind_state(
                &store,
                AdapterStateNamespace::Codex,
                second,
                SecretBytes::new(b"one-native-ref".to_vec()),
            )
            .await,
            Err(RuntimeStoreError::AdapterStateConflict)
        ));
        assert!(matches!(
            bind_state(
                &store,
                AdapterStateNamespace::Codex,
                second,
                SecretBytes::new(vec![0x55; 4 * 1024 + 1]),
            )
            .await,
            Err(RuntimeStoreError::InvalidConfig(_))
        ));
        store.shutdown().await.expect("shutdown store");
    }

    #[tokio::test]
    async fn recovery_blocks_adapter_state_mutation_but_keeps_bounded_reads_available() {
        let root = TestRoot::new("recovery-gate");
        let keys = MemoryKeyStore::new();
        let store = open_store(&root, &keys).await;
        let key = create_conversation(&store, 0x35, agentdeck_protocol::AgentKind::Codex).await;
        store
            .begin_recovery_scan()
            .await
            .expect("begin recovery scan");
        assert!(matches!(
            bind_state(
                &store,
                AdapterStateNamespace::Codex,
                key,
                SecretBytes::new(b"must-not-mutate".to_vec()),
            )
            .await,
            Err(RuntimeStoreError::RecoveryInProgress)
        ));
        assert!(
            resolve_state(&store, AdapterStateNamespace::Codex, key)
                .await
                .expect("resolve remains available during recovery")
                .is_none()
        );
        store.shutdown().await.expect("shutdown recovering store");
    }

    struct FailBindAfterCommit {
        failed: AtomicBool,
    }

    impl RuntimeStoreFaultInjector for FailBindAfterCommit {
        fn before_operation(
            &self,
            operation: RuntimeStoreOperation,
        ) -> Result<(), RuntimeStoreError> {
            if operation == RuntimeStoreOperation::BindAdapterStateAfterCommit
                && !self.failed.swap(true, Ordering::SeqCst)
            {
                return Err(RuntimeStoreError::WorkerStopped);
            }
            Ok(())
        }
    }

    #[tokio::test]
    async fn bind_after_commit_unknown_converges_with_an_identical_retry() {
        let root = TestRoot::new("commit-outcome");
        let keys = MemoryKeyStore::new();
        let store = RuntimeStoreHandle::open(
            RuntimeStoreConfig::new(root.database()).with_fault_injector(Arc::new(
                FailBindAfterCommit {
                    failed: AtomicBool::new(false),
                },
            )),
            load_or_create_storage_kek(&keys, &root.database()).expect("load test KEK"),
        )
        .await
        .expect("open commit outcome store");
        let key = create_conversation(&store, 0x41, agentdeck_protocol::AgentKind::Codex).await;
        let error = bind_state(
            &store,
            AdapterStateNamespace::Codex,
            key,
            SecretBytes::new(b"stable-after-commit-ref".to_vec()),
        )
        .await
        .expect_err("after-commit hook must surface unknown outcome");
        assert!(matches!(
            error,
            RuntimeStoreError::CommitOutcomeUnknown {
                operation: RuntimeCommitOperation::BindAdapterState
            }
        ));
        bind_state(
            &store,
            AdapterStateNamespace::Codex,
            key,
            SecretBytes::new(b"stable-after-commit-ref".to_vec()),
        )
        .await
        .expect("identical retry converges");
        assert!(matches!(
            resolve_state(&store, AdapterStateNamespace::Codex, key)
                .await
                .expect("resolve committed ref"),
            Some(secret) if secret.expose_secret() == b"stable-after-commit-ref"
        ));
        store.shutdown().await.expect("shutdown outcome store");
    }

    async fn create_bound_codex_fixture(root: &TestRoot, keys: &MemoryKeyStore) {
        let store = open_store(root, keys).await;
        let key = create_conversation(&store, 0x51, agentdeck_protocol::AgentKind::Codex).await;
        bind_state(
            &store,
            AdapterStateNamespace::Codex,
            key,
            SecretBytes::new(b"authenticated-private-ref".to_vec()),
        )
        .await
        .expect("bind tamper fixture");
        store.shutdown().await.expect("shutdown tamper fixture");
    }

    #[tokio::test]
    async fn ciphertext_tamper_and_cross_table_move_fail_closed_at_open() {
        for scenario in ["ciphertext", "cross-table"] {
            let root = TestRoot::new(scenario);
            let keys = MemoryKeyStore::new();
            create_bound_codex_fixture(&root, &keys).await;
            let connection = rusqlite::Connection::open(root.database()).expect("open raw DB");
            match scenario {
                "ciphertext" => {
                    connection
                        .execute(
                            "UPDATE codex_adapter_state
                             SET sealed_state_reference = zeroblob(length(sealed_state_reference))",
                            [],
                        )
                        .expect("tamper ciphertext");
                }
                "cross-table" => {
                    connection
                        .execute_batch(
                            "INSERT INTO claude_code_adapter_state
                                 SELECT * FROM codex_adapter_state;
                             DELETE FROM codex_adapter_state;",
                        )
                        .expect("move row across private tables");
                }
                _ => unreachable!(),
            }
            connection
                .execute_batch("PRAGMA wal_checkpoint(TRUNCATE)")
                .expect("checkpoint tamper");
            drop(connection);
            RuntimeStoreHandle::open(
                RuntimeStoreConfig::new(root.database()),
                load_or_create_storage_kek(&keys, &root.database()).expect("reload test KEK"),
            )
            .await
            .expect_err("adapter state tamper must fail closed at open");
        }
    }
}
