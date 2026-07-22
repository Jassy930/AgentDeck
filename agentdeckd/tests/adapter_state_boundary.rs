use std::fs;
use std::path::PathBuf;
use std::sync::atomic::{AtomicU64, Ordering};

use agentdeckd::runtime::store::{
    ConversationLifecycle, ConversationRecord, CreateConversationOutcome, NewConversation,
    RuntimeId, RuntimeIdKind, RuntimeStoreConfig, RuntimeStoreHandle,
};
use agentdeckd::security::{MemoryKeyStore, load_or_create_storage_kek};
use rusqlite::{Connection, OpenFlags};

static NEXT_TEMP_ID: AtomicU64 = AtomicU64::new(1);

struct TestRoot(PathBuf);

impl TestRoot {
    fn new(name: &str) -> Self {
        let sequence = NEXT_TEMP_ID.fetch_add(1, Ordering::Relaxed);
        let path = std::env::temp_dir().join(format!(
            "agentdeckd-adapter-state-{name}-{}-{sequence}",
            std::process::id()
        ));
        let _ = fs::remove_dir_all(&path);
        fs::create_dir(&path).expect("create adapter state root");
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            fs::set_permissions(&path, fs::Permissions::from_mode(0o700))
                .expect("secure adapter state root");
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

fn random_runtime_id(kind: RuntimeIdKind) -> RuntimeId {
    loop {
        let mut bytes = [0_u8; 16];
        getrandom::fill(&mut bytes).expect("read OS entropy for stable runtime id");
        if let Ok(id) = RuntimeId::from_bytes(kind, bytes) {
            return id;
        }
    }
}

#[test]
fn public_conversation_debug_omits_daemon_private_adapter_state_key() {
    // 威胁场景：若调用方把 public outcome 写入日志，私域 handle 会成为可关联 vendor
    // resume reference 的稳定能力值；Debug 必须连字段名与值一起省略。
    let adapter_state_key = RuntimeId::from_bytes(RuntimeIdKind::AdapterState, [0xa5; 16])
        .expect("construct non-zero private handle");
    let conversation = ConversationRecord {
        conversation_id: RuntimeId::from_bytes(RuntimeIdKind::Conversation, [0x5a; 16])
            .expect("construct conversation id"),
        adapter_state_key,
        catalog_revision: 1,
        command_high_water: None,
        event_high_water: None,
        accepted_command_count: 0,
        lifecycle: ConversationLifecycle::Active,
        created_at_ms: 1,
        updated_at_ms: 1,
        descriptor: runtime_descriptor::descriptor(b"debug-boundary"),
    };

    for output in [
        format!("{conversation:?}"),
        format!(
            "{:?}",
            CreateConversationOutcome::Created {
                conversation: conversation.clone(),
                conversation_activation_pending: false,
            }
        ),
        format!(
            "{:?}",
            CreateConversationOutcome::Replayed {
                conversation,
                conversation_activation_pending: false,
            }
        ),
    ] {
        assert!(!output.contains("adapter_state_key"), "{output}");
        assert!(
            !output.contains(&adapter_state_key.to_canonical_string()),
            "{output}"
        );
    }
}

async fn open_store(root: &TestRoot, keys: &MemoryKeyStore) -> RuntimeStoreHandle {
    let storage_kek =
        load_or_create_storage_kek(keys, &root.database()).expect("load adapter state StorageKEK");
    RuntimeStoreHandle::open(RuntimeStoreConfig::new(root.database()), storage_kek)
        .await
        .expect("open adapter state store")
}

#[tokio::test]
async fn daemon_private_store_retains_only_the_neutral_adapter_state_key() {
    let root = TestRoot::new("catalog-shape");
    let keys = MemoryKeyStore::new();
    let store = open_store(&root, &keys).await;
    let key = random_runtime_id(RuntimeIdKind::AdapterState);
    store
        .create_conversation(NewConversation {
            conversation_id: random_runtime_id(RuntimeIdKind::Conversation),
            adapter_state_key: key,
            descriptor: runtime_descriptor::descriptor(b"random-key"),
        })
        .await
        .expect("create private row with OS-random adapterStateKey");
    store
        .shutdown()
        .await
        .expect("shutdown private store shape test");

    let flags = OpenFlags::SQLITE_OPEN_READ_ONLY | OpenFlags::SQLITE_OPEN_NO_MUTEX;
    let connection = Connection::open_with_flags(root.database(), flags).expect("open raw DB");
    let columns = connection
        .prepare("PRAGMA table_info(conversations)")
        .expect("prepare catalog columns")
        .query_map([], |row| row.get::<_, String>(1))
        .expect("query catalog columns")
        .collect::<Result<Vec<_>, _>>()
        .expect("collect catalog columns");
    assert!(columns.contains(&"adapter_state_key".to_owned()));
    assert!(!columns.iter().any(|name| {
        let normalized = name.to_ascii_lowercase();
        normalized.contains("thread")
            || normalized.contains("session")
            || normalized.contains("resume")
            || normalized.contains("vendor")
    }));
    let persisted: Vec<u8> = connection
        .query_row("SELECT adapter_state_key FROM conversations", [], |row| {
            row.get(0)
        })
        .expect("read neutral adapterStateKey");
    assert_eq!(persisted, key.as_bytes());
}

#[test]
fn common_adapter_state_module_has_no_vendor_identity_type() {
    let root = PathBuf::from(env!("CARGO_MANIFEST_DIR"));
    let common = fs::read_to_string(root.join("src/runtime/adapter_state.rs"))
        .expect("read common adapter state module");
    for forbidden in ["ThreadId", "SessionId", "CodexResume", "ClaudeCodeResume"] {
        assert!(
            !common.contains(forbidden),
            "common adapter state module leaked {forbidden}"
        );
    }

    // 威胁场景：snapshot handoff 是 public Rust API；若它暴露 getter 或 Debug
    // 字段，client/logging 层可绕过 Runtime v2 wire 取得 daemon-private handle。
    let snapshot = fs::read_to_string(root.join("src/runtime/snapshot.rs"))
        .expect("read snapshot materializer module");
    assert!(!snapshot.contains("pub const fn adapter_state_key("));
    assert!(!snapshot.contains(".field(\"adapter_state_key\""));
    let store_surface = fs::read_to_string(root.join("src/runtime/store/mod.rs"))
        .expect("read Runtime store public surface");
    assert!(!store_surface.contains("pub(crate) adapter_state_key"));

    let runtime_router =
        fs::read_to_string(root.join("src/runtime/router.rs")).expect("read runtime router");
    assert!(runtime_router.contains("continue_adapter_state"));
    assert!(runtime_router.contains("adapter_state_key"));
    assert!(runtime_router.contains("continue_thread_stdio_compat"));
    assert!(runtime_router.contains("handle_history_stdio_compat"));
    assert!(runtime_router.contains("pub(crate) async fn prepare_turn("));
    assert!(!runtime_router.contains("pub async fn continue_thread("));
    assert!(!runtime_router.contains("pub async fn handle_history("));
    assert!(!runtime_router.contains("pub(crate) async fn resolve_approval("));
    assert!(!runtime_router.contains("execution_id: &ExecutionId"));

    let worker = fs::read_to_string(root.join("src/runtime/store/worker.rs"))
        .expect("read Runtime store worker");
    assert!(worker.contains("async fn bind_adapter_state"));
    assert!(worker.contains("async fn resolve_adapter_state"));
    assert!(!worker.contains("pub(in crate::runtime) async fn bind_adapter_state"));
    assert!(!worker.contains("pub(in crate::runtime) async fn resolve_adapter_state"));
    assert!(!worker.contains("pub(crate) async fn bind_adapter_state"));
    assert!(!worker.contains("pub(crate) async fn resolve_adapter_state"));
    assert!(!worker.contains("pub async fn bind_adapter_state"));
    assert!(!worker.contains("pub async fn resolve_adapter_state"));
    assert!(worker.contains("pub(crate) struct CodexAdapterStateVault"));
    assert!(worker.contains("pub(crate) struct ClaudeCodeAdapterStateVault"));
    assert!(worker.contains("pub(in crate::runtime) fn codex_adapter_state_vault"));
    assert!(worker.contains("pub(in crate::runtime) fn claude_code_adapter_state_vault"));
    assert!(!worker.contains("pub(crate) fn codex_adapter_state_vault("));
    assert!(!worker.contains("pub(crate) fn claude_code_adapter_state_vault("));

    let agent_contract =
        fs::read_to_string(root.join("src/agent.rs")).expect("read canonical Agent contract");
    assert!(agent_contract.contains("pub enum CanonicalAgentEvent"));
    assert!(agent_contract.contains("pub struct CanonicalAgentSessionHandle"));
    let canonical_handle = agent_contract
        .split("pub struct CanonicalAgentSessionHandle")
        .nth(1)
        .and_then(|tail| tail.split('}').next())
        .expect("canonical handle body");
    assert!(canonical_handle.contains("adapter_state_key"));
    assert!(!canonical_handle.contains("ThreadId"));
    assert!(agent_contract.contains("CanonicalAgentEventSender"));
    assert!(
        !agent_contract.contains("pub type CanonicalAgentEventSender = mpsc::Sender<ServerEvent>")
    );
    let canonical_events = agent_contract
        .split("pub enum CanonicalAgentEvent")
        .nth(1)
        .and_then(|tail| tail.split("pub type CanonicalAgentEventSender").next())
        .expect("canonical event body");
    assert!(!canonical_events.contains("ThreadId"));
    assert!(!canonical_events.contains("ServerEvent"));
    assert!(agent_contract.contains("read_adapter_history"));
    assert!(runtime_router.contains("read_adapter_history"));

    let codex_mod = fs::read_to_string(root.join("src/codex/mod.rs")).expect("read Codex module");
    let cc_mod = fs::read_to_string(root.join("src/claude_code/mod.rs")).expect("read CC module");
    assert!(!codex_mod.contains("pub mod state"));
    assert!(!cc_mod.contains("pub mod state"));
    for (state_path, own_vault, forbidden_vault) in [
        (
            "src/codex/state.rs",
            "CodexAdapterStateVault",
            "ClaudeCodeAdapterStateVault",
        ),
        (
            "src/claude_code/state.rs",
            "ClaudeCodeAdapterStateVault",
            "CodexAdapterStateVault",
        ),
    ] {
        let state = fs::read_to_string(root.join(state_path)).expect("read private state module");
        assert!(!state.contains("pub struct CodexStateRepository"));
        assert!(!state.contains("pub struct ClaudeCodeStateRepository"));
        assert!(!state.contains("pub async fn resolve"));
        assert!(state.contains(own_vault));
        assert!(!state.contains(forbidden_vault));
        assert!(!state.contains("AdapterStateNamespace"));
    }

    for adapter_path in ["src/codex/adapter.rs", "src/claude_code/adapter.rs"] {
        let adapter = fs::read_to_string(root.join(adapter_path)).expect("read adapter module");
        assert!(adapter.contains("with_state_vault"));
        assert!(!adapter.contains("with_runtime_store"));
        assert!(!adapter.contains("RuntimeStoreHandle"));
    }
    let runtime_router =
        fs::read_to_string(root.join("src/runtime/router.rs")).expect("read runtime router");
    assert!(runtime_router.contains("store.codex_adapter_state_vault()"));
    assert!(runtime_router.contains("store.claude_code_adapter_state_vault()"));
}
#[path = "support/runtime_descriptor.rs"]
mod runtime_descriptor;
