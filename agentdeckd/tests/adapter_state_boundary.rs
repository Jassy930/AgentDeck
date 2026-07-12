use std::fs;
use std::path::PathBuf;
use std::sync::atomic::{AtomicU64, Ordering};

use agentdeckd::runtime::store::{
    NewConversation, RuntimeId, RuntimeIdKind, RuntimeStoreConfig, RuntimeStoreHandle,
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

async fn open_store(root: &TestRoot, keys: &MemoryKeyStore) -> RuntimeStoreHandle {
    let storage_kek =
        load_or_create_storage_kek(keys, &root.database()).expect("load adapter state StorageKEK");
    RuntimeStoreHandle::open(RuntimeStoreConfig::new(root.database()), storage_kek)
        .await
        .expect("open adapter state store")
}

#[tokio::test]
async fn common_catalog_has_only_the_neutral_adapter_state_key() {
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
        .expect("create catalog row with OS-random adapterStateKey");
    store
        .shutdown()
        .await
        .expect("shutdown catalog shape store");

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

    let runtime_router =
        fs::read_to_string(root.join("src/runtime/router.rs")).expect("read runtime router");
    assert!(runtime_router.contains("continue_adapter_state"));
    assert!(runtime_router.contains("adapter_state_key"));
    assert!(runtime_router.contains("continue_thread_stdio_compat"));
    assert!(runtime_router.contains("handle_history_stdio_compat"));
    assert!(!runtime_router.contains("pub async fn continue_thread("));
    assert!(!runtime_router.contains("pub async fn handle_history("));

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
    assert!(!worker.contains("pub(crate) fn codex_adapter_state_vault"));
    assert!(!worker.contains("pub(crate) fn claude_code_adapter_state_vault"));

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
