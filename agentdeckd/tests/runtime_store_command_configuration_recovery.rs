#[path = "support/runtime_descriptor.rs"]
mod runtime_descriptor;

use std::fmt::Write as _;
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
use agentdeckd::security::{
    KeyStore, MemoryKeyStore, STORAGE_KEK_ACCOUNT, SecretBytes, load_or_create_storage_kek,
};
use rusqlite::{Connection, OpenFlags};
use sha2::{Digest, Sha256};

const PREFLIGHT_DATABASE_SHA256: &str =
    "07723391e1cec48d59bafa193541ec419c93e64d5deb949d3a0ef32f212f4212";
const PREFLIGHT_DATABASE_WAL_SHA256: &str =
    "7d12dcd7ea22396bf0c539c704e3ba2a6e35ca26a3a6d17e85c68041471b046e";
const PREFLIGHT_STORAGE_KEK_SHA256: &str =
    "3bc66fd8724b93765cee591d40c088a4c5c8200ac756b8aa5af19e3abfbdaf98";

static NEXT_TEMP_ID: AtomicU64 = AtomicU64::new(1);

struct TestRoot(PathBuf);

impl TestRoot {
    fn new(label: &str) -> Self {
        let sequence = NEXT_TEMP_ID.fetch_add(1, Ordering::Relaxed);
        let path = Path::new("/tmp").join(format!(
            "agentdeckd-runtime-command-configuration-recovery-{label}-{}-{sequence}",
            std::process::id()
        ));
        let _ = fs::remove_dir_all(&path);
        fs::create_dir(&path).expect("create command configuration recovery root");
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            fs::set_permissions(&path, fs::Permissions::from_mode(0o700))
                .expect("secure command configuration recovery root");
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
    RuntimeId::from_bytes(kind, [seed; 16]).expect("valid typed runtime id")
}

fn owner(seed: u8) -> IdempotencyOwner {
    IdempotencyOwner::Local {
        machine_trust_domain: [0xA1; 32],
        uid: 501,
        client_installation_id: [seed; 16],
    }
}

fn configuration(reasoning: CodexReasoningEffort) -> ConversationConfiguration {
    ConversationConfiguration::new(VendorConfigurationSnapshot::Codex(
        CodexConversationConfiguration::new(
            CodexApprovalPolicy::OnRequest,
            CodexSandboxMode::WorkspaceWrite,
            reasoning,
        ),
    ))
}

async fn configure(
    store: &RuntimeStoreHandle,
    conversation_id: RuntimeId,
    owner_seed: u8,
    key: &str,
    expected_revision: u64,
    reasoning: CodexReasoningEffort,
) -> u64 {
    match store
        .configure_conversation(ConfigureConversation {
            conversation_id,
            owner: owner(owner_seed),
            idempotency_key: key.to_owned(),
            expected_configuration_revision: expected_revision,
            configuration: configuration(reasoning),
        })
        .await
        .expect("configure recovery evidence conversation")
    {
        ConfigureConversationOutcome::Applied { configuration } => {
            configuration.configuration_revision
        }
        other => panic!("expected applied configuration, got {other:?}"),
    }
}

fn pin_evidence(database: &Path, command_id: RuntimeId) -> (i64, i64, String) {
    let connection = Connection::open_with_flags(database, OpenFlags::SQLITE_OPEN_READ_ONLY)
        .expect("open read-only command pin evidence connection");
    connection
        .query_row(
            "SELECT
                 (SELECT COUNT(*) FROM command_configuration_pins),
                 m.command_configuration_pin_count,
                 p.configuration_revision
             FROM runtime_meta AS m
             JOIN commands AS c ON c.command_id = ?1
             JOIN command_configuration_pins AS p
               ON p.conversation_id = c.conversation_id
              AND p.command_seq = c.command_seq
             WHERE m.singleton = 1",
            [&command_id.as_bytes()[..]],
            |row| Ok((row.get(0)?, row.get(1)?, row.get(2)?)),
        )
        .expect("read physical and authenticated-ledger pin evidence")
}

fn sha256_file(path: &Path) -> String {
    let digest = Sha256::digest(fs::read(path).expect("read fixture artifact for SHA-256"));
    let mut output = String::with_capacity(digest.len() * 2);
    for byte in digest {
        write!(&mut output, "{byte:02x}").expect("write SHA-256 hex");
    }
    output
}

#[cfg(unix)]
fn assert_private(path: &Path, expected_mode: u32) {
    use std::os::unix::fs::PermissionsExt;

    let metadata = fs::symlink_metadata(path).expect("read preflight fixture metadata");
    assert_eq!(metadata.permissions().mode() & 0o777, expected_mode);
    assert!(!metadata.file_type().is_symlink());
}

#[tokio::test]
async fn production_writer_reopen_query_and_recovery_preserve_revision_one_pin() {
    // 证据链必须贯穿默认 writer、重开后的 receipt reader 与逐页 recovery reader；
    // 不能只靠同一进程内的 Accept 返回值证明 command 已固定到旧 revision。
    let root = TestRoot::new("writer-reopen-recovery");
    let database = root.database();
    let keys = MemoryKeyStore::new();
    let config = RuntimeStoreConfig::new(database.clone());
    let store = RuntimeStoreHandle::open(
        config.clone(),
        load_or_create_storage_kek(&keys, &database).expect("create recovery evidence KEK"),
    )
    .await
    .expect("open recovery evidence store");
    let conversation_id = runtime_id(RuntimeIdKind::Conversation, 0x31);
    let command_owner = owner(0x41);
    store
        .create_conversation(NewConversation {
            conversation_id,
            adapter_state_key: runtime_id(RuntimeIdKind::AdapterState, 0x32),
            descriptor: runtime_descriptor::descriptor(b"command-configuration-recovery"),
        })
        .await
        .expect("create recovery evidence conversation");
    assert_eq!(
        configure(
            &store,
            conversation_id,
            0x42,
            "configuration-revision-one",
            0,
            CodexReasoningEffort::Low,
        )
        .await,
        1
    );
    let command = match store
        .accept_command(AcceptCommand {
            conversation_id,
            owner: command_owner.clone(),
            idempotency_key: "accepted-at-revision-one".to_owned(),
            expected_configuration_revision: 1,
            payload: b"recover-pinned-revision-one".to_vec(),
        })
        .await
        .expect("accept command at revision one")
    {
        AcceptOutcome::Accepted { command, .. } => command,
        other => panic!("fresh command must not replay: {other:?}"),
    };
    assert_eq!(command.configuration_revision, 1);
    assert_eq!(
        configure(
            &store,
            conversation_id,
            0x43,
            "configuration-revision-two",
            1,
            CodexReasoningEffort::High,
        )
        .await,
        2
    );
    store.shutdown().await.expect("shutdown writer store");

    let reopened = RuntimeStoreHandle::open(
        config,
        load_or_create_storage_kek(&keys, &database).expect("reload recovery evidence KEK"),
    )
    .await
    .expect("reopen recovery evidence store");
    let receipt = reopened
        .query_command_receipt(QueryCommandReceipt {
            expected_owner: command_owner,
            selector: CommandReceiptSelector::Command {
                conversation_id,
                command_id: command.command_id,
            },
        })
        .await
        .expect("query command receipt after reopen");
    assert_eq!(receipt.command_id, command.command_id);
    assert_eq!(receipt.configuration_revision, 1);
    assert_eq!(
        pin_evidence(&database, command.command_id),
        (1, 1, "00000000000000000001".to_owned())
    );

    let cursor = reopened
        .begin_recovery_scan()
        .await
        .expect("begin command pin recovery scan");
    let page = reopened
        .load_recovery_page(cursor)
        .await
        .expect("load command pin recovery page");
    let recovered = page
        .conversation
        .expect("single conversation recovery record");
    assert_eq!(recovered.conversation.conversation_id, conversation_id);
    assert_eq!(recovered.accepted.len(), 1);
    assert_eq!(recovered.accepted[0].command_id, command.command_id);
    assert_eq!(recovered.accepted[0].configuration_revision, 1);
    assert!(recovered.started.is_none());
    assert!(page.next_cursor.is_none());
    reopened
        .finish_recovery_scan(page.completion.expect("single recovery page completion"))
        .await
        .expect("finish command pin recovery scan");
    assert_eq!(
        pin_evidence(&database, command.command_id),
        (1, 1, "00000000000000000001".to_owned())
    );
    reopened
        .shutdown()
        .await
        .expect("shutdown reopened recovery evidence store");
}

#[tokio::test]
#[ignore = "B3a1c manual preflight gate; requires AGENTDECK_B3A_PREFLIGHT_FIXTURE_DIR"]
async fn real_rev1_without_pin_sample_fails_closed_without_rewriting_db_or_wal() {
    // 旧 preflight writer 已把 rev1 command 写进 v5，但没有写 authenticated pin，
    // 因此 current reader 必须拒绝整库；绝不能把缺 pin 猜成 revision 0 或原地修复。
    let source = PathBuf::from(
        std::env::var_os("AGENTDECK_B3A_PREFLIGHT_FIXTURE_DIR")
            .expect("AGENTDECK_B3A_PREFLIGHT_FIXTURE_DIR is required"),
    );
    #[cfg(unix)]
    {
        assert_private(&source, 0o700);
        for file in ["runtime.db", "runtime.db-wal", "storage-kek.bin"] {
            assert_private(&source.join(file), 0o600);
        }
    }
    assert_eq!(
        sha256_file(&source.join("runtime.db")),
        PREFLIGHT_DATABASE_SHA256
    );
    assert_eq!(
        sha256_file(&source.join("runtime.db-wal")),
        PREFLIGHT_DATABASE_WAL_SHA256
    );
    assert_eq!(
        sha256_file(&source.join("storage-kek.bin")),
        PREFLIGHT_STORAGE_KEK_SHA256
    );

    let target = TestRoot::new("real-rev1-without-pin");
    let target_database = target.database();
    let target_wal = PathBuf::from(format!("{}-wal", target_database.display()));
    let target_shm = PathBuf::from(format!("{}-shm", target_database.display()));
    for (source_file, target_file) in [
        (source.join("runtime.db"), target_database.clone()),
        (source.join("runtime.db-wal"), target_wal.clone()),
    ] {
        fs::copy(source_file, &target_file).expect("copy preflight runtime artifact");
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            fs::set_permissions(&target_file, fs::Permissions::from_mode(0o600))
                .expect("secure copied preflight runtime artifact");
        }
    }
    let database_before = sha256_file(&target_database);
    let wal_before = sha256_file(&target_wal);
    assert_eq!(database_before, PREFLIGHT_DATABASE_SHA256);
    assert_eq!(wal_before, PREFLIGHT_DATABASE_WAL_SHA256);
    assert_ne!(
        fs::metadata(&target_wal)
            .expect("read copied preflight WAL metadata")
            .len(),
        0,
        "real preflight gate must retain committed WAL frames"
    );
    assert!(
        !target_shm.exists(),
        "copied fixture must begin without an SHM artifact"
    );
    let raw_kek = fs::read(source.join("storage-kek.bin")).expect("read preflight raw KEK");
    assert_eq!(raw_kek.len(), 32);
    let keys = MemoryKeyStore::new();
    keys.store(STORAGE_KEK_ACCOUNT, &SecretBytes::new(raw_kek))
        .expect("install preflight raw KEK in MemoryKeyStore");
    let error = RuntimeStoreHandle::open(
        RuntimeStoreConfig::new(target_database.clone()),
        load_or_create_storage_kek(&keys, &target_database).expect("load preflight raw KEK"),
    )
    .await
    .expect_err("rev1 command without authenticated pin must fail closed");
    assert!(
        matches!(error, RuntimeStoreError::UnknownOrCorruptSchema),
        "missing authenticated pin must preserve corruption provenance: {error:?}"
    );
    assert_eq!(sha256_file(&target_database), database_before);
    assert_eq!(sha256_file(&target_wal), wal_before);
    assert!(
        !target_shm.exists(),
        "pre-RW corruption rejection must not materialize target SHM"
    );
    assert_eq!(
        sha256_file(&source.join("runtime.db")),
        PREFLIGHT_DATABASE_SHA256
    );
    assert_eq!(
        sha256_file(&source.join("runtime.db-wal")),
        PREFLIGHT_DATABASE_WAL_SHA256
    );
    assert_eq!(
        sha256_file(&source.join("storage-kek.bin")),
        PREFLIGHT_STORAGE_KEK_SHA256
    );
}
