use std::fmt::Write as _;
use std::fs;
use std::os::unix::fs::PermissionsExt;
use std::path::{Path, PathBuf};

use agentdeckd::runtime::store::{
    RUNTIME_SCHEMA_VERSION, RuntimeId, RuntimeIdKind, RuntimeStoreConfig, RuntimeStoreHandle,
};
use agentdeckd::security::{
    KeyStore, MemoryKeyStore, STORAGE_KEK_ACCOUNT, SecretBytes, load_or_create_storage_kek,
};
use rusqlite::{Connection, OpenFlags};
use sha2::{Digest, Sha256};

const V4_DATABASE_SHA256: &str = "5f3546ea210f042fb06d17cc42c01cf5d35c855b7b5cd97e79a51cb663f11776";
const V4_DATABASE_WAL_SHA256: &str =
    "7c7c4255a3b4c98edacefcbc0e3d0706ae22d3a975ec9b2c0311308272559bb9";
const V4_STORAGE_KEK_SHA256: &str =
    "fc8b64001c5fdd0f2f40fb67dae4a865a2c5bd17836676d6d5b58b7917e33717";

struct TestRoot(PathBuf);

impl TestRoot {
    fn new() -> Self {
        let path =
            std::env::temp_dir().join(format!("agentdeck-b1b-real-v4-v5-{}", std::process::id()));
        let _ = fs::remove_dir_all(&path);
        fs::create_dir(&path).expect("create real migration copy root");
        fs::set_permissions(&path, fs::Permissions::from_mode(0o700))
            .expect("secure real migration copy root");
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

#[derive(Debug, Eq, PartialEq)]
struct ImmutableManifest {
    wrapped_key_bundle: Vec<Vec<Option<Vec<u8>>>>,
    conversations: Vec<Vec<Option<Vec<u8>>>>,
    commands: Vec<Vec<Option<Vec<u8>>>>,
    execution_intents: Vec<Vec<Option<Vec<u8>>>>,
    events: Vec<Vec<Option<Vec<u8>>>>,
    event_stream_index: Vec<Vec<Option<Vec<u8>>>>,
    event_retention: Vec<Vec<Option<Vec<u8>>>>,
    catalog: Vec<Vec<Option<Vec<u8>>>>,
    snapshots: Vec<Vec<Option<Vec<u8>>>>,
}

fn blob_rows(connection: &Connection, sql: &str, columns: usize) -> Vec<Vec<Option<Vec<u8>>>> {
    connection
        .prepare(sql)
        .expect("prepare immutable manifest query")
        .query_map([], |row| {
            (0..columns)
                .map(|column| row.get::<_, Option<Vec<u8>>>(column))
                .collect::<Result<Vec<_>, _>>()
        })
        .expect("query immutable manifest")
        .collect::<Result<Vec<_>, _>>()
        .expect("collect immutable manifest")
}

fn immutable_manifest(database: &Path) -> ImmutableManifest {
    let connection = Connection::open_with_flags(
        database,
        OpenFlags::SQLITE_OPEN_READ_ONLY | OpenFlags::SQLITE_OPEN_NO_MUTEX,
    )
    .expect("open migration copy read-only");
    ImmutableManifest {
        wrapped_key_bundle: blob_rows(
            &connection,
            "SELECT wrapped_key_bundle FROM runtime_meta WHERE singleton = 1",
            1,
        ),
        conversations: blob_rows(
            &connection,
            "SELECT conversation_id, adapter_state_key, metadata_token, sealed_descriptor
             FROM conversations ORDER BY conversation_id",
            4,
        ),
        commands: blob_rows(
            &connection,
            "SELECT conversation_id, command_id, owner_token, idempotency_token,
                    payload_token, terminal_token, metadata_token, sealed_command, sealed_result
             FROM commands ORDER BY conversation_id, command_seq",
            9,
        ),
        execution_intents: blob_rows(
            &connection,
            "SELECT command_id, turn_id, started_event_id, daemon_boot_id,
                    execution_nonce_token, sealed_intent
             FROM execution_intents ORDER BY command_id",
            6,
        ),
        events: blob_rows(
            &connection,
            "SELECT conversation_id, event_id, command_id, metadata_token, sealed_event
             FROM event_journal ORDER BY conversation_id, event_seq",
            5,
        ),
        event_stream_index: blob_rows(
            &connection,
            "SELECT conversation_id, event_id, metadata_token
             FROM event_stream_index ORDER BY conversation_id, event_seq",
            3,
        ),
        event_retention: blob_rows(
            &connection,
            "SELECT conversation_id, range_digest, metadata_token
             FROM event_retention ORDER BY conversation_id",
            3,
        ),
        catalog: blob_rows(
            &connection,
            "SELECT metadata_token, sealed_delta
             FROM catalog_journal ORDER BY catalog_revision",
            2,
        ),
        snapshots: blob_rows(
            &connection,
            "SELECT snapshot_id, conversation_id, source_build_pin_id, content_sha256,
                    sealed_snapshot_sha256, metadata_token, sealed_snapshot
             FROM snapshots ORDER BY snapshot_id",
            7,
        ),
    }
}

fn hex(bytes: &[u8]) -> String {
    let mut output = String::with_capacity(bytes.len() * 2);
    for byte in bytes {
        write!(&mut output, "{byte:02x}").expect("write hex");
    }
    output
}

fn assert_private(path: &Path, expected_mode: u32) {
    let metadata = fs::symlink_metadata(path).expect("read sample metadata");
    assert_eq!(metadata.permissions().mode() & 0o777, expected_mode);
    assert!(!metadata.file_type().is_symlink());
}

fn copy_sample(source: &Path, target: &TestRoot) {
    for suffix in ["", "-wal"] {
        let source_file = source.join(format!("runtime.db{suffix}"));
        let target_file = PathBuf::from(format!("{}{suffix}", target.database().display()));
        fs::copy(&source_file, &target_file).expect("copy real v4 database artifact");
        fs::set_permissions(&target_file, fs::Permissions::from_mode(0o600))
            .expect("secure copied real v4 artifact");
    }
}

#[tokio::test]
#[ignore = "B1b manual real-writer gate; requires AGENTDECK_B1B_V4_FIXTURE_DIR"]
async fn real_v4_writer_sample_migrates_to_current_v9_with_byte_exact_immutable_rows() {
    // 威胁场景：合成 fixture 可能漏掉真实 v4 writer 的 WAL、sealed row、blind token
    // 与 wrapped key 组合；迁移即使单测全绿，仍可能静默 reseal 或丢失已提交行。
    assert_eq!(RUNTIME_SCHEMA_VERSION, 9);
    let source = PathBuf::from(
        std::env::var_os("AGENTDECK_B1B_V4_FIXTURE_DIR")
            .expect("AGENTDECK_B1B_V4_FIXTURE_DIR is required"),
    );
    assert_private(&source, 0o700);
    for file in ["runtime.db", "runtime.db-wal", "storage-kek.raw"] {
        assert_private(&source.join(file), 0o600);
    }
    let source_database = source.join("runtime.db");
    let kek_bytes = fs::read(source.join("storage-kek.raw")).expect("read real v4 KEK");
    assert_eq!(kek_bytes.len(), 32);
    assert_eq!(
        hex(&Sha256::digest(
            fs::read(&source_database).expect("read real v4 database")
        )),
        V4_DATABASE_SHA256
    );
    assert_eq!(
        hex(&Sha256::digest(
            fs::read(source.join("runtime.db-wal")).expect("read real v4 WAL")
        )),
        V4_DATABASE_WAL_SHA256
    );
    assert_eq!(hex(&Sha256::digest(&kek_bytes)), V4_STORAGE_KEK_SHA256);

    let target = TestRoot::new();
    copy_sample(&source, &target);
    let before = immutable_manifest(&target.database());
    assert_eq!(before.conversations.len(), 1);
    assert_eq!(before.commands.len(), 2);
    assert_eq!(before.execution_intents.len(), 1);
    assert_eq!(before.events.len(), 1);
    assert_eq!(before.catalog.len(), 1);
    assert_eq!(before.snapshots.len(), 1);

    let keys = MemoryKeyStore::new();
    keys.store(STORAGE_KEK_ACCOUNT, &SecretBytes::new(kek_bytes))
        .expect("install real v4 KEK");
    let store = RuntimeStoreHandle::open(
        RuntimeStoreConfig::new(target.database()),
        load_or_create_storage_kek(&keys, &target.database()).expect("load real v4 KEK"),
    )
    .await
    .expect("migrate real v4 writer sample");
    assert_eq!(
        store
            .inspect()
            .await
            .expect("inspect migrated real sample")
            .schema_version,
        RUNTIME_SCHEMA_VERSION
    );

    let conversation_text =
        fs::read_to_string(source.join("conversation-id.txt")).expect("read real conversation id");
    let conversation_id =
        RuntimeId::parse_canonical(RuntimeIdKind::Conversation, conversation_text.trim())
            .expect("parse real conversation id");
    assert!(
        store
            .load_conversation_snapshot(conversation_id)
            .await
            .expect("read migrated real snapshot")
            .is_some()
    );
    let mut cursor = store
        .begin_recovery_scan()
        .await
        .expect("begin real sample recovery readback");
    let mut accepted = 0;
    let mut started = 0;
    loop {
        let page = store
            .load_recovery_page(cursor)
            .await
            .expect("load real sample recovery page");
        if let Some(record) = page.conversation {
            accepted += record.accepted.len();
            started += usize::from(record.started.is_some());
        }
        match (page.next_cursor, page.completion) {
            (Some(next), None) => cursor = next,
            (None, Some(completion)) => {
                store
                    .finish_recovery_scan(completion)
                    .await
                    .expect("finish real sample recovery readback");
                break;
            }
            _ => panic!("real sample recovery cursor contract"),
        }
    }
    assert_eq!((accepted, started), (1, 1));
    store
        .shutdown()
        .await
        .expect("shutdown migrated real sample");

    let after = immutable_manifest(&target.database());
    assert_eq!(
        after, before,
        "v4→current v9 must preserve every selected byte"
    );
    let connection = Connection::open(target.database()).expect("inspect current v9 sidecars");
    let state: (
        Option<String>,
        String,
        String,
        Option<String>,
        Option<String>,
        String,
        i64,
    ) = connection
        .query_row(
            "SELECT s.current_configuration_revision, s.entry_revision, s.origin_kind,
                        s.origin_namespace, s.legacy_command_high_water,
                        c.command_high_water, length(s.metadata_token)
                 FROM conversation_state AS s
                 JOIN conversations AS c USING (conversation_id)",
            [],
            |row| {
                Ok((
                    row.get(0)?,
                    row.get(1)?,
                    row.get(2)?,
                    row.get(3)?,
                    row.get(4)?,
                    row.get(5)?,
                    row.get(6)?,
                ))
            },
        )
        .expect("read real migrated conversation state");
    assert_eq!(state.0, None);
    assert_eq!(state.1, "00000000000000000000");
    assert_eq!(state.2, "managed");
    assert_eq!(state.3, None);
    assert_eq!(state.4.as_deref(), Some(state.5.as_str()));
    assert_eq!(state.6, 32);
    let empty_sidecars: (i64, i64, i64) = connection
        .query_row(
            "SELECT
                 (SELECT COUNT(*) FROM configuration_journal),
                 (SELECT COUNT(*) FROM command_configuration_pins),
                 (SELECT COUNT(*) FROM metadata_mutation_ledger)",
            [],
            |row| Ok((row.get(0)?, row.get(1)?, row.get(2)?)),
        )
        .expect("read real empty post-v4 sidecars");
    assert_eq!(empty_sidecars, (0, 0, 0));
}
