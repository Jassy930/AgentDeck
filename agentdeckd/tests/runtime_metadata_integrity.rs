#[path = "support/runtime_descriptor.rs"]
mod runtime_descriptor;

use std::fs::{self, OpenOptions};
use std::io::{ErrorKind, Read};
#[cfg(unix)]
use std::os::unix::fs::{MetadataExt, OpenOptionsExt, PermissionsExt};
use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::sync::atomic::{AtomicU64, Ordering};

use agentdeck_protocol::runtime::ConversationMetadataMutation;
use agentdeckd::runtime::store::cipher::CipherError;
use agentdeckd::runtime::store::{
    IdempotencyOwner, NewConversation, RuntimeClock, RuntimeClockError, RuntimeId, RuntimeIdKind,
    RuntimeStoreConfig, RuntimeStoreError, RuntimeStoreHandle, UpdateConversationMetadataOutcome,
    UpdateManagedConversationMetadata,
};
use agentdeckd::security::{MemoryKeyStore, StorageKek, load_or_create_storage_kek};
use rusqlite::{Connection, OpenFlags, TransactionBehavior, params};

const MAX_ARTIFACT_BYTES: u64 = 32 * 1024 * 1024;
const REVISION_ONE: &str = "00000000000000000001";
const REVISION_TWO: &str = "00000000000000000002";

static NEXT_TEMP_ID: AtomicU64 = AtomicU64::new(1);

#[derive(Clone)]
struct ManualClock(Arc<AtomicU64>);

impl ManualClock {
    fn new(value: u64) -> Self {
        Self(Arc::new(AtomicU64::new(value)))
    }

    fn set(&self, value: u64) {
        self.0.store(value, Ordering::SeqCst);
    }
}

impl RuntimeClock for ManualClock {
    fn now_ms(&self) -> Result<u64, RuntimeClockError> {
        Ok(self.0.load(Ordering::SeqCst))
    }
}

struct TestRoot(PathBuf);

impl TestRoot {
    fn new(label: &str) -> Self {
        let sequence = NEXT_TEMP_ID.fetch_add(1, Ordering::Relaxed);
        let path = Path::new("/tmp").join(format!(
            "agentdeckd-metadata-integrity-{label}-{}-{sequence}",
            std::process::id()
        ));
        let _ = fs::remove_dir_all(&path);
        fs::create_dir(&path).expect("create metadata integrity root");
        #[cfg(unix)]
        fs::set_permissions(&path, fs::Permissions::from_mode(0o700))
            .expect("secure metadata integrity root");
        Self(path)
    }

    fn database(&self) -> PathBuf {
        self.0.join("runtime.db")
    }

    fn storage_kek(&self, keys: &MemoryKeyStore) -> StorageKek {
        load_or_create_storage_kek(keys, &self.0.join("key-state.db"))
            .expect("load metadata integrity StorageKEK")
    }
}

impl Drop for TestRoot {
    fn drop(&mut self) {
        let _ = fs::remove_dir_all(&self.0);
    }
}

#[cfg(unix)]
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
struct ArtifactIdentity {
    device: u64,
    inode: u64,
    length: u64,
    modified_seconds: i64,
    modified_nanoseconds: i64,
    changed_seconds: i64,
    changed_nanoseconds: i64,
}

#[cfg(not(unix))]
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
struct ArtifactIdentity {
    length: u64,
}

#[derive(Clone, Debug, Eq, PartialEq)]
struct ArtifactEvidence {
    bytes: Vec<u8>,
    identity: ArtifactIdentity,
}

#[derive(Clone, Debug, Eq, PartialEq)]
struct StoreArtifacts {
    main: Option<ArtifactEvidence>,
    wal: Option<ArtifactEvidence>,
    shm: Option<ArtifactEvidence>,
}

impl StoreArtifacts {
    fn capture(database: &Path) -> Self {
        let evidence = Self {
            main: read_artifact(database),
            wal: read_artifact(&sidecar(database, "-wal")),
            shm: read_artifact(&sidecar(database, "-shm")),
        };
        assert!(evidence.main.is_some(), "runtime main DB must exist");
        assert!(
            evidence
                .wal
                .as_ref()
                .is_some_and(|artifact| !artifact.bytes.is_empty()),
            "offline tamper must remain in a nonempty WAL before rejected open"
        );
        evidence
    }
}

fn sidecar(database: &Path, suffix: &str) -> PathBuf {
    PathBuf::from(format!("{}{suffix}", database.display()))
}

fn read_artifact(path: &Path) -> Option<ArtifactEvidence> {
    let mut options = OpenOptions::new();
    options.read(true);
    #[cfg(unix)]
    options.custom_flags(libc::O_CLOEXEC | libc::O_NOFOLLOW);
    let file = match options.open(path) {
        Ok(file) => file,
        Err(error) if error.kind() == ErrorKind::NotFound => return None,
        Err(error) => panic!("open runtime artifact {}: {error}", path.display()),
    };
    let metadata = file
        .metadata()
        .unwrap_or_else(|error| panic!("inspect runtime artifact {}: {error}", path.display()));
    assert!(
        metadata.file_type().is_file(),
        "runtime artifact must be a regular file: {}",
        path.display()
    );
    assert!(
        metadata.len() <= MAX_ARTIFACT_BYTES,
        "runtime artifact {} has {} bytes, exceeding the {MAX_ARTIFACT_BYTES}-byte oracle cap",
        path.display(),
        metadata.len()
    );
    let identity = artifact_identity(&metadata);
    let mut bytes = Vec::with_capacity(
        usize::try_from(metadata.len()).expect("bounded artifact length fits usize"),
    );
    file.take(MAX_ARTIFACT_BYTES + 1)
        .read_to_end(&mut bytes)
        .unwrap_or_else(|error| panic!("read runtime artifact {}: {error}", path.display()));
    assert!(
        u64::try_from(bytes.len()).expect("artifact bytes fit u64") <= MAX_ARTIFACT_BYTES,
        "runtime artifact {} grew beyond the {MAX_ARTIFACT_BYTES}-byte oracle cap",
        path.display()
    );
    Some(ArtifactEvidence { bytes, identity })
}

#[cfg(unix)]
fn artifact_identity(metadata: &fs::Metadata) -> ArtifactIdentity {
    ArtifactIdentity {
        device: metadata.dev(),
        inode: metadata.ino(),
        length: metadata.len(),
        modified_seconds: metadata.mtime(),
        modified_nanoseconds: metadata.mtime_nsec(),
        changed_seconds: metadata.ctime(),
        changed_nanoseconds: metadata.ctime_nsec(),
    }
}

#[cfg(not(unix))]
fn artifact_identity(metadata: &fs::Metadata) -> ArtifactIdentity {
    ArtifactIdentity {
        length: metadata.len(),
    }
}

#[derive(Clone, Copy, Debug)]
enum TamperCase {
    MetadataToken,
    SealedRequest,
    SealedOutcome,
    DeleteMutation,
    ConversationStateHead,
    RuntimeLedgerTotal,
    CatalogDeltaTime,
    CatalogDeltaContent,
    OldDescriptorRestore,
    CrossRowCiphertextExchange,
}

impl TamperCase {
    const fn label(self) -> &'static str {
        match self {
            Self::MetadataToken => "metadata-token",
            Self::SealedRequest => "sealed-request",
            Self::SealedOutcome => "sealed-outcome",
            Self::DeleteMutation => "delete-mutation",
            Self::ConversationStateHead => "conversation-state-head",
            Self::RuntimeLedgerTotal => "runtime-ledger-total",
            Self::CatalogDeltaTime => "catalog-delta-time",
            Self::CatalogDeltaContent => "catalog-delta-content",
            Self::OldDescriptorRestore => "old-descriptor-restore",
            Self::CrossRowCiphertextExchange => "cross-row-ciphertext-exchange",
        }
    }
}

struct Fixture {
    root: TestRoot,
    keys: MemoryKeyStore,
    clock: ManualClock,
    conversation_id: RuntimeId,
    old_descriptor: Vec<u8>,
}

impl Fixture {
    async fn create(case: TamperCase) -> Self {
        let root = TestRoot::new(case.label());
        let keys = MemoryKeyStore::new();
        let clock = ManualClock::new(100);
        let conversation_id = runtime_id(RuntimeIdKind::Conversation, 0x21);
        let store = RuntimeStoreHandle::open(
            RuntimeStoreConfig::new(root.database()).with_clock(clock.clone()),
            root.storage_kek(&keys),
        )
        .await
        .expect("open metadata integrity fixture");
        store
            .create_conversation(NewConversation {
                conversation_id,
                adapter_state_key: runtime_id(RuntimeIdKind::AdapterState, 0x61),
                descriptor: runtime_descriptor::descriptor(b"metadata-initial"),
            })
            .await
            .expect("create metadata integrity conversation");

        clock.set(200);
        apply_rename(
            &store,
            conversation_id,
            "rename-old",
            0,
            "metadata-old-aaaa",
        )
        .await;
        let old_descriptor = read_old_descriptor(&root.database(), conversation_id);

        clock.set(300);
        apply_rename(
            &store,
            conversation_id,
            "rename-new",
            1,
            "metadata-new-bbbb",
        )
        .await;
        store
            .shutdown()
            .await
            .expect("shutdown metadata integrity fixture before offline tamper");

        Self {
            root,
            keys,
            clock,
            conversation_id,
            old_descriptor,
        }
    }

    fn database(&self) -> PathBuf {
        self.root.database()
    }

    fn storage_kek(&self) -> StorageKek {
        self.root.storage_kek(&self.keys)
    }

    async fn tamper_and_assert_rejected(self, case: TamperCase) {
        tamper_without_kek(
            &self.database(),
            self.conversation_id,
            &self.old_descriptor,
            case,
        );
        // 威胁边界从攻击者关闭 SQLite handle 后开始。此后只用 filesystem handle
        // 固定 main/WAL/SHM 的 bytes 与 device/inode/mtime/ctime identity。
        let baseline = StoreArtifacts::capture(&self.database());
        let result = RuntimeStoreHandle::open(
            RuntimeStoreConfig::new(self.database()).with_clock(self.clock.clone()),
            self.storage_kek(),
        )
        .await;
        match result {
            Err(error) => {
                let after = StoreArtifacts::capture(&self.database());
                assert_eq!(
                    after,
                    baseline,
                    "{}: rejected open rewrote main/WAL/SHM bytes or identity",
                    case.label()
                );
                assert!(
                    matches!(
                        error,
                        RuntimeStoreError::UnknownOrCorruptSchema
                            | RuntimeStoreError::Cipher(CipherError::AuthenticationFailed)
                    ),
                    "{}: offline corruption did not fail through an integrity gate: {error:?}",
                    case.label()
                );
            }
            Ok(store) => {
                let after_open = StoreArtifacts::capture(&self.database());
                let artifact_drifted = after_open != baseline;
                store
                    .shutdown()
                    .await
                    .expect("shutdown unexpectedly accepted corrupted store");
                panic!(
                    "{}: offline tamper was accepted (artifact_drifted={artifact_drifted})",
                    case.label()
                );
            }
        }
    }
}

async fn apply_rename(
    store: &RuntimeStoreHandle,
    conversation_id: RuntimeId,
    idempotency_key: &str,
    expected_entry_revision: u64,
    title: &str,
) {
    let outcome = store
        .update_managed_conversation_metadata(UpdateManagedConversationMetadata {
            conversation_id,
            owner: IdempotencyOwner::Local {
                machine_trust_domain: [0xA1; 32],
                uid: 501,
                client_installation_id: [0x31; 16],
            },
            idempotency_key: idempotency_key.to_owned(),
            expected_entry_revision,
            mutation: ConversationMetadataMutation::rename(Some(title.to_owned()))
                .expect("valid equal-length metadata title"),
        })
        .await
        .expect("apply production metadata mutation");
    assert!(
        matches!(outcome, UpdateConversationMetadataOutcome::Applied { .. }),
        "fresh metadata mutation must apply: {outcome:?}"
    );
}

fn runtime_id(kind: RuntimeIdKind, seed: u8) -> RuntimeId {
    RuntimeId::from_bytes(kind, [seed; 16]).expect("valid typed runtime id")
}

fn read_old_descriptor(database: &Path, conversation_id: RuntimeId) -> Vec<u8> {
    let connection = Connection::open_with_flags(database, OpenFlags::SQLITE_OPEN_READ_ONLY)
        .expect("open read-only old descriptor observer");
    connection
        .query_row(
            "SELECT sealed_descriptor FROM conversations WHERE conversation_id = ?1",
            [&conversation_id.as_bytes()[..]],
            |row| row.get(0),
        )
        .expect("capture authenticated old descriptor ciphertext")
}

fn tamper_without_kek(
    database: &Path,
    conversation_id: RuntimeId,
    old_descriptor: &[u8],
    case: TamperCase,
) {
    // 此函数故意不接受 StorageKEK/RuntimeKeyBundle。它只模拟 store 已关闭后，
    // 无密钥攻击者对 SQLite 公共列与不透明 ciphertext 的磁盘级改写。
    let flags = OpenFlags::SQLITE_OPEN_READ_WRITE
        | OpenFlags::SQLITE_OPEN_NO_MUTEX
        | OpenFlags::SQLITE_OPEN_NOFOLLOW;
    let canonical_database = database
        .canonicalize()
        .expect("canonicalize offline metadata tamper database");
    let mut connection = Connection::open_with_flags(&canonical_database, flags)
        .expect("open offline metadata tamper connection");
    connection
        .pragma_update(None, "wal_autocheckpoint", 0_i64)
        .expect("disable offline tamper WAL autocheckpoint");
    configure_persistent_wal(&connection);
    assert_fixture_shape(&connection, conversation_id, old_descriptor);

    match case {
        TamperCase::MetadataToken => {
            bit_flip_latest_blob(&connection, "metadata_mutation_ledger", "metadata_token");
        }
        TamperCase::SealedRequest => {
            bit_flip_latest_blob(&connection, "metadata_mutation_ledger", "sealed_request");
        }
        TamperCase::SealedOutcome => {
            bit_flip_latest_blob(&connection, "metadata_mutation_ledger", "sealed_outcome");
        }
        TamperCase::DeleteMutation => {
            assert_eq!(
                connection
                    .execute(
                        "DELETE FROM metadata_mutation_ledger
                         WHERE conversation_id = ?1 AND applied_entry_revision = ?2",
                        params![&conversation_id.as_bytes()[..], REVISION_TWO],
                    )
                    .expect("delete latest metadata mutation without KEK"),
                1
            );
        }
        TamperCase::ConversationStateHead => {
            assert_eq!(
                connection
                    .execute(
                        "UPDATE conversation_state SET entry_revision = ?1
                         WHERE conversation_id = ?2",
                        params![REVISION_ONE, &conversation_id.as_bytes()[..]],
                    )
                    .expect("roll back conversation state head without KEK"),
                1
            );
        }
        TamperCase::RuntimeLedgerTotal => {
            assert_eq!(
                connection
                    .execute(
                        "UPDATE runtime_meta
                         SET metadata_mutation_count = metadata_mutation_count + 1
                         WHERE singleton = 1",
                        [],
                    )
                    .expect("diverge runtime metadata ledger total without KEK"),
                1
            );
        }
        TamperCase::CatalogDeltaTime => {
            assert_eq!(
                connection
                    .execute(
                        "UPDATE catalog_journal SET created_at_ms = created_at_ms - 1
                         WHERE catalog_revision = ?1",
                        [REVISION_TWO],
                    )
                    .expect("roll back catalog delta time without KEK"),
                1
            );
        }
        TamperCase::CatalogDeltaContent => {
            let mut sealed: Vec<u8> = connection
                .query_row(
                    "SELECT sealed_delta FROM catalog_journal WHERE catalog_revision = ?1",
                    [REVISION_TWO],
                    |row| row.get(0),
                )
                .expect("read latest catalog delta ciphertext");
            flip_last_bit(&mut sealed, "catalog delta ciphertext");
            assert_eq!(
                connection
                    .execute(
                        "UPDATE catalog_journal SET sealed_delta = ?1
                         WHERE catalog_revision = ?2",
                        params![sealed, REVISION_TWO],
                    )
                    .expect("tamper catalog delta content without KEK"),
                1
            );
        }
        TamperCase::OldDescriptorRestore => {
            assert_eq!(
                connection
                    .execute(
                        "UPDATE conversations SET sealed_descriptor = ?1
                         WHERE conversation_id = ?2",
                        params![old_descriptor, &conversation_id.as_bytes()[..]],
                    )
                    .expect("restore same-conversation old descriptor ciphertext without KEK"),
                1
            );
        }
        TamperCase::CrossRowCiphertextExchange => {
            exchange_metadata_ciphertexts(&mut connection, conversation_id);
        }
    }
    drop(connection);
}

fn assert_fixture_shape(
    connection: &Connection,
    conversation_id: RuntimeId,
    old_descriptor: &[u8],
) {
    let (row_count, metadata_total, state_head, latest_catalog, latest_descriptor): (
        i64,
        i64,
        String,
        String,
        Vec<u8>,
    ) = connection
        .query_row(
            "SELECT
                 (SELECT COUNT(*) FROM metadata_mutation_ledger
                  WHERE conversation_id = ?1),
                 (SELECT metadata_mutation_count FROM runtime_meta WHERE singleton = 1),
                 (SELECT entry_revision FROM conversation_state WHERE conversation_id = ?1),
                 (SELECT catalog_revision FROM conversations WHERE conversation_id = ?1),
                 (SELECT sealed_descriptor FROM conversations WHERE conversation_id = ?1)",
            [&conversation_id.as_bytes()[..]],
            |row| {
                Ok((
                    row.get(0)?,
                    row.get(1)?,
                    row.get(2)?,
                    row.get(3)?,
                    row.get(4)?,
                ))
            },
        )
        .expect("read metadata integrity fixture shape");
    assert_eq!(row_count, 2, "fixture needs two production ledger rows");
    assert_eq!(metadata_total, 2, "fixture runtime ledger must be nonempty");
    assert_eq!(state_head, REVISION_TWO);
    assert_eq!(latest_catalog, REVISION_TWO);
    assert_eq!(
        latest_descriptor.len(),
        old_descriptor.len(),
        "old descriptor rollback must preserve ciphertext length"
    );
    assert_ne!(
        latest_descriptor, old_descriptor,
        "production re-seal must produce a distinct latest descriptor"
    );
    let catalog_rows: i64 = connection
        .query_row(
            "SELECT COUNT(*) FROM catalog_journal
             WHERE catalog_revision IN (?1, ?2)",
            params![REVISION_ONE, REVISION_TWO],
            |row| row.get(0),
        )
        .expect("count metadata catalog deltas");
    assert_eq!(
        catalog_rows, 2,
        "fixture needs both mutation catalog deltas"
    );
}

fn bit_flip_latest_blob(connection: &Connection, table: &str, column: &str) {
    assert!(
        matches!(
            (table, column),
            ("metadata_mutation_ledger", "metadata_token")
                | ("metadata_mutation_ledger", "sealed_request")
                | ("metadata_mutation_ledger", "sealed_outcome")
        ),
        "test helper only permits fixed metadata ledger identifiers"
    );
    let select = format!("SELECT {column} FROM {table} WHERE applied_entry_revision = ?1");
    let mut blob: Vec<u8> = connection
        .query_row(&select, [REVISION_TWO], |row| row.get(0))
        .unwrap_or_else(|error| panic!("read latest {column}: {error}"));
    flip_last_bit(&mut blob, column);
    let update = format!("UPDATE {table} SET {column} = ?1 WHERE applied_entry_revision = ?2");
    assert_eq!(
        connection
            .execute(&update, params![blob, REVISION_TWO])
            .unwrap_or_else(|error| panic!("tamper latest {column}: {error}")),
        1
    );
}

fn flip_last_bit(blob: &mut [u8], label: &str) {
    *blob
        .last_mut()
        .unwrap_or_else(|| panic!("{label} must be nonempty")) ^= 0x80;
}

fn exchange_metadata_ciphertexts(connection: &mut Connection, conversation_id: RuntimeId) {
    let mut statement = connection
        .prepare(
            "SELECT applied_entry_revision, sealed_request, sealed_outcome
             FROM metadata_mutation_ledger
             WHERE conversation_id = ?1
             ORDER BY applied_entry_revision",
        )
        .expect("prepare metadata ciphertext exchange source");
    let rows = statement
        .query_map([&conversation_id.as_bytes()[..]], |row| {
            Ok((
                row.get::<_, String>(0)?,
                row.get::<_, Vec<u8>>(1)?,
                row.get::<_, Vec<u8>>(2)?,
            ))
        })
        .expect("query metadata ciphertext exchange source")
        .collect::<Result<Vec<_>, _>>()
        .expect("read metadata ciphertext exchange source");
    drop(statement);
    assert_eq!(rows.len(), 2, "exchange fixture must have exactly two rows");
    assert_eq!(
        (rows[0].0.as_str(), rows[1].0.as_str()),
        (REVISION_ONE, REVISION_TWO)
    );
    assert_eq!(
        rows[0].1.len(),
        rows[1].1.len(),
        "equal-length requests isolate AAD row binding"
    );
    assert_eq!(
        rows[0].2.len(),
        rows[1].2.len(),
        "equal-length outcomes isolate AAD row binding"
    );
    assert_ne!(rows[0].1, rows[1].1);
    assert_ne!(rows[0].2, rows[1].2);

    let transaction = connection
        .transaction_with_behavior(TransactionBehavior::Immediate)
        .expect("begin offline ciphertext exchange");
    assert_eq!(
        transaction
            .execute(
                "UPDATE metadata_mutation_ledger
                 SET sealed_request = ?1, sealed_outcome = ?2
                 WHERE conversation_id = ?3 AND applied_entry_revision = ?4",
                params![
                    &rows[1].1,
                    &rows[1].2,
                    &conversation_id.as_bytes()[..],
                    REVISION_ONE,
                ],
            )
            .expect("move revision-two ciphertexts into revision one"),
        1
    );
    assert_eq!(
        transaction
            .execute(
                "UPDATE metadata_mutation_ledger
                 SET sealed_request = ?1, sealed_outcome = ?2
                 WHERE conversation_id = ?3 AND applied_entry_revision = ?4",
                params![
                    &rows[0].1,
                    &rows[0].2,
                    &conversation_id.as_bytes()[..],
                    REVISION_TWO,
                ],
            )
            .expect("move revision-one ciphertexts into revision two"),
        1
    );
    transaction
        .commit()
        .expect("commit offline cross-row ciphertext exchange");
}

fn configure_persistent_wal(connection: &Connection) {
    let database_name = b"main\0";
    let mut enabled = 1_i32;
    // SAFETY: connection handle is live for the call, `database_name` is NUL-terminated,
    // and SQLite reads/writes exactly one i32 through the final pointer.
    let result = unsafe {
        rusqlite::ffi::sqlite3_file_control(
            connection.handle(),
            database_name.as_ptr().cast(),
            rusqlite::ffi::SQLITE_FCNTL_PERSIST_WAL,
            std::ptr::from_mut(&mut enabled).cast(),
        )
    };
    assert_eq!(
        result,
        rusqlite::ffi::SQLITE_OK,
        "enable persistent tamper WAL"
    );
}

macro_rules! metadata_integrity_case {
    ($name:ident, $case:expr) => {
        #[tokio::test]
        async fn $name() {
            let case = $case;
            Fixture::create(case)
                .await
                .tamper_and_assert_rejected(case)
                .await;
        }
    };
}

metadata_integrity_case!(
    metadata_token_tamper_fails_closed,
    TamperCase::MetadataToken
);
metadata_integrity_case!(
    sealed_request_tamper_fails_closed,
    TamperCase::SealedRequest
);
metadata_integrity_case!(
    sealed_outcome_tamper_fails_closed,
    TamperCase::SealedOutcome
);
metadata_integrity_case!(deleted_mutation_fails_closed, TamperCase::DeleteMutation);
metadata_integrity_case!(
    conversation_state_head_tamper_fails_closed,
    TamperCase::ConversationStateHead
);
metadata_integrity_case!(
    runtime_ledger_total_tamper_fails_closed,
    TamperCase::RuntimeLedgerTotal
);
metadata_integrity_case!(
    catalog_delta_time_tamper_fails_closed,
    TamperCase::CatalogDeltaTime
);
metadata_integrity_case!(
    catalog_delta_content_tamper_fails_closed,
    TamperCase::CatalogDeltaContent
);
metadata_integrity_case!(
    old_descriptor_restore_fails_closed,
    TamperCase::OldDescriptorRestore
);
metadata_integrity_case!(
    cross_row_ciphertext_exchange_fails_closed,
    TamperCase::CrossRowCiphertextExchange
);
