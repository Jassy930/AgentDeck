//! Runtime execution event integrity integration fixtures。
//!
//! 威胁场景：拥有 Runtime row keys 的旧进程或错误迁移可能写出 AEAD/MAC 均有效、但
//! 跨 row 语义不一致的 event；重启审计必须在接受任何恢复状态前 fail-close。

use std::fs;
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicU64, Ordering};

use agentdeck_protocol::runtime::identity::{CommandId, ConversationId, EntityId, EventId, ItemId};
use agentdeck_protocol::runtime::{RuntimeEvent, RuntimeEventBody, RuntimeFailure};
use agentdeck_protocol::{AgentItem, AgentItemMeta, TurnSummary};
use agentdeckd::runtime::model::MAX_RUNTIME_EVENT_BYTES;
use agentdeckd::runtime::store::cipher::{KeyWrapAad, RowAad, RuntimeKeyBundle};
use agentdeckd::runtime::store::{
    AcceptCommand, AcceptOutcome, AppendExecutionEvent, AppendExecutionEventOutcome,
    AuthorizeExecutionRelease, CommandTerminal, CompleteCommand, CompleteOutcome, EventRecord,
    ExecutionFence, IdempotencyOwner, NewConversation, RUNTIME_CRYPTO_CONTEXT_VERSION,
    RUNTIME_SCHEMA_FAMILY, RuntimeId, RuntimeIdKind, RuntimeStoreConfig, RuntimeStoreError,
    RuntimeStoreHandle, StartCommand, StartOutcome,
};
use agentdeckd::security::{MemoryKeyStore, StorageKek, load_or_create_storage_kek};
use rusqlite::{Connection, params};
use sha2::{Digest, Sha256};

use super::{runtime_descriptor, store_admission};

#[path = "runtime_configuration.rs"]
mod runtime_configuration;

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
            "agentdeckd-runtime-event-tamper-{label}-{}-{sequence}",
            std::process::id()
        ));
        let _ = fs::remove_dir_all(&path);
        fs::create_dir(&path).expect("create runtime event tamper root");
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            fs::set_permissions(&path, fs::Permissions::from_mode(0o700))
                .expect("secure runtime event tamper root");
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
            .expect("load runtime event tamper StorageKEK")
    }
}

impl Drop for TestRoot {
    fn drop(&mut self) {
        let _ = fs::remove_dir_all(&self.path);
    }
}

pub(crate) struct RuntimeEventTamperFixture {
    root: TestRoot,
    keys: MemoryKeyStore,
    pub(crate) conversation_id: RuntimeId,
    pub(crate) started: EventRecord,
    pub(crate) item: EventRecord,
    pub(crate) terminal: EventRecord,
}

impl RuntimeEventTamperFixture {
    pub(crate) async fn create(label: &str, seed: u8) -> Self {
        Self::create_inner(label, seed, false).await
    }

    pub(crate) async fn create_with_fixed_error_sized_item(label: &str, seed: u8) -> Self {
        Self::create_inner(label, seed, true).await
    }

    async fn create_inner(label: &str, seed: u8, match_fixed_error_size: bool) -> Self {
        let root = TestRoot::new(label);
        let keys = MemoryKeyStore::new();
        let store = RuntimeStoreHandle::open(
            RuntimeStoreConfig::new(root.database()),
            root.storage_kek(&keys),
        )
        .await
        .expect("open runtime event tamper fixture");
        let conversation_id = runtime_id(RuntimeIdKind::Conversation, seed);
        store
            .create_conversation(NewConversation {
                conversation_id,
                adapter_state_key: runtime_id(RuntimeIdKind::AdapterState, seed.wrapping_add(1)),
                descriptor: runtime_descriptor::descriptor(b"runtime event tamper fixture"),
            })
            .await
            .expect("create tamper conversation");
        runtime_configuration::configure_codex_revision_one(&store, conversation_id).await;
        let command = match store
            .accept_command(AcceptCommand {
                conversation_id,
                owner: IdempotencyOwner::Local {
                    machine_trust_domain: [0x11; 32],
                    uid: 501,
                    client_installation_id: [0x22; 16],
                },
                idempotency_key: format!("runtime-event-tamper-{seed}"),
                expected_configuration_revision: 1,
                payload: b"real tamper fixture prompt".to_vec(),
            })
            .await
            .expect("accept tamper command")
        {
            AcceptOutcome::Accepted { command, .. } => command,
            AcceptOutcome::Replayed { .. } => panic!("fresh tamper command cannot replay"),
        };
        let daemon_boot_id = runtime_id(RuntimeIdKind::DaemonBoot, seed.wrapping_add(2));
        let execution_nonce = format!("runtime-event-tamper-nonce-{seed}").into_bytes();
        let (turn_id, started) = match store
            .mark_started_with_event(StartCommand {
                conversation_id,
                command_id: command.command_id,
                daemon_boot_id,
                execution_nonce: execution_nonce.clone(),
            })
            .await
            .expect("start tamper command")
        {
            StartOutcome::Started { intent, event, .. } => (intent.turn_id, event),
            StartOutcome::Replayed { .. } => panic!("fresh tamper start cannot replay"),
        };
        store
            .persist_execution_fence(ExecutionFence {
                command_id: command.command_id,
                daemon_boot_id,
                execution_nonce: execution_nonce.clone(),
                process_group_id: i64::from(seed) + 20_000,
                leader_pid: i64::from(seed) + 20_000,
                leader_start_time: u64::from(seed) + 20_000,
                payload: b"real released tamper fence".to_vec(),
            })
            .await
            .expect("persist tamper fence");
        store
            .authorize_execution_release(AuthorizeExecutionRelease {
                command_id: command.command_id,
                daemon_boot_id,
                execution_nonce,
            })
            .await
            .expect("release tamper execution");
        let item_event_id = runtime_id(RuntimeIdKind::Event, seed.wrapping_add(3));
        let (item_id, entity_id, item_text) = if match_fixed_error_size {
            let error = RuntimeEvent::new(
                ConversationId::new(conversation_id.to_canonical_string()),
                EventId::new(item_event_id.to_canonical_string()),
                started
                    .event_seq
                    .checked_add(1)
                    .expect("fixture event sequence has headroom"),
                Some(CommandId::new(command.command_id.to_canonical_string())),
                None,
                None,
                RuntimeEventBody::Error {
                    failure: RuntimeFailure::new(
                        agentdeck_protocol::runtime::failure::DAEMON_RUNTIME_EXECUTION_FAILED,
                        "agent execution failed",
                    ),
                },
            )
            .expect("fixed command-bound Error is protocol-valid");
            let error_len = serde_json::to_vec(&error)
                .expect("encode fixed Error sizing target")
                .len();
            let item_id = ItemId::new("i");
            let entity_id = EntityId::new("e");
            let empty_item = RuntimeEvent::new(
                ConversationId::new(conversation_id.to_canonical_string()),
                EventId::new(item_event_id.to_canonical_string()),
                started
                    .event_seq
                    .checked_add(1)
                    .expect("fixture event sequence has headroom"),
                Some(CommandId::new(command.command_id.to_canonical_string())),
                Some(item_id.clone()),
                Some(entity_id.clone()),
                RuntimeEventBody::Item {
                    item: AgentItem::AssistantMessage {
                        text: String::new(),
                        meta: AgentItemMeta::default(),
                    },
                },
            )
            .expect("minimal sizing Item is protocol-valid");
            let item_len = serde_json::to_vec(&empty_item)
                .expect("encode minimal sizing Item")
                .len();
            let text_len = error_len
                .checked_sub(item_len)
                .expect("fixed Error must fit a padded minimal Item row");
            (item_id, entity_id, "x".repeat(text_len))
        } else {
            (
                ItemId::new("tamper-item-id"),
                EntityId::new("tamper-entity-id"),
                "real released adapter output".to_owned(),
            )
        };
        let item = match store
            .append_execution_event(AppendExecutionEvent::item(
                conversation_id,
                command.command_id,
                turn_id,
                item_event_id,
                item_id,
                entity_id,
                AgentItem::AssistantMessage {
                    text: item_text,
                    meta: AgentItemMeta::default(),
                },
            ))
            .await
            .expect("append real released item")
        {
            AppendExecutionEventOutcome::Appended { event } => event,
            AppendExecutionEventOutcome::Replayed { .. } => {
                panic!("fresh tamper item cannot replay")
            }
        };
        let terminal = match store
            .complete_command_with_event(CompleteCommand {
                conversation_id,
                command_id: command.command_id,
                turn_id,
                terminal: CommandTerminal::completed(TurnSummary {
                    total_input_tokens: Some(7),
                    total_output_tokens: Some(11),
                    elapsed_ms: 13,
                }),
            })
            .await
            .expect("complete real released execution")
        {
            CompleteOutcome::Completed { event, .. } => event,
            CompleteOutcome::Replayed { .. } => panic!("fresh tamper terminal cannot replay"),
        };
        assert_eq!(
            (started.event_seq, item.event_seq, terminal.event_seq),
            (1, 2, 3)
        );
        store.shutdown().await.expect("shutdown tamper fixture");
        Self {
            root,
            keys,
            conversation_id,
            started,
            item,
            terminal,
        }
    }

    pub(crate) async fn reopen_error(&self) -> RuntimeStoreError {
        RuntimeStoreHandle::open(
            RuntimeStoreConfig::new(self.root.database()),
            self.root.storage_kek(&self.keys),
        )
        .await
        .expect_err("corrupted runtime event store must fail closed")
    }

    pub(crate) fn flip_item_ciphertext(&self) {
        let connection = self.connection();
        let mut sealed: Vec<u8> = connection
            .query_row(
                "SELECT sealed_event FROM event_journal WHERE event_id = ?1",
                [&self.item.event_id.as_bytes()[..]],
                |row| row.get(0),
            )
            .expect("read sealed item ciphertext");
        let last = sealed.last_mut().expect("sealed event is non-empty");
        *last ^= 0x80;
        assert_eq!(
            connection
                .execute(
                    "UPDATE event_journal SET sealed_event = ?1 WHERE event_id = ?2",
                    params![sealed, &self.item.event_id.as_bytes()[..]],
                )
                .expect("flip sealed event ciphertext"),
            1
        );
        checkpoint(&connection);
    }

    pub(crate) fn delete_item_but_leave_stream_orphan(&self) {
        let connection = self.connection();
        connection
            .execute_batch("PRAGMA foreign_keys = OFF")
            .expect("disable FK for deletion corruption fixture");
        assert_eq!(
            connection
                .execute(
                    "DELETE FROM event_journal WHERE event_id = ?1",
                    [&self.item.event_id.as_bytes()[..]],
                )
                .expect("delete item audit row"),
            1
        );
        let orphan_count: i64 = connection
            .query_row(
                "SELECT COUNT(*) FROM event_stream_index WHERE event_id = ?1",
                [&self.item.event_id.as_bytes()[..]],
                |row| row.get(0),
            )
            .expect("count orphan stream membership");
        assert_eq!(orphan_count, 1);
        checkpoint(&connection);
    }

    pub(crate) fn reseal_same_length(&self, event: &EventRecord, payload: &[u8]) {
        assert_eq!(
            payload.len(),
            event.payload.len(),
            "fixture keeps row metadata exact"
        );
        let connection = self.connection();
        let (bundle, database_id) = self.load_keys(&connection);
        let sealed = seal_event(&bundle, database_id, event.event_id, payload);
        assert_eq!(
            connection
                .execute(
                    "UPDATE event_journal SET sealed_event = ?1 WHERE event_id = ?2",
                    params![sealed, &event.event_id.as_bytes()[..]],
                )
                .expect("replace authenticated same-length event body"),
            1
        );
        checkpoint(&connection);
    }

    pub(crate) fn make_authenticated_orphan(&self, orphan_command_id: RuntimeId) {
        let mut wire: RuntimeEvent =
            serde_json::from_slice(&self.item.payload).expect("decode real Item event");
        wire.command_id = Some(CommandId::new(orphan_command_id.to_canonical_string()));
        let payload = serde_json::to_vec(&wire).expect("encode orphan Item event");
        assert_eq!(payload.len(), self.item.payload.len());

        let connection = self.connection();
        connection
            .execute_batch("PRAGMA foreign_keys = OFF")
            .expect("disable FK for authenticated orphan fixture");
        let (bundle, database_id) = self.load_keys(&connection);
        assert_pristine_production_tokens(&connection, &bundle, self.conversation_id, &self.item);
        let sealed = seal_event(&bundle, database_id, self.item.event_id, &payload);
        let metadata = event_metadata_token(
            &bundle,
            self.item.conversation_id,
            self.item.event_id,
            self.item.event_seq,
            Some(orphan_command_id),
            payload.len(),
            self.item.created_at_ms,
        );
        assert_eq!(
            connection
                .execute(
                    "UPDATE event_journal
                     SET command_id = ?1, metadata_token = ?2, sealed_event = ?3
                     WHERE event_id = ?4",
                    params![
                        &orphan_command_id.as_bytes()[..],
                        &metadata[..],
                        sealed,
                        &self.item.event_id.as_bytes()[..],
                    ],
                )
                .expect("persist authenticated orphan Item"),
            1
        );
        checkpoint(&connection);
    }

    pub(crate) fn make_authenticated_sequence_gap(&self) {
        const GAP_SEQ: u64 = 4;
        let encoded_gap = encode_sequence(GAP_SEQ);
        let mut wire: RuntimeEvent =
            serde_json::from_slice(&self.item.payload).expect("decode Item for gap fixture");
        wire.event_seq = GAP_SEQ;
        let payload = serde_json::to_vec(&wire).expect("encode Item with authenticated gap seq");
        assert_eq!(payload.len(), self.item.payload.len());

        let connection = self.connection();
        connection
            .execute_batch("PRAGMA foreign_keys = OFF; BEGIN IMMEDIATE")
            .expect("begin authenticated gap rewrite");
        let (bundle, database_id) = self.load_keys(&connection);
        assert_pristine_production_tokens(&connection, &bundle, self.conversation_id, &self.item);
        let sealed = seal_event(&bundle, database_id, self.item.event_id, &payload);
        let event_metadata = event_metadata_token(
            &bundle,
            self.item.conversation_id,
            self.item.event_id,
            GAP_SEQ,
            self.item.command_id,
            payload.len(),
            self.item.created_at_ms,
        );
        assert_eq!(
            connection
                .execute(
                    "UPDATE event_journal
                     SET event_seq = ?1, metadata_token = ?2, sealed_event = ?3
                     WHERE event_id = ?4",
                    params![
                        &encoded_gap,
                        &event_metadata[..],
                        sealed,
                        &self.item.event_id.as_bytes()[..],
                    ],
                )
                .expect("move authenticated event row across one sequence"),
            1
        );
        let stream_metadata = stream_index_token(
            &bundle,
            self.item.conversation_id,
            self.item.event_id,
            GAP_SEQ,
            payload.len(),
            self.item.created_at_ms,
        );
        assert_eq!(
            connection
                .execute(
                    "UPDATE event_stream_index
                     SET event_seq = ?1, metadata_token = ?2
                     WHERE event_id = ?3",
                    params![
                        &encoded_gap,
                        &stream_metadata[..],
                        &self.item.event_id.as_bytes()[..],
                    ],
                )
                .expect("move authenticated stream membership"),
            1
        );
        assert_eq!(
            connection
                .execute(
                    "UPDATE conversations SET event_high_water = ?1
                     WHERE conversation_id = ?2",
                    params![&encoded_gap, &self.conversation_id.as_bytes()[..]],
                )
                .expect("move conversation HWM past a gap"),
            1
        );
        reauthenticate_conversation(&connection, &bundle, self.conversation_id);
        reauthenticate_retention(&connection, &bundle, self.conversation_id, &encoded_gap);
        connection
            .execute_batch("COMMIT")
            .expect("commit authenticated gap corruption");
        checkpoint(&connection);
    }

    fn connection(&self) -> Connection {
        Connection::open(self.root.database()).expect("open closed runtime tamper database")
    }

    fn load_keys(&self, connection: &Connection) -> (RuntimeKeyBundle, [u8; 16]) {
        load_keys(connection, &self.root.storage_kek(&self.keys))
    }
}

pub(crate) struct RuntimeStartedReleaseTamperFixture {
    root: TestRoot,
    keys: MemoryKeyStore,
    conversation_id: RuntimeId,
    command_id: RuntimeId,
    turn_id: RuntimeId,
    daemon_boot_id: RuntimeId,
    execution_nonce: Vec<u8>,
    pub(crate) started: EventRecord,
}

impl RuntimeStartedReleaseTamperFixture {
    pub(crate) async fn create(label: &str, seed: u8) -> Self {
        let root = TestRoot::new(label);
        let keys = MemoryKeyStore::new();
        let store = RuntimeStoreHandle::open(
            RuntimeStoreConfig::new(root.database()),
            root.storage_kek(&keys),
        )
        .await
        .expect("open started release tamper fixture");
        let conversation_id = runtime_id(RuntimeIdKind::Conversation, seed);
        store
            .create_conversation(NewConversation {
                conversation_id,
                adapter_state_key: runtime_id(RuntimeIdKind::AdapterState, seed.wrapping_add(1)),
                descriptor: runtime_descriptor::descriptor(b"started release tamper fixture"),
            })
            .await
            .expect("create started release tamper conversation");
        runtime_configuration::configure_codex_revision_one(&store, conversation_id).await;
        let command = match store
            .accept_command(AcceptCommand {
                conversation_id,
                owner: IdempotencyOwner::Local {
                    machine_trust_domain: [0x33; 32],
                    uid: 501,
                    client_installation_id: [0x44; 16],
                },
                idempotency_key: format!("started-release-tamper-{seed}"),
                expected_configuration_revision: 1,
                payload: b"started-only tamper prompt".to_vec(),
            })
            .await
            .expect("accept started release tamper command")
        {
            AcceptOutcome::Accepted { command, .. } => command,
            AcceptOutcome::Replayed { .. } => panic!("fresh started tamper command cannot replay"),
        };
        let daemon_boot_id = runtime_id(RuntimeIdKind::DaemonBoot, seed.wrapping_add(2));
        let execution_nonce = format!("started-release-tamper-nonce-{seed}").into_bytes();
        let (turn_id, started) = match store
            .mark_started_with_event(StartCommand {
                conversation_id,
                command_id: command.command_id,
                daemon_boot_id,
                execution_nonce: execution_nonce.clone(),
            })
            .await
            .expect("start started release tamper command")
        {
            StartOutcome::Started { intent, event, .. } => (intent.turn_id, event),
            StartOutcome::Replayed { .. } => panic!("fresh started tamper start cannot replay"),
        };
        store
            .persist_execution_fence(ExecutionFence {
                command_id: command.command_id,
                daemon_boot_id,
                execution_nonce: execution_nonce.clone(),
                process_group_id: i64::from(seed) + 30_000,
                leader_pid: i64::from(seed) + 30_000,
                leader_start_time: u64::from(seed) + 30_000,
                payload: b"started-only released tamper fence".to_vec(),
            })
            .await
            .expect("persist started release tamper fence");
        store
            .authorize_execution_release(AuthorizeExecutionRelease {
                command_id: command.command_id,
                daemon_boot_id,
                execution_nonce: execution_nonce.clone(),
            })
            .await
            .expect("release started-only tamper execution");
        store
            .shutdown()
            .await
            .expect("shutdown started release tamper fixture");
        Self {
            root,
            keys,
            conversation_id,
            command_id: command.command_id,
            turn_id,
            daemon_boot_id,
            execution_nonce,
            started,
        }
    }

    pub(crate) fn resign_release_time(&self, release_authorized_at_ms: u64) {
        let connection = Connection::open(self.root.database())
            .expect("open closed started release tamper database");
        let (bundle, _) = load_keys(&connection, &self.root.storage_kek(&self.keys));
        rewrite_release_time(
            &connection,
            &bundle,
            self.command_id,
            self.daemon_boot_id,
            &self.execution_nonce,
            release_authorized_at_ms,
        );
        checkpoint(&connection);
    }

    pub(crate) async fn complete_without_dynamic_item(&self) -> EventRecord {
        let store = RuntimeStoreHandle::open(
            RuntimeStoreConfig::new(self.root.database()),
            self.root.storage_kek(&self.keys),
        )
        .await
        .expect("reopen started release fixture for terminal");
        let terminal = match store
            .complete_command_with_event(CompleteCommand {
                conversation_id: self.conversation_id,
                command_id: self.command_id,
                turn_id: self.turn_id,
                terminal: CommandTerminal::completed(TurnSummary {
                    total_input_tokens: Some(3),
                    total_output_tokens: Some(5),
                    elapsed_ms: 8,
                }),
            })
            .await
            .expect("complete released fixture without dynamic item")
        {
            CompleteOutcome::Completed { event, .. } => event,
            CompleteOutcome::Replayed { .. } => {
                panic!("fresh terminal-only tamper completion cannot replay")
            }
        };
        store
            .shutdown()
            .await
            .expect("shutdown terminal-only release fixture");
        terminal
    }

    pub(crate) async fn reopen_error(&self) -> RuntimeStoreError {
        RuntimeStoreHandle::open(
            RuntimeStoreConfig::new(self.root.database()),
            self.root.storage_kek(&self.keys),
        )
        .await
        .expect_err("corrupted started release store must fail closed")
    }
}

pub(crate) fn runtime_id(kind: RuntimeIdKind, seed: u8) -> RuntimeId {
    RuntimeId::from_bytes(kind, [seed; 16]).expect("non-zero runtime tamper id")
}

fn load_keys(connection: &Connection, storage_kek: &StorageKek) -> (RuntimeKeyBundle, [u8; 16]) {
    let (database_id, wrapped): (Vec<u8>, Vec<u8>) = connection
        .query_row(
            "SELECT database_id, wrapped_key_bundle FROM runtime_meta WHERE singleton = 1",
            [],
            |row| Ok((row.get(0)?, row.get(1)?)),
        )
        .expect("read wrapped Runtime key bundle");
    let database_id: [u8; 16] = database_id.try_into().expect("fixed Runtime database id");
    let bundle = RuntimeKeyBundle::unwrap(
        storage_kek,
        &KeyWrapAad {
            schema_family: RUNTIME_SCHEMA_FAMILY.as_bytes(),
            schema_version: RUNTIME_CRYPTO_CONTEXT_VERSION,
            database_id: &database_id,
        },
        &wrapped,
    )
    .expect("unwrap Runtime event tamper keys");
    (bundle, database_id)
}

fn seal_event(
    bundle: &RuntimeKeyBundle,
    database_id: [u8; 16],
    event_id: RuntimeId,
    payload: &[u8],
) -> Vec<u8> {
    bundle
        .row_cipher()
        .seal_bounded(
            &RowAad {
                schema_family: RUNTIME_SCHEMA_FAMILY.as_bytes(),
                schema_version: RUNTIME_CRYPTO_CONTEXT_VERSION,
                database_id: &database_id,
                table: b"event_journal",
                primary_key: event_id.as_bytes(),
                column: b"sealed_event",
            },
            payload,
            MAX_RUNTIME_EVENT_BYTES,
        )
        .expect("seal authenticated event corruption")
}

fn canonical_fields(fields: &[&[u8]]) -> Vec<u8> {
    let mut encoded = b"ADF1".to_vec();
    for field in fields {
        encoded.extend_from_slice(
            &u32::try_from(field.len())
                .expect("tamper field length fits u32")
                .to_be_bytes(),
        );
        encoded.extend_from_slice(field);
    }
    encoded
}

fn optional_blob(value: Option<&[u8]>) -> Vec<u8> {
    let mut encoded = Vec::with_capacity(1 + value.map_or(0, <[u8]>::len));
    match value {
        None => encoded.push(0),
        Some(value) => {
            encoded.push(1);
            encoded.extend_from_slice(value);
        }
    }
    encoded
}

fn optional_text(value: Option<&str>) -> Vec<u8> {
    optional_blob(value.map(str::as_bytes))
}

fn metadata_token(bundle: &RuntimeKeyBundle, domain: &[u8], fields: &[&[u8]]) -> [u8; 32] {
    *bundle
        .blind_index(domain, &canonical_fields(fields))
        .expect("authenticate tamper metadata")
        .as_bytes()
}

fn rewrite_release_time(
    connection: &Connection,
    bundle: &RuntimeKeyBundle,
    command_id: RuntimeId,
    daemon_boot_id: RuntimeId,
    execution_nonce: &[u8],
    release_authorized_at_ms: u64,
) {
    let (current_time, current_token): (i64, Vec<u8>) = connection
        .query_row(
            "SELECT release_authorized_at_ms, release_token
             FROM execution_fences WHERE command_id = ?1",
            [&command_id.as_bytes()[..]],
            |row| Ok((row.get(0)?, row.get(1)?)),
        )
        .expect("read production release row before tamper");
    let current_time =
        u64::try_from(current_time).expect("production release time is non-negative");
    assert_eq!(
        current_token,
        release_token(
            bundle,
            command_id,
            daemon_boot_id,
            execution_nonce,
            current_time,
        ),
        "tamper helper must first reproduce the production release token"
    );
    let release_token = release_token(
        bundle,
        command_id,
        daemon_boot_id,
        execution_nonce,
        release_authorized_at_ms,
    );
    assert_eq!(
        connection
            .execute(
                "UPDATE execution_fences
                 SET release_authorized_at_ms = ?1, release_token = ?2
                 WHERE command_id = ?3",
                params![
                    i64::try_from(release_authorized_at_ms)
                        .expect("fixture release time fits SQLite i64"),
                    &release_token[..],
                    &command_id.as_bytes()[..],
                ],
            )
            .expect("rewrite authenticated release time"),
        1
    );
}

fn release_token(
    bundle: &RuntimeKeyBundle,
    command_id: RuntimeId,
    daemon_boot_id: RuntimeId,
    execution_nonce: &[u8],
    release_authorized_at_ms: u64,
) -> Vec<u8> {
    let authorized_at = release_authorized_at_ms.to_be_bytes();
    metadata_token(
        bundle,
        b"execution.release.v1",
        &[
            command_id.as_bytes(),
            daemon_boot_id.as_bytes(),
            execution_nonce,
            &authorized_at,
        ],
    )
    .to_vec()
}

fn encode_sequence(value: u64) -> String {
    format!("{value:020}")
}

fn event_metadata_token(
    bundle: &RuntimeKeyBundle,
    conversation_id: RuntimeId,
    event_id: RuntimeId,
    event_seq: u64,
    command_id: Option<RuntimeId>,
    logical_bytes: usize,
    created_at_ms: u64,
) -> [u8; 32] {
    let command = optional_blob(
        command_id
            .as_ref()
            .map(|command_id| &command_id.as_bytes()[..]),
    );
    metadata_token(
        bundle,
        b"event.metadata.v1",
        &[
            conversation_id.as_bytes(),
            event_id.as_bytes(),
            encode_sequence(event_seq).as_bytes(),
            &command,
            &u64::try_from(logical_bytes)
                .expect("event bytes fit u64")
                .to_be_bytes(),
            &created_at_ms.to_be_bytes(),
        ],
    )
}

fn stream_index_token(
    bundle: &RuntimeKeyBundle,
    conversation_id: RuntimeId,
    event_id: RuntimeId,
    event_seq: u64,
    logical_bytes: usize,
    created_at_ms: u64,
) -> [u8; 32] {
    metadata_token(
        bundle,
        b"event.stream-index.v1",
        &[
            conversation_id.as_bytes(),
            encode_sequence(event_seq).as_bytes(),
            event_id.as_bytes(),
            &u64::try_from(logical_bytes)
                .expect("stream bytes fit u64")
                .to_be_bytes(),
            &created_at_ms.to_be_bytes(),
        ],
    )
}

#[allow(clippy::too_many_arguments)]
fn conversation_metadata_token(
    bundle: &RuntimeKeyBundle,
    conversation_id: RuntimeId,
    adapter_state_key: &[u8],
    catalog_revision: &str,
    command_high_water: Option<&str>,
    event_high_water: Option<&str>,
    accepted_count: i64,
    lifecycle: &str,
    created_at_ms: i64,
    updated_at_ms: i64,
) -> [u8; 32] {
    let command_high_water = optional_text(command_high_water);
    let event_high_water = optional_text(event_high_water);
    metadata_token(
        bundle,
        b"conversation.metadata.v1",
        &[
            conversation_id.as_bytes(),
            adapter_state_key,
            catalog_revision.as_bytes(),
            &command_high_water,
            &event_high_water,
            &u32::try_from(accepted_count)
                .expect("accepted count is non-negative")
                .to_be_bytes(),
            lifecycle.as_bytes(),
            &u64::try_from(created_at_ms)
                .expect("created time is non-negative")
                .to_be_bytes(),
            &u64::try_from(updated_at_ms)
                .expect("updated time is non-negative")
                .to_be_bytes(),
        ],
    )
}

fn retention_metadata_token(
    bundle: &RuntimeKeyBundle,
    conversation_id: RuntimeId,
    indexed_through: &str,
    oldest: Option<&str>,
    retained_count: i64,
    retained_bytes: i64,
    range_digest: &[u8; 32],
) -> [u8; 32] {
    let indexed = optional_text(Some(indexed_through));
    let oldest = optional_text(oldest);
    metadata_token(
        bundle,
        b"event.retention.v1",
        &[
            conversation_id.as_bytes(),
            &indexed,
            &oldest,
            &u64::try_from(retained_count)
                .expect("retention count is non-negative")
                .to_be_bytes(),
            &u64::try_from(retained_bytes)
                .expect("retention bytes are non-negative")
                .to_be_bytes(),
            range_digest,
        ],
    )
}

fn assert_pristine_production_tokens(
    connection: &Connection,
    bundle: &RuntimeKeyBundle,
    conversation_id: RuntimeId,
    event: &EventRecord,
) {
    // 先用 production 写出的未改动行校准本 helper 的 domain、字段顺序与编码；否则
    // helper 漂移后造出的 MAC 无效行也会 fail-close，让 semantic tamper 测试假绿。
    let stored_event_token: Vec<u8> = connection
        .query_row(
            "SELECT metadata_token FROM event_journal WHERE event_id = ?1",
            [&event.event_id.as_bytes()[..]],
            |row| row.get(0),
        )
        .expect("read pristine production event token");
    assert_eq!(
        stored_event_token,
        event_metadata_token(
            bundle,
            event.conversation_id,
            event.event_id,
            event.event_seq,
            event.command_id,
            event.payload.len(),
            event.created_at_ms,
        )
    );

    let (stream_seq, stream_bytes, stream_created_at, stored_stream_token): (
        String,
        i64,
        i64,
        Vec<u8>,
    ) = connection
        .query_row(
            "SELECT event_seq, logical_event_bytes, created_at_ms, metadata_token
             FROM event_stream_index WHERE event_id = ?1",
            [&event.event_id.as_bytes()[..]],
            |row| Ok((row.get(0)?, row.get(1)?, row.get(2)?, row.get(3)?)),
        )
        .expect("read pristine production stream token");
    assert_eq!(stream_seq, encode_sequence(event.event_seq));
    assert_eq!(
        u64::try_from(stream_bytes).expect("stream bytes are non-negative"),
        u64::try_from(event.payload.len()).expect("event bytes fit u64")
    );
    assert_eq!(
        u64::try_from(stream_created_at).expect("stream time is non-negative"),
        event.created_at_ms
    );
    assert_eq!(
        stored_stream_token,
        stream_index_token(
            bundle,
            event.conversation_id,
            event.event_id,
            event.event_seq,
            event.payload.len(),
            event.created_at_ms,
        )
    );

    type ConversationRaw = (
        Vec<u8>,
        String,
        Option<String>,
        Option<String>,
        String,
        i64,
        i64,
        i64,
        Vec<u8>,
    );
    let conversation: ConversationRaw = connection
        .query_row(
            "SELECT adapter_state_key, catalog_revision, command_high_water,
                    event_high_water, lifecycle, created_at_ms, updated_at_ms,
                    accepted_count, metadata_token
             FROM conversations WHERE conversation_id = ?1",
            [&conversation_id.as_bytes()[..]],
            |row| {
                Ok((
                    row.get(0)?,
                    row.get(1)?,
                    row.get(2)?,
                    row.get(3)?,
                    row.get(4)?,
                    row.get(5)?,
                    row.get(6)?,
                    row.get(7)?,
                    row.get(8)?,
                ))
            },
        )
        .expect("read pristine production conversation token");
    let expected_conversation_token = conversation_metadata_token(
        bundle,
        conversation_id,
        &conversation.0,
        &conversation.1,
        conversation.2.as_deref(),
        conversation.3.as_deref(),
        conversation.7,
        &conversation.4,
        conversation.5,
        conversation.6,
    );
    assert_eq!(conversation.8, expected_conversation_token);

    let (oldest, indexed_through, retained_count, retained_bytes, stored_range, stored_token): (
        Option<String>,
        String,
        i64,
        i64,
        Vec<u8>,
        Vec<u8>,
    ) = connection
        .query_row(
            "SELECT oldest_retained_event_seq, indexed_through_event_seq,
                    retained_event_count, retained_logical_bytes, range_digest,
                    metadata_token
             FROM event_retention WHERE conversation_id = ?1",
            [&conversation_id.as_bytes()[..]],
            |row| {
                Ok((
                    row.get(0)?,
                    row.get(1)?,
                    row.get(2)?,
                    row.get(3)?,
                    row.get(4)?,
                    row.get(5)?,
                ))
            },
        )
        .expect("read pristine production retention token");
    let (actual_oldest, actual_count, actual_bytes): (Option<String>, i64, i64) = connection
        .query_row(
            "SELECT MIN(event_seq), COUNT(*), COALESCE(SUM(logical_event_bytes), 0)
             FROM event_stream_index WHERE conversation_id = ?1",
            [&conversation_id.as_bytes()[..]],
            |row| Ok((row.get(0)?, row.get(1)?, row.get(2)?)),
        )
        .expect("read pristine production retention totals");
    assert_eq!(
        (oldest.as_ref(), retained_count, retained_bytes),
        (actual_oldest.as_ref(), actual_count, actual_bytes)
    );
    let computed_range = event_range_digest(connection, conversation_id);
    assert_eq!(stored_range, computed_range);
    let expected_retention_token = retention_metadata_token(
        bundle,
        conversation_id,
        &indexed_through,
        oldest.as_deref(),
        retained_count,
        retained_bytes,
        &computed_range,
    );
    assert_eq!(stored_token, expected_retention_token);
}

fn reauthenticate_conversation(
    connection: &Connection,
    bundle: &RuntimeKeyBundle,
    conversation_id: RuntimeId,
) {
    type Raw = (
        Vec<u8>,
        String,
        Option<String>,
        Option<String>,
        String,
        i64,
        i64,
        i64,
    );
    let raw: Raw = connection
        .query_row(
            "SELECT adapter_state_key, catalog_revision, command_high_water,
                    event_high_water, lifecycle, created_at_ms, updated_at_ms, accepted_count
             FROM conversations WHERE conversation_id = ?1",
            [&conversation_id.as_bytes()[..]],
            |row| {
                Ok((
                    row.get(0)?,
                    row.get(1)?,
                    row.get(2)?,
                    row.get(3)?,
                    row.get(4)?,
                    row.get(5)?,
                    row.get(6)?,
                    row.get(7)?,
                ))
            },
        )
        .expect("read conversation tamper metadata");
    let token = conversation_metadata_token(
        bundle,
        conversation_id,
        &raw.0,
        &raw.1,
        raw.2.as_deref(),
        raw.3.as_deref(),
        raw.7,
        &raw.4,
        raw.5,
        raw.6,
    );
    assert_eq!(
        connection
            .execute(
                "UPDATE conversations SET metadata_token = ?1 WHERE conversation_id = ?2",
                params![&token[..], &conversation_id.as_bytes()[..]],
            )
            .expect("persist authenticated conversation HWM"),
        1
    );
}

fn event_range_digest(connection: &Connection, conversation_id: RuntimeId) -> [u8; 32] {
    let mut digest = Sha256::new();
    digest.update(b"agentdeck.event-retention.range.v1");
    let mut statement = connection
        .prepare(
            "SELECT event_seq, event_id, logical_event_bytes, created_at_ms, metadata_token
             FROM event_stream_index WHERE conversation_id = ?1 ORDER BY event_seq",
        )
        .expect("prepare stream range digest");
    let rows = statement
        .query_map([&conversation_id.as_bytes()[..]], |row| {
            Ok((
                row.get::<_, String>(0)?,
                row.get::<_, Vec<u8>>(1)?,
                row.get::<_, i64>(2)?,
                row.get::<_, i64>(3)?,
                row.get::<_, Vec<u8>>(4)?,
            ))
        })
        .expect("query stream range digest");
    for row in rows {
        let (event_seq, event_id, logical_bytes, created_at_ms, token) =
            row.expect("read stream range row");
        for field in [
            event_seq.as_bytes(),
            event_id.as_slice(),
            &logical_bytes.to_be_bytes(),
            &created_at_ms.to_be_bytes(),
            token.as_slice(),
        ] {
            digest.update(
                u32::try_from(field.len())
                    .expect("range field fits u32")
                    .to_be_bytes(),
            );
            digest.update(field);
        }
    }
    digest.finalize().into()
}

fn reauthenticate_retention(
    connection: &Connection,
    bundle: &RuntimeKeyBundle,
    conversation_id: RuntimeId,
    indexed_through: &str,
) {
    let (oldest, count, bytes): (Option<String>, i64, i64) = connection
        .query_row(
            "SELECT MIN(event_seq), COUNT(*), COALESCE(SUM(logical_event_bytes), 0)
             FROM event_stream_index WHERE conversation_id = ?1",
            [&conversation_id.as_bytes()[..]],
            |row| Ok((row.get(0)?, row.get(1)?, row.get(2)?)),
        )
        .expect("read rewritten retention totals");
    let range_digest = event_range_digest(connection, conversation_id);
    let token = retention_metadata_token(
        bundle,
        conversation_id,
        indexed_through,
        oldest.as_deref(),
        count,
        bytes,
        &range_digest,
    );
    assert_eq!(
        connection
            .execute(
                "UPDATE event_retention
                 SET oldest_retained_event_seq = ?1, indexed_through_event_seq = ?2,
                     retained_event_count = ?3, retained_logical_bytes = ?4,
                     range_digest = ?5, metadata_token = ?6
                 WHERE conversation_id = ?7",
                params![
                    oldest,
                    indexed_through,
                    count,
                    bytes,
                    &range_digest[..],
                    &token[..],
                    &conversation_id.as_bytes()[..],
                ],
            )
            .expect("persist authenticated retention gap"),
        1
    );
}

fn checkpoint(connection: &Connection) {
    connection
        .execute_batch("PRAGMA wal_checkpoint(TRUNCATE)")
        .expect("checkpoint runtime event corruption");
}
