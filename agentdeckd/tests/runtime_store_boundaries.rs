#[path = "support/runtime_configuration.rs"]
mod runtime_configuration;
#[path = "support/runtime_descriptor.rs"]
mod runtime_descriptor;
#[path = "support/runtime_recovery.rs"]
mod runtime_recovery;
#[path = "support/store_admission.rs"]
mod store_admission;

use std::fs;
use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::sync::atomic::{AtomicU64, AtomicUsize, Ordering};

use agentdeckd::runtime::model::{
    COMMAND_QUEUE_TTL_MS, MAX_COMMAND_PAYLOAD_BYTES, MAX_GLOBAL_QUEUED_PAYLOAD_BYTES,
};
use agentdeckd::runtime::store::cipher::{KeyWrapAad, RuntimeKeyBundle};
use agentdeckd::runtime::store::identity::RuntimeIdError;
use agentdeckd::runtime::store::{
    AcceptCommand, AcceptOutcome, IdempotencyOwner, NewConversation, QueueScope,
    RUNTIME_CRYPTO_CONTEXT_VERSION, RUNTIME_SCHEMA_FAMILY, RuntimeClock, RuntimeClockError,
    RuntimeId, RuntimeIdKind, RuntimeIdSource, RuntimeStoreConfig, RuntimeStoreError,
    RuntimeStoreHandle, StartCommand,
};
use agentdeckd::security::{MemoryKeyStore, StorageKek, load_or_create_storage_kek};
use rusqlite::{Connection, params};

const MAX_SEQUENCE: &str = "18446744073709551615";
const COMMAND_COLLISION_ATTEMPTS: usize = 16;

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
            "agentdeckd-runtime-boundaries-{label}-{}-{sequence}",
            std::process::id()
        ));
        let _ = fs::remove_dir_all(&path);
        fs::create_dir(&path).expect("create boundary test root");
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            fs::set_permissions(&path, fs::Permissions::from_mode(0o700))
                .expect("secure boundary test root");
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
            .expect("load boundary StorageKEK")
    }
}

impl Drop for TestRoot {
    fn drop(&mut self) {
        let _ = fs::remove_dir_all(&self.path);
    }
}

#[derive(Clone, Debug)]
struct ManualClock(Arc<AtomicU64>);

impl ManualClock {
    fn new(now_ms: u64) -> Self {
        Self(Arc::new(AtomicU64::new(now_ms)))
    }

    fn set(&self, now_ms: u64) {
        self.0.store(now_ms, Ordering::SeqCst);
    }
}

impl RuntimeClock for ManualClock {
    fn now_ms(&self) -> Result<u64, RuntimeClockError> {
        Ok(self.0.load(Ordering::SeqCst))
    }
}

struct RepeatingIdSource {
    bytes: [u8; 16],
    calls: Arc<AtomicUsize>,
}

impl RepeatingIdSource {
    fn new(bytes: [u8; 16], calls: Arc<AtomicUsize>) -> Self {
        Self { bytes, calls }
    }
}

impl RuntimeIdSource for RepeatingIdSource {
    fn next_id(&mut self, kind: RuntimeIdKind) -> Result<RuntimeId, RuntimeIdError> {
        self.calls.fetch_add(1, Ordering::SeqCst);
        RuntimeId::from_bytes(kind, self.bytes)
    }
}

fn runtime_id(kind: RuntimeIdKind, sequence: u32) -> RuntimeId {
    let mut bytes = [0_u8; 16];
    bytes[0] = match kind {
        RuntimeIdKind::Database => 1,
        RuntimeIdKind::Conversation => 2,
        RuntimeIdKind::Command => 3,
        RuntimeIdKind::Turn => 4,
        RuntimeIdKind::Event => 5,
        RuntimeIdKind::Approval => 8,
        RuntimeIdKind::AdapterState => 6,
        RuntimeIdKind::DaemonBoot => 7,
    };
    bytes[12..].copy_from_slice(&sequence.to_be_bytes());
    RuntimeId::from_bytes(kind, bytes).expect("non-zero typed runtime id")
}

fn conversation_input(sequence: u32) -> NewConversation {
    NewConversation {
        conversation_id: runtime_id(RuntimeIdKind::Conversation, sequence),
        adapter_state_key: runtime_id(RuntimeIdKind::AdapterState, sequence),
        descriptor: runtime_descriptor::descriptor(format!("conversation-{sequence}").as_bytes()),
    }
}

fn local_owner() -> IdempotencyOwner {
    IdempotencyOwner::Local {
        machine_trust_domain: [0x10; 32],
        uid: 501,
        client_installation_id: [0x20; 16],
    }
}

fn accept_input(
    conversation_id: RuntimeId,
    idempotency_key: impl Into<String>,
    payload: impl Into<Vec<u8>>,
) -> AcceptCommand {
    AcceptCommand {
        conversation_id,
        owner: local_owner(),
        idempotency_key: idempotency_key.into(),
        expected_configuration_revision: 1,
        payload: payload.into(),
    }
}

fn raw_connection(database: &Path) -> Connection {
    Connection::open(database).expect("open closed runtime database directly")
}

fn load_runtime_key_bundle(
    connection: &Connection,
    storage_kek: &StorageKek,
) -> (RuntimeKeyBundle, [u8; 16]) {
    let (database_id, wrapped_key_bundle): (Vec<u8>, Vec<u8>) = connection
        .query_row(
            "SELECT database_id, wrapped_key_bundle FROM runtime_meta WHERE singleton = 1",
            [],
            |row| Ok((row.get(0)?, row.get(1)?)),
        )
        .expect("read wrapped Runtime key bundle");
    let database_id: [u8; 16] = database_id
        .try_into()
        .expect("runtime database id has the authenticated fixed length");
    let key_bundle = RuntimeKeyBundle::unwrap(
        storage_kek,
        &KeyWrapAad {
            schema_family: RUNTIME_SCHEMA_FAMILY.as_bytes(),
            schema_version: RUNTIME_CRYPTO_CONTEXT_VERSION,
            database_id: &database_id,
        },
        &wrapped_key_bundle,
    )
    .expect("unwrap Runtime key bundle for authenticated boundary fixture");
    (key_bundle, database_id)
}

fn canonical_fields(fields: &[&[u8]]) -> Vec<u8> {
    let mut encoded = b"ADF1".to_vec();
    for field in fields {
        let length = u32::try_from(field.len()).expect("fixture field fits canonical encoding");
        encoded.extend_from_slice(&length.to_be_bytes());
        encoded.extend_from_slice(field);
    }
    encoded
}

fn optional_text_field(value: Option<&str>) -> Vec<u8> {
    let mut encoded = Vec::with_capacity(1 + value.map_or(0, str::len));
    match value {
        None => encoded.push(0),
        Some(value) => {
            encoded.push(1);
            encoded.extend_from_slice(value.as_bytes());
        }
    }
    encoded
}

fn optional_blob_field(value: Option<&[u8]>) -> Vec<u8> {
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

type RawConversationMetadata = (
    Vec<u8>,
    String,
    Option<String>,
    Option<String>,
    String,
    i64,
    i64,
    i64,
);

type RawRuntimeLedger = (
    Option<String>,
    i64,
    i64,
    i64,
    i64,
    i64,
    i64,
    i64,
    i64,
    i64,
    i64,
    i64,
    i64,
    i64,
    i64,
    Option<String>,
    i64,
    i64,
    i64,
    i64,
    i64,
    i64,
    i64,
    i64,
    i64,
    i64,
    i64,
    i64,
    i64,
    i64,
    i64,
    i64,
);

type RawCommandMetadata = (
    Vec<u8>,
    Vec<u8>,
    Vec<u8>,
    Vec<u8>,
    Option<Vec<u8>>,
    String,
    i64,
    i64,
    i64,
    i64,
    Option<i64>,
    Option<i64>,
    Option<Vec<u8>>,
    Option<Vec<u8>>,
    Option<Vec<u8>>,
);

fn conversation_metadata_token(
    connection: &Connection,
    key_bundle: &RuntimeKeyBundle,
    conversation_id: RuntimeId,
) -> [u8; 32] {
    let (
        adapter_state_key,
        catalog_revision,
        command_high_water,
        event_high_water,
        lifecycle,
        created_at_ms,
        updated_at_ms,
        accepted_count,
    ): RawConversationMetadata = connection
        .query_row(
            "SELECT adapter_state_key, catalog_revision, command_high_water,
                    event_high_water, lifecycle, created_at_ms, updated_at_ms,
                    accepted_count
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
        .expect("read conversation metadata fixture");
    let command_high_water = optional_text_field(command_high_water.as_deref());
    let event_high_water = optional_text_field(event_high_water.as_deref());
    let accepted_count = u32::try_from(accepted_count)
        .expect("fixture accepted count is non-negative")
        .to_be_bytes();
    let created_at_ms = u64::try_from(created_at_ms)
        .expect("fixture creation time is non-negative")
        .to_be_bytes();
    let updated_at_ms = u64::try_from(updated_at_ms)
        .expect("fixture update time is non-negative")
        .to_be_bytes();
    let encoded = canonical_fields(&[
        conversation_id.as_bytes(),
        &adapter_state_key,
        catalog_revision.as_bytes(),
        &command_high_water,
        &event_high_water,
        &accepted_count,
        lifecycle.as_bytes(),
        &created_at_ms,
        &updated_at_ms,
    ]);
    *key_bundle
        .blind_index(b"conversation.metadata.v1", &encoded)
        .expect("authenticate conversation boundary metadata")
        .as_bytes()
}

fn runtime_ledger_token(
    connection: &Connection,
    key_bundle: &RuntimeKeyBundle,
    database_id: [u8; 16],
) -> [u8; 32] {
    let (
        catalog_high_water,
        conversation_count,
        command_count,
        event_count,
        intent_count,
        fence_count,
        codex_adapter_state_count,
        claude_code_adapter_state_count,
        approval_count,
        active_approval_count,
        audit_event_logical_bytes,
        event_stream_count,
        event_stream_bytes,
        catalog_delta_count,
        catalog_delta_bytes,
        catalog_retention_floor,
        snapshot_count,
        snapshot_bytes,
        publication_stream_count,
        publication_outbox_count,
        publication_outbox_bytes,
        accepted_count,
        accepted_payload_bytes,
        started_without_fence_count,
        started_without_release_count,
        started_released_count,
        configuration_count,
        configuration_sealed_bytes,
        command_configuration_pin_count,
        metadata_mutation_count,
        active_metadata_mutation_count,
        metadata_mutation_charged_bytes,
    ): RawRuntimeLedger = connection
        .query_row(
            "SELECT catalog_high_water, conversation_count, command_count, event_count,
                    intent_count, fence_count, codex_adapter_state_count,
                    claude_code_adapter_state_count, approval_count, active_approval_count,
                    audit_event_logical_bytes, event_stream_count, event_stream_bytes,
                    catalog_delta_count, catalog_delta_bytes, catalog_retention_floor,
                    snapshot_count, snapshot_bytes, publication_stream_count,
                    publication_outbox_count, publication_outbox_bytes,
                    accepted_count, accepted_payload_bytes,
                    started_without_fence_count, started_without_release_count,
                    started_released_count, configuration_count,
                    configuration_sealed_bytes, command_configuration_pin_count,
                    metadata_mutation_count, active_metadata_mutation_count,
                    metadata_mutation_charged_bytes
             FROM runtime_meta WHERE singleton = 1",
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
                    row.get(7)?,
                    row.get(8)?,
                    row.get(9)?,
                    row.get(10)?,
                    row.get(11)?,
                    row.get(12)?,
                    row.get(13)?,
                    row.get(14)?,
                    row.get(15)?,
                    row.get(16)?,
                    row.get(17)?,
                    row.get(18)?,
                    row.get(19)?,
                    row.get(20)?,
                    row.get(21)?,
                    row.get(22)?,
                    row.get(23)?,
                    row.get(24)?,
                    row.get(25)?,
                    row.get(26)?,
                    row.get(27)?,
                    row.get(28)?,
                    row.get(29)?,
                    row.get(30)?,
                    row.get(31)?,
                ))
            },
        )
        .expect("read Runtime authenticated ledger fixture");
    let native_ledger: (i64, i64, i64, i64, i64, i64, i64, i64) = connection
        .query_row(
            "SELECT native_projection_present_count,
                    native_projection_tombstone_count,
                    native_projection_retired_count,
                    native_projection_physical_count,
                    native_projection_charged_bytes,
                    native_metadata_effect_fence_count,
                    native_metadata_effect_unreleased_count,
                    native_metadata_effect_released_count
             FROM runtime_meta WHERE singleton = 1",
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
                    row.get(7)?,
                ))
            },
        )
        .expect("read Runtime native projection ledger fixture");
    let admin_ledger: (i64, i64, i64) = connection
        .query_row(
            "SELECT admin_command_count, admin_command_pending_count,
                    admin_command_charged_bytes
             FROM runtime_meta WHERE singleton = 1",
            [],
            |row| Ok((row.get(0)?, row.get(1)?, row.get(2)?)),
        )
        .expect("read Runtime admin command ledger fixture");
    let machine_identity_count: i64 = connection
        .query_row(
            "SELECT machine_identity_count FROM runtime_meta WHERE singleton = 1",
            [],
            |row| row.get(0),
        )
        .expect("read Runtime machine identity ledger fixture");
    let mut message = Vec::with_capacity(392);
    message.extend_from_slice(&database_id);
    match catalog_high_water {
        None => message.push(0),
        Some(value) => {
            message.push(1);
            message.extend_from_slice(value.as_bytes());
        }
    }
    for value in [
        conversation_count,
        command_count,
        event_count,
        intent_count,
        fence_count,
        codex_adapter_state_count,
        claude_code_adapter_state_count,
        approval_count,
        active_approval_count,
        audit_event_logical_bytes,
        event_stream_count,
        event_stream_bytes,
        catalog_delta_count,
        catalog_delta_bytes,
    ] {
        message.extend_from_slice(
            &u64::try_from(value)
                .expect("fixture ledger counter is non-negative")
                .to_be_bytes(),
        );
    }
    match catalog_retention_floor {
        None => message.push(0),
        Some(value) => {
            message.push(1);
            message.extend_from_slice(value.as_bytes());
        }
    }
    for value in [
        snapshot_count,
        snapshot_bytes,
        publication_stream_count,
        publication_outbox_count,
        publication_outbox_bytes,
        accepted_count,
        accepted_payload_bytes,
        started_without_fence_count,
        started_without_release_count,
        started_released_count,
    ] {
        message.extend_from_slice(
            &u64::try_from(value)
                .expect("fixture ledger counter is non-negative")
                .to_be_bytes(),
        );
    }
    for value in [
        configuration_count,
        configuration_sealed_bytes,
        command_configuration_pin_count,
        metadata_mutation_count,
        active_metadata_mutation_count,
        metadata_mutation_charged_bytes,
    ] {
        message.extend_from_slice(
            &u64::try_from(value)
                .expect("fixture ledger counter is non-negative")
                .to_be_bytes(),
        );
    }
    for value in [
        native_ledger.0,
        native_ledger.1,
        native_ledger.2,
        native_ledger.3,
        native_ledger.4,
        native_ledger.5,
        native_ledger.6,
        native_ledger.7,
        admin_ledger.0,
        admin_ledger.1,
        admin_ledger.2,
    ] {
        message.extend_from_slice(
            &u64::try_from(value)
                .expect("fixture native ledger counter is non-negative")
                .to_be_bytes(),
        );
    }
    message.extend_from_slice(
        &u64::try_from(machine_identity_count)
            .expect("fixture machine identity count is non-negative")
            .to_be_bytes(),
    );
    *key_bundle
        .blind_index(b"runtime.meta.ledger.v8", &message)
        .expect("authenticate Runtime boundary ledger")
        .as_bytes()
}

fn reauthenticate_conversation(
    connection: &Connection,
    key_bundle: &RuntimeKeyBundle,
    conversation_id: RuntimeId,
) {
    let token = conversation_metadata_token(connection, key_bundle, conversation_id);
    assert_eq!(
        connection
            .execute(
                "UPDATE conversations SET metadata_token = ?1 WHERE conversation_id = ?2",
                params![&token[..], &conversation_id.as_bytes()[..]],
            )
            .expect("persist authenticated conversation boundary metadata"),
        1
    );
}

fn move_accepted_command_to_sequence(
    connection: &Connection,
    key_bundle: &RuntimeKeyBundle,
    command_id: RuntimeId,
    next_sequence: &str,
) {
    let (current_sequence, configuration_revision): (String, String) = connection
        .query_row(
            "SELECT command.command_seq, pin.configuration_revision
             FROM commands AS command
             JOIN command_configuration_pins AS pin
               ON pin.conversation_id = command.conversation_id
              AND pin.command_seq = command.command_seq
             WHERE command.command_id = ?1",
            [&command_id.as_bytes()[..]],
            |row| Ok((row.get(0)?, row.get(1)?)),
        )
        .expect("read accepted command configuration pin fixture");
    let (
        conversation_id,
        owner_token,
        idempotency_token,
        payload_token,
        terminal_token,
        state,
        logical_payload_bytes,
        accepted_at_ms,
        expires_at_ms,
        retain_until_ms,
        started_at_ms,
        terminal_at_ms,
        turn_id,
        started_event_id,
        terminal_event_id,
    ): RawCommandMetadata = connection
        .query_row(
            "SELECT conversation_id, owner_token, idempotency_token, payload_token,
                    terminal_token, state, logical_payload_bytes, accepted_at_ms,
                    expires_at_ms, retain_until_ms, started_at_ms, terminal_at_ms,
                    turn_id, started_event_id, terminal_event_id
             FROM commands WHERE command_id = ?1",
            [&command_id.as_bytes()[..]],
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
                    row.get(9)?,
                    row.get(10)?,
                    row.get(11)?,
                    row.get(12)?,
                    row.get(13)?,
                    row.get(14)?,
                ))
            },
        )
        .expect("read accepted command metadata fixture");
    assert_eq!(state, "accepted");
    assert!(terminal_token.is_none());
    assert!(started_at_ms.is_none());
    assert!(terminal_at_ms.is_none());
    assert!(turn_id.is_none());
    assert!(started_event_id.is_none());
    assert!(terminal_event_id.is_none());
    let logical_payload_bytes = u64::try_from(logical_payload_bytes)
        .expect("logical command bytes are non-negative")
        .to_be_bytes();
    let accepted_at_ms = u64::try_from(accepted_at_ms)
        .expect("accepted time is non-negative")
        .to_be_bytes();
    let expires_at_ms = u64::try_from(expires_at_ms)
        .expect("expiry time is non-negative")
        .to_be_bytes();
    let retain_until_ms = u64::try_from(retain_until_ms)
        .expect("retention time is non-negative")
        .to_be_bytes();
    let none = optional_blob_field(None);
    let encoded = canonical_fields(&[
        &conversation_id,
        command_id.as_bytes(),
        next_sequence.as_bytes(),
        &owner_token,
        &idempotency_token,
        &payload_token,
        &none,
        b"accepted",
        &logical_payload_bytes,
        &accepted_at_ms,
        &expires_at_ms,
        &retain_until_ms,
        &none,
        &none,
        &none,
        &none,
        &none,
    ]);
    let token = key_bundle
        .blind_index(b"command.metadata.v1", &encoded)
        .expect("authenticate accepted command boundary metadata");
    let mut pin_metadata = Vec::with_capacity(128);
    for field in [
        conversation_id.as_slice(),
        next_sequence.as_bytes(),
        configuration_revision.as_bytes(),
    ] {
        pin_metadata.extend_from_slice(
            &u64::try_from(field.len())
                .expect("pin metadata field length fits u64")
                .to_be_bytes(),
        );
        pin_metadata.extend_from_slice(field);
    }
    let pin_token = key_bundle
        .blind_index(b"command.configuration.pin.metadata.v1", &pin_metadata)
        .expect("authenticate command configuration pin boundary metadata");
    connection
        .execute_batch("PRAGMA defer_foreign_keys = ON")
        .expect("defer command/pin composite foreign key until the boundary fixture is complete");
    assert_eq!(
        connection
            .execute(
                "UPDATE command_configuration_pins
                 SET command_seq = ?1, metadata_token = ?2
                 WHERE conversation_id = ?3 AND command_seq = ?4",
                params![
                    next_sequence,
                    &pin_token.as_bytes()[..],
                    &conversation_id,
                    &current_sequence,
                ],
            )
            .expect("move authenticated configuration pin to boundary sequence"),
        1
    );
    assert_eq!(
        connection
            .execute(
                "UPDATE commands SET command_seq = ?1, metadata_token = ?2
                 WHERE command_id = ?3",
                params![
                    next_sequence,
                    &token.as_bytes()[..],
                    &command_id.as_bytes()[..],
                ],
            )
            .expect("move accepted command to boundary sequence"),
        1
    );
}

fn reauthenticate_runtime_ledger(
    connection: &Connection,
    key_bundle: &RuntimeKeyBundle,
    database_id: [u8; 16],
) {
    let token = runtime_ledger_token(connection, key_bundle, database_id);
    assert_eq!(
        connection
            .execute(
                "UPDATE runtime_meta SET metadata_token = ?1 WHERE singleton = 1",
                [&token[..]],
            )
            .expect("persist authenticated Runtime boundary ledger"),
        1
    );
}

fn assert_sequence_exhausted(error: &RuntimeStoreError, scope: &str) {
    assert!(matches!(error, RuntimeStoreError::Sequence(_)));
    assert_eq!(
        error.to_string(),
        format!("runtime sequence allocation failed: u64 sequence is exhausted for {scope}")
    );
    assert_eq!(error.code(), "daemon.runtime.invalid_state");
}

#[tokio::test]
async fn global_queue_and_payload_accept_exact_1024_and_256_mib_then_replay_before_rejection() {
    let root = TestRoot::new("global-queue");
    let keys = MemoryKeyStore::new();
    let clock = ManualClock::new(1_000);
    let config = RuntimeStoreConfig::new(root.database()).with_clock(clock.clone());
    let store = RuntimeStoreHandle::open(config, root.storage_kek(&keys))
        .await
        .expect("open boundary store");

    let mut conversations = Vec::with_capacity(33);
    for sequence in 1..=33_u32 {
        conversations.push(
            store
                .create_conversation(conversation_input(sequence))
                .await
                .expect("create queue fixture conversation"),
        );
    }
    for conversation in &conversations {
        runtime_configuration::configure_codex_revision_one(&store, conversation.conversation_id)
            .await;
    }

    clock.set(10_000);
    let mut first_command_id = None;
    let max_payload = vec![0x5a; MAX_COMMAND_PAYLOAD_BYTES];
    for (conversation_index, conversation) in conversations.iter().take(32).enumerate() {
        for queue_index in 0..32_u32 {
            let key = format!("request-{queue_index}");
            let outcome = store
                .accept_command(accept_input(
                    conversation.conversation_id,
                    key,
                    max_payload.clone(),
                ))
                .await
                .expect("all commands through the exact global boundary are accepted");
            let AcceptOutcome::Accepted {
                command,
                queue_position,
            } = outcome
            else {
                panic!("a unique command cannot replay")
            };
            assert_eq!(queue_position, queue_index);
            if conversation_index == 0 && queue_index == 0 {
                first_command_id = Some(command.command_id);
            }
        }
    }

    let replay = store
        .accept_command(accept_input(
            conversations[0].conversation_id,
            "request-0",
            max_payload.clone(),
        ))
        .await
        .expect("replay wins over the full global queue");
    assert!(matches!(
        replay,
        AcceptOutcome::Replayed { command }
            if Some(command.command_id) == first_command_id
    ));

    let overflow = store
        .accept_command(accept_input(
            conversations[32].conversation_id,
            "request-overflow",
            b"overflow".to_vec(),
        ))
        .await
        .expect_err("the 1025th unique queued command must be rejected");
    assert!(matches!(
        overflow,
        RuntimeStoreError::QueueFull {
            scope: QueueScope::GlobalCount
        }
    ));
    assert_eq!(overflow.code(), "daemon.command.queue_full");

    let mut cursor = store
        .begin_recovery_scan()
        .await
        .expect("begin paged exact-boundary recovery");
    let mut accepted_count = 0_u64;
    let mut accepted_payload_bytes = 0_u64;
    let completion = loop {
        let page = store
            .load_recovery_page(cursor)
            .await
            .expect("read one exact-boundary recovery page");
        let record = page.conversation.expect("catalog page has conversation");
        accepted_count += u64::try_from(record.accepted.len()).expect("accepted count fits u64");
        accepted_payload_bytes += record
            .accepted
            .iter()
            .map(|command| u64::try_from(command.payload.len()).expect("payload length fits u64"))
            .sum::<u64>();
        match (page.next_cursor, page.completion) {
            (Some(next), None) => cursor = next,
            (None, Some(completion)) => break completion,
            _ => panic!("recovery continuation shape must be canonical"),
        }
    };
    assert_eq!(accepted_count, 1_024);
    assert_eq!(accepted_payload_bytes, MAX_GLOBAL_QUEUED_PAYLOAD_BYTES);
    store
        .finish_recovery_scan(completion)
        .await
        .expect("finish exact-boundary recovery");
    store.shutdown().await.expect("shutdown boundary store");
}

#[tokio::test]
async fn command_id_sixteen_collisions_exhaust_without_adding_a_row_or_advancing_hwm() {
    let root = TestRoot::new("command-collision");
    let keys = MemoryKeyStore::new();
    let clock = ManualClock::new(1_000);
    let collision_bytes = [0xcc; 16];
    let first_calls = Arc::new(AtomicUsize::new(0));
    let initial_config = RuntimeStoreConfig::new(root.database())
        .with_clock(clock.clone())
        .with_id_source(RepeatingIdSource::new(
            collision_bytes,
            Arc::clone(&first_calls),
        ));
    let store = RuntimeStoreHandle::open(initial_config, root.storage_kek(&keys))
        .await
        .expect("open collision fixture store");
    let conversation = store
        .create_conversation(conversation_input(1))
        .await
        .expect("create collision fixture conversation");
    runtime_configuration::configure_codex_revision_one(&store, conversation.conversation_id).await;
    let first = store
        .accept_command(accept_input(
            conversation.conversation_id,
            "first",
            b"first".to_vec(),
        ))
        .await
        .expect("persist the colliding command id");
    assert!(matches!(
        first,
        AcceptOutcome::Accepted { command, .. } if command.command_id.as_bytes() == &collision_bytes
    ));
    assert_eq!(first_calls.load(Ordering::SeqCst), 2);
    store.shutdown().await.expect("close collision fixture");

    clock.set(2_000);
    let retry_calls = Arc::new(AtomicUsize::new(0));
    let retry_config = RuntimeStoreConfig::new(root.database())
        .with_clock(clock)
        .with_id_source(RepeatingIdSource::new(
            collision_bytes,
            Arc::clone(&retry_calls),
        ));
    let reopened = RuntimeStoreHandle::open(retry_config, root.storage_kek(&keys))
        .await
        .expect("reopen collision fixture");
    let error = reopened
        .accept_command(accept_input(
            conversation.conversation_id,
            "second",
            b"second".to_vec(),
        ))
        .await
        .expect_err("sixteen persisted command-id collisions must exhaust allocation");
    assert!(matches!(
        error,
        RuntimeStoreError::IdGeneration(RuntimeIdError::CollisionExhausted {
            kind: RuntimeIdKind::Command,
            attempts: COMMAND_COLLISION_ATTEMPTS,
        })
    ));
    assert_eq!(retry_calls.load(Ordering::SeqCst), 16);

    let recovery = runtime_recovery::load_recovery_state(&reopened)
        .await
        .expect("read state after collision exhaustion");
    assert_eq!(recovery.accepted.len(), 1);
    assert_eq!(recovery.conversations[0].command_high_water, Some(0));
    reopened.shutdown().await.expect("shutdown collision store");

    let raw = raw_connection(&root.database());
    let command_count: i64 = raw
        .query_row("SELECT COUNT(*) FROM commands", [], |row| row.get(0))
        .expect("count commands after collision exhaustion");
    assert_eq!(command_count, 1);
}

#[tokio::test]
async fn catalog_hwm_u64_max_returns_typed_exhaustion_and_inserts_no_additional_conversation() {
    let root = TestRoot::new("catalog-max");
    let keys = MemoryKeyStore::new();
    let clock = ManualClock::new(1_000);
    let config = RuntimeStoreConfig::new(root.database()).with_clock(clock);
    let store = RuntimeStoreHandle::open(config.clone(), root.storage_kek(&keys))
        .await
        .expect("create catalog fixture");
    let existing = store
        .create_conversation(conversation_input(1))
        .await
        .expect("create authenticated catalog boundary conversation");
    store.shutdown().await.expect("close catalog fixture");

    {
        let storage_kek = root.storage_kek(&keys);
        let mut raw = raw_connection(&root.database());
        let (key_bundle, database_id) = load_runtime_key_bundle(&raw, &storage_kek);
        let transaction = raw.transaction().expect("begin catalog boundary fixture");
        let stored_token: Vec<u8> = transaction
            .query_row(
                "SELECT metadata_token FROM runtime_meta WHERE singleton = 1",
                [],
                |row| row.get(0),
            )
            .expect("read baseline v8 ledger token");
        assert_eq!(
            runtime_ledger_token(&transaction, &key_bundle, database_id).as_slice(),
            stored_token,
            "fixture v8 ledger encoder must match the store"
        );
        assert_eq!(
            transaction
                .execute(
                    "UPDATE conversations SET catalog_revision = ?1 WHERE conversation_id = ?2",
                    params![MAX_SEQUENCE, &existing.conversation_id.as_bytes()[..]],
                )
                .expect("set legal maximum conversation catalog revision"),
            1
        );
        reauthenticate_conversation(&transaction, &key_bundle, existing.conversation_id);
        assert_eq!(
            transaction
                .execute(
                    "UPDATE runtime_meta
                     SET catalog_high_water = ?1,
                         catalog_delta_count = 0,
                         catalog_delta_bytes = 0,
                         catalog_retention_floor = NULL
                     WHERE singleton = 1",
                    [MAX_SEQUENCE],
                )
                .expect("set legal maximum catalog HWM"),
            1
        );
        transaction
            .execute("DELETE FROM catalog_journal", [])
            .expect("turn old catalog delta into a snapshot boundary");
        reauthenticate_runtime_ledger(&transaction, &key_bundle, database_id);
        transaction
            .commit()
            .expect("commit authenticated catalog boundary fixture");
    }

    let reopened = RuntimeStoreHandle::open(config, root.storage_kek(&keys))
        .await
        .expect("reopen catalog fixture");
    let error = reopened
        .create_conversation(conversation_input(2))
        .await
        .expect_err("catalog HWM at u64::MAX must exhaust");
    assert_sequence_exhausted(&error, "CatalogRevision");
    let recovery = runtime_recovery::load_recovery_state(&reopened)
        .await
        .expect("read state after catalog exhaustion");
    assert_eq!(recovery.conversations.len(), 1);
    assert_eq!(
        recovery.conversations[0].conversation_id,
        existing.conversation_id
    );
    assert_eq!(recovery.conversations[0].catalog_revision, u64::MAX);
    reopened.shutdown().await.expect("shutdown catalog store");

    let raw = raw_connection(&root.database());
    let (catalog_high_water, conversation_count): (String, i64) = raw
        .query_row(
            "SELECT catalog_high_water, (SELECT COUNT(*) FROM conversations)
             FROM runtime_meta WHERE singleton = 1",
            [],
            |row| Ok((row.get(0)?, row.get(1)?)),
        )
        .expect("read catalog zero-write evidence");
    assert_eq!(catalog_high_water, MAX_SEQUENCE);
    assert_eq!(conversation_count, 1);
}

#[tokio::test]
async fn command_hwm_u64_max_returns_typed_exhaustion_and_inserts_no_additional_command() {
    let root = TestRoot::new("command-max");
    let keys = MemoryKeyStore::new();
    let clock = ManualClock::new(1_000);
    let config = RuntimeStoreConfig::new(root.database()).with_clock(clock.clone());
    let store = RuntimeStoreHandle::open(config.clone(), root.storage_kek(&keys))
        .await
        .expect("open command HWM fixture");
    let conversation = store
        .create_conversation(conversation_input(1))
        .await
        .expect("create command HWM fixture conversation");
    runtime_configuration::configure_codex_revision_one(&store, conversation.conversation_id).await;
    clock.set(1_500);
    let existing_command = match store
        .accept_command(accept_input(
            conversation.conversation_id,
            "existing-command",
            b"existing".to_vec(),
        ))
        .await
        .expect("create command at the reachable initial sequence")
    {
        AcceptOutcome::Accepted { command, .. } => command,
        AcceptOutcome::Replayed { .. } => panic!("initial command cannot replay"),
    };
    store.shutdown().await.expect("close command HWM fixture");

    {
        let storage_kek = root.storage_kek(&keys);
        let mut raw = raw_connection(&root.database());
        let (key_bundle, _) = load_runtime_key_bundle(&raw, &storage_kek);
        let transaction = raw
            .transaction()
            .expect("begin command HWM boundary fixture");
        move_accepted_command_to_sequence(
            &transaction,
            &key_bundle,
            existing_command.command_id,
            MAX_SEQUENCE,
        );
        assert_eq!(
            transaction
                .execute(
                    "UPDATE conversations SET command_high_water = ?1 WHERE conversation_id = ?2",
                    params![MAX_SEQUENCE, &conversation.conversation_id.as_bytes()[..]],
                )
                .expect("set legal maximum command HWM"),
            1
        );
        reauthenticate_conversation(&transaction, &key_bundle, conversation.conversation_id);
        transaction
            .commit()
            .expect("commit authenticated command HWM boundary fixture");
    }

    clock.set(2_000);
    let reopened = RuntimeStoreHandle::open(config, root.storage_kek(&keys))
        .await
        .expect("reopen command HWM fixture");
    let error = reopened
        .accept_command(accept_input(
            conversation.conversation_id,
            "must-not-persist",
            b"must-not-persist".to_vec(),
        ))
        .await
        .expect_err("command HWM at u64::MAX must exhaust");
    assert_sequence_exhausted(&error, "CommandSeq");
    let recovery = runtime_recovery::load_recovery_state(&reopened)
        .await
        .expect("read state after command HWM exhaustion");
    assert_eq!(recovery.accepted.len(), 1);
    assert_eq!(recovery.accepted[0].command_id, existing_command.command_id);
    assert_eq!(recovery.conversations[0].command_high_water, Some(u64::MAX));
    reopened
        .shutdown()
        .await
        .expect("shutdown command HWM store");

    let raw = raw_connection(&root.database());
    let (command_high_water, command_count): (String, i64) = raw
        .query_row(
            "SELECT command_high_water, (SELECT COUNT(*) FROM commands)
             FROM conversations WHERE conversation_id = ?1",
            [&conversation.conversation_id.as_bytes()[..]],
            |row| Ok((row.get(0)?, row.get(1)?)),
        )
        .expect("read command zero-write evidence");
    assert_eq!(command_high_water, MAX_SEQUENCE);
    assert_eq!(command_count, 1);
}

#[tokio::test]
async fn event_hwm_u64_max_returns_typed_exhaustion_and_keeps_command_accepted() {
    let root = TestRoot::new("event-max");
    let keys = MemoryKeyStore::new();
    let clock = ManualClock::new(1_000);
    let config = RuntimeStoreConfig::new(root.database()).with_clock(clock.clone());
    let store = RuntimeStoreHandle::open(config.clone(), root.storage_kek(&keys))
        .await
        .expect("open event HWM fixture");
    let conversation = store
        .create_conversation(conversation_input(1))
        .await
        .expect("create event HWM fixture conversation");
    runtime_configuration::configure_codex_revision_one(&store, conversation.conversation_id).await;
    clock.set(2_000);
    let _expiring_command = match store
        .accept_command(accept_input(
            conversation.conversation_id,
            "event-max-expiring-command",
            b"old prompt".to_vec(),
        ))
        .await
        .expect("accept event HWM fixture command")
    {
        AcceptOutcome::Accepted { command, .. } => command,
        AcceptOutcome::Replayed { .. } => panic!("first command cannot replay"),
    };
    clock.set(2_000 + COMMAND_QUEUE_TTL_MS);
    let command = match store
        .accept_command(accept_input(
            conversation.conversation_id,
            "event-max-command",
            b"prompt".to_vec(),
        ))
        .await
        .expect("expiry creates the reachable initial event before target accept")
    {
        AcceptOutcome::Accepted { command, .. } => command,
        AcceptOutcome::Replayed { .. } => panic!("target command cannot replay"),
    };
    // 完整 open-time audit 要求物理 event journal 从 0 连续到 HWM，因此不存在一个
    // 可实际物化、同时把 HWM 推到 u64::MAX 的小型合法数据库。这里只在已打开且空闲的
    // test Store 后门写入 authenticated HWM，精确触发 allocator 边界；断言零写后立刻
    // 恢复 production event row 对应的原 HWM，再用正常 reopen 证明 fixture 没被带坏。
    let original_event_high_water: Option<String>;
    {
        let storage_kek = root.storage_kek(&keys);
        let mut raw = raw_connection(&root.database());
        let (key_bundle, _) = load_runtime_key_bundle(&raw, &storage_kek);
        let transaction = raw.transaction().expect("begin event HWM boundary fixture");
        original_event_high_water = transaction
            .query_row(
                "SELECT event_high_water FROM conversations WHERE conversation_id = ?1",
                [&conversation.conversation_id.as_bytes()[..]],
                |row| row.get(0),
            )
            .expect("read production event HWM before boundary injection");
        assert_eq!(
            original_event_high_water.as_deref(),
            Some("00000000000000000001")
        );
        assert_eq!(
            transaction
                .execute(
                    "UPDATE conversations SET event_high_water = ?1 WHERE conversation_id = ?2",
                    params![MAX_SEQUENCE, &conversation.conversation_id.as_bytes()[..]],
                )
                .expect("set legal maximum event HWM"),
            1
        );
        reauthenticate_conversation(&transaction, &key_bundle, conversation.conversation_id);
        transaction
            .commit()
            .expect("commit authenticated event HWM boundary fixture");
    }

    clock.set(3_000 + COMMAND_QUEUE_TTL_MS);
    let error = store
        .mark_started_with_event(StartCommand {
            conversation_id: conversation.conversation_id,
            command_id: command.command_id,
            daemon_boot_id: runtime_id(RuntimeIdKind::DaemonBoot, 1),
            execution_nonce: b"event-max-nonce".to_vec(),
        })
        .await
        .expect_err("event HWM at u64::MAX must exhaust");
    assert_sequence_exhausted(&error, "EventSeq");

    {
        let storage_kek = root.storage_kek(&keys);
        let mut raw = raw_connection(&root.database());
        let (state, event_count, intent_count, event_high_water): (String, i64, i64, String) = raw
            .query_row(
                "SELECT state,
                        (SELECT COUNT(*) FROM event_journal),
                        (SELECT COUNT(*) FROM execution_intents),
                        (SELECT event_high_water FROM conversations WHERE conversation_id = ?2)
                 FROM commands WHERE command_id = ?1",
                params![
                    &command.command_id.as_bytes()[..],
                    &conversation.conversation_id.as_bytes()[..]
                ],
                |row| Ok((row.get(0)?, row.get(1)?, row.get(2)?, row.get(3)?)),
            )
            .expect("read event zero-write evidence");
        assert_eq!(state, "accepted");
        assert_eq!(event_count, 2);
        assert_eq!(intent_count, 0);
        assert_eq!(event_high_water, MAX_SEQUENCE);

        let (key_bundle, _) = load_runtime_key_bundle(&raw, &storage_kek);
        let transaction = raw
            .transaction()
            .expect("begin event HWM fixture restoration");
        assert_eq!(
            transaction
                .execute(
                    "UPDATE conversations SET event_high_water = ?1 WHERE conversation_id = ?2",
                    params![
                        original_event_high_water,
                        &conversation.conversation_id.as_bytes()[..]
                    ],
                )
                .expect("restore production event HWM"),
            1
        );
        reauthenticate_conversation(&transaction, &key_bundle, conversation.conversation_id);
        transaction.commit().expect("commit event HWM restoration");
    }
    store.shutdown().await.expect("shutdown event HWM store");
    let reopened = RuntimeStoreHandle::open(config, root.storage_kek(&keys))
        .await
        .expect("restored event HWM fixture reopens");
    let recovery = runtime_recovery::load_recovery_state(&reopened)
        .await
        .expect("read restored state after event HWM exhaustion");
    assert_eq!(recovery.accepted.len(), 1);
    assert!(recovery.started.is_empty());
    assert_eq!(recovery.accepted[0].command_id, command.command_id);
    assert_eq!(recovery.conversations[0].event_high_water, Some(1));
    reopened
        .shutdown()
        .await
        .expect("shutdown restored event HWM fixture");
}
