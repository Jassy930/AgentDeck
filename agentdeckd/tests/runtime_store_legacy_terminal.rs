#[path = "support/runtime_configuration.rs"]
mod runtime_configuration;
#[path = "support/runtime_descriptor.rs"]
mod runtime_descriptor;
#[path = "support/store_admission.rs"]
mod store_admission;

use std::fs;
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicU64, Ordering};

use agentdeck_protocol::TurnSummary;
use agentdeck_protocol::runtime::identity::{CommandId, ConversationId, EventId, TurnId};
use agentdeck_protocol::runtime::{RuntimeEvent, RuntimeEventBody, RuntimeFailure};
use agentdeckd::runtime::model::MAX_RUNTIME_EVENT_BYTES;
use agentdeckd::runtime::store::cipher::{KeyWrapAad, RowAad, RuntimeKeyBundle};
use agentdeckd::runtime::store::{
    AcceptCommand, AcceptOutcome, AcceptedTerminationReason, AuthorizeExecutionRelease,
    CommandState, CommandTerminal, CompleteCommand, CompleteOutcome, ExecutionFence,
    IdempotencyOwner, NewConversation, RUNTIME_CRYPTO_CONTEXT_VERSION, RUNTIME_SCHEMA_FAMILY,
    RuntimeId, RuntimeIdKind, RuntimeStoreConfig, RuntimeStoreError, RuntimeStoreHandle,
    SanitizedTerminalFailure, StartCommand, StartOutcome, StartedBeforeReleaseTermination,
    TerminateAcceptedCommand, TerminateAcceptedOutcome, TerminateStartedBeforeRelease,
    TerminateStartedBeforeReleaseOutcome,
};
use agentdeckd::security::{MemoryKeyStore, StorageKek, load_or_create_storage_kek};
use rusqlite::{Connection, params};

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
            "agentdeckd-legacy-terminal-{label}-{}-{sequence}",
            std::process::id()
        ));
        let _ = fs::remove_dir_all(&path);
        fs::create_dir(&path).expect("create legacy terminal test root");
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            fs::set_permissions(&path, fs::Permissions::from_mode(0o700))
                .expect("secure legacy terminal test root");
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
            .expect("load legacy terminal StorageKEK")
    }
}

impl Drop for TestRoot {
    fn drop(&mut self) {
        let _ = fs::remove_dir_all(&self.path);
    }
}

struct TerminalFixture {
    root: TestRoot,
    keys: MemoryKeyStore,
    conversation_id: RuntimeId,
    command_id: RuntimeId,
    turn_id: Option<RuntimeId>,
    event: agentdeckd::runtime::store::EventRecord,
    result: Option<Vec<u8>>,
    state: CommandState,
}

#[derive(Clone, Copy)]
enum FenceMode {
    None,
    Unreleased,
    Released,
}

fn runtime_id(kind: RuntimeIdKind, seed: u8) -> RuntimeId {
    RuntimeId::from_bytes(kind, [seed; 16]).expect("valid fixture runtime id")
}

fn owner() -> IdempotencyOwner {
    IdempotencyOwner::Local {
        machine_trust_domain: [0x11; 32],
        uid: 501,
        client_installation_id: [0x22; 16],
    }
}

fn canonical_fields(fields: &[&[u8]]) -> Vec<u8> {
    let mut encoded = b"ADF1".to_vec();
    for field in fields {
        encoded.extend_from_slice(
            &u32::try_from(field.len())
                .expect("fixture field length fits u32")
                .to_be_bytes(),
        );
        encoded.extend_from_slice(field);
    }
    encoded
}

fn optional_field(value: Option<&[u8]>) -> Vec<u8> {
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

fn load_keys(connection: &Connection, storage_kek: &StorageKek) -> (RuntimeKeyBundle, [u8; 16]) {
    let (database_id, wrapped): (Vec<u8>, Vec<u8>) = connection
        .query_row(
            "SELECT database_id, wrapped_key_bundle FROM runtime_meta WHERE singleton = 1",
            [],
            |row| Ok((row.get(0)?, row.get(1)?)),
        )
        .expect("read wrapped Runtime key bundle");
    let database_id: [u8; 16] = database_id.try_into().expect("fixed database id");
    let bundle = RuntimeKeyBundle::unwrap(
        storage_kek,
        &KeyWrapAad {
            schema_family: RUNTIME_SCHEMA_FAMILY.as_bytes(),
            schema_version: RUNTIME_CRYPTO_CONTEXT_VERSION,
            database_id: &database_id,
        },
        &wrapped,
    )
    .expect("unwrap fixture Runtime key bundle");
    (bundle, database_id)
}

fn runtime_meta_count(connection: &Connection, column: &str) -> u64 {
    let value: i64 = connection
        .query_row(
            &format!("SELECT {column} FROM runtime_meta WHERE singleton = 1"),
            [],
            |row| row.get(0),
        )
        .expect("read Runtime ledger fixture counter");
    u64::try_from(value).expect("Runtime ledger fixture counter is non-negative")
}

fn reauthenticate_runtime_ledger(
    connection: &Connection,
    bundle: &RuntimeKeyBundle,
    database_id: [u8; 16],
) {
    let catalog_high_water: Option<String> = connection
        .query_row(
            "SELECT catalog_high_water FROM runtime_meta WHERE singleton = 1",
            [],
            |row| row.get(0),
        )
        .expect("read catalog ledger cursor");
    let catalog_retention_floor: Option<String> = connection
        .query_row(
            "SELECT catalog_retention_floor FROM runtime_meta WHERE singleton = 1",
            [],
            |row| row.get(0),
        )
        .expect("read catalog retention cursor");
    let mut message = database_id.to_vec();
    for value in [catalog_high_water.as_deref()] {
        match value {
            None => message.push(0),
            Some(value) => {
                message.push(1);
                message.extend_from_slice(value.as_bytes());
            }
        }
    }
    for column in [
        "conversation_count",
        "command_count",
        "event_count",
        "intent_count",
        "fence_count",
        "codex_adapter_state_count",
        "claude_code_adapter_state_count",
        "approval_count",
        "active_approval_count",
        "audit_event_logical_bytes",
        "event_stream_count",
        "event_stream_bytes",
        "catalog_delta_count",
        "catalog_delta_bytes",
    ] {
        message.extend_from_slice(&runtime_meta_count(connection, column).to_be_bytes());
    }
    match catalog_retention_floor {
        None => message.push(0),
        Some(value) => {
            message.push(1);
            message.extend_from_slice(value.as_bytes());
        }
    }
    for column in [
        "snapshot_count",
        "snapshot_bytes",
        "publication_stream_count",
        "publication_outbox_count",
        "publication_outbox_bytes",
        "accepted_count",
        "accepted_payload_bytes",
        "started_without_fence_count",
        "started_without_release_count",
        "started_released_count",
    ] {
        message.extend_from_slice(&runtime_meta_count(connection, column).to_be_bytes());
    }
    for column in [
        "configuration_count",
        "configuration_sealed_bytes",
        "command_configuration_pin_count",
        "metadata_mutation_count",
        "active_metadata_mutation_count",
        "metadata_mutation_charged_bytes",
        "native_projection_present_count",
        "native_projection_tombstone_count",
        "native_projection_retired_count",
        "native_projection_physical_count",
        "native_projection_charged_bytes",
        "native_metadata_effect_fence_count",
        "native_metadata_effect_unreleased_count",
        "native_metadata_effect_released_count",
        "admin_command_count",
        "admin_command_pending_count",
        "admin_command_charged_bytes",
        "machine_identity_count",
        "machine_remote_state_count",
        "remote_pairing_count",
        "remote_pairing_sealed_bytes",
        "remote_pairing_receipt_count",
        "remote_pairing_receipt_bytes",
        "remote_authorization_count",
        "remote_authorization_preparing_count",
        "remote_authorization_active_count",
        "remote_authorization_revoking_count",
        "remote_authorization_revoked_count",
        "remote_authorization_sealed_bytes",
        "remote_key_directory_count",
        "remote_key_directory_sealed_bytes",
        "remote_control_outbox_count",
        "remote_control_outbox_pending_count",
        "remote_control_outbox_acknowledged_count",
        "remote_control_outbox_sealed_bytes",
        "remote_replay_scope_count",
        "remote_replay_retired_scope_count",
        "remote_replay_pin_count",
        "remote_replay_sealed_bytes",
        "remote_counter_state_count",
        "remote_counter_state_sealed_bytes",
        "remote_counter_guard_manifest_count",
        "remote_key_transition_count",
        "remote_key_transition_active_count",
        "remote_key_transition_sealed_bytes",
        "remote_key_update_outbox_count",
        "remote_key_update_outbox_sealed_bytes",
    ] {
        message.extend_from_slice(&runtime_meta_count(connection, column).to_be_bytes());
    }
    let token = bundle
        .blind_index(b"runtime.meta.ledger.v15", &message)
        .expect("authenticate rewritten current-v15 Runtime ledger");
    assert_eq!(
        connection
            .execute(
                "UPDATE runtime_meta SET metadata_token = ?1 WHERE singleton = 1",
                [&token.as_bytes()[..]],
            )
            .expect("persist rewritten Runtime ledger token"),
        1
    );
}

fn command_metadata_token(
    connection: &Connection,
    bundle: &RuntimeKeyBundle,
    command_id: RuntimeId,
    terminal_token: &[u8],
    state_override: Option<CommandState>,
) -> ([u8; 32], String) {
    type Raw = (
        Vec<u8>,
        String,
        Vec<u8>,
        Vec<u8>,
        Vec<u8>,
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
    let raw: Raw = connection
        .query_row(
            "SELECT conversation_id, command_seq, owner_token, idempotency_token,
                    payload_token, state, logical_payload_bytes, accepted_at_ms, expires_at_ms,
                    retain_until_ms, started_at_ms, terminal_at_ms, turn_id,
                    started_event_id, terminal_event_id
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
        .expect("read command metadata fixture");
    let state = state_override
        .map(command_state_text)
        .unwrap_or(raw.5.as_str())
        .to_owned();
    let terminal = optional_field(Some(terminal_token));
    let started = raw
        .10
        .map(|value| u64::try_from(value).unwrap().to_be_bytes());
    let terminal_at = raw
        .11
        .map(|value| u64::try_from(value).unwrap().to_be_bytes());
    let started = optional_field(started.as_ref().map(|value| &value[..]));
    let terminal_at = optional_field(terminal_at.as_ref().map(|value| &value[..]));
    let turn = optional_field(raw.12.as_deref());
    let started_event = optional_field(raw.13.as_deref());
    let terminal_event = optional_field(raw.14.as_deref());
    let logical = u64::try_from(raw.6).unwrap().to_be_bytes();
    let accepted = u64::try_from(raw.7).unwrap().to_be_bytes();
    let expires = u64::try_from(raw.8).unwrap().to_be_bytes();
    let retain = u64::try_from(raw.9).unwrap().to_be_bytes();
    let encoded = canonical_fields(&[
        &raw.0,
        command_id.as_bytes(),
        raw.1.as_bytes(),
        &raw.2,
        &raw.3,
        &raw.4,
        &terminal,
        state.as_bytes(),
        &logical,
        &accepted,
        &expires,
        &retain,
        &started,
        &terminal_at,
        &turn,
        &started_event,
        &terminal_event,
    ]);
    let token = bundle
        .blind_index(b"command.metadata.v1", &encoded)
        .expect("authenticate rewritten command metadata");
    (*token.as_bytes(), state)
}

fn rewrite_command_terminal(
    connection: &Connection,
    bundle: &RuntimeKeyBundle,
    command_id: RuntimeId,
    terminal_token: &[u8],
    state_override: Option<CommandState>,
) {
    let (metadata_token, state) = command_metadata_token(
        connection,
        bundle,
        command_id,
        terminal_token,
        state_override,
    );
    assert_eq!(
        connection
            .execute(
                "UPDATE commands SET terminal_token = ?1, state = ?2, metadata_token = ?3
                 WHERE command_id = ?4",
                params![
                    terminal_token,
                    state,
                    &metadata_token[..],
                    &command_id.as_bytes()[..]
                ],
            )
            .expect("rewrite authenticated terminal command"),
        1
    );
}

fn replace_event_payload(
    connection: &Connection,
    bundle: &RuntimeKeyBundle,
    database_id: [u8; 16],
    event: &agentdeckd::runtime::store::EventRecord,
    payload: &[u8],
) {
    let sealed = bundle
        .row_cipher()
        .seal_bounded(
            &RowAad {
                schema_family: RUNTIME_SCHEMA_FAMILY.as_bytes(),
                schema_version: RUNTIME_CRYPTO_CONTEXT_VERSION,
                database_id: &database_id,
                table: b"event_journal",
                primary_key: event.event_id.as_bytes(),
                column: b"sealed_event",
            },
            payload,
            MAX_RUNTIME_EVENT_BYTES,
        )
        .expect("seal replacement event payload");
    let command = optional_field(
        event
            .command_id
            .as_ref()
            .map(|command_id| &command_id.as_bytes()[..]),
    );
    let seq = format!("{:020}", event.event_seq);
    let logical = u64::try_from(payload.len()).unwrap().to_be_bytes();
    let created = event.created_at_ms.to_be_bytes();
    let encoded = canonical_fields(&[
        event.conversation_id.as_bytes(),
        event.event_id.as_bytes(),
        seq.as_bytes(),
        &command,
        &logical,
        &created,
    ]);
    let metadata = bundle
        .blind_index(b"event.metadata.v1", &encoded)
        .expect("authenticate replacement event metadata");
    assert_eq!(
        connection
            .execute(
                "UPDATE event_journal
                 SET logical_event_bytes = ?1, metadata_token = ?2, sealed_event = ?3
                 WHERE event_id = ?4",
                params![
                    i64::try_from(payload.len()).unwrap(),
                    &metadata.as_bytes()[..],
                    sealed,
                    &event.event_id.as_bytes()[..]
                ],
            )
            .expect("rewrite authenticated event payload"),
        1
    );
}

fn command_state_text(state: CommandState) -> &'static str {
    match state {
        CommandState::Accepted => "accepted",
        CommandState::Started => "started",
        CommandState::Completed => "completed",
        CommandState::Failed => "failed",
        CommandState::Interrupted => "interrupted",
        CommandState::Expired => "expired",
        CommandState::Canceled => "canceled",
        CommandState::RevokedBeforeStart => "revokedBeforeStart",
    }
}

fn terminal_tag(state: CommandState) -> u8 {
    match state {
        CommandState::Completed => 1,
        CommandState::Failed => 2,
        CommandState::Interrupted => 3,
        CommandState::Canceled => 4,
        _ => panic!("fixture state is not a started terminal"),
    }
}

fn rewrite_started_terminal_as_v1(
    fixture: &TerminalFixture,
    event_payload: Option<&[u8]>,
    state_override: Option<CommandState>,
) {
    let connection = Connection::open(fixture.root.database()).expect("open terminal fixture");
    let (bundle, database_id) = load_keys(&connection, &fixture.root.storage_kek(&fixture.keys));
    let payload = event_payload.unwrap_or(&fixture.event.payload);
    if event_payload.is_some() {
        replace_event_payload(&connection, &bundle, database_id, &fixture.event, payload);
    }
    let state = state_override.unwrap_or(fixture.state);
    let result = fixture.result.as_deref().expect("started terminal result");
    let encoded = canonical_fields(&[
        fixture.conversation_id.as_bytes(),
        fixture.command_id.as_bytes(),
        fixture.turn_id.expect("started terminal turn").as_bytes(),
        &[terminal_tag(state)],
        result,
        payload,
    ]);
    let terminal = bundle
        .blind_index(b"command.terminal.v1", &encoded)
        .expect("build legacy v1 terminal token");
    rewrite_command_terminal(
        &connection,
        &bundle,
        fixture.command_id,
        terminal.as_bytes(),
        state_override,
    );
}

async fn reopen(fixture: &TerminalFixture) -> Result<RuntimeStoreHandle, RuntimeStoreError> {
    RuntimeStoreHandle::open(
        RuntimeStoreConfig::new(fixture.root.database()),
        fixture.root.storage_kek(&fixture.keys),
    )
    .await
}

async fn base_store(label: &str) -> (TestRoot, MemoryKeyStore, RuntimeStoreHandle, RuntimeId) {
    let root = TestRoot::new(label);
    let keys = MemoryKeyStore::new();
    let store = RuntimeStoreHandle::open(
        RuntimeStoreConfig::new(root.database()),
        root.storage_kek(&keys),
    )
    .await
    .expect("open terminal fixture store");
    let conversation_id = runtime_id(RuntimeIdKind::Conversation, 1);
    store
        .create_conversation(NewConversation {
            conversation_id,
            adapter_state_key: runtime_id(RuntimeIdKind::AdapterState, 2),
            descriptor: runtime_descriptor::descriptor(b"legacy terminal fixture"),
        })
        .await
        .expect("create terminal fixture conversation");
    runtime_configuration::configure_codex_revision_one(&store, conversation_id).await;
    (root, keys, store, conversation_id)
}

async fn started_terminal_fixture(
    label: &str,
    terminal: CommandTerminal,
    fence_mode: FenceMode,
) -> TerminalFixture {
    let (root, keys, store, conversation_id) = base_store(label).await;
    let command = match store
        .accept_command(AcceptCommand {
            conversation_id,
            owner: owner(),
            idempotency_key: "legacy-terminal".to_owned(),
            expected_configuration_revision: 1,
            payload: b"prompt".to_vec(),
        })
        .await
        .expect("accept terminal fixture command")
    {
        AcceptOutcome::Accepted { command, .. } => command,
        AcceptOutcome::Replayed { .. } => panic!("fresh command cannot replay"),
    };
    let daemon_boot_id = runtime_id(RuntimeIdKind::DaemonBoot, 3);
    let execution_nonce = b"legacy-terminal-nonce".to_vec();
    let intent = match store
        .mark_started_with_event(StartCommand {
            conversation_id,
            command_id: command.command_id,
            daemon_boot_id,
            execution_nonce: execution_nonce.clone(),
        })
        .await
        .expect("start terminal fixture command")
    {
        StartOutcome::Started { intent, .. } => intent,
        StartOutcome::Replayed { .. } => panic!("fresh start cannot replay"),
    };
    if !matches!(fence_mode, FenceMode::None) {
        store
            .persist_execution_fence(ExecutionFence {
                command_id: command.command_id,
                daemon_boot_id,
                execution_nonce: execution_nonce.clone(),
                process_group_id: 71,
                leader_pid: 72,
                leader_start_time: 73,
                payload: b"legacy fence".to_vec(),
            })
            .await
            .expect("persist terminal fixture fence");
    }
    let (command, event) = if matches!(fence_mode, FenceMode::Released) {
        store
            .authorize_execution_release(AuthorizeExecutionRelease {
                command_id: command.command_id,
                daemon_boot_id,
                execution_nonce,
            })
            .await
            .expect("release terminal fixture fence");
        match store
            .complete_command_with_event(CompleteCommand {
                conversation_id,
                command_id: command.command_id,
                turn_id: intent.turn_id,
                terminal,
            })
            .await
            .expect("complete terminal fixture")
        {
            CompleteOutcome::Completed { command, event } => (command, event),
            CompleteOutcome::Replayed { .. } => panic!("fresh completion cannot replay"),
        }
    } else {
        let reason = match terminal.terminal_state() {
            agentdeckd::runtime::store::TerminalState::Interrupted => {
                StartedBeforeReleaseTermination::Interrupted
            }
            agentdeckd::runtime::store::TerminalState::Canceled => {
                StartedBeforeReleaseTermination::Canceled
            }
            _ => panic!("only interrupted/canceled can terminate before release"),
        };
        match store
            .terminate_started_before_release(TerminateStartedBeforeRelease {
                conversation_id,
                command_id: command.command_id,
                turn_id: intent.turn_id,
                daemon_boot_id,
                execution_nonce,
                reason,
            })
            .await
            .expect("terminate fixture before release")
        {
            TerminateStartedBeforeReleaseOutcome::Transitioned { command, event } => {
                (command, event)
            }
            TerminateStartedBeforeReleaseOutcome::Replayed { .. } => {
                panic!("fresh termination cannot replay")
            }
        }
    };
    store.shutdown().await.expect("shutdown terminal fixture");
    TerminalFixture {
        root,
        keys,
        conversation_id,
        command_id: command.command_id,
        turn_id: command.turn_id,
        event,
        result: command.result,
        state: command.state,
    }
}

async fn accepted_fixture(label: &str, reason: AcceptedTerminationReason) -> TerminalFixture {
    let (root, keys, store, conversation_id) = base_store(label).await;
    let command = match store
        .accept_command(AcceptCommand {
            conversation_id,
            owner: owner(),
            idempotency_key: "legacy-accepted".to_owned(),
            expected_configuration_revision: 1,
            payload: b"prompt".to_vec(),
        })
        .await
        .expect("accept legacy accepted fixture")
    {
        AcceptOutcome::Accepted { command, .. } => command,
        AcceptOutcome::Replayed { .. } => panic!("fresh command cannot replay"),
    };
    let (command, event) = match store
        .terminate_accepted_command(TerminateAcceptedCommand {
            conversation_id,
            command_id: command.command_id,
            expected_owner: owner(),
            reason,
        })
        .await
        .expect("terminate accepted fixture")
    {
        TerminateAcceptedOutcome::Transitioned { command, event } => (command, event),
        _ => panic!("fresh accepted termination must transition"),
    };
    store.shutdown().await.expect("shutdown accepted fixture");
    TerminalFixture {
        root,
        keys,
        conversation_id,
        command_id: command.command_id,
        turn_id: None,
        event,
        result: None,
        state: command.state,
    }
}

fn rewrite_accepted_as_v1(
    fixture: &TerminalFixture,
    reason: AcceptedTerminationReason,
    payload: &[u8],
) {
    let connection = Connection::open(fixture.root.database()).expect("open accepted fixture");
    let (bundle, database_id) = load_keys(&connection, &fixture.root.storage_kek(&fixture.keys));
    replace_event_payload(&connection, &bundle, database_id, &fixture.event, payload);
    let (domain, tag) = match reason {
        AcceptedTerminationReason::Canceled => (b"command.canceled-before-start.v1".as_slice(), 1),
        AcceptedTerminationReason::RevokedBeforeStart => {
            (b"command.revoked-before-start.v1".as_slice(), 2)
        }
    };
    let encoded = canonical_fields(&[
        fixture.conversation_id.as_bytes(),
        fixture.command_id.as_bytes(),
        &[tag],
        payload,
    ]);
    let terminal = bundle
        .blind_index(domain, &encoded)
        .expect("build legacy accepted terminal token");
    rewrite_command_terminal(
        &connection,
        &bundle,
        fixture.command_id,
        terminal.as_bytes(),
        None,
    );
}

#[tokio::test]
async fn legacy_v1_accepted_opaque_reopens_but_canonical_is_rejected() {
    for (label, reason) in [
        ("accepted-canceled", AcceptedTerminationReason::Canceled),
        (
            "accepted-revoked",
            AcceptedTerminationReason::RevokedBeforeStart,
        ),
    ] {
        let fixture = accepted_fixture(label, reason).await;
        let opaque = vec![b'x'; fixture.event.payload.len()];
        rewrite_accepted_as_v1(&fixture, reason, &opaque);
        let reopened = reopen(&fixture)
            .await
            .expect("legacy opaque Accepted reopens");
        reopened
            .shutdown()
            .await
            .expect("shutdown reopened fixture");
    }

    let fixture = accepted_fixture("accepted-canonical", AcceptedTerminationReason::Canceled).await;
    let canonical = RuntimeEvent::new(
        ConversationId::new(fixture.conversation_id.to_canonical_string()),
        EventId::new(fixture.event.event_id.to_canonical_string()),
        fixture.event.event_seq,
        Some(CommandId::new(fixture.command_id.to_canonical_string())),
        None,
        None,
        RuntimeEventBody::Error {
            failure: RuntimeFailure::new("legacy.accepted", "canonical accepted terminal"),
        },
    )
    .expect("build canonical accepted event");
    let canonical = serde_json::to_vec(&canonical).expect("encode canonical accepted event");
    rewrite_accepted_as_v1(&fixture, AcceptedTerminationReason::Canceled, &canonical);
    let connection = Connection::open(fixture.root.database()).expect("open canonical fixture");
    let (bundle, database_id) = load_keys(&connection, &fixture.root.storage_kek(&fixture.keys));
    connection
        .execute(
            "UPDATE runtime_meta
             SET audit_event_logical_bytes = (SELECT SUM(logical_event_bytes) FROM event_journal)
             WHERE singleton = 1",
            [],
        )
        .expect("align canonical fixture audit bytes");
    reauthenticate_runtime_ledger(&connection, &bundle, database_id);
    drop(connection);
    assert!(matches!(
        reopen(&fixture).await,
        Err(RuntimeStoreError::UnknownOrCorruptSchema)
    ));
}

#[tokio::test]
async fn legacy_v1_typed_like_completed_and_failed_require_released_fence() {
    for (label, terminal) in [
        (
            "completed-released",
            CommandTerminal::completed(TurnSummary {
                total_input_tokens: None,
                total_output_tokens: None,
                elapsed_ms: 1,
            }),
        ),
        (
            "failed-released",
            CommandTerminal::failed(SanitizedTerminalFailure::execution_failed()),
        ),
    ] {
        let fixture = started_terminal_fixture(label, terminal, FenceMode::Released).await;
        let result = fixture.result.as_deref().unwrap();
        assert!(result.starts_with(b"{\"state\":"));
        assert!(
            result
                .windows(b",\"origin\":\"".len())
                .any(|value| value == b",\"origin\":\"")
        );
        rewrite_started_terminal_as_v1(&fixture, None, None);
        let reopened = reopen(&fixture)
            .await
            .expect("v1 token, not typed-looking payload, selects legacy path");
        reopened
            .shutdown()
            .await
            .expect("shutdown reopened fixture");
    }

    for remove_fence in [false, true] {
        for (label, terminal) in [
            (
                "completed-invalid-fence",
                CommandTerminal::completed(TurnSummary {
                    total_input_tokens: None,
                    total_output_tokens: None,
                    elapsed_ms: 1,
                }),
            ),
            (
                "failed-invalid-fence",
                CommandTerminal::failed(SanitizedTerminalFailure::execution_failed()),
            ),
        ] {
            let fixture = started_terminal_fixture(label, terminal, FenceMode::Released).await;
            rewrite_started_terminal_as_v1(&fixture, None, None);
            let connection = Connection::open(fixture.root.database()).expect("open fence fixture");
            if remove_fence {
                connection
                    .execute(
                        "DELETE FROM execution_fences WHERE command_id = ?1",
                        [&fixture.command_id.as_bytes()[..]],
                    )
                    .expect("remove legacy fence");
                let (bundle, database_id) =
                    load_keys(&connection, &fixture.root.storage_kek(&fixture.keys));
                connection
                    .execute(
                        "UPDATE runtime_meta
                         SET fence_count = (SELECT COUNT(*) FROM execution_fences)
                         WHERE singleton = 1",
                        [],
                    )
                    .expect("align missing-fence ledger count");
                reauthenticate_runtime_ledger(&connection, &bundle, database_id);
            } else {
                connection
                    .execute(
                        "UPDATE execution_fences
                         SET release_authorized_at_ms = NULL, release_token = NULL
                         WHERE command_id = ?1",
                        [&fixture.command_id.as_bytes()[..]],
                    )
                    .expect("make legacy fence unreleased");
            }
            drop(connection);
            assert!(matches!(
                reopen(&fixture).await,
                Err(RuntimeStoreError::UnknownOrCorruptSchema)
            ));
        }
    }
}

#[tokio::test]
async fn legacy_v1_interrupted_and_canceled_accept_all_historical_fence_shapes() {
    for (state, terminal) in [
        (CommandState::Interrupted, CommandTerminal::interrupted()),
        (CommandState::Canceled, CommandTerminal::canceled()),
    ] {
        for mode in [FenceMode::None, FenceMode::Unreleased, FenceMode::Released] {
            let label = format!("{state:?}-{}", mode as u8);
            let fixture = started_terminal_fixture(&label, terminal.clone(), mode).await;
            rewrite_started_terminal_as_v1(&fixture, None, None);
            let reopened = reopen(&fixture)
                .await
                .expect("historical interrupted/canceled fence shape reopens");
            reopened
                .shutdown()
                .await
                .expect("shutdown reopened fixture");
        }
    }
}

#[tokio::test]
async fn legacy_v1_canonical_terminal_rejects_wrong_state_and_turn() {
    let fixture = started_terminal_fixture(
        "canonical-wrong-state",
        CommandTerminal::completed(TurnSummary {
            total_input_tokens: None,
            total_output_tokens: None,
            elapsed_ms: 1,
        }),
        FenceMode::Released,
    )
    .await;
    rewrite_started_terminal_as_v1(&fixture, None, Some(CommandState::Failed));
    assert!(matches!(
        reopen(&fixture).await,
        Err(RuntimeStoreError::UnknownOrCorruptSchema)
    ));

    let fixture = started_terminal_fixture(
        "canonical-wrong-turn",
        CommandTerminal::completed(TurnSummary {
            total_input_tokens: None,
            total_output_tokens: None,
            elapsed_ms: 1,
        }),
        FenceMode::Released,
    )
    .await;
    let mut decoded: RuntimeEvent =
        serde_json::from_slice(&fixture.event.payload).expect("decode canonical terminal event");
    let RuntimeEventBody::TurnCompleted { summary, .. } = decoded.body else {
        panic!("fixture terminal must be TurnCompleted");
    };
    decoded.body = RuntimeEventBody::TurnCompleted {
        turn_id: TurnId::new(runtime_id(RuntimeIdKind::Turn, 99).to_canonical_string()),
        summary,
    };
    let wrong_turn = serde_json::to_vec(&decoded).expect("encode wrong-turn canonical terminal");
    assert_eq!(wrong_turn.len(), fixture.event.payload.len());
    rewrite_started_terminal_as_v1(&fixture, Some(&wrong_turn), None);
    assert!(matches!(
        reopen(&fixture).await,
        Err(RuntimeStoreError::UnknownOrCorruptSchema)
    ));
}
