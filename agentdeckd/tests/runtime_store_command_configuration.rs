#[path = "support/runtime_descriptor.rs"]
mod runtime_descriptor;

use std::fs;
use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};

use agentdeck_protocol::runtime::{
    CodexConversationConfiguration, ConversationConfiguration, VendorConfigurationSnapshot,
};
use agentdeck_protocol::{CodexApprovalPolicy, CodexReasoningEffort, CodexSandboxMode};
use agentdeckd::runtime::store::{
    AcceptCommand, AcceptOutcome, CommandReceiptSelector, CommandRecord, ConfigureConversation,
    ConfigureConversationOutcome, IdempotencyOwner, NewConversation, QueryCommandReceipt,
    RuntimeClock, RuntimeClockError, RuntimeId, RuntimeIdKind, RuntimeStoreConfig,
    RuntimeStoreError, RuntimeStoreHandle,
};
use agentdeckd::security::{MemoryKeyStore, StorageKek, load_or_create_storage_kek};
use rusqlite::{Connection, OpenFlags};

static NEXT_TEMP_ID: AtomicU64 = AtomicU64::new(1);

#[derive(Clone, Debug)]
struct ArmableFailClock {
    now_ms: Arc<AtomicU64>,
    fail: Arc<AtomicBool>,
}

impl ArmableFailClock {
    fn new(now_ms: u64) -> Self {
        Self {
            now_ms: Arc::new(AtomicU64::new(now_ms)),
            fail: Arc::new(AtomicBool::new(false)),
        }
    }

    fn set_fail(&self, fail: bool) {
        self.fail.store(fail, Ordering::SeqCst);
    }
}

impl RuntimeClock for ArmableFailClock {
    fn now_ms(&self) -> Result<u64, RuntimeClockError> {
        if self.fail.load(Ordering::SeqCst) {
            Err(RuntimeClockError::BeforeUnixEpoch)
        } else {
            Ok(self.now_ms.load(Ordering::SeqCst))
        }
    }
}

struct TestRoot(PathBuf);

impl TestRoot {
    fn new(label: &str) -> Self {
        let sequence = NEXT_TEMP_ID.fetch_add(1, Ordering::Relaxed);
        let path = Path::new("/tmp").join(format!(
            "agentdeckd-runtime-command-configuration-{label}-{}-{sequence}",
            std::process::id()
        ));
        let _ = fs::remove_dir_all(&path);
        fs::create_dir(&path).expect("create command configuration test root");
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            fs::set_permissions(&path, fs::Permissions::from_mode(0o700))
                .expect("secure command configuration test root");
        }
        Self(path)
    }

    fn database(&self) -> PathBuf {
        self.0.join("runtime.db")
    }

    fn storage_kek(&self, keys: &MemoryKeyStore) -> StorageKek {
        load_or_create_storage_kek(keys, &self.0.join("key-state.db"))
            .expect("load command configuration test StorageKEK")
    }
}

impl Drop for TestRoot {
    fn drop(&mut self) {
        let _ = fs::remove_dir_all(&self.0);
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
struct CommandEvidence {
    command_rows: i64,
    pin_rows: i64,
    ledger_command_count: i64,
    ledger_accepted_count: i64,
    ledger_accepted_payload_bytes: i64,
    ledger_pin_count: i64,
    conversation_accepted_count: i64,
    catalog_high_water: Option<String>,
    command_high_water: Option<String>,
    event_high_water: Option<String>,
}

fn command_evidence(path: &Path, conversation_id: RuntimeId) -> CommandEvidence {
    let connection = Connection::open_with_flags(path, OpenFlags::SQLITE_OPEN_READ_ONLY)
        .expect("open read-only command evidence connection");
    connection
        .query_row(
            "SELECT
                 (SELECT COUNT(*) FROM commands WHERE conversation_id = ?1),
                 (SELECT COUNT(*) FROM command_configuration_pins
                    WHERE conversation_id = ?1),
                 m.command_count,
                 m.accepted_count,
                 m.accepted_payload_bytes,
                 m.command_configuration_pin_count,
                 c.accepted_count,
                 m.catalog_high_water,
                 c.command_high_water,
                 c.event_high_water
             FROM runtime_meta AS m
             JOIN conversations AS c ON c.conversation_id = ?1
             WHERE m.singleton = 1",
            [&conversation_id.as_bytes()[..]],
            |row| {
                Ok(CommandEvidence {
                    command_rows: row.get(0)?,
                    pin_rows: row.get(1)?,
                    ledger_command_count: row.get(2)?,
                    ledger_accepted_count: row.get(3)?,
                    ledger_accepted_payload_bytes: row.get(4)?,
                    ledger_pin_count: row.get(5)?,
                    conversation_accepted_count: row.get(6)?,
                    catalog_high_water: row.get(7)?,
                    command_high_water: row.get(8)?,
                    event_high_water: row.get(9)?,
                })
            },
        )
        .expect("read command write evidence")
}

fn global_command_evidence(path: &Path) -> (i64, i64, i64, i64, i64) {
    let connection = Connection::open_with_flags(path, OpenFlags::SQLITE_OPEN_READ_ONLY)
        .expect("open read-only global command evidence connection");
    connection
        .query_row(
            "SELECT
                 (SELECT COUNT(*) FROM commands),
                 (SELECT COUNT(*) FROM command_configuration_pins),
                 command_count,
                 accepted_count,
                 command_configuration_pin_count
             FROM runtime_meta WHERE singleton = 1",
            [],
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
        .expect("read global command evidence")
}

fn pinned_configuration_revision(path: &Path, command_id: RuntimeId) -> String {
    let connection = Connection::open_with_flags(path, OpenFlags::SQLITE_OPEN_READ_ONLY)
        .expect("open read-only pin evidence connection");
    connection
        .query_row(
            "SELECT p.configuration_revision
             FROM command_configuration_pins AS p
             JOIN commands AS c
               ON c.conversation_id = p.conversation_id
              AND c.command_seq = p.command_seq
             WHERE c.command_id = ?1",
            [&command_id.as_bytes()[..]],
            |row| row.get(0),
        )
        .expect("read pinned command configuration revision")
}

fn assert_zero_command_state(evidence: &CommandEvidence) {
    assert_eq!(evidence.command_rows, 0);
    assert_eq!(evidence.pin_rows, 0);
    assert_eq!(evidence.ledger_command_count, 0);
    assert_eq!(evidence.ledger_accepted_count, 0);
    assert_eq!(evidence.ledger_accepted_payload_bytes, 0);
    assert_eq!(evidence.ledger_pin_count, 0);
    assert_eq!(evidence.conversation_accepted_count, 0);
    assert_eq!(evidence.command_high_water, None);
}

fn runtime_id(kind: RuntimeIdKind, seed: u8) -> RuntimeId {
    RuntimeId::from_bytes(kind, [seed; 16]).expect("valid typed runtime id")
}

fn conversation(seed: u8) -> NewConversation {
    NewConversation {
        conversation_id: runtime_id(RuntimeIdKind::Conversation, seed),
        adapter_state_key: runtime_id(RuntimeIdKind::AdapterState, seed.wrapping_add(0x40)),
        descriptor: runtime_descriptor::descriptor(
            format!("command-configuration-{seed}").as_bytes(),
        ),
    }
}

fn owner(seed: u8) -> IdempotencyOwner {
    IdempotencyOwner::Local {
        machine_trust_domain: [0xA1; 32],
        uid: 501,
        client_installation_id: [seed; 16],
    }
}

fn codex_configuration(reasoning: CodexReasoningEffort) -> ConversationConfiguration {
    ConversationConfiguration::new(VendorConfigurationSnapshot::Codex(
        CodexConversationConfiguration::new(
            CodexApprovalPolicy::OnRequest,
            CodexSandboxMode::WorkspaceWrite,
            reasoning,
        ),
    ))
}

fn configure_request(
    conversation_id: RuntimeId,
    owner_seed: u8,
    key: &str,
    expected_revision: u64,
    reasoning: CodexReasoningEffort,
) -> ConfigureConversation {
    ConfigureConversation {
        conversation_id,
        owner: owner(owner_seed),
        idempotency_key: key.to_owned(),
        expected_configuration_revision: expected_revision,
        configuration: codex_configuration(reasoning),
    }
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
        .configure_conversation(configure_request(
            conversation_id,
            owner_seed,
            key,
            expected_revision,
            reasoning,
        ))
        .await
        .expect("configure conversation")
    {
        ConfigureConversationOutcome::Applied { configuration } => {
            configuration.configuration_revision
        }
        other => panic!("expected applied configuration, got {other:?}"),
    }
}

fn accept_request(
    conversation_id: RuntimeId,
    command_owner: &IdempotencyOwner,
    key: &str,
    expected_configuration_revision: u64,
    payload: &[u8],
) -> AcceptCommand {
    AcceptCommand {
        conversation_id,
        owner: command_owner.clone(),
        idempotency_key: key.to_owned(),
        expected_configuration_revision,
        payload: payload.to_vec(),
    }
}

fn accepted(outcome: AcceptOutcome) -> CommandRecord {
    match outcome {
        AcceptOutcome::Accepted { command, .. } => command,
        other => panic!("expected accepted command, got {other:?}"),
    }
}

fn receipt_by_command(
    conversation_id: RuntimeId,
    command_id: RuntimeId,
    expected_owner: &IdempotencyOwner,
) -> QueryCommandReceipt {
    QueryCommandReceipt {
        expected_owner: expected_owner.clone(),
        selector: CommandReceiptSelector::Command {
            conversation_id,
            command_id,
        },
    }
}

fn receipt_by_idempotency(
    conversation_id: RuntimeId,
    idempotency_key: &str,
    expected_owner: &IdempotencyOwner,
) -> QueryCommandReceipt {
    QueryCommandReceipt {
        expected_owner: expected_owner.clone(),
        selector: CommandReceiptSelector::Idempotency {
            conversation_id,
            idempotency_key: idempotency_key.to_owned(),
        },
    }
}

#[tokio::test]
async fn missing_conversation_is_not_misreported_as_schema_corruption() {
    let root = TestRoot::new("missing-conversation");
    let keys = MemoryKeyStore::new();
    let store = RuntimeStoreHandle::open(
        RuntimeStoreConfig::new(root.database()),
        root.storage_kek(&keys),
    )
    .await
    .expect("open missing conversation store");
    let baseline = global_command_evidence(&root.database());

    let error = store
        .accept_command(accept_request(
            runtime_id(RuntimeIdKind::Conversation, 0x20),
            &owner(0x20),
            "missing-conversation-command",
            1,
            b"must-not-be-persisted",
        ))
        .await
        .expect_err("missing conversation must reject command acceptance");
    assert!(matches!(error, RuntimeStoreError::ConversationNotFound));
    assert_eq!(global_command_evidence(&root.database()), baseline);

    store
        .shutdown()
        .await
        .expect("shutdown missing conversation store");
}

#[tokio::test]
async fn fresh_unconfigured_expected_zero_and_one_are_required_and_zero_write() {
    let root = TestRoot::new("configuration-required");
    let keys = MemoryKeyStore::new();
    let input = conversation(0x21);
    let conversation_id = input.conversation_id;
    let store = RuntimeStoreHandle::open(
        RuntimeStoreConfig::new(root.database()),
        root.storage_kek(&keys),
    )
    .await
    .expect("open unconfigured store");
    store
        .create_conversation(input)
        .await
        .expect("create unconfigured conversation");
    let baseline = command_evidence(&root.database(), conversation_id);
    assert_zero_command_state(&baseline);
    assert_eq!(baseline.event_high_water, None);

    for expected_revision in [0, 1] {
        let error = store
            .accept_command(accept_request(
                conversation_id,
                &owner(0x31),
                &format!("unconfigured-{expected_revision}"),
                expected_revision,
                b"must-not-be-persisted",
            ))
            .await
            .expect_err("unconfigured conversation must reject command acceptance");
        assert!(
            matches!(error, RuntimeStoreError::ConfigurationRequired),
            "expected ConfigurationRequired for revision {expected_revision}, got {error:?}"
        );
        assert_eq!(
            command_evidence(&root.database(), conversation_id),
            baseline
        );
    }

    store.shutdown().await.expect("shutdown unconfigured store");
}

#[tokio::test]
async fn configured_revision_mismatch_is_typed_and_zero_write() {
    let root = TestRoot::new("configuration-conflict");
    let keys = MemoryKeyStore::new();
    let input = conversation(0x22);
    let conversation_id = input.conversation_id;
    let store = RuntimeStoreHandle::open(
        RuntimeStoreConfig::new(root.database()),
        root.storage_kek(&keys),
    )
    .await
    .expect("open configured conflict store");
    store
        .create_conversation(input)
        .await
        .expect("create configured conversation");
    assert_eq!(
        configure(
            &store,
            conversation_id,
            0x32,
            "configure-1",
            0,
            CodexReasoningEffort::Low,
        )
        .await,
        1
    );
    let baseline = command_evidence(&root.database(), conversation_id);
    assert_zero_command_state(&baseline);
    assert_eq!(
        baseline.event_high_water.as_deref(),
        Some("00000000000000000000")
    );

    for expected_revision in [0, 2] {
        let error = store
            .accept_command(accept_request(
                conversation_id,
                &owner(0x33),
                &format!("revision-mismatch-{expected_revision}"),
                expected_revision,
                b"must-not-cross-configuration-cas",
            ))
            .await
            .expect_err("configuration revision mismatch must reject command acceptance");
        match error {
            RuntimeStoreError::ConfigurationConflict {
                current_configuration_revision,
            } => assert_eq!(current_configuration_revision, 1),
            other => panic!(
                "expected ConfigurationConflict for revision {expected_revision}, got {other:?}"
            ),
        }
        assert_eq!(
            command_evidence(&root.database(), conversation_id),
            baseline
        );
    }

    store
        .shutdown()
        .await
        .expect("shutdown configured conflict store");
}

#[tokio::test]
async fn current_configuration_head_tamper_rejects_accept_before_any_command_write() {
    for tamper in ["sealed-request", "metadata-token", "event-payload"] {
        let root = TestRoot::new(tamper);
        let keys = MemoryKeyStore::new();
        let input = conversation(0x24);
        let conversation_id = input.conversation_id;
        let store = RuntimeStoreHandle::open(
            RuntimeStoreConfig::new(root.database()),
            root.storage_kek(&keys),
        )
        .await
        .expect("open configuration tamper store");
        store
            .create_conversation(input)
            .await
            .expect("create configuration tamper conversation");
        assert_eq!(
            configure(
                &store,
                conversation_id,
                0x34,
                "configure-current-head",
                0,
                CodexReasoningEffort::Medium,
            )
            .await,
            1
        );
        let baseline = command_evidence(&root.database(), conversation_id);
        assert_zero_command_state(&baseline);

        let connection = Connection::open(root.database()).expect("open configuration tamper DB");
        let changed = match tamper {
            "sealed-request" => connection.execute(
                "UPDATE configuration_journal
                 SET sealed_request = zeroblob(length(sealed_request))
                 WHERE conversation_id = ?1 AND configuration_revision = '00000000000000000001'",
                [&conversation_id.as_bytes()[..]],
            ),
            "metadata-token" => connection.execute(
                "UPDATE configuration_journal SET metadata_token = zeroblob(32)
                 WHERE conversation_id = ?1 AND configuration_revision = '00000000000000000001'",
                [&conversation_id.as_bytes()[..]],
            ),
            "event-payload" => connection.execute(
                "UPDATE event_journal SET sealed_event = zeroblob(length(sealed_event))
                 WHERE conversation_id = ?1
                   AND event_seq = (
                       SELECT event_seq FROM configuration_journal
                       WHERE conversation_id = ?1
                         AND configuration_revision = '00000000000000000001'
                   )",
                [&conversation_id.as_bytes()[..]],
            ),
            other => panic!("unexpected configuration tamper case {other}"),
        }
        .expect("tamper current configuration head");
        assert_eq!(
            changed, 1,
            "tamper case {tamper} must change exactly one row"
        );
        drop(connection);

        for expected_revision in [0, 1, 2] {
            let error = store
                .accept_command(accept_request(
                    conversation_id,
                    &owner(0x35),
                    &format!("reject-tampered-{tamper}-{expected_revision}"),
                    expected_revision,
                    b"must-not-cross-current-head-authentication",
                ))
                .await
                .expect_err("tampered current configuration head must fail closed");
            assert!(
                !matches!(error, RuntimeStoreError::ConfigurationConflict { .. }),
                "tampered head must not be hidden by expected revision {expected_revision}: {error:?}"
            );
            assert_eq!(
                command_evidence(&root.database(), conversation_id),
                baseline
            );
        }
        store
            .shutdown()
            .await
            .expect("shutdown configuration tamper store");
    }
}

#[tokio::test]
async fn current_head_authentication_rejects_gap_plus_out_of_range_revision() {
    let root = TestRoot::new("configuration-revision-bounds");
    let keys = MemoryKeyStore::new();
    let input = conversation(0x25);
    let conversation_id = input.conversation_id;
    let store = RuntimeStoreHandle::open(
        RuntimeStoreConfig::new(root.database()),
        root.storage_kek(&keys),
    )
    .await
    .expect("open configuration revision bounds store");
    store
        .create_conversation(input)
        .await
        .expect("create configuration revision bounds conversation");
    assert_eq!(
        configure(
            &store,
            conversation_id,
            0x36,
            "configure-bounds-1",
            0,
            CodexReasoningEffort::Low,
        )
        .await,
        1
    );
    assert_eq!(
        configure(
            &store,
            conversation_id,
            0x37,
            "configure-bounds-2",
            1,
            CodexReasoningEffort::Medium,
        )
        .await,
        2
    );
    let baseline = command_evidence(&root.database(), conversation_id);

    let connection = Connection::open(root.database()).expect("open revision bounds DB");
    assert_eq!(
        connection
            .execute(
                "UPDATE configuration_journal
                 SET configuration_revision = '00000000000000000003'
                 WHERE conversation_id = ?1
                   AND configuration_revision = '00000000000000000001'",
                [&conversation_id.as_bytes()[..]],
            )
            .expect("replace first revision with out-of-range row"),
        1
    );
    drop(connection);

    let error = store
        .accept_command(accept_request(
            conversation_id,
            &owner(0x38),
            "reject-revision-gap",
            2,
            b"must-not-cross-revision-bounds",
        ))
        .await
        .expect_err("gap plus out-of-range revision must fail closed");
    assert!(matches!(error, RuntimeStoreError::UnknownOrCorruptSchema));
    assert_eq!(
        command_evidence(&root.database(), conversation_id),
        baseline
    );

    store
        .shutdown()
        .await
        .expect("shutdown configuration revision bounds store");
}

#[tokio::test]
async fn exact_replay_and_same_key_conflict_do_not_consult_clock_or_drift_state() {
    let root = TestRoot::new("replay-no-clock");
    let keys = MemoryKeyStore::new();
    let clock = ArmableFailClock::new(10_000);
    let input = conversation(0x26);
    let conversation_id = input.conversation_id;
    let command_owner = owner(0x39);
    let request = accept_request(
        conversation_id,
        &command_owner,
        "clock-independent-replay",
        1,
        b"persist-once-without-replay-housekeeping",
    );
    let store = RuntimeStoreHandle::open(
        RuntimeStoreConfig::new(root.database()).with_clock(clock.clone()),
        root.storage_kek(&keys),
    )
    .await
    .expect("open replay clock store");
    store
        .create_conversation(input)
        .await
        .expect("create replay clock conversation");
    assert_eq!(
        configure(
            &store,
            conversation_id,
            0x3A,
            "configure-replay-clock",
            0,
            CodexReasoningEffort::Medium,
        )
        .await,
        1
    );
    let accepted = accepted(
        store
            .accept_command(request.clone())
            .await
            .expect("accept replay clock command"),
    );
    let baseline = command_evidence(&root.database(), conversation_id);

    clock.set_fail(true);
    let replayed = match store
        .accept_command(request)
        .await
        .expect("exact replay must not consult the clock")
    {
        AcceptOutcome::Replayed { command } => command,
        other => panic!("expected replay while clock is unavailable, got {other:?}"),
    };
    assert_eq!(replayed.command_id, accepted.command_id);
    assert_eq!(replayed.configuration_revision, 1);
    assert_eq!(
        command_evidence(&root.database(), conversation_id),
        baseline
    );

    let conflict = store
        .accept_command(accept_request(
            conversation_id,
            &command_owner,
            "clock-independent-replay",
            2,
            b"persist-once-without-replay-housekeeping",
        ))
        .await
        .expect_err("same-key conflict must not consult the clock");
    assert!(matches!(conflict, RuntimeStoreError::IdempotencyConflict));
    assert_eq!(
        command_evidence(&root.database(), conversation_id),
        baseline
    );

    clock.set_fail(false);
    store.shutdown().await.expect("shutdown replay clock store");
}

#[tokio::test]
async fn conflicting_retry_cannot_hide_authenticated_command_corruption() {
    for tamper in ["payload-token", "metadata-token", "sealed-command"] {
        let root = TestRoot::new(tamper);
        let keys = MemoryKeyStore::new();
        let input = conversation(0x27);
        let conversation_id = input.conversation_id;
        let command_owner = owner(0x3B);
        let idempotency_key = "authenticated-command-before-conflict";
        let payload = b"original-command-payload";
        let store = RuntimeStoreHandle::open(
            RuntimeStoreConfig::new(root.database()),
            root.storage_kek(&keys),
        )
        .await
        .expect("open command corruption store");
        store
            .create_conversation(input)
            .await
            .expect("create command corruption conversation");
        assert_eq!(
            configure(
                &store,
                conversation_id,
                0x3C,
                "configure-command-corruption",
                0,
                CodexReasoningEffort::Medium,
            )
            .await,
            1
        );
        accepted(
            store
                .accept_command(accept_request(
                    conversation_id,
                    &command_owner,
                    idempotency_key,
                    1,
                    payload,
                ))
                .await
                .expect("accept command before corruption"),
        );

        let connection = Connection::open(root.database()).expect("open command corruption DB");
        let sql = match tamper {
            "payload-token" => "UPDATE commands SET payload_token = zeroblob(32)",
            "metadata-token" => "UPDATE commands SET metadata_token = zeroblob(32)",
            "sealed-command" => {
                "UPDATE commands SET sealed_command = zeroblob(length(sealed_command))"
            }
            other => panic!("unexpected command tamper case {other}"),
        };
        assert_eq!(connection.execute(sql, []).expect("tamper command row"), 1);
        drop(connection);
        let tampered = command_evidence(&root.database(), conversation_id);

        let error = store
            .accept_command(accept_request(
                conversation_id,
                &command_owner,
                idempotency_key,
                2,
                payload,
            ))
            .await
            .expect_err("conflicting retry must authenticate the persisted command first");
        match tamper {
            "sealed-command" => assert!(
                matches!(error, RuntimeStoreError::Cipher(_)),
                "sealed command corruption must preserve crypto provenance: {error:?}"
            ),
            "payload-token" | "metadata-token" => assert!(
                matches!(error, RuntimeStoreError::UnknownOrCorruptSchema),
                "authenticated command metadata corruption must fail closed: {error:?}"
            ),
            other => unreachable!("unexpected command tamper case {other}"),
        }
        assert_eq!(
            command_evidence(&root.database(), conversation_id),
            tampered
        );
        store
            .shutdown()
            .await
            .expect("shutdown command corruption store");
    }
}

#[tokio::test]
async fn accepted_pin_replay_query_and_reopen_preserve_original_revision() {
    let root = TestRoot::new("pin-replay-query-reopen");
    let keys = MemoryKeyStore::new();
    let database = root.database();
    let config = RuntimeStoreConfig::new(database.clone());
    let input = conversation(0x23);
    let conversation_id = input.conversation_id;
    let command_owner = owner(0x41);
    let idempotency_key = "command-at-revision-1";
    let payload = b"prompt-pinned-to-revision-1";
    let store = RuntimeStoreHandle::open(config.clone(), root.storage_kek(&keys))
        .await
        .expect("open command pin store");
    store
        .create_conversation(input)
        .await
        .expect("create command pin conversation");
    assert_eq!(
        configure(
            &store,
            conversation_id,
            0x42,
            "configure-1",
            0,
            CodexReasoningEffort::Low,
        )
        .await,
        1
    );

    let command = accepted(
        store
            .accept_command(accept_request(
                conversation_id,
                &command_owner,
                idempotency_key,
                1,
                payload,
            ))
            .await
            .expect("accept command at configuration revision one"),
    );
    assert_eq!(command.configuration_revision, 1);
    let accepted_evidence = command_evidence(&database, conversation_id);
    assert_eq!(accepted_evidence.command_rows, 1);
    assert_eq!(accepted_evidence.pin_rows, 1);
    assert_eq!(accepted_evidence.ledger_command_count, 1);
    assert_eq!(accepted_evidence.ledger_accepted_count, 1);
    assert_eq!(
        accepted_evidence.ledger_accepted_payload_bytes,
        i64::try_from(payload.len()).expect("payload length fits i64")
    );
    assert_eq!(accepted_evidence.ledger_pin_count, 1);
    assert_eq!(accepted_evidence.conversation_accepted_count, 1);
    assert_eq!(
        accepted_evidence.command_high_water.as_deref(),
        Some("00000000000000000000")
    );
    assert_eq!(
        pinned_configuration_revision(&database, command.command_id),
        "00000000000000000001"
    );

    assert_eq!(
        configure(
            &store,
            conversation_id,
            0x43,
            "configure-2",
            1,
            CodexReasoningEffort::High,
        )
        .await,
        2
    );
    let advanced_head_evidence = command_evidence(&database, conversation_id);
    let replayed = match store
        .accept_command(accept_request(
            conversation_id,
            &command_owner,
            idempotency_key,
            1,
            payload,
        ))
        .await
        .expect("replay original command request after head advances")
    {
        AcceptOutcome::Replayed { command } => command,
        other => panic!("expected command replay, got {other:?}"),
    };
    assert_eq!(replayed.command_id, command.command_id);
    assert_eq!(replayed.configuration_revision, 1);
    assert_eq!(
        command_evidence(&database, conversation_id),
        advanced_head_evidence,
        "exact replay after configuration advance must not drift durable state"
    );

    let error = store
        .accept_command(accept_request(
            conversation_id,
            &command_owner,
            idempotency_key,
            2,
            payload,
        ))
        .await
        .expect_err("same idempotency key with a different expected revision must conflict");
    assert!(matches!(error, RuntimeStoreError::IdempotencyConflict));
    assert_eq!(
        command_evidence(&database, conversation_id),
        advanced_head_evidence,
        "same-key revision conflict must not drift durable state"
    );

    let by_command = receipt_by_command(conversation_id, command.command_id, &command_owner);
    let by_idempotency = receipt_by_idempotency(conversation_id, idempotency_key, &command_owner);
    let command_receipt = store
        .query_command_receipt(by_command.clone())
        .await
        .expect("query pinned command receipt by command id");
    assert_eq!(command_receipt.command_id, command.command_id);
    assert_eq!(command_receipt.configuration_revision, 1);
    let idempotency_receipt = store
        .query_command_receipt(by_idempotency.clone())
        .await
        .expect("query pinned command receipt by idempotency key");
    assert_eq!(idempotency_receipt, command_receipt);
    assert_eq!(idempotency_receipt.configuration_revision, 1);
    assert_eq!(command_evidence(&database, conversation_id).pin_rows, 1);
    assert_eq!(
        pinned_configuration_revision(&database, command.command_id),
        "00000000000000000001"
    );

    store.shutdown().await.expect("shutdown command pin store");
    let reopened = RuntimeStoreHandle::open(config, root.storage_kek(&keys))
        .await
        .expect("reopen command pin store");
    let reopened_by_command = reopened
        .query_command_receipt(by_command)
        .await
        .expect("query pinned command receipt by command id after reopen");
    assert_eq!(reopened_by_command, command_receipt);
    assert_eq!(reopened_by_command.configuration_revision, 1);
    let reopened_by_idempotency = reopened
        .query_command_receipt(by_idempotency)
        .await
        .expect("query pinned command receipt by idempotency key after reopen");
    assert_eq!(reopened_by_idempotency, command_receipt);
    assert_eq!(reopened_by_idempotency.configuration_revision, 1);
    assert_eq!(command_evidence(&database, conversation_id).pin_rows, 1);
    assert_eq!(
        pinned_configuration_revision(&database, command.command_id),
        "00000000000000000001"
    );
    reopened
        .shutdown()
        .await
        .expect("shutdown reopened command pin store");
}
