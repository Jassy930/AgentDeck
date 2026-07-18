#[path = "support/runtime_descriptor.rs"]
mod runtime_descriptor;

use std::fs;
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::sync::mpsc::{Receiver, SyncSender, sync_channel};
use std::sync::{Arc, Mutex};
use std::time::Duration;

use agentdeck_protocol::runtime::{
    CodexConversationConfiguration, ConversationConfiguration, VendorConfigurationSnapshot,
};
use agentdeck_protocol::{CodexApprovalPolicy, CodexReasoningEffort, CodexSandboxMode};
use agentdeckd::runtime::model::{
    RuntimeCapacityObservation, RuntimeCapacityProbe, RuntimeCapacityProbeError,
};
use agentdeckd::runtime::store::{
    AcceptCommand, AcceptOutcome, CommandReceiptSelector, CommandRecord, CommandState,
    ConfigureConversation, ConfigureConversationOutcome, IdempotencyOwner, NewConversation,
    QueryCommandReceipt, RuntimeClock, RuntimeClockError, RuntimeCommitOperation, RuntimeId,
    RuntimeIdKind, RuntimeStoreConfig, RuntimeStoreError, RuntimeStoreFaultInjector,
    RuntimeStoreHandle, RuntimeStoreLane, RuntimeStoreOperation, StartCommand, StartOutcome,
    StartedBeforeReleaseTermination, TerminateStartedBeforeRelease,
    TerminateStartedBeforeReleaseOutcome,
};
use agentdeckd::security::{MemoryKeyStore, StorageKek, load_or_create_storage_kek};
use rusqlite::types::ValueRef;
use rusqlite::{Connection, OpenFlags, ToSql, Transaction};

static NEXT_TEMP_ID: AtomicU64 = AtomicU64::new(1);
const EVIDENCE_MAX_ROWS_PER_TABLE: usize = 64;
const EVIDENCE_MAX_COLUMNS_PER_TABLE: usize = 64;
const EVIDENCE_MAX_BYTES_PER_TABLE: usize = 8 * 1024 * 1024;
const MIB: u64 = 1024 * 1024;
const GIB: u64 = 1024 * MIB;
const RUNTIME_DB_HARD_LIMIT_BYTES: u64 = 2 * GIB;

#[derive(Clone)]
struct MutableCapacityProbe(Arc<Mutex<RuntimeCapacityObservation>>);

impl MutableCapacityProbe {
    fn new(observation: RuntimeCapacityObservation) -> Self {
        Self(Arc::new(Mutex::new(observation)))
    }

    fn set(&self, observation: RuntimeCapacityObservation) {
        *self.0.lock().expect("capacity probe lock") = observation;
    }
}

impl RuntimeCapacityProbe for MutableCapacityProbe {
    fn observe(
        &self,
        _storage_path: &Path,
    ) -> Result<RuntimeCapacityObservation, RuntimeCapacityProbeError> {
        Ok(*self.0.lock().expect("capacity probe lock"))
    }
}

fn healthy_capacity() -> RuntimeCapacityObservation {
    RuntimeCapacityObservation {
        main_bytes: 8 * MIB,
        wal_bytes: 2 * MIB,
        shm_bytes: 32 * 1024,
        filesystem_total_bytes: 20 * GIB,
        filesystem_available_bytes: 4 * GIB,
    }
}

fn disk_low_capacity() -> RuntimeCapacityObservation {
    RuntimeCapacityObservation {
        filesystem_total_bytes: 4 * GIB,
        filesystem_available_bytes: 512 * MIB - 1,
        ..healthy_capacity()
    }
}

fn over_limit_capacity() -> RuntimeCapacityObservation {
    RuntimeCapacityObservation {
        main_bytes: RUNTIME_DB_HARD_LIMIT_BYTES + 1,
        wal_bytes: 0,
        shm_bytes: 0,
        filesystem_available_bytes: 8 * GIB,
        ..healthy_capacity()
    }
}

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

struct FailOperationOnce {
    target: RuntimeStoreOperation,
    armed: AtomicBool,
}

impl FailOperationOnce {
    fn new(target: RuntimeStoreOperation) -> Self {
        Self {
            target,
            armed: AtomicBool::new(true),
        }
    }
}

impl RuntimeStoreFaultInjector for FailOperationOnce {
    fn before_operation(&self, operation: RuntimeStoreOperation) -> Result<(), RuntimeStoreError> {
        if operation == self.target && self.armed.swap(false, Ordering::SeqCst) {
            Err(RuntimeStoreError::InvalidConfig(
                "injected command configuration fault",
            ))
        } else {
            Ok(())
        }
    }
}

struct BlockingOperationOnce {
    target: RuntimeStoreOperation,
    armed: AtomicBool,
    entered: SyncSender<()>,
    release: Mutex<Receiver<()>>,
}

impl BlockingOperationOnce {
    fn new(target: RuntimeStoreOperation, entered: SyncSender<()>, release: Receiver<()>) -> Self {
        Self {
            target,
            armed: AtomicBool::new(false),
            entered,
            release: Mutex::new(release),
        }
    }

    fn arm(&self) {
        assert!(
            !self.armed.swap(true, Ordering::SeqCst),
            "blocking Store fault is already armed"
        );
    }
}

impl RuntimeStoreFaultInjector for BlockingOperationOnce {
    fn before_operation(&self, operation: RuntimeStoreOperation) -> Result<(), RuntimeStoreError> {
        if operation == self.target && self.armed.swap(false, Ordering::SeqCst) {
            self.entered
                .send(())
                .map_err(|_| RuntimeStoreError::WorkerStopped)?;
            self.release
                .lock()
                .map_err(|_| RuntimeStoreError::WorkerStopped)?
                .recv_timeout(Duration::from_secs(5))
                .map_err(|_| RuntimeStoreError::WorkerStopped)?;
        }
        Ok(())
    }
}

struct FaultChain(Vec<Arc<BlockingOperationOnce>>);

impl RuntimeStoreFaultInjector for FaultChain {
    fn before_operation(&self, operation: RuntimeStoreOperation) -> Result<(), RuntimeStoreError> {
        for fault in &self.0 {
            fault.before_operation(operation)?;
        }
        Ok(())
    }
}

async fn wait_for_blocked_worker(entered: Receiver<()>) {
    tokio::task::spawn_blocking(move || entered.recv_timeout(Duration::from_secs(5)))
        .await
        .expect("join blocked Store worker observer")
        .expect("Store worker reached the controlled before-COMMIT barrier");
}

fn assert_commit_unknown(error: RuntimeStoreError, expected: RuntimeCommitOperation) {
    assert!(
        matches!(
            error,
            RuntimeStoreError::CommitOutcomeUnknown { operation } if operation == expected
        ),
        "expected CommitOutcomeUnknown({expected:?}), got {error:?}"
    );
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
    global_command_rows: i64,
    global_pin_rows: i64,
    global_accepted_rows: i64,
    global_accepted_payload_bytes: i64,
    conversation_accepted_rows: i64,
    conversation_accepted_payload_bytes: i64,
    configuration_rows: i64,
    configuration_sealed_bytes: i64,
    event_journal_rows: i64,
    event_journal_logical_bytes: i64,
    event_stream_rows: i64,
    event_stream_logical_bytes: i64,
    catalog_journal_rows: i64,
    catalog_journal_logical_bytes: i64,
    ledger_command_count: i64,
    ledger_accepted_count: i64,
    ledger_accepted_payload_bytes: i64,
    ledger_pin_count: i64,
    ledger_event_count: i64,
    ledger_audit_event_logical_bytes: i64,
    ledger_event_stream_count: i64,
    ledger_event_stream_bytes: i64,
    ledger_catalog_delta_count: i64,
    ledger_catalog_delta_bytes: i64,
    ledger_configuration_count: i64,
    ledger_configuration_sealed_bytes: i64,
    conversation_accepted_count: i64,
    catalog_high_water: Option<String>,
    command_high_water: Option<String>,
    event_high_water: Option<String>,
    configuration_head: Option<String>,
    tables: Vec<TableSnapshot>,
}

#[derive(Clone, Debug, Eq, PartialEq)]
enum SqlCell {
    Null,
    Integer(i64),
    RealBits(u64),
    Text(Vec<u8>),
    Blob(Vec<u8>),
}

impl SqlCell {
    fn from_value(value: ValueRef<'_>) -> Self {
        match value {
            ValueRef::Null => Self::Null,
            ValueRef::Integer(value) => Self::Integer(value),
            ValueRef::Real(value) => Self::RealBits(value.to_bits()),
            ValueRef::Text(value) => Self::Text(value.to_vec()),
            ValueRef::Blob(value) => Self::Blob(value.to_vec()),
        }
    }

    fn retained_bytes(value: &ValueRef<'_>) -> usize {
        match value {
            ValueRef::Null => 1,
            ValueRef::Integer(_) | ValueRef::Real(_) => 8,
            ValueRef::Text(value) | ValueRef::Blob(value) => value.len(),
        }
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
struct TableSnapshot {
    table: &'static str,
    columns: Vec<String>,
    rows: Vec<Vec<SqlCell>>,
    retained_bytes: usize,
}

fn table_snapshot(
    transaction: &Transaction<'_>,
    table: &'static str,
    sql: &str,
    parameters: &[&dyn ToSql],
) -> TableSnapshot {
    let mut statement = transaction
        .prepare(sql)
        .unwrap_or_else(|error| panic!("prepare {table} evidence snapshot: {error}"));
    let columns = statement
        .column_names()
        .into_iter()
        .map(str::to_owned)
        .collect::<Vec<_>>();
    let column_count = statement.column_count();
    assert!(
        column_count <= EVIDENCE_MAX_COLUMNS_PER_TABLE,
        "{table} evidence exceeds {EVIDENCE_MAX_COLUMNS_PER_TABLE} columns"
    );
    let mut retained_bytes = table.len();
    for column in &columns {
        retained_bytes = retained_bytes
            .checked_add(column.len())
            .expect("evidence column byte count fits usize");
    }
    assert!(
        retained_bytes <= EVIDENCE_MAX_BYTES_PER_TABLE,
        "{table} evidence columns exceed {EVIDENCE_MAX_BYTES_PER_TABLE} retained bytes"
    );
    let mut query = statement
        .query(parameters)
        .unwrap_or_else(|error| panic!("query {table} evidence snapshot: {error}"));
    let mut rows = Vec::new();
    while let Some(row) = query
        .next()
        .unwrap_or_else(|error| panic!("iterate {table} evidence snapshot: {error}"))
    {
        assert!(
            rows.len() < EVIDENCE_MAX_ROWS_PER_TABLE,
            "{table} evidence exceeds {EVIDENCE_MAX_ROWS_PER_TABLE} rows"
        );
        let mut cells = Vec::with_capacity(column_count);
        for index in 0..column_count {
            let value = row
                .get_ref(index)
                .unwrap_or_else(|error| panic!("read {table} evidence cell: {error}"));
            retained_bytes = retained_bytes
                .checked_add(SqlCell::retained_bytes(&value))
                .expect("evidence cell byte count fits usize");
            assert!(
                retained_bytes <= EVIDENCE_MAX_BYTES_PER_TABLE,
                "{table} evidence exceeds {EVIDENCE_MAX_BYTES_PER_TABLE} retained bytes"
            );
            let cell = SqlCell::from_value(value);
            cells.push(cell);
        }
        rows.push(cells);
    }
    TableSnapshot {
        table,
        columns,
        rows,
        retained_bytes,
    }
}

fn command_evidence(path: &Path, conversation_id: RuntimeId) -> CommandEvidence {
    let mut connection = Connection::open_with_flags(path, OpenFlags::SQLITE_OPEN_READ_ONLY)
        .expect("open read-only command evidence connection");
    let transaction = connection
        .transaction()
        .expect("begin consistent read-only command evidence transaction");
    let evidence = transaction
        .query_row(
            "SELECT
                 (SELECT COUNT(*) FROM commands WHERE conversation_id = ?1),
                 (SELECT COUNT(*) FROM command_configuration_pins
                    WHERE conversation_id = ?1),
                 (SELECT COUNT(*) FROM configuration_journal),
                 (SELECT COALESCE(SUM(length(sealed_request)), 0)
                    FROM configuration_journal),
                 (SELECT COUNT(*) FROM event_journal),
                 (SELECT COALESCE(SUM(logical_event_bytes), 0) FROM event_journal),
                 (SELECT COUNT(*) FROM event_stream_index),
                 (SELECT COALESCE(SUM(logical_event_bytes), 0)
                    FROM event_stream_index),
                 (SELECT COUNT(*) FROM catalog_journal),
                 (SELECT COALESCE(SUM(logical_delta_bytes), 0) FROM catalog_journal),
                 m.command_count,
                 m.accepted_count,
                 m.accepted_payload_bytes,
                 m.command_configuration_pin_count,
                 m.event_count,
                 m.audit_event_logical_bytes,
                 m.event_stream_count,
                 m.event_stream_bytes,
                 m.catalog_delta_count,
                 m.catalog_delta_bytes,
                 m.configuration_count,
                 m.configuration_sealed_bytes,
                 c.accepted_count,
                 m.catalog_high_water,
                 c.command_high_water,
                 c.event_high_water,
                 s.current_configuration_revision,
                 (SELECT COUNT(*) FROM commands),
                 (SELECT COUNT(*) FROM command_configuration_pins),
                 (SELECT COUNT(*) FROM commands WHERE state = 'accepted'),
                 (SELECT COALESCE(SUM(logical_payload_bytes), 0)
                    FROM commands WHERE state = 'accepted'),
                 (SELECT COUNT(*) FROM commands
                    WHERE conversation_id = ?1 AND state = 'accepted'),
                 (SELECT COALESCE(SUM(logical_payload_bytes), 0) FROM commands
                    WHERE conversation_id = ?1 AND state = 'accepted')
             FROM runtime_meta AS m
             JOIN conversations AS c ON c.conversation_id = ?1
             JOIN conversation_state AS s ON s.conversation_id = c.conversation_id
             WHERE m.singleton = 1",
            [&conversation_id.as_bytes()[..]],
            |row| {
                Ok(CommandEvidence {
                    command_rows: row.get(0)?,
                    pin_rows: row.get(1)?,
                    configuration_rows: row.get(2)?,
                    configuration_sealed_bytes: row.get(3)?,
                    event_journal_rows: row.get(4)?,
                    event_journal_logical_bytes: row.get(5)?,
                    event_stream_rows: row.get(6)?,
                    event_stream_logical_bytes: row.get(7)?,
                    catalog_journal_rows: row.get(8)?,
                    catalog_journal_logical_bytes: row.get(9)?,
                    ledger_command_count: row.get(10)?,
                    ledger_accepted_count: row.get(11)?,
                    ledger_accepted_payload_bytes: row.get(12)?,
                    ledger_pin_count: row.get(13)?,
                    ledger_event_count: row.get(14)?,
                    ledger_audit_event_logical_bytes: row.get(15)?,
                    ledger_event_stream_count: row.get(16)?,
                    ledger_event_stream_bytes: row.get(17)?,
                    ledger_catalog_delta_count: row.get(18)?,
                    ledger_catalog_delta_bytes: row.get(19)?,
                    ledger_configuration_count: row.get(20)?,
                    ledger_configuration_sealed_bytes: row.get(21)?,
                    conversation_accepted_count: row.get(22)?,
                    catalog_high_water: row.get(23)?,
                    command_high_water: row.get(24)?,
                    event_high_water: row.get(25)?,
                    configuration_head: row.get(26)?,
                    global_command_rows: row.get(27)?,
                    global_pin_rows: row.get(28)?,
                    global_accepted_rows: row.get(29)?,
                    global_accepted_payload_bytes: row.get(30)?,
                    conversation_accepted_rows: row.get(31)?,
                    conversation_accepted_payload_bytes: row.get(32)?,
                    tables: Vec::new(),
                })
            },
        )
        .expect("read command write evidence");
    let conversation_bytes: &[u8] = conversation_id.as_bytes();
    let target: [&dyn ToSql; 1] = [&conversation_bytes];
    let evidence = CommandEvidence {
        tables: vec![
            table_snapshot(
                &transaction,
                "runtime_meta",
                "SELECT * FROM runtime_meta WHERE singleton = 1 ORDER BY singleton",
                &[],
            ),
            table_snapshot(
                &transaction,
                "conversations",
                "SELECT * FROM conversations WHERE conversation_id = ?1 ORDER BY conversation_id",
                &target,
            ),
            table_snapshot(
                &transaction,
                "conversation_state",
                "SELECT * FROM conversation_state WHERE conversation_id = ?1 ORDER BY conversation_id",
                &target,
            ),
            table_snapshot(
                &transaction,
                "commands",
                "SELECT * FROM commands WHERE conversation_id = ?1 ORDER BY conversation_id, command_seq",
                &target,
            ),
            table_snapshot(
                &transaction,
                "command_configuration_pins",
                "SELECT * FROM command_configuration_pins WHERE conversation_id = ?1 ORDER BY conversation_id, command_seq",
                &target,
            ),
            table_snapshot(
                &transaction,
                "configuration_journal",
                "SELECT * FROM configuration_journal WHERE conversation_id = ?1 ORDER BY conversation_id, configuration_revision",
                &target,
            ),
            table_snapshot(
                &transaction,
                "event_journal",
                "SELECT * FROM event_journal WHERE conversation_id = ?1 ORDER BY conversation_id, event_seq",
                &target,
            ),
            table_snapshot(
                &transaction,
                "event_stream_index",
                "SELECT * FROM event_stream_index WHERE conversation_id = ?1 ORDER BY conversation_id, event_seq",
                &target,
            ),
            table_snapshot(
                &transaction,
                "catalog_journal",
                "SELECT * FROM catalog_journal WHERE conversation_id = ?1 ORDER BY catalog_revision",
                &target,
            ),
        ],
        ..evidence
    };
    transaction
        .commit()
        .expect("commit consistent read-only command evidence transaction");
    evidence
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
    assert_eq!(evidence.global_command_rows, 0);
    assert_eq!(evidence.global_pin_rows, 0);
    assert_eq!(evidence.global_accepted_rows, 0);
    assert_eq!(evidence.global_accepted_payload_bytes, 0);
    assert_eq!(evidence.conversation_accepted_rows, 0);
    assert_eq!(evidence.conversation_accepted_payload_bytes, 0);
    assert_eq!(evidence.ledger_command_count, 0);
    assert_eq!(evidence.ledger_accepted_count, 0);
    assert_eq!(evidence.ledger_accepted_payload_bytes, 0);
    assert_eq!(evidence.ledger_pin_count, 0);
    assert_eq!(evidence.conversation_accepted_count, 0);
    assert_eq!(evidence.command_high_water, None);
}

fn assert_physical_totals_match_ledger(evidence: &CommandEvidence) {
    assert_eq!(evidence.global_command_rows, evidence.ledger_command_count);
    assert_eq!(evidence.global_pin_rows, evidence.ledger_pin_count);
    assert_eq!(
        evidence.global_accepted_rows,
        evidence.ledger_accepted_count
    );
    assert_eq!(
        evidence.global_accepted_payload_bytes,
        evidence.ledger_accepted_payload_bytes
    );
    assert_eq!(
        evidence.conversation_accepted_rows,
        evidence.conversation_accepted_count
    );
    assert_eq!(
        i64::try_from(
            evidence
                .tables
                .iter()
                .find(|snapshot| snapshot.table == "commands")
                .expect("commands evidence snapshot")
                .rows
                .len()
        )
        .expect("commands evidence row count fits i64"),
        evidence.command_rows
    );
    assert_eq!(
        i64::try_from(
            evidence
                .tables
                .iter()
                .find(|snapshot| snapshot.table == "command_configuration_pins")
                .expect("pin evidence snapshot")
                .rows
                .len()
        )
        .expect("pin evidence row count fits i64"),
        evidence.pin_rows
    );
    assert_eq!(
        evidence.configuration_rows,
        evidence.ledger_configuration_count
    );
    assert_eq!(
        evidence.configuration_sealed_bytes,
        evidence.ledger_configuration_sealed_bytes
    );
    assert_eq!(evidence.event_journal_rows, evidence.ledger_event_count);
    assert_eq!(
        evidence.event_journal_logical_bytes,
        evidence.ledger_audit_event_logical_bytes
    );
    assert_eq!(
        evidence.event_stream_rows,
        evidence.ledger_event_stream_count
    );
    assert_eq!(
        evidence.event_stream_logical_bytes,
        evidence.ledger_event_stream_bytes
    );
    assert_eq!(
        evidence.catalog_journal_rows,
        evidence.ledger_catalog_delta_count
    );
    assert_eq!(
        evidence.catalog_journal_logical_bytes,
        evidence.ledger_catalog_delta_bytes
    );
}

fn evidence_table<'a>(evidence: &'a CommandEvidence, table: &str) -> &'a TableSnapshot {
    evidence
        .tables
        .iter()
        .find(|snapshot| snapshot.table == table)
        .unwrap_or_else(|| panic!("missing {table} evidence snapshot"))
}

fn assert_one_accepted_command(evidence: &CommandEvidence, payload_bytes: usize) {
    let payload_bytes = i64::try_from(payload_bytes).expect("payload length fits i64");
    assert_eq!(evidence.command_rows, 1);
    assert_eq!(evidence.pin_rows, 1);
    assert_eq!(evidence.global_command_rows, 1);
    assert_eq!(evidence.global_pin_rows, 1);
    assert_eq!(evidence.global_accepted_rows, 1);
    assert_eq!(evidence.global_accepted_payload_bytes, payload_bytes);
    assert_eq!(evidence.conversation_accepted_rows, 1);
    assert_eq!(evidence.conversation_accepted_payload_bytes, payload_bytes);
    assert_eq!(evidence.conversation_accepted_count, 1);
    assert_eq!(
        evidence.command_high_water.as_deref(),
        Some("00000000000000000000")
    );
    assert_physical_totals_match_ledger(evidence);
}

fn assert_accept_delta(
    baseline: &CommandEvidence,
    accepted: &CommandEvidence,
    payload_bytes: usize,
) {
    assert_zero_command_state(baseline);
    assert_one_accepted_command(accepted, payload_bytes);
    assert_one_accept_increment(baseline, accepted, payload_bytes);
}

fn assert_one_accept_increment(
    baseline: &CommandEvidence,
    accepted: &CommandEvidence,
    payload_bytes: usize,
) {
    let payload_bytes = i64::try_from(payload_bytes).expect("payload length fits i64");
    for (before, after, label) in [
        (
            baseline.command_rows,
            accepted.command_rows,
            "conversation commands",
        ),
        (baseline.pin_rows, accepted.pin_rows, "conversation pins"),
        (
            baseline.global_command_rows,
            accepted.global_command_rows,
            "global commands",
        ),
        (
            baseline.global_pin_rows,
            accepted.global_pin_rows,
            "global pins",
        ),
        (
            baseline.global_accepted_rows,
            accepted.global_accepted_rows,
            "global accepted commands",
        ),
        (
            baseline.conversation_accepted_rows,
            accepted.conversation_accepted_rows,
            "conversation accepted commands",
        ),
        (
            baseline.ledger_command_count,
            accepted.ledger_command_count,
            "ledger commands",
        ),
        (
            baseline.ledger_accepted_count,
            accepted.ledger_accepted_count,
            "ledger accepted commands",
        ),
        (
            baseline.ledger_pin_count,
            accepted.ledger_pin_count,
            "ledger pins",
        ),
        (
            baseline.conversation_accepted_count,
            accepted.conversation_accepted_count,
            "conversation accepted ledger",
        ),
    ] {
        assert_eq!(after, before + 1, "Accept must add exactly one {label}");
    }
    assert_eq!(
        accepted.global_accepted_payload_bytes,
        baseline.global_accepted_payload_bytes + payload_bytes
    );
    assert_eq!(
        accepted.conversation_accepted_payload_bytes,
        baseline.conversation_accepted_payload_bytes + payload_bytes
    );
    assert_eq!(
        accepted.ledger_accepted_payload_bytes,
        baseline.ledger_accepted_payload_bytes + payload_bytes
    );

    for table in ["commands", "command_configuration_pins"] {
        let before = evidence_table(baseline, table);
        let after = evidence_table(accepted, table);
        assert_eq!(after.columns, before.columns);
        assert_eq!(
            after.rows.len(),
            before.rows.len() + 1,
            "Accept must append exactly one {table} row"
        );
        assert_eq!(
            &after.rows[..before.rows.len()],
            before.rows.as_slice(),
            "Accept must preserve existing {table} rows"
        );
    }
    for table in [
        "conversation_state",
        "configuration_journal",
        "event_journal",
        "event_stream_index",
        "catalog_journal",
    ] {
        assert_eq!(
            evidence_table(accepted, table),
            evidence_table(baseline, table),
            "Accept must not change {table} content"
        );
    }
    assert_eq!(accepted.catalog_high_water, baseline.catalog_high_water);
    assert_eq!(accepted.event_high_water, baseline.event_high_water);
    assert_eq!(accepted.configuration_head, baseline.configuration_head);
    assert_physical_totals_match_ledger(accepted);
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

    for (relationship, expected_revision) in [("stale", 0), ("future", 2)] {
        let error = store
            .accept_command(accept_request(
                conversation_id,
                &owner(0x33),
                &format!("{relationship}-revision-{expected_revision}"),
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
                "expected ConfigurationConflict for {relationship} revision {expected_revision}, got {other:?}"
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
        let tampered_evidence = command_evidence(&root.database(), conversation_id);
        assert_ne!(
            tampered_evidence, baseline,
            "content evidence must observe the intentional {tamper} mutation"
        );

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
                tampered_evidence,
                "rejecting tampered head must not add drift beyond the injected mutation"
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
    let tampered_evidence = command_evidence(&root.database(), conversation_id);
    assert_ne!(
        tampered_evidence, baseline,
        "content evidence must observe the injected revision gap"
    );

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
        tampered_evidence,
        "revision-gap rejection must not add drift beyond the injected mutation"
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

#[tokio::test]
async fn single_worker_linearizes_configure_before_prompt() {
    let root = TestRoot::new("configure-before-prompt");
    let keys = MemoryKeyStore::new();
    let database = root.database();
    let input = conversation(0x50);
    let conversation_id = input.conversation_id;
    let command_owner = owner(0x51);
    let stale_prompt = accept_request(
        conversation_id,
        &command_owner,
        "configure-first-prompt",
        1,
        b"prompt-must-not-cross-revision-two",
    );
    let current_prompt = accept_request(
        conversation_id,
        &command_owner,
        "configure-first-prompt",
        2,
        b"prompt-must-not-cross-revision-two",
    );
    let (before_entered_tx, before_entered_rx) = sync_channel(1);
    let (before_release_tx, before_release_rx) = sync_channel(1);
    let before_commit = Arc::new(BlockingOperationOnce::new(
        RuntimeStoreOperation::ConfigureConversationBeforeCommit,
        before_entered_tx,
        before_release_rx,
    ));
    let (after_entered_tx, after_entered_rx) = sync_channel(1);
    let (after_release_tx, after_release_rx) = sync_channel(1);
    let after_commit = Arc::new(BlockingOperationOnce::new(
        RuntimeStoreOperation::ConfigureConversationAfterCommit,
        after_entered_tx,
        after_release_rx,
    ));
    let store = RuntimeStoreHandle::open(
        RuntimeStoreConfig::new(database.clone())
            .with_command_capacity(1)
            .with_fault_injector(Arc::new(FaultChain(vec![
                before_commit.clone(),
                after_commit.clone(),
            ]))),
        root.storage_kek(&keys),
    )
    .await
    .expect("open Configure-first linearization store");
    store
        .create_conversation(input)
        .await
        .expect("create Configure-first conversation");
    assert_eq!(
        configure(
            &store,
            conversation_id,
            0x52,
            "configure-first-revision-one",
            0,
            CodexReasoningEffort::Low,
        )
        .await,
        1
    );
    let baseline = command_evidence(&database, conversation_id);
    assert_zero_command_state(&baseline);
    assert_eq!(
        baseline.configuration_head.as_deref(),
        Some("00000000000000000001")
    );
    assert_physical_totals_match_ledger(&baseline);

    let configure_revision_two = configure_request(
        conversation_id,
        0x53,
        "configure-first-revision-two",
        1,
        CodexReasoningEffort::High,
    );
    before_commit.arm();
    after_commit.arm();
    let configure_task = tokio::spawn({
        let store = store.clone();
        let request = configure_revision_two.clone();
        async move { store.configure_conversation(request).await }
    });
    wait_for_blocked_worker(before_entered_rx).await;

    // biased select 先 poll stale Prompt future；dispatch 的 try_send 在首次 poll 内完成。
    // worker 仍停在 rev2 Configure before-COMMIT，capacity=1 因而固定唯一排队顺序。
    let mut queued_prompt = Box::pin(store.accept_command(stale_prompt.clone()));
    tokio::select! {
        biased;
        result = &mut queued_prompt => {
            panic!("queued Prompt bypassed the blocked Configure transaction: {result:?}");
        }
        () = tokio::task::yield_now() => {}
    }
    let busy = store
        .accept_command(accept_request(
            conversation_id,
            &owner(0x54),
            "configure-first-capacity-probe",
            1,
            b"must-not-enter-the-full-normal-lane",
        ))
        .await
        .expect_err("third normal command proves stale Prompt occupies capacity-one queue");
    assert!(matches!(
        busy,
        RuntimeStoreError::WorkerBusy {
            lane: RuntimeStoreLane::Normal
        }
    ));
    assert_eq!(
        command_evidence(&database, conversation_id),
        baseline,
        "Configure barrier, queued Prompt and WorkerBusy probe must leave zero durable drift"
    );

    before_release_tx
        .send(())
        .expect("release Configure before-COMMIT barrier");
    wait_for_blocked_worker(after_entered_rx).await;
    let after_revision_two = command_evidence(&database, conversation_id);
    assert_zero_command_state(&after_revision_two);
    assert_eq!(after_revision_two.configuration_rows, 2);
    assert_eq!(
        after_revision_two.configuration_head.as_deref(),
        Some("00000000000000000002")
    );
    assert_physical_totals_match_ledger(&after_revision_two);
    after_release_tx
        .send(())
        .expect("release Configure after-COMMIT evidence barrier");
    let configured = configure_task
        .await
        .expect("join Configure-first task")
        .expect("Configure-first transaction commits");
    assert!(matches!(
        configured,
        ConfigureConversationOutcome::Applied { configuration }
            if configuration.configuration_revision == 2
    ));
    let stale_error = queued_prompt
        .await
        .expect_err("queued stale Prompt must observe committed revision two");
    assert!(matches!(
        stale_error,
        RuntimeStoreError::ConfigurationConflict {
            current_configuration_revision: 2
        }
    ));
    assert_eq!(
        command_evidence(&database, conversation_id),
        after_revision_two,
        "stale queued Prompt must not drift any command/pin/event/catalog evidence"
    );

    let command = accepted(
        store
            .accept_command(current_prompt.clone())
            .await
            .expect("current Prompt pins committed revision two"),
    );
    assert_eq!(command.configuration_revision, 2);
    assert_eq!(
        pinned_configuration_revision(&database, command.command_id),
        "00000000000000000002"
    );
    let committed = command_evidence(&database, conversation_id);
    assert_accept_delta(
        &after_revision_two,
        &committed,
        current_prompt.payload.len(),
    );
    assert_eq!(committed.configuration_rows, 2);
    assert_eq!(
        committed.configuration_head.as_deref(),
        Some("00000000000000000002")
    );
    let replayed = match store
        .accept_command(current_prompt)
        .await
        .expect("exact Prompt retry after Configure-first linearization")
    {
        AcceptOutcome::Replayed { command } => command,
        other => panic!("Configure-first exact retry must replay: {other:?}"),
    };
    assert_eq!(replayed.command_id, command.command_id);
    assert_eq!(replayed.configuration_revision, 2);
    assert_eq!(
        command_evidence(&database, conversation_id),
        committed,
        "Configure-first exact replay must not drift any durable evidence"
    );
    store
        .shutdown()
        .await
        .expect("shutdown Configure-first linearization store");
}

#[tokio::test]
async fn single_worker_linearizes_prompt_before_configure() {
    let root = TestRoot::new("prompt-before-configure");
    let keys = MemoryKeyStore::new();
    let database = root.database();
    let input = conversation(0x53);
    let conversation_id = input.conversation_id;
    let command_owner = owner(0x54);
    let prompt_request = accept_request(
        conversation_id,
        &command_owner,
        "prompt-first-command",
        1,
        b"prompt-must-pin-before-revision-two",
    );
    let (entered_tx, entered_rx) = sync_channel(1);
    let (release_tx, release_rx) = sync_channel(1);
    let before_commit = Arc::new(BlockingOperationOnce::new(
        RuntimeStoreOperation::AcceptCommandBeforeCommit,
        entered_tx,
        release_rx,
    ));
    let store = RuntimeStoreHandle::open(
        RuntimeStoreConfig::new(database.clone())
            .with_command_capacity(1)
            .with_fault_injector(before_commit.clone()),
        root.storage_kek(&keys),
    )
    .await
    .expect("open Prompt-first linearization store");
    store
        .create_conversation(input)
        .await
        .expect("create Prompt-first conversation");
    assert_eq!(
        configure(
            &store,
            conversation_id,
            0x55,
            "prompt-first-revision-one",
            0,
            CodexReasoningEffort::Low,
        )
        .await,
        1
    );
    let baseline = command_evidence(&database, conversation_id);
    assert_zero_command_state(&baseline);
    assert_eq!(
        baseline.configuration_head.as_deref(),
        Some("00000000000000000001")
    );
    assert_physical_totals_match_ledger(&baseline);

    before_commit.arm();
    let prompt_task = tokio::spawn({
        let store = store.clone();
        let request = prompt_request.clone();
        async move { store.accept_command(request).await }
    });
    wait_for_blocked_worker(entered_rx).await;

    // 与 Configure-first 对称：先 poll Configure future，确认它已进入 capacity=1 的
    // normal queue，再释放 Prompt 的 before-COMMIT barrier。
    let configure_revision_two = configure_request(
        conversation_id,
        0x56,
        "prompt-first-revision-two",
        1,
        CodexReasoningEffort::High,
    );
    let mut queued_configure =
        Box::pin(store.configure_conversation(configure_revision_two.clone()));
    tokio::select! {
        biased;
        result = &mut queued_configure => {
            panic!("queued Configure bypassed the blocked Prompt transaction: {result:?}");
        }
        () = tokio::task::yield_now() => {}
    }
    let busy = store
        .accept_command(accept_request(
            conversation_id,
            &owner(0x57),
            "prompt-first-capacity-probe",
            1,
            b"must-not-enter-the-full-normal-lane",
        ))
        .await
        .expect_err("third normal command proves Configure occupies capacity-one queue");
    assert!(matches!(
        busy,
        RuntimeStoreError::WorkerBusy {
            lane: RuntimeStoreLane::Normal
        }
    ));
    assert_eq!(
        command_evidence(&database, conversation_id),
        baseline,
        "Prompt barrier, queued Configure and WorkerBusy probe must leave zero durable drift"
    );

    release_tx
        .send(())
        .expect("release Prompt before-COMMIT barrier");
    let command = accepted(
        prompt_task
            .await
            .expect("join Prompt-first task")
            .expect("Prompt-first transaction commits"),
    );
    assert_eq!(command.configuration_revision, 1);
    let configured = queued_configure
        .await
        .expect("queued Configure advances the head after Prompt commit");
    assert!(matches!(
        configured,
        ConfigureConversationOutcome::Applied { configuration }
            if configuration.configuration_revision == 2
    ));
    assert_eq!(
        pinned_configuration_revision(&database, command.command_id),
        "00000000000000000001"
    );

    let committed = command_evidence(&database, conversation_id);
    assert_one_accepted_command(&committed, prompt_request.payload.len());
    assert_eq!(committed.configuration_rows, 2);
    assert_eq!(
        committed.configuration_head.as_deref(),
        Some("00000000000000000002")
    );
    let configure_replay = store
        .configure_conversation(configure_revision_two)
        .await
        .expect("exact Configure retry after Prompt-first linearization");
    assert!(matches!(
        configure_replay,
        ConfigureConversationOutcome::Replayed { configuration }
            if configuration.configuration_revision == 2
    ));
    assert_eq!(
        command_evidence(&database, conversation_id),
        committed,
        "Configure exact replay must not drift any durable evidence"
    );
    let replayed = match store
        .accept_command(prompt_request.clone())
        .await
        .expect("exact Prompt retry after head advances")
    {
        AcceptOutcome::Replayed { command } => command,
        other => panic!("Prompt-first exact retry must replay: {other:?}"),
    };
    assert_eq!(replayed.command_id, command.command_id);
    assert_eq!(replayed.configuration_revision, 1);
    assert_eq!(command_evidence(&database, conversation_id), committed);

    let conflict = store
        .accept_command(accept_request(
            conversation_id,
            &command_owner,
            &prompt_request.idempotency_key,
            2,
            &prompt_request.payload,
        ))
        .await
        .expect_err("same key cannot be rebound to the newer configuration revision");
    assert!(matches!(conflict, RuntimeStoreError::IdempotencyConflict));
    assert_eq!(
        command_evidence(&database, conversation_id),
        committed,
        "same-key conflict must not drift any command/pin/event/catalog evidence"
    );
    store
        .shutdown()
        .await
        .expect("shutdown Prompt-first linearization store");
}

#[tokio::test]
async fn accept_before_and_after_commit_faults_converge_to_one_command_and_pin() {
    for (label, operation, after_commit) in [
        (
            "before-commit",
            RuntimeStoreOperation::AcceptCommandBeforeCommit,
            false,
        ),
        (
            "after-commit",
            RuntimeStoreOperation::AcceptCommandAfterCommit,
            true,
        ),
    ] {
        let root = TestRoot::new(label);
        let keys = MemoryKeyStore::new();
        let database = root.database();
        let input = conversation(if after_commit { 0x58 } else { 0x57 });
        let conversation_id = input.conversation_id;
        let command_owner = owner(if after_commit { 0x68 } else { 0x67 });
        let request = accept_request(
            conversation_id,
            &command_owner,
            "commit-fault-command",
            1,
            b"commit-fault-payload",
        );
        let config = RuntimeStoreConfig::new(database.clone())
            .with_fault_injector(Arc::new(FailOperationOnce::new(operation)));
        let store = RuntimeStoreHandle::open(config.clone(), root.storage_kek(&keys))
            .await
            .expect("open Accept COMMIT fault store");
        store
            .create_conversation(input)
            .await
            .expect("create Accept COMMIT fault conversation");
        assert_eq!(
            configure(
                &store,
                conversation_id,
                0x69,
                "commit-fault-revision-one",
                0,
                CodexReasoningEffort::Medium,
            )
            .await,
            1
        );
        let baseline = command_evidence(&database, conversation_id);
        assert_zero_command_state(&baseline);
        assert_physical_totals_match_ledger(&baseline);

        let error = store
            .accept_command(request.clone())
            .await
            .expect_err("injected Accept COMMIT fault must hide the first outcome");
        if after_commit {
            assert_commit_unknown(error, RuntimeCommitOperation::AcceptCommand);
        } else {
            assert!(matches!(error, RuntimeStoreError::InvalidConfig(_)));
        }
        let after_fault = command_evidence(&database, conversation_id);
        if after_commit {
            assert_accept_delta(&baseline, &after_fault, request.payload.len());
        } else {
            assert_eq!(
                after_fault, baseline,
                "Accept before-COMMIT fault must roll back command, pin, ledger, event and catalog"
            );
        }
        assert_physical_totals_match_ledger(&after_fault);

        let retried = store
            .accept_command(request.clone())
            .await
            .expect("exact Accept retry converges after injected COMMIT fault");
        let command = match (after_commit, retried) {
            (false, AcceptOutcome::Accepted { command, .. })
            | (true, AcceptOutcome::Replayed { command }) => command,
            (false, other) => panic!("rolled-back Accept must commit on retry: {other:?}"),
            (true, other) => panic!("committed Accept must replay on retry: {other:?}"),
        };
        assert_eq!(command.configuration_revision, 1);
        assert_eq!(
            pinned_configuration_revision(&database, command.command_id),
            "00000000000000000001"
        );
        let after_retry = command_evidence(&database, conversation_id);
        assert_accept_delta(&baseline, &after_retry, request.payload.len());
        if after_commit {
            assert_eq!(
                after_retry, after_fault,
                "after-COMMIT exact retry must not duplicate or drift any durable evidence"
            );
        }
        assert_physical_totals_match_ledger(&after_retry);
        let receipt = store
            .query_command_receipt(receipt_by_idempotency(
                conversation_id,
                &request.idempotency_key,
                &command_owner,
            ))
            .await
            .expect("query converged Accept receipt");
        assert_eq!(receipt.command_id, command.command_id);
        assert_eq!(receipt.configuration_revision, 1);
        assert_eq!(receipt.state, CommandState::Accepted);
        store
            .shutdown()
            .await
            .expect("shutdown Accept COMMIT fault store");

        let reopened = RuntimeStoreHandle::open(config, root.storage_kek(&keys))
            .await
            .expect("reopen converged Accept COMMIT fault store");
        assert_eq!(
            command_evidence(&database, conversation_id),
            after_retry,
            "reopen integrity validation must preserve the complete accepted evidence"
        );
        let reopened_receipt = reopened
            .query_command_receipt(receipt_by_idempotency(
                conversation_id,
                &request.idempotency_key,
                &command_owner,
            ))
            .await
            .expect("query converged receipt after reopen");
        assert_eq!(reopened_receipt, receipt);

        let cursor = reopened
            .begin_recovery_scan()
            .await
            .expect("begin converged command recovery scan");
        let page = reopened
            .load_recovery_page(cursor)
            .await
            .expect("load converged command recovery page");
        let recovered = page
            .conversation
            .expect("single converged command recovery record");
        assert_eq!(recovered.accepted.len(), 1);
        assert_eq!(recovered.accepted[0].command_id, command.command_id);
        assert_eq!(recovered.accepted[0].configuration_revision, 1);
        assert!(recovered.started.is_none());
        assert!(page.next_cursor.is_none());
        reopened
            .finish_recovery_scan(page.completion.expect("single recovery page completion"))
            .await
            .expect("finish converged command recovery scan");
        assert_eq!(
            command_evidence(&database, conversation_id),
            after_retry,
            "recovery integrity validation must preserve the complete accepted evidence"
        );
        reopened
            .shutdown()
            .await
            .expect("shutdown reopened Accept COMMIT fault store");
    }
}

#[tokio::test]
async fn restart_and_recovery_preserve_revision_one_for_accepted_started_and_terminal() {
    let root = TestRoot::new("restart-all-command-states");
    let keys = MemoryKeyStore::new();
    let database = root.database();
    let config = RuntimeStoreConfig::new(database.clone());
    let store = RuntimeStoreHandle::open(config.clone(), root.storage_kek(&keys))
        .await
        .expect("open command-state restart store");

    let mut conversation_ids = Vec::new();
    let mut command_owners = Vec::new();
    let mut commands = Vec::new();
    for (index, seed) in [0x60_u8, 0x61, 0x62].into_iter().enumerate() {
        let input = conversation(seed);
        let conversation_id = input.conversation_id;
        let command_owner = owner(seed.wrapping_add(0x10));
        store
            .create_conversation(input)
            .await
            .expect("create command-state restart conversation");
        assert_eq!(
            configure(
                &store,
                conversation_id,
                seed.wrapping_add(0x20),
                &format!("command-state-{index}-revision-one"),
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
                    &format!("command-state-{index}"),
                    1,
                    format!("command-state-payload-{index}").as_bytes(),
                ))
                .await
                .expect("accept command-state restart fixture"),
        );
        assert_eq!(command.configuration_revision, 1);
        conversation_ids.push(conversation_id);
        command_owners.push(command_owner);
        commands.push(command);
    }

    let started_boot_id = runtime_id(RuntimeIdKind::DaemonBoot, 0x73);
    let started_nonce = b"restart-started-nonce".to_vec();
    let started = match store
        .mark_started_with_event(StartCommand {
            conversation_id: conversation_ids[1],
            command_id: commands[1].command_id,
            daemon_boot_id: started_boot_id,
            execution_nonce: started_nonce,
        })
        .await
        .expect("start revision-one command")
    {
        StartOutcome::Started { command, .. } => command,
        other => panic!("fresh revision-one command must start: {other:?}"),
    };
    assert_eq!(started.state, CommandState::Started);
    assert_eq!(started.configuration_revision, 1);
    commands[1] = started;

    let terminal_boot_id = runtime_id(RuntimeIdKind::DaemonBoot, 0x74);
    let terminal_nonce = b"restart-terminal-nonce".to_vec();
    let terminal_intent = match store
        .mark_started_with_event(StartCommand {
            conversation_id: conversation_ids[2],
            command_id: commands[2].command_id,
            daemon_boot_id: terminal_boot_id,
            execution_nonce: terminal_nonce.clone(),
        })
        .await
        .expect("start command before terminal transition")
    {
        StartOutcome::Started {
            command, intent, ..
        } => {
            assert_eq!(command.configuration_revision, 1);
            intent
        }
        other => panic!("fresh terminal fixture must start: {other:?}"),
    };
    let terminal = match store
        .terminate_started_before_release(TerminateStartedBeforeRelease {
            conversation_id: conversation_ids[2],
            command_id: commands[2].command_id,
            turn_id: terminal_intent.turn_id,
            daemon_boot_id: terminal_boot_id,
            execution_nonce: terminal_nonce,
            reason: StartedBeforeReleaseTermination::Canceled,
        })
        .await
        .expect("terminate revision-one command before release")
    {
        TerminateStartedBeforeReleaseOutcome::Transitioned { command, .. } => command,
        other => panic!("fresh started command must transition to terminal: {other:?}"),
    };
    assert_eq!(terminal.state, CommandState::Canceled);
    assert_eq!(terminal.configuration_revision, 1);
    commands[2] = terminal;

    for (index, conversation_id) in conversation_ids.iter().copied().enumerate() {
        assert_eq!(
            configure(
                &store,
                conversation_id,
                0x80_u8.wrapping_add(u8::try_from(index).expect("small fixture index")),
                &format!("command-state-{index}-revision-two"),
                1,
                CodexReasoningEffort::High,
            )
            .await,
            2
        );
        assert_eq!(
            pinned_configuration_revision(&database, commands[index].command_id),
            "00000000000000000001"
        );
    }
    store
        .shutdown()
        .await
        .expect("shutdown command-state writer before restart");

    let reopened = RuntimeStoreHandle::open(config, root.storage_kek(&keys))
        .await
        .expect("reopen accepted/started/terminal command store");
    for (index, expected_state) in [
        CommandState::Accepted,
        CommandState::Started,
        CommandState::Canceled,
    ]
    .into_iter()
    .enumerate()
    {
        let receipt = reopened
            .query_command_receipt(receipt_by_command(
                conversation_ids[index],
                commands[index].command_id,
                &command_owners[index],
            ))
            .await
            .expect("query command-state receipt after restart");
        assert_eq!(receipt.command_id, commands[index].command_id);
        assert_eq!(receipt.configuration_revision, 1);
        assert_eq!(receipt.state, expected_state);
        assert_eq!(
            pinned_configuration_revision(&database, commands[index].command_id),
            "00000000000000000001"
        );
    }

    let mut cursor = reopened
        .begin_recovery_scan()
        .await
        .expect("begin command-state recovery scan");
    let mut recovered = Vec::new();
    let completion = loop {
        let page = reopened
            .load_recovery_page(cursor)
            .await
            .expect("load command-state recovery page");
        if let Some(conversation) = page.conversation {
            recovered.push(conversation);
        }
        if let Some(next_cursor) = page.next_cursor {
            assert!(page.completion.is_none());
            cursor = next_cursor;
        } else {
            break page
                .completion
                .expect("terminal recovery page signs completion");
        }
    };
    assert_eq!(recovered.len(), 3);

    let accepted_recovery = recovered
        .iter()
        .find(|record| record.conversation.conversation_id == conversation_ids[0])
        .expect("recover accepted conversation");
    assert_eq!(accepted_recovery.accepted.len(), 1);
    assert_eq!(
        accepted_recovery.accepted[0].command_id,
        commands[0].command_id
    );
    assert_eq!(accepted_recovery.accepted[0].configuration_revision, 1);
    assert!(accepted_recovery.started.is_none());

    let started_recovery = recovered
        .iter()
        .find(|record| record.conversation.conversation_id == conversation_ids[1])
        .expect("recover started conversation");
    assert!(started_recovery.accepted.is_empty());
    let recovered_started = started_recovery
        .started
        .as_ref()
        .expect("recover started command");
    assert_eq!(recovered_started.command.command_id, commands[1].command_id);
    assert_eq!(recovered_started.command.configuration_revision, 1);

    let terminal_recovery = recovered
        .iter()
        .find(|record| record.conversation.conversation_id == conversation_ids[2])
        .expect("recover terminal conversation");
    assert!(terminal_recovery.accepted.is_empty());
    assert!(terminal_recovery.started.is_none());

    reopened
        .finish_recovery_scan(completion)
        .await
        .expect("finish accepted/started/terminal recovery scan");
    assert_eq!(
        global_command_evidence(&database),
        (3, 3, 3, 1, 3),
        "restart/recovery must preserve global command/pin physical and authenticated totals"
    );
    for (index, conversation_id) in conversation_ids.iter().copied().enumerate() {
        let evidence = command_evidence(&database, conversation_id);
        assert_eq!(evidence.command_rows, 1);
        assert_eq!(evidence.pin_rows, 1);
        assert_eq!(
            evidence.configuration_head.as_deref(),
            Some("00000000000000000002")
        );
        assert_physical_totals_match_ledger(&evidence);
        assert_eq!(
            pinned_configuration_revision(&database, commands[index].command_id),
            "00000000000000000001"
        );
    }
    reopened
        .shutdown()
        .await
        .expect("shutdown reopened command-state store");
}

#[tokio::test]
async fn disk_low_fresh_accept_is_zero_write_and_same_handle_recovers() {
    let root = TestRoot::new("disk-low-accept");
    let keys = MemoryKeyStore::new();
    let database = root.database();
    let input = conversation(0x70);
    let conversation_id = input.conversation_id;
    let probe = MutableCapacityProbe::new(healthy_capacity());
    let store = RuntimeStoreHandle::open(
        RuntimeStoreConfig::new(database.clone()).with_capacity_probe(probe.clone()),
        root.storage_kek(&keys),
    )
    .await
    .expect("open DiskLow command store");
    store
        .create_conversation(input)
        .await
        .expect("create DiskLow conversation");
    assert_eq!(
        configure(
            &store,
            conversation_id,
            0x71,
            "disk-low-revision-one",
            0,
            CodexReasoningEffort::Medium,
        )
        .await,
        1
    );

    let baseline = command_evidence(&database, conversation_id);
    assert_zero_command_state(&baseline);
    assert_physical_totals_match_ledger(&baseline);
    let command_owner = owner(0x72);
    let request = accept_request(
        conversation_id,
        &command_owner,
        "disk-low-command",
        1,
        b"persist only after capacity recovers",
    );

    probe.set(disk_low_capacity());
    let error = store
        .accept_command(request.clone())
        .await
        .expect_err("DiskLow must reject a fresh Accept before its first durable write");
    assert!(matches!(error, RuntimeStoreError::DiskLow { .. }));
    assert_eq!(error.code(), "daemon.runtime.disk_low");
    assert_eq!(
        command_evidence(&database, conversation_id),
        baseline,
        "DiskLow rejection must not drift command, pin, ledger, event or catalog evidence"
    );

    probe.set(healthy_capacity());
    let command = accepted(
        store
            .accept_command(request.clone())
            .await
            .expect("the same handle must recover after DiskLow clears"),
    );
    assert_eq!(command.configuration_revision, 1);
    let accepted_evidence = command_evidence(&database, conversation_id);
    assert_accept_delta(&baseline, &accepted_evidence, request.payload.len());

    probe.set(disk_low_capacity());
    let replayed = match store
        .accept_command(request)
        .await
        .expect("exact replay must remain read-only under DiskLow")
    {
        AcceptOutcome::Replayed { command } => command,
        other => panic!("expected DiskLow exact replay, got {other:?}"),
    };
    assert_eq!(replayed.command_id, command.command_id);
    assert_eq!(replayed.configuration_revision, 1);
    assert_eq!(
        command_evidence(&database, conversation_id),
        accepted_evidence,
        "DiskLow exact replay must not drift command, pin, ledger, event or catalog evidence"
    );

    probe.set(healthy_capacity());
    store
        .shutdown()
        .await
        .expect("shutdown recovered DiskLow command store");
}

#[tokio::test]
async fn store_full_latches_until_reopen_while_exact_replay_is_zero_write() {
    let root = TestRoot::new("store-full-accept");
    let keys = MemoryKeyStore::new();
    let database = root.database();
    let input = conversation(0x73);
    let conversation_id = input.conversation_id;
    let probe = MutableCapacityProbe::new(healthy_capacity());
    let config = RuntimeStoreConfig::new(database.clone()).with_capacity_probe(probe.clone());
    let store = RuntimeStoreHandle::open(config.clone(), root.storage_kek(&keys))
        .await
        .expect("open StoreFull command store");
    store
        .create_conversation(input)
        .await
        .expect("create StoreFull conversation");
    assert_eq!(
        configure(
            &store,
            conversation_id,
            0x74,
            "store-full-revision-one",
            0,
            CodexReasoningEffort::Medium,
        )
        .await,
        1
    );

    let command_owner = owner(0x75);
    let seed_request = accept_request(
        conversation_id,
        &command_owner,
        "store-full-seed",
        1,
        b"durable seed for exact replay",
    );
    let seed = accepted(
        store
            .accept_command(seed_request.clone())
            .await
            .expect("accept seed command before StoreFull"),
    );
    let baseline = command_evidence(&database, conversation_id);
    assert_one_accepted_command(&baseline, seed_request.payload.len());
    let blocked_request = accept_request(
        conversation_id,
        &command_owner,
        "store-full-blocked",
        1,
        b"persist only after reopen",
    );

    probe.set(over_limit_capacity());
    let error = store
        .accept_command(blocked_request.clone())
        .await
        .expect_err("StoreFull must reject and latch a fresh Accept");
    assert!(matches!(error, RuntimeStoreError::StoreFull { .. }));
    assert_eq!(error.code(), "daemon.runtime.store_full");
    assert_eq!(
        command_evidence(&database, conversation_id),
        baseline,
        "StoreFull rejection must not drift command, pin, ledger, event or catalog evidence"
    );

    let replayed = match store
        .accept_command(seed_request.clone())
        .await
        .expect("exact replay must bypass StoreFull and the SafetyOnly latch")
    {
        AcceptOutcome::Replayed { command } => command,
        other => panic!("expected StoreFull exact replay, got {other:?}"),
    };
    assert_eq!(replayed.command_id, seed.command_id);
    assert_eq!(replayed.configuration_revision, 1);
    assert_eq!(
        command_evidence(&database, conversation_id),
        baseline,
        "StoreFull exact replay must not drift durable evidence"
    );

    probe.set(healthy_capacity());
    let latched = store
        .accept_command(blocked_request.clone())
        .await
        .expect_err("healthy capacity must not clear SafetyOnly on the same handle");
    assert!(matches!(latched, RuntimeStoreError::SafetyOnly));
    assert_eq!(latched.code(), "daemon.runtime.safety_only");
    assert_eq!(
        command_evidence(&database, conversation_id),
        baseline,
        "SafetyOnly rejection must preserve the pre-latch durable evidence"
    );

    store
        .shutdown()
        .await
        .expect("shutdown StoreFull-latched command store");
    let reopened = RuntimeStoreHandle::open(config, root.storage_kek(&keys))
        .await
        .expect("reopen command store after capacity recovers");
    let replayed_after_reopen = match reopened
        .accept_command(seed_request)
        .await
        .expect("seed exact replay must remain read-only after reopen")
    {
        AcceptOutcome::Replayed { command } => command,
        other => panic!("expected exact replay after reopen, got {other:?}"),
    };
    assert_eq!(replayed_after_reopen.command_id, seed.command_id);
    assert_eq!(
        command_evidence(&database, conversation_id),
        baseline,
        "reopen and exact replay must preserve pre-existing durable evidence"
    );

    let accepted_after_reopen = accepted(
        reopened
            .accept_command(blocked_request.clone())
            .await
            .expect("reopen must clear the handle-local SafetyOnly latch"),
    );
    assert_eq!(accepted_after_reopen.configuration_revision, 1);
    let recovered = command_evidence(&database, conversation_id);
    assert_one_accept_increment(&baseline, &recovered, blocked_request.payload.len());

    reopened
        .shutdown()
        .await
        .expect("shutdown recovered StoreFull command store");
}
