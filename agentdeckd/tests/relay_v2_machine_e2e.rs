//! P4.7 automatic candidate：真实 Relay / daemon / persistent remote client 全链路。
//!
//! 本测试刻意只替换 vendor 进程为 debug-only synthetic adapter；Relay Direct TLS、
//! enrollment、PairingCoordinator、stable same-UID UDS、RuntimeCore、RemoteManager、
//! production RemoteLink、Device E2EE 与 persistent remote state 全部使用生产组合。

#![cfg(all(unix, debug_assertions))]

use std::collections::HashSet;
use std::env;
use std::fs;
use std::fs::OpenOptions;
use std::io::{self, Write};
use std::net::{SocketAddr, TcpListener as StdTcpListener};
use std::os::unix::fs::{FileTypeExt, OpenOptionsExt, PermissionsExt};
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Condvar, Mutex};
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use agentdeck_cli::installation::{CliInstallationStore, InstallationId};
use agentdeck_cli::remote::conversations::list_persistent_remote_conversations;
use agentdeck_cli::remote::keychain::{
    MemoryRemoteKeyStore, ParsedPairedRemoteKeyAccount, RemoteKeyAccount, RemoteKeyPersistence,
    RemoteKeyStore, RemoteKeyStoreError, RemoteSecret,
};
use agentdeck_cli::remote::machines::list_persistent_remote_machines;
use agentdeck_cli::remote::mutations::{
    PersistentRemoteMutation, PersistentRemoteMutationError, PersistentRemoteMutationOutcome,
    execute_persistent_remote_mutation,
};
use agentdeck_cli::remote::pair::{
    confirm_machine_root_fingerprint, mvp_authorization, pair_production,
};
use agentdeck_cli::remote::paired_machine::PairedMachineIdentity;
use agentdeck_cli::remote::pending::PendingPairingCoordinator;
use agentdeck_cli::remote::production::{PersistentRemoteComposition, RecoveredPairedMachineStore};
use agentdeck_cli::remote::relay_transport::{PairedRuntimeConnectOutcome, connect_paired_runtime};
use agentdeck_cli::remote::runtime::{
    RemoteRuntime, RemoteRuntimeError, RemoteStreamFrameOutcome, RemoteSubscriptionBootstrapItem,
    RemoteSubscriptionReducer,
};
use agentdeck_cli::remote::selector::PersistentMachineSelector;
use agentdeck_cli::remote::signature::{
    CurrentRemoteCliSignatureVerifier, REMOTE_CLI_ACCESS_GROUP_SUFFIX, REMOTE_CLI_CODE_IDENTIFIER,
    RemoteCliSignatureAttestation, RemoteCliSignatureError, RemoteCliSignatureExpectation,
    RemoteCliSignatureKind,
};
use agentdeck_cli::remote::watch::{
    PersistentRemoteWatchControl, PersistentRemoteWatchExit, PersistentRemoteWatchRecord,
    watch_persistent_remote_conversation,
};
use agentdeck_cli::unix_transport::{InjectedEndpoint, ReplySequenceItem, RuntimeUnixClient};
use agentdeck_crypto::rand_core::SeedableRng;
use agentdeck_protocol::runtime::identity::{
    ApprovalId, CommandId, EntityId, EventId, ItemId, TurnId,
};
use agentdeck_protocol::runtime::{
    ApprovalDeliveryState, ApprovalReceipt, BackfillChunk, BackfillRange,
    ClaudeCodeConversationConfiguration, CodexConversationConfiguration, CommandReceipt,
    ConfigureConversationRequest, ConversationConfiguration, ConversationConfigurationState,
    ConversationId, ConversationMetadataMutation, ConversationMetadataMutationRequest,
    ConversationMetadataReceipt, ConversationSnapshot, ConversationStart, ConversationStartReceipt,
    CreatePairInviteRequest, IdempotencyKey, LocalOnlyAdministration, MachineEnrollRequest,
    MachineRemoteLifecycle, PromptPayload, QueryReceiptSelector, RevocationReceipt, RuntimeEvent,
    RuntimeEventBody, RuntimeInnerCursor, RuntimeReply, RuntimeRequest, RuntimeStreamItem,
    SendPromptRequest, SnapshotItem, StreamCursor, SubscriptionReceipt,
    VendorConfigurationSnapshot,
};
use agentdeck_protocol::{
    ActionDecision, ActionDecisionKind, ActionRequestVendor, AgentItem, AgentItemMeta, AgentKind,
    ClaudeCodePermissionMode, CodexApprovalPolicy, CodexCapabilities, CodexReasoningEffort,
    CodexSandboxMode, SessionCapabilities, VendorCapabilities,
};
use agentdeck_relay::config::{
    RelayReceiptSigningKeyPath, RelayV2AdminConfig, RelayV2ServerConfig, RelayV2StoreSettings,
    RelayV2TlsPaths, RelayV2TransportMode,
};
use agentdeck_relay::v2::admin::{AdminClient, AdminRequest, AdminResponse, AdminResult};
use agentdeck_relay::v2::server::tls::{TlsIdentityPaths, load_tls_identity};
use agentdeck_relay::v2::server::{RelayV2ServerError, RelayV2ServerHandle};
use agentdeckd::config::{DaemonConfig, DaemonStartupOptions};
use agentdeckd::local::listener::BoundLocalListener;
use agentdeckd::remote::bootstrap::reconcile_machine_identity;
use agentdeckd::remote::manager::RemoteManager;
use agentdeckd::runtime::singleton::SingletonGuard;
use agentdeckd::runtime::store::{RuntimeStoreConfig, RuntimeStoreHandle};
use agentdeckd::runtime::{RuntimeCore, synthetic_e2e};
use agentdeckd::security::{MemoryKeyStore, load_or_create_storage_kek};
use base64::{Engine as _, engine::general_purpose::STANDARD};
use rand_chacha::ChaCha20Rng;
use rusqlite::{Connection, OpenFlags};
use serde::{Deserialize, Serialize};
use tempfile::Builder as TempDirBuilder;
use tokio::io::{AsyncBufReadExt, BufReader};
use tokio::sync::{Notify, oneshot};

const IO_TIMEOUT: Duration = Duration::from_secs(15);
const PAIRING_TIMEOUT: Duration = Duration::from_secs(30);
const RECEIPT_SIGNER_SEED: [u8; 32] = [0x74; 32];
const REMOTE_CLI_TEAM: &str = "A1B2C3D4E5";
const P57_HOST_PROTOCOL: &str = "agentdeck-p57-host/v1";
const P57_HOST_ENABLE_ENV: &str = "AGENTDECK_P57_HOST";
const P57_HOST_PARENT_ENV: &str = "AGENTDECK_P57_HOST_PARENT";
const P57_HOST_SCENARIO_ENV: &str = "AGENTDECK_P57_HOST_SCENARIO";
const P57_HOST_R43_SCENARIO: &str = "r43-business";
const P57_HOST_R44_SCENARIO: &str = "r44-lifecycle";
const P57_HOST_R43_CONVERSATION_TITLE: &str = "R4.3 synthetic Codex";
const P57_HOST_R44_RESTART_MARKER_TITLE: &str = "R4.4 daemon restart marker";
const P57_HOST_MAX_COMMAND_BYTES: usize = 4 * 1_024;
const P57_HOST_MAX_WAIT_MS: u64 = 120_000;
static P57_HOST_OUTPUT_STARTED: AtomicBool = AtomicBool::new(false);

fn p57_host_parent() -> PathBuf {
    let Some(raw_parent) = env::var_os(P57_HOST_PARENT_ENV) else {
        return PathBuf::from("/tmp");
    };
    let requested = PathBuf::from(raw_parent);
    let parent = fs::canonicalize(&requested).expect("canonicalize injected P5.7 host parent");
    assert_eq!(
        requested, parent,
        "injected P5.7 host parent must already be canonical"
    );
    let metadata = fs::symlink_metadata(&parent).expect("read injected P5.7 host parent metadata");
    assert!(metadata.file_type().is_dir());
    assert_eq!(metadata.permissions().mode() & 0o777, 0o700);
    assert_eq!(parent.parent(), Some(Path::new("/private/tmp")));
    assert!(
        parent
            .file_name()
            .and_then(|name| name.to_str())
            .is_some_and(|name| name.starts_with("ar4."))
    );
    parent
}

fn p57_host_scenario() -> Option<&'static str> {
    match env::var(P57_HOST_SCENARIO_ENV).as_deref() {
        Err(env::VarError::NotPresent) => None,
        Ok(P57_HOST_R43_SCENARIO) => Some(P57_HOST_R43_SCENARIO),
        Ok(P57_HOST_R44_SCENARIO) => Some(P57_HOST_R44_SCENARIO),
        Ok(other) => panic!("unsupported P5.7 host scenario: {other}"),
        Err(env::VarError::NotUnicode(_)) => panic!("P5.7 host scenario must be UTF-8"),
    }
}

fn remote_cli_access_group() -> String {
    format!("{REMOTE_CLI_TEAM}{REMOTE_CLI_ACCESS_GROUP_SUFFIX}")
}

fn remote_cli_expectation() -> RemoteCliSignatureExpectation {
    RemoteCliSignatureExpectation::for_test(
        REMOTE_CLI_CODE_IDENTIFIER,
        REMOTE_CLI_TEAM,
        remote_cli_access_group(),
    )
    .expect("construct automatic production-signature expectation")
}

fn persistent_selector(identity: PairedMachineIdentity) -> PersistentMachineSelector {
    PersistentMachineSelector::parse(
        &STANDARD.encode(identity.machine_root_fingerprint().as_bytes()),
        &STANDARD.encode(identity.machine_route().as_bytes()),
    )
    .expect("construct exact persistent machine selector")
}

struct AcceptedRemoteCliSignatureVerifier;

impl CurrentRemoteCliSignatureVerifier for AcceptedRemoteCliSignatureVerifier {
    fn verify_current(
        &self,
        _expected: &RemoteCliSignatureExpectation,
    ) -> Result<RemoteCliSignatureAttestation, RemoteCliSignatureError> {
        Ok(RemoteCliSignatureAttestation::new(
            RemoteCliSignatureKind::Production,
            REMOTE_CLI_CODE_IDENTIFIER,
            REMOTE_CLI_TEAM,
            vec![remote_cli_access_group()],
        ))
    }
}

/// `MemoryRemoteKeyStore` 的 automatic-only 可快照包装；只用于在 revoke 前冻结两份旧凭据，
/// 让 active-connection terminal 与 fresh-auth terminal 可独立验证，绝不进入 production。
struct ForkableRemoteKeyStore {
    inner: MemoryRemoteKeyStore,
    accounts: Mutex<HashSet<RemoteKeyAccount>>,
}

impl ForkableRemoteKeyStore {
    fn new() -> Self {
        Self {
            inner: MemoryRemoteKeyStore::new(),
            accounts: Mutex::new(HashSet::new()),
        }
    }

    fn fork(&self) -> Result<Self, RemoteKeyStoreError> {
        let fork = Self::new();
        let accounts = self
            .accounts
            .lock()
            .map_err(|_| RemoteKeyStoreError::Poisoned)?;
        for account in accounts.iter() {
            if let Some(value) = self.inner.load(account)? {
                fork.persist_immutable(account, &value)?;
            }
        }
        Ok(fork)
    }
}

impl RemoteKeyStore for ForkableRemoteKeyStore {
    fn load(
        &self,
        account: &RemoteKeyAccount,
    ) -> Result<Option<RemoteSecret>, RemoteKeyStoreError> {
        self.inner.load(account)
    }

    fn persist_immutable(
        &self,
        account: &RemoteKeyAccount,
        value: &RemoteSecret,
    ) -> Result<RemoteKeyPersistence, RemoteKeyStoreError> {
        let outcome = self.inner.persist_immutable(account, value)?;
        self.accounts
            .lock()
            .map_err(|_| RemoteKeyStoreError::Poisoned)?
            .insert(account.clone());
        Ok(outcome)
    }

    fn compare_and_replace_exact(
        &self,
        account: &RemoteKeyAccount,
        expected: &RemoteSecret,
        replacement: &RemoteSecret,
    ) -> Result<(), RemoteKeyStoreError> {
        self.inner
            .compare_and_replace_exact(account, expected, replacement)
    }

    fn delete_exact(&self, account: &RemoteKeyAccount) -> Result<(), RemoteKeyStoreError> {
        self.inner.delete_exact(account)?;
        self.accounts
            .lock()
            .map_err(|_| RemoteKeyStoreError::Poisoned)?
            .remove(account);
        Ok(())
    }

    fn list_paired_commit_markers(
        &self,
        installation_id: uuid::Uuid,
    ) -> Result<Vec<ParsedPairedRemoteKeyAccount>, RemoteKeyStoreError> {
        self.inner.list_paired_commit_markers(installation_id)
    }
}

fn write_localhost_tls_identity(root: &Path) -> (PathBuf, PathBuf) {
    let certified = rcgen::generate_simple_self_signed(["localhost".to_owned()])
        .expect("generate localhost TLS certificate");
    let directory = root.join("relay-tls");
    fs::create_dir(&directory).expect("create Relay TLS directory");
    fs::set_permissions(&directory, fs::Permissions::from_mode(0o700))
        .expect("secure Relay TLS directory");
    let cert = directory.join("localhost-cert.pem");
    let key = directory.join("localhost-key.pem");
    fs::write(&cert, certified.cert.pem()).expect("write localhost certificate");
    fs::write(&key, certified.key_pair.serialize_pem()).expect("write localhost private key");
    fs::set_permissions(&cert, fs::Permissions::from_mode(0o600))
        .expect("secure localhost certificate");
    fs::set_permissions(&key, fs::Permissions::from_mode(0o600))
        .expect("secure localhost private key");
    (cert, key)
}

fn reserve_loopback_ports() -> (SocketAddr, SocketAddr) {
    let public = StdTcpListener::bind("127.0.0.1:0").expect("reserve Relay public port");
    let health = StdTcpListener::bind("127.0.0.1:0").expect("reserve Relay health port");
    let public_addr = public.local_addr().expect("public address");
    let health_addr = health.local_addr().expect("health address");
    drop((public, health));
    (public_addr, health_addr)
}

fn write_receipt_signing_key(root: &Path) -> RelayReceiptSigningKeyPath {
    let directory = root.join("receipt-signer");
    fs::create_dir(&directory).expect("create receipt signer directory");
    fs::set_permissions(&directory, fs::Permissions::from_mode(0o700))
        .expect("secure receipt signer directory");
    let directory = fs::canonicalize(directory).expect("canonicalize receipt signer directory");
    let path = directory.join("receipt-signing-key.seed");
    fs::write(&path, RECEIPT_SIGNER_SEED).expect("write receipt signer seed");
    fs::set_permissions(&path, fs::Permissions::from_mode(0o600))
        .expect("secure receipt signer seed");
    RelayReceiptSigningKeyPath::new(path)
}

async fn start_relay(
    root: &Path,
) -> Result<
    (
        RelayV2ServerHandle,
        agentdeck_protocol::relay_v2::EnrollmentBundleV2,
    ),
    RelayV2ServerError,
> {
    let (cert, key) = write_localhost_tls_identity(root);
    let identity = load_tls_identity(&TlsIdentityPaths::new(&cert, &key))
        .await
        .expect("load Relay test TLS identity");
    let (bind, health_bind) = reserve_loopback_ports();
    let admin_dir = root.join("relay-admin");
    fs::create_dir(&admin_dir).expect("create Relay admin directory");
    fs::set_permissions(&admin_dir, fs::Permissions::from_mode(0o700))
        .expect("secure Relay admin directory");
    let admin_socket = admin_dir.join("relay.sock");
    let mut store = RelayV2StoreSettings::new(root.join("relay-store/relay.db"));
    store.disk_reserve_bytes = 0;
    store.disk_reserve_percent = 0;
    let public_wss_url = format!("wss://localhost:{}/", bind.port());
    let handle = RelayV2ServerHandle::start(RelayV2ServerConfig {
        bind,
        health_bind,
        store,
        transport: RelayV2TransportMode::DirectTls(RelayV2TlsPaths { cert, key }),
        admin: Some(RelayV2AdminConfig {
            socket_path: admin_socket.clone(),
            public_wss_url,
            spki_pins: vec![identity.leaf_spki_sha256()],
        }),
        receipt_signing_key: write_receipt_signing_key(root),
        log_level: "info".to_owned(),
    })
    .await?;
    let response = AdminClient::new(admin_socket)
        .request(&AdminRequest::MachineEnrollCreate {})
        .await
        .expect("create one-shot machine enrollment bundle");
    let AdminResponse::Ok { result } = response else {
        panic!("Relay admin enrollment create failed: {response:?}");
    };
    let AdminResult::EnrollmentBundle { bundle } = *result else {
        panic!("Relay admin returned unrelated result");
    };
    Ok((handle, bundle))
}

fn stable_daemon_config(root: &Path) -> DaemonConfig {
    let home = root.join("home");
    fs::create_dir_all(home.join("Library/Application Support"))
        .expect("create isolated stable home parents");
    fs::set_permissions(&home, fs::Permissions::from_mode(0o700))
        .expect("secure isolated stable home");
    DaemonConfig::resolve_with_roots(
        DaemonStartupOptions {
            stable_keychain_access_group: Some("TESTTEAM.com.agentdeck.agentdeckd".to_owned()),
            ..DaemonStartupOptions::default()
        },
        &home,
        root,
    )
    .expect("resolve isolated stable daemon namespace")
}

async fn unary(client: &RuntimeUnixClient, request: RuntimeRequest) -> RuntimeReply {
    match tokio::time::timeout(IO_TIMEOUT, client.request(request))
        .await
        .expect("Runtime UDS request deadline")
        .expect("Runtime UDS request")
    {
        ReplySequenceItem::Reply(reply) => *reply,
        ReplySequenceItem::TransferComplete(_) => panic!("request unexpectedly used transfer"),
    }
}

async fn unary_with_remote_diagnostic(
    client: &RuntimeUnixClient,
    request: RuntimeRequest,
    runtime_db: &Path,
) -> RuntimeReply {
    let item = match tokio::time::timeout(IO_TIMEOUT, client.request(request)).await {
        Ok(Ok(item)) => item,
        Ok(Err(error)) => panic!("Runtime UDS request failed: {error:?}"),
        Err(_) => panic!(
            "Runtime UDS request deadline; {}",
            runtime_remote_diagnostic(runtime_db)
        ),
    };
    match item {
        ReplySequenceItem::Reply(reply) => *reply,
        ReplySequenceItem::TransferComplete(_) => panic!("request unexpectedly used transfer"),
    }
}

fn relay_device_grant_counts(database: &Path) -> (i64, i64) {
    Connection::open_with_flags(
        database,
        OpenFlags::SQLITE_OPEN_READ_ONLY | OpenFlags::SQLITE_OPEN_NO_MUTEX,
    )
    .expect("open Relay DB read-only")
    .query_row(
        "SELECT COUNT(*),
                COALESCE(SUM(CASE WHEN tombstone = 0 THEN 1 ELSE 0 END), 0)
         FROM device_grants",
        [],
        |row| Ok((row.get(0)?, row.get(1)?)),
    )
    .expect("read Relay total and active device grant counts")
}

fn runtime_command_count(database: &Path) -> i64 {
    Connection::open_with_flags(
        database,
        OpenFlags::SQLITE_OPEN_READ_ONLY | OpenFlags::SQLITE_OPEN_NO_MUTEX,
    )
    .expect("open Runtime DB read-only for command count")
    .query_row("SELECT COUNT(*) FROM commands", [], |row| row.get(0))
    .expect("read Runtime command count")
}

fn runtime_transition_counts(database: &Path) -> (i64, i64) {
    Connection::open_with_flags(
        database,
        OpenFlags::SQLITE_OPEN_READ_ONLY | OpenFlags::SQLITE_OPEN_NO_MUTEX,
    )
    .expect("open Runtime DB read-only for transition state")
    .query_row(
        "SELECT remote_key_transition_active_count,
                (SELECT COUNT(*) FROM publication_streams
                 WHERE scope = 'catalog' AND state = 'active')
         FROM runtime_meta WHERE singleton = 1",
        [],
        |row| Ok((row.get(0)?, row.get(1)?)),
    )
    .expect("read Runtime active transition and Catalog carrier counts")
}

fn copy_directory_tree(source: &Path, destination: &Path) {
    let metadata = fs::metadata(source).expect("read persistent remote state metadata");
    fs::create_dir(destination).expect("create stale persistent remote state root");
    fs::set_permissions(destination, metadata.permissions())
        .expect("preserve stale persistent remote state root permissions");
    for entry in fs::read_dir(source).expect("enumerate persistent remote state") {
        let entry = entry.expect("read persistent remote state entry");
        let source_path = entry.path();
        let destination_path = destination.join(entry.file_name());
        let entry_type = entry
            .file_type()
            .expect("read persistent remote state entry type");
        if entry_type.is_dir() {
            copy_directory_tree(&source_path, &destination_path);
        } else if entry_type.is_file() {
            fs::copy(&source_path, &destination_path)
                .expect("copy persistent remote state file into stale snapshot");
        } else {
            panic!("persistent remote state contains an unexpected non-file entry");
        }
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
struct ConversationPublicationCut {
    stream_route: [u8; 16],
    generation: [u8; 16],
    outer_seq: u64,
    inner_seq: u64,
}

fn conversation_publication_cut(
    database: &Path,
    conversation_id: &ConversationId,
) -> ConversationPublicationCut {
    let conversation = uuid::Uuid::parse_str(conversation_id.as_str())
        .expect("conversation id is a canonical Runtime UUID")
        .into_bytes();
    let connection = Connection::open_with_flags(
        database,
        OpenFlags::SQLITE_OPEN_READ_ONLY | OpenFlags::SQLITE_OPEN_NO_MUTEX,
    )
    .expect("open Runtime DB read-only for publication cut");
    let (stream_route, generation, outer, inner): (Vec<u8>, Vec<u8>, String, String) = connection
        .query_row(
            "SELECT stream_route, generation, committed_high_water, committed_inner_cursor
             FROM publication_streams
             WHERE scope = 'conversation' AND conversation_id = ?1 AND state = 'active'",
            [conversation.as_slice()],
            |row| Ok((row.get(0)?, row.get(1)?, row.get(2)?, row.get(3)?)),
        )
        .expect("read exact active conversation publication cut");
    ConversationPublicationCut {
        stream_route: stream_route
            .try_into()
            .expect("publication stream route is exactly 16 bytes"),
        generation: generation
            .try_into()
            .expect("publication generation is exactly 16 bytes"),
        outer_seq: outer.parse().expect("parse publication outer high-water"),
        inner_seq: inner.parse().expect("parse publication inner high-water"),
    }
}

fn relay_retains_exact_next_frame(database: &Path, cut: ConversationPublicationCut) -> bool {
    let next = cut
        .outer_seq
        .checked_add(1)
        .expect("publication outer sequence has an exact successor");
    Connection::open_with_flags(
        database,
        OpenFlags::SQLITE_OPEN_READ_ONLY | OpenFlags::SQLITE_OPEN_NO_MUTEX,
    )
    .expect("open Relay DB read-only for exact retained frame")
    .query_row(
        "SELECT EXISTS(
             SELECT 1 FROM frames
             WHERE stream_route = ?1 AND generation = ?2 AND stream_seq = ?3
         )",
        rusqlite::params![
            cut.stream_route.as_slice(),
            cut.generation.as_slice(),
            format!("{next:020}")
        ],
        |row| row.get(0),
    )
    .expect("read exact retained Relay frame")
}

fn relay_stream_diagnostic(database: &Path) -> String {
    let connection = Connection::open_with_flags(
        database,
        OpenFlags::SQLITE_OPEN_READ_ONLY | OpenFlags::SQLITE_OPEN_NO_MUTEX,
    )
    .expect("open Relay DB read-only for stream diagnostic");
    let streams = connection
        .query_row(
            "SELECT COALESCE(group_concat(high_water_seq || ':oldest=' || COALESCE(oldest_seq, 'none'), ','), '') FROM streams",
            [],
            |row| row.get::<_, String>(0),
        )
        .expect("read Relay stream cuts");
    let frames = connection
        .query_row(
            "SELECT COALESCE(group_concat(stream_seq, ','), '') FROM frames",
            [],
            |row| row.get::<_, String>(0),
        )
        .expect("read Relay retained frame sequences");
    let subscriptions = connection
        .query_row(
            "SELECT COALESCE(group_concat(COALESCE(start_cursor_seq, 'beforeFirst') || ':ack=' || COALESCE(ack, 'none'), ','), '') FROM subscriptions",
            [],
            |row| row.get::<_, String>(0),
        )
        .expect("read Relay subscription cuts");
    format!("relay_streams={streams}; relay_frames={frames}; relay_subscriptions={subscriptions}")
}

fn runtime_remote_diagnostic(database: &Path) -> String {
    let connection = Connection::open_with_flags(
        database,
        OpenFlags::SQLITE_OPEN_READ_ONLY | OpenFlags::SQLITE_OPEN_NO_MUTEX,
    )
    .expect("open Runtime DB read-only");
    let machine = connection
        .query_row(
            "SELECT COALESCE(group_concat(lifecycle, ','), '') FROM machine_remote_state",
            [],
            |row| row.get::<_, String>(0),
        )
        .expect("read machine remote lifecycle");
    let pairings = connection
        .query_row(
            "SELECT COALESCE(group_concat(lifecycle, ','), '') FROM remote_pairings",
            [],
            |row| row.get::<_, String>(0),
        )
        .expect("read pairing lifecycle");
    let authorizations = connection
        .query_row(
            "SELECT COALESCE(group_concat(lifecycle || ':' || grant_serial || ':r' || key_directory_revision, ','), '') FROM remote_authorization_ledger",
            [],
            |row| row.get::<_, String>(0),
        )
        .expect("read authorization lifecycle");
    let directory = connection
        .query_row(
            "SELECT COALESCE(group_concat(revision, ','), '') FROM remote_key_directory",
            [],
            |row| row.get::<_, String>(0),
        )
        .expect("read key directory revision");
    let transitions = connection
        .query_row(
            "SELECT COALESCE(group_concat(operation_kind || ':' || phase || ':recipients=' || recipient_count || ':streams=' || stream_count || ':updates=' || update_count, ','), '') FROM remote_key_transitions",
            [],
            |row| row.get::<_, String>(0),
        )
        .expect("read key transition lifecycle");
    let updates = connection
        .query_row(
            "SELECT COALESCE(group_concat(lifecycle || ':r' || key_revision || ':acks=' || applied_ack_count, ','), '') FROM remote_key_update_outbox",
            [],
            |row| row.get::<_, String>(0),
        )
        .expect("read key update lifecycle");
    let control = connection
        .query_row(
            "SELECT COALESCE(group_concat(operation_kind || ':' || lifecycle, ','), '') FROM remote_control_outbox",
            [],
            |row| row.get::<_, String>(0),
        )
        .expect("read control outbox lifecycle");
    let publications = connection
        .query_row(
            "SELECT COALESCE(group_concat(
                 scope || ':' || COALESCE(hex(conversation_id), 'catalog') || ':' || state ||
                 ':reserved=' || COALESCE(reserved_high_water, 'beforeFirst') ||
                 ':committed=' || COALESCE(committed_high_water, 'beforeFirst') ||
                 ':acked=' || COALESCE(acknowledged_high_water, 'beforeFirst') ||
                 ':inner=' || COALESCE(committed_inner_cursor, 'beforeFirst'), ','), '')
             FROM publication_streams",
            [],
            |row| row.get::<_, String>(0),
        )
        .expect("read publication stream lifecycle");
    let publication_outbox = connection
        .query_row(
            "SELECT COALESCE(group_concat(
                 hex(publication_stream_id) || ':seq=' || stream_seq || ':inner=' ||
                 COALESCE(inner_after_seq, 'beforeFirst') || '→' ||
                 COALESCE(inner_through_seq, 'beforeFirst'), ','), '')
             FROM publication_outbox",
            [],
            |row| row.get::<_, String>(0),
        )
        .expect("read publication outbox rows");
    format!(
        "machine={machine}; pairings={pairings}; auth={authorizations}; directory={directory}; transitions={transitions}; updates={updates}; control={control}; publications={publications}; publication_outbox={publication_outbox}"
    )
}

fn unix_now_ms() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_millis()
        .try_into()
        .unwrap_or(u64::MAX)
}

fn conversation_configuration(kind: AgentKind) -> ConversationConfiguration {
    match kind {
        AgentKind::Codex => ConversationConfiguration::new(VendorConfigurationSnapshot::Codex(
            CodexConversationConfiguration::new(
                CodexApprovalPolicy::OnRequest,
                CodexSandboxMode::WorkspaceWrite,
                CodexReasoningEffort::Medium,
            ),
        )),
        AgentKind::ClaudeCode => {
            ConversationConfiguration::new(VendorConfigurationSnapshot::ClaudeCode(
                ClaudeCodeConversationConfiguration::new(
                    ClaudeCodePermissionMode::Default,
                    None,
                    None,
                    None,
                )
                .expect("valid synthetic Claude Code configuration"),
            ))
        }
    }
}

#[derive(Default)]
struct ConversationActivationTrace {
    key_sync_pending: bool,
    key_update_installed: bool,
    catalog_delta_applied: bool,
}

fn observe_conversation_activation(
    outcome: RemoteStreamFrameOutcome,
    trace: &mut ConversationActivationTrace,
) {
    match outcome {
        RemoteStreamFrameOutcome::Applied(item) => {
            assert!(matches!(*item, RuntimeStreamItem::CatalogDelta(_)));
            assert!(
                trace.key_update_installed,
                "activation CatalogDelta must only apply after the exact KeyUpdate"
            );
            assert!(
                !trace.catalog_delta_applied,
                "activation CatalogDelta must apply exactly once"
            );
            trace.catalog_delta_applied = true;
        }
        RemoteStreamFrameOutcome::KeySyncPending { attempt } => {
            assert_eq!(
                attempt, 1,
                "exact-next activation must start one KeySync probe"
            );
            assert!(
                !trace.key_sync_pending
                    && !trace.key_update_installed
                    && !trace.catalog_delta_applied,
                "activation KeySync must be the first higher-revision outcome"
            );
            trace.key_sync_pending = true;
        }
        RemoteStreamFrameOutcome::KeyUpdateInstalled {
            key_directory_revision: _,
            next_attempt,
        } => {
            assert!(
                trace.key_sync_pending,
                "KeyUpdate install must follow KeySyncPending"
            );
            assert_eq!(
                next_attempt, None,
                "exact-next activation must resolve in one installed revision"
            );
            assert!(
                !trace.key_update_installed && !trace.catalog_delta_applied,
                "activation KeyUpdate must install exactly once before Catalog apply"
            );
            trace.key_update_installed = true;
        }
        RemoteStreamFrameOutcome::AuthenticatedOverlap
        | RemoteStreamFrameOutcome::AppliedDuplicate
        | RemoteStreamFrameOutcome::TransferBuffered { .. }
        | RemoteStreamFrameOutcome::TransferAlreadyComplete { .. }
        | RemoteStreamFrameOutcome::ReplayComplete { .. }
        | RemoteStreamFrameOutcome::KeySyncRouteAccepted { .. }
        | RemoteStreamFrameOutcome::KeyUpdateAckRouteAccepted { .. }
        | RemoteStreamFrameOutcome::EpochBarrierApplied { .. }
        | RemoteStreamFrameOutcome::StreamAppliedAckRouteAccepted { .. } => {}
        RemoteStreamFrameOutcome::Gap { .. } => {
            panic!("catalog activation transition produced a Relay gap")
        }
        RemoteStreamFrameOutcome::RevocationCommitted { .. } => {
            panic!("device revoked during conversation activation")
        }
    }
}

async fn create_configured_conversation(
    client: &RuntimeUnixClient,
    remote: &mut RemoteRuntime<'_, agentdeck_cli::remote::relay_transport::RelayRuntimeTransport>,
    catalog: &mut CatalogReducer,
    kind: AgentKind,
    root: &Path,
    runtime_db: &Path,
    relay_db: &Path,
) -> ConversationId {
    let label = match kind {
        AgentKind::Codex => "codex",
        AgentKind::ClaudeCode => "claude-code",
    };
    let started = unary_with_remote_diagnostic(
        client,
        RuntimeRequest::Start(ConversationStart {
            agent_kind: kind,
            idempotency_key: IdempotencyKey::new(format!("p47-start-{label}")),
            cwd: root.to_path_buf(),
            title: Some(format!("P4.7 synthetic {label}")),
        }),
        runtime_db,
    );
    tokio::pin!(started);
    let mut activation = ConversationActivationTrace::default();
    let started = loop {
        let received = remote.receive_stream_frame(catalog);
        tokio::pin!(received);
        tokio::select! {
            biased;
            outcome = &mut received => {
                observe_conversation_activation(
                    outcome.expect("process catalog activation transition"),
                    &mut activation,
                );
            }
            reply = &mut started => {
                // receive future 一旦从 Relay 取帧，就可能已经完成 durable apply，随后
                // 仅在 cumulative ACK Send 上 yield。此时丢弃 future 会让测试漏记一个
                // 已真实提交的 CatalogDelta；保留并收尾同一个 future，再接收下一帧。
                let outcome = match tokio::time::timeout(IO_TIMEOUT, received.as_mut()).await {
                    Ok(outcome) => outcome.expect("finish in-flight activation stream frame"),
                    Err(_) => panic!(
                        "in-flight activation stream frame deadline; {}; {}",
                        runtime_remote_diagnostic(runtime_db),
                        relay_stream_diagnostic(relay_db)
                    ),
                };
                observe_conversation_activation(outcome, &mut activation);
                break reply;
            },
        }
    };
    assert!(
        activation.key_sync_pending && activation.key_update_installed,
        "local Start ordering incomplete: key_sync_pending={}, key_update_installed={}",
        activation.key_sync_pending,
        activation.key_update_installed,
    );
    while !activation.catalog_delta_applied {
        let outcome =
            match tokio::time::timeout(IO_TIMEOUT, remote.receive_stream_frame(catalog)).await {
                Ok(outcome) => outcome.expect("process activation CatalogDelta after local Start"),
                Err(_) => panic!(
                    "activation CatalogDelta delivery deadline; {}; {}",
                    runtime_remote_diagnostic(runtime_db),
                    relay_stream_diagnostic(relay_db)
                ),
            };
        observe_conversation_activation(outcome, &mut activation);
    }
    let conversation_id = match started {
        RuntimeReply::ConversationStart(ConversationStartReceipt {
            conversation_id,
            replayed: false,
        }) => conversation_id,
        other => panic!("synthetic conversation Start did not return a fresh receipt: {other:?}"),
    };
    let request = ConfigureConversationRequest::new(
        conversation_id.clone(),
        IdempotencyKey::new(format!("p47-configure-{label}")),
        0,
        conversation_configuration(kind),
    );
    let configured = unary(client, RuntimeRequest::ConfigureConversation(request)).await;
    assert!(matches!(
        configured,
        RuntimeReply::Configuration(
            agentdeck_protocol::runtime::ConfigurationReceipt::Applied {
                conversation_id: configured_id,
                configuration_revision: 1,
            }
        ) if configured_id == conversation_id
    ));
    conversation_id
}

#[derive(Clone)]
struct CatalogReducer {
    cursor: RuntimeInnerCursor,
    saw_empty_snapshot: bool,
}

impl CatalogReducer {
    fn new() -> Self {
        Self {
            cursor: RuntimeInnerCursor::Catalog {
                cursor: StreamCursor::BeforeFirst,
            },
            saw_empty_snapshot: false,
        }
    }
}

impl RemoteSubscriptionReducer for CatalogReducer {
    const MAX_RETAINED_BYTES: usize = 1024;

    fn inner_cursor(&self) -> &RuntimeInnerCursor {
        &self.cursor
    }

    fn apply(&mut self, item: &RemoteSubscriptionBootstrapItem) -> Result<(), RemoteRuntimeError> {
        if let RemoteSubscriptionBootstrapItem::CatalogSnapshot(snapshot) = item {
            self.saw_empty_snapshot = snapshot.entries().is_empty();
        }
        self.cursor = match (item, &self.cursor) {
            (
                RemoteSubscriptionBootstrapItem::CatalogSnapshot(snapshot),
                RuntimeInnerCursor::Catalog { .. },
            ) => RuntimeInnerCursor::Catalog {
                cursor: snapshot.base_catalog_cursor,
            },
            (
                RemoteSubscriptionBootstrapItem::Backfill(BackfillChunk::Catalog { range, .. }),
                RuntimeInnerCursor::Catalog { cursor },
            ) if range.after() == *cursor => RuntimeInnerCursor::Catalog {
                cursor: range.through(),
            },
            _ => {
                return Err(RemoteRuntimeError::InvalidReply(
                    "P4.7 catalog reducer rejected cross-target bootstrap",
                ));
            }
        };
        Ok(())
    }

    fn apply_live(&mut self, item: &RuntimeStreamItem) -> Result<(), RemoteRuntimeError> {
        let RuntimeStreamItem::CatalogDelta(delta) = item else {
            return Err(RemoteRuntimeError::InvalidReply(
                "P4.7 catalog reducer received a non-delta",
            ));
        };
        let RuntimeInnerCursor::Catalog { cursor } = self.cursor else {
            return Err(RemoteRuntimeError::InvalidDurableState);
        };
        if cursor.checked_next().ok() != Some(delta.catalog_revision) {
            return Err(RemoteRuntimeError::InvalidReply(
                "P4.7 catalog reducer received a discontinuous delta",
            ));
        }
        self.cursor = RuntimeInnerCursor::Catalog {
            cursor: StreamCursor::At(delta.catalog_revision),
        };
        Ok(())
    }
}

#[derive(Clone)]
struct ConversationReducer {
    cursor: RuntimeInnerCursor,
    bootstrap: Vec<RemoteSubscriptionBootstrapItem>,
    live: Vec<RuntimeEvent>,
}

impl ConversationReducer {
    fn new(conversation_id: ConversationId) -> Self {
        Self {
            cursor: RuntimeInnerCursor::Conversation {
                conversation_id,
                cursor: StreamCursor::BeforeFirst,
            },
            bootstrap: Vec::new(),
            live: Vec::new(),
        }
    }

    fn history_shape(&self) -> (bool, bool) {
        let mut user = false;
        let mut assistant = false;
        for item in &self.bootstrap {
            match item {
                RemoteSubscriptionBootstrapItem::ConversationSnapshot(snapshot) => {
                    for item in snapshot.items() {
                        match item {
                            SnapshotItem::Item {
                                item: AgentItem::UserMessage { .. },
                                ..
                            } => user = true,
                            SnapshotItem::Item {
                                item: AgentItem::AssistantMessage { .. },
                                ..
                            } => assistant = true,
                            SnapshotItem::Capabilities { .. } | SnapshotItem::Item { .. } => {}
                        }
                    }
                }
                RemoteSubscriptionBootstrapItem::Backfill(BackfillChunk::Conversation {
                    events,
                    ..
                }) => {
                    for event in events {
                        match &event.body {
                            RuntimeEventBody::Item {
                                item: AgentItem::UserMessage { .. },
                            } => user = true,
                            RuntimeEventBody::Item {
                                item: AgentItem::AssistantMessage { .. },
                            } => assistant = true,
                            _ => {}
                        }
                    }
                }
                RemoteSubscriptionBootstrapItem::CatalogSnapshot(_)
                | RemoteSubscriptionBootstrapItem::Backfill(BackfillChunk::Catalog { .. }) => {}
            }
        }
        (user, assistant)
    }
}

impl RemoteSubscriptionReducer for ConversationReducer {
    const MAX_RETAINED_BYTES: usize = 64 * 1024 * 1024;

    fn inner_cursor(&self) -> &RuntimeInnerCursor {
        &self.cursor
    }

    fn apply(&mut self, item: &RemoteSubscriptionBootstrapItem) -> Result<(), RemoteRuntimeError> {
        self.cursor = match (item, &self.cursor) {
            (
                RemoteSubscriptionBootstrapItem::ConversationSnapshot(snapshot),
                RuntimeInnerCursor::Conversation {
                    conversation_id, ..
                },
            ) if &snapshot.conversation_id == conversation_id => RuntimeInnerCursor::Conversation {
                conversation_id: conversation_id.clone(),
                cursor: snapshot.base_event_cursor,
            },
            (
                RemoteSubscriptionBootstrapItem::Backfill(BackfillChunk::Conversation {
                    conversation_id,
                    range,
                    ..
                }),
                RuntimeInnerCursor::Conversation {
                    conversation_id: expected,
                    cursor,
                },
            ) if conversation_id == expected && range.after() == *cursor => {
                RuntimeInnerCursor::Conversation {
                    conversation_id: expected.clone(),
                    cursor: range.through(),
                }
            }
            _ => {
                return Err(RemoteRuntimeError::InvalidReply(
                    "P4.7 reducer rejected cross-target bootstrap",
                ));
            }
        };
        self.bootstrap.push(item.clone());
        Ok(())
    }

    fn apply_live(&mut self, item: &RuntimeStreamItem) -> Result<(), RemoteRuntimeError> {
        let RuntimeStreamItem::Event(event) = item else {
            return Err(RemoteRuntimeError::InvalidReply(
                "P4.7 conversation watch received a non-event",
            ));
        };
        let RuntimeInnerCursor::Conversation {
            conversation_id,
            cursor,
        } = &self.cursor
        else {
            return Err(RemoteRuntimeError::InvalidDurableState);
        };
        if &event.conversation_id != conversation_id
            || cursor.checked_next().ok() != Some(event.event_seq)
        {
            return Err(RemoteRuntimeError::InvalidReply(
                "P4.7 conversation watch received a discontinuous event",
            ));
        }
        self.cursor = RuntimeInnerCursor::Conversation {
            conversation_id: conversation_id.clone(),
            cursor: StreamCursor::At(event.event_seq),
        };
        self.live.push(event.clone());
        Ok(())
    }
}

struct ReplayBootstrapGateState {
    snapshot_blocked: bool,
    released: bool,
}

struct ReplayBootstrapGate {
    snapshot_applied: Notify,
    state: Mutex<ReplayBootstrapGateState>,
    released: Condvar,
}

impl ReplayBootstrapGate {
    fn new() -> Self {
        Self {
            snapshot_applied: Notify::new(),
            state: Mutex::new(ReplayBootstrapGateState {
                snapshot_blocked: false,
                released: false,
            }),
            released: Condvar::new(),
        }
    }

    fn block_once_after_snapshot(&self) {
        let mut state = self
            .state
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        if state.snapshot_blocked {
            return;
        }
        state.snapshot_blocked = true;
        self.snapshot_applied.notify_one();
        let (state, timeout) = self
            .released
            .wait_timeout_while(state, IO_TIMEOUT, |state| !state.released)
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        assert!(
            state.released && !timeout.timed_out(),
            "retained-event producer did not release the frozen snapshot reducer"
        );
    }

    fn release(&self) {
        let mut state = self
            .state
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        state.released = true;
        self.released.notify_all();
    }
}

struct ReplayGateReleaseGuard(Arc<ReplayBootstrapGate>);

impl Drop for ReplayGateReleaseGuard {
    fn drop(&mut self) {
        self.0.release();
    }
}

#[derive(Clone)]
struct GatedConversationReducer {
    conversation: ConversationReducer,
    gate: Arc<ReplayBootstrapGate>,
}

impl GatedConversationReducer {
    fn new(conversation_id: ConversationId, gate: Arc<ReplayBootstrapGate>) -> Self {
        Self {
            conversation: ConversationReducer::new(conversation_id),
            gate,
        }
    }
}

impl RemoteSubscriptionReducer for GatedConversationReducer {
    const MAX_RETAINED_BYTES: usize = ConversationReducer::MAX_RETAINED_BYTES;

    fn inner_cursor(&self) -> &RuntimeInnerCursor {
        self.conversation.inner_cursor()
    }

    fn apply(&mut self, item: &RemoteSubscriptionBootstrapItem) -> Result<(), RemoteRuntimeError> {
        self.conversation.apply(item)?;
        if matches!(
            item,
            RemoteSubscriptionBootstrapItem::ConversationSnapshot(_)
        ) {
            self.gate.block_once_after_snapshot();
        }
        Ok(())
    }

    fn apply_live(&mut self, item: &RuntimeStreamItem) -> Result<(), RemoteRuntimeError> {
        self.conversation.apply_live(item)
    }
}

#[test]
fn conversation_reducer_merges_snapshot_then_ordered_backfill_history() {
    let conversation_id = ConversationId::new("conversation-history-reducer");
    let capabilities = SessionCapabilities {
        agent_kind: AgentKind::Codex,
        agent_version: "relay-v2-history-reducer-fixture".to_owned(),
        features: Default::default(),
        vendor: VendorCapabilities::Codex(CodexCapabilities::default()),
    };
    let snapshot = ConversationSnapshot::new(
        conversation_id.clone(),
        StreamCursor::At(2),
        ConversationConfigurationState::new(0, None)
            .expect("history reducer fixture configuration state"),
        vec![
            SnapshotItem::capabilities(capabilities.clone()),
            SnapshotItem::Item {
                item_id: ItemId::new("snapshot-user-item"),
                entity_id: EntityId::new("snapshot-user-entity"),
                command_id: Some(CommandId::new("snapshot-user-command")),
                item: AgentItem::UserMessage {
                    text: "snapshot-user".to_owned(),
                    meta: AgentItemMeta::default(),
                },
            },
        ],
    )
    .expect("canonical history reducer snapshot");
    let item_event = |sequence: u64, item: AgentItem| {
        RuntimeEvent::new(
            conversation_id.clone(),
            EventId::new(format!("backfill-event-{sequence}")),
            sequence,
            Some(CommandId::new("backfill-command")),
            Some(ItemId::new(format!("backfill-item-{sequence}"))),
            Some(EntityId::new(format!("backfill-entity-{sequence}"))),
            RuntimeEventBody::Item { item },
        )
        .expect("canonical history reducer backfill event")
    };
    let first_backfill = BackfillChunk::conversation(
        conversation_id.clone(),
        capabilities.clone(),
        BackfillRange::new(StreamCursor::At(2), StreamCursor::At(3))
            .expect("first history reducer backfill range"),
        vec![item_event(
            3,
            AgentItem::AssistantMessage {
                text: "backfill-assistant-3".to_owned(),
                meta: AgentItemMeta::default(),
            },
        )],
    )
    .expect("first canonical history reducer backfill");
    let second_backfill = BackfillChunk::conversation(
        conversation_id.clone(),
        capabilities,
        BackfillRange::new(StreamCursor::At(3), StreamCursor::At(5))
            .expect("second history reducer backfill range"),
        vec![
            item_event(
                4,
                AgentItem::UserMessage {
                    text: "backfill-user-4".to_owned(),
                    meta: AgentItemMeta::default(),
                },
            ),
            item_event(
                5,
                AgentItem::AssistantMessage {
                    text: "backfill-assistant-5".to_owned(),
                    meta: AgentItemMeta::default(),
                },
            ),
        ],
    )
    .expect("second canonical history reducer backfill");

    let mut reducer = ConversationReducer::new(conversation_id.clone());
    reducer
        .apply(&RemoteSubscriptionBootstrapItem::ConversationSnapshot(
            snapshot,
        ))
        .expect("apply history reducer snapshot");
    assert_eq!(reducer.history_shape(), (true, false));
    assert_eq!(
        reducer.cursor,
        RuntimeInnerCursor::Conversation {
            conversation_id: conversation_id.clone(),
            cursor: StreamCursor::At(2),
        }
    );

    let mut discontinuous = reducer.clone();
    assert!(matches!(
        discontinuous.apply(&RemoteSubscriptionBootstrapItem::Backfill(
            second_backfill.clone()
        )),
        Err(RemoteRuntimeError::InvalidReply(_))
    ));

    reducer
        .apply(&RemoteSubscriptionBootstrapItem::Backfill(first_backfill))
        .expect("apply first history reducer backfill");
    assert_eq!(reducer.history_shape(), (true, true));
    reducer
        .apply(&RemoteSubscriptionBootstrapItem::Backfill(second_backfill))
        .expect("apply second history reducer backfill");
    assert_eq!(
        reducer.cursor,
        RuntimeInnerCursor::Conversation {
            conversation_id,
            cursor: StreamCursor::At(5),
        }
    );

    let mut history = Vec::new();
    let mut retain_message = |item: &AgentItem| match item {
        AgentItem::UserMessage { text, .. } => history.push(("user", text.clone())),
        AgentItem::AssistantMessage { text, .. } => history.push(("assistant", text.clone())),
        _ => {}
    };
    for item in &reducer.bootstrap {
        match item {
            RemoteSubscriptionBootstrapItem::ConversationSnapshot(snapshot) => {
                for item in snapshot.items() {
                    if let SnapshotItem::Item { item, .. } = item {
                        retain_message(item);
                    }
                }
            }
            RemoteSubscriptionBootstrapItem::Backfill(BackfillChunk::Conversation {
                events,
                ..
            }) => {
                for event in events {
                    if let RuntimeEventBody::Item { item } = &event.body {
                        retain_message(item);
                    }
                }
            }
            RemoteSubscriptionBootstrapItem::CatalogSnapshot(_)
            | RemoteSubscriptionBootstrapItem::Backfill(BackfillChunk::Catalog { .. }) => {}
        }
    }
    assert_eq!(
        history
            .iter()
            .map(|(role, text)| (*role, text.as_str()))
            .collect::<Vec<_>>(),
        vec![
            ("user", "snapshot-user"),
            ("assistant", "backfill-assistant-3"),
            ("user", "backfill-user-4"),
            ("assistant", "backfill-assistant-5"),
        ],
        "history must retain snapshot items before every ordered backfill event"
    );
}

async fn next_applied_event(
    runtime: &mut RemoteRuntime<'_, agentdeck_cli::remote::relay_transport::RelayRuntimeTransport>,
    reducer: &mut ConversationReducer,
    runtime_db: &Path,
    relay_db: &Path,
) -> RuntimeEvent {
    let mut observed = Vec::new();
    loop {
        let outcome = match tokio::time::timeout(IO_TIMEOUT, runtime.receive_stream_frame(reducer))
            .await
        {
            Ok(result) => result.expect("receive authenticated remote stream frame"),
            Err(error) => panic!(
                "remote watch event deadline: {error:?}; cursor={:?}; observed={observed:?}; {}; {}",
                reducer.cursor,
                runtime_remote_diagnostic(runtime_db),
                relay_stream_diagnostic(relay_db)
            ),
        };
        match outcome {
            RemoteStreamFrameOutcome::Applied(item) => {
                let RuntimeStreamItem::Event(event) = *item else {
                    panic!("conversation stream applied a non-event");
                };
                return event;
            }
            other @ (RemoteStreamFrameOutcome::AuthenticatedOverlap
            | RemoteStreamFrameOutcome::AppliedDuplicate
            | RemoteStreamFrameOutcome::TransferBuffered { .. }
            | RemoteStreamFrameOutcome::TransferAlreadyComplete { .. }
            | RemoteStreamFrameOutcome::ReplayComplete { .. }
            | RemoteStreamFrameOutcome::KeySyncPending { .. }
            | RemoteStreamFrameOutcome::KeySyncRouteAccepted { .. }
            | RemoteStreamFrameOutcome::KeyUpdateInstalled { .. }
            | RemoteStreamFrameOutcome::KeyUpdateAckRouteAccepted { .. }
            | RemoteStreamFrameOutcome::EpochBarrierApplied { .. }
            | RemoteStreamFrameOutcome::StreamAppliedAckRouteAccepted { .. }) => {
                observed.push(format!("{other:?}"));
            }
            RemoteStreamFrameOutcome::RevocationCommitted { .. } => {
                panic!("device revoked before requested business event")
            }
            RemoteStreamFrameOutcome::Gap {
                need_stream_seq,
                oldest_stream_seq,
            } => panic!(
                "authenticated conversation stream lost canonical history: need={need_stream_seq}, oldest={oldest_stream_seq}"
            ),
        }
    }
}

async fn await_replay_complete<D: RemoteSubscriptionReducer>(
    runtime: &mut RemoteRuntime<'_, agentdeck_cli::remote::relay_transport::RelayRuntimeTransport>,
    reducer: &mut D,
) {
    loop {
        let outcome = tokio::time::timeout(IO_TIMEOUT, runtime.receive_stream_frame(reducer))
            .await
            .expect("Relay replay completion deadline")
            .expect("receive replay completion");
        match outcome {
            RemoteStreamFrameOutcome::ReplayComplete { .. } => return,
            RemoteStreamFrameOutcome::Applied(_)
            | RemoteStreamFrameOutcome::AuthenticatedOverlap
            | RemoteStreamFrameOutcome::AppliedDuplicate
            | RemoteStreamFrameOutcome::TransferBuffered { .. }
            | RemoteStreamFrameOutcome::TransferAlreadyComplete { .. }
            | RemoteStreamFrameOutcome::KeySyncPending { .. }
            | RemoteStreamFrameOutcome::KeySyncRouteAccepted { .. }
            | RemoteStreamFrameOutcome::KeyUpdateInstalled { .. }
            | RemoteStreamFrameOutcome::KeyUpdateAckRouteAccepted { .. }
            | RemoteStreamFrameOutcome::EpochBarrierApplied { .. }
            | RemoteStreamFrameOutcome::StreamAppliedAckRouteAccepted { .. } => {}
            RemoteStreamFrameOutcome::Gap { .. } => panic!("fresh P4.7 stream replay has a gap"),
            RemoteStreamFrameOutcome::RevocationCommitted { .. } => {
                panic!("device revoked before replay completion")
            }
        }
    }
}

async fn connected_runtime<'a>(
    paired: &'a RecoveredPairedMachineStore<'_>,
    identity: PairedMachineIdentity,
) -> Box<RemoteRuntime<'a, agentdeck_cli::remote::relay_transport::RelayRuntimeTransport>> {
    let opened = paired
        .open_exact(identity)
        .expect("open audited paired machine");
    match tokio::time::timeout(IO_TIMEOUT, connect_paired_runtime(opened))
        .await
        .expect("paired Runtime connect deadline")
        .expect("connect production paired Runtime")
    {
        PairedRuntimeConnectOutcome::Connected(runtime) => runtime,
        PairedRuntimeConnectOutcome::Revoked => panic!("paired device revoked before E2E"),
    }
}

fn assert_persistent_machine_inventory(
    composition: &PersistentRemoteComposition,
    identity: PairedMachineIdentity,
    device_route: agentdeck_protocol::relay_v2::DeviceRouteId,
) {
    let output = list_persistent_remote_machines(composition)
        .expect("production persistent machine inventory readback");
    assert_eq!(output["operation"], "remote.machines");
    assert_eq!(
        output["result"]["installationId"],
        composition.installation_id().to_string()
    );
    let machines = output["result"]["machines"]
        .as_array()
        .expect("persistent machine inventory array");
    assert_eq!(machines.len(), 1);
    assert_eq!(
        machines[0]["machineRootFingerprint"],
        STANDARD.encode(identity.machine_root_fingerprint().as_bytes())
    );
    assert_eq!(
        machines[0]["machineRoute"],
        STANDARD.encode(identity.machine_route().as_bytes())
    );
    assert_eq!(
        machines[0]["deviceRoute"],
        STANDARD.encode(device_route.as_bytes())
    );
    assert_eq!(machines[0]["machineDisplayName"], "P4.7 automatic machine");
}

async fn assert_persistent_conversations(
    composition: &PersistentRemoteComposition,
    selector: PersistentMachineSelector,
    codex: &ConversationId,
    claude_code: &ConversationId,
) {
    let mut rng = ChaCha20Rng::from_seed([0x48; 32]);
    let outcome = tokio::time::timeout(
        IO_TIMEOUT,
        list_persistent_remote_conversations(composition, selector, &mut rng),
    )
    .await
    .expect("production persistent conversations deadline")
    .expect("production persistent authenticated Catalog readback");
    assert!(outcome.route_accepted_observed());
    assert_eq!(outcome.page_count(), 1);
    assert_eq!(outcome.conversations().len(), 2);
    assert!(
        outcome.conversations().iter().any(|entry| {
            entry.conversation_id == *codex && entry.agent_kind == AgentKind::Codex
        })
    );
    assert!(outcome.conversations().iter().any(|entry| {
        entry.conversation_id == *claude_code && entry.agent_kind == AgentKind::ClaudeCode
    }));
}

async fn smoke_persistent_conversation_watch(
    composition: &PersistentRemoteComposition,
    selector: PersistentMachineSelector,
    conversation_id: ConversationId,
) {
    let (stop_tx, stop_rx) = oneshot::channel();
    let mut stop_tx = Some(stop_tx);
    let mut saw_snapshot = false;
    let mut saw_synchronized = false;
    let mut saw_stopped = false;
    let expected = conversation_id.clone();
    let mut rng = ChaCha20Rng::from_seed([0x6f; 32]);
    let exit = tokio::time::timeout(
        IO_TIMEOUT,
        watch_persistent_remote_conversation(
            composition,
            selector,
            conversation_id,
            &mut rng,
            async move {
                stop_rx.await.map_err(|_| {
                    std::io::Error::new(
                        std::io::ErrorKind::BrokenPipe,
                        "persistent watch stop sender dropped",
                    )
                })
            },
            |record| {
                match record {
                    PersistentRemoteWatchRecord::BootstrapSnapshot { snapshot } => {
                        let decoded: ConversationSnapshot =
                            serde_json::from_slice(snapshot.canonical_json()).map_err(|error| {
                                std::io::Error::new(std::io::ErrorKind::InvalidData, error)
                            })?;
                        assert_eq!(decoded.conversation_id, expected);
                        saw_snapshot = true;
                    }
                    PersistentRemoteWatchRecord::Synchronized {
                        requested_cursor,
                        route_accepted,
                        subscription,
                        sync_complete,
                    } => {
                        assert_eq!(
                            requested_cursor,
                            RuntimeInnerCursor::Conversation {
                                conversation_id: expected.clone(),
                                cursor: StreamCursor::BeforeFirst,
                            }
                        );
                        assert!(route_accepted);
                        assert!(matches!(
                            subscription,
                            SubscriptionReceipt::Subscribed { .. }
                        ));
                        assert!(matches!(
                            sync_complete.inner_cursor,
                            RuntimeInnerCursor::Conversation {
                                conversation_id: observed,
                                ..
                            } if observed == expected
                        ));
                        saw_synchronized = true;
                        stop_tx
                            .take()
                            .expect("persistent watch synchronizes exactly once")
                            .send(())
                            .map_err(|_| {
                                std::io::Error::new(
                                    std::io::ErrorKind::BrokenPipe,
                                    "persistent watch stop receiver dropped",
                                )
                            })?;
                    }
                    PersistentRemoteWatchRecord::Control {
                        control:
                            PersistentRemoteWatchControl::Gap {
                                need_stream_seq,
                                oldest_stream_seq,
                            },
                    } => panic!(
                        "production persistent watch lost canonical history: need={need_stream_seq}, oldest={oldest_stream_seq}"
                    ),
                    PersistentRemoteWatchRecord::Stopped => saw_stopped = true,
                    PersistentRemoteWatchRecord::Revoked => {
                        panic!("active paired machine revoked during high-level watch smoke")
                    }
                    PersistentRemoteWatchRecord::BootstrapBackfill { .. }
                    | PersistentRemoteWatchRecord::Event { .. }
                    | PersistentRemoteWatchRecord::Control { .. } => {}
                }
                Ok(())
            },
        ),
    )
    .await
    .expect("production persistent watch deadline")
    .expect("production persistent watch bootstrap/cancel");
    assert_eq!(exit, PersistentRemoteWatchExit::Interrupted);
    assert!(saw_snapshot);
    assert!(saw_synchronized);
    assert!(saw_stopped);
}

struct RevokeVerificationContext<'a> {
    composition: &'a PersistentRemoteComposition,
    client_keys: &'a ForkableRemoteKeyStore,
    client_state: &'a Path,
    client_home: &'a Path,
    root: &'a Path,
    identity: PairedMachineIdentity,
    runtime_db: &'a Path,
    relay_db: &'a Path,
}

async fn verify_revoke_terminates_stale_credentials(
    context: &RevokeVerificationContext<'_>,
    conversation_id: ConversationId,
) {
    let composition = context.composition;
    let client_keys = context.client_keys;
    let client_state = context.client_state;
    let client_home = context.client_home;
    let root = context.root;
    let identity = context.identity;
    let runtime_db = context.runtime_db;
    let relay_db = context.relay_db;
    let stale_fresh_state = root.join("persistent-remote-client-stale-fresh");
    let stale_mutation_state = root.join("persistent-remote-client-stale-mutation");
    let stale_fresh_home = root.join("persistent-remote-home-stale-fresh");
    let stale_mutation_home = root.join("persistent-remote-home-stale-mutation");
    copy_directory_tree(client_state, &stale_fresh_state);
    copy_directory_tree(client_state, &stale_mutation_state);
    copy_directory_tree(client_home, &stale_fresh_home);
    copy_directory_tree(client_home, &stale_mutation_home);
    let stale_fresh_keys = Arc::new(
        client_keys
            .fork()
            .expect("fork paired keys for a fresh stale authentication"),
    );
    let stale_mutation_keys = Arc::new(
        client_keys
            .fork()
            .expect("fork paired keys for a stale persistent mutation"),
    );
    let stale_fresh_composition = PersistentRemoteComposition::injected_for_test(
        &remote_cli_expectation(),
        &AcceptedRemoteCliSignatureVerifier,
        CliInstallationStore::injected_for_test(stale_fresh_home),
        stale_fresh_keys,
        stale_fresh_state,
    )
    .expect("construct fresh-auth stale persistent remote composition");

    let selector = persistent_selector(identity);
    let expected_grant_serial = {
        let recovered = composition
            .recovered_paired_machine_store()
            .expect("recover persistent machine before revoke");
        let opened = recovered
            .open_exact(identity)
            .expect("open exact persistent machine before revoke");
        opened.grant_serial()
    };
    let mut revoke_rng = ChaCha20Rng::from_seed([0x53; 32]);
    let revoked = match tokio::time::timeout(
        IO_TIMEOUT,
        execute_persistent_remote_mutation(
            composition,
            selector,
            PersistentRemoteMutation::RevokeSelf,
            &mut revoke_rng,
        ),
    )
    .await
    {
        Ok(result) => result.expect("persistent remote revoke-self composition"),
        Err(error) => panic!(
            "persistent remote revoke-self deadline: {error:?}; {}; {}",
            runtime_remote_diagnostic(runtime_db),
            relay_stream_diagnostic(relay_db)
        ),
    };
    // `execute_persistent_remote_mutation(RevokeSelf)` 消费的就是发送 intent 的同一条
    // active Runtime：只有该连接收到 exact MachineRoot-signed terminal、完成 transport
    // shutdown/drop 并提交 crash-safe cleanup 后，才可能返回下面的 Committed receipt。
    assert!(matches!(
        revoked,
        PersistentRemoteMutationOutcome::Revocation {
            route_accepted: true,
            receipt: RevocationReceipt::Committed { grant_serial },
        } if grant_serial.0 == expected_grant_serial.value()
    ));
    assert!(
        composition
            .recovered_paired_machine_store()
            .expect("recover persistent machine inventory after revoke")
            .list()
            .expect("list after revoke cleanup")
            .is_empty()
    );
    assert_eq!(
        relay_device_grant_counts(relay_db),
        (1, 0),
        "Relay 必须保留唯一 revoke tombstone，并清零 active grant"
    );

    let stale_fresh_recovered = stale_fresh_composition
        .recovered_paired_machine_store()
        .expect("recover pre-revoke stale persistent machine");
    let fresh_opened = stale_fresh_recovered
        .open_exact(identity)
        .expect("open pre-revoke stale credentials for fresh authentication");
    let fresh_outcome = tokio::time::timeout(IO_TIMEOUT, connect_paired_runtime(fresh_opened))
        .await
        .expect("fresh stale authentication deadline")
        .expect("fresh stale authentication returns a typed terminal");
    assert!(
        matches!(fresh_outcome, PairedRuntimeConnectOutcome::Revoked),
        "pre-revoke credentials must fresh-authenticate only to typed Revoked"
    );

    let stale_composition = PersistentRemoteComposition::injected_for_test(
        &remote_cli_expectation(),
        &AcceptedRemoteCliSignatureVerifier,
        CliInstallationStore::injected_for_test(stale_mutation_home),
        stale_mutation_keys,
        stale_mutation_state,
    )
    .expect("construct stale persistent remote composition");
    let stale_selector = persistent_selector(identity);
    let commands_before_stale_request = runtime_command_count(runtime_db);
    let mut stale_rng = ChaCha20Rng::from_seed([0x54; 32]);
    let stale_error = tokio::time::timeout(
        IO_TIMEOUT,
        execute_persistent_remote_mutation(
            &stale_composition,
            stale_selector,
            PersistentRemoteMutation::Prompt(SendPromptRequest {
                conversation_id,
                idempotency_key: IdempotencyKey::new("p47-stale-prompt-after-revoke"),
                expected_configuration_revision: 1,
                prompt: PromptPayload::new("this revoked request must never enter RuntimeCore")
                    .expect("bounded stale prompt"),
            }),
            &mut stale_rng,
        ),
    )
    .await
    .expect("stale request must fail before the ordinary I/O deadline")
    .expect_err("revoked credentials cannot receive a business receipt");
    assert!(
        matches!(stale_error, PersistentRemoteMutationError::HandshakeRevoked),
        "stale persistent mutation must fail at the authenticated handshake: {stale_error:?}"
    );
    assert_eq!(
        runtime_command_count(runtime_db),
        commands_before_stale_request,
        "stale post-revoke prompt must not enter RuntimeCore's command ledger"
    );
}

struct RetainedReplayEvidence {
    cut_before_event: ConversationPublicationCut,
    configuration: ConversationConfiguration,
}

async fn inject_retained_configuration_event(
    gate: Arc<ReplayBootstrapGate>,
    socket: PathBuf,
    installation_id: InstallationId,
    kind: AgentKind,
    conversation_id: ConversationId,
    runtime_db: PathBuf,
    relay_db: PathBuf,
) -> RetainedReplayEvidence {
    gate.snapshot_applied.notified().await;
    let _release = ReplayGateReleaseGuard(gate);
    let cut_before_event = conversation_publication_cut(&runtime_db, &conversation_id);
    let configuration = conversation_configuration(kind);
    let client = RuntimeUnixClient::connect_injected_with_installation(
        InjectedEndpoint::for_test(socket),
        installation_id,
    )
    .await
    .expect("connect second same-installation Runtime UDS client");
    let configured = unary(
        &client,
        RuntimeRequest::ConfigureConversation(ConfigureConversationRequest::new(
            conversation_id.clone(),
            IdempotencyKey::new(format!(
                "p47-retained-replay-configure-{}",
                match kind {
                    AgentKind::Codex => "codex",
                    AgentKind::ClaudeCode => "claude-code",
                }
            )),
            1,
            configuration.clone(),
        )),
    )
    .await;
    assert!(matches!(
        configured,
        RuntimeReply::Configuration(
            agentdeck_protocol::runtime::ConfigurationReceipt::Applied {
                conversation_id: configured_id,
                configuration_revision: 2,
            }
        ) if configured_id == conversation_id
    ));

    let retained = tokio::time::timeout(IO_TIMEOUT, async {
        loop {
            if relay_retains_exact_next_frame(&relay_db, cut_before_event) {
                break;
            }
            tokio::time::sleep(Duration::from_millis(10)).await;
        }
    })
    .await;
    if retained.is_err() {
        panic!(
            "exact retained ConfigurationChanged frame deadline; cut={cut_before_event:?}; {}; {}",
            runtime_remote_diagnostic(&runtime_db),
            relay_stream_diagnostic(&relay_db)
        );
    }
    let cut_after_event = conversation_publication_cut(&runtime_db, &conversation_id);
    assert_eq!(cut_after_event.stream_route, cut_before_event.stream_route);
    assert_eq!(cut_after_event.generation, cut_before_event.generation);
    assert_eq!(
        cut_after_event.outer_seq,
        cut_before_event
            .outer_seq
            .checked_add(1)
            .expect("retained outer cursor exact successor")
    );
    assert_eq!(
        cut_after_event.inner_seq,
        cut_before_event
            .inner_seq
            .checked_add(1)
            .expect("retained inner cursor exact successor")
    );
    client
        .close()
        .await
        .expect("close retained-event Runtime UDS client");
    RetainedReplayEvidence {
        cut_before_event,
        configuration,
    }
}

struct AgentExerciseEvidence {
    conversation_id: ConversationId,
    prompt: SendPromptRequest,
    command_id: CommandId,
    turn_id: TurnId,
    approval_id: ApprovalId,
    approval_decision: ActionDecision,
}

struct AgentExerciseContext<'a, 'store> {
    paired: &'a RecoveredPairedMachineStore<'store>,
    identity: PairedMachineIdentity,
    local: &'a RuntimeUnixClient,
    runtime_db: &'a Path,
    relay_db: &'a Path,
    local_socket: &'a Path,
    local_installation_id: InstallationId,
}

async fn exercise_agent(
    context: &AgentExerciseContext<'_, '_>,
    kind: AgentKind,
    conversation_id: ConversationId,
    seed: u8,
) -> AgentExerciseEvidence {
    let paired = context.paired;
    let identity = context.identity;
    let local = context.local;
    let runtime_db = context.runtime_db;
    let relay_db = context.relay_db;
    let local_socket = context.local_socket;
    let local_installation_id = context.local_installation_id;
    let mut runtime = connected_runtime(paired, identity).await;
    let requested = RuntimeInnerCursor::Conversation {
        conversation_id: conversation_id.clone(),
        cursor: StreamCursor::BeforeFirst,
    };
    let mut reducer = ConversationReducer::new(conversation_id.clone());
    let mut rng = ChaCha20Rng::from_seed([seed; 32]);
    let bootstrap = tokio::time::timeout(
        IO_TIMEOUT,
        runtime.subscribe(requested, &mut reducer, &mut rng),
    )
    .await
    .expect("remote subscribe deadline")
    .expect("authenticated remote subscription bootstrap");
    assert_eq!(
        bootstrap.sync_complete().inner_cursor,
        reducer.cursor,
        "subscription bootstrap must commit the reducer's authenticated cursor"
    );
    await_replay_complete(&mut runtime, &mut reducer).await;

    let label = match kind {
        AgentKind::Codex => "codex",
        AgentKind::ClaudeCode => "claude-code",
    };
    let prompt = SendPromptRequest {
        conversation_id: conversation_id.clone(),
        idempotency_key: IdempotencyKey::new(format!("p47-prompt-{label}")),
        expected_configuration_revision: 1,
        prompt: PromptPayload::new(format!("P4.7 synthetic prompt for {label}"))
            .expect("bounded synthetic prompt"),
    };
    let accepted = tokio::time::timeout(IO_TIMEOUT, runtime.prompt(prompt.clone(), &mut rng))
        .await
        .expect("remote prompt deadline")
        .expect("authenticated daemon prompt receipt");
    let command_id = match accepted.receipt() {
        CommandReceipt::Accepted {
            command_id,
            configuration_revision: 1,
            ..
        } => command_id.clone(),
        receipt => panic!("prompt success must be daemon Accepted, got {receipt:?}"),
    };

    let mut user_seen = false;
    let mut assistant_seen = false;
    let (turn_id, approval_id, request_id) = loop {
        let event = next_applied_event(&mut runtime, &mut reducer, runtime_db, relay_db).await;
        match event.body {
            RuntimeEventBody::Item {
                item: AgentItem::UserMessage { text, .. },
            } => {
                assert_eq!(text, prompt.prompt.as_str());
                user_seen = true;
            }
            RuntimeEventBody::Item {
                item: AgentItem::AssistantMessage { text, .. },
            } => {
                assert!(
                    user_seen,
                    "canonical user prompt must precede assistant history"
                );
                let expected = match kind {
                    AgentKind::Codex => "synthetic Codex response",
                    AgentKind::ClaudeCode => "synthetic Claude Code response",
                };
                assert_eq!(text, expected);
                assistant_seen = true;
            }
            RuntimeEventBody::ActionRequest {
                turn_id,
                approval_id,
                request,
            } => {
                assert!(
                    assistant_seen,
                    "assistant history item must precede approval"
                );
                match (&kind, &request.vendor) {
                    (AgentKind::Codex, ActionRequestVendor::Codex { can_persist, .. }) => {
                        assert!(!can_persist);
                    }
                    (AgentKind::ClaudeCode, ActionRequestVendor::ClaudeCode { .. }) => {}
                    _ => panic!("synthetic approval vendor does not match conversation"),
                }
                break (turn_id, approval_id, request.request_id);
            }
            _ => {}
        }
    };

    let approval_decision = ActionDecision {
        request_id,
        decision: ActionDecisionKind::Approve,
        persist: false,
    };
    let approval = tokio::time::timeout(
        IO_TIMEOUT,
        runtime.resolve_approval(
            conversation_id.clone(),
            turn_id.clone(),
            approval_id.clone(),
            approval_decision.clone(),
            &mut rng,
        ),
    )
    .await
    .expect("remote approval deadline")
    .expect("authenticated daemon approval receipt");
    assert!(
        matches!(
            approval.receipt(),
            ApprovalReceipt::Claimed { approval_id: observed }
                | ApprovalReceipt::Applied { approval_id: observed }
                if observed == &approval_id
        ),
        "first-winner approval receipt must preserve the exact approval id: {:?}",
        approval.receipt()
    );

    let mut approval_resolved = false;
    let completed_turn = loop {
        let event = next_applied_event(&mut runtime, &mut reducer, runtime_db, relay_db).await;
        match event.body {
            RuntimeEventBody::ApprovalResolved {
                turn_id: resolved_turn,
                approval_id: resolved_approval,
                decision: Some(ActionDecisionKind::Approve),
                state: ApprovalDeliveryState::Applied,
            } => {
                assert_eq!(resolved_turn, turn_id);
                assert_eq!(resolved_approval, approval_id);
                approval_resolved = true;
            }
            RuntimeEventBody::TurnCompleted {
                turn_id: completed, ..
            } => {
                assert!(approval_resolved, "terminal must follow applied approval");
                break completed;
            }
            _ => {}
        }
    };
    assert_eq!(completed_turn, turn_id);

    let applied = tokio::time::timeout(
        IO_TIMEOUT,
        runtime.retry_approval(conversation_id.clone(), approval_id.clone(), &mut rng),
    )
    .await
    .expect("applied approval readback deadline")
    .expect("authenticated applied approval readback");
    assert!(matches!(
        applied.receipt(),
        ApprovalReceipt::Applied { approval_id: observed } if observed == &approval_id
    ));

    let status = unary(
        local,
        RuntimeRequest::QueryReceipt(QueryReceiptSelector::Command {
            conversation_id: conversation_id.clone(),
            command_id: command_id.clone(),
        }),
    )
    .await;
    assert!(
        matches!(
            status,
            RuntimeReply::Failure(failure)
                if failure.code == "daemon.runtime.invalid_state"
        ),
        "local UDS principal must not read a remote device owner's command receipt"
    );

    RemoteRuntime::shutdown(*runtime).await;

    let mut reconnected = connected_runtime(paired, identity).await;
    let replay_gate = Arc::new(ReplayBootstrapGate::new());
    let retained_event = tokio::spawn(inject_retained_configuration_event(
        replay_gate.clone(),
        local_socket.to_path_buf(),
        local_installation_id,
        kind,
        conversation_id.clone(),
        runtime_db.to_path_buf(),
        relay_db.to_path_buf(),
    ));
    let mut history = GatedConversationReducer::new(conversation_id.clone(), replay_gate);
    let requested = RuntimeInnerCursor::Conversation {
        conversation_id: conversation_id.clone(),
        cursor: StreamCursor::BeforeFirst,
    };
    let bootstrap = tokio::time::timeout(
        IO_TIMEOUT,
        reconnected.subscribe(requested, &mut history, &mut rng),
    )
    .await
    .expect("remote history subscribe deadline")
    .expect("authenticated remote history snapshot");
    let retained_event = retained_event
        .await
        .expect("join exact retained ConfigurationChanged producer");
    assert_eq!(
        bootstrap.sync_complete().inner_cursor,
        history.conversation.cursor
    );
    assert_eq!(
        history.conversation.cursor,
        RuntimeInnerCursor::Conversation {
            conversation_id: conversation_id.clone(),
            cursor: StreamCursor::At(retained_event.cut_before_event.inner_seq),
        },
        "fresh snapshot must freeze before the injected retained event"
    );
    assert_eq!(
        history.conversation.history_shape(),
        (true, true),
        "reconnected snapshot must retain user and synthetic assistant history"
    );

    let expected_inner_seq = retained_event
        .cut_before_event
        .inner_seq
        .checked_add(1)
        .expect("retained event has an exact inner successor");
    let expected_outer_seq = retained_event
        .cut_before_event
        .outer_seq
        .checked_add(1)
        .expect("retained event has an exact outer successor");
    let mut retained_applied = false;
    loop {
        let outcome =
            tokio::time::timeout(IO_TIMEOUT, reconnected.receive_stream_frame(&mut history))
                .await
                .expect("retained replay frame deadline")
                .expect("receive retained replay frame");
        match outcome {
            RemoteStreamFrameOutcome::Applied(item) => {
                assert!(
                    !retained_applied,
                    "reconnect replay applied more than the one injected retained event"
                );
                let RuntimeStreamItem::Event(event) = *item else {
                    panic!("conversation replay applied a non-event");
                };
                assert_eq!(event.conversation_id, conversation_id);
                assert_eq!(event.event_seq, expected_inner_seq);
                let RuntimeEventBody::ConfigurationChanged { state } = event.body else {
                    panic!("retained replay event was not ConfigurationChanged");
                };
                assert_eq!(state.configuration_revision(), 2);
                assert_eq!(state.configuration(), Some(&retained_event.configuration));
                assert_eq!(
                    history.conversation.cursor,
                    RuntimeInnerCursor::Conversation {
                        conversation_id: conversation_id.clone(),
                        cursor: StreamCursor::At(expected_inner_seq),
                    },
                    "retained replay must advance the reducer by exactly one inner event"
                );
                retained_applied = true;
            }
            RemoteStreamFrameOutcome::ReplayComplete { current_cursor } => {
                assert!(
                    retained_applied,
                    "ReplayComplete arrived before the injected retained event was Applied"
                );
                assert_eq!(current_cursor, StreamCursor::At(expected_outer_seq));
                break;
            }
            RemoteStreamFrameOutcome::AuthenticatedOverlap
            | RemoteStreamFrameOutcome::AppliedDuplicate
            | RemoteStreamFrameOutcome::TransferBuffered { .. }
            | RemoteStreamFrameOutcome::TransferAlreadyComplete { .. }
            | RemoteStreamFrameOutcome::KeySyncPending { .. }
            | RemoteStreamFrameOutcome::KeySyncRouteAccepted { .. }
            | RemoteStreamFrameOutcome::KeyUpdateInstalled { .. }
            | RemoteStreamFrameOutcome::KeyUpdateAckRouteAccepted { .. }
            | RemoteStreamFrameOutcome::EpochBarrierApplied { .. }
            | RemoteStreamFrameOutcome::StreamAppliedAckRouteAccepted { .. } => {}
            RemoteStreamFrameOutcome::Gap { .. } => {
                panic!("retained reconnect replay produced a Relay gap")
            }
            RemoteStreamFrameOutcome::RevocationCommitted { .. } => {
                panic!("device revoked before retained reconnect replay completed")
            }
        }
    }

    RemoteRuntime::shutdown(*reconnected).await;

    AgentExerciseEvidence {
        conversation_id,
        prompt,
        command_id,
        turn_id,
        approval_id,
        approval_decision,
    }
}

async fn smoke_persistent_mutations(
    composition: &PersistentRemoteComposition,
    selector: PersistentMachineSelector,
    evidence: AgentExerciseEvidence,
    runtime_db: &Path,
    seed: u8,
) {
    let AgentExerciseEvidence {
        conversation_id,
        prompt,
        command_id,
        turn_id,
        approval_id,
        approval_decision,
    } = evidence;
    // 低层 Runtime 只负责上面的逐帧因果断言；下面三次调用必须重新经过 production
    // composition 的 recover → exact selector → open/connect → daemon receipt → shutdown。
    let mut high_level_rng = ChaCha20Rng::from_seed([seed; 32]);
    let high_level_prompt = tokio::time::timeout(
        IO_TIMEOUT,
        execute_persistent_remote_mutation(
            composition,
            selector,
            PersistentRemoteMutation::Prompt(prompt),
            &mut high_level_rng,
        ),
    )
    .await
    .expect("production persistent prompt replay deadline")
    .expect("production persistent prompt replay receipt");
    assert!(matches!(
        high_level_prompt,
        PersistentRemoteMutationOutcome::Prompt {
            route_accepted: true,
            receipt: CommandReceipt::Replayed {
                command_id: replayed_id,
                configuration_revision: 1,
            },
        } if replayed_id == command_id
    ));

    let counts_before_approval_loser = runtime_business_counts(runtime_db);

    let high_level_approval = tokio::time::timeout(
        IO_TIMEOUT,
        execute_persistent_remote_mutation(
            composition,
            selector,
            PersistentRemoteMutation::ResolveApproval {
                conversation_id: conversation_id.clone(),
                turn_id,
                approval_id: approval_id.clone(),
                decision: approval_decision,
            },
            &mut high_level_rng,
        ),
    )
    .await
    .expect("production persistent approval replay deadline")
    .expect("production persistent approval replay receipt");
    assert!(match high_level_approval {
        PersistentRemoteMutationOutcome::Approval {
            route_accepted: true,
            receipt: ApprovalReceipt::Applied {
                approval_id: observed,
            },
        } => observed == approval_id,
        PersistentRemoteMutationOutcome::Approval {
            route_accepted: true,
            receipt:
                ApprovalReceipt::AlreadyHandled {
                    approval_id: observed,
                    decision: ActionDecisionKind::Approve,
                    state: ApprovalDeliveryState::Applied,
                },
        } => observed == approval_id,
        _ => false,
    });
    assert_eq!(
        runtime_business_counts(runtime_db),
        counts_before_approval_loser,
        "approval loser replay must not create a second claim or mutate the durable ledger"
    );

    let high_level_retry = tokio::time::timeout(
        IO_TIMEOUT,
        execute_persistent_remote_mutation(
            composition,
            selector,
            PersistentRemoteMutation::RetryApproval {
                conversation_id,
                approval_id: approval_id.clone(),
            },
            &mut high_level_rng,
        ),
    )
    .await
    .expect("production persistent retry-approval deadline")
    .expect("production persistent retry-approval receipt");
    assert!(matches!(
        high_level_retry,
        PersistentRemoteMutationOutcome::Approval {
            route_accepted: true,
            receipt: ApprovalReceipt::Applied {
                approval_id: observed,
            },
        } if observed == approval_id
    ));
    assert_eq!(
        runtime_business_counts(runtime_db),
        counts_before_approval_loser,
        "retry readback after an Applied approval must remain zero-mutation"
    );
}

#[derive(Debug, Deserialize)]
#[serde(tag = "op", rename_all = "camelCase", deny_unknown_fields)]
enum P57HostCommand {
    Status {
        #[serde(rename = "requestId")]
        request_id: String,
    },
    WaitFor {
        #[serde(rename = "requestId")]
        request_id: String,
        condition: P57HostWaitCondition,
        #[serde(rename = "timeoutMs")]
        timeout_ms: u64,
    },
    ApprovePendingPairing {
        #[serde(rename = "requestId")]
        request_id: String,
    },
    RestartDaemon {
        #[serde(rename = "requestId")]
        request_id: String,
        #[serde(rename = "markerBeforeReadiness", default)]
        marker_before_readiness: bool,
    },
    Shutdown {
        #[serde(rename = "requestId")]
        request_id: String,
    },
}

#[derive(Clone, Copy, Debug, Deserialize, Serialize)]
#[serde(rename_all = "camelCase")]
enum P57HostWaitCondition {
    PendingPairing,
    BusinessReady,
    DualScopeBusinessReady,
    WebBusinessMutated,
    BusinessMutated,
    Revoked,
    RestartBaseReady,
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
struct P57HostReady {
    kind: &'static str,
    protocol: &'static str,
    root_path: String,
    home_path: String,
    socket_path: String,
    invite_path: String,
    runtime_database_path: String,
    relay_database_path: String,
    relay_wss_origin: String,
    relay_spki_pin_base64: String,
    pid: u32,
    invite_file_mode: u32,
    daemon_generation: u64,
    scenario: Option<&'static str>,
    conversation_id: Option<String>,
    conversation_title: Option<&'static str>,
}

#[derive(Clone, Serialize)]
#[serde(rename_all = "camelCase")]
struct P57HostEvidence {
    machine_remote_lifecycle: MachineRemoteLifecycle,
    failure_code: Option<String>,
    pending_pairing_count: usize,
    relay_grant_total: i64,
    relay_grant_active: i64,
    active_transition_count: i64,
    active_catalog_stream_count: i64,
    runtime_command_count: i64,
    runtime_completed_command_count: i64,
    runtime_approval_total: i64,
    runtime_approval_applied: i64,
    runtime_revoked_authorization_count: i64,
    runtime_active_writer_count: usize,
    runtime_live_subscription_count: usize,
    runtime_barrier_subscription_count: usize,
    runtime_snapshot_sender_count: usize,
    runtime_subscription_job_count: usize,
    daemon_generation: u64,
    socket_is_unix: bool,
    socket_mode: u32,
}

impl P57HostEvidence {
    fn satisfies(&self, condition: P57HostWaitCondition) -> bool {
        match condition {
            P57HostWaitCondition::PendingPairing => {
                self.pending_pairing_count == 1
                    && self.relay_grant_total == 0
                    && self.relay_grant_active == 0
            }
            P57HostWaitCondition::BusinessReady => self.satisfies_business_ready(2, 2, 2),
            P57HostWaitCondition::DualScopeBusinessReady => {
                self.satisfies_dual_scope_business_ready()
            }
            P57HostWaitCondition::WebBusinessMutated => {
                self.runtime_command_count == 1
                    && self.runtime_completed_command_count == 1
                    && self.runtime_approval_total == 1
                    && self.runtime_approval_applied == 1
                    && self.runtime_active_writer_count == 2
                    && self.runtime_live_subscription_count == 2
                    && self.runtime_barrier_subscription_count == 0
                    && self.runtime_snapshot_sender_count == 0
                    && self.runtime_subscription_job_count == 2
            }
            P57HostWaitCondition::BusinessMutated => {
                self.runtime_command_count == 1
                    && self.runtime_completed_command_count == 1
                    && self.runtime_approval_total == 1
                    && self.runtime_approval_applied == 1
                    && self.runtime_active_writer_count == 2
                    && self.runtime_live_subscription_count == 2
                    && self.runtime_barrier_subscription_count == 0
                    && self.runtime_snapshot_sender_count == 0
                    && self.runtime_subscription_job_count == 2
            }
            P57HostWaitCondition::Revoked => {
                self.relay_grant_total == 1
                    && self.relay_grant_active == 0
                    && self.runtime_revoked_authorization_count == 1
            }
            P57HostWaitCondition::RestartBaseReady => self.satisfies_business_ready_base(),
        }
    }

    fn satisfies_business_ready(
        &self,
        expected_active_writers: usize,
        expected_live_subscriptions: usize,
        expected_subscription_jobs: usize,
    ) -> bool {
        self.satisfies_business_ready_base()
            && self.runtime_active_writer_count == expected_active_writers
            && self.runtime_live_subscription_count == expected_live_subscriptions
            && self.runtime_subscription_job_count == expected_subscription_jobs
    }

    fn satisfies_dual_scope_business_ready(&self) -> bool {
        self.satisfies_business_ready_base()
            && self.runtime_active_writer_count == 3
            && (3..=4).contains(&self.runtime_live_subscription_count)
            && self.runtime_subscription_job_count == self.runtime_live_subscription_count
    }

    fn satisfies_business_ready_base(&self) -> bool {
        self.machine_remote_lifecycle == MachineRemoteLifecycle::Active
            && self.pending_pairing_count == 0
            && self.relay_grant_total == 1
            && self.relay_grant_active == 1
            && self.active_transition_count == 0
            && self.active_catalog_stream_count == 1
            && self.runtime_barrier_subscription_count == 0
            && self.runtime_snapshot_sender_count == 0
    }
}

#[test]
fn p57_host_readiness_keeps_single_remote_and_dual_scope_topologies_exact() {
    let mut evidence = P57HostEvidence {
        machine_remote_lifecycle: MachineRemoteLifecycle::Active,
        failure_code: None,
        pending_pairing_count: 0,
        relay_grant_total: 1,
        relay_grant_active: 1,
        active_transition_count: 0,
        active_catalog_stream_count: 1,
        runtime_command_count: 0,
        runtime_completed_command_count: 0,
        runtime_approval_total: 0,
        runtime_approval_applied: 0,
        runtime_revoked_authorization_count: 0,
        runtime_active_writer_count: 2,
        runtime_live_subscription_count: 2,
        runtime_barrier_subscription_count: 0,
        runtime_snapshot_sender_count: 0,
        runtime_subscription_job_count: 2,
        daemon_generation: 1,
        socket_is_unix: true,
        socket_mode: 0o600,
    };

    assert!(evidence.satisfies(P57HostWaitCondition::BusinessReady));
    assert!(!evidence.satisfies(P57HostWaitCondition::DualScopeBusinessReady));

    evidence.runtime_active_writer_count = 3;
    evidence.runtime_live_subscription_count = 3;
    evidence.runtime_subscription_job_count = 3;
    assert!(!evidence.satisfies(P57HostWaitCondition::BusinessReady));
    assert!(evidence.satisfies(P57HostWaitCondition::DualScopeBusinessReady));

    evidence.runtime_live_subscription_count = 4;
    evidence.runtime_subscription_job_count = 4;
    assert!(evidence.satisfies(P57HostWaitCondition::DualScopeBusinessReady));

    evidence.runtime_subscription_job_count = 5;
    assert!(!evidence.satisfies(P57HostWaitCondition::DualScopeBusinessReady));
    evidence.runtime_live_subscription_count = 5;
    assert!(!evidence.satisfies(P57HostWaitCondition::DualScopeBusinessReady));
    evidence.runtime_live_subscription_count = 4;
    evidence.runtime_subscription_job_count = 4;
    evidence.runtime_active_writer_count = 2;
    assert!(!evidence.satisfies(P57HostWaitCondition::DualScopeBusinessReady));

    evidence.runtime_command_count = 1;
    evidence.runtime_completed_command_count = 1;
    evidence.runtime_approval_total = 1;
    evidence.runtime_approval_applied = 1;
    evidence.runtime_active_writer_count = 2;
    evidence.runtime_live_subscription_count = 2;
    evidence.runtime_subscription_job_count = 2;
    assert!(evidence.satisfies(P57HostWaitCondition::WebBusinessMutated));
    evidence.runtime_subscription_job_count = 1;
    assert!(!evidence.satisfies(P57HostWaitCondition::WebBusinessMutated));
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
struct P57HostStatus<'a> {
    kind: &'static str,
    protocol: &'static str,
    request_id: &'a str,
    evidence: P57HostEvidence,
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
struct P57HostWait<'a> {
    kind: &'static str,
    protocol: &'static str,
    request_id: &'a str,
    condition: P57HostWaitCondition,
    satisfied: bool,
    evidence: P57HostEvidence,
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
struct P57HostPairingApproved<'a> {
    kind: &'static str,
    protocol: &'static str,
    request_id: &'a str,
    evidence: P57HostEvidence,
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
struct P57HostDaemonRestarted<'a> {
    kind: &'static str,
    protocol: &'static str,
    request_id: &'a str,
    recovered_conversation_id: String,
    restart_marker_title: &'static str,
    metadata_entry_revision: u64,
    evidence: P57HostEvidence,
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
struct P57HostDaemonRestartReady<'a> {
    kind: &'static str,
    protocol: &'static str,
    request_id: &'a str,
    metadata_entry_revision: u64,
    evidence: P57HostEvidence,
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
struct P57HostError<'a> {
    kind: &'static str,
    protocol: &'static str,
    request_id: Option<&'a str>,
    code: &'static str,
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
struct P57HostReadinessError<'a> {
    kind: &'static str,
    protocol: &'static str,
    request_id: Option<&'a str>,
    code: &'static str,
    evidence: P57HostEvidence,
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
struct P57HostStopped<'a> {
    kind: &'static str,
    protocol: &'static str,
    request_id: Option<&'a str>,
    invite_removed: bool,
    socket_exists: bool,
}

fn emit_p57_host_record(value: &impl Serialize) {
    let stdout = io::stdout();
    let mut locked = stdout.lock();
    // libtest 会先打印不带换行的 `test <name> ... `。首条记录主动换行，保证
    // Swift Process 可以逐行只接受以 `{` 开头的严格 NDJSON，而不必解析 harness 文本。
    if !P57_HOST_OUTPUT_STARTED.swap(true, Ordering::SeqCst) {
        locked
            .write_all(b"\n")
            .expect("separate P5.7 host NDJSON from libtest prefix");
    }
    serde_json::to_writer(&mut locked, value).expect("encode P5.7 host NDJSON record");
    locked
        .write_all(b"\n")
        .expect("terminate P5.7 host NDJSON record");
    locked.flush().expect("flush P5.7 host NDJSON record");
}

fn write_p57_host_invite(root: &Path, invite: &agentdeck_protocol::e2ee::PairInviteV1) -> PathBuf {
    let path = root.join("pair-invite.secret");
    let encoded = invite
        .encode_uri(unix_now_ms())
        .expect("encode fresh P5.7 host pair invite");
    let mut file = OpenOptions::new()
        .write(true)
        .create_new(true)
        .mode(0o600)
        .open(&path)
        .expect("create private P5.7 host invite file");
    file.write_all(encoded.as_bytes())
        .expect("write private P5.7 host invite file");
    file.sync_all().expect("sync private P5.7 host invite file");
    let metadata = fs::symlink_metadata(&path).expect("read P5.7 host invite metadata");
    assert!(metadata.file_type().is_file());
    assert_eq!(metadata.permissions().mode() & 0o777, 0o600);
    path
}

struct P57DaemonInstance {
    _singleton: SingletonGuard,
    core: Arc<RuntimeCore>,
    local: RuntimeUnixClient,
    socket: PathBuf,
    stop_tx: Option<oneshot::Sender<()>>,
    listener_task: tokio::task::JoinHandle<()>,
}

impl P57DaemonInstance {
    async fn shutdown(mut self) {
        self.local
            .close()
            .await
            .expect("close P5.7 host local Runtime client");
        self.stop_tx
            .take()
            .expect("P5.7 daemon stop sender remains owned")
            .send(())
            .expect("signal P5.7 daemon listener shutdown");
        self.listener_task
            .await
            .expect("join P5.7 daemon listener task");
        self.core
            .shutdown()
            .await
            .expect("shutdown P5.7 host RuntimeCore");
    }
}

async fn start_p57_daemon_instance(
    config: &DaemonConfig,
    daemon_keys: Arc<MemoryKeyStore>,
    local_home: &Path,
) -> P57DaemonInstance {
    let singleton =
        SingletonGuard::acquire(config.paths()).expect("acquire isolated P5.7 host singleton");
    let storage_kek = load_or_create_storage_kek(daemon_keys.as_ref(), &config.paths().runtime_db)
        .expect("load isolated P5.7 host StorageKEK");
    let store = RuntimeStoreHandle::open(
        RuntimeStoreConfig::new(config.paths().runtime_db.clone()),
        storage_kek,
    )
    .await
    .expect("open P5.7 host Runtime store");
    let bootstrap = reconcile_machine_identity(config, &store, daemon_keys.as_ref())
        .await
        .expect("bootstrap P5.7 host machine identity");
    let manager = Arc::new(RemoteManager::new(
        store.clone(),
        daemon_keys,
        config.clone(),
        bootstrap,
    ));
    let router = Arc::new(synthetic_e2e::agent_router());
    let core = RuntimeCore::new_production_for_synthetic_e2e(
        store,
        router,
        PathBuf::from(env!("CARGO_BIN_EXE_agentdeckd")),
    )
    .expect("construct P5.7 host production RuntimeCore with synthetic vendor adapters")
    .with_remote_administration(manager.clone())
    .with_pairing_administration(manager.clone())
    .with_revocation_administration(manager.clone())
    .with_conversation_activation(manager.clone());
    assert!(manager.install_pairing_pending_sink(core.pairing_pending_sink()));
    let core = Arc::new(core);
    assert!(manager.install_runtime_core(&core));
    let (_, recovery_ready) = core
        .recover_for_startup()
        .await
        .expect("recover P5.7 host RuntimeCore");
    let mut listener =
        BoundLocalListener::bind_after_recovery(recovery_ready, config, &singleton, core.clone())
            .await
            .expect("bind P5.7 host stable Runtime UDS");
    let socket = listener.local_ready_permit().socket_path().to_path_buf();
    let remote_start = listener
        .take_remote_start_permit()
        .expect("P5.7 host stable listener yields remote start permit");
    let (stop_tx, stop_rx) = oneshot::channel();
    let manager_for_shutdown = manager.clone();
    let listener_task = tokio::spawn(async move {
        listener
            .serve_until(async move {
                let _ = stop_rx.await;
                manager_for_shutdown.shutdown().await;
                Ok(())
            })
            .await
            .expect("stop P5.7 host daemon listener");
    });
    manager
        .arm(remote_start)
        .await
        .expect("arm P5.7 host RemoteManager");

    fs::create_dir_all(local_home).expect("create isolated P5.7 host Runtime client home");
    fs::set_permissions(local_home, fs::Permissions::from_mode(0o700))
        .expect("secure isolated P5.7 host Runtime client home");
    let local_installation_id = CliInstallationStore::injected_for_test(local_home.to_path_buf())
        .load_or_create()
        .expect("create stable P5.7 host Runtime installation identity");
    let local = RuntimeUnixClient::connect_injected_with_installation(
        InjectedEndpoint::for_test(socket.clone()),
        local_installation_id,
    )
    .await
    .expect("connect P5.7 host same-UID Runtime UDS");
    P57DaemonInstance {
        _singleton: singleton,
        core,
        local,
        socket,
        stop_tx: Some(stop_tx),
        listener_task,
    }
}

async fn create_p57_conversation(
    local: &RuntimeUnixClient,
    root: &Path,
    idempotency_prefix: &str,
    title: &str,
) -> ConversationId {
    let RuntimeReply::ConversationStart(ConversationStartReceipt {
        conversation_id,
        replayed: false,
    }) = unary(
        local,
        RuntimeRequest::Start(ConversationStart {
            agent_kind: AgentKind::Codex,
            idempotency_key: IdempotencyKey::new(format!("{idempotency_prefix}-start-codex")),
            cwd: root.to_path_buf(),
            title: Some(title.to_owned()),
        }),
    )
    .await
    else {
        panic!("P5.7 host failed to create a fresh Codex conversation");
    };
    let configured = unary(
        local,
        RuntimeRequest::ConfigureConversation(ConfigureConversationRequest::new(
            conversation_id.clone(),
            IdempotencyKey::new(format!("{idempotency_prefix}-configure-codex")),
            0,
            conversation_configuration(AgentKind::Codex),
        )),
    )
    .await;
    assert!(matches!(
        configured,
        RuntimeReply::Configuration(
            agentdeck_protocol::runtime::ConfigurationReceipt::Applied {
                conversation_id: configured_id,
                configuration_revision: 1,
            }
        ) if configured_id == conversation_id
    ));
    conversation_id
}

fn runtime_business_counts(database: &Path) -> (i64, i64, i64, i64) {
    Connection::open_with_flags(
        database,
        OpenFlags::SQLITE_OPEN_READ_ONLY | OpenFlags::SQLITE_OPEN_NO_MUTEX,
    )
    .expect("open Runtime DB read-only for business counts")
    .query_row(
        "SELECT
            (SELECT COUNT(*) FROM commands WHERE state = 'completed'),
            (SELECT COUNT(*) FROM approval_ledger),
            (SELECT COUNT(*) FROM approval_ledger WHERE state = 'applied'),
            (SELECT COUNT(*) FROM remote_authorization_ledger WHERE lifecycle = 'revoked')",
        [],
        |row| Ok((row.get(0)?, row.get(1)?, row.get(2)?, row.get(3)?)),
    )
    .expect("read Runtime business counts")
}

async fn p57_host_evidence(
    core: &RuntimeCore,
    local: &RuntimeUnixClient,
    socket: &Path,
    runtime_db: &Path,
    relay_db: &Path,
    daemon_generation: u64,
) -> P57HostEvidence {
    let RuntimeReply::MachineRemoteStatus(machine_status) = unary(
        local,
        RuntimeRequest::MachineRemoteStatus {
            scope: LocalOnlyAdministration::LocalOnly,
        },
    )
    .await
    else {
        panic!("P5.7 host status returned unrelated Runtime reply");
    };
    let pending_reply = unary(
        local,
        RuntimeRequest::ListPendingPairings {
            scope: LocalOnlyAdministration::LocalOnly,
        },
    )
    .await;
    let pending_pairing_count = match pending_reply {
        RuntimeReply::PendingPairings { pairings } => pairings.len(),
        // BarriersCommitted intentionally fences ordinary Runtime requests until every
        // device has durably ACKed the committed cuts. The wait probe must keep polling
        // through that expected transient state; MachineRemoteStatus + transition rows
        // below still prevent it from reporting BusinessReady early.
        RuntimeReply::Failure(failure)
            if failure.code == "daemon.remote.transition.business_fenced" =>
        {
            0
        }
        RuntimeReply::Failure(failure) => panic!(
            "P5.7 host pending readback failed with code {}; {}",
            failure.code,
            runtime_remote_diagnostic(runtime_db)
        ),
        other => panic!("P5.7 host pending readback returned unrelated Runtime reply: {other:?}"),
    };
    let (relay_grant_total, relay_grant_active) = relay_device_grant_counts(relay_db);
    let (active_transition_count, active_catalog_stream_count) =
        runtime_transition_counts(runtime_db);
    let (
        runtime_completed_command_count,
        runtime_approval_total,
        runtime_approval_applied,
        runtime_revoked_authorization_count,
    ) = runtime_business_counts(runtime_db);
    let socket_metadata = fs::symlink_metadata(socket).ok();
    let (
        runtime_active_writer_count,
        runtime_live_subscription_count,
        runtime_barrier_subscription_count,
        runtime_snapshot_sender_count,
        runtime_subscription_job_count,
    ) = core.synthetic_e2e_subscription_metrics();
    P57HostEvidence {
        machine_remote_lifecycle: machine_status.lifecycle,
        failure_code: machine_status
            .failure_code
            .as_ref()
            .map(|code| code.as_str().to_owned()),
        pending_pairing_count,
        relay_grant_total,
        relay_grant_active,
        active_transition_count,
        active_catalog_stream_count,
        runtime_command_count: runtime_command_count(runtime_db),
        runtime_completed_command_count,
        runtime_approval_total,
        runtime_approval_applied,
        runtime_revoked_authorization_count,
        runtime_active_writer_count,
        runtime_live_subscription_count,
        runtime_barrier_subscription_count,
        runtime_snapshot_sender_count,
        runtime_subscription_job_count,
        daemon_generation,
        socket_is_unix: socket_metadata
            .as_ref()
            .is_some_and(|metadata| metadata.file_type().is_socket()),
        socket_mode: socket_metadata
            .map(|metadata| metadata.permissions().mode() & 0o777)
            .unwrap_or_default(),
    }
}

async fn wait_for_p57_host_evidence(
    core: &RuntimeCore,
    local: &RuntimeUnixClient,
    socket: &Path,
    runtime_db: &Path,
    relay_db: &Path,
    condition: P57HostWaitCondition,
    timeout_ms: u64,
    daemon_generation: u64,
) -> (bool, P57HostEvidence) {
    let deadline = tokio::time::Instant::now() + Duration::from_millis(timeout_ms);
    loop {
        let evidence =
            p57_host_evidence(core, local, socket, runtime_db, relay_db, daemon_generation).await;
        if evidence.satisfies(condition) {
            return (true, evidence);
        }
        if tokio::time::Instant::now() >= deadline {
            return (false, evidence);
        }
        tokio::time::sleep(Duration::from_millis(10)).await;
    }
}

async fn apply_p57_host_restart_marker(
    local: &RuntimeUnixClient,
    conversation_id: &ConversationId,
) -> u64 {
    let marker = unary(
        local,
        RuntimeRequest::UpdateConversationMetadata(
            ConversationMetadataMutationRequest::new(
                conversation_id.clone(),
                IdempotencyKey::new("r44-restart-marker"),
                0,
                ConversationMetadataMutation::rename(Some(
                    P57_HOST_R44_RESTART_MARKER_TITLE.to_owned(),
                ))
                .expect("valid R4.4 restart marker title"),
            )
            .expect("valid R4.4 restart marker request"),
        ),
    )
    .await;
    match marker {
        RuntimeReply::ConversationMetadata(ConversationMetadataReceipt::Applied {
            conversation_id: observed,
            entry_revision,
        }) if observed == *conversation_id && entry_revision == 1 => entry_revision,
        other => panic!("restarted daemon did not apply the exact marker metadata: {other:?}"),
    }
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn real_daemon_remote_link_runs_both_synthetic_agents_and_revokes_cleanly() {
    Box::pin(async move {
        let root = TempDirBuilder::new()
            .prefix("ad-p47-")
            .tempdir_in("/tmp")
            .expect("P4.7 temp root");
        let root_path = fs::canonicalize(root.path()).expect("canonicalize P4.7 temp root");
        let relay_db = root_path.join("relay-store/relay.db");
        let (relay, bundle) = start_relay(&root_path)
            .await
            .expect("start real Relay Direct TLS server");
        let config = stable_daemon_config(&root_path);
        let singleton =
            SingletonGuard::acquire(config.paths()).expect("acquire isolated singleton");
        let daemon_keys = Arc::new(MemoryKeyStore::new());
        let storage_kek =
            load_or_create_storage_kek(daemon_keys.as_ref(), &config.paths().runtime_db)
                .expect("load isolated StorageKEK");
        let store = RuntimeStoreHandle::open(
            RuntimeStoreConfig::new(config.paths().runtime_db.clone()),
            storage_kek,
        )
        .await
        .expect("open Runtime store");
        let bootstrap = reconcile_machine_identity(&config, &store, daemon_keys.as_ref())
            .await
            .expect("bootstrap machine identity");
        let manager = Arc::new(RemoteManager::new(
            store.clone(),
            daemon_keys,
            config.clone(),
            bootstrap,
        ));
        let router = Arc::new(synthetic_e2e::agent_router());
        let core = RuntimeCore::new_production_for_synthetic_e2e(
            store.clone(),
            router,
            PathBuf::from(env!("CARGO_BIN_EXE_agentdeckd")),
        )
        .expect("construct production RuntimeCore with the real daemon exec-gate binary")
        .with_remote_administration(manager.clone())
        .with_pairing_administration(manager.clone())
        .with_revocation_administration(manager.clone())
        .with_conversation_activation(manager.clone());
        assert!(manager.install_pairing_pending_sink(core.pairing_pending_sink()));
        let core = Arc::new(core);
        assert!(manager.install_runtime_core(&core));
        let (_, recovery_ready) = core
            .recover_for_startup()
            .await
            .expect("recover RuntimeCore");
        let mut listener = BoundLocalListener::bind_after_recovery(
            recovery_ready,
            &config,
            &singleton,
            core.clone(),
        )
        .await
        .expect("bind stable Runtime UDS");
        let socket = listener.local_ready_permit().socket_path().to_path_buf();
        let remote_start = listener
            .take_remote_start_permit()
            .expect("stable listener yields remote start permit");
        let (stop_tx, stop_rx) = oneshot::channel();
        let manager_for_shutdown = manager.clone();
        let listener_task = tokio::spawn(async move {
            listener
                .serve_until(async move {
                    let _ = stop_rx.await;
                    manager_for_shutdown.shutdown().await;
                    Ok(())
                })
                .await
        });
        manager.arm(remote_start).await.expect("arm RemoteManager");

        let local_home = root_path.join("runtime-local-client-home");
        fs::create_dir(&local_home).expect("create isolated Runtime local-client home");
        fs::set_permissions(&local_home, fs::Permissions::from_mode(0o700))
            .expect("secure isolated Runtime local-client home");
        let local_installation_store = CliInstallationStore::injected_for_test(local_home);
        let local_installation_id = local_installation_store
            .load_or_create()
            .expect("create stable local Runtime installation identity");
        let local = RuntimeUnixClient::connect_injected_with_installation(
            InjectedEndpoint::for_test(socket.clone()),
            local_installation_id,
        )
        .await
        .expect("connect real same-UID Runtime UDS");
        let enrollment = unary(
            &local,
            RuntimeRequest::MachineEnroll(MachineEnrollRequest {
                bundle,
                scope: LocalOnlyAdministration::LocalOnly,
            }),
        )
        .await;
        assert!(matches!(enrollment, RuntimeReply::MachineRemoteStatus(_)));

        let RuntimeReply::PairInvite(invite_reply) = unary(
            &local,
            RuntimeRequest::CreatePairInvite(CreatePairInviteRequest {
                display_name: "P4.7 automatic machine".to_owned(),
                idempotency_key: IdempotencyKey::new("p47-real-machine-invite"),
                scope: LocalOnlyAdministration::LocalOnly,
            }),
        )
        .await
        else {
            panic!("create PairInvite returned unrelated Runtime reply");
        };
        let pairing_id = invite_reply.pairing_id;
        let invite = *invite_reply.invite;
        let confirmed_root = invite.machine_root_fingerprint_display();
        let client_keys = Arc::new(ForkableRemoteKeyStore::new());
        let client_state = root_path.join("persistent-remote-client");
        let client_home = root_path.join("persistent-remote-home");
        fs::create_dir(&client_home).expect("create isolated persistent remote home");
        fs::set_permissions(&client_home, fs::Permissions::from_mode(0o700))
            .expect("secure isolated persistent remote home");
        let composition = PersistentRemoteComposition::injected_for_test(
            &remote_cli_expectation(),
            &AcceptedRemoteCliSignatureVerifier,
            CliInstallationStore::injected_for_test(client_home.clone()),
            client_keys.clone(),
            client_state.clone(),
        )
        .expect("construct injected production persistent remote composition");
        let authorization = mvp_authorization().expect("construct full P4 authorization");
        let mut pair_rng = ChaCha20Rng::from_seed([0x47; 32]);
        let prepared = PendingPairingCoordinator::new(
            client_keys.as_ref(),
            composition.installation_id().as_uuid(),
        )
        .prepare(&invite, &authorization, unix_now_ms(), &mut pair_rng)
        .expect("freeze the exact durable PairRequest before production pairing");
        let expected_request_hash = prepared.request_hash();
        let expected_device_fingerprint =
            agentdeck_crypto::sha256(&prepared.device_sign_public_key());
        let confirmed = confirm_machine_root_fingerprint(invite, &confirmed_root)
            .expect("confirm the exact full MachineRoot fingerprint");
        let pair = pair_production(&composition, confirmed, &mut pair_rng);
        let approve = async {
            loop {
                let RuntimeReply::PendingPairings { pairings } = unary(
                    &local,
                    RuntimeRequest::ListPendingPairings {
                        scope: LocalOnlyAdministration::LocalOnly,
                    },
                )
                .await
                else {
                    panic!("pending readback returned unrelated Runtime reply");
                };
                if let Some(pending) = pairings.into_iter().find(|p| p.pairing_id == pairing_id) {
                    let RuntimeReply::PendingPairings { pairings: second } = unary(
                        &local,
                        RuntimeRequest::ListPendingPairings {
                            scope: LocalOnlyAdministration::LocalOnly,
                        },
                    )
                    .await
                    else {
                        panic!("second pending readback returned unrelated Runtime reply");
                    };
                    let readback = second
                        .into_iter()
                        .find(|p| p.pairing_id == pairing_id)
                        .expect("pending remains visible before local decision");
                    assert_eq!(readback.request_hash, pending.request_hash);
                    assert_eq!(pending.request_hash, expected_request_hash);
                    assert_eq!(
                        readback.device_sign_fingerprint,
                        pending.device_sign_fingerprint
                    );
                    assert_eq!(pending.device_sign_fingerprint, expected_device_fingerprint);
                    assert_eq!(
                        relay_device_grant_counts(&relay_db),
                        (0, 0),
                        "local confirm 前 Relay grant count 必须为零"
                    );
                    let confirmed = unary(
                        &local,
                        RuntimeRequest::ConfirmPairing {
                            pairing_id,
                            scope: LocalOnlyAdministration::LocalOnly,
                        },
                    )
                    .await;
                    assert!(
                        matches!(
                            &confirmed,
                            RuntimeReply::Pairing(
                                agentdeck_protocol::runtime::PairingReceipt::Confirmed { .. }
                            )
                        ),
                        "local ConfirmPairing returned {confirmed:?}"
                    );
                    return;
                }
                tokio::time::sleep(Duration::from_millis(10)).await;
            }
        };
        let (paired_outcome, ()) = match tokio::time::timeout(PAIRING_TIMEOUT, async {
            tokio::join!(pair, approve)
        })
        .await
        {
            Ok(outcome) => outcome,
            Err(error) => panic!(
                "durable pairing/local approval overall deadline: {error:?}; {}; {}",
                runtime_remote_diagnostic(&config.paths().runtime_db),
                relay_stream_diagnostic(&relay_db)
            ),
        };
        let paired_outcome = paired_outcome.expect("durable real Relay pairing completes");
        assert!(paired_outcome.route_accepted_observed());
        assert_eq!(relay_device_grant_counts(&relay_db), (1, 1));

        let identity = PairedMachineIdentity::new(
            paired_outcome.machine_root_fingerprint(),
            paired_outcome.machine_route(),
        );
        let selector = persistent_selector(identity);
        let paired_store = composition
            .recovered_paired_machine_store()
            .expect("recover production persistent paired-machine store");
        let paired_inventory = paired_store.list().expect("list recovered paired machine");
        assert_eq!(paired_inventory.len(), 1);
        assert_eq!(paired_inventory[0].identity(), identity);
        assert_persistent_machine_inventory(&composition, identity, paired_outcome.device_route());
        // first-device zero-cut Add 必须只凭 exact DeviceSign PairResponseReceived proof
        // 收口。到 Active 前故意不构造 RemoteRuntime，确保没有普通 KeyUpdateAck 能掩盖
        // pairing receipt → transition owner 的唤醒接线缺口。
        let initial_add_ready = tokio::time::timeout(IO_TIMEOUT, async {
            loop {
                let reply = unary(
                    &local,
                    RuntimeRequest::MachineRemoteStatus {
                        scope: LocalOnlyAdministration::LocalOnly,
                    },
                )
                .await;
                let RuntimeReply::MachineRemoteStatus(status) = reply else {
                    panic!("transition status returned unrelated Runtime reply");
                };
                match status.lifecycle {
                    MachineRemoteLifecycle::Active => break,
                    MachineRemoteLifecycle::Blocked
                        if status.failure_code.as_ref().map(|code| code.as_str())
                            == Some("daemon.remote.transition.business_fenced") =>
                    {
                        tokio::time::sleep(Duration::from_millis(10)).await;
                    }
                    other => panic!("initial Add transition entered unexpected status {other:?}"),
                }
            }
        })
        .await;
        if initial_add_ready.is_err() {
            let status = unary(
                &local,
                RuntimeRequest::MachineRemoteStatus {
                    scope: LocalOnlyAdministration::LocalOnly,
                },
            )
            .await;
            panic!(
                "initial Add transition business-ready deadline; status={status:?}; {}",
                runtime_remote_diagnostic(&config.paths().runtime_db)
            );
        }
        let post_transition_diagnostic = runtime_remote_diagnostic(&config.paths().runtime_db);
        assert!(
            post_transition_diagnostic
                .contains("transitions=Add:Complete:recipients=1:streams=0:updates=1")
        );
        assert!(post_transition_diagnostic.contains("updates=Acked:r00000000000000000001:acks=0"));
        let mut activation_runtime = connected_runtime(&paired_store, identity).await;
        let mut activation_rng = ChaCha20Rng::from_seed([0x49; 32]);
        let initial_catalog = tokio::time::timeout(
            IO_TIMEOUT,
            activation_runtime.catalog_page(None, &mut activation_rng),
        )
        .await;
        let initial_catalog = match initial_catalog {
            Ok(Ok(catalog)) => catalog,
            Ok(Err(error)) => panic!("initial authenticated Catalog page failed: {error:?}"),
            Err(_) => {
                let status = unary(
                    &local,
                    RuntimeRequest::MachineRemoteStatus {
                        scope: LocalOnlyAdministration::LocalOnly,
                    },
                )
                .await;
                panic!(
                    "initial Catalog page deadline; status={status:?}; {}",
                    runtime_remote_diagnostic(&config.paths().runtime_db)
                );
            }
        };
        assert!(
            initial_catalog.snapshot().entries().is_empty(),
            "pairing 前未创建 conversation，初始 Catalog page 必须为空"
        );
        let mut catalog_reducer = CatalogReducer::new();
        let catalog_bootstrap = tokio::time::timeout(
            IO_TIMEOUT,
            activation_runtime.subscribe(
                RuntimeInnerCursor::Catalog {
                    cursor: StreamCursor::BeforeFirst,
                },
                &mut catalog_reducer,
                &mut activation_rng,
            ),
        )
        .await;
        let catalog_bootstrap = match catalog_bootstrap {
            Ok(Ok(bootstrap)) => bootstrap,
            Ok(Err(error)) => {
                panic!("initial authenticated Catalog subscription failed: {error:?}")
            }
            Err(_) => {
                let status = unary(
                    &local,
                    RuntimeRequest::MachineRemoteStatus {
                        scope: LocalOnlyAdministration::LocalOnly,
                    },
                )
                .await;
                panic!(
                    "initial Catalog subscription deadline; status={status:?}; {}",
                    runtime_remote_diagnostic(&config.paths().runtime_db)
                );
            }
        };
        assert_eq!(
            catalog_bootstrap.sync_complete().inner_cursor,
            catalog_reducer.cursor,
            "Catalog subscription must install its authenticated bootstrap before activation"
        );
        assert!(
            catalog_reducer.saw_empty_snapshot,
            "pairing 前未创建 conversation，初始 Catalog bootstrap 必须为空"
        );
        await_replay_complete(&mut activation_runtime, &mut catalog_reducer).await;
        let codex = create_configured_conversation(
            &local,
            &mut activation_runtime,
            &mut catalog_reducer,
            AgentKind::Codex,
            &root_path,
            &config.paths().runtime_db,
            &relay_db,
        )
        .await;
        let claude_code = create_configured_conversation(
            &local,
            &mut activation_runtime,
            &mut catalog_reducer,
            AgentKind::ClaudeCode,
            &root_path,
            &config.paths().runtime_db,
            &relay_db,
        )
        .await;
        RemoteRuntime::shutdown(*activation_runtime).await;

        Box::pin(assert_persistent_conversations(
            &composition,
            selector,
            &codex,
            &claude_code,
        ))
        .await;

        let agent_exercise = AgentExerciseContext {
            paired: &paired_store,
            identity,
            local: &local,
            runtime_db: &config.paths().runtime_db,
            relay_db: &relay_db,
            local_socket: &socket,
            local_installation_id,
        };
        let codex_evidence = Box::pin(exercise_agent(
            &agent_exercise,
            AgentKind::Codex,
            codex.clone(),
            0x51,
        ))
        .await;
        Box::pin(smoke_persistent_mutations(
            &composition,
            selector,
            codex_evidence,
            &config.paths().runtime_db,
            0x71,
        ))
        .await;

        let claude_code_evidence = Box::pin(exercise_agent(
            &agent_exercise,
            AgentKind::ClaudeCode,
            claude_code.clone(),
            0x52,
        ))
        .await;
        Box::pin(smoke_persistent_mutations(
            &composition,
            selector,
            claude_code_evidence,
            &config.paths().runtime_db,
            0x72,
        ))
        .await;

        Box::pin(smoke_persistent_conversation_watch(
            &composition,
            selector,
            codex.clone(),
        ))
        .await;

        let revoke_verification = RevokeVerificationContext {
            composition: &composition,
            client_keys: client_keys.as_ref(),
            client_state: &client_state,
            client_home: &client_home,
            root: &root_path,
            identity,
            runtime_db: &config.paths().runtime_db,
            relay_db: &relay_db,
        };
        Box::pin(verify_revoke_terminates_stale_credentials(
            &revoke_verification,
            codex,
        ))
        .await;

        local.close().await.expect("close local Runtime client");
        stop_tx.send(()).expect("signal daemon listener shutdown");
        listener_task
            .await
            .expect("join daemon listener task")
            .expect("stop daemon listener");
        core.shutdown().await.expect("shutdown RuntimeCore");
        relay.shutdown().await.expect("shutdown Relay server");
    })
    .await;
}

/// P5.7 Swift Process 专用的交互式 component host。
///
/// 该测试保持 ignored，且还要求显式环境门禁，避免普通 `cargo test --ignored`
/// 意外等待 stdin。stdout 只输出无 secret NDJSON；完整 bearer invite 始终只存在于
/// ready 记录指向的 0600 临时文件。
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
#[ignore = "interactive P5.7 Swift SessionSource host"]
async fn p57_real_dual_scope_ndjson_host() {
    assert_eq!(
        env::var(P57_HOST_ENABLE_ENV).as_deref(),
        Ok("1"),
        "interactive P5.7 host requires {P57_HOST_ENABLE_ENV}=1"
    );

    let host_parent = p57_host_parent();
    let host_scenario = p57_host_scenario();
    let root = TempDirBuilder::new()
        .prefix("ad-p57-host-")
        .tempdir_in(host_parent)
        .expect("P5.7 host temp root");
    let root_path = fs::canonicalize(root.path()).expect("canonicalize P5.7 host temp root");
    let relay_db = root_path.join("relay-store/relay.db");
    let (relay, bundle) = start_relay(&root_path)
        .await
        .expect("start real P5.7 host Relay Direct TLS server");
    let config = stable_daemon_config(&root_path);
    let daemon_keys = Arc::new(MemoryKeyStore::new());
    let local_home = root_path.join("runtime-host-client-home");
    let mut daemon_generation = 1_u64;
    let mut daemon =
        Some(start_p57_daemon_instance(&config, daemon_keys.clone(), &local_home).await);
    let initial_daemon = daemon.as_ref().expect("initial P5.7 daemon is present");
    let enrollment = unary(
        &initial_daemon.local,
        RuntimeRequest::MachineEnroll(MachineEnrollRequest {
            bundle,
            scope: LocalOnlyAdministration::LocalOnly,
        }),
    )
    .await;
    assert!(matches!(enrollment, RuntimeReply::MachineRemoteStatus(_)));
    let r43_conversation = match host_scenario {
        Some(P57_HOST_R43_SCENARIO | P57_HOST_R44_SCENARIO) => Some(
            create_p57_conversation(
                &initial_daemon.local,
                &root_path,
                "r43-ui",
                P57_HOST_R43_CONVERSATION_TITLE,
            )
            .await,
        ),
        None => None,
        Some(_) => unreachable!("P5.7 host scenario was validated above"),
    };
    let RuntimeReply::PairInvite(invite_reply) = unary(
        &initial_daemon.local,
        RuntimeRequest::CreatePairInvite(CreatePairInviteRequest {
            display_name: "P5.7 Swift dual-scope host".to_owned(),
            idempotency_key: IdempotencyKey::new("p57-real-dual-scope-invite"),
            scope: LocalOnlyAdministration::LocalOnly,
        }),
    )
    .await
    else {
        panic!("P5.7 host create PairInvite returned unrelated Runtime reply");
    };
    let invite_path = write_p57_host_invite(&root_path, invite_reply.invite.as_ref());
    let relay_wss_origin = invite_reply.invite.wss_url.clone();
    let relay_spki_pin_base64 = STANDARD.encode(invite_reply.invite.current_spki_pin);
    let invite_file_mode = fs::symlink_metadata(&invite_path)
        .expect("read P5.7 host invite mode")
        .permissions()
        .mode()
        & 0o777;
    let home_path = root_path.join("home");
    let initial_evidence = p57_host_evidence(
        initial_daemon.core.as_ref(),
        &initial_daemon.local,
        &initial_daemon.socket,
        &config.paths().runtime_db,
        &relay_db,
        daemon_generation,
    )
    .await;
    assert!(initial_evidence.socket_is_unix);
    assert_eq!(initial_evidence.socket_mode, 0o600);
    assert_eq!(initial_evidence.pending_pairing_count, 0);
    assert_eq!(initial_evidence.relay_grant_total, 0);
    assert_eq!(initial_evidence.relay_grant_active, 0);
    emit_p57_host_record(&P57HostReady {
        kind: "ready",
        protocol: P57_HOST_PROTOCOL,
        root_path: root_path.to_string_lossy().into_owned(),
        home_path: home_path.to_string_lossy().into_owned(),
        socket_path: initial_daemon.socket.to_string_lossy().into_owned(),
        invite_path: invite_path.to_string_lossy().into_owned(),
        runtime_database_path: config.paths().runtime_db.to_string_lossy().into_owned(),
        relay_database_path: relay_db.to_string_lossy().into_owned(),
        relay_wss_origin,
        relay_spki_pin_base64,
        pid: std::process::id(),
        invite_file_mode,
        daemon_generation,
        scenario: host_scenario,
        conversation_id: r43_conversation
            .as_ref()
            .map(|conversation_id| conversation_id.as_str().to_owned()),
        conversation_title: r43_conversation
            .as_ref()
            .map(|_| P57_HOST_R43_CONVERSATION_TITLE),
    });

    let mut shutdown_request_id = None;
    let mut lines = BufReader::new(tokio::io::stdin()).lines();
    loop {
        let line = match lines.next_line().await {
            Ok(Some(line)) => line,
            Ok(None) => break,
            Err(_) => {
                emit_p57_host_record(&P57HostError {
                    kind: "error",
                    protocol: P57_HOST_PROTOCOL,
                    request_id: None,
                    code: "host.command.read_failed",
                });
                break;
            }
        };
        if line.len() > P57_HOST_MAX_COMMAND_BYTES {
            emit_p57_host_record(&P57HostError {
                kind: "error",
                protocol: P57_HOST_PROTOCOL,
                request_id: None,
                code: "host.command.too_large",
            });
            continue;
        }
        let command = match serde_json::from_str::<P57HostCommand>(&line) {
            Ok(command) => command,
            Err(_) => {
                emit_p57_host_record(&P57HostError {
                    kind: "error",
                    protocol: P57_HOST_PROTOCOL,
                    request_id: None,
                    code: "host.command.invalid",
                });
                continue;
            }
        };
        let request_id = match &command {
            P57HostCommand::Status { request_id }
            | P57HostCommand::WaitFor { request_id, .. }
            | P57HostCommand::ApprovePendingPairing { request_id }
            | P57HostCommand::RestartDaemon { request_id, .. }
            | P57HostCommand::Shutdown { request_id } => request_id,
        };
        if request_id.is_empty()
            || request_id.len() > 64
            || !request_id
                .bytes()
                .all(|byte| byte.is_ascii_alphanumeric() || b"._-".contains(&byte))
        {
            emit_p57_host_record(&P57HostError {
                kind: "error",
                protocol: P57_HOST_PROTOCOL,
                request_id: None,
                code: "host.command.request_id_invalid",
            });
            continue;
        }

        match command {
            P57HostCommand::Status { request_id } => {
                let current = daemon.as_ref().expect("P5.7 daemon is present for status");
                let evidence = p57_host_evidence(
                    current.core.as_ref(),
                    &current.local,
                    &current.socket,
                    &config.paths().runtime_db,
                    &relay_db,
                    daemon_generation,
                )
                .await;
                emit_p57_host_record(&P57HostStatus {
                    kind: "status",
                    protocol: P57_HOST_PROTOCOL,
                    request_id: &request_id,
                    evidence,
                });
            }
            P57HostCommand::WaitFor {
                request_id,
                condition,
                timeout_ms,
            } => {
                if timeout_ms == 0 || timeout_ms > P57_HOST_MAX_WAIT_MS {
                    emit_p57_host_record(&P57HostError {
                        kind: "error",
                        protocol: P57_HOST_PROTOCOL,
                        request_id: Some(&request_id),
                        code: "host.command.timeout_invalid",
                    });
                    continue;
                }
                let current = daemon.as_ref().expect("P5.7 daemon is present for wait");
                let (satisfied, evidence) = wait_for_p57_host_evidence(
                    current.core.as_ref(),
                    &current.local,
                    &current.socket,
                    &config.paths().runtime_db,
                    &relay_db,
                    condition,
                    timeout_ms,
                    daemon_generation,
                )
                .await;
                emit_p57_host_record(&P57HostWait {
                    kind: "waitFor",
                    protocol: P57_HOST_PROTOCOL,
                    request_id: &request_id,
                    condition,
                    satisfied,
                    evidence,
                });
            }
            P57HostCommand::ApprovePendingPairing { request_id } => {
                let current = daemon
                    .as_ref()
                    .expect("P5.7 daemon is present for pairing approval");
                let pending = unary(
                    &current.local,
                    RuntimeRequest::ListPendingPairings {
                        scope: LocalOnlyAdministration::LocalOnly,
                    },
                )
                .await;
                let RuntimeReply::PendingPairings { mut pairings } = pending else {
                    emit_p57_host_record(&P57HostError {
                        kind: "error",
                        protocol: P57_HOST_PROTOCOL,
                        request_id: Some(&request_id),
                        code: "host.approve.pending_read_failed",
                    });
                    continue;
                };
                if pairings.len() != 1 {
                    emit_p57_host_record(&P57HostError {
                        kind: "error",
                        protocol: P57_HOST_PROTOCOL,
                        request_id: Some(&request_id),
                        code: "host.approve.pending_count_invalid",
                    });
                    continue;
                }
                let pairing_id = pairings.remove(0).pairing_id;
                let confirmed = unary(
                    &current.local,
                    RuntimeRequest::ConfirmPairing {
                        pairing_id: pairing_id.clone(),
                        scope: LocalOnlyAdministration::LocalOnly,
                    },
                )
                .await;
                if !matches!(
                    confirmed,
                    RuntimeReply::Pairing(
                        agentdeck_protocol::runtime::PairingReceipt::Confirmed {
                            pairing_id: confirmed_id,
                        }
                    ) if confirmed_id == pairing_id
                ) {
                    emit_p57_host_record(&P57HostError {
                        kind: "error",
                        protocol: P57_HOST_PROTOCOL,
                        request_id: Some(&request_id),
                        code: "host.approve.confirm_failed",
                    });
                    continue;
                }
                let evidence = p57_host_evidence(
                    current.core.as_ref(),
                    &current.local,
                    &current.socket,
                    &config.paths().runtime_db,
                    &relay_db,
                    daemon_generation,
                )
                .await;
                emit_p57_host_record(&P57HostPairingApproved {
                    kind: "approvePendingPairing",
                    protocol: P57_HOST_PROTOCOL,
                    request_id: &request_id,
                    evidence,
                });
            }
            P57HostCommand::RestartDaemon {
                request_id,
                marker_before_readiness,
            } => {
                if host_scenario != Some(P57_HOST_R44_SCENARIO) || daemon_generation != 1 {
                    emit_p57_host_record(&P57HostError {
                        kind: "error",
                        protocol: P57_HOST_PROTOCOL,
                        request_id: Some(&request_id),
                        code: "host.restart.scenario_invalid",
                    });
                    continue;
                }
                let previous = daemon
                    .take()
                    .expect("P5.7 daemon is present before restart");
                let expected_socket = previous.socket.clone();
                previous.shutdown().await;
                assert!(
                    !expected_socket.exists(),
                    "old Runtime socket remains after restart cut"
                );

                daemon_generation = daemon_generation
                    .checked_add(1)
                    .expect("P5.7 daemon generation remains bounded");
                let restarted =
                    start_p57_daemon_instance(&config, daemon_keys.clone(), &local_home).await;
                assert_eq!(
                    restarted.socket, expected_socket,
                    "restarted daemon must recover the exact stable Runtime endpoint"
                );
                daemon = Some(restarted);
                let current = daemon.as_ref().expect("restarted P5.7 daemon is present");
                let recovered_conversation_id = r43_conversation
                    .as_ref()
                    .expect("R4.4 lifecycle keeps the original conversation identity")
                    .clone();
                if marker_before_readiness {
                    let metadata_entry_revision =
                        apply_p57_host_restart_marker(&current.local, &recovered_conversation_id)
                            .await;
                    let (base_satisfied, evidence) = wait_for_p57_host_evidence(
                        current.core.as_ref(),
                        &current.local,
                        &current.socket,
                        &config.paths().runtime_db,
                        &relay_db,
                        P57HostWaitCondition::RestartBaseReady,
                        60_000,
                        daemon_generation,
                    )
                    .await;
                    if !base_satisfied {
                        emit_p57_host_record(&P57HostReadinessError {
                            kind: "error",
                            protocol: P57_HOST_PROTOCOL,
                            request_id: Some(&request_id),
                            code: "host.restart.base_not_ready",
                            evidence,
                        });
                        continue;
                    }
                    let restart_evidence = evidence.clone();
                    emit_p57_host_record(&P57HostDaemonRestartReady {
                        kind: "restartReady",
                        protocol: P57_HOST_PROTOCOL,
                        request_id: &request_id,
                        metadata_entry_revision,
                        evidence,
                    });
                    // Web durable recovery 会在两条 subscription active 后立即 self-revoke；
                    // host 若轮询 transient live-count，可能永远错过该窗口。这里冻结的是
                    // daemon restart + marker COMMIT + active grant 的 base linearization evidence；
                    // 两条 subscription 与 backfill 由浏览器的 authenticated evidence 断言，
                    // revoke 由后续独立 `Revoked` readback 断言。
                    emit_p57_host_record(&P57HostDaemonRestarted {
                        kind: "restartDaemon",
                        protocol: P57_HOST_PROTOCOL,
                        request_id: &request_id,
                        recovered_conversation_id: recovered_conversation_id.as_str().to_owned(),
                        restart_marker_title: P57_HOST_R44_RESTART_MARKER_TITLE,
                        metadata_entry_revision,
                        evidence: restart_evidence,
                    });
                    continue;
                }
                let (satisfied, pre_marker_evidence) = wait_for_p57_host_evidence(
                    current.core.as_ref(),
                    &current.local,
                    &current.socket,
                    &config.paths().runtime_db,
                    &relay_db,
                    P57HostWaitCondition::BusinessReady,
                    60_000,
                    daemon_generation,
                )
                .await;
                if !satisfied {
                    emit_p57_host_record(&P57HostReadinessError {
                        kind: "error",
                        protocol: P57_HOST_PROTOCOL,
                        request_id: Some(&request_id),
                        code: "host.restart.business_not_ready",
                        evidence: pre_marker_evidence,
                    });
                    continue;
                }
                let metadata_entry_revision =
                    apply_p57_host_restart_marker(&current.local, &recovered_conversation_id).await;
                let evidence = pre_marker_evidence;
                emit_p57_host_record(&P57HostDaemonRestarted {
                    kind: "restartDaemon",
                    protocol: P57_HOST_PROTOCOL,
                    request_id: &request_id,
                    recovered_conversation_id: recovered_conversation_id.as_str().to_owned(),
                    restart_marker_title: P57_HOST_R44_RESTART_MARKER_TITLE,
                    metadata_entry_revision,
                    evidence,
                });
            }
            P57HostCommand::Shutdown { request_id } => {
                shutdown_request_id = Some(request_id);
                break;
            }
        }
    }

    let invite_removed = match fs::remove_file(&invite_path) {
        Ok(()) => true,
        Err(error) if error.kind() == io::ErrorKind::NotFound => true,
        Err(error) => panic!("remove P5.7 host invite file: {error}"),
    };
    let final_daemon = daemon.take().expect("P5.7 daemon is present for shutdown");
    let final_socket = final_daemon.socket.clone();
    final_daemon.shutdown().await;
    relay
        .shutdown()
        .await
        .expect("shutdown P5.7 host Relay server");
    emit_p57_host_record(&P57HostStopped {
        kind: "stopped",
        protocol: P57_HOST_PROTOCOL,
        request_id: shutdown_request_id.as_deref(),
        invite_removed,
        socket_exists: final_socket.exists(),
    });
}
