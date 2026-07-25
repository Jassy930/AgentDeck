use std::fs;
use std::path::PathBuf;
use std::sync::Arc;
use std::sync::atomic::{AtomicU64, AtomicUsize, Ordering};

use super::*;
use crate::runtime::events::{CommandStreamEffects, SnapshotBuildPinCleanup};
use crate::runtime::store::RuntimeStoreConfig;
use crate::runtime::store::identity::{RuntimeIdError, RuntimeIdSource};
use crate::security::{MemoryKeyStore, load_or_create_storage_kek};

static NEXT_ROOT: AtomicU64 = AtomicU64::new(1);

struct FailOnceAfterRotation(std::sync::atomic::AtomicBool);

impl crate::runtime::model::RuntimeStoreFaultInjector for FailOnceAfterRotation {
    fn before_operation(&self, operation: RuntimeStoreOperation) -> Result<(), RuntimeStoreError> {
        if operation == RuntimeStoreOperation::RotatePublicationStreamAfterCommit
            && !self.0.swap(true, Ordering::SeqCst)
        {
            Err(RuntimeStoreError::InvalidConfig(
                "injected post-rotation commit fault",
            ))
        } else {
            Ok(())
        }
    }
}

struct FailOnceCreateAt {
    operation: RuntimeStoreOperation,
    armed: std::sync::atomic::AtomicBool,
}

impl FailOnceCreateAt {
    fn new(operation: RuntimeStoreOperation) -> Self {
        Self {
            operation,
            armed: std::sync::atomic::AtomicBool::new(true),
        }
    }
}

impl crate::runtime::model::RuntimeStoreFaultInjector for FailOnceCreateAt {
    fn before_operation(&self, operation: RuntimeStoreOperation) -> Result<(), RuntimeStoreError> {
        if operation == self.operation && self.armed.swap(false, Ordering::SeqCst) {
            Err(RuntimeStoreError::InvalidConfig(
                "injected conversation publication fault",
            ))
        } else {
            Ok(())
        }
    }
}

struct CountingIdSource {
    next: u8,
    calls: Arc<AtomicUsize>,
}

impl RuntimeIdSource for CountingIdSource {
    fn next_id(&mut self, kind: RuntimeIdKind) -> Result<RuntimeId, RuntimeIdError> {
        self.calls.fetch_add(1, Ordering::SeqCst);
        let bytes = [self.next; 16];
        self.next = self.next.wrapping_add(1).max(1);
        RuntimeId::from_bytes(kind, bytes)
    }
}

fn open_publication_test_store(
    label: &str,
) -> (
    PathBuf,
    RuntimeStoreConfig,
    super::super::sqlite::RuntimeSqlite,
) {
    let root = std::env::temp_dir().join(format!(
        "agentdeck-publication-{label}-{}-{}",
        std::process::id(),
        NEXT_ROOT.fetch_add(1, Ordering::Relaxed)
    ));
    let _ = fs::remove_dir_all(&root);
    fs::create_dir(&root).expect("create publication test root");
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        fs::set_permissions(&root, fs::Permissions::from_mode(0o700))
            .expect("secure publication test root");
    }
    let keys = MemoryKeyStore::new();
    let kek = load_or_create_storage_kek(&keys, &root.join("key-state.db"))
        .expect("create publication test KEK");
    let config = RuntimeStoreConfig::new(root.join("runtime.db"))
        .with_capacity_probe(super::super::pairing_tests::GenerousCapacity);
    let state = super::super::sqlite::open(&config, kek).expect("open publication test store");
    (root, config, state)
}

fn open_reopenable_publication_test_store(
    label: &str,
) -> (
    PathBuf,
    MemoryKeyStore,
    RuntimeStoreConfig,
    super::super::sqlite::RuntimeSqlite,
) {
    let root = std::env::temp_dir().join(format!(
        "agentdeck-publication-{label}-{}-{}",
        std::process::id(),
        NEXT_ROOT.fetch_add(1, Ordering::Relaxed)
    ));
    let _ = fs::remove_dir_all(&root);
    fs::create_dir(&root).expect("create reopenable publication test root");
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        fs::set_permissions(&root, fs::Permissions::from_mode(0o700))
            .expect("secure reopenable publication test root");
    }
    let keys = MemoryKeyStore::new();
    let kek = load_or_create_storage_kek(&keys, &root.join("key-state.db"))
        .expect("create reopenable publication test KEK");
    let config = RuntimeStoreConfig::new(root.join("runtime.db"))
        .with_capacity_probe(super::super::pairing_tests::GenerousCapacity);
    let state =
        super::super::sqlite::open(&config, kek).expect("open reopenable publication test store");
    (root, keys, config, state)
}

fn authenticate_catalog_directory(
    state: &super::super::sqlite::RuntimeSqlite,
) -> Result<Option<PublicationStreamRecord>, RuntimeStoreError> {
    let transaction = Transaction::new_unchecked(&state.connection, TransactionBehavior::Deferred)?;
    let ledger = super::super::sqlite::load_runtime_ledger(
        &transaction,
        &state.key_bundle,
        state.database_id,
    )?;
    let result = authenticate_directory(
        &transaction,
        &state.key_bundle,
        &ledger,
        PublicationScope::Catalog,
    );
    drop(transaction);
    result
}

fn authenticate_conversation_directory(
    state: &super::super::sqlite::RuntimeSqlite,
    conversation_id: RuntimeId,
) -> Result<Option<PublicationStreamRecord>, RuntimeStoreError> {
    let transaction = Transaction::new_unchecked(&state.connection, TransactionBehavior::Deferred)?;
    let ledger = super::super::sqlite::load_runtime_ledger(
        &transaction,
        &state.key_bundle,
        state.database_id,
    )?;
    let result = authenticate_directory(
        &transaction,
        &state.key_bundle,
        &ledger,
        PublicationScope::Conversation(conversation_id),
    );
    drop(transaction);
    result
}

fn conversation_input(seed: u8) -> crate::runtime::model::NewConversation {
    let conversation_id =
        RuntimeId::from_bytes(RuntimeIdKind::Conversation, [seed; 16]).expect("conversation id");
    crate::runtime::model::NewConversation {
        conversation_id,
        adapter_state_key: RuntimeId::from_bytes(
            RuntimeIdKind::AdapterState,
            [seed.wrapping_add(0x40); 16],
        )
        .expect("adapter state key"),
        descriptor: crate::runtime::model::ConversationDescriptor {
            agent_kind: agentdeck_protocol::AgentKind::Codex,
            title: Some(format!("publication-catalog-{seed}")),
            cwd: PathBuf::from(format!("/tmp/publication-catalog-{seed}")),
        },
    }
}

fn create_catalog_entry(
    state: &mut super::super::sqlite::RuntimeSqlite,
    config: &RuntimeStoreConfig,
    seed: u8,
) -> RuntimeId {
    let input = conversation_input(seed);
    let conversation_id = input.conversation_id;
    let descriptor = super::super::journal::canonical_conversation_descriptor(&input.descriptor)
        .expect("canonical conversation descriptor");
    let mut effects = crate::runtime::events::CommandStreamEffects::default();
    super::super::journal::create_conversation(state, config, input, descriptor, &mut effects)
        .expect("create catalog entry");
    conversation_id
}

#[test]
fn managed_conversation_and_publication_mapping_share_one_commit_boundary() {
    let (root, base_config, mut state) = open_publication_test_store("conversation-mapping-atomic");
    let input = conversation_input(0x31);
    let descriptor = super::super::journal::canonical_conversation_descriptor(&input.descriptor)
        .expect("canonical conversation descriptor");
    let config = base_config.with_fault_injector(Arc::new(FailOnceCreateAt::new(
        RuntimeStoreOperation::CreateConversationBeforeCommit,
    )));
    let mut effects = crate::runtime::events::CommandStreamEffects::default();

    assert!(matches!(
        super::super::journal::create_conversation(
            &mut state,
            &config,
            input.clone(),
            descriptor,
            &mut effects,
        ),
        Err(RuntimeStoreError::InvalidConfig(
            "injected conversation publication fault"
        ))
    ));
    let conversation_count: i64 = state
        .connection
        .query_row(
            "SELECT COUNT(*) FROM conversations WHERE conversation_id = ?1",
            [&input.conversation_id.as_bytes()[..]],
            |row| row.get(0),
        )
        .expect("count rolled-back conversation");
    assert_eq!(conversation_count, 0);
    assert_eq!(
        authenticate_conversation_directory(&state, input.conversation_id)
            .expect("authenticate rolled-back publication directory"),
        None
    );

    drop(state);
    let _ = fs::remove_dir_all(root);
}

#[test]
fn conversation_publication_mapping_replays_exactly_after_commit_fault_and_restart() {
    let (root, keys, base_config, mut state) =
        open_reopenable_publication_test_store("conversation-mapping-replay");
    let calls = Arc::new(AtomicUsize::new(0));
    let config = base_config
        .with_id_source(CountingIdSource {
            next: 0x61,
            calls: Arc::clone(&calls),
        })
        .with_fault_injector(Arc::new(FailOnceCreateAt::new(
            RuntimeStoreOperation::CreateConversationAfterCommit,
        )));
    let input = conversation_input(0x32);
    let descriptor = super::super::journal::canonical_conversation_descriptor(&input.descriptor)
        .expect("canonical conversation descriptor");
    let mut effects = crate::runtime::events::CommandStreamEffects::default();

    assert!(matches!(
        super::super::journal::create_conversation(
            &mut state,
            &config,
            input.clone(),
            descriptor,
            &mut effects,
        ),
        Err(RuntimeStoreError::CommitOutcomeUnknown {
            operation: RuntimeCommitOperation::CreateConversation,
        })
    ));
    let committed = authenticate_conversation_directory(&state, input.conversation_id)
        .expect("authenticate committed publication mapping")
        .expect("committed publication mapping");
    assert_eq!(
        committed.scope,
        PublicationScope::Conversation(input.conversation_id)
    );
    assert_ne!(committed.publication_stream_id, [0; 16]);
    assert_ne!(committed.stream_route, [0; 16]);
    assert_ne!(committed.generation, [0; 16]);
    let (global_rows, transition_rows): (i64, i64) = state
        .connection
        .query_row(
            "SELECT
                 (SELECT COUNT(*) FROM remote_key_directory),
                 (SELECT COUNT(*) FROM remote_key_transitions)",
            [],
            |row| Ok((row.get(0)?, row.get(1)?)),
        )
        .expect("count unpaired key state");
    assert_eq!(
        global_rows, 0,
        "unpaired create must not prebuild global keys"
    );
    assert_eq!(
        transition_rows, 0,
        "unpaired create must not forge an old_epoch=0 activation barrier"
    );
    let calls_after_commit = calls.load(Ordering::SeqCst);
    assert_eq!(
        calls_after_commit, 3,
        "mapping allocates exactly three axes"
    );

    drop(state);
    let kek = load_or_create_storage_kek(&keys, &root.join("key-state.db"))
        .expect("reload publication test KEK");
    let mut reopened = super::super::sqlite::open(&config, kek).expect("reopen publication store");
    let descriptor = super::super::journal::canonical_conversation_descriptor(&input.descriptor)
        .expect("canonical replay descriptor");
    let mut replay_effects = crate::runtime::events::CommandStreamEffects::default();
    assert!(matches!(
        super::super::journal::create_conversation(
            &mut reopened,
            &config,
            input.clone(),
            descriptor,
            &mut replay_effects,
        ),
        Ok(crate::runtime::model::CreateConversationOutcome::Replayed { .. })
    ));
    let replayed = authenticate_conversation_directory(&reopened, input.conversation_id)
        .expect("authenticate replayed publication mapping")
        .expect("replayed publication mapping");
    assert_eq!(replayed, committed);
    assert_eq!(
        calls.load(Ordering::SeqCst),
        calls_after_commit,
        "committed replay must not consume fresh mapping entropy"
    );

    drop(reopened);
    let _ = fs::remove_dir_all(root);
}

#[test]
fn shared_publication_fences_pre_barrier_transition_in_preflight_and_freeze_transaction() {
    use agentdeck_protocol::relay_v2::DeviceRouteId;
    use agentdeck_protocol::runtime::RuntimeStreamItem;

    let (root, base_config, mut state) = open_publication_test_store("shared-pre-barrier-fence");
    let config = base_config.with_capacity_probe(super::super::pairing_tests::GenerousCapacity);
    let conversation_id = create_catalog_entry(&mut state, &config, 0x35);
    let conversation = super::super::journal::load_conversation(
        &state.connection,
        &state.key_bundle,
        state.database_id,
        conversation_id,
    )
    .expect("load authenticated catalog conversation");
    let catalog_delta = super::super::catalog::load_delta(
        &state.connection,
        &state.key_bundle.read_only_capability(),
        state.database_id,
        &encode_sequence(conversation.catalog_revision),
    )
    .expect("load immutable catalog delta");
    let request = SharedPublicationPreflightRequest {
        publication_id: [0x41; 16],
        scope: PublicationScope::Catalog,
        inner_after: None,
        inner_through: Some(conversation.catalog_revision),
        payload_kind: PublicationPayloadKind::Catalog,
        journal_identity: SharedJournalIdentity::CatalogRange,
        canonical_item_bytes: serde_json::to_vec(&RuntimeStreamItem::CatalogDelta(catalog_delta))
            .expect("encode canonical catalog item"),
    };
    let stream_id = [0x42; 16];
    let stream_route = [0x43; 16];
    let generation = [0x44; 16];
    create_publication_stream(
        &mut state,
        &config,
        stream_id,
        PublicationScope::Catalog,
        stream_route,
        generation,
        2,
    )
    .expect("create catalog stream before transition");
    let recipient = super::super::key_transition::KeyTransitionRecipient {
        device_route: *DeviceRouteId::from_bytes([0x45; 16]).as_bytes(),
        grant_serial: 1,
    };
    super::super::key_transition::begin_key_transition_with_global_lineage_for_test(
        &mut state,
        &config,
        super::super::key_transition::BeginKeyTransition {
            operation_id: [0x46; 16],
            operation: super::super::key_transition::KeyTransitionOperation::Add,
            target: super::super::key_transition::KeyTransitionTarget::Device(recipient),
            from_revision: 1,
            to_revision: 2,
            recipients: vec![recipient],
            replay_retirement: None,
            created_at_ms: 3,
        },
        super::super::key_transition::KeyTransitionGlobalLineage {
            global_key_state_hash: [0x4a; 32],
            stable_key_lineage_hash: Some([0x4b; 32]),
        },
    )
    .expect("stage pre-barrier transition");

    assert!(matches!(
        preflight_shared_publication(
            &mut state,
            &config,
            &request,
            SharedPublicationStreamProposal {
                publication_stream_id: [0x47; 16],
                stream_route: [0x48; 16],
                generation: [0x49; 16],
            },
            4,
        ),
        Err(RuntimeStoreError::InvalidStateTransition)
    ));

    let transaction = Transaction::new_unchecked(&state.connection, TransactionBehavior::Deferred)
        .expect("begin shared freeze check");
    let stream = load_stream(&transaction, &state.key_bundle, stream_id)
        .expect("load authenticated catalog stream");
    let binding = SharedPublicationTransactionBinding {
        request,
        expected_key_directory_revision: 1,
        expected_key_id: agentdeck_protocol::e2ee::KeyId {
            purpose: agentdeck_protocol::e2ee::KeyPurpose::Catalog,
            epoch: 1,
        },
    };
    assert!(matches!(
        shared_transaction_key_axes(
            &transaction,
            &state.key_bundle,
            state.database_id,
            &stream,
            1,
            &binding,
        ),
        Err(RuntimeStoreError::InvalidStateTransition)
    ));
    drop(transaction);

    drop(state);
    let _ = fs::remove_dir_all(root);
}

#[allow(clippy::too_many_arguments)]
fn acknowledge_one_control_and_mark_needs_snapshot(
    state: &mut super::super::sqlite::RuntimeSqlite,
    config: &RuntimeStoreConfig,
    stream_id: [u8; 16],
    generation: [u8; 16],
    counter_scope: [u8; 32],
    publication_id: [u8; 16],
    sender_counter: u64,
    now_ms: u64,
) -> FrozenPublication {
    let limits = PublicationLimits {
        rows_per_stream: 1,
        bytes_per_stream: MAX_PUBLICATION_BYTES_PER_STREAM,
        rows_global: MAX_PUBLICATION_ROWS_GLOBAL,
        bytes_global: MAX_PUBLICATION_BYTES_GLOBAL,
    };
    let frozen = freeze_publication_with_limits(
        state,
        config,
        FreezePublicationRequest {
            publication_id,
            publication_stream_id: stream_id,
            generation,
            counter_scope_token: counter_scope,
            sender_counter,
            inner_after: None,
            inner_through: None,
            payload_kind: PublicationPayloadKind::Control,
            blob: vec![publication_id[0]],
        },
        now_ms,
        limits,
    )
    .expect("freeze one control publication");
    let mut rejected_id = publication_id;
    rejected_id[15] = rejected_id[15].wrapping_add(1);
    assert!(matches!(
        freeze_publication_with_limits(
            state,
            config,
            FreezePublicationRequest {
                publication_id: rejected_id,
                publication_stream_id: stream_id,
                generation,
                counter_scope_token: counter_scope,
                sender_counter: sender_counter + 1,
                inner_after: None,
                inner_through: None,
                payload_kind: PublicationPayloadKind::Control,
                blob: vec![rejected_id[0]],
            },
            now_ms + 1,
            limits,
        ),
        Err(RuntimeStoreError::PublicationNeedsSnapshot)
    ));
    acknowledge_publication_commit(
        state,
        config,
        stream_id,
        generation,
        frozen.stream_seq,
        frozen.blob_sha256,
        now_ms + 2,
    )
    .expect("commit control publication");
    acknowledge_publication_delivery(
        state,
        config,
        stream_id,
        generation,
        frozen.stream_seq,
        frozen.blob_sha256,
        now_ms + 3,
    )
    .expect("ack control publication");
    frozen
}

fn configure_managed_conversation_with_event_zero(
    state: &mut super::super::sqlite::RuntimeSqlite,
    config: &RuntimeStoreConfig,
    conversation_id: RuntimeId,
    seed: u8,
) {
    use agentdeck_protocol::runtime::{
        CodexConversationConfiguration, ConversationConfiguration, VendorConfigurationSnapshot,
    };
    use agentdeck_protocol::{CodexApprovalPolicy, CodexReasoningEffort, CodexSandboxMode};

    let prepared = super::super::configuration::prepare_configuration_request(
        super::super::ConfigureConversation {
            conversation_id,
            owner: crate::runtime::model::IdempotencyOwner::Local {
                machine_trust_domain: [seed; 32],
                uid: 501,
                client_installation_id: [seed.wrapping_add(1); 16],
            },
            idempotency_key: format!("publication-conversation-configuration-{seed}"),
            expected_configuration_revision: 0,
            configuration: ConversationConfiguration::new(VendorConfigurationSnapshot::Codex(
                CodexConversationConfiguration::new(
                    CodexApprovalPolicy::OnRequest,
                    CodexSandboxMode::WorkspaceWrite,
                    CodexReasoningEffort::Medium,
                ),
            )),
        },
    )
    .expect("prepare managed conversation configuration");
    let mut effects = CommandStreamEffects::default();
    let outcome =
        super::super::configuration::configure_conversation(state, config, prepared, &mut effects)
            .expect("append managed conversation event zero");
    assert!(matches!(
        outcome,
        super::super::ConfigureConversationOutcome::Applied { configuration }
            if configuration.event_seq == 0
    ));
}

fn store_ready_conversation_snapshot_at_zero(
    state: &mut super::super::sqlite::RuntimeSqlite,
    config: &RuntimeStoreConfig,
    conversation_id: RuntimeId,
    now_ms: u64,
) {
    let pin = super::super::stream::acquire_snapshot_build_pin(state, conversation_id, now_ms)
        .expect("acquire authenticated conversation snapshot pin");
    assert_eq!(pin.base_event_seq(), Some(0));
    let (cleanup_tx, _cleanup_rx) = tokio::sync::mpsc::unbounded_channel();
    let cleanup = SnapshotBuildPinCleanup::new(pin.clone(), cleanup_tx);
    let mut payload = Vec::with_capacity(32 + super::super::cipher::ROW_BLOB_V1_OVERHEAD_LEN);
    payload.resize(32, 0x5a);
    let write = super::super::PreparedConversationSnapshotWrite::new(pin, 1, payload, cleanup);
    super::super::snapshot::store_conversation_snapshot(state, config, write, now_ms)
        .expect("store authenticated ready conversation snapshot");
}

#[test]
fn publication_directory_rejects_valid_mac_outer_gap() {
    let (root, config, mut state) = open_publication_test_store("directory-outer-gap");
    let stream_id = [0x81; 16];
    let generation = [0x82; 16];
    let counter_scope = [0x83; 32];
    create_publication_stream(
        &mut state,
        &config,
        stream_id,
        PublicationScope::Catalog,
        [0x84; 16],
        generation,
        1,
    )
    .expect("create catalog publication stream");
    for (publication_id, sender_counter, after, through, now_ms, blob) in [
        ([0x85; 16], 1, None, Some(0), 2, b"outer-zero".as_slice()),
        ([0x86; 16], 2, Some(0), Some(1), 3, b"outer-one".as_slice()),
    ] {
        freeze_publication(
            &mut state,
            &config,
            FreezePublicationRequest {
                publication_id,
                publication_stream_id: stream_id,
                generation,
                counter_scope_token: counter_scope,
                sender_counter,
                inner_after: after,
                inner_through: through,
                payload_kind: PublicationPayloadKind::Catalog,
                blob: blob.to_vec(),
            },
            now_ms,
        )
        .expect("freeze contiguous publication row");
    }

    let gap_seq = encode_sequence(2);
    let inner_after = encode_sequence(0);
    let inner_through = encode_sequence(1);
    let blob_hash: [u8; 32] = Sha256::digest(b"outer-one").into();
    let token = outbox_token(
        &state.key_bundle,
        [0x86; 16],
        stream_id,
        generation,
        &gap_seq,
        counter_scope,
        2,
        Some(&inner_after),
        Some(&inner_through),
        PublicationPayloadKind::Catalog,
        blob_hash,
        u64::try_from(b"outer-one".len()).expect("logical bytes fit"),
        3,
    )
    .expect("recompute valid gap metadata token");
    state
        .connection
        .execute(
            "UPDATE publication_outbox SET stream_seq = ?1, metadata_token = ?2
                 WHERE publication_id = ?3",
            params![&gap_seq, &token[..], &[0x86_u8; 16][..]],
        )
        .expect("install valid-MAC outer gap");
    let transaction = Transaction::new_unchecked(&state.connection, TransactionBehavior::Immediate)
        .expect("begin stream HWM tamper transaction");
    let mut stream = load_stream(&transaction, &state.key_bundle, stream_id)
        .expect("load stream for HWM tamper");
    stream.reserved_high_water = Some(2);
    update_stream(&transaction, &state.key_bundle, &stream)
        .expect("authenticate updated reserved HWM");
    transaction.commit().expect("commit reserved HWM tamper");

    assert!(matches!(
        authenticate_catalog_directory(&state),
        Err(RuntimeStoreError::UnknownOrCorruptSchema)
    ));
    drop(state);
    let _ = fs::remove_dir_all(root);
}

#[test]
fn publication_directory_rejects_valid_mac_inner_discontinuity() {
    let (root, config, mut state) = open_publication_test_store("directory-inner-gap");
    let stream_id = [0x91; 16];
    let generation = [0x92; 16];
    let counter_scope = [0x93; 32];
    create_publication_stream(
        &mut state,
        &config,
        stream_id,
        PublicationScope::Catalog,
        [0x94; 16],
        generation,
        1,
    )
    .expect("create catalog publication stream");
    for (publication_id, sender_counter, after, through, now_ms, blob) in [
        ([0x95; 16], 1, None, Some(0), 2, b"inner-zero".as_slice()),
        ([0x96; 16], 2, Some(0), Some(1), 3, b"inner-one".as_slice()),
    ] {
        freeze_publication(
            &mut state,
            &config,
            FreezePublicationRequest {
                publication_id,
                publication_stream_id: stream_id,
                generation,
                counter_scope_token: counter_scope,
                sender_counter,
                inner_after: after,
                inner_through: through,
                payload_kind: PublicationPayloadKind::Catalog,
                blob: blob.to_vec(),
            },
            now_ms,
        )
        .expect("freeze contiguous publication row");
    }

    let stream_seq = encode_sequence(1);
    let discontinuous_after = encode_sequence(5);
    let discontinuous_through = encode_sequence(6);
    let blob_hash: [u8; 32] = Sha256::digest(b"inner-one").into();
    let token = outbox_token(
        &state.key_bundle,
        [0x96; 16],
        stream_id,
        generation,
        &stream_seq,
        counter_scope,
        2,
        Some(&discontinuous_after),
        Some(&discontinuous_through),
        PublicationPayloadKind::Catalog,
        blob_hash,
        u64::try_from(b"inner-one".len()).expect("logical bytes fit"),
        3,
    )
    .expect("recompute valid inner-gap metadata token");
    state
        .connection
        .execute(
            "UPDATE publication_outbox
                 SET inner_after_seq = ?1, inner_through_seq = ?2, metadata_token = ?3
                 WHERE publication_id = ?4",
            params![
                &discontinuous_after,
                &discontinuous_through,
                &token[..],
                &[0x96_u8; 16][..]
            ],
        )
        .expect("install valid-MAC inner discontinuity");

    assert!(matches!(
        authenticate_catalog_directory(&state),
        Err(RuntimeStoreError::UnknownOrCorruptSchema)
    ));
    drop(state);
    let _ = fs::remove_dir_all(root);
}

#[test]
fn publication_directory_rejects_valid_mac_sender_counter_regression() {
    let (root, config, mut state) = open_publication_test_store("directory-counter-gap");
    let stream_id = [0xa1; 16];
    let generation = [0xa2; 16];
    let counter_scope = [0xa3; 32];
    create_publication_stream(
        &mut state,
        &config,
        stream_id,
        PublicationScope::Catalog,
        [0xa4; 16],
        generation,
        1,
    )
    .expect("create catalog publication stream");
    for (publication_id, sender_counter, after, through, now_ms, blob) in [
        ([0xa5; 16], 1, None, Some(0), 2, b"counter-one".as_slice()),
        (
            [0xa6; 16],
            2,
            Some(0),
            Some(1),
            3,
            b"counter-two".as_slice(),
        ),
    ] {
        freeze_publication(
            &mut state,
            &config,
            FreezePublicationRequest {
                publication_id,
                publication_stream_id: stream_id,
                generation,
                counter_scope_token: counter_scope,
                sender_counter,
                inner_after: after,
                inner_through: through,
                payload_kind: PublicationPayloadKind::Catalog,
                blob: blob.to_vec(),
            },
            now_ms,
        )
        .expect("freeze increasing-counter publication row");
    }

    let stream_seq = encode_sequence(1);
    let inner_after = encode_sequence(0);
    let inner_through = encode_sequence(1);
    let regressed_counter = encode_sequence(0);
    let blob_hash: [u8; 32] = Sha256::digest(b"counter-two").into();
    let token = outbox_token(
        &state.key_bundle,
        [0xa6; 16],
        stream_id,
        generation,
        &stream_seq,
        counter_scope,
        0,
        Some(&inner_after),
        Some(&inner_through),
        PublicationPayloadKind::Catalog,
        blob_hash,
        u64::try_from(b"counter-two".len()).expect("logical bytes fit"),
        3,
    )
    .expect("recompute valid regressed-counter metadata token");
    state
        .connection
        .execute(
            "UPDATE publication_outbox SET sender_counter = ?1, metadata_token = ?2
                 WHERE publication_id = ?3",
            params![&regressed_counter, &token[..], &[0xa6_u8; 16][..]],
        )
        .expect("install valid-MAC sender counter regression");
    let transaction = Transaction::new_unchecked(&state.connection, TransactionBehavior::Immediate)
        .expect("begin counter HWM tamper transaction");
    let mut stream = load_stream(&transaction, &state.key_bundle, stream_id)
        .expect("load stream for counter HWM tamper");
    stream.sender_counter_high_water = Some(0);
    update_stream(&transaction, &state.key_bundle, &stream)
        .expect("authenticate updated counter HWM");
    transaction.commit().expect("commit counter HWM tamper");

    assert!(matches!(
        authenticate_catalog_directory(&state),
        Err(RuntimeStoreError::UnknownOrCorruptSchema)
    ));
    drop(state);
    let _ = fs::remove_dir_all(root);
}

#[test]
fn publication_directory_authenticates_metadata_without_opening_sealed_blob() {
    let (root, config, mut state) = open_publication_test_store("directory-metadata-only");
    let stream_id = [0xb1; 16];
    let generation = [0xb2; 16];
    let publication_id = [0xb3; 16];
    create_publication_stream(
        &mut state,
        &config,
        stream_id,
        PublicationScope::Catalog,
        [0xb4; 16],
        generation,
        1,
    )
    .expect("create catalog publication stream");
    freeze_publication(
        &mut state,
        &config,
        FreezePublicationRequest {
            publication_id,
            publication_stream_id: stream_id,
            generation,
            counter_scope_token: [0xb5; 32],
            sender_counter: 1,
            inner_after: None,
            inner_through: Some(0),
            payload_kind: PublicationPayloadKind::Catalog,
            blob: b"directory-must-not-open-this-sealed-blob".to_vec(),
        },
        2,
    )
    .expect("freeze publication row");
    state
        .connection
        .execute(
            "UPDATE publication_outbox
                 SET sealed_publication = zeroblob(length(sealed_publication))
                 WHERE publication_id = ?1",
            [&publication_id[..]],
        )
        .expect("break sealed publication without touching metadata");

    let selected = authenticate_catalog_directory(&state)
        .expect("directory must not open sealed publication")
        .expect("catalog stream remains selectable");
    assert_eq!(selected.publication_stream_id, stream_id);

    state
        .connection
        .execute(
            "UPDATE publication_outbox SET metadata_token = zeroblob(32)
                 WHERE publication_id = ?1",
            [&publication_id[..]],
        )
        .expect("break outbox metadata token");
    assert!(matches!(
        authenticate_catalog_directory(&state),
        Err(RuntimeStoreError::UnknownOrCorruptSchema)
    ));
    drop(state);
    let _ = fs::remove_dir_all(root);
}

#[test]
fn publication_directory_accepts_valid_mac_zero_blob_hash_without_opening_sealed_blob() {
    let (root, config, mut state) = open_publication_test_store("directory-zero-blob-hash");
    let stream_id = [0xb6; 16];
    let generation = [0xb7; 16];
    let publication_id = [0xb8; 16];
    let counter_scope = [0xb9; 32];
    let blob = b"directory-zero-hash-does-not-open-sealed-blob";
    create_publication_stream(
        &mut state,
        &config,
        stream_id,
        PublicationScope::Catalog,
        [0xba; 16],
        generation,
        1,
    )
    .expect("create catalog publication stream");
    freeze_publication(
        &mut state,
        &config,
        FreezePublicationRequest {
            publication_id,
            publication_stream_id: stream_id,
            generation,
            counter_scope_token: counter_scope,
            sender_counter: 1,
            inner_after: None,
            inner_through: Some(0),
            payload_kind: PublicationPayloadKind::Catalog,
            blob: blob.to_vec(),
        },
        2,
    )
    .expect("freeze publication row");

    let stream_seq = encode_sequence(0);
    let inner_through = encode_sequence(0);
    let token = outbox_token(
        &state.key_bundle,
        publication_id,
        stream_id,
        generation,
        &stream_seq,
        counter_scope,
        1,
        None,
        Some(&inner_through),
        PublicationPayloadKind::Catalog,
        [0; 32],
        u64::try_from(blob.len()).expect("logical bytes fit"),
        2,
    )
    .expect("recompute valid zero-hash metadata token");
    state
        .connection
        .execute(
            "UPDATE publication_outbox
                 SET blob_sha256 = zeroblob(32), metadata_token = ?1
                 WHERE publication_id = ?2",
            params![&token[..], &publication_id[..]],
        )
        .expect("install valid-MAC zero blob hash");

    let selected = authenticate_catalog_directory(&state)
        .expect("zero blob hash is valid authenticated metadata")
        .expect("catalog stream remains selectable");
    assert_eq!(selected.publication_stream_id, stream_id);
    drop(state);
    let _ = fs::remove_dir_all(root);
}

#[test]
fn publication_directory_preserves_sqlite_error_when_outbox_table_is_missing() {
    let (root, _config, state) = open_publication_test_store("directory-drop-outbox");
    state
        .connection
        .execute_batch("DROP TABLE publication_outbox")
        .expect("drop publication outbox");
    assert!(matches!(
        authenticate_catalog_directory(&state),
        Err(RuntimeStoreError::Sqlite(_))
    ));
    drop(state);
    let _ = fs::remove_dir_all(root);
}

#[test]
fn publication_directory_maps_outbox_row_type_error_to_corruption() {
    let (root, config, mut state) = open_publication_test_store("directory-row-type");
    let stream_id = [0xc1; 16];
    let generation = [0xc2; 16];
    let publication_id = [0xc3; 16];
    create_publication_stream(
        &mut state,
        &config,
        stream_id,
        PublicationScope::Catalog,
        [0xc4; 16],
        generation,
        1,
    )
    .expect("create catalog publication stream");
    freeze_publication(
        &mut state,
        &config,
        FreezePublicationRequest {
            publication_id,
            publication_stream_id: stream_id,
            generation,
            counter_scope_token: [0xc5; 32],
            sender_counter: 1,
            inner_after: None,
            inner_through: Some(0),
            payload_kind: PublicationPayloadKind::Catalog,
            blob: b"directory-row-type".to_vec(),
        },
        2,
    )
    .expect("freeze publication row");
    state
        .connection
        .execute_batch("PRAGMA ignore_check_constraints = ON")
        .expect("allow row-type corruption fixture");
    state
        .connection
        .execute(
            "UPDATE publication_outbox SET stream_seq = x'0001'
                 WHERE publication_id = ?1",
            [&publication_id[..]],
        )
        .expect("install stream-seq row type corruption");

    assert!(matches!(
        authenticate_catalog_directory(&state),
        Err(RuntimeStoreError::UnknownOrCorruptSchema)
    ));
    drop(state);
    let _ = fs::remove_dir_all(root);
}

#[test]
fn publication_directory_accepts_retired_max_ack_with_empty_outbox() {
    let (root, config, mut state) = open_publication_test_store("directory-max-ack");
    let stream_id = [0xd1; 16];
    let generation = [0xd2; 16];
    create_publication_stream(
        &mut state,
        &config,
        stream_id,
        PublicationScope::Catalog,
        [0xd3; 16],
        generation,
        1,
    )
    .expect("create catalog publication stream");
    let transaction = Transaction::new_unchecked(&state.connection, TransactionBehavior::Immediate)
        .expect("begin terminal max-HWM fixture transaction");
    let mut stream = load_stream(&transaction, &state.key_bundle, stream_id)
        .expect("load stream for terminal max-HWM fixture");
    stream.counter_scope_token = Some([0xd4; 32]);
    stream.sender_counter_high_water = Some(9);
    stream.reserved_high_water = Some(u64::MAX);
    stream.committed_high_water = Some(u64::MAX);
    stream.last_committed_blob_hash = Some([0xd5; 32]);
    stream.acknowledged_high_water = Some(u64::MAX);
    stream.last_acknowledged_blob_hash = Some([0xd5; 32]);
    stream.state = PublicationStreamState::Retired;
    update_stream(&transaction, &state.key_bundle, &stream)
        .expect("authenticate terminal max-HWM fixture");
    transaction
        .commit()
        .expect("commit terminal max-HWM fixture");

    assert_eq!(
        authenticate_catalog_directory(&state)
            .expect("retired max-HWM stream remains authenticatable"),
        None
    );
    drop(state);
    let _ = fs::remove_dir_all(root);
}

#[test]
fn publication_outbox_cap_marks_stream_needs_snapshot_without_dropping_unacked_row() {
    let root = std::env::temp_dir().join(format!(
        "agentdeck-publication-cap-{}-{}",
        std::process::id(),
        NEXT_ROOT.fetch_add(1, Ordering::Relaxed)
    ));
    let _ = fs::remove_dir_all(&root);
    fs::create_dir(&root).expect("create publication cap root");
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        fs::set_permissions(&root, fs::Permissions::from_mode(0o700))
            .expect("secure publication cap root");
    }
    let database = root.join("runtime.db");
    let keys = MemoryKeyStore::new();
    let kek =
        load_or_create_storage_kek(&keys, &root.join("key-state.db")).expect("create test KEK");
    let config = RuntimeStoreConfig::new(database)
        .with_capacity_probe(super::super::pairing_tests::GenerousCapacity);
    let mut state = super::super::sqlite::open(&config, kek).expect("open test store");
    let stream_id = [0x71; 16];
    let generation = [0x72; 16];
    create_publication_stream(
        &mut state,
        &config,
        stream_id,
        PublicationScope::Catalog,
        [0x73; 16],
        generation,
        1,
    )
    .expect("create catalog publication stream");
    let request = |publication_id: [u8; 16], after, through| FreezePublicationRequest {
        publication_id,
        publication_stream_id: stream_id,
        generation,
        counter_scope_token: [0x76; 32],
        sender_counter: u64::from(publication_id[0]),
        inner_after: after,
        inner_through: through,
        payload_kind: PublicationPayloadKind::Catalog,
        blob: vec![publication_id[0]],
    };
    let first_request = request([0x74; 16], None, Some(0));
    let first = freeze_publication_with_limits(
        &mut state,
        &config,
        first_request.clone(),
        2,
        PublicationLimits {
            rows_per_stream: 1,
            bytes_per_stream: MAX_PUBLICATION_BYTES_PER_STREAM,
            rows_global: MAX_PUBLICATION_ROWS_GLOBAL,
            bytes_global: MAX_PUBLICATION_BYTES_GLOBAL,
        },
    )
    .expect("freeze first row");
    let error = freeze_publication_with_limits(
        &mut state,
        &config,
        request([0x75; 16], Some(0), Some(1)),
        3,
        PublicationLimits {
            rows_per_stream: 1,
            bytes_per_stream: MAX_PUBLICATION_BYTES_PER_STREAM,
            rows_global: MAX_PUBLICATION_ROWS_GLOBAL,
            bytes_global: MAX_PUBLICATION_BYTES_GLOBAL,
        },
    )
    .expect_err("cap must stop new publication");
    assert!(matches!(error, RuntimeStoreError::PublicationNeedsSnapshot));
    assert_eq!(
        load_stream(&state.connection, &state.key_bundle, stream_id)
            .expect("load capped stream")
            .state,
        PublicationStreamState::NeedsSnapshot
    );
    assert_eq!(
        load_pending_publications(&state, stream_id).expect("load retained outbox"),
        std::slice::from_ref(&first),
        "unacked row must never be evicted"
    );
    assert_eq!(
        freeze_publication_with_limits(
            &mut state,
            &config,
            first_request,
            4,
            PublicationLimits {
                rows_per_stream: 1,
                bytes_per_stream: MAX_PUBLICATION_BYTES_PER_STREAM,
                rows_global: MAX_PUBLICATION_ROWS_GLOBAL,
                bytes_global: MAX_PUBLICATION_BYTES_GLOBAL,
            },
        )
        .expect("exact retry remains available after cap"),
        first
    );
    assert!(
        matches!(
            rotate_publication_stream(
                &mut state,
                &config,
                RotatePublicationStreamRequest {
                    publication_stream_id: stream_id,
                    expected_generation: generation,
                },
                5,
            ),
            Err(RuntimeStoreError::PublicationMismatch)
        ),
        "rotation must reject a stream whose exact outbox is not committed and ACKed"
    );
    drop(state);
    let _ = fs::remove_dir_all(root);
}

#[test]
fn repeated_rollover_keeps_stream_count_constant_and_commit_unknown_is_idempotent() {
    let (root, config, mut state) = open_publication_test_store("repeated-rollover");
    let stream_id = [0x21; 16];
    let first_generation = [0x22; 16];
    create_publication_stream(
        &mut state,
        &config,
        stream_id,
        PublicationScope::Catalog,
        [0x23; 16],
        first_generation,
        1,
    )
    .expect("create publication stream");
    let first_publication_id = [0x24; 16];
    acknowledge_one_control_and_mark_needs_snapshot(
        &mut state,
        &config,
        stream_id,
        first_generation,
        [0x25; 32],
        first_publication_id,
        1,
        2,
    );
    let initial_count = super::super::sqlite::load_runtime_ledger(
        &state.connection,
        &state.key_bundle,
        state.database_id,
    )
    .expect("load initial publication count")
    .publication_stream_count;
    assert_eq!(initial_count, 1);

    let first_rotation = RotatePublicationStreamRequest {
        publication_stream_id: stream_id,
        expected_generation: first_generation,
    };
    let fault_config = config
        .clone()
        .with_fault_injector(Arc::new(FailOnceAfterRotation(
            std::sync::atomic::AtomicBool::new(false),
        )));
    assert!(matches!(
        rotate_publication_stream(&mut state, &fault_config, first_rotation, 6),
        Err(RuntimeStoreError::CommitOutcomeUnknown {
            operation: RuntimeCommitOperation::RotatePublicationStream
        })
    ));
    let first_retry = rotate_publication_stream(&mut state, &fault_config, first_rotation, 6)
        .expect("exact rotation retry reads committed row");
    assert_ne!(first_retry.generation, first_generation);
    assert_ne!(first_retry.stream_route, [0x23; 16]);
    assert_eq!(first_retry.rotation_serial, 1);
    assert_eq!(first_retry.state, PublicationStreamState::Active);
    assert!(first_retry.reserved_high_water.is_none());
    assert_eq!(
        first_retry.last_acknowledged_publication_id,
        Some(first_publication_id),
        "rollover must preserve the latest ACK tombstone"
    );
    assert!(matches!(
        rotate_publication_stream(
            &mut state,
            &fault_config,
            RotatePublicationStreamRequest {
                expected_generation: [0x28; 16],
                ..first_rotation
            },
            7,
        ),
        Err(RuntimeStoreError::PublicationMismatch)
    ));
    assert!(matches!(
        freeze_publication(
            &mut state,
            &fault_config,
            FreezePublicationRequest {
                publication_id: first_publication_id,
                publication_stream_id: stream_id,
                generation: first_generation,
                counter_scope_token: [0x25; 32],
                sender_counter: 1,
                inner_after: None,
                inner_through: None,
                payload_kind: PublicationPayloadKind::Control,
                blob: vec![first_publication_id[0]],
            },
            7,
        ),
        Err(RuntimeStoreError::PublicationAlreadyAcknowledged)
    ));

    acknowledge_one_control_and_mark_needs_snapshot(
        &mut state,
        &fault_config,
        stream_id,
        first_retry.generation,
        [0x25; 32],
        [0x2a; 16],
        2,
        10,
    );
    let second_rotation = RotatePublicationStreamRequest {
        publication_stream_id: stream_id,
        expected_generation: first_retry.generation,
    };
    let second = rotate_publication_stream(&mut state, &fault_config, second_rotation, 14)
        .expect("perform second in-place rollover");
    assert_ne!(second.generation, first_retry.generation);
    assert_ne!(second.generation, first_generation);
    assert_eq!(second.rotation_serial, 2);
    assert_eq!(
        rotate_publication_stream(&mut state, &fault_config, second_rotation, 14)
            .expect("second exact retry"),
        second
    );
    assert!(matches!(
        rotate_publication_stream(&mut state, &fault_config, first_rotation, 15),
        Err(RuntimeStoreError::PublicationMismatch)
    ));
    assert_eq!(
        super::super::sqlite::load_runtime_ledger(
            &state.connection,
            &state.key_bundle,
            state.database_id,
        )
        .expect("load final publication count")
        .publication_stream_count,
        initial_count
    );
    drop(state);
    let _ = fs::remove_dir_all(root);
}

#[test]
fn rotation_exact_retry_survives_progress_in_the_new_generation() {
    // 威胁场景：rotation 的成功回复丢失后，内部 owner 已在新 generation
    // freeze 下一帧；原 rotation 的 exact retry 仍必须读回已提交结果，不能把
    // outcome unknown 永久误报为 mismatch。
    let (root, config, mut state) = open_publication_test_store("rotation-retry-progress");
    let stream_id = [0x8a; 16];
    let initial_generation = [0x8b; 16];
    let counter_scope = [0x8c; 32];
    create_publication_stream(
        &mut state,
        &config,
        stream_id,
        PublicationScope::Catalog,
        [0x8d; 16],
        initial_generation,
        1,
    )
    .expect("create rotation retry stream");
    acknowledge_one_control_and_mark_needs_snapshot(
        &mut state,
        &config,
        stream_id,
        initial_generation,
        counter_scope,
        [0x8e; 16],
        1,
        2,
    );
    let request = RotatePublicationStreamRequest {
        publication_stream_id: stream_id,
        expected_generation: initial_generation,
    };
    let rotated = rotate_publication_stream(&mut state, &config, request, 6)
        .expect("rotate to a new generation");
    let frozen = freeze_publication(
        &mut state,
        &config,
        FreezePublicationRequest {
            publication_id: [0x8f; 16],
            publication_stream_id: stream_id,
            generation: rotated.generation,
            counter_scope_token: counter_scope,
            sender_counter: 2,
            inner_after: None,
            inner_through: None,
            payload_kind: PublicationPayloadKind::Control,
            blob: b"new-generation-progress".to_vec(),
        },
        7,
    )
    .expect("advance the new generation before retrying rotation");

    let replayed = rotate_publication_stream(&mut state, &config, request, 8)
        .expect("exact rotation retry must survive later generation progress");
    assert_eq!(replayed.generation, rotated.generation);
    assert_eq!(replayed.rotation_serial, rotated.rotation_serial);
    assert_eq!(replayed.reserved_high_water, Some(frozen.stream_seq));
    assert_eq!(replayed.sender_counter_high_water, Some(2));
    assert_eq!(replayed.last_committed_blob_hash, None);

    drop(state);
    let _ = fs::remove_dir_all(root);
}

#[test]
fn rotation_lineage_survives_restart_and_rejects_old_request_or_serial_rollback() {
    let (root, keys, config, mut state) =
        open_reopenable_publication_test_store("rotation-lineage-restart");
    let stream_id = [0x2d; 16];
    let initial_generation = [0x2e; 16];
    create_publication_stream(
        &mut state,
        &config,
        stream_id,
        PublicationScope::Catalog,
        [0x2f; 16],
        initial_generation,
        1,
    )
    .expect("create restart lineage stream");
    acknowledge_one_control_and_mark_needs_snapshot(
        &mut state,
        &config,
        stream_id,
        initial_generation,
        [0x30; 32],
        [0x31; 16],
        1,
        2,
    );
    let first_request = RotatePublicationStreamRequest {
        publication_stream_id: stream_id,
        expected_generation: initial_generation,
    };
    let first = rotate_publication_stream(&mut state, &config, first_request, 6)
        .expect("first derived rotation");
    acknowledge_one_control_and_mark_needs_snapshot(
        &mut state,
        &config,
        stream_id,
        first.generation,
        [0x30; 32],
        [0x33; 16],
        2,
        10,
    );
    let second = rotate_publication_stream(
        &mut state,
        &config,
        RotatePublicationStreamRequest {
            publication_stream_id: stream_id,
            expected_generation: first.generation,
        },
        14,
    )
    .expect("second derived rotation");
    assert_eq!(second.rotation_serial, 2);
    assert_ne!(second.generation, initial_generation);
    drop(state);

    let kek =
        load_or_create_storage_kek(&keys, &root.join("key-state.db")).expect("reload lineage KEK");
    let reopened =
        super::super::sqlite::open(&config, kek).expect("reopen authenticated rotation lineage");
    let persisted = load_stream(&reopened.connection, &reopened.key_bundle, stream_id)
        .expect("load persisted rotation lineage");
    assert_eq!(persisted.rotation_serial, 2);
    assert_eq!(persisted.generation, second.generation);
    let mut reopened = reopened;
    assert!(matches!(
        rotate_publication_stream(&mut reopened, &config, first_request, 15),
        Err(RuntimeStoreError::PublicationMismatch)
    ));
    assert!(matches!(
        freeze_publication(
            &mut reopened,
            &config,
            FreezePublicationRequest {
                publication_id: [0x38; 16],
                publication_stream_id: stream_id,
                generation: persisted.generation,
                counter_scope_token: [0x30; 32],
                sender_counter: 1,
                inner_after: None,
                inner_through: None,
                payload_kind: PublicationPayloadKind::Control,
                blob: b"counter-rollback-after-restart".to_vec(),
            },
            16,
        ),
        Err(RuntimeStoreError::PublicationMismatch)
    ));
    let advanced = freeze_publication(
        &mut reopened,
        &config,
        FreezePublicationRequest {
            publication_id: [0x39; 16],
            publication_stream_id: stream_id,
            generation: persisted.generation,
            counter_scope_token: [0x30; 32],
            sender_counter: 3,
            inner_after: None,
            inner_through: None,
            payload_kind: PublicationPayloadKind::Control,
            blob: b"counter-continues-after-restart".to_vec(),
        },
        16,
    )
    .expect("same scope with a strictly higher counter remains usable");
    assert_eq!(advanced.sender_counter, 3);
    reopened
        .connection
        .execute(
            "UPDATE publication_streams SET rotation_serial = ?1
                 WHERE publication_stream_id = ?2",
            params![encode_sequence(1), &stream_id[..]],
        )
        .expect("install unauthenticated serial rollback");
    drop(reopened);

    let kek =
        load_or_create_storage_kek(&keys, &root.join("key-state.db")).expect("reload rollback KEK");
    assert!(matches!(
        super::super::sqlite::open(&config, kek),
        Err(RuntimeStoreError::UnknownOrCorruptSchema)
    ));
    let _ = fs::remove_dir_all(root);
}

#[test]
fn rotation_serial_at_u64_max_fails_closed_without_wrap() {
    let (root, config, mut state) = open_publication_test_store("rotation-serial-max");
    let stream_id = [0x34; 16];
    let generation = [0x35; 16];
    create_publication_stream(
        &mut state,
        &config,
        stream_id,
        PublicationScope::Catalog,
        [0x36; 16],
        generation,
        1,
    )
    .expect("create serial max stream");
    let transaction = Transaction::new_unchecked(&state.connection, TransactionBehavior::Immediate)
        .expect("begin serial max fixture");
    let mut stream =
        load_stream(&transaction, &state.key_bundle, stream_id).expect("load serial max stream");
    stream.rotation_serial = u64::MAX;
    stream.last_rotation_request_digest = Some([0x37; 32]);
    stream.state = PublicationStreamState::NeedsSnapshot;
    update_stream(&transaction, &state.key_bundle, &stream)
        .expect("authenticate serial max fixture");
    transaction.commit().expect("commit serial max fixture");
    assert!(matches!(
        rotate_publication_stream(
            &mut state,
            &config,
            RotatePublicationStreamRequest {
                publication_stream_id: stream_id,
                expected_generation: generation,
            },
            2,
        ),
        Err(RuntimeStoreError::PublicationMismatch)
    ));
    assert_eq!(
        load_stream(&state.connection, &state.key_bundle, stream_id)
            .expect("serial remains authenticated")
            .rotation_serial,
        u64::MAX
    );
    drop(state);
    let _ = fs::remove_dir_all(root);
}

#[test]
fn rollover_requires_authenticated_ready_snapshot_covering_committed_inner() {
    let (root, keys, config, mut state) =
        open_reopenable_publication_test_store("rollover-snapshot");
    create_catalog_entry(&mut state, &config, 0x30);
    let conversation_id = create_catalog_entry(&mut state, &config, 0x31);
    let conversation = super::super::journal::load_conversation(
        &state.connection,
        &state.key_bundle,
        state.database_id,
        conversation_id,
    )
    .expect("load authenticated catalog conversation");
    let catalog_delta = super::super::catalog::load_delta(
        &state.connection,
        &state.key_bundle.read_only_capability(),
        state.database_id,
        &encode_sequence(conversation.catalog_revision),
    )
    .expect("load immutable catalog delta");
    let preflight_request = SharedPublicationPreflightRequest {
        publication_id: [0x38; 16],
        scope: PublicationScope::Catalog,
        inner_after: conversation.catalog_revision.checked_sub(1),
        inner_through: Some(conversation.catalog_revision),
        payload_kind: PublicationPayloadKind::Catalog,
        journal_identity: SharedJournalIdentity::CatalogRange,
        canonical_item_bytes: serde_json::to_vec(
            &agentdeck_protocol::runtime::RuntimeStreamItem::CatalogDelta(catalog_delta),
        )
        .expect("encode canonical catalog item"),
    };
    let stream_id = [0x32; 16];
    let generation = [0x33; 16];
    create_publication_stream(
        &mut state,
        &config,
        stream_id,
        PublicationScope::Catalog,
        [0x34; 16],
        generation,
        1,
    )
    .expect("create catalog publication stream");
    let limits = PublicationLimits {
        rows_per_stream: 1,
        bytes_per_stream: MAX_PUBLICATION_BYTES_PER_STREAM,
        rows_global: MAX_PUBLICATION_ROWS_GLOBAL,
        bytes_global: MAX_PUBLICATION_BYTES_GLOBAL,
    };
    let frozen = freeze_publication_with_limits(
        &mut state,
        &config,
        FreezePublicationRequest {
            publication_id: [0x35; 16],
            publication_stream_id: stream_id,
            generation,
            counter_scope_token: [0x36; 32],
            sender_counter: 1,
            inner_after: None,
            inner_through: Some(conversation.catalog_revision),
            payload_kind: PublicationPayloadKind::Catalog,
            blob: b"catalog-through-h".to_vec(),
        },
        2,
        limits,
    )
    .expect("freeze catalog through authenticated H");
    assert!(matches!(
        freeze_publication_with_limits(
            &mut state,
            &config,
            FreezePublicationRequest {
                publication_id: [0x37; 16],
                publication_stream_id: stream_id,
                generation,
                counter_scope_token: [0x36; 32],
                sender_counter: 2,
                inner_after: Some(conversation.catalog_revision),
                inner_through: Some(conversation.catalog_revision + 1),
                payload_kind: PublicationPayloadKind::Catalog,
                blob: b"catalog-after-h".to_vec(),
            },
            3,
            limits,
        ),
        Err(RuntimeStoreError::PublicationNeedsSnapshot)
    ));
    acknowledge_publication_commit(
        &mut state,
        &config,
        stream_id,
        generation,
        frozen.stream_seq,
        frozen.blob_sha256,
        4,
    )
    .expect("commit catalog publication");
    acknowledge_publication_delivery(
        &mut state,
        &config,
        stream_id,
        generation,
        frozen.stream_seq,
        frozen.blob_sha256,
        5,
    )
    .expect("ack catalog publication");
    let rotation = RotatePublicationStreamRequest {
        publication_stream_id: stream_id,
        expected_generation: generation,
    };
    assert_eq!(
        preflight_shared_publication(
            &mut state,
            &config,
            &preflight_request,
            SharedPublicationStreamProposal {
                publication_stream_id: [0x39; 16],
                stream_route: [0x3a; 16],
                generation: [0x3b; 16],
            },
            6,
        )
        .expect("NeedsSnapshot must remain a typed preflight outcome"),
        SharedPublicationPreflight::RotationRequired(rotation),
        "preflight must return the exact existing stream identity instead of creating a new stream",
    );
    assert!(matches!(
        load_optional_stream(&state.connection, &state.key_bundle, [0x39; 16]),
        Ok(None)
    ));
    assert!(matches!(
        rotate_publication_stream(&mut state, &config, rotation, 6),
        Err(RuntimeStoreError::PublicationNeedsSnapshot)
    ));
    let stale_snapshot = super::super::snapshot::refresh_catalog_snapshot(
        &mut state,
        &config,
        None,
        agentdeck_protocol::runtime::StreamCursor::At(0),
    )
    .expect("materialize authenticated catalog snapshot through revision zero");
    assert!(matches!(
        rotate_publication_stream(&mut state, &config, rotation, 6),
        Err(RuntimeStoreError::PublicationNeedsSnapshot)
    ));
    super::super::snapshot::refresh_catalog_snapshot(
        &mut state,
        &config,
        Some(&stale_snapshot),
        agentdeck_protocol::runtime::StreamCursor::At(conversation.catalog_revision),
    )
    .expect("advance authenticated catalog snapshot through exact H");
    let rotated = rotate_publication_stream(&mut state, &config, rotation, 6)
        .expect("covered rollover succeeds");
    assert_ne!(rotated.generation, generation);
    assert_eq!(rotated.rotation_serial, 1);
    assert_eq!(rotated.reserved_high_water, None);
    assert_eq!(rotated.committed_high_water, None);
    assert_eq!(rotated.acknowledged_high_water, None);
    assert_eq!(
        rotated.committed_inner_cursor,
        Some(conversation.catalog_revision)
    );
    assert_eq!(
        rotated.acknowledged_inner_cursor,
        Some(conversation.catalog_revision)
    );

    drop(state);
    let kek = load_or_create_storage_kek(&keys, &root.join("key-state.db"))
        .expect("reload rollover continuity KEK");
    let mut reopened = super::super::sqlite::open(&config, kek)
        .expect("restart authenticates BeforeFirst/H rotation baseline");
    let persisted = load_stream(&reopened.connection, &reopened.key_bundle, stream_id)
        .expect("load restarted rotation baseline");
    assert_eq!(persisted.reserved_high_water, None);
    assert_eq!(persisted.committed_high_water, None);
    assert_eq!(persisted.acknowledged_high_water, None);
    assert_eq!(
        persisted.committed_inner_cursor,
        Some(conversation.catalog_revision)
    );
    assert_eq!(
        persisted.acknowledged_inner_cursor,
        Some(conversation.catalog_revision)
    );
    let continued = freeze_publication(
        &mut reopened,
        &config,
        FreezePublicationRequest {
            publication_id: [0x3c; 16],
            publication_stream_id: stream_id,
            generation: persisted.generation,
            counter_scope_token: [0x36; 32],
            sender_counter: 2,
            inner_after: Some(conversation.catalog_revision),
            inner_through: Some(conversation.catalog_revision + 1),
            payload_kind: PublicationPayloadKind::Catalog,
            blob: b"catalog-h-plus-one-after-restart".to_vec(),
        },
        7,
    )
    .expect("new generation continues at outer zero and inner H + 1");
    assert_eq!(continued.stream_seq, 0);
    assert_eq!(continued.inner_after, Some(conversation.catalog_revision));
    assert_eq!(
        continued.inner_through,
        Some(conversation.catalog_revision + 1)
    );
    drop(reopened);
    let _ = fs::remove_dir_all(root);
}

#[test]
fn conversation_rollover_preserves_authenticated_inner_cut_across_restart() {
    let (root, keys, config, mut state) =
        open_reopenable_publication_test_store("conversation-rollover-inner-cut");
    let conversation_id = create_catalog_entry(&mut state, &config, 0x4a);
    configure_managed_conversation_with_event_zero(&mut state, &config, conversation_id, 0x4b);
    let mapping = load_conversation_publication_mapping(
        &state.connection,
        &state.key_bundle,
        state.database_id,
        conversation_id,
    )
    .expect("load authenticated conversation publication mapping");
    let now_ms = config.clock.now_ms().expect("conversation rollover clock");
    let limits = PublicationLimits {
        rows_per_stream: 1,
        bytes_per_stream: MAX_PUBLICATION_BYTES_PER_STREAM,
        rows_global: MAX_PUBLICATION_ROWS_GLOBAL,
        bytes_global: MAX_PUBLICATION_BYTES_GLOBAL,
    };
    let frozen = freeze_publication_with_limits(
        &mut state,
        &config,
        FreezePublicationRequest {
            publication_id: [0x4c; 16],
            publication_stream_id: mapping.publication_stream_id,
            generation: mapping.generation,
            counter_scope_token: [0x4d; 32],
            sender_counter: 1,
            inner_after: None,
            inner_through: Some(0),
            payload_kind: PublicationPayloadKind::Event,
            blob: b"conversation-event-zero".to_vec(),
        },
        now_ms,
        limits,
    )
    .expect("freeze conversation event zero");
    assert!(matches!(
        freeze_publication_with_limits(
            &mut state,
            &config,
            FreezePublicationRequest {
                publication_id: [0x4e; 16],
                publication_stream_id: mapping.publication_stream_id,
                generation: mapping.generation,
                counter_scope_token: [0x4d; 32],
                sender_counter: 2,
                inner_after: Some(0),
                inner_through: Some(1),
                payload_kind: PublicationPayloadKind::Event,
                blob: b"conversation-event-one".to_vec(),
            },
            now_ms + 1,
            limits,
        ),
        Err(RuntimeStoreError::PublicationNeedsSnapshot)
    ));
    acknowledge_publication_commit(
        &mut state,
        &config,
        mapping.publication_stream_id,
        mapping.generation,
        frozen.stream_seq,
        frozen.blob_sha256,
        now_ms + 2,
    )
    .expect("commit conversation event zero");
    acknowledge_publication_delivery(
        &mut state,
        &config,
        mapping.publication_stream_id,
        mapping.generation,
        frozen.stream_seq,
        frozen.blob_sha256,
        now_ms + 3,
    )
    .expect("ack conversation event zero");
    let rotation = RotatePublicationStreamRequest {
        publication_stream_id: mapping.publication_stream_id,
        expected_generation: mapping.generation,
    };
    assert!(matches!(
        rotate_publication_stream(&mut state, &config, rotation, now_ms + 4),
        Err(RuntimeStoreError::PublicationNeedsSnapshot)
    ));
    store_ready_conversation_snapshot_at_zero(&mut state, &config, conversation_id, now_ms + 5);
    let rotated = rotate_publication_stream(&mut state, &config, rotation, now_ms + 6)
        .expect("rotate conversation from authenticated snapshot H");
    assert_eq!(rotated.reserved_high_water, None);
    assert_eq!(rotated.committed_high_water, None);
    assert_eq!(rotated.acknowledged_high_water, None);
    assert_eq!(rotated.committed_inner_cursor, Some(0));
    assert_eq!(rotated.acknowledged_inner_cursor, Some(0));

    drop(state);
    let kek = load_or_create_storage_kek(&keys, &root.join("key-state.db"))
        .expect("reload conversation rollover KEK");
    let mut reopened = super::super::sqlite::open(&config, kek)
        .expect("restart authenticates conversation BeforeFirst/H baseline");
    let persisted = load_stream(
        &reopened.connection,
        &reopened.key_bundle,
        mapping.publication_stream_id,
    )
    .expect("load restarted conversation rotation baseline");
    assert_eq!(persisted.reserved_high_water, None);
    assert_eq!(persisted.committed_high_water, None);
    assert_eq!(persisted.acknowledged_high_water, None);
    assert_eq!(persisted.committed_inner_cursor, Some(0));
    assert_eq!(persisted.acknowledged_inner_cursor, Some(0));
    let continued = freeze_publication(
        &mut reopened,
        &config,
        FreezePublicationRequest {
            publication_id: [0x4f; 16],
            publication_stream_id: mapping.publication_stream_id,
            generation: persisted.generation,
            counter_scope_token: [0x4d; 32],
            sender_counter: 2,
            inner_after: Some(0),
            inner_through: Some(1),
            payload_kind: PublicationPayloadKind::Event,
            blob: b"conversation-h-plus-one-after-restart".to_vec(),
        },
        now_ms + 7,
    )
    .expect("new conversation generation continues at outer zero and inner H + 1");
    assert_eq!(continued.stream_seq, 0);
    assert_eq!(continued.inner_after, Some(0));
    assert_eq!(continued.inner_through, Some(1));
    drop(reopened);
    let _ = fs::remove_dir_all(root);
}

#[test]
fn max_sequence_is_never_frozen_and_max_minus_one_rolls_over_without_wrapping() {
    let (root, config, mut state) = open_publication_test_store("rollover-u64-max");
    let stream_id = [0x41; 16];
    let generation = [0x42; 16];
    create_publication_stream(
        &mut state,
        &config,
        stream_id,
        PublicationScope::Catalog,
        [0x43; 16],
        generation,
        1,
    )
    .expect("create max-sequence stream");
    let transaction = Transaction::new_unchecked(&state.connection, TransactionBehavior::Immediate)
        .expect("begin max-sequence fixture");
    let mut stream =
        load_stream(&transaction, &state.key_bundle, stream_id).expect("load max-sequence stream");
    stream.counter_scope_token = Some([0x44; 32]);
    stream.sender_counter_high_water = Some(40);
    stream.reserved_high_water = Some(u64::MAX - 2);
    stream.committed_high_water = Some(u64::MAX - 2);
    stream.last_committed_blob_hash = Some([0x45; 32]);
    stream.acknowledged_high_water = Some(u64::MAX - 2);
    stream.last_acknowledged_blob_hash = Some([0x45; 32]);
    update_stream(&transaction, &state.key_bundle, &stream)
        .expect("install authenticated max-sequence fixture");
    transaction.commit().expect("commit max-sequence fixture");

    let publication_id = [0x46; 16];
    let request = FreezePublicationRequest {
        publication_id,
        publication_stream_id: stream_id,
        generation,
        counter_scope_token: [0x44; 32],
        sender_counter: 41,
        inner_after: None,
        inner_through: None,
        payload_kind: PublicationPayloadKind::Control,
        blob: b"terminal-sequence".to_vec(),
    };
    let frozen = freeze_publication(&mut state, &config, request.clone(), 2)
        .expect("reserve u64::MAX - 1 as the last Relay-compatible sequence");
    assert_eq!(frozen.stream_seq, u64::MAX - 1);
    acknowledge_publication_commit(
        &mut state,
        &config,
        stream_id,
        generation,
        u64::MAX - 1,
        frozen.blob_sha256,
        3,
    )
    .expect("commit terminal sequence");
    acknowledge_publication_delivery(
        &mut state,
        &config,
        stream_id,
        generation,
        u64::MAX - 1,
        frozen.blob_sha256,
        4,
    )
    .expect("ack terminal sequence");
    assert!(matches!(
        freeze_publication(
            &mut state,
            &config,
            FreezePublicationRequest {
                publication_id: [0x48; 16],
                publication_stream_id: stream_id,
                generation,
                counter_scope_token: [0x44; 32],
                sender_counter: 42,
                inner_after: None,
                inner_through: None,
                payload_kind: PublicationPayloadKind::Control,
                blob: b"u64-max-must-never-freeze".to_vec(),
            },
            5,
        ),
        Err(RuntimeStoreError::PublicationNeedsSnapshot)
    ));
    let terminal = load_stream(&state.connection, &state.key_bundle, stream_id)
        .expect("load sequence-exhausted stream");
    assert_eq!(terminal.reserved_high_water, Some(u64::MAX - 1));
    assert_eq!(terminal.sender_counter_high_water, Some(41));
    assert_eq!(terminal.state, PublicationStreamState::NeedsSnapshot);
    assert!(matches!(
        load_outbox_by_stream_seq(
            &state.connection,
            &state.key_bundle,
            state.database_id,
            stream_id,
            generation,
            u64::MAX,
        ),
        Err(RuntimeStoreError::PublicationMismatch)
    ));
    let rotated = rotate_publication_stream(
        &mut state,
        &config,
        RotatePublicationStreamRequest {
            publication_stream_id: stream_id,
            expected_generation: generation,
        },
        6,
    )
    .expect("roll over terminal sequence without wrapping");
    assert!(rotated.reserved_high_water.is_none());
    assert_eq!(rotated.rotation_serial, 1);
    assert_eq!(rotated.sender_counter_high_water, Some(41));
    assert_eq!(
        rotated.last_acknowledged_publication_id,
        Some(publication_id)
    );
    assert!(matches!(
        freeze_publication(&mut state, &config, request, 7),
        Err(RuntimeStoreError::PublicationAlreadyAcknowledged)
    ));
    let continued = freeze_publication(
        &mut state,
        &config,
        FreezePublicationRequest {
            publication_id: [0x47; 16],
            publication_stream_id: stream_id,
            generation: rotated.generation,
            counter_scope_token: [0x44; 32],
            sender_counter: 42,
            inner_after: None,
            inner_through: None,
            payload_kind: PublicationPayloadKind::Control,
            blob: b"continued-after-outer-rollover".to_vec(),
        },
        7,
    )
    .expect("outer rollover keeps the unexhausted counter scope usable");
    assert_eq!(continued.stream_seq, 0);
    assert_eq!(continued.sender_counter, 42);

    state
        .connection
        .execute(
            "UPDATE publication_streams
                 SET last_acknowledged_request_digest = zeroblob(32)
                 WHERE publication_stream_id = ?1",
            [&stream_id[..]],
        )
        .expect("tamper ACK tombstone digest without its token");
    assert!(matches!(
        load_stream(&state.connection, &state.key_bundle, stream_id),
        Err(RuntimeStoreError::UnknownOrCorruptSchema)
    ));
    drop(state);
    let _ = fs::remove_dir_all(root);
}

#[test]
fn legacy_active_max_minus_one_signed_stream_fails_before_sealer_or_counter_write() {
    let (root, config, mut state) = open_publication_test_store("signed-max-sequence");
    let stream_id = [0x51; 16];
    let generation = [0x52; 16];
    create_publication_stream(
        &mut state,
        &config,
        stream_id,
        PublicationScope::Catalog,
        [0x53; 16],
        generation,
        1,
    )
    .expect("create signed max-sequence stream");
    let transaction = Transaction::new_unchecked(&state.connection, TransactionBehavior::Immediate)
        .expect("begin signed max-sequence fixture");
    let mut stream = load_stream(&transaction, &state.key_bundle, stream_id)
        .expect("load signed max-sequence stream");
    stream.reserved_high_water = Some(LAST_RELAY_STREAM_SEQ);
    stream.committed_high_water = Some(LAST_RELAY_STREAM_SEQ);
    stream.last_committed_blob_hash = Some([0x54; 32]);
    stream.acknowledged_high_water = Some(LAST_RELAY_STREAM_SEQ);
    stream.last_acknowledged_blob_hash = Some([0x54; 32]);
    update_stream(&transaction, &state.key_bundle, &stream)
        .expect("install authenticated legacy active MAX - 1 fixture");
    transaction
        .commit()
        .expect("commit legacy active MAX - 1 fixture");

    let scope_token = [0x55; 32];
    let key_id = agentdeck_protocol::e2ee::KeyId {
        purpose: agentdeck_protocol::e2ee::KeyPurpose::Catalog,
        epoch: 1,
    };
    let genesis = super::super::remote_counter::load_record(&state, scope_token, key_id)
        .expect("load counter genesis");
    let publication_id = [0x56; 16];
    let seal_calls = Arc::new(AtomicUsize::new(0));
    let result = freeze_signed_publication(
        &mut state,
        &config,
        FreezeSignedPublicationRequest {
            publication_id,
            publication_stream_id: stream_id,
            generation,
            counter: super::super::remote_counter::RemoteCounterReservation {
                scope_token,
                key_id,
                previous_reserved_end: 0,
                reserved_end: 1_024,
                previous_db_anchor: genesis.db_anchor,
                reservation_id: [0x57; 16],
                publication_id,
            },
            inner_after: None,
            inner_through: None,
            payload_kind: PublicationPayloadKind::Control,
            shared_binding: None,
            sealer_retained_bytes: 0,
            sealer: Box::new({
                let seal_calls = Arc::clone(&seal_calls);
                move |_axes| {
                    seal_calls.fetch_add(1, Ordering::SeqCst);
                    Ok(b"must-not-seal-max".to_vec())
                }
            }),
        },
        2,
    );
    assert!(matches!(
        result,
        Err(RuntimeStoreError::PublicationNeedsSnapshot)
    ));
    assert_eq!(seal_calls.load(Ordering::SeqCst), 0);
    let exhausted = load_stream(&state.connection, &state.key_bundle, stream_id)
        .expect("load exhausted signed stream");
    assert_eq!(exhausted.state, PublicationStreamState::NeedsSnapshot);
    assert_eq!(exhausted.reserved_high_water, Some(LAST_RELAY_STREAM_SEQ));
    assert_eq!(exhausted.sender_counter_high_water, None);
    assert_eq!(
        super::super::remote_counter::load_record(&state, scope_token, key_id)
            .expect("counter remains readable")
            .kind,
        super::super::remote_counter::RemoteCounterRecordKind::Genesis
    );
    drop(state);
    let _ = fs::remove_dir_all(root);
}

#[test]
fn exhausted_sender_counter_rejects_rollover_and_stays_needs_snapshot() {
    let (root, config, mut state) = open_publication_test_store("counter-u64-max");
    let stream_id = [0x49; 16];
    let generation = [0x4a; 16];
    create_publication_stream(
        &mut state,
        &config,
        stream_id,
        PublicationScope::Catalog,
        [0x4b; 16],
        generation,
        1,
    )
    .expect("create counter exhaustion stream");
    let frozen = freeze_publication(
        &mut state,
        &config,
        FreezePublicationRequest {
            publication_id: [0x4c; 16],
            publication_stream_id: stream_id,
            generation,
            counter_scope_token: [0x4d; 32],
            sender_counter: u64::MAX,
            inner_after: None,
            inner_through: None,
            payload_kind: PublicationPayloadKind::Control,
            blob: b"counter-terminal".to_vec(),
        },
        2,
    )
    .expect("freeze the terminal sender counter exactly once");
    acknowledge_publication_commit(
        &mut state,
        &config,
        stream_id,
        generation,
        frozen.stream_seq,
        frozen.blob_sha256,
        3,
    )
    .expect("commit terminal counter publication");
    acknowledge_publication_delivery(
        &mut state,
        &config,
        stream_id,
        generation,
        frozen.stream_seq,
        frozen.blob_sha256,
        4,
    )
    .expect("ack terminal counter publication");
    assert!(matches!(
        rotate_publication_stream(
            &mut state,
            &config,
            RotatePublicationStreamRequest {
                publication_stream_id: stream_id,
                expected_generation: generation,
            },
            5,
        ),
        Err(RuntimeStoreError::PublicationCounterExhausted)
    ));
    let persisted = load_stream(&state.connection, &state.key_bundle, stream_id)
        .expect("load counter-exhausted stream");
    assert_eq!(persisted.generation, generation);
    assert_eq!(persisted.rotation_serial, 0);
    assert_eq!(persisted.sender_counter_high_water, Some(u64::MAX));
    assert_eq!(persisted.state, PublicationStreamState::NeedsSnapshot);
    drop(state);
    let _ = fs::remove_dir_all(root);
}

#[tokio::test]
async fn snapshot_and_outbox_retained_memory_stay_within_global_budgets() {
    use crate::runtime::read_pool::{
        MAX_RUNTIME_READ_RETAINED_BYTES, MAX_RUNTIME_READ_SNAPSHOT_BYTES, ReadPool, ReadPoolError,
    };

    assert_eq!(MAX_RUNTIME_READ_RETAINED_BYTES, 128 * 1024 * 1024);
    assert_eq!(MAX_RUNTIME_READ_SNAPSHOT_BYTES, 128 * 1024 * 1024);
    assert_eq!(
        super::super::snapshot::MAX_SNAPSHOT_BYTES_GLOBAL,
        512 * 1024 * 1024
    );
    assert_eq!(MAX_PUBLICATION_BYTES_GLOBAL, 512 * 1024 * 1024);

    let (root, config, mut state) = open_publication_test_store("retained-global-budgets");
    let stream_id = [0x91; 16];
    let generation = [0x92; 16];
    create_publication_stream(
        &mut state,
        &config,
        stream_id,
        PublicationScope::Catalog,
        [0x93; 16],
        generation,
        1,
    )
    .expect("create budget publication stream through production admission");
    assert_eq!(
        state.admission_state,
        super::super::admission::RuntimeAdmissionState::Normal
    );

    let scaled_limits = PublicationLimits {
        rows_per_stream: 8,
        bytes_per_stream: 8,
        rows_global: 8,
        bytes_global: 1,
    };
    let first_request = FreezePublicationRequest {
        publication_id: [0x94; 16],
        publication_stream_id: stream_id,
        generation,
        counter_scope_token: [0x95; 32],
        sender_counter: 1,
        inner_after: None,
        inner_through: Some(0),
        payload_kind: PublicationPayloadKind::Catalog,
        blob: vec![0x96],
    };
    let first =
        freeze_publication_with_limits(&mut state, &config, first_request, 2, scaled_limits)
            .expect("freeze one-byte outbox row through production admission");
    let after_first = super::super::sqlite::load_runtime_ledger(
        &state.connection,
        &state.key_bundle,
        state.database_id,
    )
    .expect("load authenticated ledger after first outbox row");
    assert_eq!(after_first.publication_outbox_count, 1);
    assert_eq!(after_first.publication_outbox_bytes, 1);

    let rejected = freeze_publication_with_limits(
        &mut state,
        &config,
        FreezePublicationRequest {
            publication_id: [0x97; 16],
            publication_stream_id: stream_id,
            generation,
            counter_scope_token: [0x95; 32],
            sender_counter: 2,
            inner_after: Some(0),
            inner_through: Some(1),
            payload_kind: PublicationPayloadKind::Catalog,
            blob: vec![0x98],
        },
        3,
        scaled_limits,
    )
    .expect_err("scaled global byte cap must reject the second retained row");
    assert!(matches!(
        rejected,
        RuntimeStoreError::PublicationNeedsSnapshot
    ));
    let after_rejection = super::super::sqlite::load_runtime_ledger(
        &state.connection,
        &state.key_bundle,
        state.database_id,
    )
    .expect("load authenticated ledger after budget rejection");
    assert_eq!(after_rejection.publication_outbox_count, 1);
    assert_eq!(after_rejection.publication_outbox_bytes, 1);
    assert_eq!(
        load_pending_publications(&state, stream_id).expect("load retained unacked row"),
        [first],
        "budget rejection must not evict the existing unacked publication"
    );

    // `run_sqlite_snapshot` 是 production snapshot retained-memory seam：第一份
    // handoff lease 存活期间必须占满 128 MiB 全池，第二份不能绕过全局预算。
    let pool = ReadPool::open_sqlite(&state.storage_path, 2, config.busy_timeout_ms)
        .expect("open production read-only WAL pool");
    let retained = pool
        .run_sqlite_snapshot(|connection| {
            connection
                .query_row("SELECT COUNT(*) FROM publication_outbox", [], |row| {
                    row.get::<_, i64>(0)
                })
                .map_err(ReadPoolError::from)
        })
        .await
        .expect("acquire full snapshot retained-memory lease");
    let (visible_outbox_rows, lease) = retained.into_parts();
    assert_eq!(visible_outbox_rows, 1);
    assert!(matches!(
        pool.run_sqlite_snapshot(|_| Ok(())).await,
        Err(ReadPoolError::Busy)
    ));
    drop(lease);
    let released = pool
        .run_sqlite_snapshot(|_| Ok(()))
        .await
        .expect("dropping the first lease returns the full snapshot budget");
    drop(released);
    pool.close_and_wait().await;

    drop(state);
    let _ = fs::remove_dir_all(root);
}
