use super::*;

use std::fs;
use std::path::PathBuf;

use agentdeck_protocol::AgentKind;
use rusqlite::params;

use crate::runtime::model::{ConversationDescriptor, NewConversation};
use crate::security::{MemoryKeyStore, load_or_create_storage_kek};

#[test]
fn metadata_capacity_exact_boundaries_cover_every_scope() {
    let ledger = RuntimeLedger::default();
    assert!(
        ensure_metadata_mutation_capacity(
            &ledger,
            MAX_METADATA_MUTATIONS_PER_CONVERSATION - 1,
            1,
            false,
        )
        .is_ok()
    );
    assert!(matches!(
        ensure_metadata_mutation_capacity(
            &ledger,
            MAX_METADATA_MUTATIONS_PER_CONVERSATION,
            1,
            false,
        ),
        Err(RuntimeStoreError::MetadataMutationLimit {
            scope: MetadataMutationLimitScope::Conversation
        })
    ));

    let mut global_count = ledger.clone();
    global_count.metadata_mutation_count = MAX_METADATA_MUTATIONS_GLOBAL - 1;
    assert!(ensure_metadata_mutation_capacity(&global_count, 0, 1, false).is_ok());
    global_count.metadata_mutation_count = MAX_METADATA_MUTATIONS_GLOBAL;
    assert!(matches!(
        ensure_metadata_mutation_capacity(&global_count, 0, 1, false),
        Err(RuntimeStoreError::MetadataMutationLimit {
            scope: MetadataMutationLimitScope::GlobalCount
        })
    ));

    let mut charged = ledger.clone();
    charged.metadata_mutation_charged_bytes = MAX_METADATA_MUTATION_CHARGED_BYTES_GLOBAL - 2;
    assert!(ensure_metadata_mutation_capacity(&charged, 0, 2, false).is_ok());
    assert!(matches!(
        ensure_metadata_mutation_capacity(&charged, 0, 3, false),
        Err(RuntimeStoreError::MetadataMutationLimit {
            scope: MetadataMutationLimitScope::GlobalChargedBytes
        })
    ));
    charged.metadata_mutation_charged_bytes = u64::MAX;
    assert!(matches!(
        ensure_metadata_mutation_capacity(&charged, 0, 1, false),
        Err(RuntimeStoreError::MetadataMutationLimit {
            scope: MetadataMutationLimitScope::GlobalChargedBytes
        })
    ));

    let mut active = ledger;
    active.active_metadata_mutation_count = MAX_ACTIVE_METADATA_MUTATIONS - 1;
    assert!(ensure_metadata_mutation_capacity(&active, 0, 1, true).is_ok());
    active.active_metadata_mutation_count = MAX_ACTIVE_METADATA_MUTATIONS;
    assert!(ensure_metadata_mutation_capacity(&active, 0, 1, false).is_ok());
    assert!(matches!(
        ensure_metadata_mutation_capacity(&active, 0, 1, true),
        Err(RuntimeStoreError::MetadataMutationLimit {
            scope: MetadataMutationLimitScope::Active
        })
    ));
}

#[test]
fn native_projected_managed_request_is_unsupported_and_claims_nothing() {
    let root = PathBuf::from(format!(
        "/tmp/agentdeck-metadata-native-origin-{}",
        std::process::id()
    ));
    let _ = fs::remove_dir_all(&root);
    fs::create_dir(&root).expect("create native-origin test root");
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        fs::set_permissions(&root, fs::Permissions::from_mode(0o700))
            .expect("secure native-origin test root");
    }
    let config = RuntimeStoreConfig::new(root.join("runtime.db"));
    let keys = MemoryKeyStore::new();
    let storage_kek = load_or_create_storage_kek(&keys, &root.join("key-state.db"))
        .expect("create native-origin StorageKEK");
    let mut state =
        super::super::sqlite::open(&config, storage_kek).expect("open native-origin sqlite state");
    let conversation_id = RuntimeId::from_bytes(RuntimeIdKind::Conversation, [0x91; 16])
        .expect("native-origin conversation id");
    let input = NewConversation {
        conversation_id,
        adapter_state_key: RuntimeId::from_bytes(RuntimeIdKind::AdapterState, [0x92; 16])
            .expect("native-origin adapter state id"),
        descriptor: ConversationDescriptor {
            agent_kind: AgentKind::ClaudeCode,
            title: Some("native projected".to_owned()),
            cwd: PathBuf::from("/tmp/native-projected"),
        },
    };
    let descriptor = super::super::journal::canonical_conversation_descriptor(&input.descriptor)
        .expect("encode native-origin descriptor");
    let mut effects = CommandStreamEffects::default();
    super::super::journal::create_conversation(
        &mut state,
        &config,
        input,
        descriptor,
        &mut effects,
    )
    .expect("create native-origin conversation");

    let entry_revision = encode_sequence(0);
    let token = super::super::configuration::conversation_state_metadata_token(
        &state.key_bundle,
        conversation_id.as_bytes(),
        None,
        &entry_revision,
        "nativeProjected",
        Some("claude-code"),
        None,
    )
    .expect("authenticate native-projected origin");
    assert_eq!(
        state
            .connection
            .execute(
                "UPDATE conversation_state
                 SET origin_kind = 'nativeProjected', origin_namespace = 'claude-code',
                     metadata_token = ?1 WHERE conversation_id = ?2",
                params![&token[..], &conversation_id.as_bytes()[..]],
            )
            .expect("install authenticated native-projected origin"),
        1
    );
    let prepared = prepare_metadata_mutation_request(UpdateManagedConversationMetadata {
        conversation_id,
        owner: IdempotencyOwner::Local {
            machine_trust_domain: [0x93; 32],
            uid: 501,
            client_installation_id: [0x94; 16],
        },
        idempotency_key: "native-metadata".to_owned(),
        expected_entry_revision: 0,
        mutation: ConversationMetadataMutation::SetArchived { archived: true },
    })
    .expect("prepare native-origin managed request");
    let error = update_managed_conversation_metadata(&mut state, &config, prepared, &mut effects)
        .expect_err("managed writer must not claim native-projected metadata");
    assert!(matches!(
        error,
        RuntimeStoreError::MetadataMutationUnsupported
    ));
    let (physical, ledger): (i64, i64) = state
        .connection
        .query_row(
            "SELECT (SELECT COUNT(*) FROM metadata_mutation_ledger),
                    metadata_mutation_count FROM runtime_meta WHERE singleton = 1",
            [],
            |row| Ok((row.get(0)?, row.get(1)?)),
        )
        .expect("read native-origin zero-claim evidence");
    assert_eq!((physical, ledger), (0, 0));
    drop(state);
    fs::remove_dir_all(root).expect("remove native-origin test root");
}
