use super::*;

use std::fmt::Write as _;
use std::fs;
use std::os::unix::fs::PermissionsExt;

use crate::runtime::store::{RUNTIME_CRYPTO_CONTEXT_VERSION, RUNTIME_SCHEMA_VERSION};
use crate::security::{
    KeyStore, MemoryKeyStore, STORAGE_KEK_ACCOUNT, SecretBytes, load_or_create_storage_kek,
};
use agentdeck_protocol::runtime::CatalogChange;
use rusqlite::{Connection, OpenFlags, params};
use sha2::{Digest, Sha256};

#[derive(Debug, Eq, PartialEq)]
struct CipherManifest {
    wrapped_key_bundle_sha256: [u8; 32],
    runtime_meta_sha256: [u8; 32],
    catalog_delta_ciphertext_sha256: [u8; 32],
    catalog_delta_manifest_sha256: [u8; 32],
    catalog_snapshot_ciphertext_sha256: [u8; 32],
    catalog_snapshot_manifest_sha256: [u8; 32],
    conversation_snapshot_ciphertext_sha256: [u8; 32],
    conversation_snapshot_manifest_sha256: [u8; 32],
}

impl CipherManifest {
    fn logical_sha256(&self) -> [u8; 32] {
        let mut hash = Sha256::new();
        for value in [
            self.wrapped_key_bundle_sha256,
            self.runtime_meta_sha256,
            self.catalog_delta_ciphertext_sha256,
            self.catalog_delta_manifest_sha256,
            self.catalog_snapshot_ciphertext_sha256,
            self.catalog_snapshot_manifest_sha256,
            self.conversation_snapshot_ciphertext_sha256,
            self.conversation_snapshot_manifest_sha256,
        ] {
            hash.update(value);
        }
        hash.finalize().into()
    }

    fn immutable_sha256(&self) -> [u8; 32] {
        let mut hash = Sha256::new();
        for value in [
            self.wrapped_key_bundle_sha256,
            self.catalog_delta_ciphertext_sha256,
            self.catalog_delta_manifest_sha256,
            self.catalog_snapshot_ciphertext_sha256,
            self.catalog_snapshot_manifest_sha256,
            self.conversation_snapshot_ciphertext_sha256,
            self.conversation_snapshot_manifest_sha256,
        ] {
            hash.update(value);
        }
        hash.finalize().into()
    }
}

fn update_field(hash: &mut Sha256, value: &[u8]) {
    hash.update((value.len() as u64).to_be_bytes());
    hash.update(value);
}

fn snapshot_manifest(connection: &Connection, scope: &str) -> ([u8; 32], [u8; 32]) {
    let mut ciphertext = Sha256::new();
    let mut manifest = Sha256::new();
    let mut count = 0_u64;
    let mut statement = connection
        .prepare(
            "SELECT snapshot_id, content_sha256, sealed_snapshot_sha256,
                    metadata_token, sealed_snapshot
             FROM snapshots WHERE target_scope = ?1 ORDER BY snapshot_id",
        )
        .unwrap();
    let rows = statement
        .query_map(params![scope], |row| {
            Ok((
                row.get::<_, Vec<u8>>(0)?,
                row.get::<_, Vec<u8>>(1)?,
                row.get::<_, Vec<u8>>(2)?,
                row.get::<_, Vec<u8>>(3)?,
                row.get::<_, Vec<u8>>(4)?,
            ))
        })
        .unwrap();
    for row in rows {
        let (id, content, sealed_hash, token, sealed) = row.unwrap();
        update_field(&mut ciphertext, &sealed);
        for value in [&id, &content, &sealed_hash, &token, &sealed] {
            update_field(&mut manifest, value);
        }
        count += 1;
    }
    assert_eq!(count, 1, "expected one {scope} snapshot row");
    update_field(&mut ciphertext, &count.to_be_bytes());
    update_field(&mut manifest, &count.to_be_bytes());
    (ciphertext.finalize().into(), manifest.finalize().into())
}

fn cipher_manifest(database: &Path, expected_schema_version: u32) -> CipherManifest {
    let connection = Connection::open_with_flags(
        database,
        OpenFlags::SQLITE_OPEN_READ_ONLY | OpenFlags::SQLITE_OPEN_NO_MUTEX,
    )
    .expect("open v4 database read-only");
    let (schema_version, wrapped, runtime_token): (u32, Vec<u8>, Vec<u8>) = connection
        .query_row(
            "SELECT schema_version, wrapped_key_bundle, metadata_token
             FROM runtime_meta WHERE singleton = 1",
            [],
            |row| Ok((row.get(0)?, row.get(1)?, row.get(2)?)),
        )
        .expect("read runtime_meta secrets-as-ciphertext");
    assert_eq!(schema_version, expected_schema_version);
    let mut runtime_meta = Sha256::new();
    update_field(&mut runtime_meta, &wrapped);
    update_field(&mut runtime_meta, &runtime_token);

    let mut catalog_ciphertext = Sha256::new();
    let mut catalog_manifest = Sha256::new();
    let mut catalog_count = 0_u64;
    let mut statement = connection
        .prepare(
            "SELECT catalog_revision, metadata_token, sealed_delta
             FROM catalog_journal ORDER BY catalog_revision",
        )
        .unwrap();
    let rows = statement
        .query_map([], |row| {
            Ok((
                row.get::<_, String>(0)?,
                row.get::<_, Vec<u8>>(1)?,
                row.get::<_, Vec<u8>>(2)?,
            ))
        })
        .unwrap();
    for row in rows {
        let (revision, token, sealed) = row.unwrap();
        update_field(&mut catalog_ciphertext, &sealed);
        update_field(&mut catalog_manifest, revision.as_bytes());
        update_field(&mut catalog_manifest, &token);
        update_field(&mut catalog_manifest, &sealed);
        catalog_count += 1;
    }
    assert_eq!(catalog_count, 1);
    update_field(&mut catalog_ciphertext, &catalog_count.to_be_bytes());
    update_field(&mut catalog_manifest, &catalog_count.to_be_bytes());

    let (catalog_snapshot_ciphertext, catalog_snapshot_manifest) =
        snapshot_manifest(&connection, "catalog");
    let (conversation_snapshot_ciphertext, conversation_snapshot_manifest) =
        snapshot_manifest(&connection, "conversation");
    CipherManifest {
        wrapped_key_bundle_sha256: Sha256::digest(&wrapped).into(),
        runtime_meta_sha256: runtime_meta.finalize().into(),
        catalog_delta_ciphertext_sha256: catalog_ciphertext.finalize().into(),
        catalog_delta_manifest_sha256: catalog_manifest.finalize().into(),
        catalog_snapshot_ciphertext_sha256: catalog_snapshot_ciphertext,
        catalog_snapshot_manifest_sha256: catalog_snapshot_manifest,
        conversation_snapshot_ciphertext_sha256: conversation_snapshot_ciphertext,
        conversation_snapshot_manifest_sha256: conversation_snapshot_manifest,
    }
}

fn hex(bytes: &[u8]) -> String {
    let mut output = String::with_capacity(bytes.len() * 2);
    for byte in bytes {
        write!(&mut output, "{byte:02x}").unwrap();
    }
    output
}

fn assert_no_private_handle(bytes: &[u8]) {
    assert!(
        !bytes
            .windows(b"adapterStateKey".len())
            .any(|window| window == b"adapterStateKey")
    );
}

#[tokio::test]
#[ignore = "A1a2 manual real-writer gate; requires AGENTDECK_A1A2_FIXTURE_DIR"]
async fn reads_runtime_v1_v4_sample_as_v2_without_rewrite() {
    // 威胁场景：只用合成 JSON 证明 dual-decode 会漏掉真实 v4 AEAD/AAD/token、
    // read-pool lease 与 paced transfer handoff 的组合错误，甚至在 open 时静默 reseal。
    assert_eq!(RUNTIME_PROTOCOL_VERSION, 2);
    assert_eq!(RUNTIME_SCHEMA_VERSION, 6);
    assert_eq!(RUNTIME_CRYPTO_CONTEXT_VERSION, 1);
    let artifact = PathBuf::from(
        std::env::var_os("AGENTDECK_A1A2_FIXTURE_DIR")
            .expect("AGENTDECK_A1A2_FIXTURE_DIR is required"),
    );
    assert_eq!(
        fs::metadata(&artifact).unwrap().permissions().mode() & 0o777,
        0o700
    );
    let database = artifact.join("runtime.db");
    let kek = fs::read(artifact.join("storage-kek.raw")).expect("read temporary legacy KEK");
    assert_eq!(kek.len(), 32);
    let conversation_text = fs::read_to_string(artifact.join("conversation-id.txt"))
        .expect("read legacy conversation id");
    let conversation_id =
        RuntimeId::parse_canonical(RuntimeIdKind::Conversation, conversation_text.trim())
            .expect("parse legacy conversation id");
    let before = cipher_manifest(&database, 4);

    let keys = MemoryKeyStore::new();
    keys.store(STORAGE_KEK_ACCOUNT, &SecretBytes::new(kek))
        .expect("install temporary legacy KEK");
    let storage_kek = load_or_create_storage_kek(&keys, &database).expect("load legacy KEK");
    let store = RuntimeStoreHandle::open(
        crate::runtime::store::RuntimeStoreConfig::new(database.clone())
            .with_command_capacity(1_024),
        storage_kek,
    )
    .await
    .expect("open real Runtime v1/v4 database with current store");

    let raw = store
        .load_conversation_snapshot(conversation_id)
        .await
        .expect("load legacy conversation snapshot")
        .expect("legacy conversation snapshot exists");
    assert!(
        !raw.payload
            .windows(b"configurationState".len())
            .any(|window| window == b"configurationState")
    );
    let legacy_plaintext_sha256: [u8; 32] = Sha256::digest(&raw.payload).into();
    drop(raw);

    let plan = store
        .acquire_backfill_pin(RuntimeBackfillTarget::Catalog, None)
        .await
        .expect("pin legacy catalog delta");
    let RuntimeBackfillPlan::Pinned(pin) = plan else {
        panic!("legacy catalog revision 0 must require a pinned backfill");
    };
    let page = store
        .load_catalog_backfill_page(pin.clone(), None)
        .await
        .expect("dual-decode legacy catalog delta");
    assert_eq!(page.deltas.len(), 1);
    assert_eq!(page.deltas[0].catalog_revision, 0);
    assert_eq!(page.deltas[0].changes.len(), 1);
    let CatalogChange::Upserted { entry } = &page.deltas[0].changes[0] else {
        panic!("legacy start must produce one Upserted delta");
    };
    assert_eq!(entry.entry_revision, 0);
    assert_eq!(entry.conversation_id.as_str(), conversation_text.trim());
    assert_no_private_handle(&serde_json::to_vec(&page.deltas).unwrap());
    let completion = page.completion().clone();
    drop(page);
    store
        .complete_backfill_page(completion)
        .await
        .expect("complete legacy catalog backfill page");
    store
        .release_backfill_pin(pin.pin_id)
        .await
        .expect("release legacy catalog pin");

    let trust_domain = store
        .machine_trust_domain()
        .expect("read machine trust domain");
    let router = Arc::new(AgentRouter::with_runtime_store(store.clone()));
    let core = Arc::new(
        RuntimeCore::new(store.clone(), router, trust_domain)
            .expect("construct read-only compatibility core"),
    );
    core.recover().await.expect("recover compatibility core");
    let (connection, mut receiver) = connect_recording(&core, 0xD3).await;
    core.handle_envelope(
        connection,
        catalog_request_envelope("a1a2-read-v1-catalog-baseline", None),
    )
    .await
    .expect("request legacy catalog baseline");
    let catalog_write = timeout(Duration::from_secs(5), receiver.recv())
        .await
        .expect("legacy catalog reply timeout")
        .expect("legacy catalog reply");
    let catalog = match decode(&catalog_write).body {
        RuntimeMessage::Reply(RuntimeReply::Catalog(snapshot)) => snapshot,
        other => panic!("expected converted legacy Catalog reply, got {other:?}"),
    };
    catalog_write
        .acknowledge()
        .expect("flush legacy Catalog reply");
    wait_catalog_jobs_idle(&core).await;
    assert_eq!(catalog.entries().len(), 1);
    assert_eq!(catalog.entries()[0].entry_revision, 0);
    assert_eq!(
        catalog.entries()[0].conversation_id.as_str(),
        conversation_text.trim()
    );
    assert_no_private_handle(&serde_json::to_vec(&catalog).unwrap());

    core.handle_envelope(
        connection,
        subscribe_conversation_envelope("a1a2-read-v1-snapshot", conversation_id),
    )
    .await
    .expect("subscribe legacy conversation snapshot");
    let receipt = timeout(Duration::from_secs(5), receiver.recv())
        .await
        .expect("subscription receipt timeout")
        .expect("subscription receipt");
    assert!(matches!(
        decode(&receipt).body,
        RuntimeMessage::Reply(RuntimeReply::Subscription(
            SubscriptionReceipt::Subscribed { .. }
        ))
    ));
    receipt.acknowledge().expect("flush subscription receipt");

    let first = timeout(Duration::from_secs(5), receiver.recv())
        .await
        .expect("legacy snapshot first part timeout")
        .expect("legacy snapshot first part");
    let RuntimeMessage::Reply(RuntimeReply::TransferPart(first_part)) = decode(&first).body else {
        panic!("legacy snapshot must use real TransferPart egress");
    };
    assert!(first_part.part_count > 1);
    let part_count = first_part.part_count;
    let mut assembled = Vec::with_capacity(first_part.total_bytes as usize);
    let mut current = Some((first, first_part));
    for expected_index in 0..part_count {
        let (write, part) = if let Some(value) = current.take() {
            value
        } else {
            let write = timeout(Duration::from_secs(5), receiver.recv())
                .await
                .expect("legacy snapshot next part timeout")
                .expect("legacy snapshot next part");
            let RuntimeMessage::Reply(RuntimeReply::TransferPart(part)) = decode(&write).body
            else {
                panic!("SyncComplete overtook legacy snapshot transfer");
            };
            (write, part)
        };
        assert_eq!(part.part_index, expected_index);
        assert_eq!(part.part_count, part_count);
        assembled.extend_from_slice(&part.part);
        assert!(receiver.try_recv().is_err());
        write.acknowledge().expect("flush legacy snapshot part");
    }
    let snapshot: ConversationSnapshot =
        serde_json::from_slice(&assembled).expect("decode converted Runtime v2 snapshot");
    assert_eq!(snapshot.configuration_state.configuration_revision(), 0);
    assert!(snapshot.configuration_state.configuration().is_none());
    assert_no_private_handle(&assembled);
    let v2_snapshot_wire_sha256: [u8; 32] = Sha256::digest(&assembled).into();
    let sync = timeout(Duration::from_secs(5), receiver.recv())
        .await
        .expect("legacy snapshot SyncComplete timeout")
        .expect("legacy snapshot SyncComplete");
    assert!(matches!(
        decode(&sync).body,
        RuntimeMessage::Reply(RuntimeReply::SyncComplete(_))
    ));
    sync.acknowledge()
        .expect("flush legacy snapshot SyncComplete");

    let raw_after = store
        .load_conversation_snapshot(conversation_id)
        .await
        .expect("reload legacy snapshot")
        .expect("legacy snapshot remains stored");
    let legacy_plaintext_after: [u8; 32] = Sha256::digest(&raw_after.payload).into();
    assert_eq!(legacy_plaintext_after, legacy_plaintext_sha256);
    drop(raw_after);
    core.disconnect(connection).await;
    core.shutdown().await.expect("shutdown compatibility core");
    drop(core);
    drop(store);

    let after = cipher_manifest(&database, RUNTIME_SCHEMA_VERSION);
    assert_eq!(
        after.immutable_sha256(),
        before.immutable_sha256(),
        "v4→current v6 migration/readback must not normalize or reseal immutable rows"
    );
    println!(
        "wrapped_key_bundle_sha256={}",
        hex(&before.wrapped_key_bundle_sha256)
    );
    println!(
        "catalog_delta_ciphertext_sha256={}",
        hex(&before.catalog_delta_ciphertext_sha256)
    );
    println!(
        "catalog_snapshot_ciphertext_sha256={}",
        hex(&before.catalog_snapshot_ciphertext_sha256)
    );
    println!(
        "conversation_snapshot_ciphertext_sha256={}",
        hex(&before.conversation_snapshot_ciphertext_sha256)
    );
    println!(
        "legacy_snapshot_plaintext_sha256={}",
        hex(&legacy_plaintext_sha256)
    );
    println!("v2_snapshot_wire_sha256={}", hex(&v2_snapshot_wire_sha256));
    println!("logical_manifest_before={}", hex(&before.logical_sha256()));
    println!("logical_manifest_after={}", hex(&after.logical_sha256()));
}
