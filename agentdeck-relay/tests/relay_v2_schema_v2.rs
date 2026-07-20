//! P4.2 Relay Store schema v2 / required receipt signer focused contract。

use std::collections::BTreeMap;
use std::ffi::OsString;
use std::fs;
use std::path::{Path, PathBuf};

use agentdeck_crypto::{
    SigningKey, ValidatedRelayReceiptSignerIdentityV1, sign_relay_admin_purge_receipt,
};
use agentdeck_protocol::relay_v2::{
    CertRole, Ed25519Signature, LinkGeneration, MachineEnrollmentResponseV1, MachineRouteId,
    PublicKeyBytes, RelayAdminPurgeReceiptV1, RootKeyId, SignedCertificate, TrustEpoch,
    enrollment_receipt_hash,
};
use agentdeck_relay::config::RelayV2ServerConfig;
use agentdeck_relay::v2::store::{
    AdminPurgeCommitRequest, AdminPurgePreparation, EnrollmentCodeSeed, PurgeMachine,
    RegisterMachine, RelayStoreHandle, RelayV2StoreConfig, StoreError,
};
use rusqlite::{Connection, params};
use tempfile::TempDir;

fn signer_identity(seed: u8) -> ValidatedRelayReceiptSignerIdentityV1 {
    ValidatedRelayReceiptSignerIdentityV1::from_signing_key(&SigningKey::from_seed(&[seed; 32]))
        .expect("valid receipt signer identity")
}

fn certificate(role: CertRole, seed: u8) -> SignedCertificate {
    SignedCertificate {
        subject_pubkey: PublicKeyBytes([seed; 32]),
        cert_role: role,
        generation: LinkGeneration::new(1),
        root_key_id: RootKeyId::from_bytes([0x51; 16]),
        trust_epoch: TrustEpoch::new(1),
        not_after_ms: None,
        signature: Ed25519Signature([seed; 64]),
    }
}

fn sidecar(path: &Path, suffix: &str) -> PathBuf {
    let mut value = path.as_os_str().to_os_string();
    value.push(suffix);
    PathBuf::from(value)
}

fn process_lock_path(path: &Path) -> PathBuf {
    let mut name = path
        .file_name()
        .expect("database has a file name")
        .to_os_string();
    name.push(".agentdeck.lock");
    path.with_file_name(name)
}

fn directory_entries(path: &Path) -> Vec<OsString> {
    let mut entries = fs::read_dir(path)
        .expect("read artifact directory")
        .map(|entry| entry.expect("read artifact entry").file_name())
        .collect::<Vec<_>>();
    entries.sort();
    entries
}

#[derive(Debug, PartialEq, Eq)]
struct SqliteArtifacts {
    database: Vec<u8>,
    wal: Option<Vec<u8>>,
    shm: Option<Vec<u8>>,
    directory_entries: Vec<OsString>,
}

fn sqlite_artifacts(path: &Path) -> SqliteArtifacts {
    SqliteArtifacts {
        database: fs::read(path).expect("read SQLite database"),
        wal: fs::read(sidecar(path, "-wal")).ok(),
        shm: fs::read(sidecar(path, "-shm")).ok(),
        directory_entries: directory_entries(path.parent().expect("database parent")),
    }
}

async fn create_signed_purge_fixture(
    path: &Path,
    signer_seed: u8,
    route_seed: u8,
) -> (
    ValidatedRelayReceiptSignerIdentityV1,
    MachineRouteId,
    RelayAdminPurgeReceiptV1,
) {
    let signing_key = SigningKey::from_seed(&[signer_seed; 32]);
    let identity = ValidatedRelayReceiptSignerIdentityV1::from_signing_key(&signing_key)
        .expect("valid signed-purge fixture identity");
    let store = RelayStoreHandle::open(RelayV2StoreConfig::new(path.to_path_buf(), identity))
        .await
        .expect("open signed-purge fixture store");
    let route = MachineRouteId::from_bytes([route_seed; 16]);
    let root_pubkey = PublicKeyBytes([route_seed.wrapping_add(1); 32]);
    let request = RegisterMachine {
        code_hash: [route_seed.wrapping_add(2); 32],
        request_hash: [route_seed.wrapping_add(3); 32],
        machine_route: route,
        root_pubkey,
        link_cert: certificate(CertRole::Link, route_seed.wrapping_add(4)),
        data_cert: certificate(CertRole::Data, route_seed.wrapping_add(5)),
        link_cert_hash: [route_seed.wrapping_add(6); 32],
        data_cert_hash: [route_seed.wrapping_add(7); 32],
    };
    store
        .seed_enrollment_code(EnrollmentCodeSeed {
            code_hash: request.code_hash,
            expires_at_ms: i64::MAX as u64,
        })
        .await
        .expect("seed signed-purge fixture enrollment code");
    store
        .register_machine(request)
        .await
        .expect("register signed-purge fixture machine");
    let purge = PurgeMachine {
        machine_route: route,
        expected_root_fingerprint: agentdeck_crypto::sha256(&root_pubkey.0),
    };
    let tbs = match store
        .prepare_admin_purge(purge.clone())
        .await
        .expect("prepare signed-purge fixture")
    {
        AdminPurgePreparation::Sign { tbs } => tbs,
        AdminPurgePreparation::Committed { .. } => panic!("fresh fixture is not committed"),
    };
    let verify_key = identity
        .bind_to_relay(store.relay_server_id())
        .expect("bind fixture verify key");
    let receipt = sign_relay_admin_purge_receipt(&signing_key, &verify_key, tbs)
        .expect("sign fixture receipt");
    store
        .commit_admin_purge(AdminPurgeCommitRequest {
            purge,
            receipt: receipt.clone(),
        })
        .await
        .expect("commit signed-purge fixture");
    store
        .shutdown()
        .await
        .expect("shutdown signed-purge fixture");
    (identity, route, receipt)
}

#[derive(Debug, Clone, Copy)]
enum ColdPurgeTamper {
    NoncanonicalJson,
    InvalidSignatureWithCanonicalHash,
    RootKeyExpectation,
    RootFingerprintExpectation,
    TrustEpochExpectation,
    EnrollmentReceiptExpectation,
    RequestHash,
    TombstoneHash,
    ReceiptHash,
    Descendant,
    RetirementMaterial,
    LegacyPortableMasquerade,
}

fn tamper_cold_purge(path: &Path, route: MachineRouteId, tamper: ColdPurgeTamper) {
    let conn = Connection::open(path).expect("open cold tamper fixture");
    match tamper {
        ColdPurgeTamper::NoncanonicalJson => {
            let mut blob = conn
                .query_row(
                    "SELECT admin_purge_receipt_blob FROM machine_routes WHERE machine_route = ?1",
                    params![route.as_bytes().as_slice()],
                    |row| row.get::<_, Vec<u8>>(0),
                )
                .expect("read canonical purge receipt");
            blob.push(b' ');
            conn.execute(
                "UPDATE machine_routes SET admin_purge_receipt_blob = ?2 WHERE machine_route = ?1",
                params![route.as_bytes().as_slice(), blob],
            )
            .expect("write noncanonical receipt JSON");
        }
        ColdPurgeTamper::InvalidSignatureWithCanonicalHash => {
            let blob = conn
                .query_row(
                    "SELECT admin_purge_receipt_blob FROM machine_routes WHERE machine_route = ?1",
                    params![route.as_bytes().as_slice()],
                    |row| row.get::<_, Vec<u8>>(0),
                )
                .expect("read signed purge receipt");
            let mut receipt: RelayAdminPurgeReceiptV1 =
                serde_json::from_slice(&blob).expect("decode signed purge receipt");
            receipt.signature.0[0] ^= 1;
            let forged_blob =
                serde_json::to_vec(&receipt).expect("encode canonical forged receipt");
            let forged_hash = receipt
                .canonical_sha256()
                .expect("hash canonical forged receipt");
            conn.execute(
                "UPDATE machine_routes
                 SET admin_purge_receipt_blob = ?2, admin_purge_receipt_hash = ?3
                 WHERE machine_route = ?1",
                params![
                    route.as_bytes().as_slice(),
                    forged_blob,
                    forged_hash.as_slice()
                ],
            )
            .expect("write forged canonical receipt and matching hash");
        }
        ColdPurgeTamper::RootKeyExpectation => {
            conn.execute(
                "UPDATE machine_routes SET root_key_id = ?2 WHERE machine_route = ?1",
                params![route.as_bytes().as_slice(), [0xa1_u8; 16].as_slice()],
            )
            .expect("tamper root key expectation");
        }
        ColdPurgeTamper::RootFingerprintExpectation => {
            conn.execute(
                "UPDATE machine_routes SET root_pubkey = ?2 WHERE machine_route = ?1",
                params![route.as_bytes().as_slice(), [0xa2_u8; 32].as_slice()],
            )
            .expect("tamper root fingerprint source");
        }
        ColdPurgeTamper::TrustEpochExpectation => {
            conn.execute(
                "UPDATE machine_routes SET trust_epoch = ?2 WHERE machine_route = ?1",
                params![route.as_bytes().as_slice(), 2_u64.to_be_bytes().as_slice()],
            )
            .expect("tamper trust epoch expectation");
        }
        ColdPurgeTamper::EnrollmentReceiptExpectation => {
            conn.execute(
                "UPDATE machine_routes SET enrollment_receipt_hash = ?2 WHERE machine_route = ?1",
                params![route.as_bytes().as_slice(), [0xa3_u8; 32].as_slice()],
            )
            .expect("tamper enrollment receipt expectation");
        }
        ColdPurgeTamper::RequestHash => {
            conn.execute(
                "UPDATE machine_routes SET admin_purge_request_hash = ?2 WHERE machine_route = ?1",
                params![route.as_bytes().as_slice(), [0xa4_u8; 32].as_slice()],
            )
            .expect("tamper purge request hash");
        }
        ColdPurgeTamper::TombstoneHash => {
            conn.execute(
                "UPDATE machine_routes SET admin_purge_tombstone_hash = ?2 WHERE machine_route = ?1",
                params![route.as_bytes().as_slice(), [0xa5_u8; 32].as_slice()],
            )
            .expect("tamper purge tombstone hash");
        }
        ColdPurgeTamper::ReceiptHash => {
            conn.execute(
                "UPDATE machine_routes SET admin_purge_receipt_hash = ?2 WHERE machine_route = ?1",
                params![route.as_bytes().as_slice(), [0xa6_u8; 32].as_slice()],
            )
            .expect("tamper canonical purge receipt hash");
        }
        ColdPurgeTamper::Descendant => {
            conn.execute(
                "INSERT INTO device_grants(
                    machine_route, device_route, auth_pubkey, auth_fingerprint,
                    grant_serial, grant_hash, revoked_at, tombstone
                 ) VALUES (?1, ?2, ?3, ?4, ?5, ?6, NULL, 0)",
                params![
                    route.as_bytes().as_slice(),
                    [0xa7_u8; 16].as_slice(),
                    [0xa8_u8; 32].as_slice(),
                    [0xa9_u8; 32].as_slice(),
                    1_u64.to_be_bytes().as_slice(),
                    [0xaa_u8; 32].as_slice(),
                ],
            )
            .expect("restore a purged descendant");
        }
        ColdPurgeTamper::RetirementMaterial => {
            conn.pragma_update(None, "ignore_check_constraints", true)
                .expect("allow offline constraint-breaking fixture");
            conn.execute(
                "UPDATE machine_routes
                 SET retirement_hash = ?2, retirement_terminal_blob = ?3
                 WHERE machine_route = ?1",
                params![
                    route.as_bytes().as_slice(),
                    [0xab_u8; 32].as_slice(),
                    [0xac_u8].as_slice()
                ],
            )
            .expect("inject forbidden retirement material");
        }
        ColdPurgeTamper::LegacyPortableMasquerade => {
            conn.pragma_update(None, "ignore_check_constraints", true)
                .expect("allow offline legacy masquerade fixture");
            conn.execute(
                "UPDATE machine_routes SET terminal_kind = 'legacy_admin_tombstone'
                 WHERE machine_route = ?1",
                params![route.as_bytes().as_slice()],
            )
            .expect("make legacy tombstone carry signed-proof columns");
        }
    }
    conn.pragma_update(None, "journal_mode", "DELETE")
        .expect("checkpoint cold tamper into main database");
    drop(conn);
    assert!(!sidecar(path, "-wal").exists(), "cold fixture has no WAL");
    assert!(!sidecar(path, "-shm").exists(), "cold fixture has no SHM");
}

#[tokio::test]
async fn cold_signed_purge_tampering_is_rejected_with_exactly_zero_artifact_write() {
    let cases = [
        ColdPurgeTamper::NoncanonicalJson,
        ColdPurgeTamper::InvalidSignatureWithCanonicalHash,
        ColdPurgeTamper::RootKeyExpectation,
        ColdPurgeTamper::RootFingerprintExpectation,
        ColdPurgeTamper::TrustEpochExpectation,
        ColdPurgeTamper::EnrollmentReceiptExpectation,
        ColdPurgeTamper::RequestHash,
        ColdPurgeTamper::TombstoneHash,
        ColdPurgeTamper::ReceiptHash,
        ColdPurgeTamper::Descendant,
        ColdPurgeTamper::RetirementMaterial,
        ColdPurgeTamper::LegacyPortableMasquerade,
    ];

    for (index, tamper) in cases.into_iter().enumerate() {
        let temp = TempDir::new().expect("tempdir");
        let path = temp.path().join("relay").join("relay.db");
        let signer_seed = u8::try_from(index).expect("case index fits u8") + 0x70;
        let route_seed = u8::try_from(index).expect("case index fits u8") + 0x30;
        let (identity, route, _) =
            create_signed_purge_fixture(&path, signer_seed, route_seed).await;
        tamper_cold_purge(&path, route, tamper);
        let before = sqlite_artifacts(&path);

        RelayStoreHandle::open(RelayV2StoreConfig::new(path.clone(), identity))
            .await
            .expect_err("cold signed-purge tampering must fail closed");

        assert_eq!(
            sqlite_artifacts(&path),
            before,
            "rejected current-schema tamper must not rewrite any SQLite artifact: {tamper:?}"
        );
    }
}

#[tokio::test]
async fn fresh_v2_store_persists_required_receipt_anchor_and_wrong_key_reopen_is_zero_write() {
    let temp = TempDir::new().expect("tempdir");
    let path = temp.path().join("relay").join("relay.db");
    let identity = signer_identity(0x41);
    let store = RelayStoreHandle::open(RelayV2StoreConfig::new(path.clone(), identity))
        .await
        .expect("open fresh schema v2 store");
    let snapshot = store.inspect().await.expect("inspect schema v2");
    assert_eq!(snapshot.schema_version, 2);
    assert_eq!(snapshot.receipt_verify_key.key_id, identity.key_id());
    assert_eq!(
        snapshot.receipt_verify_key.public_key,
        identity.public_key()
    );
    store.shutdown().await.expect("shutdown first store");

    let lock = process_lock_path(&path);
    fs::remove_file(&lock).expect("remove successful-open lock artifact");
    let before = sqlite_artifacts(&path);
    let error =
        RelayStoreHandle::open(RelayV2StoreConfig::new(path.clone(), signer_identity(0x42)))
            .await
            .expect_err("wrong receipt signer must reject current v2");
    assert!(matches!(error, StoreError::ReceiptSignerMismatch));
    assert_eq!(sqlite_artifacts(&path), before);
    assert!(!lock.exists());
}

#[tokio::test]
async fn registration_binds_canonical_receipt_and_exact_replay_bytes() {
    let temp = TempDir::new().expect("tempdir");
    let path = temp.path().join("relay").join("relay.db");
    let store =
        RelayStoreHandle::open(RelayV2StoreConfig::new(path.clone(), signer_identity(0x41)))
            .await
            .expect("open schema v2 store");
    let route = MachineRouteId::from_bytes([0x52; 16]);
    let request_hash = [0x53; 32];
    let request = RegisterMachine {
        code_hash: [0x54; 32],
        request_hash,
        machine_route: route,
        root_pubkey: PublicKeyBytes([0x55; 32]),
        link_cert: certificate(CertRole::Link, 0x56),
        data_cert: certificate(CertRole::Data, 0x57),
        link_cert_hash: [0x58; 32],
        data_cert_hash: [0x59; 32],
    };
    store
        .seed_enrollment_code(EnrollmentCodeSeed {
            code_hash: request.code_hash,
            expires_at_ms: i64::MAX as u64,
        })
        .await
        .expect("seed enrollment code");
    let first = store
        .register_machine(request.clone())
        .await
        .expect("register machine");
    let response: MachineEnrollmentResponseV1 =
        serde_json::from_slice(&first.response_blob).expect("decode canonical response");
    assert_eq!(
        first.response_blob,
        serde_json::to_vec(&response).expect("re-encode canonical response")
    );
    assert_eq!(
        first.receipt_hash,
        enrollment_receipt_hash(store.relay_server_id(), route, 1, request_hash)
    );
    let replay = store
        .register_machine(request.clone())
        .await
        .expect("exact registration replay");
    assert!(replay.duplicate);
    assert_eq!(replay.response_blob, first.response_blob);

    store.shutdown().await.expect("shutdown schema v2 store");
}

#[tokio::test]
async fn signed_root_lost_admin_purge_is_frozen_across_retry_and_restart() {
    let temp = TempDir::new().expect("tempdir");
    let path = temp.path().join("relay").join("relay.db");
    let signing_key = SigningKey::from_seed(&[0x61; 32]);
    let identity = ValidatedRelayReceiptSignerIdentityV1::from_signing_key(&signing_key)
        .expect("valid signed-purge test identity");
    let store = RelayStoreHandle::open(RelayV2StoreConfig::new(path.clone(), identity))
        .await
        .expect("open signed-purge store");
    let route = MachineRouteId::from_bytes([0x62; 16]);
    let root_pubkey = PublicKeyBytes([0x63; 32]);
    let request = RegisterMachine {
        code_hash: [0x64; 32],
        request_hash: [0x65; 32],
        machine_route: route,
        root_pubkey,
        link_cert: certificate(CertRole::Link, 0x66),
        data_cert: certificate(CertRole::Data, 0x67),
        link_cert_hash: [0x68; 32],
        data_cert_hash: [0x69; 32],
    };
    store
        .seed_enrollment_code(EnrollmentCodeSeed {
            code_hash: request.code_hash,
            expires_at_ms: i64::MAX as u64,
        })
        .await
        .expect("seed signed-purge enrollment code");
    store
        .register_machine(request)
        .await
        .expect("register signed-purge machine");
    let purge = PurgeMachine {
        machine_route: route,
        expected_root_fingerprint: agentdeck_crypto::sha256(&root_pubkey.0),
    };
    let tbs = match store
        .prepare_admin_purge(purge.clone())
        .await
        .expect("prepare first signed purge")
    {
        AdminPurgePreparation::Sign { tbs } => tbs,
        AdminPurgePreparation::Committed { .. } => panic!("active machine is not committed"),
    };
    let verify_key = identity
        .bind_to_relay(store.relay_server_id())
        .expect("bind signed-purge verify key");
    let receipt = sign_relay_admin_purge_receipt(&signing_key, &verify_key, tbs)
        .expect("sign typed admin purge receipt");
    let first = store
        .commit_admin_purge(AdminPurgeCommitRequest {
            purge: purge.clone(),
            receipt: receipt.clone(),
        })
        .await
        .expect("commit first signed purge");
    assert!(!first.duplicate);
    assert_eq!(first.receipt, receipt);
    assert_eq!(first.readback.consumed_enrollment_records, 0);

    let duplicate = store
        .commit_admin_purge(AdminPurgeCommitRequest {
            purge: purge.clone(),
            receipt: receipt.clone(),
        })
        .await
        .expect("retry exact signed purge");
    assert!(duplicate.duplicate);
    assert_eq!(duplicate.receipt, receipt);
    store.shutdown().await.expect("shutdown signed-purge store");

    let reopened = RelayStoreHandle::open(RelayV2StoreConfig::new(path, identity))
        .await
        .expect("reopen signed-purge store");
    let committed: RelayAdminPurgeReceiptV1 = match reopened
        .prepare_admin_purge(purge)
        .await
        .expect("prepare committed signed purge")
    {
        AdminPurgePreparation::Committed { receipt } => receipt,
        AdminPurgePreparation::Sign { .. } => panic!("retired machine must return frozen proof"),
    };
    assert_eq!(committed, receipt);
    reopened.shutdown().await.expect("shutdown reopened store");
}

#[test]
fn server_config_requires_receipt_signing_key_without_default() {
    let temp = TempDir::new().expect("tempdir");
    let cwd = fs::canonicalize(temp.path()).expect("canonical cwd");
    let environment = BTreeMap::new();
    let error = RelayV2ServerConfig::load_from(
        [
            "agentdeck-relay",
            "--allow-insecure-loopback",
            "--storage",
            cwd.join("relay.db").to_str().expect("storage UTF-8"),
        ],
        &environment,
        &cwd,
    )
    .expect_err("receipt signing key must be required");
    assert_eq!(error.code(), "relay.receipt.signer_required");
}
