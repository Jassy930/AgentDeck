//! P4.2 signed root-lost admin purge 的 Store 负向与事务边界契约。

use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};

use agentdeck_crypto::{
    SigningKey, ValidatedRelayReceiptSignerIdentityV1, sign_relay_admin_purge_receipt,
};
use agentdeck_protocol::relay_v2::{
    CertRole, Ed25519Signature, LinkGeneration, MachineRouteId, PublicKeyBytes,
    RelayAdminPurgeReceiptV1, RelayServerId, RootKeyId, SignedCertificate, TrustEpoch,
};
use agentdeck_relay::v2::store::{
    AdminPurgeCommitRequest, AdminPurgePreparation, EnrollmentCodeSeed, FaultInjector, FaultPoint,
    MachineReadbackQuery, PurgeMachine, RegisterMachine, RelayStoreHandle, RelayV2StoreConfig,
    StoreError,
};
use tempfile::TempDir;

const SIGNER_SEED: [u8; 32] = [0x91; 32];

fn signing_key() -> SigningKey {
    SigningKey::from_seed(&SIGNER_SEED)
}

fn signer_identity() -> ValidatedRelayReceiptSignerIdentityV1 {
    ValidatedRelayReceiptSignerIdentityV1::from_signing_key(&signing_key())
        .expect("valid receipt signer identity")
}

fn certificate(role: CertRole, seed: u8) -> SignedCertificate {
    SignedCertificate {
        subject_pubkey: PublicKeyBytes([seed; 32]),
        cert_role: role,
        generation: LinkGeneration::new(1),
        root_key_id: RootKeyId::from_bytes([0xa1; 16]),
        trust_epoch: TrustEpoch::new(1),
        not_after_ms: None,
        signature: Ed25519Signature([seed; 64]),
    }
}

fn registration(seed: u8) -> RegisterMachine {
    RegisterMachine {
        code_hash: [seed; 32],
        request_hash: [seed.wrapping_add(1); 32],
        machine_route: MachineRouteId::from_bytes([seed.wrapping_add(2); 16]),
        root_pubkey: PublicKeyBytes([seed.wrapping_add(3); 32]),
        link_cert: certificate(CertRole::Link, seed.wrapping_add(4)),
        data_cert: certificate(CertRole::Data, seed.wrapping_add(5)),
        link_cert_hash: [seed.wrapping_add(6); 32],
        data_cert_hash: [seed.wrapping_add(7); 32],
    }
}

fn purge_for(request: &RegisterMachine) -> PurgeMachine {
    PurgeMachine {
        machine_route: request.machine_route,
        expected_root_fingerprint: agentdeck_crypto::sha256(&request.root_pubkey.0),
    }
}

async fn register(store: &RelayStoreHandle, seed: u8) -> RegisterMachine {
    let request = registration(seed);
    store
        .seed_enrollment_code(EnrollmentCodeSeed {
            code_hash: request.code_hash,
            expires_at_ms: i64::MAX as u64,
        })
        .await
        .expect("seed enrollment code");
    store
        .register_machine(request.clone())
        .await
        .expect("register machine");
    request
}

async fn prepare_and_sign(
    store: &RelayStoreHandle,
    purge: &PurgeMachine,
) -> RelayAdminPurgeReceiptV1 {
    let tbs = match store
        .prepare_admin_purge(purge.clone())
        .await
        .expect("prepare signed purge")
    {
        AdminPurgePreparation::Sign { tbs } => tbs,
        AdminPurgePreparation::Committed { .. } => panic!("machine must still be active"),
    };
    let verify_key = signer_identity()
        .bind_to_relay(store.relay_server_id())
        .expect("bind receipt verify key");
    sign_relay_admin_purge_receipt(&signing_key(), &verify_key, tbs)
        .expect("sign typed purge receipt")
}

#[derive(Debug)]
struct OneShotFault {
    point: FaultPoint,
    fired: AtomicBool,
}

impl OneShotFault {
    fn new(point: FaultPoint) -> Self {
        Self {
            point,
            fired: AtomicBool::new(false),
        }
    }
}

impl FaultInjector for OneShotFault {
    fn check(&self, point: FaultPoint) -> Result<(), StoreError> {
        if point == self.point && !self.fired.swap(true, Ordering::SeqCst) {
            Err(StoreError::InjectedFault(point))
        } else {
            Ok(())
        }
    }
}

#[tokio::test]
async fn signed_admin_purge_rejects_locator_and_receipt_tampering_without_state_change() {
    let temp = TempDir::new().expect("tempdir");
    let path = temp.path().join("relay").join("relay.db");
    let store = RelayStoreHandle::open(RelayV2StoreConfig::new(path.clone(), signer_identity()))
        .await
        .expect("open store");
    let request = register(&store, 0xb1).await;
    let purge = purge_for(&request);
    let before = store
        .machine_readback(MachineReadbackQuery {
            machine_route: purge.machine_route,
            expected_root_fingerprint: purge.expected_root_fingerprint,
        })
        .await
        .expect("read active machine");

    let wrong_locator = store
        .prepare_admin_purge(PurgeMachine {
            expected_root_fingerprint: [0xff; 32],
            ..purge.clone()
        })
        .await
        .expect_err("wrong root locator must reject prepare");
    assert!(matches!(wrong_locator, StoreError::RootFingerprintMismatch));

    let receipt = prepare_and_sign(&store, &purge).await;
    let mut tampered = Vec::new();

    let mut wrong_signature = receipt.clone();
    wrong_signature.signature.0[0] ^= 0x01;
    tampered.push(wrong_signature);

    let mut wrong_key_id = receipt.clone();
    wrong_key_id.receipt_key_id =
        agentdeck_protocol::relay_v2::RelayReceiptKeyId::from_bytes([0xee; 32]);
    tampered.push(wrong_key_id);

    let mut wrong_generation = receipt.clone();
    wrong_generation.receipt_key_generation += 1;
    tampered.push(wrong_generation);

    let mut wrong_relay = receipt.clone();
    wrong_relay.relay_server_id = RelayServerId::from_bytes([0xed; 16]);
    tampered.push(wrong_relay);

    let mut wrong_route = receipt.clone();
    wrong_route.machine_route = MachineRouteId::from_bytes([0xec; 16]);
    tampered.push(wrong_route);

    let mut wrong_root_key = receipt.clone();
    wrong_root_key.root_key_id = RootKeyId::from_bytes([0xeb; 16]);
    tampered.push(wrong_root_key);

    let mut wrong_root_fingerprint = receipt.clone();
    wrong_root_fingerprint.root_fingerprint[0] ^= 0x01;
    tampered.push(wrong_root_fingerprint);

    let mut wrong_epoch = receipt.clone();
    wrong_epoch.trust_epoch = TrustEpoch::new(2);
    tampered.push(wrong_epoch);

    let mut wrong_enrollment = receipt.clone();
    wrong_enrollment.enrollment_receipt_hash[0] ^= 0x01;
    tampered.push(wrong_enrollment);

    let mut wrong_request_hash = receipt.clone();
    wrong_request_hash.purge_request_hash[0] ^= 0x01;
    tampered.push(wrong_request_hash);

    let mut wrong_tombstone_hash = receipt.clone();
    wrong_tombstone_hash.tombstone_hash[0] ^= 0x01;
    tampered.push(wrong_tombstone_hash);

    let mut wrong_readback = receipt.clone();
    wrong_readback.readback.streams = 1;
    tampered.push(wrong_readback);

    for candidate in tampered {
        let error = store
            .commit_admin_purge(AdminPurgeCommitRequest {
                purge: purge.clone(),
                receipt: candidate,
            })
            .await
            .expect_err("tampered receipt must fail closed");
        assert!(matches!(error, StoreError::AuthenticationMismatch { .. }));
        assert_eq!(
            store
                .machine_readback(MachineReadbackQuery {
                    machine_route: purge.machine_route,
                    expected_root_fingerprint: purge.expected_root_fingerprint,
                })
                .await
                .expect("receipt rejection keeps machine active"),
            before
        );
    }

    let committed = store
        .commit_admin_purge(AdminPurgeCommitRequest { purge, receipt })
        .await
        .expect("valid receipt commits after all rejections");
    assert!(!committed.duplicate);
    store.shutdown().await.expect("shutdown store");
}

#[tokio::test]
async fn signed_admin_purge_before_commit_rolls_back_and_after_commit_reuses_exact_receipt() {
    for (seed, fault_point) in [
        (0xc1, FaultPoint::PurgeBeforeCommit),
        (0xd1, FaultPoint::PurgeAfterCommit),
    ] {
        let temp = TempDir::new().expect("tempdir");
        let path = temp.path().join("relay").join("relay.db");
        let config = RelayV2StoreConfig::new(path, signer_identity())
            .with_fault_injector(Arc::new(OneShotFault::new(fault_point)));
        let store = RelayStoreHandle::open(config).await.expect("open store");
        let request = register(&store, seed).await;
        let purge = purge_for(&request);
        let receipt = prepare_and_sign(&store, &purge).await;

        let first_error = store
            .commit_admin_purge(AdminPurgeCommitRequest {
                purge: purge.clone(),
                receipt: receipt.clone(),
            })
            .await
            .expect_err("injected commit boundary must surface");

        match fault_point {
            FaultPoint::PurgeBeforeCommit => {
                assert!(matches!(
                    first_error,
                    StoreError::InjectedFault(FaultPoint::PurgeBeforeCommit)
                ));
                let prepared_again = prepare_and_sign(&store, &purge).await;
                assert_eq!(prepared_again, receipt);
            }
            FaultPoint::PurgeAfterCommit => {
                assert!(matches!(
                    first_error,
                    StoreError::CommitOutcomeUnknown {
                        operation: "admin_purge_machine"
                    }
                ));
                let committed = store
                    .prepare_admin_purge(purge.clone())
                    .await
                    .expect("post-COMMIT prepare returns persisted proof");
                assert_eq!(
                    committed,
                    AdminPurgePreparation::Committed {
                        receipt: receipt.clone()
                    }
                );
            }
            _ => unreachable!(),
        }

        let retry = store
            .commit_admin_purge(AdminPurgeCommitRequest {
                purge,
                receipt: receipt.clone(),
            })
            .await
            .expect("exact frozen receipt retry succeeds");
        assert_eq!(retry.receipt, receipt);
        assert_eq!(retry.duplicate, fault_point == FaultPoint::PurgeAfterCommit);
        store.shutdown().await.expect("shutdown store");
    }
}

#[tokio::test]
async fn fresh_v2_admin_purge_only_emits_portable_signed_tombstone() {
    let temp = TempDir::new().expect("tempdir");
    let path = temp.path().join("relay").join("relay.db");
    let store = RelayStoreHandle::open(RelayV2StoreConfig::new(path.clone(), signer_identity()))
        .await
        .expect("open store");
    let request = register(&store, 0xe1).await;
    let purge = purge_for(&request);
    let receipt = prepare_and_sign(&store, &purge).await;

    let committed = store
        .commit_admin_purge(AdminPurgeCommitRequest {
            purge: purge.clone(),
            receipt: receipt.clone(),
        })
        .await
        .expect("commit portable signed tombstone");
    assert_eq!(committed.receipt, receipt);

    let prepared = store
        .prepare_admin_purge(purge.clone())
        .await
        .expect("replay portable signed tombstone");
    assert_eq!(
        prepared,
        AdminPurgePreparation::Committed {
            receipt: receipt.clone()
        }
    );
    store.shutdown().await.expect("shutdown store");

    let conn = rusqlite::Connection::open(path).expect("open terminal readback");
    let terminal_kind: String = conn
        .query_row(
            "SELECT terminal_kind FROM machine_routes WHERE machine_route = ?1",
            [purge.machine_route.as_bytes().as_slice()],
            |row| row.get(0),
        )
        .expect("read terminal kind");
    assert_eq!(terminal_kind, "root_lost_admin_purge");
}
