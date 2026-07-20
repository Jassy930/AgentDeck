use std::fs;
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicU64, Ordering};

use agentdeck_crypto::{SigningKey, sha256, sign_tbs};
use agentdeck_protocol::e2ee::E2EE_FORMAT_VERSION;
use agentdeck_protocol::e2ee::tbs::SignedObjectType;
use agentdeck_protocol::relay_v2::{
    AUTH_SIGNATURE_FORMAT_VERSION, CertRole, DeviceRouteId, Ed25519Signature, LinkGeneration,
    MachineRouteId, RELAY_PROTOCOL_VERSION, RelayServerId, RootKeyId, TrustEpoch,
};
use agentdeck_protocol::runtime::RUNTIME_PROTOCOL_VERSION;
use agentdeckd::config::{DaemonConfig, DaemonStartupOptions};
use agentdeckd::remote::bootstrap::{
    ActiveMachineIdentity, RemoteBootstrapOutcome, reconcile_machine_identity,
};
use agentdeckd::remote::certificate::{MachineCertificateError, MachineCertificates};
use agentdeckd::remote::identity::{
    MACHINE_DATA_SIGN_ACCOUNT, MACHINE_HPKE_ACCOUNT, MACHINE_LINK_SIGN_ACCOUNT,
    MACHINE_ROOT_SIGN_ACCOUNT,
};
use agentdeckd::runtime::store::{RuntimeStoreConfig, RuntimeStoreHandle};
use agentdeckd::security::{KeyStore, MemoryKeyStore, SecretBytes, load_or_create_storage_kek};

const ROOT_SEED: [u8; 32] = [0x11; 32];
const HPKE_IKM: [u8; 32] = [0x22; 32];
const LINK_SEED: [u8; 32] = [0x33; 32];
const DATA_SEED: [u8; 32] = [0x44; 32];
const RELAY: RelayServerId = RelayServerId::from_bytes([0x55; 16]);
const ROUTE: MachineRouteId = MachineRouteId::from_bytes([0x66; 16]);

static NEXT_ROOT: AtomicU64 = AtomicU64::new(1);

struct TestRoot(PathBuf);

impl TestRoot {
    fn new() -> Self {
        let path = Path::new("/tmp").join(format!(
            "agentdeck-machine-certificates-{}-{}",
            std::process::id(),
            NEXT_ROOT.fetch_add(1, Ordering::Relaxed)
        ));
        fs::create_dir_all(&path).expect("create certificate test root");
        Self(path)
    }
}

impl Drop for TestRoot {
    fn drop(&mut self) {
        let _ = fs::remove_dir_all(&self.0);
    }
}

struct Fixture {
    _root: TestRoot,
    store: RuntimeStoreHandle,
    active: Box<ActiveMachineIdentity>,
}

impl Fixture {
    async fn new() -> Self {
        let root = TestRoot::new();
        let home = root.0.join("home");
        fs::create_dir_all(home.join("Library/Application Support"))
            .expect("create stable test home");
        let config = DaemonConfig::resolve_with_roots(
            DaemonStartupOptions {
                ephemeral: false,
                no_remote: false,
                stdio_compat: false,
                profile: None,
                stable_keychain_access_group: Some(
                    "A1B2C3D4E5.com.agentdeck.agentdeckd.stable".to_owned(),
                ),
            },
            &home,
            &root.0,
        )
        .expect("resolve stable certificate config");
        fs::create_dir_all(
            config
                .paths()
                .runtime_db
                .parent()
                .expect("runtime database has a parent directory"),
        )
        .expect("create certificate runtime directory");
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            fs::set_permissions(
                config
                    .paths()
                    .runtime_db
                    .parent()
                    .expect("runtime database has a parent directory"),
                fs::Permissions::from_mode(0o700),
            )
            .expect("secure certificate runtime directory");
        }

        let identity_keys = MemoryKeyStore::new();
        for (account, bytes) in [
            (MACHINE_ROOT_SIGN_ACCOUNT, ROOT_SEED.as_slice()),
            (MACHINE_HPKE_ACCOUNT, HPKE_IKM.as_slice()),
            (MACHINE_LINK_SIGN_ACCOUNT, LINK_SEED.as_slice()),
            (MACHINE_DATA_SIGN_ACCOUNT, DATA_SEED.as_slice()),
        ] {
            identity_keys
                .store(account, &SecretBytes::new(bytes.to_vec()))
                .expect("install deterministic identity material");
        }
        let storage_keys = MemoryKeyStore::new();
        let store = RuntimeStoreHandle::open(
            RuntimeStoreConfig::new(config.paths().runtime_db.clone()),
            load_or_create_storage_kek(&storage_keys, &config.paths().runtime_db)
                .expect("create certificate test StorageKEK"),
        )
        .await
        .expect("open certificate test store");
        let outcome = reconcile_machine_identity(&config, &store, &identity_keys)
            .await
            .expect("bootstrap deterministic active identity");
        let RemoteBootstrapOutcome::Active(active) = outcome else {
            panic!("certificate fixture identity must be active");
        };
        Self {
            _root: root,
            store,
            active,
        }
    }

    async fn shutdown(self) {
        drop(self.active);
        self.store
            .shutdown()
            .await
            .expect("shutdown certificate store");
    }
}

fn assert_certificate_contract(active: &ActiveMachineIdentity, certificates: &MachineCertificates) {
    let binding = active.binding();
    for (role, certificate, subject, generation, object_type, scope) in [
        (
            CertRole::Link,
            certificates.link(),
            binding.link_sign_public_key,
            binding.link_generation,
            SignedObjectType::LinkCert,
            "machine-link",
        ),
        (
            CertRole::Data,
            certificates.data(),
            binding.data_sign_public_key,
            binding.data_generation,
            SignedObjectType::DataCert,
            "machine-data",
        ),
    ] {
        assert_eq!(certificate.cert_role, role);
        assert_eq!(certificate.subject_pubkey.0, subject);
        assert_eq!(certificate.generation, LinkGeneration::new(generation));
        assert_eq!(
            certificate.root_key_id,
            RootKeyId::from_bytes(binding.root_key_id)
        );
        assert_eq!(
            certificate.trust_epoch,
            TrustEpoch::new(binding.trust_epoch)
        );
        assert_eq!(certificate.not_after_ms, None);

        let tbs = certificate.to_be_signed_v1(RELAY, ROUTE, binding.root_fingerprint);
        assert_eq!(tbs.object_type, object_type);
        assert_eq!(tbs.signature_format_version, AUTH_SIGNATURE_FORMAT_VERSION);
        assert_eq!(tbs.relay_protocol_version, RELAY_PROTOCOL_VERSION);
        assert_eq!(tbs.runtime_protocol_version, RUNTIME_PROTOCOL_VERSION);
        assert_eq!(tbs.e2ee_format_version, E2EE_FORMAT_VERSION);
        assert_eq!(tbs.relay_server_id, RELAY);
        assert_eq!(tbs.machine_route, ROUTE);
        assert_eq!(tbs.device_route, None);
        assert_eq!(tbs.stream_route, None);
        assert_eq!(tbs.request_route, None);
        assert_eq!(tbs.stream_generation, None);
        assert_eq!(tbs.stream_cursor, None);
        assert_eq!(tbs.role_scope, scope);
        assert_eq!(tbs.signing_key_fingerprint, binding.root_fingerprint);
        assert_eq!(tbs.root_key_id, certificate.root_key_id);
        assert_eq!(tbs.trust_epoch, certificate.trust_epoch);
        assert_eq!(tbs.serial_or_generation, generation);
        assert_eq!(tbs.not_after_ms, None);
        assert_eq!(
            tbs.signed_object_sha256,
            certificate.unsigned_canonical_sha256()
        );
        active
            .verify_certificate(RELAY, ROUTE, role, certificate)
            .expect("issued certificate must pass active root verification");
    }
}

fn resign(
    certificate: &mut agentdeck_protocol::relay_v2::SignedCertificate,
    relay: RelayServerId,
    route: MachineRouteId,
) {
    let root = SigningKey::from_seed(&ROOT_SEED);
    certificate.signature = sign_tbs(
        &root,
        &certificate.to_be_signed_v1(relay, route, sha256(&root.verifying_key().to_bytes())),
    )
    .into();
}

#[tokio::test]
async fn active_identity_issues_deterministic_root_signed_link_and_data_certificates() {
    let fixture = Fixture::new().await;
    let first = fixture
        .active
        .certificates(RELAY, ROUTE)
        .expect("issue fixed machine certificates");
    let second = fixture
        .active
        .certificates(RELAY, ROUTE)
        .expect("repeat fixed machine certificates");

    assert_certificate_contract(&fixture.active, &first);
    assert_eq!(first, second);
    assert_eq!(
        first.link().canonical_bytes(),
        second.link().canonical_bytes()
    );
    assert_eq!(
        first.data().canonical_bytes(),
        second.data().canonical_bytes()
    );
    assert_eq!(
        first.link().canonical_sha256(),
        second.link().canonical_sha256()
    );
    assert_eq!(
        first.data().canonical_sha256(),
        second.data().canonical_sha256()
    );
    assert_eq!(
        fixture
            .active
            .certificates(RelayServerId::from_bytes([0; 16]), ROUTE)
            .expect_err("zero Relay identity must never be signed"),
        MachineCertificateError::InvalidRelayServerId
    );
    assert_eq!(
        fixture
            .active
            .certificates(RELAY, MachineRouteId::from_bytes([0; 16]))
            .expect_err("zero machine route must never be signed"),
        MachineCertificateError::InvalidMachineRouteId
    );
    assert_eq!(
        fixture
            .active
            .verify_certificate(
                RelayServerId::from_bytes([0; 16]),
                ROUTE,
                CertRole::Link,
                first.link(),
            )
            .expect_err("zero Relay identity must never verify"),
        MachineCertificateError::InvalidRelayServerId
    );
    assert_eq!(
        fixture
            .active
            .verify_certificate(
                RELAY,
                MachineRouteId::from_bytes([0; 16]),
                CertRole::Link,
                first.link(),
            )
            .expect_err("zero machine route must never verify"),
        MachineCertificateError::InvalidMachineRouteId
    );

    fixture.shutdown().await;
}

#[tokio::test]
async fn certificate_verifier_rejects_every_bound_axis_even_with_a_valid_root_signature() {
    let fixture = Fixture::new().await;
    let certificates = fixture
        .active
        .certificates(RELAY, ROUTE)
        .expect("issue fixed machine certificates");
    let valid = certificates.link();

    assert_eq!(
        fixture
            .active
            .verify_certificate(
                RelayServerId::from_bytes([0x77; 16]),
                ROUTE,
                CertRole::Link,
                valid,
            )
            .expect_err("relay context is part of the signed TBS"),
        MachineCertificateError::SignatureInvalid
    );
    assert_eq!(
        fixture
            .active
            .verify_certificate(
                RELAY,
                MachineRouteId::from_bytes([0x88; 16]),
                CertRole::Link,
                valid,
            )
            .expect_err("machine route is part of the signed TBS"),
        MachineCertificateError::SignatureInvalid
    );
    assert_eq!(
        fixture
            .active
            .verify_certificate(RELAY, ROUTE, CertRole::Data, valid)
            .expect_err("certificate role is fixed"),
        MachineCertificateError::RoleMismatch
    );

    let binding = fixture.active.binding();
    let mut cases = Vec::new();

    let mut wrong_subject = valid.clone();
    wrong_subject.subject_pubkey.0 = binding.data_sign_public_key;
    resign(&mut wrong_subject, RELAY, ROUTE);
    cases.push((wrong_subject, MachineCertificateError::SubjectMismatch));

    let mut wrong_root_id = valid.clone();
    wrong_root_id.root_key_id = RootKeyId::from_bytes([0x99; 16]);
    resign(&mut wrong_root_id, RELAY, ROUTE);
    cases.push((wrong_root_id, MachineCertificateError::RootKeyIdMismatch));

    let mut wrong_epoch = valid.clone();
    wrong_epoch.trust_epoch = TrustEpoch::new(binding.trust_epoch + 1);
    resign(&mut wrong_epoch, RELAY, ROUTE);
    cases.push((wrong_epoch, MachineCertificateError::TrustEpochMismatch));

    let mut wrong_generation = valid.clone();
    wrong_generation.generation = LinkGeneration::new(binding.link_generation + 1);
    resign(&mut wrong_generation, RELAY, ROUTE);
    cases.push((
        wrong_generation,
        MachineCertificateError::GenerationMismatch,
    ));

    let mut expiring = valid.clone();
    expiring.not_after_ms = Some(1);
    resign(&mut expiring, RELAY, ROUTE);
    cases.push((expiring, MachineCertificateError::UnexpectedExpiry));

    for (certificate, expected_error) in cases {
        assert_eq!(
            fixture
                .active
                .verify_certificate(RELAY, ROUTE, CertRole::Link, &certificate)
                .expect_err("root signature cannot override a frozen binding mismatch"),
            expected_error
        );
    }

    let mut wrong_domain = valid.clone();
    let root = SigningKey::from_seed(&ROOT_SEED);
    let mut tbs = wrong_domain.to_be_signed_v1(RELAY, ROUTE, binding.root_fingerprint);
    tbs.object_type = SignedObjectType::RelayGrant;
    wrong_domain.signature = Ed25519Signature(sign_tbs(&root, &tbs).0);
    assert_eq!(
        fixture
            .active
            .verify_certificate(RELAY, ROUTE, CertRole::Link, &wrong_domain)
            .expect_err("a signature under another TBS object domain must fail"),
        MachineCertificateError::SignatureInvalid
    );

    let mut wrong_context = valid.clone();
    let mut tbs = wrong_context.to_be_signed_v1(RELAY, ROUTE, binding.root_fingerprint);
    tbs.device_route = Some(DeviceRouteId::from_bytes([0xaa; 16]));
    wrong_context.signature = Ed25519Signature(sign_tbs(&root, &tbs).0);
    assert_eq!(
        fixture
            .active
            .verify_certificate(RELAY, ROUTE, CertRole::Link, &wrong_context)
            .expect_err("an unexpected optional TBS context must fail"),
        MachineCertificateError::SignatureInvalid
    );

    let mut wrong_signature = valid.clone();
    wrong_signature.signature = Ed25519Signature([0xbb; 64]);
    assert_eq!(
        fixture
            .active
            .verify_certificate(RELAY, ROUTE, CertRole::Link, &wrong_signature)
            .expect_err("forged certificate signature must fail"),
        MachineCertificateError::SignatureInvalid
    );

    fixture.shutdown().await;
}
