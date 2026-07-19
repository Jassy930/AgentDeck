use std::collections::HashMap;
use std::sync::Mutex;

use agentdeck_crypto::{HpkePrivateKey, SigningKey, sha256};
use agentdeck_protocol::e2ee::{KeyId, KeyPurpose};
use agentdeckd::remote::identity::{
    KEY_DIRECTORY_GUARD_ACCOUNT, KeyDirectoryGuard, MACHINE_DATA_SIGN_ACCOUNT,
    MACHINE_HPKE_ACCOUNT, MACHINE_LINK_SIGN_ACCOUNT, MACHINE_ROOT_SIGN_ACCOUNT,
    MachineIdentityError, advance_counter_guard, counter_guard_account, delete_counter_guard,
    delete_key_directory_guard, delete_machine_key_material, install_key_directory_guard,
    load_counter_guard, load_key_directory_guard, load_machine_key_material,
};
use agentdeckd::security::{KeyStore, KeyStoreError, SecretBytes};

#[derive(Default)]
struct RecordingKeyStore {
    state: Mutex<RecordingState>,
}

#[derive(Default)]
struct RecordingState {
    values: HashMap<String, Vec<u8>>,
    stores: Vec<String>,
    deletes: Vec<String>,
    corrupt_readback_for: Option<String>,
    missing_readback_for: Option<String>,
    corrupt_after_store_for: Option<String>,
    missing_after_store_for: Option<String>,
}

impl RecordingKeyStore {
    fn insert(&self, account: &str, value: &[u8]) {
        self.state
            .lock()
            .expect("recording keystore lock")
            .values
            .insert(account.to_owned(), value.to_vec());
    }

    fn value(&self, account: &str) -> Option<Vec<u8>> {
        self.state
            .lock()
            .expect("recording keystore lock")
            .values
            .get(account)
            .cloned()
    }

    fn stores(&self) -> Vec<String> {
        self.state
            .lock()
            .expect("recording keystore lock")
            .stores
            .clone()
    }

    fn deletes(&self) -> Vec<String> {
        self.state
            .lock()
            .expect("recording keystore lock")
            .deletes
            .clone()
    }

    fn corrupt_next_readback_for(&self, account: &str) {
        self.state
            .lock()
            .expect("recording keystore lock")
            .corrupt_readback_for = Some(account.to_owned());
    }

    fn miss_next_readback_for(&self, account: &str) {
        self.state
            .lock()
            .expect("recording keystore lock")
            .missing_readback_for = Some(account.to_owned());
    }

    fn corrupt_readback_after_next_store_for(&self, account: &str) {
        self.state
            .lock()
            .expect("recording keystore lock")
            .corrupt_after_store_for = Some(account.to_owned());
    }

    fn miss_readback_after_next_store_for(&self, account: &str) {
        self.state
            .lock()
            .expect("recording keystore lock")
            .missing_after_store_for = Some(account.to_owned());
    }
}

impl KeyStore for RecordingKeyStore {
    fn load(&self, account: &str) -> Result<Option<SecretBytes>, KeyStoreError> {
        let mut state = self.state.lock().map_err(|_| KeyStoreError::Poisoned)?;
        let Some(value) = state.values.get(account).cloned() else {
            return Ok(None);
        };
        if state.missing_readback_for.as_deref() == Some(account) {
            state.missing_readback_for = None;
            return Ok(None);
        }
        if state.corrupt_readback_for.as_deref() == Some(account) {
            state.corrupt_readback_for = None;
            let mut corrupt = value;
            corrupt[0] ^= 0xff;
            return Ok(Some(SecretBytes::new(corrupt)));
        }
        Ok(Some(SecretBytes::new(value)))
    }

    fn store(&self, account: &str, value: &SecretBytes) -> Result<(), KeyStoreError> {
        let mut state = self.state.lock().map_err(|_| KeyStoreError::Poisoned)?;
        state.stores.push(account.to_owned());
        state
            .values
            .insert(account.to_owned(), value.expose_secret().to_vec());
        if state.corrupt_after_store_for.as_deref() == Some(account) {
            state.corrupt_after_store_for = None;
            state.corrupt_readback_for = Some(account.to_owned());
        }
        if state.missing_after_store_for.as_deref() == Some(account) {
            state.missing_after_store_for = None;
            state.missing_readback_for = Some(account.to_owned());
        }
        Ok(())
    }

    fn delete(&self, account: &str) -> Result<(), KeyStoreError> {
        let mut state = self.state.lock().map_err(|_| KeyStoreError::Poisoned)?;
        state.deletes.push(account.to_owned());
        state.values.remove(account);
        Ok(())
    }
}

fn fixed_material(store: &RecordingKeyStore) -> [[u8; 32]; 4] {
    let root = [0x11; 32];
    let hpke = [0x22; 32];
    let link = [0x33; 32];
    let data = [0x44; 32];
    store.insert(MACHINE_ROOT_SIGN_ACCOUNT, &root);
    store.insert(MACHINE_HPKE_ACCOUNT, &hpke);
    store.insert(MACHINE_LINK_SIGN_ACCOUNT, &link);
    store.insert(MACHINE_DATA_SIGN_ACCOUNT, &data);
    [root, hpke, link, data]
}

#[test]
fn existing_material_uses_agentdeck_crypto_and_never_overwrites_accounts() {
    let store = RecordingKeyStore::default();
    let root_seed = [0x51; 32];
    let hpke_ikm = [0x52; 32];
    store.insert(MACHINE_ROOT_SIGN_ACCOUNT, &root_seed);
    store.insert(MACHINE_HPKE_ACCOUNT, &hpke_ikm);
    store.insert(MACHINE_LINK_SIGN_ACCOUNT, &[0x53; 32]);
    store.insert(MACHINE_DATA_SIGN_ACCOUNT, &[0x54; 32]);

    let material = load_machine_key_material(&store).expect("load existing machine material");

    assert_eq!(
        store.value(MACHINE_ROOT_SIGN_ACCOUNT),
        Some(root_seed.to_vec())
    );
    assert_eq!(store.value(MACHINE_HPKE_ACCOUNT), Some(hpke_ikm.to_vec()));
    assert!(store.stores().is_empty());
    assert_eq!(
        material.public_identity().root().public_key(),
        &SigningKey::from_seed(&root_seed).verifying_key().to_bytes()
    );
    let (_, expected_hpke_public) = HpkePrivateKey::derive_keypair(&hpke_ikm);
    assert_eq!(
        material.public_identity().hpke().public_key().as_slice(),
        expected_hpke_public.to_bytes()
    );
    let public = material.public_identity();
    assert_eq!(
        public.root().fingerprint(),
        sha256(public.root().public_key())
    );
    assert_eq!(
        public.hpke().fingerprint(),
        sha256(public.hpke().public_key())
    );
    assert_eq!(
        public.link().fingerprint(),
        sha256(public.link().public_key())
    );
    assert_eq!(
        public.data().fingerprint(),
        sha256(public.data().public_key())
    );
}

#[test]
fn existing_only_load_never_creates_missing_material() {
    let store = RecordingKeyStore::default();
    let error = load_machine_key_material(&store).expect_err("missing key must stay missing");
    assert_eq!(error.code(), "daemon.remote.identity.key_missing");
    assert!(store.stores().is_empty());
}

#[test]
fn directory_guard_is_exact_idempotent_and_never_overwritten() {
    let store = RecordingKeyStore::default();
    let guard = KeyDirectoryGuard::new([0x71; 16], [0x72; 32], 9);

    assert_eq!(install_key_directory_guard(&store, guard).unwrap(), guard);
    assert_eq!(load_key_directory_guard(&store).unwrap(), Some(guard));
    assert_eq!(install_key_directory_guard(&store, guard).unwrap(), guard);
    assert_eq!(store.stores(), vec![KEY_DIRECTORY_GUARD_ACCOUNT]);

    let conflict = KeyDirectoryGuard::new([0x71; 16], [0x73; 32], 9);
    let error = install_key_directory_guard(&store, conflict)
        .expect_err("different guard must not overwrite existing guard");
    assert_eq!(error.code(), "daemon.remote.identity.guard_conflict");
    assert_eq!(load_key_directory_guard(&store).unwrap(), Some(guard));
    assert_eq!(store.stores(), vec![KEY_DIRECTORY_GUARD_ACCOUNT]);
}

#[test]
fn directory_guard_requires_exact_store_readback() {
    let store = RecordingKeyStore::default();
    store.corrupt_next_readback_for(KEY_DIRECTORY_GUARD_ACCOUNT);
    let error =
        install_key_directory_guard(&store, KeyDirectoryGuard::new([0x75; 16], [0x76; 32], 10))
            .expect_err("mutated guard readback must fail");
    assert_eq!(
        error.code(),
        "daemon.remote.identity.key_persistence_failed"
    );

    let missing = RecordingKeyStore::default();
    missing.miss_next_readback_for(KEY_DIRECTORY_GUARD_ACCOUNT);
    let error =
        install_key_directory_guard(&missing, KeyDirectoryGuard::new([0x77; 16], [0x78; 32], 11))
            .expect_err("missing guard readback must fail");
    assert_eq!(
        error.code(),
        "daemon.remote.identity.key_persistence_failed"
    );
}

#[test]
fn counter_guard_is_bound_to_purpose_epoch_and_only_moves_forward() {
    let store = RecordingKeyStore::default();
    let root_fingerprint = [0x81; 32];
    install_key_directory_guard(
        &store,
        KeyDirectoryGuard::new([0x82; 16], root_fingerprint, 3),
    )
    .unwrap();
    let catalog_7 = KeyId {
        purpose: KeyPurpose::Catalog,
        epoch: 7,
    };
    let reply_7 = KeyId {
        purpose: KeyPurpose::DeviceReplyTx,
        epoch: 7,
    };
    let catalog_8 = KeyId {
        purpose: KeyPurpose::Catalog,
        epoch: 8,
    };

    let first = advance_counter_guard(&store, catalog_7, 1_024).unwrap();
    assert_eq!(first.high_water(), 1_024);
    assert_eq!(
        advance_counter_guard(&store, catalog_7, 1_024).unwrap(),
        first
    );
    assert_eq!(
        advance_counter_guard(&store, catalog_7, 2_048)
            .unwrap()
            .high_water(),
        2_048
    );
    let error = advance_counter_guard(&store, catalog_7, 2_047)
        .expect_err("counter high-water must never decrease");
    assert_eq!(error.code(), "daemon.remote.identity.counter_regression");
    assert_eq!(
        load_counter_guard(&store, catalog_7)
            .unwrap()
            .unwrap()
            .high_water(),
        2_048
    );

    assert_eq!(
        advance_counter_guard(&store, reply_7, 11)
            .unwrap()
            .high_water(),
        11
    );
    assert_eq!(
        advance_counter_guard(&store, catalog_8, 12)
            .unwrap()
            .high_water(),
        12
    );
    assert_ne!(
        counter_guard_account(catalog_7),
        counter_guard_account(reply_7)
    );
    assert_ne!(
        counter_guard_account(catalog_7),
        counter_guard_account(catalog_8)
    );
    assert_eq!(counter_guard_account(catalog_7), "counter-guard/catalog/7");
}

#[test]
fn counter_guard_requires_exact_store_readback() {
    let store = RecordingKeyStore::default();
    let key_id = KeyId {
        purpose: KeyPurpose::Catalog,
        epoch: 77,
    };
    store.corrupt_next_readback_for(&counter_guard_account(key_id));
    let error = advance_counter_guard(&store, key_id, 1_024)
        .expect_err("mutated counter readback must fail");
    assert_eq!(
        error.code(),
        "daemon.remote.identity.key_persistence_failed"
    );

    let missing = RecordingKeyStore::default();
    missing.miss_next_readback_for(&counter_guard_account(key_id));
    let error = advance_counter_guard(&missing, key_id, 1_024)
        .expect_err("missing counter readback must fail");
    assert_eq!(
        error.code(),
        "daemon.remote.identity.key_persistence_failed"
    );

    let update = RecordingKeyStore::default();
    advance_counter_guard(&update, key_id, 1_024).unwrap();
    update.corrupt_readback_after_next_store_for(&counter_guard_account(key_id));
    let error = advance_counter_guard(&update, key_id, 2_048)
        .expect_err("mutated counter update readback must fail");
    assert_eq!(
        error.code(),
        "daemon.remote.identity.key_persistence_failed"
    );

    let missing_update = RecordingKeyStore::default();
    advance_counter_guard(&missing_update, key_id, 1_024).unwrap();
    missing_update.miss_readback_after_next_store_for(&counter_guard_account(key_id));
    let error = advance_counter_guard(&missing_update, key_id, 2_048)
        .expect_err("missing counter update readback must fail");
    assert_eq!(
        error.code(),
        "daemon.remote.identity.key_persistence_failed"
    );
}

#[test]
fn expected_root_fingerprint_prevents_wrong_identity_or_guard_deletion() {
    let store = RecordingKeyStore::default();
    fixed_material(&store);
    let material = load_machine_key_material(&store).unwrap();
    let root_fingerprint = material.public_identity().root().fingerprint();
    install_key_directory_guard(
        &store,
        KeyDirectoryGuard::new([0x91; 16], root_fingerprint, 1),
    )
    .unwrap();
    let scope = KeyId {
        purpose: KeyPurpose::ConversationDek,
        epoch: 4,
    };
    advance_counter_guard(&store, scope, 100).unwrap();

    let wrong = [0xff; 32];
    for error in [
        delete_machine_key_material(&store, wrong).unwrap_err(),
        delete_counter_guard(&store, scope, wrong).unwrap_err(),
        delete_key_directory_guard(&store, wrong).unwrap_err(),
    ] {
        assert_eq!(error.code(), "daemon.remote.identity.fingerprint_mismatch");
    }
    assert!(store.deletes().is_empty());

    assert!(delete_counter_guard(&store, scope, root_fingerprint).unwrap());
    delete_machine_key_material(&store, root_fingerprint).unwrap();
    assert!(delete_key_directory_guard(&store, root_fingerprint).unwrap());
    for account in [
        MACHINE_ROOT_SIGN_ACCOUNT,
        MACHINE_HPKE_ACCOUNT,
        MACHINE_LINK_SIGN_ACCOUNT,
        MACHINE_DATA_SIGN_ACCOUNT,
        KEY_DIRECTORY_GUARD_ACCOUNT,
    ] {
        assert!(store.value(account).is_none(), "{account} must be absent");
    }
}

#[test]
fn debug_and_source_boundary_do_not_expose_secrets_or_p4_2_types() {
    let store = RecordingKeyStore::default();
    let seeds = fixed_material(&store);
    let material = load_machine_key_material(&store).unwrap();
    let debug = format!("{material:?}");
    for seed in seeds {
        let hex = seed
            .iter()
            .map(|byte| format!("{byte:02x}"))
            .collect::<String>();
        assert!(!debug.contains(&hex));
    }
    assert!(debug.contains("REDACTED"));

    let source = include_str!("../src/remote/identity.rs");
    for forbidden in [
        "SignedCertificate",
        "MachineEnrollmentRequest",
        "machine_enrollment_receipts",
        "RelayEnrollmentClient",
        "RemoteLink",
        "std::env",
        "env::var",
        "std::fs",
        "File::",
        "tracing::",
        "println!",
        "eprintln!",
    ] {
        assert!(
            !source.contains(forbidden),
            "P4.1-B must not reference {forbidden}"
        );
    }
    let daemon_source = format!(
        "{}\n{}\n{}\n{}\n{}\n{}",
        include_str!("../src/lib.rs"),
        include_str!("../src/security/mod.rs"),
        include_str!("../src/security/key_store.rs"),
        include_str!("../src/config.rs"),
        include_str!("../src/main.rs"),
        include_str!("../../agentdeck-cli/src/main.rs")
    );
    for forbidden in [
        "AGENTDECK_MACHINE_KEY",
        "AGENTDECK_KEY_DIRECTORY_GUARD",
        "--machine-key-file",
        "--file-keystore",
    ] {
        assert!(
            !daemon_source.contains(forbidden),
            "production must not expose {forbidden} injection"
        );
    }
}

#[test]
fn machine_identity_errors_never_format_secret_material() {
    let error = MachineIdentityError::InvalidKeyLength {
        account: MACHINE_ROOT_SIGN_ACCOUNT,
        actual: 31,
    };
    let rendered = format!("{error:?} {error}");
    assert!(rendered.contains(MACHINE_ROOT_SIGN_ACCOUNT));
    assert!(!rendered.contains("11".repeat(32).as_str()));
}
