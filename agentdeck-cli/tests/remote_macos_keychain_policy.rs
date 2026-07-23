#![cfg(target_os = "macos")]
#![allow(dead_code)]

use std::collections::HashMap;
use std::sync::{Arc, Mutex};

#[path = "../src/remote/keychain.rs"]
mod keychain;

#[path = "../src/remote/signature.rs"]
mod signature;

#[path = "../src/remote/macos_keychain.rs"]
mod macos_keychain;

use keychain::{
    PendingRemoteKeyPurpose, REMOTE_KEYCHAIN_SERVICE, RemoteKeyAccount, RemoteKeyPersistence,
    RemoteKeyStore, RemoteKeyStoreError, RemoteSecret,
};
use macos_keychain::{
    AddOutcome, DeleteOutcome, MacOsRemoteKeyStore, RemoteKeychainOperation, RemoteKeychainPolicy,
    SecurityItemBackend,
};
use signature::{
    CurrentRemoteCliSignatureVerifier, REMOTE_CLI_CODE_IDENTIFIER, RemoteCliSignatureAttestation,
    RemoteCliSignatureError, RemoteCliSignatureExpectation, RemoteCliSignatureKind,
    VerifiedRemoteCliIdentity, verify_current_remote_cli_identity,
};
use uuid::Uuid;

const TEAM_IDENTIFIER: &str = "AUTOMATICHARNESS";
const ACCESS_GROUP: &str = "AUTOMATICHARNESS.com.agentdeck.remote.cli";

struct FixedProductionIdentity;

impl CurrentRemoteCliSignatureVerifier for FixedProductionIdentity {
    fn verify_current(
        &self,
        _expected: &RemoteCliSignatureExpectation,
    ) -> Result<RemoteCliSignatureAttestation, RemoteCliSignatureError> {
        Ok(RemoteCliSignatureAttestation::new(
            RemoteCliSignatureKind::Production,
            REMOTE_CLI_CODE_IDENTIFIER,
            TEAM_IDENTIFIER,
            vec![ACCESS_GROUP.to_owned()],
        ))
    }
}

fn verified_identity_for_policy_test() -> VerifiedRemoteCliIdentity {
    let expected = RemoteCliSignatureExpectation::for_test(
        REMOTE_CLI_CODE_IDENTIFIER,
        TEAM_IDENTIFIER,
        ACCESS_GROUP,
    )
    .unwrap();
    verify_current_remote_cli_identity(&expected, &FixedProductionIdentity).unwrap()
}

#[derive(Clone, Debug, Eq, PartialEq)]
struct PolicySnapshot {
    service: String,
    access_group: String,
    data_protection_keychain: bool,
    synchronizable: bool,
    accessible: &'static str,
    authentication_ui: &'static str,
}

impl PolicySnapshot {
    fn new(policy: &RemoteKeychainPolicy<'_>, operation: RemoteKeychainOperation) -> Self {
        Self {
            service: policy.service().to_owned(),
            access_group: policy.access_group().to_owned(),
            data_protection_keychain: policy.uses_data_protection_keychain(),
            synchronizable: policy.synchronizable(),
            accessible: policy.accessibility_name(),
            authentication_ui: policy.authentication_ui_name(operation),
        }
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
enum Operation {
    Add(PolicySnapshot, String),
    Load(PolicySnapshot, String),
    Delete(PolicySnapshot, String),
}

#[derive(Default)]
struct FakeSecurityItems {
    values: Mutex<HashMap<String, Vec<u8>>>,
    operations: Mutex<Vec<Operation>>,
    drop_next_add: Mutex<bool>,
    retain_next_delete: Mutex<bool>,
}

impl FakeSecurityItems {
    fn operations(&self) -> Vec<Operation> {
        self.operations.lock().unwrap().clone()
    }

    fn drop_next_add(&self) {
        *self.drop_next_add.lock().unwrap() = true;
    }

    fn retain_next_delete(&self) {
        *self.retain_next_delete.lock().unwrap() = true;
    }
}

impl SecurityItemBackend for FakeSecurityItems {
    fn add(
        &self,
        policy: &RemoteKeychainPolicy<'_>,
        account: &str,
        value: &[u8],
    ) -> Result<AddOutcome, ()> {
        self.operations.lock().unwrap().push(Operation::Add(
            PolicySnapshot::new(policy, RemoteKeychainOperation::Add),
            account.to_owned(),
        ));
        let mut values = self.values.lock().unwrap();
        if values.contains_key(account) {
            return Ok(AddOutcome::Duplicate);
        }
        if !std::mem::take(&mut *self.drop_next_add.lock().unwrap()) {
            values.insert(account.to_owned(), value.to_vec());
        }
        Ok(AddOutcome::Inserted)
    }

    fn load(
        &self,
        policy: &RemoteKeychainPolicy<'_>,
        account: &str,
    ) -> Result<Option<Vec<u8>>, ()> {
        self.operations.lock().unwrap().push(Operation::Load(
            PolicySnapshot::new(policy, RemoteKeychainOperation::CopyMatching),
            account.to_owned(),
        ));
        Ok(self.values.lock().unwrap().get(account).cloned())
    }

    fn delete(
        &self,
        policy: &RemoteKeychainPolicy<'_>,
        account: &str,
    ) -> Result<DeleteOutcome, ()> {
        self.operations.lock().unwrap().push(Operation::Delete(
            PolicySnapshot::new(policy, RemoteKeychainOperation::Delete),
            account.to_owned(),
        ));
        let mut values = self.values.lock().unwrap();
        if !values.contains_key(account) {
            return Ok(DeleteOutcome::NotFound);
        }
        if !std::mem::take(&mut *self.retain_next_delete.lock().unwrap()) {
            values.remove(account);
        }
        Ok(DeleteOutcome::Deleted)
    }
}

fn account() -> RemoteKeyAccount {
    RemoteKeyAccount::pending(
        Uuid::from_u128(0x1111_1111_2222_3333_4444_5555_5555_5555),
        [0x61; 32],
        PendingRemoteKeyPurpose::PairingRecord,
    )
}

fn store(backend: Arc<FakeSecurityItems>) -> MacOsRemoteKeyStore {
    let identity = verified_identity_for_policy_test();
    MacOsRemoteKeyStore::new_with_backend(&identity, backend)
}

fn expected_policy(authentication_ui: &'static str) -> PolicySnapshot {
    PolicySnapshot {
        service: REMOTE_KEYCHAIN_SERVICE.to_owned(),
        access_group: ACCESS_GROUP.to_owned(),
        data_protection_keychain: true,
        synchronizable: false,
        accessible: "after-first-unlock-this-device-only",
        authentication_ui,
    }
}

#[test]
fn every_operation_uses_the_fixed_noninteractive_cli_only_policy() {
    let backend = Arc::new(FakeSecurityItems::default());
    let store = store(Arc::clone(&backend));
    let account = account();
    let value = RemoteSecret::new(vec![0xa1; 32]);

    assert_eq!(
        store.persist_immutable(&account, &value).unwrap(),
        RemoteKeyPersistence::Inserted
    );
    assert_eq!(
        store.load(&account).unwrap().unwrap().expose_secret(),
        &[0xa1; 32]
    );
    store.delete_exact(&account).unwrap();

    let operations = backend.operations();
    assert!(
        operations.len() >= 5,
        "mutations must perform exact readback"
    );
    for operation in operations {
        let (policy, expected_ui) = match operation {
            Operation::Add(policy, _) | Operation::Delete(policy, _) => (policy, "fail"),
            Operation::Load(policy, _) => (policy, "skip"),
        };
        assert_eq!(policy, expected_policy(expected_ui));
    }
}

#[test]
fn security_framework_query_uses_skip_only_for_copy_matching() {
    let source = include_str!("../src/remote/macos_keychain.rs");
    let query = source
        .split("struct SecurityItemQuery")
        .nth(1)
        .expect("SecurityItemQuery implementation");
    assert!(query.contains("RemoteKeychainOperation::CopyMatching => kSecUseAuthenticationUISkip"));
    assert!(query.contains("RemoteKeychainOperation::Add | RemoteKeychainOperation::Delete"));
    assert!(query.contains("kSecUseAuthenticationUIFail"));
}

#[test]
fn duplicate_add_is_exactly_idempotent_and_never_updates_existing_bytes() {
    let backend = Arc::new(FakeSecurityItems::default());
    let store = store(Arc::clone(&backend));
    let account = account();
    let first = RemoteSecret::new(vec![0xb2; 32]);
    let different = RemoteSecret::new(vec![0xc3; 32]);

    assert_eq!(
        store.persist_immutable(&account, &first).unwrap(),
        RemoteKeyPersistence::Inserted
    );
    assert_eq!(
        store.persist_immutable(&account, &first).unwrap(),
        RemoteKeyPersistence::AlreadyPresent
    );
    assert_eq!(
        store.persist_immutable(&account, &different),
        Err(RemoteKeyStoreError::ImmutableConflict {
            account: account.clone(),
        })
    );
    assert_eq!(
        store.load(&account).unwrap().unwrap().expose_secret(),
        &[0xb2; 32]
    );

    assert_eq!(
        backend
            .operations()
            .iter()
            .filter(|operation| matches!(operation, Operation::Add(_, _)))
            .count(),
        3,
        "every persist attempt must call add directly; no preflight/update path"
    );
}

#[test]
fn mutation_success_requires_exact_post_operation_readback() {
    let backend = Arc::new(FakeSecurityItems::default());
    let store = store(Arc::clone(&backend));
    let account = account();
    let value = RemoteSecret::new(vec![0xd4; 32]);

    backend.drop_next_add();
    assert_eq!(
        store.persist_immutable(&account, &value),
        Err(RemoteKeyStoreError::PersistenceReadbackFailed {
            account: account.clone(),
        })
    );

    assert_eq!(
        store.persist_immutable(&account, &value).unwrap(),
        RemoteKeyPersistence::Inserted
    );
    backend.retain_next_delete();
    assert_eq!(
        store.delete_exact(&account),
        Err(RemoteKeyStoreError::DeleteReadbackFailed {
            account: account.clone(),
        })
    );
    store.delete_exact(&account).unwrap();
    store.delete_exact(&account).unwrap();
}
