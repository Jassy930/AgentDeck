use std::sync::{Arc, Barrier};

use agentdeck_cli::remote::keychain::{
    MemoryRemoteKeyStore, PairedRemoteKeyPurpose, PendingRemoteKeyPurpose, REMOTE_KEYCHAIN_SERVICE,
    RemoteKeyAccount, RemoteKeyPersistence, RemoteKeyPurpose, RemoteKeyStore, RemoteKeyStoreError,
    RemoteSecret,
};
use agentdeck_protocol::relay_v2::MachineRouteId;
use agentdeck_protocol::runtime::MachineRootFingerprint;
use uuid::Uuid;

const INSTALLATION: Uuid = Uuid::from_bytes([0; 16]);
const ZERO_32_URL_SAFE: &str = "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA";
const ZERO_16_URL_SAFE: &str = "AAAAAAAAAAAAAAAAAAAAAA";

fn pending_account(purpose: PendingRemoteKeyPurpose) -> RemoteKeyAccount {
    RemoteKeyAccount::pending(INSTALLATION, [0; 32], purpose)
}

fn paired_account(purpose: PairedRemoteKeyPurpose) -> RemoteKeyAccount {
    RemoteKeyAccount::paired(
        INSTALLATION,
        MachineRootFingerprint::from_bytes([0; 32]),
        MachineRouteId::from_bytes([0; 16]),
        purpose,
    )
}

#[test]
fn keychain_service_and_accounts_are_canonical_and_client_scoped() {
    assert_eq!(REMOTE_KEYCHAIN_SERVICE, "com.agentdeck.remote.v1");

    let pending = pending_account(PendingRemoteKeyPurpose::PairingRecord);
    assert_eq!(
        pending.as_str(),
        format!("pending/cli/{INSTALLATION}/{ZERO_32_URL_SAFE}/pending-pairing-record.v1")
    );

    let paired = paired_account(PairedRemoteKeyPurpose::DeviceSignPrivateKey);
    assert_eq!(
        paired.as_str(),
        format!(
            "cli/{INSTALLATION}/{ZERO_32_URL_SAFE}/{ZERO_16_URL_SAFE}/device-sign-private-key.v1"
        )
    );
    assert!(!pending.as_str().contains('='));
    assert!(!paired.as_str().contains('='));
}

#[test]
fn closed_key_purposes_have_unique_versioned_account_components() {
    let purposes = [
        (
            RemoteKeyPurpose::PendingPairingRecord,
            "pending-pairing-record.v1",
        ),
        (
            RemoteKeyPurpose::DeviceSignPrivateKey,
            "device-sign-private-key.v1",
        ),
        (
            RemoteKeyPurpose::DeviceHpkePrivateKey,
            "device-hpke-private-key.v1",
        ),
        (RemoteKeyPurpose::DeviceGrant, "device-grant.v1"),
        (RemoteKeyPurpose::DeviceStorageKek, "device-storage-kek.v1"),
        (RemoteKeyPurpose::CounterGuard, "counter-guard.v1"),
        (
            RemoteKeyPurpose::PairedCommitMarker,
            "paired-commit-marker.v1",
        ),
    ];

    let mut components = std::collections::BTreeSet::new();
    for (purpose, expected) in purposes {
        assert_eq!(purpose.account_component(), expected);
        assert!(components.insert(expected));
    }
}

#[test]
fn account_debug_display_and_errors_do_not_expose_stable_identifiers() {
    let account = RemoteKeyAccount::paired(
        Uuid::from_bytes([0xff; 16]),
        MachineRootFingerprint::from_bytes([0xfe; 32]),
        MachineRouteId::from_bytes([0xfd; 16]),
        PairedRemoteKeyPurpose::DeviceStorageKek,
    );
    let canonical = account.as_str().to_owned();
    let display = account.to_string();
    let debug = format!("{account:?}");
    let error = RemoteKeyStoreError::ImmutableConflict {
        account: account.clone(),
    }
    .to_string();
    let components = canonical.split('/').collect::<Vec<_>>();
    assert_eq!(components.len(), 5);

    assert!(display.starts_with("remote-key-account:"));
    assert_eq!(display.len(), "remote-key-account:".len() + 16);
    for rendered in [&display, &debug, &error] {
        assert!(!rendered.contains(&canonical));
        for identifier in &components[1..4] {
            assert!(!rendered.contains(identifier));
        }
    }
}

#[test]
fn immutable_insert_retries_exact_bytes_and_rejects_conflicts_without_overwrite() {
    let store = MemoryRemoteKeyStore::new();
    let account = paired_account(PairedRemoteKeyPurpose::DeviceStorageKek);
    let original = RemoteSecret::new(vec![0x41; 32]);

    assert_eq!(
        store
            .persist_immutable(&account, &original)
            .expect("insert fresh secret"),
        RemoteKeyPersistence::Inserted
    );
    assert_eq!(
        store
            .persist_immutable(&account, &RemoteSecret::new(vec![0x41; 32]))
            .expect("retry exact secret"),
        RemoteKeyPersistence::AlreadyPresent
    );

    let error = store
        .persist_immutable(&account, &RemoteSecret::new(vec![0x42; 32]))
        .expect_err("different bytes must not replace an immutable item");
    assert!(matches!(
        error,
        RemoteKeyStoreError::ImmutableConflict { account: ref conflicted }
            if conflicted == &account
    ));
    assert_eq!(
        store
            .load(&account)
            .expect("load original after conflict")
            .expect("original remains present")
            .expose_secret(),
        &[0x41; 32]
    );
}

#[test]
fn concurrent_immutable_insert_has_one_winner_and_never_mixes_values() {
    let store = Arc::new(MemoryRemoteKeyStore::new());
    let barrier = Arc::new(Barrier::new(3));
    let account = paired_account(PairedRemoteKeyPurpose::CounterGuard);
    let mut workers = Vec::new();

    for byte in [0x51, 0x52] {
        let store = Arc::clone(&store);
        let barrier = Arc::clone(&barrier);
        let account = account.clone();
        workers.push(std::thread::spawn(move || {
            barrier.wait();
            (
                byte,
                store.persist_immutable(&account, &RemoteSecret::new(vec![byte; 32])),
            )
        }));
    }
    barrier.wait();

    let results = workers
        .into_iter()
        .map(|worker| worker.join().expect("keystore worker did not panic"))
        .collect::<Vec<_>>();
    let inserted = results
        .iter()
        .filter_map(|(byte, result)| {
            matches!(result, Ok(RemoteKeyPersistence::Inserted)).then_some(*byte)
        })
        .collect::<Vec<_>>();
    assert_eq!(inserted.len(), 1);
    assert_eq!(
        results
            .iter()
            .filter(|(_, result)| {
                matches!(result, Err(RemoteKeyStoreError::ImmutableConflict { .. }))
            })
            .count(),
        1
    );

    let persisted = store
        .load(&account)
        .expect("load concurrent winner")
        .expect("one winner must persist");
    assert_eq!(persisted.expose_secret(), &[inserted[0]; 32]);
}

#[test]
fn concurrent_same_bytes_have_one_insert_and_idempotent_followers() {
    const WORKERS: usize = 4;
    let store = Arc::new(MemoryRemoteKeyStore::new());
    let barrier = Arc::new(Barrier::new(WORKERS + 1));
    let account = paired_account(PairedRemoteKeyPurpose::CounterGuard);
    let workers = (0..WORKERS)
        .map(|_| {
            let store = Arc::clone(&store);
            let barrier = Arc::clone(&barrier);
            let account = account.clone();
            std::thread::spawn(move || {
                barrier.wait();
                store.persist_immutable(&account, &RemoteSecret::new(vec![0x53; 32]))
            })
        })
        .collect::<Vec<_>>();
    barrier.wait();

    let results = workers
        .into_iter()
        .map(|worker| worker.join().expect("keystore worker did not panic"))
        .collect::<Vec<_>>();
    assert_eq!(
        results
            .iter()
            .filter(|result| matches!(result, Ok(RemoteKeyPersistence::Inserted)))
            .count(),
        1
    );
    assert_eq!(
        results
            .iter()
            .filter(|result| matches!(result, Ok(RemoteKeyPersistence::AlreadyPresent)))
            .count(),
        WORKERS - 1
    );
    assert_eq!(
        store
            .load(&account)
            .expect("load same-byte winner")
            .expect("winner remains present")
            .expose_secret(),
        &[0x53; 32]
    );
}

#[test]
fn delete_requires_absent_readback_and_is_idempotent() {
    let store = MemoryRemoteKeyStore::new();
    let account = paired_account(PairedRemoteKeyPurpose::DeviceGrant);
    store
        .persist_immutable(&account, &RemoteSecret::new(vec![0x61; 48]))
        .expect("seed secret");

    store.delete_exact(&account).expect("delete present item");
    assert!(store.load(&account).expect("read absent item").is_none());
    store.delete_exact(&account).expect("repeat absent delete");
}

#[test]
fn secret_debug_output_is_redacted() {
    let secret = RemoteSecret::new(vec![0xde, 0xad, 0xbe, 0xef]);
    assert_eq!(format!("{secret:?}"), "RemoteSecret([REDACTED])");
    assert!(!format!("{secret:?}").contains("222"));
}
