#![cfg(unix)]
#![allow(dead_code)]

#[path = "support/remote_pairing.rs"]
mod remote_pairing;

use std::collections::BTreeMap;
use std::fs;
use std::path::Path;

use agentdeck_cli::remote::keychain::{
    MemoryRemoteKeyStore, PairedRemoteKeyPurpose, RemoteKeyAccount, RemoteKeyStore,
};
use agentdeck_cli::remote::paired_machine::PairedMachineStore;
use agentdeck_crypto::{sha256, sign_tbs};
use agentdeck_protocol::relay_v2::auth::{DeviceRevocation, Ed25519Signature};
use agentdeck_protocol::relay_v2::frame::{AcceptedRef, RevocationCommitted, RouteAccepted};
use agentdeck_protocol::relay_v2::{
    DeviceRouteId, GrantSerial, MachineRouteId, OpaqueRouteFrame, RELAY_PROTOCOL_VERSION,
    RelayFrameBody, RootKeyId, TrustEpoch, encode,
};

use remote_pairing::{
    DEVICE_ROUTE, INSTALLATION_ID, MACHINE_ROUTE, PairingFixture, RELAY_SERVER, ROOT_KEY_ID,
};

const GRANT_SERIAL: GrantSerial = GrantSerial::new(7);
const TRUST_EPOCH: TrustEpoch = TrustEpoch::new(2);

#[derive(Debug, Eq, PartialEq)]
struct DurableSnapshot {
    keychain: Vec<(PairedRemoteKeyPurpose, Option<Vec<u8>>)>,
    files: BTreeMap<String, Vec<u8>>,
}

#[test]
fn only_exact_root_signed_revocation_terminal_mints_cleanup_authority_without_mutation() {
    let temp = tempfile::tempdir().expect("temp state root");
    let state_root = fs::canonicalize(temp.path())
        .expect("canonical tempdir")
        .join("remote-state");
    let store = MemoryRemoteKeyStore::new();
    let fixture = PairingFixture::new();
    fixture.promote(&store, &state_root, 0x91);
    let paired = PairedMachineStore::new(&store, INSTALLATION_ID, &state_root);
    let opened = paired
        .open_exact(fixture.identity())
        .expect("open audited paired machine");
    let before = durable_snapshot(&store, &state_root, &fixture);

    let valid = signed_terminal(&fixture);
    let valid_bytes = encode(&valid);
    let _verified = opened
        .verify_revocation_terminal(&valid, &valid_bytes)
        .expect("exact root-signed terminal must mint an opaque cleanup authority");
    assert_eq!(durable_snapshot(&store, &state_root, &fixture), before);

    let mut cases = Vec::new();

    let mut forged_signature = valid.clone();
    let RelayFrameBody::RevocationCommitted(committed) = &mut forged_signature.body else {
        unreachable!()
    };
    committed.signed_revocation.signature.0[0] ^= 0x80;
    cases.push(("forged signature", forged_signature));

    cases.push((
        "wrong machine route",
        terminal_with(
            &fixture,
            MachineRouteId::from_bytes([0xa1; 16]),
            DEVICE_ROUTE,
            GRANT_SERIAL,
            ROOT_KEY_ID,
            TRUST_EPOCH,
        ),
    ));
    cases.push((
        "wrong device route",
        terminal_with(
            &fixture,
            MACHINE_ROUTE,
            DeviceRouteId::from_bytes([0xa2; 16]),
            GRANT_SERIAL,
            ROOT_KEY_ID,
            TRUST_EPOCH,
        ),
    ));
    cases.push((
        "wrong grant serial",
        terminal_with(
            &fixture,
            MACHINE_ROUTE,
            DEVICE_ROUTE,
            GrantSerial::new(8),
            ROOT_KEY_ID,
            TRUST_EPOCH,
        ),
    ));
    cases.push((
        "wrong root key id",
        terminal_with(
            &fixture,
            MACHINE_ROUTE,
            DEVICE_ROUTE,
            GRANT_SERIAL,
            RootKeyId::from_bytes([0xa3; 16]),
            TRUST_EPOCH,
        ),
    ));
    cases.push((
        "wrong trust epoch",
        terminal_with(
            &fixture,
            MACHINE_ROUTE,
            DEVICE_ROUTE,
            GRANT_SERIAL,
            ROOT_KEY_ID,
            TrustEpoch::new(3),
        ),
    ));

    let mut outer_mismatch = valid.clone();
    let RelayFrameBody::RevocationCommitted(committed) = &mut outer_mismatch.body else {
        unreachable!()
    };
    committed.grant_serial = GrantSerial::new(99);
    cases.push(("outer and signed terminal disagree", outer_mismatch));

    let mut outer_device_mismatch = valid.clone();
    let RelayFrameBody::RevocationCommitted(committed) = &mut outer_device_mismatch.body else {
        unreachable!()
    };
    committed.device_route = DeviceRouteId::from_bytes([0xa5; 16]);
    cases.push((
        "outer device and signed terminal disagree",
        outer_device_mismatch,
    ));

    for (label, frame) in cases {
        let error = opened
            .verify_revocation_terminal(&frame, &encode(&frame))
            .expect_err(label);
        assert!(
            matches!(
                error.code(),
                "remote.pairing.paired_invalid" | "remote.pairing.paired_conflict"
            ),
            "{label}: unexpected typed failure {}",
            error.code()
        );
        assert_eq!(
            durable_snapshot(&store, &state_root, &fixture),
            before,
            "{label} must perform zero durable mutation"
        );
    }

    let mut noncanonical = valid_bytes.clone();
    noncanonical.push(0);
    opened
        .verify_revocation_terminal(&valid, &noncanonical)
        .expect_err("caller-provided bytes must exactly match canonical frame bytes");

    let wrong_kind = OpaqueRouteFrame {
        version: RELAY_PROTOCOL_VERSION,
        body: RelayFrameBody::RouteAccepted(RouteAccepted {
            accepted: AcceptedRef::Request {
                request_route: agentdeck_protocol::relay_v2::RequestRouteId::from_bytes([0xa4; 16]),
            },
        }),
    };
    opened
        .verify_revocation_terminal(&wrong_kind, &encode(&wrong_kind))
        .expect_err("ordinary Relay frames are not cleanup authority");

    let mut wrong_version = valid.clone();
    wrong_version.version = RELAY_PROTOCOL_VERSION + 1;
    opened
        .verify_revocation_terminal(&wrong_version, &encode(&wrong_version))
        .expect_err("wrong Relay protocol version is not cleanup authority");
    assert_eq!(durable_snapshot(&store, &state_root, &fixture), before);
}

fn signed_terminal(fixture: &PairingFixture) -> OpaqueRouteFrame {
    terminal_with(
        fixture,
        MACHINE_ROUTE,
        DEVICE_ROUTE,
        GRANT_SERIAL,
        ROOT_KEY_ID,
        TRUST_EPOCH,
    )
}

fn terminal_with(
    fixture: &PairingFixture,
    machine_route: MachineRouteId,
    device_route: DeviceRouteId,
    grant_serial: GrantSerial,
    root_key_id: RootKeyId,
    trust_epoch: TrustEpoch,
) -> OpaqueRouteFrame {
    let root = PairingFixture::root_signing_key();
    let root_fingerprint = sha256(&root.verifying_key().to_bytes());
    assert_eq!(root_fingerprint, fixture.invite().machine_root_fingerprint);
    let mut revocation = DeviceRevocation {
        machine_route,
        device_route,
        grant_serial,
        root_key_id,
        trust_epoch,
        signature: Ed25519Signature([0; 64]),
    };
    revocation.signature = sign_tbs(
        &root,
        &revocation.to_be_signed_v1(RELAY_SERVER, root_fingerprint),
    )
    .into();
    OpaqueRouteFrame {
        version: RELAY_PROTOCOL_VERSION,
        body: RelayFrameBody::RevocationCommitted(RevocationCommitted {
            device_route,
            grant_serial,
            signed_revocation: revocation,
        }),
    }
}

fn durable_snapshot(
    store: &dyn RemoteKeyStore,
    state_root: &Path,
    fixture: &PairingFixture,
) -> DurableSnapshot {
    let identity = fixture.identity();
    let purposes = [
        PairedRemoteKeyPurpose::DeviceSignPrivateKey,
        PairedRemoteKeyPurpose::DeviceHpkePrivateKey,
        PairedRemoteKeyPurpose::DeviceGrant,
        PairedRemoteKeyPurpose::DeviceStorageKek,
        PairedRemoteKeyPurpose::CounterGuard,
        PairedRemoteKeyPurpose::CommitMarker,
    ];
    let keychain = purposes
        .into_iter()
        .map(|purpose| {
            let account = RemoteKeyAccount::paired(
                INSTALLATION_ID,
                identity.machine_root_fingerprint(),
                identity.machine_route(),
                purpose,
            );
            let value = store
                .load(&account)
                .expect("snapshot Keychain item")
                .map(|secret| secret.expose_secret().to_vec());
            (purpose, value)
        })
        .collect();
    let mut files = BTreeMap::new();
    collect_files(state_root, state_root, &mut files);
    DurableSnapshot { keychain, files }
}

fn collect_files(root: &Path, current: &Path, files: &mut BTreeMap<String, Vec<u8>>) {
    let mut entries = fs::read_dir(current)
        .unwrap_or_else(|error| panic!("read state directory {}: {error}", current.display()))
        .collect::<Result<Vec<_>, _>>()
        .expect("collect state directory");
    entries.sort_unstable_by_key(|entry| entry.file_name());
    for entry in entries {
        let path = entry.path();
        let metadata = fs::symlink_metadata(&path).expect("state entry metadata");
        if metadata.is_dir() {
            collect_files(root, &path, files);
        } else if metadata.is_file() {
            let relative = path
                .strip_prefix(root)
                .expect("state path remains under root")
                .to_string_lossy()
                .into_owned();
            files.insert(relative, fs::read(&path).expect("read state file"));
        }
    }
}
