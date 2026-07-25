use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
use std::sync::{Arc, Mutex};
use std::time::Duration;

use agentdeck_crypto::{HpkePrivateKey, HpkePublicKey, SecretAeadKey, sha256};
use agentdeck_protocol::e2ee::{
    AuthorizationCapabilityV1, AuthorizationPermissionV1, DeviceAuthorizationV1,
    E2EE_FORMAT_VERSION, KeyControlV1, KeyDirectoryEntry, KeyId, KeyPurpose, KeyUpdateInfoV1,
    KeyUpdateSetV1, KeyUpdateV1, OuterContextV1, SignedSealedBlobV1,
};
use agentdeck_protocol::relay_v2::frame::{AcceptedRef, RouteAccepted};
use agentdeck_protocol::relay_v2::{
    DeviceRouteId, Ed25519Signature, GrantSerial, KeyDirectoryRevision, MachineRouteId,
    OpaqueRouteFrame, PublicKeyBytes, RELAY_PROTOCOL_VERSION, RelayFrameBody, RelayGrant,
    RelayServerId, RootKeyId, SignedCertificate, StreamRouteId, TrustEpoch,
};
use agentdeck_protocol::runtime::identity::ConversationId;
use agentdeck_protocol::runtime::{RuntimeInnerCursor, StreamCursor};
use async_trait::async_trait;

use crate::runtime::model::{
    MachineIdentityBinding, RuntimeClock, RuntimeClockError, RuntimeStoreConfig,
    RuntimeStoreFaultInjector, RuntimeStoreOperation,
};
use crate::runtime::publication::{
    PublicationCommitReceipt, PublicationDispatchKey, PublicationTransport,
    PublicationTransportOutcome,
};
use crate::runtime::store::identity::{RuntimeId, RuntimeIdKind};
use crate::runtime::store::key_transition::{
    CounterRetirementLifecycle, FrozenKeyUpdate, KeyTransitionGlobalLineage,
    KeyTransitionOperation, KeyTransitionPhase, KeyTransitionRecipient, KeyTransitionRecord,
    KeyTransitionRecovery, KeyTransitionStreamCut, KeyTransitionStreamScope, KeyTransitionTarget,
    KeyUpdateLifecycle, KeyUpdateRecord, PairingBootstrapInstallBinding,
    PairingBootstrapInstallProof, RemoteTransitionIngressClass,
};
use crate::runtime::store::pairing_grant::{ConversationKeyRotation, GlobalKeyStateV1};
use crate::runtime::store::remote_counter::{
    CounterRecoveryDisposition, CounterRecoveryStageRequest, CounterRecoveryStageTarget,
    RemoteCounterRecordKind, RemoteCounterRetirementRequest,
};
use crate::runtime::store::{
    ActiveSenderCounterBinding, FrozenPublication, MachineEnrollmentState, PublicationScope,
    RuntimeStoreError, RuntimeStoreHandle,
    active_authorization_store_with_pending_transition_for_test,
    production_aligned_active_authorization_store_for_test,
};
use crate::security::{KeyStore, MemoryKeyStore, SecretBytes, load_or_create_storage_kek};

use super::bootstrap::{machine_pairing_anchor_for_test, recover_key_directory_rotation};
use super::counter::{COUNTER_BLOCK_SIZE, CounterGuardBackend, CounterGuardPhase, CounterScope};
use super::identity::{
    KeyDirectoryGuard, OwnedKeyStoreCounterGuardBackend, install_key_directory_guard,
};
use super::publication_transport::{
    PublicationDriveOwner, tests::open_owner_with_transport_for_test,
};
use super::publisher::PublicationClass;
use super::transition::{
    AuthenticatedCommittedStreamCut, DirectoryAdvancePublicationRequest,
    DirectoryAdvancePublicationTarget, EpochBarrierPublicationRequest,
    EpochBarrierPublicationTarget, ExactDirectoryAdvanceCommit, ExactEpochBarrierCommit,
    KeyUpdateAuthority, TransitionAdvance, TransitionAnchor, TransitionBackend,
    TransitionCatalogStream, TransitionCoordinator, TransitionCoordinatorError, TransitionMaterial,
    TransitionRecipientMaterial, build_frozen_key_updates,
};
use super::transition_backend::RuntimeStoreTransitionBackend;
use super::transition_owner::{
    KeyTransitionRecoveryError, KeyTransitionRecoveryOwner, TransitionProgress, TransitionReadiness,
};
use super::transport::MachineDataAuthority;
use super::transport::tests::{
    MachineDataAuthorityOwnerLease, machine_data_authority_for_transition_test,
};

const RELAY: [u8; 16] = [0x11; 16];
const MACHINE: [u8; 16] = [0x12; 16];
const ROOT: [u8; 16] = [0x13; 16];
const DEVICE_A: [u8; 16] = [0x21; 16];
const DEVICE_B: [u8; 16] = [0x22; 16];
const CONVERSATION_A: [u8; 16] = [0x31; 16];
const CONVERSATION_B: [u8; 16] = [0x32; 16];
const OPERATION: [u8; 16] = [0x41; 16];
const REVISION: u64 = 4;

#[derive(Default)]
struct ExactPublicationTransport {
    publish_calls: AtomicUsize,
    offline_before_commit: usize,
    outcome_unknown_before_commit: usize,
    attempts: Mutex<Vec<ExactPublicationAttempt>>,
}

#[derive(Default)]
struct InFlightOfflineThenCommitTransport {
    publish_calls: AtomicUsize,
    attempts: Mutex<Vec<ExactPublicationAttempt>>,
    first_publish_entered: tokio::sync::Notify,
    release_first_publish: tokio::sync::Notify,
}

#[derive(Clone, Debug, Eq, PartialEq)]
struct ExactPublicationAttempt {
    publication_id: [u8; 16],
    publication_stream_id: [u8; 16],
    generation: [u8; 16],
    stream_seq: u64,
    counter_scope_token: [u8; 32],
    sender_counter: u64,
    blob_sha256: [u8; 32],
    counter_db_anchor: Option<[u8; 32]>,
    blob: Vec<u8>,
}

impl ExactPublicationTransport {
    fn with_outcome_unknown_before_commit(outcome_unknown_before_commit: usize) -> Self {
        Self {
            publish_calls: AtomicUsize::new(0),
            offline_before_commit: 0,
            outcome_unknown_before_commit,
            attempts: Mutex::new(Vec::new()),
        }
    }

    fn with_offline_before_commit(offline_before_commit: usize) -> Self {
        Self {
            publish_calls: AtomicUsize::new(0),
            offline_before_commit,
            outcome_unknown_before_commit: 0,
            attempts: Mutex::new(Vec::new()),
        }
    }

    fn attempts(&self) -> Vec<ExactPublicationAttempt> {
        self.attempts
            .lock()
            .expect("exact publication attempts")
            .clone()
    }
}

impl InFlightOfflineThenCommitTransport {
    fn attempts(&self) -> Vec<ExactPublicationAttempt> {
        self.attempts
            .lock()
            .expect("in-flight exact publication attempts")
            .clone()
    }

    async fn wait_until_first_publish_is_in_flight(&self) {
        self.first_publish_entered.notified().await;
    }

    fn release_first_publish_as_offline(&self) {
        self.release_first_publish.notify_one();
    }
}

#[derive(Clone, Copy)]
struct TransitionCompositionClock;

impl RuntimeClock for TransitionCompositionClock {
    fn now_ms(&self) -> Result<u64, RuntimeClockError> {
        Ok(1_800_000_000_100)
    }
}

#[async_trait]
impl PublicationTransport for ExactPublicationTransport {
    async fn publish(&self, publication: FrozenPublication) -> PublicationTransportOutcome {
        self.attempts
            .lock()
            .expect("record exact publication attempt")
            .push(ExactPublicationAttempt {
                publication_id: publication.publication_id,
                publication_stream_id: publication.publication_stream_id,
                generation: publication.generation,
                stream_seq: publication.stream_seq,
                counter_scope_token: publication.counter_scope_token,
                sender_counter: publication.sender_counter,
                blob_sha256: publication.blob_sha256,
                counter_db_anchor: publication.counter_db_anchor,
                blob: publication.blob.clone(),
            });
        let attempt = self.publish_calls.fetch_add(1, Ordering::SeqCst) + 1;
        if attempt <= self.offline_before_commit {
            return PublicationTransportOutcome::Offline;
        }
        if attempt
            <= self
                .offline_before_commit
                .saturating_add(self.outcome_unknown_before_commit)
        {
            return PublicationTransportOutcome::OutcomeUnknown;
        }
        PublicationTransportOutcome::Committed(PublicationCommitReceipt {
            key: PublicationDispatchKey::from(&publication),
        })
    }
}

#[async_trait]
impl PublicationTransport for InFlightOfflineThenCommitTransport {
    async fn publish(&self, publication: FrozenPublication) -> PublicationTransportOutcome {
        self.attempts
            .lock()
            .expect("record in-flight exact publication attempt")
            .push(ExactPublicationAttempt {
                publication_id: publication.publication_id,
                publication_stream_id: publication.publication_stream_id,
                generation: publication.generation,
                stream_seq: publication.stream_seq,
                counter_scope_token: publication.counter_scope_token,
                sender_counter: publication.sender_counter,
                blob_sha256: publication.blob_sha256,
                counter_db_anchor: publication.counter_db_anchor,
                blob: publication.blob.clone(),
            });
        let attempt = self.publish_calls.fetch_add(1, Ordering::SeqCst);
        if attempt == 0 {
            self.first_publish_entered.notify_one();
            self.release_first_publish.notified().await;
            return PublicationTransportOutcome::Offline;
        }
        PublicationTransportOutcome::Committed(PublicationCommitReceipt {
            key: PublicationDispatchKey::from(&publication),
        })
    }
}

#[derive(Clone, Copy)]
enum EpochBarrierCrashRelayPlan {
    Commit,
    OutcomeUnknown,
}

struct RecordingEpochBarrierTransport {
    plan: EpochBarrierCrashRelayPlan,
    sent: Mutex<Vec<Vec<u8>>>,
}

impl RecordingEpochBarrierTransport {
    fn new(plan: EpochBarrierCrashRelayPlan) -> Self {
        Self {
            plan,
            sent: Mutex::new(Vec::new()),
        }
    }

    fn sent_blobs(&self) -> Vec<Vec<u8>> {
        self.sent
            .lock()
            .expect("production EpochBarrier transport lock")
            .clone()
    }
}

#[async_trait]
impl PublicationTransport for RecordingEpochBarrierTransport {
    async fn publish(&self, publication: FrozenPublication) -> PublicationTransportOutcome {
        let key = PublicationDispatchKey::from(&publication);
        self.sent
            .lock()
            .expect("record production EpochBarrier publication")
            .push(publication.blob);
        match self.plan {
            EpochBarrierCrashRelayPlan::Commit => {
                PublicationTransportOutcome::Committed(PublicationCommitReceipt { key })
            }
            EpochBarrierCrashRelayPlan::OutcomeUnknown => {
                PublicationTransportOutcome::OutcomeUnknown
            }
        }
    }
}

#[derive(Debug)]
struct EpochBarrierCrashOnce {
    target: RuntimeStoreOperation,
    armed: AtomicBool,
}

impl EpochBarrierCrashOnce {
    fn new(target: RuntimeStoreOperation) -> Self {
        Self {
            target,
            armed: AtomicBool::new(true),
        }
    }

    fn fired(&self) -> bool {
        !self.armed.load(Ordering::SeqCst)
    }
}

impl RuntimeStoreFaultInjector for EpochBarrierCrashOnce {
    fn before_operation(&self, operation: RuntimeStoreOperation) -> Result<(), RuntimeStoreError> {
        if operation == self.target && self.armed.swap(false, Ordering::SeqCst) {
            return Err(RuntimeStoreError::WorkerStopped);
        }
        Ok(())
    }
}

struct ProductionEpochBarrierCrashFixture {
    _root: tempfile::TempDir,
    database: std::path::PathBuf,
    keys: Arc<MemoryKeyStore>,
    store: RuntimeStoreHandle,
    operation_id: [u8; 16],
    publication_stream_id: [u8; 16],
    replacement_key_id: KeyId,
    trust_domain: [u8; 32],
    relay_server_id: RelayServerId,
    machine_route: MachineRouteId,
    binding: MachineIdentityBinding,
    data_certificate: SignedCertificate,
}

impl ProductionEpochBarrierCrashFixture {
    fn machine_data_authority(&self) -> (MachineDataAuthority, MachineDataAuthorityOwnerLease) {
        machine_data_authority_for_transition_test(
            machine_pairing_anchor_for_test(
                self.relay_server_id,
                self.machine_route,
                &self.binding,
                self.data_certificate.clone(),
            ),
            [0x43; 32],
        )
    }

    fn key_store(&self) -> Arc<dyn KeyStore> {
        self.keys.clone()
    }

    fn counter_scope(&self) -> CounterScope {
        CounterScope::publication(
            self.trust_domain,
            self.replacement_key_id,
            self.publication_stream_id,
        )
        .expect("derive production EpochBarrier replacement scope")
    }

    fn assert_pending_counter_guard(&self) {
        let backend = OwnedKeyStoreCounterGuardBackend::new(self.key_store());
        let guard = backend
            .load_guard(&self.counter_scope())
            .expect("load production EpochBarrier CounterGuard")
            .expect("EpochBarrier crash leaves a materialized CounterGuard");
        assert_eq!(guard.phase(), CounterGuardPhase::Pending);
    }

    async fn reopen(&self) -> RuntimeStoreHandle {
        self.reopen_with_config(
            RuntimeStoreConfig::new(self.database.clone()).with_clock(TransitionCompositionClock),
        )
        .await
    }

    async fn reopen_with_config(&self, config: RuntimeStoreConfig) -> RuntimeStoreHandle {
        let storage_kek = load_or_create_storage_kek(self.keys.as_ref(), &self.database)
            .expect("reload production EpochBarrier StorageKEK");
        RuntimeStoreHandle::open(config, storage_kek)
            .await
            .expect("reopen production EpochBarrier Store")
    }
}

async fn production_epoch_barrier_crash_fixture(cut: &str) -> ProductionEpochBarrierCrashFixture {
    let root = tempfile::tempdir().expect("create production EpochBarrier crash root");
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;

        std::fs::set_permissions(root.path(), std::fs::Permissions::from_mode(0o700))
            .expect("secure production EpochBarrier crash root");
    }
    let database = root.path().join(format!("epoch-barrier-{cut}.db"));
    let keys = Arc::new(MemoryKeyStore::new());
    let storage_kek = load_or_create_storage_kek(keys.as_ref(), &database)
        .expect("create production EpochBarrier StorageKEK");
    let store = production_aligned_active_authorization_store_for_test(
        &database,
        storage_kek,
        vec![AuthorizationCapabilityV1::Catalog],
        vec![AuthorizationPermissionV1::CatalogRead],
    )
    .await;
    let publication_stream_id = [0xc1; 16];
    store
        .create_publication_stream(
            publication_stream_id,
            PublicationScope::Catalog,
            [0xc2; 16],
            [0xc3; 16],
        )
        .await
        .expect("create production EpochBarrier Catalog stream");
    assert!(
        store
            .load_active_key_transition()
            .await
            .expect("load empty EpochBarrier transition slot")
            .is_none()
    );

    let retired_key_id = store
        .load_active_sender_counter_bindings()
        .await
        .expect("load production EpochBarrier sender binding")
        .into_iter()
        .find_map(|binding| match binding {
            ActiveSenderCounterBinding::SharedPublication {
                publication_stream_id: observed_stream,
                key_id,
            } if observed_stream == publication_stream_id
                && key_id.purpose == KeyPurpose::Catalog =>
            {
                Some(key_id)
            }
            _ => None,
        })
        .expect("exact production EpochBarrier Catalog sender binding");
    let trust_domain = store
        .machine_trust_domain()
        .expect("production EpochBarrier trust domain");
    let retired_scope =
        CounterScope::publication(trust_domain, retired_key_id, publication_stream_id)
            .expect("derive production EpochBarrier retired scope");
    let replacement_key_id = KeyId {
        purpose: retired_key_id.purpose,
        epoch: retired_key_id
            .epoch
            .checked_add(1)
            .expect("production EpochBarrier key epoch has a successor"),
    };
    let replacement_scope =
        CounterScope::publication(trust_domain, replacement_key_id, publication_stream_id)
            .expect("derive production EpochBarrier replacement scope");
    let genesis = store
        .load_remote_counter_record(retired_scope.token(), retired_key_id)
        .await
        .expect("load production EpochBarrier counter genesis");
    assert_eq!(genesis.kind, RemoteCounterRecordKind::Genesis);
    let retired = store
        .retire_remote_counter(RemoteCounterRetirementRequest {
            scope_token: retired_scope.token(),
            key_id: retired_key_id,
            expected_reserved_end: genesis.reserved_end,
            expected_db_anchor: genesis.db_anchor,
            retired_through: COUNTER_BLOCK_SIZE,
        })
        .await
        .expect("retire production EpochBarrier old counter scope");
    assert_eq!(retired.kind, RemoteCounterRecordKind::Retired);

    let operation_id = [0xc4; 16];
    let staged = store
        .stage_remote_counter_recovery(CounterRecoveryStageRequest {
            operation_id,
            retired_scope_token: retired_scope.token(),
            retired_key_id,
            replacement_scope_token: replacement_scope.token(),
            target: CounterRecoveryStageTarget::SharedPublication {
                publication_stream_id,
            },
        })
        .await
        .expect("stage production EpochBarrier counter recovery");
    assert_eq!(staged.disposition, CounterRecoveryDisposition::Staged);
    assert_eq!(
        staged
            .binding
            .expect("production EpochBarrier staged recovery binding")
            .replacement_key_id,
        replacement_key_id
    );
    let transition = store
        .load_active_key_transition()
        .await
        .expect("load production EpochBarrier transition")
        .expect("production EpochBarrier transition is active");
    assert_eq!(transition.transition.operation_id, operation_id);
    assert_eq!(transition.transition.phase, KeyTransitionPhase::DrainingOld);
    let identity = store
        .load_machine_identity_state()
        .await
        .expect("load production EpochBarrier machine identity")
        .expect("production EpochBarrier machine identity exists");
    install_key_directory_guard(
        keys.as_ref(),
        KeyDirectoryGuard::new(
            identity.database_id,
            identity.binding.root_fingerprint,
            transition.transition.from_revision,
        ),
    )
    .expect("install production EpochBarrier key-directory guard");
    let Some(MachineEnrollmentState::Active(active)) = store
        .load_machine_enrollment_state()
        .await
        .expect("load production EpochBarrier machine enrollment")
    else {
        panic!("production EpochBarrier fixture must remain actively enrolled")
    };

    ProductionEpochBarrierCrashFixture {
        _root: root,
        database,
        keys,
        store,
        operation_id,
        publication_stream_id,
        replacement_key_id,
        trust_domain,
        relay_server_id: active.connection.relay_server_id,
        machine_route: MachineRouteId::from_bytes(active.record.machine_route),
        binding: active.binding,
        data_certificate: active.data_cert,
    }
}

async fn assert_epoch_barrier_phase(
    store: &RuntimeStoreHandle,
    operation_id: [u8; 16],
    phase: KeyTransitionPhase,
) {
    let transition = store
        .load_active_key_transition()
        .await
        .expect("load production EpochBarrier transition phase")
        .expect("production EpochBarrier transition remains auditable");
    assert_eq!(transition.transition.operation_id, operation_id);
    assert_eq!(transition.transition.phase, phase);
    if matches!(
        phase,
        KeyTransitionPhase::BarriersFrozen
            | KeyTransitionPhase::BarriersCommitted
            | KeyTransitionPhase::Complete
    ) {
        assert_eq!(transition.transition.cuts.len(), 1);
    }
}

fn signed_blob_sender_counter(blob: &[u8]) -> u64 {
    let nonce = SignedSealedBlobV1::from_wire_bytes(blob)
        .expect("decode production EpochBarrier signed blob")
        .inner
        .nonce;
    u64::from_be_bytes(
        nonce[4..]
            .try_into()
            .expect("EpochBarrier nonce has a fixed counter suffix"),
    )
}

fn secret(marker: u8) -> SecretBytes {
    SecretBytes::new(vec![marker; 32])
}

fn rotated_global_state() -> Arc<GlobalKeyStateV1> {
    let state = GlobalKeyStateV1::bootstrap(
        1,
        1,
        secret(0x51),
        DeviceRouteId::from_bytes(DEVICE_A),
        1,
        secret(0x52),
        1,
        secret(0x53),
    )
    .expect("bootstrap global key state")
    .activate_conversation(StreamRouteId::from_bytes(CONVERSATION_A), secret(0x54))
    .expect("activate first conversation")
    .activate_conversation(StreamRouteId::from_bytes(CONVERSATION_B), secret(0x55))
    .expect("activate second conversation");
    Arc::new(
        state
            .plan_add_device(
                DeviceRouteId::from_bytes(DEVICE_B),
                secret(0x61),
                secret(0x62),
                secret(0x63),
                vec![
                    ConversationKeyRotation::new(
                        StreamRouteId::from_bytes(CONVERSATION_B),
                        secret(0x65),
                    ),
                    ConversationKeyRotation::new(
                        StreamRouteId::from_bytes(CONVERSATION_A),
                        secret(0x64),
                    ),
                ],
                1_000,
            )
            .expect("rotate all shared keys and add recipient")
            .into_state(),
    )
}

fn recipient(device: [u8; 16], serial: u64, marker: u8) -> TransitionRecipientMaterial {
    let machine_route = MachineRouteId::from_bytes(MACHINE);
    let device_route = DeviceRouteId::from_bytes(device);
    let root_key_id = RootKeyId::from_bytes(ROOT);
    let trust_epoch = TrustEpoch::new(7);
    let grant_serial = GrantSerial::new(serial);
    let relay_grant = RelayGrant {
        machine_route,
        device_route,
        device_sign_pubkey: PublicKeyBytes([marker; 32]),
        grant_serial,
        root_key_id,
        trust_epoch,
        signature: Ed25519Signature([marker; 64]),
    };
    let (_, hpke) = HpkePrivateKey::derive_keypair(&[marker; 32]);
    let authorization = DeviceAuthorizationV1 {
        format_version: E2EE_FORMAT_VERSION,
        grant_hash: relay_grant.canonical_sha256(),
        machine_route,
        device_route,
        device_sign_fingerprint: sha256(&relay_grant.device_sign_pubkey.0),
        grant_serial,
        device_hpke_pubkey: PublicKeyBytes(
            hpke.to_bytes().try_into().expect("fixed HPKE public key"),
        ),
        capabilities: vec![AuthorizationCapabilityV1::Catalog],
        permissions: vec![AuthorizationPermissionV1::CatalogRead],
        root_key_id,
        trust_epoch,
        signature: Ed25519Signature([marker.wrapping_add(1); 64]),
    };
    TransitionRecipientMaterial {
        recipient: KeyTransitionRecipient {
            device_route: device,
            grant_serial: serial,
        },
        relay_grant,
        authorization,
        authorization_revision: KeyDirectoryRevision::new(REVISION),
    }
}

fn material() -> TransitionMaterial {
    let recipients = vec![recipient(DEVICE_A, 3, 0x71), recipient(DEVICE_B, 1, 0x72)];
    TransitionMaterial {
        recovery: KeyTransitionRecovery {
            transition: KeyTransitionRecord {
                operation_id: OPERATION,
                operation: KeyTransitionOperation::Add,
                target: KeyTransitionTarget::Device(recipients[1].recipient),
                from_revision: REVISION - 1,
                to_revision: REVISION,
                phase: KeyTransitionPhase::RotatedPreparingUpdates,
                terminal: None,
                recipients: recipients.iter().map(|entry| entry.recipient).collect(),
                global_lineage: None,
                bootstrap_install_proof: None,
                replay_retirement: None,
                counter_retirement: CounterRetirementLifecycle::Pending,
                cuts: Vec::new(),
                update_count: 0,
                created_at_ms: 900,
                state_changed_at_ms: 1_000,
                terminal_at_ms: None,
                retain_until_ms: None,
            },
            updates: Vec::new(),
        },
        global_keys: rotated_global_state(),
        anchor: TransitionAnchor {
            relay_server_id: RelayServerId::from_bytes(RELAY),
            machine_route: MachineRouteId::from_bytes(MACHINE),
            root_key_id: RootKeyId::from_bytes(ROOT),
            trust_epoch: TrustEpoch::new(7),
            machine_trust_domain: [0x14; 32],
        },
        recipients,
        activation_catalog_stream: None,
    }
}

fn material_with_bootstrap_proof() -> TransitionMaterial {
    let mut material = material();
    let target = match material.recovery.transition.target {
        KeyTransitionTarget::Device(target) => target,
        KeyTransitionTarget::Conversation { .. } => panic!("Add fixture targets a device"),
    };
    let canonical_receipt = b"coordinator-bootstrap-receipt".to_vec();
    material.recovery.transition.global_lineage = Some(KeyTransitionGlobalLineage {
        global_key_state_hash: [0x6b; 32],
        stable_key_lineage_hash: Some([0x6d; 32]),
    });
    material.recovery.transition.bootstrap_install_proof = Some(PairingBootstrapInstallProof {
        operation_id: OPERATION,
        binding: PairingBootstrapInstallBinding {
            pairing_id: [0x51; 16],
            relay_server_id: RELAY,
            pair_route: [0x52; 16],
            machine_route: MACHINE,
            device_route: target.device_route,
            grant_serial: target.grant_serial,
            root_trust_epoch: 7,
            key_revision: REVISION,
            expiry_ms: 2_000,
            invite_hash: [0x61; 32],
            request_hash: [0x62; 32],
            grant_hash: [0x63; 32],
            response_hash: [0x64; 32],
            receipt_hash: sha256(&canonical_receipt),
            device_sign_fingerprint: [0x66; 32],
            info_sha256: [0x67; 32],
            aad_sha256: [0x68; 32],
            tbs_sha256: [0x69; 32],
            key_directory_hash: [0x6a; 32],
            global_key_state_hash: [0x6b; 32],
            key_slot_digest: [0x6c; 32],
            canonical_receipt,
            received_at_ms: 950,
        },
    });
    material
}

fn full_capacity_first_grant_material() -> TransitionMaterial {
    let conversation_keys = (1_u16..=1_024)
        .map(|index| {
            let mut route = [0_u8; 16];
            route[14..].copy_from_slice(&index.to_be_bytes());
            let mut key = vec![0_u8; 32];
            key[0] = 0xa5;
            key[30..].copy_from_slice(&index.to_be_bytes());
            ConversationKeyRotation::new(StreamRouteId::from_bytes(route), SecretBytes::new(key))
        })
        .collect();
    let global_keys = GlobalKeyStateV1::bootstrap_with_conversations(
        1,
        1,
        secret(0x91),
        DeviceRouteId::from_bytes(DEVICE_A),
        1,
        secret(0x92),
        1,
        secret(0x93),
        conversation_keys,
    )
    .expect("bootstrap the authenticated 1,024-conversation state");
    let mut target = recipient(DEVICE_A, 1, 0x71);
    target.authorization_revision = KeyDirectoryRevision::new(1);
    TransitionMaterial {
        recovery: KeyTransitionRecovery {
            transition: KeyTransitionRecord {
                operation_id: [0x43; 16],
                operation: KeyTransitionOperation::Add,
                target: KeyTransitionTarget::Device(target.recipient),
                from_revision: 0,
                to_revision: 1,
                phase: KeyTransitionPhase::RotatedPreparingUpdates,
                terminal: None,
                recipients: vec![target.recipient],
                global_lineage: None,
                bootstrap_install_proof: None,
                replay_retirement: None,
                counter_retirement: CounterRetirementLifecycle::Pending,
                cuts: Vec::new(),
                update_count: 0,
                created_at_ms: 900,
                state_changed_at_ms: 1_000,
                terminal_at_ms: None,
                retain_until_ms: None,
            },
            updates: Vec::new(),
        },
        global_keys: Arc::new(global_keys),
        anchor: TransitionAnchor {
            relay_server_id: RelayServerId::from_bytes(RELAY),
            machine_route: MachineRouteId::from_bytes(MACHINE),
            root_key_id: RootKeyId::from_bytes(ROOT),
            trust_epoch: TrustEpoch::new(7),
            machine_trust_domain: [0x14; 32],
        },
        recipients: vec![target],
        activation_catalog_stream: None,
    }
}

fn last_recipient_revoked_material() -> TransitionMaterial {
    let target = KeyTransitionRecipient {
        device_route: DEVICE_A,
        grant_serial: 3,
    };
    let global_keys = GlobalKeyStateV1::bootstrap(
        1,
        1,
        secret(0x81),
        DeviceRouteId::from_bytes(DEVICE_A),
        1,
        secret(0x82),
        1,
        secret(0x83),
    )
    .expect("bootstrap last-recipient state")
    .plan_revoke_device(
        DeviceRouteId::from_bytes(DEVICE_A),
        secret(0x84),
        Vec::new(),
        2_000,
    )
    .expect("rotate catalog and revoke last recipient")
    .into_state();
    TransitionMaterial {
        recovery: KeyTransitionRecovery {
            transition: KeyTransitionRecord {
                operation_id: [0x42; 16],
                operation: KeyTransitionOperation::Revoke,
                target: KeyTransitionTarget::Device(target),
                from_revision: 1,
                to_revision: 2,
                phase: KeyTransitionPhase::RotatedPreparingUpdates,
                terminal: None,
                recipients: Vec::new(),
                global_lineage: None,
                bootstrap_install_proof: None,
                replay_retirement: None,
                counter_retirement: CounterRetirementLifecycle::Pending,
                cuts: Vec::new(),
                update_count: 0,
                created_at_ms: 1_900,
                state_changed_at_ms: 2_000,
                terminal_at_ms: None,
                retain_until_ms: None,
            },
            updates: Vec::new(),
        },
        global_keys: Arc::new(global_keys),
        anchor: TransitionAnchor {
            relay_server_id: RelayServerId::from_bytes(RELAY),
            machine_route: MachineRouteId::from_bytes(MACHINE),
            root_key_id: RootKeyId::from_bytes(ROOT),
            trust_epoch: TrustEpoch::new(7),
            machine_trust_domain: [0x14; 32],
        },
        recipients: Vec::new(),
        activation_catalog_stream: None,
    }
}

#[derive(Default)]
struct RecordingAuthority {
    infos: Mutex<Vec<KeyUpdateInfoV1>>,
}

struct FakeTransitionState {
    material: TransitionMaterial,
    load_active_transition: bool,
    committed_cuts: Vec<AuthenticatedCommittedStreamCut>,
    frozen_updates: Vec<FrozenKeyUpdate>,
    barrier_requests: Vec<EpochBarrierPublicationRequest>,
    directory_advance_requests: Vec<DirectoryAdvancePublicationRequest>,
    exact_commits: usize,
    directory_advance_commits: usize,
    old_key_drives: usize,
    business_checks: usize,
    corrupt_commit_readback: bool,
}

struct FakeTransitionBackend {
    state: Mutex<FakeTransitionState>,
}

impl FakeTransitionBackend {
    fn new(
        material: TransitionMaterial,
        committed_cuts: Vec<AuthenticatedCommittedStreamCut>,
    ) -> Self {
        Self {
            state: Mutex::new(FakeTransitionState {
                material,
                load_active_transition: true,
                committed_cuts,
                frozen_updates: Vec::new(),
                barrier_requests: Vec::new(),
                directory_advance_requests: Vec::new(),
                exact_commits: 0,
                directory_advance_commits: 0,
                old_key_drives: 0,
                business_checks: 0,
                corrupt_commit_readback: false,
            }),
        }
    }
}

#[async_trait]
impl TransitionBackend for FakeTransitionBackend {
    async fn load_transition_material(
        &self,
    ) -> Result<Option<TransitionMaterial>, TransitionCoordinatorError> {
        let state = self.state.lock().expect("backend lock");
        Ok(state.load_active_transition.then(|| state.material.clone()))
    }

    async fn freeze_key_updates_exact(
        &self,
        operation_id: [u8; 16],
        updates: Vec<FrozenKeyUpdate>,
    ) -> Result<KeyTransitionRecovery, TransitionCoordinatorError> {
        let mut state = self.state.lock().expect("backend lock");
        if state.material.recovery.transition.operation_id != operation_id {
            return Err(TransitionCoordinatorError::BackendRejected);
        }
        state.frozen_updates = updates.clone();
        state.material.recovery.transition.phase = KeyTransitionPhase::UpdatesFrozen;
        state.material.recovery.transition.update_count = updates.len() as u64;
        let bootstrap_proof = state
            .material
            .recovery
            .transition
            .bootstrap_install_proof
            .clone();
        state.material.recovery.updates = updates
            .into_iter()
            .map(|update| {
                let bootstrap_ack = bootstrap_proof.as_ref().filter(|proof| {
                    proof.binding.device_route == update.recipient.device_route
                        && proof.binding.grant_serial == update.recipient.grant_serial
                        && proof.binding.key_revision == update.key_revision
                });
                KeyUpdateRecord {
                    operation_id,
                    recipient: update.recipient,
                    key_revision: update.key_revision,
                    lifecycle: if bootstrap_ack.is_some() {
                        KeyUpdateLifecycle::Acked
                    } else {
                        KeyUpdateLifecycle::Frozen
                    },
                    canonical_update_set: update.canonical_update_set,
                    canonical_ack: bootstrap_ack
                        .map(|proof| proof.binding.canonical_receipt.clone()),
                    snapshot_flushes: Vec::new(),
                    stream_applied_acks: Vec::new(),
                    created_at_ms: 1_001,
                    state_changed_at_ms: 1_001,
                }
            })
            .collect();
        Ok(state.material.recovery.clone())
    }

    async fn drive_old_key_outbox_to_committed(
        &self,
        operation_id: [u8; 16],
    ) -> Result<Vec<AuthenticatedCommittedStreamCut>, TransitionCoordinatorError> {
        let mut state = self.state.lock().expect("backend lock");
        if state.material.recovery.transition.operation_id != operation_id {
            return Err(TransitionCoordinatorError::BackendRejected);
        }
        state.old_key_drives += 1;
        Ok(state.committed_cuts.clone())
    }

    async fn freeze_key_barriers_exact(
        &self,
        operation_id: [u8; 16],
        cuts: Vec<KeyTransitionStreamCut>,
    ) -> Result<KeyTransitionRecovery, TransitionCoordinatorError> {
        let mut state = self.state.lock().expect("backend lock");
        if state.material.recovery.transition.operation_id != operation_id {
            return Err(TransitionCoordinatorError::BackendRejected);
        }
        state.material.recovery.transition.phase = KeyTransitionPhase::BarriersFrozen;
        state.material.recovery.transition.cuts = cuts;
        Ok(state.material.recovery.clone())
    }

    async fn freeze_epoch_barrier(
        &self,
        request: EpochBarrierPublicationRequest,
    ) -> Result<EpochBarrierPublicationTarget, TransitionCoordinatorError> {
        let mut state = self.state.lock().expect("backend lock");
        let mut sealed_blob_sha256 = request.barrier_sha256;
        sealed_blob_sha256[0] ^= 0xff;
        let target = EpochBarrierPublicationTarget {
            class: PublicationClass::EpochBarrier,
            operation_id: request.operation_id,
            scope: request.scope,
            publication_stream_id: request.publication_stream_id,
            stream_route: request.stream_route,
            generation: request.generation,
            stream_seq: request.barrier_sequence,
            key_id: request.expected_key_id,
            key_directory_revision: request.expected_key_directory_revision,
            barrier_sha256: request.barrier_sha256,
            sealed_blob_sha256,
        };
        state.barrier_requests.push(request);
        Ok(target)
    }

    async fn drive_epoch_barrier_to_exact_commit(
        &self,
        target: EpochBarrierPublicationTarget,
    ) -> Result<ExactEpochBarrierCommit, TransitionCoordinatorError> {
        let mut state = self.state.lock().expect("backend lock");
        state.exact_commits += 1;
        let mut committed = target;
        if state.corrupt_commit_readback {
            committed.stream_seq = committed.stream_seq.saturating_add(1);
        }
        Ok(ExactEpochBarrierCommit { target: committed })
    }

    async fn freeze_directory_advance(
        &self,
        request: DirectoryAdvancePublicationRequest,
    ) -> Result<DirectoryAdvancePublicationTarget, TransitionCoordinatorError> {
        let mut state = self.state.lock().expect("backend lock");
        let mut sealed_blob_sha256 = request.control_sha256;
        sealed_blob_sha256[0] ^= 0xff;
        let target = DirectoryAdvancePublicationTarget {
            class: PublicationClass::DirectoryRevisionAdvance,
            operation_id: request.operation_id,
            publication_stream_id: request.publication_stream_id,
            stream_route: request.stream_route,
            generation: request.generation,
            stream_seq: 1,
            from_revision: request.from_revision,
            to_revision: request.to_revision,
            key_id: request.expected_key_id,
            control_sha256: request.control_sha256,
            sealed_blob_sha256,
        };
        state.directory_advance_requests.push(request);
        Ok(target)
    }

    async fn drive_directory_advance_to_exact_commit(
        &self,
        target: DirectoryAdvancePublicationTarget,
    ) -> Result<ExactDirectoryAdvanceCommit, TransitionCoordinatorError> {
        let mut state = self.state.lock().expect("backend lock");
        state.directory_advance_commits += 1;
        let mut committed = target;
        if state.corrupt_commit_readback {
            committed.stream_seq = committed.stream_seq.saturating_add(1);
        }
        Ok(ExactDirectoryAdvanceCommit { target: committed })
    }

    async fn mark_key_barriers_committed_exact(
        &self,
        operation_id: [u8; 16],
    ) -> Result<KeyTransitionRecovery, TransitionCoordinatorError> {
        let mut state = self.state.lock().expect("backend lock");
        if state.material.recovery.transition.operation_id != operation_id {
            return Err(TransitionCoordinatorError::BackendRejected);
        }
        state.material.recovery.transition.phase = KeyTransitionPhase::BarriersCommitted;
        Ok(state.material.recovery.clone())
    }

    async fn check_business_ingress_allowed(&self) -> Result<(), TransitionCoordinatorError> {
        let mut state = self.state.lock().expect("backend lock");
        state.business_checks += 1;
        if state.material.recovery.transition.phase == KeyTransitionPhase::BarriersCommitted {
            Ok(())
        } else {
            Err(TransitionCoordinatorError::BusinessFenced)
        }
    }
}

impl KeyUpdateAuthority for RecordingAuthority {
    fn seal_key_directory_entry(
        &self,
        _recipient: &HpkePublicKey,
        info: &KeyUpdateInfoV1,
        _context: &OuterContextV1,
        _key: &SecretAeadKey,
    ) -> Result<KeyDirectoryEntry, TransitionCoordinatorError> {
        self.infos
            .lock()
            .expect("authority lock")
            .push(info.clone());
        let marker = match info.key_purpose {
            KeyPurpose::Catalog => 1,
            KeyPurpose::ConversationDek => 2,
            KeyPurpose::DeviceCommandTx => 3,
            KeyPurpose::DeviceReplyTx => 4,
        };
        Ok(KeyDirectoryEntry {
            key_id: KeyId {
                purpose: info.key_purpose,
                epoch: info.key_epoch,
            },
            device_route: info.device_route,
            stream_route: info.stream_route,
            enc: vec![marker; 32],
            wrapped_key: vec![marker; 48],
        })
    }

    fn sign_key_update(
        &self,
        _info: &KeyUpdateInfoV1,
        _context: &OuterContextV1,
        mut update: KeyUpdateV1,
    ) -> Result<KeyUpdateV1, TransitionCoordinatorError> {
        update.signature = Ed25519Signature([0x7f; 64]);
        Ok(update)
    }
}

#[test]
fn transition_builds_complete_strictly_sorted_signed_update_set_for_every_recipient() {
    let material = material();
    let authority = RecordingAuthority::default();

    let frozen =
        build_frozen_key_updates(&material, &authority).expect("build exact recipient update sets");

    assert_eq!(frozen.len(), 2);
    for update in frozen {
        let set = KeyUpdateSetV1::from_canonical_bytes(&update.canonical_update_set)
            .expect("canonical update set readback");
        assert_eq!(set.key_directory_revision.value(), REVISION);
        assert_eq!(set.device_route.as_bytes(), &update.recipient.device_route);
        assert_eq!(set.updates.len(), 5);
        assert_eq!(set.updates[0].key_id.purpose, KeyPurpose::Catalog);
        assert_eq!(set.updates[1].key_id.purpose, KeyPurpose::ConversationDek);
        assert_eq!(
            set.updates[1].stream_route.unwrap().as_bytes(),
            &CONVERSATION_A
        );
        assert_eq!(set.updates[2].key_id.purpose, KeyPurpose::ConversationDek);
        assert_eq!(
            set.updates[2].stream_route.unwrap().as_bytes(),
            &CONVERSATION_B
        );
        assert_eq!(set.updates[3].key_id.purpose, KeyPurpose::DeviceCommandTx);
        assert_eq!(set.updates[4].key_id.purpose, KeyPurpose::DeviceReplyTx);
        assert!(set.updates.iter().all(|entry| entry.signature.0 != [0; 64]));
    }
    assert_eq!(authority.infos.lock().expect("authority lock").len(), 10);
}

#[test]
fn full_conversation_capacity_transition_update_fits_the_store_admission_bound() {
    let authority = RecordingAuthority::default();
    let frozen = build_frozen_key_updates(&full_capacity_first_grant_material(), &authority)
        .expect("build the production-shaped maximum update set");
    assert_eq!(frozen.len(), 1);
    let canonical = &frozen[0].canonical_update_set;
    let decoded = KeyUpdateSetV1::from_canonical_bytes(canonical)
        .expect("maximum update set remains canonical");
    assert_eq!(decoded.updates.len(), 1_027);
    assert!(
        canonical.len() > 256 * 1_024,
        "the regression fixture must exercise the former 256 KiB split-brain bound"
    );
    crate::runtime::store::key_transition::canonical_update_hash(canonical).unwrap_or_else(|error| {
        panic!(
            "every protocol-valid maximum update set must pass Store admission: bytes={} error={error}",
            canonical.len()
        )
    });
}

#[test]
fn revoke_last_recipient_legitimately_freezes_an_empty_update_set() {
    let authority = RecordingAuthority::default();
    let frozen = build_frozen_key_updates(&last_recipient_revoked_material(), &authority)
        .expect("zero-recipient revoke is a valid authenticated transition");
    assert!(frozen.is_empty());
    assert!(authority.infos.lock().expect("authority lock").is_empty());
}

#[test]
fn roster_revision_and_grant_axes_mismatch_fail_before_any_crypto() {
    let mut cases = Vec::new();

    let mut missing_recipient = material();
    missing_recipient.recipients.pop();
    cases.push(missing_recipient);

    let mut wrong_revision = material();
    wrong_revision.recipients[0].authorization_revision = KeyDirectoryRevision::new(REVISION - 1);
    cases.push(wrong_revision);

    let mut wrong_machine = material();
    wrong_machine.recipients[0].relay_grant.machine_route = MachineRouteId::from_bytes([0xee; 16]);
    cases.push(wrong_machine);

    for candidate in cases {
        let authority = RecordingAuthority::default();
        assert_eq!(
            build_frozen_key_updates(&candidate, &authority),
            Err(TransitionCoordinatorError::MaterialMismatch)
        );
        assert!(authority.infos.lock().expect("authority lock").is_empty());
    }
}

fn updates_frozen_material() -> TransitionMaterial {
    let mut value = material();
    let authority = RecordingAuthority::default();
    let frozen = build_frozen_key_updates(&value, &authority).expect("freeze fixture updates");
    value.recovery.transition.phase = KeyTransitionPhase::UpdatesFrozen;
    value.recovery.transition.update_count = frozen.len() as u64;
    value.recovery.updates = frozen
        .into_iter()
        .map(|update| KeyUpdateRecord {
            operation_id: OPERATION,
            recipient: update.recipient,
            key_revision: update.key_revision,
            lifecycle: KeyUpdateLifecycle::Frozen,
            canonical_update_set: update.canonical_update_set,
            canonical_ack: None,
            snapshot_flushes: Vec::new(),
            stream_applied_acks: Vec::new(),
            created_at_ms: 1_001,
            state_changed_at_ms: 1_001,
        })
        .collect();
    value
}

fn activation_barriers_frozen_material() -> TransitionMaterial {
    let mut value = updates_frozen_material();
    value.recovery.transition.operation = KeyTransitionOperation::ActivateConversation;
    value.recovery.transition.target = KeyTransitionTarget::Conversation {
        conversation_id: CONVERSATION_A,
        stream_route: CONVERSATION_A,
    };
    value.recovery.transition.phase = KeyTransitionPhase::BarriersFrozen;
    value.recovery.transition.cuts.clear();
    value.activation_catalog_stream = Some(TransitionCatalogStream {
        publication_stream_id: [0x91; 16],
        stream_route: [0xa1; 16],
        generation: [0xb1; 16],
    });
    value
}

fn draining_old_material() -> TransitionMaterial {
    let mut value = material();
    value.recovery.transition.phase = KeyTransitionPhase::DrainingOld;
    value
}

fn exact_committed_cuts() -> Vec<AuthenticatedCommittedStreamCut> {
    vec![
        AuthenticatedCommittedStreamCut {
            scope: KeyTransitionStreamScope::Catalog,
            publication_stream_id: [0x91; 16],
            stream_route: [0xa1; 16],
            generation: [0xb1; 16],
            reserved_outer_cursor: None,
            committed_outer_cursor: None,
            committed_inner_cursor: None,
        },
        AuthenticatedCommittedStreamCut {
            scope: KeyTransitionStreamScope::Conversation(CONVERSATION_A),
            publication_stream_id: [0x92; 16],
            stream_route: CONVERSATION_A,
            generation: [0xb2; 16],
            reserved_outer_cursor: Some(7),
            committed_outer_cursor: Some(7),
            committed_inner_cursor: Some(11),
        },
        AuthenticatedCommittedStreamCut {
            scope: KeyTransitionStreamScope::Conversation(CONVERSATION_B),
            publication_stream_id: [0x93; 16],
            stream_route: CONVERSATION_B,
            generation: [0xb3; 16],
            reserved_outer_cursor: Some(9),
            committed_outer_cursor: Some(9),
            committed_inner_cursor: Some(13),
        },
    ]
}

async fn recovered_barriers_frozen_material() -> TransitionMaterial {
    let backend = FakeTransitionBackend::new(updates_frozen_material(), exact_committed_cuts());
    backend
        .state
        .lock()
        .expect("backend lock")
        .corrupt_commit_readback = true;
    let authority = RecordingAuthority::default();
    let coordinator = TransitionCoordinator::new(&backend, &authority);

    assert_eq!(
        coordinator.advance_once().await,
        Err(TransitionCoordinatorError::BarrierMismatch)
    );
    let material = backend.state.lock().expect("backend lock").material.clone();
    assert_eq!(
        material.recovery.transition.phase,
        KeyTransitionPhase::BarriersFrozen
    );
    material
}

#[tokio::test]
async fn no_active_transition_is_a_side_effect_free_noop() {
    let backend = FakeTransitionBackend::new(material(), Vec::new());
    backend
        .state
        .lock()
        .expect("backend lock")
        .load_active_transition = false;
    let authority = RecordingAuthority::default();
    let coordinator = TransitionCoordinator::new(&backend, &authority);

    assert_eq!(
        coordinator.advance_once().await,
        Ok(TransitionAdvance::NoActiveTransition)
    );

    let state = backend.state.lock().expect("backend lock");
    assert!(state.frozen_updates.is_empty());
    assert!(state.barrier_requests.is_empty());
    assert_eq!(state.old_key_drives, 0);
    assert_eq!(state.exact_commits, 0);
    assert_eq!(state.business_checks, 0);
    assert!(authority.infos.lock().expect("authority lock").is_empty());
}

#[test]
fn epoch_barrier_generation_rollover_has_a_stable_typed_failure_code() {
    assert_eq!(
        TransitionCoordinatorError::SnapshotRequired.code(),
        "daemon.remote.transition.snapshot_required"
    );
}

#[tokio::test]
async fn rotated_generation_barrier_starts_at_outer_zero_from_authenticated_inner_h() {
    let mut committed = exact_committed_cuts();
    committed[0].committed_inner_cursor = Some(5);
    let backend = FakeTransitionBackend::new(updates_frozen_material(), committed);
    let authority = RecordingAuthority::default();
    let coordinator = TransitionCoordinator::new(&backend, &authority);

    assert_eq!(
        coordinator.advance_once().await,
        Ok(TransitionAdvance::ControlPlaneReady { barrier_count: 3 })
    );

    let state = backend.state.lock().expect("backend lock");
    let request = state
        .barrier_requests
        .iter()
        .find(|request| request.scope == KeyTransitionStreamScope::Catalog)
        .expect("catalog barrier request");
    assert_eq!(request.publication_stream_id, [0x91; 16]);
    assert_eq!(request.stream_route, [0xa1; 16]);
    assert_eq!(request.generation, [0xb1; 16]);
    assert_eq!(request.barrier_sequence, 0);
    assert_eq!(request.barrier.stream_cursor, StreamCursor::BeforeFirst);
    assert_eq!(
        request.barrier.inner_cursor,
        RuntimeInnerCursor::Catalog {
            cursor: StreamCursor::At(5),
        }
    );
    let stored = state
        .material
        .recovery
        .transition
        .cuts
        .iter()
        .find(|cut| cut.scope == KeyTransitionStreamScope::Catalog)
        .expect("stored catalog cut");
    assert_eq!(stored.relay_committed_outer, None);
    assert_eq!(stored.relay_committed_inner, Some(5));
    assert_eq!(stored.barrier_sequence, 0);
    assert_eq!(stored.generation, [0xb1; 16]);
}

#[tokio::test]
async fn control_only_committed_outer_keeps_tagged_inner_before_first() {
    let mut committed = exact_committed_cuts();
    committed[1].committed_inner_cursor = None;
    let backend = FakeTransitionBackend::new(updates_frozen_material(), committed);
    let authority = RecordingAuthority::default();
    let coordinator = TransitionCoordinator::new(&backend, &authority);

    assert_eq!(
        coordinator.advance_once().await,
        Ok(TransitionAdvance::ControlPlaneReady { barrier_count: 3 })
    );

    let state = backend.state.lock().expect("backend lock");
    let request = state
        .barrier_requests
        .iter()
        .find(|request| request.scope == KeyTransitionStreamScope::Conversation(CONVERSATION_A))
        .expect("control-only conversation barrier request");
    assert_eq!(request.barrier_sequence, 8);
    assert_eq!(request.barrier.stream_cursor, StreamCursor::At(7));
    assert_eq!(
        request.barrier.inner_cursor,
        RuntimeInnerCursor::Conversation {
            conversation_id: ConversationId::new(
                RuntimeId::from_bytes(RuntimeIdKind::Conversation, CONVERSATION_A)
                    .expect("conversation identity")
                    .to_canonical_string(),
            ),
            cursor: StreamCursor::BeforeFirst,
        }
    );
    let stored = state
        .material
        .recovery
        .transition
        .cuts
        .iter()
        .find(|cut| cut.scope == KeyTransitionStreamScope::Conversation(CONVERSATION_A))
        .expect("stored control-only conversation cut");
    assert_eq!(stored.relay_committed_outer, Some(7));
    assert_eq!(stored.relay_committed_inner, None);
    assert_eq!(stored.barrier_sequence, 8);
}

#[tokio::test]
async fn draining_old_waits_for_atomic_rotation_without_crypto_or_publication() {
    let backend = FakeTransitionBackend::new(draining_old_material(), Vec::new());
    let authority = RecordingAuthority::default();
    let coordinator = TransitionCoordinator::new(&backend, &authority);

    assert_eq!(
        coordinator.advance_once().await,
        Ok(TransitionAdvance::AwaitingKeyRotation)
    );

    let state = backend.state.lock().expect("backend lock");
    assert_eq!(
        state.material.recovery.transition.phase,
        KeyTransitionPhase::DrainingOld
    );
    assert!(state.frozen_updates.is_empty());
    assert!(state.barrier_requests.is_empty());
    assert_eq!(state.old_key_drives, 0);
    assert_eq!(state.exact_commits, 0);
    assert_eq!(state.business_checks, 0);
    assert!(authority.infos.lock().expect("authority lock").is_empty());
}

#[tokio::test]
async fn dedicated_epoch_barriers_reach_control_plane_but_keep_business_fenced_without_acks() {
    let backend = FakeTransitionBackend::new(updates_frozen_material(), exact_committed_cuts());
    assert_eq!(
        backend.check_business_ingress_allowed().await,
        Err(TransitionCoordinatorError::BusinessFenced)
    );
    let authority = RecordingAuthority::default();
    let coordinator = TransitionCoordinator::new(&backend, &authority);

    let outcome = coordinator
        .advance_once()
        .await
        .expect("publish exact epoch barriers");

    assert_eq!(
        outcome,
        TransitionAdvance::ControlPlaneReady { barrier_count: 3 }
    );
    let state = backend.state.lock().expect("backend lock");
    assert_eq!(
        state.material.recovery.transition.phase,
        KeyTransitionPhase::BarriersCommitted
    );
    assert_eq!(state.barrier_requests.len(), 3);
    assert_eq!(state.exact_commits, 3);
    assert!(state.directory_advance_requests.is_empty());
    assert_eq!(state.directory_advance_commits, 0);
    assert_eq!(state.old_key_drives, 1);
    assert_eq!(state.material.recovery.updates.len(), 2);
    assert!(state.material.recovery.updates.iter().all(|update| {
        update.lifecycle == KeyUpdateLifecycle::Frozen
            && update.canonical_ack.is_none()
            && update.stream_applied_acks.is_empty()
    }));
    assert_eq!(state.business_checks, 2);
    for request in &state.barrier_requests {
        let control = KeyControlV1::from_canonical_bytes(&request.canonical_control)
            .expect("canonical dedicated epoch barrier control");
        assert!(control.canonical_sha256().is_ok());
        assert_eq!(request.expected_key_directory_revision, REVISION);
        assert_eq!(request.expected_key_id.epoch, 2);
        assert_eq!(request.barrier.key_directory_revision.value(), REVISION);
        assert_eq!(request.barrier.new_epoch, 2);
        assert_eq!(request.barrier.old_epoch, 1);
        assert_eq!(
            request.barrier_sha256,
            request.barrier.canonical_sha256().expect("barrier hash")
        );
    }
}

#[tokio::test]
async fn update_phase_freezes_byte_identical_sets_before_any_barrier_work() {
    let backend = FakeTransitionBackend::new(material(), Vec::new());
    let authority = RecordingAuthority::default();
    let coordinator = TransitionCoordinator::new(&backend, &authority);

    assert_eq!(
        coordinator.advance_once().await,
        Ok(TransitionAdvance::UpdatesFrozen { recipient_count: 2 })
    );

    let state = backend.state.lock().expect("backend lock");
    assert_eq!(
        state.material.recovery.transition.phase,
        KeyTransitionPhase::UpdatesFrozen
    );
    assert_eq!(state.frozen_updates.len(), 2);
    assert_eq!(state.material.recovery.updates.len(), 2);
    for (frozen, readback) in state
        .frozen_updates
        .iter()
        .zip(&state.material.recovery.updates)
    {
        assert_eq!(frozen.canonical_update_set, readback.canonical_update_set);
        KeyUpdateSetV1::from_canonical_bytes(&readback.canonical_update_set)
            .expect("exact frozen canonical set");
    }
    assert_eq!(state.old_key_drives, 0);
    assert!(state.barrier_requests.is_empty());
}

#[tokio::test]
async fn update_freeze_readback_accepts_only_bootstrap_target_as_preacked() {
    let material = material_with_bootstrap_proof();
    let target = match material.recovery.transition.target {
        KeyTransitionTarget::Device(target) => target,
        KeyTransitionTarget::Conversation { .. } => panic!("bootstrap fixture targets a device"),
    };
    let receipt = material
        .recovery
        .transition
        .bootstrap_install_proof
        .as_ref()
        .expect("bootstrap fixture proof exists")
        .binding
        .canonical_receipt
        .clone();
    let backend = FakeTransitionBackend::new(material, Vec::new());
    let authority = RecordingAuthority::default();
    let coordinator = TransitionCoordinator::new(&backend, &authority);

    assert_eq!(
        coordinator.advance_once().await,
        Ok(TransitionAdvance::UpdatesFrozen { recipient_count: 2 })
    );
    let state = backend.state.lock().expect("backend lock");
    for update in &state.material.recovery.updates {
        if update.recipient == target {
            assert_eq!(update.lifecycle, KeyUpdateLifecycle::Acked);
            assert_eq!(update.canonical_ack.as_deref(), Some(receipt.as_slice()));
        } else {
            assert_eq!(update.lifecycle, KeyUpdateLifecycle::Frozen);
            assert!(update.canonical_ack.is_none());
        }
    }
    assert_eq!(state.old_key_drives, 0);
    assert!(state.barrier_requests.is_empty());
}

#[tokio::test]
async fn pending_old_key_outbox_cut_is_rejected_before_barrier_freeze() {
    let mut pending = exact_committed_cuts();
    pending[1].reserved_outer_cursor = Some(8);
    let backend = FakeTransitionBackend::new(updates_frozen_material(), pending);
    let authority = RecordingAuthority::default();
    let coordinator = TransitionCoordinator::new(&backend, &authority);

    assert_eq!(
        coordinator.advance_once().await,
        Err(TransitionCoordinatorError::UncommittedCut)
    );

    let state = backend.state.lock().expect("backend lock");
    assert_eq!(
        state.material.recovery.transition.phase,
        KeyTransitionPhase::UpdatesFrozen
    );
    assert_eq!(state.old_key_drives, 1);
    assert!(state.barrier_requests.is_empty());
    assert_eq!(state.exact_commits, 0);
    assert_eq!(state.business_checks, 0);
}

#[tokio::test]
async fn changed_relay_commit_readback_keeps_business_fenced() {
    let backend = FakeTransitionBackend::new(updates_frozen_material(), exact_committed_cuts());
    backend
        .state
        .lock()
        .expect("backend lock")
        .corrupt_commit_readback = true;
    let authority = RecordingAuthority::default();
    let coordinator = TransitionCoordinator::new(&backend, &authority);

    assert_eq!(
        coordinator.advance_once().await,
        Err(TransitionCoordinatorError::BarrierMismatch)
    );

    let state = backend.state.lock().expect("backend lock");
    assert_eq!(
        state.material.recovery.transition.phase,
        KeyTransitionPhase::BarriersFrozen
    );
    assert_eq!(state.barrier_requests.len(), 1);
    assert_eq!(state.exact_commits, 1);
    assert_eq!(state.business_checks, 0);
}

#[tokio::test]
async fn revoke_last_recipient_reaches_control_plane_without_barrier_or_ack_wait() {
    let backend = FakeTransitionBackend::new(last_recipient_revoked_material(), Vec::new());
    let authority = RecordingAuthority::default();
    let coordinator = TransitionCoordinator::new(&backend, &authority);

    assert_eq!(
        coordinator.advance_once().await,
        Ok(TransitionAdvance::UpdatesFrozen { recipient_count: 0 })
    );
    assert_eq!(
        coordinator.advance_once().await,
        Ok(TransitionAdvance::ControlPlaneReady { barrier_count: 0 })
    );

    let state = backend.state.lock().expect("backend lock");
    assert_eq!(
        state.material.recovery.transition.phase,
        KeyTransitionPhase::BarriersCommitted
    );
    assert!(state.material.recovery.updates.is_empty());
    assert!(state.material.recovery.transition.cuts.is_empty());
    assert_eq!(
        state.old_key_drives, 1,
        "zero-recipient revoke still audits the authenticated old-key outbox before zero-cut"
    );
    assert!(state.barrier_requests.is_empty());
    assert_eq!(state.exact_commits, 0);
    assert!(state.directory_advance_requests.is_empty());
    assert_eq!(state.directory_advance_commits, 0);
    assert_eq!(state.business_checks, 1);
}

#[tokio::test]
async fn activate_conversation_publishes_exact_directory_advance_before_control_plane() {
    let backend = FakeTransitionBackend::new(activation_barriers_frozen_material(), Vec::new());
    let authority = RecordingAuthority::default();
    let coordinator = TransitionCoordinator::new(&backend, &authority);

    assert_eq!(
        coordinator.advance_once().await,
        Ok(TransitionAdvance::ControlPlaneReady { barrier_count: 0 })
    );

    let state = backend.state.lock().expect("backend lock");
    assert!(state.barrier_requests.is_empty());
    assert_eq!(state.exact_commits, 0);
    assert_eq!(state.directory_advance_requests.len(), 1);
    assert_eq!(state.directory_advance_commits, 1);
    assert_eq!(state.business_checks, 1);
    assert_eq!(
        state.material.recovery.transition.phase,
        KeyTransitionPhase::BarriersCommitted
    );
    let request = &state.directory_advance_requests[0];
    assert_eq!(request.operation_id, OPERATION);
    assert_eq!(request.publication_stream_id, [0x91; 16]);
    assert_eq!(request.stream_route, [0xa1; 16]);
    assert_eq!(request.generation, [0xb1; 16]);
    assert_eq!(request.from_revision, REVISION - 1);
    assert_eq!(request.to_revision, REVISION);
    assert_eq!(request.expected_key_id.purpose, KeyPurpose::Catalog);
    let control = KeyControlV1::from_canonical_bytes(&request.canonical_control)
        .expect("canonical directory advance control");
    assert_eq!(
        control.sealed_payload_kind(),
        agentdeck_protocol::e2ee::SealedPayloadKind::KeyUpdate
    );
    assert_eq!(
        control.canonical_sha256().expect("directory advance hash"),
        request.control_sha256
    );
}

#[tokio::test]
async fn changed_directory_advance_commit_readback_keeps_activation_fenced() {
    let backend = FakeTransitionBackend::new(activation_barriers_frozen_material(), Vec::new());
    backend
        .state
        .lock()
        .expect("backend lock")
        .corrupt_commit_readback = true;
    let authority = RecordingAuthority::default();
    let coordinator = TransitionCoordinator::new(&backend, &authority);

    assert_eq!(
        coordinator.advance_once().await,
        Err(TransitionCoordinatorError::BarrierMismatch)
    );
    let state = backend.state.lock().expect("backend lock");
    assert_eq!(
        state.material.recovery.transition.phase,
        KeyTransitionPhase::BarriersFrozen
    );
    assert_eq!(state.directory_advance_requests.len(), 1);
    assert_eq!(state.directory_advance_commits, 1);
    assert_eq!(state.business_checks, 0);
}

#[tokio::test]
async fn barriers_frozen_restart_rebuilds_exact_requests_without_redraining_old_outbox() {
    let recovered = recovered_barriers_frozen_material().await;
    let backend = FakeTransitionBackend::new(recovered, Vec::new());
    let authority = RecordingAuthority::default();
    let coordinator = TransitionCoordinator::new(&backend, &authority);

    assert_eq!(
        coordinator.advance_once().await,
        Ok(TransitionAdvance::ControlPlaneReady { barrier_count: 3 })
    );

    let state = backend.state.lock().expect("backend lock");
    assert_eq!(
        state.material.recovery.transition.phase,
        KeyTransitionPhase::BarriersCommitted
    );
    assert_eq!(state.old_key_drives, 0);
    assert_eq!(state.barrier_requests.len(), 3);
    assert_eq!(state.exact_commits, 3);
    assert_eq!(state.business_checks, 1);
}

#[tokio::test]
async fn frozen_barrier_hash_epoch_or_route_drift_fails_before_republish() {
    let baseline = recovered_barriers_frozen_material().await;
    let mut cases = Vec::new();

    let mut changed_hash = baseline.clone();
    changed_hash.recovery.transition.cuts[0].epoch_barrier_sha256[0] ^= 0xff;
    cases.push(changed_hash);

    let mut changed_epoch = baseline.clone();
    changed_epoch.recovery.transition.cuts[0].new_epoch += 1;
    cases.push(changed_epoch);

    let mut changed_route = baseline;
    changed_route.recovery.transition.cuts[1].stream_route = [0xee; 16];
    cases.push(changed_route);

    for candidate in cases {
        let backend = FakeTransitionBackend::new(candidate, Vec::new());
        let authority = RecordingAuthority::default();
        let coordinator = TransitionCoordinator::new(&backend, &authority);

        assert_eq!(
            coordinator.advance_once().await,
            Err(TransitionCoordinatorError::ExactReadbackMismatch)
        );

        let state = backend.state.lock().expect("backend lock");
        assert_eq!(
            state.material.recovery.transition.phase,
            KeyTransitionPhase::BarriersFrozen
        );
        assert_eq!(state.old_key_drives, 0);
        assert!(state.barrier_requests.is_empty());
        assert_eq!(state.exact_commits, 0);
        assert_eq!(state.business_checks, 0);
    }
}

#[tokio::test]
async fn production_reopened_transition_wakes_on_pairing_delivery_without_second_ack() {
    let root = tempfile::tempdir().expect("create production transition composition root");
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;

        std::fs::set_permissions(root.path(), std::fs::Permissions::from_mode(0o700))
            .expect("secure production transition composition root");
    }
    let database = root.path().join("runtime.db");
    let keys = Arc::new(MemoryKeyStore::new());
    let storage_kek =
        load_or_create_storage_kek(keys.as_ref(), &database).expect("create composition KEK");
    let store = active_authorization_store_with_pending_transition_for_test(
        &database,
        storage_kek,
        vec![AuthorizationCapabilityV1::Catalog],
        vec![AuthorizationPermissionV1::CatalogRead],
    )
    .await;
    let before = store
        .load_active_key_transition()
        .await
        .expect("load production pending transition")
        .expect("fresh active authorization leaves a transition fence");
    assert_eq!(before.transition.phase, KeyTransitionPhase::DrainingOld);
    let identity = store
        .load_machine_identity_state()
        .await
        .expect("load transition machine identity")
        .expect("transition machine identity exists");
    install_key_directory_guard(
        keys.as_ref(),
        KeyDirectoryGuard::new(
            identity.database_id,
            identity.binding.root_fingerprint,
            before.transition.from_revision,
        ),
    )
    .expect("install exact pre-transition key-directory guard");
    let Some(MachineEnrollmentState::Active(active)) = store
        .load_machine_enrollment_state()
        .await
        .expect("load active machine enrollment")
    else {
        panic!("production composition fixture must remain actively enrolled")
    };
    let relay_server_id = active.connection.relay_server_id;
    let machine_route = MachineRouteId::from_bytes(active.record.machine_route);
    let (machine_data, _machine_data_owner) = machine_data_authority_for_transition_test(
        machine_pairing_anchor_for_test(
            relay_server_id,
            machine_route,
            &active.binding,
            active.data_cert.clone(),
        ),
        [0x43; 32],
    );
    let key_store: Arc<dyn KeyStore> = keys.clone();

    // 第一组 production owners 在任何 drive 前正常关闭，模拟 daemon shutdown；Store
    // 必须保留完整 authenticated transition fence，不能依赖进程内 fake state。
    let first_transport = Arc::new(ExactPublicationTransport::default());
    let first_publication =
        open_owner_with_transport_for_test(store.clone(), first_transport.clone())
            .await
            .expect("open first production publication owner");
    let first_transition = KeyTransitionRecoveryOwner::start(
        store.clone(),
        key_store.clone(),
        machine_route,
        machine_data.clone(),
        first_publication.handle(),
    )
    .expect("start first production transition owner");
    first_transition
        .shutdown()
        .await
        .expect("shutdown first transition owner");
    first_publication
        .shutdown()
        .await
        .expect("shutdown first publication owner");
    assert_eq!(first_transport.publish_calls.load(Ordering::SeqCst), 0);
    store
        .shutdown()
        .await
        .expect("shutdown first Runtime Store");

    let reopened_kek =
        load_or_create_storage_kek(keys.as_ref(), &database).expect("reload composition KEK");
    let reopened = RuntimeStoreHandle::open(
        RuntimeStoreConfig::new(database.clone()).with_clock(TransitionCompositionClock),
        reopened_kek,
    )
    .await
    .expect("reopen authenticated Runtime Store");
    let recovered = reopened
        .load_active_key_transition()
        .await
        .expect("reload transition after restart")
        .expect("restart preserves active transition");
    assert_eq!(recovered.transition, before.transition);
    assert!(
        reopened
            .check_remote_transition_ingress(RemoteTransitionIngressClass::Business)
            .await
            .is_err(),
        "reopen must keep business fenced until the real owner reaches BusinessReady"
    );

    let second_transport = Arc::new(ExactPublicationTransport::default());
    let second_publication =
        open_owner_with_transport_for_test(reopened.clone(), second_transport.clone())
            .await
            .expect("open restarted production publication owner");
    let (delivery_commit_tx, delivery_commit_rx) = tokio::sync::watch::channel(0u64);
    let second_transition = KeyTransitionRecoveryOwner::start_with_delivery_commits(
        reopened.clone(),
        key_store,
        machine_route,
        machine_data,
        second_publication.handle(),
        delivery_commit_rx,
    )
    .expect("start restarted production transition owner");
    let mut progress_rx = second_transition.handle().subscribe_progress();
    let _ = *progress_rx.borrow_and_update();
    delivery_commit_tx.send_modify(|generation| {
        *generation = generation.saturating_add(1);
    });
    let readiness = tokio::time::timeout(Duration::from_secs(2), async {
        loop {
            progress_rx
                .changed()
                .await
                .expect("transition progress owner remains open");
            match *progress_rx.borrow_and_update() {
                TransitionProgress::Ready(readiness) => break readiness,
                TransitionProgress::Blocked(code) => {
                    let observed = reopened
                        .load_active_key_transition()
                        .await
                        .expect("load failed composition transition")
                        .expect("failed composition transition remains active");
                    panic!(
                        "real backend/store/owner recovery failed in {:?}: {code}",
                        observed.transition.phase,
                    );
                }
                TransitionProgress::Idle | TransitionProgress::Pending => {}
            }
        }
    })
    .await
    .expect("durable delivery commit must wake the idle transition owner immediately");
    assert_eq!(
        readiness,
        TransitionReadiness::BusinessReady { barrier_count: 0 }
    );
    assert!(
        reopened
            .load_active_key_transition()
            .await
            .expect("reload completed bootstrap transition")
            .is_none(),
        "durable PairResponseReceived proof must let the zero-cut first-device transition complete"
    );
    reopened
        .check_remote_transition_ingress(RemoteTransitionIngressClass::Business)
        .await
        .expect("bootstrap install proof replaces only the redundant target KeyUpdateAck");
    assert_eq!(second_transport.publish_calls.load(Ordering::SeqCst), 0);

    second_transition
        .shutdown()
        .await
        .expect("shutdown restarted transition owner");
    second_publication
        .shutdown()
        .await
        .expect("shutdown restarted publication owner");
    reopened
        .shutdown()
        .await
        .expect("shutdown reopened Runtime Store");
}

#[tokio::test]
async fn production_counter_recovery_reopens_retries_unknown_barrier_and_starts_control_only() {
    let root = tempfile::tempdir().expect("create production counter recovery root");
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;

        std::fs::set_permissions(root.path(), std::fs::Permissions::from_mode(0o700))
            .expect("secure production counter recovery root");
    }
    let database = root.path().join("runtime.db");
    let keys = Arc::new(MemoryKeyStore::new());
    let storage_kek =
        load_or_create_storage_kek(keys.as_ref(), &database).expect("create recovery KEK");
    let store = production_aligned_active_authorization_store_for_test(
        &database,
        storage_kek,
        vec![AuthorizationCapabilityV1::Catalog],
        vec![AuthorizationPermissionV1::CatalogRead],
    )
    .await;
    store
        .create_publication_stream(
            [0x21; 16],
            PublicationScope::Catalog,
            [0x22; 16],
            [0x23; 16],
        )
        .await
        .expect("create fresh Catalog sender before counter recovery");
    assert!(
        store
            .load_active_key_transition()
            .await
            .expect("load empty transition slot")
            .is_none(),
        "two-device fixture must finish its membership transition before recovery staging"
    );

    let (publication_stream_id, retired_key_id) = store
        .load_active_sender_counter_bindings()
        .await
        .expect("load active shared sender bindings")
        .into_iter()
        .find_map(|binding| match binding {
            ActiveSenderCounterBinding::SharedPublication {
                publication_stream_id,
                key_id,
            } if key_id.purpose == KeyPurpose::Catalog => Some((publication_stream_id, key_id)),
            _ => None,
        })
        .expect("active Catalog sender binding");
    let trust_domain = store.machine_trust_domain().expect("machine trust domain");
    let retired_scope =
        CounterScope::publication(trust_domain, retired_key_id, publication_stream_id)
            .expect("derive retired Catalog scope");
    let replacement_key_id = KeyId {
        purpose: retired_key_id.purpose,
        epoch: retired_key_id
            .epoch
            .checked_add(1)
            .expect("Catalog epoch has a successor"),
    };
    let replacement_scope =
        CounterScope::publication(trust_domain, replacement_key_id, publication_stream_id)
            .expect("derive replacement Catalog scope");
    let genesis = store
        .load_remote_counter_record(retired_scope.token(), retired_key_id)
        .await
        .expect("load Catalog counter genesis");
    assert_eq!(genesis.kind, RemoteCounterRecordKind::Genesis);
    let retired = store
        .retire_remote_counter(RemoteCounterRetirementRequest {
            scope_token: retired_scope.token(),
            key_id: retired_key_id,
            expected_reserved_end: genesis.reserved_end,
            expected_db_anchor: genesis.db_anchor,
            retired_through: COUNTER_BLOCK_SIZE,
        })
        .await
        .expect("durably retire old Catalog scope");
    assert_eq!(retired.kind, RemoteCounterRecordKind::Retired);

    let operation_id = [0x42; 16];
    let staged = store
        .stage_remote_counter_recovery(CounterRecoveryStageRequest {
            operation_id,
            retired_scope_token: retired_scope.token(),
            retired_key_id,
            replacement_scope_token: replacement_scope.token(),
            target: CounterRecoveryStageTarget::SharedPublication {
                publication_stream_id,
            },
        })
        .await
        .expect("atomically stage Catalog counter recovery");
    assert_eq!(staged.disposition, CounterRecoveryDisposition::Staged);
    let binding = staged.binding.expect("staged recovery binding");
    assert_eq!(binding.replacement_key_id, replacement_key_id);
    let before = store
        .load_active_key_transition()
        .await
        .expect("load staged counter recovery transition")
        .expect("counter recovery transition is active");
    assert_eq!(before.transition.operation_id, operation_id);
    assert_eq!(
        before.transition.operation,
        KeyTransitionOperation::CounterRecovery
    );
    assert_eq!(before.transition.phase, KeyTransitionPhase::DrainingOld);
    let identity = store
        .load_machine_identity_state()
        .await
        .expect("load counter recovery machine identity")
        .expect("counter recovery machine identity exists");
    install_key_directory_guard(
        keys.as_ref(),
        KeyDirectoryGuard::new(
            identity.database_id,
            identity.binding.root_fingerprint,
            before.transition.from_revision,
        ),
    )
    .expect("install exact pre-recovery key-directory guard");
    let Some(MachineEnrollmentState::Active(active)) = store
        .load_machine_enrollment_state()
        .await
        .expect("load counter recovery machine enrollment")
    else {
        panic!("counter recovery fixture must remain actively enrolled")
    };
    let machine_route = MachineRouteId::from_bytes(active.record.machine_route);
    let (machine_data, _machine_data_owner) = machine_data_authority_for_transition_test(
        machine_pairing_anchor_for_test(
            active.connection.relay_server_id,
            machine_route,
            &active.binding,
            active.data_cert.clone(),
        ),
        [0x43; 32],
    );
    assert!(
        store
            .has_retired_remote_counter()
            .await
            .expect("read staged global counter fence")
    );
    assert!(
        !store
            .remote_counter_scope_allowed(retired_scope.token())
            .await
            .expect("old Catalog scope stays disabled before restart")
    );
    assert!(
        store
            .remote_counter_scope_allowed(replacement_scope.token())
            .await
            .expect("replacement Catalog scope is admitted during recovery")
    );
    store
        .shutdown()
        .await
        .expect("shutdown staged counter recovery Store");

    let reopened_kek =
        load_or_create_storage_kek(keys.as_ref(), &database).expect("reload recovery KEK");
    let reopened = RuntimeStoreHandle::open(
        RuntimeStoreConfig::new(database.clone()).with_clock(TransitionCompositionClock),
        reopened_kek,
    )
    .await
    .expect("reopen staged counter recovery Store");
    let recovered = reopened
        .load_active_key_transition()
        .await
        .expect("reload counter recovery transition")
        .expect("restart preserves counter recovery transition");
    assert_eq!(recovered.transition, before.transition);
    reopened
        .load_transition_material_projection()
        .await
        .expect("authenticate restarted counter recovery material")
        .expect("counter recovery material remains present after restart");
    assert!(
        reopened
            .has_retired_remote_counter()
            .await
            .expect("restart preserves global counter fence")
    );

    let transport = Arc::new(ExactPublicationTransport::with_outcome_unknown_before_commit(1));
    let publication = open_owner_with_transport_for_test(reopened.clone(), transport.clone())
        .await
        .expect("open recovery publication owner");
    let key_store: Arc<dyn KeyStore> = keys.clone();
    let transition = KeyTransitionRecoveryOwner::start(
        reopened.clone(),
        key_store,
        machine_route,
        machine_data,
        publication.handle(),
    )
    .expect("start recovery transition owner");
    transition
        .handle()
        .request_control_plane_progress()
        .expect("enqueue background counter-recovery progress");
    let retry = tokio::time::timeout(Duration::from_secs(5), async {
        loop {
            let recovery = reopened
                .load_active_key_transition()
                .await
                .expect("poll background counter-recovery transition")
                .expect("background counter-recovery transition remains auditable");
            if recovery.transition.phase == KeyTransitionPhase::BarriersCommitted {
                break;
            }
            tokio::time::sleep(Duration::from_millis(10)).await;
        }
    })
    .await;
    if retry.is_err() {
        let observed = reopened
            .load_active_key_transition()
            .await
            .expect("load timed-out background transition")
            .expect("timed-out background transition remains active");
        panic!(
            "owner did not retry unknown outcome: phase={:?} publish_calls={} health={:?}",
            observed.transition.phase,
            transport.publish_calls.load(Ordering::SeqCst),
            transition.observed_failure_code(),
        );
    }
    let readiness = match transition.handle().drive_to_business_ready().await {
        Ok(readiness) => readiness,
        Err(error) => {
            let observed = reopened
                .load_active_key_transition()
                .await
                .expect("load failed counter recovery transition")
                .expect("failed counter recovery remains active");
            panic!(
                "real CounterRecovery composition failed in {:?}: {error:?}",
                observed.transition.phase,
            );
        }
    };
    assert_eq!(
        readiness,
        TransitionReadiness::ControlPlaneReady { barrier_count: 1 }
    );
    assert!(
        transport.publish_calls.load(Ordering::SeqCst) >= 2,
        "the owner must retry the exact EpochBarrier after one unknown outcome"
    );
    let attempts = transport.attempts();
    assert_eq!(
        attempts.len(),
        2,
        "one unknown outcome permits one exact retry"
    );
    assert_eq!(
        attempts[0], attempts[1],
        "retry must reuse the frozen id/blob/hash/counter/stream sequence byte-for-byte"
    );
    let committed = reopened
        .load_active_key_transition()
        .await
        .expect("reload committed counter recovery")
        .expect("committed counter recovery remains auditable");
    assert_eq!(
        committed.transition.phase,
        KeyTransitionPhase::BarriersCommitted
    );
    assert_eq!(committed.transition.cuts.len(), 1);

    let recovered_counter = reopened
        .mark_remote_counter_recovery_business_ready(operation_id)
        .await
        .expect("clear counter fence only after canonical control-plane readiness");
    assert_eq!(recovered_counter.kind, RemoteCounterRecordKind::Recovered);
    let completion = reopened
        .try_complete_key_transition(operation_id)
        .await
        .expect("complete recovered counter transition");
    assert!(matches!(
        completion,
        crate::runtime::store::key_transition::KeyTransitionCompletion::Pending
    ));
    assert_eq!(
        transition
            .handle()
            .drive_to_business_ready()
            .await
            .expect("read back business readiness after counter recovery"),
        TransitionReadiness::ControlPlaneReady { barrier_count: 1 }
    );
    reopened
        .check_remote_transition_ingress(RemoteTransitionIngressClass::Business)
        .await
        .expect_err("device ACKs must still fence business after counter lineage recovery");
    assert!(
        !reopened
            .has_retired_remote_counter()
            .await
            .expect("global retired-counter fence clears after recovery")
    );
    assert!(
        !reopened
            .remote_counter_scope_allowed(retired_scope.token())
            .await
            .expect("old Catalog scope remains permanently disabled")
    );
    assert!(
        reopened
            .remote_counter_scope_allowed(replacement_scope.token())
            .await
            .expect("replacement Catalog scope remains allowed")
    );

    transition
        .shutdown()
        .await
        .expect("shutdown counter recovery transition owner");
    publication
        .shutdown()
        .await
        .expect("shutdown counter recovery publication owner");
    reopened
        .shutdown()
        .await
        .expect("shutdown recovered Runtime Store");
}

#[tokio::test]
async fn production_offline_transition_waits_for_reconnect_without_timer_retry() {
    let fixture = production_epoch_barrier_crash_fixture("offline-reconnect-wait").await;
    fixture
        .store
        .clone()
        .shutdown()
        .await
        .expect("shutdown offline-wait setup Store");
    let reopened = fixture.reopen().await;
    let transport = Arc::new(ExactPublicationTransport::with_offline_before_commit(1));
    let publication = open_owner_with_transport_for_test(reopened.clone(), transport.clone())
        .await
        .expect("open offline-wait publication owner");
    let (authority, _authority_lease) = fixture.machine_data_authority();
    let (mut reconnect_transport, _pairing_lane, reconnect_harness) =
        super::transport::active_pairing_transport_for_test(fixture.machine_route);
    let reconnect_lane = reconnect_transport
        .take_business_lane()
        .expect("claim production-shaped reconnect generation source");
    let authenticated_reconnects = reconnect_lane
        .publication_handle()
        .subscribe_authenticated_reconnects();
    let (delivery_commit_tx, delivery_commit_rx) = tokio::sync::watch::channel(0u64);
    let transition = KeyTransitionRecoveryOwner::start_with_authenticated_reconnect(
        reopened.clone(),
        fixture.key_store(),
        fixture.machine_route,
        authority,
        publication.handle(),
        authenticated_reconnects,
        Some(delivery_commit_rx),
    )
    .expect("start offline-wait transition owner");

    tokio::time::pause();
    transition
        .handle()
        .request_control_plane_progress()
        .expect("enqueue first offline transition attempt");
    for _ in 0..10_000 {
        if transport.publish_calls.load(Ordering::SeqCst) == 1
            && transition.observed_failure_code().is_some()
        {
            break;
        }
        tokio::task::yield_now().await;
    }
    assert_eq!(transport.publish_calls.load(Ordering::SeqCst), 1);
    assert!(
        transition.observed_failure_code().is_some(),
        "offline attempt must remain visibly fenced"
    );
    let settled_attempts = transition.attempt_count_for_test();
    assert_eq!(settled_attempts, 1);

    tokio::time::advance(Duration::from_secs(5 * 60)).await;
    for _ in 0..512 {
        tokio::task::yield_now().await;
    }
    assert_eq!(
        transition.attempt_count_for_test(),
        settled_attempts,
        "Relay Offline must not schedule transition owner timer retries"
    );
    assert_eq!(
        transport.publish_calls.load(Ordering::SeqCst),
        1,
        "Relay Offline must stay parked until the authenticated generation is replaced"
    );

    delivery_commit_tx.send_modify(|generation| {
        *generation = generation.saturating_add(1);
    });
    for _ in 0..512 {
        tokio::task::yield_now().await;
    }
    assert_eq!(
        transition.attempt_count_for_test(),
        settled_attempts,
        "durable pairing progress may latch while Offline but must not drive before reconnect"
    );
    assert_eq!(
        transport.publish_calls.load(Ordering::SeqCst),
        1,
        "delivery proof cannot substitute for an authenticated Relay generation"
    );

    assert!(matches!(
        transition.handle().drive_to_business_ready().await,
        Err(KeyTransitionRecoveryError::ReconnectPending)
    ));
    assert_eq!(
        transport.publish_calls.load(Ordering::SeqCst),
        1,
        "an ordinary drive command must not consume or bypass the reconnect park"
    );
    reconnect_transport
        .reconnect()
        .await
        .expect("same authenticated supervisor replaces the generation");
    assert_eq!(reconnect_harness.reconnect_count(), 1);
    for _ in 0..10_000 {
        if transport.publish_calls.load(Ordering::SeqCst) == 2 {
            break;
        }
        tokio::task::yield_now().await;
    }
    assert_eq!(transport.publish_calls.load(Ordering::SeqCst), 2);
    assert_eq!(
        transition.attempt_count_for_test(),
        settled_attempts + 1,
        "authenticated reconnect must consume the latched proof with one owner attempt"
    );
    assert_eq!(
        transition
            .handle()
            .drive_to_business_ready()
            .await
            .expect("reconnected exact EpochBarrier reaches control-plane readiness"),
        TransitionReadiness::ControlPlaneReady { barrier_count: 1 }
    );
    let attempts = transport.attempts();
    assert_eq!(attempts.len(), 2);
    assert_eq!(
        attempts[0], attempts[1],
        "reconnect retry must preserve every frozen publication axis and exact blob"
    );

    tokio::time::resume();
    transition
        .shutdown()
        .await
        .expect("shutdown offline-wait transition owner");
    publication
        .shutdown()
        .await
        .expect("shutdown offline-wait publication owner");
    drop(reconnect_lane);
    reconnect_transport.shutdown().await;
    reopened
        .shutdown()
        .await
        .expect("shutdown offline-wait Store");
}

#[tokio::test]
async fn authenticated_generation_during_full_drive_is_not_lost_before_offline_park() {
    let fixture = production_epoch_barrier_crash_fixture("generation-during-full-drive").await;
    fixture
        .store
        .clone()
        .shutdown()
        .await
        .expect("shutdown generation-during-drive setup Store");
    let reopened = fixture.reopen().await;
    let transport = Arc::new(InFlightOfflineThenCommitTransport::default());
    let publication = open_owner_with_transport_for_test(reopened.clone(), transport.clone())
        .await
        .expect("open in-flight publication owner");
    let (authority, _authority_lease) = fixture.machine_data_authority();
    let (mut reconnect_transport, _pairing_lane, reconnect_harness) =
        super::transport::active_pairing_transport_for_test(fixture.machine_route);
    let reconnect_lane = reconnect_transport
        .take_business_lane()
        .expect("claim authenticated generation source");
    let authenticated_reconnects = reconnect_lane
        .publication_handle()
        .subscribe_authenticated_reconnects();
    let transition = KeyTransitionRecoveryOwner::start_with_authenticated_reconnect(
        reopened.clone(),
        fixture.key_store(),
        fixture.machine_route,
        authority,
        publication.handle(),
        authenticated_reconnects,
        None,
    )
    .expect("start generation-during-drive transition owner");
    let mut progress_rx = transition.handle().subscribe_progress();
    let _ = *progress_rx.borrow_and_update();

    transition
        .handle()
        .request_control_plane_progress()
        .expect("start the full drive before reconnect");
    tokio::time::timeout(
        Duration::from_secs(2),
        transport.wait_until_first_publish_is_in_flight(),
    )
    .await
    .expect("first exact publication enters the in-flight gate");
    reconnect_transport
        .reconnect()
        .await
        .expect("authenticated generation changes while the full drive is still in flight");
    assert_eq!(reconnect_harness.reconnect_count(), 1);
    transport.release_first_publish_as_offline();

    let readiness = tokio::time::timeout(Duration::from_secs(2), async {
        loop {
            progress_rx
                .changed()
                .await
                .expect("transition progress owner remains open");
            match *progress_rx.borrow_and_update() {
                TransitionProgress::Ready(readiness) => break readiness,
                TransitionProgress::Blocked(code) => panic!("unexpected transition block: {code}"),
                TransitionProgress::Idle | TransitionProgress::Pending => {}
            }
        }
    })
    .await
    .expect("the in-flight authenticated generation immediately wakes the Offline park");
    assert_eq!(
        readiness,
        TransitionReadiness::ControlPlaneReady { barrier_count: 1 }
    );
    assert_eq!(transport.publish_calls.load(Ordering::SeqCst), 2);
    let attempts = transport.attempts();
    assert_eq!(attempts.len(), 2);
    assert_eq!(
        attempts[0], attempts[1],
        "generation wake must retry the exact frozen publication without resealing"
    );

    transition
        .shutdown()
        .await
        .expect("shutdown generation-during-drive transition owner");
    publication
        .shutdown()
        .await
        .expect("shutdown in-flight publication owner");
    drop(reconnect_lane);
    reconnect_transport.shutdown().await;
    reopened
        .shutdown()
        .await
        .expect("shutdown generation-during-drive Store");
}

#[tokio::test]
async fn production_machine_link_disconnect_before_register_parks_until_authenticated_reconnect() {
    let fixture = production_epoch_barrier_crash_fixture("machine-link-pre-register-offline").await;
    fixture
        .store
        .clone()
        .shutdown()
        .await
        .expect("shutdown pre-register offline setup Store");
    let reopened = fixture.reopen().await;

    let (mut reconnect_transport, _pairing_lane, reconnect_harness) =
        super::transport::active_pairing_transport_for_test(fixture.machine_route);
    let reconnect_lane = reconnect_transport
        .take_business_lane()
        .expect("claim production-shaped MachineLink publication lane");
    let publication_handle = reconnect_lane.publication_handle();
    let authenticated_reconnects = publication_handle.subscribe_authenticated_reconnects();
    let publication = PublicationDriveOwner::open(reopened.clone(), publication_handle)
        .await
        .expect("open real MachineLink publication owner");
    let (authority, _authority_lease) = fixture.machine_data_authority();
    let transition = KeyTransitionRecoveryOwner::start_with_authenticated_reconnect(
        reopened.clone(),
        fixture.key_store(),
        fixture.machine_route,
        authority,
        publication.handle(),
        authenticated_reconnects,
        None,
    )
    .expect("start real pre-register offline transition owner");

    reconnect_harness
        .push_error("relay.client.connection_lost")
        .await;
    for _ in 0..10_000 {
        if reconnect_transport.observed_failure_code().is_some() {
            break;
        }
        tokio::task::yield_now().await;
    }
    assert!(reconnect_transport.observed_failure_code().is_some());

    transition
        .handle()
        .request_control_plane_progress()
        .expect("start the first full drive after the reader disconnected");
    for _ in 0..10_000 {
        if transition.observed_failure_code().as_deref()
            == Some("daemon.remote.transition.reconnect_pending")
        {
            break;
        }
        tokio::task::yield_now().await;
    }
    assert_eq!(
        transition.observed_failure_code().as_deref(),
        Some("daemon.remote.transition.reconnect_pending"),
        "a reconnectable reader loss before RegisterStream must park, not LocalBlock"
    );
    assert_eq!(reconnect_harness.sent_count(), 0);
    let frozen = reopened
        .load_pending_publications(fixture.publication_stream_id)
        .await
        .expect("load the exact frozen EpochBarrier after the Offline park");
    assert_eq!(frozen.len(), 1);
    let expected_blob = frozen[0].blob.clone();
    let settled_attempts = transition.attempt_count_for_test();
    assert_eq!(settled_attempts, 1);

    tokio::time::pause();
    tokio::time::advance(Duration::from_secs(5 * 60)).await;
    for _ in 0..512 {
        tokio::task::yield_now().await;
    }
    assert_eq!(
        transition.attempt_count_for_test(),
        settled_attempts,
        "a real pre-register Offline result must not start a timer retry loop"
    );
    assert_eq!(reconnect_harness.sent_count(), 0);

    let mut progress_rx = transition.handle().subscribe_progress();
    assert_eq!(
        *progress_rx.borrow_and_update(),
        TransitionProgress::Pending
    );
    assert!(matches!(
        transition.handle().drive_to_business_ready().await,
        Err(KeyTransitionRecoveryError::ReconnectPending)
    ));
    assert!(
        !progress_rx
            .has_changed()
            .expect("transition owner remains open"),
        "an ordinary caller while parked must not publish a fake new progress version"
    );
    transition
        .handle()
        .request_control_plane_progress()
        .expect("retain a control-plane wake while reconnect is pending");
    for _ in 0..512 {
        tokio::task::yield_now().await;
    }
    assert_eq!(transition.attempt_count_for_test(), settled_attempts);
    tokio::time::resume();

    reconnect_transport
        .reconnect()
        .await
        .expect("same supervisor completes an authenticated reconnect");
    tokio::time::timeout(Duration::from_secs(2), async {
        while reconnect_harness.sent_count() < 2 {
            tokio::task::yield_now().await;
        }
    })
    .await
    .expect("reconnect retries RegisterStream and the exact frozen Publish");
    let sent = reconnect_harness.sent_frames();
    assert_eq!(sent.len(), 2);
    assert!(matches!(sent[0].body, RelayFrameBody::RegisterStream(_)));
    let RelayFrameBody::Publish(publish) = &sent[1].body else {
        panic!("second frame must be the frozen Publish");
    };
    assert_eq!(publish.sealed_blob.0, expected_blob);
    let accepted_stream_route = publish.stream_route;
    let accepted_stream_seq = publish.stream_seq;
    reconnect_harness
        .push_frame(OpaqueRouteFrame {
            version: RELAY_PROTOCOL_VERSION,
            body: RelayFrameBody::RouteAccepted(RouteAccepted {
                accepted: AcceptedRef::StreamFrame {
                    stream_route: accepted_stream_route,
                    stream_seq: accepted_stream_seq,
                },
            }),
        })
        .await;
    let readiness = tokio::time::timeout(Duration::from_secs(2), async {
        loop {
            progress_rx
                .changed()
                .await
                .expect("transition progress owner remains open");
            match *progress_rx.borrow_and_update() {
                TransitionProgress::Ready(readiness) => break readiness,
                TransitionProgress::Blocked(code) => panic!("unexpected transition block: {code}"),
                TransitionProgress::Idle | TransitionProgress::Pending => {}
            }
        }
    })
    .await
    .expect("matching Relay ACK releases the reconnected transition attempt");
    assert_eq!(
        readiness,
        TransitionReadiness::ControlPlaneReady { barrier_count: 1 }
    );
    assert_eq!(reconnect_harness.reconnect_count(), 1);

    transition
        .shutdown()
        .await
        .expect("shutdown real pre-register transition owner");
    publication
        .shutdown()
        .await
        .expect("shutdown real MachineLink publication owner");
    drop(reconnect_lane);
    reconnect_transport.shutdown().await;
    reopened
        .shutdown()
        .await
        .expect("shutdown real pre-register Store");
}

#[tokio::test]
async fn production_epoch_barrier_restart_after_guard_reserve_before_seal_skips_block() {
    let fixture = production_epoch_barrier_crash_fixture("pre-seal").await;
    let first_transport = Arc::new(RecordingEpochBarrierTransport::new(
        EpochBarrierCrashRelayPlan::Commit,
    ));
    let first_publication =
        open_owner_with_transport_for_test(fixture.store.clone(), first_transport.clone())
            .await
            .expect("open pre-seal EpochBarrier publication owner");
    {
        let (setup_authority, _setup_authority_lease) = fixture.machine_data_authority();
        let setup_backend = RuntimeStoreTransitionBackend::new(
            fixture.store.clone(),
            fixture.key_store(),
            fixture.machine_route,
            setup_authority,
            first_publication.handle(),
        )
        .expect("construct pre-seal EpochBarrier setup backend");
        let setup = TransitionCoordinator::new(&setup_backend, setup_backend.authority());
        assert_eq!(
            setup.advance_once().await,
            Ok(TransitionAdvance::AwaitingKeyRotation)
        );
        recover_key_directory_rotation(&fixture.store, fixture.keys.as_ref())
            .await
            .expect("recover production EpochBarrier key-directory rotation");
        assert_eq!(
            setup.advance_once().await,
            Ok(TransitionAdvance::UpdatesFrozen { recipient_count: 1 })
        );
    }

    // KeyUpdate 已用有效 production authority 冻结；只在 barrier sealer 前使 owner
    // 失效，确保失败点落在 CounterGuard reserve 后、MachineData seal 前。
    let (dead_authority, dead_authority_lease) = fixture.machine_data_authority();
    drop(dead_authority_lease);
    {
        let dead_backend = RuntimeStoreTransitionBackend::new(
            fixture.store.clone(),
            fixture.key_store(),
            fixture.machine_route,
            dead_authority,
            first_publication.handle(),
        )
        .expect("construct pre-seal EpochBarrier failing backend");
        let dead = TransitionCoordinator::new(&dead_backend, dead_backend.authority());
        assert_eq!(
            dead.advance_once().await,
            Err(TransitionCoordinatorError::BackendRejected)
        );
    }
    assert_epoch_barrier_phase(
        &fixture.store,
        fixture.operation_id,
        KeyTransitionPhase::BarriersFrozen,
    )
    .await;
    fixture.assert_pending_counter_guard();
    assert!(
        fixture
            .store
            .load_pending_publication_streams()
            .await
            .expect("read pre-seal EpochBarrier outbox")
            .is_empty(),
        "reserve 后、seal 前失败不能形成 durable publication"
    );
    assert!(first_transport.sent_blobs().is_empty());

    first_publication
        .shutdown()
        .await
        .expect("shutdown pre-seal EpochBarrier publication owner");
    fixture
        .store
        .clone()
        .shutdown()
        .await
        .expect("shutdown pre-seal EpochBarrier Store");

    let reopened = fixture.reopen().await;
    let retry_transport = Arc::new(RecordingEpochBarrierTransport::new(
        EpochBarrierCrashRelayPlan::Commit,
    ));
    let retry_publication =
        open_owner_with_transport_for_test(reopened.clone(), retry_transport.clone())
            .await
            .expect("open pre-seal EpochBarrier retry publication owner");
    let (retry_authority, _retry_authority_lease) = fixture.machine_data_authority();
    let retry_transition = KeyTransitionRecoveryOwner::start(
        reopened.clone(),
        fixture.key_store(),
        fixture.machine_route,
        retry_authority,
        retry_publication.handle(),
    )
    .expect("start pre-seal EpochBarrier retry transition owner");
    assert_eq!(
        retry_transition
            .handle()
            .drive_to_business_ready()
            .await
            .expect("restart seals and commits production EpochBarrier"),
        TransitionReadiness::ControlPlaneReady { barrier_count: 1 }
    );
    let sent = retry_transport.sent_blobs();
    assert_eq!(sent.len(), 1);
    assert!(
        signed_blob_sender_counter(&sent[0]) >= COUNTER_BLOCK_SIZE,
        "restart 必须整体跳过 reserve 后遗留的 Pending block"
    );
    assert_epoch_barrier_phase(
        &reopened,
        fixture.operation_id,
        KeyTransitionPhase::BarriersCommitted,
    )
    .await;

    retry_transition
        .shutdown()
        .await
        .expect("shutdown pre-seal EpochBarrier retry transition owner");
    retry_publication
        .shutdown()
        .await
        .expect("shutdown pre-seal EpochBarrier retry publication owner");
    reopened
        .shutdown()
        .await
        .expect("shutdown recovered pre-seal EpochBarrier Store");
}

#[tokio::test]
async fn production_epoch_barrier_computed_seal_before_freeze_commit_is_ephemeral() {
    let fixture = production_epoch_barrier_crash_fixture("computed-pre-commit").await;
    fixture
        .store
        .clone()
        .shutdown()
        .await
        .expect("shutdown EpochBarrier setup Store before installing freeze fault");
    let fault = Arc::new(EpochBarrierCrashOnce::new(
        RuntimeStoreOperation::FreezePublicationBeforeCommit,
    ));
    let faulted = fixture
        .reopen_with_config(
            RuntimeStoreConfig::new(fixture.database.clone())
                .with_clock(TransitionCompositionClock)
                .with_fault_injector(fault.clone()),
        )
        .await;
    let first_transport = Arc::new(RecordingEpochBarrierTransport::new(
        EpochBarrierCrashRelayPlan::Commit,
    ));
    let first_publication =
        open_owner_with_transport_for_test(faulted.clone(), first_transport.clone())
            .await
            .expect("open computed pre-COMMIT EpochBarrier publication owner");
    let (first_authority, _first_authority_lease) = fixture.machine_data_authority();
    let first_transition = KeyTransitionRecoveryOwner::start(
        faulted.clone(),
        fixture.key_store(),
        fixture.machine_route,
        first_authority,
        first_publication.handle(),
    )
    .expect("start computed pre-COMMIT EpochBarrier transition owner");
    let error = first_transition
        .handle()
        .drive_to_business_ready()
        .await
        .expect_err("freeze BeforeCommit fault must reject the computed EpochBarrier seal");
    assert_eq!(error.code(), "daemon.remote.transition.backend_rejected");
    assert!(
        fault.fired(),
        "FreezePublicationBeforeCommit is strictly after production sealer execution"
    );
    assert_epoch_barrier_phase(
        &faulted,
        fixture.operation_id,
        KeyTransitionPhase::BarriersFrozen,
    )
    .await;
    fixture.assert_pending_counter_guard();
    assert!(
        faulted
            .load_pending_publication_streams()
            .await
            .expect("read computed pre-COMMIT EpochBarrier outbox")
            .is_empty(),
        "computed seal without freeze COMMIT is not a durable publication"
    );
    assert!(first_transport.sent_blobs().is_empty());

    first_transition
        .shutdown()
        .await
        .expect("shutdown computed pre-COMMIT EpochBarrier transition owner");
    first_publication
        .shutdown()
        .await
        .expect("shutdown computed pre-COMMIT EpochBarrier publication owner");
    faulted
        .shutdown()
        .await
        .expect("shutdown computed pre-COMMIT EpochBarrier Store");

    let reopened = fixture.reopen().await;
    let retry_transport = Arc::new(RecordingEpochBarrierTransport::new(
        EpochBarrierCrashRelayPlan::Commit,
    ));
    let retry_publication =
        open_owner_with_transport_for_test(reopened.clone(), retry_transport.clone())
            .await
            .expect("open computed pre-COMMIT EpochBarrier retry owner");
    let (retry_authority, _retry_authority_lease) = fixture.machine_data_authority();
    let retry_transition = KeyTransitionRecoveryOwner::start(
        reopened.clone(),
        fixture.key_store(),
        fixture.machine_route,
        retry_authority,
        retry_publication.handle(),
    )
    .expect("start computed pre-COMMIT EpochBarrier retry transition owner");
    assert_eq!(
        retry_transition
            .handle()
            .drive_to_business_ready()
            .await
            .expect("restart creates the first durable EpochBarrier publication"),
        TransitionReadiness::ControlPlaneReady { barrier_count: 1 }
    );
    let sent = retry_transport.sent_blobs();
    assert_eq!(sent.len(), 1);
    assert!(
        signed_blob_sender_counter(&sent[0]) >= COUNTER_BLOCK_SIZE,
        "computed pre-COMMIT seal 的 counter block 必须整体作废"
    );

    retry_transition
        .shutdown()
        .await
        .expect("shutdown computed pre-COMMIT EpochBarrier retry transition owner");
    retry_publication
        .shutdown()
        .await
        .expect("shutdown computed pre-COMMIT EpochBarrier retry publication owner");
    reopened
        .shutdown()
        .await
        .expect("shutdown recovered computed pre-COMMIT EpochBarrier Store");
}

#[tokio::test]
async fn production_epoch_barrier_outcome_unknown_restarts_with_exact_frozen_blob() {
    let fixture = production_epoch_barrier_crash_fixture("relay-unknown").await;
    let first_transport = Arc::new(RecordingEpochBarrierTransport::new(
        EpochBarrierCrashRelayPlan::OutcomeUnknown,
    ));
    let first_publication =
        open_owner_with_transport_for_test(fixture.store.clone(), first_transport.clone())
            .await
            .expect("open outcome-unknown EpochBarrier publication owner");
    let (first_authority, _first_authority_lease) = fixture.machine_data_authority();
    let first_transition = KeyTransitionRecoveryOwner::start(
        fixture.store.clone(),
        fixture.key_store(),
        fixture.machine_route,
        first_authority,
        first_publication.handle(),
    )
    .expect("start outcome-unknown EpochBarrier transition owner");
    let error = first_transition
        .handle()
        .drive_to_business_ready()
        .await
        .expect_err("Relay outcome unknown must keep EpochBarrier fenced");
    assert_eq!(error.code(), "daemon.remote.transition.progress_pending");
    let first_sent = first_transport.sent_blobs();
    assert_eq!(first_sent.len(), 1);
    SignedSealedBlobV1::from_wire_bytes(&first_sent[0])
        .expect("outcome-unknown EpochBarrier is a real signed blob");
    assert_epoch_barrier_phase(
        &fixture.store,
        fixture.operation_id,
        KeyTransitionPhase::BarriersFrozen,
    )
    .await;
    assert_eq!(
        fixture
            .store
            .load_pending_publication_streams()
            .await
            .expect("read outcome-unknown EpochBarrier outbox"),
        vec![fixture.publication_stream_id]
    );

    first_transition
        .shutdown()
        .await
        .expect("shutdown outcome-unknown EpochBarrier transition owner");
    first_publication
        .shutdown()
        .await
        .expect("shutdown outcome-unknown EpochBarrier publication owner");
    fixture
        .store
        .clone()
        .shutdown()
        .await
        .expect("shutdown outcome-unknown EpochBarrier Store");

    let reopened = fixture.reopen().await;
    let retry_transport = Arc::new(RecordingEpochBarrierTransport::new(
        EpochBarrierCrashRelayPlan::Commit,
    ));
    let retry_publication =
        open_owner_with_transport_for_test(reopened.clone(), retry_transport.clone())
            .await
            .expect("open outcome-unknown EpochBarrier retry publication owner");
    let (retry_authority, _retry_authority_lease) = fixture.machine_data_authority();
    let retry_transition = KeyTransitionRecoveryOwner::start(
        reopened.clone(),
        fixture.key_store(),
        fixture.machine_route,
        retry_authority,
        retry_publication.handle(),
    )
    .expect("start outcome-unknown EpochBarrier retry transition owner");
    assert_eq!(
        retry_transition
            .handle()
            .drive_to_business_ready()
            .await
            .expect("outcome-unknown restart republishes exact frozen EpochBarrier"),
        TransitionReadiness::ControlPlaneReady { barrier_count: 1 }
    );
    assert_eq!(
        retry_transport.sent_blobs(),
        first_sent,
        "durable freeze 后只能逐字重发 exact EpochBarrier blob"
    );

    retry_transition
        .shutdown()
        .await
        .expect("shutdown outcome-unknown EpochBarrier retry transition owner");
    retry_publication
        .shutdown()
        .await
        .expect("shutdown outcome-unknown EpochBarrier retry publication owner");
    reopened
        .shutdown()
        .await
        .expect("shutdown recovered outcome-unknown EpochBarrier Store");
}

#[tokio::test]
async fn production_epoch_barrier_committed_restart_returns_without_resend() {
    let fixture = production_epoch_barrier_crash_fixture("post-commit-pre-local-ack").await;
    let first_transport = Arc::new(RecordingEpochBarrierTransport::new(
        EpochBarrierCrashRelayPlan::Commit,
    ));
    let first_publication =
        open_owner_with_transport_for_test(fixture.store.clone(), first_transport.clone())
            .await
            .expect("open committed EpochBarrier publication owner");
    let (first_authority, _first_authority_lease) = fixture.machine_data_authority();
    let first_transition = KeyTransitionRecoveryOwner::start(
        fixture.store.clone(),
        fixture.key_store(),
        fixture.machine_route,
        first_authority,
        first_publication.handle(),
    )
    .expect("start committed EpochBarrier transition owner");
    assert_eq!(
        first_transition
            .handle()
            .drive_to_business_ready()
            .await
            .expect("first EpochBarrier observes exact Relay COMMIT"),
        TransitionReadiness::ControlPlaneReady { barrier_count: 1 }
    );
    let first_sent = first_transport.sent_blobs();
    assert_eq!(first_sent.len(), 1);
    SignedSealedBlobV1::from_wire_bytes(&first_sent[0])
        .expect("committed EpochBarrier is a real signed blob");
    assert_epoch_barrier_phase(
        &fixture.store,
        fixture.operation_id,
        KeyTransitionPhase::BarriersCommitted,
    )
    .await;

    // 不清除 counter-recovery fence，也不写更高层 local ACK；模拟 exact Relay
    // COMMIT readback 已落库后 caller 尚未消费成功结果时进程退出。
    first_transition
        .shutdown()
        .await
        .expect("shutdown committed EpochBarrier transition owner");
    first_publication
        .shutdown()
        .await
        .expect("shutdown committed EpochBarrier publication owner");
    fixture
        .store
        .clone()
        .shutdown()
        .await
        .expect("shutdown committed EpochBarrier Store");

    let reopened = fixture.reopen().await;
    let committed_stream = reopened
        .load_publication_stream_record(fixture.publication_stream_id)
        .await
        .expect("reload committed EpochBarrier stream readback");
    assert_eq!(committed_stream.committed_high_water, Some(0));
    assert_eq!(
        committed_stream.last_committed_blob_hash,
        Some(sha256(&first_sent[0]))
    );
    let retry_transport = Arc::new(RecordingEpochBarrierTransport::new(
        EpochBarrierCrashRelayPlan::Commit,
    ));
    let retry_publication =
        open_owner_with_transport_for_test(reopened.clone(), retry_transport.clone())
            .await
            .expect("open committed EpochBarrier retry publication owner");
    let (retry_authority, _retry_authority_lease) = fixture.machine_data_authority();
    let retry_transition = KeyTransitionRecoveryOwner::start(
        reopened.clone(),
        fixture.key_store(),
        fixture.machine_route,
        retry_authority,
        retry_publication.handle(),
    )
    .expect("start committed EpochBarrier retry transition owner");
    assert_eq!(
        retry_transition
            .handle()
            .drive_to_business_ready()
            .await
            .expect("committed EpochBarrier restart returns from authenticated readback"),
        TransitionReadiness::ControlPlaneReady { barrier_count: 1 }
    );
    assert!(
        retry_transport.sent_blobs().is_empty(),
        "BarriersCommitted restart 不得 reseal 或再次发送"
    );

    retry_transition
        .shutdown()
        .await
        .expect("shutdown committed EpochBarrier retry transition owner");
    retry_publication
        .shutdown()
        .await
        .expect("shutdown committed EpochBarrier retry publication owner");
    reopened
        .shutdown()
        .await
        .expect("shutdown recovered committed EpochBarrier Store");
}
