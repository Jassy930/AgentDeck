use std::sync::atomic::{AtomicU8, AtomicUsize, Ordering};
use std::sync::{Arc, Mutex};

use agentdeck_crypto::{
    SigningKey, ValidatedRelayReceiptSignerIdentityV1, sha256, sign_relay_admin_purge_receipt,
    verify_tbs,
};
use agentdeck_protocol::relay_v2::{
    CertRole, Digest32, Ed25519Signature, LinkGeneration, MachineEnrollmentResponseV1,
    PublicKeyBytes, RELAY_RECEIPT_FORMAT_VERSION, RELAY_RECEIPT_KEY_GENERATION_MVP,
    RelayAdminPurgeReadbackV1, RelayAdminPurgeReceiptTbsV1, RelayAdminPurgeTombstoneV1,
    RelayMachineTombstoneKindV1, RelayReceiptVerifyKeyV1, SignedCertificate,
    admin_purge_tombstone_hash, enrollment_receipt_hash, purge_request_hash,
};

use crate::remote::identity::load_or_create_preparing_machine_key_material;
use crate::runtime::store::{
    ActiveMachineEnrollmentState, LocalDeletedMachineEnrollmentState,
    MachineEnrollmentConnectionMaterial, MachineRootLostPurgeMaterial,
    RelayCommittedMachineEnrollmentState, RetirePendingMachineEnrollmentState,
};
use crate::security::MemoryKeyStore;

use super::*;

const RELAY: RelayServerId = RelayServerId::from_bytes([0x31; 16]);
const ROUTE: MachineRouteId = MachineRouteId::from_bytes([0x32; 16]);
const TRUST_EPOCH: u64 = 3;

fn binding_from_material(material: &MachineKeyMaterial) -> MachineIdentityBinding {
    let public = material.public_identity();
    MachineIdentityBinding {
        root_key_id: [0x41; 16],
        trust_epoch: TRUST_EPOCH,
        link_generation: 5,
        data_generation: 7,
        key_directory_revision: 11,
        root_public_key: *public.root().public_key(),
        root_fingerprint: public.root().fingerprint(),
        machine_hpke_public_key: *public.hpke().public_key(),
        machine_hpke_fingerprint: public.hpke().fingerprint(),
        link_sign_public_key: *public.link().public_key(),
        link_sign_fingerprint: public.link().fingerprint(),
        data_sign_public_key: *public.data().public_key(),
        data_sign_fingerprint: public.data().fingerprint(),
    }
}

fn frozen_fixture() -> (MachineIdentityBinding, FrozenMachineRetirement) {
    let keys = MemoryKeyStore::new();
    let material =
        load_or_create_preparing_machine_key_material(&keys).expect("create test machine material");
    let binding = binding_from_material(&material);
    let frozen = freeze_machine_retirement(&binding, &material, RELAY, ROUTE, TRUST_EPOCH)
        .expect("freeze typed retirement");
    (binding, frozen)
}

fn clone_frozen(frozen: &FrozenMachineRetirement) -> FrozenMachineRetirement {
    FrozenMachineRetirement {
        relay_server_id: frozen.relay_server_id,
        root_fingerprint: frozen.root_fingerprint,
        retirement: frozen.retirement.clone(),
        canonical_bytes: frozen.canonical_bytes.clone(),
        canonical_hash: frozen.canonical_hash,
    }
}

fn certificate(binding: &MachineIdentityBinding, role: CertRole) -> SignedCertificate {
    let (subject, generation) = match role {
        CertRole::Link => (binding.link_sign_public_key, binding.link_generation),
        CertRole::Data => (binding.data_sign_public_key, binding.data_generation),
    };
    SignedCertificate {
        subject_pubkey: PublicKeyBytes(subject),
        cert_role: role,
        generation: LinkGeneration::new(generation),
        root_key_id: RootKeyId::from_bytes(binding.root_key_id),
        trust_epoch: TrustEpoch::new(binding.trust_epoch),
        not_after_ms: None,
        signature: Ed25519Signature([0x51; 64]),
    }
}

fn receipt_anchor() -> RelayReceiptVerifyKeyV1 {
    ValidatedRelayReceiptSignerIdentityV1::from_signing_key(&SigningKey::from_seed(&[0x71; 32]))
        .expect("valid receipt signer")
        .bind_to_relay(RELAY)
        .expect("bind receipt signer")
        .wire_anchor()
        .clone()
}

#[derive(Clone)]
struct Fixture {
    binding: MachineIdentityBinding,
    connection: MachineEnrollmentConnectionMaterial,
    link_cert: SignedCertificate,
    data_cert: SignedCertificate,
    response: MachineEnrollmentResponseV1,
    request_hash: [u8; 32],
    response_hash: [u8; 32],
}

impl Fixture {
    fn new(binding: MachineIdentityBinding) -> Self {
        let request_hash = [0x61; 32];
        let response = MachineEnrollmentResponseV1::new(
            RELAY,
            ROUTE,
            binding.trust_epoch,
            enrollment_receipt_hash(RELAY, ROUTE, binding.trust_epoch, request_hash),
        )
        .expect("valid fake enrollment response");
        let response_hash = response.canonical_sha256().expect("response hash");
        Self {
            link_cert: certificate(&binding, CertRole::Link),
            data_cert: certificate(&binding, CertRole::Data),
            connection: MachineEnrollmentConnectionMaterial {
                public_wss_url: "wss://relay.example.test/".to_owned(),
                relay_server_id: RELAY,
                receipt_verify_key: receipt_anchor(),
                spki_pins: vec![Digest32([0x53; 32])],
                expires_at_ms: 1,
            },
            binding,
            response,
            request_hash,
            response_hash,
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum FakeStage {
    Active,
    RetirePending,
    RelayCommitted,
    PurgeRootPresent,
    PurgeRootLost,
}

#[derive(Clone)]
struct TerminalData {
    committed: RetirementCommitted,
    bytes: Vec<u8>,
    hash: [u8; 32],
}

#[derive(Clone)]
struct Durable {
    stage: FakeStage,
    retirement: Option<RetireMachine>,
    terminal: Option<TerminalData>,
    root_lost_receipt: Option<RelayAdminPurgeReceiptV1>,
}

impl Default for Durable {
    fn default() -> Self {
        Self {
            stage: FakeStage::Active,
            retirement: None,
            terminal: None,
            root_lost_receipt: None,
        }
    }
}

#[derive(Default)]
struct UnknownFlags {
    prepare: bool,
    terminal: bool,
    confirm: bool,
    root_lost: bool,
}

struct FakeStore {
    fixture: Fixture,
    durable: Mutex<Durable>,
    unknown: Mutex<UnknownFlags>,
    events: Arc<Mutex<Vec<&'static str>>>,
    prepares: AtomicUsize,
    records: AtomicUsize,
    confirms: AtomicUsize,
    root_lost_records: AtomicUsize,
    loads: AtomicUsize,
}

impl FakeStore {
    fn new(binding: MachineIdentityBinding) -> Self {
        Self {
            fixture: Fixture::new(binding),
            durable: Mutex::new(Durable::default()),
            unknown: Mutex::new(UnknownFlags::default()),
            events: Arc::new(Mutex::new(Vec::new())),
            prepares: AtomicUsize::new(0),
            records: AtomicUsize::new(0),
            confirms: AtomicUsize::new(0),
            root_lost_records: AtomicUsize::new(0),
            loads: AtomicUsize::new(0),
        }
    }

    fn with_root_present_unknowns(binding: MachineIdentityBinding) -> Self {
        let store = Self::new(binding);
        *store.unknown.lock().expect("lock unknown flags") = UnknownFlags {
            prepare: true,
            terminal: true,
            confirm: true,
            root_lost: false,
        };
        store
    }

    fn with_root_lost_unknown(binding: MachineIdentityBinding) -> Self {
        let store = Self::new(binding);
        store.unknown.lock().expect("lock unknown flags").root_lost = true;
        store
    }

    fn stage(&self) -> FakeStage {
        self.durable.lock().expect("lock durable").stage
    }

    fn state(&self) -> MachineEnrollmentState {
        let durable = self.durable.lock().expect("lock durable").clone();
        let record = self.record(durable.stage);
        match durable.stage {
            FakeStage::Active => {
                MachineEnrollmentState::Active(Box::new(ActiveMachineEnrollmentState {
                    record,
                    connection: self.fixture.connection.clone(),
                    binding: self.fixture.binding.clone(),
                    link_cert: self.fixture.link_cert.clone(),
                    data_cert: self.fixture.data_cert.clone(),
                    prepare_input_hash: [0x91; 32],
                    response: self.fixture.response.clone(),
                }))
            }
            FakeStage::RetirePending => MachineEnrollmentState::RetirePending(Box::new(
                RetirePendingMachineEnrollmentState {
                    record,
                    connection: self.fixture.connection.clone(),
                    binding: self.fixture.binding.clone(),
                    link_cert: self.fixture.link_cert.clone(),
                    retirement: retirement_material(
                        durable.retirement.as_ref().expect("pending retirement"),
                    ),
                },
            )),
            FakeStage::RelayCommitted => {
                let retirement = durable.retirement.as_ref().expect("committed retirement");
                let terminal = durable.terminal.as_ref().expect("committed terminal");
                MachineEnrollmentState::RelayCommitted(Box::new(
                    RelayCommittedMachineEnrollmentState {
                        record,
                        retirement: retirement_material(retirement),
                        terminal: terminal_material(terminal),
                    },
                ))
            }
            FakeStage::PurgeRootPresent => {
                let retirement = durable.retirement.as_ref().expect("purged retirement");
                let terminal = durable.terminal.as_ref().expect("purged terminal");
                MachineEnrollmentState::PurgeReadbackAbsent(Box::new(
                    PurgeReadbackAbsentMachineEnrollmentState {
                        record,
                        database_id: [0x33; 16],
                        binding: self.fixture.binding.clone(),
                        reset_kind: MachineTrustResetKind::RootPresent,
                        proof: MachinePurgeReadbackProof::RootPresent {
                            retirement: retirement_material(retirement),
                            terminal: terminal_material(terminal),
                        },
                    },
                ))
            }
            FakeStage::PurgeRootLost => {
                let receipt = durable
                    .root_lost_receipt
                    .as_ref()
                    .expect("root-lost receipt");
                let bytes = receipt.canonical_bytes().expect("receipt bytes");
                MachineEnrollmentState::PurgeReadbackAbsent(Box::new(
                    PurgeReadbackAbsentMachineEnrollmentState {
                        record,
                        database_id: [0x33; 16],
                        binding: self.fixture.binding.clone(),
                        reset_kind: MachineTrustResetKind::RootLost,
                        proof: MachinePurgeReadbackProof::RootLost {
                            purge: MachineRootLostPurgeMaterial {
                                receipt: receipt.clone(),
                                canonical_hash: sha256(&bytes),
                                canonical_bytes: bytes,
                            },
                        },
                    },
                ))
            }
        }
    }

    fn record(&self, stage: FakeStage) -> MachineRemoteStateRecord {
        MachineRemoteStateRecord {
            lifecycle: match stage {
                FakeStage::Active => MachineRemoteLifecycle::Active,
                FakeStage::RetirePending => MachineRemoteLifecycle::RetirePending,
                FakeStage::RelayCommitted => MachineRemoteLifecycle::RelayCommitted,
                FakeStage::PurgeRootPresent | FakeStage::PurgeRootLost => {
                    MachineRemoteLifecycle::PurgeReadbackAbsent
                }
            },
            relay_server_id: *RELAY.as_bytes(),
            machine_route: *ROUTE.as_bytes(),
            root_key_id: self.fixture.binding.root_key_id,
            root_fingerprint: self.fixture.binding.root_fingerprint,
            trust_epoch: self.fixture.binding.trust_epoch,
            request_hash: self.fixture.request_hash,
            response_hash: Some(self.fixture.response_hash),
            enrollment_receipt_hash: Some(self.fixture.response.receipt_hash),
            receipt_verify_key_hash: self
                .fixture
                .connection
                .receipt_verify_key
                .canonical_sha256()
                .expect("receipt anchor hash"),
            sealed_state_bytes: 1,
        }
    }
}

fn retirement_material(retirement: &RetireMachine) -> MachineRetirementRequestMaterial {
    MachineRetirementRequestMaterial {
        retirement: retirement.clone(),
        canonical_bytes: retirement.canonical_bytes(),
        canonical_hash: retirement.canonical_sha256(),
    }
}

fn terminal_material(terminal: &TerminalData) -> MachineRetirementTerminalMaterial {
    MachineRetirementTerminalMaterial {
        committed: terminal.committed.clone(),
        canonical_frame_bytes: terminal.bytes.clone(),
        canonical_frame_hash: terminal.hash,
    }
}

fn terminal_for(retirement: &RetireMachine) -> TerminalData {
    let committed = RetirementCommitted {
        machine_route: retirement.machine_route,
        trust_epoch: retirement.trust_epoch,
        retire_hash: retirement.canonical_sha256(),
    };
    terminal_data(committed)
}

fn terminal_data(committed: RetirementCommitted) -> TerminalData {
    let bytes = encode(&OpaqueRouteFrame {
        version: RELAY_PROTOCOL_VERSION,
        body: RelayFrameBody::RetirementCommitted(committed.clone()),
    });
    TerminalData {
        committed,
        hash: sha256(&bytes),
        bytes,
    }
}

fn take_flag(
    flags: &Mutex<UnknownFlags>,
    select: impl FnOnce(&mut UnknownFlags) -> &mut bool,
) -> bool {
    let mut flags = flags.lock().expect("lock unknown flags");
    std::mem::take(select(&mut flags))
}

#[async_trait]
impl TrustResetStore for FakeStore {
    async fn load(&self) -> Result<Option<MachineEnrollmentState>, RuntimeStoreError> {
        self.loads.fetch_add(1, Ordering::SeqCst);
        self.events.lock().expect("lock events").push("load");
        Ok(Some(self.state()))
    }

    async fn prepare_retirement(
        &self,
        retirement: RetireMachine,
    ) -> Result<PrepareMachineRetirementOutcome, RuntimeStoreError> {
        self.prepares.fetch_add(1, Ordering::SeqCst);
        self.events.lock().expect("lock events").push("prepare");
        let mut durable = self.durable.lock().expect("lock durable");
        let prepared = durable.stage == FakeStage::Active;
        match durable.stage {
            FakeStage::Active => {
                durable.retirement = Some(retirement);
                durable.stage = FakeStage::RetirePending;
            }
            FakeStage::RetirePending | FakeStage::RelayCommitted | FakeStage::PurgeRootPresent => {
                if durable.retirement.as_ref() != Some(&retirement) {
                    return Err(RuntimeStoreError::MachineRemoteConflict);
                }
            }
            FakeStage::PurgeRootLost => {
                return Err(RuntimeStoreError::MachineRemoteConflict);
            }
        }
        drop(durable);
        if take_flag(&self.unknown, |flags| &mut flags.prepare) {
            return Err(RuntimeStoreError::CommitOutcomeUnknown {
                operation: RuntimeCommitOperation::PrepareMachineRetirement,
            });
        }
        let state = self.state();
        if prepared {
            Ok(PrepareMachineRetirementOutcome::Prepared { state })
        } else {
            Ok(PrepareMachineRetirementOutcome::Replayed { state })
        }
    }

    async fn record_terminal(
        &self,
        canonical_frame_bytes: Vec<u8>,
        canonical_frame_hash: [u8; 32],
    ) -> Result<RecordMachineRetirementTerminalOutcome, RuntimeStoreError> {
        self.records.fetch_add(1, Ordering::SeqCst);
        self.events.lock().expect("lock events").push("record");
        if sha256(&canonical_frame_bytes) != canonical_frame_hash {
            return Err(RuntimeStoreError::MachineRemoteConflict);
        }
        let frame =
            decode(&canonical_frame_bytes).map_err(|_| RuntimeStoreError::MachineRemoteConflict)?;
        let RelayFrameBody::RetirementCommitted(committed) = frame.body else {
            return Err(RuntimeStoreError::MachineRemoteConflict);
        };
        let candidate = TerminalData {
            committed,
            bytes: canonical_frame_bytes,
            hash: canonical_frame_hash,
        };
        let mut durable = self.durable.lock().expect("lock durable");
        let recorded = durable.stage == FakeStage::RetirePending;
        match durable.stage {
            FakeStage::RetirePending => {
                durable.terminal = Some(candidate);
                durable.stage = FakeStage::RelayCommitted;
            }
            FakeStage::RelayCommitted | FakeStage::PurgeRootPresent => {
                let existing = durable.terminal.as_ref().expect("existing terminal");
                if existing.bytes != candidate.bytes || existing.hash != candidate.hash {
                    return Err(RuntimeStoreError::MachineRemoteConflict);
                }
            }
            FakeStage::Active | FakeStage::PurgeRootLost => {
                return Err(RuntimeStoreError::MachineRemoteConflict);
            }
        }
        drop(durable);
        if take_flag(&self.unknown, |flags| &mut flags.terminal) {
            return Err(RuntimeStoreError::CommitOutcomeUnknown {
                operation: RuntimeCommitOperation::RecordMachineRetirementTerminal,
            });
        }
        let state = self.state();
        if recorded {
            Ok(RecordMachineRetirementTerminalOutcome::Recorded { state })
        } else {
            Ok(RecordMachineRetirementTerminalOutcome::Replayed { state })
        }
    }

    async fn confirm_purge_absent(
        &self,
        canonical_frame_bytes: Vec<u8>,
        canonical_frame_hash: [u8; 32],
    ) -> Result<ConfirmMachinePurgeReadbackAbsentOutcome, RuntimeStoreError> {
        self.confirms.fetch_add(1, Ordering::SeqCst);
        self.events.lock().expect("lock events").push("confirm");
        let mut durable = self.durable.lock().expect("lock durable");
        let confirmed = durable.stage == FakeStage::RelayCommitted;
        match durable.stage {
            FakeStage::RelayCommitted | FakeStage::PurgeRootPresent => {
                let terminal = durable.terminal.as_ref().expect("terminal exists");
                if terminal.bytes != canonical_frame_bytes || terminal.hash != canonical_frame_hash
                {
                    return Err(RuntimeStoreError::MachineRemoteConflict);
                }
                durable.stage = FakeStage::PurgeRootPresent;
            }
            FakeStage::Active | FakeStage::RetirePending | FakeStage::PurgeRootLost => {
                return Err(RuntimeStoreError::MachineRemoteConflict);
            }
        }
        drop(durable);
        if take_flag(&self.unknown, |flags| &mut flags.confirm) {
            return Err(RuntimeStoreError::CommitOutcomeUnknown {
                operation: RuntimeCommitOperation::ConfirmMachinePurgeReadbackAbsent,
            });
        }
        let state = self.state();
        if confirmed {
            Ok(ConfirmMachinePurgeReadbackAbsentOutcome::Confirmed { state })
        } else {
            Ok(ConfirmMachinePurgeReadbackAbsentOutcome::Replayed { state })
        }
    }

    async fn record_root_lost(
        &self,
        receipt: RelayAdminPurgeReceiptV1,
    ) -> Result<RecordRootLostMachinePurgeOutcome, RuntimeStoreError> {
        self.root_lost_records.fetch_add(1, Ordering::SeqCst);
        self.events.lock().expect("lock events").push("root_lost");
        let mut durable = self.durable.lock().expect("lock durable");
        let recorded = durable.stage == FakeStage::Active;
        match durable.stage {
            FakeStage::Active => {
                durable.root_lost_receipt = Some(receipt);
                durable.stage = FakeStage::PurgeRootLost;
            }
            FakeStage::PurgeRootLost => {
                if durable.root_lost_receipt.as_ref() != Some(&receipt) {
                    return Err(RuntimeStoreError::MachineRemoteConflict);
                }
            }
            FakeStage::RetirePending | FakeStage::RelayCommitted | FakeStage::PurgeRootPresent => {
                return Err(RuntimeStoreError::MachineRemoteConflict);
            }
        }
        drop(durable);
        if take_flag(&self.unknown, |flags| &mut flags.root_lost) {
            return Err(RuntimeStoreError::CommitOutcomeUnknown {
                operation: RuntimeCommitOperation::RecordRootLostMachinePurge,
            });
        }
        let state = self.state();
        if recorded {
            Ok(RecordRootLostMachinePurgeOutcome::Recorded { state })
        } else {
            Ok(RecordRootLostMachinePurgeOutcome::Replayed { state })
        }
    }
}

const CONTROL_SUCCESS: u8 = 0;
const CONTROL_FAILURE: u8 = 1;
const CONTROL_INVALID_TERMINAL: u8 = 2;
const CONTROL_HANG: u8 = 3;

struct FakeControl {
    mode: AtomicU8,
    failure_code: Mutex<String>,
    calls: AtomicUsize,
    requests: Mutex<Vec<Vec<u8>>>,
    events: Arc<Mutex<Vec<&'static str>>>,
}

impl FakeControl {
    fn new(mode: u8, events: Arc<Mutex<Vec<&'static str>>>) -> Self {
        Self {
            mode: AtomicU8::new(mode),
            failure_code: Mutex::new("relay.store.unavailable".to_owned()),
            calls: AtomicUsize::new(0),
            requests: Mutex::new(Vec::new()),
            events,
        }
    }

    fn set_success(&self) {
        self.mode.store(CONTROL_SUCCESS, Ordering::SeqCst);
    }

    fn set_failure_code(&self, code: &str) {
        *self.failure_code.lock().expect("lock failure code") = code.to_owned();
    }
}

#[async_trait]
impl TrustResetControlTransport for FakeControl {
    async fn retire(
        &mut self,
        retirement: RetireMachine,
    ) -> Result<ObservedRetirementTerminal, TrustResetControlFailure> {
        self.calls.fetch_add(1, Ordering::SeqCst);
        self.events.lock().expect("lock events").push("network");
        self.requests
            .lock()
            .expect("lock requests")
            .push(retirement.canonical_bytes());
        match self.mode.load(Ordering::SeqCst) {
            CONTROL_HANG => std::future::pending().await,
            CONTROL_FAILURE => Err(TrustResetControlFailure::new(
                self.failure_code.lock().expect("lock failure code").clone(),
            )),
            CONTROL_INVALID_TERMINAL => {
                let mut committed = terminal_for(&retirement).committed;
                committed.retire_hash[0] ^= 1;
                let terminal = terminal_data(committed);
                Ok(ObservedRetirementTerminal {
                    committed: terminal.committed,
                    canonical_frame_bytes: terminal.bytes,
                    canonical_frame_hash: terminal.hash,
                })
            }
            _ => {
                let terminal = terminal_for(&retirement);
                Ok(ObservedRetirementTerminal {
                    committed: terminal.committed,
                    canonical_frame_bytes: terminal.bytes,
                    canonical_frame_hash: terminal.hash,
                })
            }
        }
    }
}

fn expect_workflow_error(
    result: Result<Box<PurgeReadbackAbsentMachineEnrollmentState>, MachineTrustResetWorkflowError>,
    context: &str,
) -> MachineTrustResetWorkflowError {
    match result {
        Ok(_) => panic!("{context}"),
        Err(error) => error,
    }
}

fn root_lost_receipt(
    binding: &MachineIdentityBinding,
    enrollment_hash: [u8; 32],
) -> RelayAdminPurgeReceiptV1 {
    let signer = SigningKey::from_seed(&[0x71; 32]);
    let verify_key = ValidatedRelayReceiptSignerIdentityV1::from_signing_key(&signer)
        .expect("valid receipt signer")
        .bind_to_relay(RELAY)
        .expect("bind receipt signer");
    let readback = RelayAdminPurgeReadbackV1 {
        active_machine_routes: 0,
        retired_tombstones: 1,
        consumed_enrollment_records: 0,
        device_grants: 0,
        revocations: 0,
        streams: 0,
        frames: 0,
        subscriptions: 0,
        retirement_hash: None,
        retirement_terminal_present: false,
    };
    let request_hash = purge_request_hash(ROUTE, binding.root_fingerprint).expect("purge hash");
    let tombstone = RelayAdminPurgeTombstoneV1 {
        relay_server_id: RELAY,
        machine_route: ROUTE,
        root_key_id: RootKeyId::from_bytes(binding.root_key_id),
        root_fingerprint: binding.root_fingerprint,
        trust_epoch: TrustEpoch::new(binding.trust_epoch),
        enrollment_receipt_hash: enrollment_hash,
        purge_request_hash: request_hash,
        tombstone_kind: RelayMachineTombstoneKindV1::RootLostAdminPurge,
        readback: readback.clone(),
    };
    let tbs = RelayAdminPurgeReceiptTbsV1 {
        receipt_format_version: RELAY_RECEIPT_FORMAT_VERSION,
        relay_protocol_version: RELAY_PROTOCOL_VERSION,
        relay_server_id: RELAY,
        receipt_key_generation: RELAY_RECEIPT_KEY_GENERATION_MVP,
        receipt_key_id: verify_key.wire_anchor().key_id,
        machine_route: ROUTE,
        root_key_id: RootKeyId::from_bytes(binding.root_key_id),
        root_fingerprint: binding.root_fingerprint,
        trust_epoch: TrustEpoch::new(binding.trust_epoch),
        enrollment_receipt_hash: enrollment_hash,
        purge_request_hash: request_hash,
        tombstone_kind: RelayMachineTombstoneKindV1::RootLostAdminPurge,
        readback,
        tombstone_hash: admin_purge_tombstone_hash(&tombstone).expect("tombstone hash"),
    };
    sign_relay_admin_purge_receipt(&signer, &verify_key, tbs).expect("sign purge receipt")
}

#[test]
fn typed_retirement_is_deterministic_bound_and_redacted() {
    let keys = MemoryKeyStore::new();
    let material =
        load_or_create_preparing_machine_key_material(&keys).expect("create test machine material");
    let binding = binding_from_material(&material);
    let first = freeze_machine_retirement(&binding, &material, RELAY, ROUTE, TRUST_EPOCH)
        .expect("freeze first retirement");
    let second = freeze_machine_retirement(&binding, &material, RELAY, ROUTE, TRUST_EPOCH)
        .expect("freeze second retirement");
    assert_eq!(first.canonical_bytes(), second.canonical_bytes());
    assert_eq!(first.canonical_hash(), second.canonical_hash());
    assert_eq!(first.retirement(), second.retirement());
    let root = VerifyingKey::from_bytes(&binding.root_public_key).expect("root verifying key");
    verify_tbs(
        &root,
        &first
            .retirement()
            .to_be_signed_v1(RELAY, binding.root_fingerprint),
        &SignatureBytes::from(first.retirement().signature),
    )
    .expect("verify retirement signature");
    assert_eq!(format!("{first:?}"), "FrozenMachineRetirement([REDACTED])");

    assert_eq!(
        freeze_machine_retirement(
            &binding,
            &material,
            RelayServerId::from_bytes([0; 16]),
            ROUTE,
            TRUST_EPOCH,
        )
        .expect_err("zero Relay must fail"),
        MachineRetirementError::InvalidRelayServerId
    );
    assert_eq!(
        freeze_machine_retirement(
            &binding,
            &material,
            RELAY,
            MachineRouteId::from_bytes([0; 16]),
            TRUST_EPOCH,
        )
        .expect_err("zero route must fail"),
        MachineRetirementError::InvalidMachineRouteId
    );
    assert_eq!(
        freeze_machine_retirement(&binding, &material, RELAY, ROUTE, TRUST_EPOCH + 1)
            .expect_err("wrong epoch must fail"),
        MachineRetirementError::TrustEpochMismatch
    );
}

#[tokio::test]
async fn root_present_orders_prepare_network_record_and_local_confirmation() {
    let (binding, frozen) = frozen_fixture();
    let store = FakeStore::new(binding);
    let mut control = FakeControl::new(CONTROL_SUCCESS, Arc::clone(&store.events));
    let final_state = MachineTrustResetWorkflow::new()
        .run_root_present_with(&store, frozen, &mut control)
        .await
        .expect("complete root-present reset");

    assert_eq!(final_state.reset_kind, MachineTrustResetKind::RootPresent);
    assert_eq!(store.stage(), FakeStage::PurgeRootPresent);
    assert_eq!(control.calls.load(Ordering::SeqCst), 1);
    assert_eq!(store.records.load(Ordering::SeqCst), 1);
    assert_eq!(store.confirms.load(Ordering::SeqCst), 1);
    assert_eq!(
        *store.events.lock().expect("lock events"),
        ["prepare", "network", "record", "confirm"]
    );
}

#[tokio::test]
async fn offline_restarting_and_safe_failure_preserve_exact_retire_pending_retry() {
    for code in [
        "relay.store.unavailable",
        "daemon.remote.trust_reset.relay_restarting",
        "relay.auth.denied",
    ] {
        let (binding, frozen) = frozen_fixture();
        let store = FakeStore::new(binding);
        let mut control = FakeControl::new(CONTROL_FAILURE, Arc::clone(&store.events));
        control.set_failure_code(code);
        let error = expect_workflow_error(
            MachineTrustResetWorkflow::new()
                .run_root_present_with(&store, clone_frozen(&frozen), &mut control)
                .await,
            "control failure must preserve RetirePending",
        );
        assert_eq!(error.code(), code);
        assert_eq!(store.stage(), FakeStage::RetirePending);
        assert_eq!(store.records.load(Ordering::SeqCst), 0);
        assert_eq!(store.confirms.load(Ordering::SeqCst), 0);

        control.set_success();
        MachineTrustResetWorkflow::new()
            .run_root_present_with(&store, clone_frozen(&frozen), &mut control)
            .await
            .expect("retry exact durable retirement");
        let requests = control.requests.lock().expect("lock requests");
        assert_eq!(requests.len(), 2);
        assert_eq!(requests[0], requests[1]);
        assert_eq!(requests[0], frozen.canonical_bytes());
    }
}

#[tokio::test]
async fn missing_retirement_terminal_hits_absolute_deadline_and_preserves_exact_retry() {
    let (binding, frozen) = frozen_fixture();
    let store = FakeStore::new(binding);
    let mut control = FakeControl::new(CONTROL_HANG, Arc::clone(&store.events));
    let workflow =
        MachineTrustResetWorkflow::with_control_deadline(std::time::Duration::from_millis(10));

    let error = expect_workflow_error(
        workflow
            .run_root_present_with(&store, clone_frozen(&frozen), &mut control)
            .await,
        "missing RetirementCommitted must not hold the manager forever",
    );
    assert_eq!(error.code(), "daemon.remote.trust_reset.terminal_timeout");
    assert_eq!(store.stage(), FakeStage::RetirePending);
    assert_eq!(control.calls.load(Ordering::SeqCst), 1);
    assert_eq!(store.records.load(Ordering::SeqCst), 0);
    assert_eq!(store.confirms.load(Ordering::SeqCst), 0);

    control.set_success();
    MachineTrustResetWorkflow::new()
        .run_root_present_with(&store, frozen, &mut control)
        .await
        .expect("retry must replay the exact durable retirement");
    let requests = control.requests.lock().expect("lock requests");
    assert_eq!(requests.len(), 2);
    assert_eq!(requests[0], requests[1]);
}

#[tokio::test]
async fn invalid_terminal_is_rejected_before_store_and_preserves_pending() {
    let (binding, frozen) = frozen_fixture();
    let store = FakeStore::new(binding);
    let mut control = FakeControl::new(CONTROL_INVALID_TERMINAL, Arc::clone(&store.events));
    let error = expect_workflow_error(
        MachineTrustResetWorkflow::new()
            .run_root_present_with(&store, frozen, &mut control)
            .await,
        "mismatched terminal must fail",
    );
    assert_eq!(error.code(), "daemon.remote.trust_reset.terminal_invalid");
    assert_eq!(store.stage(), FakeStage::RetirePending);
    assert_eq!(store.records.load(Ordering::SeqCst), 0);
    assert_eq!(store.confirms.load(Ordering::SeqCst), 0);
}

#[tokio::test]
async fn relay_committed_and_purge_restart_are_zero_network() {
    let (binding, frozen) = frozen_fixture();
    let store = FakeStore::new(binding);
    let retirement = frozen.retirement().clone();
    store
        .prepare_retirement(retirement.clone())
        .await
        .expect("seed pending");
    let terminal = terminal_for(&retirement);
    store
        .record_terminal(terminal.bytes.clone(), terminal.hash)
        .await
        .expect("seed committed");
    let mut control = FakeControl::new(CONTROL_SUCCESS, Arc::clone(&store.events));
    MachineTrustResetWorkflow::new()
        .run_root_present_with(&store, clone_frozen(&frozen), &mut control)
        .await
        .expect("committed restart confirms locally");
    assert_eq!(control.calls.load(Ordering::SeqCst), 0);
    assert_eq!(store.stage(), FakeStage::PurgeRootPresent);

    let confirms = store.confirms.load(Ordering::SeqCst);
    MachineTrustResetWorkflow::new()
        .run_root_present_with(&store, frozen, &mut control)
        .await
        .expect("purge restart is terminal for this workflow");
    assert_eq!(control.calls.load(Ordering::SeqCst), 0);
    assert_eq!(store.confirms.load(Ordering::SeqCst), confirms);
}

#[tokio::test]
async fn local_deleted_is_state_conflict_with_zero_store_mutation_and_zero_network() {
    let (binding, frozen) = frozen_fixture();
    let store = FakeStore::new(binding);
    let mut record = store.record(FakeStage::Active);
    record.lifecycle = MachineRemoteLifecycle::LocalDeleted;
    let state =
        MachineEnrollmentState::LocalDeleted(Box::new(LocalDeletedMachineEnrollmentState {
            record,
            reset_kind: MachineTrustResetKind::RootPresent,
            previous_prepare_input_hash: [0x91; 32],
            purge_proof_hash: [0x92; 32],
            cleanup_witness_hash: [0x93; 32],
        }));
    let mut control = FakeControl::new(CONTROL_SUCCESS, Arc::clone(&store.events));
    let error = expect_workflow_error(
        MachineTrustResetWorkflow::new()
            .drive_root_present(&store, state, &frozen, Some(&mut control))
            .await,
        "LocalDeleted must not enter trust-reset workflow",
    );

    assert_eq!(error.code(), "daemon.remote.trust_reset.state_conflict");
    assert_eq!(control.calls.load(Ordering::SeqCst), 0);
    assert_eq!(store.prepares.load(Ordering::SeqCst), 0);
    assert_eq!(store.records.load(Ordering::SeqCst), 0);
    assert_eq!(store.confirms.load(Ordering::SeqCst), 0);
    assert!(store.events.lock().expect("lock events").is_empty());
}

#[tokio::test]
async fn three_root_present_after_commit_unknowns_converge_by_readback() {
    let (binding, frozen) = frozen_fixture();
    let store = FakeStore::with_root_present_unknowns(binding);
    let mut control = FakeControl::new(CONTROL_SUCCESS, Arc::clone(&store.events));
    MachineTrustResetWorkflow::new()
        .run_root_present_with(&store, frozen, &mut control)
        .await
        .expect("all root-present unknowns converge");
    assert_eq!(store.loads.load(Ordering::SeqCst), 3);
    assert_eq!(store.prepares.load(Ordering::SeqCst), 1);
    assert_eq!(store.records.load(Ordering::SeqCst), 1);
    assert_eq!(store.confirms.load(Ordering::SeqCst), 1);
    assert_eq!(control.calls.load(Ordering::SeqCst), 1);
    assert_eq!(store.stage(), FakeStage::PurgeRootPresent);
}

#[tokio::test]
async fn root_lost_import_is_transport_free_and_unknown_converges_exactly() {
    for unknown in [false, true] {
        let (binding, _) = frozen_fixture();
        let store = if unknown {
            FakeStore::with_root_lost_unknown(binding.clone())
        } else {
            FakeStore::new(binding.clone())
        };
        let receipt = root_lost_receipt(&binding, store.fixture.response.receipt_hash);
        let final_state = MachineTrustResetWorkflow::new()
            .run_root_lost_with(&store, receipt)
            .await
            .expect("import portable root-lost proof");
        assert_eq!(final_state.reset_kind, MachineTrustResetKind::RootLost);
        assert_eq!(store.stage(), FakeStage::PurgeRootLost);
        assert_eq!(store.root_lost_records.load(Ordering::SeqCst), 1);
        assert_eq!(store.loads.load(Ordering::SeqCst), usize::from(unknown));
        assert_eq!(
            *store.events.lock().expect("lock events"),
            if unknown {
                vec!["root_lost", "load"]
            } else {
                vec!["root_lost"]
            }
        );
    }
}
