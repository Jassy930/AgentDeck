use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
use std::sync::{Arc, Mutex as StdMutex};

use agentdeck_crypto::rand_core::{TryCryptoRng, TryRng};
use agentdeck_crypto::{
    HpkePublicKey, SigningKey, open_pair_response, seal_pair_request, seal_pair_response_received,
    sha256, sign_tbs,
};
use agentdeck_protocol::e2ee::{
    AuthorizationCapabilityV1, AuthorizationPermissionV1, AuthorizationRequestV1,
    MachineDataSignerBindingV1, PairRequestPlaintextV1, PairResponsePlaintextV1,
    PairResponseReceivedV1,
};
use agentdeck_protocol::relay_v2::frame::PairRouteCloseOutcome;
use agentdeck_protocol::relay_v2::{
    CertRole, DeviceRouteId, Ed25519Signature, KeyDirectoryRevision, LinkGeneration,
    MachineRouteId, RelayGrant, RootKeyId, TrustEpoch,
};
use agentdeck_protocol::runtime::{
    IdempotencyKey, LocalOnlyAdministration, PairingDecision, PairingReceipt, PairingState,
    PendingPairing,
};

use crate::runtime::store::pairing_grant::GlobalKeyStateV1;
use crate::runtime::store::{MachineIdentityBinding, RuntimeIdKind, RuntimeStoreConfig};
use crate::security::{MemoryKeyStore, load_or_create_storage_kek};

use super::*;

const MACHINE_ROUTE: MachineRouteId = MachineRouteId::from_bytes([0x21; 16]);
const TEST_ROOT_SEED: [u8; 32] = [0x31; 32];
const TEST_DATA_SEED: [u8; 32] = [0x32; 32];

#[derive(Clone)]
struct FakeStoredInvite {
    pairing_id: RuntimeId,
    pair_route: PairRouteId,
    lifecycle: PairingInviteLifecycle,
    canonical_invite: Vec<u8>,
    invite_hpke_private_key: Vec<u8>,
    canonical_open_frame: Vec<u8>,
    request_hash: Option<[u8; 32]>,
    device_sign_fingerprint: Option<[u8; 32]>,
    request_received_at_ms: Option<u64>,
    canonical_request: Option<Vec<u8>>,
    canonical_plaintext: Option<Vec<u8>>,
    canonical_pending_frame: Option<Vec<u8>>,
}

impl FakeStoredInvite {
    fn durable(&self) -> DurableInvite {
        let invite = PairInviteV1::from_canonical_bytes(&self.canonical_invite).unwrap();
        let pending_preparation =
            (self.lifecycle == PairingInviteLifecycle::Preparing).then(|| {
                let plaintext = PairRequestPlaintextV1::from_canonical_bytes(
                    self.canonical_plaintext.as_deref().unwrap(),
                )
                .unwrap();
                PendingPreparation {
                    request_hash: self.request_hash.unwrap(),
                    info: pair_request_info(&invite).unwrap(),
                    context: pairing_context(invite.pair_route, OuterFrameKind::PairPending),
                    recipient: HpkePublicKey::from_bytes(&plaintext.device_hpke_pubkey.0).unwrap(),
                }
            });
        DurableInvite {
            pairing_id: self.pairing_id,
            pair_route: self.pair_route,
            lifecycle: self.lifecycle,
            canonical_invite: SecretBytes::new(self.canonical_invite.clone()),
            canonical_open_frame: self.canonical_open_frame.clone(),
            invite_hpke_private_key: (self.lifecycle == PairingInviteLifecycle::Unused)
                .then(|| HpkePrivateKey::from_bytes(&self.invite_hpke_private_key).unwrap()),
            request_hash: self.request_hash,
            device_sign_fingerprint: self.device_sign_fingerprint,
            request_received_at_ms: self.request_received_at_ms,
            canonical_pair_request: self
                .canonical_request
                .as_ref()
                .map(|request| SecretBytes::new(request.clone())),
            pending_preparation,
            canonical_pending_frame: self.canonical_pending_frame.clone(),
        }
    }
}

#[derive(Default)]
struct FakeStoreState {
    by_id: BTreeMap<RuntimeId, FakeStoredInvite>,
    idempotency: HashMap<(IdempotencyOwner, String), RuntimeId>,
    due: HashSet<RuntimeId>,
    terminals: BTreeMap<RuntimeId, FakeTerminal>,
    grants: BTreeMap<RuntimeId, DurableGrant>,
    committed: BTreeMap<RuntimeId, DurableResponse>,
    authorizations: BTreeMap<RevocationKey, RelayGrant>,
    revocations: BTreeMap<RevocationKey, DurableRevocation>,
    revoked: BTreeMap<RevocationKey, DeviceRevocation>,
    delivered_receipt_hashes: BTreeMap<RuntimeId, [u8; 32]>,
    last_close_ack: Option<Vec<u8>>,
}

#[derive(Clone)]
struct FakeTerminal {
    decision: PairingDecision,
    receipt: PairingReceipt,
    close: Option<DurableClose>,
}

#[derive(Default)]
struct FakeStore {
    state: StdMutex<FakeStoreState>,
    order: Arc<StdMutex<Vec<&'static str>>>,
    receipt_purge_calls: AtomicUsize,
    recovery_calls: AtomicUsize,
    fail_receipt_purge: AtomicBool,
    fail_confirm: AtomicBool,
    commit_unknown_readback: AtomicBool,
    fail_grant_ack_before_commit: AtomicBool,
    grant_ack_unknown_readback: AtomicBool,
    fail_delivery_before_commit: AtomicBool,
    delivery_commit_unknown_readback: AtomicBool,
    fail_close_ack_before_commit: AtomicBool,
    close_ack_unknown_readback: AtomicBool,
    expose_stale_committed_recovery: AtomicBool,
    fail_revocation_begin: AtomicBool,
    fail_orphan_grant_ack: AtomicBool,
    fail_revocation_ack: AtomicBool,
}

impl FakeStore {
    fn with_order(order: Arc<StdMutex<Vec<&'static str>>>) -> Self {
        Self {
            state: StdMutex::new(FakeStoreState::default()),
            order,
            receipt_purge_calls: AtomicUsize::new(0),
            recovery_calls: AtomicUsize::new(0),
            fail_receipt_purge: AtomicBool::new(false),
            fail_confirm: AtomicBool::new(false),
            commit_unknown_readback: AtomicBool::new(false),
            fail_grant_ack_before_commit: AtomicBool::new(false),
            grant_ack_unknown_readback: AtomicBool::new(false),
            fail_delivery_before_commit: AtomicBool::new(false),
            delivery_commit_unknown_readback: AtomicBool::new(false),
            fail_close_ack_before_commit: AtomicBool::new(false),
            close_ack_unknown_readback: AtomicBool::new(false),
            expose_stale_committed_recovery: AtomicBool::new(false),
            fail_revocation_begin: AtomicBool::new(false),
            fail_orphan_grant_ack: AtomicBool::new(false),
            fail_revocation_ack: AtomicBool::new(false),
        }
    }

    fn fail_confirm(&self, value: bool) {
        self.fail_confirm.store(value, Ordering::SeqCst);
    }

    fn receipt_purge_calls(&self) -> usize {
        self.receipt_purge_calls.load(Ordering::SeqCst)
    }

    fn recovery_calls(&self) -> usize {
        self.recovery_calls.load(Ordering::SeqCst)
    }

    fn fail_receipt_purge(&self, value: bool) {
        self.fail_receipt_purge.store(value, Ordering::SeqCst);
    }

    fn commit_unknown_readback(&self, value: bool) {
        self.commit_unknown_readback.store(value, Ordering::SeqCst);
    }

    fn fail_grant_ack_before_commit(&self, value: bool) {
        self.fail_grant_ack_before_commit
            .store(value, Ordering::SeqCst);
    }

    fn grant_ack_unknown_readback(&self, value: bool) {
        self.grant_ack_unknown_readback
            .store(value, Ordering::SeqCst);
    }

    fn fail_delivery_before_commit(&self, value: bool) {
        self.fail_delivery_before_commit
            .store(value, Ordering::SeqCst);
    }

    fn delivery_commit_unknown_readback(&self, value: bool) {
        self.delivery_commit_unknown_readback
            .store(value, Ordering::SeqCst);
    }

    fn fail_close_ack_before_commit(&self, value: bool) {
        self.fail_close_ack_before_commit
            .store(value, Ordering::SeqCst);
    }

    fn close_ack_unknown_readback(&self, value: bool) {
        self.close_ack_unknown_readback
            .store(value, Ordering::SeqCst);
    }

    fn expose_stale_committed_recovery(&self, value: bool) {
        self.expose_stale_committed_recovery
            .store(value, Ordering::SeqCst);
    }

    fn fail_revocation_begin(&self, value: bool) {
        self.fail_revocation_begin.store(value, Ordering::SeqCst);
    }

    fn fail_orphan_grant_ack(&self, value: bool) {
        self.fail_orphan_grant_ack.store(value, Ordering::SeqCst);
    }

    fn fail_revocation_ack(&self, value: bool) {
        self.fail_revocation_ack.store(value, Ordering::SeqCst);
    }

    fn lifecycle(&self, pairing_id: RuntimeId) -> PairingInviteLifecycle {
        self.state
            .lock()
            .unwrap()
            .by_id
            .get(&pairing_id)
            .unwrap()
            .lifecycle
    }

    fn count(&self) -> usize {
        self.state.lock().unwrap().by_id.len()
    }

    fn single_id(&self) -> RuntimeId {
        *self.state.lock().unwrap().by_id.keys().next().unwrap()
    }

    fn mark_due(&self, pairing_id: RuntimeId) {
        self.state.lock().unwrap().due.insert(pairing_id);
    }

    fn has_secret_row(&self, pairing_id: RuntimeId) -> bool {
        self.state
            .lock()
            .unwrap()
            .by_id
            .get(&pairing_id)
            .is_some_and(|stored| !stored.invite_hpke_private_key.is_empty())
    }

    fn last_close_ack(&self) -> Option<Vec<u8>> {
        self.state.lock().unwrap().last_close_ack.clone()
    }

    fn grant_install(&self, pairing_id: RuntimeId) -> InstallGrant {
        self.state
            .lock()
            .unwrap()
            .grants
            .get(&pairing_id)
            .expect("grant must be durable")
            .install
            .clone()
    }

    fn committed_response(&self, pairing_id: RuntimeId) -> PairData {
        self.state
            .lock()
            .unwrap()
            .committed
            .get(&pairing_id)
            .expect("response must be durable")
            .frame()
            .unwrap()
    }

    fn pending_list(&self) -> Vec<PendingPairing> {
        self.state
            .lock()
            .unwrap()
            .by_id
            .values()
            .filter(|stored| stored.lifecycle == PairingInviteLifecycle::AwaitingLocalConfirmation)
            .map(|stored| stored.durable().pending().unwrap())
            .collect()
    }

    fn terminalize_locked(
        state: &mut FakeStoreState,
        pairing_id: RuntimeId,
        requested: PairingTerminalAction,
    ) -> Result<TerminalOutcome, PairingAdministrationError> {
        let requested = match requested {
            PairingTerminalAction::Cancel => PairingDecision::Cancel,
            PairingTerminalAction::Expire => PairingDecision::Expire,
        };
        if let Some(terminal) = state.terminals.get(&pairing_id) {
            let pairing_id_wire = PairingId::new(pairing_id.to_canonical_string());
            let state_value = if state.by_id.contains_key(&pairing_id) {
                match terminal.decision {
                    PairingDecision::Cancel => PairingState::Canceled,
                    PairingDecision::Expire => PairingState::Expired,
                    PairingDecision::Confirm => PairingState::GrantPreparing,
                }
            } else {
                PairingState::ClosedTombstone
            };
            let reply = if requested == terminal.decision {
                PairingReceipt::Replayed {
                    pairing_id: pairing_id_wire,
                    decision: terminal.decision,
                    state: state_value,
                }
            } else {
                PairingReceipt::AlreadyHandled {
                    pairing_id: pairing_id_wire,
                    winner: terminal.decision,
                    state: state_value,
                }
            };
            return Ok(TerminalOutcome {
                pairing_id,
                reply,
                close: terminal.close.clone(),
            });
        }
        let stored = state
            .by_id
            .get_mut(&pairing_id)
            .ok_or_else(|| pairing_error("daemon.runtime.invalid_state"))?;
        let winner = if state.due.remove(&pairing_id) {
            PairingDecision::Expire
        } else {
            requested
        };
        stored.lifecycle = match winner {
            PairingDecision::Cancel => PairingInviteLifecycle::Canceled,
            PairingDecision::Expire => PairingInviteLifecycle::Expired,
            PairingDecision::Confirm => return Err(pairing_error("daemon.runtime.invalid_state")),
        };
        let pairing_id_wire = PairingId::new(pairing_id.to_canonical_string());
        let receipt = match winner {
            PairingDecision::Cancel => PairingReceipt::Canceled {
                pairing_id: pairing_id_wire.clone(),
            },
            PairingDecision::Expire => PairingReceipt::Expired {
                pairing_id: pairing_id_wire.clone(),
            },
            PairingDecision::Confirm => unreachable!(),
        };
        let frame = ClosePairRoute {
            machine_route: MACHINE_ROUTE,
            pair_route: stored.pair_route,
        };
        let close = DurableClose {
            pairing_id,
            pair_route: stored.pair_route,
            frame,
        };
        state.terminals.insert(
            pairing_id,
            FakeTerminal {
                decision: winner,
                receipt: receipt.clone(),
                close: Some(close.clone()),
            },
        );
        Ok(TerminalOutcome {
            pairing_id,
            reply: if winner == requested {
                receipt
            } else {
                PairingReceipt::AlreadyHandled {
                    pairing_id: pairing_id_wire,
                    winner,
                    state: PairingState::Expired,
                }
            },
            close: Some(close),
        })
    }

    fn frozen_grant(
        pairing_id: RuntimeId,
        request_hash: [u8; 32],
        stored: &FakeStoredInvite,
    ) -> (PairingReceipt, DurableGrant) {
        let pairing_id_wire = PairingId::new(pairing_id.to_canonical_string());
        let receipt = PairingReceipt::Confirmed {
            pairing_id: pairing_id_wire,
        };
        let invite = PairInviteV1::from_canonical_bytes(&stored.canonical_invite).unwrap();
        let plaintext = PairRequestPlaintextV1::from_canonical_bytes(
            stored.canonical_plaintext.as_deref().unwrap(),
        )
        .unwrap();
        let root = SigningKey::from_seed(&TEST_ROOT_SEED);
        let mut grant = RelayGrant {
            machine_route: MACHINE_ROUTE,
            device_route: DeviceRouteId::from_bytes(*pairing_id.as_bytes()),
            device_sign_pubkey: plaintext.device_sign_pubkey,
            grant_serial: GrantSerial::new(1),
            root_key_id: RootKeyId::from_bytes([0x33; 16]),
            trust_epoch: TrustEpoch::new(1),
            signature: Ed25519Signature([0; 64]),
        };
        grant.signature = sign_tbs(
            &root,
            &grant.to_be_signed_v1(invite.relay_server_id, invite.machine_root_fingerprint),
        )
        .into();
        let durable = DurableGrant::for_test(
            pairing_id,
            request_hash,
            receipt.clone(),
            InstallGrant { grant },
        );
        (receipt, durable)
    }
}

#[async_trait]
impl PairingStore for FakeStore {
    async fn prepare(
        &self,
        owner: IdempotencyOwner,
        idempotency_key: String,
        canonical_invite: SecretBytes,
        invite_hpke_private_key: SecretBytes,
    ) -> Result<DurableInvite, PairingAdministrationError> {
        let invite = PairInviteV1::from_canonical_bytes(canonical_invite.expose_secret())
            .map_err(|_| pairing_error(PAIRING_INVITE_INVALID))?;
        let private = HpkePrivateKey::from_bytes(invite_hpke_private_key.expose_secret())
            .map_err(|_| pairing_error(PAIRING_INVITE_INVALID))?;
        let public: [u8; 32] = private
            .public_key()
            .to_bytes()
            .try_into()
            .map_err(|_| pairing_error(PAIRING_INVITE_INVALID))?;
        if invite.invite_secret == [0; 32]
            || invite.pair_route.as_bytes() == &[0; 16]
            || invite_hpke_private_key.expose_secret().len() != 32
            || invite_hpke_private_key
                .expose_secret()
                .iter()
                .all(|byte| *byte == 0)
            || public != invite.invite_hpke_pubkey.0
        {
            return Err(pairing_error(PAIRING_INVITE_INVALID));
        }
        let mut state = self.state.lock().unwrap();
        let key = (owner, idempotency_key);
        if let Some(pairing_id) = state.idempotency.get(&key).copied() {
            let Some(stored) = state.by_id.get(&pairing_id) else {
                let terminal = state
                    .terminals
                    .get(&pairing_id)
                    .ok_or_else(|| pairing_error(PAIRING_TERMINAL_INVALID))?;
                return Err(pairing_error(match terminal.decision {
                    PairingDecision::Cancel => PAIRING_CANCELED,
                    PairingDecision::Expire => PAIRING_EXPIRED,
                    PairingDecision::Confirm => PAIRING_ALREADY_COMPLETED,
                }));
            };
            match stored.lifecycle {
                PairingInviteLifecycle::Canceled => {
                    return Err(pairing_error(PAIRING_CANCELED));
                }
                PairingInviteLifecycle::Expired => {
                    return Err(pairing_error(PAIRING_EXPIRED));
                }
                _ => {}
            }
            let existing = PairInviteV1::from_canonical_bytes(&stored.canonical_invite).unwrap();
            if existing.machine_display_name != invite.machine_display_name {
                return Err(pairing_error("daemon.runtime.invalid_state"));
            }
            self.order.lock().unwrap().push("persist-replay");
            return Ok(stored.durable());
        }
        if state.by_id.len() >= 8 {
            return Err(pairing_error("daemon.runtime.store_full"));
        }
        let ordinal = u8::try_from(state.by_id.len() + 1).unwrap();
        let pairing_id = RuntimeId::from_bytes(RuntimeIdKind::Pairing, [ordinal; 16]).unwrap();
        let open = OpenPairRoute {
            machine_route: MACHINE_ROUTE,
            pair_route: invite.pair_route,
            absolute_expiry_ms: invite.expires_at_ms,
        };
        let stored = FakeStoredInvite {
            pairing_id,
            pair_route: invite.pair_route,
            lifecycle: PairingInviteLifecycle::RouteOpening,
            canonical_invite: canonical_invite.expose_secret().to_vec(),
            invite_hpke_private_key: invite_hpke_private_key.expose_secret().to_vec(),
            canonical_open_frame: encode(&OpaqueRouteFrame {
                version: RELAY_PROTOCOL_VERSION,
                body: RelayFrameBody::OpenPairRoute(open),
            }),
            request_hash: None,
            device_sign_fingerprint: None,
            request_received_at_ms: None,
            canonical_request: None,
            canonical_plaintext: None,
            canonical_pending_frame: None,
        };
        state.idempotency.insert(key, pairing_id);
        state.by_id.insert(pairing_id, stored.clone());
        self.order.lock().unwrap().push("persist");
        Ok(stored.durable())
    }

    async fn acknowledge_open(
        &self,
        pairing_id: RuntimeId,
        canonical_terminal: Vec<u8>,
    ) -> Result<DurableInvite, PairingAdministrationError> {
        let mut state = self.state.lock().unwrap();
        let stored = state
            .by_id
            .get_mut(&pairing_id)
            .ok_or_else(|| pairing_error(PAIRING_INVITE_INVALID))?;
        let invite = PairInviteV1::from_canonical_bytes(&stored.canonical_invite).unwrap();
        let expected = encode(&OpaqueRouteFrame {
            version: RELAY_PROTOCOL_VERSION,
            body: RelayFrameBody::PairRouteOpened(PairRouteOpened {
                machine_route: MACHINE_ROUTE,
                pair_route: stored.pair_route,
                absolute_expiry_ms: invite.expires_at_ms,
            }),
        });
        if canonical_terminal != expected {
            return Err(pairing_error(PAIRING_INVITE_INVALID));
        }
        if stored.lifecycle == PairingInviteLifecycle::RouteOpening {
            stored.lifecycle = PairingInviteLifecycle::Unused;
        }
        self.order.lock().unwrap().push("ack-commit");
        Ok(stored.durable())
    }

    async fn recover(&self) -> Result<Vec<DurableInvite>, PairingAdministrationError> {
        self.recovery_calls.fetch_add(1, Ordering::SeqCst);
        Ok(self
            .state
            .lock()
            .unwrap()
            .by_id
            .values()
            .map(FakeStoredInvite::durable)
            .collect())
    }

    async fn load(
        &self,
        pairing_id: RuntimeId,
    ) -> Result<Option<DurableInvite>, PairingAdministrationError> {
        Ok(self
            .state
            .lock()
            .unwrap()
            .by_id
            .get(&pairing_id)
            .map(FakeStoredInvite::durable))
    }

    async fn accept_request(
        &self,
        pairing_id: RuntimeId,
        verified: VerifiedPairRequestV1,
    ) -> Result<DurableInvite, PairingAdministrationError> {
        let plaintext =
            PairRequestPlaintextV1::from_canonical_bytes(verified.canonical_plaintext())
                .map_err(|_| pairing_error(PAIRING_REQUEST_INVALID))?;
        let mut state = self.state.lock().unwrap();
        let stored = state
            .by_id
            .get_mut(&pairing_id)
            .ok_or_else(|| pairing_error(PAIRING_REQUEST_INVALID))?;
        if stored.lifecycle != PairingInviteLifecycle::Unused {
            return Err(pairing_error(PAIRING_REQUEST_INVALID));
        }
        stored.lifecycle = PairingInviteLifecycle::Preparing;
        stored.request_hash = Some(verified.request_hash());
        stored.device_sign_fingerprint = Some(plaintext.device_sign_fingerprint());
        stored.request_received_at_ms = Some(unix_now_ms().unwrap());
        stored.canonical_request = Some(verified.canonical_request().to_vec());
        stored.canonical_plaintext = Some(verified.canonical_plaintext().to_vec());
        self.order.lock().unwrap().push("accept-commit");
        Ok(stored.durable())
    }

    async fn replay_request(
        &self,
        pairing_id: RuntimeId,
        canonical_request: SecretBytes,
    ) -> Result<DurableInvite, PairingAdministrationError> {
        let state = self.state.lock().unwrap();
        let stored = state
            .by_id
            .get(&pairing_id)
            .ok_or_else(|| pairing_error(PAIRING_REQUEST_INVALID))?;
        if !matches!(
            stored.lifecycle,
            PairingInviteLifecycle::Preparing | PairingInviteLifecycle::AwaitingLocalConfirmation
        ) || stored.canonical_request.as_deref() != Some(canonical_request.expose_secret())
        {
            return Err(pairing_error("daemon.runtime.invalid_state"));
        }
        self.order.lock().unwrap().push("request-replay");
        Ok(stored.durable())
    }

    async fn commit_pending(
        &self,
        pairing_id: RuntimeId,
        request_hash: [u8; 32],
        envelope: PairingControlEnvelopeV1,
    ) -> Result<DurableInvite, PairingAdministrationError> {
        let mut state = self.state.lock().unwrap();
        let stored = state
            .by_id
            .get_mut(&pairing_id)
            .ok_or_else(|| pairing_error(PAIRING_REQUEST_INVALID))?;
        let frame = encode(&OpaqueRouteFrame {
            version: RELAY_PROTOCOL_VERSION,
            body: RelayFrameBody::PairData(PairData {
                pair_route: stored.pair_route,
                sealed_blob: agentdeck_protocol::relay_v2::frame::SealedBlob(
                    envelope
                        .canonical_bytes()
                        .map_err(|_| pairing_error(PAIRING_REQUEST_INVALID))?,
                ),
            }),
        });
        if stored.lifecycle == PairingInviteLifecycle::AwaitingLocalConfirmation {
            if stored.request_hash != Some(request_hash)
                || stored.canonical_pending_frame.as_deref() != Some(&frame)
            {
                return Err(pairing_error(PAIRING_REQUEST_INVALID));
            }
            return Ok(stored.durable());
        }
        if stored.lifecycle != PairingInviteLifecycle::Preparing
            || stored.request_hash != Some(request_hash)
        {
            return Err(pairing_error(PAIRING_REQUEST_INVALID));
        }
        stored.lifecycle = PairingInviteLifecycle::AwaitingLocalConfirmation;
        stored.canonical_pending_frame = Some(frame);
        self.order.lock().unwrap().push("pending-commit");
        Ok(stored.durable())
    }

    async fn load_grant_preparation(
        &self,
        pairing_id: RuntimeId,
    ) -> Result<GrantPreparationInput, PairingAdministrationError> {
        let state = self.state.lock().unwrap();
        let stored = state
            .by_id
            .get(&pairing_id)
            .ok_or_else(|| pairing_error(PAIRING_REQUEST_INVALID))?;
        if stored.lifecycle != PairingInviteLifecycle::AwaitingLocalConfirmation {
            return Err(pairing_error(PAIRING_REQUEST_INVALID));
        }
        Ok(GrantPreparationInput::for_test(
            pairing_id,
            stored
                .request_hash
                .ok_or_else(|| pairing_error(PAIRING_REQUEST_INVALID))?,
        ))
    }

    async fn load_grant_allocation(
        &self,
        _pairing_id: RuntimeId,
        _device_sign_fingerprint: [u8; 32],
    ) -> Result<GrantAllocationInput, PairingAdministrationError> {
        Ok(GrantAllocationInput::Test {
            grant_serial: GrantSerial::new(1),
            key_directory_revision: KeyDirectoryRevision::new(1),
        })
    }

    async fn confirm_grant(
        &self,
        input: FrozenGrantInput,
    ) -> Result<GrantCommitOutcome, PairingAdministrationError> {
        if self.fail_confirm.load(Ordering::SeqCst) {
            return Err(pairing_error("daemon.runtime.store_unavailable"));
        }
        let mut state = self.state.lock().unwrap();
        if let Some(grant) = state.grants.get(&input.pairing_id).cloned() {
            return Ok(GrantCommitOutcome::Committed {
                reply: replayed_confirm_receipt(&grant.receipt)?,
                grant: Box::new(grant),
            });
        }
        if let Some(terminal) = state.terminals.get(&input.pairing_id) {
            let state_value = if state.by_id.contains_key(&input.pairing_id) {
                match terminal.decision {
                    PairingDecision::Cancel => PairingState::Canceled,
                    PairingDecision::Expire => PairingState::Expired,
                    PairingDecision::Confirm => PairingState::GrantPreparing,
                }
            } else {
                PairingState::ClosedTombstone
            };
            return Ok(GrantCommitOutcome::Terminal {
                reply: already_handled_confirm_receipt(&terminal.receipt, state_value)?,
            });
        }
        if state.due.contains(&input.pairing_id) {
            Self::terminalize_locked(&mut state, input.pairing_id, PairingTerminalAction::Expire)?;
            let receipt = state
                .terminals
                .get(&input.pairing_id)
                .expect("expiry inserts terminal")
                .receipt
                .clone();
            return Ok(GrantCommitOutcome::Terminal {
                reply: already_handled_confirm_receipt(&receipt, PairingState::Expired)?,
            });
        }
        let stored = state
            .by_id
            .get_mut(&input.pairing_id)
            .ok_or_else(|| pairing_error(PAIRING_REQUEST_INVALID))?;
        if stored.lifecycle != PairingInviteLifecycle::AwaitingLocalConfirmation
            || stored.request_hash != Some(input.request_hash)
        {
            return Err(pairing_error(PAIRING_REQUEST_INVALID));
        }
        stored.lifecycle = PairingInviteLifecycle::GrantPreparing;
        let (receipt, grant) = Self::frozen_grant(input.pairing_id, input.request_hash, stored);
        state.terminals.insert(
            input.pairing_id,
            FakeTerminal {
                decision: PairingDecision::Confirm,
                receipt: receipt.clone(),
                close: None,
            },
        );
        state.authorizations.insert(
            RevocationKey::new(
                grant.install.grant.device_route,
                grant.install.grant.grant_serial,
            ),
            grant.install.grant.clone(),
        );
        state.grants.insert(input.pairing_id, grant.clone());
        self.order
            .lock()
            .unwrap()
            .push(if self.commit_unknown_readback.load(Ordering::SeqCst) {
                "grant-commit-unknown-readback"
            } else {
                "grant-commit"
            });
        Ok(GrantCommitOutcome::Committed {
            reply: receipt,
            grant: Box::new(grant),
        })
    }

    async fn recover_grants(&self) -> Result<Vec<DurableGrant>, PairingAdministrationError> {
        let state = self.state.lock().unwrap();
        Ok(state
            .grants
            .iter()
            .filter(|(pairing_id, _)| {
                state.by_id.get(pairing_id).is_some_and(|stored| {
                    stored.lifecycle == PairingInviteLifecycle::GrantPreparing
                })
            })
            .map(|(_, grant)| grant.clone())
            .collect())
    }

    async fn acknowledge_grant_committed(
        &self,
        pairing_id: RuntimeId,
        committed: GrantCommitted,
        canonical_terminal: Vec<u8>,
    ) -> Result<DurableResponse, PairingAdministrationError> {
        if self.fail_grant_ack_before_commit.load(Ordering::SeqCst) {
            self.order.lock().unwrap().push("grant-ack-before-fault");
            return Err(pairing_error("daemon.runtime.store_unavailable"));
        }
        let expected = encode(&OpaqueRouteFrame {
            version: RELAY_PROTOCOL_VERSION,
            body: RelayFrameBody::GrantCommitted(committed.clone()),
        });
        if canonical_terminal != expected {
            return Err(pairing_error(PAIRING_GRANT_RECOVERY_UNAVAILABLE));
        }
        let mut state = self.state.lock().unwrap();
        if let Some(response) = state.committed.get(&pairing_id).cloned() {
            if response.device_route != committed.device_route
                || response.grant_serial != committed.grant_serial
                || response.grant_hash != committed.grant_hash
            {
                return Err(pairing_error(PAIRING_GRANT_RECOVERY_UNAVAILABLE));
            }
            self.order.lock().unwrap().push("grant-ack-replay");
            return Ok(response);
        }
        let grant = state
            .grants
            .get(&pairing_id)
            .cloned()
            .ok_or_else(|| pairing_error(PAIRING_GRANT_RECOVERY_UNAVAILABLE))?;
        let stored = state
            .by_id
            .get(&pairing_id)
            .ok_or_else(|| pairing_error(PAIRING_GRANT_RECOVERY_UNAVAILABLE))?;
        if stored.lifecycle != PairingInviteLifecycle::GrantPreparing
            || stored.request_hash != Some(grant.request_hash)
            || grant.install.grant.device_route != committed.device_route
            || grant.install.grant.grant_serial != committed.grant_serial
            || grant.install.grant.canonical_sha256() != committed.grant_hash
        {
            return Err(pairing_error(PAIRING_GRANT_RECOVERY_UNAVAILABLE));
        }
        let invite = PairInviteV1::from_canonical_bytes(&stored.canonical_invite).unwrap();
        let response = DurableResponse::for_test(
            pairing_id,
            grant.request_hash,
            &invite,
            &stored.invite_hpke_private_key,
            &grant.install.grant,
        );
        state.by_id.get_mut(&pairing_id).unwrap().lifecycle =
            PairingInviteLifecycle::GrantCommitted;
        state.grants.remove(&pairing_id);
        state.committed.insert(pairing_id, response.clone());
        self.order.lock().unwrap().push(
            if self.grant_ack_unknown_readback.load(Ordering::SeqCst) {
                "grant-ack-unknown-readback"
            } else {
                "grant-ack-commit"
            },
        );
        Ok(response)
    }

    async fn recover_committed(&self) -> Result<Vec<DurableResponse>, PairingAdministrationError> {
        let state = self.state.lock().unwrap();
        Ok(state
            .committed
            .iter()
            .filter(|(pairing_id, _)| {
                self.expose_stale_committed_recovery.load(Ordering::SeqCst)
                    || state.by_id.get(pairing_id).is_some_and(|stored| {
                        stored.lifecycle == PairingInviteLifecycle::GrantCommitted
                    })
            })
            .map(|(_, response)| response.clone())
            .collect())
    }

    async fn acknowledge_delivery(
        &self,
        input: DeliveryProofInput,
    ) -> Result<DeliveryOutcome, PairingAdministrationError> {
        if self.fail_delivery_before_commit.load(Ordering::SeqCst) {
            self.order.lock().unwrap().push("delivery-before-fault");
            return Err(pairing_error("daemon.runtime.store_unavailable"));
        }
        let mut state = self.state.lock().unwrap();
        if let Some(existing_hash) = state.delivered_receipt_hashes.get(&input.pairing_id) {
            if *existing_hash != input.canonical_receipt_hash {
                return Err(pairing_error(PAIRING_REQUEST_INVALID));
            }
            let close = state
                .terminals
                .get(&input.pairing_id)
                .and_then(|terminal| terminal.close.clone())
                .ok_or_else(|| pairing_error(PAIRING_TERMINAL_INVALID))?;
            self.order.lock().unwrap().push("delivery-replay");
            return Ok(DeliveryOutcome { close });
        }
        let response = state
            .committed
            .get(&input.pairing_id)
            .ok_or_else(|| pairing_error(PAIRING_REQUEST_INVALID))?;
        let stored = state
            .by_id
            .get(&input.pairing_id)
            .ok_or_else(|| pairing_error(PAIRING_REQUEST_INVALID))?;
        if stored.lifecycle != PairingInviteLifecycle::GrantCommitted
            || stored.pair_route != input.pair_route
            || response.request_hash != input.request_hash
            || response.grant_hash != input.grant_hash
            || response.response_hash != input.response_hash
            || input.canonical_receipt_hash == [0; 32]
            || input.production.is_some()
        {
            return Err(pairing_error(PAIRING_REQUEST_INVALID));
        }
        let close = DurableClose {
            pairing_id: input.pairing_id,
            pair_route: input.pair_route,
            frame: ClosePairRoute {
                machine_route: MACHINE_ROUTE,
                pair_route: input.pair_route,
            },
        };
        state.by_id.get_mut(&input.pairing_id).unwrap().lifecycle =
            PairingInviteLifecycle::Delivered;
        state
            .terminals
            .get_mut(&input.pairing_id)
            .ok_or_else(|| pairing_error(PAIRING_TERMINAL_INVALID))?
            .close = Some(close.clone());
        state
            .delivered_receipt_hashes
            .insert(input.pairing_id, input.canonical_receipt_hash);
        self.order.lock().unwrap().push(
            if self.delivery_commit_unknown_readback.load(Ordering::SeqCst) {
                "delivery-unknown-readback"
            } else {
                "delivery-commit"
            },
        );
        Ok(DeliveryOutcome { close })
    }

    async fn load_revocation_target(
        &self,
        device: DeviceHandle,
        grant_serial: RuntimeGrantSerial,
    ) -> Result<Option<RevocationTargetOutcome>, PairingAdministrationError> {
        let state = self.state.lock().unwrap();
        let key = state
            .authorizations
            .keys()
            .copied()
            .find(|key| {
                key.grant_serial == grant_serial.0
                    && device_matches_route(&device, DeviceRouteId::from_bytes(key.device_route))
            })
            .ok_or_else(|| pairing_error(REVOCATION_TARGET_INVALID));
        let Ok(key) = key else {
            return Ok(None);
        };
        if let Some(revocation) = state.revoked.get(&key) {
            return Ok(Some(RevocationTargetOutcome::Revoked(revocation.clone())));
        }
        if let Some(recovery) = state.revocations.get(&key) {
            return Ok(Some(RevocationTargetOutcome::Revoking(recovery.clone())));
        }
        Ok(state.authorizations.get(&key).cloned().map(|grant| {
            RevocationTargetOutcome::Ready(RevocationTargetInput {
                pairing_id: None,
                device,
                grant,
            })
        }))
    }

    async fn due_revocation_targets(
        &self,
    ) -> Result<Vec<RevocationTargetInput>, PairingAdministrationError> {
        let state = self.state.lock().unwrap();
        state
            .due
            .iter()
            .filter_map(|pairing_id| {
                state.by_id.get(pairing_id).and_then(|stored| {
                    matches!(
                        stored.lifecycle,
                        PairingInviteLifecycle::GrantPreparing
                            | PairingInviteLifecycle::GrantCommitted
                    )
                    .then_some((*pairing_id, stored))
                })
            })
            .map(|(pairing_id, _)| {
                let grant = state
                    .authorizations
                    .values()
                    .find(|grant| grant.device_route.as_bytes() == pairing_id.as_bytes())
                    .cloned()
                    .ok_or_else(|| pairing_error(REVOCATION_RECOVERY_UNAVAILABLE))?;
                Ok(RevocationTargetInput {
                    pairing_id: Some(pairing_id),
                    device: device_handle_for_test(grant.device_route),
                    grant,
                })
            })
            .collect()
    }

    async fn drain_revocation_targets(
        &self,
    ) -> Result<Vec<RevocationTargetInput>, PairingAdministrationError> {
        let state = self.state.lock().unwrap();
        state
            .authorizations
            .iter()
            .filter(|(key, _)| {
                !state.revocations.contains_key(key) && !state.revoked.contains_key(key)
            })
            .map(|(_, grant)| {
                Ok(RevocationTargetInput {
                    pairing_id: None,
                    device: device_handle_for_test(grant.device_route),
                    grant: grant.clone(),
                })
            })
            .collect()
    }

    async fn begin_revocation(
        &self,
        input: FrozenRevocationInput,
    ) -> Result<BeginRevocationOutcome, PairingAdministrationError> {
        if self.fail_revocation_begin.load(Ordering::SeqCst) {
            self.order.lock().unwrap().push("revocation-before-fault");
            return Err(pairing_error("daemon.runtime.store_unavailable"));
        }
        let key = RevocationKey::new(input.revocation.device_route, input.revocation.grant_serial);
        let mut state = self.state.lock().unwrap();
        let grant = state
            .authorizations
            .get(&key)
            .cloned()
            .ok_or_else(|| pairing_error(REVOCATION_TARGET_INVALID))?;
        if input.revocation.machine_route != grant.machine_route
            || input.revocation.device_route != grant.device_route
            || input.revocation.grant_serial != grant.grant_serial
            || input.revocation.root_key_id != grant.root_key_id
            || input.revocation.trust_epoch != grant.trust_epoch
            || input.revocation.signature.0 == [0; 64]
        {
            return Err(pairing_error(REVOCATION_RECOVERY_UNAVAILABLE));
        }
        if let Some(revocation) = state.revoked.get(&key) {
            if revocation != &input.revocation {
                return Err(pairing_error(REVOCATION_RECOVERY_UNAVAILABLE));
            }
            return Ok(BeginRevocationOutcome::AlreadyRevoked(revocation.clone()));
        }
        if let Some(recovery) = state.revocations.get(&key) {
            if recovery.revocation != input.revocation || recovery.pairing_id != input.pairing_id {
                return Err(pairing_error(REVOCATION_RECOVERY_UNAVAILABLE));
            }
            return Ok(BeginRevocationOutcome::Recovering(Box::new(
                recovery.clone(),
            )));
        }
        let matching_pairing = state
            .by_id
            .iter()
            .find(|(_, stored)| stored.pairing_id.as_bytes() == grant.device_route.as_bytes())
            .map(|(pairing_id, stored)| (*pairing_id, stored.lifecycle));
        if let Some(expected) = input.pairing_id
            && matching_pairing.map(|value| value.0) != Some(expected)
        {
            return Err(pairing_error(REVOCATION_RECOVERY_UNAVAILABLE));
        }
        let pairing_id = input.pairing_id.or_else(|| {
            matching_pairing.and_then(|(pairing_id, lifecycle)| {
                (lifecycle != PairingInviteLifecycle::Delivered).then_some(pairing_id)
            })
        });
        let phase = if matching_pairing
            .is_some_and(|value| value.1 == PairingInviteLifecycle::GrantPreparing)
        {
            DurableRevocationPhase::AwaitingGrantCommit
        } else {
            DurableRevocationPhase::ReadyToRevoke
        };
        if let Some(pairing_id) = pairing_id {
            let stored = state
                .by_id
                .get_mut(&pairing_id)
                .ok_or_else(|| pairing_error(REVOCATION_RECOVERY_UNAVAILABLE))?;
            if !matches!(
                stored.lifecycle,
                PairingInviteLifecycle::GrantPreparing | PairingInviteLifecycle::GrantCommitted
            ) {
                return Err(pairing_error(REVOCATION_RECOVERY_UNAVAILABLE));
            }
            stored.lifecycle = PairingInviteLifecycle::OrphanRevoking;
        }
        let recovery = DurableRevocation::for_test(pairing_id, grant, input.revocation, phase);
        state.revocations.insert(key, recovery.clone());
        self.order.lock().unwrap().push("revocation-commit");
        Ok(BeginRevocationOutcome::Recovering(Box::new(recovery)))
    }

    async fn acknowledge_orphan_grant_committed(
        &self,
        pairing_id: RuntimeId,
        committed: GrantCommitted,
        canonical_terminal: Vec<u8>,
    ) -> Result<DurableRevocation, PairingAdministrationError> {
        if self.fail_orphan_grant_ack.load(Ordering::SeqCst) {
            self.order.lock().unwrap().push("orphan-grant-ack-fault");
            return Err(pairing_error("daemon.runtime.store_unavailable"));
        }
        if canonical_terminal
            != encode(&OpaqueRouteFrame {
                version: RELAY_PROTOCOL_VERSION,
                body: RelayFrameBody::GrantCommitted(committed.clone()),
            })
        {
            return Err(pairing_error(REVOCATION_RECOVERY_UNAVAILABLE));
        }
        let mut state = self.state.lock().unwrap();
        let key = RevocationKey::new(committed.device_route, committed.grant_serial);
        let current = state
            .revocations
            .get(&key)
            .cloned()
            .ok_or_else(|| pairing_error(REVOCATION_RECOVERY_UNAVAILABLE))?;
        if current.pairing_id != Some(pairing_id) || !current.matches_grant_committed(&committed) {
            return Err(pairing_error(REVOCATION_RECOVERY_UNAVAILABLE));
        }
        let next = DurableRevocation::for_test(
            current.pairing_id,
            current.grant,
            current.revocation,
            DurableRevocationPhase::ReadyToRevoke,
        );
        state.grants.remove(&pairing_id);
        state.revocations.insert(key, next.clone());
        self.order.lock().unwrap().push("orphan-grant-ack-commit");
        Ok(next)
    }

    async fn recover_revocations(
        &self,
    ) -> Result<Vec<DurableRevocation>, PairingAdministrationError> {
        Ok(self
            .state
            .lock()
            .unwrap()
            .revocations
            .values()
            .cloned()
            .collect())
    }

    async fn acknowledge_revocation_committed(
        &self,
        committed: RevocationCommitted,
        canonical_terminal: Vec<u8>,
    ) -> Result<DeviceRevocation, PairingAdministrationError> {
        if self.fail_revocation_ack.load(Ordering::SeqCst) {
            self.order.lock().unwrap().push("revocation-ack-fault");
            return Err(pairing_error("daemon.runtime.store_unavailable"));
        }
        if canonical_terminal
            != encode(&OpaqueRouteFrame {
                version: RELAY_PROTOCOL_VERSION,
                body: RelayFrameBody::RevocationCommitted(committed.clone()),
            })
        {
            return Err(pairing_error(REVOCATION_RECOVERY_UNAVAILABLE));
        }
        let key = RevocationKey::new(committed.device_route, committed.grant_serial);
        let mut state = self.state.lock().unwrap();
        let recovery = state
            .revocations
            .get(&key)
            .cloned()
            .ok_or_else(|| pairing_error(REVOCATION_RECOVERY_UNAVAILABLE))?;
        if !recovery.matches_revocation_committed(&committed) {
            return Err(pairing_error(REVOCATION_RECOVERY_UNAVAILABLE));
        }
        state.revocations.remove(&key);
        state.revoked.insert(key, recovery.revocation.clone());
        if let Some(pairing_id) = recovery.pairing_id {
            let expired = state.due.contains(&pairing_id);
            let stored = state
                .by_id
                .get_mut(&pairing_id)
                .ok_or_else(|| pairing_error(PAIRING_TERMINAL_INVALID))?;
            stored.lifecycle = if expired {
                PairingInviteLifecycle::Expired
            } else {
                PairingInviteLifecycle::Canceled
            };
            let close = DurableClose {
                pairing_id,
                pair_route: stored.pair_route,
                frame: ClosePairRoute {
                    machine_route: MACHINE_ROUTE,
                    pair_route: stored.pair_route,
                },
            };
            state
                .terminals
                .get_mut(&pairing_id)
                .ok_or_else(|| pairing_error(PAIRING_TERMINAL_INVALID))?
                .close = Some(close);
            state.grants.remove(&pairing_id);
            state.committed.remove(&pairing_id);
        }
        self.order.lock().unwrap().push("revocation-ack-commit");
        Ok(recovery.revocation)
    }

    async fn terminalize(
        &self,
        pairing_id: RuntimeId,
        action: PairingTerminalAction,
    ) -> Result<TerminalOutcome, PairingAdministrationError> {
        self.order.lock().unwrap().push("terminal-commit");
        Self::terminalize_locked(&mut self.state.lock().unwrap(), pairing_id, action)
    }

    async fn terminalize_due(&self) -> Result<Vec<TerminalOutcome>, PairingAdministrationError> {
        let mut state = self.state.lock().unwrap();
        let due = state
            .due
            .iter()
            .copied()
            .filter(|pairing_id| {
                state.by_id.get(pairing_id).is_some_and(|stored| {
                    !matches!(
                        stored.lifecycle,
                        PairingInviteLifecycle::GrantPreparing
                            | PairingInviteLifecycle::GrantCommitted
                            | PairingInviteLifecycle::Delivered
                            | PairingInviteLifecycle::OrphanRevoking
                            | PairingInviteLifecycle::Canceled
                            | PairingInviteLifecycle::Expired
                    )
                })
            })
            .collect::<Vec<_>>();
        if !due.is_empty() {
            self.order.lock().unwrap().push("expiry-terminal-commit");
        }
        due.into_iter()
            .map(|pairing_id| {
                Self::terminalize_locked(&mut state, pairing_id, PairingTerminalAction::Expire)
            })
            .collect()
    }

    async fn recover_terminals(&self) -> Result<Vec<DurableClose>, PairingAdministrationError> {
        Ok(self
            .state
            .lock()
            .unwrap()
            .terminals
            .values()
            .filter_map(|terminal| terminal.close.clone())
            .collect())
    }

    async fn acknowledge_close(
        &self,
        pairing_id: RuntimeId,
        canonical_terminal: Vec<u8>,
    ) -> Result<PairingReceipt, PairingAdministrationError> {
        if self.fail_close_ack_before_commit.load(Ordering::SeqCst) {
            self.order.lock().unwrap().push("close-ack-before-fault");
            return Err(pairing_error("daemon.runtime.store_unavailable"));
        }
        let mut state = self.state.lock().unwrap();
        let terminal = state
            .terminals
            .get(&pairing_id)
            .cloned()
            .ok_or_else(|| pairing_error(PAIRING_TERMINAL_INVALID))?;
        let close = terminal
            .close
            .ok_or_else(|| pairing_error(PAIRING_TERMINAL_INVALID))?;
        let decoded =
            decode(&canonical_terminal).map_err(|_| pairing_error(PAIRING_TERMINAL_INVALID))?;
        if encode(&decoded) != canonical_terminal || decoded.version != RELAY_PROTOCOL_VERSION {
            return Err(pairing_error(PAIRING_TERMINAL_INVALID));
        }
        match decoded.body {
            RelayFrameBody::PairRouteClosed(PairRouteClosed { pair_route, .. })
                if pair_route == close.pair_route => {}
            _ => return Err(pairing_error(PAIRING_TERMINAL_INVALID)),
        }
        state.last_close_ack = Some(canonical_terminal);
        state.by_id.remove(&pairing_id);
        state.committed.remove(&pairing_id);
        state.delivered_receipt_hashes.remove(&pairing_id);
        state.terminals.get_mut(&pairing_id).unwrap().close = None;
        self.order.lock().unwrap().push(
            if self.close_ack_unknown_readback.load(Ordering::SeqCst) {
                "close-ack-unknown-readback"
            } else {
                "close-ack-commit"
            },
        );
        Ok(terminal.receipt)
    }

    async fn purge_expired_receipts(&self) -> Result<bool, PairingAdministrationError> {
        self.receipt_purge_calls.fetch_add(1, Ordering::SeqCst);
        if self.fail_receipt_purge.load(Ordering::SeqCst) {
            return Err(pairing_error("daemon.runtime.store_unavailable"));
        }
        Ok(false)
    }
}

struct FakeLane {
    event_rx: mpsc::UnboundedReceiver<Result<PairingTransportEvent, PairingAdministrationError>>,
    sent_tx: mpsc::UnboundedSender<OpenPairRoute>,
    sent_data_tx: mpsc::UnboundedSender<PairData>,
    sent_grant_tx: mpsc::UnboundedSender<InstallGrant>,
    sent_revoke_tx: mpsc::UnboundedSender<RevokeDevice>,
    sent_close_tx: mpsc::UnboundedSender<ClosePairRoute>,
    order: Arc<StdMutex<Vec<&'static str>>>,
    reconnects: Arc<AtomicUsize>,
    fail_send: Arc<AtomicBool>,
    send_failure_code: &'static str,
    clear_send_failure_on_reconnect: bool,
}

#[async_trait]
impl PairingLane for FakeLane {
    async fn send_open(&self, frame: OpenPairRoute) -> Result<(), PairingAdministrationError> {
        self.order.lock().unwrap().push("send");
        if self.fail_send.load(Ordering::SeqCst) {
            return Err(pairing_error(self.send_failure_code));
        }
        self.sent_tx
            .send(frame)
            .map_err(|_| pairing_error(PAIRING_TRANSPORT))
    }

    async fn send_data(&self, frame: PairData) -> Result<(), PairingAdministrationError> {
        self.order.lock().unwrap().push("send-pending");
        if self.fail_send.load(Ordering::SeqCst) {
            return Err(pairing_error(self.send_failure_code));
        }
        self.sent_data_tx
            .send(frame)
            .map_err(|_| pairing_error(PAIRING_TRANSPORT))
    }

    async fn send_install(&self, frame: InstallGrant) -> Result<(), PairingAdministrationError> {
        self.order.lock().unwrap().push("send-grant");
        if self.fail_send.load(Ordering::SeqCst) {
            return Err(pairing_error(self.send_failure_code));
        }
        self.sent_grant_tx
            .send(frame)
            .map_err(|_| pairing_error(PAIRING_TRANSPORT))
    }

    async fn send_revoke(&self, frame: RevokeDevice) -> Result<(), PairingAdministrationError> {
        self.order.lock().unwrap().push("send-revoke");
        if self.fail_send.load(Ordering::SeqCst) {
            return Err(pairing_error(self.send_failure_code));
        }
        self.sent_revoke_tx
            .send(frame)
            .map_err(|_| pairing_error(PAIRING_TRANSPORT))
    }

    async fn send_close(&self, frame: ClosePairRoute) -> Result<(), PairingAdministrationError> {
        self.order.lock().unwrap().push("send-close");
        if self.fail_send.load(Ordering::SeqCst) {
            return Err(pairing_error(self.send_failure_code));
        }
        self.sent_close_tx
            .send(frame)
            .map_err(|_| pairing_error(PAIRING_TRANSPORT))
    }

    async fn reconnect(&self) -> Result<(), PairingAdministrationError> {
        self.reconnects.fetch_add(1, Ordering::SeqCst);
        self.order.lock().unwrap().push("reconnect");
        if self.clear_send_failure_on_reconnect {
            self.fail_send.store(false, Ordering::SeqCst);
        }
        Ok(())
    }

    async fn next_event(
        &mut self,
    ) -> Result<Option<PairingTransportEvent>, PairingAdministrationError> {
        match self.event_rx.recv().await {
            Some(event) => event.map(Some),
            None => Ok(None),
        }
    }
}

#[derive(Default)]
struct FakePendingSink {
    published: Arc<StdMutex<Vec<PendingPairing>>>,
    fail: Arc<AtomicBool>,
}

impl PairingPendingSink for FakePendingSink {
    fn publish(&self, pending: PendingPairing) -> Result<usize, PairingAdministrationError> {
        if self.fail.load(Ordering::SeqCst) {
            return Err(pairing_error(
                "daemon.pairing.pending.connection_unavailable",
            ));
        }
        self.published.lock().unwrap().push(pending);
        Ok(1)
    }
}

struct FakeAuthority {
    seals: Arc<AtomicUsize>,
    grant_freezes: Arc<AtomicUsize>,
    grant_axes: Arc<StdMutex<Vec<(u64, u64)>>>,
    fail_grant_freeze: Arc<AtomicBool>,
    revocation_freezes: Arc<AtomicUsize>,
    fail_revocation_freeze: Arc<AtomicBool>,
}

impl PairingAuthority for FakeAuthority {
    fn seal_pending(
        &self,
        preparation: &PendingPreparation,
    ) -> Result<PairingControlEnvelopeV1, PairingAdministrationError> {
        assert_eq!(preparation.context.frame_kind, OuterFrameKind::PairPending);
        assert_eq!(
            preparation.context.pair_route,
            Some(preparation.info.pair_route)
        );
        let ordinal = self.seals.fetch_add(1, Ordering::SeqCst) + 1;
        Ok(PairingControlEnvelopeV1 {
            format_version: E2EE_FORMAT_VERSION,
            enc: vec![u8::try_from(ordinal).unwrap(); 32],
            ciphertext: preparation.request_hash.to_vec(),
        })
    }

    fn freeze_grant(
        &self,
        preparation: &GrantPreparationInput,
        allocation: GrantAllocationInput,
    ) -> Result<FrozenGrantInput, PairingAdministrationError> {
        let GrantAllocationInput::Test {
            grant_serial,
            key_directory_revision,
        } = allocation
        else {
            return Err(pairing_error(PAIRING_GRANT_RECOVERY_UNAVAILABLE));
        };
        if self.fail_grant_freeze.load(Ordering::SeqCst) {
            return Err(pairing_error(GrantFreezeError::CryptoFailure.code()));
        }
        self.grant_freezes.fetch_add(1, Ordering::SeqCst);
        self.grant_axes
            .lock()
            .unwrap()
            .push((grant_serial.value(), key_directory_revision.value()));
        Ok(FrozenGrantInput::for_test(
            preparation.pairing_id,
            preparation.request_hash,
        ))
    }

    fn verify_delivery(
        &self,
        response: &DurableResponse,
        canonical_envelope: &[u8],
    ) -> Result<DeliveryProofInput, PairingAdministrationError> {
        response.verify_receipt_for_test(canonical_envelope)
    }

    fn freeze_revocation(
        &self,
        grant: &RelayGrant,
    ) -> Result<DeviceRevocation, PairingAdministrationError> {
        if self.fail_revocation_freeze.load(Ordering::SeqCst) {
            return Err(pairing_error("daemon.pairing.revocation_signing_failed"));
        }
        self.revocation_freezes.fetch_add(1, Ordering::SeqCst);
        let root = SigningKey::from_seed(&TEST_ROOT_SEED);
        let relay = RelayServerId::from_bytes([0x11; 16]);
        let root_fingerprint = sha256(&root.verifying_key().to_bytes());
        let mut revocation = DeviceRevocation {
            machine_route: grant.machine_route,
            device_route: grant.device_route,
            grant_serial: grant.grant_serial,
            root_key_id: grant.root_key_id,
            trust_epoch: grant.trust_epoch,
            signature: Ed25519Signature([0; 64]),
        };
        revocation.signature =
            sign_tbs(&root, &revocation.to_be_signed_v1(relay, root_fingerprint)).into();
        Ok(revocation)
    }
}

/// 组合测试只替换系统熵与 transport；allocation、frozen grant 验证和所有 durable
/// transition 仍走 production Store seam。密码学 artifact 复用 Store suite 的严格构造器，
/// 避免在 coordinator suite 维护第二份 PairResponse/KeyDirectory 编码逻辑。
struct StoreBackedTestAuthority {
    binding: MachineIdentityBinding,
    data_certificate: SignedCertificate,
    freeze_ordinal: AtomicUsize,
}

impl StoreBackedTestAuthority {
    fn secret(seed: u8) -> SecretBytes {
        SecretBytes::new(vec![seed; 32])
    }
}

impl PairingAuthority for StoreBackedTestAuthority {
    fn seal_pending(
        &self,
        preparation: &PendingPreparation,
    ) -> Result<PairingControlEnvelopeV1, PairingAdministrationError> {
        Ok(PairingControlEnvelopeV1 {
            format_version: E2EE_FORMAT_VERSION,
            enc: vec![0x91; 32],
            ciphertext: preparation.request_hash.to_vec(),
        })
    }

    fn freeze_grant(
        &self,
        preparation: &GrantPreparationInput,
        allocation: GrantAllocationInput,
    ) -> Result<FrozenGrantInput, PairingAdministrationError> {
        let production = preparation
            .production
            .as_ref()
            .ok_or_else(|| pairing_error(PAIRING_GRANT_RECOVERY_UNAVAILABLE))?;
        let ordinal = self.freeze_ordinal.fetch_add(1, Ordering::SeqCst);
        let entropy_base = if ordinal == 0 { 0xc1 } else { 0xe1 };
        let (device_route, grant_serial, global) = match allocation {
            GrantAllocationInput::Production(GrantAllocationProjection::New {
                current_global_keys,
                ..
            }) => {
                if current_global_keys.is_some() {
                    return Err(pairing_error(PAIRING_GRANT_RECOVERY_UNAVAILABLE));
                }
                let route = DeviceRouteId::from_bytes([0xd1; 16]);
                let global = GlobalKeyStateV1::bootstrap(
                    1,
                    1,
                    Self::secret(entropy_base),
                    route,
                    1,
                    Self::secret(entropy_base.wrapping_add(1)),
                    1,
                    Self::secret(entropy_base.wrapping_add(2)),
                )
                .map_err(store_error)?;
                (route, GrantSerial::new(1), global)
            }
            GrantAllocationInput::Production(GrantAllocationProjection::Renew {
                device_route,
                next_serial,
                current_global_keys,
                ..
            }) => {
                let global = current_global_keys
                    .renew_for_device(
                        device_route,
                        Self::secret(entropy_base),
                        Self::secret(entropy_base.wrapping_add(1)),
                        Self::secret(entropy_base.wrapping_add(2)),
                    )
                    .map_err(store_error)?;
                (device_route, next_serial, global)
            }
            GrantAllocationInput::Test { .. } => {
                return Err(pairing_error(PAIRING_GRANT_RECOVERY_UNAVAILABLE));
            }
        };
        let input = crate::runtime::store::grant_input_with_for_test(
            production,
            &self.binding,
            &self.data_certificate,
            device_route,
            grant_serial,
            global,
            None,
            entropy_base.wrapping_add(3),
        );
        Ok(FrozenGrantInput {
            pairing_id: preparation.pairing_id,
            request_hash: preparation.request_hash,
            production: Some(input),
        })
    }

    fn verify_delivery(
        &self,
        response: &DurableResponse,
        canonical_envelope: &[u8],
    ) -> Result<DeliveryProofInput, PairingAdministrationError> {
        response
            .verify_receipt(canonical_envelope)
            .map(|proof| DeliveryProofInput::from_verified(response.pairing_id, proof))
    }

    fn freeze_revocation(
        &self,
        grant: &RelayGrant,
    ) -> Result<DeviceRevocation, PairingAdministrationError> {
        let mut revocation = DeviceRevocation {
            machine_route: grant.machine_route,
            device_route: grant.device_route,
            grant_serial: grant.grant_serial,
            root_key_id: grant.root_key_id,
            trust_epoch: grant.trust_epoch,
            signature: Ed25519Signature([0; 64]),
        };
        revocation.signature = sign_tbs(
            &SigningKey::from_seed(&[0x41; 32]),
            &revocation.to_be_signed_v1(
                crate::runtime::store::PAIRING_TEST_RELAY,
                self.binding.root_fingerprint,
            ),
        )
        .into();
        Ok(revocation)
    }
}

struct TestActor {
    handle: PairingCoordinatorHandle,
    cancel_tx: watch::Sender<bool>,
    task: JoinHandle<()>,
    event_tx: mpsc::UnboundedSender<Result<PairingTransportEvent, PairingAdministrationError>>,
    sent_rx: mpsc::UnboundedReceiver<OpenPairRoute>,
    sent_data_rx: mpsc::UnboundedReceiver<PairData>,
    sent_grant_rx: mpsc::UnboundedReceiver<InstallGrant>,
    sent_revoke_rx: mpsc::UnboundedReceiver<RevokeDevice>,
    sent_close_rx: mpsc::UnboundedReceiver<ClosePairRoute>,
    reconnects: Arc<AtomicUsize>,
    seals: Arc<AtomicUsize>,
    grant_freezes: Arc<AtomicUsize>,
    grant_axes: Arc<StdMutex<Vec<(u64, u64)>>>,
    fail_grant_freeze: Arc<AtomicBool>,
    revocation_freezes: Arc<AtomicUsize>,
    fail_revocation_freeze: Arc<AtomicBool>,
    fail_send: Arc<AtomicBool>,
    published: Arc<StdMutex<Vec<PendingPairing>>>,
    sink_fail: Arc<AtomicBool>,
}

impl TestActor {
    async fn stop(self) {
        self.cancel_tx.send_replace(true);
        tokio::time::timeout(Duration::from_secs(1), self.task)
            .await
            .expect("actor shutdown must be bounded")
            .expect("actor task must join");
    }
}

async fn spawn_actor(store: Arc<FakeStore>) -> TestActor {
    let (actor, ready) = spawn_actor_with_startup_send_failure(store, None).await;
    ready.unwrap();
    actor
}

async fn spawn_actor_with_startup_send_failure(
    store: Arc<FakeStore>,
    send_failure_code: Option<&'static str>,
) -> (TestActor, Result<(), PairingAdministrationError>) {
    let (event_tx, event_rx) = mpsc::unbounded_channel();
    let (sent_tx, sent_rx) = mpsc::unbounded_channel();
    let (sent_data_tx, sent_data_rx) = mpsc::unbounded_channel();
    let (sent_grant_tx, sent_grant_rx) = mpsc::unbounded_channel();
    let (sent_revoke_tx, sent_revoke_rx) = mpsc::unbounded_channel();
    let (sent_close_tx, sent_close_rx) = mpsc::unbounded_channel();
    let reconnects = Arc::new(AtomicUsize::new(0));
    let seals = Arc::new(AtomicUsize::new(0));
    let grant_freezes = Arc::new(AtomicUsize::new(0));
    let grant_axes = Arc::new(StdMutex::new(Vec::new()));
    let fail_grant_freeze = Arc::new(AtomicBool::new(false));
    let revocation_freezes = Arc::new(AtomicUsize::new(0));
    let fail_revocation_freeze = Arc::new(AtomicBool::new(false));
    let published = Arc::new(StdMutex::new(Vec::new()));
    let sink_fail = Arc::new(AtomicBool::new(false));
    let fail_send = Arc::new(AtomicBool::new(send_failure_code.is_some()));
    let lane = FakeLane {
        event_rx,
        sent_tx,
        sent_data_tx,
        sent_grant_tx,
        sent_revoke_tx,
        sent_close_tx,
        order: Arc::clone(&store.order),
        reconnects: Arc::clone(&reconnects),
        fail_send: Arc::clone(&fail_send),
        send_failure_code: send_failure_code.unwrap_or("remote.transport.closed"),
        clear_send_failure_on_reconnect: true,
    };
    let (command_tx, command_rx) = mpsc::channel(PAIRING_COMMAND_CAPACITY);
    let (cancel_tx, cancel_rx) = watch::channel(false);
    let (ready_tx, ready_rx) = oneshot::channel();
    let actor = PairingCoordinator::new_for_test(
        store,
        Box::new(lane),
        Box::new(FakeAuthority {
            seals: Arc::clone(&seals),
            grant_freezes: Arc::clone(&grant_freezes),
            grant_axes: Arc::clone(&grant_axes),
            fail_grant_freeze: Arc::clone(&fail_grant_freeze),
            revocation_freezes: Arc::clone(&revocation_freezes),
            fail_revocation_freeze: Arc::clone(&fail_revocation_freeze),
        }),
        test_invite_context(),
        Arc::new(FakePendingSink {
            published: Arc::clone(&published),
            fail: Arc::clone(&sink_fail),
        }),
    );
    let task = tokio::spawn(actor.run(command_rx, cancel_rx, ready_tx));
    let ready = ready_rx.await.unwrap();
    (
        TestActor {
            handle: PairingCoordinatorHandle { command_tx },
            cancel_tx,
            task,
            event_tx,
            sent_rx,
            sent_data_rx,
            sent_grant_rx,
            sent_revoke_rx,
            sent_close_rx,
            reconnects,
            seals,
            grant_freezes,
            grant_axes,
            fail_grant_freeze,
            revocation_freezes,
            fail_revocation_freeze,
            fail_send,
            published,
            sink_fail,
        },
        ready,
    )
}

async fn spawn_store_backed_actor(
    store: RuntimeStoreHandle,
    binding: MachineIdentityBinding,
    data_certificate: SignedCertificate,
) -> TestActor {
    let (event_tx, event_rx) = mpsc::unbounded_channel();
    let (sent_tx, sent_rx) = mpsc::unbounded_channel();
    let (sent_data_tx, sent_data_rx) = mpsc::unbounded_channel();
    let (sent_grant_tx, sent_grant_rx) = mpsc::unbounded_channel();
    let (sent_revoke_tx, sent_revoke_rx) = mpsc::unbounded_channel();
    let (sent_close_tx, sent_close_rx) = mpsc::unbounded_channel();
    let reconnects = Arc::new(AtomicUsize::new(0));
    let seals = Arc::new(AtomicUsize::new(0));
    let grant_freezes = Arc::new(AtomicUsize::new(0));
    let grant_axes = Arc::new(StdMutex::new(Vec::new()));
    let fail_grant_freeze = Arc::new(AtomicBool::new(false));
    let revocation_freezes = Arc::new(AtomicUsize::new(0));
    let fail_revocation_freeze = Arc::new(AtomicBool::new(false));
    let published = Arc::new(StdMutex::new(Vec::new()));
    let sink_fail = Arc::new(AtomicBool::new(false));
    let fail_send = Arc::new(AtomicBool::new(false));
    let order = Arc::new(StdMutex::new(Vec::new()));
    let lane = FakeLane {
        event_rx,
        sent_tx,
        sent_data_tx,
        sent_grant_tx,
        sent_revoke_tx,
        sent_close_tx,
        order,
        reconnects: Arc::clone(&reconnects),
        fail_send: Arc::clone(&fail_send),
        send_failure_code: "remote.transport.closed",
        clear_send_failure_on_reconnect: true,
    };
    let invite_context = PairingInviteContext {
        wss_url: "wss://relay.example.test:8443/".to_owned(),
        current_spki_pin: [0x52; 32],
        next_spki_pin: [0x53; 32],
        relay_server_id: crate::runtime::store::PAIRING_TEST_RELAY,
        machine_root_pubkey: PublicKeyBytes(binding.root_public_key),
        machine_root_fingerprint: binding.root_fingerprint,
        data_sign_cert: data_certificate.clone(),
    };
    let (command_tx, command_rx) = mpsc::channel(PAIRING_COMMAND_CAPACITY);
    let (cancel_tx, cancel_rx) = watch::channel(false);
    let (ready_tx, ready_rx) = oneshot::channel();
    let actor = PairingCoordinator::new_for_test(
        Arc::new(ProductionPairingStore(store)),
        Box::new(lane),
        Box::new(StoreBackedTestAuthority {
            binding,
            data_certificate,
            freeze_ordinal: AtomicUsize::new(0),
        }),
        invite_context,
        Arc::new(FakePendingSink {
            published: Arc::clone(&published),
            fail: Arc::clone(&sink_fail),
        }),
    );
    let task = tokio::spawn(actor.run(command_rx, cancel_rx, ready_tx));
    tokio::time::timeout(Duration::from_secs(5), ready_rx)
        .await
        .expect("timed out waiting for store-backed actor startup")
        .expect("store-backed actor startup channel must remain open")
        .expect("store-backed actor startup must succeed");
    TestActor {
        handle: PairingCoordinatorHandle { command_tx },
        cancel_tx,
        task,
        event_tx,
        sent_rx,
        sent_data_rx,
        sent_grant_rx,
        sent_revoke_rx,
        sent_close_rx,
        reconnects,
        seals,
        grant_freezes,
        grant_axes,
        fail_grant_freeze,
        revocation_freezes,
        fail_revocation_freeze,
        fail_send,
        published,
        sink_fail,
    }
}

fn test_invite_context() -> PairingInviteContext {
    let relay_server_id = RelayServerId::from_bytes([0x11; 16]);
    let root = SigningKey::from_seed(&TEST_ROOT_SEED);
    let data = SigningKey::from_seed(&TEST_DATA_SEED);
    let root_public_key = PublicKeyBytes(root.verifying_key().to_bytes());
    let root_fingerprint = sha256(&root_public_key.0);
    let mut data_sign_cert = SignedCertificate {
        subject_pubkey: PublicKeyBytes(data.verifying_key().to_bytes()),
        cert_role: CertRole::Data,
        generation: LinkGeneration::new(1),
        root_key_id: RootKeyId::from_bytes([0x33; 16]),
        trust_epoch: TrustEpoch::new(1),
        not_after_ms: None,
        signature: Ed25519Signature([0; 64]),
    };
    data_sign_cert.signature = sign_tbs(
        &root,
        &data_sign_cert.to_be_signed_v1(relay_server_id, MACHINE_ROUTE, root_fingerprint),
    )
    .into();
    PairingInviteContext {
        wss_url: "wss://relay.example.test:8443/".to_owned(),
        current_spki_pin: [0x41; 32],
        next_spki_pin: [0x42; 32],
        relay_server_id,
        machine_root_pubkey: root_public_key,
        machine_root_fingerprint: root_fingerprint,
        data_sign_cert,
    }
}

fn owner() -> IdempotencyOwner {
    IdempotencyOwner::Local {
        machine_trust_domain: [0x51; 32],
        uid: 501,
        client_installation_id: [0x52; 16],
    }
}

fn request(key: &str) -> CreatePairInviteRequest {
    CreatePairInviteRequest {
        display_name: "测试机器".to_owned(),
        idempotency_key: IdempotencyKey::new(key),
        scope: LocalOnlyAdministration::LocalOnly,
    }
}

fn opened(open: &OpenPairRoute) -> PairingTransportEvent {
    PairingTransportEvent::PairRouteOpened(PairRouteOpened {
        machine_route: open.machine_route,
        pair_route: open.pair_route,
        absolute_expiry_ms: open.absolute_expiry_ms,
    })
}

fn closed(close: &ClosePairRoute) -> PairingTransportEvent {
    PairingTransportEvent::PairRouteClosed(PairRouteClosed {
        pair_route: close.pair_route,
        outcome: PairRouteCloseOutcome::Closed,
    })
}

fn grant_committed(install: &InstallGrant) -> GrantCommitted {
    GrantCommitted {
        device_route: install.grant.device_route,
        grant_serial: install.grant.grant_serial,
        grant_hash: install.grant.canonical_sha256(),
    }
}

fn device_handle_for_test(route: DeviceRouteId) -> DeviceHandle {
    const HEX: &[u8; 16] = b"0123456789abcdef";
    let mut value = String::from("device-");
    for byte in route.as_bytes() {
        value.push(char::from(HEX[usize::from(byte >> 4)]));
        value.push(char::from(HEX[usize::from(byte & 0x0f)]));
    }
    DeviceHandle::new(value)
}

fn revocation_committed(revoke: &RevokeDevice) -> RevocationCommitted {
    RevocationCommitted {
        device_route: revoke.revocation.device_route,
        grant_serial: revoke.revocation.grant_serial,
        signed_revocation: revoke.revocation.clone(),
    }
}

struct DeterministicRng(u64);

impl TryRng for DeterministicRng {
    type Error = std::convert::Infallible;

    fn try_next_u32(&mut self) -> Result<u32, Self::Error> {
        Ok(self.try_next_u64()? as u32)
    }

    fn try_next_u64(&mut self) -> Result<u64, Self::Error> {
        self.0 = self
            .0
            .wrapping_mul(6_364_136_223_846_793_005)
            .wrapping_add(1);
        Ok(self.0)
    }

    fn try_fill_bytes(&mut self, destination: &mut [u8]) -> Result<(), Self::Error> {
        for chunk in destination.chunks_mut(8) {
            let bytes = self.try_next_u64()?.to_le_bytes();
            chunk.copy_from_slice(&bytes[..chunk.len()]);
        }
        Ok(())
    }
}

impl TryCryptoRng for DeterministicRng {}

fn pair_request(invite: &PairInviteV1, seed: u8) -> PairData {
    let device_signing_key = SigningKey::from_seed(&[seed; 32]);
    let (_, device_hpke_public_key) = HpkePrivateKey::derive_keypair(&[seed.wrapping_add(1); 32]);
    let plaintext = PairRequestPlaintextV1 {
        format_version: E2EE_FORMAT_VERSION,
        invite_secret: invite.invite_secret,
        device_sign_pubkey: PublicKeyBytes(device_signing_key.verifying_key().to_bytes()),
        device_hpke_pubkey: PublicKeyBytes(device_hpke_public_key.to_bytes().try_into().unwrap()),
        authorization_request: AuthorizationRequestV1 {
            format_version: E2EE_FORMAT_VERSION,
            device_display_name: format!("测试设备-{seed}"),
            capabilities: vec![AuthorizationCapabilityV1::Catalog],
            permissions: vec![AuthorizationPermissionV1::CatalogRead],
        },
    };
    let recipient = HpkePublicKey::from_bytes(&invite.invite_hpke_pubkey.0).unwrap();
    let info = pair_request_info(invite).unwrap();
    let context = pairing_context(invite.pair_route, OuterFrameKind::PairRequest);
    let envelope = seal_pair_request(
        &recipient,
        &info,
        &context,
        &plaintext,
        &device_signing_key,
        &mut DeterministicRng(u64::from(seed)),
    )
    .unwrap();
    PairData {
        pair_route: invite.pair_route,
        sealed_blob: agentdeck_protocol::relay_v2::frame::SealedBlob(
            envelope.canonical_bytes().unwrap(),
        ),
    }
}

struct StoreBackedDeviceMaterial {
    signing_key: SigningKey,
    hpke_private_key: HpkePrivateKey,
    hpke_public_key: PublicKeyBytes,
}

fn store_backed_pair_request(
    invite: &PairInviteV1,
    device_sign_seed: u8,
    device_hpke_seed: u8,
    request_rng_seed: u64,
) -> (PairData, StoreBackedDeviceMaterial) {
    let signing_key = SigningKey::from_seed(&[device_sign_seed; 32]);
    let (hpke_private_key, hpke_public_key) =
        HpkePrivateKey::derive_keypair(&[device_hpke_seed; 32]);
    let hpke_public_key = PublicKeyBytes(
        hpke_public_key
            .to_bytes()
            .try_into()
            .expect("X25519 public key is 32 bytes"),
    );
    let plaintext = PairRequestPlaintextV1 {
        format_version: E2EE_FORMAT_VERSION,
        invite_secret: invite.invite_secret,
        device_sign_pubkey: PublicKeyBytes(signing_key.verifying_key().to_bytes()),
        device_hpke_pubkey: hpke_public_key,
        authorization_request: AuthorizationRequestV1 {
            format_version: E2EE_FORMAT_VERSION,
            device_display_name: "续期设备".to_owned(),
            capabilities: vec![AuthorizationCapabilityV1::Catalog],
            permissions: vec![AuthorizationPermissionV1::CatalogRead],
        },
    };
    let recipient = HpkePublicKey::from_bytes(&invite.invite_hpke_pubkey.0).unwrap();
    let info = pair_request_info(invite).unwrap();
    let context = pairing_context(invite.pair_route, OuterFrameKind::PairRequest);
    let envelope = seal_pair_request(
        &recipient,
        &info,
        &context,
        &plaintext,
        &signing_key,
        &mut DeterministicRng(request_rng_seed),
    )
    .unwrap();
    (
        PairData {
            pair_route: invite.pair_route,
            sealed_blob: SealedBlob(envelope.canonical_bytes().unwrap()),
        },
        StoreBackedDeviceMaterial {
            signing_key,
            hpke_private_key,
            hpke_public_key,
        },
    )
}

fn store_backed_response_receipt(
    invite: &PairInviteV1,
    frame: &PairData,
    device: &StoreBackedDeviceMaterial,
    receipt_rng_seed: u64,
) -> (PairData, PairResponseV1, PairResponsePlaintextV1) {
    let response = PairResponseV1::from_canonical_bytes(&frame.sealed_blob.0)
        .expect("decode production PairResponse");
    let signer = MachineDataSignerBindingV1::from_certificate(&invite.data_sign_cert)
        .expect("bind production MachineData signer");
    let plaintext = open_pair_response(
        &device.hpke_private_key,
        &response.info,
        &pairing_context(invite.pair_route, OuterFrameKind::PairResponse),
        &response,
        &SigningKey::from_seed(&[0x43; 32]).verifying_key(),
        &signer,
        &SigningKey::from_seed(&[0x41; 32]).verifying_key(),
    )
    .expect("open production PairResponse with current DeviceHPKE");
    let receipt = seal_pair_response_received(
        &HpkePublicKey::from_bytes(&invite.invite_hpke_pubkey.0).unwrap(),
        &response.info,
        &pairing_context(invite.pair_route, OuterFrameKind::PairResponseReceived),
        PairResponseReceivedV1 {
            request_hash: plaintext.request_hash,
            grant_hash: plaintext.relay_grant.canonical_sha256(),
            response_hash: response.canonical_sha256().unwrap(),
            signature: Ed25519Signature([0; 64]),
        },
        &device.signing_key,
        &mut DeterministicRng(receipt_rng_seed),
    )
    .expect("seal production PairResponseReceived");
    (
        PairData {
            pair_route: invite.pair_route,
            sealed_blob: SealedBlob(receipt.canonical_bytes().unwrap()),
        },
        response,
        plaintext,
    )
}

struct StoreBackedPairingEvidence {
    install: InstallGrant,
    response: PairResponseV1,
    plaintext: PairResponsePlaintextV1,
    device_hpke_public_key: PublicKeyBytes,
}

async fn receive_pairing_frame<T>(
    receiver: &mut mpsc::UnboundedReceiver<T>,
    label: &'static str,
) -> T {
    tokio::time::timeout(Duration::from_secs(5), receiver.recv())
        .await
        .unwrap_or_else(|_| panic!("timed out waiting for {label}"))
        .unwrap_or_else(|| panic!("channel closed while waiting for {label}"))
}

async fn complete_store_backed_pairing(
    actor: &mut TestActor,
    store: &RuntimeStoreHandle,
    key: &str,
    device_sign_seed: u8,
    device_hpke_seed: u8,
    rng_seed: u64,
) -> StoreBackedPairingEvidence {
    let invite = create_opened_invite(actor, key).await;
    let pairing_id =
        RuntimeId::parse_canonical(RuntimeIdKind::Pairing, invite.pairing_id.as_str()).unwrap();
    let (request, device) =
        store_backed_pair_request(&invite.invite, device_sign_seed, device_hpke_seed, rng_seed);
    actor
        .event_tx
        .send(Ok(PairingTransportEvent::PairData(request)))
        .unwrap();
    receive_pairing_frame(&mut actor.sent_data_rx, "PairPending").await;
    assert!(matches!(
        actor.handle.confirm(pairing_id).await.unwrap(),
        PairingReceipt::Confirmed { .. }
    ));
    let install = receive_pairing_frame(&mut actor.sent_grant_rx, "InstallGrant").await;
    actor
        .event_tx
        .send(Ok(PairingTransportEvent::GrantCommitted(grant_committed(
            &install,
        ))))
        .unwrap();
    let response_frame = receive_pairing_frame(&mut actor.sent_data_rx, "PairResponse").await;
    let (receipt, response, plaintext) = store_backed_response_receipt(
        &invite.invite,
        &response_frame,
        &device,
        rng_seed.wrapping_add(1),
    );
    actor
        .event_tx
        .send(Ok(PairingTransportEvent::PairData(receipt)))
        .unwrap();
    let close = receive_pairing_frame(&mut actor.sent_close_rx, "ClosePairRoute").await;
    actor.event_tx.send(Ok(closed(&close))).unwrap();
    tokio::time::timeout(Duration::from_secs(1), async {
        loop {
            if store
                .load_pairing_invite(pairing_id)
                .await
                .expect("read pairing close state")
                .is_none()
            {
                break;
            }
            tokio::task::yield_now().await;
        }
    })
    .await
    .expect("PairRoute close ACK must durably remove live pairing");
    StoreBackedPairingEvidence {
        install,
        response,
        plaintext,
        device_hpke_public_key: device.hpke_public_key,
    }
}

#[derive(Clone, Copy)]
struct TestReceiptAxes {
    request_hash: [u8; 32],
    grant_hash: [u8; 32],
    response_hash: [u8; 32],
}

fn pair_response_receipt(
    store: &FakeStore,
    pairing_id: RuntimeId,
    device_seed: u8,
    axes: Option<TestReceiptAxes>,
) -> PairData {
    let response = store
        .state
        .lock()
        .unwrap()
        .committed
        .get(&pairing_id)
        .expect("committed response")
        .clone();
    let mut info = response.receipt_info().unwrap();
    let context = response.receipt_context();
    let axes = axes.unwrap_or(TestReceiptAxes {
        request_hash: response.request_hash,
        grant_hash: response.grant_hash,
        response_hash: response.response_hash,
    });
    info.request_hash = axes.request_hash;
    let device_signing_key = SigningKey::from_seed(&[device_seed; 32]);
    let recipient = HpkePublicKey::from_bytes(&response.invite.invite_hpke_pubkey.0).unwrap();
    let envelope = seal_pair_response_received(
        &recipient,
        &info,
        &context,
        PairResponseReceivedV1 {
            request_hash: axes.request_hash,
            grant_hash: axes.grant_hash,
            response_hash: axes.response_hash,
            signature: Ed25519Signature([0; 64]),
        },
        &device_signing_key,
        &mut DeterministicRng(u64::from(device_seed) + 0x6000),
    )
    .unwrap();
    PairData {
        pair_route: response.pair_route,
        sealed_blob: SealedBlob(envelope.canonical_bytes().unwrap()),
    }
}

async fn create_opened_invite(actor: &mut TestActor, key: &str) -> PairInvite {
    let handle = actor.handle.clone();
    let key = key.to_owned();
    let create = tokio::spawn(async move { handle.create(owner(), request(&key)).await });
    let open = receive_pairing_frame(&mut actor.sent_rx, "OpenPairRoute").await;
    actor.event_tx.send(Ok(opened(&open))).unwrap();
    tokio::time::timeout(Duration::from_secs(5), create)
        .await
        .expect("timed out waiting for CreatePairInvite")
        .expect("CreatePairInvite task must join")
        .expect("CreatePairInvite must succeed")
}

async fn create_pending_pairing(
    actor: &mut TestActor,
    key: &str,
    seed: u8,
) -> (PairInvite, RuntimeId) {
    let invite = create_opened_invite(actor, key).await;
    actor
        .event_tx
        .send(Ok(PairingTransportEvent::PairData(pair_request(
            &invite.invite,
            seed,
        ))))
        .unwrap();
    actor.sent_data_rx.recv().await.unwrap();
    let pairing_id =
        RuntimeId::parse_canonical(RuntimeIdKind::Pairing, invite.pairing_id.as_str()).unwrap();
    (invite, pairing_id)
}

async fn create_committed_pairing(
    actor: &mut TestActor,
    store: &FakeStore,
    key: &str,
    seed: u8,
) -> (PairInvite, RuntimeId, PairData) {
    let (invite, pairing_id) = create_pending_pairing(actor, key, seed).await;
    actor.handle.confirm(pairing_id).await.unwrap();
    let install = actor.sent_grant_rx.recv().await.unwrap();
    actor
        .event_tx
        .send(Ok(PairingTransportEvent::GrantCommitted(grant_committed(
            &install,
        ))))
        .unwrap();
    let response = actor.sent_data_rx.recv().await.unwrap();
    assert_eq!(response, store.committed_response(pairing_id));
    (invite, pairing_id, response)
}

async fn create_delivered_pairing(
    actor: &mut TestActor,
    store: &FakeStore,
    key: &str,
    seed: u8,
) -> (PairInvite, RuntimeId, ClosePairRoute) {
    let (invite, pairing_id, _) = create_committed_pairing(actor, store, key, seed).await;
    actor
        .event_tx
        .send(Ok(PairingTransportEvent::PairData(pair_response_receipt(
            store, pairing_id, seed, None,
        ))))
        .unwrap();
    let close = actor.sent_close_rx.recv().await.unwrap();
    assert_eq!(
        store.lifecycle(pairing_id),
        PairingInviteLifecycle::Delivered
    );
    (invite, pairing_id, close)
}

#[tokio::test]
async fn create_persists_before_send_and_returns_relay_tick_guarded_invite() {
    let order = Arc::new(StdMutex::new(Vec::new()));
    let store = Arc::new(FakeStore::with_order(Arc::clone(&order)));
    let mut actor = spawn_actor(Arc::clone(&store)).await;
    let invite_ttl_ms = pair_invite_ttl_ms().unwrap();
    assert!(invite_ttl_ms > 0);
    assert_eq!(
        invite_ttl_ms,
        PAIR_INVITE_MAX_TTL_MS - PAIR_INVITE_RELAY_TICK_GUARD_MS
    );
    let daemon_now_ms = 10_000_u64;
    let stale_relay_now_ms = daemon_now_ms - PAIR_INVITE_RELAY_TICK_GUARD_MS;
    assert!(
        daemon_now_ms + invite_ttl_ms <= stale_relay_now_ms + PAIR_INVITE_MAX_TTL_MS,
        "Relay clock 落后完整 guard 时仍须接受 fresh PairRoute expiry"
    );
    let before = unix_now_ms().unwrap();
    let handle = actor.handle.clone();
    let create = tokio::spawn(async move { handle.create(owner(), request("first")).await });
    let open = actor.sent_rx.recv().await.unwrap();
    assert_eq!(&*order.lock().unwrap(), &["persist", "send"]);
    assert!(
        !create.is_finished(),
        "invite must not escape before Relay ACK"
    );
    actor.event_tx.send(Ok(opened(&open))).unwrap();
    let response = create.await.unwrap().unwrap();
    let after = unix_now_ms().unwrap();
    assert_eq!(response.invite.pair_route, open.pair_route);
    assert!(response.invite.expires_at_ms >= before + invite_ttl_ms);
    assert!(response.invite.expires_at_ms <= after + invite_ttl_ms);
    assert!(response.invite.expires_at_ms <= after + PAIR_INVITE_MAX_TTL_MS);
    let pairing_id =
        RuntimeId::parse_canonical(RuntimeIdKind::Pairing, response.pairing_id.as_str()).unwrap();
    assert_eq!(store.lifecycle(pairing_id), PairingInviteLifecycle::Unused);
    assert_eq!(order.lock().unwrap().last(), Some(&"ack-commit"));
    actor.stop().await;
}

#[tokio::test]
async fn caller_drop_does_not_cancel_durable_open_and_retry_replays_exact_invite() {
    let store = Arc::new(FakeStore::default());
    let mut actor = spawn_actor(Arc::clone(&store)).await;
    let handle = actor.handle.clone();
    let abandoned = tokio::spawn(async move { handle.create(owner(), request("retry")).await });
    let open = actor.sent_rx.recv().await.unwrap();
    abandoned.abort();
    actor.event_tx.send(Ok(opened(&open))).unwrap();

    let handle = actor.handle.clone();
    let retry = tokio::spawn(async move { handle.create(owner(), request("retry")).await });
    let response = retry.await.unwrap().unwrap();
    assert_eq!(response.invite.pair_route, open.pair_route);
    assert_eq!(store.count(), 1);
    actor.stop().await;
}

#[tokio::test]
async fn restart_and_reconnect_require_generation_local_open_ack_before_replay() {
    let store = Arc::new(FakeStore::default());
    let mut first = spawn_actor(Arc::clone(&store)).await;
    let handle = first.handle.clone();
    let create = tokio::spawn(async move { handle.create(owner(), request("generation")).await });
    let original_open = first.sent_rx.recv().await.unwrap();
    first.event_tx.send(Ok(opened(&original_open))).unwrap();
    let original = create.await.unwrap().unwrap();
    first.stop().await;

    let mut second = spawn_actor(Arc::clone(&store)).await;
    let startup_open = second.sent_rx.recv().await.unwrap();
    assert_eq!(startup_open, original_open);
    let handle = second.handle.clone();
    let retry = tokio::spawn(async move { handle.create(owner(), request("generation")).await });
    let retry_open = second.sent_rx.recv().await.unwrap();
    assert_eq!(retry_open, original_open);
    assert!(
        !retry.is_finished(),
        "old generation ACK must not authorize replay"
    );
    second.event_tx.send(Ok(opened(&retry_open))).unwrap();
    let replay = retry.await.unwrap().unwrap();
    assert_eq!(replay, original);

    second
        .event_tx
        .send(Err(pairing_error("remote.transport.closed")))
        .unwrap();
    let reconnected_open = second.sent_rx.recv().await.unwrap();
    assert_eq!(reconnected_open, original_open);
    assert_eq!(second.reconnects.load(Ordering::SeqCst), 1);
    second.stop().await;
}

#[tokio::test]
async fn recoverable_startup_open_failure_keeps_actor_and_reopens_after_reconnect() {
    let store = Arc::new(FakeStore::default());
    let mut first = spawn_actor(Arc::clone(&store)).await;
    let handle = first.handle.clone();
    let create =
        tokio::spawn(async move { handle.create(owner(), request("startup-retry")).await });
    let original_open = first.sent_rx.recv().await.unwrap();
    first.event_tx.send(Ok(opened(&original_open))).unwrap();
    create.await.unwrap().unwrap();
    first.stop().await;

    let (mut second, ready) =
        spawn_actor_with_startup_send_failure(Arc::clone(&store), Some("remote.transport.closed"))
            .await;
    let ready_error = ready.expect_err("startup Open must surface the transient failure");
    assert_eq!(ready_error.code(), "remote.transport.closed");
    recoverable_startup_ready(Err(ready_error))
        .expect("transport startup failure must not become a sticky manager block");

    let reopened = tokio::time::timeout(Duration::from_secs(2), second.sent_rx.recv())
        .await
        .expect("pairing actor must retry after its startup failure")
        .expect("reconnected lane must receive the durable Open");
    assert_eq!(reopened, original_open);
    assert_eq!(second.reconnects.load(Ordering::SeqCst), 1);
    second.stop().await;
}

#[tokio::test(start_paused = true)]
async fn persistent_reconnect_tick_is_not_starved_by_sustained_commands() {
    let store = Arc::new(FakeStore::default());
    let mut first = spawn_actor(Arc::clone(&store)).await;
    let handle = first.handle.clone();
    let create =
        tokio::spawn(async move { handle.create(owner(), request("reconnect-tick")).await });
    let original_open = first.sent_rx.recv().await.unwrap();
    first.event_tx.send(Ok(opened(&original_open))).unwrap();
    create.await.unwrap().unwrap();
    let pairing_id = store.single_id();
    first.stop().await;

    let (mut second, ready) =
        spawn_actor_with_startup_send_failure(Arc::clone(&store), Some("remote.transport.closed"))
            .await;
    assert_eq!(ready.unwrap_err().code(), "remote.transport.closed");

    // 每100ms投递一个可立即处理的command。若每轮重建sleep，deadline会不断后移；持久
    // interval则仍会在总虚拟时间1s时触发reconnect。
    for _ in 0..11 {
        tokio::time::advance(Duration::from_millis(100)).await;
        let error = second.handle.confirm(pairing_id).await.unwrap_err();
        assert_eq!(error.code(), PAIRING_REQUEST_INVALID);
    }
    let reopened = second.sent_rx.recv().await.unwrap();
    assert_eq!(reopened, original_open);
    assert_eq!(second.reconnects.load(Ordering::SeqCst), 1);
    second.stop().await;
}

#[tokio::test]
async fn startup_due_only_replays_frozen_close_before_any_active_open() {
    let order = Arc::new(StdMutex::new(Vec::new()));
    let store = Arc::new(FakeStore::with_order(Arc::clone(&order)));
    let mut first = spawn_actor(Arc::clone(&store)).await;
    let handle = first.handle.clone();
    let create = tokio::spawn(async move { handle.create(owner(), request("startup-due")).await });
    let original_open = first.sent_rx.recv().await.unwrap();
    let pairing_id = store.single_id();
    store.mark_due(pairing_id);
    first.stop().await;
    assert_eq!(create.await.unwrap().unwrap_err().code(), PAIRING_STOPPED);

    let mut second = spawn_actor(Arc::clone(&store)).await;
    let close = second.sent_close_rx.recv().await.unwrap();
    assert_eq!(close.machine_route, original_open.machine_route);
    assert_eq!(close.pair_route, original_open.pair_route);
    assert!(
        second.sent_rx.try_recv().is_err(),
        "terminal route must not reopen"
    );
    assert_eq!(store.lifecycle(pairing_id), PairingInviteLifecycle::Expired);
    assert!(store.has_secret_row(pairing_id));
    {
        let observed = order.lock().unwrap();
        let terminal = observed
            .iter()
            .position(|entry| *entry == "expiry-terminal-commit")
            .unwrap();
        let sent = observed
            .iter()
            .position(|entry| *entry == "send-close")
            .unwrap();
        assert!(terminal < sent);
    }
    second.stop().await;
}

#[tokio::test]
async fn cancel_route_opening_fails_waiter_and_scrubs_only_after_exact_close_ack() {
    let store = Arc::new(FakeStore::default());
    let mut actor = spawn_actor(Arc::clone(&store)).await;
    let handle = actor.handle.clone();
    let create =
        tokio::spawn(async move { handle.create(owner(), request("cancel-opening")).await });
    let open = actor.sent_rx.recv().await.unwrap();
    let pairing_id = store.single_id();

    let receipt = actor.handle.cancel(pairing_id).await.unwrap();
    assert!(matches!(receipt, PairingReceipt::Canceled { .. }));
    assert_eq!(create.await.unwrap().unwrap_err().code(), PAIRING_CANCELED);
    let close = actor.sent_close_rx.recv().await.unwrap();
    assert_eq!(close.pair_route, open.pair_route);
    assert_eq!(store.count(), 1, "Close ACK 前必须保留 pairing row");
    assert!(
        store.has_secret_row(pairing_id),
        "Close ACK 前不得擦除 secret"
    );

    let retry_error = tokio::time::timeout(
        Duration::from_secs(1),
        actor.handle.create(owner(), request("cancel-opening")),
    )
    .await
    .expect("terminal create retry must not hang")
    .unwrap_err();
    assert_eq!(retry_error.code(), PAIRING_CANCELED);
    assert!(actor.sent_rx.try_recv().is_err());

    let terminal = PairRouteClosed {
        pair_route: close.pair_route,
        outcome: PairRouteCloseOutcome::Closed,
    };
    let canonical_terminal = encode(&OpaqueRouteFrame {
        version: RELAY_PROTOCOL_VERSION,
        body: RelayFrameBody::PairRouteClosed(terminal.clone()),
    });
    actor
        .event_tx
        .send(Ok(PairingTransportEvent::PairRouteClosed(terminal)))
        .unwrap();
    tokio::time::timeout(Duration::from_secs(1), async {
        while store.count() != 0 {
            tokio::task::yield_now().await;
        }
    })
    .await
    .expect("exact Close ACK must scrub the secret row");
    assert_eq!(
        store.last_close_ack().as_deref(),
        Some(&canonical_terminal[..])
    );

    let after_ack_retry = actor
        .handle
        .create(owner(), request("cancel-opening"))
        .await
        .unwrap_err();
    assert_eq!(after_ack_retry.code(), PAIRING_CANCELED);
    assert!(
        actor.sent_rx.try_recv().is_err(),
        "terminal retry must not send Open"
    );

    let replay = actor.handle.cancel(pairing_id).await.unwrap();
    assert!(matches!(
        replay,
        PairingReceipt::Replayed {
            decision: PairingDecision::Cancel,
            state: PairingState::ClosedTombstone,
            ..
        }
    ));
    actor.stop().await;
}

#[tokio::test]
async fn expiry_tick_wins_cancel_and_replays_unacked_frozen_close() {
    let store = Arc::new(FakeStore::default());
    let mut actor = spawn_actor(Arc::clone(&store)).await;
    let handle = actor.handle.clone();
    let create = tokio::spawn(async move { handle.create(owner(), request("tick-expiry")).await });
    let open = actor.sent_rx.recv().await.unwrap();
    let pairing_id = store.single_id();
    store.mark_due(pairing_id);

    let first_close = tokio::time::timeout(Duration::from_secs(2), actor.sent_close_rx.recv())
        .await
        .expect("bounded expiry tick must emit durable Close")
        .unwrap();
    assert_eq!(first_close.pair_route, open.pair_route);
    assert_eq!(create.await.unwrap().unwrap_err().code(), PAIRING_EXPIRED);

    let loser = actor.handle.cancel(pairing_id).await.unwrap();
    assert!(matches!(
        loser,
        PairingReceipt::AlreadyHandled {
            winner: PairingDecision::Expire,
            state: PairingState::Expired,
            ..
        }
    ));
    let cancel_replay = actor.sent_close_rx.recv().await.unwrap();
    assert_eq!(cancel_replay, first_close);
    let periodic_replay = tokio::time::timeout(Duration::from_secs(2), actor.sent_close_rx.recv())
        .await
        .expect("unacked durable Close must be retried by the next tick")
        .unwrap();
    assert_eq!(periodic_replay, first_close);
    assert!(store.has_secret_row(pairing_id));
    actor.stop().await;
}

#[test]
fn startup_ready_only_recovers_transport_and_relay_failures() {
    for code in ["remote.transport.closed", "relay.client.connection_lost"] {
        recoverable_startup_ready(Err(pairing_error(code))).unwrap();
    }
    for code in [
        "daemon.runtime.store_unavailable",
        "daemon.security.key_unavailable",
        PAIRING_INVITE_INVALID,
        PAIRING_STOPPED,
    ] {
        assert_eq!(
            recoverable_startup_ready(Err(pairing_error(code)))
                .unwrap_err()
                .code(),
            code
        );
    }
}

#[tokio::test]
async fn receipt_retention_purge_failure_blocks_startup_before_recovery() {
    let store = Arc::new(FakeStore::default());
    store.fail_receipt_purge(true);

    let (actor, ready) = spawn_actor_with_startup_send_failure(Arc::clone(&store), None).await;

    assert_eq!(
        ready
            .expect_err("retention audit failure must block startup")
            .code(),
        "daemon.runtime.store_unavailable"
    );
    assert_eq!(store.receipt_purge_calls(), 1);
    assert_eq!(store.recovery_calls(), 0);
    actor.stop().await;
}

#[tokio::test(start_paused = true)]
async fn receipt_retention_purge_reuses_startup_and_existing_expiry_tick() {
    let store = Arc::new(FakeStore::default());
    let actor = spawn_actor(Arc::clone(&store)).await;

    assert_eq!(store.receipt_purge_calls(), 1);
    assert_eq!(store.recovery_calls(), 1);

    for expected in [2, 3] {
        tokio::time::advance(EXPIRY_RECONCILE_INTERVAL).await;
        for _ in 0..16 {
            if store.receipt_purge_calls() == expected {
                break;
            }
            tokio::task::yield_now().await;
        }
        assert_eq!(store.receipt_purge_calls(), expected);
        assert_eq!(store.recovery_calls(), 1);
    }

    actor.stop().await;
}

#[tokio::test]
async fn pregrant_drain_is_nonblocking_rejects_new_authority_and_waits_for_close_ack() {
    let store = Arc::new(FakeStore::default());
    let mut actor = spawn_actor(Arc::clone(&store)).await;
    let handle = actor.handle.clone();
    let create = tokio::spawn(async move { handle.create(owner(), request("drain")).await });
    let open = actor.sent_rx.recv().await.unwrap();
    let pairing_id = store.single_id();
    let drain_handle = actor.handle.clone();
    let drain = tokio::spawn(async move { drain_handle.begin_drain().await });
    let close = actor.sent_close_rx.recv().await.unwrap();
    assert_eq!(close.pair_route, open.pair_route);
    assert!(!drain.is_finished(), "Close ACK 前 drain 不得完成");
    assert_eq!(create.await.unwrap().unwrap_err().code(), PAIRING_CANCELED);

    assert_eq!(
        actor
            .handle
            .create(owner(), request("drain-rejected"))
            .await
            .unwrap_err()
            .code(),
        PAIRING_DRAINING
    );
    assert_eq!(
        actor.handle.confirm(pairing_id).await.unwrap_err().code(),
        PAIRING_DRAINING
    );
    assert_eq!(
        actor
            .handle
            .revoke_device(
                DeviceHandle::new("device-11111111111111111111111111111111"),
                RuntimeGrantSerial::new(1),
            )
            .await
            .unwrap_err()
            .code(),
        PAIRING_DRAINING
    );

    actor
        .event_tx
        .send(Ok(PairingTransportEvent::PairRouteClosed(
            PairRouteClosed {
                pair_route: close.pair_route,
                outcome: PairRouteCloseOutcome::Closed,
            },
        )))
        .unwrap();
    drain.await.unwrap().unwrap();
    assert_eq!(store.count(), 0);
    actor.handle.begin_drain().await.unwrap();
    actor.handle.resume_after_failed_drain().await.unwrap();
    let resumed_handle = actor.handle.clone();
    let resumed = tokio::spawn(async move {
        resumed_handle
            .create(owner(), request("drain-resumed"))
            .await
    });
    let reopened = actor.sent_rx.recv().await.unwrap();
    actor.event_tx.send(Ok(opened(&reopened))).unwrap();
    resumed.await.unwrap().unwrap();
    actor.stop().await;
}

#[tokio::test]
async fn grant_preparing_drain_preserves_exact_install_ack_revoke_ack_close_order() {
    let store = Arc::new(FakeStore::default());
    let mut actor = spawn_actor(Arc::clone(&store)).await;
    let (invite, pairing_id) =
        create_pending_pairing(&mut actor, "drain-grant-preparing", 0x91).await;
    actor.handle.confirm(pairing_id).await.unwrap();
    let install = actor.sent_grant_rx.recv().await.unwrap();
    store.order.lock().unwrap().clear();

    let drain_handle = actor.handle.clone();
    let drain = tokio::spawn(async move { drain_handle.begin_drain().await });
    let replayed_install = actor.sent_grant_rx.recv().await.unwrap();
    assert_eq!(replayed_install, install);
    assert_eq!(
        store.lifecycle(pairing_id),
        PairingInviteLifecycle::OrphanRevoking
    );
    assert!(actor.sent_revoke_rx.try_recv().is_err());
    assert!(!drain.is_finished());

    actor
        .event_tx
        .send(Ok(PairingTransportEvent::GrantCommitted(grant_committed(
            &replayed_install,
        ))))
        .unwrap();
    let revoke = actor.sent_revoke_rx.recv().await.unwrap();
    actor
        .event_tx
        .send(Ok(PairingTransportEvent::RevocationCommitted(
            revocation_committed(&revoke),
        )))
        .unwrap();
    let close = actor.sent_close_rx.recv().await.unwrap();
    assert_eq!(close.pair_route, invite.invite.pair_route);
    assert!(!drain.is_finished());
    actor
        .event_tx
        .send(Ok(PairingTransportEvent::PairRouteClosed(
            PairRouteClosed {
                pair_route: close.pair_route,
                outcome: PairRouteCloseOutcome::Closed,
            },
        )))
        .unwrap();
    drain.await.unwrap().unwrap();

    {
        let order = store.order.lock().unwrap();
        let begin = order
            .iter()
            .position(|entry| *entry == "revocation-commit")
            .unwrap();
        let install_send = order
            .iter()
            .position(|entry| *entry == "send-grant")
            .unwrap();
        let grant_ack = order
            .iter()
            .position(|entry| *entry == "orphan-grant-ack-commit")
            .unwrap();
        let revoke_send = order
            .iter()
            .position(|entry| *entry == "send-revoke")
            .unwrap();
        let revoke_ack = order
            .iter()
            .position(|entry| *entry == "revocation-ack-commit")
            .unwrap();
        let close_send = order
            .iter()
            .position(|entry| *entry == "send-close")
            .unwrap();
        assert!(begin < install_send && install_send < grant_ack && grant_ack < revoke_send);
        assert!(revoke_send < revoke_ack && revoke_ack < close_send);
    }
    {
        let state = store.state.lock().unwrap();
        assert!(state.by_id.is_empty());
        assert!(state.revocations.is_empty());
        assert!(
            state
                .authorizations
                .keys()
                .all(|key| state.revoked.contains_key(key))
        );
    }
    actor.stop().await;
}

#[tokio::test]
async fn drain_restart_and_reconnect_replay_only_the_current_durable_frame() {
    let store = Arc::new(FakeStore::default());
    let mut first = spawn_actor(Arc::clone(&store)).await;
    let (_, pairing_id) = create_pending_pairing(&mut first, "drain-restart", 0x92).await;
    first.handle.confirm(pairing_id).await.unwrap();
    let install = first.sent_grant_rx.recv().await.unwrap();
    let first_handle = first.handle.clone();
    let first_drain = tokio::spawn(async move { first_handle.begin_drain().await });
    assert_eq!(first.sent_grant_rx.recv().await.unwrap(), install);
    first.stop().await;
    assert_eq!(
        first_drain.await.unwrap().unwrap_err().code(),
        PAIRING_STOPPED
    );

    let mut second = spawn_actor(Arc::clone(&store)).await;
    let startup_install = second.sent_grant_rx.recv().await.unwrap();
    assert_eq!(startup_install, install);
    assert!(second.sent_rx.try_recv().is_err());
    let second_handle = second.handle.clone();
    let drain = tokio::spawn(async move { second_handle.begin_drain().await });
    assert_eq!(second.sent_grant_rx.recv().await.unwrap(), install);

    second
        .event_tx
        .send(Err(pairing_error("remote.transport.closed")))
        .unwrap();
    assert_eq!(second.sent_grant_rx.recv().await.unwrap(), install);
    assert_eq!(second.reconnects.load(Ordering::SeqCst), 1);
    assert!(second.sent_revoke_rx.try_recv().is_err());

    second
        .event_tx
        .send(Ok(PairingTransportEvent::GrantCommitted(grant_committed(
            &install,
        ))))
        .unwrap();
    let revoke = second.sent_revoke_rx.recv().await.unwrap();
    second
        .event_tx
        .send(Err(pairing_error("remote.transport.closed")))
        .unwrap();
    assert_eq!(second.sent_revoke_rx.recv().await.unwrap(), revoke);
    assert_eq!(second.reconnects.load(Ordering::SeqCst), 2);

    second
        .event_tx
        .send(Ok(PairingTransportEvent::RevocationCommitted(
            revocation_committed(&revoke),
        )))
        .unwrap();
    let close = second.sent_close_rx.recv().await.unwrap();
    second
        .event_tx
        .send(Err(pairing_error("remote.transport.closed")))
        .unwrap();
    assert_eq!(second.sent_close_rx.recv().await.unwrap(), close);
    assert_eq!(second.reconnects.load(Ordering::SeqCst), 3);
    assert!(!drain.is_finished());

    second.event_tx.send(Ok(closed(&close))).unwrap();
    drain.await.unwrap().unwrap();
    assert_eq!(store.count(), 0);
    second.stop().await;
}

#[tokio::test(start_paused = true)]
async fn drain_ack_faults_keep_exact_recovery_pending_until_store_ack_succeeds() {
    let store = Arc::new(FakeStore::default());
    let mut actor = spawn_actor(Arc::clone(&store)).await;
    let (_, _pairing_id, _) =
        create_committed_pairing(&mut actor, &store, "drain-ack-fault", 0x93).await;
    let drain_handle = actor.handle.clone();
    let drain = tokio::spawn(async move { drain_handle.begin_drain().await });
    let revoke = actor.sent_revoke_rx.recv().await.unwrap();

    store.fail_revocation_ack(true);
    actor
        .event_tx
        .send(Ok(PairingTransportEvent::RevocationCommitted(
            revocation_committed(&revoke),
        )))
        .unwrap();
    tokio::task::yield_now().await;
    assert!(!drain.is_finished());
    assert!(actor.sent_close_rx.try_recv().is_err());
    tokio::time::advance(EXPIRY_RECONCILE_INTERVAL).await;
    let replayed_revoke = actor.sent_revoke_rx.recv().await.unwrap();
    assert_eq!(replayed_revoke, revoke);

    store.fail_revocation_ack(false);
    actor
        .event_tx
        .send(Ok(PairingTransportEvent::RevocationCommitted(
            revocation_committed(&replayed_revoke),
        )))
        .unwrap();
    let close = actor.sent_close_rx.recv().await.unwrap();
    store.fail_close_ack_before_commit(true);
    actor.event_tx.send(Ok(closed(&close))).unwrap();
    tokio::task::yield_now().await;
    assert!(!drain.is_finished());
    assert_eq!(store.count(), 1);
    tokio::time::advance(EXPIRY_RECONCILE_INTERVAL).await;
    let replayed_close = actor.sent_close_rx.recv().await.unwrap();
    assert_eq!(replayed_close, close);

    store.fail_close_ack_before_commit(false);
    actor.event_tx.send(Ok(closed(&replayed_close))).unwrap();
    drain.await.unwrap().unwrap();
    assert_eq!(store.count(), 0);
    {
        let state = store.state.lock().unwrap();
        assert!(state.revocations.is_empty());
        assert!(
            state
                .authorizations
                .keys()
                .all(|key| state.revoked.contains_key(key))
        );
    }
    actor.stop().await;
}

#[tokio::test]
async fn mixed_committed_delivered_and_standalone_authorizations_drain_serially() {
    let store = Arc::new(FakeStore::default());
    let mut actor = spawn_actor(Arc::clone(&store)).await;
    let (committed_invite, committed_id, _) =
        create_committed_pairing(&mut actor, &store, "drain-mixed-committed", 0x94).await;
    let (delivered_invite, delivered_id, delivered_close) =
        create_delivered_pairing(&mut actor, &store, "drain-mixed-delivered", 0x95).await;
    let (_, standalone_id, standalone_close) =
        create_delivered_pairing(&mut actor, &store, "drain-mixed-standalone", 0x96).await;
    actor.event_tx.send(Ok(closed(&standalone_close))).unwrap();
    for _ in 0..16 {
        if store.count() == 2 {
            break;
        }
        tokio::task::yield_now().await;
    }
    assert_eq!(store.count(), 2);

    let drain_handle = actor.handle.clone();
    let drain = tokio::spawn(async move { drain_handle.begin_drain().await });
    assert_eq!(actor.sent_close_rx.recv().await.unwrap(), delivered_close);
    let committed_revoke = actor.sent_revoke_rx.recv().await.unwrap();
    assert_eq!(
        committed_revoke.revocation.device_route.as_bytes(),
        committed_id.as_bytes()
    );
    actor
        .event_tx
        .send(Ok(PairingTransportEvent::RevocationCommitted(
            revocation_committed(&committed_revoke),
        )))
        .unwrap();
    let committed_close = actor.sent_close_rx.recv().await.unwrap();
    assert_eq!(
        committed_close.pair_route,
        committed_invite.invite.pair_route
    );
    let delivered_revoke = actor.sent_revoke_rx.recv().await.unwrap();
    assert_eq!(
        delivered_revoke.revocation.device_route.as_bytes(),
        delivered_id.as_bytes()
    );

    actor.event_tx.send(Ok(closed(&committed_close))).unwrap();
    actor
        .event_tx
        .send(Ok(PairingTransportEvent::RevocationCommitted(
            revocation_committed(&delivered_revoke),
        )))
        .unwrap();
    let standalone_revoke = actor.sent_revoke_rx.recv().await.unwrap();
    assert_eq!(
        standalone_revoke.revocation.device_route.as_bytes(),
        standalone_id.as_bytes()
    );
    actor.event_tx.send(Ok(closed(&delivered_close))).unwrap();
    assert!(!drain.is_finished());
    actor
        .event_tx
        .send(Ok(PairingTransportEvent::RevocationCommitted(
            revocation_committed(&standalone_revoke),
        )))
        .unwrap();
    drain.await.unwrap().unwrap();

    assert_eq!(
        delivered_close.pair_route,
        delivered_invite.invite.pair_route
    );
    {
        let state = store.state.lock().unwrap();
        assert!(state.by_id.is_empty());
        assert!(state.revocations.is_empty());
        assert!(
            state
                .authorizations
                .keys()
                .all(|key| state.revoked.contains_key(key))
        );
    }
    actor.stop().await;
}

#[tokio::test]
async fn failed_drain_resume_waits_for_capacity_and_only_closed_channel_stops_it() {
    let (command_tx, mut command_rx) = mpsc::channel(PAIRING_COMMAND_CAPACITY);
    let handle = PairingCoordinatorHandle { command_tx };
    for _ in 0..PAIRING_COMMAND_CAPACITY {
        let (reply, _ignored) = oneshot::channel();
        handle
            .command_tx
            .try_send(PairingCommand::BeginDrain { reply })
            .unwrap();
    }

    let resume_handle = handle.clone();
    let resume = tokio::spawn(async move { resume_handle.resume_after_failed_drain().await });
    tokio::task::yield_now().await;
    assert!(
        !resume.is_finished(),
        "a full command queue must apply backpressure instead of reporting busy"
    );

    let mut draining = true;
    while let Some(command) = command_rx.recv().await {
        match command {
            PairingCommand::BeginDrain { reply } => {
                let _ = reply.send(Ok(()));
            }
            PairingCommand::ResumeAfterFailedDrain { reply } => {
                draining = false;
                let _ = reply.send(Ok(()));
                break;
            }
            PairingCommand::Create { .. }
            | PairingCommand::Cancel { .. }
            | PairingCommand::Confirm { .. }
            | PairingCommand::RevokeDevice { .. } => {
                panic!("unexpected pairing command")
            }
        }
    }
    resume.await.unwrap().unwrap();
    assert!(!draining, "the queued resume command must take effect");

    let (closed_tx, closed_rx) = mpsc::channel(PAIRING_COMMAND_CAPACITY);
    drop(closed_rx);
    let error = PairingCoordinatorHandle {
        command_tx: closed_tx,
    }
    .resume_after_failed_drain()
    .await
    .unwrap_err();
    assert_eq!(error.code(), PAIRING_STOPPED);
}

#[tokio::test]
async fn transport_failure_fails_waiter_but_reconnects_and_reopens_durable_route() {
    let store = Arc::new(FakeStore::default());
    let mut actor = spawn_actor(Arc::clone(&store)).await;
    let handle = actor.handle.clone();
    let create = tokio::spawn(async move { handle.create(owner(), request("failure")).await });
    let open = actor.sent_rx.recv().await.unwrap();
    actor
        .event_tx
        .send(Err(pairing_error(
            "remote.transport.pairing_binding_mismatch",
        )))
        .unwrap();
    let error = create.await.unwrap().unwrap_err();
    assert_eq!(error.code(), PAIRING_TRANSPORT);
    let reopened = actor.sent_rx.recv().await.unwrap();
    assert_eq!(reopened, open);
    assert_eq!(actor.reconnects.load(Ordering::SeqCst), 1);
    assert_eq!(store.count(), 1);
    actor.stop().await;
}

#[tokio::test]
async fn active_invite_directory_stops_at_eight_without_sending_a_ninth_open() {
    let store = Arc::new(FakeStore::default());
    let mut actor = spawn_actor(Arc::clone(&store)).await;
    for ordinal in 0..8 {
        let handle = actor.handle.clone();
        let create = tokio::spawn(async move {
            handle
                .create(owner(), request(&format!("capacity-{ordinal}")))
                .await
        });
        let open = actor.sent_rx.recv().await.unwrap();
        actor.event_tx.send(Ok(opened(&open))).unwrap();
        create.await.unwrap().unwrap();
    }
    let error = actor
        .handle
        .create(owner(), request("capacity-8"))
        .await
        .unwrap_err();
    assert_eq!(error.code(), "daemon.runtime.store_full");
    assert_eq!(store.count(), 8);
    assert!(actor.sent_rx.try_recv().is_err());
    actor.stop().await;
}

#[tokio::test]
async fn verified_pair_request_commits_pending_before_exact_send_and_local_publish() {
    let order = Arc::new(StdMutex::new(Vec::new()));
    let store = Arc::new(FakeStore::with_order(Arc::clone(&order)));
    let mut actor = spawn_actor(Arc::clone(&store)).await;
    let invite = create_opened_invite(&mut actor, "pair-request").await;
    let request = pair_request(&invite.invite, 0x61);
    actor
        .event_tx
        .send(Ok(PairingTransportEvent::PairData(request)))
        .unwrap();
    let pending = actor.sent_data_rx.recv().await.unwrap();
    {
        let observed = order.lock().unwrap();
        let accepted = observed
            .iter()
            .position(|entry| *entry == "accept-commit")
            .unwrap();
        let committed = observed
            .iter()
            .position(|entry| *entry == "pending-commit")
            .unwrap();
        let sent = observed
            .iter()
            .position(|entry| *entry == "send-pending")
            .unwrap();
        assert!(accepted < committed && committed < sent);
    }
    assert_eq!(actor.seals.load(Ordering::SeqCst), 1);
    let listed = store.pending_list();
    assert_eq!(listed.len(), 1);
    assert_eq!(pending.pair_route, invite.invite.pair_route);
    tokio::task::yield_now().await;
    assert_eq!(&*actor.published.lock().unwrap(), &listed);
    actor.stop().await;
}

#[tokio::test]
async fn same_request_replays_frozen_pending_and_different_request_fails_closed() {
    let store = Arc::new(FakeStore::default());
    let mut actor = spawn_actor(Arc::clone(&store)).await;
    let invite = create_opened_invite(&mut actor, "exact-request").await;
    let request = pair_request(&invite.invite, 0x62);
    actor
        .event_tx
        .send(Ok(PairingTransportEvent::PairData(request.clone())))
        .unwrap();
    let first = actor.sent_data_rx.recv().await.unwrap();
    actor
        .event_tx
        .send(Ok(PairingTransportEvent::PairData(request)))
        .unwrap();
    let replay = actor.sent_data_rx.recv().await.unwrap();
    assert_eq!(replay, first);
    assert_eq!(actor.seals.load(Ordering::SeqCst), 1);

    actor
        .event_tx
        .send(Ok(PairingTransportEvent::PairData(pair_request(
            &invite.invite,
            0x63,
        ))))
        .unwrap();
    assert!(
        tokio::time::timeout(Duration::from_millis(30), actor.sent_data_rx.recv())
            .await
            .is_err()
    );
    assert_eq!(actor.seals.load(Ordering::SeqCst), 1);
    assert_eq!(store.pending_list().len(), 1);
    actor.stop().await;
}

#[tokio::test]
async fn preparing_and_awaiting_recovery_drive_or_replay_without_second_seal() {
    let store = Arc::new(FakeStore::default());
    let mut first = spawn_actor(Arc::clone(&store)).await;
    let invite = create_opened_invite(&mut first, "recovery-pending").await;
    let pairing_id =
        RuntimeId::parse_canonical(RuntimeIdKind::Pairing, invite.pairing_id.as_str()).unwrap();
    let request_data = pair_request(&invite.invite, 0x64);
    first.stop().await;

    let request = PairRequestV1::from_canonical_bytes(&request_data.sealed_blob.0).unwrap();
    let mut durable = store.load(pairing_id).await.unwrap().unwrap();
    let private = durable.invite_hpke_private_key.take().unwrap();
    let info = pair_request_info(&invite.invite).unwrap();
    let context = pairing_context(invite.invite.pair_route, OuterFrameKind::PairRequest);
    let verified = open_pair_request_verified(
        &private,
        &info,
        &context,
        &invite.invite.invite_secret,
        &request,
    )
    .unwrap();
    store.accept_request(pairing_id, verified).await.unwrap();
    assert_eq!(
        store.lifecycle(pairing_id),
        PairingInviteLifecycle::Preparing
    );

    let mut second = spawn_actor(Arc::clone(&store)).await;
    let reopen = second.sent_rx.recv().await.unwrap();
    second.event_tx.send(Ok(opened(&reopen))).unwrap();
    let frozen = second.sent_data_rx.recv().await.unwrap();
    assert_eq!(second.seals.load(Ordering::SeqCst), 1);
    assert_eq!(
        store.lifecycle(pairing_id),
        PairingInviteLifecycle::AwaitingLocalConfirmation
    );
    second.stop().await;

    let mut third = spawn_actor(Arc::clone(&store)).await;
    let reopen = third.sent_rx.recv().await.unwrap();
    third.event_tx.send(Ok(opened(&reopen))).unwrap();
    let replay = third.sent_data_rx.recv().await.unwrap();
    assert_eq!(replay, frozen);
    assert_eq!(third.seals.load(Ordering::SeqCst), 0);
    third.stop().await;
}

#[tokio::test]
async fn sink_failure_does_not_block_remote_pending_and_list_remains_authoritative() {
    let store = Arc::new(FakeStore::default());
    let mut actor = spawn_actor(Arc::clone(&store)).await;
    actor.sink_fail.store(true, Ordering::SeqCst);
    let invite = create_opened_invite(&mut actor, "sink-failure").await;
    actor
        .event_tx
        .send(Ok(PairingTransportEvent::PairData(pair_request(
            &invite.invite,
            0x65,
        ))))
        .unwrap();
    actor.sent_data_rx.recv().await.unwrap();
    assert!(actor.published.lock().unwrap().is_empty());
    assert_eq!(store.pending_list().len(), 1);
    actor.stop().await;
}

#[tokio::test]
async fn create_retry_in_pending_states_waits_for_generation_ack_then_returns_exact_invite() {
    let store = Arc::new(FakeStore::default());
    let mut first = spawn_actor(Arc::clone(&store)).await;
    let original = create_opened_invite(&mut first, "pending-create-retry").await;
    first
        .event_tx
        .send(Ok(PairingTransportEvent::PairData(pair_request(
            &original.invite,
            0x66,
        ))))
        .unwrap();
    first.sent_data_rx.recv().await.unwrap();
    let immediate = first
        .handle
        .create(owner(), request("pending-create-retry"))
        .await
        .unwrap();
    assert_eq!(immediate, original);
    first.stop().await;

    let mut second = spawn_actor(Arc::clone(&store)).await;
    let reopen = second.sent_rx.recv().await.unwrap();
    let handle = second.handle.clone();
    let retry = tokio::spawn(async move {
        handle
            .create(owner(), request("pending-create-retry"))
            .await
    });
    let duplicate_open = second.sent_rx.recv().await.unwrap();
    assert_eq!(duplicate_open, reopen);
    assert!(!retry.is_finished());
    second.event_tx.send(Ok(opened(&reopen))).unwrap();
    let replay = retry.await.unwrap().unwrap();
    assert_eq!(replay, original);
    second.sent_data_rx.recv().await.unwrap();
    second.stop().await;
}

#[tokio::test]
async fn withheld_ack_keeps_total_waiters_bounded() {
    let store = Arc::new(FakeStore::default());
    let mut actor = spawn_actor(Arc::clone(&store)).await;
    let mut retries = Vec::new();
    for _ in 0..PAIRING_COMMAND_CAPACITY {
        let handle = actor.handle.clone();
        retries.push(tokio::spawn(async move {
            handle.create(owner(), request("bounded-waiters")).await
        }));
        actor.sent_rx.recv().await.unwrap();
    }
    let error = actor
        .handle
        .create(owner(), request("bounded-waiters"))
        .await
        .unwrap_err();
    assert_eq!(error.code(), PAIRING_BUSY);
    let open = actor.sent_rx.try_recv().unwrap_err();
    assert!(matches!(open, mpsc::error::TryRecvError::Empty));
    actor.cancel_tx.send_replace(true);
    for retry in retries {
        assert_eq!(retry.await.unwrap().unwrap_err().code(), PAIRING_STOPPED);
    }
    tokio::time::timeout(Duration::from_secs(1), actor.task)
        .await
        .unwrap()
        .unwrap();
}

#[test]
fn pairing_actor_command_capacity_matches_active_invite_cap() {
    assert_eq!(PAIRING_COMMAND_CAPACITY, 8);
}

#[test]
fn create_terminal_replay_uses_stable_non_rebuilding_failures() {
    let pairing_id = PairingId::new("pairing-00000000-0000-0000-0000-000000000001");
    for (receipt, expected) in [
        (
            PairingReceipt::Canceled {
                pairing_id: pairing_id.clone(),
            },
            PAIRING_CANCELED,
        ),
        (
            PairingReceipt::Expired {
                pairing_id: pairing_id.clone(),
            },
            PAIRING_EXPIRED,
        ),
        (
            PairingReceipt::Confirmed { pairing_id },
            PAIRING_ALREADY_COMPLETED,
        ),
    ] {
        assert_eq!(create_terminal_error(receipt).code(), expected);
    }
}

#[tokio::test]
async fn confirm_and_grant_ack_commit_before_exact_install_and_response_sends() {
    let order = Arc::new(StdMutex::new(Vec::new()));
    let store = Arc::new(FakeStore::with_order(Arc::clone(&order)));
    let mut actor = spawn_actor(Arc::clone(&store)).await;
    let (invite, pairing_id) =
        create_pending_pairing(&mut actor, "confirm-durable-first", 0x7a).await;

    let receipt = actor.handle.confirm(pairing_id).await.unwrap();
    assert!(matches!(receipt, PairingReceipt::Confirmed { .. }));
    let first = actor.sent_grant_rx.recv().await.unwrap();
    {
        let observed = order.lock().unwrap();
        let committed = observed
            .iter()
            .position(|entry| *entry == "grant-commit")
            .unwrap();
        let sent = observed
            .iter()
            .position(|entry| *entry == "send-grant")
            .unwrap();
        assert!(committed < sent, "InstallGrant must follow durable COMMIT");
    }
    assert_eq!(actor.grant_freezes.load(Ordering::SeqCst), 1);
    assert_eq!(&*actor.grant_axes.lock().unwrap(), &[(1, 1)]);

    let replay = actor.handle.confirm(pairing_id).await.unwrap();
    assert!(matches!(
        replay,
        PairingReceipt::Replayed {
            decision: PairingDecision::Confirm,
            state: PairingState::GrantPreparing,
            ..
        }
    ));
    assert_eq!(actor.sent_grant_rx.recv().await.unwrap(), first);
    assert_eq!(actor.grant_freezes.load(Ordering::SeqCst), 1);

    actor
        .event_tx
        .send(Ok(PairingTransportEvent::PairFrameAccepted(
            agentdeck_protocol::relay_v2::frame::RouteAccepted {
                accepted: agentdeck_protocol::relay_v2::frame::AcceptedRef::PairFrame {
                    pair_route: store
                        .state
                        .lock()
                        .unwrap()
                        .by_id
                        .get(&pairing_id)
                        .unwrap()
                        .pair_route,
                },
            },
        )))
        .unwrap();
    tokio::task::yield_now().await;
    assert_eq!(
        store.lifecycle(pairing_id),
        PairingInviteLifecycle::GrantPreparing,
        "RouteAccepted must not advance endpoint delivery state"
    );
    assert!(actor.sent_data_rx.try_recv().is_err());

    let committed = grant_committed(&first);
    actor
        .event_tx
        .send(Ok(PairingTransportEvent::GrantCommitted(committed.clone())))
        .unwrap();
    let response = actor.sent_data_rx.recv().await.unwrap();
    assert_eq!(
        store.lifecycle(pairing_id),
        PairingInviteLifecycle::GrantCommitted
    );
    assert_eq!(response, store.committed_response(pairing_id));
    assert_eq!(response.pair_route, invite.invite.pair_route);
    let (canonical_response, response_hash) = {
        let state = store.state.lock().unwrap();
        let durable = state.committed.get(&pairing_id).unwrap();
        (
            durable.canonical_pair_response.clone(),
            durable.response_hash,
        )
    };
    assert_eq!(response.sealed_blob.0, canonical_response);
    let decoded = PairResponseV1::from_canonical_bytes(&response.sealed_blob.0).unwrap();
    assert_eq!(decoded.canonical_bytes().unwrap(), response.sealed_blob.0);
    assert_eq!(decoded.canonical_sha256().unwrap(), response_hash);
    {
        let observed = order.lock().unwrap();
        let committed = observed
            .iter()
            .position(|entry| *entry == "grant-ack-commit")
            .unwrap();
        let sent = observed
            .iter()
            .rposition(|entry| *entry == "send-pending")
            .unwrap();
        assert!(
            committed < sent,
            "PairResponse must follow durable ACK COMMIT"
        );
    }

    actor
        .event_tx
        .send(Ok(PairingTransportEvent::GrantCommitted(committed)))
        .unwrap();
    assert_eq!(actor.sent_data_rx.recv().await.unwrap(), response);
    assert!(actor.sent_close_rx.try_recv().is_err());
    actor.stop().await;
}

#[tokio::test]
async fn unknown_or_wrong_grant_commit_axes_are_zero_store_mutation_and_zero_response() {
    let order = Arc::new(StdMutex::new(Vec::new()));
    let store = Arc::new(FakeStore::with_order(Arc::clone(&order)));
    let mut actor = spawn_actor(Arc::clone(&store)).await;
    let (_, pairing_id) = create_pending_pairing(&mut actor, "grant-ack-axes", 0x83).await;
    actor.handle.confirm(pairing_id).await.unwrap();
    let install = actor.sent_grant_rx.recv().await.unwrap();
    let exact = grant_committed(&install);

    let mut wrong_route = exact.clone();
    wrong_route.device_route = DeviceRouteId::from_bytes([0xe1; 16]);
    let mut wrong_serial = exact.clone();
    wrong_serial.grant_serial = GrantSerial::new(exact.grant_serial.value() + 1);
    let mut wrong_hash = exact;
    wrong_hash.grant_hash[0] ^= 0xff;
    for committed in [wrong_route, wrong_serial, wrong_hash] {
        actor
            .event_tx
            .send(Ok(PairingTransportEvent::GrantCommitted(committed)))
            .unwrap();
    }

    assert!(
        tokio::time::timeout(Duration::from_millis(30), actor.sent_data_rx.recv())
            .await
            .is_err()
    );
    assert_eq!(
        store.lifecycle(pairing_id),
        PairingInviteLifecycle::GrantPreparing
    );
    assert!(store.state.lock().unwrap().committed.is_empty());
    assert!(
        order
            .lock()
            .unwrap()
            .iter()
            .all(|entry| !entry.starts_with("grant-ack"))
    );
    actor.stop().await;
}

#[tokio::test]
async fn grant_ack_before_commit_failure_is_zero_network_and_after_commit_unknown_readback_sends() {
    let order = Arc::new(StdMutex::new(Vec::new()));
    let store = Arc::new(FakeStore::with_order(Arc::clone(&order)));
    let mut actor = spawn_actor(Arc::clone(&store)).await;
    let (_, pairing_id) = create_pending_pairing(&mut actor, "grant-ack-faults", 0x84).await;
    actor.handle.confirm(pairing_id).await.unwrap();
    let install = actor.sent_grant_rx.recv().await.unwrap();
    let committed = grant_committed(&install);

    store.fail_grant_ack_before_commit(true);
    actor
        .event_tx
        .send(Ok(PairingTransportEvent::GrantCommitted(committed.clone())))
        .unwrap();
    assert!(
        tokio::time::timeout(Duration::from_millis(30), actor.sent_data_rx.recv())
            .await
            .is_err()
    );
    assert_eq!(
        store.lifecycle(pairing_id),
        PairingInviteLifecycle::GrantPreparing
    );
    assert!(store.state.lock().unwrap().committed.is_empty());

    store.fail_grant_ack_before_commit(false);
    store.grant_ack_unknown_readback(true);
    actor
        .event_tx
        .send(Ok(PairingTransportEvent::GrantCommitted(committed)))
        .unwrap();
    let response = actor.sent_data_rx.recv().await.unwrap();
    assert_eq!(response, store.committed_response(pairing_id));
    assert_eq!(
        store.lifecycle(pairing_id),
        PairingInviteLifecycle::GrantCommitted
    );
    assert!(!store.state.lock().unwrap().grants.contains_key(&pairing_id));
    {
        let observed = order.lock().unwrap();
        let readback = observed
            .iter()
            .position(|entry| *entry == "grant-ack-unknown-readback")
            .unwrap();
        let sent = observed
            .iter()
            .rposition(|entry| *entry == "send-pending")
            .unwrap();
        assert!(readback < sent);
    }
    actor.stop().await;
}

#[tokio::test]
async fn committed_restart_and_reconnect_wait_for_current_open_ack_then_replay_exact_response() {
    let store = Arc::new(FakeStore::default());
    let mut first = spawn_actor(Arc::clone(&store)).await;
    let (_, pairing_id) = create_pending_pairing(&mut first, "response-recovery", 0x85).await;
    first.handle.confirm(pairing_id).await.unwrap();
    let install = first.sent_grant_rx.recv().await.unwrap();
    first
        .event_tx
        .send(Ok(PairingTransportEvent::GrantCommitted(grant_committed(
            &install,
        ))))
        .unwrap();
    let exact = first.sent_data_rx.recv().await.unwrap();
    first.stop().await;

    let mut second = spawn_actor(Arc::clone(&store)).await;
    let startup_open = second.sent_rx.recv().await.unwrap();
    assert!(second.sent_data_rx.try_recv().is_err());
    second.event_tx.send(Ok(opened(&startup_open))).unwrap();
    assert_eq!(second.sent_data_rx.recv().await.unwrap(), exact);

    second
        .event_tx
        .send(Ok(PairingTransportEvent::PairFrameAccepted(
            agentdeck_protocol::relay_v2::frame::RouteAccepted {
                accepted: agentdeck_protocol::relay_v2::frame::AcceptedRef::PairFrame {
                    pair_route: startup_open.pair_route,
                },
            },
        )))
        .unwrap();
    assert!(
        tokio::time::timeout(Duration::from_millis(30), second.sent_data_rx.recv())
            .await
            .is_err()
    );
    assert_eq!(
        store.lifecycle(pairing_id),
        PairingInviteLifecycle::GrantCommitted
    );

    second
        .event_tx
        .send(Err(pairing_error("remote.transport.closed")))
        .unwrap();
    let reconnect_open = second.sent_rx.recv().await.unwrap();
    assert_eq!(reconnect_open, startup_open);
    assert!(second.sent_data_rx.try_recv().is_err());
    second.event_tx.send(Ok(opened(&reconnect_open))).unwrap();
    assert_eq!(second.sent_data_rx.recv().await.unwrap(), exact);
    second.stop().await;
}

#[tokio::test]
async fn committed_exact_pair_request_replays_frozen_response_and_different_request_is_rejected() {
    let store = Arc::new(FakeStore::default());
    let mut actor = spawn_actor(Arc::clone(&store)).await;
    let (invite, pairing_id, exact_response) =
        create_committed_pairing(&mut actor, &store, "response-request-replay", 0x86).await;

    actor
        .event_tx
        .send(Ok(PairingTransportEvent::PairData(pair_request(
            &invite.invite,
            0x86,
        ))))
        .unwrap();
    assert_eq!(actor.sent_data_rx.recv().await.unwrap(), exact_response);

    actor
        .event_tx
        .send(Ok(PairingTransportEvent::PairData(pair_request(
            &invite.invite,
            0x87,
        ))))
        .unwrap();
    assert!(
        tokio::time::timeout(Duration::from_millis(30), actor.sent_data_rx.recv())
            .await
            .is_err(),
        "different PairRequest must not receive the frozen response"
    );
    assert_eq!(
        store.lifecycle(pairing_id),
        PairingInviteLifecycle::GrantCommitted
    );
    actor.stop().await;
}

#[tokio::test]
async fn pair_response_send_failure_keeps_committed_recovery_and_replays_after_reopen() {
    let store = Arc::new(FakeStore::default());
    let mut actor = spawn_actor(Arc::clone(&store)).await;
    let (_, pairing_id) = create_pending_pairing(&mut actor, "response-send-failure", 0x86).await;
    actor.handle.confirm(pairing_id).await.unwrap();
    let install = actor.sent_grant_rx.recv().await.unwrap();
    actor.fail_send.store(true, Ordering::SeqCst);

    actor
        .event_tx
        .send(Ok(PairingTransportEvent::GrantCommitted(grant_committed(
            &install,
        ))))
        .unwrap();
    let reopen = actor.sent_rx.recv().await.unwrap();
    assert!(actor.sent_data_rx.try_recv().is_err());
    assert_eq!(actor.reconnects.load(Ordering::SeqCst), 1);
    assert_eq!(
        store.lifecycle(pairing_id),
        PairingInviteLifecycle::GrantCommitted
    );
    let exact = store.committed_response(pairing_id);

    actor.event_tx.send(Ok(opened(&reopen))).unwrap();
    assert_eq!(actor.sent_data_rx.recv().await.unwrap(), exact);
    actor.stop().await;
}

#[tokio::test]
async fn same_pairing_in_preparing_and_committed_recovery_fails_closed_before_network() {
    let store = Arc::new(FakeStore::default());
    let mut first = spawn_actor(Arc::clone(&store)).await;
    let (_, pairing_id) = create_pending_pairing(&mut first, "overlap-recovery", 0x87).await;
    first.handle.confirm(pairing_id).await.unwrap();
    first.sent_grant_rx.recv().await.unwrap();
    first.stop().await;

    {
        let mut state = store.state.lock().unwrap();
        let grant = state.grants.get(&pairing_id).unwrap().clone();
        let stored = state.by_id.get(&pairing_id).unwrap();
        let invite = PairInviteV1::from_canonical_bytes(&stored.canonical_invite).unwrap();
        let response = DurableResponse::for_test(
            pairing_id,
            grant.request_hash,
            &invite,
            &stored.invite_hpke_private_key,
            &grant.install.grant,
        );
        state.committed.insert(pairing_id, response);
    }
    store.expose_stale_committed_recovery(true);

    let (second, ready) = spawn_actor_with_startup_send_failure(Arc::clone(&store), None).await;
    assert_eq!(
        ready.unwrap_err().code(),
        PAIRING_GRANT_RECOVERY_UNAVAILABLE
    );
    assert!(second.sent_rx.is_empty());
    assert!(second.sent_data_rx.is_empty());
    second.stop().await;
}

#[tokio::test]
async fn valid_endpoint_receipt_commits_delivery_before_close_and_late_receipts_are_noops() {
    let order = Arc::new(StdMutex::new(Vec::new()));
    let store = Arc::new(FakeStore::with_order(Arc::clone(&order)));
    let mut actor = spawn_actor(Arc::clone(&store)).await;
    let (_, pairing_id, _) =
        create_committed_pairing(&mut actor, &store, "delivery-valid", 0x88).await;
    let receipt = pair_response_receipt(&store, pairing_id, 0x88, None);

    actor
        .event_tx
        .send(Ok(PairingTransportEvent::PairData(receipt.clone())))
        .unwrap();
    let close = actor.sent_close_rx.recv().await.unwrap();
    assert_eq!(close.pair_route, receipt.pair_route);
    assert_eq!(
        store.lifecycle(pairing_id),
        PairingInviteLifecycle::Delivered
    );
    {
        let observed = order.lock().unwrap();
        let committed = observed
            .iter()
            .position(|entry| *entry == "delivery-commit")
            .unwrap();
        let sent = observed
            .iter()
            .position(|entry| *entry == "send-close")
            .unwrap();
        assert!(
            committed < sent,
            "Close must follow durable delivery COMMIT"
        );
    }
    assert!(actor.sent_rx.try_recv().is_err());
    assert!(actor.sent_data_rx.try_recv().is_err());

    actor
        .event_tx
        .send(Ok(PairingTransportEvent::PairFrameAccepted(
            agentdeck_protocol::relay_v2::frame::RouteAccepted {
                accepted: agentdeck_protocol::relay_v2::frame::AcceptedRef::PairFrame {
                    pair_route: receipt.pair_route,
                },
            },
        )))
        .unwrap();
    actor
        .event_tx
        .send(Ok(PairingTransportEvent::PairData(receipt.clone())))
        .unwrap();
    assert!(
        tokio::time::timeout(Duration::from_millis(30), actor.sent_close_rx.recv())
            .await
            .is_err(),
        "RouteAccepted and late receipt must not enqueue another Close"
    );
    assert_eq!(
        store.lifecycle(pairing_id),
        PairingInviteLifecycle::Delivered
    );

    let closed = PairRouteClosed {
        pair_route: close.pair_route,
        outcome: PairRouteCloseOutcome::Closed,
    };
    actor
        .event_tx
        .send(Ok(PairingTransportEvent::PairRouteClosed(closed)))
        .unwrap();
    tokio::time::timeout(Duration::from_secs(1), async {
        while store.count() != 0 {
            tokio::task::yield_now().await;
        }
    })
    .await
    .expect("Close ACK must scrub delivered secrets");
    assert!(!store.has_secret_row(pairing_id));
    assert!(store.state.lock().unwrap().committed.is_empty());
    actor.stop().await;
}

#[tokio::test]
async fn encrypted_receipt_tamper_corpus_is_zero_write_zero_close_then_valid_receipt_converges() {
    let order = Arc::new(StdMutex::new(Vec::new()));
    let store = Arc::new(FakeStore::with_order(Arc::clone(&order)));
    let mut actor = spawn_actor(Arc::clone(&store)).await;
    let (_, pairing_id, _) =
        create_committed_pairing(&mut actor, &store, "delivery-tamper", 0x89).await;
    let response = store
        .state
        .lock()
        .unwrap()
        .committed
        .get(&pairing_id)
        .unwrap()
        .clone();
    let exact_axes = TestReceiptAxes {
        request_hash: response.request_hash,
        grant_hash: response.grant_hash,
        response_hash: response.response_hash,
    };
    let valid = pair_response_receipt(&store, pairing_id, 0x89, Some(exact_axes));

    let mut bad_ciphertext = valid.clone();
    let mut envelope =
        PairingControlEnvelopeV1::from_canonical_bytes(&bad_ciphertext.sealed_blob.0).unwrap();
    envelope.ciphertext[0] ^= 1;
    bad_ciphertext.sealed_blob.0 = envelope.canonical_bytes().unwrap();
    let mut trailing = valid.clone();
    trailing.sealed_blob.0.push(0);
    let mut wrong_route = valid.clone();
    wrong_route.pair_route = PairRouteId::from_bytes([0xee; 16]);
    let mut wrong_request = exact_axes;
    wrong_request.request_hash[0] ^= 1;
    let mut wrong_grant = exact_axes;
    wrong_grant.grant_hash[0] ^= 1;
    let mut wrong_response = exact_axes;
    wrong_response.response_hash[0] ^= 1;
    let invalid = [
        bad_ciphertext,
        trailing,
        wrong_route,
        pair_response_receipt(&store, pairing_id, 0x89, Some(wrong_request)),
        pair_response_receipt(&store, pairing_id, 0x89, Some(wrong_grant)),
        pair_response_receipt(&store, pairing_id, 0x89, Some(wrong_response)),
        pair_response_receipt(&store, pairing_id, 0x8f, Some(exact_axes)),
    ];
    for receipt in invalid {
        actor
            .event_tx
            .send(Ok(PairingTransportEvent::PairData(receipt)))
            .unwrap();
    }
    assert!(
        tokio::time::timeout(Duration::from_millis(100), actor.sent_close_rx.recv())
            .await
            .is_err()
    );
    assert_eq!(
        store.lifecycle(pairing_id),
        PairingInviteLifecycle::GrantCommitted
    );
    assert!(
        store
            .state
            .lock()
            .unwrap()
            .delivered_receipt_hashes
            .is_empty()
    );
    assert!(
        order
            .lock()
            .unwrap()
            .iter()
            .all(|entry| !entry.starts_with("delivery"))
    );

    actor
        .event_tx
        .send(Ok(PairingTransportEvent::PairData(valid)))
        .unwrap();
    actor.sent_close_rx.recv().await.unwrap();
    assert_eq!(
        store.lifecycle(pairing_id),
        PairingInviteLifecycle::Delivered
    );
    actor.stop().await;
}

#[tokio::test]
async fn delivery_and_close_faults_recover_without_open_or_response_replay() {
    let order = Arc::new(StdMutex::new(Vec::new()));
    let store = Arc::new(FakeStore::with_order(Arc::clone(&order)));
    let mut first = spawn_actor(Arc::clone(&store)).await;
    let (_, pairing_id, _) =
        create_committed_pairing(&mut first, &store, "delivery-faults", 0x8a).await;
    let receipt = pair_response_receipt(&store, pairing_id, 0x8a, None);

    store.fail_delivery_before_commit(true);
    first
        .event_tx
        .send(Ok(PairingTransportEvent::PairData(receipt.clone())))
        .unwrap();
    assert!(
        tokio::time::timeout(Duration::from_millis(30), first.sent_close_rx.recv())
            .await
            .is_err()
    );
    assert_eq!(
        store.lifecycle(pairing_id),
        PairingInviteLifecycle::GrantCommitted
    );

    store.fail_delivery_before_commit(false);
    store.delivery_commit_unknown_readback(true);
    first.fail_send.store(true, Ordering::SeqCst);
    first
        .event_tx
        .send(Ok(PairingTransportEvent::PairData(receipt.clone())))
        .unwrap();
    let recovered_close = first.sent_close_rx.recv().await.unwrap();
    assert_eq!(first.reconnects.load(Ordering::SeqCst), 1);
    assert_eq!(
        store.lifecycle(pairing_id),
        PairingInviteLifecycle::Delivered
    );
    assert!(first.sent_rx.try_recv().is_err());
    assert!(first.sent_data_rx.try_recv().is_err());

    store.fail_close_ack_before_commit(true);
    first
        .event_tx
        .send(Ok(PairingTransportEvent::PairRouteClosed(
            PairRouteClosed {
                pair_route: recovered_close.pair_route,
                outcome: PairRouteCloseOutcome::Closed,
            },
        )))
        .unwrap();
    tokio::time::timeout(Duration::from_secs(1), async {
        while !order.lock().unwrap().contains(&"close-ack-before-fault") {
            tokio::task::yield_now().await;
        }
    })
    .await
    .unwrap();
    assert_eq!(store.count(), 1);
    first.stop().await;

    let mut second = spawn_actor(Arc::clone(&store)).await;
    let startup_close = second.sent_close_rx.recv().await.unwrap();
    assert_eq!(startup_close, recovered_close);
    assert!(second.sent_rx.try_recv().is_err());
    assert!(second.sent_data_rx.try_recv().is_err());

    store.fail_close_ack_before_commit(false);
    store.close_ack_unknown_readback(true);
    second
        .event_tx
        .send(Ok(PairingTransportEvent::PairRouteClosed(
            PairRouteClosed {
                pair_route: startup_close.pair_route,
                outcome: PairRouteCloseOutcome::AlreadyAbsent,
            },
        )))
        .unwrap();
    tokio::time::timeout(Duration::from_secs(1), async {
        while store.count() != 0 {
            tokio::task::yield_now().await;
        }
    })
    .await
    .expect("post-COMMIT unknown readback must converge to scrubbed tombstone");
    assert!(
        order
            .lock()
            .unwrap()
            .contains(&"close-ack-unknown-readback")
    );
    assert!(store.state.lock().unwrap().committed.is_empty());

    second
        .event_tx
        .send(Ok(PairingTransportEvent::PairData(receipt)))
        .unwrap();
    assert!(
        tokio::time::timeout(Duration::from_millis(30), second.sent_close_rx.recv())
            .await
            .is_err(),
        "receipt after scrub is late and must not produce Close"
    );
    second.stop().await;
}

#[tokio::test]
async fn confirm_crypto_and_store_failures_are_zero_network_and_leave_pending() {
    let store = Arc::new(FakeStore::default());
    let mut actor = spawn_actor(Arc::clone(&store)).await;
    let (_, pairing_id) = create_pending_pairing(&mut actor, "confirm-failures", 0x7b).await;

    actor.fail_grant_freeze.store(true, Ordering::SeqCst);
    assert_eq!(
        actor.handle.confirm(pairing_id).await.unwrap_err().code(),
        GrantFreezeError::CryptoFailure.code()
    );
    assert!(actor.sent_grant_rx.try_recv().is_err());
    assert_eq!(
        store.lifecycle(pairing_id),
        PairingInviteLifecycle::AwaitingLocalConfirmation
    );

    actor.fail_grant_freeze.store(false, Ordering::SeqCst);
    store.fail_confirm(true);
    assert_eq!(
        actor.handle.confirm(pairing_id).await.unwrap_err().code(),
        "daemon.runtime.store_unavailable"
    );
    assert!(actor.sent_grant_rx.try_recv().is_err());
    assert_eq!(
        store.lifecycle(pairing_id),
        PairingInviteLifecycle::AwaitingLocalConfirmation
    );
    actor.stop().await;
}

#[tokio::test]
async fn confirm_cancel_and_expiry_preserve_first_valid_winner() {
    let cancel_store = Arc::new(FakeStore::default());
    let mut cancel_actor = spawn_actor(Arc::clone(&cancel_store)).await;
    let (_, canceled_id) =
        create_pending_pairing(&mut cancel_actor, "cancel-wins-confirm", 0x7c).await;
    assert!(matches!(
        cancel_actor.handle.cancel(canceled_id).await.unwrap(),
        PairingReceipt::Canceled { .. }
    ));
    cancel_actor.sent_close_rx.recv().await.unwrap();
    assert!(matches!(
        cancel_actor.handle.confirm(canceled_id).await.unwrap(),
        PairingReceipt::AlreadyHandled {
            winner: PairingDecision::Cancel,
            state: PairingState::Canceled,
            ..
        }
    ));
    assert!(cancel_actor.sent_grant_rx.try_recv().is_err());
    cancel_actor.stop().await;

    let expiry_store = Arc::new(FakeStore::default());
    let mut expiry_actor = spawn_actor(Arc::clone(&expiry_store)).await;
    let (_, expired_id) =
        create_pending_pairing(&mut expiry_actor, "expiry-wins-confirm", 0x7d).await;
    expiry_store.mark_due(expired_id);
    assert!(matches!(
        expiry_actor.handle.confirm(expired_id).await.unwrap(),
        PairingReceipt::AlreadyHandled {
            winner: PairingDecision::Expire,
            state: PairingState::Expired,
            ..
        }
    ));
    expiry_actor.sent_close_rx.recv().await.unwrap();
    assert!(expiry_actor.sent_grant_rx.try_recv().is_err());
    expiry_actor.stop().await;

    let confirm_store = Arc::new(FakeStore::default());
    let mut confirm_actor = spawn_actor(Arc::clone(&confirm_store)).await;
    let (_, confirmed_id) =
        create_pending_pairing(&mut confirm_actor, "confirm-wins-cancel", 0x7e).await;
    assert!(matches!(
        confirm_actor.handle.confirm(confirmed_id).await.unwrap(),
        PairingReceipt::Confirmed { .. }
    ));
    confirm_actor.sent_grant_rx.recv().await.unwrap();
    assert!(matches!(
        confirm_actor.handle.cancel(confirmed_id).await.unwrap(),
        PairingReceipt::AlreadyHandled {
            winner: PairingDecision::Confirm,
            state: PairingState::GrantPreparing,
            ..
        }
    ));
    assert!(confirm_actor.sent_close_rx.try_recv().is_err());
    confirm_actor.stop().await;
}

#[tokio::test]
async fn post_commit_send_failure_restart_and_reconnect_replay_exact_install_after_open_ack() {
    let store = Arc::new(FakeStore::default());
    store.commit_unknown_readback(true);
    let mut first = spawn_actor(Arc::clone(&store)).await;
    let (_, pairing_id) = create_pending_pairing(&mut first, "grant-recovery", 0x7f).await;
    first.fail_send.store(true, Ordering::SeqCst);

    assert!(matches!(
        first.handle.confirm(pairing_id).await.unwrap(),
        PairingReceipt::Confirmed { .. }
    ));
    let exact = store.grant_install(pairing_id);
    let failed_generation_open = first.sent_rx.recv().await.unwrap();
    assert!(first.sent_grant_rx.try_recv().is_err());
    assert_eq!(first.reconnects.load(Ordering::SeqCst), 1);
    first.stop().await;

    let mut second = spawn_actor(Arc::clone(&store)).await;
    let startup_open = second.sent_rx.recv().await.unwrap();
    assert_eq!(startup_open, failed_generation_open);
    assert!(second.sent_grant_rx.try_recv().is_err());
    second.event_tx.send(Ok(opened(&startup_open))).unwrap();
    assert_eq!(second.sent_grant_rx.recv().await.unwrap(), exact);

    second
        .event_tx
        .send(Err(pairing_error("remote.transport.closed")))
        .unwrap();
    let reconnect_open = second.sent_rx.recv().await.unwrap();
    assert_eq!(reconnect_open, startup_open);
    assert!(second.sent_grant_rx.try_recv().is_err());
    second.event_tx.send(Ok(opened(&reconnect_open))).unwrap();
    assert_eq!(second.sent_grant_rx.recv().await.unwrap(), exact);
    second.stop().await;
}

#[tokio::test]
async fn local_revocation_is_exact_commit_before_send_and_ack_before_receipt_and_close() {
    let store = Arc::new(FakeStore::default());
    let mut actor = spawn_actor(Arc::clone(&store)).await;
    let (invite, pairing_id, _) =
        create_committed_pairing(&mut actor, &store, "local-revoke", 0x81).await;
    let grant = store
        .state
        .lock()
        .unwrap()
        .authorizations
        .values()
        .next()
        .unwrap()
        .clone();
    let device = device_handle_for_test(grant.device_route);

    let error = actor
        .handle
        .revoke_device(device.clone(), RuntimeGrantSerial::new(2))
        .await
        .unwrap_err();
    assert_eq!(error.code(), REVOCATION_TARGET_INVALID);
    assert_eq!(actor.revocation_freezes.load(Ordering::SeqCst), 0);
    assert!(actor.sent_revoke_rx.try_recv().is_err());

    store.order.lock().unwrap().clear();
    let handle = actor.handle.clone();
    let retry_device = device.clone();
    let revoke = tokio::spawn(async move {
        handle
            .revoke_device(retry_device, RuntimeGrantSerial::new(1))
            .await
    });
    let exact = actor.sent_revoke_rx.recv().await.unwrap();
    assert_eq!(exact.revocation.device_route, grant.device_route);
    assert_eq!(exact.revocation.grant_serial, grant.grant_serial);
    assert_eq!(
        &*store.order.lock().unwrap(),
        &["revocation-commit", "send-revoke"]
    );
    assert!(!revoke.is_finished());

    actor
        .event_tx
        .send(Ok(PairingTransportEvent::PairFrameAccepted(
            agentdeck_protocol::relay_v2::frame::RouteAccepted {
                accepted: agentdeck_protocol::relay_v2::frame::AcceptedRef::PairFrame {
                    pair_route: invite.invite.pair_route,
                },
            },
        )))
        .unwrap();
    let mut wrong = revocation_committed(&exact);
    wrong.grant_serial = GrantSerial::new(2);
    actor
        .event_tx
        .send(Ok(PairingTransportEvent::RevocationCommitted(wrong)))
        .unwrap();
    tokio::task::yield_now().await;
    assert!(!revoke.is_finished());
    assert!(actor.sent_close_rx.try_recv().is_err());

    actor
        .event_tx
        .send(Ok(PairingTransportEvent::RevocationCommitted(
            revocation_committed(&exact),
        )))
        .unwrap();
    let close = actor.sent_close_rx.recv().await.unwrap();
    assert_eq!(close.pair_route, invite.invite.pair_route);
    assert!(matches!(
        revoke.await.unwrap().unwrap(),
        RevocationReceipt::Committed { grant_serial } if grant_serial == RuntimeGrantSerial::new(1)
    ));
    {
        let order = store.order.lock().unwrap();
        assert!(
            order
                .iter()
                .position(|entry| *entry == "revocation-ack-commit")
                .unwrap()
                < order
                    .iter()
                    .position(|entry| *entry == "send-close")
                    .unwrap()
        );
    }
    assert_eq!(actor.revocation_freezes.load(Ordering::SeqCst), 1);

    assert!(matches!(
        actor
            .handle
            .revoke_device(device, RuntimeGrantSerial::new(1))
            .await
            .unwrap(),
        RevocationReceipt::Committed { .. }
    ));
    assert_eq!(actor.revocation_freezes.load(Ordering::SeqCst), 1);
    assert_eq!(
        store.lifecycle(pairing_id),
        PairingInviteLifecycle::Canceled
    );
    actor.stop().await;
}

#[tokio::test]
async fn due_grant_preparing_revokes_in_strict_install_ack_revoke_ack_close_order() {
    let store = Arc::new(FakeStore::default());
    let mut actor = spawn_actor(Arc::clone(&store)).await;
    let (invite, pairing_id) = create_pending_pairing(&mut actor, "orphan-two-phase", 0x82).await;
    actor.handle.confirm(pairing_id).await.unwrap();
    let install = actor.sent_grant_rx.recv().await.unwrap();
    store.mark_due(pairing_id);
    store.order.lock().unwrap().clear();

    let replayed_install = tokio::time::timeout(Duration::from_secs(2), actor.sent_grant_rx.recv())
        .await
        .expect("expiry tick must drive orphan install")
        .unwrap();
    assert_eq!(replayed_install, install);
    assert_eq!(
        store.lifecycle(pairing_id),
        PairingInviteLifecycle::OrphanRevoking
    );
    assert!(actor.sent_revoke_rx.try_recv().is_err());

    let mut wrong = grant_committed(&install);
    wrong.grant_hash[0] ^= 1;
    actor
        .event_tx
        .send(Ok(PairingTransportEvent::GrantCommitted(wrong)))
        .unwrap();
    tokio::task::yield_now().await;
    assert!(actor.sent_revoke_rx.try_recv().is_err());

    store.fail_orphan_grant_ack(true);
    actor
        .event_tx
        .send(Ok(PairingTransportEvent::GrantCommitted(grant_committed(
            &install,
        ))))
        .unwrap();
    tokio::task::yield_now().await;
    assert!(actor.sent_revoke_rx.try_recv().is_err());
    store.fail_orphan_grant_ack(false);
    actor
        .event_tx
        .send(Ok(PairingTransportEvent::GrantCommitted(grant_committed(
            &install,
        ))))
        .unwrap();
    let revoke = actor.sent_revoke_rx.recv().await.unwrap();
    assert_eq!(revoke.revocation.device_route, install.grant.device_route);
    actor
        .event_tx
        .send(Ok(PairingTransportEvent::RevocationCommitted(
            revocation_committed(&revoke),
        )))
        .unwrap();
    let close = actor.sent_close_rx.recv().await.unwrap();
    assert_eq!(close.pair_route, invite.invite.pair_route);
    assert_eq!(store.lifecycle(pairing_id), PairingInviteLifecycle::Expired);
    {
        let order = store.order.lock().unwrap();
        let begin = order
            .iter()
            .position(|entry| *entry == "revocation-commit")
            .unwrap();
        let install_send = order
            .iter()
            .position(|entry| *entry == "send-grant")
            .unwrap();
        let grant_ack = order
            .iter()
            .position(|entry| *entry == "orphan-grant-ack-commit")
            .unwrap();
        let revoke_send = order
            .iter()
            .position(|entry| *entry == "send-revoke")
            .unwrap();
        let revoke_ack = order
            .iter()
            .position(|entry| *entry == "revocation-ack-commit")
            .unwrap();
        let close_send = order
            .iter()
            .position(|entry| *entry == "send-close")
            .unwrap();
        assert!(begin < install_send && install_send < grant_ack && grant_ack < revoke_send);
        assert!(revoke_send < revoke_ack && revoke_ack < close_send);
    }
    assert_eq!(actor.revocation_freezes.load(Ordering::SeqCst), 1);
    actor.stop().await;
}

#[tokio::test]
async fn revocation_freeze_and_begin_failures_are_zero_network_and_zero_state_transition() {
    let store = Arc::new(FakeStore::default());
    let mut actor = spawn_actor(Arc::clone(&store)).await;
    let (_, pairing_id, _) =
        create_committed_pairing(&mut actor, &store, "revoke-failures", 0x84).await;
    let grant = store
        .state
        .lock()
        .unwrap()
        .authorizations
        .values()
        .next()
        .unwrap()
        .clone();
    let device = device_handle_for_test(grant.device_route);

    actor.fail_revocation_freeze.store(true, Ordering::SeqCst);
    assert_eq!(
        actor
            .handle
            .revoke_device(device.clone(), RuntimeGrantSerial::new(1))
            .await
            .unwrap_err()
            .code(),
        "daemon.pairing.revocation_signing_failed"
    );
    assert_eq!(
        store.lifecycle(pairing_id),
        PairingInviteLifecycle::GrantCommitted
    );
    assert!(actor.sent_revoke_rx.try_recv().is_err());

    actor.fail_revocation_freeze.store(false, Ordering::SeqCst);
    store.fail_revocation_begin(true);
    assert_eq!(
        actor
            .handle
            .revoke_device(device, RuntimeGrantSerial::new(1))
            .await
            .unwrap_err()
            .code(),
        "daemon.runtime.store_unavailable"
    );
    assert_eq!(
        store.lifecycle(pairing_id),
        PairingInviteLifecycle::GrantCommitted
    );
    assert!(store.state.lock().unwrap().revocations.is_empty());
    assert!(actor.sent_revoke_rx.try_recv().is_err());
    actor.stop().await;
}

#[tokio::test]
async fn revocation_send_failure_ack_failure_and_restart_replay_only_current_frame() {
    let store = Arc::new(FakeStore::default());
    let mut first = spawn_actor(Arc::clone(&store)).await;
    let (_, pairing_id, _) =
        create_committed_pairing(&mut first, &store, "revoke-recovery", 0x83).await;
    let grant = store
        .state
        .lock()
        .unwrap()
        .authorizations
        .values()
        .next()
        .unwrap()
        .clone();
    first.fail_send.store(true, Ordering::SeqCst);
    let handle = first.handle.clone();
    let device = device_handle_for_test(grant.device_route);
    let revoke_waiter = tokio::spawn(async move {
        handle
            .revoke_device(device, RuntimeGrantSerial::new(1))
            .await
    });
    let exact = first.sent_revoke_rx.recv().await.unwrap();
    assert_eq!(first.reconnects.load(Ordering::SeqCst), 1);
    assert!(!revoke_waiter.is_finished());

    store.fail_revocation_ack(true);
    first
        .event_tx
        .send(Ok(PairingTransportEvent::RevocationCommitted(
            revocation_committed(&exact),
        )))
        .unwrap();
    tokio::task::yield_now().await;
    assert!(!revoke_waiter.is_finished());
    assert!(first.sent_close_rx.try_recv().is_err());
    first.stop().await;
    assert_eq!(
        revoke_waiter.await.unwrap().unwrap_err().code(),
        PAIRING_STOPPED
    );

    store.fail_revocation_ack(false);
    let mut second = spawn_actor(Arc::clone(&store)).await;
    let replay = second.sent_revoke_rx.recv().await.unwrap();
    assert_eq!(replay, exact);
    assert!(second.sent_rx.try_recv().is_err());
    assert!(second.sent_data_rx.try_recv().is_err());
    assert!(second.sent_grant_rx.try_recv().is_err());
    second
        .event_tx
        .send(Ok(PairingTransportEvent::RevocationCommitted(
            revocation_committed(&replay),
        )))
        .unwrap();
    second.sent_close_rx.recv().await.unwrap();
    assert_eq!(
        store.lifecycle(pairing_id),
        PairingInviteLifecycle::Canceled
    );
    second.stop().await;
}

#[tokio::test]
async fn production_store_renewal_supersedes_and_restart_recovers_only_current_revocation() {
    let root = tempfile::Builder::new()
        .prefix("agentdeck-p43-renewal-")
        .tempdir()
        .expect("create renewal composition root");
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        std::fs::set_permissions(root.path(), std::fs::Permissions::from_mode(0o700))
            .expect("secure renewal composition root");
    }
    let database = root.path().join("runtime.db");
    let keys = MemoryKeyStore::new();
    let store = RuntimeStoreHandle::open(
        RuntimeStoreConfig::new(database.clone()),
        load_or_create_storage_kek(&keys, &database).expect("create renewal StorageKEK"),
    )
    .await
    .expect("open renewal composition Store");
    let (binding, data_certificate) = crate::runtime::store::make_active_for_test(&store).await;
    let mut actor =
        spawn_store_backed_actor(store.clone(), binding.clone(), data_certificate.clone()).await;

    let first =
        complete_store_backed_pairing(&mut actor, &store, "renewal-first", 0xa4, 0xa5, 1).await;
    let second =
        complete_store_backed_pairing(&mut actor, &store, "renewal-second", 0xa4, 0xb5, 11).await;

    assert_eq!(
        first.install.grant.device_sign_pubkey, second.install.grant.device_sign_pubkey,
        "renewal identity is the same DeviceSign key"
    );
    assert_ne!(
        first.device_hpke_public_key, second.device_hpke_public_key,
        "renewal must bind the fresh DeviceHPKE key"
    );
    assert_eq!(
        first.plaintext.device_authorization.device_hpke_pubkey,
        first.device_hpke_public_key
    );
    assert_eq!(
        second.plaintext.device_authorization.device_hpke_pubkey,
        second.device_hpke_public_key
    );
    assert_eq!(
        second.install.grant.device_route,
        first.install.grant.device_route
    );
    assert_eq!(first.install.grant.grant_serial, GrantSerial::new(1));
    assert_eq!(second.install.grant.grant_serial, GrantSerial::new(2));
    for evidence in [&first, &second] {
        assert_eq!(
            evidence.response.info.machine_route,
            evidence.install.grant.machine_route
        );
        assert_eq!(
            evidence.response.info.device_route,
            evidence.install.grant.device_route
        );
        assert_eq!(
            evidence.response.info.grant_serial,
            evidence.install.grant.grant_serial
        );
        assert_eq!(
            evidence.response.info.root_trust_epoch,
            evidence.install.grant.trust_epoch
        );
        assert_eq!(evidence.plaintext.relay_grant, evidence.install.grant);
        assert_eq!(
            evidence.response.info.request_hash,
            evidence.plaintext.request_hash
        );
    }

    let authorization_rows = rusqlite::Connection::open(&database)
        .expect("open renewal evidence DB")
        .prepare(
            "SELECT grant_serial, lifecycle FROM remote_authorization_ledger \
             ORDER BY grant_serial",
        )
        .expect("prepare renewal lifecycle evidence")
        .query_map([], |row| {
            Ok((row.get::<_, String>(0)?, row.get::<_, String>(1)?))
        })
        .expect("query renewal lifecycle evidence")
        .collect::<Result<Vec<_>, _>>()
        .expect("collect renewal lifecycle evidence");
    assert_eq!(
        authorization_rows,
        [
            ("00000000000000000001".to_owned(), "superseded".to_owned()),
            ("00000000000000000002".to_owned(), "active".to_owned()),
        ]
    );

    let current_device = device_handle_for_test(second.install.grant.device_route);
    let revoke_handle = actor.handle.clone();
    let revoke_waiter = tokio::spawn(async move {
        revoke_handle
            .revoke_device(current_device, RuntimeGrantSerial::new(2))
            .await
    });
    let exact_revoke =
        receive_pairing_frame(&mut actor.sent_revoke_rx, "initial RevokeDevice").await;
    assert_eq!(
        exact_revoke.revocation.device_route,
        second.install.grant.device_route
    );
    assert_eq!(exact_revoke.revocation.grant_serial, GrantSerial::new(2));
    actor.stop().await;
    assert_eq!(
        tokio::time::timeout(Duration::from_secs(5), revoke_waiter)
            .await
            .expect("timed out waiting for stopped revoke waiter")
            .expect("revoke waiter task must join")
            .unwrap_err()
            .code(),
        PAIRING_STOPPED
    );
    store
        .shutdown()
        .await
        .expect("shutdown before renewal restart");

    let reopened = RuntimeStoreHandle::open(
        RuntimeStoreConfig::new(database.clone()),
        load_or_create_storage_kek(&keys, &database).expect("reload renewal StorageKEK"),
    )
    .await
    .expect("reopen renewal composition Store");
    let mut restarted =
        spawn_store_backed_actor(reopened.clone(), binding.clone(), data_certificate.clone()).await;
    let replayed_revoke =
        receive_pairing_frame(&mut restarted.sent_revoke_rx, "replayed RevokeDevice").await;
    assert_eq!(replayed_revoke, exact_revoke);
    assert!(restarted.sent_rx.try_recv().is_err());
    assert!(restarted.sent_data_rx.try_recv().is_err());
    assert!(restarted.sent_grant_rx.try_recv().is_err());
    assert!(restarted.sent_close_rx.try_recv().is_err());
    assert!(restarted.sent_revoke_rx.try_recv().is_err());
    restarted
        .event_tx
        .send(Ok(PairingTransportEvent::RevocationCommitted(
            revocation_committed(&replayed_revoke),
        )))
        .unwrap();
    tokio::time::timeout(Duration::from_secs(1), async {
        loop {
            if reopened
                .list_revocation_recovery()
                .await
                .expect("read revocation recovery")
                .is_empty()
            {
                break;
            }
            tokio::task::yield_now().await;
        }
    })
    .await
    .expect("RevocationCommitted must durably clear the current outbox frame");

    let rejected = create_opened_invite(&mut restarted, "renewal-after-revoke").await;
    let rejected_id =
        RuntimeId::parse_canonical(RuntimeIdKind::Pairing, rejected.pairing_id.as_str()).unwrap();
    let (request, _) = store_backed_pair_request(&rejected.invite, 0xa4, 0xc5, 21);
    restarted
        .event_tx
        .send(Ok(PairingTransportEvent::PairData(request)))
        .unwrap();
    receive_pairing_frame(&mut restarted.sent_data_rx, "rejected renewal PairPending").await;
    assert_eq!(
        restarted
            .handle
            .confirm(rejected_id)
            .await
            .unwrap_err()
            .code(),
        "daemon.pairing.grant_route_revoked"
    );
    assert!(restarted.sent_grant_rx.try_recv().is_err());

    assert!(matches!(
        restarted.handle.cancel(rejected_id).await.unwrap(),
        PairingReceipt::Canceled { .. }
    ));
    let close = receive_pairing_frame(
        &mut restarted.sent_close_rx,
        "rejected renewal ClosePairRoute",
    )
    .await;
    restarted.event_tx.send(Ok(closed(&close))).unwrap();
    tokio::time::timeout(Duration::from_secs(1), async {
        loop {
            if reopened
                .load_pairing_invite(rejected_id)
                .await
                .expect("read rejected renewal cleanup")
                .is_none()
            {
                break;
            }
            tokio::task::yield_now().await;
        }
    })
    .await
    .expect("rejected renewal cleanup must close durably");
    restarted.stop().await;
    reopened
        .shutdown()
        .await
        .expect("shutdown renewal composition Store");
}

#[tokio::test]
async fn more_than_transport_capacity_recovers_deterministically_one_revocation_at_a_time() {
    let store = Arc::new(FakeStore::default());
    {
        let mut state = store.state.lock().unwrap();
        for seed in 1_u8..=9 {
            let route = DeviceRouteId::from_bytes([seed; 16]);
            let grant = RelayGrant {
                machine_route: MACHINE_ROUTE,
                device_route: route,
                device_sign_pubkey: PublicKeyBytes([seed.wrapping_add(20); 32]),
                grant_serial: GrantSerial::new(1),
                root_key_id: RootKeyId::from_bytes([0x33; 16]),
                trust_epoch: TrustEpoch::new(1),
                signature: Ed25519Signature([seed; 64]),
            };
            let revocation = DeviceRevocation {
                machine_route: MACHINE_ROUTE,
                device_route: route,
                grant_serial: GrantSerial::new(1),
                root_key_id: RootKeyId::from_bytes([0x33; 16]),
                trust_epoch: TrustEpoch::new(1),
                signature: Ed25519Signature([seed.wrapping_add(1); 64]),
            };
            let key = RevocationKey::new(route, GrantSerial::new(1));
            state.authorizations.insert(key, grant.clone());
            state.revocations.insert(
                key,
                DurableRevocation::for_test(
                    None,
                    grant,
                    revocation,
                    DurableRevocationPhase::ReadyToRevoke,
                ),
            );
        }
    }
    let mut actor = spawn_actor(Arc::clone(&store)).await;
    for seed in 1_u8..=9 {
        let revoke = actor.sent_revoke_rx.recv().await.unwrap();
        assert_eq!(
            revoke.revocation.device_route,
            DeviceRouteId::from_bytes([seed; 16])
        );
        assert!(actor.sent_revoke_rx.try_recv().is_err());
        actor
            .event_tx
            .send(Ok(PairingTransportEvent::RevocationCommitted(
                revocation_committed(&revoke),
            )))
            .unwrap();
    }
    tokio::task::yield_now().await;
    assert!(store.state.lock().unwrap().revocations.is_empty());
    assert!(actor.sent_revoke_rx.try_recv().is_err());
    actor.stop().await;
}
