//! W2a 浏览器 pairing 的 transport-neutral 状态机。
//!
//! PairInvite 解析、指纹确认、PairRequest/PairPending/PairResponse/receipt 的编码与密码学
//! 全部留在 Rust/WASM。host 只取得连接 URL、opaque binary frame 与脱敏 view state。

use agentdeck_crypto::{
    HpkePrivateKey, HpkePublicKey, PairResponseExpectedV1, SigningKey, VerifiedPairResponseV1,
    VerifyingKey, open_pair_pending, open_pair_response_verified, seal_pair_request,
    seal_pair_response_received,
};
use agentdeck_protocol::e2ee::{
    AuthorizationCapabilityV1, AuthorizationPermissionV1, AuthorizationRequestV1,
    E2EE_FORMAT_VERSION, MachineDataSignerBindingV1, OuterContextV1, OuterFrameKind, PairInviteV1,
    PairRequestInfoV1, PairRequestPlaintextV1, PairResponseReceivedV1, PairResponseV1,
    PairingControlEnvelopeV1,
};
use agentdeck_protocol::relay_v2::frame::{
    AcceptedRef, Hello, PairData, PairRouteCloseOutcome, PairingHello, Pong, SealedBlob,
};
use agentdeck_protocol::relay_v2::{
    DeviceRouteId, MachineRouteId, OpaqueRouteFrame, PublicKeyBytes, RELAY_PROTOCOL_VERSION,
    RelayFrameBody, decode, encode,
};
use agentdeck_protocol::runtime::RUNTIME_PROTOCOL_VERSION;
use serde::{Deserialize, Serialize};

use crate::DeterministicRng;
use crate::w2_business::{W2BusinessCore, W2BusinessEvidence};

const WEB_DEVICE_DISPLAY_NAME: &str = "Relay Web Test Companion";

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct W2PairingPreview {
    pub machine_display_name: String,
    pub machine_root_fingerprint: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct W2PairingEvidence {
    pub fingerprint_confirmed: bool,
    pub authenticated: bool,
    pub pending_observed: bool,
    pub response_verified: bool,
    pub receipt_sent: bool,
    pub route_accepted_observed: bool,
    pub paired: bool,
    pub machine_route_present: bool,
    pub device_route_present: bool,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, thiserror::Error)]
pub enum W2PairingError {
    #[error("web.remote.pairing.invite_invalid")]
    InviteInvalid,
    #[error("web.remote.pairing.root_fingerprint_mismatch")]
    RootFingerprintMismatch,
    #[error("web.remote.pairing.state_invalid")]
    StateInvalid,
    #[error("web.remote.pairing.frame_invalid")]
    FrameInvalid,
    #[error("web.remote.pairing.handshake_rejected")]
    HandshakeRejected,
    #[error("web.remote.pairing.crypto_failed")]
    CryptoFailed,
    #[error("web.remote.pairing.route_mismatch")]
    RouteMismatch,
    #[error("web.remote.pairing.relay_rejected")]
    RelayRejected,
    #[error("web.remote.pairing.outcome_unknown")]
    OutcomeUnknown,
    #[error("web.remote.pairing.entropy_unavailable")]
    EntropyUnavailable,
    #[error("web.remote.pairing.serialization_failed")]
    SerializationFailed,
    #[error("web.remote.business.state_invalid")]
    BusinessStateInvalid,
    #[error("web.remote.business.frame_invalid")]
    BusinessFrameInvalid,
    #[error("web.remote.business.handshake_rejected")]
    BusinessHandshakeRejected,
    #[error("web.remote.business.crypto_failed")]
    BusinessCryptoFailed,
    #[error("web.remote.business.relay_rejected")]
    BusinessRelayRejected,
    #[error("web.remote.business.outcome_unknown")]
    BusinessOutcomeUnknown,
    #[error("web.remote.business.authorization_denied")]
    BusinessAuthorizationDenied,
    #[error("web.remote.business.counter_exhausted")]
    BusinessCounterExhausted,
}

impl W2PairingError {
    #[must_use]
    pub const fn code(self) -> &'static str {
        match self {
            Self::InviteInvalid => "web.remote.pairing.invite_invalid",
            Self::RootFingerprintMismatch => "web.remote.pairing.root_fingerprint_mismatch",
            Self::StateInvalid => "web.remote.pairing.state_invalid",
            Self::FrameInvalid => "web.remote.pairing.frame_invalid",
            Self::HandshakeRejected => "web.remote.pairing.handshake_rejected",
            Self::CryptoFailed => "web.remote.pairing.crypto_failed",
            Self::RouteMismatch => "web.remote.pairing.route_mismatch",
            Self::RelayRejected => "web.remote.pairing.relay_rejected",
            Self::OutcomeUnknown => "web.remote.pairing.outcome_unknown",
            Self::EntropyUnavailable => "web.remote.pairing.entropy_unavailable",
            Self::SerializationFailed => "web.remote.pairing.serialization_failed",
            Self::BusinessStateInvalid => "web.remote.business.state_invalid",
            Self::BusinessFrameInvalid => "web.remote.business.frame_invalid",
            Self::BusinessHandshakeRejected => "web.remote.business.handshake_rejected",
            Self::BusinessCryptoFailed => "web.remote.business.crypto_failed",
            Self::BusinessRelayRejected => "web.remote.business.relay_rejected",
            Self::BusinessOutcomeUnknown => "web.remote.business.outcome_unknown",
            Self::BusinessAuthorizationDenied => "web.remote.business.authorization_denied",
            Self::BusinessCounterExhausted => "web.remote.business.counter_exhausted",
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum PairingPhase {
    Inspected,
    Confirmed,
    HelloSent,
    PairingHelloSent,
    RequestSent,
    ReceiptSent,
    Paired,
    Failed,
}

struct PairingMaterial {
    device_signing_key: SigningKey,
    device_hpke_private_key: HpkePrivateKey,
    device_sign_pubkey: [u8; 32],
    device_hpke_pubkey: [u8; 32],
    authorization: AuthorizationRequestV1,
    request_hash: [u8; 32],
    request_frame: Vec<u8>,
    rng: DeterministicRng,
    receipt_frame: Option<Vec<u8>>,
    response_hash: Option<[u8; 32]>,
    verified_response: Option<VerifiedPairResponseV1>,
}

struct W2SeedMaterial {
    device_sign_seed: [u8; 32],
    device_hpke_ikm: [u8; 32],
    hpke_rng_seed: [u8; 32],
}

impl Drop for W2SeedMaterial {
    fn drop(&mut self) {
        self.device_sign_seed.fill(0);
        self.device_hpke_ikm.fill(0);
        self.hpke_rng_seed.fill(0);
    }
}

impl std::fmt::Debug for PairingMaterial {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter.write_str("PairingMaterial([REDACTED])")
    }
}

pub struct W2PairingCore {
    invite: PairInviteV1,
    connect_url: String,
    phase: PairingPhase,
    fingerprint_confirmed: bool,
    material: Option<PairingMaterial>,
    business: Option<W2BusinessCore>,
    pending_observed: bool,
    response_verified: bool,
    receipt_sent: bool,
    route_accepted_observed: bool,
    machine_route: Option<MachineRouteId>,
    device_route: Option<DeviceRouteId>,
}

impl std::fmt::Debug for W2PairingCore {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("W2PairingCore")
            .field("phase", &self.phase)
            .field("pairing_material", &"<redacted>")
            .finish()
    }
}

impl Drop for W2PairingCore {
    fn drop(&mut self) {
        self.invite.invite_secret.fill(0);
    }
}

impl W2PairingCore {
    pub fn inspect(encoded: &str, now_ms: u64) -> Result<Self, W2PairingError> {
        let invite =
            PairInviteV1::decode_uri(encoded, now_ms).map_err(|_| W2PairingError::InviteInvalid)?;
        let connect_url = format!("{}v2/pair", invite.wss_url);
        Ok(Self {
            invite,
            connect_url,
            phase: PairingPhase::Inspected,
            fingerprint_confirmed: false,
            material: None,
            business: None,
            pending_observed: false,
            response_verified: false,
            receipt_sent: false,
            route_accepted_observed: false,
            machine_route: None,
            device_route: None,
        })
    }

    #[must_use]
    pub fn preview(&self) -> W2PairingPreview {
        W2PairingPreview {
            machine_display_name: self.invite.machine_display_name.clone(),
            machine_root_fingerprint: self.invite.machine_root_fingerprint_display(),
        }
    }

    pub fn confirm(
        &mut self,
        fingerprint: &str,
        now_ms: u64,
        device_sign_seed: [u8; 32],
        device_hpke_ikm: [u8; 32],
        hpke_rng_seed: [u8; 32],
    ) -> Result<(), W2PairingError> {
        let seeds = W2SeedMaterial {
            device_sign_seed,
            device_hpke_ikm,
            hpke_rng_seed,
        };
        if self.phase != PairingPhase::Inspected {
            return Err(W2PairingError::StateInvalid);
        }
        self.invite
            .validate(now_ms)
            .map_err(|_| W2PairingError::InviteInvalid)?;
        if fingerprint != self.invite.machine_root_fingerprint_display() {
            return Err(W2PairingError::RootFingerprintMismatch);
        }

        let authorization = mvp_authorization().map_err(|_| W2PairingError::CryptoFailed)?;
        let device_signing_key = SigningKey::from_seed(&seeds.device_sign_seed);
        let device_sign_pubkey = device_signing_key.verifying_key().to_bytes();
        let (device_hpke_private_key, device_hpke_public_key) =
            HpkePrivateKey::derive_keypair(&seeds.device_hpke_ikm);
        let device_hpke_pubkey: [u8; 32] = device_hpke_public_key
            .to_bytes()
            .try_into()
            .map_err(|_| W2PairingError::CryptoFailed)?;
        let invite_hash = self
            .invite
            .canonical_sha256()
            .map_err(|_| W2PairingError::InviteInvalid)?;
        let request_info = request_info(&self.invite, invite_hash);
        let plaintext = PairRequestPlaintextV1 {
            format_version: E2EE_FORMAT_VERSION,
            invite_secret: self.invite.invite_secret,
            device_sign_pubkey: PublicKeyBytes(device_sign_pubkey),
            device_hpke_pubkey: PublicKeyBytes(device_hpke_pubkey),
            authorization_request: authorization.clone(),
        };
        let invite_recipient = HpkePublicKey::from_bytes(&self.invite.invite_hpke_pubkey.0)
            .map_err(|_| W2PairingError::CryptoFailed)?;
        let mut rng = DeterministicRng::new(seeds.hpke_rng_seed);
        let request = seal_pair_request(
            &invite_recipient,
            &request_info,
            &pair_context(self.invite.pair_route, OuterFrameKind::PairRequest),
            &plaintext,
            &device_signing_key,
            &mut rng,
        )
        .map_err(|_| W2PairingError::CryptoFailed)?;
        let canonical_request = request
            .canonical_bytes()
            .map_err(|_| W2PairingError::CryptoFailed)?;
        let request_hash = agentdeck_crypto::sha256(&canonical_request);
        let request_frame = pair_data_frame(self.invite.pair_route, canonical_request);

        self.material = Some(PairingMaterial {
            device_signing_key,
            device_hpke_private_key,
            device_sign_pubkey,
            device_hpke_pubkey,
            authorization,
            request_hash,
            request_frame,
            rng,
            receipt_frame: None,
            response_hash: None,
            verified_response: None,
        });
        self.fingerprint_confirmed = true;
        self.phase = PairingPhase::Confirmed;
        Ok(())
    }

    pub fn connect_url(&self) -> Result<&str, W2PairingError> {
        if self.phase == PairingPhase::Inspected || self.phase == PairingPhase::Failed {
            return Err(W2PairingError::StateInvalid);
        }
        Ok(&self.connect_url)
    }

    pub fn start_hello(&mut self) -> Result<Vec<u8>, W2PairingError> {
        if self.phase != PairingPhase::Confirmed {
            return Err(W2PairingError::StateInvalid);
        }
        self.phase = PairingPhase::HelloSent;
        Ok(frame(RelayFrameBody::Hello(Hello {
            protocol_version: RELAY_PROTOCOL_VERSION,
        })))
    }

    pub fn start_pairing_hello(&mut self) -> Result<Vec<u8>, W2PairingError> {
        if self.phase != PairingPhase::HelloSent {
            return Err(W2PairingError::StateInvalid);
        }
        self.phase = PairingPhase::PairingHelloSent;
        Ok(frame(RelayFrameBody::PairingHello(PairingHello {
            relay_server_id: self.invite.relay_server_id,
            pair_route: self.invite.pair_route,
        })))
    }

    pub fn accept_authenticated(&mut self, bytes: &[u8]) -> Result<Vec<u8>, W2PairingError> {
        if self.phase != PairingPhase::PairingHelloSent {
            return Err(W2PairingError::StateInvalid);
        }
        let decoded = decode(bytes).map_err(|_| self.fail(W2PairingError::FrameInvalid))?;
        match decoded.body {
            RelayFrameBody::Authenticated(authenticated)
                if authenticated.heartbeat_interval_secs > 0 =>
            {
                let request = self
                    .material
                    .as_ref()
                    .ok_or(W2PairingError::StateInvalid)?
                    .request_frame
                    .clone();
                self.phase = PairingPhase::RequestSent;
                Ok(request)
            }
            RelayFrameBody::Error(_) => Err(self.fail(W2PairingError::RelayRejected)),
            _ => Err(self.fail(W2PairingError::HandshakeRejected)),
        }
    }

    /// 消费 authenticated pairing connection 的单个 opaque frame，并返回可选发送动作。
    /// 空 `Vec` 表示本帧只推进了本地状态；非空值仍是完整 canonical Relay frame。
    pub fn accept_pair_frame(
        &mut self,
        bytes: &[u8],
        now_ms: u64,
    ) -> Result<Vec<u8>, W2PairingError> {
        if !matches!(
            self.phase,
            PairingPhase::RequestSent | PairingPhase::ReceiptSent
        ) {
            return Err(W2PairingError::StateInvalid);
        }
        self.invite
            .validate(now_ms)
            .map_err(|_| self.fail(W2PairingError::InviteInvalid))?;
        let decoded = decode(bytes).map_err(|_| self.fail(W2PairingError::FrameInvalid))?;
        match decoded.body {
            RelayFrameBody::Ping(ping) => {
                Ok(frame(RelayFrameBody::Pong(Pong { nonce: ping.nonce })))
            }
            RelayFrameBody::PairData(data) => self.accept_pair_data(data, now_ms),
            RelayFrameBody::RouteAccepted(accepted) => {
                if !matches!(
                    accepted.accepted,
                    AcceptedRef::PairFrame { pair_route } if pair_route == self.invite.pair_route
                ) {
                    return Err(self.fail(W2PairingError::RouteMismatch));
                }
                self.route_accepted_observed = true;
                Ok(Vec::new())
            }
            RelayFrameBody::PairRouteClosed(closed) => {
                if closed.pair_route != self.invite.pair_route {
                    return Err(self.fail(W2PairingError::RouteMismatch));
                }
                if self.phase != PairingPhase::ReceiptSent {
                    return Err(self.fail(W2PairingError::OutcomeUnknown));
                }
                match closed.outcome {
                    PairRouteCloseOutcome::Closed => {
                        let business = self.promote_business().map_err(|error| self.fail(error))?;
                        self.business = Some(business);
                        self.phase = PairingPhase::Paired;
                        Ok(Vec::new())
                    }
                    PairRouteCloseOutcome::AlreadyAbsent => {
                        Err(self.fail(W2PairingError::OutcomeUnknown))
                    }
                }
            }
            RelayFrameBody::Error(_) => Err(self.fail(W2PairingError::RelayRejected)),
            RelayFrameBody::ServerRestarting(_) => Err(W2PairingError::OutcomeUnknown),
            _ => Err(self.fail(W2PairingError::FrameInvalid)),
        }
    }

    #[must_use]
    pub const fn paired(&self) -> bool {
        matches!(self.phase, PairingPhase::Paired)
    }

    #[must_use]
    pub fn evidence(&self) -> W2PairingEvidence {
        W2PairingEvidence {
            fingerprint_confirmed: self.fingerprint_confirmed,
            authenticated: matches!(
                self.phase,
                PairingPhase::RequestSent | PairingPhase::ReceiptSent | PairingPhase::Paired
            ),
            pending_observed: self.pending_observed,
            response_verified: self.response_verified,
            receipt_sent: self.receipt_sent,
            route_accepted_observed: self.route_accepted_observed,
            paired: self.paired(),
            machine_route_present: self.machine_route.is_some(),
            device_route_present: self.device_route.is_some(),
        }
    }

    pub fn business_connect_url(&self) -> Result<&str, W2PairingError> {
        self.business()?.connect_url()
    }

    pub fn business_start_hello(&mut self) -> Result<Vec<u8>, W2PairingError> {
        self.business_mut()?.start_hello()
    }

    pub fn business_accept_challenge(&mut self, bytes: &[u8]) -> Result<Vec<u8>, W2PairingError> {
        self.business_mut()?.accept_challenge(bytes)
    }

    pub fn business_accept_authenticated(&mut self, bytes: &[u8]) -> Result<(), W2PairingError> {
        self.business_mut()?.accept_authenticated(bytes)
    }

    pub fn business_start_catalog(&mut self) -> Result<Vec<u8>, W2PairingError> {
        self.business_mut()?.start_catalog()
    }

    pub fn business_start_conversation(&mut self) -> Result<Vec<u8>, W2PairingError> {
        self.business_mut()?.start_conversation()
    }

    pub fn business_start_prompt(&mut self) -> Result<Vec<u8>, W2PairingError> {
        self.business_mut()?.start_prompt()
    }

    pub fn business_start_approval(&mut self) -> Result<Vec<u8>, W2PairingError> {
        self.business_mut()?.start_approval()
    }

    pub fn business_accept_frame(&mut self, bytes: &[u8]) -> Result<Vec<u8>, W2PairingError> {
        self.business_mut()?.accept_frame(bytes)
    }

    pub fn business_evidence(&self) -> Result<W2BusinessEvidence, W2PairingError> {
        Ok(self.business()?.evidence())
    }

    fn accept_pair_data(&mut self, data: PairData, now_ms: u64) -> Result<Vec<u8>, W2PairingError> {
        if data.pair_route != self.invite.pair_route {
            return Err(self.fail(W2PairingError::RouteMismatch));
        }
        let control = PairingControlEnvelopeV1::from_canonical_bytes(&data.sealed_blob.0);
        let response = PairResponseV1::from_canonical_bytes(&data.sealed_blob.0);
        match (control, response) {
            (Ok(envelope), Err(_)) => {
                self.verify_pending(&envelope, now_ms)?;
                self.pending_observed = true;
                Ok(Vec::new())
            }
            (Err(_), Ok(_)) => self.verify_response_and_receipt(&data.sealed_blob.0, now_ms),
            _ => Err(self.fail(W2PairingError::FrameInvalid)),
        }
    }

    fn verify_pending(
        &mut self,
        envelope: &PairingControlEnvelopeV1,
        now_ms: u64,
    ) -> Result<(), W2PairingError> {
        let certificate = self.invite.data_sign_cert.clone();
        if certificate
            .not_after_ms
            .is_some_and(|not_after_ms| now_ms >= not_after_ms)
        {
            return Err(self.fail(W2PairingError::FrameInvalid));
        }
        let verifier = VerifyingKey::from_bytes(&certificate.subject_pubkey.0)
            .map_err(|_| W2PairingError::CryptoFailed);
        let signer = MachineDataSignerBindingV1::from_certificate(&certificate)
            .map_err(|_| W2PairingError::CryptoFailed);
        let invite_hash = self
            .invite
            .canonical_sha256()
            .map_err(|_| W2PairingError::InviteInvalid);
        let pending = match (verifier, signer, invite_hash) {
            (Ok(verifier), Ok(signer), Ok(invite_hash)) => {
                let material = self.material.as_ref().ok_or(W2PairingError::StateInvalid)?;
                open_pair_pending(
                    &material.device_hpke_private_key,
                    &request_info(&self.invite, invite_hash),
                    &pair_context(self.invite.pair_route, OuterFrameKind::PairPending),
                    envelope,
                    &verifier,
                    &signer,
                )
                .map_err(|_| W2PairingError::CryptoFailed)
            }
            (Err(error), _, _) | (_, Err(error), _) | (_, _, Err(error)) => Err(error),
        };
        let pending = pending.map_err(|error| self.fail(error))?;
        let material = self.material.as_ref().ok_or(W2PairingError::StateInvalid)?;
        if pending.request_hash != material.request_hash {
            return Err(self.fail(W2PairingError::FrameInvalid));
        }
        Ok(())
    }

    fn verify_response_and_receipt(
        &mut self,
        canonical_response: &[u8],
        now_ms: u64,
    ) -> Result<Vec<u8>, W2PairingError> {
        let replay_hash = agentdeck_crypto::sha256(canonical_response);
        if let Some(material) = self.material.as_ref()
            && let Some(receipt) = material.receipt_frame.as_ref()
        {
            if material.response_hash == Some(replay_hash) && self.response_verified {
                return Ok(receipt.clone());
            }
            return Err(self.fail(W2PairingError::FrameInvalid));
        }

        let pair_route = self.invite.pair_route;
        let result = {
            let material = self.material.as_mut().ok_or(W2PairingError::StateInvalid)?;
            let verified = open_pair_response_verified(
                &material.device_hpke_private_key,
                PairResponseExpectedV1::new(
                    &self.invite,
                    material.request_hash,
                    material.device_sign_pubkey,
                    material.device_hpke_pubkey,
                    &material.authorization,
                    now_ms,
                ),
                canonical_response,
            )
            .map_err(|_| W2PairingError::CryptoFailed)?;
            let grant_hash = verified.relay_grant().canonical_sha256();
            let invite_recipient = HpkePublicKey::from_bytes(&self.invite.invite_hpke_pubkey.0)
                .map_err(|_| W2PairingError::CryptoFailed)?;
            let receipt = seal_pair_response_received(
                &invite_recipient,
                verified.info(),
                &pair_context(pair_route, OuterFrameKind::PairResponseReceived),
                PairResponseReceivedV1 {
                    request_hash: material.request_hash,
                    grant_hash,
                    response_hash: verified.response_hash(),
                    signature: agentdeck_protocol::relay_v2::Ed25519Signature([0; 64]),
                },
                &material.device_signing_key,
                &mut material.rng,
            )
            .map_err(|_| W2PairingError::CryptoFailed)?
            .canonical_bytes()
            .map_err(|_| W2PairingError::CryptoFailed)?;
            Ok::<_, W2PairingError>((
                pair_data_frame(pair_route, receipt),
                verified.info().machine_route,
                verified.info().device_route,
                verified.response_hash(),
                verified,
            ))
        };
        let (receipt_frame, machine_route, device_route, response_hash, verified_response) =
            result.map_err(|error| self.fail(error))?;
        let material = self.material.as_mut().ok_or(W2PairingError::StateInvalid)?;
        material.receipt_frame = Some(receipt_frame.clone());
        material.response_hash = Some(response_hash);
        material.verified_response = Some(verified_response);
        self.machine_route = Some(machine_route);
        self.device_route = Some(device_route);
        self.response_verified = true;
        self.receipt_sent = true;
        self.phase = PairingPhase::ReceiptSent;
        Ok(receipt_frame)
    }

    fn promote_business(&mut self) -> Result<W2BusinessCore, W2PairingError> {
        let material = self.material.take().ok_or(W2PairingError::StateInvalid)?;
        let PairingMaterial {
            device_signing_key,
            device_hpke_private_key,
            rng,
            verified_response,
            ..
        } = material;
        let verified_response = verified_response.ok_or(W2PairingError::StateInvalid)?;
        W2BusinessCore::new(
            &self.invite.wss_url,
            device_signing_key,
            device_hpke_private_key,
            verified_response,
            rng,
        )
    }

    fn business(&self) -> Result<&W2BusinessCore, W2PairingError> {
        if !self.paired() {
            return Err(W2PairingError::BusinessStateInvalid);
        }
        self.business
            .as_ref()
            .ok_or(W2PairingError::BusinessStateInvalid)
    }

    fn business_mut(&mut self) -> Result<&mut W2BusinessCore, W2PairingError> {
        if !self.paired() {
            return Err(W2PairingError::BusinessStateInvalid);
        }
        self.business
            .as_mut()
            .ok_or(W2PairingError::BusinessStateInvalid)
    }

    fn fail(&mut self, error: W2PairingError) -> W2PairingError {
        self.phase = PairingPhase::Failed;
        error
    }
}

fn frame(body: RelayFrameBody) -> Vec<u8> {
    encode(&OpaqueRouteFrame {
        version: RELAY_PROTOCOL_VERSION,
        body,
    })
}

fn pair_data_frame(
    pair_route: agentdeck_protocol::relay_v2::PairRouteId,
    carrier: Vec<u8>,
) -> Vec<u8> {
    frame(RelayFrameBody::PairData(PairData {
        pair_route,
        sealed_blob: SealedBlob(carrier),
    }))
}

fn request_info(invite: &PairInviteV1, invite_hash: [u8; 32]) -> PairRequestInfoV1 {
    PairRequestInfoV1 {
        e2ee_format_version: E2EE_FORMAT_VERSION,
        runtime_protocol_version: RUNTIME_PROTOCOL_VERSION,
        relay_server_id: invite.relay_server_id,
        pair_route: invite.pair_route,
        invite_hash,
        expiry_ms: invite.expires_at_ms,
    }
}

fn pair_context(
    pair_route: agentdeck_protocol::relay_v2::PairRouteId,
    frame_kind: OuterFrameKind,
) -> OuterContextV1 {
    OuterContextV1 {
        frame_kind,
        relay_protocol_version: RELAY_PROTOCOL_VERSION,
        e2ee_format_version: E2EE_FORMAT_VERSION,
        machine_route: None,
        device_route: None,
        stream_route: None,
        request_route: None,
        pair_route: Some(pair_route),
        stream_generation: None,
        stream_cursor: None,
        stream_seq: None,
        message_key_epoch: 0,
    }
}

fn mvp_authorization() -> Result<AuthorizationRequestV1, agentdeck_protocol::e2ee::PairingError> {
    let request = AuthorizationRequestV1 {
        format_version: E2EE_FORMAT_VERSION,
        device_display_name: WEB_DEVICE_DISPLAY_NAME.to_owned(),
        capabilities: vec![
            AuthorizationCapabilityV1::Catalog,
            AuthorizationCapabilityV1::Conversation,
            AuthorizationCapabilityV1::Prompt,
            AuthorizationCapabilityV1::Command,
            AuthorizationCapabilityV1::Approval,
            AuthorizationCapabilityV1::Metadata,
            AuthorizationCapabilityV1::SelfRevocation,
        ],
        permissions: vec![
            AuthorizationPermissionV1::CatalogRead,
            AuthorizationPermissionV1::ConversationRead,
            AuthorizationPermissionV1::ConversationStart,
            AuthorizationPermissionV1::PromptSend,
            AuthorizationPermissionV1::CommandCancel,
            AuthorizationPermissionV1::ApprovalResolve,
            AuthorizationPermissionV1::ApprovalRetry,
            AuthorizationPermissionV1::MetadataWrite,
            AuthorizationPermissionV1::RevokeSelf,
        ],
    };
    request.validate()?;
    Ok(request)
}

#[cfg(target_arch = "wasm32")]
mod wasm {
    use wasm_bindgen::prelude::*;

    use super::{W2PairingCore, W2PairingError};

    fn js_error(error: W2PairingError) -> JsValue {
        JsValue::from_str(error.code())
    }

    fn random_seed() -> Result<[u8; 32], W2PairingError> {
        let mut seed = [0_u8; 32];
        getrandom_04::fill(&mut seed).map_err(|_| W2PairingError::EntropyUnavailable)?;
        Ok(seed)
    }

    #[wasm_bindgen(js_name = W2PairingSession)]
    pub struct W2PairingSession {
        core: W2PairingCore,
    }

    #[wasm_bindgen(js_class = W2PairingSession)]
    impl W2PairingSession {
        #[wasm_bindgen(constructor)]
        pub fn new(encoded_invite: &str, now_ms: u64) -> Result<W2PairingSession, JsValue> {
            let core = W2PairingCore::inspect(encoded_invite, now_ms).map_err(js_error)?;
            Ok(Self { core })
        }

        #[wasm_bindgen(js_name = previewJson)]
        pub fn preview_json(&self) -> Result<String, JsValue> {
            serde_json::to_string(&self.core.preview())
                .map_err(|_| js_error(W2PairingError::SerializationFailed))
        }

        #[wasm_bindgen(js_name = confirm)]
        pub fn confirm(&mut self, fingerprint: &str, now_ms: u64) -> Result<(), JsValue> {
            self.core
                .confirm(
                    fingerprint,
                    now_ms,
                    random_seed().map_err(js_error)?,
                    random_seed().map_err(js_error)?,
                    random_seed().map_err(js_error)?,
                )
                .map_err(js_error)
        }

        #[wasm_bindgen(js_name = connectUrl)]
        pub fn connect_url(&self) -> Result<String, JsValue> {
            self.core.connect_url().map(str::to_owned).map_err(js_error)
        }

        #[wasm_bindgen(js_name = startHello)]
        pub fn start_hello(&mut self) -> Result<Vec<u8>, JsValue> {
            self.core.start_hello().map_err(js_error)
        }

        #[wasm_bindgen(js_name = startPairingHello)]
        pub fn start_pairing_hello(&mut self) -> Result<Vec<u8>, JsValue> {
            self.core.start_pairing_hello().map_err(js_error)
        }

        #[wasm_bindgen(js_name = acceptAuthenticated)]
        pub fn accept_authenticated(&mut self, bytes: &[u8]) -> Result<Vec<u8>, JsValue> {
            self.core.accept_authenticated(bytes).map_err(js_error)
        }

        #[wasm_bindgen(js_name = acceptPairFrame)]
        pub fn accept_pair_frame(&mut self, bytes: &[u8], now_ms: u64) -> Result<Vec<u8>, JsValue> {
            self.core.accept_pair_frame(bytes, now_ms).map_err(js_error)
        }

        #[wasm_bindgen(js_name = paired)]
        pub fn paired(&self) -> bool {
            self.core.paired()
        }

        #[wasm_bindgen(js_name = evidenceJson)]
        pub fn evidence_json(&self) -> Result<String, JsValue> {
            serde_json::to_string(&self.core.evidence())
                .map_err(|_| js_error(W2PairingError::SerializationFailed))
        }

        #[wasm_bindgen(js_name = businessConnectUrl)]
        pub fn business_connect_url(&self) -> Result<String, JsValue> {
            self.core
                .business_connect_url()
                .map(str::to_owned)
                .map_err(js_error)
        }

        #[wasm_bindgen(js_name = businessStartHello)]
        pub fn business_start_hello(&mut self) -> Result<Vec<u8>, JsValue> {
            self.core.business_start_hello().map_err(js_error)
        }

        #[wasm_bindgen(js_name = businessAcceptChallenge)]
        pub fn business_accept_challenge(&mut self, bytes: &[u8]) -> Result<Vec<u8>, JsValue> {
            self.core.business_accept_challenge(bytes).map_err(js_error)
        }

        #[wasm_bindgen(js_name = businessAcceptAuthenticated)]
        pub fn business_accept_authenticated(&mut self, bytes: &[u8]) -> Result<(), JsValue> {
            self.core
                .business_accept_authenticated(bytes)
                .map_err(js_error)
        }

        #[wasm_bindgen(js_name = businessStartCatalog)]
        pub fn business_start_catalog(&mut self) -> Result<Vec<u8>, JsValue> {
            self.core.business_start_catalog().map_err(js_error)
        }

        #[wasm_bindgen(js_name = businessStartConversation)]
        pub fn business_start_conversation(&mut self) -> Result<Vec<u8>, JsValue> {
            self.core.business_start_conversation().map_err(js_error)
        }

        #[wasm_bindgen(js_name = businessStartPrompt)]
        pub fn business_start_prompt(&mut self) -> Result<Vec<u8>, JsValue> {
            self.core.business_start_prompt().map_err(js_error)
        }

        #[wasm_bindgen(js_name = businessStartApproval)]
        pub fn business_start_approval(&mut self) -> Result<Vec<u8>, JsValue> {
            self.core.business_start_approval().map_err(js_error)
        }

        #[wasm_bindgen(js_name = businessAcceptFrame)]
        pub fn business_accept_frame(&mut self, bytes: &[u8]) -> Result<Vec<u8>, JsValue> {
            self.core.business_accept_frame(bytes).map_err(js_error)
        }

        #[wasm_bindgen(js_name = businessEvidenceJson)]
        pub fn business_evidence_json(&self) -> Result<String, JsValue> {
            serde_json::to_string(&self.core.business_evidence().map_err(js_error)?)
                .map_err(|_| js_error(W2PairingError::SerializationFailed))
        }
    }
}
